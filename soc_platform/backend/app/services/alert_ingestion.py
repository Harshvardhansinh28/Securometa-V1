from datetime import datetime
from typing import Callable

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.alert import Alert, RawAlert

# Important:
# These imports ensure SQLAlchemy knows these tables exist,
# especially because alerts.case_id has a foreign key to cases.id.
from app.models.case import Case, CaseAlert, CaseTimeline, CaseNote  # noqa: F401
from app.models.incident import Incident, IncidentEvent, IncidentEntity, ThreatIndicator  # noqa: F401
from app.models.raw_payload import RawPayload  # noqa: F401

from app.models.connector import ConnectorSyncState
from app.models.tenant import Tenant
from app.schemas.alert import NormalizedAlert
from app.services.fingerprint import stable_json_hash
from app.services.incident_ingestion import incident_ingestion_service
from app.services.redpanda import redpanda_producer

logger = get_logger(__name__)


class AlertIngestionService:
    def ingest_alert(
        self,
        db: Session,
        tenant: Tenant,
        platform: str,
        raw_alert: dict,
        normalizer: Callable[[Tenant, dict], NormalizedAlert],
    ) -> Alert:
        source_alert_id = self._extract_source_alert_id(
            platform=platform,
            raw_alert=raw_alert,
        )

        payload_hash = stable_json_hash(raw_alert)

        raw_alert_obj = self._store_raw_alert(
            db=db,
            tenant_id=tenant.id,
            platform=platform,
            source_alert_id=source_alert_id,
            raw_payload=raw_alert,
            payload_hash=payload_hash,
        )

        normalized = normalizer(tenant, raw_alert)

        alert = self._upsert_normalized_alert(
            db=db,
            normalized=normalized,
            raw_alert_id=raw_alert_obj.id,
        )

        redpanda_producer.publish(
            topic="alerts.normalized",
            key=f"{platform}:{source_alert_id}",
            value={
                "tenant_id": tenant.id,
                "tenant_key": tenant.tenant_key,
                "tenant_name": tenant.tenant_name,
                "platform": platform,
                "source_alert_id": source_alert_id,
                "alert_id": alert.id,
                "title": alert.title,
                "severity": alert.severity,
                "priority": alert.priority,
                "status": alert.status,
                "last_updated_at": alert.last_updated_at,
            },
        )

        # New incident layer:
        # Every normalized alert also creates/updates a unified incident,
        # incident event, and extracted entities.
        try:
            incident_ingestion_service.upsert_incident_from_alert(
                db=db,
                alert=alert,
                raw_payload=raw_alert,
            )

        except Exception as exc:
            db.rollback()
            logger.exception(
                "Incident auto-ingestion failed | platform=%s | source_alert_id=%s | error=%s",
                platform,
                source_alert_id,
                exc,
            )

        return alert

    def mark_sync_success(
        self,
        db: Session,
        tenant_id: int,
        platform: str,
    ) -> None:
        state = self._get_or_create_sync_state(
            db=db,
            tenant_id=tenant_id,
            platform=platform,
        )

        state.last_success_at = datetime.utcnow()
        state.sync_status = "healthy"
        state.last_error = None

        db.commit()

    def mark_sync_failure(
        self,
        db: Session,
        tenant_id: int,
        platform: str,
        error: str,
    ) -> None:
        state = self._get_or_create_sync_state(
            db=db,
            tenant_id=tenant_id,
            platform=platform,
        )

        state.last_failure_at = datetime.utcnow()
        state.sync_status = "failed"
        state.last_error = error[:5000]

        db.commit()

    def _store_raw_alert(
        self,
        db: Session,
        tenant_id: int,
        platform: str,
        source_alert_id: str,
        raw_payload: dict,
        payload_hash: str,
    ) -> RawAlert:
        existing = (
            db.query(RawAlert)
            .filter(
                RawAlert.platform == platform,
                RawAlert.source_alert_id == source_alert_id,
                RawAlert.payload_hash == payload_hash,
            )
            .first()
        )

        if existing:
            return existing

        raw_alert_obj = RawAlert(
            tenant_id=tenant_id,
            platform=platform,
            source_alert_id=source_alert_id,
            raw_payload=raw_payload,
            payload_hash=payload_hash,
        )

        db.add(raw_alert_obj)

        try:
            db.commit()
            db.refresh(raw_alert_obj)
            return raw_alert_obj

        except IntegrityError:
            db.rollback()

            existing = (
                db.query(RawAlert)
                .filter(
                    RawAlert.platform == platform,
                    RawAlert.source_alert_id == source_alert_id,
                    RawAlert.payload_hash == payload_hash,
                )
                .first()
            )

            if existing:
                return existing

            raise

    def _upsert_normalized_alert(
        self,
        db: Session,
        normalized: NormalizedAlert,
        raw_alert_id: int,
    ) -> Alert:
        existing = (
            db.query(Alert)
            .filter(
                Alert.platform == normalized.platform,
                Alert.source_alert_id == normalized.source_alert_id,
            )
            .first()
        )

        if existing:
            existing.title = normalized.title
            existing.description = normalized.description
            existing.severity = normalized.severity
            existing.priority = normalized.priority
            existing.status = normalized.status
            existing.assigned_to = normalized.assigned_to
            existing.entity_type = normalized.entity_type
            existing.entity_value = normalized.entity_value
            existing.source_url = normalized.source_url
            existing.event_time = normalized.event_time
            existing.last_updated_at = normalized.last_updated_at
            existing.fingerprint = normalized.fingerprint
            existing.raw_alert_id = raw_alert_id

            db.commit()
            db.refresh(existing)

            return existing

        alert = Alert(
            tenant_id=normalized.tenant_id,
            platform=normalized.platform,
            source_alert_id=normalized.source_alert_id,
            title=normalized.title,
            description=normalized.description,
            severity=normalized.severity,
            priority=normalized.priority,
            status=normalized.status,
            assigned_to=normalized.assigned_to,
            entity_type=normalized.entity_type,
            entity_value=normalized.entity_value,
            source_url=normalized.source_url,
            event_time=normalized.event_time,
            last_updated_at=normalized.last_updated_at,
            fingerprint=normalized.fingerprint,
            raw_alert_id=raw_alert_id,
        )

        db.add(alert)
        db.commit()
        db.refresh(alert)

        return alert

    def _extract_source_alert_id(
        self,
        platform: str,
        raw_alert: dict,
    ) -> str:
        if platform == "seceon":
            value = raw_alert.get("alert_id")

        elif platform == "securonix":
            value = raw_alert.get("incidentId")

        else:
            raise ValueError(f"Unsupported platform: {platform}")

        if not value:
            raise ValueError(f"Missing source alert ID for platform={platform}")

        return str(value)

    def _get_or_create_sync_state(
        self,
        db: Session,
        tenant_id: int,
        platform: str,
    ) -> ConnectorSyncState:
        state = (
            db.query(ConnectorSyncState)
            .filter(
                ConnectorSyncState.tenant_id == tenant_id,
                ConnectorSyncState.platform == platform,
            )
            .first()
        )

        if state:
            return state

        state = ConnectorSyncState(
            tenant_id=tenant_id,
            platform=platform,
            sync_status="healthy",
        )

        db.add(state)
        db.commit()
        db.refresh(state)

        return state


alert_ingestion_service = AlertIngestionService()
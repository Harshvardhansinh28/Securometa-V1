from datetime import datetime, timezone, timedelta
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.alert import Alert
from app.models.incident import Incident, IncidentEntity, IncidentEvent
from app.models.raw_payload import RawPayload
from app.services.entity_extraction import extract_entities_from_payload
from app.services.field_mapping import (
    get_first_available,
    infer_src_dest_from_message,
    infer_workflow_status,
    severity_to_risk_score,
    value_or_default,
)
from app.services.raw_payload_store import raw_payload_store

logger = get_logger(__name__)


def parse_datetime_safely(value: Any) -> datetime | None:
    if value is None:
        return None

    if isinstance(value, datetime):
        return value.replace(tzinfo=None)

    if isinstance(value, int):
        try:
            if value > 10_000_000_000:
                return datetime.fromtimestamp(value / 1000, tz=timezone.utc).replace(tzinfo=None)

            return datetime.fromtimestamp(value, tz=timezone.utc).replace(tzinfo=None)

        except Exception:
            return None

    if isinstance(value, str):
        text = value.strip()

        if not text:
            return None

        formats = [
            "%m/%d/%Y, %I:%M:%S %p",
            "%m/%d/%y, %I:%M:%S %p",
            "%Y-%m-%d %H:%M:%S",
            "%Y/%m/%d %H:%M:%S",
            "%d/%m/%Y, %I:%M:%S %p",
            "%d/%m/%y, %I:%M:%S %p",
            "%m/%d/%Y %I:%M:%S %p",
            "%m/%d/%y %I:%M:%S %p",
        ]

        for fmt in formats:
            try:
                return datetime.strptime(text, fmt)
            except Exception:
                continue

        try:
            return datetime.fromisoformat(text.replace("Z", "+00:00")).replace(tzinfo=None)
        except Exception:
            return None

    return None


def epoch_ms_to_ist_naive(ms: Any) -> datetime | None:
    try:
        if not ms:
            return None

        return (
            datetime.fromtimestamp(int(ms) / 1000, tz=timezone.utc)
            + timedelta(hours=5, minutes=30)
        ).replace(tzinfo=None)

    except Exception:
        return None


class IncidentIngestionService:
    def upsert_incident_from_alert(
        self,
        db: Session,
        alert: Alert,
        raw_payload: dict[str, Any],
    ) -> Incident:
        raw_payload_record = raw_payload_store.store(
            db=db,
            tenant_id=alert.tenant_id,
            platform=alert.platform,
            object_type="incident_from_alert",
            source_object_id=alert.source_alert_id,
            raw_json=raw_payload,
        )

        incident = self._upsert_incident(
            db=db,
            alert=alert,
            raw_payload=raw_payload,
            raw_payload_record=raw_payload_record,
        )

        self._upsert_summary_event(
            db=db,
            incident=incident,
            alert=alert,
            raw_payload=raw_payload,
            raw_payload_record=raw_payload_record,
        )

        self._extract_and_store_entities(
            db=db,
            incident=incident,
            raw_payload=raw_payload,
        )

        return incident

    def _upsert_incident(
        self,
        db: Session,
        alert: Alert,
        raw_payload: dict[str, Any],
        raw_payload_record: RawPayload,
    ) -> Incident:
        source_incident_id = self._get_source_incident_id(alert, raw_payload)

        existing = (
            db.query(Incident)
            .filter(
                Incident.platform == alert.platform,
                Incident.source_incident_id == source_incident_id,
            )
            .first()
        )

        event_type_name = (
            get_first_available(raw_payload, "event_type_name")
            or alert.title
            or "not_available_in_summary"
        )

        event_category = (
            get_first_available(raw_payload, "event_category")
            or event_type_name
            or "not_available_in_summary"
        )

        event_origin = (
            get_first_available(raw_payload, "event_origin")
            or f"{alert.platform}_summary_api"
        )

        risk_score = self._safe_float(get_first_available(raw_payload, "risk_score"))

        if risk_score is None:
            risk_score = severity_to_risk_score(alert.severity, alert.priority)

        event_time_value = (
            get_first_available(raw_payload, "event_timestamp")
            or raw_payload.get("lastUpdateDate")
        )

        first_seen_at = (
            alert.event_time
            or parse_datetime_safely(event_time_value)
            or epoch_ms_to_ist_naive(raw_payload.get("lastUpdateDate"))
            or alert.last_updated_at
            or datetime.utcnow()
        )

        last_seen_at = (
            alert.last_updated_at
            or parse_datetime_safely(raw_payload.get("update_time"))
            or parse_datetime_safely(event_time_value)
            or epoch_ms_to_ist_naive(raw_payload.get("lastUpdateDate"))
            or first_seen_at
        )

        workflow_status = infer_workflow_status(
            alert_status=alert.status,
            assigned_to=alert.assigned_to,
        )

        category = value_or_default(event_category)
        incident_type = "alert_summary_enriched"

        description = value_or_default(
            alert.description,
            default="description_not_available_in_summary",
        )

        if existing:
            existing.alert_id = alert.id
            existing.source_alert_id = alert.source_alert_id
            existing.title = value_or_default(alert.title)
            existing.description = description
            existing.severity = value_or_default(alert.severity, "unknown")
            existing.priority = value_or_default(alert.priority, "P3")
            existing.status = value_or_default(alert.status, "open")
            existing.category = category
            existing.sub_category = value_or_default(raw_payload.get("sub_category"))
            existing.incident_type = incident_type
            existing.event_type_name = value_or_default(event_type_name)
            existing.event_category = value_or_default(event_category)
            existing.event_origin = value_or_default(event_origin)
            existing.risk_score = risk_score
            existing.confidence_score = 0.6
            existing.assigned_to = value_or_default(alert.assigned_to, "unassigned")
            existing.workflow_status = workflow_status
            existing.first_seen_at = first_seen_at
            existing.last_seen_at = last_seen_at
            existing.source_created_at = first_seen_at
            existing.source_updated_at = last_seen_at
            existing.hydration_status = "summary_enriched"
            existing.hydrated_at = datetime.utcnow()
            existing.raw_payload_id = raw_payload_record.id

            db.commit()
            db.refresh(existing)
            return existing

        incident = Incident(
            tenant_id=alert.tenant_id,
            platform=alert.platform,
            source_incident_id=source_incident_id,
            source_alert_id=alert.source_alert_id,
            alert_id=alert.id,
            case_id=alert.case_id,
            title=value_or_default(alert.title),
            description=description,
            severity=value_or_default(alert.severity, "unknown"),
            priority=value_or_default(alert.priority, "P3"),
            status=value_or_default(alert.status, "open"),
            category=category,
            sub_category=value_or_default(raw_payload.get("sub_category")),
            incident_type=incident_type,
            event_type_name=value_or_default(event_type_name),
            event_category=value_or_default(event_category),
            event_origin=value_or_default(event_origin),
            risk_score=risk_score,
            confidence_score=0.6,
            assigned_to=value_or_default(alert.assigned_to, "unassigned"),
            workflow_status=workflow_status,
            first_seen_at=first_seen_at,
            last_seen_at=last_seen_at,
            source_created_at=first_seen_at,
            source_updated_at=last_seen_at,
            hydration_status="summary_enriched",
            hydrated_at=datetime.utcnow(),
            raw_payload_id=raw_payload_record.id,
        )

        db.add(incident)
        db.commit()
        db.refresh(incident)

        return incident

    def _upsert_summary_event(
        self,
        db: Session,
        incident: Incident,
        alert: Alert,
        raw_payload: dict[str, Any],
        raw_payload_record: RawPayload,
    ) -> IncidentEvent:
        event_id = get_first_available(raw_payload, "event_id")

        source_event_id = (
            str(event_id)
            if event_id
            else f"{alert.platform}:{alert.tenant_id}:{alert.source_alert_id}:summary"
        )

        existing = (
            db.query(IncidentEvent)
            .filter(
                IncidentEvent.platform == alert.platform,
                IncidentEvent.source_event_id == source_event_id,
            )
            .first()
        )

        message = (
            get_first_available(raw_payload, "message")
            or alert.description
            or "message_not_available_in_summary"
        )

        src_ip = get_first_available(raw_payload, "src_ip")
        dest_ip = get_first_available(raw_payload, "dest_ip")

        inferred_src_ip, inferred_dest_ip = infer_src_dest_from_message(message)

        src_ip = src_ip or inferred_src_ip or "not_available_in_summary"
        dest_ip = dest_ip or inferred_dest_ip or "not_available_in_summary"

        event_time = (
            parse_datetime_safely(get_first_available(raw_payload, "event_timestamp"))
            or alert.event_time
            or alert.last_updated_at
            or datetime.utcnow()
        )

        event_type_id = value_or_default(
            get_first_available(raw_payload, "event_type_id")
        )

        event_type_name = value_or_default(
            get_first_available(raw_payload, "event_type_name")
            or alert.title
        )

        event_category = value_or_default(
            get_first_available(raw_payload, "event_category")
            or event_type_name
        )

        event_origin = value_or_default(
            get_first_available(raw_payload, "event_origin")
            or f"{alert.platform}_summary_api"
        )

        event_generator_ip = value_or_default(
            get_first_available(raw_payload, "event_generator_ip")
        )

        event_generator_type = value_or_default(
            get_first_available(raw_payload, "event_generator_type")
        )

        source_data_type = value_or_default(
            get_first_available(raw_payload, "source_data_type")
        )

        src_host_name = value_or_default(get_first_available(raw_payload, "src_host_name"))
        dst_host_name = value_or_default(get_first_available(raw_payload, "dst_host_name"))
        user_name = value_or_default(get_first_available(raw_payload, "user_name"))

        if existing:
            existing.incident_id = incident.id
            existing.tenant_id = alert.tenant_id
            existing.event_time = event_time
            existing.event_type_id = event_type_id
            existing.event_type_name = event_type_name
            existing.event_category = event_category
            existing.event_origin = event_origin
            existing.event_generator_ip = event_generator_ip
            existing.event_generator_type = event_generator_type
            existing.source_data_type = source_data_type
            existing.src_ip = src_ip
            existing.dest_ip = dest_ip
            existing.src_host_name = src_host_name
            existing.dst_host_name = dst_host_name
            existing.user_name = user_name
            existing.message = str(message)
            existing.raw_message = str(message)
            existing.raw_payload_id = raw_payload_record.id

            db.commit()
            db.refresh(existing)
            return existing

        event = IncidentEvent(
            incident_id=incident.id,
            tenant_id=alert.tenant_id,
            platform=alert.platform,
            source_event_id=source_event_id,
            event_time=event_time,
            event_type_id=event_type_id,
            event_type_name=event_type_name,
            event_category=event_category,
            event_origin=event_origin,
            event_generator_ip=event_generator_ip,
            event_generator_type=event_generator_type,
            source_data_type=source_data_type,
            src_ip=src_ip,
            dest_ip=dest_ip,
            src_host_name=src_host_name,
            dst_host_name=dst_host_name,
            user_name=user_name,
            message=str(message),
            raw_message=str(message),
            raw_payload_id=raw_payload_record.id,
        )

        db.add(event)
        db.commit()
        db.refresh(event)

        return event

    def _extract_and_store_entities(
        self,
        db: Session,
        incident: Incident,
        raw_payload: dict[str, Any],
    ) -> None:
        entities = extract_entities_from_payload(raw_payload)

        for entity in entities:
            existing = (
                db.query(IncidentEntity)
                .filter(
                    IncidentEntity.incident_id == incident.id,
                    IncidentEntity.entity_type == entity["entity_type"],
                    IncidentEntity.entity_value == entity["entity_value"],
                )
                .first()
            )

            if existing:
                continue

            incident_entity = IncidentEntity(
                incident_id=incident.id,
                tenant_id=incident.tenant_id,
                entity_type=entity["entity_type"],
                entity_value=entity["entity_value"],
                source_field=entity["source_field"],
                confidence=entity["confidence"],
            )

            db.add(incident_entity)

            try:
                db.commit()
            except IntegrityError:
                db.rollback()

    def _get_source_incident_id(
        self,
        alert: Alert,
        raw_payload: dict[str, Any],
    ) -> str:
        if alert.platform == "securonix":
            return str(raw_payload.get("incidentId") or alert.source_alert_id)

        if alert.platform == "seceon":
            return str(
                raw_payload.get("alert_id")
                or raw_payload.get("event_id")
                or alert.source_alert_id
            )

        return alert.source_alert_id

    def _safe_float(self, value: Any) -> float | None:
        try:
            if value is None:
                return None
            return float(value)
        except Exception:
            return None


incident_ingestion_service = IncidentIngestionService()
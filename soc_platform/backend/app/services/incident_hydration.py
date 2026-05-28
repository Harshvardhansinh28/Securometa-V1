from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.connectors.seceon import SeceonConnector
from app.connectors.securonix import SecuronixConnector
from app.core.config import get_settings
from app.core.logging import get_logger
from app.models.incident import Incident, IncidentEvent
from app.models.tenant import TenantPlatformAccount
from app.services.entity_extraction import extract_entities_from_payload
from app.services.incident_ingestion import parse_datetime_safely
from app.services.raw_payload_store import raw_payload_store
from app.services.threat_indicator_store import threat_indicator_store

logger = get_logger(__name__)
settings = get_settings()


class IncidentHydrationService:

    def hydrate_incident_by_id(
        self,
        db: Session,
        incident_id: int,
    ) -> dict:
        incident = (
            db.query(Incident)
            .filter(Incident.id == incident_id)
            .first()
        )

        if not incident:
            return {
                "incident_id": incident_id,
                "status": "failed",
                "reason": "incident_not_found",
            }

        if incident.platform == "seceon":
            return self._hydrate_one_seceon_incident(
                db=db,
                connector=SeceonConnector(),
                incident=incident,
            )

        if incident.platform == "securonix":
            return self._hydrate_one_securonix_incident(
                db=db,
                connector=SecuronixConnector(),
                incident=incident,
            )

        return {
            "incident_id": incident_id,
            "status": "failed",
            "reason": f"unsupported_platform_{incident.platform}",
        }
    def hydrate_seceon_incidents(
        self,
        db: Session,
        limit: int | None = None,
    ) -> dict:
        max_items = limit or settings.hydration_max_incidents_per_run

        incidents = (
            db.query(Incident)
            .filter(
                Incident.platform == "seceon",
                Incident.hydration_status.in_(
                    ["summary", "summary_enriched", "partial", "failed"]
                ),
            )
            .order_by(Incident.updated_at.desc())
            .limit(max_items)
            .all()
        )

        connector = SeceonConnector()

        hydrated = 0
        partial = 0
        failed = 0
        details = []

        for incident in incidents:
            try:
                result = self._hydrate_one_seceon_incident(
                    db=db,
                    connector=connector,
                    incident=incident,
                )

                details.append(result)

                if result["status"] == "hydrated":
                    hydrated += 1
                elif result["status"] == "partial":
                    partial += 1
                else:
                    failed += 1

            except Exception as exc:
                db.rollback()

                incident.hydration_status = "failed"
                incident.hydrated_at = datetime.utcnow()
                db.commit()

                failed += 1

                details.append(
                    {
                        "incident_id": incident.id,
                        "status": "failed",
                        "error": str(exc),
                    }
                )

        return {
            "platform": "seceon",
            "processed": len(incidents),
            "hydrated": hydrated,
            "partial": partial,
            "failed": failed,
            "details": details,
        }

    def hydrate_securonix_incidents(
        self,
        db: Session,
        limit: int | None = None,
    ) -> dict:
        max_items = limit or settings.hydration_max_incidents_per_run

        incidents = (
            db.query(Incident)
            .filter(
                Incident.platform == "securonix",
                Incident.hydration_status.in_(
                    ["summary", "summary_enriched", "partial", "failed"]
                ),
            )
            .order_by(Incident.updated_at.desc())
            .limit(max_items)
            .all()
        )

        connector = SecuronixConnector()

        hydrated = 0
        partial = 0
        failed = 0
        details = []

        for incident in incidents:
            try:
                result = self._hydrate_one_securonix_incident(
                    db=db,
                    connector=connector,
                    incident=incident,
                )

                details.append(result)

                if result["status"] == "hydrated":
                    hydrated += 1
                elif result["status"] == "partial":
                    partial += 1
                else:
                    failed += 1

            except Exception as exc:
                db.rollback()

                incident.hydration_status = "failed"
                incident.hydrated_at = datetime.utcnow()
                db.commit()

                failed += 1

                details.append(
                    {
                        "incident_id": incident.id,
                        "status": "failed",
                        "error": str(exc),
                    }
                )

        return {
            "platform": "securonix",
            "processed": len(incidents),
            "hydrated": hydrated,
            "partial": partial,
            "failed": failed,
            "details": details,
        }

    def _hydrate_one_seceon_incident(
        self,
        db: Session,
        connector: SeceonConnector,
        incident: Incident,
    ) -> dict:
        account = (
            db.query(TenantPlatformAccount)
            .filter(
                TenantPlatformAccount.tenant_id == incident.tenant_id,
                TenantPlatformAccount.platform == "seceon",
                TenantPlatformAccount.is_enabled.is_(True),
            )
            .first()
        )

        if not account or not account.external_tenant_id:
            incident.hydration_status = "failed"
            incident.hydrated_at = datetime.utcnow()
            db.commit()

            return {
                "incident_id": incident.id,
                "status": "failed",
                "reason": "missing_seceon_tenant_mapping",
            }

        events = (
            db.query(IncidentEvent)
            .filter(IncidentEvent.incident_id == incident.id)
            .all()
        )

        if not events:
            incident.hydration_status = "partial"
            incident.hydrated_at = datetime.utcnow()
            db.commit()

            return {
                "incident_id": incident.id,
                "status": "partial",
                "reason": "no_incident_events_found",
            }

        stored_indicators = 0
        event_attempts = 0
        event_success = 0
        event_failures = []

        for event in events:
            event_id = event.source_event_id

            if not event_id or event_id.endswith(":summary"):
                continue

            event_attempts += 1

            try:
                threat_response = connector.fetch_threat_indicators_by_event_id(
                    tenant_external_id=account.external_tenant_id,
                    event_id=event_id,
                )

                count = threat_indicator_store.store_from_response(
                    db=db,
                    tenant_id=incident.tenant_id,
                    platform=incident.platform,
                    incident_id=incident.id,
                    incident_event_id=event.id,
                    source_event_id=event_id,
                    response_payload=threat_response,
                )

                stored_indicators += count
                event_success += 1

            except Exception as exc:
                db.rollback()

                event_failures.append(
                    {
                        "event_id": event_id,
                        "error": str(exc),
                    }
                )

        if event_attempts == 0:
            incident.hydration_status = "partial"
            status = "partial"
            reason = "no_real_event_id_available"

        elif event_success > 0:
            incident.hydration_status = "hydrated"
            status = "hydrated"
            reason = "threat_indicators_fetched"

        else:
            incident.hydration_status = "failed"
            status = "failed"
            reason = "all_event_hydration_attempts_failed"

        incident.hydrated_at = datetime.utcnow()
        db.commit()

        return {
            "incident_id": incident.id,
            "source_incident_id": incident.source_incident_id,
            "status": status,
            "reason": reason,
            "events_attempted": event_attempts,
            "events_success": event_success,
            "indicators_stored": stored_indicators,
            "event_failures": event_failures,
        }

    def _hydrate_one_securonix_incident(
        self,
        db: Session,
        connector: SecuronixConnector,
        incident: Incident,
    ) -> dict:
        account = (
            db.query(TenantPlatformAccount)
            .filter(
                TenantPlatformAccount.tenant_id == incident.tenant_id,
                TenantPlatformAccount.platform == "securonix",
                TenantPlatformAccount.is_enabled.is_(True),
            )
            .first()
        )

        if not account or not account.external_tenant_name:
            incident.hydration_status = "failed"
            incident.hydrated_at = datetime.utcnow()
            db.commit()

            return {
                "incident_id": incident.id,
                "status": "failed",
                "reason": "missing_securonix_tenant_mapping",
            }

        detail_payload = connector.fetch_incident_detail(
            tenant_name=account.external_tenant_name,
            incident_id=incident.source_incident_id,
        )

        raw_payload = raw_payload_store.store(
            db=db,
            tenant_id=incident.tenant_id,
            platform=incident.platform,
            object_type="securonix_incident_detail",
            source_object_id=incident.source_incident_id,
            raw_json=detail_payload,
        )

        extracted_detail = self._extract_securonix_detail_payload(detail_payload)

        if extracted_detail:
            self._update_incident_from_securonix_detail(
                incident=incident,
                detail=extracted_detail,
                raw_payload_id=raw_payload.id,
            )

        violations_payload = None
        violations_stored = 0

        try:
            violations_payload = connector.fetch_violations_by_incident_id(
                tenant_name=account.external_tenant_name,
                incident_id=incident.source_incident_id,
            )
        except Exception as exc:
            violations_payload = {
                "error": str(exc),
                "message": "violations_fetch_failed",
            }

        if violations_payload:
            violations_stored = self._store_securonix_violations_as_events(
                db=db,
                incident=incident,
                violations_payload=violations_payload,
            )

        self._extract_entities_from_hydrated_payload(
            db=db,
            incident=incident,
            payload=detail_payload,
        )

        if extracted_detail or violations_stored > 0:
            incident.hydration_status = "hydrated"
            status = "hydrated"
            reason = "incident_detail_fetched"
        else:
            incident.hydration_status = "partial"
            status = "partial"
            reason = "detail_fetched_but_no_extra_fields_mapped"

        incident.hydrated_at = datetime.utcnow()
        db.commit()

        return {
            "incident_id": incident.id,
            "source_incident_id": incident.source_incident_id,
            "status": status,
            "reason": reason,
            "detail_payload_stored": True,
            "violations_stored": violations_stored,
        }

    def _extract_securonix_detail_payload(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        candidates = []

        result = payload.get("result")

        if isinstance(result, dict):
            candidates.append(result)

            data = result.get("data")
            if isinstance(data, dict):
                candidates.append(data)

            if isinstance(data, list) and data:
                for item in data:
                    if isinstance(item, dict):
                        candidates.append(item)

        for key in ["incident", "incidentDetails", "data", "response"]:
            value = payload.get(key)

            if isinstance(value, dict):
                candidates.append(value)

            if isinstance(value, list) and value:
                for item in value:
                    if isinstance(item, dict):
                        candidates.append(item)

        if not candidates and payload:
            candidates.append(payload)

        best = {}

        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue

            if len(candidate.keys()) > len(best.keys()):
                best = candidate

        return best

    def _update_incident_from_securonix_detail(
        self,
        incident: Incident,
        detail: dict[str, Any],
        raw_payload_id: int,
    ) -> None:
        title = (
            detail.get("policyName")
            or detail.get("policy")
            or detail.get("threatName")
            or detail.get("title")
            or incident.title
        )

        description = (
            detail.get("description")
            or detail.get("threatDescription")
            or detail.get("reason")
            or incident.description
        )

        status = (
            detail.get("incidentStatus")
            or detail.get("status")
            or incident.status
        )

        risk_score = self._safe_float(
            detail.get("riskScore")
            or detail.get("risk_score")
            or detail.get("threatScore")
            or incident.risk_score
        )

        assigned_to = (
            detail.get("assignedTo")
            or detail.get("assignee")
            or detail.get("owner")
            or incident.assigned_to
        )

        workflow_status = (
            detail.get("workflow")
            or detail.get("workflowStatus")
            or detail.get("workflow_status")
            or incident.workflow_status
        )

        last_seen_at = (
            parse_datetime_safely(detail.get("lastUpdateDate"))
            or parse_datetime_safely(detail.get("updatedAt"))
            or incident.last_seen_at
        )

        incident.title = str(title)
        incident.description = str(description) if description else incident.description
        incident.status = str(status).lower() if status else incident.status
        incident.risk_score = risk_score
        incident.assigned_to = str(assigned_to) if assigned_to else incident.assigned_to
        incident.workflow_status = str(workflow_status) if workflow_status else incident.workflow_status
        incident.last_seen_at = last_seen_at
        incident.source_updated_at = last_seen_at
        incident.raw_payload_id = raw_payload_id

    def _store_securonix_violations_as_events(
        self,
        db: Session,
        incident: Incident,
        violations_payload: dict[str, Any],
    ) -> int:
        raw_payload = raw_payload_store.store(
            db=db,
            tenant_id=incident.tenant_id,
            platform=incident.platform,
            object_type="securonix_violations",
            source_object_id=incident.source_incident_id,
            raw_json=violations_payload,
        )

        violations = self._extract_list_from_payload(violations_payload)

        stored = 0

        for idx, violation in enumerate(violations):
            if not isinstance(violation, dict):
                continue

            source_event_id = str(
                violation.get("violationId")
                or violation.get("id")
                or violation.get("eventId")
                or f"{incident.source_incident_id}:violation:{idx}"
            )

            existing = (
                db.query(IncidentEvent)
                .filter(
                    IncidentEvent.platform == incident.platform,
                    IncidentEvent.source_event_id == source_event_id,
                )
                .first()
            )

            event_time = (
                parse_datetime_safely(violation.get("eventTime"))
                or parse_datetime_safely(violation.get("activityTime"))
                or parse_datetime_safely(violation.get("createdAt"))
            )

            message = (
                violation.get("message")
                or violation.get("description")
                or violation.get("activity")
                or incident.description
            )

            if existing:
                existing.incident_id = incident.id
                existing.tenant_id = incident.tenant_id
                existing.event_time = event_time
                existing.event_type_name = str(
                    violation.get("policyName")
                    or violation.get("threatName")
                    or incident.event_type_name
                )
                existing.message = str(message) if message else existing.message
                existing.raw_payload_id = raw_payload.id
                db.commit()
                stored += 1
                continue

            event = IncidentEvent(
                incident_id=incident.id,
                tenant_id=incident.tenant_id,
                platform=incident.platform,
                source_event_id=source_event_id,
                event_time=event_time,
                event_type_id=str(violation.get("policyId") or "not_available_in_summary"),
                event_type_name=str(
                    violation.get("policyName")
                    or violation.get("threatName")
                    or incident.event_type_name
                ),
                event_category=str(violation.get("category") or incident.event_category),
                event_origin="securonix_violation_detail",
                event_generator_ip="not_available_in_summary",
                event_generator_type="not_available_in_summary",
                source_data_type=str(violation.get("resourceGroup") or "not_available_in_summary"),
                src_ip=str(violation.get("sourceIp") or violation.get("src_ip") or "not_available_in_summary"),
                dest_ip=str(violation.get("destinationIp") or violation.get("dest_ip") or "not_available_in_summary"),
                src_host_name=str(violation.get("sourceHost") or "not_available_in_summary"),
                dst_host_name=str(violation.get("destinationHost") or "not_available_in_summary"),
                user_name=str(violation.get("accountName") or violation.get("user") or "not_available_in_summary"),
                message=str(message) if message else "message_not_available_in_summary",
                raw_message=str(message) if message else "message_not_available_in_summary",
                raw_payload_id=raw_payload.id,
            )

            db.add(event)
            db.commit()
            stored += 1

        return stored

    def _extract_entities_from_hydrated_payload(
        self,
        db: Session,
        incident: Incident,
        payload: dict[str, Any],
    ) -> None:
        from app.models.incident import IncidentEntity

        entities = extract_entities_from_payload(payload)

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

            record = IncidentEntity(
                incident_id=incident.id,
                tenant_id=incident.tenant_id,
                entity_type=entity["entity_type"],
                entity_value=entity["entity_value"],
                source_field=entity["source_field"],
                confidence=entity["confidence"],
            )

            db.add(record)
            db.commit()

    def _extract_list_from_payload(
        self,
        payload: dict[str, Any],
    ) -> list:
        for key in ["response", "data", "items", "violations", "violationItems", "result"]:
            value = payload.get(key)

            if isinstance(value, list):
                return value

            if isinstance(value, dict):
                nested = self._extract_list_from_payload(value)
                if nested:
                    return nested

        return []

    def _safe_float(self, value: Any) -> float | None:
        try:
            if value is None:
                return None
            return float(value)
        except Exception:
            return None


incident_hydration_service = IncidentHydrationService()
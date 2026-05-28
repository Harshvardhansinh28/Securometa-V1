from datetime import datetime
from typing import Any

from app.models.tenant import Tenant
from app.schemas.alert import NormalizedAlert
from app.services.fingerprint import build_alert_fingerprint


def normalize_seceon_alert(
    tenant: Tenant,
    raw_alert: dict[str, Any],
) -> NormalizedAlert:
    source_alert_id = str(raw_alert.get("alert_id") or "").strip()

    if not source_alert_id:
        raise ValueError("Seceon alert missing alert_id")

    raw_severity = str(raw_alert.get("severity") or "UNKNOWN").upper()

    severity_map = {
        "CRITICAL": "critical",
        "MAJOR": "high",
        "MINOR": "medium",
        "WARNING": "low",
        "INFO": "info",
    }

    priority_map = {
        "CRITICAL": "P1",
        "MAJOR": "P2",
        "MINOR": "P3",
        "WARNING": "P4",
        "INFO": "P5",
    }

    assigned_to = raw_alert.get("assigned_to")
    if isinstance(assigned_to, str) and not assigned_to.strip():
        assigned_to = None

    update_time = raw_alert.get("update_time")
    last_updated_at = None

    if isinstance(update_time, str) and update_time.strip():
        try:
            last_updated_at = datetime.fromisoformat(
                update_time.replace("Z", "+00:00")
            ).replace(tzinfo=None)
        except Exception:
            last_updated_at = None

    title = raw_alert.get("alert_type") or "Seceon Alert"
    description = raw_alert.get("message") or ""

    fingerprint = build_alert_fingerprint(
        tenant_key=tenant.tenant_key,
        platform="seceon",
        source_alert_id=source_alert_id,
    )

    return NormalizedAlert(
        tenant_id=tenant.id,
        tenant_key=tenant.tenant_key,
        tenant_name=tenant.tenant_name,
        platform="seceon",
        source_alert_id=source_alert_id,
        title=str(title)[:500],
        description=str(description),
        severity=severity_map.get(raw_severity, "unknown"),
        priority=priority_map.get(raw_severity, "P3"),
        status="open",
        assigned_to=assigned_to,
        entity_type=None,
        entity_value=None,
        source_url=None,
        event_time=last_updated_at,
        last_updated_at=last_updated_at,
        fingerprint=fingerprint,
        raw_payload=raw_alert,
    )
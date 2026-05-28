from datetime import datetime, timezone, timedelta
from typing import Any

from app.models.tenant import Tenant
from app.schemas.alert import NormalizedAlert
from app.services.fingerprint import build_alert_fingerprint


def epoch_ms_to_datetime_ist_naive(ms: Any) -> datetime | None:
    try:
        if not ms:
            return None

        dt = datetime.fromtimestamp(
            int(ms) / 1000,
            tz=timezone.utc,
        ) + timedelta(hours=5, minutes=30)

        return dt.replace(tzinfo=None)

    except Exception:
        return None


def extract_reason_fields(reason_list: Any) -> tuple[str, str]:
    policy = ""
    threat = ""

    for item in reason_list or []:
        text = ""

        if isinstance(item, str):
            text = item
        elif isinstance(item, dict):
            text = item.get("text") or item.get("reason") or ""

        if not isinstance(text, str):
            continue

        if text.startswith("Policy:"):
            policy = text.replace("Policy:", "").strip()
        elif text.startswith("Threat:"):
            threat = text.replace("Threat:", "").strip()

    if not policy:
        policy = threat

    return policy, threat


def normalize_securonix_incident(
    tenant: Tenant,
    raw_incident: dict[str, Any],
) -> NormalizedAlert:
    source_alert_id = str(raw_incident.get("incidentId") or "").strip()

    if not source_alert_id:
        raise ValueError("Securonix incident missing incidentId")

    policy, threat = extract_reason_fields(raw_incident.get("reason"))

    raw_priority = str(raw_incident.get("priority") or "").lower()

    severity_map = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "info",
    }

    priority_map = {
        "critical": "P1",
        "high": "P2",
        "medium": "P3",
        "low": "P4",
        "info": "P5",
    }

    violator_name = raw_incident.get("violatorText") or ""
    violator_id = raw_incident.get("violatorSubText") or ""

    if violator_id:
        violator = f"{violator_name} ({violator_id})"
    else:
        violator = violator_name

    last_updated_at = epoch_ms_to_datetime_ist_naive(
        raw_incident.get("lastUpdateDate")
    )

    title = policy or "Securonix Incident"
    description = threat or raw_incident.get("description") or ""

    fingerprint = build_alert_fingerprint(
        tenant_key=tenant.tenant_key,
        platform="securonix",
        source_alert_id=source_alert_id,
    )

    return NormalizedAlert(
        tenant_id=tenant.id,
        tenant_key=tenant.tenant_key,
        tenant_name=tenant.tenant_name,
        platform="securonix",
        source_alert_id=source_alert_id,
        title=str(title)[:500],
        description=str(description),
        severity=severity_map.get(raw_priority, "unknown"),
        priority=priority_map.get(raw_priority, "P3"),
        status="open",
        assigned_to=None,
        entity_type="violator" if violator else None,
        entity_value=violator or None,
        source_url=raw_incident.get("url"),
        event_time=last_updated_at,
        last_updated_at=last_updated_at,
        fingerprint=fingerprint,
        raw_payload=raw_incident,
    )
import re
from datetime import datetime
from typing import Any


IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


FIELD_ALIASES = {
    "event_id": [
        "event_id",
        "eventId",
        "event_uuid",
        "eventUUID",
        "id",
    ],
    "event_timestamp": [
        "event_timestamp",
        "eventTimestamp",
        "timestamp",
        "event_time",
        "eventTime",
        "create_time",
        "created_time",
        "update_time",
        "lastUpdateDate",
    ],
    "event_type_id": [
        "event_type_id",
        "eventTypeId",
        "event_type",
        "eventType",
    ],
    "event_type_name": [
        "event_type_name",
        "eventTypeName",
        "alert_type",
        "alertType",
        "policy_name",
        "policyName",
        "threat_name",
        "threatName",
        "title",
    ],
    "event_category": [
        "event_category",
        "eventCategory",
        "category",
        "alert_category",
        "alertCategory",
        "threat_category",
        "threatCategory",
        "event_origin",
        "eventOrigin",
    ],
    "event_origin": [
        "event_origin",
        "eventOrigin",
        "origin",
        "source",
        "event_source",
        "eventSource",
    ],
    "event_generator_ip": [
        "event_generator_ip",
        "eventGeneratorIp",
        "generator_ip",
        "device_ip",
        "deviceIp",
        "sensor_ip",
        "sensorIp",
    ],
    "event_generator_type": [
        "event_generator_type",
        "eventGeneratorType",
        "generator_type",
        "device_type",
        "deviceType",
    ],
    "source_data_type": [
        "source_data_type",
        "sourceDataType",
        "data_source",
        "dataSource",
        "source_type",
        "sourceType",
    ],
    "src_ip": [
        "src_ip",
        "srcIp",
        "source_ip",
        "sourceIp",
        "sourceAddress",
        "source_address",
        "src",
        "source",
    ],
    "dest_ip": [
        "dest_ip",
        "dst_ip",
        "destIp",
        "dstIp",
        "destination_ip",
        "destinationIp",
        "destinationAddress",
        "destination_address",
        "dst",
        "destination",
    ],
    "src_host_name": [
        "src_host_name",
        "srcHostName",
        "source_host",
        "sourceHost",
        "source_hostname",
        "sourceHostname",
    ],
    "dst_host_name": [
        "dst_host_name",
        "dstHostName",
        "destination_host",
        "destinationHost",
        "destination_hostname",
        "destinationHostname",
    ],
    "user_name": [
        "user_name",
        "username",
        "user",
        "account_name",
        "accountName",
        "src_user",
        "sourceUser",
    ],
    "message": [
        "message",
        "description",
        "raw_message",
        "rawMessage",
        "event_message",
        "eventMessage",
        "msg",
    ],
    "risk_score": [
        "risk_score",
        "riskScore",
        "threat_score",
        "threatScore",
        "score",
    ],
}


def deep_get(payload: dict[str, Any], key: str) -> Any:
    if key in payload:
        return payload.get(key)

    for payload_key, payload_value in payload.items():
        if str(payload_key).lower() == key.lower():
            return payload_value

    return None


def get_first_available(payload: dict[str, Any], logical_field: str) -> Any:
    aliases = FIELD_ALIASES.get(logical_field, [])

    for alias in aliases:
        value = deep_get(payload, alias)

        if value is not None and str(value).strip() != "":
            return value

    return None


def value_or_default(value: Any, default: str = "not_available_in_summary") -> str:
    if value is None:
        return default

    text = str(value).strip()

    if not text or text.lower() in {"none", "null", "nan"}:
        return default

    return text


def extract_ips_from_text(text: Any) -> list[str]:
    if text is None:
        return []

    return IP_REGEX.findall(str(text))


def infer_src_dest_from_message(message: Any) -> tuple[str | None, str | None]:
    ips = extract_ips_from_text(message)

    if not ips:
        return None, None

    if len(ips) == 1:
        return ips[0], None

    return ips[0], ips[1]


def severity_to_risk_score(severity: str | None, priority: str | None = None) -> float:
    sev = (severity or "").lower()
    pri = (priority or "").upper()

    if sev == "critical" or pri == "P1":
        return 90.0

    if sev == "high" or pri == "P2":
        return 75.0

    if sev == "medium" or pri == "P3":
        return 50.0

    if sev == "low" or pri == "P4":
        return 25.0

    return 10.0


def infer_workflow_status(alert_status: str | None, assigned_to: str | None) -> str:
    status = (alert_status or "").lower()

    if status in {"closed", "resolved"}:
        return "closed"

    if assigned_to:
        return "assigned"

    if status in {"open", "new"}:
        return "open_unassigned"

    return "open"
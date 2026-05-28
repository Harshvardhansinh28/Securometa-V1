import hashlib
import json


def stable_json_hash(payload: dict) -> str:
    serialized = json.dumps(
        payload,
        sort_keys=True,
        default=str,
        separators=(",", ":"),
    )

    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def build_alert_fingerprint(
    tenant_key: str,
    platform: str,
    source_alert_id: str,
) -> str:
    raw = f"{tenant_key}|{platform}|{source_alert_id}"

    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
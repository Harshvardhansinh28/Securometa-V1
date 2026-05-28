import json
import re
from typing import Any


IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_REGEX = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
EMAIL_REGEX = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
HASH_REGEX = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")
DOMAIN_REGEX = re.compile(
    r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|in|ae|io|co|edu|gov|mil|info|biz)\b",
    re.IGNORECASE,
)


STRUCTURED_FIELD_MAP = {
    "src_ip": "source_ip",
    "source_ip": "source_ip",
    "sourceAddress": "source_ip",
    "source_address": "source_ip",
    "dest_ip": "destination_ip",
    "dst_ip": "destination_ip",
    "destination_ip": "destination_ip",
    "destinationAddress": "destination_ip",
    "user": "user",
    "username": "user",
    "user_name": "user",
    "account_name": "user",
    "src_host_name": "source_host",
    "source_host": "source_host",
    "dst_host_name": "destination_host",
    "destination_host": "destination_host",
    "domain": "domain",
    "url": "url",
    "request_url": "url",
    "hash": "hash",
    "file_hash": "hash",
}


def flatten_dict(data: dict[str, Any], parent_key: str = "") -> dict[str, Any]:
    items = {}

    for key, value in data.items():
        new_key = f"{parent_key}.{key}" if parent_key else str(key)

        if isinstance(value, dict):
            items.update(flatten_dict(value, new_key))
        else:
            items[new_key] = value

    return items


def add_entity(
    entities: set[tuple[str, str, str]],
    entity_type: str,
    entity_value: Any,
    source_field: str,
) -> None:
    if entity_value is None:
        return

    value = str(entity_value).strip()

    if not value:
        return

    if len(value) > 500:
        return

    entities.add((entity_type, value, source_field))


def extract_entities_from_payload(payload: dict[str, Any]) -> list[dict[str, Any]]:
    entities: set[tuple[str, str, str]] = set()

    flattened = flatten_dict(payload)

    for field_name, value in flattened.items():
        short_field = field_name.split(".")[-1]

        if short_field in STRUCTURED_FIELD_MAP:
            add_entity(
                entities=entities,
                entity_type=STRUCTURED_FIELD_MAP[short_field],
                entity_value=value,
                source_field=field_name,
            )

    serialized = json.dumps(payload, default=str)

    for ip in IP_REGEX.findall(serialized):
        add_entity(entities, "ip", ip, "regex_payload")

    for url in URL_REGEX.findall(serialized):
        add_entity(entities, "url", url, "regex_payload")

    for email in EMAIL_REGEX.findall(serialized):
        add_entity(entities, "email", email, "regex_payload")

    for hash_value in HASH_REGEX.findall(serialized):
        add_entity(entities, "hash", hash_value, "regex_payload")

    for domain in DOMAIN_REGEX.findall(serialized):
        if not domain.lower().startswith("http"):
            add_entity(entities, "domain", domain, "regex_payload")

    return [
        {
            "entity_type": entity_type,
            "entity_value": entity_value,
            "source_field": source_field,
            "confidence": 0.9 if source_field != "regex_payload" else 0.7,
        }
        for entity_type, entity_value, source_field in sorted(entities)
    ]
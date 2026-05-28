from typing import Any


SENSITIVE_KEYS = {
    "token",
    "authorization",
    "cookie",
    "password",
    "secret",
    "apikey",
    "api_key",
    "access_token",
    "refresh_token",
}


def mask_sensitive_value(value: Any) -> Any:
    if value is None:
        return None

    if not isinstance(value, str):
        return "***"

    if len(value) <= 6:
        return "***"

    return f"{value[:3]}***{value[-3:]}"


def sanitize_dict(data: dict) -> dict:
    sanitized = {}

    for key, value in data.items():
        normalized_key = str(key).lower()

        if normalized_key in SENSITIVE_KEYS:
            sanitized[key] = mask_sensitive_value(value)
        elif isinstance(value, dict):
            sanitized[key] = sanitize_dict(value)
        else:
            sanitized[key] = value

    return sanitized
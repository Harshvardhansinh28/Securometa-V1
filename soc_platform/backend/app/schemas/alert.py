from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class NormalizedAlert(BaseModel):
    tenant_id: int
    tenant_key: str
    tenant_name: str

    platform: str
    source_alert_id: str

    title: str = Field(min_length=1, max_length=500)
    description: str | None = None

    severity: str = "unknown"
    priority: str = "P3"
    status: str = "open"

    assigned_to: str | None = None

    entity_type: str | None = None
    entity_value: str | None = None

    source_url: str | None = None

    event_time: datetime | None = None
    last_updated_at: datetime | None = None

    fingerprint: str

    raw_payload: dict[str, Any]


class AlertResponse(BaseModel):
    id: int
    tenant_id: int
    platform: str
    source_alert_id: str
    title: str
    description: str | None
    severity: str
    priority: str
    status: str
    assigned_to: str | None
    entity_type: str | None
    entity_value: str | None
    source_url: str | None
    event_time: datetime | None
    last_updated_at: datetime | None
    ingested_at: datetime

    class Config:
        from_attributes = True
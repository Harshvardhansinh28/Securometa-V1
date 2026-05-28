from datetime import datetime
from pydantic import BaseModel


class IncidentResponse(BaseModel):
    id: int
    tenant_id: int
    platform: str

    source_incident_id: str
    source_alert_id: str | None

    alert_id: int | None
    case_id: int | None

    title: str
    description: str | None

    severity: str
    priority: str
    status: str

    category: str | None
    sub_category: str | None
    incident_type: str | None

    event_type_name: str | None
    event_category: str | None
    event_origin: str | None

    risk_score: float | None
    confidence_score: float | None

    assigned_to: str | None
    workflow_status: str | None

    first_seen_at: datetime | None
    last_seen_at: datetime | None

    hydration_status: str
    hydrated_at: datetime | None

    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class IncidentEventResponse(BaseModel):
    id: int
    incident_id: int
    tenant_id: int
    platform: str

    source_event_id: str
    event_time: datetime | None

    event_type_id: str | None
    event_type_name: str | None

    event_category: str | None
    event_origin: str | None

    event_generator_ip: str | None
    event_generator_type: str | None

    source_data_type: str | None

    src_ip: str | None
    dest_ip: str | None

    src_host_name: str | None
    dst_host_name: str | None

    user_name: str | None

    message: str | None
    raw_message: str | None

    created_at: datetime

    class Config:
        from_attributes = True


class IncidentEntityResponse(BaseModel):
    id: int
    incident_id: int
    tenant_id: int
    entity_type: str
    entity_value: str
    source_field: str | None
    confidence: float | None
    created_at: datetime

    class Config:
        from_attributes = True


class ThreatIndicatorResponse(BaseModel):
    id: int
    incident_id: int | None
    incident_event_id: int | None
    tenant_id: int

    indicator_type: str
    indicator_value: str

    source: str | None
    category: str | None
    reputation: str | None
    confidence: float | None

    created_at: datetime

    class Config:
        from_attributes = True
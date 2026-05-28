from sqlalchemy import DateTime, Float, ForeignKey, Index, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Incident(Base):
    __tablename__ = "incidents"

    __table_args__ = (
        UniqueConstraint(
            "platform",
            "source_incident_id",
            name="uq_incident_platform_source",
        ),
        Index("idx_incident_tenant_status", "tenant_id", "status"),
        Index("idx_incident_platform", "platform"),
        Index("idx_incident_severity", "severity"),
        Index("idx_incident_priority", "priority"),
        Index("idx_incident_hydration", "hydration_status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), nullable=False)

    platform: Mapped[str] = mapped_column(String(50), nullable=False)

    source_incident_id: Mapped[str] = mapped_column(String(255), nullable=False)
    source_alert_id: Mapped[str | None] = mapped_column(String(255), nullable=True)

    alert_id: Mapped[int | None] = mapped_column(ForeignKey("alerts.id"), nullable=True)
    case_id: Mapped[int | None] = mapped_column(ForeignKey("cases.id"), nullable=True)

    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    severity: Mapped[str] = mapped_column(String(50), nullable=False, default="unknown")
    priority: Mapped[str] = mapped_column(String(20), nullable=False, default="P3")
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="open")

    category: Mapped[str | None] = mapped_column(String(255), nullable=True)
    sub_category: Mapped[str | None] = mapped_column(String(255), nullable=True)
    incident_type: Mapped[str | None] = mapped_column(String(255), nullable=True)

    event_type_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    event_category: Mapped[str | None] = mapped_column(String(255), nullable=True)
    event_origin: Mapped[str | None] = mapped_column(String(255), nullable=True)

    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    confidence_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    assigned_to: Mapped[str | None] = mapped_column(String(255), nullable=True)
    workflow_status: Mapped[str | None] = mapped_column(String(255), nullable=True)

    first_seen_at: Mapped[DateTime | None] = mapped_column(DateTime, nullable=True)
    last_seen_at: Mapped[DateTime | None] = mapped_column(DateTime, nullable=True)

    source_created_at: Mapped[DateTime | None] = mapped_column(DateTime, nullable=True)
    source_updated_at: Mapped[DateTime | None] = mapped_column(DateTime, nullable=True)

    hydration_status: Mapped[str] = mapped_column(String(50), nullable=False, default="pending")
    hydrated_at: Mapped[DateTime | None] = mapped_column(DateTime, nullable=True)

    raw_payload_id: Mapped[int | None] = mapped_column(ForeignKey("raw_payloads.id"), nullable=True)

    created_at: Mapped[DateTime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[DateTime] = mapped_column(
        DateTime,
        server_default=func.now(),
        onupdate=func.now(),
    )


class IncidentEvent(Base):
    __tablename__ = "incident_events"

    __table_args__ = (
        UniqueConstraint(
            "platform",
            "source_event_id",
            name="uq_incident_event_platform_source",
        ),
        Index("idx_incident_event_incident", "incident_id"),
        Index("idx_incident_event_tenant_time", "tenant_id", "event_time"),
        Index("idx_incident_event_src_ip", "src_ip"),
        Index("idx_incident_event_dest_ip", "dest_ip"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), nullable=False)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), nullable=False)

    platform: Mapped[str] = mapped_column(String(50), nullable=False)

    source_event_id: Mapped[str] = mapped_column(String(255), nullable=False)

    event_time: Mapped[DateTime | None] = mapped_column(DateTime, nullable=True)

    event_type_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    event_type_name: Mapped[str | None] = mapped_column(String(255), nullable=True)

    event_category: Mapped[str | None] = mapped_column(String(255), nullable=True)
    event_origin: Mapped[str | None] = mapped_column(String(255), nullable=True)

    event_generator_ip: Mapped[str | None] = mapped_column(String(100), nullable=True)
    event_generator_type: Mapped[str | None] = mapped_column(String(100), nullable=True)

    source_data_type: Mapped[str | None] = mapped_column(String(255), nullable=True)

    src_ip: Mapped[str | None] = mapped_column(String(100), nullable=True)
    dest_ip: Mapped[str | None] = mapped_column(String(100), nullable=True)

    src_host_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    dst_host_name: Mapped[str | None] = mapped_column(String(255), nullable=True)

    user_name: Mapped[str | None] = mapped_column(String(255), nullable=True)

    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    raw_payload_id: Mapped[int | None] = mapped_column(ForeignKey("raw_payloads.id"), nullable=True)

    created_at: Mapped[DateTime] = mapped_column(DateTime, server_default=func.now())


class IncidentEntity(Base):
    __tablename__ = "incident_entities"

    __table_args__ = (
        UniqueConstraint(
            "incident_id",
            "entity_type",
            "entity_value",
            name="uq_incident_entity",
        ),
        Index("idx_incident_entity_value", "entity_type", "entity_value"),
        Index("idx_incident_entity_tenant", "tenant_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), nullable=False)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), nullable=False)

    entity_type: Mapped[str] = mapped_column(String(100), nullable=False)
    entity_value: Mapped[str] = mapped_column(String(500), nullable=False)

    source_field: Mapped[str | None] = mapped_column(String(255), nullable=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)

    created_at: Mapped[DateTime] = mapped_column(DateTime, server_default=func.now())


class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"

    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "indicator_type",
            "indicator_value_hash",
            "source",
            name="uq_threat_indicator",
        ),
        Index("idx_threat_indicator_value_hash", "indicator_type", "indicator_value_hash"),
        Index("idx_threat_indicator_incident", "incident_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id"), nullable=True)
    incident_event_id: Mapped[int | None] = mapped_column(ForeignKey("incident_events.id"), nullable=True)

    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), nullable=False)

    indicator_type: Mapped[str] = mapped_column(String(100), nullable=False)
    indicator_value: Mapped[str] = mapped_column(String(500), nullable=False)

    # Hash is used for uniqueness/indexing because indicator_value can be long.
    indicator_value_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    source: Mapped[str | None] = mapped_column(String(100), nullable=True)
    category: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reputation: Mapped[str | None] = mapped_column(String(255), nullable=True)

    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)

    raw_payload_id: Mapped[int | None] = mapped_column(ForeignKey("raw_payloads.id"), nullable=True)

    created_at: Mapped[DateTime] = mapped_column(DateTime, server_default=func.now())
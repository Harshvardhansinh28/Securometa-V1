from sqlalchemy import DateTime, ForeignKey, Index, JSON, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class RawAlert(Base):
    __tablename__ = "raw_alerts"

    __table_args__ = (
        UniqueConstraint(
            "platform",
            "source_alert_id",
            "payload_hash",
            name="uq_raw_alert_payload",
        ),
        Index("idx_raw_tenant_platform", "tenant_id", "platform"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    platform: Mapped[str] = mapped_column(String(50), nullable=False)

    source_alert_id: Mapped[str] = mapped_column(String(255), nullable=False)
    raw_payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    received_at: Mapped[DateTime] = mapped_column(DateTime, server_default=func.now())


class Alert(Base):
    __tablename__ = "alerts"

    __table_args__ = (
        UniqueConstraint("platform", "source_alert_id", name="uq_alert_source"),
        Index("idx_alert_tenant_status", "tenant_id", "status"),
        Index("idx_alert_severity", "severity"),
        Index("idx_alert_priority", "priority"),
        Index("idx_alert_fingerprint", "fingerprint"),
        Index("idx_alert_case", "case_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    platform: Mapped[str] = mapped_column(String(50), nullable=False)

    source_alert_id: Mapped[str] = mapped_column(String(255), nullable=False)

    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    severity: Mapped[str] = mapped_column(String(50), nullable=False, default="unknown")
    priority: Mapped[str] = mapped_column(String(20), nullable=False, default="P3")
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="open")

    assigned_to: Mapped[str | None] = mapped_column(String(255), nullable=True)

    entity_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    entity_value: Mapped[str | None] = mapped_column(String(500), nullable=True)

    source_url: Mapped[str | None] = mapped_column(Text, nullable=True)

    event_time: Mapped[DateTime | None] = mapped_column(DateTime, nullable=True)
    last_updated_at: Mapped[DateTime | None] = mapped_column(DateTime, nullable=True)
    ingested_at: Mapped[DateTime] = mapped_column(DateTime, server_default=func.now())

    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)

    raw_alert_id: Mapped[int | None] = mapped_column(ForeignKey("raw_alerts.id"), nullable=True)
    case_id: Mapped[int | None] = mapped_column(ForeignKey("cases.id"), nullable=True)
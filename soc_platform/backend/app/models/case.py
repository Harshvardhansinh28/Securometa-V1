from sqlalchemy import DateTime, ForeignKey, Index, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Case(Base):
    __tablename__ = "cases"

    __table_args__ = (
        Index("idx_case_tenant_status", "tenant_id", "status"),
        Index("idx_case_priority", "priority"),
        Index("idx_case_sla", "ack_due_at", "escalation_due_at", "resolution_due_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    case_number: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)

    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), nullable=False)

    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    severity: Mapped[str] = mapped_column(String(50), nullable=False)
    priority: Mapped[str] = mapped_column(String(20), nullable=False)

    status: Mapped[str] = mapped_column(String(50), nullable=False, default="new")

    owner_user_id: Mapped[int | None] = mapped_column(nullable=True)
    assigned_team: Mapped[str | None] = mapped_column(String(100), nullable=True)

    source_platform_summary: Mapped[str | None] = mapped_column(String(255), nullable=True)

    first_alert_time: Mapped[DateTime | None] = mapped_column(DateTime, nullable=True)
    last_activity_time: Mapped[DateTime | None] = mapped_column(DateTime, nullable=True)

    ack_due_at: Mapped[DateTime | None] = mapped_column(DateTime, nullable=True)
    escalation_due_at: Mapped[DateTime | None] = mapped_column(DateTime, nullable=True)
    resolution_due_at: Mapped[DateTime | None] = mapped_column(DateTime, nullable=True)

    acknowledged_at: Mapped[DateTime | None] = mapped_column(DateTime, nullable=True)
    escalated_at: Mapped[DateTime | None] = mapped_column(DateTime, nullable=True)
    contained_at: Mapped[DateTime | None] = mapped_column(DateTime, nullable=True)
    resolved_at: Mapped[DateTime | None] = mapped_column(DateTime, nullable=True)
    closed_at: Mapped[DateTime | None] = mapped_column(DateTime, nullable=True)

    closure_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    closure_summary: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[DateTime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[DateTime] = mapped_column(
        DateTime,
        server_default=func.now(),
        onupdate=func.now(),
    )


class CaseAlert(Base):
    __tablename__ = "case_alerts"

    __table_args__ = (
        UniqueConstraint("case_id", "alert_id", name="uq_case_alert"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"), nullable=False)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id"), nullable=False)

    linked_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    linked_at: Mapped[DateTime] = mapped_column(DateTime, server_default=func.now())


class CaseTimeline(Base):
    __tablename__ = "case_timeline"

    __table_args__ = (
        Index("idx_timeline_case_time", "case_id", "created_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"), nullable=False)

    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    event_title: Mapped[str] = mapped_column(String(500), nullable=False)
    event_description: Mapped[str | None] = mapped_column(Text, nullable=True)

    actor_type: Mapped[str] = mapped_column(String(50), nullable=False, default="system")
    actor_id: Mapped[int | None] = mapped_column(nullable=True)

    created_at: Mapped[DateTime] = mapped_column(DateTime, server_default=func.now())


class CaseNote(Base):
    __tablename__ = "case_notes"

    __table_args__ = (
        Index("idx_case_notes_case_time", "case_id", "created_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"), nullable=False)

    note_type: Mapped[str] = mapped_column(String(50), nullable=False, default="internal")
    note_text: Mapped[str] = mapped_column(Text, nullable=False)

    created_by: Mapped[int | None] = mapped_column(nullable=True)
    created_at: Mapped[DateTime] = mapped_column(DateTime, server_default=func.now())
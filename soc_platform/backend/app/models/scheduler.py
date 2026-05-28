from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class PollingConfig(Base):
    __tablename__ = "polling_config"

    __table_args__ = (
        UniqueConstraint("tenant_id", "platform", name="uq_polling_config_tenant_platform"),
        Index("idx_polling_config_enabled", "is_enabled", "platform"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    platform: Mapped[str] = mapped_column(String(50), nullable=False)

    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    poll_interval_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=300)
    max_records_per_cycle: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    lookback_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=720)

    hydration_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=100)

    created_at: Mapped[DateTime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[DateTime] = mapped_column(
        DateTime,
        server_default=func.now(),
        onupdate=func.now(),
    )


class PollingState(Base):
    __tablename__ = "polling_state"

    __table_args__ = (
        UniqueConstraint("tenant_id", "platform", name="uq_polling_state_tenant_platform"),
        Index("idx_polling_state_next_run", "next_run_at"),
        Index("idx_polling_state_status", "status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    platform: Mapped[str] = mapped_column(String(50), nullable=False)

    last_run_at: Mapped[DateTime | None] = mapped_column(DateTime, nullable=True)
    next_run_at: Mapped[DateTime | None] = mapped_column(DateTime, nullable=True)

    last_success_at: Mapped[DateTime | None] = mapped_column(DateTime, nullable=True)
    last_failure_at: Mapped[DateTime | None] = mapped_column(DateTime, nullable=True)

    last_seen_source_time: Mapped[DateTime | None] = mapped_column(DateTime, nullable=True)
    last_seen_source_id: Mapped[str | None] = mapped_column(String(255), nullable=True)

    status: Mapped[str] = mapped_column(String(50), nullable=False, default="due")
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    updated_at: Mapped[DateTime] = mapped_column(
        DateTime,
        server_default=func.now(),
        onupdate=func.now(),
    )


class SyncRun(Base):
    __tablename__ = "sync_runs"

    __table_args__ = (
        Index("idx_sync_runs_tenant_platform", "tenant_id", "platform"),
        Index("idx_sync_runs_started", "started_at"),
        Index("idx_sync_runs_status", "status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    tenant_id: Mapped[int | None] = mapped_column(ForeignKey("tenants.id"), nullable=True)
    platform: Mapped[str] = mapped_column(String(50), nullable=False)

    run_type: Mapped[str] = mapped_column(String(50), nullable=False, default="summary")

    started_at: Mapped[DateTime] = mapped_column(DateTime, nullable=False)
    finished_at: Mapped[DateTime | None] = mapped_column(DateTime, nullable=True)

    status: Mapped[str] = mapped_column(String(50), nullable=False, default="running")

    records_fetched: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    records_inserted: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    records_updated: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    records_skipped: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)


class HydrationQueue(Base):
    __tablename__ = "hydration_queue"

    __table_args__ = (
        UniqueConstraint("incident_id", name="uq_hydration_queue_incident"),
        Index("idx_hydration_queue_status_next", "status", "next_attempt_at"),
        Index("idx_hydration_queue_platform", "platform"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), nullable=False)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), nullable=False)

    platform: Mapped[str] = mapped_column(String(50), nullable=False)

    status: Mapped[str] = mapped_column(String(50), nullable=False, default="queued")
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=100)

    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    next_attempt_at: Mapped[DateTime | None] = mapped_column(DateTime, nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[DateTime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[DateTime] = mapped_column(
        DateTime,
        server_default=func.now(),
        onupdate=func.now(),
    )
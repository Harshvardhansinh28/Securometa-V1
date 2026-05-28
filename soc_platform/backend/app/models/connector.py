from sqlalchemy import DateTime, ForeignKey, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class ConnectorSyncState(Base):
    __tablename__ = "connector_sync_state"

    __table_args__ = (
        UniqueConstraint("tenant_id", "platform", name="uq_sync_tenant_platform"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    platform: Mapped[str] = mapped_column(String(50), nullable=False)

    last_success_at: Mapped[DateTime | None] = mapped_column(DateTime, nullable=True)
    last_failure_at: Mapped[DateTime | None] = mapped_column(DateTime, nullable=True)
    last_cursor: Mapped[str | None] = mapped_column(String(500), nullable=True)

    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    sync_status: Mapped[str] = mapped_column(String(50), nullable=False, default="healthy")

    updated_at: Mapped[DateTime] = mapped_column(
        DateTime,
        server_default=func.now(),
        onupdate=func.now(),
    )
from sqlalchemy import DateTime, ForeignKey, Index, JSON, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class RawPayload(Base):
    __tablename__ = "raw_payloads"

    __table_args__ = (
        UniqueConstraint(
            "platform",
            "object_type",
            "source_object_id",
            "payload_hash",
            name="uq_raw_payload_object_hash",
        ),
        Index("idx_raw_payload_tenant_platform", "tenant_id", "platform"),
        Index("idx_raw_payload_object", "object_type", "source_object_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), nullable=False)

    platform: Mapped[str] = mapped_column(String(50), nullable=False)

    object_type: Mapped[str] = mapped_column(String(100), nullable=False)
    source_object_id: Mapped[str] = mapped_column(String(255), nullable=False)

    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    raw_json: Mapped[dict] = mapped_column(JSON, nullable=False)

    received_at: Mapped[DateTime] = mapped_column(DateTime, server_default=func.now())
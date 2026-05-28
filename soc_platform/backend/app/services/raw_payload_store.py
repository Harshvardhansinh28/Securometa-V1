from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.raw_payload import RawPayload
from app.services.fingerprint import stable_json_hash


class RawPayloadStore:
    def store(
        self,
        db: Session,
        tenant_id: int,
        platform: str,
        object_type: str,
        source_object_id: str,
        raw_json: dict,
    ) -> RawPayload:
        payload_hash = stable_json_hash(raw_json)

        existing = (
            db.query(RawPayload)
            .filter(
                RawPayload.platform == platform,
                RawPayload.object_type == object_type,
                RawPayload.source_object_id == source_object_id,
                RawPayload.payload_hash == payload_hash,
            )
            .first()
        )

        if existing:
            return existing

        raw_payload = RawPayload(
            tenant_id=tenant_id,
            platform=platform,
            object_type=object_type,
            source_object_id=source_object_id,
            payload_hash=payload_hash,
            raw_json=raw_json,
        )

        db.add(raw_payload)

        try:
            db.commit()
            db.refresh(raw_payload)
            return raw_payload

        except IntegrityError:
            db.rollback()

            existing = (
                db.query(RawPayload)
                .filter(
                    RawPayload.platform == platform,
                    RawPayload.object_type == object_type,
                    RawPayload.source_object_id == source_object_id,
                    RawPayload.payload_hash == payload_hash,
                )
                .first()
            )

            if existing:
                return existing

            raise


raw_payload_store = RawPayloadStore()
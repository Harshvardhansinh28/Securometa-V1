from datetime import datetime, timedelta

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.incident import Incident
from app.models.scheduler import HydrationQueue
from app.services.incident_hydration import incident_hydration_service

logger = get_logger(__name__)


class HydrationQueueService:
    def enqueue_incident(
        self,
        db: Session,
        incident: Incident,
        priority: int = 100,
    ) -> HydrationQueue:
        existing = (
            db.query(HydrationQueue)
            .filter(HydrationQueue.incident_id == incident.id)
            .first()
        )

        if existing:
            if existing.status in {"hydrated", "partial", "failed"}:
                existing.status = "queued"
                existing.next_attempt_at = datetime.utcnow()
                existing.priority = priority
                existing.last_error = None

            db.commit()
            db.refresh(existing)
            return existing

        job = HydrationQueue(
            incident_id=incident.id,
            tenant_id=incident.tenant_id,
            platform=incident.platform,
            status="queued",
            priority=priority,
            attempt_count=0,
            next_attempt_at=datetime.utcnow(),
        )

        db.add(job)

        try:
            db.commit()
            db.refresh(job)
            return job

        except IntegrityError:
            db.rollback()

            existing = (
                db.query(HydrationQueue)
                .filter(HydrationQueue.incident_id == incident.id)
                .first()
            )

            if existing:
                return existing

            raise

    def process_due_jobs(
        self,
        db: Session,
        limit: int = 20,
    ) -> dict:
        now = datetime.utcnow()

        jobs = (
            db.query(HydrationQueue)
            .filter(
                HydrationQueue.status.in_(["queued", "retry_wait"]),
                HydrationQueue.next_attempt_at <= now,
            )
            .order_by(
                HydrationQueue.priority.asc(),
                HydrationQueue.created_at.asc(),
            )
            .limit(limit)
            .all()
        )

        processed = 0
        hydrated = 0
        partial = 0
        failed = 0
        details = []

        for job in jobs:
            processed += 1

            try:
                job.status = "hydrating"
                job.attempt_count += 1
                db.commit()

                result = incident_hydration_service.hydrate_incident_by_id(
                    db=db,
                    incident_id=job.incident_id,
                )

                result_status = result.get("status")

                if result_status == "hydrated":
                    job.status = "hydrated"
                    job.last_error = None
                    hydrated += 1

                elif result_status == "partial":
                    job.status = "partial"
                    job.last_error = result.get("reason")
                    partial += 1

                else:
                    self._mark_retry_or_failed(
                        job=job,
                        error=result.get("reason") or str(result),
                    )
                    failed += 1

                db.commit()

                details.append(
                    {
                        "job_id": job.id,
                        "incident_id": job.incident_id,
                        "platform": job.platform,
                        "status": job.status,
                        "result": result,
                    }
                )

            except Exception as exc:
                db.rollback()

                try:
                    job = (
                        db.query(HydrationQueue)
                        .filter(HydrationQueue.id == job.id)
                        .first()
                    )

                    if job:
                        self._mark_retry_or_failed(
                            job=job,
                            error=str(exc),
                        )
                        db.commit()

                except Exception:
                    db.rollback()

                failed += 1

                details.append(
                    {
                        "job_id": job.id if job else None,
                        "incident_id": job.incident_id if job else None,
                        "platform": job.platform if job else None,
                        "status": "failed",
                        "error": str(exc),
                    }
                )

                logger.exception(
                    "Hydration queue job failed incident_id=%s error=%s",
                    job.incident_id if job else None,
                    exc,
                )

        return {
            "processed": processed,
            "hydrated": hydrated,
            "partial": partial,
            "failed": failed,
            "details": details,
        }

    def _mark_retry_or_failed(
        self,
        job: HydrationQueue,
        error: str,
    ) -> None:
        job.last_error = error[:5000]

        if job.attempt_count >= 3:
            job.status = "failed"
            job.next_attempt_at = None
            return

        job.status = "retry_wait"
        job.next_attempt_at = datetime.utcnow() + timedelta(minutes=5 * job.attempt_count)


hydration_queue_service = HydrationQueueService()
from datetime import datetime, timedelta

from sqlalchemy.orm import Session, joinedload

from app.connectors.seceon import SeceonConnector
from app.connectors.securonix import SecuronixConnector
from app.core.config import get_settings
from app.core.logging import get_logger
from app.models.alert import Alert
from app.models.incident import Incident
from app.models.scheduler import PollingConfig, PollingState, SyncRun
from app.models.tenant import Tenant, TenantPlatformAccount
from app.normalizers.seceon import normalize_seceon_alert
from app.normalizers.securonix import normalize_securonix_incident
from app.services.alert_ingestion import alert_ingestion_service
from app.services.hydration_queue import hydration_queue_service

logger = get_logger(__name__)
settings = get_settings()


class SchedulerService:
    def run_due_summary_syncs(
        self,
        db: Session,
    ) -> dict:
        due_configs = self._get_due_configs(db)

        results = []

        for config in due_configs:
            result = self._run_one_config(
                db=db,
                config=config,
            )
            results.append(result)

        return {
            "due_configs": len(due_configs),
            "results": results,
        }

    def _get_due_configs(
        self,
        db: Session,
    ) -> list[PollingConfig]:
        now = datetime.utcnow()

        configs = (
            db.query(PollingConfig)
            .filter(PollingConfig.is_enabled.is_(True))
            .order_by(PollingConfig.priority.asc(), PollingConfig.id.asc())
            .limit(settings.scheduler_max_due_configs_per_tick)
            .all()
        )

        due = []

        for config in configs:
            state = self._get_or_create_state(
                db=db,
                tenant_id=config.tenant_id,
                platform=config.platform,
                poll_interval_seconds=config.poll_interval_seconds,
            )

            if state.next_run_at is None or state.next_run_at <= now:
                due.append(config)

        return due

    def _run_one_config(
        self,
        db: Session,
        config: PollingConfig,
    ) -> dict:
        started_at = datetime.utcnow()

        sync_run = SyncRun(
            tenant_id=config.tenant_id,
            platform=config.platform,
            run_type="summary",
            started_at=started_at,
            status="running",
        )

        db.add(sync_run)
        db.commit()
        db.refresh(sync_run)

        state = self._get_or_create_state(
            db=db,
            tenant_id=config.tenant_id,
            platform=config.platform,
            poll_interval_seconds=config.poll_interval_seconds,
        )

        try:
            account = (
                db.query(TenantPlatformAccount)
                .options(joinedload(TenantPlatformAccount.tenant))
                .filter(
                    TenantPlatformAccount.tenant_id == config.tenant_id,
                    TenantPlatformAccount.platform == config.platform,
                    TenantPlatformAccount.is_enabled.is_(True),
                )
                .first()
            )

            if not account:
                raise RuntimeError(
                    f"No enabled tenant_platform_account for tenant_id={config.tenant_id} platform={config.platform}"
                )

            tenant = account.tenant

            connector, normalizer = self._get_connector_and_normalizer(config.platform)

            raw_records = connector.fetch_alerts_for_tenant(
                tenant=tenant,
                platform_account=account,
                max_alerts_per_tenant=config.max_records_per_cycle,
            )

            fetched = len(raw_records)
            inserted_or_updated = 0
            skipped = 0
            queued = 0

            for raw_record in raw_records:
                try:
                    alert = alert_ingestion_service.ingest_alert(
                        db=db,
                        tenant=tenant,
                        platform=config.platform,
                        raw_alert=raw_record,
                        normalizer=normalizer,
                    )

                    inserted_or_updated += 1

                    if config.hydration_enabled:
                        incident = (
                            db.query(Incident)
                            .filter(
                                Incident.platform == config.platform,
                                Incident.source_alert_id == alert.source_alert_id,
                            )
                            .first()
                        )

                        if incident:
                            hydration_queue_service.enqueue_incident(
                                db=db,
                                incident=incident,
                                priority=self._priority_for_alert(alert),
                            )
                            queued += 1

                except Exception as item_exc:
                    db.rollback()
                    skipped += 1

                    logger.exception(
                        "Record ingestion failed tenant_id=%s platform=%s error=%s",
                        config.tenant_id,
                        config.platform,
                        item_exc,
                    )

            now = datetime.utcnow()

            sync_run.status = "success"
            sync_run.finished_at = now
            sync_run.records_fetched = fetched
            sync_run.records_inserted = inserted_or_updated
            sync_run.records_updated = 0
            sync_run.records_skipped = skipped

            state.last_run_at = now
            state.last_success_at = now
            state.status = "healthy"
            state.last_error = None
            state.next_run_at = now + timedelta(seconds=config.poll_interval_seconds)

            db.commit()

            return {
                "tenant_id": config.tenant_id,
                "platform": config.platform,
                "status": "success",
                "fetched": fetched,
                "ingested": inserted_or_updated,
                "skipped": skipped,
                "hydration_queued": queued,
                "next_run_at": state.next_run_at,
            }

        except Exception as exc:
            db.rollback()

            now = datetime.utcnow()

            sync_run = db.query(SyncRun).filter(SyncRun.id == sync_run.id).first()
            if sync_run:
                sync_run.status = "failed"
                sync_run.finished_at = now
                sync_run.error_message = str(exc)[:5000]

            state = self._get_or_create_state(
                db=db,
                tenant_id=config.tenant_id,
                platform=config.platform,
                poll_interval_seconds=config.poll_interval_seconds,
            )

            state.last_run_at = now
            state.last_failure_at = now
            state.status = "failed"
            state.last_error = str(exc)[:5000]
            state.next_run_at = now + timedelta(seconds=config.poll_interval_seconds)

            db.commit()

            logger.exception(
                "Scheduled sync failed tenant_id=%s platform=%s error=%s",
                config.tenant_id,
                config.platform,
                exc,
            )

            return {
                "tenant_id": config.tenant_id,
                "platform": config.platform,
                "status": "failed",
                "error": str(exc),
                "next_run_at": state.next_run_at,
            }

    def _get_or_create_state(
        self,
        db: Session,
        tenant_id: int,
        platform: str,
        poll_interval_seconds: int,
    ) -> PollingState:
        state = (
            db.query(PollingState)
            .filter(
                PollingState.tenant_id == tenant_id,
                PollingState.platform == platform,
            )
            .first()
        )

        if state:
            return state

        state = PollingState(
            tenant_id=tenant_id,
            platform=platform,
            status="due",
            next_run_at=datetime.utcnow(),
        )

        db.add(state)
        db.commit()
        db.refresh(state)

        return state

    def _get_connector_and_normalizer(
        self,
        platform: str,
    ):
        if platform == "seceon":
            return SeceonConnector(), normalize_seceon_alert

        if platform == "securonix":
            return SecuronixConnector(), normalize_securonix_incident

        raise ValueError(f"Unsupported platform: {platform}")

    def _priority_for_alert(
        self,
        alert: Alert,
    ) -> int:
        if alert.priority == "P1" or alert.severity == "critical":
            return 10

        if alert.priority == "P2" or alert.severity == "high":
            return 20

        if alert.priority == "P3" or alert.severity == "medium":
            return 50

        return 100


scheduler_service = SchedulerService()
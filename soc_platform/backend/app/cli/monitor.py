import argparse
import time
from datetime import datetime

from sqlalchemy.orm import Session, joinedload

from app.connectors.seceon import SeceonConnector
from app.connectors.securonix import SecuronixConnector
from app.core.config import get_settings
from app.db.session import SessionLocal
from app.models.tenant import Tenant, TenantPlatformAccount

# Important:
# These imports make sure SQLAlchemy registers case-related tables in metadata.
# Do not remove them, even if VS Code says they are unused.
from app.models.case import Case, CaseAlert, CaseTimeline, CaseNote  # noqa: F401

from app.normalizers.seceon import normalize_seceon_alert
from app.normalizers.securonix import normalize_securonix_incident
from app.services.alert_ingestion import alert_ingestion_service

settings = get_settings()

SUPPORTED_PLATFORMS = {"seceon", "securonix", "all"}


def log(message: str) -> None:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{now}] {message}", flush=True)


def get_enabled_accounts(
    db: Session,
    platform: str,
    tenant_limit: int,
) -> list[TenantPlatformAccount]:
    return (
        db.query(TenantPlatformAccount)
        .options(joinedload(TenantPlatformAccount.tenant))
        .join(Tenant, Tenant.id == TenantPlatformAccount.tenant_id)
        .filter(
            TenantPlatformAccount.platform == platform,
            TenantPlatformAccount.is_enabled.is_(True),
            Tenant.status == "active",
        )
        .order_by(TenantPlatformAccount.id.asc())
        .limit(tenant_limit)
        .all()
    )


def get_connector_and_normalizer(platform: str):
    if platform == "seceon":
        return SeceonConnector(), normalize_seceon_alert

    if platform == "securonix":
        return SecuronixConnector(), normalize_securonix_incident

    raise ValueError(f"Unsupported platform: {platform}")


def sync_platform_once(
    db: Session,
    platform: str,
    tenant_limit: int,
    max_alerts_per_tenant: int,
) -> dict:
    connector, normalizer = get_connector_and_normalizer(platform)

    accounts = get_enabled_accounts(
        db=db,
        platform=platform,
        tenant_limit=tenant_limit,
    )

    total_fetched = 0
    total_ingested = 0
    failures = []

    log(
        f"Starting sync | platform={platform} | "
        f"tenant_limit={tenant_limit} | tenants_loaded={len(accounts)} | "
        f"max_alerts_per_tenant={max_alerts_per_tenant}"
    )

    for account in accounts:
        tenant = account.tenant

        # Capture scalar values early so rollback does not break logging/failure handling.
        tenant_id = tenant.id
        tenant_name = tenant.tenant_name

        tenant_display = (
            account.external_tenant_name
            or account.external_tenant_id
            or tenant_name
        )

        try:
            raw_alerts = connector.fetch_alerts_for_tenant(
                tenant=tenant,
                platform_account=account,
                max_alerts_per_tenant=max_alerts_per_tenant,
            )

            fetched_count = len(raw_alerts)
            ingested_count = 0

            for raw_alert in raw_alerts:
                try:
                    alert_ingestion_service.ingest_alert(
                        db=db,
                        tenant=tenant,
                        platform=platform,
                        raw_alert=raw_alert,
                        normalizer=normalizer,
                    )
                    ingested_count += 1

                except Exception as alert_exc:
                    db.rollback()

                    failures.append(
                        {
                            "tenant_id": tenant_id,
                            "tenant_name": tenant_name,
                            "platform": platform,
                            "tenant_display": tenant_display,
                            "error": f"Alert ingestion failed: {str(alert_exc)}",
                        }
                    )

                    log(
                        f"ALERT_INGEST_FAILED | platform={platform} | "
                        f"tenant={tenant_display} | error={str(alert_exc)[:300]}"
                    )

            alert_ingestion_service.mark_sync_success(
                db=db,
                tenant_id=tenant_id,
                platform=platform,
            )

            total_fetched += fetched_count
            total_ingested += ingested_count

            log(
                f"SUCCESS | platform={platform} | tenant={tenant_display} | "
                f"fetched={fetched_count} | ingested={ingested_count}"
            )

        except Exception as exc:
            error_message = str(exc)

            db.rollback()

            try:
                alert_ingestion_service.mark_sync_failure(
                    db=db,
                    tenant_id=tenant_id,
                    platform=platform,
                    error=error_message,
                )

            except Exception as health_exc:
                db.rollback()
                log(
                    f"SYNC_STATE_UPDATE_FAILED | platform={platform} | "
                    f"tenant={tenant_display} | error={str(health_exc)[:300]}"
                )

            failures.append(
                {
                    "tenant_id": tenant_id,
                    "tenant_name": tenant_name,
                    "platform": platform,
                    "tenant_display": tenant_display,
                    "error": error_message,
                }
            )

            log(
                f"FAILED | platform={platform} | tenant={tenant_display} | "
                f"error={error_message[:300]}"
            )

    summary = {
        "platform": platform,
        "tenants_processed": len(accounts),
        "total_fetched": total_fetched,
        "total_ingested": total_ingested,
        "failures": failures,
    }

    log(
        f"SUMMARY | platform={platform} | tenants={summary['tenants_processed']} | "
        f"fetched={total_fetched} | ingested={total_ingested} | "
        f"failures={len(failures)}"
    )

    return summary


def run_cycle(
    platform: str,
    tenant_limit: int,
    max_alerts_per_tenant: int,
) -> None:
    db = SessionLocal()

    try:
        if platform == "all":
            sync_platform_once(
                db=db,
                platform="seceon",
                tenant_limit=tenant_limit,
                max_alerts_per_tenant=max_alerts_per_tenant,
            )

            sync_platform_once(
                db=db,
                platform="securonix",
                tenant_limit=tenant_limit,
                max_alerts_per_tenant=max_alerts_per_tenant,
            )

        else:
            sync_platform_once(
                db=db,
                platform=platform,
                tenant_limit=tenant_limit,
                max_alerts_per_tenant=max_alerts_per_tenant,
            )

    finally:
        db.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Unified SOC Platform CLI live monitor"
    )

    parser.add_argument(
        "--platform",
        choices=SUPPORTED_PLATFORMS,
        default="all",
        help="Platform to sync: seceon, securonix, or all",
    )

    parser.add_argument(
        "--tenant-limit",
        type=int,
        default=settings.connector_tenant_limit,
        help="Maximum number of tenants to sync per platform",
    )

    parser.add_argument(
        "--max-alerts-per-tenant",
        type=int,
        default=settings.connector_max_alerts_per_tenant,
        help="Maximum alerts/incidents to fetch per tenant per cycle",
    )

    parser.add_argument(
        "--interval",
        type=int,
        default=settings.connector_poll_interval_seconds,
        help="Polling interval in seconds",
    )

    parser.add_argument(
        "--run-once",
        action="store_true",
        help="Run one sync cycle and exit",
    )

    args = parser.parse_args()

    if args.tenant_limit <= 0:
        raise ValueError("--tenant-limit must be greater than 0")

    if args.max_alerts_per_tenant <= 0:
        raise ValueError("--max-alerts-per-tenant must be greater than 0")

    if args.interval < 10:
        raise ValueError("--interval should not be less than 10 seconds")

    log(
        f"CLI monitor started | platform={args.platform} | "
        f"tenant_limit={args.tenant_limit} | "
        f"max_alerts_per_tenant={args.max_alerts_per_tenant} | "
        f"interval={args.interval}s | run_once={args.run_once}"
    )

    if args.run_once:
        run_cycle(
            platform=args.platform,
            tenant_limit=args.tenant_limit,
            max_alerts_per_tenant=args.max_alerts_per_tenant,
        )
        log("CLI monitor finished one-time sync")
        return

    while True:
        cycle_start = datetime.now()

        log("Polling cycle started")

        run_cycle(
            platform=args.platform,
            tenant_limit=args.tenant_limit,
            max_alerts_per_tenant=args.max_alerts_per_tenant,
        )

        cycle_end = datetime.now()
        elapsed = (cycle_end - cycle_start).total_seconds()
        sleep_seconds = max(args.interval - elapsed, 0)

        log(
            f"Polling cycle completed | elapsed={elapsed:.2f}s | "
            f"sleeping={sleep_seconds:.2f}s"
        )

        time.sleep(sleep_seconds)


if __name__ == "__main__":
    main()
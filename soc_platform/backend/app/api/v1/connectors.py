from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.connectors.seceon import SeceonConnector
from app.connectors.securonix import SecuronixConnector
from app.core.logging import get_logger
from app.db.session import get_db
from app.models.tenant import Tenant, TenantPlatformAccount
from app.normalizers.seceon import normalize_seceon_alert
from app.normalizers.securonix import normalize_securonix_incident
from app.services.alert_ingestion import alert_ingestion_service

logger = get_logger(__name__)

router = APIRouter(prefix="/connectors", tags=["Connectors"])


@router.post("/sync/{platform}")
def sync_platform(
    platform: str,
    db: Session = Depends(get_db),
):
    platform = platform.lower().strip()

    if platform not in {"seceon", "securonix"}:
        raise HTTPException(
            status_code=400,
            detail="Unsupported platform. Allowed values: seceon, securonix",
        )

    accounts = (
        db.query(TenantPlatformAccount)
        .join(Tenant, Tenant.id == TenantPlatformAccount.tenant_id)
        .filter(
            TenantPlatformAccount.platform == platform,
            TenantPlatformAccount.is_enabled.is_(True),
            Tenant.status == "active",
        )
        .all()
    )

    if platform == "seceon":
        connector = SeceonConnector()
        normalizer = normalize_seceon_alert
    else:
        connector = SecuronixConnector()
        normalizer = normalize_securonix_incident

    total_fetched = 0
    total_ingested = 0
    failures = []

    for account in accounts:
        tenant = account.tenant

        try:
            raw_alerts = connector.fetch_alerts_for_tenant(
                tenant=tenant,
                platform_account=account,
            )

            total_fetched += len(raw_alerts)

            for raw_alert in raw_alerts:
                alert_ingestion_service.ingest_alert(
                    db=db,
                    tenant=tenant,
                    platform=platform,
                    raw_alert=raw_alert,
                    normalizer=normalizer,
                )
                total_ingested += 1

            alert_ingestion_service.mark_sync_success(
                db=db,
                tenant_id=tenant.id,
                platform=platform,
            )

        except Exception as exc:
            logger.exception(
                "Connector sync failed. tenant_id=%s platform=%s",
                account.tenant_id,
                platform,
            )

            alert_ingestion_service.mark_sync_failure(
                db=db,
                tenant_id=account.tenant_id,
                platform=platform,
                error=str(exc),
            )

            failures.append(
                {
                    "tenant_id": account.tenant_id,
                    "platform": platform,
                    "error": str(exc),
                }
            )

    return {
        "platform": platform,
        "tenants_processed": len(accounts),
        "total_fetched": total_fetched,
        "total_ingested": total_ingested,
        "failures": failures,
    }


@router.get("/health")
def connector_health(
    db: Session = Depends(get_db),
):
    from app.models.connector import ConnectorSyncState

    states = db.query(ConnectorSyncState).all()

    return [
        {
            "tenant_id": state.tenant_id,
            "platform": state.platform,
            "sync_status": state.sync_status,
            "last_success_at": state.last_success_at,
            "last_failure_at": state.last_failure_at,
            "last_error": state.last_error,
            "updated_at": state.updated_at,
        }
        for state in states
    ]
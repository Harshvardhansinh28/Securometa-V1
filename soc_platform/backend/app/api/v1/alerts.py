from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.alert import Alert, RawAlert
from app.schemas.alert import AlertResponse

router = APIRouter(prefix="/alerts", tags=["Alerts"])


@router.get("", response_model=list[AlertResponse])
def list_alerts(
    tenant_id: int | None = Query(default=None),
    platform: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    priority: str | None = Query(default=None),
    status: str | None = Query(default=None),
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    query = db.query(Alert)

    if tenant_id:
        query = query.filter(Alert.tenant_id == tenant_id)

    if platform:
        query = query.filter(Alert.platform == platform)

    if severity:
        query = query.filter(Alert.severity == severity)

    if priority:
        query = query.filter(Alert.priority == priority)

    if status:
        query = query.filter(Alert.status == status)

    return (
        query.order_by(Alert.ingested_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


@router.get("/{alert_id}", response_model=AlertResponse)
def get_alert(
    alert_id: int,
    db: Session = Depends(get_db),
):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()

    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    return alert


@router.get("/{alert_id}/raw")
def get_alert_raw_payload(
    alert_id: int,
    db: Session = Depends(get_db),
):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()

    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    if not alert.raw_alert_id:
        raise HTTPException(status_code=404, detail="Raw payload not found")

    raw_alert = db.query(RawAlert).filter(RawAlert.id == alert.raw_alert_id).first()

    if not raw_alert:
        raise HTTPException(status_code=404, detail="Raw payload not found")

    return {
        "alert_id": alert.id,
        "platform": alert.platform,
        "source_alert_id": alert.source_alert_id,
        "raw_payload": raw_alert.raw_payload,
    }
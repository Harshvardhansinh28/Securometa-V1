from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.alert import Alert
from app.models.case import Case
from app.models.incident import Incident, IncidentEntity

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/summary")
def dashboard_summary(
    db: Session = Depends(get_db),
):
    total_alerts = db.query(Alert).count()
    open_alerts = db.query(Alert).filter(Alert.status == "open").count()

    total_incidents = db.query(Incident).count()
    open_incidents = db.query(Incident).filter(Incident.status == "open").count()

    total_cases = db.query(Case).count()
    open_cases = (
        db.query(Case)
        .filter(Case.status.notin_(["closed", "resolved"]))
        .count()
    )

    critical_incidents = (
        db.query(Incident)
        .filter(Incident.severity == "critical")
        .count()
    )

    high_incidents = (
        db.query(Incident)
        .filter(Incident.severity == "high")
        .count()
    )

    extracted_entities = db.query(IncidentEntity).count()

    return {
        "alerts": {
            "total": total_alerts,
            "open": open_alerts,
        },
        "incidents": {
            "total": total_incidents,
            "open": open_incidents,
            "critical": critical_incidents,
            "high": high_incidents,
        },
        "cases": {
            "total": total_cases,
            "open": open_cases,
        },
        "entities": {
            "extracted": extracted_entities,
        },
    }


@router.get("/alerts-by-platform")
def alerts_by_platform(
    db: Session = Depends(get_db),
):
    rows = (
        db.query(Alert.platform, func.count(Alert.id))
        .group_by(Alert.platform)
        .all()
    )

    return [
        {
            "platform": platform,
            "count": count,
        }
        for platform, count in rows
    ]


@router.get("/incidents-by-severity")
def incidents_by_severity(
    db: Session = Depends(get_db),
):
    rows = (
        db.query(Incident.severity, func.count(Incident.id))
        .group_by(Incident.severity)
        .all()
    )

    return [
        {
            "severity": severity,
            "count": count,
        }
        for severity, count in rows
    ]


@router.get("/incidents-by-platform")
def incidents_by_platform(
    db: Session = Depends(get_db),
):
    rows = (
        db.query(Incident.platform, func.count(Incident.id))
        .group_by(Incident.platform)
        .all()
    )

    return [
        {
            "platform": platform,
            "count": count,
        }
        for platform, count in rows
    ]


@router.get("/top-entities")
def top_entities(
    limit: int = 20,
    db: Session = Depends(get_db),
):
    rows = (
        db.query(
            IncidentEntity.entity_type,
            IncidentEntity.entity_value,
            func.count(IncidentEntity.id).label("count"),
        )
        .group_by(
            IncidentEntity.entity_type,
            IncidentEntity.entity_value,
        )
        .order_by(func.count(IncidentEntity.id).desc())
        .limit(limit)
        .all()
    )

    return [
        {
            "entity_type": entity_type,
            "entity_value": entity_value,
            "count": count,
        }
        for entity_type, entity_value, count in rows
    ]


@router.get("/latest-incidents")
def latest_incidents(
    limit: int = 20,
    db: Session = Depends(get_db),
):
    incidents = (
        db.query(Incident)
        .order_by(Incident.updated_at.desc())
        .limit(limit)
        .all()
    )

    return incidents
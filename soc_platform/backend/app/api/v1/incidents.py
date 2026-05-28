from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.incident import Incident, IncidentEntity, IncidentEvent, ThreatIndicator
from app.schemas.incident import (
    IncidentEntityResponse,
    IncidentEventResponse,
    IncidentResponse,
    ThreatIndicatorResponse,
)
from app.services.incident_case import incident_case_service

router = APIRouter(prefix="/incidents", tags=["Incidents"])


class CreateCaseFromIncidentRequest(BaseModel):
    assigned_team: str | None = None


@router.get("", response_model=list[IncidentResponse])
def list_incidents(
    tenant_id: int | None = Query(default=None),
    platform: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    priority: str | None = Query(default=None),
    status: str | None = Query(default=None),
    hydration_status: str | None = Query(default=None),
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    query = db.query(Incident)

    if tenant_id:
        query = query.filter(Incident.tenant_id == tenant_id)

    if platform:
        query = query.filter(Incident.platform == platform)

    if severity:
        query = query.filter(Incident.severity == severity)

    if priority:
        query = query.filter(Incident.priority == priority)

    if status:
        query = query.filter(Incident.status == status)

    if hydration_status:
        query = query.filter(Incident.hydration_status == hydration_status)

    return (
        query.order_by(Incident.updated_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


@router.get("/{incident_id}", response_model=IncidentResponse)
def get_incident(
    incident_id: int,
    db: Session = Depends(get_db),
):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()

    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    return incident


@router.get("/{incident_id}/events", response_model=list[IncidentEventResponse])
def get_incident_events(
    incident_id: int,
    db: Session = Depends(get_db),
):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()

    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    return (
        db.query(IncidentEvent)
        .filter(IncidentEvent.incident_id == incident_id)
        .order_by(IncidentEvent.event_time.asc(), IncidentEvent.created_at.asc())
        .all()
    )


@router.get("/{incident_id}/entities", response_model=list[IncidentEntityResponse])
def get_incident_entities(
    incident_id: int,
    db: Session = Depends(get_db),
):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()

    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    return (
        db.query(IncidentEntity)
        .filter(IncidentEntity.incident_id == incident_id)
        .order_by(IncidentEntity.entity_type.asc(), IncidentEntity.entity_value.asc())
        .all()
    )


@router.get("/{incident_id}/threat-indicators", response_model=list[ThreatIndicatorResponse])
def get_incident_threat_indicators(
    incident_id: int,
    db: Session = Depends(get_db),
):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()

    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    return (
        db.query(ThreatIndicator)
        .filter(ThreatIndicator.incident_id == incident_id)
        .order_by(ThreatIndicator.created_at.desc())
        .all()
    )


@router.get("/{incident_id}/details")
def get_incident_details(
    incident_id: int,
    db: Session = Depends(get_db),
):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()

    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    events = (
        db.query(IncidentEvent)
        .filter(IncidentEvent.incident_id == incident_id)
        .order_by(IncidentEvent.event_time.asc(), IncidentEvent.created_at.asc())
        .all()
    )

    entities = (
        db.query(IncidentEntity)
        .filter(IncidentEntity.incident_id == incident_id)
        .order_by(IncidentEntity.entity_type.asc(), IncidentEntity.entity_value.asc())
        .all()
    )

    threat_indicators = (
        db.query(ThreatIndicator)
        .filter(ThreatIndicator.incident_id == incident_id)
        .order_by(ThreatIndicator.created_at.desc())
        .all()
    )

    return {
        "incident": incident,
        "events": events,
        "entities": entities,
        "threat_indicators": threat_indicators,
    }


@router.post("/{incident_id}/create-case")
def create_case_from_incident(
    incident_id: int,
    request: CreateCaseFromIncidentRequest,
    db: Session = Depends(get_db),
):
    case = incident_case_service.create_case_from_incident(
        db=db,
        incident_id=incident_id,
        assigned_team=request.assigned_team,
    )

    return {
        "message": "Case created from incident",
        "case_id": case.id,
        "case_number": case.case_number,
        "status": case.status,
        "assigned_team": case.assigned_team,
    }
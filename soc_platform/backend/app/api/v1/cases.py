from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.case import Case, CaseAlert, CaseNote, CaseTimeline

router = APIRouter(prefix="/cases", tags=["Cases"])


@router.get("")
def list_cases(
    tenant_id: int | None = Query(default=None),
    status: str | None = Query(default=None),
    priority: str | None = Query(default=None),
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    query = db.query(Case)

    if tenant_id:
        query = query.filter(Case.tenant_id == tenant_id)

    if status:
        query = query.filter(Case.status == status)

    if priority:
        query = query.filter(Case.priority == priority)

    cases = (
        query.order_by(Case.updated_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    return cases


@router.get("/{case_id}")
def get_case(
    case_id: int,
    db: Session = Depends(get_db),
):
    case = db.query(Case).filter(Case.id == case_id).first()

    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    return case


@router.get("/{case_id}/details")
def get_case_details(
    case_id: int,
    db: Session = Depends(get_db),
):
    case = db.query(Case).filter(Case.id == case_id).first()

    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    alerts = (
        db.query(CaseAlert)
        .filter(CaseAlert.case_id == case_id)
        .all()
    )

    timeline = (
        db.query(CaseTimeline)
        .filter(CaseTimeline.case_id == case_id)
        .order_by(CaseTimeline.created_at.asc())
        .all()
    )

    notes = (
        db.query(CaseNote)
        .filter(CaseNote.case_id == case_id)
        .order_by(CaseNote.created_at.desc())
        .all()
    )

    return {
        "case": case,
        "linked_alerts": alerts,
        "timeline": timeline,
        "notes": notes,
    }
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.services.incident_hydration import incident_hydration_service

router = APIRouter(prefix="/hydration", tags=["Hydration"])


@router.post("/seceon")
def hydrate_seceon(
    limit: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    return incident_hydration_service.hydrate_seceon_incidents(
        db=db,
        limit=limit,
    )


@router.post("/securonix")
def hydrate_securonix(
    limit: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    return incident_hydration_service.hydrate_securonix_incidents(
        db=db,
        limit=limit,
    )


@router.post("/all")
def hydrate_all(
    limit: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    seceon_result = incident_hydration_service.hydrate_seceon_incidents(
        db=db,
        limit=limit,
    )

    securonix_result = incident_hydration_service.hydrate_securonix_incidents(
        db=db,
        limit=limit,
    )

    return {
        "seceon": seceon_result,
        "securonix": securonix_result,
    }
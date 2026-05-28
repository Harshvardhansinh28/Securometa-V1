from fastapi import APIRouter

from app.api.v1.alerts import router as alerts_router
from app.api.v1.cases import router as cases_router
from app.api.v1.connectors import router as connectors_router
from app.api.v1.dashboard import router as dashboard_router
from app.api.v1.hydration import router as hydration_router
from app.api.v1.incidents import router as incidents_router

api_router = APIRouter()

api_router.include_router(alerts_router)
api_router.include_router(cases_router)
api_router.include_router(connectors_router)
api_router.include_router(dashboard_router)
api_router.include_router(hydration_router)
api_router.include_router(incidents_router)
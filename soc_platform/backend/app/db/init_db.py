from app.db.base import Base
from app.db.session import engine

from app.models.tenant import Tenant, TenantPlatformAccount
from app.models.connector import ConnectorSyncState
from app.models.alert import RawAlert, Alert
from app.models.case import Case, CaseAlert, CaseTimeline, CaseNote
from app.models.raw_payload import RawPayload
from app.models.incident import (
    Incident,
    IncidentEvent,
    IncidentEntity,
    ThreatIndicator,
)
from app.models.scheduler import (
    PollingConfig,
    PollingState,
    SyncRun,
    HydrationQueue,
)


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
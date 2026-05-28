from abc import ABC, abstractmethod
from typing import Any

from app.models.tenant import Tenant, TenantPlatformAccount


class BaseConnector(ABC):
    platform: str

    @abstractmethod
    def fetch_alerts_for_tenant(
        self,
        tenant: Tenant,
        platform_account: TenantPlatformAccount,
        max_alerts_per_tenant: int | None = None,
    ) -> list[dict[str, Any]]:
        raise NotImplementedError
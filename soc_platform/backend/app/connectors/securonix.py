from datetime import datetime, timezone
from urllib.parse import urljoin

import requests

from app.connectors.base import BaseConnector
from app.core.config import get_settings
from app.core.logging import get_logger
from app.models.tenant import Tenant, TenantPlatformAccount

logger = get_logger(__name__)
settings = get_settings()


class SecuronixConnector(BaseConnector):
    platform = "securonix"

    def _verify_tls(self):
        return (
            settings.securonix_ca_bundle
            if settings.securonix_ca_bundle
            else settings.securonix_verify_tls
        )

    def _headers(self) -> dict:
        return {
            "token": settings.securonix_token,
            "Cookie": settings.securonix_cookie,
        }

    def fetch_alerts_for_tenant(
        self,
        tenant: Tenant,
        platform_account: TenantPlatformAccount,
        max_alerts_per_tenant: int | None = None,
    ) -> list[dict]:
        tenant_name = platform_account.external_tenant_name

        if not tenant_name:
            logger.warning(
                "Skipping Securonix tenant because external_tenant_name is missing. tenant_id=%s",
                tenant.id,
            )
            return []

        alert_limit = max_alerts_per_tenant or settings.connector_max_alerts_per_tenant
        alert_limit = max(1, min(alert_limit, 1000))

        to_time = int(datetime.now(timezone.utc).timestamp() * 1000)
        from_time = to_time - (12 * 60 * 60 * 1000)

        url = f"{settings.securonix_base_url}/Snypr/ws/incident/get"

        params = {
            "type": "list",
            "from": from_time,
            "to": to_time,
            "rangeType": "opened",
            "max": alert_limit,
            "order": "desc",
            "tenantname": tenant_name,
        }

        response = requests.get(
            url,
            headers=self._headers(),
            params=params,
            verify=self._verify_tls(),
            timeout=settings.connector_timeout_seconds,
        )

        if response.status_code != 200:
            raise RuntimeError(
                f"Securonix API failed for tenant_id={tenant.id}. "
                f"HTTP={response.status_code}. Response={response.text[:500]}"
            )

        data = response.json()

        items = (
            data.get("result", {})
            .get("data", {})
            .get("incidentItems", [])
        )

        if not isinstance(items, list):
            raise RuntimeError(
                f"Invalid Securonix response format for tenant_id={tenant.id}"
            )

        open_items = [
            item for item in items
            if item.get("incidentStatus") == "Open"
        ]

        open_items = open_items[:alert_limit]

        logger.info(
            "Fetched %s open Securonix incidents for tenant_id=%s external_tenant_name=%s",
            len(open_items),
            tenant.id,
            tenant_name,
        )

        return open_items

    def fetch_incident_detail(
        self,
        tenant_name: str,
        incident_id: str,
    ) -> dict:
        if not tenant_name:
            raise ValueError("tenant_name is required")

        if not incident_id:
            raise ValueError("incident_id is required")

        url = self._build_url(settings.securonix_incident_detail_path)

        params = {
            "type": settings.securonix_incident_detail_type,
            "incidentId": incident_id,
            "tenantname": tenant_name,
        }

        response = requests.get(
            url,
            headers=self._headers(),
            params=params,
            verify=self._verify_tls(),
            timeout=settings.connector_timeout_seconds,
        )

        if response.status_code != 200:
            raise RuntimeError(
                f"Securonix incident detail API failed. "
                f"tenant={tenant_name} incident_id={incident_id} "
                f"HTTP={response.status_code} Response={response.text[:500]}"
            )

        data = response.json()

        if not isinstance(data, dict):
            raise RuntimeError(
                f"Invalid Securonix incident detail response for incident_id={incident_id}"
            )

        return data

    def fetch_violations_by_incident_id(
        self,
        tenant_name: str,
        incident_id: str,
    ) -> dict | None:
        if not settings.securonix_violations_path:
            return None

        url = self._build_url(settings.securonix_violations_path)

        params = {
            "incidentId": incident_id,
            "tenantname": tenant_name,
        }

        response = requests.get(
            url,
            headers=self._headers(),
            params=params,
            verify=self._verify_tls(),
            timeout=settings.connector_timeout_seconds,
        )

        if response.status_code != 200:
            raise RuntimeError(
                f"Securonix violations API failed. "
                f"tenant={tenant_name} incident_id={incident_id} "
                f"HTTP={response.status_code} Response={response.text[:500]}"
            )

        data = response.json()

        if not isinstance(data, dict):
            raise RuntimeError(
                f"Invalid Securonix violations response for incident_id={incident_id}"
            )

        return data

    def query_tpi_by_indicator(
        self,
        tenant_name: str,
        indicator_value: str,
    ) -> dict | None:
        if not settings.securonix_tpi_path:
            return None

        if not indicator_value:
            return None

        url = self._build_url(settings.securonix_tpi_path)

        params = {
            "tenantname": tenant_name,
            "query": indicator_value,
        }

        response = requests.get(
            url,
            headers=self._headers(),
            params=params,
            verify=self._verify_tls(),
            timeout=settings.connector_timeout_seconds,
        )

        if response.status_code != 200:
            raise RuntimeError(
                f"Securonix TPI API failed. "
                f"tenant={tenant_name} indicator={indicator_value} "
                f"HTTP={response.status_code} Response={response.text[:500]}"
            )

        data = response.json()

        if not isinstance(data, dict):
            raise RuntimeError(
                f"Invalid Securonix TPI response for indicator={indicator_value}"
            )

        return data

    def _build_url(self, path: str) -> str:
        if not path:
            raise ValueError("Securonix path is required")

        base = settings.securonix_base_url.rstrip("/")

        if path.startswith("http://") or path.startswith("https://"):
            return path

        if not path.startswith("/"):
            path = f"/{path}"

        return urljoin(base, path)
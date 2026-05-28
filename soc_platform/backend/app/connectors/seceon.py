from urllib.parse import urljoin

import requests

from app.connectors.base import BaseConnector
from app.core.config import get_settings
from app.core.logging import get_logger
from app.models.tenant import Tenant, TenantPlatformAccount

logger = get_logger(__name__)
settings = get_settings()


class SeceonConnector(BaseConnector):
    platform = "seceon"

    def _verify_tls(self):
        return (
            settings.seceon_ca_bundle
            if settings.seceon_ca_bundle
            else settings.seceon_verify_tls
        )

    def _headers(self) -> dict:
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {settings.seceon_token}",
        }

    def fetch_alerts_for_tenant(
        self,
        tenant: Tenant,
        platform_account: TenantPlatformAccount,
        max_alerts_per_tenant: int | None = None,
    ) -> list[dict]:
        if not platform_account.external_tenant_id:
            logger.warning(
                "Skipping Seceon tenant because external_tenant_id is missing. tenant_id=%s",
                tenant.id,
            )
            return []

        alert_limit = max_alerts_per_tenant or settings.connector_max_alerts_per_tenant
        alert_limit = max(1, min(alert_limit, 5000))

        url = f"{settings.seceon_base_url}?tenant_id={platform_account.external_tenant_id}"

        payload = {
            "alert_status": ["OPEN"],
            "severity": ["CRITICAL", "MAJOR"],
            "size": alert_limit,
        }

        response = requests.post(
            url,
            headers=self._headers(),
            json=payload,
            verify=self._verify_tls(),
            timeout=settings.connector_timeout_seconds,
        )

        if response.status_code != 200:
            raise RuntimeError(
                f"Seceon API failed for tenant_id={tenant.id}. "
                f"HTTP={response.status_code}. Response={response.text[:500]}"
            )

        data = response.json()
        alerts = data.get("response", [])

        if not isinstance(alerts, list):
            raise RuntimeError(
                f"Invalid Seceon response format for tenant_id={tenant.id}"
            )

        alerts = alerts[:alert_limit]

        logger.info(
            "Fetched %s Seceon alerts for tenant_id=%s external_tenant_id=%s",
            len(alerts),
            tenant.id,
            platform_account.external_tenant_id,
        )

        return alerts

    def fetch_threat_indicators_by_event_id(
        self,
        tenant_external_id: str,
        event_id: str,
    ) -> dict:
        """
        Fetch Seceon threat indicators using event_id.

        The exact endpoint path is configurable through:
        SECEON_THREAT_INDICATOR_PATH

        Expected request style for MVP:
        GET <host>/<path>?tenant_id=<tenant_id>&event_id=<event_id>

        If Seceon requires POST instead, we will adjust this method only.
        """

        if not tenant_external_id:
            raise ValueError("tenant_external_id is required")

        if not event_id:
            raise ValueError("event_id is required")

        base_host = self._extract_host_from_base_url(settings.seceon_base_url)

        path = settings.seceon_threat_indicator_path.strip()

        if not path.startswith("/"):
            path = f"/{path}"

        url = urljoin(base_host, path)

        params = {
            "tenant_id": tenant_external_id,
            "event_id": event_id,
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
                f"Seceon threat indicator API failed. "
                f"tenant_id={tenant_external_id} event_id={event_id} "
                f"HTTP={response.status_code} Response={response.text[:500]}"
            )

        data = response.json()

        if not isinstance(data, dict):
            raise RuntimeError(
                f"Invalid Seceon threat indicator response for event_id={event_id}"
            )

        return data

    def fetch_event_detail_by_event_id(
        self,
        tenant_external_id: str,
        event_id: str,
    ) -> dict | None:
        """
        Optional event detail fetch.

        We keep this optional because we still need exact Seceon Swagger path.
        If SECEON_EVENT_DETAIL_PATH is blank, this safely returns None.
        """

        if not settings.seceon_event_detail_path:
            return None

        base_host = self._extract_host_from_base_url(settings.seceon_base_url)

        path = settings.seceon_event_detail_path.strip()

        if not path.startswith("/"):
            path = f"/{path}"

        url = urljoin(base_host, path)

        params = {
            "tenant_id": tenant_external_id,
            "event_id": event_id,
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
                f"Seceon event detail API failed. "
                f"tenant_id={tenant_external_id} event_id={event_id} "
                f"HTTP={response.status_code} Response={response.text[:500]}"
            )

        data = response.json()

        if not isinstance(data, dict):
            raise RuntimeError(
                f"Invalid Seceon event detail response for event_id={event_id}"
            )

        return data

    def _extract_host_from_base_url(self, base_url: str) -> str:
        """
        Converts:
        https://103.225.225.54/api/v1/alert/search
        into:
        https://103.225.225.54
        """

        if "/api/" in base_url:
            return base_url.split("/api/")[0]

        return base_url.rstrip("/")
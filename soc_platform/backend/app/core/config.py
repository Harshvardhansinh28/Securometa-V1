from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Unified SOC Platform"
    app_env: str = "dev"
    app_debug: bool = False

    api_v1_prefix: str = "/api/v1"

    database_url: str = "mysql+pymysql://soc_user:soc_password_change_me@127.0.0.1:3307/soc_platform?charset=utf8mb4"

    redpanda_bootstrap_servers: str = "127.0.0.1:9092"
    redpanda_enabled: bool = False

    seceon_base_url: str = ""
    seceon_token: str = ""
    seceon_verify_tls: bool = True
    seceon_ca_bundle: str | None = None
    seceon_threat_indicator_path: str = "/api/v1/threatIndicator/byEventId"
    seceon_event_detail_path: str | None = None

    securonix_base_url: str = ""
    securonix_token: str = ""
    securonix_cookie: str = ""
    securonix_verify_tls: bool = True
    securonix_ca_bundle: str | None = None
    securonix_incident_detail_path: str = "/Snypr/ws/incident/get"
    securonix_incident_detail_type: str = "details"
    securonix_violations_path: str | None = None
    securonix_tpi_path: str | None = None

    connector_timeout_seconds: int = 60
    connector_max_workers: int = 5

    connector_tenant_limit: int = 5
    connector_max_alerts_per_tenant: int = 100
    connector_poll_interval_seconds: int = 300

    hydration_max_incidents_per_run: int = 20

    scheduler_tick_seconds: int = 30
    scheduler_max_due_configs_per_tick: int = 10
    scheduler_hydration_enabled: bool = True
    scheduler_hydration_batch_size: int = 20

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
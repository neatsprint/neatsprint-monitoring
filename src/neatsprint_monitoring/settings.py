from neatsprint_lib.settings import ServiceSettings


class Settings(ServiceSettings):
    service_name: str = "monitoring"
    api_prefix: str = "monitor"
    bootstrap_token: str | None = None
    service_token: str | None = None
    worklog_internal_url: str = "http://neatsprint-worklog:8000"
    team_internal_url: str = "http://neatsprint-team:8000"
    outbox_enabled: bool = True
    outbox_stream: str = "neatsprint.events"
    s3_endpoint: str | None = None
    s3_bucket: str = "neatsprint"
    s3_access_key: str | None = None
    s3_secret_key: str | None = None
    s3_region: str = "us-east-1"
    screenshot_max_bytes: int = 10 * 1024 * 1024
    screenshot_daily_quota: int = 2000
    privacy_window_hours: int = 24
    retention_days: int = 30
    capture_interval_seconds: int = 420
    job_interval_seconds: int = 30
    monitoring_encryption_key: str = "dev-monitoring-key-change-me"
    clamav_host: str | None = None
    clamav_port: int = 3310


settings = Settings()

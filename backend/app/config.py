from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "postgresql+asyncpg://warroom:changeme@postgres:5432/warroom"
    redis_url: str = "redis://redis:6379/0"

    sophos_client_id: str = ""
    sophos_client_secret: str = ""
    sophos_tenant_id: str = ""

    maxmind_license_key: str = ""
    abuseipdb_api_key: str = ""
    virustotal_api_key: str = ""
    shodan_api_key: str = ""
    sophos_intelix_client_id: str = ""
    sophos_intelix_client_secret: str = ""

    collector_interval: int = 300

    log_level: str = "INFO"

    dashboard_title: str = "Warroom Security Dashboard"

    # If empty: backend runs in open mode (warning logged). If set, every
    # /api/* request must carry an X-API-Key header matching this value.
    warroom_api_key: str = ""

    class Config:
        env_file = ".env"


settings = Settings()

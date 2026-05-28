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

    # --- AI agent ---
    agent_enabled: bool = False
    agent_provider: str = "lmstudio"  # lmstudio | openai-compatible (extensible)
    agent_base_url: str = "http://host.docker.internal:1234/v1"
    agent_api_key: str = ""           # optional for local LMStudio
    agent_model: str = ""             # model id reported by /v1/models
    agent_interval_seconds: int = 120
    # If true, "block_ip" / "acknowledge" recommendations execute automatically
    # at any confidence; otherwise they stay pending. The threshold below acts
    # as an independent fast-lane: any decision whose confidence (in %) is
    # ≥ this value auto-executes even when ``agent_auto_execute`` is false.
    # Set to 101 to disable the fast-lane entirely.
    agent_auto_execute: bool = False
    agent_auto_execute_threshold: int = 90  # percent (0..100)
    # Empty -> fall back to DEFAULT_SYSTEM_PROMPT in app.agent.
    agent_system_prompt: str = ""
    # WAF loop — rule-based, fires on every new WAF row with a 4xx/5xx status
    agent_waf_enabled: bool = False
    agent_waf_threshold: int = 4       # 4+ failed requests in 24h -> block
    agent_waf_interval_seconds: int = 60
    # IPS loop — rule-based; IDP/IPS events already classify as intrusion,
    # so the threshold is lower than WAF and severity-high triggers immediately.
    agent_ips_enabled: bool = False
    agent_ips_threshold: int = 3       # 3+ IPS hits in 24h -> block
    agent_ips_interval_seconds: int = 60
    # Failed-login loop — rule-based; brute-force detection.
    agent_failed_login_enabled: bool = False
    agent_failed_login_threshold: int = 5  # 5+ failed logins in 24h -> block
    agent_failed_login_interval_seconds: int = 60
    # Subnet-coordinated brute-force: when a /24 emits ≥ N attempts from
    # ≥ M distinct IPs, every active IP in that subnet gets blocked.
    agent_failed_login_subnet_attempts: int = 10
    agent_failed_login_subnet_min_ips: int = 3

    # --- OSINT-Provider Quota limits (for the /stats.html cost view) ---
    # Defaults reflect the documented free tiers; 0 disables the warning.
    osint_abuseipdb_daily_limit: int = 1000     # Standard free tier
    osint_abuseipdb_monthly_limit: int = 0      # AbuseIPDB tracks per-day
    osint_virustotal_daily_limit: int = 500     # Public API
    osint_virustotal_monthly_limit: int = 15500
    osint_shodan_daily_limit: int = 0           # Shodan is monthly
    osint_shodan_monthly_limit: int = 100
    osint_greynoise_daily_limit: int = 10000    # Community
    osint_greynoise_monthly_limit: int = 0
    osint_intelix_daily_limit: int = 10000      # Sophos Intelix free tier
    osint_intelix_monthly_limit: int = 0
    osint_ipinfo_daily_limit: int = 0           # ip-api.com free is unlimited but rate-limited
    osint_ipinfo_monthly_limit: int = 50000

    class Config:
        env_file = ".env"


settings = Settings()

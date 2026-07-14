from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "postgresql+asyncpg://warroom:changeme@postgres:5432/warroom"
    redis_url: str = "redis://redis:6379/0"

    sophos_client_id: str = ""
    sophos_client_secret: str = ""
    sophos_tenant_id: str = ""

    # --- Firewall IOC delivery ---
    # Two independent ways to get the blocklists onto the firewall; either or
    # both may be active (admin-selectable).
    # 1) Pull-based plaintext threat feeds (/ioc_IP, /ioc_domain, /ioc_url) that
    #    the firewall fetches as third-party threat feeds. When off, the feeds
    #    serve an empty body so a firewall that still polls them clears its list.
    firewall_threat_feed_enabled: bool = True
    # 2) Push-based delivery via the Sophos Central Firewall API MDR threat-feed
    #    indicators endpoint (POST /firewall/v1/firewalls/{id}/mdr-threat-feed/
    #    indicators). Reuses the existing Sophos Central OAuth credentials.
    firewall_mdr_feed_enabled: bool = False
    # Which Central-managed firewalls to push to: comma-separated firewall IDs.
    # Empty = every firewall returned by /firewall/v1/firewalls.
    firewall_mdr_feed_firewall_ids: str = ""
    # How often (seconds) to reconcile the blocklists with the firewalls' MDR feed.
    firewall_mdr_feed_sync_interval_seconds: int = 300

    # --- Microsoft 365 audit-log collector (Management Activity API) ---
    # Entra ID app registration with application permission ActivityFeed.Read
    # on "Office 365 Management APIs" (+ admin consent). Empty = collector idles.
    o365_tenant_id: str = ""
    o365_client_id: str = ""
    o365_client_secret: str = ""

    # --- Entra ID conditional-access IP blocking (reuses the O365 app reg;
    # additionally needs Graph application permissions Policy.ReadWrite.
    # ConditionalAccess + Policy.Read.All, admin-consented). When enabled,
    # blocked_ips are synced into a named location bound to a CA block policy
    # so M365 logins from those IPs are rejected by Microsoft directly. ---
    entra_block_enabled: bool = False
    entra_named_location_id: str = ""   # auto-created on first sync if empty
    entra_ca_policy_id: str = ""        # auto-created (report-only) if empty
    entra_block_sync_interval_minutes: int = 10
    # Break-glass accounts excluded from the auto-created block policy
    # (comma-separated UPNs or object ids). Required by Microsoft's
    # BlockEveryonePolicy guard — without an exclusion the create is rejected.
    entra_ca_exclude_users: str = ""

    # --- Telegram approval / notifications ---
    telegram_enabled: bool = False
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""          # numeric chat or group id
    telegram_poll_interval_seconds: int = 5

    # --- Microsoft Teams command channel ---
    # HMAC secret from the Teams "Outgoing Webhook" (Teams → Warroom commands).
    teams_outgoing_secret: str = ""
    # Incoming-webhook URL for outbound notifications (Warroom → Teams), optional.
    teams_incoming_webhook: str = ""

    # --- Internal hostname resolution ---
    # Resolve hostnames for internal (private) IPs and show them everywhere an
    # internal IP appears. Sources tried in order: Sophos endpoints → reverse
    # DNS → NetBIOS. All best-effort and cached.
    hostname_resolve_enabled: bool = True
    # Comma-separated internal DNS server IPs to query for PTR records of private
    # IPs (the container's default resolver usually can't). Empty ⇒ system resolver.
    internal_dns_servers: str = ""
    hostname_netbios_enabled: bool = True        # NetBIOS NBSTAT fallback (UDP 137)
    hostname_cache_ttl_hours: int = 168          # keep a positive hit for a week
    hostname_negative_ttl_hours: int = 6         # retry a miss after 6h

    # --- M365 login watch ---
    # Alerts (with a revoke-sessions option) when a user signs in from a device
    # or country not in their baseline. First run seeds the baseline silently.
    m365_login_watch_enabled: bool = False
    m365_login_watch_interval_seconds: int = 120
    m365_login_watch_lookback_minutes: int = 30   # scan window per pass (overlap-safe)

    # --- IP connection monitoring ---
    # Background job tracks which internal hosts talk to specially-flagged
    # ("monitored") blocklist / watchlist IPs and alerts on new sessions.
    ip_monitor_enabled: bool = True
    ip_monitor_interval_seconds: int = 60        # scan cadence (NetFlow is 60s-bucketed)
    ip_monitor_lookback_minutes: int = 10        # how far back each scan aggregates
    ip_monitor_session_gap_hours: int = 24       # quiet gap after which a known pair re-alerts
    ip_monitor_max_alerts_per_scan: int = 20     # safety cap so a burst can't flood the channels

    maxmind_license_key: str = ""
    abuseipdb_api_key: str = ""
    virustotal_api_key: str = ""
    shodan_api_key: str = ""
    sophos_intelix_client_id: str = ""
    sophos_intelix_client_secret: str = ""

    # When on, EVERY OSINT IP lookup also queries Shodan (spends a credit each
    # time). Turn off to make Shodan credit-frugal again (human-only + the
    # malicious-IP exception below).
    shodan_auto_every_lookup: bool = True
    # Shodan credits are scarce. With shodan_auto_every_lookup off, routine OSINT
    # skips Shodan; only human-initiated lookups query it. Exception: automated
    # agent loops may still spend a credit when the cheaper providers already
    # flag the IP as clearly malicious. Set shodan_auto_on_malicious=False to
    # make Shodan strictly human-only.
    shodan_auto_on_malicious: bool = True
    shodan_auto_abuse_threshold: int = 80   # AbuseIPDB confidence % that counts as "malicious"

    collector_interval: int = 300

    # --- Firewall-log retention (firewall_logs grows fast; connection logs
    # dominate). High-volume 'Firewall' connection logs are pruned sooner than
    # security-relevant types (WAF/IPS/Auth/ATP/…). Deletes run batched. ---
    firewall_log_retention_enabled: bool = True
    firewall_log_connection_retention_days: int = 14   # log_type='Firewall'
    firewall_log_retention_days: int = 90              # all other (security) rows
    firewall_log_retention_interval_hours: int = 6

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
    # LLM sampling controls used on every decision call (/chat/completions).
    # temperature: 0 = deterministic, higher = more creative. max_tokens caps
    # the response length — reasoning models need headroom for their hidden
    # think block, so keep this generous (≈3000).
    agent_temperature: float = 0.2
    agent_max_tokens: int = 3000
    # Let the free-form analyst chat run read-only SQL against Postgres to answer
    # data questions (validated SELECT-only, READ ONLY txn, statement timeout).
    chat_sql_enabled: bool = True
    # Use OpenAI-style structured outputs (response_format json_schema). The
    # decision schema is derived from the Pydantic LLMDecision model. Disable
    # for servers/models that don't support response_format (then the tolerant
    # parser handles plain JSON / reasoning output).
    agent_structured_output: bool = True
    # Language for the agent's own output: LLM system prompts (de/en defaults),
    # the analyst chat persona, and Telegram notifications. Admin-overridden
    # prompts always win regardless of this. "en" or "de".
    agent_language: str = "en"
    # Master switch: if true, non-destructive recommendations (acknowledge)
    # execute automatically; otherwise they stay pending. Block actions ALWAYS
    # require human approval regardless of this switch. Actions are chosen purely
    # from per-source thresholds in the prompts — there is no confidence score.
    agent_auto_execute: bool = False
    # Self-learning auto-approval: when enabled, the agent records every human
    # approval/rejection per decision "signature" (source_type|action|rule).
    # Once a signature's NET score (approvals − rejections) reaches
    # agent_learning_threshold, matching new decisions are auto-approved and
    # executed without asking — including block actions. Off by default (opt-in);
    # execute_decision still re-checks the whitelist on every run.
    agent_learning_enabled: bool = False
    agent_learning_threshold: int = 3
    # Empty -> fall back to DEFAULT_SYSTEM_PROMPT in app.agent.
    agent_system_prompt: str = ""
    # Per-source LLM system prompts for rule-based decisions. Empty -> fall
    # back to the bundled defaults (DEFAULT_WAF_PROMPT / _IPS_PROMPT /
    # _FAILED_LOGIN_PROMPT) defined in app.agent.
    agent_waf_system_prompt: str = ""
    agent_ips_system_prompt: str = ""
    agent_failed_login_system_prompt: str = ""
    agent_anomaly_system_prompt: str = ""
    # WAF loop — rule-based, fires on every new WAF row with a 4xx/5xx status
    agent_waf_enabled: bool = False
    agent_waf_threshold: int = 4       # 4+ failed requests in 24h -> block
    agent_waf_interval_seconds: int = 60
    # IPS loop — rule-based; IDP/IPS events already classify as intrusion,
    # so the threshold is lower than WAF and severity-high triggers immediately.
    agent_ips_enabled: bool = False
    agent_ips_threshold: int = 3       # 3+ IPS hits in 24h -> block
    agent_ips_interval_seconds: int = 60
    # FW-anomaly loop — Isolation Forest over NetFlow (like the dashboard), then
    # OSINT + LLM triage per anomalous public IP. Malicious → block via the
    # approval pipeline + verdict 'malicious'; everything else → 'suspicious'.
    agent_anomaly_enabled: bool = False
    agent_anomaly_interval_seconds: int = 900   # analysis is heavier than log sweeps
    agent_anomaly_hours: int = 24               # NetFlow window fed to the forest
    agent_anomaly_min_flows: int = 5            # ignore IPs below this flow count
    agent_anomaly_max_ips: int = 10             # OSINT/LLM cap per sweep
    # Per-connection (src→dst pair) C2/exfil detection + alarming. Notify-only:
    # marks the external destination 'suspicious' and raises a Telegram/Teams
    # alarm for high-confidence C2 beaconing / atypical uploads. OFF by default.
    agent_connanom_enabled: bool = False
    agent_connanom_interval_seconds: int = 1800  # per-connection sweep cadence
    agent_connanom_hours: int = 24               # NetFlow recent window
    agent_connanom_min_score: float = 0.7        # alarm only at/above this score
    agent_connanom_max_alerts: int = 10          # alarm cap per sweep
    # Central-Event loop — rule-based; analyses the Sophos Central *event* stream
    # (separate from alerts) filtered to security-relevant event_types. The
    # high-volume firewall ATP events are deliberately excluded (already covered
    # by the WAF/IPS loops via firewall_logs).
    agent_event_enabled: bool = True
    agent_event_interval_seconds: int = 120
    # Comma-separated Sophos event_type values fed to the LLM. Default: the
    # endpoint threat / exploit / C2 / malicious-app detections that have no
    # other path to the LLM.
    agent_event_types: str = (
        "Event::Endpoint::Threat::CommandAndControlDetected,"
        "Event::Endpoint::Threat::Detected,"
        "Event::Endpoint::Threat::CleanupFailed,"
        "Event::Endpoint::HmpaExploitPrevented,"
        "Event::Endpoint::Application::Detected"
    )
    # Empty ⇒ DEFAULT_EVENT_PROMPT in app.agent.
    agent_event_system_prompt: str = ""
    # Failed-login loop — rule-based; brute-force detection.
    agent_failed_login_enabled: bool = False
    agent_failed_login_threshold: int = 5  # 5+ failed logins in 24h -> block
    agent_failed_login_interval_seconds: int = 60
    # Subnet-coordinated brute-force: when a /24 emits ≥ N attempts from
    # ≥ M distinct IPs, every active IP in that subnet gets blocked.
    agent_failed_login_subnet_attempts: int = 10
    agent_failed_login_subnet_min_ips: int = 3
    # Distributed brute-force detection: the agent receives ALL failed-login
    # attempts from the last N minutes as JSON and derives itself whether
    # attempts cluster in the same /24 network. ``attempts``/``min_ips`` are the
    # per-/24 thresholds handed to the LLM as a hint for "what counts as
    # coordinated". This process only ever looks at login logs.
    agent_failed_login_distributed_enabled: bool = True
    agent_failed_login_distributed_window_minutes: int = 60
    agent_failed_login_distributed_attempts: int = 20   # per-/24 attempts hint
    agent_failed_login_distributed_min_ips: int = 4     # per-network distinct-IP hint
    # When on, the distributed sweep resolves each busy /24 to its real allocated
    # network (CIDR) via the OSINT/ipinfo-RDAP lookup and can block the whole
    # network (with human approval). Off ⇒ legacy naive-/24 grouping.
    agent_failed_login_network_block_enabled: bool = True
    # Empty ⇒ DEFAULT_DISTRIBUTED_LOGIN_PROMPT in app.agent.
    agent_failed_login_distributed_system_prompt: str = ""

    # User-centric brute-force alert: failed logins are aggregated by USERNAME
    # (every IP that tried that user + its failed-attempt count) and handed to the
    # LLM, which classifies "bruteforce" (few IPs, many tries) vs
    # "distributed_bruteforce" (many IPs, same user). On a hit we send a Telegram
    # notification that the user is endangered — no block, just a warning.
    agent_failed_login_user_alert_enabled: bool = True
    agent_failed_login_user_window_minutes: int = 60
    agent_failed_login_user_min_attempts: int = 10      # pre-filter before the LLM
    agent_failed_login_user_distributed_min_ips: int = 3  # distinct-IP hint for "distributed"
    agent_failed_login_user_alert_cooldown_minutes: int = 60  # re-notify the same user at most this often
    # Empty ⇒ DEFAULT_USER_LOGIN_PROMPT in app.agent.
    agent_failed_login_user_system_prompt: str = ""

    # Triage prompt — used by the manual / OSINT-initiated LLM triage path.
    # Empty ⇒ fall back to DEFAULT_TRIAGE_PROMPT in app.agent.
    agent_triage_system_prompt: str = ""

    # Analyst-persona system prompt for the free-form chat (in-app chat / Teams /
    # Telegram conversation). Empty ⇒ DEFAULT_ANALYST_PROMPT in command_service.
    analyst_system_prompt: str = ""

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

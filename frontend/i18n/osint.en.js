// English dictionary for the OSINT page. Loaded as a global before js/i18n.js.
window.I18N = window.I18N || {};
window.I18N.en = window.I18N.en || {};
window.I18N.en.osint = {
    provider_limits: "Provider limits",
    page_title: "OSINT lookup",

    // query card
    check_heading: "Check IP, domain or URL",
    type_auto: "Auto-detect",
    type_ip: "IP address",
    type_domain: "Domain",
    type_url: "URL",
    query_placeholder: "e.g. 91.206.156.176, evil-domain.com or https://…",
    query_btn: "Look up",
    force_label: "Bypass cache (fresh live lookup)",
    sources_hint: "<strong>IP:</strong> Intelix · AbuseIPDB · VirusTotal · Shodan · GreyNoise · ipinfo &nbsp;|&nbsp; <strong>Domain:</strong> Intelix · VirusTotal · DNS &nbsp;|&nbsp; <strong>URL:</strong> Intelix · VirusTotal",

    // result card
    result: "Result",
    block_now: "Block now",
    block_now_title: "Add the value to the blocklist immediately",
    triage_btn: "To AI triage",
    triage_title: "Hand the value to the AI agent for assessment",
    recheck: "Re-check",
    recheck_title: "Bypass cache",

    // recent queries
    recent: "Recently looked up",
    clear: "Clear",
    no_queries: "No lookups yet.",

    // persistent history
    persistent_history: "Persistent OSINT history",
    all_types: "All types",
    all: "All",
    abuse_50: "Abuse ≥ 50%",
    abuse_80: "Abuse ≥ 80%",
    search_placeholder: "search…",
    total_stored: "({n} stored)",
    no_entries: "No entries.",
    history_load_failed: "Failed to load history",

    // history table headers
    col_value: "Value",
    col_type: "Type",
    col_abuse: "Abuse",
    col_vt: "VT",
    col_greynoise: "GreyNoise",
    col_location: "Location",
    col_count: "#",
    col_last: "Last seen",

    // modal (shared)
    modal_title: "OSINT check",
    modal_title_for: "OSINT check for {label}: {value}",
    recheck_cache: "Re-check (bypass cache)",
    btn_title: "OSINT check for {label} {value}",

    // loading / status
    loading_parallel: "Querying sources in parallel — 5–10 seconds for uncached entries…",
    loading_fresh: "Cache bypassed, fresh request running…",
    cache_note: "Data from the 1h cache (use “Re-check” for a live lookup)",
    error: "Error",

    // triage
    add_watchlist: "Add to watchlist",
    watchlist_comment_prompt: "Comment for the watchlist entry (optional):",
    watchlist_added: "{ip} added to the watchlist.",
    watchlist_link: "Monitoring",
    watchlist_failed: "Watchlist failed",
    triage_hand_over: "Hand to AI triage",
    triage_note_prompt: "Optional note for the AI agent (context):",
    triage_running: "AI triage running — the agent is assessing the value (may take a few seconds)…",
    triage_failed: "AI triage failed",
    ai_decision: "AI decision",
    decision_link: "View decision #{id} in the agent log",

    // block action
    block_confirm: "Add {label} \"{value}\" to the blocklist immediately?",
    block_success: "<strong>{value}</strong> has been blocked.",
    open_blocklist: "Open blocklist",
    block_failed: "Block failed",

    // Shodan
    shodan_querying: "Querying Shodan…",
    shodan_failed: "Shodan lookup failed",
    shodan_on_demand: "Queried on demand only — consumes one Shodan credit.",
    shodan_query: "Query Shodan",
    shodan_no_record: "no record in Shodan",
    open_shodan_search: "Open Shodan search",
    open_shodan: "Open Shodan",
    l_country_city: "Country/City",
    sev_critical: "critical",
    sev_high: "high",
    sev_medium: "medium",
    sev_low: "low",
    kev_tip: "CISA KEV — actively exploited in the wild",
    cve_truncated: "(only the worst scored)",
    l_open_ports: "Open ports",
    l_as_of: "As of",

    // sections
    sec_vt_domain: "VirusTotal (Domain)",
    sec_vt_url: "VirusTotal (URL)",
    sec_dns: "DNS resolution",

    // connections
    conn_loading: "Loading known connections…",
    conn_load_failed: "Could not load connections",
    no_connections: "no connections",
    none_fw: "none",
    known_connections: "Known connections",
    netflow_last_days: "(NetFlow, last {days} days)",
    last_days: "(last {days} days)",
    fw_blocked_attempts: "Firewall: blocked/denied attempts",
    not_available: "not available",
    outbound: "Outbound (IP → destination)",
    inbound: "Inbound (source → IP)",
    peers: "peers",
    flows: "flows",
    attempts: "attempts",
    top: "Top {n}",
    col_peer: "Peer",
    col_port: "Port",
    col_proto: "Proto",
    col_bytes: "Bytes",
    col_flows: "Flows",

    // generic provider states
    no_data: "no data",
    unknown: "unknown",

    // AbuseIPDB
    l_confidence: "Confidence",
    l_total_reports: "Total reports",
    l_distinct_reporters: "Distinct reporters",
    l_last_report: "Last report",
    l_whitelist: "Whitelist",
    yes: "yes",
    no: "no",
    open_abuseipdb: "Open AbuseIPDB",

    // VirusTotal
    l_verdict: "Verdict",
    verdict_value: "{mal} malicious / {sus} suspicious",
    l_reputation: "Reputation",
    l_registered: "Registered",
    l_categories: "Categories",
    l_http_status: "HTTP status",
    open_virustotal: "Open VirusTotal",
    vt_unknown: "Not known to VirusTotal",
    open_vt_search: "Open VT search",

    // GreyNoise
    gn_unobserved: "Not in the GreyNoise dataset (no internet scan noise from this IP)",
    l_classification: "Classification",
    l_name: "Name",
    l_last_seen: "Last seen",
    l_tor: "Status",
    tor_exit_yes: "Tor exit node",
    tor_exit_no: "Not a Tor exit node",
    open_tor: "Check in ExoneraTor",
    rdns_none: "No PTR record",
    open_greynoise: "Open GreyNoise",

    // Intelix
    intelix_no_ip: "No Intelix entry for this IP",
    intelix_no_record: "No Intelix entry",
    l_category: "Category",
    l_description: "Description",
    l_risk: "Risk",

    // ipinfo
    l_location: "Location",
    open_ipinfo: "Open ipinfo.io",

    // DNS
    dns_no_resolve: "Does not resolve currently",
    dns_no_records: "no A/AAAA records",
};

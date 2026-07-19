// German dictionary for the OSINT page. Loaded as a global before js/i18n.js.
window.I18N = window.I18N || {};
window.I18N.de = window.I18N.de || {};
window.I18N.de.osint = {
    provider_limits: "Provider-Limits",
    page_title: "OSINT-Abfrage",

    // query card
    check_heading: "IP, Domain oder URL prüfen",
    type_auto: "Auto-Erkennung",
    type_ip: "IP-Adresse",
    type_domain: "Domain",
    type_url: "URL",
    query_placeholder: "z. B. 91.206.156.176, evil-domain.com oder https://…",
    query_btn: "Abfragen",
    force_label: "Cache umgehen (frische Live-Abfrage)",
    sources_hint: "<strong>IP:</strong> Intelix · AbuseIPDB · VirusTotal · Shodan · GreyNoise · ipinfo &nbsp;|&nbsp; <strong>Domain:</strong> Intelix · VirusTotal · DNS &nbsp;|&nbsp; <strong>URL:</strong> Intelix · VirusTotal",

    // result card
    result: "Ergebnis",
    block_now: "Sofort blocken",
    block_now_title: "Wert sofort auf die Blocklist setzen",
    triage_btn: "An KI-Triage",
    triage_title: "Wert dem KI-Agenten zur Bewertung übergeben",
    recheck: "Neu prüfen",
    recheck_title: "Cache umgehen",

    // recent queries
    recent: "Zuletzt abgefragt",
    clear: "Leeren",
    no_queries: "Noch keine Abfragen.",

    // persistent history
    persistent_history: "Persistente OSINT-Historie",
    all_types: "Alle Typen",
    all: "Alle",
    abuse_50: "Abuse ≥ 50%",
    abuse_80: "Abuse ≥ 80%",
    search_placeholder: "suchen…",
    total_stored: "({n} gespeichert)",
    no_entries: "Keine Einträge.",
    history_load_failed: "Historie laden fehlgeschlagen",

    // history table headers
    col_value: "Wert",
    col_type: "Typ",
    col_abuse: "Abuse",
    col_vt: "VT",
    col_greynoise: "GreyNoise",
    col_location: "Standort",
    col_count: "#",
    col_last: "Zuletzt",

    // modal (shared)
    modal_title: "OSINT-Check",
    modal_title_for: "OSINT-Check für {label}: {value}",
    recheck_cache: "Neu prüfen (Cache umgehen)",
    btn_title: "OSINT-Check für {label} {value}",

    // loading / status
    loading_parallel: "Quellen werden parallel abgefragt — 5–10 Sekunden bei nicht gecachten Einträgen…",
    loading_fresh: "Cache umgangen, frische Anfrage läuft…",
    cache_note: "Daten aus dem 1h-Cache (Knopf „Neu prüfen“ für Live-Abfrage)",
    error: "Fehler",

    // triage
    add_watchlist: "Auf Watchlist",
    watchlist_comment_prompt: "Kommentar für den Watchlist-Eintrag (optional):",
    watchlist_added: "{ip} auf die Watchlist gesetzt.",
    watchlist_link: "Überwachung",
    watchlist_failed: "Watchlist fehlgeschlagen",
    triage_hand_over: "An KI-Triage übergeben",
    triage_note_prompt: "Optionaler Hinweis für den KI-Agenten (Kontext):",
    triage_running: "KI-Triage läuft — der Agent prüft den Wert (kann einige Sekunden dauern)…",
    triage_failed: "KI-Triage fehlgeschlagen",
    ai_decision: "KI-Entscheidung",
    decision_link: "Decision #{id} im Agent-Log ansehen",

    // block action
    block_confirm: "{label} \"{value}\" sofort auf die Blocklist setzen?",
    block_success: "<strong>{value}</strong> wurde geblockt.",
    open_blocklist: "Blocklist öffnen",
    block_failed: "Blocken fehlgeschlagen",

    // Shodan
    shodan_querying: "Shodan wird abgefragt…",
    shodan_failed: "Shodan-Abfrage fehlgeschlagen",
    shodan_on_demand: "Wird nur auf Anfrage abgefragt — verbraucht ein Shodan-Credit.",
    shodan_query: "Shodan abfragen",
    shodan_no_record: "kein Eintrag bei Shodan",
    open_shodan_search: "Shodan-Suche öffnen",
    open_shodan: "Shodan öffnen",
    l_country_city: "Land/Stadt",
    sev_critical: "kritisch",
    sev_high: "hoch",
    sev_medium: "mittel",
    sev_low: "niedrig",
    kev_tip: "CISA KEV — aktiv in freier Wildbahn ausgenutzt",
    cve_truncated: "(nur die schwersten bewertet)",
    l_open_ports: "Offene Ports",
    l_as_of: "Stand",

    // sections
    sec_vt_domain: "VirusTotal (Domain)",
    sec_vt_url: "VirusTotal (URL)",
    sec_dns: "DNS-Auflösung",

    // connections
    conn_loading: "Bekannte Verbindungen werden geladen…",
    conn_load_failed: "Verbindungen konnten nicht geladen werden",
    no_connections: "keine Verbindungen",
    none_fw: "keine",
    known_connections: "Bekannte Verbindungen",
    netflow_last_days: "(NetFlow, letzte {days} Tage)",
    last_days: "(letzte {days} Tage)",
    fw_blocked_attempts: "Firewall: geblockte/abgelehnte Versuche",
    not_available: "nicht verfügbar",
    outbound: "Ausgehend (IP → Ziel)",
    inbound: "Eingehend (Quelle → IP)",
    peers: "Peers",
    flows: "Flows",
    attempts: "Versuche",
    top: "Top {n}",
    col_peer: "Peer",
    col_port: "Port",
    col_proto: "Proto",
    col_bytes: "Bytes",
    col_flows: "Flows",

    // generic provider states
    no_data: "keine Daten",
    unknown: "unbekannt",

    // AbuseIPDB
    l_confidence: "Confidence",
    l_total_reports: "Reports gesamt",
    l_distinct_reporters: "Distinct Reporter",
    l_last_report: "Letzte Meldung",
    l_whitelist: "Whitelist",
    yes: "ja",
    no: "nein",
    open_abuseipdb: "AbuseIPDB öffnen",

    // VirusTotal
    l_verdict: "Verdict",
    verdict_value: "{mal} bösartig / {sus} verdächtig",
    l_reputation: "Reputation",
    l_registered: "Registriert",
    l_categories: "Kategorien",
    l_http_status: "HTTP-Status",
    open_virustotal: "VirusTotal öffnen",
    vt_unknown: "Bei VirusTotal nicht bekannt",
    open_vt_search: "VT-Suche öffnen",

    // GreyNoise
    gn_unobserved: "Nicht im GreyNoise-Datensatz (kein Internet-Scan-Noise von dieser IP)",
    l_classification: "Klassifikation",
    l_name: "Name",
    l_last_seen: "Letzte Sichtung",
    l_tor: "Status",
    tor_exit_yes: "Tor Exit-Node",
    tor_exit_no: "Kein Tor Exit-Node",
    open_tor: "In ExoneraTor prüfen",
    open_greynoise: "GreyNoise öffnen",

    // Intelix
    intelix_no_ip: "Kein Intelix-Eintrag für diese IP",
    intelix_no_record: "Kein Intelix-Eintrag",
    l_category: "Kategorie",
    l_description: "Beschreibung",
    l_risk: "Risiko",

    // ipinfo
    l_location: "Ort",
    open_ipinfo: "ipinfo.io öffnen",

    // DNS
    dns_no_resolve: "Löst aktuell nicht auf",
    dns_no_records: "keine A/AAAA-Records",
};

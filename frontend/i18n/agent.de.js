// German dictionary for the Agent page. Loaded as a global before js/i18n.js.
window.I18N = window.I18N || {};
window.I18N.de = window.I18N.de || {};
window.I18N.de.agent = {
    // header / page
    page_title: "🤖 Agent — Audit & Human-in-the-loop",
    run_alerts: "Alerts",
    run_waf_title: "WAF-Scan über die letzte Stunde",
    run_ips_title: "IPS-Scan über die letzte Stunde",
    run_login_title: "Failed-Login-Scan über die letzte Stunde",
    configure_title: "Agent konfigurieren",

    // stat boxes
    stat_total: "Decisions gesamt",
    stat_pending: "Pending",
    stat_pending_sub: "warten auf Freigabe",
    stat_executed: "Executed",
    stat_executed_sub: "ausgeführt",
    stat_rejected: "Rejected / Superseded",
    stat_rejected_sub: "abgelehnt oder ersetzt",
    stat_failed: "Failed",
    stat_failed_sub: "Execution-Fehler",

    // workflow card
    workflow_title: "KI-Workflow",
    download_drawio_title: "drawio-Diagramm herunterladen",
    legend_critical: "kritisch (Block / IOC)",
    legend_approved: "genehmigt / auto / Whitelist",
    legend_override: "Override / Acknowledge / Scheduler",
    legend_llm: "LLM / OSINT",
    legend_persist: "Persistierung / Review",
    legend_reject: "Reject / Audit / Sonst",

    // cards
    timeline_title: "Aktivität — Decisions pro Stunde (Agent vs. Mensch)",
    log_title: "Decision-Log",

    // filters
    filter_all_status: "Alle Status",
    filter_both: "Beide",
    filter_only_agent: "Nur Agent",
    filter_only_human: "Nur Mensch",
    filter_all_actions: "Alle Actions",
    search_placeholder: "Volltext (Begründung, IP, Alert-Typ…)",
    approve_all: "Alle Pending genehmigen",
    approve_all_title: "Genehmigt alle aktuell sichtbaren pending Decisions auf einmal. Whitelist-/Sicherheits-Checks greifen pro Decision wie bei Einzel-Approve.",

    // table headers
    col_source: "Quelle",
    col_reasoning: "Begründung",
    col_alarm: "Alarm",

    // modals
    detail_title: "Decision-Detail",

    // workflow badges (JS)
    wf_interval: "alle {n} Sek",
    wf_off: "AUS",
    no_model: "kein Modell gewählt",

    // actors / list cells
    actor_agent: "Agent",
    actor_human: "Mensch",
    no_decisions: "Keine Decisions im aktuellen Filter.",
    triage: "Triage",
    distributed_bf: "verteilter Brute-Force",
    logins: "Logins",
    unit_networks: "Netz(e)",
    top: "Top",
    ips_hits: "IPS-Hits",
    failed_logins: "Failed-Logins",
    error: "Fehler",

    // detail fields
    f_decision_id: "Decision-ID",
    f_decided_by: "Entschieden von",
    f_action: "Aktion",
    f_action_args: "Aktion-Args",
    f_created: "Erstellt",
    f_decided: "Entschieden",
    f_supersedes: "Supersedes",
    agent_reasoning: "Agent-Begründung",
    human_comment: "Mensch-Kommentar",

    // rule context heads
    ctx_waf: "WAF-Kontext",
    ctx_ips: "IPS-Kontext",
    ctx_distributed_bf: "Verteilter-Brute-Force-Kontext",
    ctx_subnet_bf: "Subnet-Brute-Force-Kontext",
    ctx_failed_login: "Failed-Login-Kontext",
    ctx_triage: "Triage-Kontext",

    // rule context rows
    r_rule: "Regel",
    r_threshold: "Schwelle",
    r_country_city: "Land/Stadt",
    r_4xx_24h: "4xx in 24h",
    r_5xx_24h: "5xx in 24h",
    r_http_statuses: "HTTP-Statuses",
    r_hosts: "Hosts",
    r_hits_24h: "Hits in 24h",
    r_severities: "Severities",
    r_signatures: "Signaturen",
    r_categories: "Kategorien",
    r_value: "Wert",
    r_type: "Typ",
    r_operator_note: "Operator-Hinweis",
    r_login_attempts_window: "Login-Versuche im Fenster",
    r_time_window: "Zeitfenster",
    r_affected_networks: "Betroffene Netze",
    r_affected_24: "Betroffene /24-Netze",
    r_block_target: "Block-Ziel",
    r_top_networks: "Top-Netze (Versuche / IPs)",
    r_top_24: "Top /24 (Versuche / IPs)",
    whole_network: "ganzes Netz",
    too_large: "zu groß",
    r_subnet: "Subnet",
    r_subnet_attempts_24h: "Versuche im Subnet (24h)",
    r_subnet_distinct_ips: "Distinct IPs im Subnet",
    r_block_scope: "Block-Umfang",
    all_254_hosts: "alle 254 Hosts im /24",
    net_broadcast_excl: "Network/Broadcast ausgenommen",
    r_observed_ips: "Gesehene Angreifer-IPs",
    r_more_subnet_ips: "Weitere Subnet-IPs (Sample)",
    r_failed_logins_24h: "Failed-Logins in 24h",
    r_attempted_users: "Versuchte User",
    r_components: "Komponenten",
    r_osint_hits: "OSINT-Treffer",
    r_osint_summary: "OSINT-Summary",

    // alarm context
    alarm_context: "Alarm-Kontext",
    f_alert_id: "Alert-ID",
    f_category: "Kategorie",
    f_source_ip: "Quell-IP",
    f_dest_ip: "Ziel-IP",
    f_acknowledged: "Acknowledged",
    no: "nein",
    show_raw_data: "Raw-Data anzeigen",
    alarm_not_in_db: "Alarm nicht (mehr) in der DB",

    // human action panel
    human_decision: "Menschliche Entscheidung",
    human_decision_hint: "Du kannst die Empfehlung des Agents ausführen, ablehnen oder eine andere Aktion wählen (Override).",
    comment_saved: "Kommentar (wird gespeichert)",
    comment_placeholder: "Optionaler Begründungstext",
    execute_recommendation: "Empfehlung ausführen",
    reject: "Ablehnen",
    override_other_action: "Override mit anderer Aktion",
    isolate_manual: "isolate (manuell über Endpoints-API)",
    target_ip_placeholder: "Ziel-IP (für block_ip)",
    override_execute: "Override + ausführen",
    private_ip_warn: "Quell-IP ist privat / reserviert — block_ip wird abgelehnt",
    chain_history: "Verlauf (Chain)",

    // confirms / alerts
    target_ip_missing: "Ziel-IP fehlt",
    override_confirm: "Override: {action} jetzt ausführen?",
    no_pending_filter: "Keine pending Decisions im aktuellen Filter.",
    bulk_count_unknown: "(Anzahl konnte nicht ermittelt werden — Bulk-Approve trotzdem versuchen?)",
    bulk_pending_count: "{n} pending Decision(s){filter}",
    bulk_confirm: "{count} ausführen?\n\nWhitelist- und Sicherheits-Checks greifen weiterhin pro Decision.",
    running: "… läuft",
    bulk_executed: "{n} ausgeführt",
    bulk_failed: ", {n} fehlgeschlagen (siehe Konsole)",
};

// English dictionary for the Agent page. Loaded as a global before js/i18n.js.
window.I18N = window.I18N || {};
window.I18N.en = window.I18N.en || {};
window.I18N.en.agent = {
    // header / page
    page_title: "🤖 Agent — Audit & Human-in-the-loop",
    run_alerts: "Alerts",
    run_waf_title: "WAF scan over the last hour",
    run_ips_title: "IPS scan over the last hour",
    run_login_title: "Failed-login scan over the last hour",
    configure_title: "Configure agent",

    // stat boxes
    stat_total: "Total decisions",
    stat_pending: "Pending",
    stat_pending_sub: "awaiting approval",
    stat_executed: "Executed",
    stat_executed_sub: "executed",
    stat_rejected: "Rejected / Superseded",
    stat_rejected_sub: "rejected or replaced",
    stat_failed: "Failed",
    stat_failed_sub: "execution error",

    // workflow card
    workflow_title: "AI Workflow",
    download_drawio_title: "Download drawio diagram",
    legend_critical: "critical (block / IOC)",
    legend_approved: "approved / auto / whitelist",
    legend_override: "Override / Acknowledge / Scheduler",
    legend_llm: "LLM / OSINT",
    legend_persist: "Persistence / Review",
    legend_reject: "Reject / Audit / Other",

    // cards
    timeline_title: "Activity — decisions per hour (agent vs. human)",
    log_title: "Decision Log",

    // filters
    filter_all_status: "All statuses",
    filter_both: "Both",
    filter_only_agent: "Agent only",
    filter_only_human: "Human only",
    filter_all_actions: "All actions",
    search_placeholder: "Full text (reason, IP, alert type…)",
    approve_all: "Approve all pending",
    approve_all_title: "Approves all currently visible pending decisions at once. Whitelist/security checks apply per decision as with a single approve.",

    // table headers
    col_source: "Source",
    col_reasoning: "Reason",
    col_alarm: "Alarm",

    // modals
    detail_title: "Decision Detail",

    // workflow badges (JS)
    wf_interval: "every {n} sec",
    wf_off: "OFF",
    no_model: "no model selected",

    // actors / list cells
    actor_agent: "Agent",
    actor_human: "Human",
    no_decisions: "No decisions in the current filter.",
    triage: "Triage",
    distributed_bf: "distributed brute-force",
    logins: "logins",
    unit_networks: "network(s)",
    top: "Top",
    ips_hits: "IPS hits",
    failed_logins: "failed logins",
    error: "Error",

    // detail fields
    f_decision_id: "Decision ID",
    f_decided_by: "Decided by",
    f_action: "Action",
    f_action_args: "Action args",
    f_created: "Created",
    f_decided: "Decided",
    f_supersedes: "Supersedes",
    agent_reasoning: "Agent reasoning",
    human_comment: "Human comment",

    // rule context heads
    ctx_waf: "WAF context",
    ctx_ips: "IPS context",
    ctx_distributed_bf: "Distributed brute-force context",
    ctx_subnet_bf: "Subnet brute-force context",
    ctx_failed_login: "Failed-login context",
    ctx_triage: "Triage context",

    // rule context rows
    r_rule: "Rule",
    r_threshold: "Threshold",
    r_country_city: "Country/City",
    r_4xx_24h: "4xx in 24h",
    r_5xx_24h: "5xx in 24h",
    r_http_statuses: "HTTP statuses",
    r_hosts: "Hosts",
    r_hits_24h: "Hits in 24h",
    r_severities: "Severities",
    r_signatures: "Signatures",
    r_categories: "Categories",
    r_value: "Value",
    r_type: "Type",
    r_operator_note: "Operator note",
    r_login_attempts_window: "Login attempts in window",
    r_time_window: "Time window",
    r_affected_networks: "Affected networks",
    r_affected_24: "Affected /24 networks",
    r_block_target: "Block target",
    r_top_networks: "Top networks (attempts / IPs)",
    r_top_24: "Top /24 (attempts / IPs)",
    whole_network: "whole network",
    too_large: "too large",
    r_subnet: "Subnet",
    r_subnet_attempts_24h: "Attempts in subnet (24h)",
    r_subnet_distinct_ips: "Distinct IPs in subnet",
    r_block_scope: "Block scope",
    all_254_hosts: "all 254 hosts in the /24",
    net_broadcast_excl: "network/broadcast excluded",
    r_observed_ips: "Observed attacker IPs",
    r_more_subnet_ips: "More subnet IPs (sample)",
    r_failed_logins_24h: "Failed logins in 24h",
    r_attempted_users: "Attempted users",
    r_components: "Components",
    r_osint_hits: "OSINT hits",
    r_osint_summary: "OSINT summary",

    // alarm context
    alarm_context: "Alarm context",
    f_alert_id: "Alert ID",
    f_category: "Category",
    f_source_ip: "Source IP",
    f_dest_ip: "Destination IP",
    f_acknowledged: "Acknowledged",
    no: "no",
    show_raw_data: "Show raw data",
    alarm_not_in_db: "Alarm no longer in the DB",

    // human action panel
    human_decision: "Human decision",
    human_decision_hint: "You can execute the agent's recommendation, reject it, or choose another action (override).",
    comment_saved: "Comment (will be saved)",
    comment_placeholder: "Optional justification text",
    execute_recommendation: "Execute recommendation",
    reject: "Reject",
    override_other_action: "Override with another action",
    isolate_manual: "isolate (manually via Endpoints API)",
    target_ip_placeholder: "Target IP (for block_ip)",
    override_execute: "Override + execute",
    private_ip_warn: "Source IP is private / reserved — block_ip will be rejected",
    chain_history: "History (chain)",

    // confirms / alerts
    target_ip_missing: "Target IP missing",
    override_confirm: "Override: {action} — execute now?",
    no_pending_filter: "No pending decisions in the current filter.",
    bulk_count_unknown: "(Count could not be determined — attempt bulk approve anyway?)",
    bulk_pending_count: "{n} pending decision(s){filter}",
    bulk_confirm: "Execute {count}?\n\nWhitelist and security checks still apply per decision.",
    running: "… running",
    bulk_executed: "{n} executed",
    bulk_failed: ", {n} failed (see console)",
};

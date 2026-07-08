// English dictionary for the Monitoring page. Extends window.I18N.en.
window.I18N = window.I18N || {};
window.I18N.en = window.I18N.en || {};
window.I18N.en.monitored = {
    title: "Monitoring — connections to flagged IPs",
    intro: "This page analyses the IPs flagged <i class=\"bi bi-binoculars\"></i> <strong>Monitor</strong> on the <a href=\"/blocked.html\">blocklist / watchlist</a>: which internal hosts talk to them, and when. When a <strong>new connection</strong> appears, a notification is sent via Telegram/Teams.",
    disabled_warn: "Monitoring is currently disabled (ip_monitor_enabled=false).",
    scan_now: "Scan now",
    scan_failed: "Scan failed",

    stat_ips: "Monitored IPs",
    stat_hosts: "Host connections",
    stat_new24h: "New connections (24h)",
    stat_last_event: "Last event",

    events_title: "New connections (event log)",
    filter_events: "Filter (host, IP, country…)",
    empty_events: "No events yet. Flag IPs with \"Monitor\" on the blocklist/watchlist.",
    col_type: "Type",
    col_host: "Host",
    col_direction: "Direction",
    col_ip: "Monitored IP",
    col_portproto: "Port/proto",
    col_notified: "Notified",
    type_new: "New",
    type_reappeared: "Reappeared",
    dir_outbound: "Host → IP",
    dir_inbound: "IP → Host",
    not_sent: "Not sent (no channel configured)",

    ips_title: "Monitored IPs",
    filter_ips: "Filter (IP, comment, country…)",
    filter_by_ip_title: "Filter by this IP",
    empty_ips: "No IP flagged for monitoring. Flag one with \"Monitor\" on the blocklist/watchlist.",
    col_lists: "Lists",
    col_hosts: "Hosts",
    col_last_activity: "Last activity",
    col_new24h: "New (24h)",
    btn_details: "Connections",

    conn_title: "Connections",
    conn_intro: "<strong>{n}</strong> known host connection(s) to <code>{ip}</code> (persistent baseline, outlives the 30-day NetFlow window).",
    no_conns: "No connections recorded yet — the next scan will fill this in.",
    conn_failed: "Could not load connections",
    col_volume: "Volume",
    col_first_seen: "First seen",
    col_last_seen: "Last seen",
};

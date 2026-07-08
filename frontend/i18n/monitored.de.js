// German dictionary for the Monitoring page. Extends window.I18N.de.
window.I18N = window.I18N || {};
window.I18N.de = window.I18N.de || {};
window.I18N.de.monitored = {
    title: "Überwachung — Verbindungen zu markierten IPs",
    intro: "Diese Seite wertet die auf der <a href=\"/blocked.html\">Blocklist / Watchlist</a> mit <i class=\"bi bi-binoculars\"></i> <strong>Überwachen</strong> markierten IPs aus: welche internen Hosts wann mit ihnen reden. Taucht eine <strong>neue Verbindung</strong> auf, wird über Telegram/Teams benachrichtigt.",
    disabled_warn: "Die Überwachung ist derzeit deaktiviert (ip_monitor_enabled=false).",
    scan_now: "Jetzt scannen",
    scan_failed: "Scan fehlgeschlagen",

    stat_ips: "Überwachte IPs",
    stat_hosts: "Host-Verbindungen",
    stat_new24h: "Neue Verbindungen (24h)",
    stat_last_event: "Letztes Ereignis",

    events_title: "Neue Verbindungen (Ereignis-Verlauf)",
    filter_events: "Filter (Host, IP, Land…)",
    empty_events: "Noch keine Ereignisse. Markiere IPs mit „Überwachen\" auf der Blocklist/Watchlist.",
    col_type: "Typ",
    col_host: "Host",
    col_direction: "Richtung",
    col_ip: "Überwachte IP",
    col_portproto: "Port/Proto",
    col_notified: "Benachrichtigt",
    type_new: "Neu",
    type_reappeared: "Wieder aktiv",
    dir_outbound: "Host → IP",
    dir_inbound: "IP → Host",
    not_sent: "Nicht gesendet (kein Kanal konfiguriert)",

    ips_title: "Überwachte IPs",
    filter_ips: "Filter (IP, Kommentar, Land…)",
    empty_ips: "Keine IP zur Überwachung markiert. Auf der Blocklist/Watchlist mit „Überwachen\" markieren.",
    col_lists: "Listen",
    col_hosts: "Hosts",
    col_last_activity: "Letzte Aktivität",
    col_new24h: "Neu (24h)",
    btn_details: "Verbindungen",

    conn_title: "Verbindungen",
    conn_intro: "<strong>{n}</strong> bekannte Host-Verbindung(en) zu <code>{ip}</code> (persistente Baseline, überdauert das 30-Tage-NetFlow-Fenster).",
    no_conns: "Noch keine Verbindungen erfasst — der nächste Scan füllt die Daten.",
    conn_failed: "Verbindungen konnten nicht geladen werden",
    col_volume: "Volumen",
    col_first_seen: "Erstmals",
    col_last_seen: "Zuletzt",
};

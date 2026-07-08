// German dictionary for the Firewall Anomalies page. Loaded as a global before js/i18n.js.
window.I18N = window.I18N || {};
window.I18N.de = window.I18N.de || {};
window.I18N.de.fwAnomalies = {
    page_title: "Warroom - FW-Anomalien",

    // topbar controls
    ip_focus_placeholder: "IP-Fokus (optional)",
    ip_focus_title: "Bestimmte IP analysieren — leer = gesamtes Netzwerk",
    role_title: "Rolle: ohne IP-Fokus = Quell- vs. Ziel-IPs analysieren; mit IP-Fokus = Rolle der gewählten IP",
    role_src: "Quelle",
    role_dst: "Ziel",
    range_6h: "6 Stunden",
    range_24h: "24 Stunden",
    range_3d: "3 Tage",
    range_7d: "7 Tage",
    min_flows_title: "Mindestanzahl Flows pro IP",

    // content header
    header_title: "Firewall-Anomalien",
    header_sub: "Isolation Forest · NetFlow · 3 frei wählbare Dimensionen",

    // stat tiles
    stat_analyzed: "Analysierte IPs",
    stat_anomalies: "Anomalien",
    stat_over_threshold: "über Schwelle",
    stat_top_score: "Höchster Score",
    stat_threshold: "Schwelle",
    stat_threshold_sub: "Score ≥ = Anomalie",

    // dimension selector card
    dims_title: "Analyse-Dimensionen",
    dims_title_sub: "— 3 frei wählbar (X · Y · Z)",
    dims_hint: "Wähle die drei Achsen, in deren Raum die Quell-IPs verglichen werden. Der Isolation-Forest-<strong>Score wird aus genau diesen drei Dimensionen berechnet</strong>, und beide Graphen unten zeigen sie als Achsen. Jede Dimension lässt sich nur einmal wählen.",
    axis_x: "Achse X",
    axis_y: "Achse Y",
    axis_z: "Achse Z",

    // dimension display labels
    dim_volume: "Volumen (Bytes)",
    dim_ports: "Ziel-Ports",
    dim_dst_ips: "Ziel-IPs",
    dim_src_ips: "Quell-IPs",
    dim_flows: "Flows",
    dim_packets: "Pakete",
    dim_night: "Tageszeit (Nacht)",
    dim_country: "Land-Seltenheit",

    // Treiber-Chip-Tooltip + kontextuelle Fokus-Beschreibung (interpoliert)
    percentile: "Perzentil {p}%",
    focus_from: "Ziel-IPs, die von {ip} (Quelle) kontaktiert werden",
    focus_to: "Quell-IPs, die {ip} (Ziel) kontaktieren",
    focus_all_src: "Alle Quell-IPs (global)",
    focus_all_dst: "Alle Ziel-IPs (global)",

    // chart titles (interpolated)
    scatter_title: "Bubble: {x} × {y} · Blasengröße = {z} · rot = Anomalie",
    scatter3d_title: "3-D-Ansicht — {x} × {y} × {z} (rot = Anomalie)",
    scatter3d_hint: "Jeder Punkt ist eine IP im Raum der <strong>drei gewählten Dimensionen</strong> (Achse X, Y, Z). <strong>Rote</strong> Punkte sind Anomalien — sie heben sich in diesem Raum vom Normalbereich ab. Mit der Maus <strong>drehen, zoomen</strong> und über Punkte fahren für Details (inkl. Land &amp; Score).",
    legend_normal: "normal",
    legend_anomaly: "Anomalie",

    // anomaly table
    table_title: "Auffälligste Quell-IPs",
    table_hint: "Verglichen werden die <strong id=\"anDimsText\">drei gewählten Dimensionen</strong>. Je höher der Score (0–1), desto leichter isoliert das Modell die IP von der Masse — z. B. Exfil-Hosts mit ungewöhnlichem Volumen, Portscanner oder Quellen aus seltenen Ländern. Die farbigen Chips unter dem Score zeigen die <strong>treibende(n) Dimension(en)</strong> — also worin die IP am stärksten aus der Masse heraussticht (Perzentil-Rang der IP in dieser Dimension). <strong>Klick auf eine Zeile</strong> zeigt alle bekannten Verbindungen (ein- &amp; ausgehend, inkl. geblockter Firewall-Versuche).",
    dims_text: "{x}, {y} und {z}",
    filter_placeholder: "Filter (IP, Land…)",
    peer_hdr_title: "Haupt-Gegenstelle (Top nach Volumen) — Klick auf die Zeile zeigt alle Verbindungen",
    source_ip: "Quell-IP",
    col_volume: "Volumen",
    col_dst_ports: "Ziel-Ports",
    col_dst_ips: "Ziel-IPs",
    col_night: "Nacht",
    col_last_seen: "Zuletzt",

    // table row / cells
    rarity_title: "Seltenheit (höher = ungewöhnlicher)",
    internal: "intern",
    more_peers: "weitere Gegenstellen",
    row_click_title: "Klick: alle Verbindungen anzeigen",
    block: "blocken",

    // refresh / status
    analyzing: "Analysiere…",
    focus_info: "Analyse: {desc} · {n} IPs",
    window_label: "letzte {h} h · NetFlow",
    analysis_failed: "Analyse fehlgeschlagen",
    no_netflow_data: "Keine NetFlow-Daten im Zeitfenster.",

    // analyst verdict (schädlich / unschädlich)
    verdict_col: "Bewertung",
    verdict_comment_col: "Kommentar",
    verdict_set: "Bewerten",
    verdict_malicious: "Schädlich",
    verdict_suspicious: "Verdächtig",
    verdict_benign: "Unschädlich",
    verdict_title: "Anomalie bewerten",
    verdict_edit: "Bewertung bearbeiten",
    verdict_comment_label: "Kommentar",
    verdict_comment_ph: "Optionaler Kommentar…",
    verdict_clear: "Bewertung entfernen",
    verdict_updated: "Zuletzt aktualisiert: {time}",
    verdict_pick: "Bitte „Schädlich\", „Verdächtig\" oder „Unschädlich\" wählen.",
    verdict_failed: "Speichern fehlgeschlagen",

    // block action
    block_confirm: "IP {ip} auf die Blocklist setzen?",
    block_comment: "FW-Anomalie-Dashboard (Isolation Forest / NetFlow)",
    block_done: "✓ geblockt",
    block_failed: "Block fehlgeschlagen",

    // connections modal
    conn_title: "Verbindungen",
    osint_title: "OSINT-Check",
    osint_recheck: "Neu prüfen (Cache umgehen)",
    timeframe: "Zeitfenster",
    win_24h: "24 h",
    win_7d: "7 Tage",
    win_30d: "30 Tage",
    conn_load_failed: "Konnte Verbindungen nicht laden",
    conn_intro: "Alle bekannten Verbindungen der letzten <strong>{days} Tage</strong> für <code>{ip}</code> aus dem NetFlow-Ledger, plus geblockte Firewall-Versuche.",
    netflow_unavailable: "NetFlow nicht verfügbar",
    timeout: "Zeitüberschreitung",
    outbound: "Ausgehend",
    inbound: "Eingehend",
    dest: "Ziel",
    source: "Quelle",
    blocked_fw_attempts: "Geblockte Firewall-Versuche",
    no_netflow_conns: "Keine NetFlow-Verbindungen.",
    truncated: "(gekürzt — nur Top nach Volumen)",
    peers: "Gegenstellen",

    // table headers (connection tables)
    port: "Port",
    proto: "Proto",
    packets: "Pakete",
    first_seen: "Erstmals",
    attempts: "Versuche",
};

// English dictionary for the Firewall Anomalies page. Loaded as a global before js/i18n.js.
window.I18N = window.I18N || {};
window.I18N.en = window.I18N.en || {};
window.I18N.en.fwAnomalies = {
    page_title: "Warroom - FW Anomalies",

    // topbar controls
    ip_focus_placeholder: "IP focus (optional)",
    ip_focus_title: "Analyze a specific IP — empty = entire network",
    role_title: "Role: without IP focus = analyze source vs. destination IPs; with IP focus = role of the selected IP",
    role_src: "Source",
    role_dst: "Destination",
    range_6h: "6 hours",
    range_24h: "24 hours",
    range_3d: "3 days",
    range_7d: "7 days",
    min_flows_title: "Minimum number of flows per IP",

    // content header
    header_title: "Firewall Anomalies",
    header_sub: "Isolation Forest · NetFlow · 3 freely selectable dimensions",

    // stat tiles
    stat_analyzed: "Analyzed IPs",
    stat_anomalies: "Anomalies",
    stat_over_threshold: "above threshold",
    stat_top_score: "Top score",
    stat_threshold: "Threshold",
    stat_threshold_sub: "Score ≥ = anomaly",

    // dimension selector card
    dims_title: "Analysis dimensions",
    dims_title_sub: "— 3 freely selectable (X · Y · Z)",
    dims_hint: "Choose the three axes in whose space the source IPs are compared. The Isolation Forest <strong>score is computed from exactly these three dimensions</strong>, and both charts below plot them as axes. Each dimension can be selected only once.",
    axis_x: "Axis X",
    axis_y: "Axis Y",
    axis_z: "Axis Z",

    // dimension display labels
    dim_volume: "Volume (Bytes)",
    dim_ports: "Destination ports",
    dim_dst_ips: "Destination IPs",
    dim_flows: "Flows",
    dim_packets: "Packets",
    dim_night: "Time of day (night)",
    dim_country: "Country rarity",

    // chart titles (interpolated)
    scatter_title: "Bubble: {x} × {y} · bubble size = {z} · red = anomaly",
    scatter3d_title: "3-D view — {x} × {y} × {z} (red = anomaly)",
    scatter3d_hint: "Each point is an IP in the space of the <strong>three chosen dimensions</strong> (Axis X, Y, Z). <strong>Red</strong> points are anomalies — they stand out from the normal range in this space. Use the mouse to <strong>rotate, zoom</strong> and hover over points for details (incl. country &amp; score).",
    legend_normal: "normal",
    legend_anomaly: "Anomaly",

    // anomaly table
    table_title: "Most notable source IPs",
    table_hint: "The <strong id=\"anDimsText\">three chosen dimensions</strong> are compared. The higher the score (0–1), the more easily the model isolates the IP from the crowd — e.g. exfil hosts with unusual volume, port scanners or sources from rare countries. The coloured chips below the score show the <strong>driving dimension(s)</strong> — i.e. where the IP stands out most from the crowd (the IP's percentile rank in that dimension). <strong>Click a row</strong> to show all known connections (inbound &amp; outbound, incl. blocked firewall attempts).",
    dims_text: "{x}, {y} and {z}",
    filter_placeholder: "Filter (IP, country…)",
    peer_hdr_title: "Main counterpart (top by volume) — click the row to show all connections",
    source_ip: "Source IP",
    col_volume: "Volume",
    col_dst_ports: "Destination ports",
    col_dst_ips: "Destination IPs",
    col_night: "Night",
    col_last_seen: "Last seen",

    // table row / cells
    rarity_title: "Rarity (higher = more unusual)",
    internal: "internal",
    more_peers: "more counterparts",
    row_click_title: "Click: show all connections",
    block: "block",

    // refresh / status
    analyzing: "Analyzing…",
    focus_info: "Analysis: {desc} · {n} IPs",
    window_label: "last {h} h · NetFlow",
    analysis_failed: "Analysis failed",
    no_netflow_data: "No NetFlow data in the time window.",

    // block action
    block_confirm: "Add IP {ip} to the blocklist?",
    block_comment: "FW anomaly dashboard (Isolation Forest / NetFlow)",
    block_done: "✓ blocked",
    block_failed: "Block failed",

    // connections modal
    conn_title: "Connections",
    osint_title: "OSINT check",
    osint_recheck: "Re-check (bypass cache)",
    timeframe: "Time window",
    win_24h: "24 h",
    win_7d: "7 days",
    win_30d: "30 days",
    conn_load_failed: "Could not load connections",
    conn_intro: "All known connections over the last <strong>{days} days</strong> for <code>{ip}</code> from the NetFlow ledger, plus blocked firewall attempts.",
    netflow_unavailable: "NetFlow unavailable",
    timeout: "Timeout",
    outbound: "Outbound",
    inbound: "Inbound",
    dest: "Destination",
    source: "Source",
    blocked_fw_attempts: "Blocked firewall attempts",
    no_netflow_conns: "No NetFlow connections.",
    truncated: "(truncated — top by volume only)",
    peers: "counterparts",

    // table headers (connection tables)
    port: "Port",
    proto: "Proto",
    packets: "Packets",
    first_seen: "First seen",
    attempts: "Attempts",
};

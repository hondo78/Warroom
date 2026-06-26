// German dictionary for the NetFlow page. Loaded as a global before js/i18n.js.
window.I18N = window.I18N || {};
window.I18N.de = window.I18N.de || {};
window.I18N.de.netflow = {
    // header / page
    page_title: "NetFlow",
    all_firewalls: "Alle Firewalls",
    days_1: "24 Stunden",
    days_7: "7 Tage",
    days_30: "30 Tage",

    // stat tiles
    tile_volume: "Volumen",
    tile_flows: "Flows",
    tile_packets: "Pakete",
    tile_total: "gesamt",
    tile_source_ips: "Source-IPs",
    tile_destinations: "Destinations",
    tile_unique: "eindeutig",
    rate_bytes: "{rate}/s im Schnitt",
    rate_flows: "{rate} /min im Schnitt",

    // chart card titles
    bandwidth_title: "Bandbreite (Bytes über Zeit)",
    top_talkers_title: "Top-Talker (Source-IPs nach Bytes)",
    top_destinations_title: "Top-Destinationen nach Bytes",
    top_ports_title: "Top-Ports / Services",
    protocol_mix_title: "Protokoll-Mix",

    // interface utilisation card
    iface_util_title: "Interface-Auslastung",
    edit_names: "Namen bearbeiten",
    iface_hint: "SNMP-Index aus NetFlow-Records. Namen können editiert und werden persistiert.",
    col_interface: "Interface",
    col_bytes_ingress: "Bytes Ingress",
    col_bytes_egress: "Bytes Egress",
    col_mbps_in: "Ø Mbps In",
    col_mbps_out: "Ø Mbps Out",
    col_flows_in_out: "Flows In/Out",
    no_iface_data: "Keine Interface-Daten. NetFlow-Export muss INPUT_SNMP / OUTPUT_SNMP enthalten (Standard bei v9).",

    // map + top flows
    dest_map_title: "Destination-Karte (wo gehen die Bytes hin)",
    top_flows_title: "Top-Flows",
    filter_placeholder: "Filter (IP, Port, Service…)",
    group_none: "Gruppierung: keine (5-Tuple)",
    group_src: "Quell-IP",
    group_dst: "Ziel-IP",
    group_src_dst: "Quelle → Ziel",
    group_port: "Port + Protokoll",
    group_proto: "Protokoll",
    minbytes_none: "Min. Bytes: keine",
    limit_rows: "50 Zeilen",
    unexpected_response: "Unerwartete Server-Antwort (keine Liste).",
    no_data_selection: "Keine Daten für die aktuelle Auswahl.",

    // flows table columns
    col_port: "Port",
    col_service: "Service",
    col_protocol: "Protokoll",
    col_bytes: "Bytes",
    col_packets: "Pakete",
    col_flows: "Flows",
    col_org: "Org",
    col_proto_num: "Proto-Nr",

    // iface-name editor modal
    iface_modal_title: "Firewall- und Interface-Namen",
    iface_modal_fw_hint: "<strong>Firewall-Hostnamen</strong> — pro Zeile: <code>firewall_ip Hostname</code><br>Beispiel: <code>10.0.1.1 HQ Firewall</code>",
    iface_modal_iface_hint: "<strong>Interface-Namen</strong> — pro Zeile: <code>firewall_ip iface_idx Name</code><br>Beispiel: <code>10.0.1.1 7 WAN</code>. Aktuell beobachtete Indizes stehen in der Tabelle oben.",
    cancel: "Abbrechen",
    save: "Speichern",
    save_failed: "Speichern fehlgeschlagen: {error}",

    // OSINT modal
    osint_title: "OSINT-Check",
    osint_recheck: "Neu prüfen (Cache umgehen)",
};

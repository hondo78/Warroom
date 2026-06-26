// English dictionary for the NetFlow page. Loaded as a global before js/i18n.js.
window.I18N = window.I18N || {};
window.I18N.en = window.I18N.en || {};
window.I18N.en.netflow = {
    // header / page
    page_title: "NetFlow",
    all_firewalls: "All firewalls",
    days_1: "24 hours",
    days_7: "7 days",
    days_30: "30 days",

    // stat tiles
    tile_volume: "Volume",
    tile_flows: "Flows",
    tile_packets: "Packets",
    tile_total: "total",
    tile_source_ips: "Source IPs",
    tile_destinations: "Destinations",
    tile_unique: "unique",
    rate_bytes: "{rate}/s on average",
    rate_flows: "{rate} /min on average",

    // chart card titles
    bandwidth_title: "Bandwidth (bytes over time)",
    top_talkers_title: "Top talkers (source IPs by bytes)",
    top_destinations_title: "Top destinations by bytes",
    top_ports_title: "Top ports / services",
    protocol_mix_title: "Protocol mix",

    // interface utilisation card
    iface_util_title: "Interface utilisation",
    edit_names: "Edit names",
    iface_hint: "SNMP index from NetFlow records. Names can be edited and are persisted.",
    col_interface: "Interface",
    col_bytes_ingress: "Bytes ingress",
    col_bytes_egress: "Bytes egress",
    col_mbps_in: "Ø Mbps in",
    col_mbps_out: "Ø Mbps out",
    col_flows_in_out: "Flows in/out",
    no_iface_data: "No interface data. NetFlow export must include INPUT_SNMP / OUTPUT_SNMP (default in v9).",

    // map + top flows
    dest_map_title: "Destination map (where the bytes go)",
    top_flows_title: "Top flows",
    filter_placeholder: "Filter (IP, port, service…)",
    group_none: "Grouping: none (5-tuple)",
    group_src: "Source IP",
    group_dst: "Destination IP",
    group_src_dst: "Source → destination",
    group_port: "Port + protocol",
    group_proto: "Protocol",
    minbytes_none: "Min. bytes: none",
    limit_rows: "50 rows",
    unexpected_response: "Unexpected server response (not a list).",
    no_data_selection: "No data for the current selection.",

    // flows table columns
    col_port: "Port",
    col_service: "Service",
    col_protocol: "Protocol",
    col_bytes: "Bytes",
    col_packets: "Packets",
    col_flows: "Flows",
    col_org: "Org",
    col_proto_num: "Proto no.",

    // iface-name editor modal
    iface_modal_title: "Firewall and interface names",
    iface_modal_fw_hint: "<strong>Firewall hostnames</strong> — one per line: <code>firewall_ip hostname</code><br>Example: <code>10.0.1.1 HQ Firewall</code>",
    iface_modal_iface_hint: "<strong>Interface names</strong> — one per line: <code>firewall_ip iface_idx name</code><br>Example: <code>10.0.1.1 7 WAN</code>. Currently observed indices are listed in the table above.",
    cancel: "Cancel",
    save: "Save",
    save_failed: "Save failed: {error}",

    // OSINT modal
    osint_title: "OSINT check",
    osint_recheck: "Re-check (bypass cache)",
};

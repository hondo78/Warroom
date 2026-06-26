// English dictionary for the Endpoints page. Loaded as a global before js/i18n.js.
window.I18N = window.I18N || {};
window.I18N.en = window.I18N.en || {};
window.I18N.en.endpoints = {
    page_title: "Endpoint Management — Sophos Central",

    // dashboard stat boxes
    stat_endpoints: "Endpoints",
    stat_endpoints_sub: "managed devices",
    stat_online: "Online",
    stat_online_sub: "currently connected",
    stat_bad: "Health “bad”",
    stat_bad_sub: "needs attention",
    stat_isolated: "Isolated",
    stat_isolated_sub: "disconnected from network",

    // tabs
    tab_inventory: "Inventory",
    tab_groups: "Groups",
    tab_policies: "Policies",
    tab_settings: "Settings",
    tab_exploits: "Exploits",
    tab_downloads: "Downloads / Installer",

    // inventory
    device_inventory: "Device Inventory",
    search_hostname: "Search hostname — Enter",
    all_health: "All Health",
    all_isolation: "All Isolation",
    isolated: "isolated",
    not_isolated: "not isolated",
    no: "no",
    no_endpoints: "No endpoints. Check Sophos Central credentials or run the collector.",

    // table columns
    col_hostname: "Hostname",
    col_type: "Type",
    col_os: "OS",
    col_ipv4: "IPv4",
    col_health: "Health",
    col_isolation: "Isolation",
    col_tamper: "Tamper",
    col_last_seen: "Last Seen",
    col_name: "Name",
    col_endpoints: "Endpoints",
    col_created: "Created",
    col_priority: "Priority",
    col_locked: "locked",
    col_description: "Description",
    col_count: "Count",
    col_thumbprint: "Thumbprint",
    col_value: "Value",
    col_comment: "Comment",
    col_scan_mode: "Scan Mode",

    // row badges / action titles
    threats: "Threats",
    services: "Services",
    online: "online",
    tamper_on: "Tamper Protection on",
    tamper_off: "Tamper Protection off",
    details: "Details",
    lift_isolation: "Lift isolation",
    isolate: "Isolate",
    start_scan: "Start scan",
    remove_from_sophos: "Remove from Sophos",

    // detail modal
    loading_live: "Loading live data…",
    health_overall: "Health overall",
    threats_services: "Threats / Services",
    tamper_protection: "Tamper Protection",
    raw_json: "Raw JSON",
    error: "Error",

    // isolation / scan / delete actions
    action_failed: "{verb} failed: {msg}",
    scan_confirm: "Start an on-demand scan on this endpoint?",
    scan_started: "Scan triggered.",
    scan_failed: "Scan failed: {msg}",
    delete_confirm: "Remove endpoint \"{name}\" from Sophos Central?\nThe device will be de-registered (affects the live tenant).",
    remove_failed: "Removal failed: {msg}",

    // downloads
    loading_installers: "Loading installers…",
    downloads_unavailable: "Downloads currently unavailable",
    no_installers: "No installers.",
    download: "Download",
    no_link: "no link",

    // groups
    open_tab_to_load: "Open tab to load…",
    endpoint_groups: "Endpoint Groups",
    new_group: "New group…",
    create: "Create",
    no_groups: "No groups.",
    clients: "Clients",
    no_type: "(no type)",
    name_required: "Name required.",
    create_failed: "Create failed: {msg}",
    delete_group_confirm: "Delete group \"{name}\"?",
    delete_failed: "Delete failed: {msg}",

    // policies
    policies_title: "Policies",
    no_policies: "No policies.",
    endpoint_policies_clients: "Endpoint Policies (Clients)",
    server_policies: "Server Policies",

    // exploits
    detected_exploits_title: "Detected Exploits (Exploit Mitigation)",
    exploits_hint: "Detections by Exploit Mitigation (CryptoGuard / WipeGuard / Exploit Blocks). Source: <code>/endpoint/v1/settings/exploit-mitigation/detected-exploits</code>.",
    no_exploits: "No detected exploits.",

    // settings (tamper + collections)
    tamper_global: "Tamper Protection (global)",
    enabled: "enabled",
    disabled: "disabled",
    unavailable: "unavailable",
    change_failed: "Change failed: {msg}",

    allowed_items_title: "Allowed Items (Allow List)",
    blocked_items_title: "Blocked Items (Block List)",
    exclusions_title: "Scan Exclusions",
    local_sites_title: "Web Control — Local Sites",
    ph_value_allow: "Value (SHA256 / Signer / Path)",
    ph_value_block: "Value (SHA256 / Signer)",
    ph_path_process: "Path / Process",
    ph_url: "URL / Domain / IP",
    ph_tags: "Tags (comma)",
    add_item: "Add",
    no_entries: "No entries.",
    enter_values: "Please enter values.",
    add_failed: "Add failed: {msg}",
    delete_entry_confirm: "Delete entry?",

    // installer packages card
    installer_packages: "Installer Packages",
};

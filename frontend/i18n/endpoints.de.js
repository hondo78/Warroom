// German dictionary for the Endpoints page. Loaded as a global before js/i18n.js.
window.I18N = window.I18N || {};
window.I18N.de = window.I18N.de || {};
window.I18N.de.endpoints = {
    page_title: "Endpoint-Verwaltung — Sophos Central",

    // dashboard stat boxes
    stat_endpoints: "Endpoints",
    stat_endpoints_sub: "verwaltete Geräte",
    stat_online: "Online",
    stat_online_sub: "aktuell verbunden",
    stat_bad: "Health „bad“",
    stat_bad_sub: "Handlungsbedarf",
    stat_isolated: "Isoliert",
    stat_isolated_sub: "vom Netz getrennt",

    // tabs
    tab_inventory: "Inventar",
    tab_groups: "Gruppen",
    tab_policies: "Policies",
    tab_settings: "Einstellungen",
    tab_exploits: "Exploits",
    tab_downloads: "Downloads / Installer",

    // inventory
    device_inventory: "Geräte-Inventar",
    search_hostname: "Hostname suchen — Enter",
    all_health: "Alle Health",
    all_isolation: "Alle Isolation",
    isolated: "isoliert",
    not_isolated: "nicht isoliert",
    no: "nein",
    no_endpoints: "Keine Endpoints. Sophos-Central-Credentials prüfen oder Collector laufen lassen.",

    // table columns
    col_hostname: "Hostname",
    col_type: "Typ",
    col_os: "OS",
    col_ipv4: "IPv4",
    col_health: "Health",
    col_isolation: "Isolation",
    col_tamper: "Tamper",
    col_last_seen: "Zuletzt",
    col_name: "Name",
    col_endpoints: "Endpoints",
    col_created: "Erstellt",
    col_priority: "Priorität",
    col_locked: "gesperrt",
    col_description: "Beschreibung",
    col_count: "Anzahl",
    col_thumbprint: "Thumbprint",
    col_value: "Wert",
    col_comment: "Kommentar",
    col_scan_mode: "Scan-Modus",

    // row badges / action titles
    threats: "Threats",
    services: "Services",
    online: "online",
    tamper_on: "Tamper Protection an",
    tamper_off: "Tamper Protection aus",
    details: "Details",
    lift_isolation: "Isolation aufheben",
    isolate: "Isolieren",
    start_scan: "Scan starten",
    remove_from_sophos: "Aus Sophos entfernen",

    // detail modal
    loading_live: "Lade Live-Daten…",
    health_overall: "Health gesamt",
    threats_services: "Threats / Services",
    tamper_protection: "Tamper Protection",
    raw_json: "Roh-JSON",
    error: "Fehler",

    // isolation / scan / delete actions
    action_failed: "{verb} fehlgeschlagen: {msg}",
    scan_confirm: "On-Demand-Scan auf diesem Endpoint starten?",
    scan_started: "Scan angestoßen.",
    scan_failed: "Scan fehlgeschlagen: {msg}",
    delete_confirm: "Endpoint \"{name}\" aus Sophos Central entfernen?\nDas Gerät wird de-registriert (wirkt auf den Live-Tenant).",
    remove_failed: "Entfernen fehlgeschlagen: {msg}",

    // downloads
    loading_installers: "Lade Installer…",
    downloads_unavailable: "Downloads aktuell nicht verfügbar",
    no_installers: "Keine Installer.",
    download: "Download",
    no_link: "kein Link",

    // groups
    open_tab_to_load: "Tab öffnen zum Laden…",
    endpoint_groups: "Endpoint-Gruppen",
    new_group: "Neue Gruppe…",
    create: "Anlegen",
    no_groups: "Keine Gruppen.",
    clients: "Clients",
    no_type: "(ohne Typ)",
    name_required: "Name erforderlich.",
    create_failed: "Anlegen fehlgeschlagen: {msg}",
    delete_group_confirm: "Gruppe \"{name}\" löschen?",
    delete_failed: "Löschen fehlgeschlagen: {msg}",

    // policies
    policies_title: "Richtlinien (Policies)",
    no_policies: "Keine Policies.",
    endpoint_policies_clients: "Endpoint-Policies (Clients)",
    server_policies: "Server-Policies",

    // exploits
    detected_exploits_title: "Erkannte Exploits (Exploit-Mitigation)",
    exploits_hint: "Erkennungen durch Exploit-Mitigation (CryptoGuard / WipeGuard / Exploit-Blocks). Quelle: <code>/endpoint/v1/settings/exploit-mitigation/detected-exploits</code>.",
    no_exploits: "Keine erkannten Exploits.",

    // settings (tamper + collections)
    tamper_global: "Tamper-Protection (global)",
    enabled: "aktiviert",
    disabled: "deaktiviert",
    unavailable: "nicht verfügbar",
    change_failed: "Änderung fehlgeschlagen: {msg}",

    allowed_items_title: "Erlaubte Objekte (Allow-Liste)",
    blocked_items_title: "Blockierte Objekte (Block-Liste)",
    exclusions_title: "Scan-Ausschlüsse",
    local_sites_title: "Web-Control — lokale Sites",
    ph_value_allow: "Wert (SHA256 / Signer / Pfad)",
    ph_value_block: "Wert (SHA256 / Signer)",
    ph_path_process: "Pfad / Prozess",
    ph_url: "URL / Domain / IP",
    ph_tags: "Tags (Komma)",
    add_item: "Hinzufügen",
    no_entries: "Keine Einträge.",
    enter_values: "Bitte Werte eingeben.",
    add_failed: "Hinzufügen fehlgeschlagen: {msg}",
    delete_entry_confirm: "Eintrag löschen?",

    // installer packages card
    installer_packages: "Installer-Pakete",
};

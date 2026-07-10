window.I18N = window.I18N || {}; window.I18N.de = window.I18N.de || {};
window.I18N.de.o365 = {
    page_title: "☁️ Microsoft 365 — Login-Audit",

    range_24h: "24 Stunden",
    range_7d: "7 Tage",
    range_30d: "30 Tage",
    range_90d: "90 Tage",

    status_all: "Alle Logins",
    status_failed: "Nur fehlgeschlagen",
    status_success: "Nur erfolgreich",

    not_configured: "<strong>Nicht konfiguriert.</strong> Hinterlege Tenant-ID, Client-ID und Client-Secret der Entra-ID-App-Registrierung (Berechtigung <code>ActivityFeed.Read</code> auf den Office 365 Management APIs, Application + Admin-Consent) unter <a href=\"/admin.html\">Admin</a>. Der Collector startet danach automatisch.",

    stat_total: "Logins gesamt",
    stat_total_sub: "im gewählten Zeitraum",
    stat_failed: "Fehlgeschlagen",
    stat_users: "Benutzer",
    stat_users_sub: "eindeutige UPNs",
    stat_ips: "Quell-IPs",
    stat_ips_sub: "eindeutige Adressen",

    login_events: "Login-Ereignisse",
    quick_filter: "Schnellfilter über alle Spalten…",
    filter: "filtern…",
    sort: "Sortieren",

    col_user: "Benutzer",
    col_result: "Ergebnis",
    col_app: "App",
    col_device: "Gerät",
    col_ip: "IP",
    col_location: "Standort",
    col_error: "Fehler",

    top_failed_users: "Top fehlgeschlagene Benutzer",
    top_countries: "Top Herkunftsländer",

    osint_check: "OSINT-Check",
    recheck: "Neu prüfen (Cache umgehen)",

    no_failures: "Keine Fehlversuche",
    no_geo: "Keine Geo-Daten",
    no_events: "Keine Login-Ereignisse (Filter aktiv?).",

    unknown: "Unbekannt",
    compliant: "Compliant (verwaltet)",
    noncompliant: "Nicht compliant / nicht verwaltet",
    whitelisted_tip: "IP ist whitelisted — Block nicht möglich",
    block_tip: "IP blockieren",

    confirm_block: "IP {ip} auf die Blockliste setzen?",
    block_failed: "Block fehlgeschlagen:",

    // login watch (new device / location + session revoke)
    watch_title: "Login-Überwachung — neue Geräte & Standorte",
    watch_hint: "Meldet jede erfolgreiche Anmeldung von einem <strong>neuen Gerät</strong> oder aus einem <strong>neuen Land</strong> (Baseline pro Benutzer) — per Telegram (mit Freigabe-Buttons) bzw. Teams. <strong>Freigeben = alle Sessions des Benutzers widerrufen</strong> (erneute Anmeldung überall nötig).",
    watch_run_now: "Jetzt prüfen",
    watch_active: "Aktiv",
    watch_inactive: "Inaktiv",
    watch_not_seeded: "Baseline noch nicht aufgebaut",
    watch_alerts: "Alarme (neues Gerät / neuer Standort)",
    watch_profiles: "Bekannte Geräte & Standorte pro Benutzer",
    watch_col_new: "Neu",
    watch_col_devices: "Geräte",
    watch_col_locations: "Standorte",
    watch_new_device: "Neues Gerät",
    watch_new_location: "Neuer Standort",
    watch_no_alerts: "Keine Alarme — alle Anmeldungen kamen von bekannten Geräten/Standorten.",
    watch_no_profiles: "Noch keine Baseline. \"Jetzt prüfen\" klicken, um sie aus der Login-Historie aufzubauen (ohne Alarme).",
    watch_btn_revoke: "Sessions widerrufen",
    watch_btn_retry: "Erneut versuchen",
    watch_btn_dismiss: "Verwerfen",
    watch_revoked: "widerrufen",
    watch_seen: "{n}× gesehen · zuletzt {last}",
    watch_confirm_revoke: "ALLE Sessions von {user} widerrufen? Der Benutzer muss sich überall neu anmelden.",
    watch_confirm_revoke_decision: "Freigeben widerruft ALLE Sessions dieses Benutzers. Fortfahren?",
    watch_action_failed: "Aktion fehlgeschlagen",
    watch_seeded: "Baseline aufgebaut: {n} Profile aus der Login-Historie übernommen (ohne Alarme).",
};

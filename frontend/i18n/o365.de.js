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
};

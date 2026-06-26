window.I18N = window.I18N || {}; window.I18N.en = window.I18N.en || {};
window.I18N.en.o365 = {
    page_title: "☁️ Microsoft 365 — Login Audit",

    range_24h: "24 hours",
    range_7d: "7 days",
    range_30d: "30 days",
    range_90d: "90 days",

    status_all: "All logins",
    status_failed: "Failed only",
    status_success: "Successful only",

    not_configured: "<strong>Not configured.</strong> Enter the tenant ID, client ID and client secret of the Entra ID app registration (permission <code>ActivityFeed.Read</code> on the Office 365 Management APIs, Application + admin consent) under <a href=\"/admin.html\">Admin</a>. The collector starts automatically afterwards.",

    stat_total: "Total logins",
    stat_total_sub: "in the selected period",
    stat_failed: "Failed",
    stat_users: "Users",
    stat_users_sub: "unique UPNs",
    stat_ips: "Source IPs",
    stat_ips_sub: "unique addresses",

    login_events: "Login events",
    quick_filter: "Quick filter across all columns…",
    filter: "filter…",
    sort: "Sort",

    col_user: "User",
    col_result: "Result",
    col_app: "App",
    col_device: "Device",
    col_ip: "IP",
    col_location: "Location",
    col_error: "Error",

    top_failed_users: "Top failed users",
    top_countries: "Top source countries",

    osint_check: "OSINT check",
    recheck: "Re-check (bypass cache)",

    no_failures: "No failed attempts",
    no_geo: "No geo data",
    no_events: "No login events (filter active?).",

    unknown: "Unknown",
    compliant: "Compliant (managed)",
    noncompliant: "Not compliant / not managed",
    whitelisted_tip: "IP is whitelisted — block not possible",
    block_tip: "Block IP",

    confirm_block: "Add IP {ip} to the blocklist?",
    block_failed: "Block failed:",
};

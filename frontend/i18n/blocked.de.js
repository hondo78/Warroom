// German dictionary for the Blocklist page. Extends window.I18N.de.
window.I18N = window.I18N || {};
window.I18N.de = window.I18N.de || {};
window.I18N.de.blocked = {
    title: "Blocklist",
    blocked_ips: "Geblockte IPs",
    blocked_domains: "Geblockte Domains",
    blocked_urls: "Geblockte URLs",
    last_block: "Letzter Block",
    tab_whitelist: "Whitelist",

    hint_ip: "Die Liste wird live unter <code id=\"iocFeedUrlIp\">/ioc_IP</code> als TXT bereitgestellt (Header <code>X-API-Key</code> erforderlich).",
    hint_domain: "Die Liste wird live unter <code id=\"iocFeedUrlDomain\">/ioc_domain</code> als TXT bereitgestellt. Nur reine Hostnamen — Wildcards <code>*.domain.tld</code> erlaubt. URLs gehören in den URL-Tab.",
    hint_url: "Die Liste wird live unter <code id=\"iocFeedUrlUrl\">/ioc_url</code> als TXT bereitgestellt. Vollständige URLs inkl. <code>http(s)://</code> und Pfad.",
    hint_whitelist: "IPs auf der Whitelist können <strong>niemals</strong> geblockt werden — weder manuell, noch durch den Agent, noch über Bulk-Block. Die \"Auto-Refresh\"-Funktion zieht die IPs aller bekannten Firewalls (firewall_locations, firewall_logs, NetFlow-Exporter, Sophos-API) automatisch hier rein. Manuell hinzugefügte Einträge bleiben dauerhaft erhalten — Auto-Einträge werden bei jedem Refresh aktualisiert.",

    ph_ip: "IP-Adresse (z.B. 203.0.113.1)",
    ph_domain: "Hostname (z.B. evil.example.com oder *.adsrv.net)",
    ph_url: "URL (z.B. https://evil.example.com/phish?id=1)",
    ph_comment: "Kommentar (optional)",
    ph_whitelist_ip: "IP-Adresse (manuell, z.B. 10.0.1.1)",
    ph_whitelist_comment: "Kommentar (z.B. HQ Firewall WAN)",

    filter_ip: "Liste filtern (IP, Kommentar…)",
    filter_domain: "Liste filtern (Domain, Kommentar…)",
    filter_url: "Liste filtern (URL, Kommentar…)",
    filter_whitelist: "Filter (IP, Quelle, Kommentar…)",

    btn_block_ip: "IP blocken",
    btn_block_domain: "Domain blocken",
    btn_block_url: "URL blocken",
    btn_whitelist_ip: "IP whitelisten",
    btn_auto_refresh: "Auto-Refresh aus Firewall-API",
    btn_unblock: "Unblock",
    btn_remove: "Entfernen",

    col_comment: "Kommentar",
    col_blocked: "Geblockt",
    col_source: "Quelle",
    col_added: "Hinzugefügt",

    empty_ips: "Keine geblockten IPs",
    empty_domains: "Keine geblockten Domains",
    empty_urls: "Keine geblockten URLs",
    empty_whitelist: "Keine Whitelist-Einträge — auf \"Auto-Refresh\" klicken um Firewall-IPs zu importieren",

    osint_title: "OSINT-Check",
    osint_recheck: "Neu prüfen (Cache umgehen)",

    alert_enter_ip: "Bitte IP angeben",
    alert_enter_domain: "Bitte Domain oder URL angeben",
    alert_enter_url: "Bitte URL angeben",

    confirm_unblock_ip: "IP {ip} aus Blocklist entfernen?",
    confirm_unblock_domain: "Domain {domain} aus Blocklist entfernen?",
    confirm_unblock_url: "URL {url} aus Blocklist entfernen?",
    confirm_whitelist_remove: "IP {ip} von der Whitelist entfernen? Sie kann danach wieder geblockt werden.",

    err_block_failed: "Block fehlgeschlagen: ",
    err_unblock_failed: "Unblock fehlgeschlagen: ",
    err_whitelist_failed: "Whitelist fehlgeschlagen: ",
    err_refresh_failed: "Refresh fehlgeschlagen: ",
    err_generic: "Fehler: ",

    refresh_done: "Auto-Refresh fertig:\n+ {added} neu\n· {refreshed} aktualisiert\n− {stale} verstaut",
    refresh_removed_from_blocklist: "⚠ {n} IPs aus Blocklist entfernt",
};

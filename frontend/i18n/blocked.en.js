// English dictionary for the Blocklist page. Extends window.I18N.en.
window.I18N = window.I18N || {};
window.I18N.en = window.I18N.en || {};
window.I18N.en.blocked = {
    title: "Blocklist",
    blocked_ips: "Blocked IPs",
    blocked_domains: "Blocked Domains",
    blocked_urls: "Blocked URLs",
    last_block: "Last Block",
    tab_whitelist: "Whitelist",

    hint_ip: "The list is served live as TXT at <code id=\"iocFeedUrlIp\">/ioc_IP</code> (header <code>X-API-Key</code> required).",
    hint_domain: "The list is served live as TXT at <code id=\"iocFeedUrlDomain\">/ioc_domain</code>. Hostnames only — wildcards <code>*.domain.tld</code> allowed. URLs belong in the URL tab.",
    hint_url: "The list is served live as TXT at <code id=\"iocFeedUrlUrl\">/ioc_url</code>. Full URLs including <code>http(s)://</code> and path.",
    hint_whitelist: "IPs on the whitelist can <strong>never</strong> be blocked — neither manually, nor by the agent, nor via bulk block. The \"Auto-Refresh\" function automatically pulls in the IPs of all known firewalls (firewall_locations, firewall_logs, NetFlow exporter, Sophos API). Manually added entries persist permanently — auto entries are updated on every refresh.",

    ph_ip: "IP address (e.g. 203.0.113.1)",
    ph_domain: "Hostname (e.g. evil.example.com or *.adsrv.net)",
    ph_url: "URL (e.g. https://evil.example.com/phish?id=1)",
    ph_comment: "Comment (optional)",
    ph_whitelist_ip: "IP address (manual, e.g. 10.0.1.1)",
    ph_whitelist_comment: "Comment (e.g. HQ Firewall WAN)",

    filter_ip: "Filter list (IP, comment…)",
    filter_domain: "Filter list (domain, comment…)",
    filter_url: "Filter list (URL, comment…)",
    filter_whitelist: "Filter (IP, source, comment…)",

    btn_block_ip: "Block IP",
    btn_block_domain: "Block Domain",
    btn_block_url: "Block URL",
    btn_whitelist_ip: "Whitelist IP",
    btn_auto_refresh: "Auto-Refresh from Firewall API",
    btn_unblock: "Unblock",
    btn_remove: "Remove",

    col_comment: "Comment",
    col_blocked: "Blocked",
    col_source: "Source",
    col_added: "Added",

    empty_ips: "No blocked IPs",
    empty_domains: "No blocked domains",
    empty_urls: "No blocked URLs",
    empty_whitelist: "No whitelist entries — click \"Auto-Refresh\" to import firewall IPs",

    osint_title: "OSINT Check",
    osint_recheck: "Re-check (bypass cache)",

    alert_enter_ip: "Please enter an IP",
    alert_enter_domain: "Please enter a domain or URL",
    alert_enter_url: "Please enter a URL",

    confirm_unblock_ip: "Remove IP {ip} from the blocklist?",
    confirm_unblock_domain: "Remove domain {domain} from the blocklist?",
    confirm_unblock_url: "Remove URL {url} from the blocklist?",
    confirm_whitelist_remove: "Remove IP {ip} from the whitelist? It can be blocked again afterwards.",

    err_block_failed: "Block failed: ",
    err_unblock_failed: "Unblock failed: ",
    err_whitelist_failed: "Whitelist failed: ",
    err_refresh_failed: "Refresh failed: ",
    err_generic: "Error: ",

    refresh_done: "Auto-Refresh done:\n+ {added} new\n· {refreshed} updated\n− {stale} pruned",
    refresh_removed_from_blocklist: "⚠ {n} IPs removed from blocklist",
};

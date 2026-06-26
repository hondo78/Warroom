window.I18N = window.I18N || {}; window.I18N.de = window.I18N.de || {};
window.I18N.de.firewalls = {
    // header
    whitelistAutoFill: "Whitelist auto-fill",
    pageTitle: "🔥 Firewalls — Übersicht",

    // stat boxes
    statKnownFirewalls: "Bekannte Firewalls",
    statKnownFirewallsHint: "nach Name gruppiert",
    statWhitelistedIps: "IPs auf Whitelist",
    statWhitelistedIpsHint: "vor Self-Block geschützt",
    statInterfaces: "Interfaces (∑)",
    statInterfacesHint: "NetFlow Exporter-Indizes",
    statLogs: "Logs (∑)",
    statLogsHint: "aus firewall_logs",

    // firewall list card
    firewallList: "Firewall-Liste",
    filterPlaceholder: "Filter (Name, IP, Land, Stadt…)",
    colIpsKnown: "IPs (bekannt)",
    colLocation: "Standort",
    colInterfaces: "Interfaces",
    colLogs: "Logs ∑",
    colLastLog: "Letzter Log",
    colLastFlow: "Letzter Flow",
    colWhitelist: "Whitelist",
    colActions: "Aktionen",

    // interfaces card
    interfaces: "Interfaces",
    colIndex: "Index",
    colName: "Name",
    colBytesIn: "Bytes In",
    colBytesOut: "Bytes Out",
    colFlowsIn: "Flows In",
    colFlowsOut: "Flows Out",
    colLastActive: "Zuletzt aktiv",

    // table cell content / labels
    tipWhitelisted: "whitelisted",
    tipNotWhitelisted: "nicht whitelisted",
    tipWhitelistThisIp: "diese IP whitelisten",
    wlAll: "alle",
    wlNone: "keine",
    whitelistAll: "Alle whitelisten",
    removeLocation: "Standort entfernen",
    unnamed: "(ohne Namen)",
    whitelist: "Whitelist",

    // empty states
    emptyFirewalls: "Keine bekannten Firewalls. Sophos-Syslog konfigurieren (Port 5514) oder einen Standort über /index.html hinzufügen.",
    emptyInterfaces: "Keine NetFlow-Interface-Daten in den letzten 24h.",

    // confirms / alerts
    confirmWhitelistAll: "Alle {count} IP(s) von \"{name}\" whitelisten?",
    confirmDeleteLocation: "Firewall-Standort \"{label}\" entfernen?\nHinweis: Wenn die Firewall weiter Syslog/NetFlow sendet, taucht sie über die Quellen erneut auf.",
    whitelistFailed: "Whitelist fehlgeschlagen: {error}",
    interfaceListFailed: "Interface-Liste fehlgeschlagen: {error}",
    removeFailed: "Entfernen fehlgeschlagen: {error}",
    refreshFailed: "Refresh fehlgeschlagen: {error}",
    whitelistUpdated: "Whitelist aktualisiert:\n+ {added} neu\n· {refreshed} aktualisiert\n− {removed} alte Auto-Einträge entfernt",
    whitelistRescued: "⚠ {count} IPs aus Blocklist gerettet",
};

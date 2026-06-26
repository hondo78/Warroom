window.I18N = window.I18N || {}; window.I18N.de = window.I18N.de || {};
window.I18N.de.email = {
    page_title: "✉️ Email Management — Sophos Central",
    unavailable_title: "Email Management API nicht erreichbar.",
    unavailable_hint: "Diese Seite nutzt die in <a href=\"/admin.html\" class=\"alert-link\">Admin</a> hinterlegten Sophos-Central-Zugangsdaten. Eine <code>404</code> bedeutet meist, dass der Tenant keine Email-Security-Lizenz hat.",

    stat_mailboxes: "Mailboxen",
    stat_mailboxes_sub: "verwaltete Postfächer",
    stat_quarantine: "Quarantäne",
    stat_quarantine_sub: "Nachrichten im Zeitfenster",
    stat_postdelivery: "Post-Delivery",
    stat_postdelivery_sub: "nachträglich isoliert",
    stat_selected: "Ausgewählt",
    stat_selected_sub: "für Bulk-Aktionen",

    mailbox_management: "Mailbox-Verwaltung",
    new_mailbox: "Neue Mailbox",
    edit_mailbox: "Mailbox bearbeiten",
    search_mailbox: "Suche (E-Mail, Name…) — Enter",
    search_quarantine: "Suche (Absender, Betreff…) — Enter",

    last_24h: "Letzte 24 h",
    last_7d: "Letzte 7 Tage",
    last_30d: "Letzte 30 Tage",

    col_email: "E-Mail",
    col_displayname: "Anzeigename",
    col_type: "Typ",
    col_domain: "Domain",
    col_received: "Empfangen",
    col_recipient: "Empfänger",

    open_tab_load: "Tab öffnen zum Laden…",
    postdelivery_quarantine: "Post-Delivery Quarantäne",
    release: "Freigeben",

    detail: "Detail",
    details: "Details",
    message: "Nachricht",
    attachments: "Anhänge",
    attachments_count: "{count} Anhang/Anhänge",
    no_subject: "(kein Betreff)",

    email_address: "E-Mail-Adresse",
    mailbox_hint: "Felder werden 1:1 an die Sophos Mailbox-API übergeben. Pflichtfelder hängen von der Tenant-Konfiguration ab.",

    api_unreachable: "API: nicht erreichbar",
    api_unreachable_full: "Email-API nicht erreichbar.",
    no_mailboxes: "Keine Mailboxen gefunden.",
    no_messages: "Keine Nachrichten im Zeitfenster.",
    status_blocked: "blockiert",
    status_active: "aktiv",

    email_required: "E-Mail-Adresse erforderlich.",
    save_failed: "Speichern fehlgeschlagen:",
    delete_failed: "Löschen fehlgeschlagen:",
    no_mailbox_id: "Keine Mailbox-ID im Datensatz.",
    no_message_id: "Keine Message-ID.",
    confirm_delete_mailbox: "Mailbox \"{email}\" wirklich löschen?\nDiese Aktion wirkt direkt auf den Sophos-Tenant.",

    no_messages_selected: "Keine Nachrichten ausgewählt.",
    confirm_release_many: "{count} Nachricht(en) freigeben.\n\n[OK] = Absender zusätzlich auf Allow-Liste setzen\n[Abbrechen] = nur freigeben",
    confirm_delete_many: "{count} Nachricht(en) endgültig löschen?\nDiese Aktion wirkt direkt auf den Sophos-Tenant.",
    confirm_release_one: "Nachricht freigeben.\n[OK] = Absender auch erlauben  ·  [Abbrechen] = nur freigeben",
    confirm_delete_one: "Nachricht endgültig löschen?",
    confirm_block_sender: "Absender zusätzlich auf Block-Liste setzen?\n[OK] = ja  ·  [Abbrechen] = nur löschen",
    action_failed: "Aktion \"{action}\" fehlgeschlagen:",
};

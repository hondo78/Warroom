window.I18N = window.I18N || {}; window.I18N.en = window.I18N.en || {};
window.I18N.en.email = {
    page_title: "✉️ Email Management — Sophos Central",
    unavailable_title: "Email Management API unreachable.",
    unavailable_hint: "This page uses the Sophos Central credentials stored in <a href=\"/admin.html\" class=\"alert-link\">Admin</a>. A <code>404</code> usually means the tenant has no Email Security license.",

    stat_mailboxes: "Mailboxes",
    stat_mailboxes_sub: "managed mailboxes",
    stat_quarantine: "Quarantine",
    stat_quarantine_sub: "messages in time window",
    stat_postdelivery: "Post-Delivery",
    stat_postdelivery_sub: "isolated after delivery",
    stat_selected: "Selected",
    stat_selected_sub: "for bulk actions",

    mailbox_management: "Mailbox Management",
    new_mailbox: "New Mailbox",
    edit_mailbox: "Edit Mailbox",
    search_mailbox: "Search (email, name…) — Enter",
    search_quarantine: "Search (sender, subject…) — Enter",

    last_24h: "Last 24 h",
    last_7d: "Last 7 days",
    last_30d: "Last 30 days",

    col_email: "Email",
    col_displayname: "Display name",
    col_type: "Type",
    col_domain: "Domain",
    col_received: "Received",
    col_recipient: "Recipient",

    open_tab_load: "Open tab to load…",
    postdelivery_quarantine: "Post-Delivery Quarantine",
    release: "Release",

    detail: "Detail",
    details: "Details",
    message: "Message",
    attachments: "Attachments",
    attachments_count: "{count} attachment(s)",
    no_subject: "(no subject)",

    email_address: "Email address",
    mailbox_hint: "Fields are passed 1:1 to the Sophos Mailbox API. Required fields depend on the tenant configuration.",

    api_unreachable: "API: unreachable",
    api_unreachable_full: "Email API unreachable.",
    no_mailboxes: "No mailboxes found.",
    no_messages: "No messages in time window.",
    status_blocked: "blocked",
    status_active: "active",

    email_required: "Email address required.",
    save_failed: "Save failed:",
    delete_failed: "Delete failed:",
    no_mailbox_id: "No mailbox ID in record.",
    no_message_id: "No message ID.",
    confirm_delete_mailbox: "Really delete mailbox \"{email}\"?\nThis action affects the Sophos tenant directly.",

    no_messages_selected: "No messages selected.",
    confirm_release_many: "Release {count} message(s).\n\n[OK] = also add sender to allow list\n[Cancel] = release only",
    confirm_delete_many: "Permanently delete {count} message(s)?\nThis action affects the Sophos tenant directly.",
    confirm_release_one: "Release message.\n[OK] = also allow sender  ·  [Cancel] = release only",
    confirm_delete_one: "Permanently delete message?",
    confirm_block_sender: "Also add sender to block list?\n[OK] = yes  ·  [Cancel] = delete only",
    action_failed: "Action \"{action}\" failed:",
};

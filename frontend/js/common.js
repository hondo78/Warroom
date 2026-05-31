// Shared helpers used across multiple pages. Loaded before the per-page
// scripts so every page shares one definition.
//
// NOTE: formatTime() and truncate() are intentionally NOT here — they differ
// per page (year shown on the blocklist, em-dash placeholder on firewalls,
// "…" vs "..." in the agent view). Keep those local to each page.

// HTML-escape arbitrary values before inserting them into innerHTML.
function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// Like escapeHtml but also neutralises backticks — use for values placed
// inside HTML attribute values.
function escapeAttr(str) {
    return escapeHtml(str).replace(/`/g, '&#96;');
}

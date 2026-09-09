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

// For values embedded inside a single-quoted JS string in an inline handler,
// e.g. onclick="doThing('${escapeJsAttr(v)}')".
//
// escapeAttr() alone is NOT enough there. The browser decodes the attribute
// value (&#39; back to ') BEFORE the handler is compiled as JavaScript, so an
// apostrophe in attacker-controlled data — a sprayed username, a blocked URL —
// closes the string literal and the rest of the value runs as code in the
// operator's session. Escaping for JavaScript first and for HTML second
// survives both passes: the quote arrives at the JS parser as \'.
function escapeJsAttr(str) {
    return escapeAttr(String(str ?? '')
        .replace(/\\/g, '\\\\')
        .replace(/'/g, "\\'")
        .replace(/[\r\n\u2028\u2029]/g, ' '));
}

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

// ---------------------------------------------------------------------------
// poll(fn, ms): setInterval that stops while the tab is hidden.
//
// Every page used to poll unconditionally, so a forgotten background tab kept
// firing 20 parallel aggregates a minute at the request pool. Hidden tabs now
// skip their ticks; when the tab comes back, anything that missed a tick runs
// once straight away instead of waiting out the rest of its interval.
// ---------------------------------------------------------------------------
const _pollers = [];

function poll(fn, ms) {
    const p = { fn, ms, last: Date.now() };
    _pollers.push(p);
    return setInterval(() => {
        // The second check stops a tick landing right after a catch-up run.
        if (document.hidden || Date.now() - p.last < ms / 2) return;
        p.last = Date.now();
        fn();
    }, ms);
}

document.addEventListener('visibilitychange', () => {
    if (document.hidden) return;
    const now = Date.now();
    _pollers.forEach(p => {
        if (now - p.last >= p.ms) { p.last = now; p.fn(); }
    });
});

// Re-run everything this page polls — or reload, on pages that poll nothing.
function refreshPage() {
    if (!_pollers.length) { location.reload(); return; }
    const now = Date.now();
    _pollers.forEach(p => { p.last = now; p.fn(); });
}

// ---------------------------------------------------------------------------
// API status: retry "still computing" 503s, surface real failures.
//
// The backend cache (@cached) answers a cold key with 503 + Retry-After rather
// than run the same heavy aggregate twice. No page handled that, so after a
// restart or a switch to a 30-day range tiles simply stayed empty. Same-origin
// GETs under /api/ are retried here, once, centrally; while that happens a pill
// says so, and if a request really fails the pill says that instead and offers
// a retry. Non-GET requests are never retried — they may not be idempotent.
// ---------------------------------------------------------------------------
(function () {
    const nativeFetch = window.fetch.bind(window);
    const MAX_RETRIES = 6;
    let computing = 0;
    const failed = new Set();   // API paths whose last attempt failed

    function apiPath(input, init) {
        const method = ((init && init.method) || (input instanceof Request ? input.method : 'GET')).toUpperCase();
        if (method !== 'GET') return null;
        try {
            const u = new URL(typeof input === 'string' || input instanceof URL ? input : input.url, location.href);
            return u.origin === location.origin && u.pathname.startsWith('/api/') ? u.pathname : null;
        } catch (e) { return null; }
    }

    const sleep = ms => new Promise(r => setTimeout(r, ms));

    window.fetch = async function (input, init) {
        const path = apiPath(input, init);
        if (!path) return nativeFetch(input, init);
        let resp;
        try {
            resp = await nativeFetch(input, init);
            if (resp.status === 503) {
                computing++; render();
                try {
                    for (let i = 0; i < MAX_RETRIES && resp.status === 503; i++) {
                        const ra = parseInt(resp.headers.get('Retry-After') || '', 10);
                        await sleep(Math.min(Number.isFinite(ra) ? ra : 5, 15) * 1000);
                        resp = await nativeFetch(input, init);
                    }
                } finally { computing--; }
            }
        } catch (e) {
            failed.add(path); render();
            throw e;
        }
        if (resp.status >= 500) failed.add(path); else failed.delete(path);
        render();
        return resp;
    };

    let pill = null;
    function render() {
        if (!document.body) return;
        if (!pill) {
            pill = document.createElement('div');
            pill.id = 'apiStatusPill';
            pill.setAttribute('role', 'status');
            pill.style.cssText = 'position:fixed;right:16px;bottom:16px;z-index:2000;display:none;'
                + 'align-items:center;gap:.5rem;padding:.4rem .8rem;border-radius:999px;font-size:.85rem;'
                + 'box-shadow:0 2px 10px rgba(0,0,0,.25);background:var(--bs-body-bg);color:var(--bs-body-color);'
                + 'border:1px solid var(--bs-border-color)';
            document.body.appendChild(pill);
        }
        if (failed.size) {
            pill.style.display = 'flex';
            pill.style.borderColor = 'var(--bs-danger)';
            pill.innerHTML = `<i class="bi bi-exclamation-triangle-fill text-danger"></i>`
                + `<span>${escapeHtml(t('common.api_failed', { n: failed.size }))}</span>`
                + `<button type="button" class="btn btn-sm btn-outline-danger py-0">${escapeHtml(t('common.retry'))}</button>`;
            pill.title = [...failed].join('\n');
            pill.querySelector('button').onclick = () => { failed.clear(); render(); refreshPage(); };
        } else if (computing > 0) {
            pill.style.display = 'flex';
            pill.style.borderColor = 'var(--bs-border-color)';
            pill.title = '';
            pill.innerHTML = `<span class="spinner-border spinner-border-sm text-secondary"></span>`
                + `<span>${escapeHtml(t('common.computing'))}</span>`;
        } else {
            pill.style.display = 'none';
        }
    }
})();

// ---------------------------------------------------------------------------
// URL state: <select data-url-state="days"> keeps its value in ?days=…
//
// Filters survive a reload and a view can be shared as a link. Values are
// restored synchronously here — page scripts load after this file and read the
// controls in their DOMContentLoaded handlers, so they see the restored value.
// A value equal to the control's markup default is left out of the URL.
// Selects filled asynchronously (e.g. the firewall list) get the value applied
// once the matching option appears.
// ---------------------------------------------------------------------------
(function () {
    const params = new URLSearchParams(location.search);

    function isToggle(el) { return el.type === 'checkbox' || el.type === 'radio'; }

    function setValue(el, v) {
        if (isToggle(el)) { el.checked = v === '1'; return; }
        if (el.tagName === 'SELECT' && ![...el.options].some(o => o.value === v)) {
            el._urlPending = v;
            const mo = new MutationObserver(() => {
                if ([...el.options].some(o => o.value === v)) {
                    mo.disconnect();
                    delete el._urlPending;
                    el.value = v;
                    el.dispatchEvent(new Event('change'));
                }
            });
            mo.observe(el, { childList: true, subtree: true });
            return;
        }
        el.value = v;
    }

    function isDefault(el) {
        if (isToggle(el)) return el.checked === el.defaultChecked;
        if (el.tagName === 'SELECT') {
            const def = [...el.options].find(o => o.defaultSelected) || el.options[0];
            return !def || el.value === def.value;
        }
        return el.value === el.defaultValue;
    }

    function write() {
        const p = new URLSearchParams(location.search);
        document.querySelectorAll('[data-url-state]').forEach(el => {
            const key = el.dataset.urlState;
            // Still waiting for its options: keep the value it was opened with.
            if (el._urlPending !== undefined) p.set(key, el._urlPending);
            else if (isDefault(el)) p.delete(key);
            else p.set(key, isToggle(el) ? (el.checked ? '1' : '0') : el.value);
        });
        const qs = p.toString();
        history.replaceState(history.state, '', location.pathname + (qs ? '?' + qs : '') + location.hash);
    }

    document.querySelectorAll('[data-url-state]').forEach(el => {
        const key = el.dataset.urlState;
        if (params.has(key)) setValue(el, params.get(key));
        el.addEventListener('change', write);
        if (!isToggle(el) && el.tagName !== 'SELECT') el.addEventListener('input', write);
    });
})();

// ---------------------------------------------------------------------------
// Quick search (Ctrl+K, or "/" outside a text field).
//
// One box for "I have an IP / a host / a user — where do I look?". It knows
// what the input looks like and offers the pages that can answer it, each a
// deep link (most via the URL state above), plus a jump to any sidebar page.
// ---------------------------------------------------------------------------
(function () {
    const IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/;
    const IPV6 = /^[0-9a-f:]+:[0-9a-f:.]*$/i;
    const URLRE = /^https?:\/\//i;
    const DOMAIN = /^(?=.{3,253}$)([a-z0-9-]+\.)+[a-z]{2,}$/i;

    function kind(q) {
        if (IPV4.test(q) || (q.includes(':') && IPV6.test(q))) return 'ip';
        if (URLRE.test(q)) return 'url';
        if (DOMAIN.test(q)) return 'domain';
        return 'text';
    }

    function pages() {
        const seen = new Set();
        return [...document.querySelectorAll('.sidebar-menu a.nav-link')]
            .map(a => ({ href: a.getAttribute('href'), label: (a.textContent || '').trim() }))
            .filter(p => p.href && p.href !== '#' && p.label && !seen.has(p.href) && seen.add(p.href));
    }

    function actions(q) {
        const out = [];
        const enc = encodeURIComponent(q);
        if (q) {
            const k = kind(q);
            if (k === 'ip') {
                out.push({ icon: 'bi-person-vcard', label: t('common.qs_dossier', { q }), href: `/dossier.html?ip=${enc}` });
            }
            if (k !== 'text') {
                out.push({ icon: 'bi-globe2', label: t('common.qs_osint', { q }), href: `/osint.html?q=${enc}` });
            }
            out.push(
                { icon: 'bi-laptop', label: t('common.qs_endpoints', { q }), href: `/endpoints.html?epSearch=${enc}` },
                { icon: 'bi-hdd-network', label: t('common.qs_devices', { q }), href: `/?deviceSearch=${enc}` },
                { icon: 'bi-microsoft', label: t('common.qs_m365', { q }), href: `/o365.html?o365GlobalFilter=${enc}` },
                { icon: 'bi-envelope', label: t('common.qs_mailboxes', { q }), href: `/email.html?mbSearch=${enc}` },
                { icon: 'bi-bug', label: t('common.qs_honeypot', { q }), href: `/honeypot.html?credSearch=${enc}` },
            );
        }
        const ql = q.toLowerCase();
        pages().filter(p => !ql || p.label.toLowerCase().includes(ql))
            .forEach(p => out.push({ icon: 'bi-arrow-right-short', label: p.label, href: p.href, page: true }));
        return out;
    }

    let overlay = null, input = null, list = null, items = [], sel = 0;

    function build() {
        overlay = document.createElement('div');
        overlay.id = 'quickSearch';
        overlay.style.cssText = 'position:fixed;inset:0;z-index:2100;background:rgba(0,0,0,.45);display:none;'
            + 'align-items:flex-start;justify-content:center;padding:12vh 16px 16px';
        overlay.innerHTML =
            `<div style="width:100%;max-width:560px;background:var(--bs-body-bg);color:var(--bs-body-color);`
            + `border:1px solid var(--bs-border-color);border-radius:.5rem;box-shadow:0 10px 40px rgba(0,0,0,.4);overflow:hidden">`
            + `<input type="text" class="form-control form-control-lg border-0 rounded-0" autocomplete="off" spellcheck="false" `
            + `aria-label="${escapeAttr(t('common.qs_placeholder'))}" placeholder="${escapeAttr(t('common.qs_placeholder'))}">`
            + `<div class="list-group list-group-flush" style="max-height:50vh;overflow:auto"></div></div>`;
        document.body.appendChild(overlay);
        input = overlay.querySelector('input');
        list = overlay.querySelector('.list-group');
        overlay.addEventListener('mousedown', e => { if (e.target === overlay) close(); });
        input.addEventListener('input', update);
        input.addEventListener('keydown', e => {
            if (e.key === 'ArrowDown') { sel = Math.min(sel + 1, items.length - 1); paint(); e.preventDefault(); }
            else if (e.key === 'ArrowUp') { sel = Math.max(sel - 1, 0); paint(); e.preventDefault(); }
            else if (e.key === 'Enter') { go(items[sel]); e.preventDefault(); }
            else if (e.key === 'Escape') { close(); }
        });
    }

    function update() { items = actions(input.value.trim()); sel = 0; paint(); }

    function paint() {
        list.innerHTML = items.map((it, i) =>
            `<a href="${escapeAttr(it.href)}" class="list-group-item list-group-item-action d-flex align-items-center gap-2${i === sel ? ' active' : ''}">`
            + `<i class="bi ${it.icon}"></i><span class="text-truncate">${escapeHtml(it.label)}</span>`
            + (it.page ? `<small class="ms-auto opacity-50">${escapeHtml(t('common.qs_page'))}</small>` : '')
            + `</a>`).join('')
            || `<div class="list-group-item text-body-secondary">${escapeHtml(t('common.qs_none'))}</div>`;
        list.querySelector('.active')?.scrollIntoView({ block: 'nearest' });
    }

    function go(it) { if (it) location.href = it.href; }

    function open() {
        if (!overlay) build();
        overlay.style.display = 'flex';
        input.value = '';
        update();
        input.focus();
    }
    function close() { if (overlay) overlay.style.display = 'none'; }
    window.openQuickSearch = open;

    document.addEventListener('keydown', e => {
        const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName) || e.target.isContentEditable;
        if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); open(); }
        else if (e.key === '/' && !typing) { e.preventDefault(); open(); }
    });

    // Header button, next to the language switcher.
    // The admin pages' header has no right-hand group yet; give them one.
    let bar = document.querySelector('.app-header .container-fluid .ms-auto')
           || document.querySelector('.app-header .ms-auto');
    const hdr = document.querySelector('.app-header .container-fluid');
    if (!bar && hdr) {
        bar = document.createElement('div');
        bar.className = 'd-flex align-items-center gap-2 ms-auto';
        hdr.appendChild(bar);
    }
    if (bar && !document.getElementById('quickSearchBtn')) {
        const b = document.createElement('button');
        b.id = 'quickSearchBtn';
        b.type = 'button';
        b.className = 'btn btn-outline-secondary btn-sm d-flex align-items-center gap-1';
        b.title = t('common.qs_placeholder');
        b.innerHTML = `<i class="bi bi-search"></i><kbd class="d-none d-md-inline" style="font-size:.7rem">Ctrl K</kbd>`;
        b.addEventListener('click', open);
        bar.insertBefore(b, bar.firstChild);
    }
})();

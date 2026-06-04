// Microsoft 365 login-audit page. The full result set (≤500 rows) is kept in
// memory; sorting and per-column filtering happen client-side on re-render.

let _o365Items = [];
let _o365Sort = { key: 'created_at', dir: 'desc' };
const _o365Filters = {};

document.addEventListener('DOMContentLoaded', () => {
    refreshO365();
    setInterval(refreshO365, 60000);

    // Column sort: click header toggles asc/desc
    document.querySelectorAll('#o365SortRow th[data-sort]').forEach(th => {
        th.addEventListener('click', () => {
            const key = th.dataset.sort;
            if (_o365Sort.key === key) {
                _o365Sort.dir = _o365Sort.dir === 'asc' ? 'desc' : 'asc';
            } else {
                _o365Sort = { key, dir: 'asc' };
            }
            renderO365Table();
        });
    });

    // Per-column filters + global quick filter
    document.querySelectorAll('.o365-col-filter').forEach(input => {
        input.addEventListener('input', () => {
            _o365Filters[input.dataset.col] = input.value.toLowerCase().trim();
            renderO365Table();
        });
    });
    const global = document.getElementById('o365GlobalFilter');
    if (global) global.addEventListener('input', renderO365Table);
});

function formatTime(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    return d.toLocaleString('de-DE', {
        day: '2-digit', month: '2-digit', year: '2-digit',
        hour: '2-digit', minute: '2-digit',
    });
}

async function refreshO365() {
    const days = document.getElementById('o365Days').value;
    const status = document.getElementById('o365Status').value;
    try {
        const r = await fetch(`/api/o365/logins?days=${days}&status=${status}&limit=500`);
        const d = await r.json();
        const s = d.stats || {};

        document.getElementById('o365NotConfigured').style.display = d.configured ? 'none' : '';
        document.getElementById('o365Total').textContent = (s.total ?? 0).toLocaleString('de-DE');
        document.getElementById('o365Failed').textContent = (s.failed ?? 0).toLocaleString('de-DE');
        document.getElementById('o365Users').textContent = (s.unique_users ?? 0).toLocaleString('de-DE');
        document.getElementById('o365Ips').textContent = (s.unique_ips ?? 0).toLocaleString('de-DE');

        _o365Items = d.items || [];
        renderO365Table();

        renderTopList('o365TopUsers', s.top_failed_users || [], x => x.user, 'Keine Fehlversuche');
        renderTopList('o365TopCountries', s.top_countries || [], x => x.country, 'Keine Geo-Daten');
    } catch (err) {
        console.error('O365 refresh failed:', err);
    }
}

// Per-column text used for both filtering and sorting. created_at stays ISO
// so lexicographic order equals chronological order.
function _o365ColText(x, col) {
    switch (col) {
        case 'created_at': return x.created_at || '';
        case 'user_id': return x.user_id || '';
        case 'result': return x.operation === 'UserLoginFailed' ? 'failed' : 'ok';
        case 'app': return x.application || x.application_id || '';
        case 'device': return _deviceText(x.device);
        case 'client_ip': return x.client_ip || '';
        case 'location': return [x.country, x.city].filter(Boolean).join(', ');
        case 'logon_error': return x.logon_error || '';
        default: return '';
    }
}

function renderO365Table() {
    const tbody = document.getElementById('o365Table');
    if (!tbody) return;

    let rows = _o365Items.slice();

    // column filters
    for (const [col, val] of Object.entries(_o365Filters)) {
        if (!val) continue;
        rows = rows.filter(x => {
            const text = col === 'created_at'
                ? formatTime(x.created_at).toLowerCase()
                : _o365ColText(x, col).toLowerCase();
            return text.includes(val);
        });
    }

    // global quick filter across all columns
    const g = (document.getElementById('o365GlobalFilter')?.value || '').toLowerCase().trim();
    if (g) {
        const COLS = ['created_at', 'user_id', 'result', 'app', 'device', 'client_ip', 'location', 'logon_error'];
        rows = rows.filter(x =>
            COLS.some(c => _o365ColText(x, c).toLowerCase().includes(g)) ||
            formatTime(x.created_at).toLowerCase().includes(g)
        );
    }

    // sort
    const { key, dir } = _o365Sort;
    const mul = dir === 'asc' ? 1 : -1;
    rows.sort((a, b) => mul * _o365ColText(a, key).localeCompare(_o365ColText(b, key), 'de', { numeric: true }));

    // header indicators
    document.querySelectorAll('#o365SortRow th[data-sort]').forEach(th => {
        const ind = th.querySelector('.sort-ind');
        if (ind) ind.textContent = th.dataset.sort === key ? (dir === 'asc' ? '▲' : '▼') : '';
    });

    if (!rows.length) {
        tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;color:var(--text-secondary);padding:1.5rem">Keine Login-Ereignisse (Filter aktiv?).</td></tr>';
        return;
    }

    tbody.innerHTML = rows.map(x => {
        const failed = x.operation === 'UserLoginFailed';
        const badge = failed
            ? '<span class="badge text-bg-danger">FAILED</span>'
            : '<span class="badge text-bg-success">OK</span>';
        const loc = [x.country, x.city].filter(Boolean).join(', ') || '—';
        // Whitelisted IPs can never be blocked (backend refuses with 409)
        // — show a shield instead of a dead button.
        const blockBtn = x.whitelisted
            ? '<span title="IP ist whitelisted — Block nicht möglich" style="color:var(--accent-green)">🛡</span>'
            : (failed && x.client_ip)
                ? `<button class="block-link" onclick="blockO365Ip('${escapeAttr(x.client_ip)}', this)" title="IP blockieren">block</button>`
                : '';
        const osint = typeof osintButton === 'function' ? osintButton(x.client_ip, 'osint-btn', 'ip') : '';
        // Friendly name from the backend's well-known-app mapping;
        // unknown IDs render as a shortened GUID with full ID on hover.
        const appCell = x.application
            ? escapeHtml(x.application)
            : x.application_id
                ? `<code style="font-size:.75rem" title="${escapeAttr(x.application_id)}">${escapeHtml(x.application_id.slice(0, 8))}…</code>`
                : '—';
        return `<tr>
            <td style="white-space:nowrap">${formatTime(x.created_at)}</td>
            <td>${escapeHtml(x.user_id || '—')}</td>
            <td>${badge}</td>
            <td title="${escapeAttr(x.application_id || '')}">${appCell}</td>
            <td>${_deviceCell(x.device)}</td>
            <td><code style="font-size:.82rem">${escapeHtml(x.client_ip || '—')}</code>${osint}</td>
            <td>${escapeHtml(loc)}</td>
            <td title="${escapeAttr(x.logon_error || '')}">${escapeHtml(truncateStr(x.logon_error || '—', 28))}</td>
            <td>${blockBtn}</td>
        </tr>`;
    }).join('');
}

function truncateStr(str, n) {
    return str.length > n ? str.slice(0, n - 1) + '…' : str;
}

// Plain-text device summary used for sorting + filtering.
function _deviceText(dev) {
    if (!dev) return '';
    return [dev.name, dev.os, dev.browser].filter(Boolean).join(' ');
}

// Rich device cell: name (or OS) + OS/browser secondary + compliance dot.
function _deviceCell(dev) {
    if (!dev || (!dev.name && !dev.os && !dev.browser)) return '—';
    const primary = dev.name || dev.os || 'Unbekannt';
    const secondaryBits = [];
    if (dev.name && dev.os) secondaryBits.push(dev.os);
    if (dev.browser) secondaryBits.push(dev.browser);
    const secondary = secondaryBits.length
        ? `<div style="font-size:.7rem;color:var(--text-secondary)">${escapeHtml(secondaryBits.join(' · '))}</div>`
        : '';
    let badge = '';
    if (dev.compliant === true) {
        badge = ' <span title="Compliant (verwaltet)" style="color:var(--accent-green)">●</span>';
    } else if (dev.compliant === false) {
        badge = ' <span title="Nicht compliant / nicht verwaltet" style="color:var(--accent-red)">○</span>';
    }
    return `<div>${escapeHtml(primary)}${badge}</div>${secondary}`;
}

function renderTopList(tbodyId, rows, labelFn, emptyText) {
    const tbody = document.getElementById(tbodyId);
    if (!rows.length) {
        tbody.innerHTML = `<tr><td style="text-align:center;color:var(--text-secondary)">${emptyText}</td></tr>`;
        return;
    }
    tbody.innerHTML = rows.map(x =>
        `<tr><td>${escapeHtml(labelFn(x) || '—')}</td><td style="text-align:right"><strong>${x.count.toLocaleString('de-DE')}</strong></td></tr>`
    ).join('');
}

async function blockO365Ip(ip, btn) {
    if (!confirm(`IP ${ip} auf die Blockliste setzen?`)) return;
    try {
        const resp = await fetch('/api/firewall/block-ip', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, comment: 'O365 failed login' }),
        });
        const data = await resp.json().catch(() => ({}));
        if (!resp.ok) throw new Error(data.detail || `HTTP ${resp.status}`);
        if (btn) { btn.textContent = 'blocked'; btn.disabled = true; }
    } catch (err) {
        alert('Block fehlgeschlagen: ' + err.message);
    }
}

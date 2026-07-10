// Microsoft 365 login-audit page. The full result set (≤500 rows) is kept in
// memory; sorting and per-column filtering happen client-side on re-render.

let _o365Items = [];
let _o365Sort = { key: 'created_at', dir: 'desc' };
const _o365Filters = {};

document.addEventListener('DOMContentLoaded', () => {
    refreshO365();
    refreshLoginWatch();
    setInterval(refreshO365, 60000);
    setInterval(refreshLoginWatch, 60000);

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

        renderTopList('o365TopUsers', s.top_failed_users || [], x => x.user, t('o365.no_failures'));
        renderTopList('o365TopCountries', s.top_countries || [], x => x.country, t('o365.no_geo'));
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
        tbody.innerHTML = `<tr><td colspan="9" style="text-align:center;color:var(--text-secondary);padding:1.5rem">${escapeHtml(t('o365.no_events'))}</td></tr>`;
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
            ? `<span title="${escapeAttr(t('o365.whitelisted_tip'))}" style="color:var(--accent-green)">🛡</span>`
            : (failed && x.client_ip)
                ? `<button class="block-link" onclick="blockO365Ip('${escapeAttr(x.client_ip)}', this)" title="${escapeAttr(t('o365.block_tip'))}">block</button>`
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
    const primary = dev.name || dev.os || t('o365.unknown');
    const secondaryBits = [];
    if (dev.name && dev.os) secondaryBits.push(dev.os);
    if (dev.browser) secondaryBits.push(dev.browser);
    const secondary = secondaryBits.length
        ? `<div style="font-size:.7rem;color:var(--text-secondary)">${escapeHtml(secondaryBits.join(' · '))}</div>`
        : '';
    let badge = '';
    if (dev.compliant === true) {
        badge = ` <span title="${escapeAttr(t('o365.compliant'))}" style="color:var(--accent-green)">●</span>`;
    } else if (dev.compliant === false) {
        badge = ` <span title="${escapeAttr(t('o365.noncompliant'))}" style="color:var(--accent-red)">○</span>`;
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
    if (!confirm(t('o365.confirm_block', { ip }))) return;
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
        alert(t('o365.block_failed') + ' ' + err.message);
    }
}

// ---- Login watch (new device / location alerts + session revoke) -------------

async function refreshLoginWatch() {
    try {
        const r = await fetch('/api/o365/login-profiles');
        if (!r.ok) return;
        const d = await r.json();

        const status = document.getElementById('watchStatus');
        if (status) {
            if (!d.seeded) {
                status.className = 'badge text-bg-secondary';
                status.textContent = t('o365.watch_not_seeded');
            } else if (d.enabled) {
                status.className = 'badge text-bg-success';
                status.textContent = t('o365.watch_active');
            } else {
                status.className = 'badge text-bg-warning';
                status.textContent = t('o365.watch_inactive');
            }
        }
        renderWatchAlerts(d.alerts || []);
        renderWatchProfiles(d.users || []);
    } catch (err) {
        console.error('login watch refresh failed:', err);
    }
}

function _watchStatusBadge(s) {
    const cls = { pending: 'text-bg-warning', executed: 'text-bg-danger',
                  rejected: 'text-bg-secondary', failed: 'text-bg-danger' }[s] || 'text-bg-secondary';
    const label = s === 'executed' ? t('o365.watch_revoked') : s;
    return `<span class="badge ${cls}">${escapeHtml(label)}</span>`;
}

function renderWatchAlerts(alerts) {
    const tbody = document.getElementById('watchAlertsTable');
    if (!tbody) return;
    if (!alerts.length) {
        tbody.innerHTML = `<tr><td colspan="7" class="text-center text-secondary py-3">${t('o365.watch_no_alerts')}</td></tr>`;
        return;
    }
    tbody.innerHTML = alerts.map(a => {
        const ctx = a.context || {};
        const news = [];
        if (ctx.new_device) news.push(`<span class="badge text-bg-danger" title="${escapeAttr(t('o365.watch_new_device'))}"><i class="bi bi-phone"></i> ${escapeHtml(ctx.new_device)}</span>`);
        if (ctx.new_location) news.push(`<span class="badge text-bg-warning" title="${escapeAttr(t('o365.watch_new_location'))}"><i class="bi bi-geo-alt"></i> ${escapeHtml(ctx.new_location)}</span>`);
        let action = '—';
        // 'failed' stays actionable — a transient failure (e.g. a revoke before
        // the Graph permission was granted) can be retried with the same button.
        if (a.status === 'pending' || a.status === 'failed') {
            const retry = a.status === 'failed';
            const errTip = retry && a.error ? ` <span class="ack-label" title="${escapeAttr(a.error)}">❗</span>` : '';
            const label = retry ? t('o365.watch_btn_retry') : t('o365.watch_btn_revoke');
            action = `<button class="ack-btn" onclick="watchDecision(${a.id}, 'approve', this)">${label}</button>
                      <button class="block-link" style="margin-left:.3rem" onclick="watchDecision(${a.id}, 'reject', this)">${t('o365.watch_btn_dismiss')}</button>${errTip}`;
        }
        const loc = [ctx.country, ctx.city].filter(Boolean).join(' / ') || '—';
        return `<tr title="${escapeAttr(a.reasoning || '')}">
            <td style="white-space:nowrap">${formatTime(a.created_at)}</td>
            <td>${escapeHtml(a.user || '—')}</td>
            <td>${news.join(' ') || '—'}</td>
            <td><code>${escapeHtml(a.ip || '—')}</code></td>
            <td>${escapeHtml(loc)}</td>
            <td>${_watchStatusBadge(a.status)}</td>
            <td>${action}</td>
        </tr>`;
    }).join('');
}

function renderWatchProfiles(users) {
    const tbody = document.getElementById('watchProfilesTable');
    if (!tbody) return;
    if (!users.length) {
        tbody.innerHTML = `<tr><td colspan="4" class="text-center text-secondary py-3">${t('o365.watch_no_profiles')}</td></tr>`;
        return;
    }
    const pill = (e, icon) =>
        `<span class="badge text-bg-secondary me-1" title="${escapeAttr(t('o365.watch_seen', { n: e.seen_count, last: formatTime(e.last_seen) }))}"><i class="bi ${icon}"></i> ${escapeHtml(e.label || e.value)}</span>`;
    tbody.innerHTML = users.map(u => `
        <tr>
            <td>${escapeHtml(u.user)}</td>
            <td>${u.devices.map(e => pill(e, 'bi-phone')).join(' ') || '—'}</td>
            <td>${u.locations.map(e => pill(e, 'bi-geo-alt')).join(' ') || '—'}</td>
            <td><button class="block-link" onclick="revokeUserSessions('${escapeAttr(u.user)}', this)">${t('o365.watch_btn_revoke')}</button></td>
        </tr>`).join('');
}

// Approve (= revoke sessions) or reject a pending login-watch decision — same
// endpoints the dashboard's agent card uses.
async function watchDecision(id, verb, btn) {
    if (verb === 'approve' && !confirm(t('o365.watch_confirm_revoke_decision'))) return;
    if (btn) btn.disabled = true;
    try {
        const r = await fetch(`/api/agent/decisions/${id}/${verb}`, { method: 'POST' });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
        await refreshLoginWatch();
    } catch (err) {
        alert(t('o365.watch_action_failed') + ': ' + err.message);
        if (btn) btn.disabled = false;
    }
}

// Operator-initiated immediate revoke for a user (no pending decision).
async function revokeUserSessions(user, btn) {
    if (!confirm(t('o365.watch_confirm_revoke', { user }))) return;
    if (btn) { btn.disabled = true; }
    try {
        const r = await fetch('/api/o365/revoke-sessions', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ user }),
        });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
        if (btn) { btn.textContent = t('o365.watch_revoked'); }
    } catch (err) {
        alert(t('o365.watch_action_failed') + ': ' + err.message);
        if (btn) btn.disabled = false;
    }
}

async function watchRunNow(btn) {
    if (btn) btn.disabled = true;
    try {
        const r = await fetch('/api/o365/login-watch/run-now', { method: 'POST' });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
        await refreshLoginWatch();
        if (d.seed) alert(t('o365.watch_seeded', { n: d.profiles || 0 }));
    } catch (err) {
        alert(t('o365.watch_action_failed') + ': ' + err.message);
    } finally {
        if (btn) btn.disabled = false;
    }
}

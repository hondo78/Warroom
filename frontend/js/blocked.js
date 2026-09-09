// Locale for number/date formatting follows the active UI language, so English
// mode renders English-style dates/numbers instead of German ones.
const BLK_LOCALE = (typeof currentLang === 'function' && currentLang() === 'de') ? 'de-DE' : 'en-US';

document.addEventListener('DOMContentLoaded', () => {
    initFilters();
    setFeedUrls();
    refreshBlocked();
    window.addEventListener('warroom:blocklist-changed', refreshBlocked);
    setInterval(refreshBlocked, 30000);
});

function setFeedUrls() {
    const ip = document.getElementById('iocFeedUrlIp');
    if (ip) ip.textContent = `${window.location.origin}/ioc_IP`;
    const dom = document.getElementById('iocFeedUrlDomain');
    if (dom) dom.textContent = `${window.location.origin}/ioc_domain`;
    const url = document.getElementById('iocFeedUrlUrl');
    if (url) url.textContent = `${window.location.origin}/ioc_url`;
}

function switchBlockedTab(tab) {
    document.querySelectorAll('[data-tab]').forEach(b => {
        const on = b.dataset.tab === tab;
        b.classList.toggle('active', on);
        b.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    document.querySelectorAll('[data-pane]').forEach(p => {
        p.classList.toggle('active', p.dataset.pane === tab);
    });
    // The audit trail is only fetched when actually opened — it is the one list
    // here that is pure history and needs no periodic refresh.
    if (tab === 'knownusers') updateKnownUserDecisions();
    if (tab === 'burned') updateBurnedTable();
}

const _filterInputs = {};
function initFilters() {
    document.querySelectorAll('input[data-filter-for]').forEach(input => {
        const tbodyId = input.dataset.filterFor;
        const tbody = document.getElementById(tbodyId);
        if (!tbody) return;
        _filterInputs[tbodyId] = input;
        input.addEventListener('input', () => applyTableFilter(tbody, input.value));
        new MutationObserver(() => {
            const term = (_filterInputs[tbodyId]?.value || '').trim();
            if (term) applyTableFilter(tbody, term);
        }).observe(tbody, { childList: true });
    });
}

function applyTableFilter(tbody, term) {
    const t = (term || '').toLowerCase().trim();
    tbody.querySelectorAll(':scope > tr').forEach(tr => {
        const match = !t || tr.textContent.toLowerCase().includes(t);
        tr.classList.toggle('filter-hidden', !match);
    });
}

async function refreshBlocked() {
    await Promise.all([
        updateBlockedIpsTable(),
        updateBlockedDomainsTable(),
        updateBlockedUrlsTable(),
        updateWatchlistTable(),
        updateWhitelistTable(),
        updateKnownUsersTable(),
        // Also refreshed here, not only when its tab is opened: the tab badge it
        // fills is the summary of the instant-block trigger list and read 0 on
        // every page load until someone clicked the tab.
        updateBurnedTable(),
    ]);
}

// Monitor toggle button shared by the blocklist-IP and watchlist rows. Clicking
// flips the `monitored` flag; monitored IPs are analysed on the Überwachung page.
function monitorToggleCell(ip, monitored) {
    const on = !!monitored;
    const cls = on ? 'btn-info' : 'btn-outline-secondary';
    const label = on ? t('blocked.monitoring_on') : t('blocked.monitor_off');
    return `<button class="btn btn-sm ${cls} py-0" style="font-size:.72rem" title="${escapeAttr(t('blocked.monitor_title'))}" onclick="toggleMonitor('${escapeJsAttr(ip)}', ${on ? 'false' : 'true'}, this)"><i class="bi bi-binoculars"></i> ${label}</button>`;
}

async function toggleMonitor(ip, monitored, btn) {
    if (btn) btn.disabled = true;
    try {
        const r = await fetch('/api/firewall/monitor', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, monitored }),
        });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
        refreshBlocked();
    } catch (err) {
        alert(t('blocked.err_monitor_failed') + err.message);
        if (btn) btn.disabled = false;
    }
}

async function updateWatchlistTable() {
    try {
        const resp = await fetch('/api/firewall/watchlist');
        const items = (await resp.json()).items || [];
        setCount('tabCountWatchlist', items.length);
        const tbody = document.getElementById('watchlistTable');
        if (!tbody) return;
        if (!items.length) {
            tbody.innerHTML = emptyRow(5, t('blocked.empty_watchlist_ips'));
            return;
        }
        tbody.innerHTML = items.map(w => `
            <tr>
                <td><code>${escapeHtml(w.ip)}</code>${typeof osintButton === 'function' ? osintButton(w.ip, 'osint-btn', 'ip') : ''}</td>
                <td>${escapeHtml(w.comment || '-')}</td>
                <td>${formatTime(w.added_at)}</td>
                <td>${monitorToggleCell(w.ip, w.monitored)}</td>
                <td><button class="restore-btn" onclick="watchlistRemove('${escapeJsAttr(w.ip)}', this)">${t('blocked.btn_remove')}</button></td>
            </tr>`).join('');
    } catch (err) {
        console.error('Watchlist update failed:', err);
    }
}

async function watchlistAdd() {
    const ip = document.getElementById('watchlistIpInput').value.trim();
    const comment = document.getElementById('watchlistCommentInput').value.trim();
    if (!ip) return;
    try {
        const r = await fetch('/api/firewall/watchlist', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, comment }),
        });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
        document.getElementById('watchlistIpInput').value = '';
        document.getElementById('watchlistCommentInput').value = '';
        await updateWatchlistTable();
        switchBlockedTab('watchlist');
    } catch (err) { alert(t('blocked.err_watchlist_failed') + err.message); }
}

async function watchlistRemove(ip, btn) {
    if (!confirm(t('blocked.confirm_watchlist_remove', { ip }))) return;
    if (btn) btn.disabled = true;
    try {
        const r = await fetch(`/api/firewall/watchlist/${encodeURIComponent(ip)}`, { method: 'DELETE' });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        await updateWatchlistTable();
    } catch (err) { alert(t('blocked.err_watchlist_failed') + err.message); if (btn) btn.disabled = false; }
}

async function updateWhitelistTable() {
    try {
        const resp = await fetch('/api/firewall/whitelist');
        const payload = await resp.json();
        const items = payload.items || [];
        setCount('tabCountWhitelist', items.length);

        const tbody = document.getElementById('whitelistTable');
        if (!tbody) return;
        if (!items.length) {
            tbody.innerHTML = emptyRow(5, t('blocked.empty_whitelist'));
            return;
        }
        tbody.innerHTML = items.map(w => {
            const isManual = w.source === 'manual';
            const sourceBadge = isManual
                ? '<span class="severity-badge severity-low">manual</span>'
                : `<span class="severity-badge severity-medium" title="${escapeHtml(w.source)}">${escapeHtml(w.source.split('·')[0].trim())}</span>`;
            return `
                <tr>
                    <td><code>${escapeHtml(w.ip)}</code></td>
                    <td>${sourceBadge}</td>
                    <td>${escapeHtml(w.comment || '-')}</td>
                    <td>${formatTime(w.created_at)}</td>
                    <td><button class="restore-btn" onclick="whitelistRemove('${escapeJsAttr(w.ip)}', this)">${t('blocked.btn_remove')}</button></td>
                </tr>`;
        }).join('');
    } catch (err) {
        console.error('Whitelist update failed:', err);
    }
}

async function whitelistAdd() {
    const ip = document.getElementById('whitelistIpInput').value.trim();
    const comment = document.getElementById('whitelistCommentInput').value.trim();
    if (!ip) { alert(t('blocked.alert_enter_ip')); return; }
    try {
        const r = await fetch('/api/firewall/whitelist', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ ip, comment: comment || null }),
        });
        const data = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(data.detail || `HTTP ${r.status}`);
        document.getElementById('whitelistIpInput').value = '';
        document.getElementById('whitelistCommentInput').value = '';
        await updateWhitelistTable();
        // If the IP was on the block list, that just got dropped too
        await updateBlockedIpsTable();
        switchBlockedTab('whitelist');
    } catch (err) { alert(t('blocked.err_whitelist_failed') + err.message); }
}

async function whitelistRemove(ip, btn) {
    if (!confirm(t('blocked.confirm_whitelist_remove', { ip }))) return;
    btn.disabled = true; btn.textContent = '...';
    try {
        const r = await fetch(`/api/firewall/whitelist/${encodeURIComponent(ip)}`, {method: 'DELETE'});
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        await updateWhitelistTable();
    } catch (err) {
        alert(t('blocked.err_generic') + err.message);
        btn.disabled = false; btn.textContent = t('blocked.btn_remove');
    }
}

async function whitelistRefresh() {
    try {
        const r = await fetch('/api/firewall/whitelist/refresh', {method: 'POST'});
        const d = await r.json();
        if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
        await updateWhitelistTable();
        await updateBlockedIpsTable();
        const extra = d.removed_from_blocklist.length
            ? '\n' + t('blocked.refresh_removed_from_blocklist', { n: d.removed_from_blocklist.length })
            : '';
        alert(t('blocked.refresh_done', {
            added: d.added.length,
            refreshed: d.refreshed.length,
            stale: d.removed_stale_auto.length,
        }) + extra);
    } catch (err) { alert(t('blocked.err_refresh_failed') + err.message); }
}

// Block provenance: which detection created it + whether AI or a human did it.
const BLOCK_SRC_KEYS = {
    manual: 'blocked.src_manual', bulk: 'blocked.src_bulk', chat: 'blocked.src_chat',
    anomaly: 'blocked.src_anomaly', connection: 'blocked.src_connection',
    waf: 'blocked.src_waf', ips: 'blocked.src_ips', failed_login: 'blocked.src_failed_login',
    event: 'blocked.src_event', triage: 'blocked.src_triage', alert: 'blocked.src_alert',
    agent: 'blocked.src_agent',
};
function blockSourceLabel(src) {
    const k = BLOCK_SRC_KEYS[src];
    return k ? t(k) : (src || '-');
}
function blockOriginCell(b) {
    const byAgent = (b.blocked_by || 'human') === 'agent';
    const who = byAgent
        ? `<span class="badge text-bg-info" title="${escapeAttr(t('blocked.by_agent'))}"><i class="bi bi-robot"></i> ${t('blocked.who_ai')}</span>`
        : `<span class="badge text-bg-secondary" title="${escapeAttr(t('blocked.by_human'))}"><i class="bi bi-person"></i> ${t('blocked.who_human')}</span>`;
    const src = `<span class="badge text-bg-dark ms-1">${escapeHtml(blockSourceLabel(b.source))}</span>`;
    return who + src;
}

async function updateBlockedIpsTable() {
    try {
        const resp = await fetch('/api/firewall/blocked-ips');
        const payload = await resp.json();
        const items = payload.items || [];

        setCount('bIpCount', items.length);
        setCount('tabCountIps', items.length);
        bumpLastBlock(items, 'IP');

        const tbody = document.getElementById('blockedIpsTable');
        if (!items.length) {
            tbody.innerHTML = emptyRow(6, t('blocked.empty_ips'));
            return;
        }
        tbody.innerHTML = items.map(b => `
            <tr>
                <td><code>${escapeHtml(b.ip)}</code>${typeof osintButton === 'function' ? osintButton(b.ip, 'osint-btn', 'ip') : ''}</td>
                <td>${escapeHtml(b.comment || '-')}</td>
                <td>${formatTime(b.blocked_at)}</td>
                <td>${blockOriginCell(b)}</td>
                <td>${monitorToggleCell(b.ip, b.monitored)}</td>
                <td><button class="restore-btn" onclick="unblockIp('${escapeJsAttr(b.ip)}', this)">${t('blocked.btn_unblock')}</button></td>
            </tr>`).join('');
    } catch (err) {
        console.error('Blocked IPs update failed:', err);
    }
}

async function updateBlockedDomainsTable() {
    try {
        const resp = await fetch('/api/firewall/blocked-domains');
        const payload = await resp.json();
        const items = payload.items || [];

        setCount('bDomainCount', items.length);
        setCount('tabCountDomains', items.length);
        bumpLastBlock(items, 'Domain');

        const tbody = document.getElementById('blockedDomainsTable');
        if (!items.length) {
            tbody.innerHTML = emptyRow(4, t('blocked.empty_domains'));
            return;
        }
        tbody.innerHTML = items.map(b => `
            <tr>
                <td><code>${escapeHtml(b.domain)}</code>${typeof osintButton === 'function' ? osintButton(b.domain, 'osint-btn', 'domain') : ''}</td>
                <td>${escapeHtml(b.comment || '-')}</td>
                <td>${formatTime(b.blocked_at)}</td>
                <td><button class="restore-btn" onclick="unblockDomain('${escapeJsAttr(b.domain)}', this)">${t('blocked.btn_unblock')}</button></td>
            </tr>`).join('');
    } catch (err) {
        console.error('Blocked domains update failed:', err);
    }
}

async function updateBlockedUrlsTable() {
    try {
        const resp = await fetch('/api/firewall/blocked-urls');
        const payload = await resp.json();
        const items = payload.items || [];

        setCount('bUrlCount', items.length);
        setCount('tabCountUrls', items.length);
        bumpLastBlock(items.map(i => ({ ...i, _label: i.url })), 'URL');

        const tbody = document.getElementById('blockedUrlsTable');
        if (!items.length) {
            tbody.innerHTML = emptyRow(4, t('blocked.empty_urls'));
            return;
        }
        tbody.innerHTML = items.map(b => `
            <tr>
                <td><code class="waf-url" title="${escapeHtml(b.url)}" onclick="this.classList.toggle('expanded')">${escapeHtml(b.url)}</code>${typeof osintButton === 'function' ? osintButton(b.url, 'osint-btn', 'url') : ''}</td>
                <td>${escapeHtml(b.comment || '-')}</td>
                <td>${formatTime(b.blocked_at)}</td>
                <td><button class="restore-btn" onclick="unblockUrl('${escapeJsAttr(b.url)}', this)">${t('blocked.btn_unblock')}</button></td>
            </tr>`).join('');
    } catch (err) {
        console.error('Blocked URLs update failed:', err);
    }
}

let _lastBlockSeen = { ts: 0, type: '', label: '' };
function bumpLastBlock(items, kind) {
    for (const it of items) {
        if (!it.blocked_at) continue;
        const ts = new Date(it.blocked_at).getTime();
        if (ts > _lastBlockSeen.ts) {
            _lastBlockSeen = { ts, type: kind, label: it.ip || it.domain || it.url || it._label || '' };
        }
    }
    const el = document.getElementById('bLastBlock');
    const sub = document.getElementById('bLastBlockType');
    if (!el || !sub) return;
    if (!_lastBlockSeen.ts) {
        el.textContent = '-';
        sub.textContent = '—';
        return;
    }
    el.textContent = _lastBlockSeen.label;
    sub.textContent = `${_lastBlockSeen.type} · ${formatTime(new Date(_lastBlockSeen.ts).toISOString())}`;
}

async function blockIpManual() {
    const ip = document.getElementById('blockIpInput').value.trim();
    const comment = document.getElementById('blockIpCommentInput').value.trim();
    if (!ip) {
        alert(t('blocked.alert_enter_ip'));
        return;
    }
    try {
        const resp = await fetch('/api/firewall/block-ip', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, comment: comment || null }),
        });
        const data = await resp.json().catch(() => ({}));
        if (!resp.ok) throw new Error(data.detail || `HTTP ${resp.status}`);
        document.getElementById('blockIpInput').value = '';
        document.getElementById('blockIpCommentInput').value = '';
        await updateBlockedIpsTable();
    } catch (err) {
        alert(t('blocked.err_block_failed') + err.message);
    }
}

async function unblockIp(ip, btn) {
    if (!confirm(t('blocked.confirm_unblock_ip', { ip }))) return;
    btn.disabled = true;
    btn.textContent = '...';
    try {
        const resp = await fetch('/api/firewall/unblock-ip', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip }),
        });
        const data = await resp.json().catch(() => ({}));
        if (!resp.ok) throw new Error(data.detail || `HTTP ${resp.status}`);
        await updateBlockedIpsTable();
    } catch (err) {
        alert(t('blocked.err_unblock_failed') + err.message);
        btn.disabled = false;
        btn.textContent = t('blocked.btn_unblock');
    }
}

async function blockDomainManual() {
    const domain = document.getElementById('blockDomainInput').value.trim();
    const comment = document.getElementById('blockDomainCommentInput').value.trim();
    if (!domain) {
        alert(t('blocked.alert_enter_domain'));
        return;
    }
    try {
        const resp = await fetch('/api/firewall/block-domain', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain, comment: comment || null }),
        });
        const data = await resp.json().catch(() => ({}));
        if (!resp.ok) throw new Error(data.detail || `HTTP ${resp.status}`);
        document.getElementById('blockDomainInput').value = '';
        document.getElementById('blockDomainCommentInput').value = '';
        await updateBlockedDomainsTable();
        switchBlockedTab('domains');
    } catch (err) {
        alert(t('blocked.err_block_failed') + err.message);
    }
}

async function unblockDomain(domain, btn) {
    if (!confirm(t('blocked.confirm_unblock_domain', { domain }))) return;
    btn.disabled = true;
    btn.textContent = '...';
    try {
        const resp = await fetch('/api/firewall/unblock-domain', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain }),
        });
        const data = await resp.json().catch(() => ({}));
        if (!resp.ok) throw new Error(data.detail || `HTTP ${resp.status}`);
        await updateBlockedDomainsTable();
    } catch (err) {
        alert(t('blocked.err_unblock_failed') + err.message);
        btn.disabled = false;
        btn.textContent = t('blocked.btn_unblock');
    }
}

async function blockUrlManual() {
    const url = document.getElementById('blockUrlInput').value.trim();
    const comment = document.getElementById('blockUrlCommentInput').value.trim();
    if (!url) {
        alert(t('blocked.alert_enter_url'));
        return;
    }
    try {
        const resp = await fetch('/api/firewall/block-url', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url, comment: comment || null }),
        });
        const data = await resp.json().catch(() => ({}));
        if (!resp.ok) throw new Error(data.detail || `HTTP ${resp.status}`);
        document.getElementById('blockUrlInput').value = '';
        document.getElementById('blockUrlCommentInput').value = '';
        await updateBlockedUrlsTable();
        switchBlockedTab('urls');
    } catch (err) {
        alert(t('blocked.err_block_failed') + err.message);
    }
}

async function unblockUrl(url, btn) {
    if (!confirm(t('blocked.confirm_unblock_url', { url }))) return;
    btn.disabled = true;
    btn.textContent = '...';
    try {
        const resp = await fetch('/api/firewall/unblock-url', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url }),
        });
        const data = await resp.json().catch(() => ({}));
        if (!resp.ok) throw new Error(data.detail || `HTTP ${resp.status}`);
        await updateBlockedUrlsTable();
    } catch (err) {
        alert(t('blocked.err_unblock_failed') + err.message);
        btn.disabled = false;
        btn.textContent = t('blocked.btn_unblock');
    }
}

function setCount(id, n) {
    const el = document.getElementById(id);
    if (el) el.textContent = (n || 0).toLocaleString(BLK_LOCALE);
}

function emptyRow(cols, msg) {
    return `<tr><td colspan="${cols}" style="text-align:center;color:var(--text-secondary);padding:1.5rem">${escapeHtml(msg)}</td></tr>`;
}

function formatTime(isoStr) {
    if (!isoStr) return '-';
    const d = new Date(isoStr);
    return d.toLocaleString(BLK_LOCALE, {
        day: '2-digit', month: '2-digit', year: '2-digit',
        hour: '2-digit', minute: '2-digit',
    });
}

// escapeHtml(), escapeAttr() and escapeJsAttr() live in js/common.js

// --- Known-user directory (basis of the invalid-username auto-block) ---------
// The rule blocks without asking anyone, so the operator must be able to see
// WHY a name counts as real (learned vs. manually added), correct it in both
// directions, and read back every block it produced.

async function updateKnownUsersTable() {
    try {
        const r = await fetch('/api/agent/invalid-user-directory');
        const d = await r.json();
        const entries = d.entries || [];
        setCount('tabCountKnownUsers', d.effective_count || 0);

        const status = document.getElementById('knownUsersStatus');
        if (status) {
            // "armed" is the field that matters: while false, nothing is blocked.
            const armed = d.armed
                ? `<span class="severity-badge severity-high">${t('blocked.knownuser_armed')}</span>`
                : `<span class="severity-badge severity-low">${t('blocked.knownuser_disarmed')}</span>`;
            // Generic names that still count as real (admin, root, …) weaken the
            // rule silently, so the warning names them instead of just counting.
            const shielding = d.generic_shielding || [];
            const genericWarn = shielding.length
                ? `<div class="text-warning mt-1" style="font-size:.8rem">${escapeHtml(t(
                    shielding.length === 1 ? 'blocked.generic_warning_one' : 'blocked.generic_warning_many',
                    { n: shielding.length, names: shielding.join(', ') },
                ))}</div>`
                : '';
            status.innerHTML = armed
                + ` <span class="text-secondary" style="font-size:.8rem">`
                + t('blocked.knownuser_counts', {
                    e: d.effective_count || 0, l: d.learned_count || 0,
                    m: d.manual_count || 0, x: d.excluded_count || 0,
                }) + '</span>'
                + (d.armed ? '' : `<div class="detail-error mt-1" style="font-size:.8rem">${t('blocked.knownuser_disarmed_hint', { n: d.min_directory })}</div>`)
                + genericWarn;
        }

        const tbody = document.getElementById('knownUsersTable');
        if (!tbody) return;
        if (!entries.length) {
            tbody.innerHTML = emptyRow(4, t('blocked.empty_knownusers'));
            return;
        }
        tbody.innerHTML = entries.map(e => {
            const origin = e.origin === 'learned'
                ? `<span class="severity-badge severity-medium">${t('blocked.origin_learned')}</span>`
                : e.origin === 'manual'
                    ? `<span class="severity-badge severity-low">${t('blocked.origin_manual')}</span>`
                    : `<span class="severity-badge severity-low">${t('blocked.origin_both')}</span>`;
            const counts = e.counts_as_real
                ? '<span class="text-success">✓</span>'
                : `<span class="text-danger">✗ ${escapeHtml(t('blocked.origin_excluded'))}</span>`;
            // A purely learned name has no override row to delete — offer the
            // exclusion instead, so the button always does something real.
            const action = e.origin === 'learned' && !e.excluded
                ? `<button class="restore-btn" onclick="knownUserSet('${escapeJsAttr(e.user)}','deny',this)">${t('blocked.btn_exclude')}</button>`
                : `<button class="restore-btn" onclick="knownUserRemove('${escapeJsAttr(e.user)}', this)">${t('blocked.btn_remove')}</button>`;
            // Only worth flagging while the name still counts — once excluded it
            // shields nobody, and a badge there would just be noise.
            const generic = e.generic && e.counts_as_real
                ? ` <span class="severity-badge severity-high">${t('blocked.generic_badge')}</span>`
                : '';
            return `<tr>
                <td><code>${escapeHtml(e.user)}</code>${generic}</td>
                <td>${origin}</td>
                <td>${counts}</td>
                <td>${action}</td>
            </tr>`;
        }).join('');
    } catch (err) {
        console.error('Known-user directory update failed:', err);
    }
}

async function knownUserAdd() {
    const user = document.getElementById('knownUserInput').value.trim();
    const status = document.getElementById('knownUserStatus').value || 'allow';
    const comment = document.getElementById('knownUserComment').value.trim();
    if (!user) { alert(t('blocked.alert_enter_user')); return; }
    try {
        const r = await fetch('/api/agent/invalid-user-directory', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ user, status, comment: comment || null }),
        });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
        document.getElementById('knownUserInput').value = '';
        document.getElementById('knownUserComment').value = '';
        await updateKnownUsersTable();
    } catch (err) { alert(t('blocked.err_generic') + err.message); }
}

async function knownUserSet(user, status, btn) {
    btn.disabled = true; btn.textContent = '...';
    try {
        const r = await fetch('/api/agent/invalid-user-directory', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ user, status, comment: null }),
        });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        await updateKnownUsersTable();
    } catch (err) {
        alert(t('blocked.err_generic') + err.message);
        btn.disabled = false; btn.textContent = t('blocked.btn_exclude');
    }
}

async function knownUserRemove(user, btn) {
    if (!confirm(t('blocked.confirm_knownuser_remove', { user }))) return;
    btn.disabled = true; btn.textContent = '...';
    try {
        const r = await fetch(`/api/agent/invalid-user-directory/${encodeURIComponent(user)}`, {method: 'DELETE'});
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        await updateKnownUsersTable();
    } catch (err) {
        alert(t('blocked.err_generic') + err.message);
        btn.disabled = false; btn.textContent = t('blocked.btn_remove');
    }
}

// --- Burned usernames: the instant-block trigger list ------------------------
// One attempt with a name from here is enough to block, so the list must be
// readable, correctable, and honest about which entries have ever fired.

// Kept so the status selector can re-render without another round-trip.
let BURNED_ENTRIES = [];

async function updateBurnedTable() {
    const tbody = document.getElementById('burnedTable');
    if (!tbody) return;
    try {
        const r = await fetch('/api/agent/invalid-usernames?limit=5000');
        const d = await r.json();
        const entries = d.entries || [];
        BURNED_ENTRIES = entries;
        setCount('tabCountBurned', d.active_count || 0);

        const status = document.getElementById('burnedStatus');
        if (status) {
            const state = d.enabled
                ? `<span class="severity-badge severity-high">${t('blocked.burned_on')}</span>`
                : `<span class="severity-badge severity-low">${t('blocked.burned_off')}</span>`;
            status.innerHTML = state
                + ` <span class="text-secondary" style="font-size:.8rem">`
                + t('blocked.burned_counts', {
                    a: d.active_count || 0, i: d.ignored_count || 0, s: d.shown || 0,
                }) + '</span>'
                + (d.enabled ? '' : `<div class="detail-error mt-1" style="font-size:.8rem;text-align:left;padding:0">${t('blocked.burned_off_hint')}</div>`);
        }

        renderBurnedTable();
    } catch (err) {
        console.error('Burned username list failed:', err);
    }
}

// Filters on the data, not on the rendered text: a status is a field, and
// matching it by the German word for it breaks the moment the page is English.
function renderBurnedTable() {
    const tbody = document.getElementById('burnedTable');
    if (!tbody) return;
    const mode = document.getElementById('burnedStatusFilter')?.value || '';
    const entries = BURNED_ENTRIES.filter(e =>
        mode === '' ? true
        : mode === 'shadowed' ? e.shadowed
        : mode === 'fired' ? (e.block_hits || 0) > 0
        // A shadowed name is listed as active but cannot fire — showing it under
        // "blocks on sight" would be the opposite of the truth.
        : mode === 'active' ? (e.status === 'active' && !e.shadowed)
        : e.status === mode);

    if (!entries.length) {
        tbody.innerHTML = emptyRow(6, mode
            ? t('blocked.empty_burned_filtered') : t('blocked.empty_burned'));
        return;
    }
    {
        tbody.innerHTML = entries.map(e => {
            const active = e.status === 'active';
            // Shadowed wins the display: the entry says "active" in the table but
            // the directory has declared it a real account, so it cannot fire.
            const badge = e.shadowed
                ? `<span class="severity-badge severity-low">${t('blocked.burned_shadowed')}</span>`
                : active
                    ? `<span class="severity-badge severity-high">${t('blocked.burned_active')}</span>`
                    : `<span class="severity-badge severity-low">${t('blocked.burned_ignored')}</span>`;
            const origin = e.origin === 'manual'
                ? ` <span class="badge text-bg-secondary">${t('blocked.origin_manual')}</span>` : '';
            // "Park" beats "delete": a deleted name is re-learned by the next
            // spray, so the exclusion would silently undo itself.
            const action = active
                ? `<button class="restore-btn" onclick="burnedSet('${escapeJsAttr(e.user)}','ignored',this)">${t('blocked.btn_burned_ignore')}</button>`
                : `<button class="restore-btn" onclick="burnedSet('${escapeJsAttr(e.user)}','active',this)">${t('blocked.btn_burned_activate')}</button>`;
            return `<tr>
                <td><code>${escapeHtml(e.user)}</code>${origin}</td>
                <td style="font-size:.78rem">${e.burned_by_ip ? `<code>${escapeHtml(e.burned_by_ip)}</code>` : '—'}</td>
                <td>${e.block_hits || 0}</td>
                <td style="font-size:.78rem">${formatTime(e.last_seen)}</td>
                <td>${badge}</td>
                <td>${action} <button class="restore-btn" onclick="burnedRemove('${escapeJsAttr(e.user)}', this)">${t('blocked.btn_remove')}</button></td>
            </tr>`;
        }).join('');
    }
}

async function burnedAdd() {
    const user = document.getElementById('burnedInput').value.trim();
    const comment = document.getElementById('burnedComment').value.trim();
    if (!user) { alert(t('blocked.alert_enter_user')); return; }
    try {
        const r = await fetch('/api/agent/invalid-usernames', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ user, status: 'active', comment: comment || null }),
        });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
        document.getElementById('burnedInput').value = '';
        document.getElementById('burnedComment').value = '';
        await updateBurnedTable();
    } catch (err) { alert(t('blocked.err_generic') + err.message); }
}

async function burnedSet(user, status, btn) {
    btn.disabled = true; btn.textContent = '...';
    try {
        const r = await fetch('/api/agent/invalid-usernames', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ user, status, comment: null }),
        });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        await updateBurnedTable();
    } catch (err) { alert(t('blocked.err_generic') + err.message); btn.disabled = false; }
}

async function burnedRemove(user, btn) {
    if (!confirm(t('blocked.confirm_burned_remove', { user }))) return;
    btn.disabled = true; btn.textContent = '...';
    try {
        const r = await fetch(`/api/agent/invalid-usernames/${encodeURIComponent(user)}`, {method: 'DELETE'});
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        await updateBurnedTable();
    } catch (err) { alert(t('blocked.err_generic') + err.message); btn.disabled = false; }
}

async function burnedBackfill() {
    const hours = parseInt(prompt(t('blocked.burned_backfill_prompt'), '72'), 10);
    if (!hours || Number.isNaN(hours)) return;
    try {
        const r = await fetch(`/api/agent/invalid-usernames/backfill?hours=${hours}`, {method: 'POST'});
        const d = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
        alert(t('blocked.burned_backfill_done', { n: d.burned || 0, o: d.offenders || 0, h: d.hours }));
        await updateBurnedTable();
    } catch (err) { alert(t('blocked.err_generic') + err.message); }
}

// --- Backtest: what the rule would have done, without doing it ---------------
// The rule is silent unless attacked, so this is the only way to tell a working
// rule from a broken one on a quiet day — and the only way to tune the
// thresholds against real traffic instead of guessing.

// What the last run showed, so the block action sends back exactly the sources
// the operator had in front of them — the server re-checks them anyway.
let BACKTEST_LAST = null;

async function runBacktest() {
    const summary = document.getElementById('backtestSummary');
    const tbody = document.getElementById('backtestTable');
    if (!summary || !tbody) return;
    BACKTEST_LAST = null;
    document.getElementById('backtestBlockBar').style.display = 'none';

    const hours = parseInt(document.getElementById('backtestHours').value, 10) || 24;
    const mu = document.getElementById('backtestMinUnknown').value.trim();
    const ma = document.getElementById('backtestMinAttempts').value.trim();
    const qs = new URLSearchParams({ hours: String(hours) });
    // Left blank means "use the configured thresholds" — don't send an empty
    // value, the endpoint would reject it.
    if (mu) qs.set('min_unknown', mu);
    if (ma) qs.set('min_attempts', ma);

    summary.innerHTML = `<span class="text-secondary" style="font-size:.8rem">${t('blocked.backtest_running')}</span>`;
    tbody.innerHTML = '';
    try {
        const r = await fetch(`/api/agent/invalid-user-backtest?${qs.toString()}`);
        const d = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);

        const offenders = d.offenders || [];
        let head = `<span style="font-size:.8rem">${escapeHtml(t('blocked.backtest_summary', {
            a: d.attempts_total || 0, p: d.attempts_public || 0,
            d: d.distinct_ips || 0, o: offenders.length,
            w: d.would_block_count || 0,
        }))}</span>`;
        // Which input was replayed changes how to read the result, so name it.
        head += `<div class="text-secondary mt-1" style="font-size:.75rem">${escapeHtml(d.source === 'database'
            ? t('blocked.backtest_source_db', { n: d.cache_hours })
            : t('blocked.backtest_source_cache'))}</div>`;
        if (d.truncated) {
            head += `<div class="text-warning mt-1" style="font-size:.75rem">${escapeHtml(t('blocked.backtest_truncated', { n: d.row_cap }))}</div>`;
        }
        // A disarmed directory yields zero hits for a reason that has nothing to
        // do with the traffic — saying so beats letting it read as all-clear.
        if (!d.armed) {
            head += `<div class="detail-error mt-1" style="font-size:.8rem;text-align:left;padding:0">${t('blocked.backtest_disarmed')}</div>`;
        } else if (offenders.length) {
            head += `<div class="text-secondary mt-1" style="font-size:.75rem">${escapeHtml(t('blocked.backtest_caveat', { w: d.live_window_minutes || 15 }))}</div>`;
            // The per-run cap is a silent truncation in the live rule; a test run
            // that hid it would promise more than a real run delivers.
            if ((d.would_block_count || 0) > (d.max_blocks_per_run || 0)) {
                head += `<div class="text-warning mt-1" style="font-size:.75rem">${escapeHtml(t('blocked.backtest_cap', { n: d.max_blocks_per_run }))}</div>`;
            }
        }
        summary.innerHTML = head;

        if (!offenders.length) {
            tbody.innerHTML = emptyRow(5, (d.attempts_total || 0) === 0
                ? t('blocked.backtest_no_data') : t('blocked.backtest_empty'));
            return;
        }

        // Offer the retro-block only for hits a live run would actually act on,
        // and only while the directory is armed — otherwise there is no evidence.
        const blockable = offenders.filter(o => o.would_block).map(o => o.ip);
        if (d.armed && blockable.length) {
            BACKTEST_LAST = { hours: d.hours, ips: blockable, params: { mu, ma } };
            document.getElementById('backtestBlockLabel').textContent =
                t('blocked.backtest_block_btn', { n: blockable.length });
            document.getElementById('backtestBlockBar').style.display = '';
        }
        tbody.innerHTML = offenders.map(o => {
            const verdict = o.whitelisted
                ? `<span class="severity-badge severity-low">${t('blocked.verdict_whitelisted')}</span>`
                : o.already_blocked
                    ? `<span class="severity-badge severity-medium">${t('blocked.verdict_already_blocked')}</span>`
                    : `<span class="severity-badge severity-high">${t('blocked.verdict_would_block')}</span>`;
            const names = (o.unknown_users || []).slice(0, 6).map(escapeHtml).join(', ');
            const more = (o.unknown_user_count || 0) > 6 ? ' …' : '';
            return `<tr>
                <td><code>${escapeHtml(o.ip)}</code></td>
                <td>${escapeHtml(o.country || '-')}</td>
                <td>${o.attempts || 0}</td>
                <td>${o.unknown_user_count || 0}<div class="text-secondary" style="font-size:.72rem">${names}${more}</div></td>
                <td>${verdict}</td>
            </tr>`;
        }).join('');
    } catch (err) {
        summary.innerHTML = `<span class="detail-error" style="font-size:.8rem;padding:0">${escapeHtml(t('blocked.err_backtest') + err.message)}</span>`;
    }
}

async function blockBacktestHits() {
    if (!BACKTEST_LAST || !BACKTEST_LAST.ips.length) return;
    const { hours, ips, params } = BACKTEST_LAST;
    if (!confirm(t('blocked.backtest_block_confirm', { n: ips.length, h: hours }))) return;

    const bar = document.getElementById('backtestBlockBar');
    const label = document.getElementById('backtestBlockLabel');
    const previous = label.textContent;
    label.textContent = t('blocked.backtest_block_running');
    bar.querySelector('button').disabled = true;
    try {
        const payload = { hours, ips };
        if (params.mu) payload.min_unknown = parseInt(params.mu, 10);
        if (params.ma) payload.min_attempts = parseInt(params.ma, 10);
        const r = await fetch('/api/agent/invalid-user-backtest-block', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload),
        });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);

        const n = d.blocked_count || 0, s = (d.skipped || []).length;
        alert(n === 0 ? t('blocked.backtest_blocked_none')
            : s ? t('blocked.backtest_blocked_partial', { n, s })
                : t('blocked.backtest_blocked_ok', { n }));
        // Re-run so the table reflects the new reality: what was just blocked
        // now reads "already blocked" instead of still inviting the same action.
        await runBacktest();
        await updateBlockedIpsTable();
        await updateKnownUserDecisions();
    } catch (err) {
        alert(t('blocked.err_backtest_block') + err.message);
        label.textContent = previous;
    } finally {
        // Re-enabled on every path. Only the error path used to do it, so a
        // successful partial block (some IPs skipped) left the operator with a
        // visible bar and a dead button until they reloaded the page.
        const btn = document.getElementById('backtestBlockBar')?.querySelector('button');
        if (btn) btn.disabled = false;
    }
}

// Audit trail: every block this rule made, with the evidence that caused it.
async function updateKnownUserDecisions() {
    const tbody = document.getElementById('knownUserDecisionsTable');
    if (!tbody) return;
    try {
        const r = await fetch('/api/agent/decisions?source_type=invalid_user&limit=50');
        const d = await r.json();
        const items = d.items || [];
        if (!items.length) {
            tbody.innerHTML = emptyRow(3, t('blocked.empty_knownuser_decisions'));
            return;
        }
        tbody.innerHTML = items.map(it => {
            const ctx = (it.action_args && it.action_args.context) || {};
            const users = (ctx.unknown_users || []).slice(0, 6).map(escapeHtml).join(', ');
            const more = (ctx.unknown_user_count || 0) > 6 ? ' …' : '';
            const evidence = t('blocked.knownuser_evidence', {
                n: ctx.unknown_user_count || 0,
                a: ctx.attempts || 0,
                w: ctx.window_minutes || 0,
            });
            return `<tr>
                <td>${formatTime(it.created_at)}</td>
                <td><code>${escapeHtml(it.source_ip || '-')}</code>${ctx.country ? ` <span class="text-secondary" style="font-size:.72rem">${escapeHtml(ctx.country)}</span>` : ''}</td>
                <td>${escapeHtml(evidence)}<div class="text-secondary" style="font-size:.72rem">${users}${more}</div></td>
            </tr>`;
        }).join('');
    } catch (err) {
        console.error('Known-user decisions failed:', err);
    }
}

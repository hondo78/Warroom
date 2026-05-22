document.addEventListener('DOMContentLoaded', () => {
    initMap();
    initCharts();
    initTableFilters();
    refreshAll();

    // Auto-refresh every 60s
    setInterval(refreshAll, 60000);

    document.getElementById('timeRange').addEventListener('change', refreshAll);
});

// --- Generic client-side table search filter ---

const _filterInputs = {};  // tbodyId -> HTMLInputElement

function initTableFilters() {
    document.querySelectorAll('input[data-filter-for]').forEach(input => {
        const tbodyId = input.dataset.filterFor;
        const tbody = document.getElementById(tbodyId);
        if (!tbody) return;
        _filterInputs[tbodyId] = input;
        input.addEventListener('input', () => applyTableFilter(tbody, input.value));

        // Re-apply filter whenever rows are replaced (every refreshAll cycle).
        new MutationObserver(() => {
            const term = (_filterInputs[tbodyId]?.value || '').trim();
            if (term) applyTableFilter(tbody, term);
        }).observe(tbody, {childList: true});
    });
}

function applyTableFilter(tbody, term) {
    const t = (term || '').toLowerCase().trim();
    const rows = tbody.querySelectorAll(':scope > tr');
    let visible = 0;
    rows.forEach(tr => {
        const match = !t || tr.textContent.toLowerCase().includes(t);
        tr.classList.toggle('filter-hidden', !match);
        if (match) visible++;
    });
    // Don't hide a placeholder/empty row if it's the only one.
    if (rows.length === 1 && rows[0].querySelector('td[colspan]')) {
        rows[0].classList.remove('filter-hidden');
    }
}

function getDays() {
    return parseInt(document.getElementById('timeRange').value, 10) || 7;
}

async function refreshAll() {
    const days = getDays();
    await Promise.all([
        updateSummary(),
        updateHealthTile(),
        updateDevicesStats(),
        updateTimeline(days),
        updateSeverity(days),
        updateCategories(days),
        updateAttackers(days),
        updateFirewallStats(days),
        updateMap(days),
        updateAlertsTable(),
        updateEventsTable(),
        updateDetectionsTable(),
        updateDevicesTable(),
        updateFwLogsTable(),
        updateBlockedIpsTable(),
        updateFailedLogins(),
        updateWafWidget(),
        updateIpsWidget(),
    ]);
}

async function updateIpsWidget() {
    try {
        const days = parseInt(document.getElementById('ipsDays')?.value || '7', 10);
        const [statsResp, recentResp] = await Promise.all([
            fetch(`/api/firewall-logs/ips/stats?days=${days}`),
            fetch(`/api/firewall-logs/ips/recent?days=${days}&limit=300`),
        ]);
        const stats = await statsResp.json();
        const items = await recentResp.json();

        // Stat card
        const totalEl = document.getElementById('ipsTotal');
        const subEl = document.getElementById('ipsSub');
        if (totalEl) totalEl.textContent = (stats.total || 0).toLocaleString('de-DE');
        if (subEl) {
            const dropped = stats.dropped || 0;
            const high = stats.high_severity || 0;
            const parts = [`${(stats.last_24h || 0).toLocaleString('de-DE')} in 24h`];
            parts.push(`${dropped.toLocaleString('de-DE')} blockiert`);
            if (high > 0) parts.push(`${high.toLocaleString('de-DE')} high/critical`);
            subEl.textContent = parts.join(' · ');
        }

        // Summary block
        const sumEl = document.getElementById('ipsSummary');
        if (sumEl) {
            const block = (title, items, fmt) => {
                if (!items || !items.length) return '';
                const pills = items.map(fmt).join('');
                return `<div class="waf-sum-block"><span class="waf-sum-title">${title}</span>${pills}</div>`;
            };
            sumEl.innerHTML = [
                block('Top Quellen', stats.top_attackers, a =>
                    `<span class="waf-pill" title="${escapeHtml([a.country, a.city].filter(Boolean).join(', '))}">${escapeHtml(a.ip)} <em>${a.count}</em></span>`),
                block('Top Signaturen', stats.top_signatures, s => {
                    const label = s.signature_id ? `${s.signature_id} · ${s.signature}` : s.signature;
                    return `<span class="waf-pill waf-pill-attack" title="${escapeHtml(s.signature || '')}">${escapeHtml(truncate(label, 50))} <em>${s.count}</em></span>`;
                }),
                block('Top Kategorien', stats.top_categories, c =>
                    `<span class="waf-pill">${escapeHtml(truncate(c.category, 40))} <em>${c.count}</em></span>`),
            ].join('');
        }

        // Recent events table
        const tbody = document.getElementById('ipsTable');
        if (!items.length) {
            tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;color:var(--text-secondary);padding:1.5rem">Keine IPS-Detections. SFOS IPS/IDP-Logs an Syslog-Server (Port 5514) senden.</td></tr>';
            return;
        }
        tbody.innerHTML = items.map(l => {
            const blockedBadge = l.source_blocked
                ? ' <span class="blocked-badge" title="IP geblockt">BLOCKED</span>'
                : '';
            const blockLink = l.source_ip && !l.source_blocked && isPublicIpClient(l.source_ip)
                ? ` <a class="block-link" href="#" onclick="event.preventDefault();blockFromCell('${l.source_ip}', 'IPS: ${(l.signature_msg || l.threat || 'attack').replace(/'/g, '').slice(0,80)}')">[block]</a>`
                : '';
            const osintBtn = osintButton(l.source_ip);
            const srcCell = l.source_ip
                ? `<code>${escapeHtml(l.source_ip)}${l.source_port ? ':' + l.source_port : ''}</code>${blockedBadge}${blockLink}${osintBtn}`
                : '-';
            const dstCell = l.destination_ip
                ? `<code>${escapeHtml(l.destination_ip)}${l.destination_port ? ':' + l.destination_port : ''}</code>`
                : '-';
            const sigText = l.signature_msg || l.threat || l.message || '';
            const sigLabel = l.signature_id ? `${l.signature_id} · ${sigText}` : sigText;
            const sigCell = sigText
                ? `<code class="waf-url" title="${escapeHtml(sigText)}" onclick="this.classList.toggle('expanded')">${escapeHtml(sigLabel)}</code>`
                : '<span class="muted-cell">—</span>';
            const action = l.action;
            const actionLower = (action || '').toLowerCase();
            const isBlock = ['drop','dropped','deny','denied','block','blocked','reject','rejected'].includes(actionLower);
            const isAllow = ['allow','allowed','accept','accepted','detect','detected'].includes(actionLower);
            let actionCell;
            if (action) {
                const cls = isBlock ? 'waf-action-block' : (isAllow ? 'waf-action-allow' : 'waf-action-other');
                actionCell = `<span class="waf-action ${cls}">${escapeHtml(action)}</span>`;
            } else {
                actionCell = '<span class="muted-cell" title="Keine Action im Log">—</span>';
            }
            return `
            <tr title="${escapeHtml([l.platform, l.rule_priority].filter(Boolean).join(' / '))}">
                <td>${formatTime(l.created_at)}</td>
                <td>${severityBadge(l.severity)}</td>
                <td>${srcCell}</td>
                <td>${escapeHtml([l.country, l.city].filter(Boolean).join(', ') || '-')}</td>
                <td>${dstCell}</td>
                <td>${escapeHtml(l.protocol || '-')}</td>
                <td>${sigCell}</td>
                <td>${escapeHtml(l.category || l.log_subtype || '-')}</td>
                <td>${actionCell}</td>
            </tr>`;
        }).join('');
    } catch (err) {
        console.error('IPS widget update failed:', err);
    }
}

async function updateWafWidget() {
    try {
        const days = parseInt(document.getElementById('wafDays')?.value || '7', 10);
        const includeAllowed = !!document.getElementById('wafIncludeAllowed')?.checked;
        const [statsResp, recentResp] = await Promise.all([
            fetch(`/api/firewall-logs/waf/stats?days=${days}`),
            fetch(`/api/firewall-logs/waf/recent?days=${days}&limit=300&include_allowed=${includeAllowed}`),
        ]);
        const stats = await statsResp.json();
        const items = await recentResp.json();

        // Stat card — counts attacks only (allowed traffic isn't a "detection")
        const totalEl = document.getElementById('wafTotal');
        const subEl = document.getElementById('wafSub');
        if (totalEl) totalEl.textContent = (stats.total || 0).toLocaleString('de-DE');
        if (subEl) {
            const blocked = stats.blocked || 0;
            const allowed = stats.allowed_all || 0;
            const parts = [`${(stats.last_24h || 0).toLocaleString('de-DE')} in 24h`];
            parts.push(`${blocked.toLocaleString('de-DE')} blockiert`);
            if (allowed > 0) parts.push(`${allowed.toLocaleString('de-DE')} sauber`);
            subEl.textContent = parts.join(' · ');
        }

        // Summary block: top attackers / hosts / attacks as compact pills
        const sumEl = document.getElementById('wafSummary');
        if (sumEl) {
            const block = (title, items, fmt) => {
                if (!items || !items.length) return '';
                const pills = items.map(fmt).join('');
                return `<div class="waf-sum-block"><span class="waf-sum-title">${title}</span>${pills}</div>`;
            };
            sumEl.innerHTML = [
                block('Top Quellen', stats.top_attackers, a =>
                    `<span class="waf-pill" title="${escapeHtml([a.country, a.city].filter(Boolean).join(', '))}">${escapeHtml(a.ip)} <em>${a.count}</em></span>`),
                block('Top Hosts', stats.top_hosts, h =>
                    `<span class="waf-pill">${escapeHtml(truncate(h.host, 40))} <em>${h.count}</em></span>`),
                block('Top Attacks', stats.top_attacks, a =>
                    `<span class="waf-pill waf-pill-attack">${escapeHtml(truncate(a.attack, 40))} <em>${a.count}</em></span>`),
            ].join('');
        }

        // Recent events table
        const tbody = document.getElementById('wafTable');
        if (!items.length) {
            tbody.innerHTML = '<tr><td colspan="10" style="text-align:center;color:var(--text-secondary);padding:1.5rem">Keine WAF-Detections. SFOS Web Server Protection / WAF-Logs an Syslog-Server (Port 5514) senden.</td></tr>';
            return;
        }
        tbody.innerHTML = items.map(l => {
            const blockedBadge = l.source_blocked
                ? ' <span class="blocked-badge" title="IP geblockt">BLOCKED</span>'
                : '';
            const blockLink = l.source_ip && !l.source_blocked && isPublicIpClient(l.source_ip)
                ? ` <a class="block-link" href="#" onclick="event.preventDefault();blockFromCell('${l.source_ip}', 'WAF: ${(l.reason || l.threat || 'attack').replace(/'/g, '').slice(0,80)}')">[block]</a>`
                : '';
            const osintBtn = osintButton(l.source_ip);
            const srcCell = l.source_ip
                ? `<code>${escapeHtml(l.source_ip)}</code>${blockedBadge}${blockLink}${osintBtn}`
                : '-';

            const reason = l.reason || l.threat || l.message;
            const reasonCell = reason
                ? escapeHtml(reason)
                : '<span class="muted-cell" title="Keine Attack-Begründung im Log — vermutlich erlaubter Request">—</span>';

            const action = l.action;
            const actionLower = (action || '').toLowerCase();
            const isBlock = ['deny','denied','drop','dropped','block','blocked','reject','rejected'].includes(actionLower);
            const isAllow = ['allow','allowed','accept','accepted','pass','passed'].includes(actionLower);
            let actionCell;
            if (action) {
                const cls = isBlock ? 'waf-action-block' : (isAllow ? 'waf-action-allow' : 'waf-action-other');
                actionCell = `<span class="waf-action ${cls}">${escapeHtml(action)}</span>`;
            } else {
                actionCell = '<span class="muted-cell" title="Keine Action im Log gesetzt">—</span>';
            }

            const status = l.http_status
                ? `<span class="waf-status waf-status-${(String(l.http_status)[0] || 'x')}xx">${escapeHtml(l.http_status)}</span>`
                : '-';

            const fullUrl = l.http_query || '';
            const urlCell = fullUrl
                ? `<code class="waf-url" title="${escapeHtml(fullUrl)}" onclick="this.classList.toggle('expanded')">${escapeHtml(fullUrl)}</code>`
                : '-';

            const isBlockable = l.source_ip && !l.source_blocked && isPublicIpClient(l.source_ip);
            const blockComment = `WAF: ${(l.reason || l.threat || 'attack').replace(/"/g, '').slice(0, 80)}`;
            return `
            <tr data-ip="${escapeHtml(l.source_ip || '')}" data-blockable="${isBlockable ? '1' : '0'}" data-block-comment="${escapeHtml(blockComment)}" title="${escapeHtml(l.user_agent || '')}">
                <td>${formatTime(l.created_at)}</td>
                <td>${severityBadge(l.severity)}</td>
                <td>${srcCell}</td>
                <td>${escapeHtml([l.country, l.city].filter(Boolean).join(', ') || '-')}</td>
                <td>${escapeHtml(l.host || '-')}</td>
                <td>${escapeHtml(l.http_method || '-')}</td>
                <td>${urlCell}</td>
                <td>${status}</td>
                <td>${reasonCell}</td>
                <td>${actionCell}</td>
            </tr>`;
        }).join('');
    } catch (err) {
        console.error('WAF widget update failed:', err);
    }
}

async function blockAllWaf() {
    await blockAllFromTable({
        tbodyId: 'wafTable',
        buttonId: 'wafBlockAll',
        defaultComment: 'bulk: WAF',
        refresh: () => Promise.all([updateBlockedIpsTable(), updateWafWidget()]),
    });
}

async function updateFailedLogins() {
    try {
        const days = parseInt(document.getElementById('failedLoginsDays')?.value || '7', 10);
        const resp = await fetch(`/api/firewall-logs/failed-logins?days=${days}&limit=300`);
        const items = await resp.json();
        const tbody = document.getElementById('failedLoginsTable');
        if (!items.length) {
            tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;color:var(--text-secondary);padding:1.5rem">Keine fehlgeschlagenen Logins. SFOS Authentication-/Admin-Logs an Syslog-Server (UDP/TCP 5514) aktivieren: System → Administration → Notification settings.</td></tr>';
            return;
        }
        tbody.innerHTML = items.map(l => {
            const isBlockable = isPublicIpClient(l.source_ip);
            const blockedTitle = l.blocked
                ? `IP ist auf der Firewall geblockt${l.blocked_at ? ' seit ' + formatTime(l.blocked_at) : ''}${l.blocked_status ? ' (' + l.blocked_status + ')' : ''}`
                : '';
            const blockedBadge = l.blocked
                ? ` <span class="blocked-badge" title="${escapeHtml(blockedTitle)}">BLOCKED</span>`
                : '';
            let actionCell;
            if (l.blocked) {
                actionCell = `<span class="ack-label" title="${escapeHtml(blockedTitle)}">geblockt</span>`;
            } else if (isBlockable) {
                actionCell = `<button class="ack-btn" onclick="blockFromCell('${l.source_ip}', 'failed-login: ${(l.last_message || '').replace(/'/g, '').slice(0,80)}')">Blocken</button>`;
            } else {
                actionCell = '<span class="ack-label">privat</span>';
            }
            const users = (l.recent_users || []).filter(Boolean).join(', ');
            const counter24h = l.attempts_24h > 0
                ? `<span class="login-count login-count-hot">${fmtCount(l.attempts_24h)}</span>`
                : `<span class="login-count">0</span>`;
            const counterTotal = `<span class="login-count">${fmtCount(l.attempts_total)}</span>`;
            const blockComment = `failed-login: ${(l.last_message || '').replace(/"/g, '').slice(0, 80)}`;
            return `
                <tr class="${l.blocked ? 'row-blocked' : ''}" data-ip="${escapeHtml(l.source_ip || '')}" data-blockable="${(!l.blocked && isBlockable) ? '1' : '0'}" data-block-comment="${escapeHtml(blockComment)}" title="${escapeHtml(l.last_message || '')}">
                    <td><code>${escapeHtml(l.source_ip)}</code>${blockedBadge}${osintButton(l.source_ip)}</td>
                    <td>${escapeHtml([l.country, l.city].filter(Boolean).join(', ') || '-')}</td>
                    <td>${counter24h}</td>
                    <td>${counterTotal}</td>
                    <td>${escapeHtml(users || '-')}</td>
                    <td>${escapeHtml(l.component || '-')}${l.mechanism ? ' / ' + escapeHtml(l.mechanism) : ''}</td>
                    <td>${formatTime(l.last_attempt)}</td>
                    <td>${escapeHtml(truncate(l.last_message, 60))}</td>
                    <td>${actionCell}</td>
                </tr>`;
        }).join('');
    } catch (err) {
        console.error('Failed-logins update failed:', err);
    }
}

async function blockAllFromTable({ tbodyId, buttonId, defaultComment, refresh }) {
    const tbody = document.getElementById(tbodyId);
    if (!tbody) return;
    const rows = tbody.querySelectorAll('tr[data-blockable="1"]:not(.filter-hidden)');
    const ips = [];
    const seen = new Set();
    rows.forEach(tr => {
        const ip = tr.dataset.ip;
        if (!ip || seen.has(ip)) return;
        seen.add(ip);
        ips.push(ip);
    });
    if (!ips.length) {
        alert('Keine blockbaren IPs in der aktuellen Ansicht.');
        return;
    }
    if (!confirm(`${ips.length} IP(s) auf die Blocklist setzen?`)) return;

    const btn = buttonId ? document.getElementById(buttonId) : null;
    const originalLabel = btn ? btn.textContent : '';
    if (btn) { btn.disabled = true; btn.textContent = `Blocke ${ips.length}…`; }

    try {
        const resp = await fetch('/api/firewall/block-ips', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ips, comment: defaultComment }),
        });
        const data = await resp.json().catch(() => ({}));
        if (!resp.ok) throw new Error(data.detail || `HTTP ${resp.status}`);
    } catch (err) {
        alert('Block fehlgeschlagen: ' + err.message);
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = originalLabel; }
        if (refresh) await refresh();
    }
}

async function blockAllFailedLogins() {
    await blockAllFromTable({
        tbodyId: 'failedLoginsTable',
        buttonId: 'failedLoginsBlockAll',
        defaultComment: 'bulk: failed-login',
        refresh: () => Promise.all([updateBlockedIpsTable(), updateFailedLogins()]),
    });
}

function fmtCount(n) {
    return (n || 0).toLocaleString('de-DE');
}

async function updateBlockedIpsTable() {
    try {
        const resp = await fetch('/api/firewall/blocked-ips');
        const payload = await resp.json();

        const feedEl = document.getElementById('iocFeedUrlDashboard');
        if (feedEl) feedEl.textContent = `${window.location.origin}/ioc_IP`;

        const tbody = document.getElementById('blockedIpsTable');
        if (!payload.items || payload.items.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--text-secondary);padding:1.5rem">Keine geblockten IPs</td></tr>';
            return;
        }
        tbody.innerHTML = payload.items.map(b => `
            <tr>
                <td><code>${b.ip}</code>${osintButton(b.ip)}</td>
                <td>${b.comment || '-'}</td>
                <td>${formatTime(b.blocked_at)}</td>
                <td><button class="restore-btn" onclick="unblockIp('${b.ip}', this)">Unblock</button></td>
            </tr>`).join('');
    } catch (err) {
        console.error('Blocked IPs update failed:', err);
    }
}

async function blockIpManual() {
    const ip = document.getElementById('blockIpInput').value.trim();
    const comment = document.getElementById('blockCommentInput').value.trim();
    if (!ip) {
        alert('Bitte IP angeben');
        return;
    }
    await blockIpRequest(ip, comment);
    document.getElementById('blockIpInput').value = '';
    document.getElementById('blockCommentInput').value = '';
}

async function blockIpRequest(ip, comment) {
    try {
        const resp = await fetch('/api/firewall/block-ip', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, comment: comment || null }),
        });
        const data = await resp.json().catch(() => ({}));
        if (!resp.ok) throw new Error(data.detail || `HTTP ${resp.status}`);
        await updateBlockedIpsTable();
    } catch (err) {
        alert('Block fehlgeschlagen: ' + err.message);
    }
}

async function unblockIp(ip, btn) {
    if (!confirm(`IP ${ip} aus Blocklist entfernen?`)) return;
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
        alert('Unblock fehlgeschlagen: ' + err.message);
        btn.disabled = false;
        btn.textContent = 'Unblock';
    }
}

async function blockFromCell(ip, comment) {
    if (!confirm(`IP ${ip} auf die Blocklist setzen?`)) return;
    await blockIpRequest(ip, comment);
}

function isPublicIpClient(ip) {
    if (!ip) return false;
    const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(ip);
    if (!m) return false;
    const a = +m[1], b = +m[2];
    if (a === 10) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 127) return false;
    if (a === 0) return false;
    if (a === 169 && b === 254) return false;
    if (a >= 224) return false;
    return true;
}

let _deviceSearchTimer = null;
function debouncedReloadDevices() {
    clearTimeout(_deviceSearchTimer);
    _deviceSearchTimer = setTimeout(updateDevicesTable, 250);
}

async function updateDevicesStats() {
    try {
        const resp = await fetch('/api/endpoints/stats');
        const data = await resp.json();
        document.getElementById('devicesTotal').textContent = (data.total || 0).toLocaleString();
        const isolated = (data.by_isolation && data.by_isolation.isolated) || 0;
        const bad = (data.by_health && data.by_health.bad) || 0;
        const sub = [];
        sub.push(`${isolated} isoliert`);
        if (bad > 0) sub.push(`${bad} bad`);
        sub.push(`${data.online || 0} online`);
        document.getElementById('devicesSub').textContent = sub.join(' · ');
    } catch (err) {
        console.error('Devices stats failed:', err);
    }
}

async function updateDevicesTable() {
    try {
        const params = new URLSearchParams({ limit: '200' });
        const search = document.getElementById('deviceSearch')?.value.trim();
        const health = document.getElementById('deviceHealth')?.value;
        const isolation = document.getElementById('deviceIsolation')?.value;
        if (search) params.set('search', search);
        if (health) params.set('health', health);
        if (isolation) params.set('isolation', isolation);

        const resp = await fetch('/api/endpoints/list?' + params.toString());
        const devices = await resp.json();
        const tbody = document.getElementById('devicesTable');

        if (devices.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--text-secondary);padding:2rem">Keine Endpoints. Sophos Central muss Geräte managen, dann auf "Daten sammeln" klicken.</td></tr>';
            return;
        }

        tbody.innerHTML = devices.map(d => {
            const isolated = d.isolation === 'isolated';
            const actionBtn = isolated
                ? `<button class="restore-btn" onclick="setIsolation('${d.id}', false, this)">Restore</button>`
                : `<button class="isolate-btn" onclick="setIsolation('${d.id}', true, this)">Isolate</button>`;
            return `
            <tr${isolated ? ' class="device-isolated"' : ''}>
                <td>${d.hostname || '-'}</td>
                <td>${d.os || '-'}</td>
                <td>${d.ipv4 || '-'}</td>
                <td>${formatTime(d.last_seen_at)}</td>
                <td>${healthBadge(d.health)}</td>
                <td>${isolationBadge(d.isolation)}</td>
                <td>${actionBtn}</td>
            </tr>`;
        }).join('');
    } catch (err) {
        console.error('Devices table failed:', err);
    }
}

function healthBadge(health) {
    const h = (health || 'unknown').toLowerCase();
    return `<span class="health-badge health-${h}">${h}</span>`;
}

function isolationBadge(status) {
    const s = (status || 'unknown');
    const cls = s === 'isolated' ? 'isolation-on' : 'isolation-off';
    return `<span class="isolation-badge ${cls}">${s}</span>`;
}

async function setIsolation(endpointId, enabled, btn) {
    const verb = enabled ? 'isolieren' : 'wiederherstellen';
    const comment = prompt(`Endpoint ${verb}? Optionaler Kommentar:`, '');
    if (comment === null) return;  // user cancelled

    btn.disabled = true;
    btn.textContent = '...';
    try {
        const path = enabled ? 'isolate' : 'restore';
        const resp = await fetch(`/api/endpoints/${encodeURIComponent(endpointId)}/${path}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ comment: comment || null }),
        });
        if (!resp.ok) {
            const err = await resp.json().catch(() => ({}));
            throw new Error(err.detail || `HTTP ${resp.status}`);
        }
        await Promise.all([updateDevicesTable(), updateDevicesStats()]);
    } catch (err) {
        alert(`Aktion fehlgeschlagen: ${err.message}`);
        btn.disabled = false;
        btn.textContent = enabled ? 'Isolate' : 'Restore';
    }
}

async function updateHealthTile() {
    const valueEl = document.getElementById('healthScore');
    const subEl = document.getElementById('healthScoreSub');
    const cardEl = document.getElementById('healthCard');
    try {
        const resp = await fetch('/api/sophos/health-check');
        const payload = await resp.json();
        if (!payload.available) {
            valueEl.textContent = 'n/a';
            subEl.textContent = 'API nicht verfügbar';
            return;
        }
        // Sophos returns { overall: "good"|"attention"|"poor", services: {...} }
        // — extract whatever is sensible.
        const data = payload.data || {};
        const overall = data.overall || data.status || 'unknown';
        const issues = countHealthIssues(data);
        valueEl.textContent = overall.toUpperCase();
        subEl.textContent = issues > 0
            ? `${issues} Punkt${issues === 1 ? '' : 'e'} mit Aufmerksamkeitsbedarf`
            : 'Alles im grünen Bereich';
        cardEl.classList.remove('critical', 'warning', 'info', 'success');
        cardEl.classList.add(overallToClass(overall));
    } catch (err) {
        console.error('Health update failed:', err);
        valueEl.textContent = '-';
        subEl.textContent = 'Fehler beim Laden';
    }
}

function countHealthIssues(data) {
    // Sophos response format varies; try common shapes.
    if (Array.isArray(data.endpoint?.protection?.alerts)) {
        return data.endpoint.protection.alerts.length;
    }
    if (typeof data.numberOfAlerts === 'number') {
        return data.numberOfAlerts;
    }
    let n = 0;
    for (const v of Object.values(data.services || {})) {
        if (v && (v.status === 'attention' || v.status === 'poor')) n++;
    }
    return n;
}

function overallToClass(overall) {
    const o = (overall || '').toLowerCase();
    if (o === 'good' || o === 'ok' || o === 'green') return 'success';
    if (o === 'attention' || o === 'warning' || o === 'yellow') return 'warning';
    if (o === 'poor' || o === 'critical' || o === 'red') return 'critical';
    return 'info';
}

async function updateSummary() {
    try {
        const resp = await fetch('/api/stats/summary');
        const data = await resp.json();

        document.getElementById('totalAlerts').textContent = data.total_alerts.toLocaleString();
        document.getElementById('alerts24h').textContent = data.alerts_24h.toLocaleString();
        document.getElementById('totalEvents').textContent = data.total_events.toLocaleString();
        document.getElementById('events24h').textContent = data.events_24h.toLocaleString();
        document.getElementById('totalDetections').textContent = data.total_detections.toLocaleString();
        document.getElementById('detections24h').textContent = data.detections_24h.toLocaleString();
        document.getElementById('totalFwLogs').textContent = (data.total_fw_logs || 0).toLocaleString();
        document.getElementById('fwLogs24h').textContent = (data.fw_logs_24h || 0).toLocaleString();
        document.getElementById('highSeverity').textContent = data.high_severity_week.toLocaleString();
    } catch (err) {
        console.error('Summary update failed:', err);
    }
}

function formatTime(isoStr) {
    if (!isoStr) return '-';
    const d = new Date(isoStr);
    return d.toLocaleString('de-DE', {
        day: '2-digit', month: '2-digit',
        hour: '2-digit', minute: '2-digit',
    });
}

function severityBadge(severity) {
    const s = (severity || 'unknown').toLowerCase();
    return `<span class="severity-badge severity-${s}">${s}</span>`;
}

function truncate(str, len) {
    if (!str) return '-';
    return str.length > len ? str.substring(0, len) + '...' : str;
}

function deviceTypeBadge(type) {
    if (!type) return '-';
    const t = String(type).toLowerCase();
    return `<span class="device-type-badge device-type-${t}">${t}</span>`;
}

function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function ipWithActions(ip, comment) {
    if (!ip) return '';
    const isPub = isPublicIpClient(ip);
    const blockLink = isPub
        ? ` <a class="block-link" href="#" onclick="event.preventDefault();event.stopPropagation();blockFromCell('${ip}', '${(comment || '').replace(/'/g, '').slice(0,80)}')">[block]</a>`
        : '';
    return `<code>${escapeHtml(ip)}</code>${blockLink}${osintButton(ip)}`;
}

function sourceCellWithBlock(ip, country, comment, destIp) {
    if (!ip && !destIp) return '-';
    const countryStr = country ? ` <span class="ip-country">(${escapeHtml(country)})</span>` : '';
    const srcPart = ip ? `${ipWithActions(ip, comment)}${countryStr}` : '';
    // Show destination too — for ATP/firewall alerts the threat IP is usually
    // the destination. Skip if identical to source or absent.
    const dstPart = destIp && destIp !== ip
        ? `<div class="ip-dst-row"><span class="ip-arrow">→</span> ${ipWithActions(destIp, comment)}</div>`
        : '';
    return srcPart + dstPart || ipWithActions(destIp, comment);
}

async function updateAlertsTable() {
    try {
        const resp = await fetch('/api/alerts/recent?limit=200');
        const alerts = await resp.json();
        const tbody = document.getElementById('alertsTable');

        tbody.innerHTML = alerts.map(a => {
            const acked = !!a.acknowledged_at;
            const cls = ['alert-row'];
            if (acked) cls.push('alert-acked');
            const actionCell = acked
                ? `<span class="ack-label">${escapeHtml(a.acknowledged_action || 'acknowledged')}</span>`
                : `<button class="ack-btn" data-id="${a.id}" onclick="event.stopPropagation();acknowledgeAlert('${a.id}', this)">Ack</button>`;
            const desc = escapeHtml(a.description || '');
            return `
            <tr class="${cls.join(' ')}" onclick="showAlertDetail('${a.id}')" title="${desc}">
                <td>${formatTime(a.created_at)}</td>
                <td>${severityBadge(a.severity)}</td>
                <td>${escapeHtml(truncate(a.type, 30))}</td>
                <td>${escapeHtml(truncate(a.description, 80))}</td>
                <td>${sourceCellWithBlock(a.source_ip, a.country, a.type || 'alert', a.destination_ip)}</td>
                <td>${actionCell}</td>
            </tr>`;
        }).join('');
    } catch (err) {
        console.error('Alerts table update failed:', err);
    }
}

async function showAlertDetail(alertId) {
    const modal = document.getElementById('alertDetailModal');
    const body = document.getElementById('alertDetailBody');
    body.textContent = 'Wird geladen…';
    modal.classList.add('active');

    try {
        const resp = await fetch(`/api/alerts/${encodeURIComponent(alertId)}`);
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const a = await resp.json();
        body.innerHTML = renderAlertDetail(a);
    } catch (err) {
        body.innerHTML = `<div class="detail-error">Fehler: ${escapeHtml(err.message)}</div>`;
    }
}

function closeAlertDetail() {
    document.getElementById('alertDetailModal').classList.remove('active');
}

function ipFieldWithBlock(ip, comment) {
    if (!ip) return null;
    const safeIp = escapeHtml(ip);
    if (!isPublicIpClient(ip)) {
        return `<span class="detail-mono">${safeIp}</span> <span class="ack-label">privat</span>`;
    }
    const safeComment = (comment || '').replace(/'/g, '').slice(0, 80);
    return `<span class="detail-mono">${safeIp}</span> <button class="ack-btn" onclick="blockFromDetail('${ip}', '${safeComment}', this)">IP blocken</button> <button class="osint-btn osint-btn-detail" onclick="showOsint('${ip}')">🔍 OSINT</button>`;
}

function renderAlertDetail(a) {
    const ipComment = `${a.type || 'alert'} ${a.id}`.slice(0, 80);
    const fields = [
        ['ID', a.id, true],
        ['Erstellt', a.created_at ? new Date(a.created_at).toLocaleString('de-DE') : '-'],
        ['Ingested', a.ingested_at ? new Date(a.ingested_at).toLocaleString('de-DE') : '-'],
        ['Schwere', a.severity, false, severityBadge(a.severity)],
        ['Typ', a.type, true],
        ['Kategorie', a.category],
        ['Quell-IP', a.source_ip, false, ipFieldWithBlock(a.source_ip, ipComment)],
        ['Ziel-IP', a.destination_ip, false, ipFieldWithBlock(a.destination_ip, ipComment)],
        ['Land', [a.country, a.city].filter(Boolean).join(', ') || '-'],
        ['Lat/Lon', a.lat != null ? `${a.lat}, ${a.lon}` : '-'],
        ['Agent', a.agent],
        ['Tenant', a.tenant_id, true],
        ['Acknowledged', a.acknowledged_at ? `${new Date(a.acknowledged_at).toLocaleString('de-DE')} (${a.acknowledged_action || ''})` : 'Nein'],
    ];

    const fieldsHtml = fields.map(([label, value, mono, raw]) => {
        if (value === null || value === undefined || value === '') return '';
        const cls = mono ? ' class="detail-mono"' : '';
        const v = raw !== undefined ? raw : escapeHtml(value);
        return `<dt>${escapeHtml(label)}</dt><dd${cls}>${v}</dd>`;
    }).join('');

    const desc = a.description
        ? `<div class="detail-section"><h4>Beschreibung</h4><div class="detail-description">${escapeHtml(a.description)}</div></div>`
        : '';

    const raw = a.raw_data
        ? `<div class="detail-section"><h4>Sophos Raw Data</h4><pre class="detail-raw">${escapeHtml(JSON.stringify(a.raw_data, null, 2))}</pre></div>`
        : '';

    const ackBtn = !a.acknowledged_at
        ? `<button class="ack-btn" onclick="acknowledgeAlertFromDetail('${a.id}')">Bei Sophos acknowledgen</button>`
        : '';

    return `
        <dl class="detail-grid">${fieldsHtml}</dl>
        ${desc}
        ${raw}
        ${ackBtn}
    `;
}

async function blockFromDetail(ip, comment, btn) {
    if (!confirm(`IP ${ip} auf die Blocklist setzen?`)) return;
    btn.disabled = true;
    btn.textContent = '...';
    try {
        await blockIpRequest(ip, comment);
        btn.textContent = '✓ geblockt';
    } catch (err) {
        btn.disabled = false;
        btn.textContent = 'IP blocken';
        alert('Block fehlgeschlagen: ' + err.message);
    }
}

async function acknowledgeAlertFromDetail(alertId) {
    if (!confirm('Diesen Alarm bei Sophos Central als acknowledged markieren?')) return;
    try {
        const resp = await fetch(`/api/alerts/${encodeURIComponent(alertId)}/action`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({action: 'acknowledge'}),
        });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        closeAlertDetail();
        await updateAlertsTable();
    } catch (err) {
        alert('Fehler: ' + err.message);
    }
}

async function acknowledgeAlert(alertId, btn) {
    if (!confirm('Diesen Alarm bei Sophos Central als acknowledged markieren?')) return;
    btn.disabled = true;
    btn.textContent = '...';
    try {
        const resp = await fetch(`/api/alerts/${encodeURIComponent(alertId)}/action`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'acknowledge' }),
        });
        if (!resp.ok) {
            const err = await resp.json().catch(() => ({}));
            throw new Error(err.detail || `HTTP ${resp.status}`);
        }
        await updateAlertsTable();
    } catch (err) {
        alert('Acknowledge fehlgeschlagen: ' + err.message);
        btn.disabled = false;
        btn.textContent = 'Ack';
    }
}

async function updateEventsTable() {
    try {
        const resp = await fetch('/api/events/recent?limit=200');
        const events = await resp.json();
        const tbody = document.getElementById('eventsTable');

        tbody.innerHTML = events.map(e => `
            <tr>
                <td>${formatTime(e.created_at)}</td>
                <td>${severityBadge(e.severity)}</td>
                <td>${e.device || '-'}</td>
                <td>${deviceTypeBadge(e.device_type)}</td>
                <td>${e.group || '-'}</td>
                <td>${truncate(e.name, 60)}</td>
            </tr>
        `).join('');
    } catch (err) {
        console.error('Events table update failed:', err);
    }
}

async function updateDetectionsTable() {
    try {
        const resp = await fetch('/api/detections/recent?limit=200');
        const detections = await resp.json();
        const tbody = document.getElementById('detectionsTable');

        tbody.innerHTML = detections.map(d => {
            const desc = escapeHtml(d.description || '');
            const ipCell = (d.source_ip || d.destination_ip)
                ? sourceCellWithBlock(d.source_ip, d.country, d.type || 'detection', d.destination_ip)
                : '';
            const deviceLabel = escapeHtml(d.device || '-');
            const cell = ipCell ? `${deviceLabel}<br>${ipCell}` : deviceLabel;
            return `
                <tr class="alert-row" onclick="showAlertDetail('${d.id}')" title="${desc}">
                    <td>${formatTime(d.created_at)}</td>
                    <td>${severityBadge(d.severity)}</td>
                    <td>${escapeHtml(truncate(d.type, 30))}</td>
                    <td>${escapeHtml(truncate(d.description, 80))}</td>
                    <td>${cell}</td>
                </tr>`;
        }).join('');
    } catch (err) {
        console.error('Detections table update failed:', err);
    }
}

async function updateFwLogsTable() {
    try {
        const resp = await fetch('/api/firewall-logs/recent?limit=500');
        const logs = await resp.json();
        const tbody = document.getElementById('fwLogsTable');

        if (logs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;color:var(--text-secondary);padding:2rem">Keine Firewall-Logs. Sophos Firewall Syslog an Port 5514 (UDP/TCP) konfigurieren.</td></tr>';
            return;
        }

        tbody.innerHTML = logs.map(l => {
            const blockedBadge = l.source_blocked
                ? ' <span class="blocked-badge" title="IP ist aktuell auf der Firewall geblockt">BLOCKED</span>'
                : '';
            const blockLink = l.source_ip && !l.source_blocked && isPublicIpClient(l.source_ip)
                ? ` <a class="block-link" href="#" onclick="event.preventDefault();blockFromCell('${l.source_ip}', '${(l.threat || l.log_type || 'fw-log').replace(/'/g, "")}')">[block]</a>`
                : '';
            const osintBtn = osintButton(l.source_ip);
            const srcCell = l.source_ip
                ? `${l.source_ip}${l.source_port ? ':' + l.source_port : ''}${blockedBadge}${blockLink}${osintBtn}`
                : '-';
            return `
            <tr>
                <td>${formatTime(l.created_at)}</td>
                <td>${severityBadge(l.severity)}</td>
                <td>${l.log_type || '-'}${l.log_subtype ? '/' + l.log_subtype : ''}</td>
                <td>${l.firewall || '-'}</td>
                <td>${srcCell}</td>
                <td>${l.destination_ip || '-'}${l.destination_port ? ':' + l.destination_port : ''}</td>
                <td>${l.action || '-'}</td>
                <td>${truncate(l.threat || l.message, 40)}</td>
                <td>${l.country || '-'}${l.city ? ', ' + l.city : ''}</td>
            </tr>`;
        }).join('');
    } catch (err) {
        console.error('FW logs table update failed:', err);
    }
}

async function triggerCollection() {
    try {
        const resp = await fetch('/api/collect', { method: 'POST' });
        const data = await resp.json();
        alert('Datensammlung gestartet');
    } catch (err) {
        alert('Fehler: ' + err.message);
    }
}

function showFirewallModal() {
    document.getElementById('fwModal').classList.add('active');
}

function hideFirewallModal() {
    document.getElementById('fwModal').classList.remove('active');
}

async function addFirewall() {
    const data = {
        name: document.getElementById('fwName').value,
        ip: document.getElementById('fwIp').value,
        lat: parseFloat(document.getElementById('fwLat').value),
        lon: parseFloat(document.getElementById('fwLon').value),
        country: document.getElementById('fwCountry').value,
        city: document.getElementById('fwCity').value,
    };

    if (!data.name || isNaN(data.lat) || isNaN(data.lon)) {
        alert('Name, Breitengrad und Laengengrad sind Pflichtfelder');
        return;
    }

    try {
        await fetch('/api/firewalls', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data),
        });
        hideFirewallModal();
        // Clear form
        ['fwName', 'fwIp', 'fwLat', 'fwLon', 'fwCountry', 'fwCity'].forEach(id => {
            document.getElementById(id).value = '';
        });
        refreshAll();
    } catch (err) {
        alert('Fehler: ' + err.message);
    }
}

// OSINT helpers (showOsint/closeOsint/reloadOsint/osintButton) live in /js/osint.js.


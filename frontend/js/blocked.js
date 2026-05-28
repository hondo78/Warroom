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
        updateWhitelistTable(),
    ]);
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
            tbody.innerHTML = emptyRow(5, 'Keine Whitelist-Einträge — auf "Auto-Refresh" klicken um Firewall-IPs zu importieren');
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
                    <td><button class="restore-btn" onclick="whitelistRemove('${escapeAttr(w.ip)}', this)">Entfernen</button></td>
                </tr>`;
        }).join('');
    } catch (err) {
        console.error('Whitelist update failed:', err);
    }
}

async function whitelistAdd() {
    const ip = document.getElementById('whitelistIpInput').value.trim();
    const comment = document.getElementById('whitelistCommentInput').value.trim();
    if (!ip) { alert('IP angeben'); return; }
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
    } catch (err) { alert('Whitelist fehlgeschlagen: ' + err.message); }
}

async function whitelistRemove(ip, btn) {
    if (!confirm(`IP ${ip} von der Whitelist entfernen? Sie kann danach wieder geblockt werden.`)) return;
    btn.disabled = true; btn.textContent = '...';
    try {
        const r = await fetch(`/api/firewall/whitelist/${encodeURIComponent(ip)}`, {method: 'DELETE'});
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        await updateWhitelistTable();
    } catch (err) {
        alert('Fehler: ' + err.message);
        btn.disabled = false; btn.textContent = 'Entfernen';
    }
}

async function whitelistRefresh() {
    try {
        const r = await fetch('/api/firewall/whitelist/refresh', {method: 'POST'});
        const d = await r.json();
        if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
        await updateWhitelistTable();
        await updateBlockedIpsTable();
        alert(`Auto-Refresh fertig:\n+ ${d.added.length} neu\n· ${d.refreshed.length} aktualisiert\n− ${d.removed_stale_auto.length} verstaut\n${d.removed_from_blocklist.length ? '⚠ ' + d.removed_from_blocklist.length + ' IPs aus Blocklist entfernt' : ''}`);
    } catch (err) { alert('Refresh fehlgeschlagen: ' + err.message); }
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
            tbody.innerHTML = emptyRow(4, 'Keine geblockten IPs');
            return;
        }
        tbody.innerHTML = items.map(b => `
            <tr>
                <td><code>${escapeHtml(b.ip)}</code>${typeof osintButton === 'function' ? osintButton(b.ip, 'osint-btn', 'ip') : ''}</td>
                <td>${escapeHtml(b.comment || '-')}</td>
                <td>${formatTime(b.blocked_at)}</td>
                <td><button class="restore-btn" onclick="unblockIp('${escapeAttr(b.ip)}', this)">Unblock</button></td>
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
            tbody.innerHTML = emptyRow(4, 'Keine geblockten Domains');
            return;
        }
        tbody.innerHTML = items.map(b => `
            <tr>
                <td><code>${escapeHtml(b.domain)}</code>${typeof osintButton === 'function' ? osintButton(b.domain, 'osint-btn', 'domain') : ''}</td>
                <td>${escapeHtml(b.comment || '-')}</td>
                <td>${formatTime(b.blocked_at)}</td>
                <td><button class="restore-btn" onclick="unblockDomain('${escapeAttr(b.domain)}', this)">Unblock</button></td>
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
            tbody.innerHTML = emptyRow(4, 'Keine geblockten URLs');
            return;
        }
        tbody.innerHTML = items.map(b => `
            <tr>
                <td><code class="waf-url" title="${escapeHtml(b.url)}" onclick="this.classList.toggle('expanded')">${escapeHtml(b.url)}</code>${typeof osintButton === 'function' ? osintButton(b.url, 'osint-btn', 'url') : ''}</td>
                <td>${escapeHtml(b.comment || '-')}</td>
                <td>${formatTime(b.blocked_at)}</td>
                <td><button class="restore-btn" onclick="unblockUrl('${escapeAttr(b.url)}', this)">Unblock</button></td>
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
        alert('Bitte IP angeben');
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

async function blockDomainManual() {
    const domain = document.getElementById('blockDomainInput').value.trim();
    const comment = document.getElementById('blockDomainCommentInput').value.trim();
    if (!domain) {
        alert('Bitte Domain oder URL angeben');
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
        alert('Block fehlgeschlagen: ' + err.message);
    }
}

async function unblockDomain(domain, btn) {
    if (!confirm(`Domain ${domain} aus Blocklist entfernen?`)) return;
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
        alert('Unblock fehlgeschlagen: ' + err.message);
        btn.disabled = false;
        btn.textContent = 'Unblock';
    }
}

async function blockUrlManual() {
    const url = document.getElementById('blockUrlInput').value.trim();
    const comment = document.getElementById('blockUrlCommentInput').value.trim();
    if (!url) {
        alert('Bitte URL angeben');
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
        alert('Block fehlgeschlagen: ' + err.message);
    }
}

async function unblockUrl(url, btn) {
    if (!confirm(`URL ${url} aus Blocklist entfernen?`)) return;
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
        alert('Unblock fehlgeschlagen: ' + err.message);
        btn.disabled = false;
        btn.textContent = 'Unblock';
    }
}

function setCount(id, n) {
    const el = document.getElementById(id);
    if (el) el.textContent = (n || 0).toLocaleString('de-DE');
}

function emptyRow(cols, msg) {
    return `<tr><td colspan="${cols}" style="text-align:center;color:var(--text-secondary);padding:1.5rem">${escapeHtml(msg)}</td></tr>`;
}

function formatTime(isoStr) {
    if (!isoStr) return '-';
    const d = new Date(isoStr);
    return d.toLocaleString('de-DE', {
        day: '2-digit', month: '2-digit', year: '2-digit',
        hour: '2-digit', minute: '2-digit',
    });
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

function escapeAttr(str) {
    return escapeHtml(str).replace(/`/g, '&#96;');
}

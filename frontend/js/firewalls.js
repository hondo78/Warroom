document.addEventListener('DOMContentLoaded', () => {
    refreshFirewalls();
    // 120s matches the /api/firewalls/extended cache TTL — refreshing more often
    // just re-fetches the same cached payload.
    setInterval(refreshFirewalls, 120000);
});

async function refreshFirewalls() {
    try {
        const r = await fetch('/api/firewalls/extended');
        const d = await r.json();
        const items = d.items || [];

        // Stats reflect FIREWALL count, not IP count
        const totalIps = items.reduce((s, x) => s + (x.ip_count || 0), 0);
        const wlIps = items.reduce((s, x) => s + (x.whitelisted_count || 0), 0);
        document.getElementById('fwCount').textContent = items.length.toLocaleString('de-DE');
        document.getElementById('fwWhitelisted').textContent = `${wlIps} / ${totalIps}`;
        document.getElementById('fwIfaces').textContent = items.reduce((s, x) => s + (x.iface_count || 0), 0).toLocaleString('de-DE');
        document.getElementById('fwLogs').textContent = items.reduce((s, x) => s + (x.log_count || 0), 0).toLocaleString('de-DE');

        const tbody = document.getElementById('fwListTable');
        if (!items.length) {
            tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;color:var(--text-secondary);padding:1.5rem">Keine bekannten Firewalls. Sophos-Syslog konfigurieren (Port 5514) oder einen Standort über /index.html hinzufügen.</td></tr>';
            return;
        }
        tbody.innerHTML = items.map(fw => {
            const ipBlocks = (fw.ips || []).map(ipObj => {
                const wlIcon = ipObj.whitelisted
                    ? '<span title="whitelisted" style="color:var(--accent-green)">🛡</span>'
                    : '<span title="nicht whitelisted" style="color:var(--accent-red);opacity:.5">⚠</span>';
                const sources = (ipObj.sources || []).map(s => {
                    const lbl = ({location: 'loc', syslog: 'log', netflow: 'flow'})[s] || s;
                    return `<span class="ip-country" style="font-size:.7rem;margin-left:.2rem">${lbl}</span>`;
                }).join('');
                const stats = [];
                if (ipObj.log_count) stats.push(`${ipObj.log_count.toLocaleString('de-DE')} logs`);
                if (ipObj.iface_count) stats.push(`${ipObj.iface_count} ifaces`);
                const statsTxt = stats.length ? ` <span class="ip-country" style="font-size:.7rem">· ${stats.join(' · ')}</span>` : '';
                const wlBtn = !ipObj.whitelisted
                    ? ` <button class="block-link" onclick="whitelistIp('${escapeAttr(ipObj.ip)}', '${escapeAttr(fw.name || ipObj.ip)}', this)" title="diese IP whitelisten">+wl</button>`
                    : '';
                return `<div style="line-height:1.6">${wlIcon} <code style="font-size:.82rem">${escapeHtml(ipObj.ip)}</code>${sources}${statsTxt}${wlBtn}</div>`;
            }).join('');

            const locCell = escapeHtml([fw.country, fw.city].filter(Boolean).join(', ') || '—');
            const lastLog = fw.last_log ? formatTime(fw.last_log) : '—';
            const lastFlow = fw.last_flow ? formatTime(fw.last_flow) : '—';

            // Click an interface count in the row → show interfaces across all IPs of this firewall
            const ipsCsv = (fw.ips || []).map(x => x.ip).join(',');
            const ifaceLink = fw.iface_count > 0
                ? `<button class="osint-btn" onclick="showIfacesForFw('${escapeAttr(ipsCsv)}', '${escapeAttr(fw.name || fw.ips[0]?.ip || '?')}')">${fw.iface_count} 🔍</button>`
                : '0';

            const wlSummary = fw.whitelisted_count === fw.ip_count
                ? '<span class="severity-badge severity-low">✓ alle</span>'
                : fw.whitelisted_count === 0
                    ? '<span class="severity-badge severity-critical">✗ keine</span>'
                    : `<span class="severity-badge severity-high">${fw.whitelisted_count}/${fw.ip_count}</span>`;

            const actions = [];
            if (fw.whitelisted_count < fw.ip_count) {
                actions.push(`<button class="ack-btn" onclick="whitelistAllIps('${escapeAttr(ipsCsv)}', '${escapeAttr(fw.name || '')}', this)">Alle whitelisten</button>`);
            }
            if (fw.location_id) {
                actions.push(`<button class="block-link" onclick="deleteFw(${fw.location_id}, '${escapeAttr(fw.name || '')}', this)">Standort entfernen</button>`);
            }

            const fwLabel = fw.name
                ? `<strong>${escapeHtml(fw.name)}</strong>`
                : `<em>(ohne Namen)</em>`;
            return `
                <tr>
                    <td>${fwLabel}<div class="ip-country" style="font-size:.72rem">${fw.ip_count} IP${fw.ip_count === 1 ? '' : 's'}</div></td>
                    <td>${ipBlocks}</td>
                    <td>${locCell}</td>
                    <td>${ifaceLink}</td>
                    <td>${(fw.log_count || 0).toLocaleString('de-DE')}</td>
                    <td>${lastLog}</td>
                    <td>${lastFlow}</td>
                    <td>${wlSummary}</td>
                    <td>${actions.join(' ') || '<span class="ack-label">—</span>'}</td>
                </tr>`;
        }).join('');
    } catch (err) {
        console.error('Firewalls update failed:', err);
    }
}

async function showIfacesForFw(ipsCsv, name) {
    const ips = ipsCsv.split(',').filter(Boolean);
    if (!ips.length) return;
    document.getElementById('fwIfaceTitle').textContent = `${name} (${ips.length} IP${ips.length === 1 ? '' : 's'})`;
    document.getElementById('fwIfaceCard').style.display = '';
    const tbody = document.getElementById('fwIfaceTable');
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--text-secondary);padding:1rem">Lade…</td></tr>';
    try {
        // Fetch interfaces for every IP in parallel, then merge
        const results = await Promise.all(ips.map(ip =>
            fetch(`/api/firewalls/${encodeURIComponent(ip)}/interfaces`).then(r => r.json()).then(d => ({ip, items: d.items || []}))
        ));
        const merged = [];
        for (const {ip, items} of results) {
            for (const it of items) merged.push({...it, _ip: ip});
        }
        if (!merged.length) {
            tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--text-secondary);padding:1.5rem">Keine NetFlow-Interface-Daten in den letzten 24h.</td></tr>';
            return;
        }
        merged.sort((a, b) => (b.bytes_in + b.bytes_out) - (a.bytes_in + a.bytes_out));
        tbody.innerHTML = merged.map(it => `
            <tr>
                <td><code>${it.iface_idx}</code>${ips.length > 1 ? ` <span class="ip-country" style="font-size:.7rem">${escapeHtml(it._ip)}</span>` : ''}</td>
                <td>${escapeHtml(it.name || '-')}</td>
                <td>${formatBytes(it.bytes_in)}</td>
                <td>${formatBytes(it.bytes_out)}</td>
                <td>${(it.flows_in || 0).toLocaleString('de-DE')}</td>
                <td>${(it.flows_out || 0).toLocaleString('de-DE')}</td>
                <td>${formatTime(it.last_seen)}</td>
            </tr>`).join('');
        document.getElementById('fwIfaceCard').scrollIntoView({behavior: 'smooth', block: 'nearest'});
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="7" class="detail-error">${escapeHtml(err.message)}</td></tr>`;
    }
}

async function whitelistIp(ip, name, btn) {
    btn.disabled = true; btn.textContent = '...';
    try {
        const r = await fetch('/api/firewall/whitelist', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ip, comment: `manual: firewall ${name || ip}`}),
        });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        await refreshFirewalls();
    } catch (err) {
        alert('Whitelist fehlgeschlagen: ' + err.message);
        btn.disabled = false; btn.textContent = '+wl';
    }
}

async function whitelistAllIps(ipsCsv, name, btn) {
    const ips = ipsCsv.split(',').filter(Boolean);
    if (!confirm(`Alle ${ips.length} IP(s) von "${name}" whitelisten?`)) return;
    btn.disabled = true; btn.textContent = '...';
    try {
        for (const ip of ips) {
            await fetch('/api/firewall/whitelist', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ip, comment: `manual: firewall ${name || ip}`}),
            });
        }
        await refreshFirewalls();
    } catch (err) {
        alert('Whitelist fehlgeschlagen: ' + err.message);
        btn.disabled = false; btn.textContent = 'Alle whitelisten';
    }
}

async function showIfaces(ip, name) {
    try {
        const r = await fetch(`/api/firewalls/${encodeURIComponent(ip)}/interfaces`);
        const d = await r.json();
        const items = d.items || [];
        document.getElementById('fwIfaceTitle').textContent = `${name} (${ip})`;
        document.getElementById('fwIfaceCard').style.display = '';
        const tbody = document.getElementById('fwIfaceTable');
        if (!items.length) {
            tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--text-secondary);padding:1.5rem">Keine NetFlow-Interface-Daten in den letzten 24h.</td></tr>';
            return;
        }
        tbody.innerHTML = items.map(it => `
            <tr>
                <td><code>${it.iface_idx}</code></td>
                <td>${escapeHtml(it.name || '-')}</td>
                <td>${formatBytes(it.bytes_in)}</td>
                <td>${formatBytes(it.bytes_out)}</td>
                <td>${(it.flows_in || 0).toLocaleString('de-DE')}</td>
                <td>${(it.flows_out || 0).toLocaleString('de-DE')}</td>
                <td>${formatTime(it.last_seen)}</td>
            </tr>`).join('');
        document.getElementById('fwIfaceCard').scrollIntoView({behavior: 'smooth', block: 'nearest'});
    } catch (err) {
        alert('Interface-Liste fehlgeschlagen: ' + err.message);
    }
}

function hideIfaces() {
    document.getElementById('fwIfaceCard').style.display = 'none';
}

async function whitelistFw(ip, name, btn) {
    btn.disabled = true; btn.textContent = '...';
    try {
        const r = await fetch('/api/firewall/whitelist', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ip, comment: `manual: firewall ${name || ip}`}),
        });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        await refreshFirewalls();
    } catch (err) {
        alert('Whitelist fehlgeschlagen: ' + err.message);
        btn.disabled = false; btn.textContent = 'Whitelist';
    }
}

async function deleteFw(locId, label, btn) {
    if (!confirm(`Firewall-Standort "${label}" entfernen?\nHinweis: Wenn die Firewall weiter Syslog/NetFlow sendet, taucht sie über die Quellen erneut auf.`)) return;
    btn.disabled = true; btn.textContent = '...';
    try {
        const r = await fetch(`/api/firewalls/${locId}`, {method: 'DELETE'});
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        await refreshFirewalls();
    } catch (err) {
        alert('Entfernen fehlgeschlagen: ' + err.message);
        btn.disabled = false; btn.textContent = 'Entfernen';
    }
}

async function refreshWhitelistFromHere() {
    try {
        const r = await fetch('/api/firewall/whitelist/refresh', {method: 'POST'});
        const d = await r.json();
        if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
        alert(`Whitelist aktualisiert:\n+ ${d.added.length} neu\n· ${d.refreshed.length} aktualisiert\n− ${d.removed_stale_auto.length} alte Auto-Einträge entfernt\n${d.removed_from_blocklist.length ? '⚠ ' + d.removed_from_blocklist.length + ' IPs aus Blocklist gerettet' : ''}`);
        await refreshFirewalls();
    } catch (err) { alert('Refresh fehlgeschlagen: ' + err.message); }
}

// --- helpers ---

function formatTime(isoStr) {
    if (!isoStr) return '—';
    const d = new Date(isoStr);
    return d.toLocaleString('de-DE', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
}

function formatBytes(b) {
    if (!b) return '0 B';
    const k = 1024, sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(b) / Math.log(k));
    return parseFloat((b / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// escapeHtml() and escapeAttr() live in js/common.js

// generic table filter from existing pattern
document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('input[data-filter-for]').forEach(input => {
        const tbody = document.getElementById(input.dataset.filterFor);
        if (!tbody) return;
        input.addEventListener('input', () => {
            const t = (input.value || '').toLowerCase().trim();
            tbody.querySelectorAll(':scope > tr').forEach(tr => {
                const match = !t || tr.textContent.toLowerCase().includes(t);
                tr.classList.toggle('filter-hidden', !match);
            });
        });
    });
});

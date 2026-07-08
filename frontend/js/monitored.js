// Monitoring page — which internal hosts talk to specially-flagged ("monitored")
// blocklist / watchlist IPs, and the timeline of new-connection events.

const MON_LOCALE = (typeof currentLang === 'function' && currentLang() === 'de') ? 'de-DE' : 'en-US';

document.addEventListener('DOMContentLoaded', () => {
    initFilters();
    refreshMonitored();
    setInterval(refreshMonitored, 30000);
    document.getElementById('connModal').addEventListener('click', e => {
        if (e.target.id === 'connModal') closeConnModal();
    });
    // Delegated clicks: IP chips filter by exact IP, details buttons open the
    // connections modal. Reading the value from data-* (not an inline onclick)
    // keeps API-supplied strings out of any JS-string context.
    document.addEventListener('click', e => {
        const chip = e.target.closest('.mon-ip-filter');
        if (chip) {
            // Don't hijack a text-selection drag ending on the chip (copying the IP).
            if (String(window.getSelection() || '').length) return;
            filterByIp(chip.dataset.ip);
            return;
        }
        const btn = e.target.closest('button[data-conn-ip]');
        if (btn) openConnModal(btn.dataset.connIp);
    });
});

// A query that is a complete IP address filters by exact match against the
// row's IPs (data-ips: monitored IP and, for events, the host) — so clicking
// 1.2.3.4 doesn't also keep 11.2.3.45 or rows merely mentioning the IP in a
// comment. Free text keeps the usual substring semantics.
function isFullIp(q) {
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(q) || (q.includes(':') && /^[0-9a-f:]+$/i.test(q));
}

function initFilters() {
    document.querySelectorAll('input[data-filter-for]').forEach(input => {
        const tbody = document.getElementById(input.dataset.filterFor);
        if (!tbody) return;
        const apply = () => {
            const q = input.value.toLowerCase().trim();
            const exact = q && isFullIp(q);
            tbody.querySelectorAll(':scope > tr').forEach(tr => {
                let show;
                if (!q) show = true;
                else if (exact) show = (tr.dataset.ips || '').toLowerCase().split(',').includes(q);
                else show = tr.textContent.toLowerCase().includes(q);
                tr.style.display = show ? '' : 'none';
            });
        };
        input.addEventListener('input', apply);
        new MutationObserver(apply).observe(tbody, { childList: true });
    });
}

// A monitored IP rendered as a clickable chip that filters both tables by
// exactly this IP. No inline onclick: the IP travels via data-ip and a
// delegated listener, so untrusted values never reach a JS-string context.
let _ipLinkTitle;   // constant per page load — computed once, not per row
function ipLink(ip) {
    if (_ipLinkTitle === undefined) _ipLinkTitle = escapeAttr(t('monitored.filter_by_ip_title'));
    return `<code class="mon-ip-filter" data-ip="${escapeAttr(ip)}" title="${_ipLinkTitle}">${escapeHtml(ip)}</code>`;
}

// Focus the page on one monitored IP: fill both filter inputs and apply, so the
// event timeline and the IP list narrow to that address.
function filterByIp(ip) {
    document.querySelectorAll('input[data-filter-for]').forEach(inp => {
        inp.value = ip;
        inp.dispatchEvent(new Event('input', { bubbles: true }));
    });
    document.getElementById('monEventsTable')?.closest('.card')
        ?.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function fmtTime(iso) {
    if (!iso) return '—';
    try {
        return new Date(iso).toLocaleString(MON_LOCALE, {
            day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit',
        });
    } catch (e) { return '—'; }
}

function fmtBytes(b) {
    b = Number(b) || 0;
    const u = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    let i = 0;
    while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
    return `${b.toFixed(b >= 100 || i === 0 ? 0 : 1)} ${u[i]}`;
}

function dirBadge(direction) {
    // outbound = host → monitored IP, inbound = monitored IP → host
    const out = direction === 'outbound';
    const cls = out ? 'text-bg-primary' : 'text-bg-warning';
    const label = out ? t('monitored.dir_outbound') : t('monitored.dir_inbound');
    return `<span class="badge ${cls}">${label}</span>`;
}

async function refreshMonitored() {
    try {
        const [ipsResp, evResp] = await Promise.all([
            fetch('/api/firewall/monitored'),
            fetch('/api/firewall/monitored/events?limit=200'),
        ]);
        const ipsData = await ipsResp.json();
        const evData = await evResp.json();

        const warn = document.getElementById('monitorDisabledWarn');
        if (warn) warn.style.display = ipsData.monitor_enabled === false ? '' : 'none';

        renderIps(ipsData.items || []);
        renderEvents(evData.events || []);
    } catch (err) {
        console.error('Monitoring refresh failed:', err);
    }
}

function renderIps(items) {
    document.getElementById('mIpCount').textContent = items.length.toLocaleString(MON_LOCALE);
    const hostTotal = items.reduce((s, x) => s + (x.host_count || 0), 0);
    const new24 = items.reduce((s, x) => s + (x.new_events_24h || 0), 0);
    document.getElementById('mHostCount').textContent = hostTotal.toLocaleString(MON_LOCALE);
    document.getElementById('mNew24h').textContent = new24.toLocaleString(MON_LOCALE);

    const tbody = document.getElementById('monIpsTable');
    if (!items.length) {
        tbody.innerHTML = `<tr><td colspan="8" class="text-center text-secondary py-3">${t('monitored.empty_ips')}</td></tr>`;
        return;
    }
    tbody.innerHTML = items.map(m => {
        const lists = (m.lists || []).map(l =>
            `<span class="badge ${l === 'blocked' ? 'text-bg-danger' : 'text-bg-info'} me-1">${escapeHtml(l)}</span>`).join('');
        const osint = typeof osintButton === 'function' ? osintButton(m.ip, 'osint-btn', 'ip') : '';
        const newBadge = m.new_events_24h
            ? `<span class="badge text-bg-danger">${m.new_events_24h}</span>`
            : '<span class="text-secondary">0</span>';
        return `<tr data-ips="${escapeAttr(m.ip)}">
            <td>${ipLink(m.ip)}${osint}</td>
            <td>${lists}</td>
            <td>${escapeHtml(m.comment || '-')}</td>
            <td>${escapeHtml(m.country || '-')}</td>
            <td>${(m.host_count || 0).toLocaleString(MON_LOCALE)}</td>
            <td style="white-space:nowrap">${fmtTime(m.last_activity)}</td>
            <td>${newBadge}</td>
            <td><button class="btn btn-sm btn-outline-primary py-0" style="font-size:.72rem" data-conn-ip="${escapeAttr(m.ip)}"><i class="bi bi-hdd-network"></i> ${t('monitored.btn_details')}</button></td>
        </tr>`;
    }).join('');
}

function renderEvents(events) {
    const last = events[0];
    document.getElementById('mLastEvent').textContent = last ? fmtTime(last.detected_at) : '—';

    const tbody = document.getElementById('monEventsTable');
    if (!events.length) {
        tbody.innerHTML = `<tr><td colspan="8" class="text-center text-secondary py-3">${t('monitored.empty_events')}</td></tr>`;
        return;
    }
    tbody.innerHTML = events.map(e => {
        const isNew = e.event_type === 'new_pair';
        const typeBadge = isNew
            ? `<span class="badge text-bg-danger">${t('monitored.type_new')}</span>`
            : `<span class="badge text-bg-warning">${t('monitored.type_reappeared')}</span>`;
        const notif = e.notified
            ? `<span class="badge text-bg-success" title="${escapeAttr(e.source_list || '')}">✓</span>`
            : `<span class="badge text-bg-secondary" title="${escapeAttr(e.notify_error || t('monitored.not_sent'))}">–</span>`;
        const portProto = e.port != null ? `${e.port}/${escapeHtml(e.protocol || '?')}` : escapeHtml(e.protocol || '-');
        return `<tr data-ips="${escapeAttr([e.monitored_ip, e.host].filter(Boolean).join(','))}">
            <td style="white-space:nowrap">${fmtTime(e.detected_at)}</td>
            <td>${typeBadge}</td>
            <td><code>${escapeHtml(e.host)}</code></td>
            <td>${dirBadge(e.direction)}</td>
            <td>${ipLink(e.monitored_ip)}</td>
            <td>${portProto}</td>
            <td>${escapeHtml(e.country || '-')}</td>
            <td>${notif}</td>
        </tr>`;
    }).join('');
}

async function scanNow(btn) {
    if (btn) { btn.disabled = true; }
    try {
        const r = await fetch('/api/firewall/monitored/scan', { method: 'POST' });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        await refreshMonitored();
    } catch (err) {
        alert(t('monitored.scan_failed') + ': ' + err.message);
    } finally {
        if (btn) btn.disabled = false;
    }
}

async function openConnModal(ip) {
    const modal = document.getElementById('connModal');
    document.getElementById('connModalTitle').textContent = `${t('monitored.conn_title')} · ${ip}`;
    const body = document.getElementById('connModalBody');
    body.innerHTML = `<div class="text-secondary py-3">${t('common.loading')}</div>`;
    modal.classList.add('active');
    try {
        const r = await fetch(`/api/firewall/monitored/${encodeURIComponent(ip)}/connections`);
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const d = await r.json();
        const rows = d.connections || [];
        if (!rows.length) {
            body.innerHTML = `<p class="text-secondary">${t('monitored.no_conns')}</p>`;
            return;
        }
        const trs = rows.map(c => `<tr>
            <td><code>${escapeHtml(c.host)}</code></td>
            <td>${dirBadge(c.direction)}</td>
            <td>${c.port != null ? c.port + '/' + escapeHtml(c.protocol || '?') : escapeHtml(c.protocol || '-')}</td>
            <td>${fmtBytes(c.bytes)}</td>
            <td>${(c.flows || 0).toLocaleString(MON_LOCALE)}</td>
            <td style="white-space:nowrap">${fmtTime(c.first_seen)}</td>
            <td style="white-space:nowrap">${fmtTime(c.last_seen)}</td>
        </tr>`).join('');
        body.innerHTML = `<p class="admin-hint" style="margin:0 0 .75rem">${t('monitored.conn_intro', { n: rows.length, ip: escapeHtml(ip) })}</p>
            <div class="table-scroll"><table class="table table-sm table-hover align-middle">
            <thead><tr>
                <th>${t('monitored.col_host')}</th><th>${t('monitored.col_direction')}</th><th>${t('monitored.col_portproto')}</th>
                <th>${t('monitored.col_volume')}</th><th>Flows</th><th>${t('monitored.col_first_seen')}</th><th>${t('monitored.col_last_seen')}</th>
            </tr></thead><tbody>${trs}</tbody></table></div>`;
    } catch (err) {
        body.innerHTML = `<div class="detail-error">${t('monitored.conn_failed')}: ${escapeHtml(err.message)}</div>`;
    }
}

function closeConnModal() {
    document.getElementById('connModal').classList.remove('active');
}

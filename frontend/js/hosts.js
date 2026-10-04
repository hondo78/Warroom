// Internal-hosts inventory. Auto-fed from NetFlow + Sophos endpoints, enriched
// with resolved hostnames (Sophos / DNS / NetBIOS / manual). Missing names can
// be filled in manually.

const HOSTS_LOCALE = (typeof currentLang === 'function' && currentLang() === 'de') ? 'de-DE' : 'en-US';
let _hostsItems = [];
let _hostsPollTimer = null;
const _hostsSort = { key: 'last_seen', dir: 'desc' };

document.addEventListener('DOMContentLoaded', () => {
    initFilters();
    loadNmapEnabled().then(refreshHosts);
    loadPortChanges();
    poll(refreshHosts, 60000);
    poll(loadPortChanges, 60000);
    document.getElementById('hostModal').addEventListener('click', e => {
        if (e.target.id === 'hostModal') closeHostModal();
    });
    document.getElementById('hostDetailModal').addEventListener('click', e => {
        if (e.target.id === 'hostDetailModal') closeHostDetail();
    });
    document.getElementById('netScanModal').addEventListener('click', e => {
        if (e.target.id === 'netScanModal') closeNetScan();
    });
    // Column sorting: click a header, click again to flip direction.
    document.querySelectorAll('#hostsSortRow th[data-sort]').forEach(th => {
        th.addEventListener('click', () => {
            const key = th.dataset.sort;
            if (_hostsSort.key === key) {
                _hostsSort.dir = _hostsSort.dir === 'asc' ? 'desc' : 'asc';
            } else {
                _hostsSort.key = key;
                // text columns read better ascending, numbers/dates descending
                _hostsSort.dir = ['hostname', 'source', 'os'].includes(key) ? 'asc' : 'desc';
            }
            renderHosts();
        });
    });
});

// Numeric IPv4 value so 172.16.16.9 sorts before 172.16.16.100.
function _ipNum(ip) {
    const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)/.exec(ip || '');
    return m ? ((+m[1] * 256 + +m[2]) * 256 + +m[3]) * 256 + +m[4] : -1;
}

function _hostsSortVal(h, key) {
    switch (key) {
        case 'ip': return _ipNum(h.ip);
        case 'hostname': return (h.hostname || '').toLowerCase();
        case 'source': return h.source || '';
        case 'mac': return h.mac || '';
        case 'os': return [h.os, h.device_type].filter(Boolean).join(' ').toLowerCase();
        case 'last_seen': return h.last_seen || '';
        case 'bytes': return h.bytes || 0;
        case 'open_ports': return h.open_ports == null ? -1 : h.open_ports;
        case 'online': return h.online === true ? 2 : (h.online === false ? 1 : 0);
        default: return '';
    }
}

function initFilters() {
    document.querySelectorAll('input[data-filter-for]').forEach(input => {
        const tbody = document.getElementById(input.dataset.filterFor);
        if (!tbody) return;
        const apply = () => {
            const q = input.value.toLowerCase().trim();
            tbody.querySelectorAll(':scope > tr').forEach(tr => {
                tr.style.display = (!q || tr.textContent.toLowerCase().includes(q)) ? '' : 'none';
            });
        };
        input.addEventListener('input', apply);
        new MutationObserver(apply).observe(tbody, { childList: true });
    });
}

function fmtTime(iso) {
    if (!iso) return '—';
    try {
        return new Date(iso).toLocaleString(HOSTS_LOCALE, {
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

const _SRC_BADGE = {
    sophos:  'text-bg-primary',
    dns:     'text-bg-info',
    netbios: 'text-bg-secondary',
    manual:  'text-bg-success',
};

// Host-identity changes (IP↔MAC↔hostname). Card stays hidden when there are none.
const _ID_SEV = { high: 'text-bg-danger', medium: 'text-bg-warning', low: 'text-bg-secondary' };
const _ID_TYPE = { ip_mac_change: 'identity_ipmac', hostname_change: 'identity_hostname', mac_moved: 'identity_moved', new_device: 'identity_new' };
async function loadIdentityEvents() {
    const tb = document.getElementById('hIdentityTable');
    if (!tb) return;
    try {
        const r = await fetch('/api/hosts/identity/events?limit=50');
        if (!r.ok) return;
        const evs = (await r.json()).events || [];
        if (!evs.length) { setAnalysisTab('identity', false); return; }
        setAnalysisTab('identity', true);
        tb.innerHTML = evs.map(e => `<tr>
            <td style="white-space:nowrap">${fmtTime(e.detected_at)}</td>
            <td><span class="badge ${_ID_SEV[e.severity] || 'text-bg-secondary'}">${escapeHtml(e.severity || '')}</span></td>
            <td>${escapeHtml(tOr('hosts.' + (_ID_TYPE[e.event_type] || ''), e.event_type))}</td>
            <td style="font-size:.85rem">${escapeHtml(e.detail || '')}</td>
        </tr>`).join('');
    } catch (e) { /* ignore */ }
}

// Reconcile names: re-resolve every internal host now (DNS/NetBIOS/Sophos/DHCP),
// then refresh the table.
async function resolveHostsNow(btn) {
    const label = btn?.querySelector('span');
    const orig = label?.textContent;
    if (btn) btn.disabled = true;
    if (label) label.textContent = t('hosts.resolving_now');
    try {
        const days = document.getElementById('hostsDays')?.value || '7';
        const r = await fetch('/api/hosts/internal/resolve?days=' + encodeURIComponent(days), { method: 'POST' });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
        await refreshHosts();
        if (label) label.textContent = t('hosts.resolved_n', { n: d.resolved || 0, total: d.processed || 0 });
        setTimeout(() => { if (label && orig) label.textContent = orig; }, 4000);
    } catch (err) {
        alert(t('hosts.resolve_failed') + ': ' + err.message);
        if (label && orig) label.textContent = orig;
    } finally {
        if (btn) btn.disabled = false;
    }
}

async function refreshHosts() {
    const days = document.getElementById('hostsDays').value || '7';
    try {
        const r = await fetch(`/api/hosts/internal?days=${days}`);
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const d = await r.json();
        _hostsItems = d.items || [];
        renderHosts();
        loadIdentityEvents();
        loadPresenceAnalytics();

        const named = _hostsItems.filter(h => h.hostname).length;
        document.getElementById('hTotal').textContent = _hostsItems.length.toLocaleString(HOSTS_LOCALE);
        document.getElementById('hNamed').textContent = named.toLocaleString(HOSTS_LOCALE);
        document.getElementById('hUnnamed').textContent = (_hostsItems.length - named).toLocaleString(HOSTS_LOCALE);
        document.getElementById('hResolving').textContent = (d.resolving || 0).toLocaleString(HOSTS_LOCALE);

        // Names arrive asynchronously — re-fetch shortly while some are pending.
        if (_hostsPollTimer) { clearTimeout(_hostsPollTimer); _hostsPollTimer = null; }
        if (d.resolving > 0) _hostsPollTimer = setTimeout(refreshHosts, 6000);
    } catch (err) {
        console.error('hosts refresh failed:', err);
    }
}

function renderHosts() {
    const tbody = document.getElementById('hostsTable');
    // Sort indicators on the headers.
    document.querySelectorAll('#hostsSortRow th[data-sort]').forEach(th => {
        const ind = th.querySelector('.sort-ind');
        if (ind) ind.textContent = th.dataset.sort === _hostsSort.key ? (_hostsSort.dir === 'asc' ? ' ▲' : ' ▼') : '';
    });
    if (!_hostsItems.length) {
        tbody.innerHTML = `<tr><td colspan="10" class="text-center text-secondary py-3">${t('hosts.empty')}</td></tr>`;
        return;
    }
    const mul = _hostsSort.dir === 'asc' ? 1 : -1;
    const key = _hostsSort.key;
    const rows = _hostsItems.slice().sort((a, b) => {
        const va = _hostsSortVal(a, key), vb = _hostsSortVal(b, key);
        if (typeof va === 'string' || typeof vb === 'string') {
            return mul * String(va).localeCompare(String(vb), HOSTS_LOCALE, { numeric: true });
        }
        return mul * (va - vb);
    });
    tbody.innerHTML = rows.map(h => {
        const src = h.source
            ? `<span class="badge ${_SRC_BADGE[h.source] || 'text-bg-secondary'}">${escapeHtml(tOr('hosts.src_' + h.source, h.source))}</span>`
            : '';
        const name = h.hostname
            ? `<strong>${escapeHtml(h.hostname)}</strong>`
            : `<span class="text-secondary">${t('hosts.unnamed')}</span>`;
        const osType = [h.os, h.device_type].filter(Boolean).map(escapeHtml).join(' · ') || '—';
        const traffic = (h.bytes || h.flows)
            ? `${fmtBytes(h.bytes)} <span class="text-secondary" style="font-size:.72rem">· ${(h.flows || 0).toLocaleString(HOSTS_LOCALE)} Flows</span>`
            : '<span class="text-secondary">—</span>';
        // data-hn="skip" keeps the global annotator from double-labelling the IP.
        const mac = h.mac
            ? `<code style="font-size:.78rem">${escapeHtml(h.mac)}</code>`
            : '<span class="text-secondary">—</span>';
        // The whole row expands to show the host's ports (open + formerly open).
        const ip = escapeAttr(h.ip);
        const portsCell = (h.open_ports != null)
            ? `<span class="badge text-bg-info">${h.open_ports} ${t('hosts.ports_open')}</span>`
            : '<span class="text-secondary" style="font-size:.72rem">—</span>';
        // Live online status dot: green=online, gray=offline, faint=unknown.
        let dot;
        if (h.online === true) dot = `<span title="${escapeAttr(t('hosts.online') + (h.last_online ? ' · ' + fmtTime(h.last_online) : ''))}" style="color:#22c55e">●</span>`;
        else if (h.online === false) dot = `<span title="${escapeAttr(t('hosts.offline') + (h.last_online ? ' · ' + t('hosts.last_online') + ' ' + fmtTime(h.last_online) : ''))}" style="color:#6b7280">●</span>`;
        else dot = `<span title="${escapeAttr(t('hosts.online_unknown'))}" class="text-secondary" style="opacity:.4">●</span>`;
        return `<tr data-ip="${ip}" style="cursor:pointer" onclick="openHostDetail('${ip}')" title="${escapeAttr(t('hosts.row_toggle'))}">
            <td class="text-center">${dot}</td>
            <td><code data-hn="skip" style="font-size:.82rem">${escapeHtml(h.ip)}</code></td>
            <td>${name}</td>
            <td>${src}</td>
            <td>${mac}</td>
            <td>${osType}</td>
            <td>${portsCell}</td>
            <td style="white-space:nowrap">${fmtTime(h.last_seen)}</td>
            <td style="white-space:nowrap">${traffic}</td>
            <td style="white-space:nowrap"><button class="btn btn-sm btn-outline-secondary py-0" style="font-size:.72rem" onclick="event.stopPropagation(); openHostModal('${ip}')"><i class="bi bi-pencil"></i> ${t('hosts.btn_edit')}</button></td>
        </tr>`;
    }).join('');
}

// nmap enabled? (drives whether the scan button shows). Loaded once on init.
let _nmapEnabled = false;

let _presenceEnabled = false;

async function loadNmapEnabled() {
    try {
        const s = await (await fetch('/api/admin/settings')).json();
        _nmapEnabled = !!s.host_nmap_enabled;
        _presenceEnabled = !!s.host_presence_enabled;
    } catch (e) { /* leave off */ }
    const btn = document.getElementById('netScanBtn');
    if (btn) btn.style.display = _nmapEnabled ? '' : 'none';
    const pb = document.getElementById('pingBtn');
    if (pb) pb.style.display = _presenceEnabled ? '' : 'none';
}

// --- analysis tabs -----------------------------------------------------------
// The three analysis sections (presence / identity / port-changes) share one
// tabbed card. Each loader calls setAnalysisTab(name, hasData) to toggle its tab;
// the whole card is hidden until at least one tab has content.
function showAnalysisTab(name) {
    document.querySelectorAll('#hAnalysisTabs .nav-link').forEach(a => a.classList.remove('active'));
    document.querySelectorAll('#hAnalysisCard .tab-pane').forEach(p => p.classList.remove('active', 'show'));
    const link = document.querySelector(`#hAnalysisTabs li[data-tab="${name}"] .nav-link`);
    const pane = document.getElementById('pane-' + name);
    if (link) link.classList.add('active');
    if (pane) pane.classList.add('active', 'show');
    // a chart rendered inside a hidden pane computes height 0; resize once visible
    if (name === 'presence' && _pTrendChart) { try { _pTrendChart.resize(); } catch (e) { /* noop */ } }
}

function setAnalysisTab(name, visible) {
    const li = document.querySelector(`#hAnalysisTabs li[data-tab="${name}"]`);
    if (li) li.style.display = visible ? '' : 'none';
    if (!visible) {
        const pane = document.getElementById('pane-' + name);
        if (pane) pane.classList.remove('active', 'show');
        li?.querySelector('.nav-link')?.classList.remove('active');
    }
    const tabs = [...document.querySelectorAll('#hAnalysisTabs li[data-tab]')];
    const shown = tabs.filter(t => t.style.display !== 'none');
    const wrap = document.getElementById('hAnalysisCard');
    if (wrap) wrap.style.display = shown.length ? '' : 'none';
    // keep exactly one visible tab active
    const hasActive = shown.some(t => t.querySelector('.nav-link').classList.contains('active'));
    if (!hasActive && shown.length) showAnalysisTab(shown[0].dataset.tab);
}

// --- online-status analysis --------------------------------------------------
let _pTrendChart = null;

async function loadPresenceAnalytics() {
    if (!_presenceEnabled) { setAnalysisTab('presence', false); return; }
    setAnalysisTab('presence', true);
    const days = document.getElementById('presenceRange')?.value || '7';
    const hours = Math.max(1, parseInt(days, 10) * 24);
    try {
        const [sum, trend, hosts] = await Promise.all([
            fetch(`/api/hosts/presence/summary?days=${days}`).then(r => r.json()),
            fetch(`/api/hosts/presence/trend?hours=${hours}`).then(r => r.json()),
            fetch(`/api/hosts/presence/hosts?days=${days}`).then(r => r.json()),
        ]);
        document.getElementById('pOnline').textContent = (sum.online_now ?? 0).toLocaleString(HOSTS_LOCALE);
        document.getElementById('pOffline').textContent = (sum.offline_now ?? 0).toLocaleString(HOSTS_LOCALE);
        document.getElementById('pNever').textContent = (sum.never_online ?? 0).toLocaleString(HOSTS_LOCALE);
        document.getElementById('pAvail').textContent = sum.avg_availability_pct != null ? sum.avg_availability_pct + '%' : '—';
        document.getElementById('pLastSweep').textContent = sum.last_sweep
            ? t('hosts.p_last_sweep', {t: fmtTime(sum.last_sweep)}) : t('hosts.p_no_sweep');
        _renderTrend(trend.points || []);
        _renderReliability(hosts.hosts || []);
    } catch (e) { /* ignore */ }
}

function _renderTrend(points) {
    const ctx = document.getElementById('pTrendChart');
    if (!ctx || typeof Chart === 'undefined') return;
    const labels = points.map(p => fmtTime(p.ts));
    const data = {
        labels,
        datasets: [
            { label: t('hosts.p_online_now'), data: points.map(p => p.online), borderColor: '#22c55e', backgroundColor: 'rgba(34,197,94,.15)', fill: true, tension: .3, pointRadius: 0 },
            { label: t('hosts.p_total'), data: points.map(p => p.total), borderColor: '#64748b', borderDash: [4, 4], fill: false, tension: .3, pointRadius: 0 },
        ]
    };
    if (_pTrendChart) { _pTrendChart.data = data; _pTrendChart.update(); return; }
    _pTrendChart = new Chart(ctx, {
        type: 'line', data,
        options: { responsive: true, maintainAspectRatio: false,
            scales: { y: { beginAtZero: true, ticks: { precision: 0 } } },
            plugins: { legend: { labels: { boxWidth: 12, font: { size: 11 } } } } }
    });
}

function _renderReliability(hosts) {
    const tb = document.getElementById('pHostsTable');
    if (!tb) return;
    if (!hosts.length) { tb.innerHTML = `<tr><td colspan="6" class="text-secondary py-2">${t('hosts.p_none')}</td></tr>`; return; }
    tb.innerHTML = hosts.map(h => {
        const dot = h.online === true ? '<span style="color:#22c55e">●</span>'
            : (h.online === false ? '<span style="color:#6b7280">●</span>' : '<span class="text-secondary" style="opacity:.4">●</span>');
        const av = h.availability_pct;
        const avColor = av == null ? 'text-secondary' : (av >= 99 ? 'text-success' : (av >= 90 ? '' : 'text-warning'));
        return `<tr>
            <td class="text-center">${dot}</td>
            <td><code data-hn="skip" style="font-size:.82rem">${escapeHtml(h.ip)}</code></td>
            <td>${h.hostname ? escapeHtml(h.hostname) : '<span class="text-secondary">—</span>'}</td>
            <td class="text-end ${avColor}">${av == null ? '—' : av + '%'}</td>
            <td class="text-end">${(h.changes || 0).toLocaleString(HOSTS_LOCALE)}</td>
            <td style="white-space:nowrap;font-size:.8rem">${fmtTime(h.last_online)}</td>
        </tr>`;
    }).join('');
}

async function pingHostsNow(btn) {
    if (btn) { btn.disabled = true; btn.innerHTML = `<span class="spinner-border spinner-border-sm"></span> ${t('hosts.pinging')}`; }
    try {
        const r = await fetch('/api/hosts/ping', { method: 'POST' });
        const d = await r.json();
        if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
        await refreshHosts();
    } catch (e) {
        alert(t('hosts.ping_failed') + ': ' + e.message);
    } finally {
        if (btn) { btn.disabled = false; btn.innerHTML = `<i class="bi bi-broadcast-pin"></i> ${t('hosts.ping')}`; }
    }
}

// --- whole-network scan ------------------------------------------------------
let _netScanPolling = false;

function openNetScan() {
    document.getElementById('netScanStatus').textContent = '';
    document.getElementById('netScanStart').disabled = false;
    document.getElementById('netScanModal').classList.add('active');
}

function closeNetScan() {
    document.getElementById('netScanModal').classList.remove('active');
}

async function startNetScan() {
    const cidr = document.getElementById('netCidr').value.trim();
    const profile = document.getElementById('netProfile').value;
    const statusEl = document.getElementById('netScanStatus');
    const startBtn = document.getElementById('netScanStart');
    if (!cidr) { statusEl.textContent = t('hosts.netscan_need_cidr'); return; }
    startBtn.disabled = true;
    statusEl.innerHTML = `<span class="spinner-border spinner-border-sm"></span> ${t('hosts.netscan_running')}`;
    try {
        const r = await fetch(`/api/hosts/scan-network?cidr=${encodeURIComponent(cidr)}&profile=${encodeURIComponent(profile)}`, { method: 'POST' });
        const d = await r.json();
        if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
        const scanId = d.scan_id;
        if (!scanId) { statusEl.textContent = d.note || t('hosts.netscan_running'); return; }
        // Poll the scan run until it finishes (a /24 with -sV can take minutes).
        for (let i = 0; i < 400; i++) {
            await new Promise(res => setTimeout(res, 3000));
            let s;
            try { s = await (await fetch(`/api/hosts/scans/${scanId}`)).json(); }
            catch (e) { continue; }
            if (s.status === 'done') {
                statusEl.innerHTML = `<span class="text-success">${t('hosts.netscan_done', {hosts: s.os_guess || '', ports: s.ports_open || 0})}</span>`;
                refreshHosts();
                loadPortChanges();
                startBtn.disabled = false;
                return;
            }
            if (s.status === 'error') {
                statusEl.innerHTML = `<span class="detail-error">${t('hosts.scan_failed')}: ${escapeHtml(s.error || '?')}</span>`;
                startBtn.disabled = false;
                return;
            }
        }
        statusEl.textContent = t('hosts.netscan_running');
        startBtn.disabled = false;
    } catch (e) {
        statusEl.innerHTML = `<span class="detail-error">${t('hosts.scan_failed')}: ${escapeHtml(e.message)}</span>`;
        startBtn.disabled = false;
    }
}

function _portsTable(ports, opened) {
    // opened=true → currently open (show "open since"); false → formerly open
    // (show when it closed).
    if (!ports.length) return '';
    const sinceHdr = opened ? t('hosts.pt_since') : t('hosts.pt_closed_since');
    const rows = ports.map(p => `<tr${opened ? '' : ' class="text-secondary"'}>
        <td><code>${p.port}/${escapeHtml(p.proto)}</code></td>
        <td>${escapeHtml(p.service || '—')}</td>
        <td>${escapeHtml([p.product, p.version].filter(Boolean).join(' ') || '—')}</td>
        <td style="white-space:nowrap">${fmtTime(opened ? p.first_seen : p.last_state_change)}</td>
    </tr>`).join('');
    const title = opened
        ? `<strong>${_pcIcon('opened')} ${t('hosts.open_ports_title')} (${ports.length})</strong>`
        : `<strong>${_pcIcon('closed')} ${t('hosts.closed_ports_title')} (${ports.length})</strong>`;
    return `<div class="mb-2">${title}
        <table class="table table-sm mb-1" style="background:rgba(0,0,0,.12)">
            <thead><tr><th>${t('hosts.pt_port')}</th><th>${t('hosts.pt_service')}</th><th>${t('hosts.pt_version')}</th><th>${sinceHdr}</th></tr></thead>
            <tbody>${rows}</tbody></table></div>`;
}

// --- host detail modal -------------------------------------------------------
let _hdIp = null;

function closeHostDetail() {
    _hdIp = null;
    document.getElementById('hostDetailModal').classList.remove('active');
}

function editFromDetail() {
    const ip = _hdIp;
    closeHostDetail();
    if (ip) openHostModal(ip);
}

async function scanFromDetail() {
    if (!_hdIp) return;
    const btn = document.getElementById('hdScanBtn');
    const profile = document.getElementById('hdProfile')?.value || 'quick';
    if (btn) { btn.disabled = true; btn.innerHTML = `<span class="spinner-border spinner-border-sm"></span> ${t('hosts.scanning')}`; }
    try {
        const r = await fetch(`/api/hosts/${encodeURIComponent(_hdIp)}/scan?profile=${encodeURIComponent(profile)}`, { method: 'POST' });
        const d = await r.json();
        if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
        const ip = _hdIp;
        for (let i = 0; i < 240; i++) {
            await new Promise(res => setTimeout(res, 2500));
            if (_hdIp !== ip) break;   // user closed / switched host
            let s;
            try { s = await (await fetch(`/api/hosts/${encodeURIComponent(ip)}/scan`)).json(); }
            catch (e) { continue; }
            const st = s.scan && s.scan.status;
            if (st === 'done' || st === 'error') {
                if (st === 'error') alert(t('hosts.scan_failed') + ': ' + (s.scan.error || '?'));
                refreshHosts();
                loadPortChanges();
                if (_hdIp === ip) await openHostDetail(ip);   // re-render the modal
                return;
            }
        }
    } catch (e) {
        alert(t('hosts.scan_failed') + ': ' + e.message);
    } finally {
        if (btn) { btn.disabled = false; btn.innerHTML = `<i class="bi bi-radar"></i> ${t('hosts.scan')}`; }
    }
}

async function openHostDetail(ip) {
    _hdIp = ip;
    const modal = document.getElementById('hostDetailModal');
    const meta = _hostsItems.find(h => h.ip === ip) || { ip };
    document.getElementById('hdTitle').textContent = meta.hostname ? `${meta.hostname} — ${ip}` : ip;
    document.getElementById('hdScanBtn').style.display = _nmapEnabled ? '' : 'none';
    document.getElementById('hdProfile').style.display = _nmapEnabled ? '' : 'none';
    const body = document.getElementById('hdBody');
    body.innerHTML = `<div class="text-secondary">${t('common.loading')}</div>`;
    modal.classList.add('active');

    // Meta grid from the already-loaded row data.
    const row = (label, val) => `<div><span class="text-secondary" style="font-size:.72rem">${label}</span><br>${val}</div>`;
    const osType = [meta.os, meta.device_type].filter(Boolean).map(escapeHtml).join(' · ') || '—';
    const traffic = (meta.bytes || meta.flows)
        ? `${fmtBytes(meta.bytes)} · ${(meta.flows || 0).toLocaleString(HOSTS_LOCALE)} Flows` : '—';
    const onlineTxt = meta.online === true
        ? `<span style="color:#22c55e">● ${t('hosts.online')}</span>`
        : (meta.online === false ? `<span style="color:#6b7280">● ${t('hosts.offline')}</span>${meta.last_online ? ` <span class="text-secondary" style="font-size:.72rem">(${fmtTime(meta.last_online)})</span>` : ''}` : `<span class="text-secondary">${t('hosts.online_unknown')}</span>`);
    const metaGrid = `<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:.6rem;margin-bottom:1rem">
        ${row(t('hosts.col_online'), onlineTxt)}
        ${row(t('hosts.col_ip'), `<code data-hn="skip">${escapeHtml(ip)}</code>`)}
        ${row(t('hosts.col_hostname'), meta.hostname ? `<strong>${escapeHtml(meta.hostname)}</strong>` : `<span class="text-secondary">${t('hosts.unnamed')}</span>`)}
        ${row(t('hosts.col_mac'), meta.mac ? `<code>${escapeHtml(meta.mac)}</code>` : '—')}
        ${row(t('hosts.col_os'), osType)}
        ${row(t('hosts.col_last'), fmtTime(meta.last_seen))}
        ${row(t('hosts.col_traffic'), traffic)}
    </div>`;

    try {
        const [scan, evs] = await Promise.all([
            fetch(`/api/hosts/${encodeURIComponent(ip)}/scan`).then(r => r.json()),
            fetch(`/api/hosts/${encodeURIComponent(ip)}/port-events?limit=200`).then(r => r.json()),
        ]);
        if (_hdIp !== ip) return;   // user navigated away while loading
        let inner;
        if (!scan.scan) {
            const hint = _nmapEnabled ? t('hosts.not_scanned_hint') : t('hosts.not_scanned_disabled');
            inner = `<p class="text-secondary">${escapeHtml(hint)}</p>`;
        } else {
            const all = scan.ports || [];
            const open = all.filter(p => p.state === 'open');
            const closed = all.filter(p => p.state !== 'open');
            const sc = scan.scan;
            const scanInfo = `<p class="text-secondary" style="font-size:.76rem;margin:-.3rem 0 .6rem">${t('hosts.last_scan')}: ${fmtTime(sc.finished_at || sc.started_at)} · ${escapeHtml(sc.profile)} · ${sc.ports_open} ${t('hosts.ports_open')}${sc.os_guess ? ' · ' + escapeHtml(sc.os_guess) : ''}</p>`;
            inner = scanInfo + _portsTable(open, true);
            if (!open.length) inner += `<p class="text-secondary">${t('hosts.no_open_ports')}</p>`;
            inner += _portsTable(closed, false);
            const events = evs.events || [];
            if (events.length) {
                inner += `<div style="font-size:.82rem;margin-top:.5rem"><strong>${t('hosts.pc_timeline')}</strong>${events.map(e =>
                    `<div>${_pcIcon(e.event_type)} <span class="text-secondary">${fmtTime(e.detected_at)}</span> — ${escapeHtml(e.detail || '')}</div>`).join('')}</div>`;
            }
        }
        body.innerHTML = metaGrid + inner;
    } catch (e) {
        body.innerHTML = metaGrid + `<p class="detail-error">${escapeHtml(e.message)}</p>`;
    }
}

function _pcIcon(type) {
    return { opened: '🟢', closed: '🔴', service_change: '🟡' }[type] || '•';
}

async function loadPortChanges() {
    const tbody = document.getElementById('hPortChangesTable');
    if (!tbody) return;
    try {
        const d = await (await fetch('/api/hosts/port-events?limit=100')).json();
        const events = d.events || [];
        if (!events.length) { setAnalysisTab('portchanges', false); return; }
        setAnalysisTab('portchanges', true);
        tbody.innerHTML = events.map(e => `<tr>
            <td style="white-space:nowrap">${fmtTime(e.detected_at)}</td>
            <td><code data-hn="skip" style="font-size:.82rem">${escapeHtml(e.ip)}</code></td>
            <td>${_pcIcon(e.event_type)} ${escapeHtml(tOr('hosts.pc_' + e.event_type, e.event_type))}</td>
            <td style="font-size:.82rem">${escapeHtml(e.detail || '')}</td>
        </tr>`).join('');
    } catch (e) { /* keep hidden */ }
}

function exportHostsCsv() {
    window.location = '/api/hosts/export.csv';
}

let _hostEditIp = null;
function openHostModal(ip) {
    _hostEditIp = ip;
    const h = _hostsItems.find(x => x.ip === ip) || {};
    document.getElementById('hostModalIp').textContent = ip;
    document.getElementById('hostModalName').value = (h.source === 'manual' ? h.hostname : '') || '';
    const meta = document.getElementById('hostModalMeta');
    meta.textContent = h.hostname
        ? t('hosts.current_resolved', { name: h.hostname, source: tOr('hosts.src_' + h.source, h.source) })
        : t('hosts.none_resolved');
    document.getElementById('hostClearBtn').style.display = (h.source === 'manual') ? '' : 'none';
    document.getElementById('hostModal').classList.add('active');
    setTimeout(() => document.getElementById('hostModalName').focus(), 50);
}

function closeHostModal() {
    document.getElementById('hostModal').classList.remove('active');
}

async function saveHostname() {
    const name = document.getElementById('hostModalName').value.trim();
    if (!name) { alert(t('hosts.name_required')); return; }
    await _postHostname(_hostEditIp, name);
}

async function clearHostname() {
    await _postHostname(_hostEditIp, '');
}

async function _postHostname(ip, hostname) {
    if (!ip) return;
    try {
        const r = await fetch('/api/hosts/internal/hostname', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, hostname }),
        });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
        // Reflect immediately in the local list, then close.
        const h = _hostsItems.find(x => x.ip === ip);
        if (h) { h.hostname = d.hostname; h.source = d.source; }
        renderHosts();
        closeHostModal();
    } catch (err) {
        alert(t('hosts.save_failed') + ': ' + err.message);
    }
}

// Internal-hosts inventory. Auto-fed from NetFlow + Sophos endpoints, enriched
// with resolved hostnames (Sophos / DNS / NetBIOS / manual). Missing names can
// be filled in manually.

const HOSTS_LOCALE = (typeof currentLang === 'function' && currentLang() === 'de') ? 'de-DE' : 'en-US';
let _hostsItems = [];
let _hostsPollTimer = null;
const _hostsSort = { key: 'last_seen', dir: 'desc' };

document.addEventListener('DOMContentLoaded', () => {
    initFilters();
    refreshHosts();
    setInterval(refreshHosts, 60000);
    document.getElementById('hostModal').addEventListener('click', e => {
        if (e.target.id === 'hostModal') closeHostModal();
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
    const card = document.getElementById('hIdentityCard');
    const tb = document.getElementById('hIdentityTable');
    if (!card || !tb) return;
    try {
        const r = await fetch('/api/hosts/identity/events?limit=50');
        if (!r.ok) return;
        const evs = (await r.json()).events || [];
        if (!evs.length) { card.style.display = 'none'; return; }
        card.style.display = '';
        tb.innerHTML = evs.map(e => `<tr>
            <td style="white-space:nowrap">${fmtTime(e.detected_at)}</td>
            <td><span class="badge ${_ID_SEV[e.severity] || 'text-bg-secondary'}">${escapeHtml(e.severity || '')}</span></td>
            <td>${escapeHtml(t('hosts.' + (_ID_TYPE[e.event_type] || '')) || e.event_type)}</td>
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
        tbody.innerHTML = `<tr><td colspan="7" class="text-center text-secondary py-3">${t('hosts.empty')}</td></tr>`;
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
            ? `<span class="badge ${_SRC_BADGE[h.source] || 'text-bg-secondary'}">${escapeHtml(t('hosts.src_' + h.source) || h.source)}</span>`
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
        return `<tr>
            <td><code data-hn="skip" style="font-size:.82rem">${escapeHtml(h.ip)}</code></td>
            <td>${name}</td>
            <td>${src}</td>
            <td>${mac}</td>
            <td>${osType}</td>
            <td style="white-space:nowrap">${fmtTime(h.last_seen)}</td>
            <td style="white-space:nowrap">${traffic}</td>
            <td><button class="btn btn-sm btn-outline-secondary py-0" style="font-size:.72rem" onclick="openHostModal('${escapeAttr(h.ip)}')"><i class="bi bi-pencil"></i> ${t('hosts.btn_edit')}</button></td>
        </tr>`;
    }).join('');
}

let _hostEditIp = null;
function openHostModal(ip) {
    _hostEditIp = ip;
    const h = _hostsItems.find(x => x.ip === ip) || {};
    document.getElementById('hostModalIp').textContent = ip;
    document.getElementById('hostModalName').value = (h.source === 'manual' ? h.hostname : '') || '';
    const meta = document.getElementById('hostModalMeta');
    meta.textContent = h.hostname
        ? t('hosts.current_resolved', { name: h.hostname, source: t('hosts.src_' + h.source) || h.source })
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

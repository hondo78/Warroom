// Honeypot management page — create/manage remote decoy pods and view hits.

const HP_LOCALE = (typeof currentLang === 'function' && currentLang() === 'de') ? 'de-DE' : 'en-US';
let _hpServices = {};       // name -> {port, label}
let _hpFileTemplates = {};  // kind -> {label, example}
let _hpPods = [];
let _editPodId = null;

const _FILE_LABEL = { file: 'Datei' };
function _svcLabel(s) { return _hpServices[s]?.label || _FILE_LABEL[s] || s; }

let _hpSources = [];
const _podsSort = { key: 'last_seen', dir: 'desc' };
const _srcSort = { key: 'last_seen', dir: 'desc' };

// Numeric IPv4 value so 172.16.16.9 sorts before 172.16.16.100.
function _ipNum(ip) {
    const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)/.exec(ip || '');
    return m ? ((+m[1] * 256 + +m[2]) * 256 + +m[3]) * 256 + +m[4] : -1;
}

// Wire a sortable header row: click sorts, click again flips direction.
function _initSort(rowId, state, rerender) {
    document.querySelectorAll(`#${rowId} th[data-sort]`).forEach(th => {
        th.addEventListener('click', () => {
            const key = th.dataset.sort;
            if (state.key === key) state.dir = state.dir === 'asc' ? 'desc' : 'asc';
            else { state.key = key; state.dir = ['name', 'host', 'country'].includes(key) ? 'asc' : 'desc'; }
            rerender();
        });
    });
}

function _applySort(rows, state, valFn) {
    const mul = state.dir === 'asc' ? 1 : -1;
    return rows.slice().sort((a, b) => {
        const va = valFn(a, state.key), vb = valFn(b, state.key);
        if (typeof va === 'string' || typeof vb === 'string') {
            return mul * String(va).localeCompare(String(vb), HP_LOCALE, { numeric: true });
        }
        return mul * (va - vb);
    });
}

function _sortIndicators(rowId, state) {
    document.querySelectorAll(`#${rowId} th[data-sort]`).forEach(th => {
        const ind = th.querySelector('.sort-ind');
        if (ind) ind.textContent = th.dataset.sort === state.key ? (state.dir === 'asc' ? ' ▲' : ' ▼') : '';
    });
}

document.addEventListener('DOMContentLoaded', () => {
    initFilters();
    _initSort('podsSortRow', _podsSort, renderPods);
    _initSort('srcSortRow', _srcSort, () => renderSources(_hpSources));
    refreshHoneypot();
    setInterval(refreshHoneypot, 30000);
    ['createPodModal', 'deployModal', 'editPodModal'].forEach(id => {
        document.getElementById(id).addEventListener('click', e => {
            if (e.target.id === id) e.target.classList.remove('active');
        });
    });
});

function _podSortVal(p, key) {
    switch (key) {
        case 'status': return (p.online ? 2 : 0) + (p.enabled ? 0 : -1);   // online>offline>disabled
        case 'name': return (p.name || '').toLowerCase();
        case 'host': return (p.host_info?.hostname || p.host_ip || '').toLowerCase();
        case 'hits': return p.events_24h || 0;
        case 'last_seen': return p.last_seen || '';
        default: return '';
    }
}

function _srcSortVal(s, key) {
    switch (key) {
        case 'source_ip': return _ipNum(s.source_ip);
        case 'country': return (s.country || '').toLowerCase();
        case 'hits': return s.hits || 0;
        case 'logins': return s.logins || 0;
        case 'first_seen': return s.first_seen || '';
        case 'last_seen': return s.last_seen || '';
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
    try { return new Date(iso).toLocaleString(HP_LOCALE, { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }); }
    catch (e) { return '—'; }
}

async function refreshHoneypot() {
    try {
        const [pr, er] = await Promise.all([
            fetch('/api/honeypot/pods'),
            fetch('/api/honeypot/sources?limit=500'),
        ]);
        const pd = await pr.json();
        _hpServices = pd.services || {};
        _hpFileTemplates = pd.file_templates || {};
        _hpPods = pd.items || [];
        renderPods();
        renderSources((await er.json()).sources || []);
    } catch (err) {
        console.error('honeypot refresh failed:', err);
    }
}

function _svcBadges(services) {
    return Object.keys(_hpServices).filter(s => services && services[s])
        .map(s => `<span class="badge text-bg-secondary me-1">${escapeHtml(_hpServices[s].label)}</span>`).join('') || '—';
}

function renderPods() {
    const tbody = document.getElementById('podsTable');
    _sortIndicators('podsSortRow', _podsSort);
    if (!_hpPods.length) {
        tbody.innerHTML = `<tr><td colspan="7" class="text-center text-secondary py-3">${t('honeypot.no_pods')}</td></tr>`;
        return;
    }
    tbody.innerHTML = _applySort(_hpPods, _podsSort, _podSortVal).map(p => {
        const dot = p.online
            ? `<span class="badge text-bg-success">● ${t('honeypot.online')}</span>`
            : `<span class="badge text-bg-secondary">○ ${t('honeypot.offline')}</span>`;
        const dis = p.enabled ? '' : ` <span class="badge text-bg-warning">${t('honeypot.disabled')}</span>`;
        const host = p.host_info?.hostname
            ? `<code>${escapeHtml(p.host_info.hostname)}</code>${p.host_ip ? ' <span class="text-secondary" style="font-size:.72rem">' + escapeHtml(p.host_ip) + '</span>' : ''}`
            : (p.host_ip ? `<code>${escapeHtml(p.host_ip)}</code>` : '<span class="text-secondary">—</span>');
        const hits = p.events_24h
            ? `<span class="badge text-bg-danger">${p.events_24h}</span>`
            : '<span class="text-secondary">0</span>';
        return `<tr>
            <td>${dot}${dis}</td>
            <td>${escapeHtml(p.name)}</td>
            <td>${host}</td>
            <td>${_svcBadges(p.services)}${(p.files && p.files.length) ? ` <span class="badge text-bg-info" title="${escapeAttr(t('honeypot.files_label'))}">🪤 ${p.files.length}</span>` : ''}</td>
            <td>${hits}</td>
            <td style="white-space:nowrap">${fmtTime(p.last_seen)}</td>
            <td>
                <button class="btn btn-sm btn-outline-secondary py-0" style="font-size:.72rem" onclick="openEditPod('${escapeAttr(p.id)}')"><i class="bi bi-gear"></i> ${t('honeypot.edit')}</button>
                <button class="btn btn-sm ${p.enabled ? 'btn-outline-warning' : 'btn-outline-success'} py-0" style="font-size:.72rem" onclick="togglePod('${escapeAttr(p.id)}', ${p.enabled ? 'false' : 'true'})">${p.enabled ? t('honeypot.pause') : t('honeypot.resume')}</button>
            </td>
        </tr>`;
    }).join('');
}

const _EVT_BADGE = { login: 'text-bg-danger', http_request: 'text-bg-warning', connect: 'text-bg-secondary' };

// The accesses list, grouped by source IP. Each row expands to its connections.
function renderSources(sources) {
    _hpSources = sources || _hpSources;
    const tbody = document.getElementById('hpEventsTable');
    _sortIndicators('srcSortRow', _srcSort);
    const hideAcked = document.getElementById('hpHideAcked')?.checked;
    let list = _applySort(_hpSources, _srcSort, _srcSortVal);
    if (hideAcked) list = list.filter(s => !s.acknowledged);
    if (!list.length) {
        tbody.innerHTML = `<tr><td colspan="9" class="text-center text-secondary py-3">${t(hideAcked ? 'honeypot.no_open_events' : 'honeypot.no_events')}</td></tr>`;
        return;
    }
    tbody.innerHTML = list.map(s => {
        const osint = typeof osintButton === 'function' ? osintButton(s.source_ip, 'osint-btn', 'ip') : '';
        const svcs = (s.services || []).map(sv => {
            const isFile = sv === 'file';
            return `<span class="badge ${isFile ? 'text-bg-info' : 'text-bg-secondary'} me-1">${isFile ? '🪤 ' : ''}${escapeHtml(_svcLabel(sv))}</span>`;
        }).join('') || '—';
        const logins = s.logins
            ? `<span class="badge text-bg-danger" title="${escapeAttr(t('honeypot.captured_logins'))}">${s.logins}</span>`
            : '<span class="text-secondary">0</span>';
        const ackBadge = s.acknowledged
            ? ` <span class="badge text-bg-success" style="font-size:.62rem" title="${escapeAttr(t('honeypot.ack_at', { time: fmtTime(s.acknowledged_at) }))}"><i class="bi bi-check2"></i></span>`
            : '';
        const ip = escapeAttr(s.source_ip);
        const action = s.acknowledged
            ? `<button class="btn btn-sm btn-outline-secondary py-0" style="font-size:.72rem" title="${escapeAttr(t('honeypot.unack_title'))}" onclick="event.stopPropagation(); unackSource('${ip}', this)"><i class="bi bi-arrow-counterclockwise"></i> <span data-i18n="honeypot.unack">Öffnen</span></button>`
            : `<button class="btn btn-sm btn-outline-success py-0" style="font-size:.72rem" title="${escapeAttr(t('honeypot.ack_title'))}" onclick="event.stopPropagation(); ackSource('${ip}', this)"><i class="bi bi-check2"></i> <span data-i18n="honeypot.ack">Bestätigen</span></button>`;
        return `<tr class="hp-src-row" data-ip="${ip}" style="cursor:pointer${s.acknowledged ? ';opacity:.55' : ''}" onclick="toggleSource(this, '${ip}')">
            <td><i class="bi bi-caret-right-fill hp-caret"></i></td>
            <td><code>${escapeHtml(s.source_ip)}</code>${osint}${ackBadge}</td>
            <td>${escapeHtml([s.country, s.city].filter(Boolean).join(', ') || '—')}</td>
            <td>${svcs}</td>
            <td><span class="badge text-bg-warning">${s.hits}</span></td>
            <td>${logins}</td>
            <td style="white-space:nowrap">${fmtTime(s.first_seen)}</td>
            <td style="white-space:nowrap">${fmtTime(s.last_seen)}</td>
            <td style="white-space:nowrap">${action}</td>
        </tr>`;
    }).join('');
}

// --- Acknowledge honeypot alerts (per source IP) -----------------------------
async function ackSource(ip, btn) {
    if (btn) btn.disabled = true;
    try {
        const r = await fetch(`/api/honeypot/sources/${encodeURIComponent(ip)}/ack`, { method: 'POST' });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const s = _hpSources.find(x => x.source_ip === ip);
        if (s) { s.acknowledged = true; s.acknowledged_at = new Date().toISOString(); }
        renderSources();
    } catch (e) { alert(t('honeypot.ack_failed') + ': ' + e.message); if (btn) btn.disabled = false; }
}

async function unackSource(ip, btn) {
    if (btn) btn.disabled = true;
    try {
        const r = await fetch(`/api/honeypot/sources/${encodeURIComponent(ip)}/ack`, { method: 'DELETE' });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const s = _hpSources.find(x => x.source_ip === ip);
        if (s) { s.acknowledged = false; s.acknowledged_at = null; }
        renderSources();
    } catch (e) { alert(t('honeypot.ack_failed') + ': ' + e.message); if (btn) btn.disabled = false; }
}

async function ackAllSources(btn) {
    if (!confirm(t('honeypot.ack_all_confirm'))) return;
    if (btn) btn.disabled = true;
    try {
        const r = await fetch('/api/honeypot/sources/ack-all', { method: 'POST' });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const now = new Date().toISOString();
        _hpSources.forEach(s => { s.acknowledged = true; s.acknowledged_at = now; });
        renderSources();
    } catch (e) { alert(t('honeypot.ack_failed') + ': ' + e.message); }
    finally { if (btn) btn.disabled = false; }
}

// Format one event's captured payload for the detail table.
function _payloadHtml(e) {
    const p = e.payload || {};
    if (e.service === 'file' || p.path) {
        const bits = [];
        if (p.user) bits.push(`<i class="bi bi-person"></i> ${escapeHtml(p.user)}${p.uid != null ? ` <span class="text-secondary">(uid ${p.uid})</span>` : ''}`);
        if (p.process) bits.push(`<i class="bi bi-gear"></i> <code>${escapeHtml(p.process)}</code>${p.pid ? ` <span class="text-secondary">[${p.pid}]</span>` : ''}`);
        if (p.parent) bits.push(`<span class="text-secondary" title="${escapeAttr(t('honeypot.parent_process'))}"><i class="bi bi-arrow-return-right"></i> ${escapeHtml(p.parent)}</span>`);
        const tip = [p.cmdline ? 'cmd: ' + p.cmdline : '', p.exe ? 'exe: ' + p.exe : ''].filter(Boolean).join('\n');
        const who = bits.length
            ? `<div class="mt-1" style="font-size:.76rem"${tip ? ` title="${escapeAttr(tip)}"` : ''}>${bits.join(' &nbsp;·&nbsp; ')}</div>`
            : ` <span class="text-secondary" style="font-size:.72rem">(${t('honeypot.actor_unknown')})</span>`;
        const cmd = p.cmdline
            ? `<div class="text-secondary" style="font-size:.72rem;word-break:break-all"><code>${escapeHtml(p.cmdline.slice(0, 140))}</code></div>`
            : '';
        return `<span class="badge text-bg-danger me-1">${escapeHtml(p.access || 'access')}</span><code>${escapeHtml(p.path || '')}</code>${who}${cmd}`;
    }
    if (p.username || p.password) return `${t('honeypot.login')}: <code>${escapeHtml(p.username || '')}</code> / <code>${escapeHtml(p.password || '')}</code>`;
    if (p.http_method) return `<code>${escapeHtml(p.http_method)} ${escapeHtml((p.path || '').slice(0, 80))}</code>${p.user_agent ? ' <span class="text-secondary" style="font-size:.7rem">' + escapeHtml(p.user_agent.slice(0, 40)) + '</span>' : ''}`;
    if (p.commands) return `<code>${escapeHtml((p.commands || []).join(' ').slice(0, 80))}</code>`;
    if (p.data) return `<code class="text-secondary">${escapeHtml(String(p.data).slice(0, 70))}</code>`;
    return '<span class="text-secondary">—</span>';
}

async function toggleSource(rowEl, ip) {
    const next = rowEl.nextElementSibling;
    if (next && next.classList.contains('hp-detail-row')) {   // collapse
        next.remove();
        rowEl.querySelector('.hp-caret')?.classList.replace('bi-caret-down-fill', 'bi-caret-right-fill');
        return;
    }
    rowEl.querySelector('.hp-caret')?.classList.replace('bi-caret-right-fill', 'bi-caret-down-fill');
    const detail = document.createElement('tr');
    detail.className = 'hp-detail-row';
    detail.innerHTML = `<td></td><td colspan="8" class="py-2"><div class="text-secondary">${t('common.loading')}</div></td>`;
    rowEl.after(detail);
    try {
        const r = await fetch(`/api/honeypot/events?source_ip=${encodeURIComponent(ip)}&limit=500`);
        const events = (await r.json()).events || [];
        const rows = events.map(e => {
            const svc = `<span class="badge ${e.service === 'file' ? 'text-bg-info' : (_EVT_BADGE[e.event_type] || 'text-bg-secondary')}">${e.service === 'file' ? '🪤 ' : ''}${escapeHtml(_svcLabel(e.service))}</span>`;
            return `<tr>
                <td style="white-space:nowrap">${fmtTime(e.created_at)}</td>
                <td>${escapeHtml(e.honeypot || '—')}</td>
                <td>${svc} <span class="text-secondary" style="font-size:.72rem">:${e.dest_port ?? '?'}</span></td>
                <td>${escapeHtml(e.event_type || '')}</td>
                <td>${_payloadHtml(e)}</td>
            </tr>`;
        }).join('');
        detail.innerHTML = `<td></td><td colspan="8" class="py-2">
            <table class="table table-sm mb-0" style="background:rgba(0,0,0,.12)">
                <thead><tr>
                    <th data-i18n="common.time">Zeit</th><th data-i18n="honeypot.col_pod">Pod</th><th data-i18n="honeypot.col_service">Service</th>
                    <th data-i18n="honeypot.col_type">Typ</th><th data-i18n="honeypot.col_payload">Payload</th>
                </tr></thead>
                <tbody>${rows || `<tr><td colspan="5" class="text-secondary">${t('honeypot.no_events')}</td></tr>`}</tbody>
            </table></td>`;
        if (window.i18nApply) window.i18nApply(detail);
    } catch (err) {
        detail.innerHTML = `<td></td><td colspan="8" class="detail-error">${escapeHtml(err.message)}</td>`;
    }
}

// ---- create pod --------------------------------------------------------------
function _serviceCheckboxes(containerId, selected) {
    const box = document.getElementById(containerId);
    box.innerHTML = Object.keys(_hpServices).map(s => {
        const on = selected ? !!selected[s] : true;
        return `<label class="form-check form-check-inline" style="margin:0">
            <input class="form-check-input hp-svc" type="checkbox" value="${escapeAttr(s)}" ${on ? 'checked' : ''}>
            <span class="form-check-label" style="font-size:.82rem">${escapeHtml(_hpServices[s].label)} <span class="text-secondary">:${_hpServices[s].port}</span></span>
        </label>`;
    }).join('');
}

function _selectedServices(containerId) {
    return Array.from(document.querySelectorAll(`#${containerId} .hp-svc:checked`)).map(c => c.value);
}

// --- decoy files -------------------------------------------------------------
function addFileRow(containerId, path, kind) {
    const box = document.getElementById(containerId);
    const opts = Object.keys(_hpFileTemplates).map(k =>
        `<option value="${escapeAttr(k)}" ${k === kind ? 'selected' : ''}>${escapeHtml(_hpFileTemplates[k].label)}</option>`).join('');
    const firstKind = kind || Object.keys(_hpFileTemplates)[0] || 'credentials';
    const example = _hpFileTemplates[firstKind]?.example || '/root/secret.txt';
    const row = document.createElement('div');
    row.className = 'hp-file-row d-flex gap-1 mb-1';
    row.innerHTML =
        `<input class="form-control form-control-sm hp-file-path" style="flex:2" placeholder="${escapeAttr(example)}" value="${escapeAttr(path || '')}">
         <select class="form-select form-select-sm hp-file-kind" style="flex:1">${opts}</select>
         <button class="btn btn-sm btn-outline-danger py-0" onclick="this.parentElement.remove()">×</button>`;
    box.appendChild(row);
    // Fill the path placeholder with the example of the selected kind on change.
    const sel = row.querySelector('.hp-file-kind');
    const inp = row.querySelector('.hp-file-path');
    sel.addEventListener('change', () => { inp.placeholder = _hpFileTemplates[sel.value]?.example || ''; });
}

function _collectFiles(containerId) {
    return Array.from(document.querySelectorAll(`#${containerId} .hp-file-row`)).map(r => ({
        path: r.querySelector('.hp-file-path').value.trim(),
        kind: r.querySelector('.hp-file-kind').value,
    })).filter(f => f.path);
}

function openCreatePod() {
    document.getElementById('podName').value = '';
    _serviceCheckboxes('podServices', null);   // default: all on (backend uses DEFAULT set, but show all)
    // Pre-check only the sensible defaults:
    const defaults = new Set(['ssh', 'telnet', 'ftp', 'http', 'rdp', 'smb', 'mysql', 'vnc']);
    document.querySelectorAll('#podServices .hp-svc').forEach(c => { c.checked = defaults.has(c.value); });
    document.getElementById('podFiles').innerHTML = '';
    document.getElementById('createPodModal').classList.add('active');
}
function closeCreatePod() { document.getElementById('createPodModal').classList.remove('active'); }

async function createPod() {
    const name = document.getElementById('podName').value.trim();
    if (!name) { alert(t('honeypot.name_required')); return; }
    const services = _selectedServices('podServices');
    const files = _collectFiles('podFiles');
    try {
        const r = await fetch('/api/honeypot/pods', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, services, files }),
        });
        const d = await r.json();
        if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
        closeCreatePod();
        document.getElementById('deployToken').value = d.token;
        document.getElementById('deploySnippet').textContent = d.deploy;
        document.getElementById('deployModal').classList.add('active');
        refreshHoneypot();
    } catch (err) { alert(t('honeypot.create_failed') + ': ' + err.message); }
}
function closeDeploy() { document.getElementById('deployModal').classList.remove('active'); }

// ---- edit / toggle / delete --------------------------------------------------
function openEditPod(id) {
    _editPodId = id;
    const p = _hpPods.find(x => x.id === id);
    if (!p) return;
    document.getElementById('editPodName').textContent = p.name;
    _serviceCheckboxes('editPodServices', p.services);
    const fbox = document.getElementById('editPodFiles');
    fbox.innerHTML = '';
    (p.files || []).forEach(f => addFileRow('editPodFiles', f.path, f.kind));
    document.getElementById('editPodModal').classList.add('active');
}
function closeEditPod() { document.getElementById('editPodModal').classList.remove('active'); }

async function saveEditPod() {
    const services = _selectedServices('editPodServices');
    const files = _collectFiles('editPodFiles');
    await _patchPod(_editPodId, { services, files });
    closeEditPod();
}
async function togglePod(id, enabled) { await _patchPod(id, { enabled }); }

async function _patchPod(id, body) {
    try {
        const r = await fetch(`/api/honeypot/pods/${encodeURIComponent(id)}`, {
            method: 'PATCH', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        refreshHoneypot();
    } catch (err) { alert(t('honeypot.save_failed') + ': ' + err.message); }
}

async function deletePod() {
    const p = _hpPods.find(x => x.id === _editPodId);
    if (!confirm(t('honeypot.confirm_delete', { name: p ? p.name : '' }))) return;
    try {
        const r = await fetch(`/api/honeypot/pods/${encodeURIComponent(_editPodId)}`, { method: 'DELETE' });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        closeEditPod();
        refreshHoneypot();
    } catch (err) { alert(t('honeypot.save_failed') + ': ' + err.message); }
}

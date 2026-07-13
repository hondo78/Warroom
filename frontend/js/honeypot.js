// Honeypot management page — create/manage remote decoy pods and view hits.

const HP_LOCALE = (typeof currentLang === 'function' && currentLang() === 'de') ? 'de-DE' : 'en-US';
let _hpServices = {};       // name -> {port, label}
let _hpFileTemplates = {};  // kind -> {label, example}
let _hpPods = [];
let _editPodId = null;

const _FILE_LABEL = { file: 'Datei' };
function _svcLabel(s) { return _hpServices[s]?.label || _FILE_LABEL[s] || s; }

document.addEventListener('DOMContentLoaded', () => {
    initFilters();
    refreshHoneypot();
    setInterval(refreshHoneypot, 30000);
    ['createPodModal', 'deployModal', 'editPodModal'].forEach(id => {
        document.getElementById(id).addEventListener('click', e => {
            if (e.target.id === id) e.target.classList.remove('active');
        });
    });
});

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
    if (!_hpPods.length) {
        tbody.innerHTML = `<tr><td colspan="7" class="text-center text-secondary py-3">${t('honeypot.no_pods')}</td></tr>`;
        return;
    }
    tbody.innerHTML = _hpPods.map(p => {
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
    const tbody = document.getElementById('hpEventsTable');
    if (!sources.length) {
        tbody.innerHTML = `<tr><td colspan="8" class="text-center text-secondary py-3">${t('honeypot.no_events')}</td></tr>`;
        return;
    }
    tbody.innerHTML = sources.map(s => {
        const osint = typeof osintButton === 'function' ? osintButton(s.source_ip, 'osint-btn', 'ip') : '';
        const svcs = (s.services || []).map(sv => {
            const isFile = sv === 'file';
            return `<span class="badge ${isFile ? 'text-bg-info' : 'text-bg-secondary'} me-1">${isFile ? '🪤 ' : ''}${escapeHtml(_svcLabel(sv))}</span>`;
        }).join('') || '—';
        const logins = s.logins
            ? `<span class="badge text-bg-danger" title="${escapeAttr(t('honeypot.captured_logins'))}">${s.logins}</span>`
            : '<span class="text-secondary">0</span>';
        return `<tr class="hp-src-row" data-ip="${escapeAttr(s.source_ip)}" style="cursor:pointer" onclick="toggleSource(this, '${escapeAttr(s.source_ip)}')">
            <td><i class="bi bi-caret-right-fill hp-caret"></i></td>
            <td><code>${escapeHtml(s.source_ip)}</code>${osint}</td>
            <td>${escapeHtml([s.country, s.city].filter(Boolean).join(', ') || '—')}</td>
            <td>${svcs}</td>
            <td><span class="badge text-bg-warning">${s.hits}</span></td>
            <td>${logins}</td>
            <td style="white-space:nowrap">${fmtTime(s.first_seen)}</td>
            <td style="white-space:nowrap">${fmtTime(s.last_seen)}</td>
        </tr>`;
    }).join('');
}

// Format one event's captured payload for the detail table.
function _payloadHtml(e) {
    const p = e.payload || {};
    if (e.service === 'file' || p.path) {
        const who = (p.process || p.user) ? ` <span class="text-secondary" style="font-size:.72rem">(${escapeHtml(p.process || '?')} · ${escapeHtml(p.user || '?')})</span>` : '';
        return `<span class="badge text-bg-danger me-1">${escapeHtml(p.access || 'access')}</span><code>${escapeHtml(p.path || '')}</code>${who}`;
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
    detail.innerHTML = `<td></td><td colspan="7" class="py-2"><div class="text-secondary">${t('common.loading')}</div></td>`;
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
        detail.innerHTML = `<td></td><td colspan="7" class="py-2">
            <table class="table table-sm mb-0" style="background:rgba(0,0,0,.12)">
                <thead><tr>
                    <th data-i18n="common.time">Zeit</th><th data-i18n="honeypot.col_pod">Pod</th><th data-i18n="honeypot.col_service">Service</th>
                    <th data-i18n="honeypot.col_type">Typ</th><th data-i18n="honeypot.col_payload">Payload</th>
                </tr></thead>
                <tbody>${rows || `<tr><td colspan="5" class="text-secondary">${t('honeypot.no_events')}</td></tr>`}</tbody>
            </table></td>`;
        if (window.i18nApply) window.i18nApply(detail);
    } catch (err) {
        detail.innerHTML = `<td></td><td colspan="7" class="detail-error">${escapeHtml(err.message)}</td>`;
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

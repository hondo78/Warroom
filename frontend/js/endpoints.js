// Endpoint management — inventory (DB-backed, fast) + live actions
// (isolate/restore/scan/delete) and the Sophos installer downloads.

let _epRows = [];

document.addEventListener('DOMContentLoaded', () => {
    loadStats();
    loadEndpoints();
    const s = document.getElementById('epSearch');
    if (s) s.addEventListener('keydown', e => { if (e.key === 'Enter') loadEndpoints(); });
    const lazy = (tabId, flagEl, fn) => document.getElementById(tabId).addEventListener('shown.bs.tab', () => {
        if (!document.getElementById(flagEl).dataset.loaded) fn();
    });
    lazy('tab-downloads', 'epDownloads', loadDownloads);
    lazy('tab-groups', 'grpTable', loadGroups);
    lazy('tab-policies', 'polTable', loadPolicies);
    lazy('tab-settings', 'col-allowed-items', loadSettings);
    lazy('tab-exploits', 'exTable', loadDetectedExploits);

    // Delegated click-to-sort for every table in the endpoint tabs. Works for
    // dynamically (re-)rendered tables too, since the handler is on document.
    document.addEventListener('click', e => {
        const th = e.target.closest('th');
        if (!th) return;
        const table = th.closest('.tab-content table');
        if (!table || !th.closest('thead')) return;
        const label = th.textContent.trim();
        if (label === '' || label === 'Aktionen') return;  // action columns
        const idx = Array.prototype.indexOf.call(th.parentElement.cells, th);
        sortEndpointTable(table, idx);
    });
});

// Sort key: prefer an explicit data-sort (ISO dates etc.), else cell text.
function _cellKey(td) {
    if (!td) return '';
    return td.dataset && td.dataset.sort != null ? td.dataset.sort : td.textContent.trim();
}

// Group-aware client-side sort. Rows that are a single colspan cell act as
// group headers (e.g. the policy type rows) — data rows are sorted WITHIN each
// group, preserving the grouping.
function sortEndpointTable(table, colIndex) {
    const tbody = table.tBodies[0];
    if (!tbody) return;
    const asc = !(table.dataset.sortCol === String(colIndex) && table.dataset.sortDir === 'asc');
    table.dataset.sortCol = colIndex;
    table.dataset.sortDir = asc ? 'asc' : 'desc';
    const mul = asc ? 1 : -1;

    const groups = [];
    let cur = null;
    for (const r of Array.from(tbody.rows)) {
        const isHeader = r.cells.length === 1 && r.cells[0].hasAttribute('colspan');
        if (isHeader) { cur = { header: r, rows: [] }; groups.push(cur); }
        else { if (!cur) { cur = { header: null, rows: [] }; groups.push(cur); } cur.rows.push(r); }
    }

    const cmp = (a, b) => {
        const ka = _cellKey(a.cells[colIndex]), kb = _cellKey(b.cells[colIndex]);
        const aNum = ka !== '' && isFinite(Number(ka));
        const bNum = kb !== '' && isFinite(Number(kb));
        if (aNum && bNum) return (Number(ka) - Number(kb)) * mul;
        return ka.localeCompare(kb, 'de', { numeric: true, sensitivity: 'base' }) * mul;
    };

    const frag = document.createDocumentFragment();
    for (const g of groups) {
        g.rows.sort(cmp);
        if (g.header) frag.appendChild(g.header);
        for (const r of g.rows) frag.appendChild(r);
    }
    tbody.appendChild(frag);

    if (table.tHead && table.tHead.rows[0]) {
        const cells = table.tHead.rows[0].cells;
        for (let i = 0; i < cells.length; i++) {
            cells[i].dataset.sortInd = (i === colIndex) ? (asc ? '▲' : '▼') : '';
        }
    }
}

function refreshEndpoints() {
    loadStats();
    loadEndpoints();
    if (document.getElementById('epDownloads').dataset.loaded) loadDownloads();
}

const HEALTH_BADGE = { good: 'text-bg-success', suspicious: 'text-bg-warning', bad: 'text-bg-danger' };

async function loadStats() {
    try {
        const d = await (await fetch('/api/endpoints/stats')).json();
        document.getElementById('epTotal').textContent = (d.total || 0).toLocaleString('de-DE');
        document.getElementById('epOnline').textContent = (d.online || 0).toLocaleString('de-DE');
        document.getElementById('epBad').textContent = ((d.by_health || {}).bad || 0).toLocaleString('de-DE');
        document.getElementById('epIsolated').textContent = ((d.by_isolation || {}).isolated || 0).toLocaleString('de-DE');
    } catch (_) { /* leave dashes */ }
}

async function loadEndpoints() {
    const tbody = document.getElementById('epTable');
    tbody.innerHTML = '<tr><td colspan="9" class="text-center text-secondary py-4">Lade…</td></tr>';
    try {
        const params = new URLSearchParams({ limit: '500' });
        const s = document.getElementById('epSearch').value.trim();
        const h = document.getElementById('epHealth').value;
        const iso = document.getElementById('epIsolation').value;
        if (s) params.set('search', s);
        if (h) params.set('health', h);
        if (iso) params.set('isolation', iso);
        _epRows = await (await fetch(`/api/endpoints/list?${params}`)).json();
        if (!_epRows.length) {
            tbody.innerHTML = '<tr><td colspan="9" class="text-center text-secondary py-4">Keine Endpoints. Sophos-Central-Credentials prüfen oder Collector laufen lassen.</td></tr>';
            return;
        }
        tbody.innerHTML = _epRows.map((e, i) => {
            const hb = HEALTH_BADGE[e.health] || 'text-bg-secondary';
            const healthCell = `<span class="badge ${hb}">${escapeHtml(e.health || '?')}</span>`
                + (e.health_threats && e.health_threats !== 'good' ? ` <span class="badge text-bg-danger" title="Threats">T</span>` : '')
                + (e.health_services && e.health_services !== 'good' ? ` <span class="badge text-bg-warning" title="Services">S</span>` : '');
            const isolated = e.isolation === 'isolated';
            const isoCell = isolated
                ? '<span class="badge text-bg-warning">isoliert</span>'
                : '<span class="badge text-bg-secondary">nein</span>';
            const tamper = e.tamper_protection === true ? '<span title="Tamper Protection an" style="color:var(--accent-green,#2ecc71)">✓</span>'
                : e.tamper_protection === false ? '<span title="Tamper Protection aus" style="color:var(--accent-red,#e74c3c)">✗</span>' : '—';
            const online = e.online ? ' <span class="badge text-bg-success" title="online">●</span>' : '';
            return `<tr>
                <td><strong>${escapeHtml(e.hostname || '—')}</strong>${online}</td>
                <td>${escapeHtml(e.type || '—')}</td>
                <td>${escapeHtml(e.os || '—')}</td>
                <td>${e.ipv4 ? '<code>' + escapeHtml(e.ipv4) + '</code>' : '—'}</td>
                <td>${healthCell}</td>
                <td>${isoCell}</td>
                <td class="text-center">${tamper}</td>
                <td class="text-nowrap" data-sort="${escapeAttr(e.last_seen_at || '')}">${formatTime(e.last_seen_at)}</td>
                <td class="text-nowrap">
                    <button class="btn btn-sm btn-outline-secondary" onclick="viewEndpoint(${i})" title="Details"><i class="bi bi-eye"></i></button>
                    ${isolated
                        ? `<button class="btn btn-sm btn-outline-success" onclick="toggleIsolation('${e.id}', true, this)" title="Isolation aufheben"><i class="bi bi-shield-check"></i></button>`
                        : `<button class="btn btn-sm btn-outline-warning" onclick="toggleIsolation('${e.id}', false, this)" title="Isolieren"><i class="bi bi-shield-lock"></i></button>`}
                    <button class="btn btn-sm btn-outline-info" onclick="scanEndpoint('${e.id}', this)" title="Scan starten"><i class="bi bi-search"></i></button>
                    <button class="btn btn-sm btn-outline-danger" onclick="deleteEndpoint(${i}, this)" title="Aus Sophos entfernen"><i class="bi bi-trash"></i></button>
                </td>
            </tr>`;
        }).join('');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="9" class="detail-error">${escapeHtml(err.message)}</td></tr>`;
    }
}

async function viewEndpoint(i) {
    const e = _epRows[i];
    document.getElementById('epDetailTitle').textContent = `Endpoint · ${e.hostname || e.id}`;
    const body = document.getElementById('epDetailBody');
    body.innerHTML = '<div class="text-secondary">Lade Live-Daten…</div>';
    bootstrap.Modal.getOrCreateInstance(document.getElementById('epDetailModal')).show();
    try {
        const d = await (await fetch(`/api/endpoints/${encodeURIComponent(e.id)}`)).json();
        const h = d.health || {};
        const services = ((h.services || {}).serviceDetails || [])
            .map(s => `<li><code>${escapeHtml(s.name)}</code>: ${escapeHtml(s.status)}</li>`).join('');
        body.innerHTML = `
            <dl class="row mb-2">
                <dt class="col-4">Hostname</dt><dd class="col-8">${escapeHtml(d.hostname || '—')}</dd>
                <dt class="col-4">Health gesamt</dt><dd class="col-8"><span class="badge ${HEALTH_BADGE[(h.overall)] || 'text-bg-secondary'}">${escapeHtml(h.overall || '?')}</span></dd>
                <dt class="col-4">Threats / Services</dt><dd class="col-8">${escapeHtml((h.threats||{}).status||'?')} / ${escapeHtml((h.services||{}).status||'?')}</dd>
                <dt class="col-4">OS</dt><dd class="col-8">${escapeHtml((d.os||{}).name || '—')}</dd>
                <dt class="col-4">Tamper Protection</dt><dd class="col-8">${(d.tamperProtectionEnabled ?? '—')}</dd>
                <dt class="col-4">Isolation</dt><dd class="col-8">${escapeHtml((d.isolation||{}).status || '—')}</dd>
            </dl>
            ${services ? `<h6>Dienste</h6><ul>${services}</ul>` : ''}
            <details><summary class="text-secondary" style="cursor:pointer">Roh-JSON</summary><pre class="mb-0" style="white-space:pre-wrap;word-break:break-word">${escapeHtml(JSON.stringify(d, null, 2))}</pre></details>`;
    } catch (err) {
        body.innerHTML = `<div class="detail-error">Fehler: ${escapeHtml(err.message)}</div>`;
    }
}

async function toggleIsolation(id, isolated, btn) {
    const verb = isolated ? 'Isolation aufheben' : 'Isolieren';
    if (!confirm(`${verb}?`)) return;
    btn.disabled = true;
    try {
        const url = `/api/endpoints/${encodeURIComponent(id)}/${isolated ? 'restore' : 'isolate'}`;
        const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ comment: 'Warroom UI' }) });
        if (!r.ok) { const d = await r.json().catch(() => ({})); throw new Error(d.detail || `HTTP ${r.status}`); }
        await loadEndpoints(); await loadStats();
    } catch (err) { alert(`${verb} fehlgeschlagen: ${err.message}`); btn.disabled = false; }
}

async function scanEndpoint(id, btn) {
    if (!confirm('On-Demand-Scan auf diesem Endpoint starten?')) return;
    btn.disabled = true;
    try {
        const r = await fetch(`/api/endpoints/${encodeURIComponent(id)}/scan`, { method: 'POST' });
        if (!r.ok) { const d = await r.json().catch(() => ({})); throw new Error(d.detail || `HTTP ${r.status}`); }
        alert('Scan angestoßen.');
    } catch (err) { alert('Scan fehlgeschlagen: ' + err.message); }
    finally { btn.disabled = false; }
}

async function deleteEndpoint(i, btn) {
    const e = _epRows[i];
    if (!confirm(`Endpoint "${e.hostname || e.id}" aus Sophos Central entfernen?\nDas Gerät wird de-registriert (wirkt auf den Live-Tenant).`)) return;
    btn.disabled = true;
    try {
        const r = await fetch(`/api/endpoints/${encodeURIComponent(e.id)}`, { method: 'DELETE' });
        if (!r.ok) { const d = await r.json().catch(() => ({})); throw new Error(d.detail || `HTTP ${r.status}`); }
        await loadEndpoints(); await loadStats();
    } catch (err) { alert('Entfernen fehlgeschlagen: ' + err.message); btn.disabled = false; }
}

const PLATFORM_BADGE = { windows: 'text-bg-primary', macOS: 'text-bg-secondary', linux: 'text-bg-warning' };

async function loadDownloads() {
    const box = document.getElementById('epDownloads');
    box.dataset.loaded = '1';
    box.innerHTML = '<div class="text-secondary">Lade Installer…</div>';
    try {
        const d = await (await fetch('/api/endpoints/downloads')).json();
        if (!d.available) {
            box.innerHTML = `<div class="alert alert-warning mb-0">Downloads aktuell nicht verfügbar${d.error ? ' (' + escapeHtml(d.error) + ')' : ''}.</div>`;
            return;
        }
        document.getElementById('epLicensed').innerHTML = (d.licensedProducts || [])
            .map(p => `<span class="badge text-bg-info ms-1">${escapeHtml(p)}</span>`).join('');
        const installers = d.installers || [];
        if (!installers.length) { box.innerHTML = '<div class="text-secondary">Keine Installer.</div>'; return; }
        box.innerHTML = '<div class="row g-3">' + installers.map(it => {
            const pb = PLATFORM_BADGE[it.platform] || 'text-bg-secondary';
            const sup = (it.supportedProducts || []).map(s => `<span class="badge text-bg-dark me-1">${escapeHtml(s)}</span>`).join('');
            const dl = it.downloadUrl
                ? `<a class="btn btn-success btn-sm" href="${escapeAttr(it.downloadUrl)}" target="_blank" rel="noopener"><i class="bi bi-download"></i> Download</a>`
                : '<span class="text-secondary">kein Link</span>';
            return `<div class="col-md-6 col-lg-4"><div class="card h-100"><div class="card-body">
                <h5 class="card-title">${escapeHtml(it.productName || 'Installer')}</h5>
                <p class="mb-2"><span class="badge ${pb}">${escapeHtml(it.platform || '?')}</span> <span class="badge text-bg-secondary">${escapeHtml(it.type || '')}</span></p>
                <div class="mb-2" style="font-size:.78rem">${sup}</div>
                ${dl}
            </div></div></div>`;
        }).join('') + '</div>';
    } catch (err) {
        box.innerHTML = `<div class="detail-error">Fehler: ${escapeHtml(err.message)}</div>`;
    }
}

// ---- Groups ----
async function loadGroups() {
    const tb = document.getElementById('grpTable'); tb.dataset.loaded = '1';
    tb.innerHTML = '<tr><td colspan="5" class="text-center text-secondary py-4">Lade…</td></tr>';
    try {
        const d = await (await fetch('/api/endpoints/groups')).json();
        const items = d.items || [];
        if (!items.length) { tb.innerHTML = '<tr><td colspan="5" class="text-center text-secondary py-4">Keine Gruppen.</td></tr>'; return; }
        // Split into Clients (type=computer) and Server (type=server).
        const LABELS = { computer: '💻 Clients', server: '🖥 Server' };
        const ORDER = ['computer', 'server'];
        const groups = {};
        for (const g of items) (groups[g.type || '(ohne Typ)'] ||= []).push(g);
        const keys = Object.keys(groups).sort((a, b) => {
            const ia = ORDER.indexOf(a), ib = ORDER.indexOf(b);
            return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib) || a.localeCompare(b);
        });
        const rowHtml = g => `<tr>
            <td><strong>${escapeHtml(g.name || '—')}</strong></td>
            <td>${escapeHtml(g.type || '—')}</td>
            <td>${(g.endpoints && g.endpoints.total) ?? '—'}</td>
            <td class="text-nowrap" data-sort="${escapeAttr(g.createdAt || '')}">${formatTime(g.createdAt)}</td>
            <td><button class="btn btn-sm btn-outline-danger" onclick="deleteGroup('${g.id}','${escapeAttr(g.name || '')}',this)" title="Löschen"><i class="bi bi-trash"></i></button></td>
        </tr>`;
        tb.innerHTML = keys.map(t => {
            const rows = groups[t].slice().sort((a, b) => (a.name || '').localeCompare(b.name || '', 'de', { numeric: true }));
            return `<tr class="table-active"><td colspan="5"><i class="bi bi-collection"></i> <strong>${escapeHtml(LABELS[t] || t)}</strong> <span class="text-secondary">(${rows.length})</span></td></tr>`
                + rows.map(rowHtml).join('');
        }).join('');
    } catch (e) { tb.innerHTML = `<tr><td colspan="5" class="detail-error">${escapeHtml(e.message)}</td></tr>`; }
}
async function createGroup() {
    const name = document.getElementById('grpName').value.trim();
    const type = document.getElementById('grpType').value;
    if (!name) { alert('Name erforderlich.'); return; }
    try {
        const r = await fetch('/api/endpoints/groups', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name, type }) });
        const d = await r.json().catch(() => ({})); if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
        document.getElementById('grpName').value = ''; await loadGroups();
    } catch (e) { alert('Anlegen fehlgeschlagen: ' + e.message); }
}
async function deleteGroup(id, name, btn) {
    if (!confirm(`Gruppe "${name}" löschen?`)) return; btn.disabled = true;
    try {
        const r = await fetch(`/api/endpoints/groups/${encodeURIComponent(id)}`, { method: 'DELETE' });
        if (!r.ok) { const d = await r.json().catch(() => ({})); throw new Error(d.detail || `HTTP ${r.status}`); }
        await loadGroups();
    } catch (e) { alert('Löschen fehlgeschlagen: ' + e.message); btn.disabled = false; }
}

// ---- Policies ----
let _pol = [];
async function loadPolicies() {
    const tb = document.getElementById('polTable'); tb.dataset.loaded = '1';
    tb.innerHTML = '<tr><td colspan="4" class="text-center text-secondary py-4">Lade…</td></tr>';
    try {
        const d = await (await fetch('/api/endpoints/policies')).json(); _pol = d.items || [];
        if (!_pol.length) { tb.innerHTML = '<tr><td colspan="4" class="text-center text-secondary py-4">Keine Policies.</td></tr>'; return; }
        // Split into Endpoint/Client (type without 'server-' prefix) and Server,
        // then group by type and sort each group by priority (0 = höchste).
        const buckets = { client: {}, server: {} };
        for (const p of _pol) {
            const t = p.type || '(ohne Typ)';
            const b = t.startsWith('server-') ? buckets.server : buckets.client;
            (b[t] ||= []).push(p);
        }
        const rowHtml = p => `<tr>
            <td>${escapeHtml(p.name || '—')}</td>
            <td>${p.priority ?? '—'}</td>
            <td>${p.lockedByManagingAccount ? '🔒' : '—'}</td>
            <td><button class="btn btn-sm btn-outline-secondary" onclick="viewPolicy('${p.id}')" title="Details"><i class="bi bi-eye"></i></button></td>
        </tr>`;
        const renderBucket = (label, icon, b) => {
            const keys = Object.keys(b).sort();
            if (!keys.length) return '';
            let h = `<tr class="table-primary"><td colspan="4">${icon} <strong>${label}</strong> <span class="text-secondary">(${keys.reduce((n, k) => n + b[k].length, 0)})</span></td></tr>`;
            for (const t of keys) {
                const items = b[t].slice().sort((a, c) => (a.priority ?? 1e9) - (c.priority ?? 1e9));
                const tl = t.startsWith('server-') ? t.slice(7) : t;
                h += `<tr class="table-active"><td colspan="4">&nbsp;&nbsp;<i class="bi bi-file-earmark-ruled"></i> <strong>${escapeHtml(tl)}</strong> <span class="text-secondary">(${items.length})</span></td></tr>`;
                h += items.map(rowHtml).join('');
            }
            return h;
        };
        tb.innerHTML = renderBucket('Endpoint-Policies (Clients)', '💻', buckets.client)
            + renderBucket('Server-Policies', '🖥', buckets.server);
    } catch (e) { tb.innerHTML = `<tr><td colspan="4" class="detail-error">${escapeHtml(e.message)}</td></tr>`; }
}
async function viewPolicy(id) {
    const p = _pol.find(x => x.id === id);
    if (!p) return;
    document.getElementById('epDetailTitle').textContent = `Policy · ${p.name || p.id}`;
    const body = document.getElementById('epDetailBody'); body.innerHTML = '<div class="text-secondary">Lade…</div>';
    bootstrap.Modal.getOrCreateInstance(document.getElementById('epDetailModal')).show();
    try {
        const d = await (await fetch(`/api/endpoints/policies/${encodeURIComponent(p.id)}`)).json();
        body.innerHTML = `<pre class="mb-0" style="white-space:pre-wrap;word-break:break-word">${escapeHtml(JSON.stringify(d, null, 2))}</pre>`;
    } catch (e) { body.innerHTML = `<div class="detail-error">${escapeHtml(e.message)}</div>`; }
}

// ---- Detected exploits (exploit-mitigation) ----
async function loadDetectedExploits() {
    const tb = document.getElementById('exTable'); tb.dataset.loaded = '1';
    tb.innerHTML = '<tr><td colspan="4" class="text-center text-secondary py-4">Lade…</td></tr>';
    try {
        const d = await (await fetch('/api/endpoints/detected-exploits')).json();
        if (!d.available) { tb.innerHTML = `<tr><td colspan="4" class="text-center text-secondary py-4">nicht verfügbar${d.error ? ` (${escapeHtml(d.error)})` : ''}</td></tr>`; return; }
        const items = d.items || [];
        if (!items.length) { tb.innerHTML = '<tr><td colspan="4" class="text-center text-secondary py-4">Keine erkannten Exploits. 👍</td></tr>'; return; }
        tb.innerHTML = items.map(x => `<tr>
            <td>${escapeHtml(x.description || '—')}</td>
            <td>${x.count ?? '—'}</td>
            <td><code style="font-size:.72rem" title="${escapeAttr(x.thumbprint || '')}">${escapeHtml((x.thumbprint || '').slice(0, 16))}${x.thumbprint && x.thumbprint.length > 16 ? '…' : ''}</code></td>
            <td class="text-nowrap" data-sort="${escapeAttr(x.lastSeenAt || '')}">${formatTime(x.lastSeenAt)}</td>
        </tr>`).join('');
    } catch (e) { tb.innerHTML = `<tr><td colspan="4" class="detail-error">${escapeHtml(e.message)}</td></tr>`; }
}

// ---- Settings (tamper + collections) ----
const COLLECTIONS = {
    'allowed-items': {
        title: 'Erlaubte Objekte (Allow-Liste)',
        cols: [['Typ', it => it.type || Object.keys(it.properties || {})[0] || '—'], ['Wert', it => Object.values(it.properties || {})[0] || '—'], ['Kommentar', it => it.comment || ''], ['Erstellt', it => formatTime(it.createdAt), it => it.createdAt || '']],
        add: [{ k: 'type', type: 'select', opts: ['sha256', 'certificateSigner', 'path'] }, { k: 'value', ph: 'Wert (SHA256 / Signer / Pfad)' }, { k: 'comment', ph: 'Kommentar' }],
        build: f => ({ type: f.type, properties: { [f.type]: f.value }, comment: f.comment || '' }),
    },
    'blocked-items': {
        title: 'Blockierte Objekte (Block-Liste)',
        cols: [['Typ', it => it.type || Object.keys(it.properties || {})[0] || '—'], ['Wert', it => Object.values(it.properties || {})[0] || '—'], ['Kommentar', it => it.comment || ''], ['Erstellt', it => formatTime(it.createdAt), it => it.createdAt || '']],
        add: [{ k: 'type', type: 'select', opts: ['sha256', 'certificateSigner'] }, { k: 'value', ph: 'Wert (SHA256 / Signer)' }, { k: 'comment', ph: 'Kommentar' }],
        build: f => ({ type: f.type, properties: { [f.type]: f.value }, comment: f.comment || '' }),
    },
    'exclusions': {
        title: 'Scan-Ausschlüsse',
        cols: [['Typ', it => it.type], ['Wert', it => it.value], ['Scan-Modus', it => it.scanMode || '—']],
        add: [{ k: 'type', type: 'select', opts: ['path', 'posixPath', 'virtualPath', 'process'] }, { k: 'value', ph: 'Pfad / Prozess' }, { k: 'scanMode', type: 'select', opts: ['onDemandAndOnAccess', 'onDemand', 'onAccess'] }],
        build: f => ({ type: f.type, value: f.value, scanMode: f.scanMode || 'onDemandAndOnAccess' }),
    },
    'local-sites': {
        title: 'Web-Control — lokale Sites',
        cols: [['URL', it => it.url], ['Tags', it => (it.tags || []).join(', ')], ['Kommentar', it => it.comment || '']],
        add: [{ k: 'url', ph: 'URL / Domain / IP' }, { k: 'tags', ph: 'Tags (Komma)' }, { k: 'comment', ph: 'Kommentar' }],
        build: f => ({ url: f.url, tags: f.tags ? f.tags.split(',').map(s => s.trim()).filter(Boolean) : undefined, comment: f.comment || '' }),
    },
};

async function loadSettings() {
    document.getElementById('col-allowed-items').dataset.loaded = '1';
    try {
        const t = await (await fetch('/api/endpoints/settings/tamper-protection')).json();
        document.getElementById('tamperToggle').checked = !!t.enabled;
        document.getElementById('tamperStatus').textContent = t.available === false
            ? ('nicht verfügbar' + (t.error ? ` (${t.error})` : ''))
            : (t.enabled ? 'aktiviert' : 'deaktiviert');
    } catch (_) { /* ignore */ }
    for (const c of Object.keys(COLLECTIONS)) renderCollection(c);
}

async function setTamper(cb) {
    try {
        const r = await fetch('/api/endpoints/settings/tamper-protection', { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enabled: cb.checked }) });
        if (!r.ok) { const d = await r.json().catch(() => ({})); throw new Error(d.detail || `HTTP ${r.status}`); }
        document.getElementById('tamperStatus').textContent = cb.checked ? 'aktiviert' : 'deaktiviert';
    } catch (e) { alert('Änderung fehlgeschlagen: ' + e.message); cb.checked = !cb.checked; }
}

async function renderCollection(coll) {
    const cfg = COLLECTIONS[coll];
    const host = document.getElementById('col-' + coll);
    const span = cfg.cols.length + 1;
    host.innerHTML = `<div class="card mb-3"><div class="card-header"><h3 class="card-title mb-0">${escapeHtml(cfg.title)}</h3></div>
        <div class="card-body">
            <div class="filter-row" id="add-${coll}"></div>
            <div class="table-scroll"><table class="table table-sm table-hover align-middle"><thead><tr>${cfg.cols.map(c => `<th>${escapeHtml(c[0])}</th>`).join('')}<th></th></tr></thead>
            <tbody id="tb-${coll}"><tr><td colspan="${span}" class="text-center text-secondary py-3">Lade…</td></tr></tbody></table></div>
        </div></div>`;
    document.getElementById('add-' + coll).innerHTML = cfg.add.map(f => f.type === 'select'
        ? `<select class="form-select form-select-sm" id="f-${coll}-${f.k}" style="max-width:170px">${f.opts.map(o => `<option value="${o}">${o}</option>`).join('')}</select>`
        : `<input class="form-control form-control-sm" id="f-${coll}-${f.k}" placeholder="${escapeAttr(f.ph || f.k)}">`
    ).join('') + `<button class="btn btn-success btn-sm" onclick="addCollectionItem('${coll}')"><i class="bi bi-plus-lg"></i> Hinzufügen</button>`;
    const tb = document.getElementById('tb-' + coll);
    try {
        const d = await (await fetch(`/api/endpoints/settings/${coll}`)).json();
        if (!d.available) { tb.innerHTML = `<tr><td colspan="${span}" class="text-center text-secondary py-3">nicht verfügbar${d.error ? ` (${escapeHtml(d.error)})` : ''}</td></tr>`; return; }
        const items = d.items || [];
        if (!items.length) { tb.innerHTML = `<tr><td colspan="${span}" class="text-center text-secondary py-3">Keine Einträge.</td></tr>`; return; }
        tb.innerHTML = items.map(it => `<tr>${cfg.cols.map(c => {
            const sk = c[2] ? c[2](it) : null;
            return `<td${sk != null ? ` data-sort="${escapeAttr(String(sk))}"` : ''}>${escapeHtml(String(c[1](it) ?? ''))}</td>`;
        }).join('')}<td><button class="btn btn-sm btn-outline-danger" onclick="deleteCollectionItem('${coll}','${it.id}',this)" title="Löschen"><i class="bi bi-trash"></i></button></td></tr>`).join('');
    } catch (e) { tb.innerHTML = `<tr><td colspan="${span}" class="detail-error">${escapeHtml(e.message)}</td></tr>`; }
}

async function addCollectionItem(coll) {
    const cfg = COLLECTIONS[coll]; const f = {};
    for (const fld of cfg.add) f[fld.k] = (document.getElementById(`f-${coll}-${fld.k}`).value || '').trim();
    if (!Object.values(f).some(Boolean)) { alert('Bitte Werte eingeben.'); return; }
    try {
        const r = await fetch(`/api/endpoints/settings/${coll}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(cfg.build(f)) });
        const d = await r.json().catch(() => ({})); if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
        await renderCollection(coll);
    } catch (e) { alert('Hinzufügen fehlgeschlagen: ' + e.message); }
}

async function deleteCollectionItem(coll, id, btn) {
    if (!confirm('Eintrag löschen?')) return; btn.disabled = true;
    try {
        const r = await fetch(`/api/endpoints/settings/${coll}/${encodeURIComponent(id)}`, { method: 'DELETE' });
        if (!r.ok) { const d = await r.json().catch(() => ({})); throw new Error(d.detail || `HTTP ${r.status}`); }
        await renderCollection(coll);
    } catch (e) { alert('Löschen fehlgeschlagen: ' + e.message); btn.disabled = false; }
}

function formatTime(isoStr) {
    if (!isoStr) return '—';
    const d = new Date(isoStr);
    if (isNaN(d)) return escapeHtml(String(isoStr));
    return d.toLocaleString('de-DE', { day: '2-digit', month: '2-digit', year: '2-digit', hour: '2-digit', minute: '2-digit' });
}

// escapeHtml() / escapeAttr() live in js/common.js

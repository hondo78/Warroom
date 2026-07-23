// Sophos XDR: Data Lake (telemetry SQL) + Live Discover (live osquery on
// endpoints). Both are async: start a run, poll status, fetch results.
const _dlTemplates = {};   // saved-query id -> template
const _ldTemplates = {};

document.addEventListener('DOMContentLoaded', () => {
    const nav = document.querySelector('a[href="/xdr.html"]');
    if (nav) nav.classList.add('active');

    document.querySelectorAll('.xdr-tabs .nav-link').forEach(a =>
        a.addEventListener('click', () => switchTab(a.dataset.tab, a)));
    document.getElementById('dlRun').addEventListener('click', runDataLake);
    document.getElementById('ldRun').addEventListener('click', runLiveDiscover);
    document.getElementById('dlSaved').addEventListener('change', e => {
        if (_dlTemplates[e.target.value]) document.getElementById('dlSql').value = _dlTemplates[e.target.value];
    });
    document.getElementById('ldSaved').addEventListener('change', e => {
        if (_ldTemplates[e.target.value]) document.getElementById('ldSql').value = _ldTemplates[e.target.value];
    });

    loadSavedQueries();
    loadEndpoints();
});

function switchTab(tab, link) {
    document.querySelectorAll('.xdr-tabs .nav-link').forEach(a => a.classList.toggle('active', a === link));
    document.getElementById('tab-datalake').style.display = tab === 'datalake' ? '' : 'none';
    document.getElementById('tab-livediscover').style.display = tab === 'livediscover' ? '' : 'none';
}

function _fillSelect(sel, items, map, placeholder) {
    sel.innerHTML = `<option value="">${placeholder}</option>`;
    (items || []).forEach(q => {
        if (!q.id) return;
        map[q.id] = q.template || q.description || '';
        const o = document.createElement('option');
        o.value = q.id; o.textContent = q.name || q.id;
        sel.appendChild(o);
    });
}

async function loadSavedQueries() {
    try {
        const [dl, ld] = await Promise.all([
            fetch('/api/xdr/datalake/queries').then(r => r.json()),
            fetch('/api/xdr/livediscover/queries').then(r => r.json()),
        ]);
        _fillSelect(document.getElementById('dlSaved'), dl.items, _dlTemplates, t('xdr.savedPlaceholder'));
        _fillSelect(document.getElementById('ldSaved'), ld.items, _ldTemplates, t('xdr.savedPlaceholder'));
    } catch (e) { /* ignore */ }
}

async function loadEndpoints() {
    const box = document.getElementById('ldEndpoints');
    try {
        const d = await (await fetch('/api/xdr/endpoints')).json();
        const eps = d.items || [];
        if (!eps.length) { box.innerHTML = `<span class="d-muted">${t('xdr.noEndpoints')}</span>`; return; }
        box.innerHTML = eps.map(e => `<label class="d-inline-flex align-items-center gap-1 me-3 mb-1" style="font-size:.82rem">
            <input type="checkbox" class="ep-cb" value="${escapeHtml(e.id)}"> ${escapeHtml(e.hostname || e.id)}
            <span class="ip-country" style="font-size:.68rem">${escapeHtml(e.platform || '')}</span></label>`).join('');
    } catch (e) { box.innerHTML = `<span class="d-bad">${t('xdr.epError')}</span>`; }
}

async function _poll(statusUrl, statusEl, label) {
    for (let i = 0; i < 60; i++) {
        const d = await (await fetch(statusUrl)).json();
        const st = d.status, res = d.result;
        statusEl.innerHTML = `${label}: <b>${escapeHtml(st || '?')}</b>${res && res !== 'notAvailable' ? ' · ' + escapeHtml(res) : ''}`;
        if (st === 'finished' || st === 'failed' || st === 'error' || st === 'canceled') return d;
        await new Promise(r => setTimeout(r, 2500));
    }
    return { status: 'timeout' };
}

function _renderResults(container, data) {
    const cols = (data.metadata && data.metadata.columns) || [];
    const rows = data.items || [];
    const total = (data.pages && data.pages.total) != null ? data.pages.total : rows.length;
    if (!rows.length) { container.innerHTML = `<p class="d-muted">${t('xdr.noRows')}</p>`; return; }
    const colNames = cols.length ? cols.map(c => c.name) : Object.keys(rows[0]);
    const head = colNames.map(c => `<th>${escapeHtml(c)}</th>`).join('');
    const body = rows.map(r => `<tr>${colNames.map(c => `<td>${escapeHtml(r[c] == null ? '' : String(r[c]))}</td>`).join('')}</tr>`).join('');
    container.innerHTML = `<div class="d-muted mb-1" style="font-size:.8rem">${rows.length} / ${total} ${t('xdr.rows')}</div>
        <div class="xdr-scroll"><table class="xdr-table"><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>`;
}

async function runDataLake() {
    const sql = document.getElementById('dlSql').value.trim();
    const status = document.getElementById('dlStatus'), result = document.getElementById('dlResult');
    if (!sql) { status.textContent = t('xdr.needSql'); return; }
    result.innerHTML = ''; status.textContent = t('xdr.starting');
    try {
        const run = await (await fetch('/api/xdr/datalake/run', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ template: sql, hours: parseInt(document.getElementById('dlHours').value, 10) }),
        }).then(async r => { if (!r.ok) throw new Error((await r.json()).detail || r.status); return r; })).json();
        const d = await _poll(`/api/xdr/datalake/runs/${run.id}`, status, t('xdr.status'));
        if (d.status === 'finished') {
            _renderResults(result, await (await fetch(`/api/xdr/datalake/runs/${run.id}/results`)).json());
        } else {
            result.innerHTML = `<p class="d-bad">${t('xdr.runFailed')} (${escapeHtml(d.status || '?')})</p>`;
        }
    } catch (e) { status.innerHTML = `<span class="d-bad">${t('xdr.error')}: ${escapeHtml(e.message)}</span>`; }
}

async function runLiveDiscover() {
    const sql = document.getElementById('ldSql').value.trim();
    const status = document.getElementById('ldStatus'), result = document.getElementById('ldResult');
    const ids = [...document.querySelectorAll('.ep-cb:checked')].map(c => c.value);
    if (!sql) { status.textContent = t('xdr.needSql'); return; }
    if (!ids.length) { status.textContent = t('xdr.needEndpoints'); return; }
    result.innerHTML = ''; status.textContent = t('xdr.starting');
    try {
        const run = await (await fetch('/api/xdr/livediscover/run', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ template: sql, endpoint_ids: ids }),
        }).then(async r => { if (!r.ok) throw new Error((await r.json()).detail || r.status); return r; })).json();
        const d = await _poll(`/api/xdr/livediscover/runs/${run.id}`, status, t('xdr.status'));
        if (d.status === 'finished') {
            _renderResults(result, await (await fetch(`/api/xdr/livediscover/runs/${run.id}/results`)).json());
        } else {
            result.innerHTML = `<p class="d-bad">${t('xdr.runFailed')} (${escapeHtml(d.status || '?')})</p>`;
        }
    } catch (e) { status.innerHTML = `<span class="d-bad">${t('xdr.error')}: ${escapeHtml(e.message)}</span>`; }
}

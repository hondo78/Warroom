// NetFlow anomaly dashboard — Isolation Forest over 3 FREELY CHOSEN dimensions.
// The user picks any 3 of AN_DIMS; the backend scores each IP in exactly that
// 3-D space and both charts plot the chosen axes (x=X, y=Y, z/size=Z).
//
// Mirror of the backend ANOMALY_DIMENSIONS registry (backend/app/main.py).
// `axis` drives log vs linear scaling; `color` gives each dimension a stable
// colour used for the driver chips and chart series.
const AN_DIMS = [
    { key: 'volume',  label: t('fwAnomalies.dim_volume'),  axis: 'log',    color: '#0dcaf0' },
    { key: 'ports',   label: t('fwAnomalies.dim_ports'),   axis: 'linear', color: '#ffc107' },
    { key: 'dst_ips', label: t('fwAnomalies.dim_dst_ips'), axis: 'linear', color: '#fd7e14' },
    { key: 'flows',   label: t('fwAnomalies.dim_flows'),   axis: 'log',    color: '#20c997' },
    { key: 'packets', label: t('fwAnomalies.dim_packets'), axis: 'log',    color: '#6f42c1' },
    { key: 'night',   label: t('fwAnomalies.dim_night'),   axis: 'linear', color: '#0d6efd' },
    { key: 'country', label: t('fwAnomalies.dim_country'), axis: 'linear', color: '#198754' },
];
const AN_DIM_BY_KEY = Object.fromEntries(AN_DIMS.map(d => [d.key, d]));
const AN_DEFAULT_DIMS = ['volume', 'ports', 'night'];
// Currently selected dimension keys for [X, Y, Z].
let _anDims = AN_DEFAULT_DIMS.slice();

let _anScatter = null;
let _anItems = [];
let _anScatterData = [];   // last scatter points, so charts can recolour on verdict change
let _anVerdicts = {};   // ip -> { verdict, comment, updated_at }; analyst marks
const _anSort = { key: 'score', dir: 'desc' };
const AN_COLS = 13;

// Verdict → chart colour (matches the badge palette: danger / warning / success).
function verdictOf(ip) { return _anVerdicts[ip]?.verdict || null; }

// Number formatting follows the chosen UI language (thousands separators differ
// between en/de). Language can't change without a reload, so resolve it once.
const AN_LANG = (typeof currentLang === 'function') ? currentLang() : 'en';
const AN_LOCALE = AN_LANG === 'de' ? 'de-DE' : 'en-US';

// Format a raw dimension value for axis ticks / hover, per dimension type.
function fmtDimVal(key, v) {
    if (key === 'volume') return fmtBytes(v);
    if (key === 'night') return Math.round((v || 0) * 100) + '%';
    if (key === 'country') return 'r' + (Number(v) || 0).toFixed(1);
    return (Number(v) || 0).toLocaleString(AN_LOCALE);
}

// Numeric plot value; log axes need a positive floor so 0 doesn't break them.
function dimPlotVal(key, v) {
    const n = Number(v) || 0;
    return AN_DIM_BY_KEY[key]?.axis === 'log' ? Math.max(1, n) : n;
}

document.addEventListener('DOMContentLoaded', () => {
    initFilters();
    initDimSelectors();
    document.getElementById('anHours').addEventListener('change', anomalyRefresh);
    document.getElementById('anMinFlows').addEventListener('change', anomalyRefresh);
    document.getElementById('anRole').addEventListener('change', anomalyRefresh);
    const ipInput = document.getElementById('anIp');
    ipInput.addEventListener('change', anomalyRefresh);
    ipInput.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); anomalyRefresh(); } });
    // Row click → connection detail (ignore clicks on the inline buttons/links).
    document.getElementById('anTable').addEventListener('click', e => {
        if (e.target.closest('button, a, input')) return;
        const tr = e.target.closest('tr[data-ip]');
        if (tr) anShowConnections(tr.dataset.ip);
    });
    document.getElementById('connModal').addEventListener('click', e => {
        if (e.target.id === 'connModal') closeConn();
    });
    document.getElementById('verdictModal').addEventListener('click', e => {
        if (e.target.id === 'verdictModal') closeVerdict();
    });
    // Click a column header to sort; click again to flip direction.
    document.querySelectorAll('#anSortRow th[data-sort]').forEach(th => {
        th.addEventListener('click', () => {
            const key = th.dataset.sort;
            if (_anSort.key === key) {
                _anSort.dir = _anSort.dir === 'asc' ? 'desc' : 'asc';
            } else {
                _anSort.key = key;
                // text columns read better ascending, numbers descending first
                _anSort.dir = (key === 'ip' || key === 'country') ? 'asc' : 'desc';
            }
            _anRenderRows();
        });
    });
    anomalyRefresh();
});

function initFilters() {
    document.querySelectorAll('input[data-filter-for]').forEach(input => {
        const tbody = document.getElementById(input.dataset.filterFor);
        if (!tbody) return;
        input.addEventListener('input', () => {
            const q = input.value.toLowerCase().trim();
            tbody.querySelectorAll(':scope > tr').forEach(tr => {
                tr.style.display = (!q || tr.textContent.toLowerCase().includes(q)) ? '' : 'none';
            });
        });
    });
}

// Build the three X/Y/Z dimension dropdowns and keep them mutually exclusive
// (a dimension picked in one select is disabled in the others).
const AN_DIM_SELECTS = ['anDimX', 'anDimY', 'anDimZ'];
function initDimSelectors() {
    AN_DIM_SELECTS.forEach((id, i) => {
        const sel = document.getElementById(id);
        if (!sel) return;
        sel.innerHTML = AN_DIMS.map(d => `<option value="${d.key}">${escapeHtml(d.label)}</option>`).join('');
        sel.value = _anDims[i];
        sel.addEventListener('change', () => onDimChange(i, sel.value));
    });
    syncDimOptionStates();
}

function onDimChange(idx, key) {
    // If the newly picked dimension is already used elsewhere, swap the two so
    // all three stay distinct.
    const dup = _anDims.indexOf(key);
    if (dup !== -1 && dup !== idx) {
        _anDims[dup] = _anDims[idx];
        const other = document.getElementById(AN_DIM_SELECTS[dup]);
        if (other) other.value = _anDims[dup];
    }
    _anDims[idx] = key;
    syncDimOptionStates();
    anomalyRefresh();
}

// Disable, in each select, the options currently chosen in the OTHER selects.
function syncDimOptionStates() {
    AN_DIM_SELECTS.forEach((id, i) => {
        const sel = document.getElementById(id);
        if (!sel) return;
        const takenElsewhere = _anDims.filter((_, j) => j !== i);
        Array.from(sel.options).forEach(o => { o.disabled = takenElsewhere.includes(o.value); });
        sel.value = _anDims[i];
    });
}

function fmtTs(iso) {
    if (!iso) return '—';
    try {
        return new Date(iso).toLocaleString(AN_LOCALE, { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
    } catch (e) { return '—'; }
}

function fmtBytes(b) {
    b = Number(b) || 0;
    const u = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    let i = 0;
    while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
    return `${b.toFixed(b >= 100 || i === 0 ? 0 : 1)} ${u[i]}`;
}

function scoreBadge(s) {
    const pct = Math.round(s * 100);
    const cls = s >= 0.8 ? 'text-bg-danger' : s >= 0.62 ? 'text-bg-warning' : 'text-bg-secondary';
    return `<span class="badge ${cls}">${s.toFixed(3)}</span> <span class="text-secondary" style="font-size:.72rem">${pct}%</span>`;
}

function driverChips(drivers) {
    if (!drivers || !drivers.length) return '';
    // `d.dim` is the dimension KEY (e.g. "volume"); resolve colour + localized
    // label from the registry so chips follow the chosen language.
    return '<div style="margin-top:.2rem">' + drivers.map(d => {
        const dim = AN_DIM_BY_KEY[d.dim];
        const color = dim?.color || '#6c757d';
        const label = dim?.label || d.dim;
        const title = t('fwAnomalies.percentile', { p: Math.round((d.pct || 0) * 100) });
        return `<span class="badge" style="font-size:.66rem;background:${color};color:#0b0e14" title="${escapeAttr(title)}">${escapeHtml(label)}</span>`;
    }).join(' ') + '</div>';
}

// Reflect the chosen dimensions in the chart titles + table caption.
function updateDimLabels() {
    const [x, y, z] = _anDims.map(k => AN_DIM_BY_KEY[k]?.label || k);
    const set = (id, txt) => { const el = document.getElementById(id); if (el) el.textContent = txt; };
    set('anScatterTitle', t('fwAnomalies.scatter_title', { x, y, z }));
    set('an3dTitle', t('fwAnomalies.scatter3d_title', { x, y, z }));
    set('anDimsText', t('fwAnomalies.dims_text', { x, y, z }));
}

// The distinct-peer dimension is contextual: when SOURCE IPs are scored the
// peers are destinations ("Destination IPs"); when DESTINATION IPs are scored
// the peers are sources ("Source IPs"). Labels come from i18n by key — never
// from the backend — so the page stays in the chosen language. Selections are
// preserved (the dropdowns key by dimension key, only the text is refreshed).
function applyDimMeta(focus) {
    const dd = AN_DIM_BY_KEY['dst_ips'];
    if (dd) dd.label = (focus && focus.entity === 'dst_ip')
        ? t('fwAnomalies.dim_src_ips') : t('fwAnomalies.dim_dst_ips');
    AN_DIM_SELECTS.forEach(id => {
        const sel = document.getElementById(id);
        if (!sel) return;
        Array.from(sel.options).forEach(o => {
            const opt = AN_DIM_BY_KEY[o.value];
            if (opt) o.textContent = opt.label;
        });
    });
}

// Build the localized "what was scored" line from the structured focus object.
function focusDescription(focus) {
    const f = focus || {};
    if (f.scope === 'focus' && f.ip) {
        return f.role === 'src'
            ? t('fwAnomalies.focus_from', { ip: f.ip })
            : t('fwAnomalies.focus_to', { ip: f.ip });
    }
    return f.entity === 'dst_ip'
        ? t('fwAnomalies.focus_all_dst')
        : t('fwAnomalies.focus_all_src');
}

async function anomalyRefresh() {
    const hours = document.getElementById('anHours').value || '24';
    const minFlows = document.getElementById('anMinFlows').value || '5';
    const ip = (document.getElementById('anIp').value || '').trim();
    const role = document.getElementById('anRole').value || 'src';
    const tbody = document.getElementById('anTable');
    tbody.innerHTML = `<tr><td colspan="${AN_COLS}" class="text-center text-secondary py-3">${t('fwAnomalies.analyzing')}</td></tr>`;
    updateDimLabels();
    try {
        const params = new URLSearchParams({ hours, min_flows: minFlows, limit: '80', dims: _anDims.join(','), role });
        if (ip) params.set('ip', ip);
        const r = await fetch('/api/firewall/anomalies?' + params.toString());
        if (!r.ok) {
            const e = await r.json().catch(() => ({}));
            throw new Error(e.detail || `HTTP ${r.status}`);
        }
        const d = await r.json();

        // Adopt the contextual peer label, then refresh chart titles + scope line.
        applyDimMeta(d.focus);
        updateDimLabels();
        const fi = document.getElementById('anFocusInfo');
        if (fi) fi.textContent = t('fwAnomalies.focus_info', {
            desc: focusDescription(d.focus),
            n: (d.analyzed || 0).toLocaleString(AN_LOCALE),
        });
        const ipHdr = document.getElementById('anIpHdr');
        if (ipHdr) ipHdr.textContent = d.focus?.entity === 'dst_ip' ? t('common.dest_ip') : t('fwAnomalies.source_ip');
        const peerHdr = document.getElementById('anPeerHdr');
        if (peerHdr) peerHdr.textContent = d.focus?.entity === 'dst_ip' ? t('fwAnomalies.source_ip') : t('common.dest_ip');

        document.getElementById('anAnalyzed').textContent = (d.analyzed || 0).toLocaleString(AN_LOCALE);
        document.getElementById('anAnomalies').textContent = (d.anomaly_count || 0).toLocaleString(AN_LOCALE);
        document.getElementById('anWindow').textContent = t('fwAnomalies.window_label', { h: d.window_hours });
        document.getElementById('anThreshold').textContent = (d.params?.threshold ?? '—').toString();
        const top = (d.anomalies || [])[0];
        document.getElementById('anTopScore').textContent = top ? top.score.toFixed(3) : '—';
        document.getElementById('anTopIp').textContent = top ? top.ip : '—';

        await Promise.all([loadVerdicts(), loadWatchlist()]);
        _anScatterData = d.scatter || [];
        renderScatter(_anScatterData);
        render3d(_anScatterData);
        renderTable(d.anomalies || []);
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="${AN_COLS}" class="detail-error">${t('fwAnomalies.analysis_failed')}: ${escapeHtml(err.message)}</td></tr>`;
    }
}

function renderTable(items) {
    _anItems = items || [];
    _anRenderRows();
}

function _anSortVal(it, k) {
    switch (k) {
        case 'bytes': return it.bytes || 0;
        case 'flows': return it.flows || 0;
        case 'dports': return it.distinct_dst_ports || 0;
        case 'dips': return it.distinct_dst_ips || 0;
        case 'night': return it.night_ratio || 0;
        case 'ip': return it.ip || '';
        case 'peer': return it.top_peer || '';
        case 'country': return it.country || '';
        case 'last_seen': return it.last_seen || '';
        case 'score':
        default: return it.score || 0;
    }
}

function _anUpdateSortIndicators() {
    document.querySelectorAll('#anSortRow th[data-sort]').forEach(th => {
        const ind = th.querySelector('.sort-ind');
        if (ind) ind.textContent = th.dataset.sort === _anSort.key ? (_anSort.dir === 'asc' ? ' ▲' : ' ▼') : '';
    });
}

function _anRenderRows() {
    const tbody = document.getElementById('anTable');
    if (!tbody) return;
    _anUpdateSortIndicators();
    if (!_anItems.length) {
        tbody.innerHTML = `<tr><td colspan="${AN_COLS}" class="text-center text-secondary py-3">${t('fwAnomalies.no_netflow_data')}</td></tr>`;
        return;
    }
    const mul = _anSort.dir === 'asc' ? 1 : -1;
    const key = _anSort.key;
    const items = _anItems.slice().sort((a, b) => {
        const va = _anSortVal(a, key), vb = _anSortVal(b, key);
        if (typeof va === 'string' || typeof vb === 'string') {
            return mul * String(va).localeCompare(String(vb), AN_LANG, { numeric: true });
        }
        return mul * (va - vb);
    });
    tbody.innerHTML = items.map(it => {
        const osint = typeof osintButton === 'function' ? osintButton(it.ip, 'osint-btn', 'ip') : '';
        // Verdict overrides the default anomaly tint: malicious → stronger red,
        // suspicious → amber, benign → dimmed/neutral so triaged rows recede.
        const verdict = _anVerdicts[it.ip];
        let baseBg = it.is_anomaly ? 'background:rgba(220,53,69,.08);' : '';
        if (verdict?.verdict === 'malicious') baseBg = 'background:rgba(220,53,69,.18);';
        else if (verdict?.verdict === 'suspicious') baseBg = 'background:rgba(255,193,7,.14);';
        else if (verdict?.verdict === 'benign') baseBg = 'background:rgba(120,144,170,.10);opacity:.7;';
        const night = Math.round((it.night_ratio || 0) * 100);
        const country = it.country
            ? `${escapeHtml(it.country)} <span class="text-secondary" style="font-size:.7rem" title="${escapeAttr(t('fwAnomalies.rarity_title'))}">r${(it.country_rarity ?? 0).toFixed(1)}</span>`
            : `<span class="text-secondary">${t('fwAnomalies.internal')}</span>`;
        // Top counterpart + how many more distinct peers there are.
        const more = Math.max(0, (it.distinct_dst_ips || 0) - 1);
        const peer = it.top_peer
            ? `<code style="font-size:.82rem">${escapeHtml(it.top_peer)}</code>` +
              (more > 0 ? ` <span class="text-secondary" style="font-size:.7rem" title="${escapeAttr(t('fwAnomalies.more_peers'))}">+${more}</span>` : '')
            : '<span class="text-secondary">—</span>';
        return `<tr data-ip="${escapeAttr(it.ip)}" style="${baseBg}cursor:pointer" title="${escapeAttr(t('fwAnomalies.row_click_title'))}">
            <td>${scoreBadge(it.score)}${driverChips(it.drivers)}</td>
            <td><code style="font-size:.82rem">${escapeHtml(it.ip || '')}</code>${watchlistBadge(it.ip)}${osint}</td>
            <td>${peer}</td>
            <td>${country}</td>
            <td>${fmtBytes(it.bytes)}</td>
            <td>${(it.flows || 0).toLocaleString(AN_LOCALE)}</td>
            <td>${(it.distinct_dst_ports || 0).toLocaleString(AN_LOCALE)}</td>
            <td>${(it.distinct_dst_ips || 0).toLocaleString(AN_LOCALE)}</td>
            <td>${night}%</td>
            <td style="white-space:nowrap">${fmtTs(it.last_seen)}</td>
            <td>${verdictCell(it.ip)}</td>
            <td>${verdictCommentCell(it.ip)}</td>
            <td><button class="block-link" onclick="anomBlockIp('${escapeAttr(it.ip)}', this)">${t('fwAnomalies.block')}</button></td>
        </tr>`;
    }).join('');
    // Re-apply the active text filter (rows were rebuilt by the sort).
    const f = document.querySelector('input[data-filter-for="anTable"]');
    if (f && f.value.trim()) {
        const q = f.value.toLowerCase().trim();
        tbody.querySelectorAll(':scope > tr').forEach(tr => {
            tr.style.display = tr.textContent.toLowerCase().includes(q) ? '' : 'none';
        });
    }
}

// Bubble view of the 3 chosen dimensions: x=X, y=Y, bubble size=Z, colour=Anomalie.
function renderScatter(points) {
    const ctx = document.getElementById('anScatter');
    if (!ctx) return;
    const [kx, ky, kz] = _anDims;
    const dx = AN_DIM_BY_KEY[kx], dy = AN_DIM_BY_KEY[ky], dz = AN_DIM_BY_KEY[kz];
    const valOf = (p, k) => (p.vals ? p.vals[k] : 0) || 0;

    // The Z dimension drives bubble size. Heavy-tailed (log) dims are mapped via
    // log1p so a few huge values don't swamp the rest; map min–max onto 4–24px.
    const zScale = v => (dz.axis === 'log' ? Math.log1p(v || 0) : (v || 0));
    let zMin = Infinity, zMax = -Infinity;
    for (const p of points) { const v = zScale(valOf(p, kz)); zMin = Math.min(zMin, v); zMax = Math.max(zMax, v); }
    const zSpan = (zMax - zMin) || 1;
    const radius = v => 4 + ((zScale(v) - zMin) / zSpan) * 20;

    const mk = p => ({ x: dimPlotVal(kx, valOf(p, kx)), y: dimPlotVal(ky, valOf(p, ky)),
                       r: radius(valOf(p, kz)), ip: p.ip, score: p.score,
                       rawx: valOf(p, kx), rawy: valOf(p, ky), rawz: valOf(p, kz),
                       verdict: verdictOf(p.ip), comment: _anVerdicts[p.ip]?.comment || '' });
    // Group by verdict first (marked points get the badge colour), then fall
    // back to the anomaly/normal split for unrated points.
    const g = { malicious: [], suspicious: [], benign: [], anom: [], normal: [] };
    for (const p of points) {
        const v = verdictOf(p.ip);
        if (v && g[v]) g[v].push(mk(p));
        else (p.anom ? g.anom : g.normal).push(mk(p));
    }
    // Unrated first (drawn underneath), verdicted on top with a light border so
    // "malicious" (solid red) stays distinct from an unrated anomaly.
    const datasets = [
        { label: t('fwAnomalies.legend_normal'),  data: g.normal, backgroundColor: 'rgba(120,144,170,.40)' },
        { label: t('fwAnomalies.legend_anomaly'), data: g.anom,   backgroundColor: 'rgba(220,53,69,.55)' },
        { label: t('fwAnomalies.verdict_malicious'),  data: g.malicious,  backgroundColor: AN_VERDICT_META.malicious.color,  borderColor: '#fff', borderWidth: 1 },
        { label: t('fwAnomalies.verdict_suspicious'), data: g.suspicious, backgroundColor: AN_VERDICT_META.suspicious.color, borderColor: '#fff', borderWidth: 1 },
        { label: t('fwAnomalies.verdict_benign'),     data: g.benign,     backgroundColor: AN_VERDICT_META.benign.color,     borderColor: '#fff', borderWidth: 1 },
    ].filter(d => d.data.length);
    const data = { datasets };
    const axisType = d => (d.axis === 'log' ? 'logarithmic' : 'linear');
    const opts = {
        responsive: true,
        scales: {
            x: { type: axisType(dx), title: { display: true, text: dx.label } },
            y: { type: axisType(dy), title: { display: true, text: dy.label } },
        },
        plugins: {
            legend: { labels: { usePointStyle: true } },
            tooltip: {
                callbacks: {
                    label: (c) => {
                        const r = c.raw;
                        return `${r.ip} · score ${r.score.toFixed(3)} · `
                            + `${dx.label} ${fmtDimVal(kx, r.rawx)} · `
                            + `${dy.label} ${fmtDimVal(ky, r.rawy)} · `
                            + `${dz.label} ${fmtDimVal(kz, r.rawz)}`;
                    },
                    afterLabel: (c) => {
                        const r = c.raw;
                        if (!r.verdict) return '';
                        const label = t(AN_VERDICT_META[r.verdict].key);
                        return `${t('fwAnomalies.verdict_col')}: ${label}` + (r.comment ? ` — ${r.comment}` : '');
                    },
                },
            },
        },
    };
    if (_anScatter) { _anScatter.data = data; _anScatter.options = opts; _anScatter.update(); }
    else _anScatter = new Chart(ctx, { type: 'bubble', data, options: opts });
}

// 3-D scatter (Plotly): rotatable point cloud over the 3 chosen dimensions.
// x=X, y=Y, z=Z, colour=Anomalie; Land + score shown on hover.
let _an3dKey = '';   // dimension signature of the current plot
function render3d(points) {
    const el = document.getElementById('an3d');
    if (!el || typeof Plotly === 'undefined') return;
    if (!points.length) { Plotly.purge(el); _an3dKey = ''; return; }

    const [kx, ky, kz] = _anDims;
    const dx = AN_DIM_BY_KEY[kx], dy = AN_DIM_BY_KEY[ky], dz = AN_DIM_BY_KEY[kz];
    const valOf = (p, k) => (p.vals ? p.vals[k] : 0) || 0;

    const hover = p => {
        const v = _anVerdicts[p.ip];
        let s = `<b>${p.ip}</b><br>${t('common.score')} ${p.score.toFixed(3)}`
            + `<br>${dx.label} ${fmtDimVal(kx, valOf(p, kx))}`
            + `<br>${dy.label} ${fmtDimVal(ky, valOf(p, ky))}`
            + `<br>${dz.label} ${fmtDimVal(kz, valOf(p, kz))}`
            + (p.country ? `<br>${t('common.country')} ${p.country}` : '');
        if (v) s += `<br>${t('fwAnomalies.verdict_col')}: ${t(AN_VERDICT_META[v.verdict].key)}`
            + (v.comment ? `<br>${escapeHtml(v.comment)}` : '');
        return s;
    };
    const trace = (pts, name, color, size, opacity) => ({
        type: 'scatter3d', mode: 'markers', name,
        x: pts.map(p => dimPlotVal(kx, valOf(p, kx))),
        y: pts.map(p => dimPlotVal(ky, valOf(p, ky))),
        z: pts.map(p => dimPlotVal(kz, valOf(p, kz))),
        text: pts.map(hover),
        hoverinfo: 'text',
        marker: { size, color, opacity, line: { width: 0 } },
    });
    // Verdict groups first (marked points), then unrated anomaly / normal.
    const grp = { malicious: [], suspicious: [], benign: [], anom: [], normal: [] };
    for (const p of points) {
        const v = verdictOf(p.ip);
        if (v && grp[v]) grp[v].push(p);
        else (p.anom ? grp.anom : grp.normal).push(p);
    }
    const data = [
        trace(grp.normal,     t('fwAnomalies.legend_normal'),     'rgba(120,144,170,.55)', 3, 0.5),
        trace(grp.anom,       t('fwAnomalies.legend_anomaly'),    'rgba(220,53,69,.75)',   5, 0.85),
        trace(grp.malicious,  t('fwAnomalies.verdict_malicious'), AN_VERDICT_META.malicious.color,  6, 1),
        trace(grp.suspicious, t('fwAnomalies.verdict_suspicious'),AN_VERDICT_META.suspicious.color, 6, 1),
        trace(grp.benign,     t('fwAnomalies.verdict_benign'),    AN_VERDICT_META.benign.color,     6, 1),
    ].filter(tr => tr.x.length);
    const ax = (dim) => {
        const a = { title: { text: dim.label }, gridcolor: 'rgba(148,163,184,.25)',
                    zerolinecolor: 'rgba(148,163,184,.4)', color: '#cbd5e1' };
        if (dim.axis === 'log') a.type = 'log';
        return a;
    };
    const layout = {
        margin: { l: 0, r: 0, t: 0, b: 0 },
        paper_bgcolor: 'rgba(0,0,0,0)',
        font: { color: '#cbd5e1' },
        legend: { orientation: 'h', y: 1.02 },
        scene: { xaxis: ax(dx), yaxis: ax(dy), zaxis: ax(dz) },
    };
    // Plotly.react does not reliably re-apply 3-D scene axis type (log/linear)
    // or titles when the plot already exists. So when the chosen dimensions
    // change, purge and rebuild so the axes fully adopt them; for a same-dimension
    // refresh we react() to preserve the user's current rotation/zoom.
    const cfg = { responsive: true, displaylogo: false };
    const key = _anDims.join(',');
    if (_an3dKey !== key) {
        Plotly.purge(el);
        _an3dKey = key;
        Plotly.newPlot(el, data, layout, cfg);
    } else {
        Plotly.react(el, data, layout, cfg);
    }
}

// "AI analysis (unrated)" button: triggers the anomaly agent sweep without the
// per-sweep cap, so every anomaly that has no verdict yet gets OSINT+LLM triage
// (already-rated IPs are skipped server-side). The sweep runs in the background;
// we poll the verdicts for a while so new 🤖 ratings appear as they are written.
async function anomalyAiScan(btn) {
    if (btn) btn.disabled = true;
    const label = btn?.querySelector('span');
    const orig = label?.textContent;
    try {
        const r = await fetch('/api/agent/anomaly-run-now?all=true', { method: 'POST' });
        if (!r.ok) {
            const e = await r.json().catch(() => ({}));
            throw new Error(e.detail || `HTTP ${r.status}`);
        }
        for (let i = 1; i <= 10; i++) {           // ~2.5 min of live updates
            if (label) label.textContent = t('fwAnomalies.ai_scan_running');
            await new Promise(res => setTimeout(res, 15000));
            await loadVerdicts();
            _anRenderRows();
            renderScatter(_anScatterData);
            render3d(_anScatterData);
        }
    } catch (err) {
        alert(t('fwAnomalies.ai_scan_failed') + ': ' + err.message);
    } finally {
        if (btn) btn.disabled = false;
        if (label && orig) label.textContent = orig;
    }
}

async function anomBlockIp(ip, btn) {
    if (!ip || !confirm(t('fwAnomalies.block_confirm', { ip }))) return;
    if (btn) { btn.disabled = true; btn.textContent = '…'; }
    try {
        const r = await fetch('/api/firewall/block-ip', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, comment: t('fwAnomalies.block_comment') }),
        });
        const data = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(data.detail || `HTTP ${r.status}`);
        if (btn) { btn.textContent = t('fwAnomalies.block_done'); btn.classList.add('text-success'); }
    } catch (err) {
        alert(t('fwAnomalies.block_failed') + ': ' + err.message);
        if (btn) { btn.disabled = false; btn.textContent = t('fwAnomalies.block'); }
    }
}

// ---- Analyst verdict (schädlich / unschädlich + comment) ---------------------
// Anomalies have no stable id (recomputed each run), so a verdict is keyed by
// the IP and persisted server-side. _anVerdicts mirrors that table for the
// currently shown rows.

// Watchlist membership for the shown rows — badge in the IP column + prefilled
// state in the verdict modal. Loaded once per refresh, updated in place on add.
let _anWatchlist = new Set();
async function loadWatchlist() {
    try {
        const r = await fetch('/api/firewall/watchlist');
        if (!r.ok) return;
        const d = await r.json();
        _anWatchlist = new Set((d.items || []).map(w => w.ip));
    } catch (e) { /* keep the previous set on error */ }
}

function watchlistBadge(ip) {
    if (!_anWatchlist.has(ip)) return '';
    return ` <span class="badge text-bg-info" style="font-size:.62rem" title="${escapeAttr(t('fwAnomalies.on_watchlist'))}"><i class="bi bi-binoculars"></i></span>`;
}

async function loadVerdicts() {
    try {
        const r = await fetch('/api/firewall/anomaly-verdicts');
        if (!r.ok) return;
        const d = await r.json();
        _anVerdicts = d.verdicts || {};
    } catch (e) { /* keep the previous map on error */ }
}

// Render the verdict cell: a coloured badge when marked (comment on hover),
// otherwise a neutral "assess" button. Both open the verdict modal.
// Badge colour + label per verdict value (malicious / suspicious / benign).
const AN_VERDICT_META = {
    malicious:  { cls: 'text-bg-danger',  key: 'fwAnomalies.verdict_malicious',  color: '#dc3545' },
    suspicious: { cls: 'text-bg-warning', key: 'fwAnomalies.verdict_suspicious', color: '#ffc107' },
    benign:     { cls: 'text-bg-success', key: 'fwAnomalies.verdict_benign',     color: '#198754' },
};

function verdictCell(ip) {
    const v = _anVerdicts[ip];
    const meta = v && AN_VERDICT_META[v.verdict];
    if (meta) {
        const label = t(meta.key);
        // 🤖 = set by the anomaly agent (OSINT triage); a human save takes ownership.
        const agent = v.created_by === 'agent' ? ' 🤖' : '';
        const note = v.comment ? ' 💬' : '';
        const title = (v.created_by === 'agent' ? t('fwAnomalies.verdict_by_agent') + ' — ' : '')
            + (v.comment || t('fwAnomalies.verdict_edit'));
        return `<button class="badge ${meta.cls}" style="border:0;cursor:pointer" title="${escapeAttr(title)}" onclick="openVerdictModal('${escapeAttr(ip)}')">${escapeHtml(label)}${agent}${note}</button>`;
    }
    return `<button class="btn btn-sm btn-outline-secondary py-0" style="font-size:.72rem" onclick="openVerdictModal('${escapeAttr(ip)}')">${t('fwAnomalies.verdict_set')}</button>`;
}

// The verdict's comment, truncated with the full text on hover.
function verdictCommentCell(ip) {
    const c = _anVerdicts[ip]?.comment;
    if (!c) return '<span class="text-secondary">—</span>';
    const short = c.length > 60 ? c.slice(0, 60) + '…' : c;
    return `<span style="font-size:.8rem" title="${escapeAttr(c)}">${escapeHtml(short)}</span>`;
}

let _verdictIp = null;
function openVerdictModal(ip) {
    _verdictIp = ip;
    const v = _anVerdicts[ip];
    document.getElementById('verdictIp').textContent = ip;
    document.getElementById('verdictMal').checked = v?.verdict === 'malicious';
    document.getElementById('verdictSus').checked = v?.verdict === 'suspicious';
    document.getElementById('verdictBen').checked = v?.verdict === 'benign';
    document.getElementById('verdictComment').value = v?.comment || '';
    const meta = document.getElementById('verdictMeta');
    meta.textContent = v?.updated_at ? t('fwAnomalies.verdict_updated', { time: fmtTs(v.updated_at) }) : '';
    document.getElementById('verdictClearBtn').style.display = v ? '' : 'none';
    // Watchlist option: an IP already on the watchlist shows as such instead of
    // offering a redundant add (_anWatchlist is refreshed with every analysis).
    const wlBox = document.getElementById('verdictWatchlist');
    const wlState = document.getElementById('verdictWatchlistState');
    const listed = _anWatchlist.has(ip);
    wlBox.checked = listed;
    wlBox.disabled = listed;
    wlState.textContent = listed ? t('fwAnomalies.verdict_watchlist_already') : '';
    document.getElementById('verdictModal').classList.add('active');
}

function closeVerdict() {
    document.getElementById('verdictModal').classList.remove('active');
}

async function saveVerdict() {
    const verdict = document.querySelector('input[name="verdictChoice"]:checked')?.value || '';
    if (!verdict) { alert(t('fwAnomalies.verdict_pick')); return; }
    const ip = _verdictIp;
    const comment = document.getElementById('verdictComment').value;
    const wlBox = document.getElementById('verdictWatchlist');
    const wantWatchlist = wlBox.checked && !wlBox.disabled;   // disabled = already listed
    const ok = await _postVerdict(ip, verdict, comment);
    if (ok && wantWatchlist) {
        try {
            const r = await fetch('/api/firewall/watchlist', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip, comment: comment.trim() || t('fwAnomalies.verdict_watchlist_comment') }),
            });
            const d = await r.json().catch(() => ({}));
            if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
            _anWatchlist.add(ip);
            _anRenderRows();   // show the watchlist badge immediately
        } catch (err) {
            // Verdict is already saved — only the watchlist add failed.
            alert(t('fwAnomalies.verdict_watchlist_failed') + ': ' + err.message);
        }
    }
}

async function clearVerdict() {
    await _postVerdict(_verdictIp, '', '');
}

async function _postVerdict(ip, verdict, comment) {
    if (!ip) return false;
    try {
        const r = await fetch('/api/firewall/anomaly-verdict', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, verdict, comment }),
        });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
        if (verdict) _anVerdicts[ip] = { verdict: d.verdict, comment: d.comment, created_by: d.created_by || 'human', updated_at: d.updated_at };
        else delete _anVerdicts[ip];
        closeVerdict();
        _anRenderRows();
        // Recolour the charts so the new verdict shows without a full refresh.
        renderScatter(_anScatterData);
        render3d(_anScatterData);
        return true;
    } catch (err) {
        alert(t('fwAnomalies.verdict_failed') + ': ' + err.message);
        return false;
    }
}

// ---- Connection detail modal (row click) -------------------------------------
// Pulls everything we know about an IP's connections from /api/ip/{ip}/connections:
// NetFlow outbound (IP→peer) + inbound (peer→IP), plus blocked firewall attempts.
let _connIp = null;          // IP currently shown in the modal (for the day buttons)
function closeConn() {
    document.getElementById('connModal').classList.remove('active');
}

// Time-window buttons. Busy IPs (many peers) can time out on large windows, so we
// default to 7 days and let the user widen/narrow it.
function connDayBar(days) {
    const opts = [[1, t('fwAnomalies.win_24h')], [7, t('fwAnomalies.win_7d')], [30, t('fwAnomalies.win_30d')]];
    return '<div style="margin:0 0 .75rem;display:flex;gap:.4rem;align-items:center">'
        + `<span class="text-secondary" style="font-size:.78rem">${t('fwAnomalies.timeframe')}:</span>`
        + opts.map(([v, l]) => `<button class="btn btn-sm ${v === days ? 'btn-primary' : 'btn-outline-secondary'}" onclick="anShowConnections(_connIp, ${v})">${l}</button>`).join('')
        + '</div>';
}

async function anShowConnections(ip, days = 7) {
    if (!ip) return;
    _connIp = ip;
    const modal = document.getElementById('connModal');
    const body = document.getElementById('connModalBody');
    document.getElementById('connModalTitle').textContent = `${t('fwAnomalies.conn_title')} · ${ip}`;
    body.innerHTML = connDayBar(days) + `<div class="text-secondary py-3">${t('common.loading')}</div>`;
    modal.classList.add('active');
    try {
        const r = await fetch(`/api/ip/${encodeURIComponent(ip)}/connections?days=${days}`);
        if (!r.ok) {
            const e = await r.json().catch(() => ({}));
            throw new Error(e.detail || `HTTP ${r.status}`);
        }
        body.innerHTML = connDayBar(days) + renderConnBody(await r.json());
    } catch (err) {
        body.innerHTML = connDayBar(days) + `<div class="detail-error">${t('fwAnomalies.conn_load_failed')}: ${escapeHtml(err.message)}</div>`;
    }
}

// One NetFlow direction → a table (peer, country, port, proto, volume, flows, packets, seen).
function connNfTable(side, peerLabel) {
    const rows = (side && side.connections) || [];
    if (!rows.length) return `<p class="text-secondary" style="margin:.25rem 0 1rem">${t('fwAnomalies.no_netflow_conns')}</p>`;
    const trs = rows.map(c => `<tr>
        <td><code style="font-size:.8rem">${escapeHtml(c.peer || '')}</code></td>
        <td>${c.country ? escapeHtml(c.country) : '<span class="text-secondary">—</span>'}</td>
        <td>${c.port ?? '—'}</td>
        <td>${escapeHtml(c.protocol || '—')}</td>
        <td>${fmtBytes(c.bytes)}</td>
        <td>${(c.flows || 0).toLocaleString(AN_LOCALE)}</td>
        <td>${(c.packets || 0).toLocaleString(AN_LOCALE)}</td>
        <td style="white-space:nowrap">${fmtTs(c.first_seen)}</td>
        <td style="white-space:nowrap">${fmtTs(c.last_seen)}</td>
    </tr>`).join('');
    const trunc = side.truncated ? ` <span class="text-secondary" style="font-size:.72rem">${t('fwAnomalies.truncated')}</span>` : '';
    return `<div class="table-scroll"><table class="table table-sm table-hover align-middle">
        <thead><tr>
            <th>${peerLabel}</th><th>${t('common.country')}</th><th>${t('fwAnomalies.port')}</th><th>${t('fwAnomalies.proto')}</th>
            <th>${t('fwAnomalies.col_volume')}</th><th>Flows</th><th>${t('fwAnomalies.packets')}</th><th>${t('fwAnomalies.first_seen')}</th><th>${t('fwAnomalies.col_last_seen')}</th>
        </tr></thead><tbody>${trs}</tbody></table></div>${trunc ? `<div>${trunc}</div>` : ''}`;
}

// Blocked firewall attempts for one direction (peer, country, port, proto, action, events, last seen).
function connFwTable(side, peerLabel) {
    const rows = (side && side.connections) || [];
    if (!rows.length) return '';
    const trs = rows.map(c => `<tr>
        <td><code style="font-size:.8rem">${escapeHtml(c.peer || '')}</code></td>
        <td>${c.country ? escapeHtml(c.country) : '<span class="text-secondary">—</span>'}</td>
        <td>${c.port ?? '—'}</td>
        <td>${escapeHtml(c.protocol || '—')}</td>
        <td><span class="badge text-bg-danger">${escapeHtml(c.action || 'deny')}</span></td>
        <td>${(c.events || 0).toLocaleString(AN_LOCALE)}</td>
        <td style="white-space:nowrap">${fmtTs(c.last_seen)}</td>
    </tr>`).join('');
    return `<div class="table-scroll"><table class="table table-sm table-hover align-middle">
        <thead><tr>
            <th>${peerLabel}</th><th>${t('common.country')}</th><th>${t('fwAnomalies.port')}</th><th>${t('fwAnomalies.proto')}</th><th>${t('common.action')}</th><th>${t('fwAnomalies.attempts')}</th><th>${t('fwAnomalies.col_last_seen')}</th>
        </tr></thead><tbody>${trs}</tbody></table></div>`;
}

function connSummary(side) {
    if (!side) return '';
    return `<span class="text-secondary" style="font-size:.78rem">`
        + `${(side.peers || 0).toLocaleString(AN_LOCALE)} ${t('fwAnomalies.peers')} · ${fmtBytes(side.bytes || 0)} · ${(side.flows || 0).toLocaleString(AN_LOCALE)} Flows</span>`;
}

function renderConnBody(d) {
    const parts = [];
    parts.push(`<p class="admin-hint" style="margin:0 0 .75rem">${t('fwAnomalies.conn_intro', { days: d.days, ip: escapeHtml(d.ip) })}</p>`);

    // NetFlow outbound (IP as source → peers) and inbound (peers → IP).
    if (d.netflow_available === false) {
        parts.push(`<div class="detail-error" style="margin-bottom:1rem">${t('fwAnomalies.netflow_unavailable')}: ${escapeHtml(d.netflow_reason || t('fwAnomalies.timeout'))}</div>`);
    }
    parts.push(`<h4 style="margin:.25rem 0">${t('fwAnomalies.outbound')} <small class="text-secondary">(${escapeHtml(d.ip)} → ${t('fwAnomalies.dest')})</small> ${connSummary(d.outbound)}</h4>`);
    parts.push(connNfTable(d.outbound, t('common.dest_ip')));
    parts.push(`<h4 style="margin:1rem 0 .25rem">${t('fwAnomalies.inbound')} <small class="text-secondary">(${t('fwAnomalies.source')} → ${escapeHtml(d.ip)})</small> ${connSummary(d.inbound)}</h4>`);
    parts.push(connNfTable(d.inbound, t('fwAnomalies.source_ip')));

    // Blocked firewall attempts (only shown when present).
    const fb = d.firewall_blocked || {};
    const fbOut = connFwTable(fb.outbound, t('common.dest_ip'));
    const fbIn = connFwTable(fb.inbound, t('fwAnomalies.source_ip'));
    if (fbOut || fbIn) {
        parts.push(`<h4 style="margin:1.25rem 0 .25rem">${t('fwAnomalies.blocked_fw_attempts')}</h4>`);
        if (fbOut) { parts.push(`<div class="text-secondary" style="font-size:.78rem;margin:.25rem 0">${t('fwAnomalies.outbound')} (${escapeHtml(d.ip)} → ${t('fwAnomalies.dest')})</div>`); parts.push(fbOut); }
        if (fbIn) { parts.push(`<div class="text-secondary" style="font-size:.78rem;margin:.5rem 0 .25rem">${t('fwAnomalies.inbound')} (${t('fwAnomalies.source')} → ${escapeHtml(d.ip)})</div>`); parts.push(fbIn); }
    }
    return parts.join('');
}

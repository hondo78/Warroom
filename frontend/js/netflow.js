let nfMap;
let nfMapMarkers = [];
let nfTimelineChart, nfTalkersChart, nfDestsChart, nfPortsChart, nfProtoChart, nfIfaceChart;

const PALETTE = ['#3b82f6', '#ef4444', '#22c55e', '#f59e0b', '#8b5cf6', '#06b6d4', '#ec4899', '#14b8a6', '#eab308', '#a78bfa'];

// Number / date formatting follows the chosen UI language (thousands separators
// and date order differ between en/de). Language can't change without a reload.
const NF_LANG = (typeof currentLang === 'function') ? currentLang() : 'en';
const NF_LOCALE = NF_LANG === 'de' ? 'de-DE' : 'en-US';

document.addEventListener('DOMContentLoaded', async () => {
    initNfMap();
    initNfCharts();
    initFilters();
    await loadFirewalls();
    await netflowRefresh();
    document.getElementById('nfDays').addEventListener('change', netflowRefresh);
    document.getElementById('nfFirewall').addEventListener('change', netflowRefresh);
    setInterval(netflowRefresh, 60000);
});

function initFilters() {
    document.querySelectorAll('input[data-filter-for]').forEach(input => {
        const tbody = document.getElementById(input.dataset.filterFor);
        if (!tbody) return;
        input.addEventListener('input', () => {
            const t = input.value.toLowerCase().trim();
            tbody.querySelectorAll(':scope > tr').forEach(tr => {
                tr.style.display = (!t || tr.textContent.toLowerCase().includes(t)) ? '' : 'none';
            });
        });
    });
}

function getDays() {
    return parseInt(document.getElementById('nfDays').value, 10) || 1;
}

function getFirewall() {
    return document.getElementById('nfFirewall').value || 'all';
}

function qs() {
    return `days=${getDays()}&firewall=${encodeURIComponent(getFirewall())}`;
}

function fmtBytes(b) {
    if (!b) return '0 B';
    const u = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    let i = 0;
    while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
    return `${b.toFixed(b >= 100 ? 0 : 1)} ${u[i]}`;
}

function fmtNum(n) {
    if (!n && n !== 0) return '-';
    return n.toLocaleString(NF_LOCALE);
}

async function loadFirewalls() {
    try {
        const r = await fetch('/api/netflow/firewalls');
        const fws = await r.json();
        const sel = document.getElementById('nfFirewall');
        sel.innerHTML = `<option value="all">${t('netflow.all_firewalls')}</option>` +
            fws.map(f => {
                const label = f.name && f.name !== f.ip ? `${f.name} (${f.ip})` : f.ip;
                return `<option value="${f.ip}">${label}</option>`;
            }).join('');
    } catch (e) {
        console.error('Firewall list failed:', e);
    }
}

async function netflowRefresh() {
    await Promise.all([
        updateSummary(),
        updateTimeline(),
        updateTalkers(),
        updateDestinations(),
        updatePorts(),
        updateProtocols(),
        updateGeo(),
        updateFlowsTable(),
        updateInterfaces(),
    ]);
}

async function updateSummary() {
    const r = await fetch(`/api/netflow/summary?${qs()}`);
    const d = await r.json();
    document.getElementById('nfBytes').textContent = fmtBytes(d.bytes);
    document.getElementById('nfFlows').textContent = fmtNum(d.flows);
    document.getElementById('nfPackets').textContent = fmtNum(d.packets);
    document.getElementById('nfSources').textContent = fmtNum(d.unique_sources);
    document.getElementById('nfDests').textContent = fmtNum(d.unique_destinations);

    const seconds = (Date.now() - new Date(d.since).getTime()) / 1000;
    const bytesRate = seconds > 0 ? d.bytes / seconds : 0;
    const flowsRate = seconds > 0 ? (d.flows / seconds * 60) : 0;
    document.getElementById('nfBytesRate').textContent = t('netflow.rate_bytes', {rate: fmtBytes(bytesRate)});
    document.getElementById('nfFlowsRate').textContent = t('netflow.rate_flows', {rate: fmtNum(Math.round(flowsRate))});
}

function initNfCharts() {
    const dark = {
        color: '#94a3b8',
        scales: {
            x: {ticks: {color: '#94a3b8'}, grid: {color: '#2a3a4e'}},
            y: {ticks: {color: '#94a3b8'}, grid: {color: '#2a3a4e'}},
        },
        plugins: {legend: {labels: {color: '#e2e8f0'}}},
        responsive: true,
        maintainAspectRatio: false,
    };

    nfTimelineChart = new Chart(document.getElementById('nfTimelineChart'), {
        type: 'line',
        data: {labels: [], datasets: [{label: 'Bytes', data: [], borderColor: PALETTE[0], backgroundColor: PALETTE[0] + '33', fill: true, tension: 0.3}]},
        options: {
            ...dark,
            scales: {
                ...dark.scales,
                y: {...dark.scales.y, ticks: {...dark.scales.y.ticks, callback: v => fmtBytes(v)}},
            },
        },
    });
    nfTalkersChart = new Chart(document.getElementById('nfTalkersChart'), {
        type: 'bar',
        data: {labels: [], datasets: [{label: 'Bytes', data: [], backgroundColor: PALETTE[1]}]},
        options: {...dark, indexAxis: 'y', scales: {...dark.scales, x: {...dark.scales.x, ticks: {...dark.scales.x.ticks, callback: v => fmtBytes(v)}}}},
    });
    nfDestsChart = new Chart(document.getElementById('nfDestsChart'), {
        type: 'bar',
        data: {labels: [], datasets: [{label: 'Bytes', data: [], backgroundColor: PALETTE[2]}]},
        options: {...dark, indexAxis: 'y', scales: {...dark.scales, x: {...dark.scales.x, ticks: {...dark.scales.x.ticks, callback: v => fmtBytes(v)}}}},
    });
    nfPortsChart = new Chart(document.getElementById('nfPortsChart'), {
        type: 'bar',
        data: {labels: [], datasets: [{label: 'Bytes', data: [], backgroundColor: PALETTE[3]}]},
        options: {...dark, indexAxis: 'y', scales: {...dark.scales, x: {...dark.scales.x, ticks: {...dark.scales.x.ticks, callback: v => fmtBytes(v)}}}},
    });
    nfProtoChart = new Chart(document.getElementById('nfProtoChart'), {
        type: 'doughnut',
        data: {labels: [], datasets: [{data: [], backgroundColor: PALETTE}]},
        options: {responsive: true, maintainAspectRatio: false, plugins: {legend: {labels: {color: '#e2e8f0'}}}},
    });

    nfIfaceChart = new Chart(document.getElementById('nfIfaceChart'), {
        type: 'bar',
        data: {
            labels: [],
            datasets: [
                {label: 'Bytes In', data: [], backgroundColor: PALETTE[0], stack: 'iface'},
                {label: 'Bytes Out', data: [], backgroundColor: PALETTE[1], stack: 'iface'},
            ],
        },
        options: {
            ...dark,
            scales: {
                x: {...dark.scales.x, stacked: true},
                y: {
                    ...dark.scales.y,
                    stacked: true,
                    ticks: {...dark.scales.y.ticks, callback: v => fmtBytes(v)},
                },
            },
        },
    });
}

async function updateTimeline() {
    const r = await fetch(`/api/netflow/timeline?${qs()}`);
    const d = await r.json();
    nfTimelineChart.data.labels = d.points.map(p => p.ts ? new Date(p.ts).toLocaleString(NF_LOCALE) : '');
    nfTimelineChart.data.datasets[0].data = d.points.map(p => p.bytes);
    nfTimelineChart.update();
}

async function updateTalkers() {
    const r = await fetch(`/api/netflow/top-talkers?${qs()}&limit=15`);
    const d = await r.json();
    nfTalkersChart.data.labels = d.map(x => `${x.ip}${x.country ? ' (' + x.country + ')' : ''}`);
    nfTalkersChart.data.datasets[0].data = d.map(x => x.bytes);
    nfTalkersChart.update();
}

async function updateDestinations() {
    const r = await fetch(`/api/netflow/top-destinations?${qs()}&limit=15`);
    const d = await r.json();
    nfDestsChart.data.labels = d.map(x => `${x.ip}${x.country ? ' (' + x.country + ')' : ''}`);
    nfDestsChart.data.datasets[0].data = d.map(x => x.bytes);
    nfDestsChart.update();
}

async function updatePorts() {
    const r = await fetch(`/api/netflow/top-ports?${qs()}&limit=15`);
    const d = await r.json();
    nfPortsChart.data.labels = d.map(x => {
        const lbl = x.service ? `${x.port}/${x.protocol} ${x.service}` : `${x.port}/${x.protocol || '?'}`;
        return lbl;
    });
    nfPortsChart.data.datasets[0].data = d.map(x => x.bytes);
    nfPortsChart.update();
}

async function updateProtocols() {
    const r = await fetch(`/api/netflow/protocols?${qs()}`);
    const d = await r.json();
    nfProtoChart.data.labels = d.map(x => x.protocol);
    nfProtoChart.data.datasets[0].data = d.map(x => x.bytes);
    nfProtoChart.update();
}

function initNfMap() {
    nfMap = L.map('nfMap', {worldCopyJump: true}).setView([20, 0], 2);
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}.png', {
        attribution: '© OpenStreetMap contributors © CARTO',
    }).addTo(nfMap);
}

async function updateGeo() {
    nfMapMarkers.forEach(m => nfMap.removeLayer(m));
    nfMapMarkers = [];
    const r = await fetch(`/api/netflow/geo?${qs()}&limit=200`);
    const d = await r.json();
    if (!d.length) return;
    const maxBytes = Math.max(...d.map(x => x.bytes));
    d.forEach(p => {
        const radius = 4 + Math.sqrt(p.bytes / maxBytes) * 18;
        const m = L.circleMarker([p.lat, p.lon], {
            radius,
            fillColor: '#3b82f6',
            color: '#3b82f6',
            weight: 1,
            fillOpacity: 0.55,
        }).bindPopup(`
            <strong>${p.ip}</strong><br>
            ${p.city || ''} ${p.country ? '(' + p.country + ')' : ''}<br>
            ${fmtBytes(p.bytes)} · ${fmtNum(p.flows)} ${t('netflow.tile_flows')}
        `).addTo(nfMap);
        nfMapMarkers.push(m);
    });
}

async function updateInterfaces() {
    const r = await fetch(`/api/netflow/interfaces?${qs()}`);
    const d = await r.json();

    const labels = d.map(i => {
        const fw = i.firewall_name || i.firewall_ip;
        return `${i.name || 'idx ' + i.iface_idx} @ ${fw}`;
    });
    nfIfaceChart.data.labels = labels;
    nfIfaceChart.data.datasets[0].data = d.map(i => i.bytes_in);
    nfIfaceChart.data.datasets[1].data = d.map(i => i.bytes_out);
    nfIfaceChart.update();

    const tbody = document.getElementById('nfIfaceTable');
    if (!d.length) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;color:var(--text-secondary);padding:1.5rem">${t('netflow.no_iface_data')}</td></tr>`;
        return;
    }
    tbody.innerHTML = d.map(i => {
        const fwLabel = i.firewall_name && i.firewall_name !== i.firewall_ip
            ? `<strong>${i.firewall_name}</strong><br><span style="color:var(--text-secondary);font-size:0.75rem">${i.firewall_ip}</span>`
            : `<code>${i.firewall_ip || '-'}</code>`;
        return `
            <tr>
                <td>${fwLabel}</td>
                <td><strong>${i.name || ''}</strong>${i.name ? ' ' : ''}<span style="color:var(--text-secondary)">idx ${i.iface_idx}</span></td>
                <td>${fmtBytes(i.bytes_in)}</td>
                <td>${fmtBytes(i.bytes_out)}</td>
                <td>${i.mbps_in_avg.toFixed(2)}</td>
                <td>${i.mbps_out_avg.toFixed(2)}</td>
                <td>${fmtNum(i.flows_in)} / ${fmtNum(i.flows_out)}</td>
            </tr>`;
    }).join('');
}

async function openIfaceNameEditor() {
    const [aliasResp, ifaceResp] = await Promise.all([
        fetch('/api/netflow/firewall-aliases'),
        fetch('/api/netflow/iface-names'),
    ]);
    const aliases = await aliasResp.json();
    const ifaceMap = await ifaceResp.json();

    const aliasLines = Object.entries(aliases).map(([ip, name]) => `${ip} ${name}`);
    document.getElementById('fwAliasText').value = aliasLines.join('\n');

    const ifaceLines = [];
    for (const [fw, ifs] of Object.entries(ifaceMap)) {
        for (const [idx, name] of Object.entries(ifs)) {
            ifaceLines.push(`${fw} ${idx} ${name}`);
        }
    }
    document.getElementById('ifaceMapText').value = ifaceLines.join('\n');
    document.getElementById('ifaceModal').classList.add('active');
}

function closeIfaceNameEditor() {
    document.getElementById('ifaceModal').classList.remove('active');
}

async function saveIfaceNames() {
    // Firewall aliases: 2 columns (ip, name)
    const aliasMap = {};
    for (const raw of document.getElementById('fwAliasText').value.split('\n')) {
        const line = raw.trim();
        if (!line || line.startsWith('#')) continue;
        const m = line.match(/^(\S+)\s+(.+)$/);
        if (!m) continue;
        aliasMap[m[1]] = m[2].trim();
    }

    // Interface names: 3 columns (ip, idx, name)
    const ifaceMap = {};
    for (const raw of document.getElementById('ifaceMapText').value.split('\n')) {
        const line = raw.trim();
        if (!line || line.startsWith('#')) continue;
        const m = line.match(/^(\S+)\s+(\d+)\s+(.+)$/);
        if (!m) continue;
        const [, fw, idx, name] = m;
        if (!ifaceMap[fw]) ifaceMap[fw] = {};
        ifaceMap[fw][idx] = name.trim();
    }

    try {
        const [r1, r2] = await Promise.all([
            fetch('/api/netflow/firewall-aliases', {
                method: 'PUT',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({aliases: aliasMap}),
            }),
            fetch('/api/netflow/iface-names', {
                method: 'PUT',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({names: ifaceMap}),
            }),
        ]);
        if (!r1.ok || !r2.ok) throw new Error('save failed');
    } catch (e) {
        alert(t('netflow.save_failed', {error: e.message}));
        return;
    }
    closeIfaceNameEditor();
    await Promise.all([loadFirewalls(), netflowRefresh()]);
}

// Sort state for the flows table: {key, dir} ('asc'|'desc')
const _flowsSort = {key: 'bytes', dir: 'desc'};

// Column definitions per grouping mode. Each entry: {key, label, type, render}
const FLOW_COLUMNS = {
    none: [
        {key: 'src_ip', labelKey: 'common.source_ip', type: 'text', render: f => `<code>${f.src_ip}</code>${osintButton(f.src_ip)}`},
        {key: 'dst_ip', labelKey: 'common.dest_ip', type: 'text', render: f => `<code>${f.dst_ip}</code>${osintButton(f.dst_ip)}`},
        {key: 'dst_port', labelKey: 'netflow.col_port', type: 'num', render: f => f.dst_port || '-'},
        {key: 'service', labelKey: 'netflow.col_service', type: 'text', render: f => f.service || '-'},
        {key: 'protocol', labelKey: 'netflow.col_protocol', type: 'text', render: f => f.protocol || '-'},
        {key: 'bytes', labelKey: 'netflow.col_bytes', type: 'num', render: f => fmtBytes(f.bytes), align: 'right'},
        {key: 'packets', labelKey: 'netflow.col_packets', type: 'num', render: f => fmtNum(f.packets), align: 'right'},
        {key: 'flows', labelKey: 'netflow.col_flows', type: 'num', render: f => fmtNum(f.flows), align: 'right'},
    ],
    src: [
        {key: 'ip', labelKey: 'common.source_ip', type: 'text', render: f => `<code>${f.ip}</code>${osintButton(f.ip)}`},
        {key: 'country', labelKey: 'common.country', type: 'text', render: f => [f.country, f.city].filter(Boolean).join(', ') || '-'},
        {key: 'org', labelKey: 'netflow.col_org', type: 'text', render: f => f.org || '-'},
        {key: 'bytes', labelKey: 'netflow.col_bytes', type: 'num', render: f => fmtBytes(f.bytes), align: 'right'},
        {key: 'packets', labelKey: 'netflow.col_packets', type: 'num', render: f => fmtNum(f.packets), align: 'right'},
        {key: 'flows', labelKey: 'netflow.col_flows', type: 'num', render: f => fmtNum(f.flows), align: 'right'},
    ],
    dst: [
        {key: 'ip', labelKey: 'common.dest_ip', type: 'text', render: f => `<code>${f.ip}</code>${osintButton(f.ip)}`},
        {key: 'country', labelKey: 'common.country', type: 'text', render: f => [f.country, f.city].filter(Boolean).join(', ') || '-'},
        {key: 'org', labelKey: 'netflow.col_org', type: 'text', render: f => f.org || '-'},
        {key: 'bytes', labelKey: 'netflow.col_bytes', type: 'num', render: f => fmtBytes(f.bytes), align: 'right'},
        {key: 'packets', labelKey: 'netflow.col_packets', type: 'num', render: f => fmtNum(f.packets), align: 'right'},
        {key: 'flows', labelKey: 'netflow.col_flows', type: 'num', render: f => fmtNum(f.flows), align: 'right'},
    ],
    src_dst: [
        {key: 'src_ip', labelKey: 'common.source_ip', type: 'text', render: f => `<code>${f.src_ip}</code>${osintButton(f.src_ip)}`},
        {key: 'dst_ip', labelKey: 'common.dest_ip', type: 'text', render: f => `<code>${f.dst_ip}</code>${osintButton(f.dst_ip)}`},
        {key: 'bytes', labelKey: 'netflow.col_bytes', type: 'num', render: f => fmtBytes(f.bytes), align: 'right'},
        {key: 'packets', labelKey: 'netflow.col_packets', type: 'num', render: f => fmtNum(f.packets), align: 'right'},
        {key: 'flows', labelKey: 'netflow.col_flows', type: 'num', render: f => fmtNum(f.flows), align: 'right'},
    ],
    port: [
        {key: 'port', labelKey: 'netflow.col_port', type: 'num', render: f => f.port || '-'},
        {key: 'service', labelKey: 'netflow.col_service', type: 'text', render: f => f.service || '-'},
        {key: 'protocol', labelKey: 'netflow.col_protocol', type: 'text', render: f => f.protocol || '-'},
        {key: 'bytes', labelKey: 'netflow.col_bytes', type: 'num', render: f => fmtBytes(f.bytes), align: 'right'},
        {key: 'flows', labelKey: 'netflow.col_flows', type: 'num', render: f => fmtNum(f.flows), align: 'right'},
    ],
    proto: [
        {key: 'protocol', labelKey: 'netflow.col_protocol', type: 'text', render: f => f.protocol || '-'},
        {key: 'protocol_num', labelKey: 'netflow.col_proto_num', type: 'num', render: f => f.protocol_num != null ? f.protocol_num : '-'},
        {key: 'bytes', labelKey: 'netflow.col_bytes', type: 'num', render: f => fmtBytes(f.bytes), align: 'right'},
        {key: 'flows', labelKey: 'netflow.col_flows', type: 'num', render: f => fmtNum(f.flows), align: 'right'},
    ],
};

const GROUP_BY_ENDPOINT = {
    none: '/api/netflow/top-flows',
    src: '/api/netflow/top-talkers',
    dst: '/api/netflow/top-destinations',
    src_dst: '/api/netflow/top-flows',  // client-side aggregated
    port: '/api/netflow/top-ports',
    proto: '/api/netflow/protocols',
};

function aggregateSrcDst(flows) {
    const map = new Map();
    for (const f of flows) {
        const key = `${f.src_ip}|${f.dst_ip}`;
        const cur = map.get(key) || {src_ip: f.src_ip, dst_ip: f.dst_ip, bytes: 0, packets: 0, flows: 0};
        cur.bytes += f.bytes;
        cur.packets += f.packets;
        cur.flows += f.flows;
        map.set(key, cur);
    }
    return [...map.values()];
}

async function updateFlowsTable() {
    const groupBy = document.getElementById('nfGroupBy')?.value || 'none';
    const limit = parseInt(document.getElementById('nfFlowLimit')?.value || '200', 10);
    const minBytes = parseInt(document.getElementById('nfMinBytes')?.value || '0', 10);
    const endpoint = GROUP_BY_ENDPOINT[groupBy] || GROUP_BY_ENDPOINT.none;

    renderFlowsHeader(groupBy);

    try {
        const url = `${endpoint}?${qs()}&limit=${limit}`;
        const r = await fetch(url);
        if (!r.ok) {
            const err = await r.text();
            renderFlowsError(groupBy, `HTTP ${r.status}: ${err.slice(0, 200)}`);
            return;
        }
        let items = await r.json();
        if (!Array.isArray(items)) {
            renderFlowsError(groupBy, t('netflow.unexpected_response'));
            return;
        }
        if (groupBy === 'src_dst') items = aggregateSrcDst(items);
        if (minBytes > 0) items = items.filter(f => (f.bytes || 0) >= minBytes);
        sortFlowItems(items, _flowsSort);
        renderFlowsBody(items, groupBy);
    } catch (err) {
        renderFlowsError(groupBy, err.message);
    }
}

function renderFlowsError(groupBy, msg) {
    const cols = FLOW_COLUMNS[groupBy] || FLOW_COLUMNS.none;
    document.getElementById('nfFlowsTable').innerHTML =
        `<tr><td colspan="${cols.length}" style="text-align:center;color:var(--accent-red);padding:1.5rem">${msg}</td></tr>`;
}

function sortFlowItems(items, sortState) {
    const key = sortState.key;
    const dir = sortState.dir === 'asc' ? 1 : -1;
    items.sort((a, b) => {
        const va = a[key];
        const vb = b[key];
        if (va === vb) return 0;
        if (va == null) return 1;
        if (vb == null) return -1;
        if (typeof va === 'number' && typeof vb === 'number') return (va - vb) * dir;
        return String(va).localeCompare(String(vb)) * dir;
    });
}

function renderFlowsHeader(groupBy) {
    const head = document.getElementById('nfFlowsHead');
    const cols = FLOW_COLUMNS[groupBy] || FLOW_COLUMNS.none;
    const cells = cols.map(c => {
        const isSorted = _flowsSort.key === c.key;
        const arrow = isSorted ? (_flowsSort.dir === 'asc' ? ' ▲' : ' ▼') : '';
        const align = c.align === 'right' ? ' style="text-align:right"' : '';
        return `<th class="sortable${isSorted ? ' sorted' : ''}" onclick="toggleFlowSort('${c.key}')"${align}>${t(c.labelKey)}${arrow}</th>`;
    }).join('');
    head.innerHTML = `<tr>${cells}</tr>`;
}

function renderFlowsBody(items, groupBy) {
    const tbody = document.getElementById('nfFlowsTable');
    const cols = FLOW_COLUMNS[groupBy] || FLOW_COLUMNS.none;
    if (!items.length) {
        tbody.innerHTML = `<tr><td colspan="${cols.length}" style="text-align:center;color:var(--text-secondary);padding:2rem">${t('netflow.no_data_selection')}</td></tr>`;
        return;
    }
    tbody.innerHTML = items.map(it => {
        const cells = cols.map(c => {
            const align = c.align === 'right' ? ' style="text-align:right"' : '';
            return `<td${align}>${c.render(it)}</td>`;
        }).join('');
        return `<tr>${cells}</tr>`;
    }).join('');
}

function toggleFlowSort(key) {
    if (_flowsSort.key === key) {
        _flowsSort.dir = _flowsSort.dir === 'asc' ? 'desc' : 'asc';
    } else {
        _flowsSort.key = key;
        // Numeric columns default to desc, text to asc
        const groupBy = document.getElementById('nfGroupBy')?.value || 'none';
        const col = (FLOW_COLUMNS[groupBy] || []).find(c => c.key === key);
        _flowsSort.dir = col && col.type === 'num' ? 'desc' : 'asc';
    }
    updateFlowsTable();
}

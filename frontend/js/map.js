let attackMap = null;
let attackerMarkers = null;
let firewallMarkers = null;
let connectionLines = null;
let shodanMarkers = null;
let _shodanVisible = false;   // optional layer, off by default

const ATTACK_CATEGORIES = [
    {key: 'malware',    label: 'Malware / C2',        color: '#7f1d1d'},
    {key: 'exploit',    label: 'Exploit / IDP',       color: '#dc2626'},
    {key: 'bruteforce', label: 'Brute-Force / Auth',  color: '#e11d48'},
    {key: 'web',        label: 'Web / URL-Filter',    color: '#be185d'},
    {key: 'scan',       label: 'Scan / Recon',        color: '#fb7185'},
    {key: 'fwblock',    label: 'Firewall Drop',       color: '#c2410c'},
    {key: 'm365_fail',  label: 'M365 Login fehlgeschlagen', color: '#f59e0b'},
    {key: 'm365_ok',    label: 'M365 Login OK',       color: '#22c55e'},
    {key: 'other',      label: 'Sonstiger Angriff',   color: '#ef4444'},
];
const ATTACK_COLOR_BY_KEY = Object.fromEntries(
    ATTACK_CATEGORIES.map(c => [c.key, c.color])
);

const ALL_DIRECTIONS = ['inbound', 'outbound', 'mixed', 'unknown'];
const _activeCategories = new Set(ATTACK_CATEGORIES.map(c => c.key));
const _activeDirections = new Set(ALL_DIRECTIONS);
let _lastAttackData = null;
let _legendEl = null;

function initMap() {
    attackMap = L.map('attack-map', {
        center: [30, 10],
        zoom: 2,
        minZoom: 2,
        maxZoom: 12,
        zoomControl: true,
        attributionControl: false,
    });

    // Dark tile layer
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        subdomains: 'abcd',
        maxZoom: 19,
    }).addTo(attackMap);

    attackerMarkers = L.layerGroup().addTo(attackMap);
    firewallMarkers = L.layerGroup().addTo(attackMap);
    connectionLines = L.layerGroup().addTo(attackMap);
    shodanMarkers = L.layerGroup().addTo(attackMap);

    addAttackLegend();
}

function addAttackLegend() {
    const legend = L.control({position: 'bottomright'});
    legend.onAdd = () => {
        const div = L.DomUtil.create('div', 'attack-legend');
        _legendEl = div;
        renderLegend();
        L.DomEvent.disableClickPropagation(div);
        L.DomEvent.disableScrollPropagation(div);
        div.addEventListener('click', onLegendClick);
        return div;
    };
    legend.addTo(attackMap);
}

function renderLegend() {
    if (!_legendEl) return;
    const catItems = ATTACK_CATEGORIES.map(c => {
        const off = _activeCategories.has(c.key) ? '' : ' legend-row-off';
        return `<div class="legend-row legend-clickable${off}" data-cat="${c.key}" title="Klick zum An/Ausschalten">
            <span class="legend-swatch" style="background:${c.color}"></span>
            <span class="legend-label">${c.label}</span>
        </div>`;
    }).join('');
    const dirRows = [
        {key: 'inbound',  cls: 'legend-marker-in',    label: '↓ eingehend (Angreifer → uns)'},
        {key: 'outbound', cls: 'legend-marker-out',   label: '↑ ausgehend (intern → C2)'},
        {key: 'mixed',    cls: 'legend-marker-mixed', label: '⇅ beide Richtungen'},
        {key: 'unknown',  cls: 'legend-marker-unk',   label: '? unbekannt'},
    ].map(d => {
        const off = _activeDirections.has(d.key) ? '' : ' legend-row-off';
        return `<div class="legend-row legend-clickable${off}" data-dir="${d.key}" title="Klick zum An/Ausschalten">
            <span class="legend-marker ${d.cls}"></span>
            <span class="legend-label">${d.label}</span>
        </div>`;
    }).join('');
    const shodanOff = _shodanVisible ? '' : ' legend-row-off';
    _legendEl.innerHTML = `
        <div class="legend-title">Angriffsart</div>${catItems}
        <div class="legend-title legend-title-sub">Richtung</div>${dirRows}
        <div class="legend-title legend-title-sub">Layer</div>
        <div class="legend-row legend-clickable${shodanOff}" data-layer="shodan" title="Shodan-Hosts (Ports/CVEs) ein/ausblenden">
            <span class="legend-swatch" style="background:#a855f7"></span>
            <span class="legend-label">Shodan-Hosts (Ports/CVEs)</span>
        </div>
        <div class="legend-actions">
            <button type="button" class="legend-btn" data-action="all">Alle</button>
            <button type="button" class="legend-btn" data-action="none">Keine</button>
        </div>`;
}

function onLegendClick(ev) {
    const row = ev.target.closest('[data-cat],[data-dir],[data-action],[data-layer]');
    if (!row) return;
    const cat = row.dataset.cat;
    const dir = row.dataset.dir;
    const action = row.dataset.action;
    const layer = row.dataset.layer;
    if (layer === 'shodan') {
        _shodanVisible = !_shodanVisible;
        renderLegend();
        updateShodanLayer();
        return;
    }
    if (cat) {
        if (_activeCategories.has(cat)) _activeCategories.delete(cat);
        else _activeCategories.add(cat);
    } else if (dir) {
        if (_activeDirections.has(dir)) _activeDirections.delete(dir);
        else _activeDirections.add(dir);
    } else if (action === 'all') {
        ATTACK_CATEGORIES.forEach(c => _activeCategories.add(c.key));
        ALL_DIRECTIONS.forEach(d => _activeDirections.add(d));
    } else if (action === 'none') {
        _activeCategories.clear();
        _activeDirections.clear();
    }
    renderLegend();
    renderAttackerLayer();
}

function isAttackVisible(atk) {
    const cat = atk._category || categorizeAttack(atk);
    const dir = atk.direction || 'unknown';
    return _activeCategories.has(cat) && _activeDirections.has(dir);
}

const DIRECTION_LABELS = {
    inbound:  '↓ eingehend',
    outbound: '↑ ausgehend',
    mixed:    '⇅ beide Richtungen',
    unknown:  'unbekannt',
};

function getDirectionStyle(direction) {
    // Returns marker stroke style + line style for a given direction.
    switch (direction) {
        case 'outbound':
            return {weight: 2, dashArray: '3 3', lineDashArray: '2 6', lineWeight: 1.2};
        case 'mixed':
            return {weight: 2.5, dashArray: '6 2', lineDashArray: '6 4 2 4', lineWeight: 1.5};
        case 'inbound':
        case 'unknown':
        default:
            return {weight: 1, dashArray: null, lineDashArray: '4 6', lineWeight: 1};
    }
}

function categorizeAttack(atk) {
    const haystack = [
        ...(atk.log_types || []),
        ...(atk.alert_types || []),
        ...(atk.categories || []),
        ...(atk.threats || []),
        ...(atk.actions || []),
    ].join(' ').toLowerCase();

    const hasAny = (...words) => words.some(w => haystack.includes(w));

    // M365 logins carry explicit category markers from the map API — check
    // them first so 'login' doesn't fall through to the bruteforce bucket.
    if (hasAny('m365_fail', 'o365loginfailed'))
        return 'm365_fail';
    if (hasAny('m365_ok', 'o365loginok'))
        return 'm365_ok';
    if (hasAny('malware', 'anti-virus', 'antivirus', 'sandstorm', 'ransom', 'trojan', 'atp', 'c2', 'command-and-control', 'callback'))
        return 'malware';
    if (hasAny('idp', 'ips', 'intrusion', 'exploit', 'cve', 'vulnerab'))
        return 'exploit';
    if (hasAny('auth', 'login', 'credential', 'brute', 'password', 'failed login', 'ssl vpn', 'user portal'))
        return 'bruteforce';
    if (hasAny('web filter', 'url', 'content filter', 'application filter'))
        return 'web';
    if (hasAny('scan', 'probe', 'recon', 'port sweep'))
        return 'scan';
    if (hasAny('firewall', 'drop', 'deny', 'denied'))
        return 'fwblock';
    return 'other';
}

function getAttackColor(atk) {
    return ATTACK_COLOR_BY_KEY[categorizeAttack(atk)] || ATTACK_COLOR_BY_KEY.other;
}

function getAttackCategoryLabel(key) {
    const c = ATTACK_CATEGORIES.find(c => c.key === key);
    return c ? c.label : 'Sonstiger Angriff';
}

async function updateMap(days) {
    try {
        const resp = await fetch(`/api/map/attacks?days=${days}`);
        const data = await resp.json();
        // Pre-categorize once so filtering is cheap on every toggle.
        data.attackers.forEach(a => { a._category = categorizeAttack(a); });
        _lastAttackData = data;

        firewallMarkers.clearLayers();
        const fwPositions = [];
        data.firewalls.forEach(fw => {
            const marker = L.circleMarker([fw.lat, fw.lon], {
                radius: 10,
                fillColor: '#3b82f6',
                color: '#60a5fa',
                weight: 2,
                opacity: 1,
                fillOpacity: 0.8,
            });
            marker.bindPopup(`
                <strong>${fw.name}</strong><br>
                IP: ${fw.ip || 'n/a'}<br>
                ${fw.city || ''} ${fw.country || ''}
            `);
            firewallMarkers.addLayer(marker);
            fwPositions.push([fw.lat, fw.lon]);
        });
        _lastAttackData._fwPositions = fwPositions;

        renderAttackerLayer();
    } catch (err) {
        console.error('Map update failed:', err);
    }
}

function renderAttackerLayer() {
    if (!_lastAttackData) return;
    attackerMarkers.clearLayers();
    connectionLines.clearLayers();
    const fwPositions = _lastAttackData._fwPositions || [];

    _lastAttackData.attackers.forEach(atk => {
        if (!isAttackVisible(atk)) return;

        const radius = Math.min(3 + Math.log2(atk.count + 1) * 3, 18);
        const color = ATTACK_COLOR_BY_KEY[atk._category];
        const direction = atk.direction || 'unknown';
        const dirStyle = getDirectionStyle(direction);

        const marker = L.circleMarker([atk.lat, atk.lon], {
            radius: radius,
            fillColor: color,
            color: direction === 'mixed' ? '#fef9c3' : color,
            weight: dirStyle.weight,
            dashArray: dirStyle.dashArray,
            opacity: 0.95,
            fillOpacity: 0.65,
        });
        marker.bindPopup(buildAttackPopup(atk), {maxWidth: 360, minWidth: 240});
        attackerMarkers.addLayer(marker);

        if (fwPositions.length > 0) {
            let nearest = fwPositions[0];
            let minDist = Infinity;
            fwPositions.forEach(pos => {
                const d = Math.pow(pos[0] - atk.lat, 2) + Math.pow(pos[1] - atk.lon, 2);
                if (d < minDist) {
                    minDist = d;
                    nearest = pos;
                }
            });
            const line = L.polyline(
                [[atk.lat, atk.lon], nearest],
                {
                    color: color,
                    weight: dirStyle.lineWeight,
                    opacity: direction === 'outbound' ? 0.45 : 0.35,
                    dashArray: dirStyle.lineDashArray,
                }
            );
            connectionLines.addLayer(line);
        }
    });
}

function getSeverityColor(severity) {
    switch (severity) {
        case 'critical': return '#ef4444';
        case 'high': return '#f59e0b';
        case 'medium': return '#3b82f6';
        case 'low': return '#22c55e';
        default: return '#94a3b8';
    }
}

function _popEsc(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function _popTime(iso) {
    if (!iso) return '-';
    const d = new Date(iso);
    return d.toLocaleString('de-DE', {
        day: '2-digit', month: '2-digit', year: '2-digit',
        hour: '2-digit', minute: '2-digit',
    });
}

function _popList(label, arr, max) {
    if (!arr || !arr.length) return '';
    const shown = arr.slice(0, max || 4).map(_popEsc).join(', ');
    const more = arr.length > (max || 4) ? ` <span class="popup-more">+${arr.length - (max || 4)}</span>` : '';
    return `<div class="popup-row"><span class="popup-key">${label}:</span> <span class="popup-val">${shown}${more}</span></div>`;
}

function _popSourceLabel(src) {
    if (src === 'central') return 'Sophos Central';
    if (src === 'firewall') return 'Firewall Syslog';
    if (src === 'both') return 'Central + Firewall';
    return src || '-';
}

function buildAttackPopup(atk) {
    const ip = _popEsc(atk.ip || '-');
    const loc = [atk.city, atk.country].filter(Boolean).map(_popEsc).join(', ') || 'Unbekannt';
    const sev = _popEsc(atk.severity || 'unbekannt');
    const sevColor = getSeverityColor(atk.severity);
    const category = atk._category || categorizeAttack(atk);
    const catColor = ATTACK_COLOR_BY_KEY[category];
    const catLabel = _popEsc(getAttackCategoryLabel(category));
    const blockedBadge = atk.blocked
        ? `<span class="popup-badge popup-blocked" title="geblockt${atk.blocked_at ? ' seit ' + _popTime(atk.blocked_at) : ''}">BLOCKED</span>`
        : '';
    const isPub = (typeof isPublicIpClient === 'function') && isPublicIpClient(atk.ip);
    const blockBtn = (!atk.blocked && isPub)
        ? `<button class="ack-btn" onclick="blockFromCell('${_popEsc(atk.ip)}', 'attack-map: ${_popEsc((atk.threats && atk.threats[0]) || (atk.alert_types && atk.alert_types[0]) || 'attack')}')">Blocken</button>`
        : '';
    const osintBtn = (typeof osintButton === 'function') ? osintButton(atk.ip) : '';

    const asnLine = (atk.asn || atk.org)
        ? `<div class="popup-row"><span class="popup-key">ASN/Org:</span> <span class="popup-val">${_popEsc(atk.asn || '')}${atk.asn && atk.org ? ' · ' : ''}${_popEsc(atk.org || '')}</span></div>`
        : '';

    const direction = atk.direction || 'unknown';
    const dirLabel = _popEsc(DIRECTION_LABELS[direction] || direction);
    const dirCls = `popup-dir popup-dir-${direction}`;

    const lines = [
        `<div class="popup-head">
            <code class="popup-ip">${ip}</code>
            ${blockedBadge}
            ${osintBtn}
        </div>`,
        `<div class="popup-row"><span class="popup-key">Kategorie:</span> <span class="popup-val"><span class="popup-cat-dot" style="background:${catColor}"></span>${catLabel}</span></div>`,
        `<div class="popup-row"><span class="popup-key">Richtung:</span> <span class="popup-val ${dirCls}">${dirLabel}</span></div>`,
        `<div class="popup-row"><span class="popup-key">Standort:</span> <span class="popup-val">${loc}</span></div>`,
        asnLine,
        `<div class="popup-row"><span class="popup-key">Angriffe:</span> <span class="popup-val"><strong>${(atk.count || 0).toLocaleString('de-DE')}</strong></span></div>`,
        `<div class="popup-row"><span class="popup-key">Schwere:</span> <span class="popup-val" style="color:${sevColor}">${sev}</span></div>`,
        `<div class="popup-row"><span class="popup-key">Quelle:</span> <span class="popup-val">${_popEsc(_popSourceLabel(atk.source))}</span></div>`,
        `<div class="popup-row"><span class="popup-key">Erster:</span> <span class="popup-val">${_popTime(atk.first_seen)}</span></div>`,
        `<div class="popup-row"><span class="popup-key">Letzter:</span> <span class="popup-val">${_popTime(atk.last_seen)}</span></div>`,
        _popList('Alert-Typen', atk.alert_types, 4),
        _popList('Kategorien', atk.categories, 4),
        _popList('Threats', atk.threats, 4),
        _popList('Aktionen', atk.actions, 4),
        _popList('Log-Typen', atk.log_types, 4),
        _popList('Ziel-Ports', atk.dest_ports, 8),
        _popList('Ziel-IPs', atk.dest_ips, 4),
        _popList('User', atk.users, 4),
        _popList('Firewalls', atk.firewalls, 3),
    ];
    const actions = blockBtn
        ? `<div class="popup-actions">${blockBtn}</div>`
        : '';
    return `<div class="map-popup">${lines.filter(Boolean).join('')}${actions}</div>`;
}

// ── Shodan host layer (optional) ──────────────────────────────────────────
// Long-term Shodan intel (open ports + known CVEs) harvested via OSINT lookups.
// Colour scales with CVE count; radius with the exposed port count.

function _shodanColor(cveCount) {
    if (cveCount >= 20) return '#dc2626';   // red    — heavily vulnerable
    if (cveCount >= 6)  return '#f97316';   // orange
    if (cveCount >= 1)  return '#eab308';   // yellow
    return '#a855f7';                        // purple — exposed ports, no known CVE
}

async function updateShodanLayer() {
    if (!shodanMarkers) return;
    if (!_shodanVisible) {
        shodanMarkers.clearLayers();
        return;
    }
    try {
        const resp = await fetch('/api/shodan/hosts?days=365');
        const data = await resp.json();
        shodanMarkers.clearLayers();
        (data.hosts || []).forEach(h => {
            if (h.lat == null || h.lon == null) return;
            const color = _shodanColor(h.cve_count);
            const radius = Math.min(4 + Math.log2((h.port_count || 0) + 1) * 2.2, 16);
            const marker = L.circleMarker([h.lat, h.lon], {
                radius,
                fillColor: color,
                color: color,
                weight: 1.5,
                opacity: 0.9,
                fillOpacity: 0.55,
                dashArray: h.cve_count ? null : '2 3',
            });
            marker.bindPopup(buildShodanPopup(h), {maxWidth: 360, minWidth: 240});
            shodanMarkers.addLayer(marker);
        });
    } catch (err) {
        console.error('Shodan layer update failed:', err);
    }
}

function buildShodanPopup(h) {
    const ports = (h.ports || []).slice(0, 24).join(', ');
    const cves = (h.vulns || []).slice(0, 12);
    const cveLinks = cves.map(c =>
        `<a href="https://nvd.nist.gov/vuln/detail/${_popEsc(c)}" target="_blank" rel="noopener">${_popEsc(c)}</a>`
    ).join(', ');
    const moreCve = h.cve_count > cves.length ? ` … (+${h.cve_count - cves.length})` : '';
    const loc = [h.city, h.country].filter(Boolean).join(', ');
    const lines = [
        `<div class="popup-title">🛰️ ${_popEsc(h.ip)}</div>`,
        loc ? `<div class="popup-row">${_popEsc(loc)}</div>` : '',
        h.org ? `<div class="popup-row"><span>Org</span> ${_popEsc(h.org)}</div>` : '',
        h.os ? `<div class="popup-row"><span>OS</span> ${_popEsc(h.os)}</div>` : '',
        `<div class="popup-row"><span>Ports (${h.port_count})</span> ${_popEsc(ports) || '—'}</div>`,
        h.cve_count
            ? `<div class="popup-row"><span>CVEs (${h.cve_count})</span> ${cveLinks}${moreCve}</div>`
            : `<div class="popup-row"><span>CVEs</span> keine bekannt</div>`,
        h.last_seen ? `<div class="popup-row"><span>Gesehen</span> ${_popTime(h.last_seen)}</div>` : '',
    ];
    const actions = `<div class="popup-actions">
        <a class="block-link" href="https://www.shodan.io/host/${_popEsc(h.ip)}" target="_blank" rel="noopener">Shodan ↗</a>
        ${typeof osintButton === 'function' ? osintButton(h.ip, 'block-link', 'ip') : ''}
    </div>`;
    return `<div class="map-popup">${lines.filter(Boolean).join('')}${actions}</div>`;
}

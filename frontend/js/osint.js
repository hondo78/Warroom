// OSINT helpers — shared between dashboard and netflow page.
// Provides showOsint(ip), closeOsint(), reloadOsint(), and the osintButton(ip) snippet.

let _osintCurrentIp = null;

function _osintEscape(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function _osintIsPublic(ip) {
    if (!ip || typeof ip !== 'string') return false;
    if (ip.includes(':')) return !(ip === '::1' || ip.startsWith('fe80:') || ip.startsWith('fc') || ip.startsWith('fd'));
    const m = ip.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
    if (!m) return false;
    const a = +m[1], b = +m[2];
    if (a === 10 || a === 127 || a === 0) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 169 && b === 254) return false;
    if (a >= 224) return false;  // multicast/reserved
    return true;
}

function osintButton(ip, classes = 'osint-btn') {
    if (!ip || !_osintIsPublic(ip)) return '';
    return ` <button class="${classes}" title="OSINT-Check für ${_osintEscape(ip)}" onclick="event.stopPropagation();showOsint('${ip}')">🔍</button>`;
}

async function showOsint(ip) {
    _osintCurrentIp = ip;
    const modal = document.getElementById('osintModal');
    const body = document.getElementById('osintModalBody');
    const titleEl = document.getElementById('osintModalTitle');
    if (!modal || !body) {
        console.error('OSINT modal not present in DOM');
        return;
    }
    if (titleEl) titleEl.textContent = `OSINT-Check für ${ip}`;
    body.innerHTML = '<div class="osint-loading">Quellen werden parallel abgefragt — 5–10 Sekunden bei nicht gecachten IPs…</div>';
    modal.classList.add('active');
    await _osintRun(ip, false);
}

async function reloadOsint() {
    if (_osintCurrentIp) {
        document.getElementById('osintModalBody').innerHTML = '<div class="osint-loading">Cache umgangen, frische Anfrage läuft…</div>';
        await _osintRun(_osintCurrentIp, true);
    }
}

function closeOsint() {
    document.getElementById('osintModal').classList.remove('active');
    _osintCurrentIp = null;
}

async function _osintRun(ip, force) {
    const body = document.getElementById('osintModalBody');
    try {
        const url = `/api/osint/${encodeURIComponent(ip)}${force ? '?force=true' : ''}`;
        const r = await fetch(url);
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const d = await r.json();
        body.innerHTML = _osintRender(d);
    } catch (err) {
        body.innerHTML = `<div class="detail-error">Fehler: ${_osintEscape(err.message)}</div>`;
    }
}

function _osintRender(d) {
    if (d.error) return `<div class="detail-error">${_osintEscape(d.error)}</div>`;
    const sections = [
        ['Sophos Intelix', _osintRenderIntelix(d.intelix)],
        ['AbuseIPDB', _osintRenderAbuse(d.abuseipdb)],
        ['VirusTotal', _osintRenderVT(d.virustotal)],
        ['Shodan', _osintRenderShodan(d.shodan)],
        ['GreyNoise', _osintRenderGN(d.greynoise)],
        ['ipinfo.io', _osintRenderIpInfo(d.ipinfo)],
    ];
    const cards = sections.map(([title, content]) => `
        <div class="osint-card">
            <h4>${_osintEscape(title)}</h4>
            ${content}
        </div>
    `).join('');
    const cacheNote = d.cached
        ? '<div class="osint-cache-note">Daten aus dem 1h-Cache (Knopf „Neu prüfen" für Live-Abfrage)</div>'
        : '';
    return cacheNote + `<div class="osint-grid">${cards}</div>`;
}

function _osintHead(p) {
    if (!p) return '<div class="osint-na">keine Daten</div>';
    if (p.available === false) return `<div class="osint-na">nicht verfügbar (${_osintEscape(p.reason || 'unbekannt')})</div>`;
    return null;
}

function _osintLink(url, label) {
    if (!url) return '';
    return `<a class="osint-link" href="${_osintEscape(url)}" target="_blank" rel="noopener">${_osintEscape(label)} ↗</a>`;
}

function _osintRow(label, value) {
    if (value === null || value === undefined || value === '') return '';
    return `<dt>${_osintEscape(label)}</dt><dd>${value}</dd>`;
}

function _osintRenderAbuse(p) {
    const head = _osintHead(p); if (head !== null) return head;
    const score = p.abuse_score ?? 0;
    const sev = score >= 75 ? 'osint-bad' : score >= 25 ? 'osint-warn' : 'osint-ok';
    return `
        <dl class="detail-grid osint-dl">
            ${_osintRow('Confidence', `<span class="osint-score ${sev}">${score}/100</span>`)}
            ${_osintRow('Reports gesamt', _osintEscape(String(p.total_reports ?? 0)))}
            ${_osintRow('Distinct Reporter', _osintEscape(String(p.distinct_users ?? 0)))}
            ${_osintRow('Letzte Meldung', _osintEscape(p.last_reported || '-'))}
            ${_osintRow('ISP', _osintEscape(p.isp || ''))}
            ${_osintRow('Domain', _osintEscape(p.domain || ''))}
            ${_osintRow('Usage', _osintEscape(p.usage_type || ''))}
            ${_osintRow('Whitelist', p.is_whitelisted === true ? 'ja' : p.is_whitelisted === false ? 'nein' : '')}
        </dl>
        ${_osintLink(p.url, 'AbuseIPDB öffnen')}
    `;
}

function _osintRenderVT(p) {
    const head = _osintHead(p); if (head !== null) return head;
    const mal = p.malicious ?? 0, sus = p.suspicious ?? 0;
    const cls = mal > 0 ? 'osint-bad' : sus > 0 ? 'osint-warn' : 'osint-ok';
    const tags = (p.tags || []).map(t => `<span class="osint-tag">${_osintEscape(t)}</span>`).join(' ');
    return `
        <dl class="detail-grid osint-dl">
            ${_osintRow('Verdict', `<span class="osint-score ${cls}">${mal} bösartig / ${sus} verdächtig</span>`)}
            ${_osintRow('Harmless', _osintEscape(String(p.harmless ?? 0)))}
            ${_osintRow('Undetected', _osintEscape(String(p.undetected ?? 0)))}
            ${_osintRow('Reputation', p.reputation != null ? _osintEscape(String(p.reputation)) : '')}
            ${_osintRow('AS Owner', _osintEscape(p.as_owner || ''))}
            ${_osintRow('ASN', p.asn != null ? _osintEscape(String(p.asn)) : '')}
            ${_osintRow('Country', _osintEscape(p.country || ''))}
            ${tags ? _osintRow('Tags', tags) : ''}
        </dl>
        ${_osintLink(p.url, 'VirusTotal öffnen')}
    `;
}

function _osintRenderShodan(p) {
    const head = _osintHead(p); if (head !== null) return head;
    if (p.no_record) return `<div class="osint-na">kein Eintrag bei Shodan</div>${_osintLink(p.url, 'Shodan-Suche öffnen')}`;
    const ports = (p.ports || []).slice(0, 30).map(pt => `<span class="osint-tag">${pt}</span>`).join(' ');
    const vulns = (p.vulns || []).slice(0, 30).map(v => `<span class="osint-tag osint-vuln">${_osintEscape(v)}</span>`).join(' ');
    const tags = (p.tags || []).map(t => `<span class="osint-tag">${_osintEscape(t)}</span>`).join(' ');
    return `
        <dl class="detail-grid osint-dl">
            ${_osintRow('Org', _osintEscape(p.org || ''))}
            ${_osintRow('ASN', _osintEscape(p.asn || ''))}
            ${_osintRow('Land/Stadt', _osintEscape([p.country, p.city].filter(Boolean).join(', ')))}
            ${_osintRow('OS', _osintEscape(p.os || ''))}
            ${ports ? _osintRow('Offene Ports', ports) : ''}
            ${vulns ? _osintRow('Vulns', vulns) : ''}
            ${tags ? _osintRow('Tags', tags) : ''}
            ${_osintRow('Hostnames', _osintEscape((p.hostnames || []).slice(0, 5).join(', ')))}
            ${_osintRow('Stand', _osintEscape(p.last_update || ''))}
        </dl>
        ${_osintLink(p.url, 'Shodan öffnen')}
    `;
}

function _osintRenderGN(p) {
    const head = _osintHead(p); if (head !== null) return head;
    if (p.classification === 'unobserved' || p.noise === false) {
        return `<div class="osint-na">Nicht im GreyNoise-Datensatz (kein Internet-Scan-Noise von dieser IP)</div>`;
    }
    const cls = p.classification === 'malicious' ? 'osint-bad' : p.classification === 'benign' ? 'osint-ok' : 'osint-warn';
    return `
        <dl class="detail-grid osint-dl">
            ${_osintRow('Klassifikation', `<span class="osint-score ${cls}">${_osintEscape(p.classification || 'unknown')}</span>`)}
            ${_osintRow('Name', _osintEscape(p.name || ''))}
            ${_osintRow('Letzte Sichtung', _osintEscape(p.last_seen || ''))}
        </dl>
        ${_osintLink(p.url, 'GreyNoise öffnen')}
    `;
}

function _osintAsString(value) {
    if (value === null || value === undefined) return '';
    if (typeof value === 'string') return value;
    if (Array.isArray(value)) return value.map(_osintAsString).filter(Boolean).join(', ');
    if (typeof value === 'object') return value.name || value.description || JSON.stringify(value);
    return String(value);
}

function _osintRenderIntelix(p) {
    const head = _osintHead(p); if (head !== null) return head;
    if (p.no_record) return `<div class="osint-na">Kein Intelix-Eintrag für diese IP</div>`;

    const category = _osintAsString(p.category);
    const description = _osintAsString(p.category_description);
    const productivity = _osintAsString(p.productivity_category);
    const security = _osintAsString(p.security_category);

    let score = p.score;
    if (typeof score !== 'number') score = parseInt(score, 10);
    const scoreCls = !isFinite(score) ? 'osint-warn'
        : score >= 70 ? 'osint-bad'
        : score >= 30 ? 'osint-warn'
        : 'osint-ok';

    const catLower = category.toLowerCase();
    let catCls = 'osint-warn';
    if (/malicious|phishing|spam|botnet|c2|malware/i.test(catLower)) catCls = 'osint-bad';
    else if (catLower && catLower !== 'uncategorized' && catLower !== 'unknown') catCls = 'osint-ok';

    return `
        <dl class="detail-grid osint-dl">
            ${_osintRow('Kategorie', category ? `<span class="osint-score ${catCls}">${_osintEscape(category)}</span>` : '')}
            ${_osintRow('Beschreibung', _osintEscape(description))}
            ${_osintRow('Productivity', _osintEscape(productivity))}
            ${_osintRow('Security', _osintEscape(security))}
            ${_osintRow('Score', isFinite(score) ? `<span class="osint-score ${scoreCls}">${score}</span>` : '')}
        </dl>
    `;
}

function _osintRenderIpInfo(p) {
    const head = _osintHead(p); if (head !== null) return head;
    return `
        <dl class="detail-grid osint-dl">
            ${_osintRow('Hostname', _osintEscape(p.hostname || ''))}
            ${_osintRow('Ort', _osintEscape([p.city, p.region, p.country].filter(Boolean).join(', ')))}
            ${_osintRow('Org', _osintEscape(p.org || ''))}
            ${_osintRow('Loc', _osintEscape(p.loc || ''))}
            ${_osintRow('Postal', _osintEscape(p.postal || ''))}
            ${_osintRow('Timezone', _osintEscape(p.timezone || ''))}
        </dl>
        ${_osintLink(p.url, 'ipinfo.io öffnen')}
    `;
}

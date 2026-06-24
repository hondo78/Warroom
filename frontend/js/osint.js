// OSINT helpers — shared between dashboard, netflow and blocklist page.
// Provides showOsint(value, type), closeOsint(), reloadOsint(), and an
// osintButton(value, classes, type) helper. `type` is 'ip' (default),
// 'domain' or 'url'.

let _osintCurrent = { value: null, type: 'ip' };

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

function osintButton(value, classes = 'osint-btn', type = 'ip') {
    if (!value) return '';
    if (type === 'ip' && !_osintIsPublic(value)) return '';
    if (type === 'domain' && !_osintLooksLikeDomain(value)) return '';
    if (type === 'url' && !_osintLooksLikeUrl(value)) return '';
    const safe = _osintEscape(value);
    const label = { ip: 'IP', domain: 'Domain', url: 'URL' }[type] || 'IP';
    // JSON.stringify wraps the value in double quotes; those would otherwise
    // terminate the surrounding onclick="..." attribute. HTML-escape so the
    // browser decodes &quot; back to " before the JS parser sees it.
    const arg = _osintEscape(JSON.stringify(value));
    return ` <button class="${classes}" title="OSINT-Check für ${label} ${safe}" onclick="event.stopPropagation();showOsint(${arg}, '${type}')">🔍</button>`;
}

function _osintLooksLikeDomain(v) {
    if (typeof v !== 'string') return false;
    const host = v.startsWith('*.') ? v.slice(2) : v;
    return /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(host);
}

function _osintLooksLikeUrl(v) {
    if (typeof v !== 'string') return false;
    return /^https?:\/\//i.test(v);
}

async function showOsint(value, type = 'ip') {
    _osintCurrent = { value, type };
    const modal = document.getElementById('osintModal');
    const body = document.getElementById('osintModalBody');
    const titleEl = document.getElementById('osintModalTitle');
    if (!modal || !body) {
        console.error('OSINT modal not present in DOM');
        return;
    }
    _ensureTriageButton(modal);
    const label = { ip: 'IP', domain: 'Domain', url: 'URL' }[type] || 'IP';
    if (titleEl) titleEl.textContent = `OSINT-Check für ${label}: ${value}`;
    body.innerHTML = '<div class="osint-loading">Quellen werden parallel abgefragt — 5–10 Sekunden bei nicht gecachten Einträgen…</div>';
    modal.classList.add('active');
    await _osintRun(value, type, false);
}

// Inject the AI-triage action into the shared modal once per page — keeps the
// static modal markup in the HTML files unchanged.
function _ensureTriageButton(modal) {
    if (modal.querySelector('#osintTriageBtn')) return;
    const actions = modal.querySelector('.modal-actions');
    if (!actions) return;
    const btn = document.createElement('button');
    btn.id = 'osintTriageBtn';
    btn.innerHTML = '🤖 An KI-Triage übergeben';
    btn.onclick = triageFromOsint;
    actions.insertBefore(btn, actions.firstChild);
}

function _osintTriageMsg(html, kind) {
    const body = document.getElementById('osintModalBody');
    if (!body) return;
    let box = document.getElementById('osintTriageMsg');
    if (!box) {
        box = document.createElement('div');
        box.id = 'osintTriageMsg';
        body.prepend(box);
    }
    box.className = `alert alert-${kind} mb-3`;
    box.innerHTML = html;
}

async function triageFromOsint() {
    const { value, type } = _osintCurrent;
    if (!value) return;
    const note = prompt('Optionaler Hinweis für den KI-Agenten (Kontext):', '') || null;
    const btn = document.getElementById('osintTriageBtn');
    if (btn) btn.disabled = true;
    _osintTriageMsg('<i class="bi bi-robot"></i> KI-Triage läuft — der Agent prüft den Wert (kann einige Sekunden dauern)…', 'info');
    try {
        const r = await fetch('/api/agent/triage', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ value, type, note }),
        });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
        const conf = Math.round((d.confidence || 0) * 100);
        const acted = d.action && d.action !== 'no_action';
        _osintTriageMsg(
            `<i class="bi bi-robot"></i> KI-Entscheidung: <strong>${_osintEscape(d.action || '?')}</strong> (${conf}% Konfidenz)` +
            `${d.reasoning ? '<br><small>' + _osintEscape(d.reasoning) + '</small>' : ''}` +
            `<br><a href="/agent.html" class="alert-link">Decision #${d.decision_id} im Agent-Log ansehen ↗</a>`,
            acted ? 'warning' : 'secondary'
        );
    } catch (err) {
        _osintTriageMsg(`KI-Triage fehlgeschlagen: ${_osintEscape(err.message)}`, 'danger');
    } finally {
        if (btn) btn.disabled = false;
    }
}

async function reloadOsint() {
    if (_osintCurrent.value) {
        document.getElementById('osintModalBody').innerHTML = '<div class="osint-loading">Cache umgangen, frische Anfrage läuft…</div>';
        await _osintRun(_osintCurrent.value, _osintCurrent.type, true);
    }
}

function closeOsint() {
    document.getElementById('osintModal').classList.remove('active');
    _osintCurrent = { value: null, type: 'ip' };
}

// Human-triggered Shodan lookup — the only way Shodan runs for a person.
async function shodanLookup() {
    const ip = _osintCurrent.value;
    if (!ip || _osintCurrent.type !== 'ip') return;
    const card = document.getElementById('osintShodanCard');
    const btn = card ? card.querySelector('.osint-shodan-btn') : null;
    if (btn) { btn.disabled = true; btn.textContent = '🛰️ Shodan wird abgefragt…'; }
    try {
        const r = await fetch(`/api/osint/shodan/${encodeURIComponent(ip)}`, { method: 'POST' });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const s = await r.json();
        if (card) card.innerHTML = _osintRenderShodanBody(s);
    } catch (err) {
        if (card) card.innerHTML = `<div class="detail-error">Shodan-Abfrage fehlgeschlagen: ${_osintEscape(err.message)}</div>`;
    }
}

async function _osintRun(value, type, force) {
    const body = document.getElementById('osintModalBody');
    try {
        let url;
        if (type === 'domain') {
            url = `/api/osint/domain/${encodeURIComponent(value)}`;
        } else if (type === 'url') {
            url = `/api/osint/url?u=${encodeURIComponent(value)}`;
        } else {
            url = `/api/osint/${encodeURIComponent(value)}`;
        }
        if (force) url += (url.includes('?') ? '&' : '?') + 'force=true';
        const r = await fetch(url);
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const d = await r.json();
        body.innerHTML = _osintRender(d, type);
        if (type === 'ip') _osintLoadConnections(value);
    } catch (err) {
        body.innerHTML = `<div class="detail-error">Fehler: ${_osintEscape(err.message)}</div>`;
    }
}

function _osintRender(d, type) {
    if (d.error) return `<div class="detail-error">${_osintEscape(d.error)}</div>`;
    let sections;
    if (type === 'domain') {
        sections = [
            ['Sophos Intelix', _osintRenderIntelixUrl(d.intelix)],
            ['VirusTotal (Domain)', _osintRenderVTDomain(d.virustotal)],
            ['DNS-Auflösung', _osintRenderDns(d.dns)],
        ];
    } else if (type === 'url') {
        sections = [
            ['Sophos Intelix', _osintRenderIntelixUrl(d.intelix)],
            ['VirusTotal (URL)', _osintRenderVTUrl(d.virustotal)],
        ];
    } else {
        sections = [
            ['Sophos Intelix', _osintRenderIntelix(d.intelix)],
            ['AbuseIPDB', _osintRenderAbuse(d.abuseipdb)],
            ['VirusTotal', _osintRenderVT(d.virustotal)],
            ['Shodan', _osintRenderShodan(d.shodan)],
            ['GreyNoise', _osintRenderGN(d.greynoise)],
            ['ipinfo.io', _osintRenderIpInfo(d.ipinfo)],
        ];
    }
    const cards = sections.map(([title, content]) => `
        <div class="osint-card">
            <h4>${_osintEscape(title)}</h4>
            ${content}
        </div>
    `).join('');
    const cacheNote = d.cached
        ? '<div class="osint-cache-note">Daten aus dem 1h-Cache (Knopf „Neu prüfen" für Live-Abfrage)</div>'
        : '';
    // Connection history (NetFlow) is loaded asynchronously for IPs only.
    const conn = type === 'ip'
        ? '<div id="osintConnections" style="margin-top:1rem"><div class="osint-loading">Bekannte Verbindungen werden geladen…</div></div>'
        : '';
    return cacheNote + `<div class="osint-grid">${cards}</div>` + conn;
}

// --- Connection history (from/to the IP, via NetFlow) ---------------------------

async function _osintLoadConnections(ip) {
    const el = document.getElementById('osintConnections');
    if (!el) return;
    try {
        const r = await fetch(`/api/ip/${encodeURIComponent(ip)}/connections?days=30&limit=100`);
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const d = await r.json();
        el.innerHTML = _osintRenderConnections(d);
    } catch (err) {
        el.innerHTML = `<div class="detail-error">Verbindungen konnten nicht geladen werden: ${_osintEscape(err.message)}</div>`;
    }
}

function _osintProtoName(p) {
    return ({ 1: 'ICMP', 6: 'TCP', 17: 'UDP', 47: 'GRE', 50: 'ESP', 58: 'ICMPv6' })[p] || (p != null ? 'proto ' + p : '—');
}

function _osintFmtBytes(b) {
    b = Number(b) || 0;
    const u = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    let i = 0;
    while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
    return `${b.toFixed(b >= 100 || i === 0 ? 0 : 1)} ${u[i]}`;
}

function _osintFmtTs(iso) {
    if (!iso) return '—';
    try { return new Date(iso).toLocaleString('de-DE', { day: '2-digit', month: '2-digit', year: '2-digit', hour: '2-digit', minute: '2-digit' }); }
    catch (e) { return '—'; }
}

function _osintConnTable(side, label, arrow) {
    const c = (side && side.connections) || [];
    if (!c.length) return `<div class="osint-conn-head">${arrow} ${label}: <span class="osint-na">keine Verbindungen</span></div>`;
    const rows = c.map(x => `<tr>
        <td><code style="font-size:.8rem">${_osintEscape(x.peer || '')}</code>${x.country ? ` <span class="ip-country" style="font-size:.7rem">${_osintEscape(x.country)}</span>` : ''}</td>
        <td>${x.port != null ? x.port : '—'}</td>
        <td>${_osintEscape(_osintProtoName(x.protocol))}</td>
        <td style="text-align:right">${_osintFmtBytes(x.bytes)}</td>
        <td style="text-align:right">${(x.flows || 0).toLocaleString('de-DE')}</td>
        <td style="white-space:nowrap">${_osintFmtTs(x.last_seen)}</td>
    </tr>`).join('');
    const ge = side.truncated ? '≥ ' : '';
    const trunc = side.truncated ? ` · Top ${c.length}` : '';
    return `
        <div class="osint-conn-head" style="margin:.6rem 0 .3rem">
            ${arrow} <strong>${label}</strong>: ${ge}${(side.peers || 0).toLocaleString('de-DE')} Peers ·
            ${ge}${_osintFmtBytes(side.bytes)} · ${ge}${(side.flows || 0).toLocaleString('de-DE')} Flows${trunc}
        </div>
        <div class="table-scroll" style="max-height:240px">
            <table class="table table-sm table-hover align-middle" style="margin:0">
                <thead><tr><th>Peer</th><th>Port</th><th>Proto</th><th style="text-align:right">Bytes</th><th style="text-align:right">Flows</th><th>Zuletzt</th></tr></thead>
                <tbody>${rows}</tbody>
            </table>
        </div>`;
}

function _osintFwTable(side, label, arrow) {
    const c = (side && side.connections) || [];
    if (!c.length) return `<div class="osint-conn-head" style="margin:.6rem 0 .3rem">${arrow} <strong>${label}</strong>: <span class="osint-na">keine</span></div>`;
    const rows = c.map(x => `<tr>
        <td><code style="font-size:.8rem">${_osintEscape(x.peer || '')}</code>${x.country ? ` <span class="ip-country" style="font-size:.7rem">${_osintEscape(x.country)}</span>` : ''}</td>
        <td>${x.port != null ? x.port : '—'}</td>
        <td>${_osintEscape(x.protocol || '—')}</td>
        <td><span class="badge text-bg-danger" style="font-size:.66rem">${_osintEscape(x.action || 'deny')}</span></td>
        <td style="text-align:right">${(x.events || 0).toLocaleString('de-DE')}</td>
        <td style="white-space:nowrap">${_osintFmtTs(x.last_seen)}</td>
    </tr>`).join('');
    const trunc = side.truncated ? ` · Top ${c.length}` : '';
    return `
        <div class="osint-conn-head" style="margin:.6rem 0 .3rem">
            ${arrow} <strong>${label}</strong>: ${(side.peers || 0).toLocaleString('de-DE')} Peers ·
            ${(side.events || 0).toLocaleString('de-DE')} Versuche${trunc}
        </div>
        <div class="table-scroll" style="max-height:240px">
            <table class="table table-sm table-hover align-middle" style="margin:0">
                <thead><tr><th>Peer</th><th>Port</th><th>Proto</th><th>Action</th><th style="text-align:right">Versuche</th><th>Zuletzt</th></tr></thead>
                <tbody>${rows}</tbody>
            </table>
        </div>`;
}

function _osintRenderConnections(d) {
    const nfBody = (d.netflow_available === false)
        ? `<div class="osint-na">${_osintEscape(d.netflow_reason || 'nicht verfügbar')}</div>`
        : `${_osintConnTable(d.outbound, 'Ausgehend (IP → Ziel)', '↗')}
           ${_osintConnTable(d.inbound, 'Eingehend (Quelle → IP)', '↘')}`;
    const netflowCard = `<div class="osint-card osint-conn-card">
        <h4>Bekannte Verbindungen <span class="text-secondary" style="font-size:.8rem">(NetFlow, letzte ${d.days} Tage)</span></h4>
        ${nfBody}
    </div>`;
    const fb = d.firewall_blocked || {};
    let fwCard = '';
    if (fb.available === false) {
        fwCard = `<div class="osint-card osint-conn-card" style="margin-top:1rem">
            <h4>Firewall: geblockte/abgelehnte Versuche</h4>
            <div class="osint-na">${_osintEscape(fb.reason || 'nicht verfügbar')}</div>
        </div>`;
    } else {
        const hasFw = ((fb.outbound && fb.outbound.connections && fb.outbound.connections.length) ||
                       (fb.inbound && fb.inbound.connections && fb.inbound.connections.length));
        if (hasFw) fwCard = `<div class="osint-card osint-conn-card" style="margin-top:1rem">
            <h4>Firewall: geblockte/abgelehnte Versuche <span class="text-secondary" style="font-size:.8rem">(letzte ${d.days} Tage)</span></h4>
            ${_osintFwTable(fb.outbound, 'Ausgehend (IP → Ziel)', '↗')}
            ${_osintFwTable(fb.inbound, 'Eingehend (Quelle → IP)', '↘')}
        </div>`;
    }
    return netflowCard + fwCard;
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
    // Shodan is opt-in: the skipped sentinel renders a button instead of data,
    // so opening the panel never spends a Shodan credit.
    if (p && p.skipped) {
        return `<div id="osintShodanCard">
            <div class="osint-na">Wird nur auf Anfrage abgefragt — verbraucht ein Shodan-Credit.</div>
            <button class="osint-shodan-btn" onclick="shodanLookup()">🛰️ Shodan abfragen</button>
        </div>`;
    }
    return `<div id="osintShodanCard">${_osintRenderShodanBody(p)}</div>`;
}

function _osintRenderShodanBody(p) {
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

function _osintRenderVTDomain(p) {
    const head = _osintHead(p); if (head !== null) return head;
    const mal = p.malicious ?? 0, sus = p.suspicious ?? 0;
    const cls = mal > 0 ? 'osint-bad' : sus > 0 ? 'osint-warn' : 'osint-ok';
    const tags = (p.tags || []).map(t => `<span class="osint-tag">${_osintEscape(t)}</span>`).join(' ');
    const cats = p.categories && typeof p.categories === 'object'
        ? Object.entries(p.categories).slice(0, 8)
            .map(([engine, cat]) => `<span class="osint-tag">${_osintEscape(cat)} <em>(${_osintEscape(engine)})</em></span>`).join(' ')
        : '';
    const createdAt = p.creation_date
        ? new Date(p.creation_date * 1000).toLocaleDateString('de-DE')
        : '';
    return `
        <dl class="detail-grid osint-dl">
            ${_osintRow('Verdict', `<span class="osint-score ${cls}">${mal} bösartig / ${sus} verdächtig</span>`)}
            ${_osintRow('Harmless', _osintEscape(String(p.harmless ?? 0)))}
            ${_osintRow('Undetected', _osintEscape(String(p.undetected ?? 0)))}
            ${_osintRow('Reputation', p.reputation != null ? _osintEscape(String(p.reputation)) : '')}
            ${_osintRow('Registrar', _osintEscape(p.registrar || ''))}
            ${_osintRow('Registriert', _osintEscape(createdAt))}
            ${tags ? _osintRow('Tags', tags) : ''}
            ${cats ? _osintRow('Kategorien', cats) : ''}
        </dl>
        ${_osintLink(p.url, 'VirusTotal öffnen')}
    `;
}

function _osintRenderVTUrl(p) {
    const head = _osintHead(p); if (head !== null) return head;
    if (p.no_record) return `<div class="osint-na">Bei VirusTotal nicht bekannt</div>${_osintLink(p.url, 'VT-Suche öffnen')}`;
    const mal = p.malicious ?? 0, sus = p.suspicious ?? 0;
    const cls = mal > 0 ? 'osint-bad' : sus > 0 ? 'osint-warn' : 'osint-ok';
    const tags = (p.tags || []).map(t => `<span class="osint-tag">${_osintEscape(t)}</span>`).join(' ');
    const cats = p.categories && typeof p.categories === 'object'
        ? Object.entries(p.categories).slice(0, 8)
            .map(([engine, cat]) => `<span class="osint-tag">${_osintEscape(cat)} <em>(${_osintEscape(engine)})</em></span>`).join(' ')
        : '';
    return `
        <dl class="detail-grid osint-dl">
            ${_osintRow('Verdict', `<span class="osint-score ${cls}">${mal} bösartig / ${sus} verdächtig</span>`)}
            ${_osintRow('Harmless', _osintEscape(String(p.harmless ?? 0)))}
            ${_osintRow('Undetected', _osintEscape(String(p.undetected ?? 0)))}
            ${_osintRow('Reputation', p.reputation != null ? _osintEscape(String(p.reputation)) : '')}
            ${_osintRow('Title', _osintEscape(p.title || ''))}
            ${_osintRow('Final URL', _osintEscape(p.final_url || ''))}
            ${_osintRow('HTTP-Status', p.http_status != null ? _osintEscape(String(p.http_status)) : '')}
            ${tags ? _osintRow('Tags', tags) : ''}
            ${cats ? _osintRow('Kategorien', cats) : ''}
        </dl>
        ${_osintLink(p.url, 'VirusTotal öffnen')}
    `;
}

function _osintRenderIntelixUrl(p) {
    const head = _osintHead(p); if (head !== null) return head;
    if (p.no_record) return `<div class="osint-na">Kein Intelix-Eintrag</div>`;

    const category = _osintAsString(p.category);
    const description = _osintAsString(p.category_description);
    const productivity = _osintAsString(p.productivity_category);
    const security = _osintAsString(p.security_category);
    const risk = _osintAsString(p.risk_level);

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
            ${_osintRow('Risiko', _osintEscape(risk))}
            ${_osintRow('Score', isFinite(score) ? `<span class="osint-score ${scoreCls}">${score}</span>` : '')}
        </dl>
    `;
}

function _osintRenderDns(p) {
    const head = _osintHead(p); if (head !== null) return head;
    if (p.resolves === false) {
        return `<div class="osint-na">Löst aktuell nicht auf (${_osintEscape(p.reason || 'NXDOMAIN')})</div>`;
    }
    const ip4 = (p.ipv4 || []).map(ip =>
        `<span class="osint-tag">${_osintEscape(ip)}</span>${osintButton(ip, 'osint-btn')}`
    ).join(' ');
    const ip6 = (p.ipv6 || []).map(ip => `<span class="osint-tag">${_osintEscape(ip)}</span>`).join(' ');
    return `
        <dl class="detail-grid osint-dl">
            ${ip4 ? _osintRow('A-Records (IPv4)', ip4) : ''}
            ${ip6 ? _osintRow('AAAA-Records (IPv6)', ip6) : ''}
            ${!ip4 && !ip6 ? _osintRow('Status', '<span class="osint-na">keine A/AAAA-Records</span>') : ''}
        </dl>
    `;
}

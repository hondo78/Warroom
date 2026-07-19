// Language-aware number/date formatting (en-US unless UI is German).
const OS_LOCALE = (typeof currentLang === 'function' && currentLang() === 'de') ? 'de-DE' : 'en-US';
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
    const btnTitle = _osintEscape(t('osint.btn_title', { label, value }));
    return ` <button class="${classes}" title="${btnTitle}" onclick="event.stopPropagation();showOsint(${arg}, '${type}')">🔍</button>`;
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
    // Watchlist add only makes sense for IPs.
    const wlBtn = modal.querySelector('#osintWatchlistBtn');
    if (wlBtn) wlBtn.style.display = (type === 'ip') ? '' : 'none';
    const label = { ip: 'IP', domain: 'Domain', url: 'URL' }[type] || 'IP';
    if (titleEl) titleEl.textContent = t('osint.modal_title_for', { label, value });
    body.innerHTML = `<div class="osint-loading">${_osintEscape(t('osint.loading_parallel'))}</div>`;
    modal.classList.add('active');
    await _osintRun(value, type, false);
}

// Inject the AI-triage action into the shared modal once per page — keeps the
// static modal markup in the HTML files unchanged.
function _ensureTriageButton(modal) {
    const actions = modal.querySelector('.modal-actions');
    if (!actions) return;
    if (!modal.querySelector('#osintTriageBtn')) {
        const btn = document.createElement('button');
        btn.id = 'osintTriageBtn';
        btn.innerHTML = '🤖 ' + _osintEscape(t('osint.triage_hand_over'));
        btn.onclick = triageFromOsint;
        actions.insertBefore(btn, actions.firstChild);
    }
    if (!modal.querySelector('#osintWatchlistBtn')) {
        const wl = document.createElement('button');
        wl.id = 'osintWatchlistBtn';
        wl.innerHTML = '🔭 ' + _osintEscape(t('osint.add_watchlist'));
        wl.onclick = watchlistFromOsint;
        actions.insertBefore(wl, actions.firstChild);
    }
}

// Put the currently-checked IP on the watchlist, with an optional comment.
async function watchlistFromOsint() {
    const { value, type } = _osintCurrent;
    if (!value || type !== 'ip') return;
    const comment = prompt(t('osint.watchlist_comment_prompt'), '');
    if (comment === null) return;   // cancelled
    const btn = document.getElementById('osintWatchlistBtn');
    if (btn) btn.disabled = true;
    try {
        const r = await fetch('/api/firewall/watchlist', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: value, comment: comment.trim() }),
        });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
        _osintTriageMsg(
            '🔭 ' + _osintEscape(t('osint.watchlist_added', { ip: value })) +
            ` <a href="/monitored.html" class="alert-link">${_osintEscape(t('osint.watchlist_link'))} ↗</a>`,
            'success');
    } catch (err) {
        _osintTriageMsg(`${_osintEscape(t('osint.watchlist_failed'))}: ${_osintEscape(err.message)}`, 'danger');
    } finally {
        if (btn) btn.disabled = false;
    }
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
    const note = prompt(t('osint.triage_note_prompt'), '') || null;
    const btn = document.getElementById('osintTriageBtn');
    if (btn) btn.disabled = true;
    _osintTriageMsg('<i class="bi bi-robot"></i> ' + _osintEscape(t('osint.triage_running')), 'info');
    try {
        const r = await fetch('/api/agent/triage', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ value, type, note }),
        });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
        const acted = d.action && d.action !== 'no_action';
        _osintTriageMsg(
            `<i class="bi bi-robot"></i> ${_osintEscape(t('osint.ai_decision'))}: <strong>${_osintEscape(d.action || '?')}</strong>` +
            `${d.reasoning ? '<br><small>' + _osintEscape(d.reasoning) + '</small>' : ''}` +
            `<br><a href="/agent.html" class="alert-link">${_osintEscape(t('osint.decision_link', { id: d.decision_id }))} ↗</a>`,
            acted ? 'warning' : 'secondary'
        );
    } catch (err) {
        _osintTriageMsg(`${_osintEscape(t('osint.triage_failed'))}: ${_osintEscape(err.message)}`, 'danger');
    } finally {
        if (btn) btn.disabled = false;
    }
}

async function reloadOsint() {
    if (_osintCurrent.value) {
        document.getElementById('osintModalBody').innerHTML = `<div class="osint-loading">${_osintEscape(t('osint.loading_fresh'))}</div>`;
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
    if (btn) { btn.disabled = true; btn.textContent = '🛰️ ' + t('osint.shodan_querying'); }
    try {
        const r = await fetch(`/api/osint/shodan/${encodeURIComponent(ip)}`, { method: 'POST' });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const s = await r.json();
        if (card) card.innerHTML = _osintRenderShodanBody(s);
    } catch (err) {
        if (card) card.innerHTML = `<div class="detail-error">${_osintEscape(t('osint.shodan_failed'))}: ${_osintEscape(err.message)}</div>`;
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
        body.innerHTML = `<div class="detail-error">${_osintEscape(t('osint.error'))}: ${_osintEscape(err.message)}</div>`;
    }
}

function _osintRender(d, type) {
    if (d.error) return `<div class="detail-error">${_osintEscape(d.error)}</div>`;
    let sections;
    if (type === 'domain') {
        sections = [
            ['Sophos Intelix', _osintRenderIntelixUrl(d.intelix)],
            [t('osint.sec_vt_domain'), _osintRenderVTDomain(d.virustotal)],
            [t('osint.sec_dns'), _osintRenderDns(d.dns)],
        ];
    } else if (type === 'url') {
        sections = [
            ['Sophos Intelix', _osintRenderIntelixUrl(d.intelix)],
            [t('osint.sec_vt_url'), _osintRenderVTUrl(d.virustotal)],
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
        ? `<div class="osint-cache-note">${_osintEscape(t('osint.cache_note'))}</div>`
        : '';
    // Connection history (NetFlow) is loaded asynchronously for IPs only.
    const conn = type === 'ip'
        ? `<div id="osintConnections" style="margin-top:1rem"><div class="osint-loading">${_osintEscape(t('osint.conn_loading'))}</div></div>`
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
        el.innerHTML = `<div class="detail-error">${_osintEscape(t('osint.conn_load_failed'))}: ${_osintEscape(err.message)}</div>`;
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
    try { return new Date(iso).toLocaleString(OS_LOCALE, { day: '2-digit', month: '2-digit', year: '2-digit', hour: '2-digit', minute: '2-digit' }); }
    catch (e) { return '—'; }
}

function _osintConnTable(side, label, arrow) {
    const c = (side && side.connections) || [];
    if (!c.length) return `<div class="osint-conn-head">${arrow} ${label}: <span class="osint-na">${_osintEscape(t('osint.no_connections'))}</span></div>`;
    const rows = c.map(x => `<tr>
        <td><code style="font-size:.8rem">${_osintEscape(x.peer || '')}</code>${x.country ? ` <span class="ip-country" style="font-size:.7rem">${_osintEscape(x.country)}</span>` : ''}</td>
        <td>${x.port != null ? x.port : '—'}</td>
        <td>${_osintEscape(_osintProtoName(x.protocol))}</td>
        <td style="text-align:right">${_osintFmtBytes(x.bytes)}</td>
        <td style="text-align:right">${(x.flows || 0).toLocaleString(OS_LOCALE)}</td>
        <td style="white-space:nowrap">${_osintFmtTs(x.last_seen)}</td>
    </tr>`).join('');
    const ge = side.truncated ? '≥ ' : '';
    const trunc = side.truncated ? ` · ${t('osint.top', { n: c.length })}` : '';
    return `
        <div class="osint-conn-head" style="margin:.6rem 0 .3rem">
            ${arrow} <strong>${label}</strong>: ${ge}${(side.peers || 0).toLocaleString(OS_LOCALE)} ${_osintEscape(t('osint.peers'))} ·
            ${ge}${_osintFmtBytes(side.bytes)} · ${ge}${(side.flows || 0).toLocaleString(OS_LOCALE)} ${_osintEscape(t('osint.flows'))}${trunc}
        </div>
        <div class="table-scroll" style="max-height:240px">
            <table class="table table-sm table-hover align-middle" style="margin:0">
                <thead><tr><th>${_osintEscape(t('osint.col_peer'))}</th><th>${_osintEscape(t('osint.col_port'))}</th><th>${_osintEscape(t('osint.col_proto'))}</th><th style="text-align:right">${_osintEscape(t('osint.col_bytes'))}</th><th style="text-align:right">${_osintEscape(t('osint.col_flows'))}</th><th>${_osintEscape(t('osint.col_last'))}</th></tr></thead>
                <tbody>${rows}</tbody>
            </table>
        </div>`;
}

function _osintFwTable(side, label, arrow) {
    const c = (side && side.connections) || [];
    if (!c.length) return `<div class="osint-conn-head" style="margin:.6rem 0 .3rem">${arrow} <strong>${label}</strong>: <span class="osint-na">${_osintEscape(t('osint.none_fw'))}</span></div>`;
    const rows = c.map(x => `<tr>
        <td><code style="font-size:.8rem">${_osintEscape(x.peer || '')}</code>${x.country ? ` <span class="ip-country" style="font-size:.7rem">${_osintEscape(x.country)}</span>` : ''}</td>
        <td>${x.port != null ? x.port : '—'}</td>
        <td>${_osintEscape(x.protocol || '—')}</td>
        <td><span class="badge text-bg-danger" style="font-size:.66rem">${_osintEscape(x.action || 'deny')}</span></td>
        <td style="text-align:right">${(x.events || 0).toLocaleString(OS_LOCALE)}</td>
        <td style="white-space:nowrap">${_osintFmtTs(x.last_seen)}</td>
    </tr>`).join('');
    const trunc = side.truncated ? ` · ${t('osint.top', { n: c.length })}` : '';
    return `
        <div class="osint-conn-head" style="margin:.6rem 0 .3rem">
            ${arrow} <strong>${label}</strong>: ${(side.peers || 0).toLocaleString(OS_LOCALE)} ${_osintEscape(t('osint.peers'))} ·
            ${(side.events || 0).toLocaleString(OS_LOCALE)} ${_osintEscape(t('osint.attempts'))}${trunc}
        </div>
        <div class="table-scroll" style="max-height:240px">
            <table class="table table-sm table-hover align-middle" style="margin:0">
                <thead><tr><th>${_osintEscape(t('osint.col_peer'))}</th><th>${_osintEscape(t('osint.col_port'))}</th><th>${_osintEscape(t('osint.col_proto'))}</th><th>${_osintEscape(t('common.action'))}</th><th style="text-align:right">${_osintEscape(t('osint.attempts'))}</th><th>${_osintEscape(t('osint.col_last'))}</th></tr></thead>
                <tbody>${rows}</tbody>
            </table>
        </div>`;
}

function _osintRenderConnections(d) {
    const outLabel = t('osint.outbound');
    const inLabel = t('osint.inbound');
    const nfBody = (d.netflow_available === false)
        ? `<div class="osint-na">${_osintEscape(d.netflow_reason || t('osint.not_available'))}</div>`
        : `${_osintConnTable(d.outbound, outLabel, '↗')}
           ${_osintConnTable(d.inbound, inLabel, '↘')}`;
    const netflowCard = `<div class="osint-card osint-conn-card">
        <h4>${_osintEscape(t('osint.known_connections'))} <span class="text-secondary" style="font-size:.8rem">${_osintEscape(t('osint.netflow_last_days', { days: d.days }))}</span></h4>
        ${nfBody}
    </div>`;
    const fb = d.firewall_blocked || {};
    let fwCard = '';
    if (fb.available === false) {
        fwCard = `<div class="osint-card osint-conn-card" style="margin-top:1rem">
            <h4>${_osintEscape(t('osint.fw_blocked_attempts'))}</h4>
            <div class="osint-na">${_osintEscape(fb.reason || t('osint.not_available'))}</div>
        </div>`;
    } else {
        const hasFw = ((fb.outbound && fb.outbound.connections && fb.outbound.connections.length) ||
                       (fb.inbound && fb.inbound.connections && fb.inbound.connections.length));
        if (hasFw) fwCard = `<div class="osint-card osint-conn-card" style="margin-top:1rem">
            <h4>${_osintEscape(t('osint.fw_blocked_attempts'))} <span class="text-secondary" style="font-size:.8rem">${_osintEscape(t('osint.last_days', { days: d.days }))}</span></h4>
            ${_osintFwTable(fb.outbound, outLabel, '↗')}
            ${_osintFwTable(fb.inbound, inLabel, '↘')}
        </div>`;
    }
    return netflowCard + fwCard;
}

function _osintHead(p) {
    if (!p) return `<div class="osint-na">${_osintEscape(t('osint.no_data'))}</div>`;
    if (p.available === false) return `<div class="osint-na">${_osintEscape(t('osint.not_available'))} (${_osintEscape(p.reason || t('osint.unknown'))})</div>`;
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
            ${_osintRow(t('osint.l_confidence'), `<span class="osint-score ${sev}">${score}/100</span>`)}
            ${_osintRow(t('osint.l_total_reports'), _osintEscape(String(p.total_reports ?? 0)))}
            ${_osintRow(t('osint.l_distinct_reporters'), _osintEscape(String(p.distinct_users ?? 0)))}
            ${_osintRow(t('osint.l_last_report'), _osintEscape(p.last_reported || '-'))}
            ${_osintRow('ISP', _osintEscape(p.isp || ''))}
            ${_osintRow('Domain', _osintEscape(p.domain || ''))}
            ${_osintRow('Usage', _osintEscape(p.usage_type || ''))}
            ${_osintRow(t('osint.l_whitelist'), p.is_whitelisted === true ? t('osint.yes') : p.is_whitelisted === false ? t('osint.no') : '')}
        </dl>
        ${_osintLink(p.url, t('osint.open_abuseipdb'))}
    `;
}

function _osintRenderVT(p) {
    const head = _osintHead(p); if (head !== null) return head;
    const mal = p.malicious ?? 0, sus = p.suspicious ?? 0;
    const cls = mal > 0 ? 'osint-bad' : sus > 0 ? 'osint-warn' : 'osint-ok';
    const tags = (p.tags || []).map(t => `<span class="osint-tag">${_osintEscape(t)}</span>`).join(' ');
    return `
        <dl class="detail-grid osint-dl">
            ${_osintRow(t('osint.l_verdict'), `<span class="osint-score ${cls}">${t('osint.verdict_value', { mal, sus })}</span>`)}
            ${_osintRow('Harmless', _osintEscape(String(p.harmless ?? 0)))}
            ${_osintRow('Undetected', _osintEscape(String(p.undetected ?? 0)))}
            ${_osintRow(t('osint.l_reputation'), p.reputation != null ? _osintEscape(String(p.reputation)) : '')}
            ${_osintRow('AS Owner', _osintEscape(p.as_owner || ''))}
            ${_osintRow('ASN', p.asn != null ? _osintEscape(String(p.asn)) : '')}
            ${_osintRow(t('common.country'), _osintEscape(p.country || ''))}
            ${tags ? _osintRow('Tags', tags) : ''}
        </dl>
        ${_osintLink(p.url, t('osint.open_virustotal'))}
    `;
}

function _osintRenderShodan(p) {
    // Shodan is opt-in: the skipped sentinel renders a button instead of data,
    // so opening the panel never spends a Shodan credit.
    if (p && p.skipped) {
        return `<div id="osintShodanCard">
            <div class="osint-na">${_osintEscape(t('osint.shodan_on_demand'))}</div>
            <button class="osint-shodan-btn" onclick="shodanLookup()">🛰️ ${_osintEscape(t('osint.shodan_query'))}</button>
        </div>`;
    }
    return `<div id="osintShodanCard">${_osintRenderShodanBody(p)}</div>`;
}

// CVE list coloured by CVSS severity. Uses cve_severity (from the free Shodan
// CVE DB) when present: a severity summary line + per-CVE colour + KEV star;
// falls back to plain CVE tags when severity wasn't resolved.
const _SEV_CLASS = { critical: 'osint-vuln-critical', high: 'osint-vuln-high',
                     medium: 'osint-vuln-medium', low: 'osint-vuln-low' };
function _osintRenderVulns(p) {
    const sev = p.cve_severity;
    if (sev && sev.total) {
        const c = sev.counts || {};
        const parts = [];
        for (const band of ['critical', 'high', 'medium', 'low']) {
            if (c[band]) parts.push(`<span class="osint-tag ${_SEV_CLASS[band]}">${c[band]} ${t('osint.sev_' + band)}</span>`);
        }
        if (sev.kev) parts.push(`<span class="osint-tag osint-vuln-critical" title="${_osintEscape(t('osint.kev_tip'))}">★ ${sev.kev} KEV</span>`);
        const summary = `<div style="margin-bottom:.3rem">${parts.join(' ')}${sev.truncated ? ` <span class="osint-na">${_osintEscape(t('osint.cve_truncated'))}</span>` : ''}</div>`;
        // The worst CVEs, coloured; each links to its Shodan CVE-DB entry.
        const top = (sev.top || []).map(v => {
            const cls = _SEV_CLASS[v.severity] || 'osint-vuln';
            const score = (v.cvss_v3 ?? v.cvss);
            const star = v.kev ? '★' : '';
            const label = `${v.cve}${score != null ? ' ' + score : ''}${star}`;
            return `<a class="osint-tag ${cls}" href="https://www.cvedetails.com/cve/${encodeURIComponent(v.cve)}/" target="_blank" rel="noopener" title="${_osintEscape((v.severity || '') + (v.epss != null ? ' · EPSS ' + Math.round(v.epss * 100) + '%' : ''))}">${_osintEscape(label)}</a>`;
        }).join(' ');
        return _osintRow('CVEs', summary + top);
    }
    const vulns = (p.vulns || []).slice(0, 30).map(v => `<span class="osint-tag osint-vuln">${_osintEscape(v)}</span>`).join(' ');
    return vulns ? _osintRow('Vulns', vulns) : '';
}

function _osintRenderShodanBody(p) {
    const head = _osintHead(p); if (head !== null) return head;
    if (p.no_record) return `<div class="osint-na">${_osintEscape(t('osint.shodan_no_record'))}</div>${_osintLink(p.url, t('osint.open_shodan_search'))}`;
    const ports = (p.ports || []).slice(0, 30).map(pt => `<span class="osint-tag">${pt}</span>`).join(' ');
    const tags = (p.tags || []).map(t => `<span class="osint-tag">${_osintEscape(t)}</span>`).join(' ');
    return `
        <dl class="detail-grid osint-dl">
            ${_osintRow('Org', _osintEscape(p.org || ''))}
            ${_osintRow('ASN', _osintEscape(p.asn || ''))}
            ${_osintRow(t('osint.l_country_city'), _osintEscape([p.country, p.city].filter(Boolean).join(', ')))}
            ${_osintRow('OS', _osintEscape(p.os || ''))}
            ${ports ? _osintRow(t('osint.l_open_ports'), ports) : ''}
            ${_osintRenderVulns(p)}
            ${tags ? _osintRow('Tags', tags) : ''}
            ${_osintRow('Hostnames', _osintEscape((p.hostnames || []).slice(0, 5).join(', ')))}
            ${_osintRow(t('osint.l_as_of'), _osintEscape(p.last_update || ''))}
        </dl>
        ${_osintLink(p.url, t('osint.open_shodan'))}
    `;
}

function _osintRenderGN(p) {
    const head = _osintHead(p); if (head !== null) return head;
    if (p.classification === 'unobserved' || p.noise === false) {
        return `<div class="osint-na">${_osintEscape(t('osint.gn_unobserved'))}</div>`;
    }
    const cls = p.classification === 'malicious' ? 'osint-bad' : p.classification === 'benign' ? 'osint-ok' : 'osint-warn';
    return `
        <dl class="detail-grid osint-dl">
            ${_osintRow(t('osint.l_classification'), `<span class="osint-score ${cls}">${_osintEscape(p.classification || 'unknown')}</span>`)}
            ${_osintRow(t('osint.l_name'), _osintEscape(p.name || ''))}
            ${_osintRow(t('osint.l_last_seen'), _osintEscape(p.last_seen || ''))}
        </dl>
        ${_osintLink(p.url, t('osint.open_greynoise'))}
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
    if (p.no_record) return `<div class="osint-na">${_osintEscape(t('osint.intelix_no_ip'))}</div>`;

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
            ${_osintRow(t('osint.l_category'), category ? `<span class="osint-score ${catCls}">${_osintEscape(category)}</span>` : '')}
            ${_osintRow(t('osint.l_description'), _osintEscape(description))}
            ${_osintRow('Productivity', _osintEscape(productivity))}
            ${_osintRow('Security', _osintEscape(security))}
            ${_osintRow(t('common.score'), isFinite(score) ? `<span class="osint-score ${scoreCls}">${score}</span>` : '')}
        </dl>
    `;
}

function _osintRenderIpInfo(p) {
    const head = _osintHead(p); if (head !== null) return head;
    return `
        <dl class="detail-grid osint-dl">
            ${_osintRow('Hostname', _osintEscape(p.hostname || ''))}
            ${_osintRow(t('osint.l_location'), _osintEscape([p.city, p.region, p.country].filter(Boolean).join(', ')))}
            ${_osintRow('Org', _osintEscape(p.org || ''))}
            ${_osintRow('Loc', _osintEscape(p.loc || ''))}
            ${_osintRow('Postal', _osintEscape(p.postal || ''))}
            ${_osintRow('Timezone', _osintEscape(p.timezone || ''))}
        </dl>
        ${_osintLink(p.url, t('osint.open_ipinfo'))}
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
        ? new Date(p.creation_date * 1000).toLocaleDateString(OS_LOCALE)
        : '';
    return `
        <dl class="detail-grid osint-dl">
            ${_osintRow(t('osint.l_verdict'), `<span class="osint-score ${cls}">${t('osint.verdict_value', { mal, sus })}</span>`)}
            ${_osintRow('Harmless', _osintEscape(String(p.harmless ?? 0)))}
            ${_osintRow('Undetected', _osintEscape(String(p.undetected ?? 0)))}
            ${_osintRow(t('osint.l_reputation'), p.reputation != null ? _osintEscape(String(p.reputation)) : '')}
            ${_osintRow('Registrar', _osintEscape(p.registrar || ''))}
            ${_osintRow(t('osint.l_registered'), _osintEscape(createdAt))}
            ${tags ? _osintRow('Tags', tags) : ''}
            ${cats ? _osintRow(t('osint.l_categories'), cats) : ''}
        </dl>
        ${_osintLink(p.url, t('osint.open_virustotal'))}
    `;
}

function _osintRenderVTUrl(p) {
    const head = _osintHead(p); if (head !== null) return head;
    if (p.no_record) return `<div class="osint-na">${_osintEscape(t('osint.vt_unknown'))}</div>${_osintLink(p.url, t('osint.open_vt_search'))}`;
    const mal = p.malicious ?? 0, sus = p.suspicious ?? 0;
    const cls = mal > 0 ? 'osint-bad' : sus > 0 ? 'osint-warn' : 'osint-ok';
    const tags = (p.tags || []).map(t => `<span class="osint-tag">${_osintEscape(t)}</span>`).join(' ');
    const cats = p.categories && typeof p.categories === 'object'
        ? Object.entries(p.categories).slice(0, 8)
            .map(([engine, cat]) => `<span class="osint-tag">${_osintEscape(cat)} <em>(${_osintEscape(engine)})</em></span>`).join(' ')
        : '';
    return `
        <dl class="detail-grid osint-dl">
            ${_osintRow(t('osint.l_verdict'), `<span class="osint-score ${cls}">${t('osint.verdict_value', { mal, sus })}</span>`)}
            ${_osintRow('Harmless', _osintEscape(String(p.harmless ?? 0)))}
            ${_osintRow('Undetected', _osintEscape(String(p.undetected ?? 0)))}
            ${_osintRow(t('osint.l_reputation'), p.reputation != null ? _osintEscape(String(p.reputation)) : '')}
            ${_osintRow('Title', _osintEscape(p.title || ''))}
            ${_osintRow('Final URL', _osintEscape(p.final_url || ''))}
            ${_osintRow(t('osint.l_http_status'), p.http_status != null ? _osintEscape(String(p.http_status)) : '')}
            ${tags ? _osintRow('Tags', tags) : ''}
            ${cats ? _osintRow(t('osint.l_categories'), cats) : ''}
        </dl>
        ${_osintLink(p.url, t('osint.open_virustotal'))}
    `;
}

function _osintRenderIntelixUrl(p) {
    const head = _osintHead(p); if (head !== null) return head;
    if (p.no_record) return `<div class="osint-na">${_osintEscape(t('osint.intelix_no_record'))}</div>`;

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
            ${_osintRow(t('osint.l_category'), category ? `<span class="osint-score ${catCls}">${_osintEscape(category)}</span>` : '')}
            ${_osintRow(t('osint.l_description'), _osintEscape(description))}
            ${_osintRow('Productivity', _osintEscape(productivity))}
            ${_osintRow('Security', _osintEscape(security))}
            ${_osintRow(t('osint.l_risk'), _osintEscape(risk))}
            ${_osintRow(t('common.score'), isFinite(score) ? `<span class="osint-score ${scoreCls}">${score}</span>` : '')}
        </dl>
    `;
}

function _osintRenderDns(p) {
    const head = _osintHead(p); if (head !== null) return head;
    if (p.resolves === false) {
        return `<div class="osint-na">${_osintEscape(t('osint.dns_no_resolve'))} (${_osintEscape(p.reason || 'NXDOMAIN')})</div>`;
    }
    const ip4 = (p.ipv4 || []).map(ip =>
        `<span class="osint-tag">${_osintEscape(ip)}</span>${osintButton(ip, 'osint-btn')}`
    ).join(' ');
    const ip6 = (p.ipv6 || []).map(ip => `<span class="osint-tag">${_osintEscape(ip)}</span>`).join(' ');
    return `
        <dl class="detail-grid osint-dl">
            ${ip4 ? _osintRow('A-Records (IPv4)', ip4) : ''}
            ${ip6 ? _osintRow('AAAA-Records (IPv6)', ip6) : ''}
            ${!ip4 && !ip6 ? _osintRow(t('common.status'), `<span class="osint-na">${_osintEscape(t('osint.dns_no_records'))}</span>`) : ''}
        </dl>
    `;
}

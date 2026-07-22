// IP dossier: everything Warroom knows about one IP, aggregated from
// /api/ip/{ip}/dossier. Supports a ?ip= deep link.
document.addEventListener('DOMContentLoaded', () => {
    const nav = document.querySelector('a[href="/dossier.html"]');
    if (nav) nav.classList.add('active');

    const ip = document.getElementById('dossierIp');
    const days = document.getElementById('dossierDays');
    document.getElementById('dossierBtn').addEventListener('click', load);
    ip.addEventListener('keydown', e => { if (e.key === 'Enter') load(); });

    const q = new URLSearchParams(location.search).get('ip');
    if (q) { ip.value = q; load(); }

    async function load() {
        const val = ip.value.trim();
        if (!val) return;
        history.replaceState(null, '', `?ip=${encodeURIComponent(val)}`);
        const res = document.getElementById('dossierResult');
        res.innerHTML = `<p class="d-muted">${t('common.loading')}</p>`;
        try {
            const r = await fetch(`/api/ip/${encodeURIComponent(val)}/dossier?days=${days.value}`);
            const d = await r.json();
            if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
            res.innerHTML = render(d);
            if (window.i18nApply) window.i18nApply(res);
        } catch (e) {
            res.innerHTML = `<p class="d-bad">${t('dossier.error')}: ${escapeHtml(e.message)}</p>`;
        }
    }
});

function _row(k, v) {
    if (v === null || v === undefined || v === '') return '';
    return `<div class="drow"><span class="k">${k}</span><span>${v}</span></div>`;
}
function _num(n) { return (Number(n) || 0).toLocaleString('en-US'); }
function _bytes(b) {
    b = Number(b) || 0; if (!b) return '0 B';
    const u = ['B', 'KB', 'MB', 'GB', 'TB']; const i = Math.floor(Math.log(b) / Math.log(1024));
    return (b / Math.pow(1024, i)).toFixed(1) + ' ' + u[i];
}
function _time(s) { return s ? (window.formatTime ? formatTime(s) : new Date(s).toLocaleString('en-US')) : '—'; }
function _card(title, body) { return `<div class="dcard"><h5>${title}</h5>${body}</div>`; }

function render(d) {
    const cards = [];

    // Overview
    const bl = d.blocklist || {}, wl = d.whitelist || {};
    let ov = _row('IP', `<code>${escapeHtml(d.ip)}</code>`);
    ov += _row(t('dossier.type'), d.is_public
        ? `<span class="dbadge d-warn">${t('dossier.external')}</span>`
        : `<span class="dbadge d-ok">${t('dossier.internal')}</span>`);
    ov += _row(t('dossier.blocklist'), bl.blocked
        ? `<span class="dbadge d-bad">${t('dossier.blocked')}</span> <span class="d-muted" style="font-size:.75rem">${escapeHtml(bl.source || '')} · ${escapeHtml(bl.blocked_by || '')}</span>`
        : `<span class="dbadge d-ok">${t('dossier.not_blocked')}</span>`);
    if (bl.blocked && bl.comment) ov += `<div class="d-muted" style="font-size:.8rem;margin-top:.3rem">${escapeHtml(bl.comment)}</div>`;
    ov += _row(t('dossier.whitelist'), wl.whitelisted ? `<span class="dbadge d-ok">✓</span>` : '<span class="d-muted">—</span>');
    if (d.host) {
        ov += _row(t('dossier.hostname'), escapeHtml(d.host.hostname || '—'));
        if (d.host.mac) ov += _row('MAC', `<code>${escapeHtml(d.host.mac)}</code>`);
    }
    cards.push(_card(t('dossier.overview'), ov));

    // OSINT
    if (d.osint && !d.osint.error) {
        const o = d.osint;
        let b = _row(t('dossier.geo'), escapeHtml([o.country, o.org].filter(Boolean).join(' · ') || '—'));
        if (o.rdns) b += _row('Reverse DNS', `<code>${escapeHtml(o.rdns)}</code>`);
        b += _row('AbuseIPDB', o.abuse_score != null ? `<b>${o.abuse_score}%</b>` : '—');
        b += _row('VirusTotal', o.vt_malicious != null ? `${o.vt_malicious} malicious` : '—');
        b += _row('GreyNoise', o.greynoise ? escapeHtml(o.greynoise) : '—');
        b += _row('Sophos Intelix', o.intelix_category ? escapeHtml(o.intelix_category) : '—');
        b += _row('Tor', o.tor_exit_node ? `<span class="dbadge d-bad">${t('dossier.tor_exit')}</span>` : '<span class="d-muted">—</span>');
        if (o.shodan_ports && o.shodan_ports.length) b += _row('Shodan Ports', o.shodan_ports.slice(0, 12).join(', '));
        if (o.shodan_cves) b += _row('Shodan CVEs', `<span class="dbadge d-warn">${o.shodan_cves}</span>`);
        cards.push(_card('OSINT', b));
    } else if (d.osint && d.osint.error) {
        cards.push(_card('OSINT', `<span class="d-muted">${escapeHtml(d.osint.error)}</span>`));
    }

    // Firewall
    const fw = d.firewall || {}, src = fw.as_source || {}, dst = fw.as_destination || {};
    let f = _row(t('dossier.as_source'), `<b>${_num(src.count)}</b>`);
    f += _row(t('dossier.as_dest'), `<b>${_num(dst.count)}</b>`);
    if (src.count) {
        f += _row(t('dossier.last_seen'), _time(src.last_seen));
        if (src.top_actions) f += _row(t('dossier.actions'), src.top_actions.map(a => `${escapeHtml(a.action)} (${_num(a.count)})`).join(', '));
        if (src.top_dst_ports) f += _row(t('dossier.top_ports'), src.top_dst_ports.map(p => `${p.port} (${_num(p.count)})`).join(', '));
    }
    cards.push(_card(t('dossier.firewall'), f));

    // NetFlow
    const nf = d.netflow || {};
    if (nf.out_flows || nf.in_flows) {
        let n = _row(t('dossier.outbound'), `${_num(nf.out_flows)} flows · ${_bytes(nf.out_bytes)}`);
        n += _row(t('dossier.inbound'), `${_num(nf.in_flows)} flows · ${_bytes(nf.in_bytes)}`);
        if (nf.top_dst_ports && nf.top_dst_ports.length) n += _row(t('dossier.top_ports'), nf.top_dst_ports.map(p => `${p.port} (${_num(p.flows)})`).join(', '));
        cards.push(_card('NetFlow', n));
    }

    // Honeypot
    const hp = d.honeypot || {};
    if (hp.hits) {
        let h = _row(t('dossier.hits'), `<span class="dbadge d-bad">${_num(hp.hits)}</span>`);
        h += _row(t('dossier.last_seen'), _time(hp.last_seen));
        if (hp.event_types && hp.event_types.length) h += _row(t('dossier.events'), escapeHtml(hp.event_types.join(', ')));
        cards.push(_card('Honeypot', h));
    }

    // Agent decisions
    const ad = d.agent_decisions || [];
    if (ad.length) {
        const items = ad.map(x => `<div style="border-top:1px solid var(--border,#2a3a4e);padding:.4rem 0">
            <div class="drow"><span><span class="dbadge ${x.action === 'block_ip' ? 'd-bad' : 'd-warn'}">${escapeHtml(x.action)}</span> <span class="d-muted" style="font-size:.75rem">${escapeHtml(x.source_type || '')} · ${escapeHtml(x.status || '')}</span></span><span class="d-muted" style="font-size:.75rem">${_time(x.created_at)}</span></div>
            ${x.reasoning ? `<div class="d-muted" style="font-size:.8rem;margin-top:.2rem">${escapeHtml(x.reasoning)}</div>` : ''}</div>`).join('');
        cards.push(_card(t('dossier.agent'), items));
    }

    return `<div class="dossier-grid">${cards.join('')}</div>`;
}

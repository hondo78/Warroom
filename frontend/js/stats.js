// OSINT-Provider usage statistics: outbound API calls + quota utilization.

let _data = null;
let _trendChart = null;

const PROVIDER_LABELS = {
    abuseipdb:  { label: 'AbuseIPDB',     color: '#3b82f6', url: 'https://www.abuseipdb.com/account/api' },
    virustotal: { label: 'VirusTotal',    color: '#8b5cf6', url: 'https://www.virustotal.com/gui/my-apikey' },
    shodan:     { label: 'Shodan',        color: '#ef4444', url: 'https://account.shodan.io/' },
    greynoise:  { label: 'GreyNoise',     color: '#10b981', url: 'https://www.greynoise.io/' },
    intelix:    { label: 'Sophos Intelix', color: '#06b6d4', url: 'https://api.labs.sophos.com/' },
    ipinfo:     { label: 'ip-api.com',    color: '#f59e0b', url: 'https://ip-api.com/' },
};

document.addEventListener('DOMContentLoaded', () => {
    loadStats();
});

async function loadStats() {
    const days = parseInt(document.getElementById('statsDays').value, 10) || 7;
    try {
        const r = await fetch(`/api/admin/stats/osint-usage?days=${days}`);
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        _data = await r.json();
        renderAll();
    } catch (err) {
        alert('Fehler: ' + err.message);
    }
}

async function flushAndReload() {
    try { await fetch('/api/admin/stats/osint-usage/flush', { method: 'POST' }); } catch (_) {}
    await loadStats();
}

function renderAll() {
    renderKpis();
    renderProviderCards();
    renderTrend();
    renderTable();
}

function renderKpis() {
    const t = _data.totals;
    setText('kHeute', fmt(t.today_real));
    setText('kMonat', fmt(t.month_real));
    setText('kCache', t.global_cache_hit_rate_pct == null ? '—' : `${t.global_cache_hit_rate_pct} %`);
    setText('kCacheTotal', `${fmt(t.window_cache_hit)} aus Cache (Window)`);
    setText('kWarn', fmt(t.providers_near_limit));
}

function renderProviderCards() {
    const container = document.getElementById('providerCards');
    container.innerHTML = _data.providers.map(p => {
        const meta = PROVIDER_LABELS[p.provider] || { label: p.provider, color: '#94a3b8' };
        const dailyBar  = quotaBar(p.today_real, p.daily_limit, p.daily_used_pct);
        const monthlyBar = quotaBar(p.month_real, p.monthly_limit, p.monthly_used_pct);
        const warnBadge = p.warn_level === 'exceeded'
            ? '<span class="severity-badge severity-critical">LIMIT ÜBERSCHRITTEN</span>'
            : p.warn_level === 'warn'
            ? '<span class="severity-badge severity-high">nahe Limit</span>'
            : '<span class="severity-badge severity-low">ok</span>';
        const cacheRate = p.cache_hit_rate_pct == null ? '—' : `${p.cache_hit_rate_pct} %`;
        return `
        <div class="col-lg-6 col-xl-4">
            <div class="card h-100">
                <div class="card-header d-flex justify-content-between align-items-center" style="border-top:3px solid ${meta.color}">
                    <h4 class="card-title mb-0">${escapeHtml(meta.label)}</h4>
                    ${warnBadge}
                </div>
                <div class="card-body">
                    <div class="mb-2"><strong>Tag</strong> · ${fmt(p.today_real)} ${p.daily_limit ? '/ ' + fmt(p.daily_limit) : '<small class="text-secondary">(kein Limit)</small>'}</div>
                    ${dailyBar}
                    <div class="mb-2 mt-3"><strong>Monat</strong> · ${fmt(p.month_real)} ${p.monthly_limit ? '/ ' + fmt(p.monthly_limit) : '<small class="text-secondary">(kein Limit)</small>'}</div>
                    ${monthlyBar}
                    <hr class="my-3" style="opacity:.2">
                    <div class="d-flex justify-content-between small text-secondary">
                        <span><i class="bi bi-lightning-charge"></i> Cache-Hit ${cacheRate}</span>
                        <span>${fmt(p.window_cache_hit)} aus Cache</span>
                    </div>
                    <div class="d-flex justify-content-between small text-secondary mt-1">
                        <span>OK ${fmt(p.window.success || 0)} · 404 ${fmt(p.window.no_record || 0)} · Fehler ${fmt(p.window.error || 0)}</span>
                        <span>${p.last_called_at ? new Date(p.last_called_at).toLocaleString('de-DE', {dateStyle:'short', timeStyle:'short'}) : '—'}</span>
                    </div>
                </div>
            </div>
        </div>`;
    }).join('');
}

function quotaBar(used, limit, pct) {
    if (!limit) {
        return '<div class="progress" style="height:8px"><div class="progress-bar bg-secondary" style="width:0%"></div></div>';
    }
    const cls = pct >= 100 ? 'bg-danger' : pct >= 80 ? 'bg-warning' : 'bg-success';
    const widthClamped = Math.min(100, pct ?? 0);
    return `<div class="progress" style="height:10px" title="${pct?.toFixed(1) || 0} %">
        <div class="progress-bar ${cls}" role="progressbar" style="width:${widthClamped}%"></div>
    </div>
    <div class="small text-secondary mt-1">${(pct ?? 0).toFixed(1)} %</div>`;
}

function renderTrend() {
    // Build a union of all days across all providers
    const dayMap = new Map();
    for (const p of _data.providers) {
        for (const r of (p.by_day || [])) {
            if (!dayMap.has(r.day)) dayMap.set(r.day, {});
            const cnt = (r.success || 0) + (r.no_record || 0) + (r.error || 0);
            dayMap.get(r.day)[p.provider] = (dayMap.get(r.day)[p.provider] || 0) + cnt;
        }
    }
    const days = [...dayMap.keys()].sort();
    const labels = days.map(d => new Date(d).toLocaleDateString('de-DE', { month: '2-digit', day: '2-digit' }));
    const datasets = _data.providers.map(p => {
        const meta = PROVIDER_LABELS[p.provider] || { label: p.provider, color: '#94a3b8' };
        return {
            label: meta.label,
            data: days.map(d => dayMap.get(d)[p.provider] || 0),
            backgroundColor: meta.color + 'b3',
            borderColor: meta.color,
            borderWidth: 1,
            stack: 'a',
        };
    });
    if (_trendChart) _trendChart.destroy();
    const ctx = document.getElementById('trendChart').getContext('2d');
    _trendChart = new Chart(ctx, {
        type: 'bar',
        data: { labels, datasets },
        options: {
            responsive: true, maintainAspectRatio: false,
            scales: {
                x: { stacked: true, ticks: { color: '#94a3b8' } },
                y: { stacked: true, beginAtZero: true, ticks: { color: '#94a3b8' } },
            },
            plugins: { legend: { labels: { color: '#e2e8f0' } } },
        },
    });
}

function renderTable() {
    const tbody = document.getElementById('providerTable');
    tbody.innerHTML = _data.providers.map(p => {
        const meta = PROVIDER_LABELS[p.provider] || { label: p.provider, color: '#94a3b8' };
        const warnClass = p.warn_level === 'exceeded' ? 'severity-critical' : p.warn_level === 'warn' ? 'severity-high' : 'severity-low';
        const dailyTxt = p.daily_limit
            ? `${fmt(p.daily_limit)} <small class="text-secondary">(${(p.daily_used_pct ?? 0).toFixed(1)} %)</small>`
            : '<small class="text-secondary">—</small>';
        const monthlyTxt = p.monthly_limit
            ? `${fmt(p.monthly_limit)} <small class="text-secondary">(${(p.monthly_used_pct ?? 0).toFixed(1)} %)</small>`
            : '<small class="text-secondary">—</small>';
        return `<tr>
            <td><span class="severity-badge ${warnClass}" style="background:${meta.color}33;border:1px solid ${meta.color}80;color:#e2e8f0">${escapeHtml(meta.label)}</span></td>
            <td class="text-end">${fmt(p.today_real)}</td>
            <td class="text-end">${fmt(p.month_real)}</td>
            <td>${dailyTxt}</td>
            <td>${monthlyTxt}</td>
            <td class="text-end">${p.cache_hit_rate_pct == null ? '—' : p.cache_hit_rate_pct + ' %'}</td>
            <td class="text-end"><span class="text-success">${fmt(p.window.success || 0)}</span> / <span class="text-secondary">${fmt(p.window.no_record || 0)}</span> / <span class="text-danger">${fmt(p.window.error || 0)}</span></td>
            <td>${p.last_called_at ? new Date(p.last_called_at).toLocaleString('de-DE') : '—'}</td>
        </tr>`;
    }).join('');
}

function fmt(n) {
    if (n == null) return '—';
    if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M';
    if (n >= 10_000) return (n / 1000).toFixed(1) + 'k';
    return n.toLocaleString('de-DE');
}

function setText(id, txt) {
    const el = document.getElementById(id);
    if (el) el.textContent = txt;
}

function escapeHtml(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({
        '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
    }[c]));
}

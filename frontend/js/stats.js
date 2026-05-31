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

let _llmData = null;
let _llmSourceChart = null;
let _llmTrendChart = null;
let _llmAnalyzeData = null;
let _llmAnalyzeChart = null;
let _llmAnalyzeSources = new Set();  // active source filter; empty = all
let _llmAnalyzeInited = false;

document.addEventListener('DOMContentLoaded', () => {
    loadStats();
});

async function loadStats() {
    const days = parseInt(document.getElementById('statsDays').value, 10) || 7;
    try {
        const [osintResp, llmResp] = await Promise.all([
            fetch(`/api/admin/stats/osint-usage?days=${days}`),
            fetch(`/api/admin/stats/llm-usage?days=${days}`),
        ]);
        if (!osintResp.ok) throw new Error(`OSINT HTTP ${osintResp.status}`);
        if (!llmResp.ok)   throw new Error(`LLM HTTP ${llmResp.status}`);
        _data    = await osintResp.json();
        _llmData = await llmResp.json();
        renderAll();
    } catch (err) {
        alert('Fehler: ' + err.message);
    }
}

async function flushAndReload() {
    try {
        await Promise.all([
            fetch('/api/admin/stats/osint-usage/flush', { method: 'POST' }),
            fetch('/api/admin/stats/llm-usage/flush',   { method: 'POST' }),
        ]);
    } catch (_) {}
    await loadStats();
}

function renderAll() {
    renderKpis();
    renderProviderCards();
    renderTrend();
    renderTable();
    renderLlmKpis();
    renderLlmSourceChart();
    renderLlmTrendChart();
    renderLlmSourceTable();
    renderLlmModelTable();
    if (!_llmAnalyzeInited) {
        initLlmAnalyzer();
        _llmAnalyzeInited = true;
    }
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

// escapeHtml() lives in js/common.js


// ============================================================
// LLM-Section
// ============================================================

const LLM_SOURCE_LABELS = {
    alert:        { label: 'Sophos Alert',  color: '#ef4444' },
    waf:          { label: 'WAF',           color: '#f59e0b' },
    ips:          { label: 'IPS',           color: '#8b5cf6' },
    failed_login: { label: 'Failed-Login',  color: '#06b6d4' },
    test:         { label: 'Test (Probe)',  color: '#94a3b8' },
    manual:       { label: 'Manuell',       color: '#3b82f6' },
};

function renderLlmKpis() {
    const t = _llmData.totals;
    setText('llmHeute', fmt(t.today_calls));
    setText('llmMonat', fmt(t.month_calls));
    setText('llmSuccess', t.success_rate_pct == null ? '—' : `${t.success_rate_pct} %`);
    setText('llmSuccessTotal', `Fenster: ${fmt(t.window_calls)} Calls`);
    setText('llmAvgMs', t.avg_duration_ms == null ? '—' : Math.round(t.avg_duration_ms));
    setText('llmLastCalled', t.last_called_at
        ? 'letzter Call: ' + new Date(t.last_called_at).toLocaleString('de-DE')
        : 'letzter Call: —');
    setText('llmTokensMonth', fmt(t.month_tokens));
    setText('llmTokensToday', `heute: ${fmt(t.today_tokens)}`);
}

function renderLlmSourceChart() {
    const sources = (_llmData.by_source || []).filter(s => s.count > 0);
    const labels  = sources.map(s => (LLM_SOURCE_LABELS[s.source] || {label: s.source}).label);
    const success = sources.map(s => s.success);
    const errors  = sources.map(s => s.error);
    if (_llmSourceChart) _llmSourceChart.destroy();
    const el = document.getElementById('llmSourceChart');
    if (!el || !sources.length) {
        if (_llmSourceChart) _llmSourceChart.destroy();
        if (el) el.getContext('2d').clearRect(0, 0, el.width, el.height);
        return;
    }
    _llmSourceChart = new Chart(el.getContext('2d'), {
        type: 'bar',
        data: {
            labels,
            datasets: [
                { label: 'Erfolg', data: success, backgroundColor: 'rgba(34,197,94,0.7)', borderColor: 'rgba(34,197,94,1)', borderWidth: 1, stack: 'a' },
                { label: 'Fehler', data: errors,  backgroundColor: 'rgba(239,68,68,0.7)', borderColor: 'rgba(239,68,68,1)', borderWidth: 1, stack: 'a' },
            ],
        },
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

function renderLlmTrendChart() {
    const totals = _llmData.totals_by_day || [];
    const labels = totals.map(t => new Date(t.day).toLocaleDateString('de-DE', { month: '2-digit', day: '2-digit' }));
    const calls  = totals.map(t => t.count);
    const tokens = totals.map(t => t.prompt_tokens + t.completion_tokens);
    if (_llmTrendChart) _llmTrendChart.destroy();
    const el = document.getElementById('llmTrendChart');
    if (!el || !totals.length) {
        if (_llmTrendChart) _llmTrendChart.destroy();
        if (el) el.getContext('2d').clearRect(0, 0, el.width, el.height);
        return;
    }
    _llmTrendChart = new Chart(el.getContext('2d'), {
        type: 'bar',
        data: {
            labels,
            datasets: [
                { label: 'Calls',  data: calls,  backgroundColor: 'rgba(139,92,246,0.7)', yAxisID: 'y',  order: 2 },
                { label: 'Tokens', data: tokens, type: 'line', borderColor: '#22c55e', backgroundColor: 'rgba(34,197,94,0.15)', tension: 0.25, yAxisID: 'y1', order: 1 },
            ],
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            scales: {
                x:  { ticks: { color: '#94a3b8' } },
                y:  { position: 'left',  beginAtZero: true, ticks: { color: '#94a3b8' }, title: { display: true, text: 'Calls', color: '#94a3b8' } },
                y1: { position: 'right', beginAtZero: true, ticks: { color: '#22c55e' }, title: { display: true, text: 'Tokens', color: '#22c55e' }, grid: { drawOnChartArea: false } },
            },
            plugins: { legend: { labels: { color: '#e2e8f0' } } },
        },
    });
}

function renderLlmSourceTable() {
    const tbody = document.getElementById('llmSourceTable');
    const rows = (_llmData.by_source || []).filter(s => s.count > 0);
    if (!rows.length) {
        tbody.innerHTML = '<tr><td colspan="8" class="text-center text-secondary py-3">Noch keine LLM-Aufrufe — der Agent muss eingeschaltet sein und einen Lauf gemacht haben.</td></tr>';
        return;
    }
    tbody.innerHTML = rows.map(s => {
        const meta = LLM_SOURCE_LABELS[s.source] || { label: s.source, color: '#94a3b8' };
        return `<tr>
            <td><span class="severity-badge" style="background:${meta.color}33;border:1px solid ${meta.color}80;color:#e2e8f0">${escapeHtml(meta.label)}</span></td>
            <td class="text-end"><strong>${fmt(s.count)}</strong></td>
            <td class="text-end text-success">${fmt(s.success)}</td>
            <td class="text-end ${s.error ? 'text-danger' : 'text-secondary'}">${fmt(s.error)}</td>
            <td class="text-end">${fmt(s.prompt_tokens)}</td>
            <td class="text-end">${fmt(s.completion_tokens)}</td>
            <td class="text-end">${s.avg_duration_ms == null ? '—' : Math.round(s.avg_duration_ms)}</td>
            <td>${s.last_called_at ? new Date(s.last_called_at).toLocaleString('de-DE') : '—'}</td>
        </tr>`;
    }).join('');
}

function renderLlmModelTable() {
    const tbody = document.getElementById('llmModelTable');
    const rows = (_llmData.by_model || []).filter(m => m.count > 0);
    if (!rows.length) {
        tbody.innerHTML = '<tr><td colspan="5" class="text-center text-secondary py-3">Kein Modell-Lauf erfasst.</td></tr>';
        return;
    }
    tbody.innerHTML = rows.map(m => `<tr>
        <td><code style="font-size:.8rem">${escapeHtml(m.model)}</code></td>
        <td class="text-end"><strong>${fmt(m.count)}</strong></td>
        <td class="text-end">${fmt(m.prompt_tokens)}</td>
        <td class="text-end">${fmt(m.completion_tokens)}</td>
        <td class="text-end">${m.avg_duration_ms == null ? '—' : Math.round(m.avg_duration_ms)}</td>
    </tr>`).join('');
}


// ============================================================
// LLM Analyzer — date pickers + source filter + stacked chart
// ============================================================

function initLlmAnalyzer() {
    // Default range: last 7 days, ending today (UTC date matches what the
    // backend day-buckets store, so no off-by-one surprises)
    const today = new Date();
    const past = new Date(today);
    past.setDate(today.getDate() - 6);
    const fromEl = document.getElementById('llmAnalyzeFrom');
    const toEl = document.getElementById('llmAnalyzeTo');
    if (fromEl && !fromEl.value) fromEl.value = isoDate(past);
    if (toEl && !toEl.value) toEl.value = isoDate(today);

    // Build source-filter chips from the known list. Click toggles inclusion.
    const wrap = document.getElementById('llmSourceFilter');
    if (wrap) {
        // Keep the label, drop any existing chips
        wrap.querySelectorAll('.source-chip').forEach(el => el.remove());
        for (const src of Object.keys(LLM_SOURCE_LABELS)) {
            const meta = LLM_SOURCE_LABELS[src];
            const btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'btn btn-sm source-chip';
            btn.dataset.source = src;
            btn.dataset.active = '1';
            btn.style.borderColor = meta.color;
            btn.style.color = '#e2e8f0';
            btn.style.background = meta.color + '66';
            btn.textContent = meta.label;
            btn.onclick = () => toggleSourceFilter(src, btn);
            wrap.appendChild(btn);
        }
    }
    loadLlmAnalyze();
}

function toggleSourceFilter(src, btn) {
    const active = btn.dataset.active === '1';
    if (active) {
        _llmAnalyzeSources.add(src);  // when set is non-empty, treat as "only these"
        btn.dataset.active = '0';
        const meta = LLM_SOURCE_LABELS[src];
        btn.style.background = 'transparent';
        btn.style.color = '#94a3b8';
        // Switch semantics: if all were active and now one is hidden, lock
        // the visible ones via the filter set
        if (_llmAnalyzeSources.size === Object.keys(LLM_SOURCE_LABELS).length) {
            // turned every chip off; reset to all-on
            _llmAnalyzeSources.clear();
            document.querySelectorAll('.source-chip').forEach(b => {
                const m = LLM_SOURCE_LABELS[b.dataset.source];
                b.dataset.active = '1';
                b.style.background = m.color + '66';
                b.style.color = '#e2e8f0';
            });
        }
    } else {
        _llmAnalyzeSources.delete(src);
        btn.dataset.active = '1';
        const meta = LLM_SOURCE_LABELS[src];
        btn.style.background = meta.color + '66';
        btn.style.color = '#e2e8f0';
    }
    renderLlmAnalyzeChart();
}

function llmAnalyzeQuickRange(days) {
    const today = new Date();
    const past = new Date(today);
    past.setDate(today.getDate() - (days - 1));
    document.getElementById('llmAnalyzeFrom').value = isoDate(past);
    document.getElementById('llmAnalyzeTo').value   = isoDate(today);
    loadLlmAnalyze();
}

async function loadLlmAnalyze() {
    const from = document.getElementById('llmAnalyzeFrom').value;
    const to = document.getElementById('llmAnalyzeTo').value;
    if (!from || !to) return;
    const params = new URLSearchParams({ from, to });
    try {
        const r = await fetch(`/api/admin/stats/llm-usage?${params}`);
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        _llmAnalyzeData = await r.json();
        renderLlmAnalyzeChart();
    } catch (err) {
        alert('Fehler: ' + err.message);
    }
}

function renderLlmAnalyzeChart() {
    if (!_llmAnalyzeData) return;
    const bySrcByDay = _llmAnalyzeData.by_source_by_day || {};
    const totals = _llmAnalyzeData.totals_by_day || [];

    // Decide which sources to chart. Filter-set empty = all known sources.
    const includedSources = _llmAnalyzeSources.size === 0
        ? Object.keys(LLM_SOURCE_LABELS).filter(s => bySrcByDay[s])
        : [...Object.keys(LLM_SOURCE_LABELS)]
            .filter(s => bySrcByDay[s] && !_llmAnalyzeSources.has(s));

    // Build the day axis from totals_by_day so the chart always has dense
    // x labels even on days where some sources had zero calls.
    const dayLabels = totals.map(t => t.day);
    const dayDisplay = dayLabels.map(d => new Date(d).toLocaleDateString('de-DE', { month: '2-digit', day: '2-digit' }));

    // Calls per source per day (stacked bars)
    const callDatasets = includedSources.map(src => {
        const meta = LLM_SOURCE_LABELS[src] || { label: src, color: '#94a3b8' };
        const series = bySrcByDay[src] || [];
        const map = new Map(series.map(r => [r.day, r.count]));
        return {
            label: meta.label,
            data: dayLabels.map(d => map.get(d) || 0),
            backgroundColor: meta.color + 'b3',
            borderColor: meta.color,
            borderWidth: 1,
            stack: 'calls',
            yAxisID: 'y',
            type: 'bar',
            order: 2,
        };
    });

    // Tokens — sum prompt + completion across the included sources per day
    const tokenSeries = dayLabels.map(d => {
        let sum = 0;
        for (const src of includedSources) {
            const row = (bySrcByDay[src] || []).find(r => r.day === d);
            if (row) sum += (row.prompt_tokens || 0) + (row.completion_tokens || 0);
        }
        return sum;
    });

    const datasets = [
        ...callDatasets,
        {
            label: 'Tokens (Summe)',
            type: 'line',
            data: tokenSeries,
            borderColor: '#22c55e',
            backgroundColor: 'rgba(34,197,94,0.12)',
            tension: 0.25,
            yAxisID: 'y1',
            order: 1,
            pointRadius: 3,
            fill: false,
        },
    ];

    if (_llmAnalyzeChart) _llmAnalyzeChart.destroy();
    const el = document.getElementById('llmAnalyzeChart');
    if (!el) return;
    _llmAnalyzeChart = new Chart(el.getContext('2d'), {
        data: { labels: dayDisplay, datasets },
        options: {
            responsive: true, maintainAspectRatio: false,
            scales: {
                x:  { stacked: true, ticks: { color: '#94a3b8' } },
                y:  { stacked: true, position: 'left', beginAtZero: true,
                      ticks: { color: '#94a3b8' },
                      title: { display: true, text: 'Calls', color: '#94a3b8' } },
                y1: { position: 'right', beginAtZero: true,
                      ticks: { color: '#22c55e' },
                      title: { display: true, text: 'Tokens', color: '#22c55e' },
                      grid: { drawOnChartArea: false } },
            },
            plugins: { legend: { labels: { color: '#e2e8f0' } } },
        },
    });

    // Footer with running totals over the selected window+filter
    let totalCalls = 0, totalTokens = 0;
    for (const src of includedSources) {
        for (const row of (bySrcByDay[src] || [])) {
            totalCalls += row.count;
            totalTokens += (row.prompt_tokens || 0) + (row.completion_tokens || 0);
        }
    }
    const footer = document.getElementById('llmAnalyzeFooter');
    if (footer) {
        const from = document.getElementById('llmAnalyzeFrom').value;
        const to = document.getElementById('llmAnalyzeTo').value;
        const dayCount = dayLabels.length;
        const avgPerDay = dayCount ? Math.round(totalCalls / dayCount * 10) / 10 : 0;
        const tokensPerCall = totalCalls ? Math.round(totalTokens / totalCalls) : 0;
        const srcNote = _llmAnalyzeSources.size
            ? `${includedSources.length} von ${Object.keys(LLM_SOURCE_LABELS).length} Quellen aktiv`
            : `alle ${Object.keys(LLM_SOURCE_LABELS).length} Quellen`;
        footer.textContent =
            `${from} bis ${to} (${dayCount} Tag${dayCount === 1 ? '' : 'e'}) · `
            + `${srcNote} · `
            + `${fmt(totalCalls)} Calls (Ø ${avgPerDay}/Tag) · `
            + `${fmt(totalTokens)} Tokens (Ø ${fmt(tokensPerCall)}/Call)`;
    }
}

function isoDate(d) {
    const yyyy = d.getFullYear();
    const mm = String(d.getMonth() + 1).padStart(2, '0');
    const dd = String(d.getDate()).padStart(2, '0');
    return `${yyyy}-${mm}-${dd}`;
}

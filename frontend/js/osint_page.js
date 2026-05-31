// OSINT query page. Reuses the render helpers from osint.js (_osintRender)
// and the shared /api/osint/* endpoints, but shows the result inline on the
// page instead of in the modal. The modal is still present so the 🔍
// sub-lookups inside a result (e.g. DNS A-records) keep working.

const OSINT_HISTORY_KEY = 'warroomOsintHistory';

// The value/type currently shown in the result card — used by the
// "Sofort blocken" and "An KI-Triage" actions.
let _osintLast = { value: null, type: null };

document.addEventListener('DOMContentLoaded', () => {
    const input = document.getElementById('osintQuery');
    input.addEventListener('keydown', e => { if (e.key === 'Enter') runOsintQuery(); });
    input.focus();
    renderHistory();
});

// Best-effort classification when the type select is on "auto".
function detectOsintType(v) {
    v = v.trim();
    if (/^https?:\/\//i.test(v)) return 'url';
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return 'ip';
    if (v.includes(':') && /^[0-9a-f:]+$/i.test(v)) return 'ip';  // IPv6
    if (v.includes('/') || v.includes('?')) return 'url';
    return 'domain';
}

async function runOsintQuery(forceOverride) {
    const raw = document.getElementById('osintQuery').value.trim();
    if (!raw) { document.getElementById('osintQuery').focus(); return; }

    let type = document.getElementById('osintType').value;
    if (type === 'auto') type = detectOsintType(raw);
    const force = forceOverride === true || document.getElementById('osintForce').checked;

    const label = { ip: 'IP', domain: 'Domain', url: 'URL' }[type] || 'IP';
    _osintLast = { value: raw, type };
    document.getElementById('osintResultTitle').textContent = `${label}: ${raw}`;
    document.getElementById('osintResultCard').style.display = '';
    hideActionMsg();
    const results = document.getElementById('osintResults');
    results.innerHTML = '<div class="osint-loading">Quellen werden parallel abgefragt — 5–10 Sekunden bei nicht gecachten Einträgen…</div>';
    document.getElementById('osintResultCard').scrollIntoView({ behavior: 'smooth', block: 'nearest' });

    try {
        let url;
        if (type === 'domain') url = `/api/osint/domain/${encodeURIComponent(raw)}`;
        else if (type === 'url') url = `/api/osint/url?u=${encodeURIComponent(raw)}`;
        else url = `/api/osint/${encodeURIComponent(raw)}`;
        if (force) url += (url.includes('?') ? '&' : '?') + 'force=true';

        const r = await fetch(url);
        const d = await r.json();
        if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
        // _osintRender lives in osint.js and returns the same card grid used by
        // the modal everywhere else in the dashboard.
        results.innerHTML = _osintRender(d, type);
        addHistory(raw, type);
    } catch (err) {
        results.innerHTML = `<div class="detail-error">Fehler: ${escapeHtml(err.message)}</div>`;
    }
}

// ---- actions: immediate block / hand to AI triage ----

function showActionMsg(html, kind) {
    const box = document.getElementById('osintActionMsg');
    box.className = `alert alert-${kind} mb-3`;
    box.innerHTML = html;
}
function hideActionMsg() {
    const box = document.getElementById('osintActionMsg');
    box.className = 'alert d-none mb-3';
    box.innerHTML = '';
}

async function blockCurrent() {
    const { value, type } = _osintLast;
    if (!value) return;
    const label = { ip: 'IP', domain: 'Domain', url: 'URL' }[type] || type;
    if (!confirm(`${label} "${value}" sofort auf die Blocklist setzen?`)) return;

    const endpoint = { ip: '/api/firewall/block-ip', domain: '/api/firewall/block-domain', url: '/api/firewall/block-url' }[type];
    const keyName = { ip: 'ip', domain: 'domain', url: 'url' }[type];
    const payload = { comment: 'OSINT manual block' };
    payload[keyName] = value;
    try {
        const r = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
        showActionMsg(`<i class="bi bi-shield-slash"></i> <strong>${escapeHtml(value)}</strong> wurde geblockt. <a href="/blocked.html" class="alert-link">Blocklist öffnen ↗</a>`, 'success');
    } catch (err) {
        showActionMsg(`Blocken fehlgeschlagen: ${escapeHtml(err.message)}`, 'danger');
    }
}

async function triageCurrent() {
    const { value, type } = _osintLast;
    if (!value) return;
    const note = prompt('Optionaler Hinweis für den KI-Agenten (Kontext):', '') || null;
    showActionMsg('<i class="bi bi-robot"></i> KI-Triage läuft — der Agent prüft den Wert (kann einige Sekunden dauern)…', 'info');
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
        const kind = acted ? 'warning' : 'secondary';
        showActionMsg(
            `<i class="bi bi-robot"></i> KI-Entscheidung: <strong>${escapeHtml(d.action || '?')}</strong> (${conf}% Konfidenz)` +
            `${d.reasoning ? '<br><small>' + escapeHtml(d.reasoning) + '</small>' : ''}` +
            `<br><a href="/agent.html" class="alert-link">Decision #${d.decision_id} im Agent-Log ansehen ↗</a>`,
            kind
        );
    } catch (err) {
        showActionMsg(`KI-Triage fehlgeschlagen: ${escapeHtml(err.message)}`, 'danger');
    }
}

// ---- recent-query history (localStorage) ----

function loadHistory() {
    try { return JSON.parse(localStorage.getItem(OSINT_HISTORY_KEY) || '[]'); }
    catch (_) { return []; }
}

function addHistory(value, type) {
    let hist = loadHistory().filter(h => !(h.value === value && h.type === type));
    hist.unshift({ value, type });
    hist = hist.slice(0, 20);
    try { localStorage.setItem(OSINT_HISTORY_KEY, JSON.stringify(hist)); } catch (_) {}
    renderHistory();
}

function renderHistory() {
    const box = document.getElementById('osintHistory');
    const hist = loadHistory();
    if (!hist.length) {
        box.innerHTML = '<span class="text-secondary">Noch keine Abfragen.</span>';
        return;
    }
    const icon = { ip: '🌐', domain: '🔗', url: '📄' };
    // Reference history entries by index to sidestep quote-escaping in onclick.
    box.innerHTML = hist.map((h, i) =>
        `<button class="osint-btn" style="margin:.15rem" onclick="rerunHistory(${i})">${icon[h.type] || '🔍'} ${escapeHtml(h.value)}</button>`
    ).join(' ');
}

function rerunHistory(i) {
    const h = loadHistory()[i];
    if (!h) return;
    document.getElementById('osintQuery').value = h.value;
    document.getElementById('osintType').value = h.type;
    runOsintQuery();
}

function clearOsintHistory() {
    try { localStorage.removeItem(OSINT_HISTORY_KEY); } catch (_) {}
    renderHistory();
}

// escapeHtml() lives in js/common.js

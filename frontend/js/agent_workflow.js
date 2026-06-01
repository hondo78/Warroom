// Agent-Workflow admin page. Renders the LLM decision pipeline and one editable
// card per stage from GET /api/agent/workflow (+ /api/admin/settings for the
// current prompt texts). All writes go through PUT /api/admin/settings.

let WF = null;        // workflow structure
let SETTINGS = null;  // current settings snapshot (for prompt values)

const ACT_COLOR = {
    block_ip: 'danger', block_ips: 'danger', block_subnet: 'danger',
    block_domain: 'danger', block_url: 'danger',
    isolate: 'warning', acknowledge: 'info', no_action: 'secondary',
};

document.addEventListener('DOMContentLoaded', loadWorkflow);

async function loadWorkflow() {
    try {
        const [wfR, setR] = await Promise.all([
            fetch('/api/agent/workflow'),
            fetch('/api/admin/settings'),
        ]);
        if (!wfR.ok) throw new Error(`workflow HTTP ${wfR.status}`);
        WF = await wfR.json();
        SETTINGS = await setR.json();
        renderPipeline(WF.pipeline || []);
        populateGlobal(WF.global || {});
        renderStages(WF.stages || []);
        const badge = document.getElementById('wfStructuredBadge');
        const on = !!(WF.global && WF.global.structured_output);
        badge.textContent = on ? 'Structured Output: AN' : 'Structured Output: AUS';
        badge.className = 'badge ' + (on ? 'text-bg-success' : 'text-bg-secondary');
    } catch (e) {
        toast('Laden fehlgeschlagen: ' + e.message, 'error');
    }
}

function renderPipeline(steps) {
    document.getElementById('wfPipeline').innerHTML = steps.map((s, i) =>
        `<div class="wf-step"><h6>${i + 1}. ${escapeHtml(s.step)}</h6><small>${escapeHtml(s.detail)}</small></div>`
    ).join('');
}

function populateGlobal(g) {
    document.getElementById('g_agent_enabled').checked = !!g.enabled;
    document.getElementById('g_agent_structured_output').checked = !!g.structured_output;
    document.getElementById('g_agent_model').value = g.model || '';
    document.getElementById('g_agent_temperature').value = g.temperature ?? 0.2;
    document.getElementById('g_agent_max_tokens').value = g.max_tokens ?? 3000;
    document.getElementById('g_agent_auto_execute').checked = !!g.auto_execute;
    document.getElementById('g_agent_auto_execute_threshold').value = g.auto_execute_threshold ?? 90;
}

async function saveGlobal() {
    const payload = {
        agent_enabled: document.getElementById('g_agent_enabled').checked,
        agent_structured_output: document.getElementById('g_agent_structured_output').checked,
        agent_model: document.getElementById('g_agent_model').value,
        agent_temperature: parseFloat(document.getElementById('g_agent_temperature').value),
        agent_max_tokens: parseInt(document.getElementById('g_agent_max_tokens').value, 10),
        agent_auto_execute: document.getElementById('g_agent_auto_execute').checked,
        agent_auto_execute_threshold: parseInt(document.getElementById('g_agent_auto_execute_threshold').value, 10),
    };
    await putSettings(payload, 'Global gespeichert');
}

function renderStages(stages) {
    document.getElementById('wfStages').innerHTML = stages.map(st => {
        const off = st.enabled ? '' : 'wf-stage-off';
        const acts = (st.allowed_actions || []).map(a =>
            `<span class="badge wf-act text-bg-${ACT_COLOR[a] || 'secondary'}">${escapeHtml(a)}</span>`
        ).join(' ');
        const numFields = (st.settings || []).map(s =>
            `<div class="col-md-3"><label class="form-label">${escapeHtml(s.label)}</label>
                <input type="number" class="form-control form-control-sm" id="st_${st.key}_${s.key}"
                       value="${s.value ?? ''}" min="${s.min ?? 0}" max="${s.max ?? 1000000}"></div>`
        ).join('');
        const enableToggle = st.enabled_key
            ? `<div class="form-check form-switch d-inline-block ms-2 align-middle"><input class="form-check-input" type="checkbox" id="st_${st.key}_enabled" ${st.enabled ? 'checked' : ''}></div>`
            : '<span class="badge text-bg-info ms-2">on-demand</span>';
        const promptVal = (SETTINGS && SETTINGS[st.prompt_key]) || '';
        const promptBadge = st.prompt_overridden
            ? '<span class="badge text-bg-warning">eigener Prompt</span>'
            : '<span class="badge text-bg-secondary">Default-Prompt</span>';
        const runBtn = st.run_now
            ? `<button class="btn btn-outline-secondary btn-sm" onclick="runNow('${st.run_now}')"><i class="bi bi-play"></i> Jetzt ausführen</button>`
            : '';
        return `
        <div class="card mb-3 ${off}">
            <div class="card-header d-flex justify-content-between align-items-center flex-wrap gap-2">
                <h3 class="card-title mb-0">${escapeHtml(st.label)} ${enableToggle}</h3>
                <div>${acts}</div>
            </div>
            <div class="card-body">
                <p class="admin-hint mb-2"><strong>Trigger:</strong> ${escapeHtml(st.trigger)} · ${promptBadge}</p>
                ${numFields ? `<div class="row g-2 align-items-end mb-1">${numFields}</div>` : ''}
                <label class="form-label mt-2">System-Prompt <span class="text-secondary">(leer ⇒ eingebauter Default)</span></label>
                <textarea class="form-control form-control-sm wf-prompt" id="st_${st.key}_prompt" rows="10" placeholder="(leer → Default für ${escapeHtml(st.label)})">${escapeHtml(promptVal)}</textarea>
                <div class="d-flex justify-content-between gap-2 mt-2 flex-wrap">
                    <div>${runBtn}</div>
                    <div class="d-flex gap-2 flex-wrap">
                        <button class="btn btn-outline-secondary btn-sm" onclick="loadDefaultPrompt('${st.prompt_source}','st_${st.key}_prompt')"><i class="bi bi-arrow-counterclockwise"></i> Default laden</button>
                        <button class="btn btn-outline-secondary btn-sm" onclick="clearPromptField('st_${st.key}_prompt')"><i class="bi bi-eraser"></i> Leeren</button>
                        <button class="btn btn-primary btn-sm" onclick="saveStage('${st.key}')">Stufe speichern</button>
                    </div>
                </div>
            </div>
        </div>`;
    }).join('');
}

function saveStage(key) {
    const st = (WF.stages || []).find(s => s.key === key);
    if (!st) return;
    const payload = {};
    if (st.enabled_key) {
        const cb = document.getElementById(`st_${key}_enabled`);
        if (cb) payload[st.enabled_key] = cb.checked;
    }
    for (const s of (st.settings || [])) {
        const el = document.getElementById(`st_${key}_${s.key}`);
        if (el) { const n = parseInt(el.value, 10); if (!Number.isNaN(n)) payload[s.key] = n; }
    }
    const pt = document.getElementById(`st_${key}_prompt`);
    if (pt) payload[st.prompt_key] = pt.value;
    putSettings(payload, `Stufe „${st.label}" gespeichert`);
}

async function putSettings(payload, okMsg) {
    Object.keys(payload).forEach(k => {
        const v = payload[k];
        if (typeof v === 'number' && Number.isNaN(v)) delete payload[k];
    });
    try {
        const r = await fetch('/api/admin/settings', {
            method: 'PUT', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        const d = await r.json();
        if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
        toast(`${okMsg}: ${(d.updated || []).join(', ') || '—'}`, 'success');
        await loadWorkflow();
    } catch (e) {
        toast('Speichern fehlgeschlagen: ' + e.message, 'error');
    }
}

async function loadDefaultPrompt(source, targetId) {
    try {
        const r = await fetch(`/api/admin/agent/default-prompt?source=${encodeURIComponent(source)}`);
        const d = await r.json();
        if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
        const ta = document.getElementById(targetId);
        if (!ta) return;
        if (ta.value && !confirm('Aktuellen Prompt mit dem Default überschreiben?')) return;
        ta.value = d.default || '';
        toast('Default-Prompt geladen — noch nicht gespeichert.', 'info');
    } catch (e) {
        toast('Fehler: ' + e.message, 'error');
    }
}

function clearPromptField(id) {
    const ta = document.getElementById(id);
    if (ta && (!ta.value || confirm('Feld leeren? Beim Speichern greift der eingebaute Default-Prompt.'))) ta.value = '';
}

async function runNow(url) {
    try {
        const r = await fetch(url, { method: 'POST' });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        toast('Lauf angestoßen — Ergebnisse erscheinen unter /agent.html.', 'success');
    } catch (e) {
        toast('Fehler: ' + e.message, 'error');
    }
}

let toastTimer = null;
function toast(msg, type = 'info') {
    const el = document.getElementById('adminToast');
    if (!el) return;
    el.textContent = msg;
    el.className = `admin-toast toast-${type}`;
    el.classList.remove('hidden');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.add('hidden'), 5000);
}

// escapeHtml() lives in js/common.js

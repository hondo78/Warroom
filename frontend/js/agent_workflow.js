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

// Backend ships German text for pipeline/stage/field labels (the structure
// lives there). Prefer the i18n dict keyed by the stable id, fall back to the
// backend text when no translation exists. t() returns the key verbatim on a
// miss, which is how we detect "untranslated".
function wfT(key, fallback) {
    const v = t(key);
    return v === key ? fallback : v;
}
const stageLabel = st => wfT(`agentWorkflow.stages.${st.key}.label`, st.label);

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
        populateLearning(WF.global || {});
        renderStages(WF.stages || []);
        loadPatterns();
        const badge = document.getElementById('wfStructuredBadge');
        const on = !!(WF.global && WF.global.structured_output);
        badge.textContent = on ? t('agentWorkflow.structuredOn') : t('agentWorkflow.structuredOff');
        badge.className = 'badge ' + (on ? 'text-bg-success' : 'text-bg-secondary');
    } catch (e) {
        toast(t('agentWorkflow.loadFailed', { error: e.message }), 'error');
    }
}

function renderPipeline(steps) {
    document.getElementById('wfPipeline').innerHTML = steps.map((s, i) => {
        const step = wfT(`agentWorkflow.pipeline.${s.key}.step`, s.step);
        const detail = wfT(`agentWorkflow.pipeline.${s.key}.detail`, s.detail);
        return `<div class="wf-step"><h6>${i + 1}. ${escapeHtml(step)}</h6><small>${escapeHtml(detail)}</small></div>`;
    }).join('');
}

function populateGlobal(g) {
    document.getElementById('g_agent_enabled').checked = !!g.enabled;
    document.getElementById('g_agent_structured_output').checked = !!g.structured_output;
    document.getElementById('g_agent_model').value = g.model || '';
    document.getElementById('g_agent_temperature').value = g.temperature ?? 0.2;
    document.getElementById('g_agent_max_tokens').value = g.max_tokens ?? 3000;
    document.getElementById('g_agent_auto_execute').checked = !!g.auto_execute;
}

async function saveGlobal() {
    const payload = {
        agent_enabled: document.getElementById('g_agent_enabled').checked,
        agent_structured_output: document.getElementById('g_agent_structured_output').checked,
        agent_model: document.getElementById('g_agent_model').value,
        agent_temperature: parseFloat(document.getElementById('g_agent_temperature').value),
        agent_max_tokens: parseInt(document.getElementById('g_agent_max_tokens').value, 10),
        agent_auto_execute: document.getElementById('g_agent_auto_execute').checked,
    };
    await putSettings(payload, t('agentWorkflow.globalSaved'));
}

// --- Self-learning auto-approval ------------------------------------------

function populateLearning(g) {
    const en = document.getElementById('g_agent_learning_enabled');
    const th = document.getElementById('g_agent_learning_threshold');
    if (en) en.checked = !!g.learning_enabled;
    if (th) th.value = g.learning_threshold ?? 3;
}

async function saveLearning() {
    const payload = {
        agent_learning_enabled: document.getElementById('g_agent_learning_enabled').checked,
        agent_learning_threshold: parseInt(document.getElementById('g_agent_learning_threshold').value, 10),
    };
    await putSettings(payload, t('agentWorkflow.learnSaved'));
}

async function loadPatterns() {
    const tb = document.getElementById('wfPatterns');
    if (!tb) return;
    try {
        const r = await fetch('/api/agent/approval-patterns');
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const d = await r.json();
        renderPatterns(d.patterns || [], d.threshold);
    } catch (e) {
        tb.innerHTML = `<tr><td colspan="9" class="text-secondary">${t('agentWorkflow.error', { error: e.message })}</td></tr>`;
    }
}

function renderPatterns(patterns, threshold) {
    const tb = document.getElementById('wfPatterns');
    if (!tb) return;
    if (!patterns.length) {
        tb.innerHTML = `<tr><td colspan="9" class="text-secondary">${t('agentWorkflow.learnNoPatterns')}</td></tr>`;
        return;
    }
    tb.innerHTML = patterns.map(p => {
        const badge = p.eligible
            ? `<span class="badge text-bg-success">${t('agentWorkflow.learnEligible')}</span>`
            : `<span class="badge text-bg-secondary">${t('agentWorkflow.learnProgress', { n: p.net, t: threshold })}</span>`;
        const rule = p.rule ? escapeHtml(p.rule) : '<span class="text-secondary">—</span>';
        return `<tr>
            <td>${escapeHtml(p.source_type)}</td>
            <td><span class="badge wf-act text-bg-${ACT_COLOR[p.action] || 'secondary'}">${escapeHtml(p.action)}</span></td>
            <td>${rule}</td>
            <td class="text-end">${p.approvals}</td>
            <td class="text-end">${p.rejections}</td>
            <td class="text-end"><strong>${p.net}</strong></td>
            <td class="text-end">${p.auto_approved}</td>
            <td>${badge}</td>
            <td class="text-end"><button class="block-link" onclick="forgetPattern(${p.id})">${t('agentWorkflow.learnForget')}</button></td>
        </tr>`;
    }).join('');
}

async function forgetPattern(id) {
    if (!confirm(t('agentWorkflow.learnForgetConfirm'))) return;
    try {
        const r = await fetch(`/api/agent/approval-patterns/${id}`, { method: 'DELETE' });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        toast(t('agentWorkflow.learnForgotten'), 'success');
        loadPatterns();
    } catch (e) {
        toast(t('agentWorkflow.error', { error: e.message }), 'error');
    }
}

function renderStages(stages) {
    document.getElementById('wfStages').innerHTML = stages.map(st => {
        const off = st.enabled ? '' : 'wf-stage-off';
        const acts = (st.allowed_actions || []).map(a =>
            `<span class="badge wf-act text-bg-${ACT_COLOR[a] || 'secondary'}">${escapeHtml(a)}</span>`
        ).join(' ');
        const numFields = (st.settings || []).map(s =>
            `<div class="col-md-3"><label class="form-label">${escapeHtml(wfT(`agentWorkflow.fields.${s.key}`, s.label))}</label>
                <input type="number" class="form-control form-control-sm" id="st_${st.key}_${s.key}"
                       value="${s.value ?? ''}" min="${s.min ?? 0}" max="${s.max ?? 1000000}"></div>`
        ).join('');
        const enableToggle = st.enabled_key
            ? `<div class="form-check form-switch d-inline-block ms-2 align-middle"><input class="form-check-input" type="checkbox" id="st_${st.key}_enabled" ${st.enabled ? 'checked' : ''}></div>`
            : `<span class="badge text-bg-info ms-2">${t('agentWorkflow.onDemand')}</span>`;
        const promptVal = (SETTINGS && SETTINGS[st.prompt_key]) || '';
        const promptBadge = st.prompt_overridden
            ? `<span class="badge text-bg-warning">${t('agentWorkflow.promptCustom')}</span>`
            : `<span class="badge text-bg-secondary">${t('agentWorkflow.promptDefault')}</span>`;
        const runBtn = st.run_now
            ? `<button class="btn btn-outline-secondary btn-sm" onclick="runNow('${st.run_now}')"><i class="bi bi-play"></i> ${t('agentWorkflow.runNow')}</button>`
            : '';
        return `
        <div class="card mb-3 ${off}">
            <div class="card-header d-flex justify-content-between align-items-center flex-wrap gap-2">
                <h3 class="card-title mb-0">${escapeHtml(stageLabel(st))} ${enableToggle}</h3>
                <div>${acts}</div>
            </div>
            <div class="card-body">
                <p class="admin-hint mb-2"><strong>${t('agentWorkflow.triggerLabel')}</strong> ${escapeHtml(wfT(`agentWorkflow.stages.${st.key}.trigger`, st.trigger))} · ${promptBadge}</p>
                ${numFields ? `<div class="row g-2 align-items-end mb-1">${numFields}</div>` : ''}
                <label class="form-label mt-2">${t('agentWorkflow.systemPrompt')} <span class="text-secondary">${t('agentWorkflow.systemPromptHint')}</span></label>
                <textarea class="form-control form-control-sm wf-prompt" id="st_${st.key}_prompt" rows="10" placeholder="${escapeHtml(t('agentWorkflow.promptPlaceholder', { stage: stageLabel(st) }))}">${escapeHtml(promptVal)}</textarea>
                <div class="d-flex justify-content-between gap-2 mt-2 flex-wrap">
                    <div>${runBtn}</div>
                    <div class="d-flex gap-2 flex-wrap">
                        <button class="btn btn-outline-secondary btn-sm" onclick="loadDefaultPrompt('${st.prompt_source}','st_${st.key}_prompt')"><i class="bi bi-arrow-counterclockwise"></i> ${t('agentWorkflow.loadDefault')}</button>
                        <button class="btn btn-outline-secondary btn-sm" onclick="clearPromptField('st_${st.key}_prompt')"><i class="bi bi-eraser"></i> ${t('agentWorkflow.clear')}</button>
                        <button class="btn btn-primary btn-sm" onclick="saveStage('${st.key}')">${t('agentWorkflow.saveStage')}</button>
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
    putSettings(payload, t('agentWorkflow.stageSaved', { stage: stageLabel(st) }));
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
        toast(`${okMsg}: ${(d.updated || []).join(', ') || t('common.none')}`, 'success');
        await loadWorkflow();
    } catch (e) {
        toast(t('agentWorkflow.saveFailed', { error: e.message }), 'error');
    }
}

async function loadDefaultPrompt(source, targetId) {
    try {
        const r = await fetch(`/api/admin/agent/default-prompt?source=${encodeURIComponent(source)}`);
        const d = await r.json();
        if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
        const ta = document.getElementById(targetId);
        if (!ta) return;
        if (ta.value && !confirm(t('agentWorkflow.confirmOverwrite'))) return;
        ta.value = d.default || '';
        toast(t('agentWorkflow.defaultLoaded'), 'info');
    } catch (e) {
        toast(t('agentWorkflow.error', { error: e.message }), 'error');
    }
}

function clearPromptField(id) {
    const ta = document.getElementById(id);
    if (ta && (!ta.value || confirm(t('agentWorkflow.confirmClear')))) ta.value = '';
}

async function runNow(url) {
    try {
        const r = await fetch(url, { method: 'POST' });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        toast(t('agentWorkflow.runStarted'), 'success');
    } catch (e) {
        toast(t('agentWorkflow.error', { error: e.message }), 'error');
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

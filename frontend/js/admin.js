const SECTIONS = {
    sophos: ['sophos_client_id', 'sophos_client_secret', 'sophos_tenant_id'],
    geoip: ['maxmind_license_key', 'abuseipdb_api_key', 'virustotal_api_key', 'shodan_api_key', 'sophos_intelix_client_id', 'sophos_intelix_client_secret'],
    osintQuota: [
        'osint_abuseipdb_daily_limit', 'osint_abuseipdb_monthly_limit',
        'osint_virustotal_daily_limit', 'osint_virustotal_monthly_limit',
        'osint_shodan_daily_limit', 'osint_shodan_monthly_limit',
        'osint_greynoise_daily_limit', 'osint_greynoise_monthly_limit',
        'osint_intelix_daily_limit', 'osint_intelix_monthly_limit',
        'osint_ipinfo_daily_limit', 'osint_ipinfo_monthly_limit',
    ],
    general: ['collector_interval', 'log_level', 'dashboard_title'],
    agent: ['agent_enabled', 'agent_provider', 'agent_base_url', 'agent_api_key', 'agent_model', 'agent_interval_seconds', 'agent_auto_execute', 'agent_auto_execute_threshold', 'agent_system_prompt', 'agent_waf_enabled', 'agent_waf_threshold', 'agent_waf_interval_seconds', 'agent_ips_enabled', 'agent_ips_threshold', 'agent_ips_interval_seconds', 'agent_failed_login_enabled', 'agent_failed_login_threshold', 'agent_failed_login_interval_seconds', 'agent_failed_login_subnet_attempts', 'agent_failed_login_subnet_min_ips'],
};

document.addEventListener('DOMContentLoaded', () => {
    loadSettings();
    const feed = document.getElementById('iocFeedUrl');
    if (feed) feed.textContent = `${window.location.origin}/ioc_IP`;
    const feedDomain = document.getElementById('iocFeedDomainUrl');
    if (feedDomain) feedDomain.textContent = `${window.location.origin}/ioc_domain`;
    const feedUrl = document.getElementById('iocFeedUrlUrl');
    if (feedUrl) feedUrl.textContent = `${window.location.origin}/ioc_url`;
});

async function loadSettings() {
    try {
        const resp = await fetch('/api/admin/settings');
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const data = await resp.json();
        applyToForm(data);
    } catch (err) {
        toast(`Fehler beim Laden: ${err.message}`, 'error');
    }
}

function applyToForm(data) {
    document.querySelectorAll('[data-key]').forEach(el => {
        const key = el.dataset.key;
        if (!(key in data)) return;
        const value = data[key];

        // Secret fields: API returns {is_set: bool, value: ""}.
        // Show empty input but mark via placeholder whether a value is stored.
        if (el.dataset.secret === '1') {
            if (value && typeof value === 'object' && 'is_set' in value) {
                el.value = '';
                el.placeholder = value.is_set
                    ? '••• gespeichert (leer lassen, um nicht zu ändern)'
                    : 'Nicht gesetzt';
            }
            return;
        }

        if (el.type === 'checkbox' || el.dataset.bool === '1') {
            el.checked = !!value;
        } else {
            el.value = value !== null && value !== undefined ? value : '';
        }
    });

    const ro = data._readonly || {};
    setText('roDbUrl', ro.database_url || '-');
    setText('roRedisUrl', ro.redis_url || '-');
    const apiKeyEl = document.getElementById('roApiKey');
    if (apiKeyEl) {
        apiKeyEl.innerHTML = ro.warroom_api_key_is_set
            ? '<span class="health-badge health-good">gesetzt</span>'
            : '<span class="health-badge health-bad">leer (Open Mode)</span>';
    }
}

function setText(id, txt) {
    const el = document.getElementById(id);
    if (el) el.textContent = txt;
}

async function saveSection(section) {
    const keys = SECTIONS[section];
    if (!keys) return;
    const payload = {};
    for (const key of keys) {
        const el = document.querySelector(`[data-key="${key}"]`);
        if (!el) continue;
        if (el.dataset.secret === '1') {
            // Empty secret field => keep stored value (skip from payload)
            if (el.value === '') continue;
            payload[key] = el.value;
        } else if (el.type === 'checkbox' || el.dataset.bool === '1') {
            payload[key] = el.checked;
        } else if (el.type === 'number') {
            const n = parseInt(el.value, 10);
            if (!Number.isNaN(n)) payload[key] = n;
        } else {
            payload[key] = el.value;
        }
    }

    if (Object.keys(payload).length === 0) {
        toast('Keine Änderungen.', 'info');
        return;
    }

    try {
        const resp = await fetch('/api/admin/settings', {
            method: 'PUT',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload),
        });
        const data = await resp.json();
        if (!resp.ok) {
            throw new Error(data.detail || `HTTP ${resp.status}`);
        }
        applyToForm(data.settings);
        toast(`Gespeichert: ${data.updated.join(', ')}`, 'success');
    } catch (err) {
        toast(`Fehler beim Speichern: ${err.message}`, 'error');
    }
}

async function testConnection(target) {
    toast(`Teste ${target}…`, 'info');
    try {
        const resp = await fetch(`/api/admin/test/${target}`, {method: 'POST'});
        const data = await resp.json();
        if (data.ok) {
            const detail = target === 'sophos' && data.tenant_id
                ? ` Tenant: ${data.tenant_id}`
                : '';
            toast(`✓ ${target} OK.${detail}`, 'success');
        } else {
            toast(`✗ ${target}: ${data.error || 'unbekannter Fehler'}`, 'error');
        }
    } catch (err) {
        toast(`Test-Fehler: ${err.message}`, 'error');
    }
}

async function loadAgentModels() {
    toast('Lade Modelle vom Agent-Endpoint…', 'info');
    try {
        const resp = await fetch('/api/admin/agent/models');
        const data = await resp.json();
        if (!data.ok) {
            toast(`Modell-Liste fehlgeschlagen: ${data.error}`, 'error');
            return;
        }
        const sel = document.getElementById('agentModelSelect');
        if (!sel) return;
        sel.innerHTML = '<option value="">— verfügbare Modelle —</option>' +
            (data.models || []).map(m => `<option value="${m}">${m}</option>`).join('');
        toast(`${(data.models || []).length} Modell(e) gefunden.`, 'success');
    } catch (err) {
        toast(`Fehler: ${err.message}`, 'error');
    }
}

async function agentRunNow() {
    try {
        const resp = await fetch('/api/agent/run-now', {method: 'POST'});
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        toast('Agent-Lauf angestoßen. Empfehlungen erscheinen im Dashboard.', 'success');
    } catch (err) {
        toast(`Fehler: ${err.message}`, 'error');
    }
}

async function loadAgentDefaultPrompt() {
    try {
        const r = await fetch('/api/admin/agent/default-prompt');
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const d = await r.json();
        const ta = document.getElementById('agentSystemPrompt');
        if (!ta) return;
        if (ta.value && !confirm('Den aktuellen Prompt mit dem Default überschreiben?')) return;
        ta.value = d.default || '';
        toast('Default-Prompt geladen — noch nicht gespeichert.', 'info');
    } catch (err) {
        toast(`Fehler: ${err.message}`, 'error');
    }
}

function clearAgentPrompt() {
    const ta = document.getElementById('agentSystemPrompt');
    if (!ta) return;
    if (ta.value && !confirm('Feld leeren? Beim Speichern wird dann der eingebaute Default-Prompt verwendet.')) return;
    ta.value = '';
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

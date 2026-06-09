const SECTIONS = {
    sophos: ['sophos_client_id', 'sophos_client_secret', 'sophos_tenant_id'],
    o365: ['o365_tenant_id', 'o365_client_id', 'o365_client_secret'],
    entra: ['entra_block_enabled', 'entra_block_sync_interval_minutes', 'entra_ca_exclude_users'],
    telegram: ['telegram_enabled', 'telegram_bot_token', 'telegram_chat_id', 'telegram_poll_interval_seconds'],
    teams: ['teams_outgoing_secret', 'teams_incoming_webhook'],
    geoip: ['maxmind_license_key', 'abuseipdb_api_key', 'virustotal_api_key', 'shodan_api_key', 'shodan_auto_on_malicious', 'shodan_auto_abuse_threshold', 'sophos_intelix_client_id', 'sophos_intelix_client_secret'],
    osintQuota: [
        'osint_abuseipdb_daily_limit', 'osint_abuseipdb_monthly_limit',
        'osint_virustotal_daily_limit', 'osint_virustotal_monthly_limit',
        'osint_shodan_daily_limit', 'osint_shodan_monthly_limit',
        'osint_greynoise_daily_limit', 'osint_greynoise_monthly_limit',
        'osint_intelix_daily_limit', 'osint_intelix_monthly_limit',
        'osint_ipinfo_daily_limit', 'osint_ipinfo_monthly_limit',
    ],
    general: ['collector_interval', 'log_level', 'dashboard_title'],
    firewallRetention: ['firewall_log_retention_enabled', 'firewall_log_connection_retention_days', 'firewall_log_retention_days'],
    agent: ['agent_enabled', 'agent_provider', 'agent_base_url', 'agent_api_key', 'agent_model', 'agent_interval_seconds', 'agent_temperature', 'agent_max_tokens', 'agent_auto_execute', 'agent_auto_execute_threshold', 'agent_waf_enabled', 'agent_waf_threshold', 'agent_waf_interval_seconds', 'agent_ips_enabled', 'agent_ips_threshold', 'agent_ips_interval_seconds', 'agent_failed_login_enabled', 'agent_failed_login_threshold', 'agent_failed_login_interval_seconds', 'agent_failed_login_subnet_attempts', 'agent_failed_login_subnet_min_ips', 'agent_failed_login_distributed_enabled', 'agent_failed_login_distributed_window_minutes', 'agent_failed_login_distributed_attempts', 'agent_failed_login_distributed_min_ips'],
    // System-Prompts werden auf /agent-workflow.html bearbeitet (nicht mehr hier).
};

document.addEventListener('DOMContentLoaded', () => {
    loadSettings();
    loadCaPolicyState();
    const feed = document.getElementById('iocFeedUrl');
    if (feed) feed.textContent = `${window.location.origin}/ioc_IP`;
    const feedDomain = document.getElementById('iocFeedDomainUrl');
    if (feedDomain) feedDomain.textContent = `${window.location.origin}/ioc_domain`;
    const feedUrl = document.getElementById('iocFeedUrlUrl');
    if (feedUrl) feedUrl.textContent = `${window.location.origin}/ioc_url`;
});

// admin.html doesn't load common.js, so provide a local HTML-escape.
function adminEsc(str) {
    return String(str ?? '').replace(/[&<>"']/g, c => (
        { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
    ));
}

// --- Conditional-Access block policy on/off ---
async function loadCaPolicyState() {
    const status = document.getElementById('caPolicyStatus');
    const toggle = document.getElementById('caPolicyToggle');
    const label = document.getElementById('caPolicyToggleLabel');
    if (!status || !toggle) return;
    try {
        const r = await fetch('/api/admin/entra/ca-policy');
        const d = await r.json();
        if (!d.configured) {
            status.innerHTML = 'M365-App nicht konfiguriert.';
            toggle.disabled = true; label.textContent = '—';
            return;
        }
        if (!d.found) {
            status.innerHTML = d.error
                ? `Keine Policy gefunden (${adminEsc(d.error)}).`
                : 'Keine Warroom-Policy gefunden. Lege sie im Entra-Portal an oder nutze „Jetzt syncen“.';
            toggle.disabled = true; label.textContent = '—';
            return;
        }
        toggle.disabled = false;
        toggle.checked = d.enabled;
        toggle.dataset.excludes = d.exclude_users || '';
        label.textContent = d.enabled ? 'Erzwingung AN' : 'Erzwingung AUS';
        const stateBadge = d.state === 'enabled'
            ? '<span class="health-badge health-bad">erzwingend</span>'
            : d.state === 'disabled'
                ? '<span class="health-badge health-good">deaktiviert</span>'
                : `<span class="health-badge">${adminEsc(d.state)}</span>`;
        status.innerHTML = `Policy: <strong>${adminEsc(d.displayName || "—")}</strong> &nbsp; ${stateBadge}`;
    } catch (err) {
        status.textContent = `Status nicht abrufbar: ${err.message}`;
        toggle.disabled = true;
    }
}

async function toggleCaPolicy(el) {
    const enabled = el.checked;
    const payload = { enabled };

    // When ACTIVATING (enforcing), ask for / confirm the break-glass accounts
    // that must never be blocked. Pre-fill with whatever is already stored.
    if (enabled) {
        const current = el.dataset.excludes || '';
        const input = prompt(
            'Erzwingung aktivieren — ausgeschlossene Konten (Break-Glass), die nie geblockt werden.\n' +
            'UPN(s) oder Objekt-ID(s), kommagetrennt. Mindestens eines ist erforderlich:',
            current
        );
        if (input === null) {            // user cancelled → revert toggle, do nothing
            el.checked = false;
            return;
        }
        if (!input.trim()) {
            toast('Mindestens ein Break-Glass-Konto erforderlich — Aktivierung abgebrochen.', 'error');
            el.checked = false;
            return;
        }
        payload.exclude_users = input.trim();
    }

    el.disabled = true;
    try {
        const r = await fetch('/api/admin/entra/ca-policy', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        const d = await r.json();
        if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
        toast(`Policy ${enabled ? 'aktiviert (erzwingend)' : 'deaktiviert'}.`, 'success');
    } catch (err) {
        toast(`Umschalten fehlgeschlagen: ${err.message}`, 'error');
        el.checked = !enabled; // revert visual state
    } finally {
        el.disabled = false;
        loadCaPolicyState();
    }
}

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
        } else if (el.dataset.float === '1') {
            const f = parseFloat(el.value);
            if (!Number.isNaN(f)) payload[key] = f;
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

async function entraSyncNow() {
    toast('Entra-Sync läuft…', 'info');
    try {
        const resp = await fetch('/api/admin/entra/sync-now', { method: 'POST' });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.detail || `HTTP ${resp.status}`);
        toast(`✓ ${data.ranges} IP-Range(s) zu Entra synchronisiert.`, 'success');
    } catch (err) {
        toast(`Entra-Sync fehlgeschlagen: ${err.message}`, 'error');
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

async function runFirewallRetention() {
    if (!confirm('Firewall-Log-Retention jetzt ausführen? Alte Logs werden batchweise im Hintergrund gelöscht (kann je nach Rückstand einige Minuten dauern).')) return;
    try {
        const resp = await fetch('/api/admin/firewall-retention/run-now', { method: 'POST' });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        toast('Retention-Lauf angestoßen — Löschung läuft im Hintergrund.', 'success');
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

const SECTIONS = {
    sophos: ['sophos_client_id', 'sophos_client_secret', 'sophos_tenant_id'],
    o365: ['o365_tenant_id', 'o365_client_id', 'o365_client_secret'],
    hostnames: ['hostname_resolve_enabled', 'internal_dns_servers', 'hostname_netbios_enabled', 'hostname_cache_ttl_hours', 'hostname_negative_ttl_hours',
        'firewall_api_enabled', 'firewall_api_host', 'firewall_api_port', 'firewall_api_user', 'firewall_api_password', 'firewall_api_verify_tls', 'firewall_dhcp_entity', 'firewall_dhcp_refresh_seconds'],
    entra: ['entra_block_enabled', 'entra_block_sync_interval_minutes', 'entra_ca_exclude_users'],
    telegram: ['telegram_enabled', 'telegram_bot_token', 'telegram_chat_id', 'telegram_poll_interval_seconds'],
    teams: ['teams_outgoing_secret', 'teams_incoming_webhook'],
    analyst: ['analyst_system_prompt', 'chat_sql_enabled'],
    geoip: ['maxmind_license_key', 'abuseipdb_api_key', 'virustotal_api_key', 'shodan_api_key', 'shodan_auto_every_lookup', 'shodan_auto_on_malicious', 'shodan_auto_abuse_threshold', 'sophos_intelix_client_id', 'sophos_intelix_client_secret'],
    osintQuota: [
        'osint_abuseipdb_daily_limit', 'osint_abuseipdb_monthly_limit',
        'osint_virustotal_daily_limit', 'osint_virustotal_monthly_limit',
        'osint_shodan_daily_limit', 'osint_shodan_monthly_limit',
        'osint_greynoise_daily_limit', 'osint_greynoise_monthly_limit',
        'osint_intelix_daily_limit', 'osint_intelix_monthly_limit',
        'osint_ipinfo_daily_limit', 'osint_ipinfo_monthly_limit',
    ],
    firewallFeed: ['firewall_threat_feed_enabled', 'firewall_mdr_feed_enabled', 'firewall_mdr_feed_firewall_ids', 'firewall_mdr_feed_sync_interval_seconds'],
    general: ['collector_interval', 'log_level', 'dashboard_title'],
    firewallRetention: ['firewall_log_retention_enabled', 'firewall_log_connection_retention_days', 'firewall_log_retention_days'],
    mcp: ['mcp_enabled', 'mcp_api_key'],
    auth: ['auth_enabled'],
    agent: ['agent_enabled', 'agent_provider', 'agent_base_url', 'agent_api_key', 'agent_model', 'agent_interval_seconds', 'agent_temperature', 'agent_max_tokens', 'agent_auto_execute', 'agent_language', 'agent_event_enabled', 'agent_event_interval_seconds', 'agent_event_types', 'agent_waf_enabled', 'agent_waf_threshold', 'agent_waf_interval_seconds', 'agent_ips_enabled', 'agent_ips_threshold', 'agent_ips_interval_seconds', 'agent_failed_login_enabled', 'agent_failed_login_threshold', 'agent_failed_login_interval_seconds', 'agent_failed_login_subnet_attempts', 'agent_failed_login_subnet_min_ips', 'agent_failed_login_distributed_enabled', 'agent_failed_login_distributed_window_minutes', 'agent_failed_login_distributed_attempts', 'agent_failed_login_distributed_min_ips', 'agent_failed_login_network_block_enabled'],
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
    const mcpUrl = document.getElementById('mcpUrl');
    if (mcpUrl) mcpUrl.textContent = `${window.location.origin}/mcp/`;
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
            status.innerHTML = t('admin.caM365NotConfigured');
            toggle.disabled = true; label.textContent = '—';
            return;
        }
        if (!d.found) {
            status.innerHTML = d.error
                ? t('admin.caNoPolicyError', { error: adminEsc(d.error) })
                : t('admin.caNoPolicy');
            toggle.disabled = true; label.textContent = '—';
            return;
        }
        toggle.disabled = false;
        toggle.checked = d.enabled;
        toggle.dataset.excludes = d.exclude_users || '';
        label.textContent = d.enabled ? t('admin.enforcementOn') : t('admin.enforcementOff');
        const stateBadge = d.state === 'enabled'
            ? `<span class="health-badge health-bad">${t('admin.stateEnforcing')}</span>`
            : d.state === 'disabled'
                ? `<span class="health-badge health-good">${t('admin.stateDisabled')}</span>`
                : `<span class="health-badge">${adminEsc(d.state)}</span>`;
        status.innerHTML = t('admin.caPolicyStatus', { name: adminEsc(d.displayName || "—"), badge: stateBadge });
    } catch (err) {
        status.textContent = t('admin.statusUnavailable', { error: err.message });
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
            t('admin.enforcePrompt'),
            current
        );
        if (input === null) {            // user cancelled → revert toggle, do nothing
            el.checked = false;
            return;
        }
        if (!input.trim()) {
            toast(t('admin.breakGlassRequired'), 'error');
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
        toast(enabled ? t('admin.policyEnabled') : t('admin.policyDisabled'), 'success');
    } catch (err) {
        toast(t('admin.toggleFailed', { error: err.message }), 'error');
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
        toast(t('admin.loadError', { error: err.message }), 'error');
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
                    ? t('admin.secretStored')
                    : t('admin.secretNotSet');
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
            ? `<span class="health-badge health-good">${t('admin.apiKeySet')}</span>`
            : `<span class="health-badge health-bad">${t('admin.apiKeyEmpty')}</span>`;
    }
}

function setText(id, txt) {
    const el = document.getElementById(id);
    if (el) el.textContent = txt;
}

// Test the Sophos Firewall DHCP read with the currently SAVED settings.
// Always requests debug so we can show the firewall's raw response when nothing
// (or an error) comes back — that's what reveals the right entity/schema.
async function testFirewallDhcp(btn) {
    const out = document.getElementById('fwDhcpTestResult');
    const raw = document.getElementById('fwDhcpRaw');
    if (raw) { raw.style.display = 'none'; raw.textContent = ''; }
    if (out) { out.className = 'ms-2 small text-secondary'; out.textContent = t('admin.fwDhcpTesting'); }
    if (btn) btn.disabled = true;
    try {
        const r = await fetch('/api/firewall/dhcp/test?debug=1', { method: 'POST' });
        const d = await r.json().catch(() => ({}));
        const ok = d.ok && (d.count > 0);
        if (ok) {
            const s = (d.sample || []).map(x => x.ip + '→' + x.hostname).slice(0, 3).join(', ');
            out.className = 'ms-2 small text-success';
            out.textContent = t('admin.fwDhcpOk', { n: d.count }) + (s ? ' · ' + s : '');
        } else {
            out.className = 'ms-2 small text-warning';
            out.textContent = d.ok ? t('admin.fwDhcpZero') : (d.error || ('HTTP ' + r.status));
            if (raw && (d.raw || d.http_status != null)) {
                raw.style.display = 'block';
                let ent = '';
                if (d.entities) {
                    ent = 'Entities:\n' + Object.entries(d.entities).map(([k, v]) =>
                        `  ${k}: ${v.count > 0 ? v.count + ' record(s)' : (v.code ? 'code ' + v.code + ' ' + (v.status || '') : '—')}`).join('\n') + '\n\n';
                }
                raw.textContent = `HTTP ${d.http_status ?? '?'}\n\n${ent}${d.raw || '(no body)'}`;
            }
        }
    } catch (err) {
        if (out) { out.className = 'ms-2 small text-danger'; out.textContent = err.message; }
    } finally {
        if (btn) btn.disabled = false;
    }
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
        toast(t('admin.noChanges'), 'info');
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
        toast(t('admin.saved', { items: data.updated.join(', ') }), 'success');
    } catch (err) {
        toast(t('admin.saveError', { error: err.message }), 'error');
    }
}

async function testConnection(target) {
    toast(t('admin.testing', { target }), 'info');
    try {
        const resp = await fetch(`/api/admin/test/${target}`, {method: 'POST'});
        const data = await resp.json();
        if (data.ok) {
            const detail = target === 'sophos' && data.tenant_id
                ? t('admin.testTenant', { tenant: data.tenant_id })
                : '';
            toast(t('admin.testOk', { target, detail }), 'success');
        } else {
            toast(t('admin.testFail', { target, error: data.error || t('admin.unknownError') }), 'error');
        }
    } catch (err) {
        toast(t('admin.testError', { error: err.message }), 'error');
    }
}

async function syncMdrFeed() {
    toast(t('admin.mdrPushing'), 'info');
    try {
        const resp = await fetch('/api/firewall/mdr-feed/sync', { method: 'POST' });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.detail || `HTTP ${resp.status}`);
        if (data.skipped) { toast(t('admin.mdrSkipped', { reason: data.skipped }), 'info'); return; }
        const fws = data.firewalls || [];
        if (!fws.length) { toast(t('admin.mdrNoTargets', { note: data.note || '—' }), 'info'); return; }
        const failed = fws.filter(f => f.error);
        const pushed = fws.reduce((s, f) => s + (f.pushed || 0), 0);
        const rejected = fws.reduce((s, f) => s + (f.rejected ? f.rejected.length : 0), 0);
        if (failed.length === fws.length) {
            toast(t('admin.mdrPushFailed', { details: failed.map(f => f.firewall_id + ' (' + f.error + ')').join('; ') }), 'error');
        } else if (rejected || failed.length) {
            toast(t('admin.mdrPartial', { pushed, rejected }) + (failed.length ? t('admin.mdrPartialFailed', { n: failed.length }) : '') + '.', 'info');
        } else {
            toast(t('admin.mdrPushOk', { pushed, n: fws.length }), 'success');
        }
    } catch (err) {
        toast(t('admin.mdrPushFailedErr', { error: err.message }), 'error');
    }
}

async function verifyMdrFeed() {
    toast(t('admin.mdrVerifying'), 'info');
    try {
        const resp = await fetch('/api/firewall/mdr-feed/verify', { method: 'POST' });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.detail || `HTTP ${resp.status}`);
        if (data.error) { toast(t('admin.mdrVerifyError', { error: data.error }), 'info'); return; }
        const fws = data.firewalls || [];
        if (!fws.length) { toast(t('admin.mdrVerifyNone'), 'info'); return; }
        const parts = fws.map(f =>
            t('admin.mdrVerifyPart', { id: f.firewall_id.slice(0, 8), completed: f.completed, total: f.transactions }) +
            (f.pending ? t('admin.mdrVerifyPending', { n: f.pending }) : '') +
            (f.failed ? t('admin.mdrVerifyFailedPart', { n: f.failed }) : ''));
        const allApplied = fws.every(f => f.applied);
        const anyFailed = fws.some(f => f.failed);
        toast(t('admin.mdrVerifyResult', { at: data.pushed_at ? new Date(data.pushed_at).toLocaleString() : '—', parts: parts.join(' | ') }),
              allApplied ? 'success' : anyFailed ? 'error' : 'info');
    } catch (err) {
        toast(t('admin.mdrVerifyFailed', { error: err.message }), 'error');
    }
}

async function entraSyncNow() {
    toast(t('admin.entraSyncing'), 'info');
    try {
        const resp = await fetch('/api/admin/entra/sync-now', { method: 'POST' });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.detail || `HTTP ${resp.status}`);
        toast(t('admin.entraSyncOk', { ranges: data.ranges }), 'success');
    } catch (err) {
        toast(t('admin.entraSyncFailed', { error: err.message }), 'error');
    }
}

async function resetAnalystPersona() {
    try {
        const r = await fetch('/api/chat/default-persona');
        const d = await r.json();
        const ta = document.querySelector('[data-key="analyst_system_prompt"]');
        if (ta && d.prompt) { ta.value = d.prompt; toast(t('admin.personaLoaded'), 'info'); }
    } catch (err) {
        toast(t('admin.personaLoadFailed', { error: err.message }), 'error');
    }
}

async function loadAgentModels() {
    toast(t('admin.loadingModels'), 'info');
    try {
        const resp = await fetch('/api/admin/agent/models');
        const data = await resp.json();
        if (!data.ok) {
            toast(t('admin.modelListFailed', { error: data.error }), 'error');
            return;
        }
        const sel = document.getElementById('agentModelSelect');
        if (!sel) return;
        sel.innerHTML = `<option value="">${t('admin.availableModels')}</option>` +
            (data.models || []).map(m => `<option value="${m}">${m}</option>`).join('');
        toast(t('admin.modelsFound', { n: (data.models || []).length }), 'success');
    } catch (err) {
        toast(t('admin.errorGeneric', { error: err.message }), 'error');
    }
}

async function runFirewallRetention() {
    if (!confirm(t('admin.retentionConfirm'))) return;
    try {
        const resp = await fetch('/api/admin/firewall-retention/run-now', { method: 'POST' });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        toast(t('admin.retentionStarted'), 'success');
    } catch (err) {
        toast(t('admin.errorGeneric', { error: err.message }), 'error');
    }
}

async function agentRunNow() {
    try {
        const resp = await fetch('/api/agent/run-now', {method: 'POST'});
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        toast(t('admin.agentRunStarted'), 'success');
    } catch (err) {
        toast(t('admin.errorGeneric', { error: err.message }), 'error');
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


// --- Users, roles & audit (only meaningful when auth is enabled) -------------
document.addEventListener('DOMContentLoaded', () => { loadUsers(); });

async function loadUsers() {
    const tb = document.getElementById('userTable');
    if (!tb) return;
    try {
        const r = await fetch('/api/auth/users');
        if (!r.ok) { tb.innerHTML = ''; return; }
        const d = await r.json();
        tb.innerHTML = (d.users || []).map(u => `<tr>
            <td>${adminEsc(u.username)}</td>
            <td><select class="form-select form-select-sm" style="width:auto;display:inline-block" onchange="updateRole(${u.id}, this.value)">
                ${['viewer', 'analyst', 'admin'].map(r => `<option value="${r}"${r === u.role ? ' selected' : ''}>${r}</option>`).join('')}
            </select></td>
            <td class="admin-hint">${u.last_login ? new Date(u.last_login).toLocaleString() : '—'}</td>
            <td><button class="btn btn-outline-danger btn-sm py-0" onclick="deleteUser(${u.id}, '${adminEsc(u.username)}')"><i class="bi bi-trash"></i></button></td>
        </tr>`).join('') || `<tr><td colspan="4" class="admin-hint">${t('admin.authNoUsers') || 'Keine Benutzer / no users'}</td></tr>`;
    } catch (e) { /* ignore */ }
}

async function createUser() {
    const username = document.getElementById('newUser').value.trim();
    const password = document.getElementById('newPass').value;
    const role = document.getElementById('newRole').value;
    if (!username || password.length < 6) { alert(t('admin.authPwShort') || 'Benutzername + Passwort (min. 6 Zeichen) nötig.'); return; }
    const r = await fetch('/api/auth/users', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password, role }),
    });
    if (!r.ok) { const e = await r.json().catch(() => ({})); alert((e.detail || 'Fehler')); return; }
    document.getElementById('newUser').value = ''; document.getElementById('newPass').value = '';
    loadUsers();
}

async function updateRole(id, role) {
    const r = await fetch(`/api/auth/users/${id}`, {
        method: 'PATCH', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ role }),
    });
    if (!r.ok) { const e = await r.json().catch(() => ({})); alert(e.detail || 'Fehler'); loadUsers(); }
}

async function deleteUser(id, name) {
    if (!confirm((t('admin.authDelConfirm') || 'Benutzer löschen?') + ' ' + name)) return;
    const r = await fetch(`/api/auth/users/${id}`, { method: 'DELETE' });
    if (!r.ok) { const e = await r.json().catch(() => ({})); alert(e.detail || 'Fehler'); }
    loadUsers();
}

async function loadAudit() {
    const tb = document.getElementById('auditTable');
    if (!tb) return;
    try {
        const r = await fetch('/api/audit?limit=200');
        if (!r.ok) { tb.innerHTML = `<tr><td colspan="5" class="admin-hint">${t('admin.authAuditNeedAdmin') || 'Nur für Admins bei aktiver Anmeldung.'}</td></tr>`; return; }
        const d = await r.json();
        tb.innerHTML = (d.entries || []).map(e => `<tr>
            <td>${e.created_at ? new Date(e.created_at).toLocaleString() : ''}</td>
            <td>${adminEsc(e.username || '—')}</td>
            <td><code>${adminEsc(e.method)} ${adminEsc(e.path)}</code></td>
            <td><span class="badge ${e.status >= 400 ? 'text-bg-danger' : 'text-bg-secondary'}">${e.status}</span></td>
            <td class="admin-hint">${adminEsc(e.ip || '')}</td>
        </tr>`).join('') || `<tr><td colspan="5" class="admin-hint">—</td></tr>`;
    } catch (e) { /* ignore */ }
}

// Tor-only Kali box: status, target allow-list, and the command audit trail
// with the human-in-the-loop approve/reject workflow.
// True while a command is in flight. The 20s status poll re-enables the run
// button from loadKaliStatus(), which used to undo the in-flight guard below and
// let a second click send the same command through the box a second time — one
// operator approval, two executions.
let K_RUNNING = false;
const K_LOCALE = (typeof currentLang === 'function' && currentLang() === 'de') ? 'de-DE' : 'en-US';

document.addEventListener('DOMContentLoaded', () => {
    refreshKali();
    setInterval(refreshKali, 20000);

    const input = document.getElementById('kInput');
    if (input) {
        input.addEventListener('keydown', e => {
            if (e.key === 'Enter') { e.preventDefault(); runKaliCommand(); }
        });
        // Debounced so a fast typist does not fire a request per keystroke.
        let timer = null;
        input.addEventListener('input', () => {
            clearTimeout(timer);
            timer = setTimeout(checkKaliCommand, 350);
        });
    }
});

// --- Console -----------------------------------------------------------------
// The guards are strict by design, so the console says up front whether a
// command will be accepted. That check writes nothing: without it every typo
// would land in the audit trail as a "blocked" row and bury the real ones.

let K_LAST_CHECK = null;

async function checkKaliCommand() {
    const el = document.getElementById('kCheck');
    const command = document.getElementById('kInput').value.trim();
    if (!command) { el.innerHTML = ''; K_LAST_CHECK = null; return; }
    try {
        const r = await fetch('/api/kali/check', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ command }),
        });
        const d = await r.json();
        K_LAST_CHECK = d;
        if (d.allowed) {
            const msg = (d.targets && d.targets.length)
                ? t('kali.console_ok', { targets: d.targets.join(', ') })
                : t('kali.console_ok_notarget');
            el.innerHTML = `<span class="text-success"><i class="bi bi-check-circle"></i> ${escapeHtml(msg)}</span>`;
        } else {
            el.innerHTML = `<span class="text-warning"><i class="bi bi-exclamation-triangle"></i> ${escapeHtml(t('kali.console_blocked', { reason: d.reason || '' }))}</span>`;
        }
    } catch (e) { el.innerHTML = ''; K_LAST_CHECK = null; }
}

async function runKaliCommand() {
    const input = document.getElementById('kInput');
    const btn = document.getElementById('kRunBtn');
    const out = document.getElementById('kResult');
    const command = input.value.trim();
    if (!command) return;

    K_RUNNING = true;
    btn.disabled = true;
    out.innerHTML = `<span class="text-secondary" style="font-size:.8rem">${t('kali.console_running')}</span>`;
    try {
        const r = await fetch('/api/kali/commands', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ command }),
        });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
        renderKaliResult(d);
        // Only clear the input on a run that actually reached the box — a
        // refused command stays put so it can be corrected instead of retyped.
        if (d.status === 'done') { input.value = ''; document.getElementById('kCheck').innerHTML = ''; }
        refreshKali();
    } catch (e) {
        out.innerHTML = `<div class="detail-error" style="font-size:.8rem;text-align:left;padding:0">${escapeHtml(t('kali.console_error', { reason: e.message }))}</div>`;
    } finally {
        K_RUNNING = false;
        btn.disabled = false;
    }
}

function renderKaliResult(d) {
    const out = document.getElementById('kResult');
    if (d.status === 'blocked') {
        out.innerHTML = `<div class="text-warning" style="font-size:.8rem"><i class="bi bi-shield-x"></i> ${escapeHtml(t('kali.console_blocked', { reason: d.reason || '' }))}</div>`;
        return;
    }
    if (d.status === 'error') {
        out.innerHTML = `<div class="detail-error" style="font-size:.8rem;text-align:left;padding:0">${escapeHtml(t('kali.console_error', { reason: d.reason || d.error || '' }))}</div>`;
        return;
    }
    const head = `<div class="mb-1" style="font-size:.78rem">${escapeHtml(t('kali.console_result', {
        code: d.exit_code ?? '—', exit: d.tor_exit_ip || '—',
    }))}</div>`;
    const body = [];
    if (d.stdout) body.push(`<div class="k-out">${escapeHtml(d.stdout)}</div>`);
    if (d.stderr) body.push(`<div class="k-out text-warning">${escapeHtml(d.stderr)}</div>`);
    out.innerHTML = head + (body.join('') ||
        `<span class="text-secondary" style="font-size:.8rem">${t('kali.console_empty_out')}</span>`);
}

async function refreshKali() {
    await Promise.all([loadKaliStatus(), loadKaliCommands()]);
}

async function loadKaliStatus() {
    try {
        const s = await (await fetch('/api/kali/status')).json();
        const en = document.getElementById('kEnabled');
        en.textContent = s.enabled ? t('kali.on') : t('kali.off');
        en.className = s.enabled ? 'text-success' : 'text-secondary';
        const exit = document.getElementById('kExit');
        if (!s.enabled) { exit.textContent = '—'; }
        else if (s.reachable) { exit.innerHTML = `<code>${escapeHtml(s.exit_ip || '?')}</code>${s.is_tor ? ' <i class="bi bi-check-circle-fill text-success" title="Tor bestätigt"></i>' : ' <i class="bi bi-exclamation-triangle text-warning"></i>'}`; }
        else { exit.innerHTML = `<span class="text-warning" style="font-size:.8rem">${t('kali.unreachable')}</span>`; }
        document.getElementById('kApproval').textContent = s.require_approval ? t('kali.yes') : t('kali.no');
        const al = document.getElementById('kAllowlist');
        al.innerHTML = (s.allowlist && s.allowlist.length)
            ? s.allowlist.map(e => `<span class="badge text-bg-info me-1">${escapeHtml(e)}</span>`).join('')
            : `<span class="text-secondary" style="font-size:.82rem">${t('kali.allowlist_empty')}</span>`;

        const bins = document.getElementById('kBinaries');
        if (bins && s.allowed_binaries) bins.textContent = s.allowed_binaries.join(', ');
        // With the integration off, an input that accepts text but can never run
        // anything is a trap — say so and take the controls away.
        const input = document.getElementById('kInput'), btn = document.getElementById('kRunBtn');
        if (input && btn) {
            input.disabled = !s.enabled;
            btn.disabled = !s.enabled || K_RUNNING;
            if (!s.enabled) {
                document.getElementById('kCheck').innerHTML =
                    `<span class="text-warning">${t('kali.console_disabled')}</span>`;
            }
        }
    } catch (e) { /* ignore */ }
}

const _K_BADGE = {
    pending: 'text-bg-warning', done: 'text-bg-success', blocked: 'text-bg-danger',
    rejected: 'text-bg-secondary', error: 'text-bg-danger', approved: 'text-bg-info',
};

async function loadKaliCommands() {
    const tbody = document.getElementById('kTable');
    const status = document.getElementById('kFilter')?.value || '';
    try {
        const url = '/api/kali/commands?limit=200' + (status ? '&status=' + encodeURIComponent(status) : '');
        const d = await (await fetch(url)).json();
        const cmds = d.commands || [];
        // "Wartet auf Freigabe" counts every command awaiting a human, not just
        // the ones the current filter happens to show: counted off the filtered
        // list, selecting "done" reported zero commands pending while real ones
        // sat there unapproved.
        const pendingSource = (status && status !== 'pending')
            ? ((await (await fetch('/api/kali/commands?limit=1000&status=pending')).json()).commands || [])
            : cmds;
        document.getElementById('kPending').textContent =
            pendingSource.filter(c => c.status === 'pending').length.toLocaleString(K_LOCALE);
        if (!cmds.length) {
            tbody.innerHTML = `<tr><td colspan="6" class="text-center text-secondary py-3">${t('kali.no_commands')}</td></tr>`;
            return;
        }
        tbody.innerHTML = cmds.map(c => {
            const badge = `<span class="badge ${_K_BADGE[c.status] || 'text-bg-secondary'}">${escapeHtml(c.status)}</span>`;
            const act = c.status === 'pending'
                ? `<button class="btn btn-sm btn-outline-success py-0" style="font-size:.72rem" onclick="approveKali(${c.id}, this)"><i class="bi bi-check2"></i> ${t('kali.approve')}</button>
                   <button class="btn btn-sm btn-outline-danger py-0" style="font-size:.72rem" onclick="rejectKali(${c.id}, this)"><i class="bi bi-x"></i> ${t('kali.reject')}</button>`
                : `<button class="btn btn-sm btn-outline-secondary py-0" style="font-size:.72rem" onclick="toggleKaliDetail(${c.id}, this)"><i class="bi bi-eye"></i> ${t('kali.view')}</button>`;
            return `<tr data-id="${c.id}">
                <td style="white-space:nowrap">${fmtKtime(c.created_at)}</td>
                <td>${badge}${c.reason ? ` <i class="bi bi-info-circle text-secondary" title="${escapeAttr(c.reason)}"></i>` : ''}</td>
                <td><code class="k-cmd">${escapeHtml(c.command)}</code></td>
                <td style="font-size:.78rem">${escapeHtml(c.targets || '—')}</td>
                <td style="font-size:.78rem">${escapeHtml(c.actor || '—')}</td>
                <td style="white-space:nowrap">${act}</td>
            </tr>`;
        }).join('');
        // stash for detail rendering
        window._kCmds = {}; cmds.forEach(c => window._kCmds[c.id] = c);
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="6" class="detail-error">${escapeHtml(e.message)}</td></tr>`;
    }
}

function fmtKtime(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    return d.toLocaleString(K_LOCALE, { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' });
}

function toggleKaliDetail(id, btn) {
    const row = btn.closest('tr');
    const next = row.nextElementSibling;
    if (next && next.classList.contains('k-detail-row')) { next.remove(); return; }
    const c = (window._kCmds || {})[id] || {};
    const detail = document.createElement('tr');
    detail.className = 'k-detail-row';
    const parts = [];
    if (c.reason) parts.push(`<div class="mb-1"><strong>${t('kali.reason')}:</strong> ${escapeHtml(c.reason)}</div>`);
    if (c.tor_exit_ip) parts.push(`<div class="mb-1"><strong>Tor-Exit:</strong> <code>${escapeHtml(c.tor_exit_ip)}</code> · exit_code ${c.exit_code ?? '—'}</div>`);
    if (c.stdout) parts.push(`<div class="k-out">${escapeHtml(c.stdout)}</div>`);
    if (c.stderr) parts.push(`<div class="k-out text-warning">${escapeHtml(c.stderr)}</div>`);
    detail.innerHTML = `<td></td><td colspan="5" class="py-2">${parts.join('') || `<span class="text-secondary">${t('kali.no_output')}</span>`}</td>`;
    row.after(detail);
}

async function approveKali(id, btn) {
    if (!confirm(t('kali.approve_confirm'))) return;
    if (btn) btn.disabled = true;
    try {
        const r = await fetch(`/api/kali/commands/${id}/approve`, { method: 'POST' });
        const d = await r.json();
        if (!r.ok || d.error) throw new Error(d.detail || d.error || `HTTP ${r.status}`);
        refreshKali();
    } catch (e) { alert(t('kali.action_failed') + ': ' + e.message); if (btn) btn.disabled = false; }
}

async function rejectKali(id, btn) {
    if (btn) btn.disabled = true;
    try {
        const r = await fetch(`/api/kali/commands/${id}/reject`, { method: 'POST' });
        const d = await r.json();
        if (!r.ok || d.error) throw new Error(d.detail || d.error || `HTTP ${r.status}`);
        refreshKali();
    } catch (e) { alert(t('kali.action_failed') + ': ' + e.message); if (btn) btn.disabled = false; }
}

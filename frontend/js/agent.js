let _aTimelineChart = null;

document.addEventListener('DOMContentLoaded', () => {
    refreshAgentPage();
    setInterval(refreshAgentPage, 30000);
});

async function refreshAgentPage() {
    await Promise.all([updateAgentStats(), updateAgentTimeline(), updateAgentList(), updateWorkflowBadges()]);
}

async function updateWorkflowBadges() {
    try {
        const r = await fetch('/api/admin/settings');
        if (!r.ok) return;
        const s = await r.json();
        const intervalEl = document.getElementById('wfInterval');
        if (intervalEl) intervalEl.textContent = `alle ${s.agent_interval_seconds || '?'} Sek` + (s.agent_enabled ? '' : '  ·  AUS');
        const modelEl = document.getElementById('wfModel');
        if (modelEl) modelEl.textContent = `(${s.agent_provider || 'lmstudio'} · ${s.agent_model || 'kein Modell gewählt'})`;
    } catch (e) { /* still ok if it fails */ }
}

async function updateAgentStats() {
    try {
        const r = await fetch('/api/agent/decisions/stats');
        const d = await r.json();
        const by = d.by_status || {};
        document.getElementById('aTotal').textContent = (d.total || 0).toLocaleString('de-DE');
        document.getElementById('aPending').textContent = (by.pending || 0).toLocaleString('de-DE');
        document.getElementById('aExecuted').textContent = (by.executed || 0).toLocaleString('de-DE');
        document.getElementById('aRejected').textContent = ((by.rejected || 0) + (by.superseded || 0)).toLocaleString('de-DE');
        document.getElementById('aFailed').textContent = (by.failed || 0).toLocaleString('de-DE');
        const actorMix = d.by_actor || {};
        document.getElementById('aActorMix').textContent = `${actorMix.agent || 0} Agent · ${actorMix.human || 0} Mensch`;
    } catch (err) { console.error(err); }
}

async function updateAgentTimeline() {
    try {
        const r = await fetch('/api/agent/decisions/timeline?days=7');
        const rows = await r.json();
        const labels = [...new Set(rows.map(x => x.ts))].sort();
        const labelSet = new Set(labels);
        const agentByTs = {};
        const humanByTs = {};
        rows.forEach(x => {
            const bucket = x.actor === 'human' ? humanByTs : agentByTs;
            bucket[x.ts] = (bucket[x.ts] || 0) + x.count;
        });
        const data = {
            labels: labels.map(formatTime),
            datasets: [
                { label: 'Agent', data: labels.map(t => agentByTs[t] || 0), backgroundColor: 'rgba(59,130,246,0.6)', borderColor: '#3b82f6' },
                { label: 'Mensch', data: labels.map(t => humanByTs[t] || 0), backgroundColor: 'rgba(34,197,94,0.6)', borderColor: '#22c55e' },
            ]
        };
        const ctx = document.getElementById('aTimelineChart').getContext('2d');
        if (_aTimelineChart) _aTimelineChart.destroy();
        _aTimelineChart = new Chart(ctx, {
            type: 'bar',
            data,
            options: {
                responsive: true, maintainAspectRatio: false,
                scales: { x: { stacked: true, ticks: { color: '#94a3b8' } }, y: { stacked: true, beginAtZero: true, ticks: { color: '#94a3b8' } } },
                plugins: { legend: { labels: { color: '#e2e8f0' } } }
            }
        });
    } catch (err) { console.error(err); }
}

async function updateAgentList() {
    try {
        const status = document.getElementById('aFilterStatus')?.value || '';
        const actor = document.getElementById('aFilterActor')?.value || '';
        const action = document.getElementById('aFilterAction')?.value || '';
        const params = new URLSearchParams({ limit: '200' });
        if (status) params.set('status', status);
        if (actor) params.set('decided_by', actor);
        if (action) params.set('action', action);
        const r = await fetch('/api/agent/decisions?' + params);
        const d = await r.json();
        const items = d.items || [];
        const tbody = document.getElementById('aDecisionsTable');
        if (!items.length) {
            tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--text-secondary);padding:1.5rem">Keine Decisions im aktuellen Filter.</td></tr>';
            return;
        }
        tbody.innerHTML = items.map(d => {
            const sourceBadge = ({
                waf:           '<span class="severity-badge severity-high" title="WAF rule-based">WAF</span>',
                ips:           '<span class="severity-badge severity-critical" title="IPS/IDP rule-based">IPS</span>',
                failed_login:  '<span class="severity-badge severity-high" title="Brute-force rule-based">Login</span>',
                triage:        '<span class="severity-badge severity-medium" title="OSINT/Manual-Triage">Triage</span>',
            })[d.source_type] || '<span class="severity-badge severity-medium" title="Sophos Alert">Alert</span>';
            const actor = d.decided_by === 'human'
                ? '<span class="severity-badge severity-low">Mensch</span>'
                : `<span class="severity-badge severity-medium">Agent</span> ${sourceBadge}`;
            const actionBadge = `<span class="severity-badge severity-${actionToSeverity(d.action)}">${escapeHtml(d.action)}</span>`;
            const conf = Math.round((d.confidence || 0) * 100);
            const confCls = conf >= 80 ? 'severity-critical' : conf >= 50 ? 'severity-high' : 'severity-medium';
            // Inline OSINT button: stop propagation so clicking 🔍 doesn't
            // also fire the row-level showAgentDetail(d.id).
            const osintBtn = (ip) => (typeof osintButton === 'function')
                ? osintButton(ip, 'osint-btn').replace('onclick="', 'onclick="event.stopPropagation();')
                : '';
            let alertCell;
            if (d.alert) {
                alertCell = `${severityBadge(d.alert.severity)} ${escapeHtml(truncate(d.alert.type || '', 25))}${d.alert.source_ip ? '<br><code style="font-size:.78rem">' + escapeHtml(d.alert.source_ip) + '</code>' + osintBtn(d.alert.source_ip) : ''}`;
            } else if (d.source_type === 'triage') {
                const ctx = (d.action_args || {}).context || {};
                const val = ctx.value || d.source_ip || '?';
                const isIp = (ctx.value_type || 'ip') === 'ip';
                alertCell = `<code style="font-size:.78rem">${escapeHtml(truncate(val, 32))}</code>${isIp ? osintBtn(val) : ''}<br><span class="ip-country" style="font-size:.72rem">Triage · ${escapeHtml(ctx.value_type || 'ip')}</span>`;
            } else if (d.source_type === 'failed_login' && (d.action_args || {}).context && d.action_args.context.distributed_brute_force_indicator) {
                const ctx = d.action_args.context;
                // New decisions carry network_summary (real CIDRs via OSINT);
                // older ones carry subnet_summary (/24). Support both.
                const summ = ctx.network_summary || ctx.subnet_summary || [];
                const top = summ[0];
                const topNet = top ? (top.network || top.subnet24) : null;
                const topTxt = top ? `${topNet} (${top.attempts}× / ${top.distinct_ips} IPs)` : '—';
                const unit = ctx.network_summary ? 'Netz(e)' : '/24';
                alertCell = `<span class="ip-country" style="font-size:.78rem">👥 verteilter Brute-Force</span><br><span class="ip-country" style="font-size:.72rem">${ctx.total_login_attempts || 0} Logins · ${summ.length} ${unit} · Top: ${escapeHtml(topTxt)}</span>`;
            } else if (['waf','ips','failed_login'].includes(d.source_type) && d.source_ip) {
                const ctx = (d.action_args || {}).context || {};
                let sub;
                if (d.source_type === 'waf') {
                    sub = `${ctx.count_4xx_24h || 0}× 4xx · ${ctx.count_5xx_24h || 0}× 5xx (24h)`;
                } else if (d.source_type === 'ips') {
                    sub = `${ctx.count_24h || 0} IPS-Hits (24h)${(ctx.severities||[]).length ? ' · ' + ctx.severities.join('/') : ''}`;
                } else {
                    sub = `${ctx.count_24h || 0} Failed-Logins (24h)`;
                }
                alertCell = `<code style="font-size:.78rem">${escapeHtml(d.source_ip)}</code>${osintBtn(d.source_ip)}<br><span class="ip-country" style="font-size:.72rem">${escapeHtml(sub)}</span>`;
            } else {
                alertCell = '<span class="ack-label">—</span>';
            }
            const statusCls = ({executed: 'health-good', rejected: 'health-unknown', superseded: 'health-unknown', failed: 'health-bad', pending: 'health-suspicious'}[d.status] || 'health-unknown');
            return `
                <tr style="cursor:pointer" onclick="showAgentDetail(${d.id})">
                    <td>${formatTime(d.created_at)}</td>
                    <td>${actor}</td>
                    <td>${actionBadge}</td>
                    <td>${d.decided_by === 'human' ? '<span class="ack-label">—</span>' : '<span class="severity-badge ' + confCls + '">' + conf + '%</span>'}</td>
                    <td title="${escapeHtml(d.reasoning || '')}">${escapeHtml(truncate(d.reasoning || '-', 60))}${d.human_comment ? '<br><small class="ip-country">💬 ' + escapeHtml(truncate(d.human_comment, 60)) + '</small>' : ''}</td>
                    <td>${alertCell}</td>
                    <td><span class="health-badge ${statusCls}">${escapeHtml(d.status)}</span></td>
                    <td onclick="event.stopPropagation()">${
                        d.status === 'pending'
                            ? `<button class="ack-btn" onclick="showAgentDetail(${d.id})">Bearbeiten</button>`
                            : ''
                    }</td>
                </tr>`;
        }).join('');
    } catch (err) { console.error(err); }
}

async function showAgentDetail(id) {
    const modal = document.getElementById('agentDetailModal');
    const body = document.getElementById('agentDetailBody');
    body.textContent = 'Wird geladen…';
    modal.classList.add('active');
    try {
        const r = await fetch(`/api/agent/decisions/${id}`);
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const d = await r.json();
        body.innerHTML = renderAgentDetail(d);
    } catch (err) {
        body.innerHTML = `<div class="detail-error">Fehler: ${escapeHtml(err.message)}</div>`;
    }
}

function closeAgentDetail() {
    document.getElementById('agentDetailModal').classList.remove('active');
}

function renderAgentDetail(d) {
    const a = d.alert || {};
    const conf = Math.round((d.confidence || 0) * 100);
    const isPending = d.status === 'pending';
    const candidateIp = a.source_ip || d.source_ip || '';
    const isPublicIp = /^(?!10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.|0\.)\d+\.\d+\.\d+\.\d+$/.test(candidateIp);

    const fields = [
        ['Decision-ID', d.id],
        ['Entschieden von', d.decided_by === 'human' ? 'Mensch' : `Agent (${escapeHtml(d.model || '?')})`],
        ['Aktion', `<span class="severity-badge severity-${actionToSeverity(d.action)}">${escapeHtml(d.action)}</span>`, true],
        ['Aktion-Args', '<code>' + escapeHtml(JSON.stringify(d.action_args || {})) + '</code>', true],
        ['Konfidenz', d.decided_by === 'human' ? '—' : `${conf}%`],
        ['Status', d.status],
        ['Erstellt', formatTime(d.created_at)],
        ['Entschieden', d.decided_at ? formatTime(d.decided_at) : '—'],
        ['Supersedes', d.supersedes ? `<a href="#" onclick="event.preventDefault();showAgentDetail(${d.supersedes})">#${d.supersedes}</a>` : '—', true],
        ['Fehler', d.error ? `<span style="color:var(--accent-red)">${escapeHtml(d.error)}</span>` : '—', true],
    ];
    const fieldsHtml = fields.map(([label, val, raw]) =>
        `<dt>${escapeHtml(label)}</dt><dd>${raw ? val : escapeHtml(String(val))}</dd>`
    ).join('');

    const reasoningBlock = d.reasoning
        ? `<div class="detail-section"><h4>Agent-Begründung</h4><div class="detail-description">${escapeHtml(d.reasoning)}</div></div>`
        : '';

    const humanCommentBlock = d.human_comment
        ? `<div class="detail-section"><h4>Mensch-Kommentar</h4><div class="detail-description">${escapeHtml(d.human_comment)}</div></div>`
        : '';

    // Rule-context block: WAF / IPS / failed-login decisions don't have an
    // alert row attached, so render the context dict stored in action_args.
    const ctx = (d.action_args || {}).context || {};
    let ruleBlock = '';
    if (['waf', 'ips', 'failed_login', 'triage'].includes(d.source_type)) {
        const isDistributed = d.source_type === 'failed_login' && ctx.distributed_brute_force_indicator;
        const isSubnet = d.source_type === 'failed_login' && ctx.subnet_brute_force_indicator;
        const head = ({
            waf:          'WAF-Kontext',
            ips:          'IPS-Kontext',
            failed_login: isDistributed ? 'Verteilter-Brute-Force-Kontext'
                        : isSubnet ? 'Subnet-Brute-Force-Kontext'
                        : 'Failed-Login-Kontext',
            triage:       'Triage-Kontext',
        })[d.source_type];
        const rows = [
            ['Regel', escapeHtml(ctx.rule || '-')],
            ['Schwelle', ctx.threshold ?? '-'],
            ['Land/Stadt', escapeHtml([ctx.country, ctx.city].filter(Boolean).join(', ') || '-')],
        ];
        if (d.source_type === 'waf') {
            rows.push(
                ['4xx in 24h', ctx.count_4xx_24h ?? '-'],
                ['5xx in 24h', ctx.count_5xx_24h ?? '-'],
                ['HTTP-Statuses', (ctx.statuses || []).map(s => escapeHtml(String(s))).join(', ') || '-'],
                ['Hosts', (ctx.hosts || []).map(h => '<code style="font-size:.78rem">' + escapeHtml(h) + '</code>').join(', ') || '-'],
            );
        } else if (d.source_type === 'ips') {
            rows.push(
                ['Hits in 24h', ctx.count_24h ?? '-'],
                ['Severities', (ctx.severities || []).map(escapeHtml).join(', ') || '-'],
                ['Signaturen', (ctx.signatures || []).map(s => '<code style="font-size:.78rem">' + escapeHtml(s) + '</code>').join(', ') || '-'],
                ['Kategorien', (ctx.categories || []).map(escapeHtml).join(', ') || '-'],
            );
        } else if (d.source_type === 'triage') {
            rows.push(
                ['Wert', '<code style="font-size:.8rem">' + escapeHtml(ctx.value || '-') + '</code>'],
                ['Typ', escapeHtml(ctx.value_type || '-')],
                ['Operator-Hinweis', ctx.note ? escapeHtml(ctx.note) : '—'],
            );
        } else if (isDistributed) {
            // New decisions: network_summary (real CIDRs); older: subnet_summary (/24).
            const isNet = !!ctx.network_summary;
            const summ = ctx.network_summary || ctx.subnet_summary || [];
            const aa = d.action_args || {};
            const targetTxt = aa.target_subnet
                ? '<code style="font-size:.8rem">' + escapeHtml(aa.target_subnet) + '</code> (ganzes Netz)'
                : (Array.isArray(aa.target_ips) ? '<strong>' + aa.target_ips.length + ' IP(s)</strong>: ' + aa.target_ips.slice(0, 15).map(i => '<code style="font-size:.78rem">' + escapeHtml(i) + '</code>').join(', ') : '—');
            rows.push(
                ['Login-Versuche im Fenster', ctx.total_login_attempts ?? '-'],
                ['Zeitfenster', (ctx.window_minutes ?? '-') + ' min'],
                [isNet ? 'Betroffene Netze' : 'Betroffene /24-Netze', summ.length],
                ['Block-Ziel', targetTxt],
                [isNet ? 'Top-Netze (Versuche / IPs)' : 'Top /24 (Versuche / IPs)',
                    summ.slice(0, 10).map(s => '<code style="font-size:.78rem">' + escapeHtml(s.network || s.subnet24) + '</code>'
                        + (s.network_name ? ' <span class="ip-country" style="font-size:.72rem">' + escapeHtml(s.network_name) + '</span>' : '')
                        + ' (' + s.attempts + '× / ' + s.distinct_ips + ' IPs)'
                        + (s.too_large ? ' <span class="ip-country" style="font-size:.7rem">⚠ zu groß</span>' : '')).join('<br>') || '-'],
            );
        } else if (isSubnet) {
            rows.push(
                ['Subnet', '<code style="font-size:.8rem">' + escapeHtml(ctx.subnet || '?') + '</code>'],
                ['Versuche im Subnet (24h)', ctx.subnet_attempts ?? '-'],
                ['Distinct IPs im Subnet', ctx.subnet_distinct_ips ?? '-'],
                ['Block-Umfang', '<strong>alle 254 Hosts im /24</strong> (Network/Broadcast ausgenommen)'],
                ['Gesehene Angreifer-IPs', (ctx.observed_ips || []).map(i => '<code style="font-size:.78rem">' + escapeHtml(i) + '</code>').join(', ') || '-'],
                ['Weitere Subnet-IPs (Sample)', (ctx.subnet_ip_sample || []).slice(0, 10).map(i => '<code style="font-size:.78rem">' + escapeHtml(i) + '</code>').join(', ') || '-'],
            );
        } else {
            rows.push(
                ['Failed-Logins in 24h', ctx.count_24h ?? '-'],
                ['Versuchte User', (ctx.users || []).map(u => '<code style="font-size:.78rem">' + escapeHtml(u) + '</code>').join(', ') || '-'],
                ['Komponenten', (ctx.components || []).map(escapeHtml).join(', ') || '-'],
            );
        }
        const osintSum = ctx.osint_summary || {};
        if (ctx.osint_reasons) rows.push(['OSINT-Treffer', (ctx.osint_reasons || []).map(escapeHtml).join(', ')]);
        if (osintSum.intelix_category || osintSum.abuseipdb_score != null || osintSum.virustotal_malicious != null) {
            const bits = [];
            if (osintSum.intelix_category) bits.push('Intelix: ' + escapeHtml(String(osintSum.intelix_category)));
            if (osintSum.abuseipdb_score != null) bits.push('AbuseIPDB: ' + escapeHtml(String(osintSum.abuseipdb_score)));
            if (osintSum.virustotal_malicious != null) bits.push('VT mal.: ' + escapeHtml(String(osintSum.virustotal_malicious)));
            if (osintSum.greynoise_classification) bits.push('GreyNoise: ' + escapeHtml(String(osintSum.greynoise_classification)));
            if (bits.length) rows.push(['OSINT-Summary', bits.join(' · ')]);
        }
        // Header label: rule sources without a single source_ip (distributed /
        // triage of a domain/URL) shouldn't show a dangling "· ?".
        const headLabel = d.source_ip
            ? escapeHtml(d.source_ip) + (typeof osintButton === 'function' ? osintButton(d.source_ip) : '')
            : (d.source_type === 'triage' ? escapeHtml(ctx.value || '') : '');
        ruleBlock = `
        <div class="detail-section">
            <h4>${head}${headLabel ? ' · ' + headLabel : ''}</h4>
            <dl class="detail-grid">${rows.map(([k, v]) => `<dt>${escapeHtml(k)}</dt><dd>${v}</dd>`).join('')}</dl>
        </div>`;
    }

    const alertHtml = a.id
        ? `
        <div class="detail-section">
            <h4>Alarm-Kontext</h4>
            <dl class="detail-grid">
                <dt>Alert-ID</dt><dd class="detail-mono">${escapeHtml(a.id)}</dd>
                <dt>Typ</dt><dd>${escapeHtml(a.type || '-')}</dd>
                <dt>Severity</dt><dd>${severityBadge(a.severity)}</dd>
                <dt>Kategorie</dt><dd>${escapeHtml(a.category || '-')}</dd>
                <dt>Quell-IP</dt><dd>${a.source_ip ? '<code>' + escapeHtml(a.source_ip) + '</code>' + (typeof osintButton === 'function' ? osintButton(a.source_ip) : '') : '-'}</dd>
                <dt>Ziel-IP</dt><dd>${a.destination_ip ? '<code>' + escapeHtml(a.destination_ip) + '</code>' : '-'}</dd>
                <dt>Land/Stadt</dt><dd>${escapeHtml([a.country, a.city].filter(Boolean).join(', ') || '-')}</dd>
                <dt>Agent</dt><dd>${escapeHtml(a.agent || '-')}</dd>
                <dt>Erstellt</dt><dd>${formatTime(a.created_at)}</dd>
                <dt>Acknowledged</dt><dd>${a.acknowledged_at ? formatTime(a.acknowledged_at) + ' (' + escapeHtml(a.acknowledged_action || '') + ')' : 'nein'}</dd>
            </dl>
            ${a.description ? `<div class="detail-description">${escapeHtml(a.description)}</div>` : ''}
            ${a.raw_data ? `<details><summary class="ack-label" style="cursor:pointer">Raw-Data anzeigen</summary><pre class="detail-raw">${escapeHtml(JSON.stringify(a.raw_data, null, 2))}</pre></details>` : ''}
        </div>`
        : '<div class="detail-section"><h4>Alarm-Kontext</h4><div class="ack-label">Alarm nicht (mehr) in der DB</div></div>';

    const actionPanel = isPending
        ? `
        <div class="detail-section">
            <h4>Menschliche Entscheidung</h4>
            <p class="admin-hint">Du kannst die Empfehlung des Agents ausführen, ablehnen oder eine andere Aktion wählen (Override).</p>
            <label class="admin-hint" style="display:block;margin-bottom:.3rem">Kommentar (wird gespeichert)</label>
            <textarea id="hcComment" class="form-control form-control-sm" rows="2" placeholder="Optionaler Begründungstext"></textarea>

            <div class="filter-row mt-2">
                <button class="ack-btn" onclick="approveDecision(${d.id})">✓ Empfehlung ausführen</button>
                <button class="block-link" onclick="rejectDecision(${d.id})">✗ Ablehnen</button>
            </div>

            <h4 style="margin-top:1rem">Override mit anderer Aktion</h4>
            <div class="filter-row">
                <select id="hcAction" class="form-select form-select-sm" style="width:auto">
                    <option value="block_ip">block_ip</option>
                    <option value="acknowledge">acknowledge</option>
                    <option value="isolate" disabled>isolate (manuell über Endpoints-API)</option>
                    <option value="no_action">no_action</option>
                </select>
                <input type="text" id="hcTargetIp" class="form-control form-control-sm" placeholder="Ziel-IP (für block_ip)" value="${escapeHtml(candidateIp)}" style="max-width:220px">
                <button class="ack-btn" onclick="overrideDecision(${d.id}, '${escapeHtml(a.id || '')}', '${escapeHtml(d.source_type || 'alert')}', '${escapeHtml(d.source_ip || '')}')">Override + ausführen</button>
            </div>
            ${!isPublicIp && candidateIp ? '<small class="ack-label">⚠ Quell-IP ist privat / reserviert — block_ip wird abgelehnt</small>' : ''}
        </div>`
        : '';

    const chainBlock = (d.chain && d.chain.length)
        ? `<div class="detail-section"><h4>Verlauf (Chain)</h4><ul style="padding-left:1.2rem">${d.chain.map(c => `<li><a href="#" onclick="event.preventDefault();showAgentDetail(${c.id})">#${c.id}</a> · ${escapeHtml(c.action)} · ${escapeHtml(c.status)} · ${escapeHtml(c.decided_by)}</li>`).join('')}</ul></div>`
        : '';

    return `
        <dl class="detail-grid">${fieldsHtml}</dl>
        ${reasoningBlock}
        ${humanCommentBlock}
        ${ruleBlock}
        ${alertHtml}
        ${chainBlock}
        ${actionPanel}
    `;
}

async function approveDecision(id) {
    const comment = document.getElementById('hcComment')?.value || null;
    try {
        const r = await fetch(`/api/agent/decisions/${id}/approve`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({comment}),
        });
        if (!r.ok) {
            const e = await r.json().catch(() => ({}));
            throw new Error(e.detail || `HTTP ${r.status}`);
        }
        closeAgentDetail();
        await refreshAgentPage();
    } catch (err) { alert('Fehler: ' + err.message); }
}

async function rejectDecision(id) {
    const comment = document.getElementById('hcComment')?.value || null;
    try {
        const r = await fetch(`/api/agent/decisions/${id}/reject`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({comment}),
        });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        closeAgentDetail();
        await refreshAgentPage();
    } catch (err) { alert('Fehler: ' + err.message); }
}

async function overrideDecision(decisionId, alertId, sourceType, sourceIp) {
    const action = document.getElementById('hcAction').value;
    const targetIp = document.getElementById('hcTargetIp').value.trim();
    const comment = document.getElementById('hcComment')?.value || null;
    const args = {};
    if (action === 'block_ip') {
        if (!targetIp) { alert('Ziel-IP fehlt'); return; }
        args.target_ip = targetIp;
    }
    if (!confirm(`Override: ${action}${action === 'block_ip' ? ' ' + targetIp : ''} jetzt ausführen?`)) return;
    const payload = {
        action, action_args: args, comment,
        supersedes: decisionId, execute: true,
        source_type: sourceType || 'alert',
    };
    if (alertId) payload.alert_id = alertId;
    if (!alertId && sourceIp) payload.source_ip = sourceIp;
    try {
        const r = await fetch('/api/agent/decisions/manual', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload),
        });
        if (!r.ok) {
            const e = await r.json().catch(() => ({}));
            throw new Error(e.detail || `HTTP ${r.status}`);
        }
        closeAgentDetail();
        await refreshAgentPage();
    } catch (err) { alert('Fehler: ' + err.message); }
}

async function approveAllPending() {
    // Mirror the active list filters so a user only bulk-approves the rows
    // currently visible. Status is always forced to "pending" server-side.
    const actor = document.getElementById('aFilterActor')?.value || '';
    const action = document.getElementById('aFilterAction')?.value || '';

    // Probe count first so the confirm prompt is honest. Limit is capped at
    // 500 by the backend; if there happen to be more pending decisions we
    // still proceed (the bulk endpoint isn't limit-bound on its own).
    const params = new URLSearchParams({ limit: '500', status: 'pending' });
    if (actor) params.set('decided_by', actor);
    if (action) params.set('action', action);
    let pendingCount = 0;
    let probeError = '';
    try {
        const probe = await fetch('/api/agent/decisions?' + params);
        if (!probe.ok) throw new Error(`HTTP ${probe.status}`);
        const pd = await probe.json();
        pendingCount = (pd.items || []).length;
    } catch (e) {
        probeError = e.message || String(e);
        console.warn('approve-all probe failed:', probeError);
    }

    if (!probeError && pendingCount === 0) {
        alert('Keine pending Decisions im aktuellen Filter.');
        return;
    }

    const filterLabel = action ? `Action=${action}` : '';
    const countText = probeError
        ? '(Anzahl konnte nicht ermittelt werden — Bulk-Approve trotzdem versuchen?)'
        : `${pendingCount} pending Decision(s)${filterLabel ? ' (' + filterLabel + ')' : ''}`;
    const msg = `${countText} ausführen?\n\n`
        + 'Whitelist- und Sicherheits-Checks greifen weiterhin pro Decision.';
    if (!confirm(msg)) return;

    const body = {};
    if (action) body.action = action;

    const btn = document.querySelector('button[onclick="approveAllPending()"]');
    if (btn) { btn.disabled = true; btn.textContent = '… läuft'; }
    try {
        const r = await fetch('/api/agent/decisions/approve-all-pending', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(body),
        });
        const d = await r.json();
        if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
        let msgOut = `${d.approved} ausgeführt`;
        if (d.failed) msgOut += `, ${d.failed} fehlgeschlagen (siehe Konsole)`;
        if (d.errors?.length) console.warn('bulk-approve errors:', d.errors);
        alert(msgOut);
        await refreshAgentPage();
    } catch (err) {
        alert('Fehler: ' + err.message);
    } finally {
        if (btn) { btn.disabled = false; btn.innerHTML = '<i class="bi bi-check2-all"></i> Alle Pending genehmigen'; }
    }
}

async function agentRunNow() {
    try {
        const r = await fetch('/api/agent/run-now', {method: 'POST'});
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        setTimeout(refreshAgentPage, 2000);
    } catch (err) { alert('Fehler: ' + err.message); }
}

async function agentRunNowRule(kind) {
    // kind: 'waf' | 'ips' | 'failed-login'
    try {
        const r = await fetch(`/api/agent/${kind}-run-now?window_minutes=60`, {method: 'POST'});
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        setTimeout(refreshAgentPage, 3000);
    } catch (err) { alert('Fehler: ' + err.message); }
}
// Backwards-compat alias used by older inline handlers
async function agentWafRunNow() { return agentRunNowRule('waf'); }

// === Shared helpers (mini copies — agent.js is otherwise standalone) ===

function formatTime(isoStr) {
    if (!isoStr) return '-';
    const d = new Date(isoStr);
    return d.toLocaleString('de-DE', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
}

// escapeHtml() lives in js/common.js

function truncate(s, n) {
    if (!s) return '-';
    return s.length > n ? s.substring(0, n) + '…' : s;
}

function severityBadge(s) {
    const sev = (s || 'unknown').toLowerCase();
    return `<span class="severity-badge severity-${sev}">${sev}</span>`;
}

function actionToSeverity(action) {
    return ({ block_ip: 'critical', block_subnet: 'critical', isolate: 'high', acknowledge: 'medium', no_action: 'low' })[action] || 'unknown';
}

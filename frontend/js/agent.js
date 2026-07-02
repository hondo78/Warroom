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
        if (intervalEl) intervalEl.textContent = t('agent.wf_interval', {n: s.agent_interval_seconds || '?'}) + (s.agent_enabled ? '' : '  ·  ' + t('agent.wf_off'));
        const modelEl = document.getElementById('wfModel');
        if (modelEl) modelEl.textContent = `(${s.agent_provider || 'lmstudio'} · ${s.agent_model || t('agent.no_model')})`;
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
        document.getElementById('aRejected').textContent = ((by.rejected || 0) + (by.superseded || 0) + (by.declined || 0)).toLocaleString('de-DE');
        document.getElementById('aFailed').textContent = (by.failed || 0).toLocaleString('de-DE');
        const actorMix = d.by_actor || {};
        document.getElementById('aActorMix').textContent = `${actorMix.agent || 0} ${t('agent.actor_agent')} · ${actorMix.human || 0} ${t('agent.actor_human')}`;
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
                { label: t('agent.actor_agent'), data: labels.map(ts => agentByTs[ts] || 0), backgroundColor: 'rgba(59,130,246,0.6)', borderColor: '#3b82f6' },
                { label: t('agent.actor_human'), data: labels.map(ts => humanByTs[ts] || 0), backgroundColor: 'rgba(34,197,94,0.6)', borderColor: '#22c55e' },
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
            tbody.innerHTML = `<tr><td colspan="8" style="text-align:center;color:var(--text-secondary);padding:1.5rem">${t('agent.no_decisions')}</td></tr>`;
            return;
        }
        tbody.innerHTML = items.map(d => {
            const sourceBadge = ({
                waf:           '<span class="severity-badge severity-high" title="WAF rule-based">WAF</span>',
                ips:           '<span class="severity-badge severity-critical" title="IPS/IDP rule-based">IPS</span>',
                failed_login:  '<span class="severity-badge severity-high" title="Brute-force rule-based">Login</span>',
                triage:        '<span class="severity-badge severity-medium" title="OSINT/Manual-Triage">Triage</span>',
                event:         '<span class="severity-badge severity-critical" title="Sophos Central Event">Event</span>',
            })[d.source_type] || '<span class="severity-badge severity-medium" title="Sophos Alert">Alert</span>';
            const autoBadge = (d.action_args || {}).auto_approved
                ? ` <span class="severity-badge severity-low" title="${escapeHtml(t('agent.auto_approved_title'))}">🤖</span>`
                : '';
            const actor = (d.decided_by === 'human'
                ? `<span class="severity-badge severity-low">${t('agent.actor_human')}</span>`
                : `<span class="severity-badge severity-medium">${t('agent.actor_agent')}</span> ${sourceBadge}`) + autoBadge;
            const actionBadge = `<span class="severity-badge severity-${actionToSeverity(d.action)}">${escapeHtml(d.action)}</span>`;
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
                alertCell = `<code style="font-size:.78rem">${escapeHtml(truncate(val, 32))}</code>${isIp ? osintBtn(val) : ''}<br><span class="ip-country" style="font-size:.72rem">${t('agent.triage')} · ${escapeHtml(ctx.value_type || 'ip')}</span>`;
            } else if (d.source_type === 'failed_login' && (d.action_args || {}).context && d.action_args.context.distributed_brute_force_indicator) {
                const ctx = d.action_args.context;
                // New decisions carry network_summary (real CIDRs via OSINT);
                // older ones carry subnet_summary (/24). Support both.
                const summ = ctx.network_summary || ctx.subnet_summary || [];
                const top = summ[0];
                const topNet = top ? (top.network || top.subnet24) : null;
                const topTxt = top ? `${topNet} (${top.attempts}× / ${top.distinct_ips} IPs)` : '—';
                const unit = ctx.network_summary ? t('agent.unit_networks') : '/24';
                alertCell = `<span class="ip-country" style="font-size:.78rem">👥 ${t('agent.distributed_bf')}</span><br><span class="ip-country" style="font-size:.72rem">${ctx.total_login_attempts || 0} ${t('agent.logins')} · ${summ.length} ${unit} · ${t('agent.top')}: ${escapeHtml(topTxt)}</span>`;
            } else if (d.source_type === 'event') {
                const ctx = (d.action_args || {}).context || {};
                const ip = ctx.destination_ip || ctx.source_ip || d.source_ip;
                const shortType = (ctx.event_type || '').split('::').pop() || 'Event';
                const ep = ctx.endpoint ? ' · ' + escapeHtml(truncate(ctx.endpoint, 24)) : '';
                alertCell = `<span class="ip-country" style="font-size:.78rem">🖥 ${escapeHtml(shortType)}</span>${ep}${ip ? '<br><code style="font-size:.78rem">' + escapeHtml(ip) + '</code>' + osintBtn(ip) : ''}`;
            } else if (['waf','ips','failed_login'].includes(d.source_type) && d.source_ip) {
                const ctx = (d.action_args || {}).context || {};
                let sub;
                if (d.source_type === 'waf') {
                    sub = `${ctx.count_4xx_24h || 0}× 4xx · ${ctx.count_5xx_24h || 0}× 5xx (24h)`;
                } else if (d.source_type === 'ips') {
                    sub = `${ctx.count_24h || 0} ${t('agent.ips_hits')} (24h)${(ctx.severities||[]).length ? ' · ' + ctx.severities.join('/') : ''}`;
                } else {
                    sub = `${ctx.count_24h || 0} ${t('agent.failed_logins')} (24h)`;
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
                    <td title="${escapeHtml(d.reasoning || '')}">${escapeHtml(truncate(d.reasoning || '-', 60))}${d.human_comment ? '<br><small class="ip-country">💬 ' + escapeHtml(truncate(d.human_comment, 60)) + '</small>' : ''}</td>
                    <td>${alertCell}</td>
                    <td><span class="health-badge ${statusCls}">${escapeHtml(d.status)}</span></td>
                    <td onclick="event.stopPropagation()">${
                        d.status === 'pending'
                            ? `<button class="ack-btn" onclick="showAgentDetail(${d.id})">${t('common.edit')}</button>`
                            : ''
                    }</td>
                </tr>`;
        }).join('');
    } catch (err) { console.error(err); }
}

async function showAgentDetail(id) {
    const modal = document.getElementById('agentDetailModal');
    const body = document.getElementById('agentDetailBody');
    body.textContent = t('common.loading');
    modal.classList.add('active');
    try {
        const r = await fetch(`/api/agent/decisions/${id}`);
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const d = await r.json();
        body.innerHTML = renderAgentDetail(d);
    } catch (err) {
        body.innerHTML = `<div class="detail-error">${t('agent.error')}: ${escapeHtml(err.message)}</div>`;
    }
}

function closeAgentDetail() {
    document.getElementById('agentDetailModal').classList.remove('active');
}

function renderAgentDetail(d) {
    const a = d.alert || {};
    const isPending = d.status === 'pending';
    const candidateIp = a.source_ip || d.source_ip || '';
    const isPublicIp = /^(?!10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.|0\.)\d+\.\d+\.\d+\.\d+$/.test(candidateIp);

    const fields = [
        [t('agent.f_decision_id'), d.id],
        [t('agent.f_decided_by'), d.decided_by === 'human' ? t('agent.actor_human') : `${t('agent.actor_agent')} (${escapeHtml(d.model || '?')})`],
        [t('agent.f_action'), `<span class="severity-badge severity-${actionToSeverity(d.action)}">${escapeHtml(d.action)}</span>`, true],
        [t('agent.f_action_args'), '<code>' + escapeHtml(JSON.stringify(d.action_args || {})) + '</code>', true],
        [t('common.status'), d.status],
        [t('agent.f_created'), formatTime(d.created_at)],
        [t('agent.f_decided'), d.decided_at ? formatTime(d.decided_at) : '—'],
        [t('agent.f_supersedes'), d.supersedes ? `<a href="#" onclick="event.preventDefault();showAgentDetail(${d.supersedes})">#${d.supersedes}</a>` : '—', true],
        [t('agent.error'), d.error ? `<span style="color:var(--accent-red)">${escapeHtml(d.error)}</span>` : '—', true],
    ];
    const fieldsHtml = fields.map(([label, val, raw]) =>
        `<dt>${escapeHtml(label)}</dt><dd>${raw ? val : escapeHtml(String(val))}</dd>`
    ).join('');

    const reasoningBlock = d.reasoning
        ? `<div class="detail-section"><h4>${t('agent.agent_reasoning')}</h4><div class="detail-description">${escapeHtml(d.reasoning)}</div></div>`
        : '';

    const humanCommentBlock = d.human_comment
        ? `<div class="detail-section"><h4>${t('agent.human_comment')}</h4><div class="detail-description">${escapeHtml(d.human_comment)}</div></div>`
        : '';

    // Rule-context block: WAF / IPS / failed-login decisions don't have an
    // alert row attached, so render the context dict stored in action_args.
    const ctx = (d.action_args || {}).context || {};
    let ruleBlock = '';
    if (['waf', 'ips', 'failed_login', 'triage'].includes(d.source_type)) {
        const isDistributed = d.source_type === 'failed_login' && ctx.distributed_brute_force_indicator;
        const isSubnet = d.source_type === 'failed_login' && ctx.subnet_brute_force_indicator;
        const head = ({
            waf:          t('agent.ctx_waf'),
            ips:          t('agent.ctx_ips'),
            failed_login: isDistributed ? t('agent.ctx_distributed_bf')
                        : isSubnet ? t('agent.ctx_subnet_bf')
                        : t('agent.ctx_failed_login'),
            triage:       t('agent.ctx_triage'),
        })[d.source_type];
        const rows = [
            [t('agent.r_rule'), escapeHtml(ctx.rule || '-')],
            [t('agent.r_threshold'), ctx.threshold ?? '-'],
            [t('agent.r_country_city'), escapeHtml([ctx.country, ctx.city].filter(Boolean).join(', ') || '-')],
        ];
        if (d.source_type === 'waf') {
            rows.push(
                [t('agent.r_4xx_24h'), ctx.count_4xx_24h ?? '-'],
                [t('agent.r_5xx_24h'), ctx.count_5xx_24h ?? '-'],
                [t('agent.r_http_statuses'), (ctx.statuses || []).map(s => escapeHtml(String(s))).join(', ') || '-'],
                [t('agent.r_hosts'), (ctx.hosts || []).map(h => '<code style="font-size:.78rem">' + escapeHtml(h) + '</code>').join(', ') || '-'],
            );
        } else if (d.source_type === 'ips') {
            rows.push(
                [t('agent.r_hits_24h'), ctx.count_24h ?? '-'],
                [t('agent.r_severities'), (ctx.severities || []).map(escapeHtml).join(', ') || '-'],
                [t('agent.r_signatures'), (ctx.signatures || []).map(s => '<code style="font-size:.78rem">' + escapeHtml(s) + '</code>').join(', ') || '-'],
                [t('agent.r_categories'), (ctx.categories || []).map(escapeHtml).join(', ') || '-'],
            );
        } else if (d.source_type === 'triage') {
            rows.push(
                [t('agent.r_value'), '<code style="font-size:.8rem">' + escapeHtml(ctx.value || '-') + '</code>'],
                [t('agent.r_type'), escapeHtml(ctx.value_type || '-')],
                [t('agent.r_operator_note'), ctx.note ? escapeHtml(ctx.note) : '—'],
            );
        } else if (isDistributed) {
            // New decisions: network_summary (real CIDRs); older: subnet_summary (/24).
            const isNet = !!ctx.network_summary;
            const summ = ctx.network_summary || ctx.subnet_summary || [];
            const aa = d.action_args || {};
            const targetTxt = aa.target_subnet
                ? '<code style="font-size:.8rem">' + escapeHtml(aa.target_subnet) + '</code> (' + t('agent.whole_network') + ')'
                : (Array.isArray(aa.target_ips) ? '<strong>' + aa.target_ips.length + ' IP(s)</strong>: ' + aa.target_ips.slice(0, 15).map(i => '<code style="font-size:.78rem">' + escapeHtml(i) + '</code>').join(', ') : '—');
            rows.push(
                [t('agent.r_login_attempts_window'), ctx.total_login_attempts ?? '-'],
                [t('agent.r_time_window'), (ctx.window_minutes ?? '-') + ' min'],
                [isNet ? t('agent.r_affected_networks') : t('agent.r_affected_24'), summ.length],
                [t('agent.r_block_target'), targetTxt],
                [isNet ? t('agent.r_top_networks') : t('agent.r_top_24'),
                    summ.slice(0, 10).map(s => '<code style="font-size:.78rem">' + escapeHtml(s.network || s.subnet24) + '</code>'
                        + (s.network_name ? ' <span class="ip-country" style="font-size:.72rem">' + escapeHtml(s.network_name) + '</span>' : '')
                        + ' (' + s.attempts + '× / ' + s.distinct_ips + ' IPs)'
                        + (s.too_large ? ' <span class="ip-country" style="font-size:.7rem">⚠ ' + t('agent.too_large') + '</span>' : '')).join('<br>') || '-'],
            );
        } else if (isSubnet) {
            rows.push(
                [t('agent.r_subnet'), '<code style="font-size:.8rem">' + escapeHtml(ctx.subnet || '?') + '</code>'],
                [t('agent.r_subnet_attempts_24h'), ctx.subnet_attempts ?? '-'],
                [t('agent.r_subnet_distinct_ips'), ctx.subnet_distinct_ips ?? '-'],
                [t('agent.r_block_scope'), '<strong>' + t('agent.all_254_hosts') + '</strong> (' + t('agent.net_broadcast_excl') + ')'],
                [t('agent.r_observed_ips'), (ctx.observed_ips || []).map(i => '<code style="font-size:.78rem">' + escapeHtml(i) + '</code>').join(', ') || '-'],
                [t('agent.r_more_subnet_ips'), (ctx.subnet_ip_sample || []).slice(0, 10).map(i => '<code style="font-size:.78rem">' + escapeHtml(i) + '</code>').join(', ') || '-'],
            );
        } else {
            rows.push(
                [t('agent.r_failed_logins_24h'), ctx.count_24h ?? '-'],
                [t('agent.r_attempted_users'), (ctx.users || []).map(u => '<code style="font-size:.78rem">' + escapeHtml(u) + '</code>').join(', ') || '-'],
                [t('agent.r_components'), (ctx.components || []).map(escapeHtml).join(', ') || '-'],
            );
        }
        const osintSum = ctx.osint_summary || {};
        if (ctx.osint_reasons) rows.push([t('agent.r_osint_hits'), (ctx.osint_reasons || []).map(escapeHtml).join(', ')]);
        if (osintSum.intelix_category || osintSum.abuseipdb_score != null || osintSum.virustotal_malicious != null) {
            const bits = [];
            if (osintSum.intelix_category) bits.push('Intelix: ' + escapeHtml(String(osintSum.intelix_category)));
            if (osintSum.abuseipdb_score != null) bits.push('AbuseIPDB: ' + escapeHtml(String(osintSum.abuseipdb_score)));
            if (osintSum.virustotal_malicious != null) bits.push('VT mal.: ' + escapeHtml(String(osintSum.virustotal_malicious)));
            if (osintSum.greynoise_classification) bits.push('GreyNoise: ' + escapeHtml(String(osintSum.greynoise_classification)));
            if (bits.length) rows.push([t('agent.r_osint_summary'), bits.join(' · ')]);
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
            <h4>${t('agent.alarm_context')}</h4>
            <dl class="detail-grid">
                <dt>${t('agent.f_alert_id')}</dt><dd class="detail-mono">${escapeHtml(a.id)}</dd>
                <dt>${t('agent.r_type')}</dt><dd>${escapeHtml(a.type || '-')}</dd>
                <dt>${t('common.severity')}</dt><dd>${severityBadge(a.severity)}</dd>
                <dt>${t('agent.f_category')}</dt><dd>${escapeHtml(a.category || '-')}</dd>
                <dt>${t('agent.f_source_ip')}</dt><dd>${a.source_ip ? '<code>' + escapeHtml(a.source_ip) + '</code>' + (typeof osintButton === 'function' ? osintButton(a.source_ip) : '') : '-'}</dd>
                <dt>${t('agent.f_dest_ip')}</dt><dd>${a.destination_ip ? '<code>' + escapeHtml(a.destination_ip) + '</code>' : '-'}</dd>
                <dt>${t('agent.r_country_city')}</dt><dd>${escapeHtml([a.country, a.city].filter(Boolean).join(', ') || '-')}</dd>
                <dt>${t('agent.actor_agent')}</dt><dd>${escapeHtml(a.agent || '-')}</dd>
                <dt>${t('agent.f_created')}</dt><dd>${formatTime(a.created_at)}</dd>
                <dt>${t('agent.f_acknowledged')}</dt><dd>${a.acknowledged_at ? formatTime(a.acknowledged_at) + ' (' + escapeHtml(a.acknowledged_action || '') + ')' : t('agent.no')}</dd>
            </dl>
            ${a.description ? `<div class="detail-description">${escapeHtml(a.description)}</div>` : ''}
            ${a.raw_data ? `<details><summary class="ack-label" style="cursor:pointer">${t('agent.show_raw_data')}</summary><pre class="detail-raw">${escapeHtml(JSON.stringify(a.raw_data, null, 2))}</pre></details>` : ''}
        </div>`
        : `<div class="detail-section"><h4>${t('agent.alarm_context')}</h4><div class="ack-label">${t('agent.alarm_not_in_db')}</div></div>`;

    const actionPanel = isPending
        ? `
        <div class="detail-section">
            <h4>${t('agent.human_decision')}</h4>
            <p class="admin-hint">${t('agent.human_decision_hint')}</p>
            <label class="admin-hint" style="display:block;margin-bottom:.3rem">${t('agent.comment_saved')}</label>
            <textarea id="hcComment" class="form-control form-control-sm" rows="2" placeholder="${t('agent.comment_placeholder')}"></textarea>

            <div class="filter-row mt-2">
                <button class="ack-btn" onclick="approveDecision(${d.id})">✓ ${t('agent.execute_recommendation')}</button>
                <button class="block-link" onclick="rejectDecision(${d.id})">✗ ${t('agent.reject')}</button>
            </div>

            <h4 style="margin-top:1rem">${t('agent.override_other_action')}</h4>
            <div class="filter-row">
                <select id="hcAction" class="form-select form-select-sm" style="width:auto">
                    <option value="block_ip">block_ip</option>
                    <option value="acknowledge">acknowledge</option>
                    <option value="isolate" disabled>${t('agent.isolate_manual')}</option>
                    <option value="no_action">no_action</option>
                </select>
                <input type="text" id="hcTargetIp" class="form-control form-control-sm" placeholder="${t('agent.target_ip_placeholder')}" value="${escapeHtml(candidateIp)}" style="max-width:220px">
                <button class="ack-btn" onclick="overrideDecision(${d.id}, '${escapeHtml(a.id || '')}', '${escapeHtml(d.source_type || 'alert')}', '${escapeHtml(d.source_ip || '')}')">${t('agent.override_execute')}</button>
            </div>
            ${!isPublicIp && candidateIp ? `<small class="ack-label">⚠ ${t('agent.private_ip_warn')}</small>` : ''}
        </div>`
        : '';

    const chainBlock = (d.chain && d.chain.length)
        ? `<div class="detail-section"><h4>${t('agent.chain_history')}</h4><ul style="padding-left:1.2rem">${d.chain.map(c => `<li><a href="#" onclick="event.preventDefault();showAgentDetail(${c.id})">#${c.id}</a> · ${escapeHtml(c.action)} · ${escapeHtml(c.status)} · ${escapeHtml(c.decided_by)}</li>`).join('')}</ul></div>`
        : '';

    // Auto-approved provenance + post-hoc decline (revert the block).
    const auto = (d.action_args || {}).auto_approved;
    const autoBlock = auto
        ? `<div class="detail-section"><h4>🤖 ${t('agent.auto_approved_title')}</h4><div class="detail-description">${t('agent.auto_approved_desc', {net: auto.net, t: auto.threshold})}</div></div>`
        : '';

    const BLOCK_ACTIONS = ['block_ip', 'block_ips', 'block_subnet', 'block_domain', 'block_url'];
    const declinePanel = (d.status === 'executed' && BLOCK_ACTIONS.includes(d.action))
        ? `
        <div class="detail-section">
            <h4>${t('agent.decline_title')}</h4>
            <p class="admin-hint">${auto ? t('agent.decline_hint_auto') : t('agent.decline_hint')}</p>
            <label class="admin-hint" style="display:block;margin-bottom:.3rem">${t('agent.comment_saved')}</label>
            <textarea id="dcComment" class="form-control form-control-sm" rows="2" placeholder="${t('agent.comment_placeholder')}"></textarea>
            <div class="form-check mt-2">
                <input class="form-check-input" type="checkbox" id="dcReset">
                <label class="form-check-label admin-hint" for="dcReset">${t('agent.decline_reset')}</label>
            </div>
            <div class="filter-row mt-2">
                <button class="block-link" onclick="declineDecision(${d.id})">↩ ${t('agent.decline_revert')}</button>
            </div>
        </div>`
        : '';

    return `
        <dl class="detail-grid">${fieldsHtml}</dl>
        ${reasoningBlock}
        ${humanCommentBlock}
        ${autoBlock}
        ${ruleBlock}
        ${alertHtml}
        ${chainBlock}
        ${actionPanel}
        ${declinePanel}
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
    } catch (err) { alert(t('agent.error') + ': ' + err.message); }
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
    } catch (err) { alert(t('agent.error') + ': ' + err.message); }
}

async function declineDecision(id) {
    const comment = document.getElementById('dcComment')?.value || null;
    const reset = !!document.getElementById('dcReset')?.checked;
    if (!confirm(t('agent.decline_confirm'))) return;
    try {
        const r = await fetch(`/api/agent/decisions/${id}/decline`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({reset_pattern: reset, comment}),
        });
        if (!r.ok) {
            const e = await r.json().catch(() => ({}));
            throw new Error(e.detail || `HTTP ${r.status}`);
        }
        const d = await r.json();
        const rev = d.reverted || {};
        const n = (rev.removed_ips || []).length + (rev.removed_domain ? 1 : 0) + (rev.removed_url ? 1 : 0);
        let msg = t('agent.decline_done', {n});
        if (d.pattern_reset) msg += ' · ' + t('agent.decline_pattern_reset');
        alert(msg);
        closeAgentDetail();
        await refreshAgentPage();
    } catch (err) { alert(t('agent.error') + ': ' + err.message); }
}

async function overrideDecision(decisionId, alertId, sourceType, sourceIp) {
    const action = document.getElementById('hcAction').value;
    const targetIp = document.getElementById('hcTargetIp').value.trim();
    const comment = document.getElementById('hcComment')?.value || null;
    const args = {};
    if (action === 'block_ip') {
        if (!targetIp) { alert(t('agent.target_ip_missing')); return; }
        args.target_ip = targetIp;
    }
    if (!confirm(t('agent.override_confirm', {action: action + (action === 'block_ip' ? ' ' + targetIp : '')}))) return;
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
    } catch (err) { alert(t('agent.error') + ': ' + err.message); }
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
        alert(t('agent.no_pending_filter'));
        return;
    }

    const filterLabel = action ? `Action=${action}` : '';
    const countText = probeError
        ? t('agent.bulk_count_unknown')
        : t('agent.bulk_pending_count', {n: pendingCount, filter: filterLabel ? ' (' + filterLabel + ')' : ''});
    const msg = t('agent.bulk_confirm', {count: countText});
    if (!confirm(msg)) return;

    const body = {};
    if (action) body.action = action;

    const btn = document.querySelector('button[onclick="approveAllPending()"]');
    if (btn) { btn.disabled = true; btn.textContent = t('agent.running'); }
    try {
        const r = await fetch('/api/agent/decisions/approve-all-pending', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(body),
        });
        const d = await r.json();
        if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
        let msgOut = t('agent.bulk_executed', {n: d.approved});
        if (d.failed) msgOut += t('agent.bulk_failed', {n: d.failed});
        if (d.errors?.length) console.warn('bulk-approve errors:', d.errors);
        alert(msgOut);
        await refreshAgentPage();
    } catch (err) {
        alert(t('agent.error') + ': ' + err.message);
    } finally {
        if (btn) { btn.disabled = false; btn.innerHTML = '<i class="bi bi-check2-all"></i> ' + t('agent.approve_all'); }
    }
}

async function agentRunNow() {
    try {
        const r = await fetch('/api/agent/run-now', {method: 'POST'});
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        setTimeout(refreshAgentPage, 2000);
    } catch (err) { alert(t('agent.error') + ': ' + err.message); }
}

async function agentRunNowRule(kind) {
    // kind: 'waf' | 'ips' | 'failed-login'
    try {
        const r = await fetch(`/api/agent/${kind}-run-now?window_minutes=60`, {method: 'POST'});
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        setTimeout(refreshAgentPage, 3000);
    } catch (err) { alert(t('agent.error') + ': ' + err.message); }
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

// Email Management page — talks to the /api/email/* proxy, which forwards to
// the Sophos Central Email API (/email/v1). Field names in Sophos payloads
// vary a little between API versions, so reads use tolerant `pick()` lookups
// rather than hard-coding one key.

// Selected message ids, kept per quarantine flavour (false = pre-delivery).
const selected = { false: new Set(), true: new Set() };
// Cache of last-loaded rows so the detail modal / actions can look them up.
const cache = { mailboxes: [], false: [], true: [] };

document.addEventListener('DOMContentLoaded', () => {
    loadMailboxes();
    // Lazy-load a quarantine tab the first time it's shown.
    document.getElementById('tab-quarantine').addEventListener('shown.bs.tab', () => {
        if (!cache[false].length) loadQuarantine(false);
    });
    document.getElementById('tab-postdelivery').addEventListener('shown.bs.tab', () => {
        if (!cache[true].length) loadQuarantine(true);
    });
    // Enter triggers the search in each box.
    bindEnter('mbSearch', loadMailboxes);
    // Quarantine search filters the already-loaded rows client-side (the Sophos
    // search endpoint only takes a date window, not a text query).
    bindFilter('qSearch', 'quarantineTable');
    bindFilter('pdSearch', 'postdeliveryTable');
});

function bindFilter(inputId, tableId) {
    const el = document.getElementById(inputId);
    if (!el) return;
    el.addEventListener('input', () => {
        const t = el.value.toLowerCase().trim();
        document.querySelectorAll(`#${tableId} > tr`).forEach(tr => {
            tr.classList.toggle('filter-hidden', !!t && !tr.textContent.toLowerCase().includes(t));
        });
    });
}

function bindEnter(id, fn) {
    const el = document.getElementById(id);
    if (el) el.addEventListener('keydown', e => { if (e.key === 'Enter') fn(); });
}

function refreshEmail() {
    loadMailboxes();
    if (cache[false].length || isActive('pane-quarantine')) loadQuarantine(false);
    if (cache[true].length || isActive('pane-postdelivery')) loadQuarantine(true);
}

function isActive(paneId) {
    const el = document.getElementById(paneId);
    return el && el.classList.contains('active');
}

// First value present among the given keys of obj.
function pick(obj, ...keys) {
    for (const k of keys) {
        if (obj && obj[k] !== undefined && obj[k] !== null && obj[k] !== '') return obj[k];
    }
    return undefined;
}

function setApiStatus(ok, msg) {
    const badge = document.getElementById('emailApiStatus');
    const alertBox = document.getElementById('emailUnavailable');
    if (ok) {
        badge.className = 'badge text-bg-success';
        badge.textContent = 'API: OK';
        alertBox.classList.add('d-none');
    } else {
        badge.className = 'badge text-bg-danger';
        badge.textContent = 'API: nicht erreichbar';
        document.getElementById('emailUnavailableMsg').textContent = msg ? `(${msg})` : '';
        alertBox.classList.remove('d-none');
    }
}

function updateSelectedCount() {
    const total = selected[false].size + selected[true].size;
    document.getElementById('statSelected').textContent = total.toLocaleString('de-DE');
}

// ---------------------------------------------------------------- Mailboxes

async function loadMailboxes() {
    const tbody = document.getElementById('mailboxTable');
    const search = document.getElementById('mbSearch').value.trim();
    tbody.innerHTML = '<tr><td colspan="6" class="text-center text-secondary py-4">Lade…</td></tr>';
    try {
        const url = '/api/email/mailboxes' + (search ? `?search=${encodeURIComponent(search)}` : '');
        const r = await fetch(url);
        const d = await r.json();
        if (!d.available) { setApiStatus(false, d.error); }
        else { setApiStatus(true); }
        const items = d.items || [];
        cache.mailboxes = items;
        document.getElementById('statMailboxes').textContent = d.available ? items.length.toLocaleString('de-DE') : '—';

        if (!items.length) {
            tbody.innerHTML = `<tr><td colspan="6" class="text-center text-secondary py-4">${d.available ? 'Keine Mailboxen gefunden.' : 'Email-API nicht erreichbar.'}</td></tr>`;
            return;
        }
        tbody.innerHTML = items.map((m, i) => {
            const email = pick(m, 'email', 'primaryEmail', 'emailAddress', 'address') || '—';
            const name = pick(m, 'displayName', 'name') || '';
            const type = pick(m, 'type', 'mailboxType') || '—';
            const domain = pick(m, 'domain') || (email.includes('@') ? email.split('@')[1] : '—');
            const stat = m.blocked
                ? '<span class="severity-badge severity-critical">blockiert</span>'
                : '<span class="severity-badge severity-low">aktiv</span>';
            return `<tr>
                <td><code>${escapeHtml(email)}</code></td>
                <td>${escapeHtml(name)}</td>
                <td><span class="severity-badge severity-high">${escapeHtml(type)}</span></td>
                <td>${escapeHtml(domain)}</td>
                <td>${stat}</td>
                <td>
                    <button class="osint-btn" onclick="viewMailbox(${i})" title="Details"><i class="bi bi-eye"></i></button>
                    <button class="ack-btn" onclick="editMailbox(${i})" title="Bearbeiten"><i class="bi bi-pencil"></i></button>
                    <button class="block-link" onclick="deleteMailbox(${i}, this)" title="Löschen"><i class="bi bi-trash"></i></button>
                </td>
            </tr>`;
        }).join('');
    } catch (err) {
        setApiStatus(false, err.message);
        tbody.innerHTML = `<tr><td colspan="6" class="detail-error">${escapeHtml(err.message)}</td></tr>`;
    }
}

function mailboxId(m) {
    return pick(m, 'id', 'mailboxId', 'uuid');
}

async function viewMailbox(i) {
    const m = cache.mailboxes[i];
    showDetailModal(`Mailbox · ${escapeHtml(pick(m, 'email', 'primaryEmail') || '')}`, renderJson(m));
    // Best-effort live fetch for the full record.
    const id = mailboxId(m);
    if (!id) return;
    try {
        const r = await fetch(`/api/email/mailboxes/${encodeURIComponent(id)}`);
        if (r.ok) document.getElementById('detailBody').innerHTML = renderJson(await r.json());
    } catch (_) { /* keep the cached view */ }
}

function openMailboxModal() {
    document.getElementById('mailboxModalTitle').textContent = 'Neue Mailbox';
    document.getElementById('mbId').value = '';
    document.getElementById('mbEmail').value = '';
    document.getElementById('mbDisplayName').value = '';
    document.getElementById('mbType').value = 'user';
    bootstrap.Modal.getOrCreateInstance(document.getElementById('mailboxModal')).show();
}

function editMailbox(i) {
    const m = cache.mailboxes[i];
    document.getElementById('mailboxModalTitle').textContent = 'Mailbox bearbeiten';
    document.getElementById('mbId').value = mailboxId(m) || '';
    document.getElementById('mbEmail').value = pick(m, 'email', 'primaryEmail', 'emailAddress') || '';
    document.getElementById('mbDisplayName').value = pick(m, 'displayName', 'name') || '';
    document.getElementById('mbType').value = pick(m, 'type', 'mailboxType') || 'user';
    bootstrap.Modal.getOrCreateInstance(document.getElementById('mailboxModal')).show();
}

async function saveMailbox() {
    const id = document.getElementById('mbId').value;
    const body = {
        email: document.getElementById('mbEmail').value.trim(),
        displayName: document.getElementById('mbDisplayName').value.trim(),
        type: document.getElementById('mbType').value,
    };
    if (!body.email) { alert('E-Mail-Adresse erforderlich.'); return; }
    const btn = document.getElementById('mbSaveBtn');
    btn.disabled = true; btn.textContent = '…';
    try {
        const url = id ? `/api/email/mailboxes/${encodeURIComponent(id)}` : '/api/email/mailboxes';
        const r = await fetch(url, {
            method: id ? 'PATCH' : 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
        bootstrap.Modal.getOrCreateInstance(document.getElementById('mailboxModal')).hide();
        await loadMailboxes();
    } catch (err) {
        alert('Speichern fehlgeschlagen: ' + err.message);
    } finally {
        btn.disabled = false; btn.textContent = 'Speichern';
    }
}

async function deleteMailbox(i, btn) {
    const m = cache.mailboxes[i];
    const email = pick(m, 'email', 'primaryEmail') || mailboxId(m);
    if (!confirm(`Mailbox "${email}" wirklich löschen?\nDiese Aktion wirkt direkt auf den Sophos-Tenant.`)) return;
    const id = mailboxId(m);
    if (!id) { alert('Keine Mailbox-ID im Datensatz.'); return; }
    btn.disabled = true;
    try {
        const r = await fetch(`/api/email/mailboxes/${encodeURIComponent(id)}`, { method: 'DELETE' });
        if (!r.ok) { const d = await r.json().catch(() => ({})); throw new Error(d.detail || `HTTP ${r.status}`); }
        await loadMailboxes();
    } catch (err) {
        alert('Löschen fehlgeschlagen: ' + err.message);
        btn.disabled = false;
    }
}

// --------------------------------------------------------------- Quarantine

async function loadQuarantine(postDelivery) {
    const tableId = postDelivery ? 'postdeliveryTable' : 'quarantineTable';
    const statId = postDelivery ? 'statPostDelivery' : 'statQuarantine';
    const searchEl = document.getElementById(postDelivery ? 'pdSearch' : 'qSearch');
    const hoursEl = document.getElementById(postDelivery ? 'pdHours' : 'qHours');
    const tbody = document.getElementById(tableId);
    tbody.innerHTML = '<tr><td colspan="7" class="text-center text-secondary py-4">Lade…</td></tr>';
    selected[postDelivery].clear();
    updateSelectedCount();
    try {
        const params = new URLSearchParams({ post_delivery: postDelivery, hours: hoursEl.value });
        if (searchEl.value.trim()) params.set('search', searchEl.value.trim());
        const r = await fetch(`/api/email/quarantine?${params}`);
        const d = await r.json();
        if (!d.available) setApiStatus(false, d.error); else setApiStatus(true);
        const items = d.items || [];
        cache[postDelivery] = items;
        document.getElementById(statId).textContent = d.available ? items.length.toLocaleString('de-DE') : '—';

        if (!items.length) {
            tbody.innerHTML = `<tr><td colspan="7" class="text-center text-secondary py-4">${d.available ? 'Keine Nachrichten im Zeitfenster.' : 'Email-API nicht erreichbar.'}</td></tr>`;
            return;
        }
        tbody.innerHTML = items.map((msg, i) => {
            const id = msgId(msg);
            const recv = pick(msg, 'receivedAt', 'quarantinedAt', 'sentAt', 'date');
            const from = formatAddr(pick(msg, 'from', 'envelopeSender', 'sender')) || '—';
            const to = pick(msg, 'forRecipient') || formatRecipients(pick(msg, 'envelopeRecipients', 'recipients', 'to'));
            const subject = pick(msg, 'subject') || '(kein Betreff)';
            const reason = pick(msg, 'reason', 'quarantineReason', 'category', 'classification') || '—';
            const att = (pick(msg, 'attachments') || {}).total || 0;
            const clip = att > 0 ? ` <i class="bi bi-paperclip" title="${att} Anhang/Anhänge"></i>` : '';
            return `<tr>
                <td><input type="checkbox" class="q-check" data-pd="${postDelivery}" value="${escapeAttr(id || '')}" onclick="toggleOne(this, ${postDelivery})" ${id ? '' : 'disabled'}></td>
                <td><span class="text-nowrap">${formatTime(recv)}</span></td>
                <td><code>${escapeHtml(truncate(from, 38))}</code></td>
                <td>${escapeHtml(truncate(to, 38))}${clip}</td>
                <td>${escapeHtml(truncate(subject, 50))}</td>
                <td><span class="severity-badge severity-high">${escapeHtml(truncate(String(reason), 24))}</span></td>
                <td class="text-nowrap">
                    <button class="osint-btn" onclick="viewMessage(${i}, ${postDelivery})" title="Details"><i class="bi bi-eye"></i></button>
                    <button class="ack-btn" onclick="releaseOne(${i}, ${postDelivery}, this)" title="Freigeben"><i class="bi bi-box-arrow-up"></i></button>
                    <button class="block-link" onclick="deleteOne(${i}, ${postDelivery}, this)" title="Löschen"><i class="bi bi-trash"></i></button>
                </td>
            </tr>`;
        }).join('');
    } catch (err) {
        setApiStatus(false, err.message);
        tbody.innerHTML = `<tr><td colspan="7" class="detail-error">${escapeHtml(err.message)}</td></tr>`;
    }
}

function msgId(msg) {
    return pick(msg, 'id', 'messageId', 'quarantineId', 'uuid');
}

// Sophos addresses come as {name?, localAddress, domainAddress} objects.
function formatAddr(a) {
    if (!a) return '';
    if (typeof a === 'string') return a;
    if (a.localAddress && a.domainAddress) {
        const email = `${a.localAddress}@${a.domainAddress}`;
        return a.name ? `${a.name} <${email}>` : email;
    }
    return pick(a, 'name', 'email', 'address') || '';
}

function formatRecipients(r) {
    if (!r) return '—';
    if (Array.isArray(r)) return r.map(formatAddr).filter(Boolean).join(', ') || '—';
    return formatAddr(r) || String(r);
}

function toggleOne(cb, pd) {
    if (cb.checked) selected[pd].add(cb.value); else selected[pd].delete(cb.value);
    updateSelectedCount();
}

function toggleAll(master, pd) {
    const tableId = pd ? 'postdeliveryTable' : 'quarantineTable';
    document.querySelectorAll(`#${tableId} .q-check`).forEach(cb => {
        if (cb.disabled) return;
        cb.checked = master.checked;
        if (master.checked) selected[pd].add(cb.value); else selected[pd].delete(cb.value);
    });
    updateSelectedCount();
}

async function viewMessage(i, pd) {
    const msg = cache[pd][i];
    const id = msgId(msg);
    showDetailModal(`Nachricht · ${escapeHtml(truncate(pick(msg, 'subject') || '', 60))}`, renderJson(msg));
    if (!id) return;
    // The message itself is already in the search result; only attachments need
    // a separate call.
    try {
        const params = new URLSearchParams({ post_delivery: pd });
        const r = await fetch(`/api/email/quarantine/${encodeURIComponent(id)}/attachments?${params}`);
        if (!r.ok) return;
        const d = await r.json();
        const atts = (d.attachments && d.attachments.items) || [];
        let html = renderJson(msg);
        if (Array.isArray(atts) && atts.length) {
            html += '<hr><h6>Anhänge</h6><ul>' + atts.map(a =>
                `<li><code>${escapeHtml(pick(a, 'fileName', 'name', 'filename') || '?')}</code> <span class="text-secondary">${escapeHtml(String(pick(a, 'sizeInBytes', 'size', 'fileSize') || ''))}</span></li>`
            ).join('') + '</ul>';
        }
        document.getElementById('detailBody').innerHTML = html;
    } catch (_) { /* keep cached view */ }
}

// ---- actions ----

async function releaseSelected(pd) {
    const ids = [...selected[pd]];
    if (!ids.length) { alert('Keine Nachrichten ausgewählt.'); return; }
    const allow = confirm(`${ids.length} Nachricht(en) freigeben.\n\n[OK] = Absender zusätzlich auf Allow-Liste setzen\n[Abbrechen] = nur freigeben`);
    await runQuarantineAction('release', ids, pd, { allow_sender: allow });
}

async function deleteSelected(pd) {
    const ids = [...selected[pd]];
    if (!ids.length) { alert('Keine Nachrichten ausgewählt.'); return; }
    if (!confirm(`${ids.length} Nachricht(en) endgültig löschen?\nDiese Aktion wirkt direkt auf den Sophos-Tenant.`)) return;
    const block = confirm('Absender zusätzlich auf Block-Liste setzen?\n[OK] = ja  ·  [Abbrechen] = nur löschen');
    await runQuarantineAction('delete', ids, pd, { block_sender: block });
}

async function releaseOne(i, pd, btn) {
    const id = msgId(cache[pd][i]);
    if (!id) { alert('Keine Message-ID.'); return; }
    const allow = confirm('Nachricht freigeben.\n[OK] = Absender auch erlauben  ·  [Abbrechen] = nur freigeben');
    btn.disabled = true;
    await runQuarantineAction('release', [id], pd, { allow_sender: allow });
}

async function deleteOne(i, pd, btn) {
    const id = msgId(cache[pd][i]);
    if (!id) { alert('Keine Message-ID.'); return; }
    if (!confirm('Nachricht endgültig löschen?')) return;
    const block = confirm('Absender zusätzlich blocken?\n[OK] = ja  ·  [Abbrechen] = nur löschen');
    btn.disabled = true;
    await runQuarantineAction('delete', [id], pd, { block_sender: block });
}

async function runQuarantineAction(action, ids, pd, extra) {
    try {
        const r = await fetch(`/api/email/quarantine/${action}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ids, post_delivery: pd, ...extra }),
        });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
        await loadQuarantine(pd);
    } catch (err) {
        alert(`Aktion "${action}" fehlgeschlagen: ${err.message}`);
        await loadQuarantine(pd);
    }
}

// ------------------------------------------------------------------ helpers

function showDetailModal(title, html) {
    document.getElementById('detailTitle').innerHTML = title;
    document.getElementById('detailBody').innerHTML = html;
    bootstrap.Modal.getOrCreateInstance(document.getElementById('detailModal')).show();
}

function renderJson(obj) {
    return `<pre class="mb-0" style="white-space:pre-wrap;word-break:break-word">${escapeHtml(JSON.stringify(obj, null, 2))}</pre>`;
}

function formatTime(isoStr) {
    if (!isoStr) return '—';
    const d = new Date(isoStr);
    if (isNaN(d)) return escapeHtml(String(isoStr));
    return d.toLocaleString('de-DE', { day: '2-digit', month: '2-digit', year: '2-digit', hour: '2-digit', minute: '2-digit' });
}

function truncate(str, n) {
    str = String(str ?? '');
    return str.length > n ? str.slice(0, n - 1) + '…' : str;
}

// escapeHtml() and escapeAttr() live in js/common.js

// AI chat with persisted sessions. Each session has its own context; a new
// session starts fresh (empty context). The server stores the history — the
// client only tracks which session is active.
let _currentSession = null;   // null = a new, unsaved session (fresh context)

document.addEventListener('DOMContentLoaded', () => {
    const input = document.getElementById('chatInput');
    const send = document.getElementById('chatSend');

    send.addEventListener('click', submit);
    input.addEventListener('keydown', e => { if (e.key === 'Enter') submit(); });
    document.querySelectorAll('.chip').forEach(c =>
        c.addEventListener('click', () => { input.value = c.dataset.cmd; submit(); }));
    document.getElementById('newChatBtn').addEventListener('click', newChat);

    loadSessions();
    newChat();   // start every visit with a fresh context

    async function submit() {
        const msg = input.value.trim();
        if (!msg) return;
        userMsg(msg);
        input.value = '';
        input.disabled = send.disabled = true;
        const thinking = botMsg('…', true);
        try {
            const r = await fetch('/api/chat/command', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: msg, session_id: _currentSession }),
            });
            thinking.remove();
            // A slow chat can hit a proxy 502/504 whose body is HTML, not JSON —
            // surface a clear message instead of a JSON parse error.
            const ct = r.headers.get('content-type') || '';
            if (!ct.includes('application/json')) {
                throw new Error((r.status === 502 || r.status === 504)
                    ? t('chat.timeout') : `HTTP ${r.status}`);
            }
            const d = await r.json();
            if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
            botMsg(d.reply || t('chat.no_reply'));
            _currentSession = d.session_id || _currentSession;
            // Refresh the list so a new session appears / titles + order update.
            loadSessions();
        } catch (err) {
            thinking.remove();
            botMsg(t('chat.error', { msg: err.message }));
        } finally {
            input.disabled = send.disabled = false;
            input.focus();
        }
    }
});

function newChat() {
    _currentSession = null;
    document.getElementById('chatLog').innerHTML = '';
    botMsg(t('chat.greeting'));
    _markActive();
    const inp = document.getElementById('chatInput');
    if (inp) inp.focus();
}

async function loadSessions() {
    const list = document.getElementById('sessionList');
    if (!list) return;
    try {
        const r = await fetch('/api/chat/sessions');
        const d = await r.json();
        const sessions = d.sessions || [];
        if (!sessions.length) {
            list.innerHTML = `<div class="session-empty">${t('chat.no_sessions')}</div>`;
            return;
        }
        list.innerHTML = '';
        sessions.forEach(s => {
            const item = document.createElement('div');
            item.className = 'session-item' + (s.id === _currentSession ? ' active' : '');
            item.dataset.id = s.id;
            const title = document.createElement('span');
            title.className = 's-title';
            title.textContent = s.title || 'Chat';
            title.title = `${s.title || 'Chat'} · ${s.messages} ${t('chat.msg_count')}`;
            title.addEventListener('click', () => openSession(s.id));
            title.addEventListener('dblclick', () => renameSession(s.id, s.title));
            const ren = document.createElement('span');
            ren.className = 's-ren';
            ren.innerHTML = '<i class="bi bi-pencil"></i>';
            ren.title = t('chat.rename');
            ren.addEventListener('click', ev => { ev.stopPropagation(); renameSession(s.id, s.title); });
            const del = document.createElement('span');
            del.className = 's-del';
            del.innerHTML = '<i class="bi bi-trash"></i>';
            del.title = t('common.delete') || 'Delete';
            del.addEventListener('click', ev => { ev.stopPropagation(); deleteSession(s.id); });
            item.append(title, ren, del);
            list.appendChild(item);
        });
    } catch (e) { /* ignore */ }
}

async function openSession(id) {
    try {
        const r = await fetch(`/api/chat/sessions/${id}`);
        if (!r.ok) return;
        const d = await r.json();
        _currentSession = id;
        const log = document.getElementById('chatLog');
        log.innerHTML = '';
        (d.messages || []).forEach(m => {
            if (m.role === 'user') userMsg(m.content);
            else botMsg(m.content);
        });
        if (!(d.messages || []).length) botMsg(t('chat.greeting'));
        _markActive();
    } catch (e) { /* ignore */ }
}

async function renameSession(id, current) {
    const name = prompt(t('chat.rename_prompt'), current || '');
    if (name === null) return;   // cancelled
    const title = name.trim();
    if (!title) return;
    try {
        await fetch(`/api/chat/sessions/${id}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ title }),
        });
        loadSessions();
    } catch (e) { /* ignore */ }
}

async function deleteSession(id) {
    try {
        await fetch(`/api/chat/sessions/${id}`, { method: 'DELETE' });
        if (id === _currentSession) newChat();
        loadSessions();
    } catch (e) { /* ignore */ }
}

function _markActive() {
    document.querySelectorAll('.session-item').forEach(el =>
        el.classList.toggle('active', Number(el.dataset.id) === _currentSession));
}

function _md(s) {
    // minimal, safe markdown: escape then apply **bold** and `code`
    const esc = String(s).replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
    return esc.replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>').replace(/`([^`]+)`/g, '<code>$1</code>');
}

function _append(cls, html) {
    const log = document.getElementById('chatLog');
    const div = document.createElement('div');
    div.className = 'chat-msg ' + cls;
    div.innerHTML = html;
    log.appendChild(div);
    log.scrollTop = log.scrollHeight;
    return div;
}

function userMsg(text) { return _append('user', _md(text)); }
function botMsg(text, pending) { return _append('bot' + (pending ? ' pending' : ''), _md(text)); }

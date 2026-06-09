document.addEventListener('DOMContentLoaded', () => {
    const input = document.getElementById('chatInput');
    const send = document.getElementById('chatSend');
    botMsg("Hi! Ich nehme Befehle in natürlicher Sprache entgegen — z.B. „blockiere 1.2.3.4“, „isoliere PC-12345“, „zeig die Quarantäne“, „OSINT zu 8.8.8.8“ oder „Statistik-Report“. Schreib „hilfe“ für die Übersicht.");

    send.addEventListener('click', submit);
    input.addEventListener('keydown', e => { if (e.key === 'Enter') submit(); });
    document.querySelectorAll('.chip').forEach(c =>
        c.addEventListener('click', () => { input.value = c.dataset.cmd; submit(); }));

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
                body: JSON.stringify({ message: msg }),
            });
            const d = await r.json();
            thinking.remove();
            if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
            botMsg(d.reply || '(keine Antwort)');
        } catch (err) {
            thinking.remove();
            botMsg('⚠️ Fehler: ' + err.message);
        } finally {
            input.disabled = send.disabled = false;
            input.focus();
        }
    }
});

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

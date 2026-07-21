// Loaded on every page. When user auth is enabled, redirects to the login page
// if the session is missing, and shows the current user + a logout button in the
// topbar. When auth is disabled it does nothing. Same-origin fetches include the
// session cookie automatically, so other page scripts need no changes.
(async function () {
    if (location.pathname.endsWith('/login.html')) return;
    try {
        const r = await fetch('/api/auth/me');
        if (r.status === 401) {
            location.href = '/login.html?next=' + encodeURIComponent(location.pathname + location.search);
            return;
        }
        if (!r.ok) return;
        const d = await r.json();
        if (!d.auth_enabled) return;
        _addUserMenu(d.username, d.role);
    } catch (e) { /* offline / ignore */ }

    function _addUserMenu(username, role) {
        const bar = document.querySelector('.app-header .ms-auto')
                 || document.querySelector('.app-header .container-fluid');
        if (!bar || document.getElementById('userMenu')) return;
        const el = document.createElement('span');
        el.id = 'userMenu';
        el.className = 'd-flex align-items-center gap-2 ms-2';
        el.innerHTML =
            `<span class="d-none d-sm-inline" style="font-size:.85rem;opacity:.85">` +
            `<i class="bi bi-person-circle"></i> ${_esc(username)} ` +
            `<span class="badge text-bg-secondary" style="text-transform:capitalize">${_esc(role)}</span></span>` +
            `<button class="btn btn-outline-secondary btn-sm" id="logoutBtn" title="Logout"><i class="bi bi-box-arrow-right"></i></button>`;
        bar.appendChild(el);
        document.getElementById('logoutBtn').addEventListener('click', async () => {
            try { await fetch('/api/auth/logout', { method: 'POST' }); } catch (e) {}
            location.href = '/login.html';
        });
    }
    function _esc(s) { return String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])); }
})();

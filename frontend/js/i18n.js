// Lightweight client-side i18n for Warroom.
//
// Dictionaries are plain globals (window.I18N.de / .en) loaded synchronously via
// /i18n/de.js + /i18n/en.js BEFORE this file and before page scripts, so t() is
// ready by the time any DOMContentLoaded handler runs — no async race.
//
// Usage:
//   - Static markup: <h3 data-i18n="agent.title">…</h3>
//                    <input data-i18n-placeholder="chat.ask">
//                    <button data-i18n-title="common.refresh">
//                    element with markup: <span data-i18n-html="x">…</span>
//   - JS strings:    t('admin.saved') or t('agent.pushed', {n: 5})
//
// The sidebar nav is identical on every page, so it is translated here by an
// href→key map instead of editing 14 duplicated sidebars.

(function () {
    const SUPPORTED = ['en', 'de'];
    const STORAGE_KEY = 'warroom_lang';

    function detectLang() {
        const saved = localStorage.getItem(STORAGE_KEY);
        if (saved && SUPPORTED.includes(saved)) return saved;
        const nav = (navigator.language || navigator.userLanguage || 'en').toLowerCase();
        return nav.startsWith('de') ? 'de' : 'en';   // browser → de, else English
    }

    let LANG = detectLang();
    const DICT = (window.I18N && window.I18N[LANG]) || {};
    const FALLBACK = (window.I18N && window.I18N.en) || {};

    // t('a.b.c') walks nested dict objects; falls back to English, then to the
    // key itself. {vars} are interpolated as {name} placeholders.
    function lookup(dict, key) {
        return key.split('.').reduce((o, k) => (o && typeof o === 'object' ? o[k] : undefined), dict);
    }
    function t(key, vars) {
        let s = lookup(DICT, key);
        if (s === undefined) s = lookup(FALLBACK, key);
        if (s === undefined) return key;
        if (vars) for (const k in vars) s = s.replace(new RegExp('\\{' + k + '\\}', 'g'), vars[k]);
        return s;
    }
    window.t = t;
    window.currentLang = () => LANG;

    // href → nav label key (sidebar is duplicated across all pages).
    const NAV = {
        '/': 'nav.dashboard',
        '/chat.html': 'nav.chat',
        '/netflow.html': 'nav.netflow',
        '/blocked.html': 'nav.blocklist',
        '/monitored.html': 'nav.monitoring',
        '/firewalls.html': 'nav.firewalls',
        '/firewall-anomalies.html': 'nav.fw_anomalies',
        '/endpoints.html': 'nav.endpoints',
        '/hosts.html': 'nav.hosts',
        '/honeypot.html': 'nav.honeypot',
        '/agent.html': 'nav.agent',
        '/agent-workflow.html': 'nav.agent_workflow',
        '/email.html': 'nav.email',
        '/o365.html': 'nav.m365',
        '/osint.html': 'nav.osint',
        '/dossier.html': 'nav.dossier',
        '/xdr.html': 'nav.xdr',
        '/stats.html': 'nav.statistics',
        '/admin.html': 'nav.admin',
    };

    function applyStatic(root) {
        const scope = root || document;
        scope.querySelectorAll('[data-i18n]').forEach(el => {
            const v = t(el.getAttribute('data-i18n'));
            if (v) el.textContent = v;
        });
        scope.querySelectorAll('[data-i18n-html]').forEach(el => {
            const v = t(el.getAttribute('data-i18n-html'));
            if (v) el.innerHTML = v;
        });
        scope.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
            const v = t(el.getAttribute('data-i18n-placeholder'));
            if (v) el.setAttribute('placeholder', v);
        });
        scope.querySelectorAll('[data-i18n-title]').forEach(el => {
            const v = t(el.getAttribute('data-i18n-title'));
            if (v) el.setAttribute('title', v);
        });
        scope.querySelectorAll('[data-i18n-aria-label]').forEach(el => {
            const v = t(el.getAttribute('data-i18n-aria-label'));
            if (v) el.setAttribute('aria-label', v);
        });
    }

    function applyNav() {
        document.querySelectorAll('.sidebar-menu a.nav-link').forEach(a => {
            const href = a.getAttribute('href');
            const key = NAV[href];
            if (!key) return;
            const p = a.querySelector('p');
            if (p) p.textContent = t(key);
        });
    }

    function injectSwitcher() {
        const bar = document.querySelector('.app-header .container-fluid .ms-auto')
                 || document.querySelector('.app-header .ms-auto');
        if (!bar || document.getElementById('langSwitcher')) return;
        const sel = document.createElement('select');
        sel.id = 'langSwitcher';
        sel.className = 'form-select form-select-sm';
        sel.style.width = 'auto';
        sel.title = 'Language';
        sel.innerHTML = '<option value="en">EN</option><option value="de">DE</option>';
        sel.value = LANG;
        sel.addEventListener('change', () => {
            localStorage.setItem(STORAGE_KEY, sel.value);
            location.reload();
        });
        bar.insertBefore(sel, bar.firstChild);
    }

    function applyAll() {
        document.documentElement.lang = LANG;
        applyStatic();
        applyNav();
        injectSwitcher();
    }

    // Expose so dynamically-rendered content can be (re)translated by callers.
    window.i18nApply = applyStatic;

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', applyAll);
    } else {
        applyAll();
    }
})();

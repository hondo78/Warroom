// Global internal-hostname annotator.
//
// Wherever an internal (private) IP is shown inside a <code> element, this
// appends the resolved hostname (from Sophos inventory / reverse DNS / NetBIOS,
// via POST /api/hostnames). It watches the DOM, so it covers every table and
// modal without per-page wiring. Results are cached client-side, and IPs the
// backend is still resolving are re-polled a few times.

(function () {
    const PRIV = /\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/;

    const resolved = new Map();      // ip -> {hostname, source}  (hostname null = none)
    const elByIp = new Map();        // ip -> Set<HTMLElement> awaiting a name
    let pendingReq = new Set();      // ips to request on the next debounced flush
    let flushTimer = null;
    const pollAttempts = new Map();  // ip -> remaining background re-polls

    function firstPrivateIp(text) {
        const m = PRIV.exec(text || '');
        return m ? m[0] : null;
    }

    function annotate(el, info) {
        if (!el.isConnected || el.dataset.hnDone === '1') return;
        el.dataset.hnDone = '1';
        if (!info || !info.hostname) return;
        const span = document.createElement('span');
        span.className = 'ip-hostname';
        span.textContent = info.hostname;
        span.title = info.hostname + (info.source ? ' · ' + info.source : '');
        el.insertAdjacentElement('afterend', span);
    }

    function attach(ip, el) {
        if (resolved.has(ip)) { annotate(el, resolved.get(ip)); return; }
        let set = elByIp.get(ip);
        if (!set) { set = new Set(); elByIp.set(ip, set); }
        set.add(el);
        pendingReq.add(ip);
        scheduleFlush();
    }

    function applyResolved(ip, info) {
        resolved.set(ip, info);
        const set = elByIp.get(ip);
        if (set) { set.forEach(el => annotate(el, info)); elByIp.delete(ip); }
    }

    function scheduleFlush() {
        if (flushTimer) return;
        flushTimer = setTimeout(flush, 200);
    }

    async function flush() {
        flushTimer = null;
        if (!pendingReq.size) return;
        const ips = Array.from(pendingReq).slice(0, 500);
        pendingReq = new Set(Array.from(pendingReq).slice(500));
        if (pendingReq.size) scheduleFlush();
        try {
            const r = await fetch('/api/hostnames', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ips }),
            });
            if (!r.ok) return;
            const d = await r.json();
            const names = d.hostnames || {};
            for (const ip of ips) {
                if (names[ip]) {
                    applyResolved(ip, names[ip]);
                } else {
                    // Still resolving on the backend — re-poll a few times.
                    const left = pollAttempts.has(ip) ? pollAttempts.get(ip) : 5;
                    if (left > 0) {
                        pollAttempts.set(ip, left - 1);
                        setTimeout(() => { if (!resolved.has(ip)) { pendingReq.add(ip); scheduleFlush(); } }, 4000);
                    } else {
                        applyResolved(ip, { hostname: null });   // give up; stop re-scanning
                    }
                }
            }
        } catch (e) { /* offline / transient — try again on the next mutation */ }
    }

    function scan(root) {
        const scope = (root && root.querySelectorAll) ? root : document;
        scope.querySelectorAll('code:not([data-hn])').forEach(el => {
            const ip = firstPrivateIp(el.textContent);
            el.dataset.hn = ip ? 'seen' : 'skip';   // never look at this element again
            if (ip) attach(ip, el);
        });
    }

    let scanTimer = null;
    function scheduleScan() {
        if (scanTimer) return;
        scanTimer = setTimeout(() => { scanTimer = null; scan(document); }, 150);
    }

    function start() {
        scan(document);
        new MutationObserver(muts => {
            for (const m of muts) {
                if (m.addedNodes && m.addedNodes.length) { scheduleScan(); return; }
            }
        }).observe(document.body, { childList: true, subtree: true });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', start);
    } else {
        start();
    }
})();

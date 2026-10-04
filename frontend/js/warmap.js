// WarMap: one map component with two views of the same data —
//   • "globe": a WebGL globe (globe.gl) with animated arcs and pulsing hubs,
//   • "2d":    a dark Leaflet map with curved, animated arcs.
// The user switches with the toggle in the top-left corner; the choice is
// remembered per browser. Pages hand over plain data and never touch either
// library directly:
//
//   const wm = createWarMap(containerEl, { storageKey: 'dash' });
//   wm.setHubs([{ lat, lon, popup }]);                       // our firewalls
//   wm.setPoints([{ lat, lon, color, size, label, popup }]); // remote ends
//   wm.setArcs([{ from: [lat, lon], to: [lat, lon], color, weight }]);
//   wm.setOverlay([...points]);                              // optional extra layer
//   wm.overlayEl                                             // put a legend here
//
// size is 1..12 (roughly a marker radius in px). popup is trusted HTML the
// caller already escaped; label is plain text for the hover tooltip.
// Arcs flow from `from` to `to`, so callers express direction by the order.

(function () {
    const GLOBE_TEXTURE = '/img/earth-night.jpg';
    const MODE_KEY = 'warroom_map_mode';
    // A globe with thousands of animated arcs drops frames on modest GPUs and
    // reads as noise anyway; the strongest arcs carry the picture.
    const GLOBE_MAX_ARCS = 400;

    function hasWebGL() {
        try {
            const c = document.createElement('canvas');
            return !!(window.WebGLRenderingContext && (c.getContext('webgl2') || c.getContext('webgl')));
        } catch (e) { return false; }
    }

    function loadMode(key) {
        try { return localStorage.getItem(`${MODE_KEY}:${key}`); } catch (e) { return null; }
    }
    function saveMode(key, mode) {
        try { localStorage.setItem(`${MODE_KEY}:${key}`, mode); } catch (e) { /* private mode */ }
    }

    const tr = (key, fallback) => (typeof tOr === 'function' ? tOr(key, fallback) : fallback);

    // Points along a curved path between two coordinates, for the 2D view.
    // The bend is perpendicular to the straight line and grows with distance;
    // the target longitude is shifted by ±360 so arcs take the short way round.
    function curve(from, to, steps) {
        const [lat1, lon1] = from;
        let [lat2, lon2] = to;
        if (lon2 - lon1 > 180) lon2 -= 360;
        else if (lon1 - lon2 > 180) lon2 += 360;
        const dx = lon2 - lon1, dy = lat2 - lat1;
        const dist = Math.sqrt(dx * dx + dy * dy);
        const cx = (lon1 + lon2) / 2 - dy * 0.2, cy = (lat1 + lat2) / 2 + dx * 0.2;
        const n = Math.max(8, Math.min(steps || 32, Math.round(dist)));
        const out = [];
        for (let i = 0; i <= n; i++) {
            const t = i / n, u = 1 - t;
            out.push([u * u * lat1 + 2 * u * t * cy + t * t * lat2,
                      u * u * lon1 + 2 * u * t * cx + t * t * lon2]);
        }
        return out;
    }

    function withAlpha(hex, a) {
        const m = /^#([0-9a-f]{6})$/i.exec(hex || '');
        if (!m) return hex;
        const n = parseInt(m[1], 16);
        return `rgba(${n >> 16},${(n >> 8) & 255},${n & 255},${a})`;
    }

    window.createWarMap = function (container, opts) {
        opts = opts || {};
        const storageKey = opts.storageKey || 'default';
        const webgl = hasWebGL() && typeof Globe === 'function';
        let mode = loadMode(storageKey) || (webgl ? 'globe' : '2d');
        if (!webgl) mode = '2d';

        container.classList.add('warmap');
        container.innerHTML = '';
        const globeEl = document.createElement('div');
        globeEl.className = 'warmap-view warmap-globe';
        const flatEl = document.createElement('div');
        flatEl.className = 'warmap-view warmap-flat';
        const overlayEl = document.createElement('div');
        overlayEl.className = 'warmap-overlay';
        const panel = document.createElement('div');
        panel.className = 'warmap-panel';
        panel.hidden = true;
        const toggle = document.createElement('div');
        toggle.className = 'warmap-toggle btn-group btn-group-sm';
        toggle.innerHTML =
            `<button type="button" class="btn btn-dark" data-mode="globe"${webgl ? '' : ' disabled'}>`
            + `<i class="bi bi-globe2"></i> ${escapeHtml(tr('common.map_globe', 'Globe'))}</button>`
            + `<button type="button" class="btn btn-dark" data-mode="2d">`
            + `<i class="bi bi-map"></i> ${escapeHtml(tr('common.map_2d', '2D'))}</button>`;
        container.append(globeEl, flatEl, overlayEl, panel, toggle);

        const state = { hubs: [], points: [], arcs: [], overlay: [] };
        let globe = null, flat = null;

        // ── Globe ──────────────────────────────────────────────────────────
        function showPanel(html) {
            panel.innerHTML = `<button type="button" class="btn-close btn-close-white warmap-panel-close" aria-label="Close"></button>${html}`;
            panel.hidden = false;
            panel.querySelector('.warmap-panel-close').onclick = () => { panel.hidden = true; };
            if (window.i18nApply) window.i18nApply(panel);
        }

        function buildGlobe() {
            globe = new Globe(globeEl, { animateIn: true })
                .globeImageUrl(GLOBE_TEXTURE)
                .backgroundColor('rgba(0,0,0,0)')
                .showAtmosphere(true)
                .atmosphereColor('#3b82f6')
                .atmosphereAltitude(0.18)
                .pointLat('lat').pointLng('lon')
                .pointColor('color')
                .pointRadius(d => 0.15 + (d.size || 3) * 0.05)
                .pointAltitude(d => 0.004 + (d.size || 3) * 0.0015)
                .pointResolution(8)
                .pointsMerge(false)
                .pointLabel(d => `<div class="warmap-tip">${escapeHtml(d.label || '')}</div>`)
                .onPointClick(d => { if (d.popup) showPanel(d.popup); })
                .arcStartLat(d => d.from[0]).arcStartLng(d => d.from[1])
                .arcEndLat(d => d.to[0]).arcEndLng(d => d.to[1])
                .arcColor(d => [withAlpha(d.color, 0.15), withAlpha(d.color, 0.95)])
                .arcStroke(d => 0.25 + (d.weight || 1) * 0.25)
                .arcDashLength(0.35)
                .arcDashGap(0.9)
                .arcDashInitialGap(() => Math.random())
                .arcDashAnimateTime(d => 1800 + (1 - Math.min(d.weight || 1, 3) / 3) * 2400)
                .arcAltitudeAutoScale(0.45)
                .ringLat('lat').ringLng('lon')
                .ringColor(() => t => `rgba(96,165,250,${1 - t})`)
                .ringMaxRadius(4)
                .ringPropagationSpeed(2)
                .ringRepeatPeriod(1400);
            const ctl = globe.controls();
            ctl.autoRotate = true;
            ctl.autoRotateSpeed = 0.35;
            // Stop spinning as soon as someone grabs the globe; they want to look.
            globeEl.addEventListener('pointerdown', () => { ctl.autoRotate = false; }, { once: true });
            globe.pointOfView({ lat: 35, lng: 10, altitude: 1.7 });
            new ResizeObserver(() => {
                globe.width(globeEl.clientWidth).height(globeEl.clientHeight);
            }).observe(globeEl);
            renderGlobe();
        }

        function renderGlobe() {
            if (!globe) return;
            const hubPoints = state.hubs.map(h => ({ ...h, color: '#60a5fa', size: 4, label: h.label }));
            globe.pointsData([...state.overlay, ...state.points, ...hubPoints]);
            const arcs = state.arcs.length > GLOBE_MAX_ARCS
                ? [...state.arcs].sort((a, b) => (b.weight || 0) - (a.weight || 0)).slice(0, GLOBE_MAX_ARCS)
                : state.arcs;
            globe.arcsData(arcs);
            globe.ringsData(state.hubs);
        }

        // ── 2D ─────────────────────────────────────────────────────────────
        function buildFlat() {
            const map = L.map(flatEl, {
                center: [30, 10], zoom: 2, minZoom: 2, maxZoom: 12,
                worldCopyJump: true,
            });
            map.attributionControl.setPrefix(false);
            // Carto's dark basemap started answering every tile with an
            // "API KEY REQUIRED" image; Esri's dark canvas needs no key.
            const esri = 'https://server.arcgisonline.com/ArcGIS/rest/services/Canvas';
            L.tileLayer(`${esri}/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}`, {
                maxNativeZoom: 16, maxZoom: 19,
                attribution: 'Tiles &copy; Esri &mdash; Esri, HERE, Garmin, OpenStreetMap contributors',
            }).addTo(map);
            // Place names above the arcs, but never in the way of a click.
            const labels = map.createPane('warmapLabels');
            labels.style.zIndex = 450;
            labels.style.pointerEvents = 'none';
            L.tileLayer(`${esri}/World_Dark_Gray_Reference/MapServer/tile/{z}/{y}/{x}`, {
                maxNativeZoom: 16, maxZoom: 19, pane: 'warmapLabels',
            }).addTo(map);
            flat = {
                map,
                arcs: L.layerGroup().addTo(map),
                overlay: L.layerGroup().addTo(map),
                points: L.layerGroup().addTo(map),
                hubs: L.layerGroup().addTo(map),
            };
            renderFlat();
        }

        function circle(p) {
            const m = L.circleMarker([p.lat, p.lon], {
                radius: p.size || 4,
                fillColor: p.color, color: p.stroke || p.color,
                weight: p.strokeWeight || 1, dashArray: p.dashArray || null,
                opacity: 0.95, fillOpacity: 0.65,
            });
            if (p.popup) m.bindPopup(p.popup, { maxWidth: 360, minWidth: 240 });
            else if (p.label) m.bindTooltip(p.label);
            return m;
        }

        function renderFlat() {
            if (!flat) return;
            flat.arcs.clearLayers();
            flat.points.clearLayers();
            flat.overlay.clearLayers();
            flat.hubs.clearLayers();
            state.arcs.forEach(a => {
                const w = a.weight || 1;
                flat.arcs.addLayer(L.polyline(curve(a.from, a.to), {
                    color: a.color, weight: 0.6 + w * 0.6, opacity: 0.55,
                    className: 'warmap-arc', interactive: false,
                }));
            });
            state.overlay.forEach(p => flat.overlay.addLayer(circle(p)));
            state.points.forEach(p => flat.points.addLayer(circle(p)));
            state.hubs.forEach(h => {
                const m = L.marker([h.lat, h.lon], {
                    icon: L.divIcon({ className: 'warmap-hub', html: '<span></span>', iconSize: [14, 14] }),
                });
                if (h.popup) m.bindPopup(h.popup);
                flat.hubs.addLayer(m);
            });
        }

        // ── Mode switching ────────────────────────────────────────────────
        function apply() {
            container.dataset.mode = mode;
            toggle.querySelectorAll('[data-mode]').forEach(b =>
                b.classList.toggle('active', b.dataset.mode === mode));
            panel.hidden = true;
            if (mode === 'globe') {
                if (!globe) buildGlobe(); else { globe.resumeAnimation(); renderGlobe(); }
            } else {
                if (globe) globe.pauseAnimation();
                if (!flat) buildFlat(); else { flat.map.invalidateSize(); renderFlat(); }
            }
        }
        toggle.addEventListener('click', e => {
            const b = e.target.closest('[data-mode]');
            if (!b || b.disabled || b.dataset.mode === mode) return;
            mode = b.dataset.mode;
            saveMode(storageKey, mode);
            apply();
        });

        function render() { if (mode === 'globe') renderGlobe(); else renderFlat(); }

        apply();

        return {
            overlayEl,
            get mode() { return mode; },
            setHubs(h) { state.hubs = (h || []).filter(x => x.lat != null && x.lon != null); render(); },
            setPoints(p) { state.points = (p || []).filter(x => x.lat != null && x.lon != null); render(); },
            setArcs(a) { state.arcs = a || []; render(); },
            setOverlay(p) { state.overlay = (p || []).filter(x => x.lat != null && x.lon != null); render(); },
        };
    };

    // Nearest hub to a coordinate (plain degrees — good enough to pick which
    // of a handful of firewalls an arc should land on).
    window.nearestHub = function (hubs, lat, lon) {
        let best = null, min = Infinity;
        (hubs || []).forEach(h => {
            const d = (h.lat - lat) ** 2 + (h.lon - lon) ** 2;
            if (d < min) { min = d; best = h; }
        });
        return best;
    };
})();

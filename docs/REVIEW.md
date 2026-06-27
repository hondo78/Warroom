# Warroom – Project Review & Improvement Roadmap

Status: 2026-05-29. Complete review of backend, frontend, collectors,
DB schema and infrastructure. Findings are verified against the code; severities
reflect the use as an **internal tool behind VPN/firewall**.

## Overall impression

Solid, well-thought-out architecture for a private SecOps tool. Particularly good:

- **API key cleanly injected server-side** – nginx appends `X-API-Key` to
  `/api/*`, the key is never in the browser (`frontend/nginx.conf.template`).
- **Auth global** via `dependencies=[Depends(verify_api_key)]`
  (`backend/app/main.py:107`), comparison timing-safe via `hmac.compare_digest`.
- **Consistent XSS protection**: `escapeHtml()` is used in all JS files before
  `innerHTML`.
- **Live IOC feeds without sync logic** – block/unblock instantly in the feed.
- **Runtime configuration** via the Admin UI without restarting containers.
- SQL parameterized throughout (`:since`, `:ips`); no real injection
  found – the `text()` fragments are static constants.

## Correction to an often-assumed point

**There are NO secrets in the Git repo.** `.env` is in `.gitignore` and appears
neither in `git ls-files` nor in the `git log`. The real credentials exist
only in the local `.env` working copy – correct. (Nevertheless: protect the local
`.env`, never commit it.)

---

## Prioritized improvements

### P1 – Do before production use

| # | Topic | File(s) | Recommendation |
|---|-------|-----------|------------|
| 1 | **Open-mode default** | `config.py:27`, `main.py:42` | `WARROOM_API_KEY` defaults to empty → completely open. Enforce/document setting it (now marked "strongly recommended" in the README). |
| 2 | **Grafana admin/admin + anonymous** | `docker-compose.yml:98-102` | Default password and anonymous viewer access. Set the password via `GRAFANA_ADMIN_PASSWORD`; disable anonymous if necessary. |
| 3 | **No HTTPS** | `nginx.conf.template` | Only port 80. Put a TLS reverse proxy in front or a certificate in nginx. |
| 4 | **Security headers missing** | `nginx.conf.template` | Add `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, CSP. Quick to implement, high benefit. |

### P2 – Robustness & data retention

| # | Topic | File(s) | Recommendation |
|---|-------|-----------|------------|
| 5 | **No DB retention** | `db/init.sql` | `firewall_logs`, `events`, `alerts`, `geoip_cache` grow unbounded (only NetFlow has a 30-day cleanup). Cleanup job or range partitioning by `created_at`. |
| 6 | **Syslog queue drops silently** | `syslog/syslog_receiver.py` (queue maxsize 10000) | Under load spikes, messages are dropped with a mere `warning`. Add a counter/metric and possibly persistence. |
| 7 | **Healthchecks missing** | `docker-compose.yml` (syslog, netflow, backend, frontend) | Only postgres/redis have healthchecks. A crash otherwise goes unnoticed. |
| 8 | **No resource limits** | `docker-compose.yml` | `deploy.resources.limits` per service so a leak does not kill the host. |
| 9 | **LLM endpoint outage** | `agent.py`, `main.py:72-91` | The scheduler keeps firing every ~120 s, every decision "failed". Backoff/circuit breaker on repeated failure. |

### P3 – Code quality & maintainability

| # | Topic | File(s) | Recommendation |
|---|-------|-----------|------------|
| 10 | **JS duplication** | `frontend/js/*.js` | `escapeHtml`/`formatTime`/`truncate` defined 4–6×. Centralize in `js/common.js`. |
| 11 | **inline `onclick` with string interpolation** | `app.js` (block buttons) | Comma/quote breakage possible. Switch to `addEventListener` + `data-*` attributes. |
| 12 | **Duplicate SQL fragments** | `agent.py` vs. `main.py` (`_WAF_FILTER_SQL*`) | Define the WAF/IPS filter in one place and import it. |
| 13 | **Blocking MaxMind lookup in async** | `geoip_service.py:92` | `_lookup_maxmind` is synchronous; memory-mapped → minimal, but cleaner via `run_in_executor`. |
| 14 | **Redis client never closed** | `geoip_service.py:24-28` | Add `await _redis.aclose()` in the `lifespan` shutdown. |
| 15 | **LLM JSON parsing tolerant** | `agent.py` `_parse_decision` | Takes the "last block" – reasoning models can leave draft actions behind. Stricter schema/validation. |
| 16 | **Hardcoded /24 subnet mask** | `agent.py` (failed-login subnet) | Make the mask configurable (e.g. also /16). |
| 17 | **Postgres SSL disabled** | `grafana/.../postgres.yml:sslmode=disable` | Acceptable within the same Docker network; enable for external DB access. |

### P4 – Nice-to-have

- Structured (JSON) logging in the backend for aggregation.
- Subresource Integrity (SRI) for CDN scripts in the HTML pages.
- Document a DB backup/WAL strategy for `postgres_data`.
- IDN/homograph check in domain/URL normalization (`main.py`).
- NetFlow template cache without TTL (theoretical memory drift with
  long-running exporters that reuse templates).

---

## Quick wins (small, immediate, high benefit)

1. ✅ **Done** – Security headers + CSP in `nginx.conf.template` (P1 #4).
   CSP keeps `'unsafe-inline'` in `script-src` for now, because inline
   `onclick` handlers still exist (see P3 #11). After their rework,
   `'unsafe-inline'` can be removed → strict policy.
2. ✅ **Partially done** – `frontend/js/common.js` now centralizes
   `escapeHtml()` + `escapeAttr()` (previously duplicated 5×/2×). `formatTime()`
   and `truncate()` deliberately stay page-local (they differ per page).
3. ✅ **Done** – Redis `close_redis()` is called in the `lifespan` shutdown
   (`geoip_service.py` / `main.py`).
4. ⬜ Open – Healthcheck for `backend` (`GET /` or `/health`) and `syslog`
   (P2 #7). Note: global auth dependency → either an auth-free
   `/health` endpoint or the healthcheck sends the `X-API-Key`.
5. ⬜ Open – Cron cleanup query for `firewall_logs`/`geoip_cache` (P2 #5).

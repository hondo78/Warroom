# Warroom — Project Description

> Security operations dashboard for Sophos Central & Sophos Firewalls with
> AI agent, OSINT enrichment and automated defense.
> Setup: see [`../README.md`](../README.md).

## 1. What is this about?

Warroom brings together the security-relevant data sources of a Sophos environment in
one place and turns monitoring into an active defense:

- **See:** alerts/events/detections from Sophos Central, firewall logs
  (IPS, WAF, auth) and NetFlow — with a live map of attacker geolocation.
- **Assess:** check IPs/domains/URLs against several OSINT sources (Intelix,
  AbuseIPDB, VirusTotal, Shodan, GreyNoise, ipinfo, DNS) — manually or via AI.
- **Act:** hits land on central blocklists that the firewalls pull as
  IOC feeds; manage mailboxes/quarantine via the Sophos Email API.

**Target audience:** SecOps/admins of small–medium Sophos environments who want a
self-hosted cockpit without SaaS dependency.
**Principles:** self-hosted, human stays in control (AI recommends
by default), whitelist protects your own IPs from accidental blocking.

## 2. Architecture

Everything runs in containers (`docker-compose.yml`):

| Container  | Port (host)    | Task |
|------------|----------------|---------|
| `frontend` | `8448`         | Nginx: static UI + reverse proxy `/api/`→backend, sets API key |
| `backend`  | internal `8000`  | FastAPI: REST API, Sophos integration, AI agent, OSINT, IOC feeds |
| `syslog`   | `5514/udp+tcp` | Sophos Firewall syslog → `firewall_logs` |
| `netflow`  | `2055/udp`     | NetFlow v5/v9/IPFIX → `netflow_buckets` |
| `postgres` | internal `5432`  | Persistence |
| `redis`    | internal `6379`  | Cache (summaries, OSINT lookups) |
| `grafana`  | `3030`         | Dashboards directly on the DB |

**Stack:** FastAPI + SQLAlchemy 2 (async) + APScheduler · PostgreSQL 16 · Redis 7
· Vanilla JS/AdminLTE (no build step) · GeoIP MaxMind GeoLite2 · AI via an
OpenAI-compatible endpoint (LMStudio/Ollama/vLLM/OpenAI) · Grafana 11.

**Backend modules (`backend/app/`):** `main.py` (routes, scheduler) ·
`sophos_client.py` (Central + Email API) · `collector.py` (sync) · `agent.py`
(AI loops, triage) · `osint.py` (lookups, 1 h cache) · `settings_store.py` (live
config) · `geoip_service.py` · `*_metrics.py`.

**Data flow:**
1. Sophos Central API → `collector` → DB
2. Firewall syslog → `syslog` → `firewall_logs`
3. NetFlow → `netflow` → `netflow_buckets`
4. UI → backend reads DB (partly Redis-cached) → frontend
5. Block action (UI/AI/OSINT) → `blocked_ips/_domains/_urls`
6. Firewall pulls `/ioc_IP` · `/ioc_domain` · `/ioc_url` → live from the tables

## 3. AI agent (optional)

Uses an OpenAI-compatible model; receives structured JSON and must return strict
JSON (`action`/`args`/`confidence`/`reasoning`) — the backend
re-validates every response. Loops (individually activatable, own prompt): alert,
WAF, IPS, failed login (per IP) as well as **distributed brute-force** (the agent
receives all logins of the last 60 min, groups them itself by /24, counts and
recommends `block_subnet`/`block_ips`) and **triage** (value from the OSINT page).
Recommendations are `pending` by default (approval by a human); optionally
auto-execute/confidence threshold. Model, intervals, thresholds, temperature,
max tokens and prompts are configurable live in the admin area.

## 4. Usage

Entry point: `http://<host>:8448`.

| Page | URL | Usage |
|-------|-----|---------|
| Dashboard | `/` | Situational picture, attack map, firewall logs; block IPs, acknowledge alerts, isolate endpoints |
| NetFlow | `/netflow.html` | Top talkers, destinations, ports, protocols, throughput |
| Blocklist | `/blocked.html` | Block IPs/domains/URLs, whitelist, IOC feeds |
| Firewalls | `/firewalls.html` | Locations, interfaces, whitelist |
| Agent | `/agent.html` | Approve/reject AI decisions, LLM statistics |
| Email | `/email.html` | Manage mailboxes, search quarantine, release/delete |
| OSINT | `/osint.html` | Check IP/domain/URL → block immediately or hand to AI triage |
| Stats | `/stats.html` | OSINT/LLM usage, cache rate |
| Admin | `/admin.html` | API keys, intervals, LLM parameters, prompts — live |
| Grafana | `:3030` | Prebuilt DB dashboards |

**Typical workflows:** block an attack (suspicious IP → 🔍 OSINT → block immediately
or hand to AI triage → firewall pulls IOC feed) · operate the agent (Admin: model/
loops/thresholds → Agent: check recommendations/auto-execute) · distributed
brute-force (agent detects /24 clusters of the last 60 min) · email (search the
quarantine, release/delete, allow/block sender).

**Data sources:** Sophos credentials in Admin/`.env`; firewall syslog on
`host:5514`; NetFlow on `host:2055`; firewall pulls `/ioc_*`.

## 5. Security

`X-API-Key` on all `/api/*` (injected by Nginx) · strict CSP & security headers
· whitelist prevents self-block · AI by default only recommends · secrets masked in
the Admin API. More: [`REVIEW.md`](REVIEW.md).

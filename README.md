# Warroom

Security operations dashboard for small to medium-sized Sophos environments.
Aggregates data from **Sophos Central** (alerts, events, endpoints, firewalls),
**Sophos Firewall (SFOS) syslog** (IPS, WAF, auth, traffic) as well as **NetFlow
v5/v9/IPFIX**, and enriches IPs via **GeoIP + AbuseIPDB / VirusTotal / Shodan /
Sophos Intelix / GreyNoise**. Blocked IPs, domains and URLs are published as
**IOC feeds** (TXT) that firewalls pull via URL.

> **In one sentence:** Pour in your logs, see attackers on a map,
> block them with a single click (or via AI agent) – and the firewall pulls
> the blocklist itself.

```
┌──────────────────┐  Syslog 5514     ┌──────────┐
│ Sophos Firewall  │ ───────────────► │ syslog   │──┐
└──────────────────┘  NetFlow 2055    └──────────┘  │
        │                                            ▼
        │              ┌──────────┐    ┌────────────────────┐
        │              │ netflow  │ ──►│   PostgreSQL       │◄──┐
        │              └──────────┘    └────────────────────┘   │
        ▼                                       ▲                │
┌──────────────────┐    REST API                │                │
│ Sophos Central   │ ◄───────────────────  ┌─────────┐           │
└──────────────────┘                       │ backend │ ──► Redis │
                                           └─────────┘  (Cache)  │
                                                ▲                │
                                                │ /ioc_IP        │
                                                ▼                │
                                            ┌─────────┐          │
                              Browser ◄───► │ nginx   │          │
                                            └─────────┘          │
                                                 ▲               │
                                                 │ HTTP-Pull     │
                                                 │ (X-API-Key)   │
                                            ┌────┴────┐          │
                                            │Firewall │──────────┘
                                            └─────────┘    Blocklist
```

---

## Contents

> 📖 Detailed **project description, architecture & usage**: [`docs/PROJEKTBESCHREIBUNG.md`](docs/PROJEKTBESCHREIBUNG.md)

- [What can Warroom do? (User view)](#what-can-warroom-do-user-view)
- [Requirements](#requirements)
- [Setup in 6 steps](#setup-in-6-steps)
- [What do I need to obtain? (Checklist)](#what-do-i-need-to-obtain-checklist)
- [Connecting data sources](#connecting-data-sources)
- [IOC feeds for firewalls](#ioc-feeds-for-firewalls)
- [Block API (Web UI)](#block-api-web-ui)
- [AI agent (optional)](#ai-agent-optional)
- [Microsoft 365 audit logs (optional)](#microsoft-365-audit-logs-optional)
- [Entra ID login blocking (optional)](#entra-id-login-blocking-optional)
- [Telegram approvals (optional)](#telegram-approvals-optional)
- [AI chat & Teams commands](#ai-chat--teams-commands)
- [Security & hardening](#security--hardening)
- [Stack & services](#stack--services)
- [Troubleshooting](#troubleshooting)

---

## What can Warroom do? (User view)

After logging in (dashboard at `http://<host>:8448`), the following pages are
available:

| Page | URL | What you can do there |
|-------|-----|------------------------|
| **Dashboard** | `/` | Alerts, events & detections from Sophos Central; live map with attacker geolocation; firewall logs (IPS / WAF / auth / failed logins); AI agent recommendations; endpoint overview. Block IPs directly with a click, acknowledge alerts, isolate endpoints. |
| **AI Chat** | `/chat.html` | Natural-language commands: block IP/domain/FQDN/URL, isolate endpoint, query quarantine, OSINT lookup, statistics report. The same engine is reachable via **Microsoft Teams**. |
| **Blocklist** | `/blocked.html` | Manually block/unblock IPs, domains and URLs; maintain the whitelist; inspect the finished IOC feeds. |
| **NetFlow** | `/netflow.html` | Traffic analysis: top talkers, destinations, ports, protocol mix, interface throughput. |
| **Firewalls** | `/firewalls.html` | Firewall locations on the map, interface statistics, whitelist management. |
| **Endpoints** | `/endpoints.html` | Sophos Endpoint Management API: device **inventory** (health/isolation/tamper/OS) with detail view, isolate/release, on-demand scan, de-register · **groups** (create/delete) · **policies** (list + detail) · **settings** (global tamper protection, allow/block list, scan exclusions, web control local sites — each add/delete) · **installer downloads** per platform. |
| **Agent** | `/agent.html` | Decision log of the AI agent; approve/reject recommendations; LLM statistics. Detects, among other things, **distributed brute-force attacks** (many source IPs across multiple /24 networks against the same account → `block_ips`) and accepts **triage inputs**. |
| **Agent Workflow** | `/agent-workflow.html` | Visualizes the decision pipeline and makes **every stage** (trigger, thresholds, interval, allowed actions, system prompt, auto-execute) editable live. The LLM is addressed with **structured outputs** (Pydantic schema via `response_format`) and validated in a typed manner. |
| **Email** | `/email.html` | Sophos Email Management API: manage mailboxes (create/modify/delete), search quarantine & post-delivery quarantine, release/delete messages (optionally allow/block sender). |
| **Microsoft 365** | `/o365.html` | M365 login audit (Management Activity API): successful & failed sign-ins with app, **device** (name/OS/browser/compliance), source IP, location. Columns **sortable and filterable**; OSINT drilldown per IP; failed logins directly blockable (whitelisted IPs protected). |
| **OSINT** | `/osint.html` | Check an IP, domain or URL manually — Sophos Intelix, AbuseIPDB, VirusTotal, GreyNoise, ipinfo & DNS in parallel; cache bypass. **Shodan** is credit-frugal opt-in: only via the "🛰️ Query Shodan" button. Checked values can be **blocked immediately** or handed to the **AI triage**. Every lookup is stored in a searchable **persistent history** (`osint_results`) (beyond the 1h Redis cache); open ports & CVEs additionally as a map layer. |
| **Stats** | `/stats.html` | Usage of the OSINT providers (daily/monthly limits), LLM calls & tokens, cache hit rate. |
| **Admin** | `/admin.html` | Edit all API keys, intervals, log level and agent settings **live** – without restarting containers. |
| **Grafana** | `:3030` | Prebuilt dashboards (Warroom, NetFlow, Blocklist) directly on the PostgreSQL DB. |

---

## Requirements

On the host you only need:

- **Docker** and **Docker Compose v2** (`docker compose version` ≥ 2.x)
- **Git**
- Free ports on the host: **8448** (dashboard), **3030** (Grafana),
  **5514/udp+tcp** (syslog), **2055/udp** (NetFlow)
- Optional, but recommended: a second device that sends syslog/NetFlow
  (Sophos Firewall or similar)

There is **no build step** for the frontend (vanilla JS) and no local
Python installation needed – everything runs in containers.

---

## Setup in 6 steps

```bash
# 1) Clone
git clone https://github.com/hondo78/Warroom.git
cd Warroom

# 2) Create configuration
cp .env.example .env

# 3) Fill in .env – at minimum:
#    - POSTGRES_PASSWORD + DATABASE_URL (same password!)
#    - WARROOM_API_KEY   (openssl rand -hex 32)   [strongly recommended]
#    - GRAFANA_ADMIN_PASSWORD
#    - SOPHOS_CLIENT_ID / SOPHOS_CLIENT_SECRET     [for Sophos Central data]
$EDITOR .env

# 4) (Optional) Provide GeoIP databases – see checklist below.
#    Without them, Warroom runs with the ip-api.com fallback.
#    Place GeoLite2-City.mmdb and GeoLite2-ASN.mmdb into ./geoip/.

# 5) Start
docker compose up -d

# 6) Check status
docker compose ps
docker compose logs -f backend
```

Then reachable at:

- **Dashboard:** <http://localhost:8448>
- **Admin UI:** <http://localhost:8448/admin.html>
- **Grafana:** <http://localhost:3030> (login with `GRAFANA_ADMIN_*`)

The rest of the configuration (OSINT keys, agent, intervals) can be added
conveniently in the **Admin UI** – no restart is needed.

---

## What do I need to obtain? (Checklist)

| # | What | Required? | Where from | Where to |
|---|-----|----------|-------|-------|
| 1 | **DB password** | ✅ | make one up yourself | `POSTGRES_PASSWORD` **and** `DATABASE_URL` in `.env` |
| 2 | **WARROOM_API_KEY** | ⭐ strongly recommended | `openssl rand -hex 32` | `WARROOM_API_KEY` in `.env` |
| 3 | **Grafana password** | ⭐ recommended | make one up yourself | `GRAFANA_ADMIN_PASSWORD` in `.env` |
| 4 | **Sophos Central credentials** | for Central data | Sophos Central → Global Settings → API Credentials Management → *Add Credential* | `SOPHOS_CLIENT_ID` / `SOPHOS_CLIENT_SECRET` |
| 5 | **GeoLite2-City.mmdb + GeoLite2-ASN.mmdb** | optional | [MaxMind GeoLite2](https://www.maxmind.com/en/geolite2/signup) (free) | files in `./geoip/` |
| 6 | **AbuseIPDB key** | optional | <https://www.abuseipdb.com> | `ABUSEIPDB_API_KEY` |
| 7 | **VirusTotal key** | optional | <https://www.virustotal.com> | `VIRUSTOTAL_API_KEY` |
| 8 | **Shodan key** | optional | <https://account.shodan.io> | `SHODAN_API_KEY` |
| 9 | **Sophos Intelix credentials** | optional | <https://api.labs.sophos.com> | `SOPHOS_INTELIX_CLIENT_ID/SECRET` |
| 10 | **LLM endpoint** (for AI agent) | optional | LMStudio / Ollama / vLLM / OpenAI | `AGENT_*` in `.env` |

> **GeoIP note:** `geoip/*.mmdb`, `*.tar.gz` and `*.zip` are excluded in
> `.gitignore` (the files are large and subject to the
> MaxMind license). Download them after registration and unpack
> `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb` directly into `./geoip/`.
> Backend and syslog service mount this directory automatically.

---

## Connecting data sources

### Sophos Firewall Syslog

*System → Administration → Notification settings → Syslog Server:*

- **Host:** IP of the Warroom host
- **Port:** 5514 (UDP or TCP)
- **Format:** Standard / Device-Syslog
- Enabled categories: **Firewall** (traffic), **IPS**, **WAF**,
  **Authentication**, **Admin**, **System**

### NetFlow

Point the NetFlow export (v5/v9/IPFIX) of the firewall/router to
**`<warroom-host>:2055/udp`**. Buckets are aggregated per minute,
retention by default 30 days (`RETENTION_DAYS` in the `netflow` service).

### Sophos Central

As soon as `SOPHOS_CLIENT_ID`/`SECRET` are set, the `collector` fetches
alerts, events, endpoints and firewall status every `COLLECTOR_INTERVAL`
seconds (default 300).

---

## IOC feeds for firewalls

The lists are maintained at <http://localhost:8448/blocked.html>. Every
block/unblock action is visible in the feed **immediately** (live from the DB, no
push, no reconcile, no cache).

| Feed | Endpoint | Format |
|------|----------|--------|
| IPs | `GET /ioc_IP` | one IPv4/IPv6 per line, sorted |
| Domains | `GET /ioc_domain` | hostnames, wildcards `*.evil.tld` allowed |
| URLs | `GET /ioc_url` | full URLs incl. `http(s)://` and path |

All feeds expect the header `X-API-Key: <WARROOM_API_KEY>` (except in Open
Mode).

```
GET https://<warroom-host>:8448/ioc_IP
Header: X-API-Key: <WARROOM_API_KEY>
```

### Firewall integration

**Sophos XG / XGS** — *Hosts and Services → IP List → Add* → enter the URL,
use "Custom HTTP Headers" for `X-API-Key`, update interval e.g. 5 min.

**Fortinet FortiGate** — *Security Fabric → External Connectors → Threat Feeds
→ IP Address* → enter the URL, set the HTTP header `X-API-Key`.

**pfSense / OPNsense (pfBlockerNG)** — add the URL as an IPv4 feed source.
pfBlockerNG does not send custom headers → either place the endpoint behind a
proxy with an IP whitelist, or allow Open Mode (`WARROOM_API_KEY` empty) only for
the firewall IP via nginx config.

---

## Block API (Web UI)

The block buttons in the dashboard and the blocklist page call the following
endpoints:

| Method | Route | Body |
|---------|-------|------|
| POST | `/api/firewall/block-ip` | `{"ip": "1.2.3.4", "comment": "..."}` |
| POST | `/api/firewall/block-ips` | `{"ips": ["1.2.3.4", ...]}` |
| POST | `/api/firewall/unblock-ip` | `{"ip": "1.2.3.4"}` |
| GET | `/api/firewall/blocked-ips` | – |
| POST | `/api/firewall/block-domain` | `{"domain": "evil.tld", "comment": "..."}` |
| POST | `/api/firewall/block-domains` | `{"domains": ["evil.tld", "*.adsrv.tld"]}` |
| POST | `/api/firewall/unblock-domain` | `{"domain": "evil.tld"}` |
| GET | `/api/firewall/blocked-domains` | – |
| POST | `/api/firewall/block-url` | `{"url": "https://evil.tld/x", "comment":""}` |
| POST | `/api/firewall/block-urls` | `{"urls": ["https://a/b", "http://c/d"]}` |
| POST | `/api/firewall/unblock-url` | `{"url": "https://evil.tld/x"}` |
| GET | `/api/firewall/blocked-urls` | – |

IPs end up in `blocked_ips`, hostnames in `blocked_domains`, URLs in
`blocked_urls`. The feeds read these tables live → no sync logic.

---

## AI agent (optional)

The agent analyzes firewall logs (WAF/IPS/failed login) via LLM and proposes
blocks – or executes them automatically. **Off** by default.

1. Provide an LLM endpoint (LMStudio/Ollama/vLLM locally or OpenAI).
   `host.docker.internal` points from the container to the Docker host.
2. In the Admin UI or `.env`: set `AGENT_ENABLED=true`, `AGENT_BASE_URL`,
   `AGENT_MODEL`.
3. By default, recommendations remain **pending** and must be approved at
   `/agent.html`. `AGENT_AUTO_EXECUTE=true` or the confidence fast lane
   (`AGENT_AUTO_EXECUTE_THRESHOLD`) execute them automatically.

> The bundled system prompts are in **German**. If you use an
> English-language model, adapt the prompts in the Admin UI.

---

## Microsoft 365 audit logs (optional)

Pulls **login events** (UserLoggedIn / UserLoginFailed) from the Microsoft
365 Management Activity API and enriches them with GeoIP. Failed
logins additionally appear as alerts on the attack map and are also evaluated by
the AI agent. Display at `/o365.html`, configuration at
**Admin → Microsoft 365**.

**Azure app registration (one-time):**

1. [entra.microsoft.com](https://entra.microsoft.com) → **App registrations →
   New registration** (single tenant).
2. **API permissions → Office 365 Management APIs → Application permissions →
   `ActivityFeed.Read`** → **Grant admin consent**.
3. **Certificates & secrets → New client secret** → copy the value.
4. In Warroom **Admin → Microsoft 365**: enter tenant ID, client ID, client secret
   → **Test connection**. The collector starts automatically
   (audit events arrive with a ~5–30 min delay).

> Known Microsoft app IDs are resolved to readable names (Azure Portal,
> Outlook Web App, Teams, …); unknown ones appear as a shortened GUID.

---

## Entra ID login blocking (optional)

Additionally syncs the Warroom blocklist into an Entra **Named Location** bound
to a **Conditional Access policy** — M365 logins from blocked IPs are
then rejected directly at Microsoft (complementing the firewall IOC feed).
Configuration at **Admin → Entra ID**.

- **Uses the same app registration** as the M365 collector, but additionally
  needs the Graph application permissions
  `Policy.ReadWrite.ConditionalAccess` + `Policy.Read.All` (admin consent) as well as
  an **Entra ID P1** license (included in Microsoft 365 E3/E5).
- **Named Location & policy are created automatically** (self-healing: if the
  policy is deleted externally, the next sync recreates it). Policy name:
  *"Warroom — Block IPs (managed)"*.
- **Security default report-only:** The policy initially enforces nothing. Via
  the admin toggle *"Enforcement ON/OFF"* you arm it — at which point a
  **break-glass account** is mandatorily requested (UPN or object ID) that is never
  blocked (protection against locking yourself out). UPNs are resolved to the object ID
  permission-free from the M365 audit logs.

---

## Telegram approvals (optional)

Sends **every open agent decision** as a Telegram message with
**✅ Approve / ❌ Reject** buttons; the decision is executed directly from Telegram
(long-polling, no public webhook needed). Configuration at
**Admin → Telegram**.

1. Create a bot via [@BotFather](https://t.me/BotFather) → copy the bot token.
2. Determine the `chat_id` (e.g. via `@userinfobot`) and **message the bot once
   first** or add it to the group.
3. In Warroom **Admin → Telegram**: enter token + chat ID, enable,
   **send a test message**.

> Only the configured chat may execute approvals; taps from other chats
> are rejected.

---

## AI chat & Teams commands

A **natural-language command interface** — reachable via the
in-app **AI chat** (`/chat.html`) and **Microsoft Teams**. With it the following can be executed
by message:

- **Blocklist:** set IP / domain / FQDN / URL
  ("block 1.2.3.4", "block boese.example")
- **Isolate endpoint** ("isolate PC-12345")
- **Query quarantine** ("show the quarantine")
- **OSINT** for IP/domain ("OSINT for 8.8.8.8") — inexpensive providers; Shodan stays
  button-only
- **Statistics report** ("statistics report for the last 7 days")

Intent detection first runs through a **keyword parser** (immediate
response for clear commands) and falls back to the
**LLM agent** for unclear phrasings — so the core commands work even without an agent.

**Free chat with the LLM:** Anything that is not a recognized command is answered by
a **security analyst persona** (LLM) — classify threats, explain CVEs,
assess indicators, interpret logs. Works across **all three
channels** (AI chat, Teams, Telegram). The persona's system prompt is
editable at **Admin → AI Analyst — Persona** (with "Load default"). Requires
an enabled agent (LLM endpoint).

**Setting up Microsoft Teams** (Admin → Microsoft Teams):
1. In the team → **… → Manage → Outgoing Webhooks → Create**.
2. Callback URL: `https://<warroom>/api/teams/command` (Warroom must be reachable
   via HTTPS).
3. Store the **HMAC secret** generated by Teams in the admin area — every Teams
   request is signature-verified with it.
4. In the team write `@Botname <command>`.

> Security: The Teams endpoint is exempted from the `X-API-Key` check and
> authenticates solely via the HMAC signature. Block commands from
> chat/Teams are direct human actions and are executed immediately
> (whitelist IPs remain protected).

---

## Shodan host intelligence (optional)

Delivers **open ports** and **known CVEs** per IP. These are stored long-term in
`shodan_hosts` and displayed as an optional map layer
(markers colored by CVE count, popup with ports + CVE links). Requires a
**Shodan API key** (Admin → OSINT).

**Shodan credits are scarce — that's why Shodan is never queried automatically:**

- **Human:** only via the **"🛰️ Query Shodan"** button in the OSINT panel
  (`POST /api/osint/shodan/{ip}`). The routine OSINT panel does **not** trigger
  a Shodan query.
- **Automatic:** the rule-based agent loops query Shodan only when the
  inexpensive providers already classify the IP as **clearly malicious**
  (AbuseIPDB ≥ threshold / VirusTotal ≥ 3 / GreyNoise = malicious). Controllable
  via *Shodan: auto-query on malicious IP* + *threshold* (Admin → OSINT);
  turn it off ⇒ Shodan is purely manual.

You'll find the map layer in the **attack map legend** under "LAYER →
Shodan Hosts" (and in the OSIRIS dashboard as a separate layer).

---

## Security & hardening

Warroom is intended as an **internal tool behind VPN/firewall**. Before
using it with real data, be sure to note:

- **Set `WARROOM_API_KEY`.** Without it, the backend runs in *Open Mode* – anyone
  with network access can operate the dashboard, block/unblock IPs and
  isolate endpoints. There is **no user login**; the API key is the
  only access control.
- **`.env` contains plaintext secrets** (DB password, Sophos secret, API keys).
  The file is in `.gitignore` and must **never** be committed. In the
  DB (`app_settings`) too, secrets are stored unencrypted → protect DB access.
- **Grafana** is preset with `admin/admin` and allows **anonymous
  viewer access** (all logs/maps visible without login). Change the password and
  set `GF_AUTH_ANONYMOUS_ENABLED=false` if not desired.
- **No HTTPS out-of-the-box** – nginx listens on port 80 (mapped to 8448).
  For production, put a TLS reverse proxy in front.
- **Exposed ports** (5514, 2055, 3030, 5051, 5540, 8448) should only be exposed in
  the trusted network. **RedisInsight (5540)** runs without auth and
  allows full read/write access to the cache, **pgAdmin (5051)** does have
  a login (`PGADMIN_EMAIL`/`PGADMIN_PASSWORD`) but grants full DB access →
  secure both behind a firewall/proxy and change the default passwords.
- **M365/Telegram secrets** (client secret, bot token) are, like all others,
  stored unencrypted in `app_settings`. The Entra app should only have the minimally
  required Graph permissions.

A detailed assessment including an improvement roadmap is in
[`docs/REVIEW.md`](docs/REVIEW.md).

---

## Stack & services

| Component | Tech |
|------------|------|
| Backend | FastAPI 0.115, SQLAlchemy 2 async, APScheduler |
| Database | PostgreSQL 16 |
| Cache | Redis 7 |
| Frontend | Vanilla JS + Nginx (no build step) |
| Syslog | Custom Python receiver (UDP/TCP 5514) |
| NetFlow | Custom Python collector (UDP 2055) |
| GeoIP | MaxMind GeoLite2 (fallback: ip-api.com) |
| Dashboards | Grafana 11 |
| Redis GUI | RedisInsight (cache inspection) |
| DB GUI | pgAdmin 4 (PostgreSQL management) |
| Cloud APIs | Sophos Central/Email, Microsoft 365 (Management Activity + Graph), Telegram |

| Container | Port (host) | Description |
|-----------|-------------|--------------|
| `frontend` | `8448` | Nginx, static files + reverse proxy |
| `backend` | (internal 8000) | FastAPI, REST + IOC feeds |
| `syslog` | `5514/udp+tcp` | Sophos Firewall syslog receiver |
| `netflow` | `2055/udp` | NetFlow v5/v9/IPFIX collector |
| `postgres` | (internal 5432) | Data persistence |
| `redis` | (internal 6379) | Cache (summary, OSINT lookups) |
| `redisinsight` | `5540` | RedisInsight — Redis GUI (cache preconfigured) |
| `pgadmin` | `5051` | pgAdmin 4 — PostgreSQL GUI ("Warroom DB" server preconfigured) |
| `grafana` | `3030` | Dashboards |

### Data flow

1. **Sophos Central API** → `collector.py` (every 300 s default) → DB
2. **Sophos Firewall syslog** → `syslog` service → DB (`firewall_logs`)
3. **NetFlow** → `netflow` service → DB (`netflow_buckets`)
4. **Microsoft 365 Activity API** → `o365_client.py` → DB (`o365_audit_logs`)
5. **Dashboard** → backend reads from DB → frontend renders
6. **Block action (UI/agent/Telegram)** → `blocked_ips` / `_domains` / `_urls`
7. **Firewall pulls** `/ioc_*` → backend reads the tables live
8. **Optional: Entra sync** → blocklist → Named Location + Conditional Access policy

---

## Troubleshooting

| Symptom | Cause / solution |
|---------|------------------|
| Dashboard empty, no alerts | Sophos credentials missing/wrong → `docker compose logs backend`. Without Sophos, only syslog/NetFlow/blocklist stay populated. |
| `401 invalid or missing X-API-Key` when fetching the feed | Firewall does not send the `X-API-Key` header or sends it wrong. |
| Map shows no locations | GeoIP DB missing and ip-api.com is rate-limited → place mmdb files into `./geoip/`. |
| Syslog/NetFlow does not arrive | Are ports 5514/2055 open on the host? Does the firewall send to the right IP? |
| Postgres does not start | `POSTGRES_PASSWORD` ≠ password in `DATABASE_URL`. They must be identical. |
| Change in `.env` has no effect | `.env` values are only start values. Apply running changes via `/admin.html` or re-apply with `docker compose up -d`. |
| M365 page empty / "not configured" | Entra app credentials missing under Admin → Microsoft 365, or `ActivityFeed.Read` consent not granted. Audit events also arrive with a delay. |
| Entra sync `403 not licensed` | Tenant without Entra ID P1 (included in M365 E3/E5) — assign a license to a user. The CA policy cannot be created/activated without P1. |
| Entra policy cannot be activated | No break-glass account set (Microsoft's "BlockEveryonePolicy" protection) or UPN not resolvable → enter the object ID. |
| Telegram approval does not arrive | Bot not enabled, wrong `chat_id`, or the bot was never messaged / not in the group. Check with "send test message". |

---

## License

Private project — no official support.

## Trademarks

Sophos, Sophos Central, Sophos Firewall and Sophos Intelix are registered
trademarks of Sophos Ltd. This project is not affiliated with Sophos.

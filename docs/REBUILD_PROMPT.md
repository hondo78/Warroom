# One-shot prompt: rebuild Warroom, better from the ground up

> Paste everything below the line into a capable coding agent. It is written to be
> self-contained: it describes what Warroom does, what the first version taught us,
> and how the rebuild must be structured so those lessons are designed in rather
> than patched on. Network anomalies get the most detailed specification, because
> that is where the first version was weakest for the people using it.

---

## 0. Your role and how to work

You are a senior engineer building **Warroom**: a self-hosted security operations
dashboard for a small IT team running Sophos firewalls, Sophos Central endpoints and
Microsoft 365. It runs on one Linux host with Docker Compose, on the LAN, operated by
one to five people who are IT generalists, not full-time SOC analysts.

Work in the phases of section 9. Each phase must end runnable (`docker compose up`),
with migrations applied, tests green and a short CHANGELOG entry. Do not start a phase
before the previous one meets its acceptance criteria. When a requirement is ambiguous,
choose the option that keeps the system simpler for the operator, write the decision
into `docs/decisions/NNN-title.md`, and move on.

All user-facing text, code, comments, docs and commit messages are **English**.
The UI ships with English and German translations (English is the source language).

## 1. What Warroom is for

One screen that answers, for a non-specialist: **"Is anything attacking us or
misbehaving on our network right now, why do you think so, and what should I do?"**

Core jobs:

1. **Collect** security telemetry: Sophos firewall syslog, NetFlow/IPFIX, Sophos
   Central (alerts, events, detections, endpoints, email quarantine, XDR), Microsoft
   365 sign-ins, honeypot sensors.
2. **Enrich** IPs, domains and URLs: GeoIP/ASN, reverse DNS, RDAP network ranges,
   OSINT reputation (AbuseIPDB, VirusTotal, Shodan, GreyNoise, ipinfo, Sophos Intelix,
   Tor exit list), CVE severity (CVSS/KEV/EPSS), internal host identity (hostname,
   MAC, owner, OS).
3. **Detect**: attacks from firewall logs (IPS, WAF, brute force, password spraying,
   invalid-username sweeps), risky M365 sign-ins (new device or country per user),
   network anomalies from NetFlow (section 6), honeypot and canary-password hits.
4. **Decide and act** with a human in the loop: an AI agent proposes actions (block
   IP/subnet/domain/URL, isolate endpoint, revoke M365 sessions, acknowledge, notify).
   Humans approve in the UI, Telegram or Teams. Every action is audited and revertible.
5. **Enforce**: publish blocklists as IOC feeds the firewalls pull (`/ioc/ip`,
   `/ioc/domain`, `/ioc/url`), push them to Sophos Central MDR threat feeds, and sync
   them to an Entra ID Named Location / Conditional Access policy.
6. **Investigate**: IP dossier, OSINT lookup, log search, an AI chat that answers
   questions with read-only SQL, and an MCP server so external AI tools can query logs.

## 2. Feature inventory (scope to rebuild)

Rebuild all of these. "Same as v1" means the behaviour is right and only the
structure changes.

**Ingest**
- Syslog receiver (UDP+TCP 5514) for Sophos SFOS key=value logs: Firewall, IPS/IDP,
  ATP, Anti-Virus, Sandstorm, Web/Content filter, WAF, Authentication, Anti-Spam.
  Parse into typed columns; GeoIP/ASN enrich attacker IPs at ingest.
- NetFlow v5/v9/IPFIX collector (UDP 2055) with per-exporter template caches. Store
  flows at a resolution that supports beacon detection (section 6.2): keep per-flow
  start/end timestamps in a short-lived raw table, plus 1-minute rollups for analytics.
  Store interface counters separately.
- Sophos Central collector (OAuth client credentials, whoami → region/tenant, retry on
  429/5xx): alerts, events, detections, endpoints, firewall inventory, account health,
  email quarantine metrics.
- Sophos XDR via the **Fusion GraphQL API only** (detections, cases with comments and
  evidence, events, process lineage, Live Endpoint Search). Do not implement the
  deprecated XDR Data Lake / Live Discover REST APIs.
- SFOS direct APIs (v23 REST with API key, XML API as fallback) for DHCP leases
  (IP↔MAC↔hostname) and interface data. Parse by shape, not by fixed schema.
- Microsoft 365 Management Activity API (sign-ins), Graph for Entra Named Locations,
  Conditional Access (created report-only, with a break-glass exclusion) and
  `revokeSignInSessions`.

**Internal hosts**
- Host inventory merged from Sophos endpoints, DHCP, PTR on internal DNS and NetBIOS.
- Identity tracking: alert on IP↔MAC and hostname changes.
- Presence (ping/TCP sweep) with history; nmap TCP-connect scans, **private ranges
  only**, with port-change diffs.
- **The device, not the IP, is the unit of identity** everywhere downstream (section 6).

**Blocking and lists**
- Block/unblock IP, CIDR (max /22), domain, URL with reason, source and actor.
- Allowlist (never block), watchlist (observe), monitored IPs (alert on new or
  reappearing connections).
- IOC feeds for the firewalls. The firewall cannot send custom headers, so protect the
  feeds with **a dedicated read-only feed token in the URL path plus a source-IP
  allowlist**, not with "unauthenticated by necessity".

**Detection and agent**
- Rule-based detectors: WAF scanner (distinct paths per source in a rolling window),
  IPS repeat offenders, failed logins per IP and per /24, distributed brute force
  across many IPs (resolve real network ranges via RDAP to propose a subnet block),
  user-centric brute force ("this user is being targeted"), invalid-username sweeps
  against a directory of known-good usernames with a "burned username" list that
  blocks new sources on their first attempt (no LLM; deterministic; disarms itself
  when the directory is too small).
- M365 sign-in watch: per-user baseline of devices and countries; anything new
  proposes `revoke_sessions`.
- AI agent: see section 5.
- Honeypot: a stdlib-only remote sensor agent (low-interaction SSH, Telnet, FTP, HTTP,
  RDP, SMB, MySQL, VNC listeners; bait files watched with fanotify/inotify; process
  allowlist), each pod with its own token, heartbeat-driven config and optional TLS
  pinning. Plus a **decoy VPN login page** on its own port: one submission records
  the attempt (passwords stored in clear text **on purpose**, admin-only, redacted
  everywhere else), blocks the source and burns the username. The decoy page ships
  with no comments, no external assets and nothing that reveals it is a trap; its
  submit paths look like a real VPN portal's.
- Canary passwords: store only an HMAC fingerprint (subkey derived from the master
  secret); a match on any login surface raises a critical alert and is redacted.

**Investigation**
- IP dossier: everything known about one IP (logs, flows, OSINT, honeypot, block
  provenance, decisions, findings, identity).
- OSINT page with history and a per-context provider matrix (which providers may be
  used by manual lookups, dossier, agent, honeypot, MCP, chat) and quota tracking.
- AI chat: intents (block, isolate, OSINT, report) plus an analyst persona that may run
  SQL that is **SELECT only, single statement, READ ONLY transaction, statement
  timeout, outer LIMIT, table allowlist that excludes every secret-bearing table**.
- MCP server (Streamable HTTP, bearer token): search/count/aggregate/describe logs,
  OSINT, dossier, honeypot stats. Read-only tools and action tools are separate and
  separately enabled.
- Optional, off by default: a Tor-only Kali container for outside-in checks, with a
  binary allowlist, metacharacter rejection, an explicit target allowlist (empty means
  nothing), human approval per command and a full audit trail. Enforce the guard in
  **one** shared library used by both sides, not two copies.

**UI pages**: Dashboard (live attack globe/map, KPI tiles, recent alerts), Findings
(the anomaly inbox, section 6), Network (NetFlow), Hosts, Blocklists, Endpoints
(Sophos Central management), XDR, Email, Microsoft 365, Honeypot, OSINT, IP Dossier,
AI Chat, Agent (decisions and approvals), Kali (optional), Statistics (quotas, LLM
usage, cache), Settings, Users and Audit.

## 3. Architecture: build these in from day one

Each item below fixes a concrete v1 pain point. Treat them as requirements.

### 3.1 Process layout
- **Separate processes** in Compose: `api` (FastAPI, stateless, may run multiple
  workers), `worker` (all scheduled and background jobs), `ingest-syslog`,
  `ingest-netflow`, `db`, `redis`, `web` (nginx serving the built frontend).
  v1 ran the API and ~45 scheduled jobs in one uvicorn process, so it could not scale
  and one slow job starved the API.
- Scheduler: one registry of jobs with name, interval, enabled flag, last run,
  duration, last error, next run. Guard every job with a Postgres advisory lock so a
  second worker never runs it twice. Expose the registry read-only in the UI.
- Every container gets a healthcheck, memory limit and restart policy. Postgres was
  repeatedly OOM-killed in v1 because nothing was limited.

### 3.2 Data layer
- **PostgreSQL 16 + TimescaleDB.** v1 kept 300 GB of firewall logs in one plain table,
  deleted old rows in batches, and autovacuum never ran: bloat, slow aggregates, a full
  disk, and partitioning that became impossible once the disk was full. With hypertables:
  - `fw_security_events` (IPS, WAF, ATP, AV, auth, …), retained 90 days.
  - `fw_connections` (log_type Firewall, ~90% of volume), retained 14–30 days.
  - `flows_raw` (per-flow, 48 h) and `flows_1m` (1-minute rollup, 30–90 days).
  - Daily chunks, **native compression after 2 days**, retention policies (chunk
    drop, no DELETE), continuous aggregates for every dashboard aggregate (map per
    day × source IP, timelines, top talkers, per-device daily traffic baselines).
  - Configure per-table autovacuum thresholds explicitly for the non-hypertables.
- Use `inet`/`cidr` for every IP column (not VARCHAR): smaller, CIDR queries, IPv6.
- Typed columns for every field you query; keep the unparsed remainder in a small
  JSONB `extra`, not the whole raw line in every row.
- **Alembic** for all schema changes. No DDL at application startup. Index builds on
  large tables use `CREATE INDEX CONCURRENTLY` in their own migration.
- Two connection pools: a request pool (fail fast: 5 s pool timeout, ~30–45 s
  statement timeout) and a background pool (long timeout). Request handlers may never
  use the background pool.
- Never run unbounded `COUNT(*)` on big tables; use estimates or aggregates.
- **Backups are part of the product**: nightly `pg_dump` (or pgBackRest) to a
  configurable target, retention, a restore test job, and a dashboard tile that turns
  red when the last good backup is older than 36 h. v1 had no backup at all.
- Disk guard: a job that warns at 80% and 90% disk usage and shows projected
  days-until-full from ingest rate.

### 3.3 API design
- FastAPI app factory, **one APIRouter per domain** (`ingest`, `hosts`, `findings`,
  `blocking`, `agent`, `sophos`, `m365`, `osint`, `honeypot`, `chat`, `admin`, …).
  Layers: router → service → repository. v1's `main.py` reached 9,000 lines with 267
  routes, which made every change risky.
- Integrations implement one interface: `settings schema`, `health()`, `jobs()`,
  `routers()`. Adding an integration must not touch core files.
- Pydantic models for every request/response; the generated OpenAPI spec produces a
  typed TypeScript client for the frontend.
- One error model (`{code, message, detail}`) and cursor pagination everywhere.
- **Heavy queries are jobs, not 503s.** An expensive aggregate either reads a
  continuous aggregate or returns `202 {job_id}` that the client polls. Response
  caching in Redis is single-flight (one recomputation per key) with
  stale-while-revalidate.
- Prometheus `/metrics` (ingest rate, parse errors, dropped messages, queue depth,
  job durations, LLM latency/tokens, OSINT quota) and structured JSON logs.

### 3.4 Settings and secrets
- Settings are typed Pydantic models **grouped per module**, stored in the DB,
  overriding env defaults. The admin UI is **generated from the schema** (title,
  description, type, range, enum, secret flag, required role), so no setting exists
  without UI and none is editable in two places. v1 had 184 flat settings, 65 without
  UI, and five editable on two pages in different ways.
- Show the effective value and where it comes from (default / env / DB).
- Secrets: Fernet-encrypted at rest; key from env or a mounted file; write-only in
  the UI (show "set", never the value). Document key backup prominently.
- Prompts are **versioned files** in the repo (overridable per installation), not
  settings blobs.

### 3.5 Security
- **Authentication always on** (v1 made it opt-in): first-run setup wizard creates the
  admin. Roles: viewer < analyst < admin. Sessions via HttpOnly, SameSite=Strict
  cookies; CSRF protection on mutations.
- Machine clients get scoped API tokens (IOC feed read, MCP read, MCP actions, Teams
  webhook HMAC, honeypot pod token). No shared global API key.
- Audit log of every mutation and every executed action, with actor, before/after.
- Strict CSP without `'unsafe-inline'` (no inline handlers anywhere), all frontend
  assets self-hosted (no runtime CDN), TLS termination supported.
- Admin tools (pgAdmin, RedisInsight, Grafana) are off by default and never
  anonymous.

### 3.6 Frontend
- **Vite + TypeScript + React**, one shared layout (sidebar, header, search, language
  switch). v1 duplicated the sidebar in 26 HTML files and had no build step.
- **TanStack Query** for all data: polling pauses in hidden tabs, retries, cache,
  stale data shown while refetching. v1 had to retrofit all of this by hand.
- Every page's filters live in the URL (shareable, reload-safe).
- A global command palette (Ctrl+K): type an IP, domain, hostname, user or page name
  and jump to the right place.
- Every widget has loading, empty, error-with-retry and stale states.
- Charts: Apache ECharts. Maps: globe.gl (3D) with a deck.gl/MapLibre 2D mode, base
  map tiles from a keyless or self-hosted source. Carto's dark tiles began requiring
  an API key and silently broke v1's map.
- i18n with typed keys; English source, German translation; no hard-coded strings.
- Accessibility: keyboard navigation, colour is never the only signal, respects
  `prefers-reduced-motion`.

### 3.7 One model for everything that needs attention: **Finding**
Every detector, whether rule, ML, honeypot, M365 or Sophos, writes **Findings** to one
table. The agent, notifications, inbox and dossier all consume Findings. (v1 had a
separate path per source: ten agent loops, three anomaly engines with three score
meanings, and anomaly results that were never stored.)

```
finding
  id, fingerprint (detector + entity + kind; stable across runs, used for dedup)
  detector, kind, entity_type (device | external_ip | user | ...), entity_id
  counterpart (optional: destination, service, user)
  first_seen, last_seen, occurrences (days seen), status
    (new | open | acknowledged | benign | malicious | resolved | suppressed)
  severity (info | low | medium | high | critical)  -- from risk, same bands everywhere
  risk (0–100), confidence (low | medium | high)
  headline        -- one plain-language sentence (section 6.4)
  explanation     -- structured "why" items: rule, threshold, observed, expected
  evidence        -- references + snapshots: flow ids/time range, log ids, OSINT ids
  ai_assessment   -- optional: verdict, reasoning, sources used, model, timestamp
  assignee, comments, verdict history
```

### 3.8 Agent and actions
- **Policy engine** decides which proposed actions need approval: by action type,
  target class (internal / external / CIDR size), detector and confidence. Defaults:
  blocks and isolations need approval; acknowledge and notify do not. Optional
  "learned auto-approve" after N consistent human approvals of the same signature,
  with a burst limiter and an alert when it triggers.
- Actions are idempotent, have a dry-run preview ("this will add 1 IP to feed X,
  push to 3 firewalls, add to Entra named location") and a one-click revert.
- The allowlist is checked at proposal **and** at execution.
- LLM access goes through one provider abstraction (any OpenAI-compatible endpoint;
  local LM Studio by default) with structured outputs, timeouts, token accounting
  and a per-detector enable switch. The LLM **explains and recommends**; it never
  silently changes a score or executes on its own.

### 3.9 Quality
- Tests: unit tests for every detector against **synthetic scenario fixtures**
  (section 6.7), API contract tests, a smoke test that calls every GET route, and
  Playwright end-to-end tests that load every page and exercise its main action.
- CI: lint (ruff, eslint), type check (mypy/pyright, tsc), tests, build.
- No silent `except Exception: pass`; every swallowed error increments a metric.

## 4. Lessons from v1 to keep (do not "fix" these)

- Firewalls pull IOC feeds over plain HTTP from the LAN and cannot add headers.
- WAF/IPS filters must be defined once and reused by both queries and partial-index
  predicates; a predicate that differs by one character makes Postgres ignore the index.
- Agent "cannot judge" is not "invalid": unknown states fail closed (no block, but
  notify), and unknown notification events go to every channel.
- Never block your own infrastructure: allowlist checks at proposal and execution.
- Honeypot passwords are stored in clear text deliberately; access is admin-only.
- Parsers for SFOS must be schema-tolerant (firmware changes field names).
- An internal IP's identity changes (DHCP); key analytics by device (MAC/hostname).

## 5. Agent detail

Inputs: Findings above a per-detector threshold. For each it gathers context (device
card, destination card with OSINT per the provider matrix, related findings, recent
decisions, allowlist hits), asks the LLM for a structured `Decision {action, targets,
confidence, reasoning, evidence_refs}`, validates it (allowed actions, CIDR ≤ /22,
≤ 256 IPs per bulk action, never allowlisted), and files it as a proposal through the
policy engine. Approvals via UI, Telegram (inline buttons, only the configured chat)
and Teams. Notifications carry the Finding headline and a deep link. Agent quality
statistics: approval rate per detector, reverted actions, time-to-decision.

## 6. Network anomalies: understandable and traceable

This is the most important part of the rebuild. The v1 engines detected real things
but the people using them could not tell **what** happened, **why** it was flagged,
**compared to what**, or **how to verify it**. Concretely, v1:

- showed three different score scales (Isolation Forest over the population, a
  hand-tuned rule product, a per-service forest) with the same colour badge;
- compared hosts only to other hosts in the same window, never to their own history;
- had no seasonality, and an inconsistent "night" (00–06 in one engine, 22–06 in the
  others, in database time);
- named drivers ("ports", "r2.3", "extremity 0.94") without values or a normal range;
- stored no findings (recomputed per request), so nothing could be referenced, tracked
  or compared over time;
- offered no evidence drill-down for connection and service anomalies;
- stored verdicts per IP forever, so "benign" on a CDN address silenced every host,
  while the next run still flagged it again;
- re-scored when the user changed a chart axis;
- keyed everything by IP (DHCP churn looked like "new" devices) and covered IPv4 and
  outbound traffic only.

Design the replacement around these principles:

1. **Every finding answers four questions on one screen**: What happened? Why is it
   unusual? Compared to what? How can I check it myself?
2. **Plain language first, math on demand.** The primary UI never shows algorithm
   names. Details live behind "How was this measured?".
3. **One risk scale (0–100) and one severity scale** across all detectors, with the
   bands shown in a legend.
4. **Baselines the user can see**: the device's own history, its peer group, and the
   whole network.
5. **Every claim links to evidence** (the flows and log lines that produced it).
6. **Human feedback changes future behaviour**, at the scope the human chooses.

### 6.1 Entities and context
- **Device** = internal host identity (MAC → hostname → Sophos endpoint → owner/OS),
  with IP history. All per-host baselines key on the device.
- **Destination** = external IP enriched with: reverse DNS, **domain names seen for it**
  (firewall web-filter/SNI/DNS logs, so users see `login.microsoftonline.com`, not
  `20.190.x.x`), ASN and organisation, country, OSINT reputation summary, first time
  seen on the network, number of internal devices talking to it.
- **Service** = port/protocol mapped to a human name (HTTPS, SSH, DNS, RDP, SMB, …),
  "unidentified" otherwise.
- **Known-good catalogue** shipped with the product and editable: major SaaS/CDN/cloud
  ASNs and domains (Microsoft 365, Windows Update, Google, Apple, AWS, Azure,
  Cloudflare, Akamai, Sophos), plus local rules. A destination in the catalogue is
  labelled ("Microsoft 365") and down-weighted, never silently hidden.
- **Device roles** (workstation, server, printer, IoT, firewall, …) from Sophos
  endpoint data and user tagging; peer groups are by role.

### 6.2 Baselines
- Per device, per hour-of-week (168 slots) with robust statistics (median and MAD,
  or quantiles) over 28 days for: bytes out, bytes in, flows, distinct destinations,
  distinct services, distinct countries, new-destination rate.
- Per device × destination and device × service: first seen, days active, typical
  volume.
- Per role (peer group) and network-wide equivalents.
- Baselines are computed by the worker into tables (continuous aggregates where
  possible), versioned by date, and shown in the UI as a shaded "normal range" band.
- "Night" or "off-hours" is defined once from the **site's working hours and
  timezone** (a setting, default Mon–Fri 07:00–19:00 local), never from UTC clock
  hours.
- Cold start: until a device has 7 days of history, compare against its peer group
  and say so ("new device, compared with other workstations").

### 6.3 Detectors (each produces Findings with explanation items)
Each detector documents its inputs, rules, thresholds and output in
`docs/detectors/<name>.md`, and the same text (localised) appears in the UI under "How
was this measured?".

| Kind | Plain name in UI | Core logic (thresholds configurable, defaults shown) |
|---|---|---|
| `exfiltration` | Unusual upload | Bytes out to one destination ≥ 50 MB/24 h **and** ≥ 10× the device's own baseline for that hour-of-week **and** upload share ≥ 75 %, destination not in the known-good catalogue (catalogue hits are capped at medium). |
| `beaconing` | Regular "call home" | From raw flow start times: ≥ 20 connections over ≥ 2 h to one destination, inter-arrival times clustered (coefficient of variation ≤ 0.3 after removing outliers, or a dominant period from the inter-arrival histogram), small and similar payloads, destination contacted by ≤ 2 devices. Tolerate jitter. |
| `new_destination` | First contact with a rare server | Device's first-ever contact with a destination that ≤ 1 other device has contacted in 28 days, with meaningful volume or repeated contact; boosted for new country/ASN for this device, recently registered domains, poor reputation. |
| `new_service` | New kind of traffic | Device uses a service (port/protocol) it has never used and that is rare for its peer group (e.g. a workstation starting outbound SSH, SMB to the internet, RDP). |
| `fanout_scan` | Scanning other machines | One device contacts ≥ 50 internal hosts or ≥ 100 ports in 10 min (lateral movement or a scan). **Internal↔internal traffic is in scope.** |
| `inbound_exposure` | Newly reachable from the internet | Successful inbound connections from the internet to an internal service that had none in the baseline. |
| `volume_spike` | Traffic far above normal | Total device traffic outside its hour-of-week normal range by ≥ 5 robust deviations. |
| `unusual_combination` | Unusual overall pattern | Isolation Forest over per-device daily features **as a secondary detector only**. Explanations are two-sided (unusually high *or* low), expressed as observed vs. peer median, and computed independently of what any chart displays. Capped at medium unless corroborated. |

Scoring:
- Each detector produces explanation items: `{rule, observed, expected, threshold,
  passed, weight}`. Risk = documented weighted combination, then adjusted by context
  multipliers (destination reputation, known-good catalogue, device criticality,
  off-hours, corroboration by other findings on the same device within 24 h).
- Risk → severity bands: 0–29 info, 30–49 low, 50–69 medium, 70–84 high, 85–100
  critical. Same bands, colours and labels everywhere.
- Confidence reflects data quality (baseline age, sample size, flow sampling).
- Support IPv4 and IPv6. Handle NetFlow sampling rates explicitly.

### 6.4 Plain-language headline and explanation
Every Finding gets a deterministic, template-generated headline: no LLM required, so
it is always present and reproducible. The style:

- "**PC-ACCOUNTING-03** uploaded **2.1 GB** to **185.x.x.x** (ExampleHost, Romania)
  between 01:10 and 03:40. It normally uploads about **40 MB per night**: **52×**
  more than usual."
- "**NAS-01** contacted **update.example.net** every **60 seconds** (±3 s) for **9
  hours**. No other device talks to this server."
- "**LAPTOP-HR-07** used **SSH to the internet** for the first time. No other
  workstation does this."

Below the headline, a checklist shows each rule as passed ✓ or not ✗, with observed
value, normal value and threshold:
"✓ Upload volume 2.1 GB (normal ≤ 60 MB, threshold 50 MB)", "✓ Destination first
seen today", "✗ Destination reputation: no reports (AbuseIPDB 0, VirusTotal 0/94)".

An optional **AI assessment** sits in its own clearly labelled box: verdict
suggestion, reasoning, which sources it used, model name and time. It never replaces
the deterministic explanation.

### 6.5 UI for network anomalies
**Findings inbox** (default view of the Network Anomalies page):
- Cards grouped by device by default, sorted by risk: severity pill, headline,
  2–3 "why" chips with numbers ("52× normal upload", "new destination", "outside
  working hours"), age ("first seen 2 h ago, seen on 3 days"), status, assignee.
- Filters: severity, kind, status, device, role, destination, time range; saved
  views; everything in the URL.
- Top of page: "Since yesterday: 2 new high, 5 medium, 14 suppressed by your rules",
  with a 14-day trend.

**Finding detail** (one page per finding, stable URL):
1. **What happened**: headline, severity, risk, confidence, status, timestamps.
2. **Why it is flagged**: the rule checklist from 6.4, with an expandable "How was
   this measured?" that shows the detector description and the exact thresholds.
3. **Compared to normal**: charts with the normal-range band shaded. Examples: the
   device's daily upload for 28 days with today highlighted; the hour-of-week heatmap
   of normal activity with the event overlaid; the peer-group distribution with this
   device marked.
4. **Timeline**: flows for the device↔destination pair over time. For beaconing,
   show a dot strip of connection times plus an inter-arrival histogram with the
   detected period marked, so anyone can see the regularity.
5. **Who is involved**: device card (hostname, MAC, IP history, owner, OS, Sophos
   health, role, link to Hosts) and destination card (IP, domains, ASN/org, country,
   reputation summary, first seen on network, devices talking to it, link to IP
   dossier).
6. **Evidence**: paginated table of the underlying flows and matching firewall log
   lines for the finding's time range, with CSV export, and the exact query used.
7. **What to do**: suggested next steps per kind (e.g. "Ask the user whether a
   backup or upload was expected"), and actions: mark benign (with scope), mark
   malicious, isolate endpoint (Sophos), block destination, create a known-good
   rule, assign, comment. Every action shows a preview and is audited.
8. **History**: occurrences of this fingerprint over time, verdict history, related
   findings on the same device or destination.

**Explorer** (advanced, secondary tab): a 2D scatter of devices on two chosen
features with clickable points that open the device. Changing axes never changes
detection results. 3D views are optional, never the primary presentation.

**Glossary**: every term in the UI (beaconing, upload share, peer group, baseline,
risk, confidence) has a one-sentence tooltip and a glossary page.

### 6.6 Feedback, suppression and accountability
- Verdicts are set **per finding** and optionally create a **rule** with explicit
  scope: this device ↔ this destination / this device ↔ this service / this
  destination for all devices / this ASN or domain for all devices / this device for
  this kind. Each rule has a reason, an author, a creation date and an **optional
  expiry**.
- Suppressed findings are still recorded (status `suppressed`, linked rule) and
  counted on the inbox, so nothing disappears silently. Rules list shows hit counts and
  last hit; stale rules (no hits in 90 days) are flagged for review.
- "Malicious" verdicts raise the reputation of the destination for all future
  scoring and feed the blocklist proposal.
- Monthly quality report: findings per detector, verdict mix, false-positive rate,
  time-to-triage; detectors with high false-positive rates are highlighted for
  threshold review.

### 6.7 Verification
- Synthetic scenario generator for tests and demos: inject a beacon (60 s ± 5 s for
  6 h), an exfiltration (2 GB in 1 h), a scan (500 internal hosts in 5 min), a new
  outbound SSH, a printer suddenly talking to the internet, a DHCP address change, and
  benign look-alikes (Windows Update bursts, backup to a known cloud, video calls).
  Every detector has tests asserting it catches its scenario and ignores the
  look-alikes.
- Replay mode: run detectors over a past time range without creating notifications,
  to tune thresholds and see what would have been flagged.

## 7. Dashboard and map
- KPI tiles (open findings by severity, blocks today, ingest health, last backup),
  attack globe with a 2D toggle: animated arcs from attacker to the nearest firewall
  (reverse for outbound), colour = category, thickness = volume, pulsing rings on our
  sites, click opens the source with block/OSINT actions, legend filters by category
  and direction, optional Shodan exposure layer. The same component shows NetFlow
  destinations on the Network page.
- Ingest health panel: messages/s per source, parse error rate, dropped messages,
  lag; a red banner if any source has been silent for longer than its expected
  interval.

## 8. Non-functional requirements
- Single host, Docker Compose, Linux. All services restart cleanly; data survives
  `docker compose down`.
- Scale target: 10 M firewall log lines/day, 50 k flows/min, 2,000 internal devices,
  dashboard p95 < 2 s, finding detail < 3 s.
- Resource limits on every container; documented sizing guide.
- Local LLM by default (OpenAI-compatible endpoint at `host.docker.internal:1234`);
  everything works with the LLM disabled (deterministic explanations still present).
- No data leaves the host except explicit integrations (Sophos, Microsoft, OSINT
  providers per matrix, notification channels); OSINT calls are quota-tracked.

## 9. Delivery phases and acceptance criteria

1. **Foundation**: Compose layout, Postgres+Timescale, Alembic, auth with setup
   wizard, schema-driven settings, job registry, metrics, backups, frontend shell
   (layout, i18n, command palette, URL state). *Accept:* fresh install to logged-in
   empty dashboard in < 10 min; backup and restore test pass; Playwright smoke green.
2. **Ingest**: syslog, NetFlow (raw + 1 m), Sophos Central, M365, SFOS, GeoIP. Ingest
   health panel. *Accept:* sustained 50 k flows/min and 200 syslog msg/s with zero
   drops on the reference host; compression and retention policies active.
3. **Hosts and enrichment**: device identity, roles, OSINT with provider matrix and
   quotas, destination enrichment incl. domain names. *Accept:* every internal IP in
   flows resolves to a device or "unknown device" with a reason.
4. **Findings and network anomalies**: the Finding model, baselines, all detectors of
   6.3, inbox, detail page, rules and verdicts, scenario generator, replay.
   *Accept:* every synthetic scenario is detected with the right kind and severity,
   look-alikes are not flagged, and a non-specialist tester can explain each finding
   from its page alone.
5. **Rule detectors, agent and actions**: WAF, IPS, brute-force family, M365 watch,
   policy engine, approvals (UI/Telegram/Teams), IOC feeds, MDR push, Entra sync,
   revert. *Accept:* end-to-end "attack → finding → proposal → approval → block →
   feed → revert" works and is fully audited.
6. **Investigation and the rest**: dossier, OSINT page, chat with safe SQL, MCP,
   honeypot sensors and decoy, canary passwords, Sophos endpoint/XDR/email pages,
   optional Kali, dashboard globe. *Accept:* feature parity with section 2.
7. **Hardening**: load tests, security review (CSP, auth, token scopes, SQL guard),
   docs for operators (install, sizing, backup/restore, key backup, tuning detectors).

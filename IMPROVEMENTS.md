# Warroom — Analysis & Prioritised Improvements

Snapshot taken at commit `b30dcd8`. No code was changed to produce this.

Each item says how confident I am and how I know. Where I could not verify
something, it says so rather than guessing — a list like this is only useful if
its certain and uncertain entries can be told apart.

---

## Architecture, in one page

A single FastAPI backend fronted by nginx, with four satellite containers
(syslog receiver, NetFlow collector, an optional Tor-only Kali box, Grafana) and
Postgres + Redis behind them. The frontend is server-less static HTML with one
JS file per page — no build step, no framework.

**What is genuinely well built:**

- **Two database pools.** A small fail-fast request pool with a 45 s statement
  timeout, and a separate background pool that may run for minutes. This is the
  fix for a real outage (heavy aggregates starving the request path) and the
  reasoning is written down where it happened.
- **Defence in depth on LLM-generated SQL.** `SET TRANSACTION READ ONLY` is the
  real control; the keyword denylist is correctly described as a second layer
  rather than the primary one.
- **Fail-closed security decisions, mostly.** The Kali guard, the brute-force
  directory ("cannot judge" ≠ "invalid") and the notification matrix ("unknown
  event is delivered everywhere") all pick the safe direction deliberately and
  say why.
- **Schema-tolerant parsing.** Both SFOS transports parse by shape, which has
  already survived one firmware change.

**The main structural problem is size concentration:**

| | |
|---|---|
| `main.py` | 8,747 lines, **253 endpoints** |
| `agent.py` | 3,830 lines |
| Backend total | 29,804 lines |
| Test total | 2,177 lines (**≈7%**) |
| Scheduled jobs | 46, all registered in one `lifespan()` |

`main.py` is the thing most likely to make future work slow and risky. It is
also why this repository is hard to split into reviewable commits: unrelated
features are interleaved inside the same functions.

---

## P0 — Security, act first

### 1. The chat LLM can read every secret-bearing table but one
**Confident — verified directly.** `sql_query.DENIED_TABLES` contains exactly
one entry: `app_settings`. Everything else is reachable by any SQL the chat LLM
writes:

| Table | What is in it |
|---|---|
| `honeypot_logins` | **Attacker passwords in cleartext** — stored that way on purpose |
| `users` | Password hashes |
| `monitored_passwords` | **Canary fingerprints** |
| `kali_commands` | Pentest command audit trail |

The `monitored_passwords` case is a direct contradiction in the current threat
model. `serialize()` deliberately omits `fingerprint` with the comment that it
"is the one field that would let someone test guesses offline" — and then the
chat can simply `SELECT fingerprint FROM monitored_passwords`. Whatever the API
withholds, the SQL path hands over.

This matters more than it looks: query results go to an **external LLM provider**
unless the local model is in use.

*Fix:* deny-list `honeypot_logins`, `users`, `monitored_passwords`,
`kali_commands`; better, invert it to an allow-list of the tables the analyst
chat is actually meant to reason over (firewall logs, netflow, alerts, blocked
IPs). An allow-list also survives new tables being added, which a denylist does
not.

### 2. `/ioc_*` feeds are unauthenticated, and three comments deny it
**Confident — confirmed in the code review.** `verify_api_key()` returns early
for any path starting with `/ioc_`. nginx has no `allow/deny`, no `auth_request`
and no rate limit on those locations. Anyone who reaches the port reads the
complete blocklist.

The trade-off may be deliberate (firewalls pull these feeds anonymously), but
`main.py:3468`, `:3694`, `:3821` and `nginx.conf.template:175` still state the
opposite. Either constrain it (source ACL for the firewall's address, or a token
in the path) or correct the comments — right now the code and its documentation
disagree about an access-control decision.

### 3. The Kali box trusts its caller unless you opt out
**Confident — verified live.** `KALI_TARGET_ALLOWLIST` is wired into
`docker-compose.yml` but **empty**, so `BOX_ALLOWLIST` is inactive and the box
uses the allow-list supplied in the request payload. Anything holding
`KALI_API_TOKEN` can send `"allowlist": ["0.0.0.0/0"]`.

The box calls itself the authoritative guard; today it is only authoritative
about binaries and patterns, not targets. *Fix:* set the variable. One line of
configuration.

### 4. The `analyst` role can enable the Kali box
**Plausible — from the code review, not re-verified.** `PUT /api/admin/settings`
requires only `analyst`, and `kali_mcp_enabled` / `kali_require_approval` are
ordinary managed settings. An analyst can therefore switch on remote command
execution and switch off the human approval gate.

*Fix:* require `admin` for a named set of privileged keys, rather than raising
the bar for all settings (which would change who can do routine work).

---

## P1 — Correctness and operations

### 5. Unbounded in-memory caches
**Confident — confirmed in the code review.** `service_anomaly._baseline_cache`
(and the identical pattern at `connection_anomaly.py:102/152`) key on an
hour-rotating string with no eviction, no size cap and no TTL sweep —
`_BASELINE_TTL` only *skips* stale entries, it never frees them. Each entry
holds a per-(host, service) dict over a 30-day baseline. That is a slow leak
measured in hundreds of MB per month of uptime, and it will present as an
unexplained backend restart.

### 6. Approve-command race
**Plausible — not reproduced.** `approve_command()` reads with `db.get()` then
acts, with no row lock and no conditional `UPDATE ... WHERE status='pending'`.
Two concurrent approvals (two tabs, two operators, a retried request) can each
see `pending` and both execute — running an intrusive pentest command twice and
clobbering the first result.

### 7. Indexes are created non-concurrently at startup
**Confident.** `ensure_schema()` runs `CREATE INDEX` without `CONCURRENTLY`
inside the startup path, against tables including a 55M-row `firewall_logs`.
On a cold start where an index is genuinely missing this takes a write lock for
as long as the build runs.

### 8. `presence_trend` grows without bound
**From the code review, not re-verified.** No retention job, unlike
`firewall_logs`, which has one.

---

## P2 — Maintainability

### 9. Duplicated logic that must not drift
Three pairs, each kept in sync only by a comment:

- **The Kali guard** — ~90 lines duplicated between `backend/app/kali_client.py`
  and `kali/box/kali_api.py`. This is the highest-stakes copy in the repository:
  the two already diverged once (the argv-vs-raw-string and `@server` holes had
  to be fixed twice, in lock-step). The box ships standalone so it cannot import
  the backend — the answer is a build-time shared file, not discipline.
- **Partial-index predicates** — `database.py:871` duplicates
  `_WAF_FILTER_SQL` / `_IPS_FILTER_SQL` from `main.py`. A semantic edit to one
  side silently de-indexes the widget into a sequential scan over ~29M rows. The
  DDL should be generated from the Python constant.
- **`formatTime()`** — defined separately in **seven** page scripts and in
  neither `common.js` nor `honeypot.js`. This already caused a production
  `ReferenceError` this week.

### 10. `admin.html` is the only page that does not load `common.js`
**Confident.** Hence the parallel `adminEsc()` / `adminEscJs()` helpers. Either
load it there like everywhere else, or document why not — right now it is an
undocumented exception that new code keeps tripping over.

### 11. 65 of 172 settings have no UI
**Confident — measured.** 107 settings have a control; the rest are reachable
only by editing the database or the environment. The recent admin split into six
per-module pages makes this visible per module, which is the right moment to
decide: surface them, or mark them explicitly as environment-only.

### 12. Five agent settings are editable in two places, two ways
**Confident — measured.** `agent_enabled`, `agent_model`, `agent_temperature`,
`agent_max_tokens`, `agent_auto_execute` exist on both `admin-ai.html` (via
`data-key`/`SECTIONS`) and `agent-workflow.html` (via hand-rolled `g_` ids and
`putSettings`). Two mechanisms, one truth. Converge `agent-workflow.html` onto
`data-key`.

### 13. `main.py` should be split
**Confident.** 253 endpoints in one file. A router-per-domain split (honeypot,
kali, agent, netflow, osint, admin, xdr) costs little — FastAPI's `APIRouter` is
designed for it — and would make the repository reviewable and commit-splittable
again. This is the single highest-leverage refactor here.

---

## P3 — Testing

### 14. The largest modules have no tests at all
**Confident — measured.** Test-to-code ratio is ≈7%. Untested by line count:

| Module | Lines |
|---|---|
| `main.py` | 8,747 |
| `agent.py` | 3,830 |
| `command_service.py` | 644 |
| `mcp_server.py` | 559 |
| `nmap_scan.py` | 506 |
| `firewall_feed.py` | 433 |
| `kali_client.py` | 402 *(guard is tested; the client is not)* |

The existing tests are genuinely good — they test behaviour and argue for it in
their names (`test_a_typo_of_a_real_user_never_reaches_the_burn_list`). The
problem is coverage, not quality.

**Where tests would have paid already this week**, each of these being a real
defect that shipped:

- `actor_name()` — the session dict written to a `VARCHAR` column, latent until
  auth was switched on, in six places.
- The Kali guard's raw-string-vs-argv matching.
- `parse_interfaces()` returning zero interfaces against the real schema.
- A DHCP scope becoming a phantom host at its own gateway.

Highest value per hour: **an endpoint smoke test** that imports the app and
asserts every route responds without a 500 on a representative request. Cheap,
and it would have caught the `actor_name` class of bug immediately.

### 15. No test covers the frontend
`node --check` is a syntax check, not a test. The `formatTime` crash, the dead
`(status ? cmds : cmds)` ternary and the wrong colspans all pass it.

---

## What I could not determine

**Dead code.** I tried twice and both approaches failed honestly:

- Functions with no call site → 217 hits, almost all FastAPI route handlers,
  which are invoked by decorator and never by name.
- Routes not referenced by the frontend → 48 hits, most of them false: the
  frontend builds parameterised URLs with template literals, and several
  endpoints are legitimately non-browser (honeypot agents call
  `/api/honeypot/agent/*`, attackers call the decoy routes, monitoring calls
  `/api/health`).

Static analysis cannot answer this for a decorator-routed app with dynamic
client URLs. Doing it properly needs runtime evidence — `coverage.py` over the
test suite plus a week of production access logs through nginx, then treating
anything hit by neither as a candidate. Worth doing, but as its own exercise.

**301 broad `except Exception` handlers, 41 of which swallow silently.** Many
are deliberate and correct (best-effort enrichment, notification fan-out). Some
are almost certainly hiding real failures — the SFOS fallback bug was exactly
this shape. Distinguishing them needs case-by-case reading, not a grep.

---

## Suggested order

1. Lock down the chat SQL surface (**#1**) — smallest change, largest exposure.
2. Set `KALI_TARGET_ALLOWLIST` (**#3**) — one line.
3. Decide and then align `/ioc_*` (**#2**) — a decision, then either code or comments.
4. Cap the anomaly caches (**#5**) — one shared fix covers both modules.
5. Extract the Kali guard into a shared file (**#9**) — it has already drifted once.
6. Add the endpoint smoke test (**#14**).
7. Start splitting `main.py` into routers (**#13**) — everything above gets easier afterwards.

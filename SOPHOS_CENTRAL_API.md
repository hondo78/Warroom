# Sophos Central API — what exists, what we use, what is worth using

Written against [developer.sophos.com](https://developer.sophos.com/) as of
2026-09-22. The point of this file is to answer "what *can* we do with it"
once, honestly, so the answer does not have to be re-derived from the portal
every time somebody asks.

Three columns matter: what Sophos offers, what Warroom and Watchtower actually
call today, and — the only judgement in here — whether the rest is worth
building. A capability list with no opinion attached is just the vendor's
marketing page rewritten.

---

## The change that prompted this

On **2026-09-18** Sophos shipped the **Fusion XDR GraphQL APIs**: five GraphQL
endpoints replacing the classic XDR Query and Live Discover REST APIs. The old
routes are marked *"don't use for new integrations"*. Warroom was built entirely
on those old routes.

Three things about GraphQL break assumptions the REST client is built on, and
each one fails quietly rather than loudly:

| | REST | GraphQL |
|---|---|---|
| Host | the tenant's data region (`api-eu01…`) | always `api.taegis.sophos.com` |
| Failure | HTTP 4xx/5xx | **HTTP 200** with an `errors` array in the body |
| Detection severity | 0–10 | 0–1 float |
| Timestamps | ISO-8601 strings | `{ seconds, nanos }` |
| Case status/type/verdict | fixed enums | per-tenant UUIDs from lookup queries |
| Live query targeting | endpoints named on the run | session: create → fill → run |

The second row is the dangerous one. A client that decides success with
`raise_for_status()` reads a permissions failure, a malformed query and a
backend outage all as **"no detections found"** — which is indistinguishable
from good news, so nobody investigates it. `sophos_graphql.execute()` treats any
`errors` array as a failure, including when partial `data` arrives alongside it,
and `test_sophos_graphql.py` pins exactly that.

---

## What the documentation got wrong

Four of the query documents, written from the migration guides, were rejected
by the live schema. Introspection (`__type`, `__schema`) against the
real tenant settled each one — the server is the authority, the guide is a
description of it:

| Written from the guide | What the server actually has |
|---|---|
| `case { primaryStatusId typeId }` — UUID scalars | `primaryStatus { id name title isClosed }`, `type { id name title }` — nested objects |
| `caseTypes { id name }` | `caseTypes(arguments: {}) { types { … } }` — a required `arguments` object whose every member is optional, and a differently-named wrapper per lookup |
| `detectionAggregatesBySeverity(in: { cql_query }) { severity count }` | takes `earliest` as a `TimestampInput`, **not** a QL string, and returns one `aggregation` node with named buckets |
| `events { values { commandline hostname … } }` | `values` is a `Map!` scalar — selecting subfields on it is rejected. Taking the whole map is also the better answer: telemetry differs by sensor, and naming fields drops whatever this integration had not thought of |

That last row is the one to remember: **the same API speaks two time formats.**
The search query takes its bounds inside a QL predicate; the aggregate takes a
`{seconds}` struct. Mixing them fails as *"Field is not defined by type"*, which
reads like a typo rather than a category error.

**`detectionAggregatesBySeverity` returns `internal service error`** on this
tenant for every legal `group_by` (DOMAIN, WATCHLIST, HOSTNAME, DETECTOR, USER).
The document validates; the server fails. Kept rather than removed, so the
caller gets a 502 that says so instead of an empty chart that looks like zero
detections.

---

## Full capability map

**Legend:** ✅ implemented · ◻ available, not built · ⛔ not worth it for us ·
🕓 not released yet

### Fusion XDR — the new GraphQL surface

| API | Operations | Status | Notes |
|---|---|---|---|
| **Detections v2** | `detectionSearch`, `detectionRetrieveById`, `detectionRetrieveByHost`, `detectionRetrieveByEntity`, `detectionRetrieveByGroupKey`, `detectionAggregatesBySeverity`, `detectionCountByTenant`, `detectionPoll` | ✅ | Filtered with Fusion QL (`from alert where … earliest=-24h`). QL, **not** SQL — a query copied from the old API fails at the server |
| **Cases v2** | `cases`, `case`, `caseComments`, `caseEvidence`, `caseFiles` · `createCase`, `updateCase`, `addCaseComment`, `addEvidenceToCase`, `mergeCase`, `splitCase`, `createCaseLink`, `createCaseRule`, `createCaseTemplate`, `deleteCase*` | ✅ read + comment | Write paths beyond comments are built but unwired — see *Deliberately not wired* |
| **Events v1** | `events(input: { rns: [...] })` | ✅ | Resolves the event ids a case or detection cites. No pagination: you name the ids |
| **Threat Timeline v2** | `searchLineage`, `processLineageTreeSearch`, `lineageNodeTopRelatedEvents`, `enrichmentJobs`, `enrichmentQueries` | ✅ `searchLineage` | Process ancestry for a detection. The tree queries are worth adding when there is a UI that can draw one |
| **Live Endpoint Search v1** | `liveDiscoverCategories/Queries/Query`, `liveDiscoverQueryRun(s)`, `…RunResults(Csv)`, `…RunEndpoints` · `createLiveDiscoverSession`, `endpointSessions`, `runLiveDiscoverQuery`, `cancelLiveDiscoverQueryRun`, `create/update/deleteLiveDiscoverQuery` | ✅ run + results | Session model. A session with no endpoints runs against nothing and **reports success** — the client refuses an empty list rather than letting that happen |
| **Data Lake Search** | QL search over the lake | 🕓 | **Planned October 2026.** Request/response format is not public. The SQL-based XDR Query API stays the only programmatic lake access until then |

### Established REST APIs

| API | What it gives | Status |
|---|---|---|
| **Common — Alerts** | list, `POST /alerts/{id}/actions` | ✅ |
| **SIEM** | `/siem/v1/events` | ✅ |
| **Endpoint** | list, isolation, on-demand scan, delete, groups, installers | ✅ |
| **Firewall** | inventory, MDR threat-feed indicators + transaction status | ✅ |
| **Account Health Check** | posture score, historical, regional comparison | ✅ |
| **Email** | mailboxes CRUD, quarantine (pre + post delivery), clawback | ✅ |
| **XDR Query / Live Discover (REST)** | SQL over the lake, osquery on endpoints | ✅ *(deprecated upstream, kept)* |
| **Audit Events** *(new 2026-06-09)* | who changed what in Central | ◻ **worth building** |
| **Endpoint Tags** *(new 2026-03-16)* | key-value tags on endpoints | ◻ worth building |
| **Device Software** *(new 2026-04-07)* | bulk software assignment | ◻ |
| **DNS Protection v2** *(GA 2026-05-11)* | locations, policies, custom domain lists | ◻ |
| **Web Filtering** | site lists and profiles | ◻ |
| **Common — Directory** | users, groups, admins, roles | ◻ |
| **Licensing** | licences and firewall inventory | ◻ |
| **Mobile** | enrolment, compliance, lock/wipe/locate | ⛔ no mobile estate here |
| **Cloud Security** | runtime detection for containers | ⛔ |
| **Switch / Wi-Fi** | MAC filtering, task monitoring | ⛔ |
| **Partner / Organization / Business Automation** | multi-tenant admin, billing | ⛔ single tenant |
| **Account Management** | API token lifecycle | ⛔ done in the console, once |

### Why the ◻ recommendations

**Audit Events** is the one genuinely missing piece. Warroom can isolate an
endpoint, push a threat feed and comment on a case — all through one API
credential, so Central's own history attributes every one of them to "Warroom".
Warroom has its own audit log, but nothing reconciles the two, and "did this
change come from us or from a person in the console?" is exactly the question an
incident asks. Comments already carry a `[Warroom · <actor>]` prefix for this
reason; Audit Events would close the loop for everything else.

**Endpoint Tags** would let the host inventory carry ownership without a second
database to keep in step with Central.

**DNS Protection** and **Web Filtering** are real capability, but nothing in
either product currently acts on DNS or URL policy — they would be data with no
consumer, which is how the 65 unused settings in Warroom happened.

---

## Deliberately not wired

**Case creation and mutation.** `createCase`, `updateCase`, `mergeCase` and
`splitCase` are implemented on the client and reachable from code, but no HTTP
route exposes them. Creating a case in Central is an action a human takes in
Central, and an automated one arriving from a monitoring tool is a case nobody
owns. Comments are different: they attach context to a case a person already
opened.

**Data Lake GraphQL search.** Announced for October 2026 with no public format.
A guessed endpoint would fail at the server, months from now, in whatever code
happened to call it.

**Partner and Organization APIs.** Correct for an MSP, meaningless here.

---

## Where it lives

| | |
|---|---|
| `backend/app/sophos_graphql.py` | transport, the query documents, both scale conversions |
| `backend/app/sophos_client.py` | `gql_*` methods on `SophosClient`, alongside the REST ones |
| `backend/app/main.py` | `/api/xdr/detections`, `/api/xdr/cases*`, `/api/xdr/events`, `/api/xdr/livesearch/*` |
| `backend/tests/test_sophos_graphql.py` | the HTTP-200-is-not-success rule, and the scale conversions |

Both transports stay. Deprecated is not removed, a tenant that has not been
migrated still answers on the old routes, and this is the same reasoning that
kept the SFOS XML transport alive next to v23 REST — which turned out to be the
right call twice.

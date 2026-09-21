"""Sophos Central's Fusion XDR GraphQL APIs.

Sophos announced these on 2026-09-18: five GraphQL APIs — Detections, Cases,
Events, Threat Timeline and Live Endpoint Search — replacing the classic XDR
Query and Live Discover REST APIs, which are deprecated and explicitly marked
"don't use for new integrations". Warroom is built on those deprecated routes,
so this module is the successor transport.

Three things are different enough to be worth stating, because each one breaks
an assumption the REST client is built on:

**One host, no data region.** REST calls go to the tenant's regional host
(``api-eu01`` and friends). GraphQL does not: every request goes to
``api.taegis.sophos.com``, with the tenant named only by the ``X-Tenant-ID``
header. Pointing GraphQL at the regional host fails in a way that looks like an
auth problem.

**HTTP 200 is not success.** A GraphQL server reports failure in the body, as an
``errors`` array, with status 200. Code that trusts ``raise_for_status()`` reads
a total failure as an empty result — and in a security tool "no detections" is
the most dangerous thing a bug can say. :func:`execute` treats any ``errors`` as
a failure, and the one test that matters here pins exactly that.

**Partial data is still a failure.** GraphQL can return ``data`` *and* ``errors``
together: some fields resolved, others did not. Using the half that arrived
would silently under-report. Callers that genuinely want partial results have to
ask for them.

Severity scales differ too: the REST detections API used 0–10, GraphQL uses a
0–1 float. :func:`severity_to_ten` converts, because every existing Warroom
threshold, notification rule and UI badge is written against the old scale.
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# Fixed. Not the tenant's data region — see the module docstring.
GRAPHQL_URL = "https://api.taegis.sophos.com/graphql"

# GraphQL bodies are larger and the Data Lake behind them is slower than the
# REST list endpoints, so the default is more generous than SophosClient's 30s.
DEFAULT_TIMEOUT = 60.0


class SophosGraphQLError(RuntimeError):
    """A GraphQL request that did not fully succeed.

    Carries the raw ``errors`` array so a caller can tell a permissions problem
    from a malformed query from an outage — three failures that need three
    different reactions and would otherwise all read as "no results"."""

    def __init__(self, message: str, errors: list | None = None,
                 data: dict | None = None):
        super().__init__(message)
        self.errors = errors or []
        self.data = data

    @property
    def codes(self) -> list[str]:
        out = []
        for e in self.errors:
            if isinstance(e, dict):
                ext = e.get("extensions") or {}
                code = ext.get("code") or ext.get("errorType")
                if code:
                    out.append(str(code))
        return out


async def execute(client: httpx.AsyncClient, headers: dict, query: str,
                  variables: dict | None = None, *,
                  operation: str | None = None,
                  allow_partial: bool = False,
                  timeout: float = DEFAULT_TIMEOUT) -> dict:
    """Run one GraphQL document. Returns ``data``; raises on any error.

    ``allow_partial`` is opt-in and deliberately awkward to reach: the default
    is that a response carrying errors is a failed response, whatever else came
    with it.
    """
    body: dict[str, Any] = {"query": query, "variables": variables or {}}
    if operation:
        body["operationName"] = operation

    resp = await client.post(GRAPHQL_URL, json=body,
                             headers={**headers, "Content-Type": "application/json"},
                             timeout=timeout)
    # A transport-level failure is still a failure — 401, 429 and 5xx never
    # carry a GraphQL envelope.
    if resp.status_code >= 400:
        raise SophosGraphQLError(
            f"GraphQL HTTP {resp.status_code}: {resp.text[:300]}")

    try:
        payload = resp.json()
    except ValueError as e:
        raise SophosGraphQLError(f"GraphQL response was not JSON: {e}") from e

    errors = payload.get("errors")
    data = payload.get("data")

    if errors:
        summary = "; ".join(
            str(e.get("message", e))[:200] for e in errors if isinstance(e, dict)
        ) or str(errors)[:300]
        if allow_partial and data:
            # Said loudly. A partial answer that nobody is told about is how a
            # dashboard ends up confidently showing two thirds of the truth.
            logger.warning("GraphQL partial result (%s): %s", operation or "?", summary)
            return data
        raise SophosGraphQLError(f"GraphQL error: {summary}", errors, data)

    if data is None:
        # No data and no errors is not a valid GraphQL response. Returning {}
        # would make it indistinguishable from an empty but successful one.
        raise SophosGraphQLError("GraphQL response had neither data nor errors")
    return data


def severity_to_ten(value: Any) -> float | None:
    """GraphQL's 0–1 float → the 0–10 scale everything in Warroom already uses.

    Every threshold, notification rule and severity badge in this codebase was
    written against the REST scale. Converting at the boundary keeps that one
    change from rippling through all of them — and keeps a 0.9 from being read
    as "almost nothing" by a rule expecting 9."""
    if value is None:
        return None
    try:
        v = float(value)
    except (TypeError, ValueError):
        return None
    # Defensive: if Sophos ever sends the old scale here, do not multiply it
    # into nonsense. A value above 1 is already on the 0–10 scale.
    return round(v * 10, 1) if v <= 1.0 else round(v, 1)


def ts_to_iso(value: Any) -> str | None:
    """GraphQL timestamps are ``{seconds, nanos}``, not ISO strings."""
    if not isinstance(value, dict):
        return None
    seconds = value.get("seconds")
    if seconds is None:
        return None
    from datetime import datetime, timezone
    try:
        micros = int(value.get("nanos") or 0) // 1000
        return datetime.fromtimestamp(int(seconds), tz=timezone.utc).replace(
            microsecond=micros).isoformat()
    except (TypeError, ValueError, OSError):
        return None


# --- Detections ---------------------------------------------------------------

DETECTION_FIELDS = """
      id
      status
      suppressed
      metadata {
        title
        severity
        created_at { seconds nanos }
        first_seen_at { seconds nanos }
      }
      sensor_types
      attack_technique_ids
      source_entities { display_name subtype }
      target_entities { display_name subtype }
      event_ids { id }
"""

DETECTION_SEARCH = """
query SearchDetections($in: SearchRequestInput) {
  detectionSearch(in: $in) {
    status
    reason
    alerts {
      total_results
      list {%s}
    }
  }
}
""" % DETECTION_FIELDS

DETECTION_BY_ID = """
query DetectionsById($in: GetByIDRequestInput) {
  detectionRetrieveById(in: $in) {
    alerts { list {%s} }
  }
}
""" % DETECTION_FIELDS

DETECTION_BY_HOST = """
query DetectionsByHost($in: GetByIDRequestInput) {
  detectionRetrieveByHost(in: $in) {
    alerts { total_results list {%s} }
  }
}
""" % DETECTION_FIELDS

DETECTION_AGGREGATES = """
query DetectionSeverity($in: AggregateAlertsBySeverityInputInput) {
  detectionAggregatesBySeverity(in: $in) {
    aggregation {
      key
      count
      severities { info low medium high critical }
    }
  }
}
"""


def epoch_input(seconds_ago: int) -> dict:
    """A ``TimestampInput``: ``{seconds}``, not a QL string.

    The aggregate query takes structured time bounds while the search query
    takes them inside a QL predicate. Two time formats on one API is a trap that
    only shows up as "Field is not defined by type"."""
    import time
    return {"seconds": int(time.time()) - seconds_ago}


def detection_query(*, min_severity: float = 0.4, status: str = "OPEN",
                    earliest: str = "-24h", extra: str = "") -> str:
    """A Fusion QL predicate for the detection search.

    QL, not SQL — the deprecated XDR Query API took SQL and the two are not
    interchangeable. Severity here is the 0–1 scale.
    """
    parts = [f"severity >= {min_severity}"]
    if status:
        parts.append(f"status = '{status}'")
    if extra:
        parts.append(extra)
    return f"from alert where {' and '.join(parts)} earliest={earliest}"


# --- Cases --------------------------------------------------------------------

# Written against the live schema, not against the migration guide's prose.
# The guide describes `primaryStatusId`/`typeId` as UUID scalars; the server
# nests the whole object and rejects the flat names outright. Every field below
# was read back from `__type` introspection against the real tenant.
CASE_FIELDS = """
      id
      shortId
      title
      severity
      createdAt
      updatedAt
      closedAt
      assigneeId
      type { id name title }
      primaryStatus { id name title isClosed }
      secondaryStatus { id name title }
"""

CASES_SEARCH = """
query SearchCases($query: String!, $page: Int!, $perPage: Int!) {
  cases(arguments: {
    query: $query
    pagination: { offset: { page: $page, perPage: $perPage } }
  }) {
    totalCount
    cases {%s}
  }
}
""" % CASE_FIELDS

CASE_BY_ID = """
query GetCase($id: ID!) {
  case(id: $id) {%s
    keyFindings { content documentType documentVersion }
  }
}
""" % CASE_FIELDS

CASE_COMMENTS = """
query CaseComments($caseId: ID!) {
  caseComments(caseId: $caseId) {
    comments { id content createdAt authorId }
  }
}
"""

CASE_EVIDENCE = """
query CaseEvidence($caseId: ID!) {
  caseEvidence(caseId: $caseId) {
    detectionsEvidence { detectionId }
    eventsEvidence { eventId }
    assetsEvidence { assetId }
  }
}
"""

CREATE_CASE = """
mutation CreateCase($input: CreateCaseInput!) {
  createCase(input: $input) { id shortId title severity }
}
"""

UPDATE_CASE = """
mutation UpdateCase($input: UpdateCaseInput!) {
  updateCase(input: $input) { id shortId primaryStatusId }
}
"""

ADD_CASE_COMMENT = """
mutation AddCaseComment($input: AddCaseCommentInput!) {
  addCaseComment(input: $input) { id createdAt }
}
"""

# Reference data. Types, statuses and verdicts moved from fixed REST enums to
# UUIDs resolved through lookup queries — hard-coding one is how an integration
# breaks on a tenant that was provisioned differently.
# Three lookups, three differently-named wrapper fields — `types`,
# `primaryStatuses`, `secondaryStatuses` — and each takes a required
# `arguments` object whose every member is optional. Not guessable; introspected.
CASE_REFERENCE = """
query CaseReference {
  caseTypes(arguments: {}) { types { id name title } }
  casePrimaryStatuses(arguments: {}) { primaryStatuses { id name title isClosed } }
  caseSecondaryStatuses(arguments: {}) { secondaryStatuses { id name title } }
}
"""


# --- Events -------------------------------------------------------------------

# `values` is a `Map!` scalar, not an object. The guide's example selects
# subfields on it and the server rejects that outright — one more place where
# the prose describes an older shape than the schema has. Taking the whole map
# is also the better answer: an event's normalized telemetry differs by sensor,
# and naming fields here would quietly drop whatever this integration had not
# thought of.
EVENTS_BY_RN = """
query EventDetails($input: EventsInput!) {
  events(input: $input) {
    rn
    eventType
    summary
    eventTime
    ingestTime
    values
  }
}
"""


# --- Threat Timeline ----------------------------------------------------------

SEARCH_LINEAGE = """
query SearchLineage($input: SearchLineageInput!) {
  searchLineage(input: $input) {
    processCorrelationId
    counts { lineageNode lineageNodeDetections }
    matchingCounts { lineageNode lineageNodeDetections }
  }
}
"""


# --- Live Endpoint Search -----------------------------------------------------

LD_CATEGORIES = "query { liveDiscoverCategories { id name } }"

LD_QUERIES = """
query LiveDiscoverQueries($pageSize: Int) {
  liveDiscoverQueries(params: { pageSize: $pageSize }) {
    items { id name description categoryId }
  }
}
"""

LD_CREATE_SESSION = """
mutation CreateSession {
  createLiveDiscoverSession { session { name } }
}
"""

LD_ASSIGN_ENDPOINTS = """
mutation AssignEndpoints($sessions: [String!]!, $ids: [String!]!) {
  endpointSessions(input: {
    sessions: $sessions
    action: add
    filter: { ids: $ids }
  }) { requestedAt completedAt }
}
"""

LD_RUN_SAVED = """
mutation RunQuery($queryId: String!, $sessionId: String!) {
  runLiveDiscoverQuery(input: {
    savedQuery: { queryId: $queryId }
    sessionId: $sessionId
    matchEndpoints: { all: false }
  }) { executionSummary { id status } }
}
"""

LD_RUN_STATUS = """
query RunStatus($runId: ID!) {
  liveDiscoverQueryRun(runId: $runId) { id status createdAt finishedAt }
}
"""

LD_RESULTS = """
query GetResults($runId: ID!, $pageSize: Int, $fromKey: String) {
  liveDiscoverQueryRunResults(runId: $runId,
                              params: { pageSize: $pageSize, fromKey: $fromKey }) {
    items { endpointId hostname additionalColumns }
    pages { fromKey nextKey size }
    metadata { columns { name type } }
  }
}
"""


def flatten_detection(node: dict) -> dict:
    """GraphQL detection → the flat shape the rest of Warroom already speaks.

    Done here rather than in each caller so the 0–1 severity and the
    ``{seconds, nanos}`` timestamps are converted exactly once. Two callers
    converting independently is how one of them ends up not converting."""
    meta = node.get("metadata") or {}
    return {
        "id": node.get("id"),
        "status": node.get("status"),
        "suppressed": bool(node.get("suppressed")),
        "title": meta.get("title"),
        "severity": severity_to_ten(meta.get("severity")),
        "severity_raw": meta.get("severity"),
        "created_at": ts_to_iso(meta.get("created_at")),
        "first_seen_at": ts_to_iso(meta.get("first_seen_at")),
        "sensor_types": node.get("sensor_types") or [],
        "mitre_techniques": node.get("attack_technique_ids") or [],
        "source_entities": [e.get("display_name")
                            for e in (node.get("source_entities") or [])
                            if isinstance(e, dict)],
        "target_entities": [e.get("display_name")
                            for e in (node.get("target_entities") or [])
                            if isinstance(e, dict)],
        "event_ids": [e.get("id") for e in (node.get("event_ids") or [])
                      if isinstance(e, dict)],
    }

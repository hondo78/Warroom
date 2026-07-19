"""AI agent loop — analyzes alerts and proposes actions.

Wire format: OpenAI-compatible /chat/completions, so the same code drives
LMStudio, Ollama, vLLM and the OpenAI API itself. The model is prompted to
return a strict JSON object — we re-validate before persisting and never
trust the LLM with raw API access.

Decisions land in `agent_decisions` as ``status='pending'`` unless
``settings.agent_auto_execute`` is true and the action is one of the safe
ones (``acknowledge``, ``block_ip``). Manual operator approval is the
default safety mechanism.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select, text

from app import login_cache
from app import waf_path_cache
from app.config import settings
from app.database import async_session
from app.models import (
    AgentApprovalPattern, AgentDecision, Alert, AnomalyVerdict, BlockedDomain,
    BlockedIp, BlockedUrl, Event, FirewallLog, WhitelistedIp,
)

logger = logging.getLogger(__name__)

ALLOWED_ACTIONS = {
    "block_ip", "block_ips", "block_subnet", "block_domain", "block_url",
    "acknowledge", "isolate", "notify", "no_action", "revoke_sessions",
}
# isolate stays manual. Block actions ALWAYS require human approval and are
# never auto-executed — regardless of agent_auto_execute. Only the listed
# non-destructive actions may auto-run.
BLOCK_ACTIONS = {
    "block_ip", "block_ips", "block_subnet", "block_domain", "block_url",
}
AUTO_EXECUTABLE_ACTIONS = {
    "acknowledge",
}
# Hard upper bound for block_subnet to avoid accidentally blocking enormous
# ranges if the rule ever misfires on a /16 or /8 prefix.
MAX_SUBNET_HOSTS = 1024  # /22 IPv4
# Upper bound for block_ips (distributed brute-force): a coordinated attack can
# span many sources, but cap it so a misfire can't blocklist thousands at once.
MAX_BULK_IPS = 256

# Human-readable label for the source_type column, used in blocked_ips.comment
# so a downstream operator immediately sees where the block originated.
_SOURCE_LABELS: dict[str, str] = {
    "alert": "Alert",
    "waf":   "WAF",
    "ips":   "IPS",
    "failed_login": "Login",
    "triage": "Triage",
    "event": "Event",
    "anomaly": "Anomaly",
    "m365_login": "M365-Login",
}


def _source_label(source_type: str | None) -> str:
    return _SOURCE_LABELS.get((source_type or "").lower(), source_type or "?")


# --- Pydantic: typed contract for every LLM decision -----------------------
# A single model is the source of truth both for VALIDATING the model's reply
# and for the JSON schema we hand it via response_format (structured outputs).


class LLMDecision(BaseModel):
    """Validated shape of an agent decision returned by the LLM."""

    action: str
    args: dict[str, Any] = Field(default_factory=dict)
    reasoning: str = ""

    @field_validator("reasoning", mode="before")
    @classmethod
    def _coerce_reasoning(cls, v: Any) -> str:
        return str(v or "")[:2000]

    @field_validator("args", mode="before")
    @classmethod
    def _coerce_args(cls, v: Any) -> dict:
        return v if isinstance(v, dict) else {}


def _decision_response_format(allowed_actions: list[str]) -> dict[str, Any]:
    """OpenAI-compatible ``response_format`` spec for structured outputs. The
    ``action`` enum is narrowed to the actions this stage may emit, so the model
    physically cannot return an out-of-scope action. ``strict`` is off because
    ``args`` is intentionally free-form."""
    return {
        "type": "json_schema",
        "json_schema": {
            "name": "agent_decision",
            "strict": False,
            "schema": {
                "type": "object",
                "properties": {
                    "action": {"type": "string", "enum": list(allowed_actions)},
                    "args": {"type": "object"},
                    "reasoning": {"type": "string"},
                },
                "required": ["action", "reasoning"],
                "additionalProperties": True,
            },
        },
    }


def _validate_decision(content: str) -> dict[str, Any]:
    """Turn raw model output into a validated decision dict.

    With structured outputs the content is already clean JSON and validates
    directly via Pydantic. For models that wrap JSON in prose / <think> blocks
    or emit a draft + final object, fall back to the tolerant extractor
    (``_parse_decision``), then re-validate through the same model."""
    try:
        dec = LLMDecision.model_validate_json(content or "")
        if dec.action.strip() in ALLOWED_ACTIONS:
            return dec.model_dump()
    except Exception:
        pass
    raw = _parse_decision(content)  # tolerant; raises if truly unparseable
    return LLMDecision.model_validate(raw).model_dump()


def _should_auto_execute(action: str) -> tuple[bool, str]:
    """Decide whether a fresh decision can auto-execute and tell us why.

    The action is chosen purely from per-source thresholds (in the prompt) —
    there is no confidence score. Auto-execution is gated only by the action's
    risk class and the ``agent_auto_execute`` master switch.

    Returns (should_execute, reason). The reason is logged so the audit
    trail explains why an action ran without human approval.
    """
    # Hard rule: every block decision needs human approval — no exceptions.
    if action in BLOCK_ACTIONS:
        return False, ""
    if action not in AUTO_EXECUTABLE_ACTIONS:
        return False, ""
    if settings.agent_auto_execute:
        return True, "agent_auto_execute master switch is ON"
    return False, ""


# ---------------------------------------------------------------------------
# Self-learning auto-approval
#
# Every human approve/reject is recorded per decision "signature". A signature
# groups *similar* decisions by source_type + action + a best-available
# rule/signature field. Once a signature's NET score (approvals − rejections)
# reaches settings.agent_learning_threshold, matching NEW decisions are
# auto-approved and executed without asking — block actions included. Rejections
# subtract from the net, so a pattern can lose (and later regain) eligibility.
# ---------------------------------------------------------------------------

def _signature_rule(source_type: str | None, action_args: dict | None,
                    alert_type: str | None) -> str:
    """Best-available 'rule/signature' identifier for grouping similar
    decisions. Empty string when a source has no stable sub-signature (then a
    pattern is effectively source_type+action)."""
    st = source_type or "alert"
    ctx = (action_args or {}).get("context") or {}
    if st == "event":
        return str(ctx.get("event_type") or "")
    if st == "ips":
        cats = [str(c).strip().lower() for c in (ctx.get("categories") or []) if c]
        return "/".join(sorted(set(cats)))
    if st == "triage":
        return str(ctx.get("value_type") or "")
    if st == "failed_login":
        if ctx.get("distributed_brute_force_indicator"):
            return "distributed"
        if ctx.get("subnet_brute_force_indicator"):
            return "subnet"
        return "per_ip"
    if st == "alert":
        return str(alert_type or "")
    # waf and anything else: group by source_type + action only.
    return str(ctx.get("rule") or "")


async def _decision_signature(rec: AgentDecision) -> tuple[str, str]:
    """Return (signature, rule) for a decision. Loads the alert type for
    alert-sourced decisions so their signature reflects the alarm type."""
    st = rec.source_type or "alert"
    alert_type = None
    if st == "alert" and rec.alert_id:
        async with async_session() as db:
            a = await db.get(Alert, rec.alert_id)
            alert_type = a.alert_type if a else None
    rule = _signature_rule(st, rec.action_args, alert_type)
    signature = f"{st}|{rec.action}|{rule}".lower()
    return signature, rule


async def record_approval_feedback(rec: AgentDecision, approved: bool) -> None:
    """Record one human approve/reject against the decision's pattern.
    Best-effort: learning must never break the approve/reject flow."""
    try:
        signature, rule = await _decision_signature(rec)
        async with async_session() as db:
            pat = (await db.execute(
                select(AgentApprovalPattern).where(AgentApprovalPattern.signature == signature)
            )).scalar_one_or_none()
            if pat is None:
                pat = AgentApprovalPattern(
                    signature=signature, source_type=rec.source_type or "alert",
                    action=rec.action, rule=rule,
                )
                db.add(pat)
            if approved:
                pat.approvals = (pat.approvals or 0) + 1
            else:
                pat.rejections = (pat.rejections or 0) + 1
            pat.last_decided_at = datetime.now(timezone.utc)
            await db.commit()
    except Exception as e:
        logger.warning(f"agent: record_approval_feedback failed: {e}")


async def record_feedback_by_id(decision_id: int, approved: bool) -> None:
    """Load a decision fresh and record one human approve/reject against its
    pattern. Convenience wrapper for the API handlers."""
    async with async_session() as db:
        rec = await db.get(AgentDecision, decision_id)
    if rec is not None:
        await record_approval_feedback(rec, approved)


async def _maybe_learned_auto_approve(rec: AgentDecision) -> bool:
    """If learning is on and this decision's pattern has enough net approvals,
    execute it now (auto-approve) and return True. execute_decision still
    re-checks the whitelist, so a learned block can't hit a protected IP."""
    if not settings.agent_learning_enabled:
        return False
    threshold = max(1, int(settings.agent_learning_threshold or 3))
    try:
        signature, _rule = await _decision_signature(rec)
        async with async_session() as db:
            pat = (await db.execute(
                select(AgentApprovalPattern).where(AgentApprovalPattern.signature == signature)
            )).scalar_one_or_none()
            net = ((pat.approvals or 0) - (pat.rejections or 0)) if pat else 0
            if pat is None or net < threshold:
                return False
            pat.auto_approved = (pat.auto_approved or 0) + 1
            pat.last_decided_at = datetime.now(timezone.utc)
            await db.commit()

        # Annotate provenance so the UI/audit trail shows it wasn't a human.
        async with async_session() as db:
            r = await db.get(AgentDecision, rec.id)
            if r is None:
                return False
            note = f"Auto-approved by learned pattern (net {net} ≥ threshold {threshold})."
            r.human_comment = r.human_comment or note
            aa = dict(r.action_args or {})
            aa["auto_approved"] = {"by": "learned_pattern", "signature": signature,
                                   "net": net, "threshold": threshold}
            r.action_args = aa
            await db.commit()
    except Exception as e:
        logger.warning(f"agent: learned auto-approve check failed for {rec.id}: {e}")
        return False

    logger.info(f"agent: learned auto-approve decision {rec.id} "
                f"(sig={signature}, net={net}>={threshold})")
    try:
        await execute_decision(rec.id)
    except Exception as e:
        logger.warning(f"agent: learned auto-approve execute failed for {rec.id}: {e}")
    return True


DEFAULT_SYSTEM_PROMPT = """Du bist ein Security-Operations-Assistent für Warroom.
Du bekommst einen einzelnen Alarm und sollst eine Empfehlung für die nächste Aktion abgeben.

Erlaubte Aktionen:
- "block_ip": Quell-IP auf die Blocklist setzen. Nur für öffentliche IPs sinnvoll. Nutze "target_ip" im args-Feld.
- "acknowledge": Alarm als gesichtet markieren (kein weiteres Handeln nötig, z.B. false positive).
- "isolate": Endpoint isolieren (nur bei aktivem Malware-/Threat-Befund mit klarem Endpoint-Bezug).
- "no_action": Mehr Daten abwarten, weder blocken noch acknowledgen.

Die Aktion ergibt sich allein aus den Indikatoren/Schwellenwerten — gib KEINE
confidence aus.

Antworte ausschließlich mit gültigem JSON (kein ```-Fence, kein zusätzlicher Text).
BEISPIEL:
{
  "action": "block_ip",
  "args": {"target_ip": "203.0.113.45"},
  "reasoning": "Bekannte C2-IP mit mehrfachen failed logins von öffentlicher Quelle. Klar bösartig."
}

Wähle block_ip / isolate nur bei klar bösartigen Indikatoren (bekannte C2-IPs,
mehrfache failed logins von public IP, dokumentierte Malware-Treffer, etc.).
Bei privaten IPs (10.x, 172.16-31.x, 192.168.x) niemals block_ip empfehlen.

WICHTIG: Wenn "source_ip_is_whitelisted" true ist (z.B. eigene Firewall-IP), NIEMALS
block_ip empfehlen — das System würde das ohnehin verweigern, aber die Empfehlung
landet als 'failed' in der DB und verschwendet Zeit."""


DEFAULT_SYSTEM_PROMPT_EN = """You are a security operations assistant for Warroom.
You receive a single alert and should recommend the next action.

Allowed actions:
- "block_ip": Add the source IP to the blocklist. Only meaningful for public IPs. Use "target_ip" in the args field.
- "acknowledge": Mark the alert as reviewed (no further action needed, e.g. false positive).
- "isolate": Isolate the endpoint (only for an active malware/threat finding with a clear endpoint reference).
- "no_action": Wait for more data, neither block nor acknowledge.

The action follows solely from the indicators/thresholds — Gib KEINE
confidence aus.

Reply exclusively with valid JSON (no ```-fence, no additional text).
EXAMPLE:
{
  "action": "block_ip",
  "args": {"target_ip": "203.0.113.45"},
  "reasoning": "Known C2 IP with multiple failed logins from a public source. Clearly malicious."
}

Only choose block_ip / isolate for clearly malicious indicators (known C2 IPs,
multiple failed logins from a public IP, documented malware hits, etc.).
For private IPs (10.x, 172.16-31.x, 192.168.x) never recommend block_ip.

IMPORTANT: When "source_ip_is_whitelisted" is true (e.g. our own firewall IP), NEVER
recommend block_ip — the system would refuse it anyway, but the recommendation
lands as 'failed' in the DB and wastes time."""


# --- Default System-Prompts für die regel-getriebenen Loops ---
# Jeder dieser Prompts kann in der Admin-Seite überschrieben werden. Leer ⇒
# Fallback auf diese Defaults. Die Prompts spiegeln die früher hartcodierten
# Regel-Leitern wider, sind aber jetzt für das LLM gedacht — Schwellen kommen
# als ``thresholds`` im JSON, das LLM darf davon begründet abweichen.

DEFAULT_WAF_PROMPT = """Du bist ein WAF-Security-Analyst für Warroom.

INPUT (JSON, vom System gestellt):
  - source_ip       — angreifende öffentliche IPv4
  - context         — Aggregat-Werte zur IP (4xx/5xx-Counts in 24 h, HTTP-Statuses,
                       Hosts, Land/Stadt) und die konfigurierte Schwelle (threshold).
                       PFAD-INTELLIGENZ (aus Redis-Cache, über 24 h gesammelt):
                         distinct_paths_24h — Anzahl UNTERSCHIEDLICHER Pfade, die die
                                              IP angefragt hat
                         path_4xx_count     — wie viele davon mit 4xx (meist 404)
                                              beantwortet wurden
                         sample_paths       — Stichprobe der angefragten Pfade (max 60)
  - osint           — OSINT-Lookup (abuseipdb, virustotal, shodan, greynoise,
                       intelix, ipinfo). Felder können fehlen wenn ein Provider
                       keinen Key/Account hat.
  - allowed_actions — erlaubte Werte für `action`

ENTSCHEIDUNGSREGELN (in Reihenfolge prüfen, erste passende greift). Ist eine
Schwelle erreicht ⇒ action="block_ip", sonst action="no_action". Gib KEINE
confidence aus.
1. WORDLIST-/DIRECTORY-BRUTE-FORCE (forced browsing / Verzeichnis-Scan):
   Viele UNTERSCHIEDLICHE Pfade von einer IP, überwiegend 404 — typischer
   Scanner/Wordlist-Angriff (z. B. /wp-admin, /.env, /.git, /phpmyadmin,
   /admin, /config.php, /backup.zip …). Prüfe sample_paths auf solche Muster.
   Indiz: distinct_paths_24h >= 15 UND der Großteil ist 4xx (path_4xx_count)
                                                    → block_ip.
   Begründe im reasoning, dass es ein Wordlist-/Verzeichnis-Brute-Force ist,
   und nenne 2-3 verdächtige Pfade aus sample_paths.
2. count_4xx_24h + count_5xx_24h >= threshold       → block_ip.
3. OSINT Sophos-Intelix-Treffer (security_category gesetzt ODER
   intelix.score >= 70 ODER intelix.category ∈ {Malicious, High Risk, Bad})
                                                    → block_ip.
4. SHODAN-CVE-SCHWERE: shodan.cve_severity.has_high_critical = true — die IP
   exponiert MINDESTENS EINE CVE mit CVSS High/Critical (>= 7.0), ODER
   shodan.cve_severity.kev > 0 (CISA-KEV, aktiv ausgenutzt).
                                                    → block_ip.
   NUR mittlere/niedrige CVEs (has_high_critical = false) sind KEIN Block-Grund.
   Nenne im reasoning die schwerste CVE-ID + CVSS/Severity (aus cve_severity.top).
5. OSINT-Treffer anderer Provider (abuseipdb.abuse_score >= 75 ODER
   virustotal.malicious >= 2 ODER greynoise.classification = "malicious")
                                                    → block_ip.
6. Sonst                                            → no_action.

AUSGABE (strikt JSON, kein ```-Fence, kein zusätzlicher Text). BEISPIEL:
{
  "action": "block_ip",
  "args": {"target_ip": "203.0.113.45"},
  "reasoning": "Wordlist-Scan: 42 unterschiedliche Pfade, fast alle 404 (u.a. /.env, /wp-admin, /phpmyadmin). Klarer Directory-Brute-Force."
}
"""


DEFAULT_WAF_PROMPT_EN = """You are a WAF security analyst for Warroom.

INPUT (JSON, provided by the system):
  - source_ip       — attacking public IPv4
  - context         — aggregate values for the IP (4xx/5xx counts over 24h, HTTP statuses,
                       hosts, country/city) and the configured threshold (threshold).
                       PATH INTELLIGENCE (from the Redis cache, collected over 24h):
                         distinct_paths_24h — number of DISTINCT paths the IP
                                              has requested
                         path_4xx_count     — how many of those were answered
                                              with 4xx (mostly 404)
                         sample_paths       — sample of requested paths (max 60)
  - osint           — OSINT lookup (abuseipdb, virustotal, shodan, greynoise,
                       intelix, ipinfo). Fields may be missing if a provider
                       has no key/account.
  - allowed_actions — permitted values for `action`

DECISION RULES (check in order, first match wins). If a threshold is reached ⇒
action="block_ip", otherwise action="no_action". Gib KEINE
confidence aus.
1. WORDLIST / DIRECTORY BRUTE-FORCE (forced browsing / directory scan):
   Many DISTINCT paths from one IP, predominantly 404 — typical
   scanner/wordlist attack (e.g. /wp-admin, /.env, /.git, /phpmyadmin,
   /admin, /config.php, /backup.zip …). Check sample_paths for such patterns.
   Indicator: distinct_paths_24h >= 15 AND the majority is 4xx (path_4xx_count)
                                                    → block_ip.
   Explain in the reasoning that it is a wordlist/directory brute-force,
   and name 2-3 suspicious paths from sample_paths.
2. count_4xx_24h + count_5xx_24h >= threshold       → block_ip.
3. OSINT Sophos Intelix hit (security_category set OR
   intelix.score >= 70 OR intelix.category ∈ {Malicious, High Risk, Bad})
                                                    → block_ip.
4. SHODAN CVE SEVERITY: shodan.cve_severity.has_high_critical = true — the IP
   exposes AT LEAST ONE CVE with CVSS High/Critical (>= 7.0), OR
   shodan.cve_severity.kev > 0 (CISA KEV, actively exploited).
                                                    → block_ip.
   Medium/low CVEs only (has_high_critical = false) are NOT a block reason.
   Name in the reasoning the worst CVE id + CVSS/severity (from cve_severity.top).
5. OSINT hit from other providers (abuseipdb.abuse_score >= 75 OR
   virustotal.malicious >= 2 OR greynoise.classification = "malicious")
                                                    → block_ip.
6. Otherwise                                        → no_action.

OUTPUT (strict JSON, no ```-fence, no additional text). EXAMPLE:
{
  "action": "block_ip",
  "args": {"target_ip": "203.0.113.45"},
  "reasoning": "Wordlist scan: 42 distinct paths, almost all 404 (incl. /.env, /wp-admin, /phpmyadmin). Clear directory brute-force."
}
"""


DEFAULT_IPS_PROMPT = """Du bist ein IPS/IDP-Security-Analyst für Warroom.

INPUT (JSON):
  - source_ip
  - context         — count_24h (IPS-Hits in 24h), severities (Liste), signatures,
                       categories, threshold (konfigurierte Schwelle), Land/Stadt
  - osint           — wie WAF
  - allowed_actions

ENTSCHEIDUNGSREGELN (erste passende greift). Ist eine Schwelle erreicht ⇒
action="block_ip", sonst action="no_action". Gib KEINE confidence aus.
1. severities enthält "high" oder "critical"         → block_ip.
   IPS klassifiziert das System bereits als Intrusion-Attempt; bei hoher
   Schwere ist Block ohne weitere Belege gerechtfertigt.
2. count_24h >= threshold                            → block_ip.
3. OSINT-Sophos-Intelix-Treffer                      → block_ip.
4. SHODAN-CVE-SCHWERE: shodan.cve_severity.has_high_critical = true (mind. eine
   CVE mit CVSS High/Critical >= 7.0) ODER kev > 0    → block_ip.
   Nur mittlere/niedrige CVEs sind KEIN Block-Grund. Nenne die schwerste CVE+CVSS.
5. OSINT-Treffer anderer Provider                    → block_ip.
6. Sonst                                             → no_action.

AUSGABE (strikt JSON, kein ```-Fence, kein zusätzlicher Text). BEISPIEL:
{
  "action": "block_ip",
  "args": {"target_ip": "198.51.100.7"},
  "reasoning": "IPS-Treffer mit Schweregrad 'high' (Signatur SQL-Injection), 18 Hits in 24h. Eindeutiger Intrusion-Versuch."
}
"""


DEFAULT_IPS_PROMPT_EN = """You are an IPS/IDP security analyst for Warroom.

INPUT (JSON):
  - source_ip
  - context         — count_24h (IPS hits in 24h), severities (list), signatures,
                       categories, threshold (configured threshold), country/city
  - osint           — like WAF
  - allowed_actions

DECISION RULES (first match wins). If a threshold is reached ⇒
action="block_ip", otherwise action="no_action". Do not output any confidence.
1. severities contains "high" or "critical"          → block_ip.
   IPS already classifies the system as an intrusion attempt; at high
   severity a block is justified without further evidence.
2. count_24h >= threshold                            → block_ip.
3. OSINT Sophos Intelix hit                          → block_ip.
4. SHODAN CVE SEVERITY: shodan.cve_severity.has_high_critical = true (>= one CVE
   with CVSS High/Critical >= 7.0) OR kev > 0         → block_ip.
   Medium/low CVEs only are NOT a block reason. Name the worst CVE + CVSS.
5. OSINT hit from other providers                    → block_ip.
6. Otherwise                                         → no_action.

OUTPUT (strict JSON, no ```-fence, no additional text). EXAMPLE:
{
  "action": "block_ip",
  "args": {"target_ip": "198.51.100.7"},
  "reasoning": "IPS hit with severity 'high' (signature SQL injection), 18 hits in 24h. Unambiguous intrusion attempt."
}
"""


DEFAULT_FAILED_LOGIN_PROMPT = """Du bist ein Brute-Force/Login-Security-Analyst für Warroom.
Du bewertest EINE einzelne Quell-IP mit fehlgeschlagenen Login-Versuchen.

INPUT (JSON):
  - source_ip       — die IP, um die es geht
  - context         — count_24h, users (Liste), components
                       (SSL VPN/Admin/User Portal/IPSec), threshold, Land/Stadt
  - osint           — OSINT-Lookup (abuseipdb, virustotal, shodan, greynoise,
                       intelix, ipinfo). Felder können fehlen.
  - allowed_actions — "block_ip", "no_action"

ENTSCHEIDUNGSREGELN (erste passende greift). Ist eine Schwelle erreicht ⇒
action="block_ip", sonst action="no_action". Gib KEINE confidence aus.
1. count_24h >= threshold                          → block_ip.
2. OSINT Sophos-Intelix-Treffer                    → block_ip.
3. SHODAN-CVE-SCHWERE: shodan.cve_severity.has_high_critical = true (mind. eine
   CVE mit CVSS High/Critical >= 7.0) ODER kev > 0  → block_ip.
   Nur mittlere/niedrige CVEs sind KEIN Block-Grund. Nenne die schwerste CVE+CVSS.
4. OSINT-Treffer anderer Provider                  → block_ip.
5. Sonst                                           → no_action.

AUSGABE (strikt JSON, kein ```-Fence, kein zusätzlicher Text). BEISPIEL:
{
  "action": "block_ip",
  "args": {"target_ip": "192.0.2.88"},
  "reasoning": "61 fehlgeschlagene SSL-VPN-Logins in 24h auf mehrere User (admin, root). Schwelle (10) klar überschritten — Brute-Force."
}
"""


DEFAULT_FAILED_LOGIN_PROMPT_EN = """You are a brute-force/login security analyst for Warroom.
You assess ONE single source IP with failed login attempts.

INPUT (JSON):
  - source_ip       — the IP in question
  - context         — count_24h, users (list), components
                       (SSL VPN/Admin/User Portal/IPSec), threshold, country/city
  - osint           — OSINT lookup (abuseipdb, virustotal, shodan, greynoise,
                       intelix, ipinfo). Fields may be missing.
  - allowed_actions — "block_ip", "no_action"

DECISION RULES (first match wins). If a threshold is reached ⇒
action="block_ip", otherwise action="no_action". Do not output any confidence.
1. count_24h >= threshold                          → block_ip.
2. OSINT Sophos Intelix hit                        → block_ip.
3. SHODAN CVE SEVERITY: shodan.cve_severity.has_high_critical = true (>= one CVE
   with CVSS High/Critical >= 7.0) OR kev > 0       → block_ip.
   Medium/low CVEs only are NOT a block reason. Name the worst CVE + CVSS.
4. OSINT hit from other providers                  → block_ip.
5. Otherwise                                       → no_action.

OUTPUT (strict JSON, no ```-fence, no additional text). EXAMPLE:
{
  "action": "block_ip",
  "args": {"target_ip": "192.0.2.88"},
  "reasoning": "61 failed SSL-VPN logins in 24h against multiple users (admin, root). Threshold (10) clearly exceeded — brute-force."
}
"""


DEFAULT_DISTRIBUTED_LOGIN_PROMPT = """Du bist ein Analyst für VERTEILTE Brute-Force-Angriffe (Distributed Brute Force) in Warroom.

Du bekommst die fehlgeschlagenen Login-Versuche der letzten Minuten als JSON,
bereits aggregiert nach ihrem tatsächlichen NETZ (CIDR, per OSINT/ipinfo-RDAP
ermittelt — nicht das naive /24). Deine Aufgabe: erkenne, ob aus EINEM Netz
koordiniert von mehreren unterschiedlichen IPs angegriffen wird, und blocke dann
das ganze Netz.

INPUT (JSON):
  - window_minutes        — Beobachtungsfenster in Minuten
  - total_login_attempts  — Gesamtzahl übergebener Versuche
  - thresholds            — {min_attempts_per_net, min_distinct_ips_per_net}:
                            Richtwert, ab wann ein Netz als koordiniert gilt
  - max_block_hosts       — maximale Größe (Adressen) für block_subnet
  - networks              — Aggregat je Netz: {network (CIDR), network_name,
                            attempts, distinct_ips, subnets24, countries,
                            too_large (Netz > max_block_hosts)}
  - login_attempts        — Einzelversuche, je {ip, subnet24, network, user,
                            component, country, ts}
  - allowed_actions       — "block_subnet", "block_ips", "no_action"

VORGEHEN:
1. Betrachte `networks`. Ein Netz gilt als verteilter Brute-Force, wenn
   attempts >= thresholds.min_attempts_per_net UND distinct_ips >=
   thresholds.min_distinct_ips_per_net (bei klarem Muster begründet abweichen).
2. Entscheidung (Aktion ergibt sich aus den Schwellen — gib KEINE confidence aus):
   - Genau EIN auffälliges Netz mit too_large=false → action="block_subnet",
       args={"target_subnet":"<CIDR aus networks.network>"}.
       So wird das GANZE Netz geblockt (Mensch muss bestätigen).
   - Auffälliges Netz aber too_large=true, ODER MEHRERE auffällige Netze, ODER
       gestreute Einzel-IPs → action="block_ips",
       args={"target_ips":[... die auffälligen Quell-IPs ...]}.
   - Kein Netz über der Schwelle → action="no_action".
3. reasoning: nenne das/die betroffenen Netze (CIDR + network_name), deren
   attempts und distinct_ips.

WICHTIG: Nutze als target_subnet ausschließlich einen CIDR-Wert aus
`networks.network`. Erfinde keine Präfixe. Die Whitelist (eigene IPs) wird vom
System bei der Ausführung erneut geprüft; jeder Block braucht menschliche Freigabe.

AUSGABE (strikt JSON, kein ```-Fence, kein zusätzlicher Text). BEISPIEL:
{
  "action": "block_subnet",
  "args": {"target_subnet": "203.0.113.0/24"},
  "reasoning": "Netz 203.0.113.0/24 (ExampleHoster): 240 Versuche von 17 unterschiedlichen IPs in 15 Min — koordinierter verteilter Brute-Force."
}
"""


DEFAULT_DISTRIBUTED_LOGIN_PROMPT_EN = """You are an analyst for DISTRIBUTED brute-force attacks (Distributed Brute Force) in Warroom.

You receive the failed login attempts of the last few minutes as JSON,
already aggregated by their actual NETWORK (CIDR, determined via OSINT/ipinfo-RDAP
— not the naive /24). Your task: detect whether ONE network is attacking in a
coordinated way from several distinct IPs, and then block the whole network.

INPUT (JSON):
  - window_minutes        — observation window in minutes
  - total_login_attempts  — total number of attempts handed over
  - thresholds            — {min_attempts_per_net, min_distinct_ips_per_net}:
                            guideline for when a network counts as coordinated
  - max_block_hosts       — maximum size (addresses) for block_subnet
  - networks              — aggregate per network: {network (CIDR), network_name,
                            attempts, distinct_ips, subnets24, countries,
                            too_large (network > max_block_hosts)}
  - login_attempts        — individual attempts, each {ip, subnet24, network, user,
                            component, country, ts}
  - allowed_actions       — "block_subnet", "block_ips", "no_action"

PROCEDURE:
1. Look at `networks`. A network counts as a distributed brute-force when
   attempts >= thresholds.min_attempts_per_net AND distinct_ips >=
   thresholds.min_distinct_ips_per_net (deviate with justification when the pattern is clear).
2. Decision (the action follows from the thresholds — Do not output any confidence):
   - Exactly ONE suspicious network with too_large=false → action="block_subnet",
       args={"target_subnet":"<CIDR from networks.network>"}.
       This blocks the WHOLE network (a human must confirm).
   - Suspicious network but too_large=true, OR MULTIPLE suspicious networks, OR
       scattered individual IPs → action="block_ips",
       args={"target_ips":[... the suspicious source IPs ...]}.
   - No network above the threshold → action="no_action".
3. reasoning: name the affected network(s) (CIDR + network_name), their
   attempts and distinct_ips.

IMPORTANT: Use as target_subnet exclusively a CIDR value from
`networks.network`. Do not invent prefixes. The whitelist (our own IPs) is
re-checked by the system at execution time; every block requires human approval.

OUTPUT (strict JSON, no ```-fence, no additional text). EXAMPLE:
{
  "action": "block_subnet",
  "args": {"target_subnet": "203.0.113.0/24"},
  "reasoning": "Network 203.0.113.0/24 (ExampleHoster): 240 attempts from 17 distinct IPs in 15 min — coordinated distributed brute-force."
}
"""


DEFAULT_TRIAGE_PROMPT = """Du bist ein Threat-Intelligence-Triage-Analyst für Warroom.
Ein Operator hat einen Indikator (IP, Domain oder URL) zur Bewertung übergeben.

INPUT (JSON):
  - value           — der zu prüfende Wert
  - value_type      — "ip" | "domain" | "url"
  - note            — optionaler Hinweis des Operators (Kontext, kann fehlen)
  - osint           — OSINT-Lookup (bei IP: abuseipdb, virustotal, shodan,
                       greynoise, intelix, ipinfo; bei domain/url: intelix,
                       virustotal, ggf. dns). Felder können fehlen.
  - allowed_actions — erlaubte Werte für `action` (genau eine Block-Aktion
                       passend zum value_type, plus "no_action")

ENTSCHEIDUNGSREGELN (erste passende greift). Ist ein Indikator/eine Schwelle
erreicht ⇒ Block, sonst no_action. Gib KEINE confidence aus.
1. OSINT Sophos-Intelix-Treffer (security_category gesetzt ODER
   intelix.score >= 70 ODER intelix.category ∈ {Malicious, Phishing, Spam,
   High Risk, Bad})                                  → Block.
2. SHODAN-CVE-SCHWERE (nur bei value_type="ip"): shodan.cve_severity.has_high_critical
   = true (CVE mit CVSS High/Critical >= 7.0) ODER kev > 0 → Block.
   Nur mittlere/niedrige CVEs sind KEIN Block-Grund. Nenne die schwerste CVE+CVSS.
3. OSINT-Treffer anderer Provider (abuseipdb.abuse_score >= 75 ODER
   virustotal.malicious >= 2 ODER greynoise.classification = "malicious")
                                                      → Block.
4. Eindeutiger Hinweis des Operators in `note`, der bösartiges Verhalten
   belegt                                             → Block.
5. Sonst (keine belastbaren Indikatoren)              → no_action.

Die Block-Aktion ist genau die in allowed_actions enthaltene
(block_ip / block_domain / block_url). Bei privaten/reservierten IPs niemals
block_ip empfehlen.

AUSGABE (strikt JSON, kein ```-Fence, kein zusätzlicher Text). BEISPIEL:
{
  "action": "block_ip",
  "args": {},
  "reasoning": "Shodan meldet 5 CVEs (u.a. CVE-2021-44228, CVE-2019-0708) — exponiertes, verwundbares System. Block empfohlen."
}
"""


DEFAULT_TRIAGE_PROMPT_EN = """You are a threat-intelligence triage analyst for Warroom.
An operator has submitted an indicator (IP, domain or URL) for assessment.

INPUT (JSON):
  - value           — the value to check
  - value_type      — "ip" | "domain" | "url"
  - note            — optional hint from the operator (context, may be missing)
  - osint           — OSINT lookup (for IP: abuseipdb, virustotal, shodan,
                       greynoise, intelix, ipinfo; for domain/url: intelix,
                       virustotal, possibly dns). Fields may be missing.
  - allowed_actions — permitted values for `action` (exactly one block action
                       matching the value_type, plus "no_action")

DECISION RULES (first match wins). If an indicator/threshold is
reached ⇒ Block, otherwise no_action. Do not output any confidence.
1. OSINT Sophos Intelix hit (security_category set OR
   intelix.score >= 70 OR intelix.category ∈ {Malicious, Phishing, Spam,
   High Risk, Bad})                                  → Block.
2. SHODAN CVE SEVERITY (only for value_type="ip"): shodan.cve_severity.has_high_critical
   = true (CVE with CVSS High/Critical >= 7.0) OR kev > 0 → Block.
   Medium/low CVEs only are NOT a block reason. Name the worst CVE + CVSS.
3. OSINT hit from other providers (abuseipdb.abuse_score >= 75 OR
   virustotal.malicious >= 2 OR greynoise.classification = "malicious")
                                                      → Block.
4. Clear hint from the operator in `note` that proves malicious
   behaviour                                          → Block.
5. Otherwise (no solid indicators)                    → no_action.

The block action is exactly the one contained in allowed_actions
(block_ip / block_domain / block_url). For private/reserved IPs never
recommend block_ip.

OUTPUT (strict JSON, no ```-fence, no additional text). EXAMPLE:
{
  "action": "block_ip",
  "args": {},
  "reasoning": "Shodan reports 5 CVEs (incl. CVE-2021-44228, CVE-2019-0708) — exposed, vulnerable system. Block recommended."
}
"""


DEFAULT_USER_LOGIN_PROMPT = """Du bist ein SOC-Analyst für Warroom und bewertet
fehlgeschlagene Login-Versuche, die auf EINEN Benutzernamen gerichtet sind.

INPUT (JSON):
  - username                 — der betroffene Benutzer
  - window_minutes           — Zeitfenster der Auswertung
  - total_failed_attempts    — Summe der fehlgeschlagenen Logins auf diesen User
  - distinct_ips             — Anzahl unterschiedlicher Quell-IPs
  - distributed_hint_min_ips — ab so vielen unterschiedlichen IPs gilt es als verteilt
  - ip_breakdown             — Liste {ip, failed_attempts, country} (je IP die Anzahl
                               fehlgeschlagener Versuche auf diesen User)
  - countries                — beobachtete Herkunftsländer
  - allowed_actions          — ["notify", "no_action"]

ENTSCHEIDUNGSREGELN (erste passende greift). Ist ein Muster/eine Schwelle
erreicht ⇒ action="notify", sonst action="no_action". Gib KEINE confidence aus.
1. DISTRIBUTED BRUTEFORCE: viele unterschiedliche Quell-IPs (distinct_ips >=
   distributed_hint_min_ips), die denselben User attackieren — typischerweise je
   IP wenige Versuche, in Summe aber viele. → action="notify",
   args={"classification":"distributed_bruteforce", ...}.
2. BRUTEFORCE: eine oder sehr wenige IPs mit vielen Fehlversuchen auf den User
   (klares Hochfrequenz-Muster). → action="notify",
   args={"classification":"bruteforce", ...}.
3. Sonst (vereinzelte Fehlversuche, kein Muster, plausibel Tippfehler/abgelaufenes
   Passwort) → action="no_action".

Beziehe die Zahlen ein: total_failed_attempts, distinct_ips und die Verteilung in
ip_breakdown. Ein einzelner Fehlversuch von einer IP ist KEINE Bruteforce.

AUSGABE (strikt JSON, kein ```-Fence, kein zusätzlicher Text). BEISPIEL:
{
  "action": "notify",
  "args": {"classification": "distributed_bruteforce",
           "endangered_user": "administrator",
           "distinct_ips": 23, "total_attempts": 145},
  "reasoning": "145 Fehlversuche auf 'administrator' von 23 unterschiedlichen IPs — klares verteiltes Brute-Force-Muster (je IP nur wenige Versuche)."
}
"""


DEFAULT_USER_LOGIN_PROMPT_EN = """You are a SOC analyst for Warroom and assess
failed login attempts that are directed at ONE username.

INPUT (JSON):
  - username                 — the affected user
  - window_minutes           — evaluation time window
  - total_failed_attempts    — sum of failed logins against this user
  - distinct_ips             — number of distinct source IPs
  - distributed_hint_min_ips — from this many distinct IPs on it counts as distributed
  - ip_breakdown             — list {ip, failed_attempts, country} (per IP the number
                               of failed attempts against this user)
  - countries                — observed origin countries
  - allowed_actions          — ["notify", "no_action"]

DECISION RULES (first match wins). If a pattern/threshold is
reached ⇒ action="notify", otherwise action="no_action". Do not output any confidence.
1. DISTRIBUTED BRUTEFORCE: many distinct source IPs (distinct_ips >=
   distributed_hint_min_ips) attacking the same user — typically few attempts
   per IP, but many in total. → action="notify",
   args={"classification":"distributed_bruteforce", ...}.
2. BRUTEFORCE: one or very few IPs with many failed attempts against the user
   (clear high-frequency pattern). → action="notify",
   args={"classification":"bruteforce", ...}.
3. Otherwise (isolated failures, no pattern, plausibly typo/expired
   password) → action="no_action".

Take the numbers into account: total_failed_attempts, distinct_ips and the distribution in
ip_breakdown. A single failed attempt from one IP is NOT a bruteforce.

OUTPUT (strict JSON, no ```-fence, no additional text). EXAMPLE:
{
  "action": "notify",
  "args": {"classification": "distributed_bruteforce",
           "endangered_user": "administrator",
           "distinct_ips": 23, "total_attempts": 145},
  "reasoning": "145 failed attempts against 'administrator' from 23 distinct IPs — clear distributed brute-force pattern (only a few attempts per IP)."
}
"""


DEFAULT_EVENT_PROMPT = """Du bist ein Endpoint-Security-Analyst für Warroom.
Du bewertest EIN einzelnes Sophos-Central-Event (Endpoint-Threat / Exploit /
Command-and-Control / verdächtige Anwendung).

INPUT (JSON):
  - source_ip       — Quell-IP des Events (kann fehlen / privat sein)
  - context         — Event-Details: event_type, name, severity, endpoint
                       (Gerätename), source_ip, destination_ip (externe/C2-IP,
                       falls vorhanden), group, time
  - osint           — OSINT-Lookup der relevanten öffentlichen IP (abuseipdb,
                       virustotal, shodan, greynoise, intelix, ipinfo). Felder
                       können fehlen.
  - allowed_actions — "block_ip", "isolate", "acknowledge", "no_action"

ENTSCHEIDUNGSREGELN (erste passende greift). Gib KEINE confidence aus.
1. C2 / aktiver Threat mit bekannter externer IP (destination_ip ODER source_ip
   öffentlich) und bösartigem Befund — Event-Typ enthält "CommandAndControl"
   oder "Threat::Detected", ODER OSINT belegt Bösartigkeit (intelix-Treffer,
   abuseipdb.abuse_score >= 75, virustotal.malicious >= 2,
   greynoise.classification = "malicious", ODER shodan.cve_severity.has_high_critical (High/Critical-CVE oder KEV))
                                                    → block_ip (target_ip = die
       bösartige externe IP). Nenne im reasoning die ausschlaggebenden Signale.
2. Aktiver Endpoint-Befund OHNE blockbare externe IP, aber mit klarem Gerätebezug
   (Threat::Detected / CleanupFailed / HmpaExploitPrevented auf einem Endpoint)
                                                    → isolate. Der Endpoint muss
       isoliert und untersucht werden (Ausführung erfolgt manuell über Endpoints).
3. Eindeutig harmlos / bereits bereinigt / reines Informations-Event
                                                    → acknowledge.
4. Sonst (unklar, mehr Daten nötig)                 → no_action.

AUSGABE (strikt JSON, kein ```-Fence, kein zusätzlicher Text). BEISPIEL:
{
  "action": "block_ip",
  "args": {"target_ip": "203.0.113.45"},
  "reasoning": "C2-Detection (CommandAndControlDetected) auf Endpoint PC-07 zu 203.0.113.45; AbuseIPDB 95%, Intelix 'Malicious'. Externe C2-IP blocken."
}
"""


DEFAULT_EVENT_PROMPT_EN = """You are an endpoint security analyst for Warroom.
You assess ONE single Sophos Central event (endpoint threat / exploit /
command-and-control / suspicious application).

INPUT (JSON):
  - source_ip       — source IP of the event (may be missing / private)
  - context         — event details: event_type, name, severity, endpoint
                       (device name), source_ip, destination_ip (external/C2 IP,
                       if present), group, time
  - osint           — OSINT lookup of the relevant public IP (abuseipdb,
                       virustotal, shodan, greynoise, intelix, ipinfo). Fields
                       may be missing.
  - allowed_actions — "block_ip", "isolate", "acknowledge", "no_action"

DECISION RULES (first match wins). Do not output any confidence.
1. C2 / active threat with a known external IP (destination_ip OR source_ip
   public) and a malicious finding — event type contains "CommandAndControl"
   or "Threat::Detected", OR OSINT proves maliciousness (intelix hit,
   abuseipdb.abuse_score >= 75, virustotal.malicious >= 2,
   greynoise.classification = "malicious", OR shodan.cve_severity.has_high_critical (High/Critical CVE or KEV))
                                                    → block_ip (target_ip = the
       malicious external IP). Name in the reasoning the decisive signals.
2. Active endpoint finding WITHOUT a blockable external IP, but with a clear
   device reference (Threat::Detected / CleanupFailed / HmpaExploitPrevented on an endpoint)
                                                    → isolate. The endpoint must
       be isolated and investigated (execution is performed manually via Endpoints).
3. Clearly harmless / already cleaned up / pure informational event
                                                    → acknowledge.
4. Otherwise (unclear, more data needed)            → no_action.

OUTPUT (strict JSON, no ```-fence, no additional text). EXAMPLE:
{
  "action": "block_ip",
  "args": {"target_ip": "203.0.113.45"},
  "reasoning": "C2 detection (CommandAndControlDetected) on endpoint PC-07 to 203.0.113.45; AbuseIPDB 95%, Intelix 'Malicious'. Block the external C2 IP."
}
"""


DEFAULT_ANOMALY_PROMPT = """Du bist ein Netzwerk-Anomalie-Analyst für Warroom.

INPUT (JSON, vom System gestellt):
  - source_ip       — auffällige öffentliche IP aus der NetFlow-Anomalie-Analyse
                      (Isolation Forest über Volumen / Ziel-Ports / Nachtaktivität).
  - context         — Anomalie-Merkmale: anomaly_score (0–1), drivers (treibende
                      Dimensionen), bytes, flows, distinct_dst_ports,
                      distinct_dst_ips, night_ratio, country, window_hours.
  - osint           — OSINT-Lookup (abuseipdb, virustotal, shodan, greynoise,
                      intelix, ipinfo). Felder können fehlen, wenn ein Provider
                      keinen Key hat.
  - allowed_actions — erlaubte Werte für `action`

ENTSCHEIDUNGSREGELN (in Reihenfolge prüfen, erste passende greift):
1. OSINT Sophos-Intelix-Treffer (security_category gesetzt ODER intelix.score >= 70
   ODER intelix.category ∈ {Malicious, High Risk, Bad, botnet})   → block_ip.
2. abuseipdb.abuse_score >= 75 ODER virustotal.malicious >= 2
   ODER greynoise.classification = "malicious"                    → block_ip.
3. SHODAN-CVE-SCHWERE: shodan.cve_severity.has_high_critical=true
   (CVE mit CVSS High/Critical >= 7.0) ODER kev > 0               → block_ip.
   Nur mittlere/niedrige CVEs sind KEIN Block-Grund.
4. Sonst                                                          → no_action.

Die Anomalie selbst (hoher Score) ist KEIN Block-Grund — nur OSINT-Belege zählen.
Gib KEINE confidence aus.

REASONING-PFLICHT — nenne im reasoning immer:
  a) die konkreten Schädlichkeits-Indikatoren (Provider + Werte); bei no_action,
     warum die IP unauffällig ist (z. B. bekannter Cloud-/CDN-/Update-Dienst),
  b) den FQDN bzw. die Domain der IP, falls OSINT welche liefert
     (abuseipdb.domain, abuseipdb.hostnames, shodan.hostnames, ipinfo.hostname).

AUSGABE (strikt JSON, kein ```-Fence, kein zusätzlicher Text). BEISPIEL:
{
  "action": "block_ip",
  "args": {"target_ip": "203.0.113.45"},
  "reasoning": "AbuseIPDB-Score 92, VirusTotal 5x malicious. FQDN: scanner.evil-host.net. Portscan-Verhalten (drivers: ports, 480 Ziel-Ports)."
}
"""


DEFAULT_ANOMALY_PROMPT_EN = """You are a network anomaly analyst for Warroom.

INPUT (JSON, provided by the system):
  - source_ip       — conspicuous public IP from the NetFlow anomaly analysis
                      (Isolation Forest over volume / destination ports / night activity).
  - context         — anomaly features: anomaly_score (0–1), drivers (driving
                      dimensions), bytes, flows, distinct_dst_ports,
                      distinct_dst_ips, night_ratio, country, window_hours.
  - osint           — OSINT lookup (abuseipdb, virustotal, shodan, greynoise,
                      intelix, ipinfo). Fields may be missing if a provider
                      has no key.
  - allowed_actions — permitted values for `action`

DECISION RULES (check in order, first match wins):
1. OSINT Sophos Intelix hit (security_category set OR intelix.score >= 70
   OR intelix.category ∈ {Malicious, High Risk, Bad, botnet})     → block_ip.
2. abuseipdb.abuse_score >= 75 OR virustotal.malicious >= 2
   OR greynoise.classification = "malicious"                      → block_ip.
3. SHODAN CVE SEVERITY: shodan.cve_severity.has_high_critical=true
   (CVE with CVSS High/Critical >= 7.0) OR kev > 0                → block_ip.
   Medium/low CVEs only are NOT a block reason.
4. Otherwise                                                      → no_action.

The anomaly itself (high score) is NOT a reason to block — only OSINT evidence
counts. Do not output any confidence.

REASONING REQUIREMENTS — always name in the reasoning:
  a) the concrete maliciousness indicators (provider + values); for no_action,
     why the IP is unremarkable (e.g. a known cloud/CDN/update service),
  b) the FQDN or domain of the IP if OSINT provides one
     (abuseipdb.domain, abuseipdb.hostnames, shodan.hostnames, ipinfo.hostname).

OUTPUT (strict JSON, no ```-fence, no additional text). EXAMPLE:
{
  "action": "block_ip",
  "args": {"target_ip": "203.0.113.45"},
  "reasoning": "AbuseIPDB score 92, VirusTotal 5x malicious. FQDN: scanner.evil-host.net. Port-scan behaviour (drivers: ports, 480 destination ports)."
}
"""


# Mapping source_type → (setting_attr, default_prompt) für den Lookup.
# _RULE_PROMPTS is the German map; _RULE_PROMPTS_EN holds the English twin
# defaults. _prompt_for() picks the right-language default per _agent_lang(),
# unless an admin override is configured (which always wins).
_RULE_PROMPTS = {
    "waf":          ("agent_waf_system_prompt", DEFAULT_WAF_PROMPT),
    "ips":          ("agent_ips_system_prompt", DEFAULT_IPS_PROMPT),
    "event":        ("agent_event_system_prompt", DEFAULT_EVENT_PROMPT),
    "failed_login": ("agent_failed_login_system_prompt", DEFAULT_FAILED_LOGIN_PROMPT),
    "failed_login_distributed": ("agent_failed_login_distributed_system_prompt", DEFAULT_DISTRIBUTED_LOGIN_PROMPT),
    "failed_login_user": ("agent_failed_login_user_system_prompt", DEFAULT_USER_LOGIN_PROMPT),
    "triage":       ("agent_triage_system_prompt", DEFAULT_TRIAGE_PROMPT),
    "anomaly":      ("agent_anomaly_system_prompt", DEFAULT_ANOMALY_PROMPT),
}

_RULE_PROMPTS_EN = {
    "waf":          DEFAULT_WAF_PROMPT_EN,
    "ips":          DEFAULT_IPS_PROMPT_EN,
    "event":        DEFAULT_EVENT_PROMPT_EN,
    "failed_login": DEFAULT_FAILED_LOGIN_PROMPT_EN,
    "failed_login_distributed": DEFAULT_DISTRIBUTED_LOGIN_PROMPT_EN,
    "failed_login_user": DEFAULT_USER_LOGIN_PROMPT_EN,
    "triage":       DEFAULT_TRIAGE_PROMPT_EN,
    "anomaly":      DEFAULT_ANOMALY_PROMPT_EN,
}


def _agent_lang() -> str:
    """Resolve the configured agent prompt language ("de" or "en", default en)."""
    return "de" if getattr(settings, "agent_language", "en") == "de" else "en"


def _prompt_for(source_type: str) -> str:
    """Admin override (if set) always wins; otherwise the EN/DE default per
    the configured agent_language."""
    attr, default = _RULE_PROMPTS[source_type]
    override = (getattr(settings, attr, "") or "").strip()
    if override:
        return override
    if _agent_lang() == "en":
        return _RULE_PROMPTS_EN[source_type]
    return default


def default_prompt(source_type: str, lang: str | None = None) -> str | None:
    """The bundled (non-override) default prompt for a source in the requested
    language ("de"/"en"); falls back to the configured agent_language. Returns
    None for an unknown source. Used by the admin 'load default' endpoint."""
    lang = lang if lang in ("de", "en") else _agent_lang()
    if source_type == "alert":
        return DEFAULT_SYSTEM_PROMPT_EN if lang == "en" else DEFAULT_SYSTEM_PROMPT
    if source_type not in _RULE_PROMPTS:
        return None
    return _RULE_PROMPTS_EN[source_type] if lang == "en" else _RULE_PROMPTS[source_type][1]


def _allowed_actions_for_source(source_type: str) -> list[str]:
    # Central events relate to endpoints/threats, so they may additionally
    # isolate the endpoint or acknowledge the event (block stays IP-based).
    if source_type == "event":
        return ["block_ip", "isolate", "acknowledge", "no_action"]
    # Per-entity LLM paths (WAF/IPS/per-IP failed-login) only ever block or skip
    # a single IP. Subnet-/bulk-blocks come from the distributed sweep, which
    # validates its own action set inline.
    return ["block_ip", "no_action"]


def _osint_summary(osint: dict[str, Any]) -> dict[str, Any]:
    """Compact summary of the relevant OSINT signals — stored in the
    decision audit trail so the UI can show why the LLM decided what it did
    without storing the full provider payloads."""
    if not isinstance(osint, dict):
        return {}
    sev = (osint.get("shodan") or {}).get("cve_severity") or {}
    return {
        "cached": osint.get("cached"),
        "abuseipdb_score": (osint.get("abuseipdb") or {}).get("abuse_score"),
        "virustotal_malicious": (osint.get("virustotal") or {}).get("malicious"),
        "intelix_security_category": (osint.get("intelix") or {}).get("security_category"),
        "intelix_category": (osint.get("intelix") or {}).get("category"),
        "intelix_score": (osint.get("intelix") or {}).get("score"),
        "greynoise_classification": (osint.get("greynoise") or {}).get("classification"),
        "cve_high_critical": sev.get("high_critical"),
        "cve_kev": sev.get("kev"),
        "cve_max_cvss": sev.get("max_cvss"),
    }


def _is_public_ip(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_multicast or addr.is_reserved or addr.is_unspecified)


def _build_user_prompt(alert: Alert, already_blocked: bool, whitelisted: bool, whitelist_sample: list[str]) -> str:
    """One alert + relevant context in a compact, model-friendly block."""
    fields = {
        "id": alert.id,
        "type": alert.alert_type,
        "severity": alert.severity,
        "category": alert.category,
        "description": (alert.description or "")[:1000],
        "source_ip": alert.source_ip,
        "destination_ip": alert.destination_ip,
        "country": alert.attacker_country,
        "city": alert.attacker_city,
        "agent": alert.managed_agent_name,
        "created_at": alert.created_at.isoformat() if alert.created_at else None,
        "source_ip_is_public": _is_public_ip(alert.source_ip),
        "source_ip_already_blocked": already_blocked,
        "source_ip_is_whitelisted": whitelisted,
        "whitelisted_sample": whitelist_sample[:10],
    }
    return "Neuer Alarm:\n" + json.dumps(fields, indent=2, ensure_ascii=False, default=str)


async def _call_llm(
    prompt: str,
    system_prompt: str | None = None,
    source: str = "alert",
    allowed_actions: list[str] | None = None,
) -> dict[str, Any]:
    """Send a /chat/completions request and return a Pydantic-validated decision.

    Uses OpenAI-style **structured outputs** (``response_format`` with a JSON
    schema derived from ``LLMDecision`` and the stage's ``allowed_actions``) so
    the model returns clean, schema-constrained JSON. Servers that reject
    ``response_format`` (400/422) transparently fall back to a plain request +
    tolerant parsing. Every call is recorded into ``llm_metrics``; recorder
    failures are swallowed so telemetry never breaks the pipeline.
    """
    import time
    from app import llm_metrics

    base = (settings.agent_base_url or "").rstrip("/")
    if not base:
        raise RuntimeError("agent_base_url not configured")
    url = f"{base}/chat/completions"
    headers = {"Content-Type": "application/json"}
    if settings.agent_api_key:
        headers["Authorization"] = f"Bearer {settings.agent_api_key}"
    # Caller may pass a per-source system prompt; default to the alert prompt.
    # Admin override (agent_system_prompt) wins, else the EN/DE default per language.
    if system_prompt is None:
        system_prompt = (settings.agent_system_prompt or "").strip()
        if not system_prompt:
            system_prompt = (
                DEFAULT_SYSTEM_PROMPT_EN if _agent_lang() == "en"
                else DEFAULT_SYSTEM_PROMPT
            )
    model_name = settings.agent_model or "local-model"
    allowed = list(allowed_actions) if allowed_actions else sorted(ALLOWED_ACTIONS)
    payload: dict[str, Any] = {
        "model": model_name,
        # Admin-configurable sampling controls (fall back to sane defaults).
        "temperature": float(getattr(settings, "agent_temperature", 0.2) or 0.0),
        "max_tokens": int(getattr(settings, "agent_max_tokens", 3000) or 3000),
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
    }
    use_structured = bool(getattr(settings, "agent_structured_output", True))
    started = time.monotonic()
    prompt_tokens = completion_tokens = 0
    try:
        async with httpx.AsyncClient(timeout=60) as client:
            send = dict(payload)
            if use_structured:
                send["response_format"] = _decision_response_format(allowed)
            r = await client.post(url, headers=headers, json=send)
            # Some servers/models don't support response_format → retry plain.
            if use_structured and r.status_code in (400, 422):
                logger.info(
                    "agent: server rejected response_format "
                    f"(HTTP {r.status_code}); retrying without structured output"
                )
                r = await client.post(url, headers=headers, json=payload)
        if r.status_code != 200:
            raise RuntimeError(f"LLM HTTP {r.status_code}: {r.text[:200]}")
        data = r.json()
        usage = data.get("usage") or {}
        prompt_tokens = int(usage.get("prompt_tokens") or 0)
        completion_tokens = int(usage.get("completion_tokens") or 0)
        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as e:
            raise RuntimeError(f"Unexpected response shape: {e}") from e
        decision = _validate_decision(content)
    except Exception:
        duration_ms = int((time.monotonic() - started) * 1000)
        try:
            await llm_metrics.record(
                source=source, status="error", model=model_name,
                duration_ms=duration_ms,
                prompt_tokens=prompt_tokens, completion_tokens=completion_tokens,
            )
        except Exception:
            pass
        raise

    duration_ms = int((time.monotonic() - started) * 1000)
    try:
        await llm_metrics.record(
            source=source, status="success", model=model_name,
            duration_ms=duration_ms,
            prompt_tokens=prompt_tokens, completion_tokens=completion_tokens,
        )
    except Exception:
        pass
    return decision


def _extract_json_objects(text: str) -> list[dict[str, Any]]:
    """Find every top-level balanced ``{…}`` block in ``text`` and parse it.
    Returns the successfully-parsed dicts in source order. Used to handle
    reasoning models that emit draft + final JSON, or JSON-shaped fragments
    inside their think-trace.
    """
    results: list[dict[str, Any]] = []
    i = 0
    n = len(text)
    while i < n:
        if text[i] != "{":
            i += 1
            continue
        depth = 0
        in_string = False
        escape = False
        end = -1
        for j in range(i, n):
            ch = text[j]
            if in_string:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == '"':
                    in_string = False
                continue
            if ch == '"':
                in_string = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = j
                    break
        if end < 0:
            break
        try:
            obj = json.loads(text[i : end + 1])
            if isinstance(obj, dict):
                results.append(obj)
        except json.JSONDecodeError:
            pass
        i = end + 1
    return results


def _parse_decision(content: str) -> dict[str, Any]:
    """Extract the decision JSON from the LLM's reply.

    Tolerant against (a) ```-fences, (b) reasoning-model preambles like
    ``<think>…</think>`` or prose thinking, (c) trailing text, and
    (d) multiple ``{…}`` blocks (a "draft" inside the thinking + the final
    answer): we collect every balanced block, then pick the LAST one whose
    ``action`` is one of the allowed values. If none qualifies, fall back to
    the very last block so the existing validation produces a useful error.
    """
    import re

    text = (content or "").strip()
    # Strip Qwen-style hidden reasoning blocks
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
    # Strip surrounding ```/```json fence
    if text.startswith("```"):
        text = text.split("\n", 1)[-1]
        if text.endswith("```"):
            text = text[: text.rfind("```")].rstrip()

    obj: dict[str, Any] | None = None
    # Fast path: whole string is JSON
    try:
        candidate = json.loads(text)
        if isinstance(candidate, dict):
            obj = candidate
    except json.JSONDecodeError:
        pass

    if obj is None or (obj.get("action") or "").strip() not in ALLOWED_ACTIONS:
        blocks = _extract_json_objects(text)
        if not blocks:
            raise RuntimeError(f"LLM did not return JSON; raw={content[:300]!r}")
        # Prefer the last block with a valid action; otherwise last block at all
        for cand in reversed(blocks):
            act = (cand.get("action") or "").strip()
            if act in ALLOWED_ACTIONS:
                obj = cand
                break
        else:
            obj = blocks[-1]

    action = (obj.get("action") or "").strip()
    if action not in ALLOWED_ACTIONS:
        raise RuntimeError(f"Invalid action {action!r}; must be one of {ALLOWED_ACTIONS}")
    args = obj.get("args") or {}
    if not isinstance(args, dict):
        args = {}
    reasoning = str(obj.get("reasoning") or "")[:2000]
    return {"action": action, "args": args, "reasoning": reasoning}


async def analyze_alert(alert: Alert) -> dict[str, Any] | None:
    """Run the LLM on a single alert. Returns the parsed decision dict (not yet
    persisted) or None on failure."""
    async with async_session() as db:
        blocked = (
            (await db.execute(
                select(BlockedIp.ip).where(BlockedIp.ip == (alert.source_ip or ""))
            )).first()
            is not None
        )
        whitelisted = (
            (await db.execute(
                select(WhitelistedIp.ip).where(WhitelistedIp.ip == (alert.source_ip or ""))
            )).first()
            is not None
        )
        wl_sample = (await db.execute(
            select(WhitelistedIp.ip).order_by(WhitelistedIp.ip).limit(20)
        )).scalars().all()
    prompt = _build_user_prompt(alert, already_blocked=blocked, whitelisted=whitelisted, whitelist_sample=list(wl_sample))
    try:
        return await _call_llm(
            prompt, source="alert",
            allowed_actions=["block_ip", "acknowledge", "isolate", "no_action"],
        )
    except Exception as e:
        logger.warning(f"agent: analyze_alert({alert.id}) failed: {e}")
        return None


async def agent_loop() -> None:
    """One pass: pick recent alerts that don't have a decision yet, call the
    LLM, persist the decision. Optionally auto-execute safe actions."""
    if not settings.agent_enabled:
        return
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    async with async_session() as db:
        # Alerts that are < 24h old and don't yet have any agent_decision row
        sub = select(AgentDecision.alert_id)
        candidates = (
            await db.execute(
                select(Alert)
                .where(Alert.created_at >= cutoff, Alert.id.notin_(sub))
                .order_by(Alert.created_at.desc())
                .limit(10)
            )
        ).scalars().all()

    if not candidates:
        return

    logger.info(f"agent: analyzing {len(candidates)} new alert(s)")
    for alert in candidates:
        decision = await analyze_alert(alert)
        if decision is None:
            continue
        await _persist_decision(alert, decision)


def _event_types() -> list[str]:
    """Configured Sophos event_type filter (CSV) → list, empties stripped."""
    raw = settings.agent_event_types or ""
    return [t.strip() for t in raw.split(",") if t.strip()]


async def agent_event_loop(force: bool = False) -> None:
    """Feed fresh, security-relevant Sophos Central *events* (the event stream,
    separate from alerts) to the LLM. Events of the configured types that don't
    yet have an agent decision are handed to ``_llm_decide_rule`` — the decision
    logic lives in ``agent_event_system_prompt`` (admin-editable).

    ``force=True`` runs even when otherwise disabled (manual trigger)."""
    if (not settings.agent_enabled or not settings.agent_event_enabled) and not force:
        return
    types = _event_types()
    if not types:
        return

    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    async with async_session() as db:
        # Events of the configured types, < 24h old, without an existing
        # event-decision (dedup via the event_id we stash in the decision context).
        rows = (await db.execute(text("""
            SELECT e.id, e.event_type, e.severity, e.name, e.source_ip,
                   e.destination_ip, e.group_name, e.created_at,
                   e.raw_data->'endpoint'->>'name'      AS endpoint_name,
                   COALESCE(e.raw_data->>'managedAgentName',
                            e.raw_data->'managedAgent'->>'name') AS managed_agent
            FROM events e
            WHERE e.created_at >= :cutoff
              AND e.event_type = ANY(:types)
              AND NOT EXISTS (
                    SELECT 1 FROM agent_decisions d
                    WHERE d.source_type = 'event'
                      AND d.action_args->'context'->>'event_id' = e.id
              )
            ORDER BY e.created_at DESC
            LIMIT 20
        """), {"cutoff": cutoff, "types": types})).fetchall()

    if not rows:
        return

    logger.info(f"agent[event]: analyzing {len(rows)} new event(s)")
    for r in rows:
        ev_id, ev_type, severity, name, src_ip, dst_ip, group, created, endpoint_name, managed_agent = r
        # Prefer a public IP as the OSINT/block target — for C2/threat events the
        # malicious party is usually the external destination, not the endpoint.
        candidate_ip = next(
            (ip for ip in (dst_ip, src_ip) if ip and _is_public_ip(ip)), None
        )
        context = {
            "event_id": ev_id,
            "event_type": ev_type,
            "name": name,
            "severity": severity,
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "endpoint": endpoint_name or managed_agent,
            "group": group,
            "time": created.isoformat() if created else None,
        }
        await _llm_decide_rule(source_type="event", ip=candidate_ip, context=context)


async def _notify_telegram_pending(decision_id: int) -> None:
    """Push an interactive approval prompt for a freshly-stored pending
    decision. Best-effort — never blocks the agent if Telegram is down.
    The push is also retried by the telegram_push_pending scheduler job."""
    try:
        from app.telegram_client import send_decision_request
        from app.models import AgentDecision as _AD
        async with async_session() as db:
            rec = await db.get(_AD, decision_id)
            if rec is None or rec.status != "pending" or rec.telegram_message_id is not None:
                return
            mid = await send_decision_request(rec)
            if mid is not None:
                rec.telegram_message_id = mid
                await db.commit()
    except Exception as e:
        logger.debug(f"telegram approval push skipped: {e}")


async def _persist_decision(alert: Alert, decision: dict[str, Any]) -> None:
    """Store the LLM's recommendation. Auto-executes safe actions if enabled."""
    record = AgentDecision(
        alert_id=alert.id,
        action=decision["action"],
        action_args=decision.get("args") or {},
        reasoning=decision.get("reasoning") or "",
        status="pending",
        model=settings.agent_model or "local-model",
    )
    async with async_session() as db:
        db.add(record)
        await db.commit()
        await db.refresh(record)

    # Learned auto-approval takes precedence: if the human has approved this
    # decision's pattern enough times, execute it without asking.
    if await _maybe_learned_auto_approve(record):
        return

    should, why = _should_auto_execute(decision["action"])
    if should:
        logger.info(f"agent: auto-executing decision {record.id} ({why})")
        try:
            await execute_decision(record.id)
        except Exception as e:
            logger.warning(f"agent: auto-execute failed for decision {record.id}: {e}")
    else:
        await _notify_telegram_pending(record.id)


async def execute_decision(decision_id: int) -> dict[str, Any]:
    """Execute the persisted recommendation. Idempotent — already-executed
    decisions return their stored state without re-running."""
    async with async_session() as db:
        rec: AgentDecision | None = await db.get(AgentDecision, decision_id)
        if rec is None:
            raise ValueError(f"decision {decision_id} not found")
        if rec.status == "executed":
            return {"already": True, "status": rec.status}

        result: dict[str, Any] = {}
        try:
            if rec.action == "block_ip":
                ip = (rec.action_args or {}).get("target_ip")
                if not ip:
                    if rec.source_type == "waf":
                        ip = rec.source_ip
                    elif rec.alert_id:
                        a = await db.get(Alert, rec.alert_id)
                        ip = a.source_ip if a else None
                if not ip or not _is_public_ip(ip):
                    raise ValueError("no usable public IP for block_ip")
                # Hard guard: whitelisted IPs (our own firewalls) can never be blocked
                wl = await db.execute(select(WhitelistedIp.ip).where(WhitelistedIp.ip == ip))
                if wl.first() is not None:
                    raise ValueError(f"IP {ip} is whitelisted — block refused")
                existing = await db.execute(select(BlockedIp).where(BlockedIp.ip == ip))
                if existing.scalar_one_or_none() is None:
                    src_label = _source_label(rec.source_type)
                    db.add(BlockedIp(
                        ip=ip,
                        comment=f"agent[{src_label}]: {rec.reasoning[:200]}",
                        blocked_at=datetime.now(timezone.utc),
                        blocked_by=rec.decided_by or "agent",
                        source=rec.source_type or "agent",
                    ))
                result = {"ip": ip, "source": rec.source_type}

            elif rec.action == "block_subnet":
                cidr = (rec.action_args or {}).get("target_subnet")
                if not cidr:
                    raise ValueError("no target_subnet for block_subnet")
                try:
                    network = ipaddress.ip_network(cidr, strict=False)
                except ValueError as e:
                    raise ValueError(f"invalid CIDR {cidr!r}: {e}")
                # Defence-in-depth: never enumerate-and-block a private/reserved
                # range (matches the per-IP public check on block_ip/block_ips).
                if not network.is_global:
                    raise ValueError(f"subnet {cidr} is not a public/global network — block refused")
                if network.num_addresses > MAX_SUBNET_HOSTS:
                    raise ValueError(
                        f"subnet {cidr} too large "
                        f"({network.num_addresses} addresses, max {MAX_SUBNET_HOSTS})"
                    )
                hosts_to_block = [str(addr) for addr in network.hosts()]
                if not hosts_to_block:
                    raise ValueError(f"subnet {cidr} has no usable hosts")
                # Pre-fetch whitelist and existing blocked IPs in two queries
                wl = set((await db.execute(
                    select(WhitelistedIp.ip).where(WhitelistedIp.ip.in_(hosts_to_block))
                )).scalars().all())
                existing = set((await db.execute(
                    select(BlockedIp.ip).where(BlockedIp.ip.in_(hosts_to_block))
                )).scalars().all())
                now_ts = datetime.now(timezone.utc)
                src_label = _source_label(rec.source_type)
                comment = f"agent[{src_label}] subnet-block {cidr}: {(rec.reasoning or '')[:160]}"
                added: list[str] = []
                skipped_wl: list[str] = []
                for ip in hosts_to_block:
                    if ip in wl:
                        skipped_wl.append(ip)
                        continue
                    if ip in existing:
                        continue
                    db.add(BlockedIp(ip=ip, comment=comment, blocked_at=now_ts,
                                     blocked_by=rec.decided_by or "agent",
                                     source=rec.source_type or "agent"))
                    added.append(ip)
                if skipped_wl:
                    logger.warning(
                        f"agent: subnet-block {cidr} skipped {len(skipped_wl)} "
                        f"whitelisted IP(s): {skipped_wl[:5]}{'…' if len(skipped_wl) > 5 else ''}"
                    )
                logger.info(
                    f"agent: subnet-block {cidr}: +{len(added)} new, "
                    f"{len(existing)} already blocked, {len(skipped_wl)} whitelisted"
                )
                result = {
                    "subnet": cidr,
                    "added": len(added),
                    "already_blocked": len(existing),
                    "skipped_whitelist": len(skipped_wl),
                    "total_hosts": len(hosts_to_block),
                }

            elif rec.action == "block_ips":
                # Bulk block of a distributed brute-force's source IPs. Each is
                # re-validated (public, not whitelisted, not already blocked).
                raw_ips = (rec.action_args or {}).get("target_ips") or []
                if not isinstance(raw_ips, list) or not raw_ips:
                    raise ValueError("no target_ips for block_ips")
                # Dedupe + keep only public IPs, capped at the bulk limit.
                seen: set[str] = set()
                candidates: list[str] = []
                for raw in raw_ips:
                    ip = str(raw or "").strip()
                    if ip and ip not in seen and _is_public_ip(ip):
                        seen.add(ip)
                        candidates.append(ip)
                if not candidates:
                    raise ValueError("no usable public IPs in target_ips")
                if len(candidates) > MAX_BULK_IPS:
                    raise ValueError(
                        f"block_ips list too large ({len(candidates)} IPs, max {MAX_BULK_IPS})"
                    )
                wl = set((await db.execute(
                    select(WhitelistedIp.ip).where(WhitelistedIp.ip.in_(candidates))
                )).scalars().all())
                existing = set((await db.execute(
                    select(BlockedIp.ip).where(BlockedIp.ip.in_(candidates))
                )).scalars().all())
                now_ts = datetime.now(timezone.utc)
                src_label = _source_label(rec.source_type)
                comment = f"agent[{src_label}] distributed-block: {(rec.reasoning or '')[:160]}"
                added: list[str] = []
                skipped_wl: list[str] = []
                for ip in candidates:
                    if ip in wl:
                        skipped_wl.append(ip)
                        continue
                    if ip in existing:
                        continue
                    db.add(BlockedIp(ip=ip, comment=comment, blocked_at=now_ts,
                                     blocked_by=rec.decided_by or "agent",
                                     source=rec.source_type or "agent"))
                    added.append(ip)
                if skipped_wl:
                    logger.warning(
                        f"agent: block_ips skipped {len(skipped_wl)} whitelisted IP(s)"
                    )
                logger.info(
                    f"agent: block_ips +{len(added)} new, {len(existing)} already, "
                    f"{len(skipped_wl)} whitelisted"
                )
                result = {
                    "blocked": len(added),
                    "already_blocked": len(existing),
                    "skipped_whitelist": len(skipped_wl),
                    "total": len(candidates),
                }

            elif rec.action == "block_domain":
                domain = (rec.action_args or {}).get("target_domain")
                if not domain:
                    raise ValueError("no target_domain for block_domain")
                domain = str(domain).strip().lower()
                existing = await db.execute(
                    select(BlockedDomain).where(BlockedDomain.domain == domain)
                )
                if existing.scalar_one_or_none() is None:
                    src_label = _source_label(rec.source_type)
                    db.add(BlockedDomain(
                        domain=domain,
                        comment=f"agent[{src_label}]: {(rec.reasoning or '')[:200]}",
                        blocked_at=datetime.now(timezone.utc),
                    ))
                result = {"domain": domain, "source": rec.source_type}

            elif rec.action == "block_url":
                url = (rec.action_args or {}).get("target_url")
                if not url:
                    raise ValueError("no target_url for block_url")
                url = str(url).strip()
                existing = await db.execute(
                    select(BlockedUrl).where(BlockedUrl.url == url)
                )
                if existing.scalar_one_or_none() is None:
                    src_label = _source_label(rec.source_type)
                    db.add(BlockedUrl(
                        url=url,
                        comment=f"agent[{src_label}]: {(rec.reasoning or '')[:200]}",
                        blocked_at=datetime.now(timezone.utc),
                    ))
                result = {"url": url, "source": rec.source_type}

            elif rec.action == "acknowledge":
                if rec.alert_id:
                    a = await db.get(Alert, rec.alert_id)
                    if a is not None and a.acknowledged_at is None:
                        a.acknowledged_at = datetime.now(timezone.utc)
                        a.acknowledged_action = "agent-acknowledge"
                result = {"alert_id": rec.alert_id, "source_type": rec.source_type}

            elif rec.action == "isolate":
                # We don't auto-isolate endpoints — that needs an explicit
                # human approval through the existing /api/endpoints/...
                # API. Manual-only.
                raise ValueError("isolate requires manual approval via the endpoints API")

            elif rec.action == "no_action":
                result = {"noop": True}

            elif rec.action == "revoke_sessions":
                # M365 login watch: kill every session/refresh token of the
                # user via Graph — forces re-auth on all devices.
                user = str((rec.action_args or {}).get("target_user") or "").strip()
                if not user:
                    raise ValueError("no target_user for revoke_sessions")
                from app.entra_client import entra_client
                result = await entra_client.revoke_sign_in_sessions(user)

            else:
                raise ValueError(f"unknown action {rec.action!r}")

            rec.status = "executed"
            rec.error = None            # clear any error from a previous failed attempt
            rec.decided_at = datetime.now(timezone.utc)
            await db.commit()
        except Exception as e:
            rec.status = "failed"
            rec.error = str(e)[:500]
            rec.decided_at = datetime.now(timezone.utc)
            await db.commit()
            raise

    return {"status": "executed", "result": result}


async def revert_decision(decision_id: int) -> dict[str, Any]:
    """Undo the blocklist effect of an executed decision — used when a human
    declines an auto-approved (or otherwise executed) block after the fact.
    Removes the IP(s)/domain/URL this decision put on the blocklist. Acknowledge
    / no_action have nothing to revert. Idempotent: already-absent entries are
    simply skipped."""
    async with async_session() as db:
        rec: AgentDecision | None = await db.get(AgentDecision, decision_id)
        if rec is None:
            raise ValueError(f"decision {decision_id} not found")

        args = rec.action_args or {}
        removed_ips: list[str] = []
        removed_domain: str | None = None
        removed_url: str | None = None

        async def _del_ips(ips: list[str]) -> None:
            uniq = sorted({str(i).strip() for i in ips if str(i).strip()})
            if not uniq:
                return
            rows = (await db.execute(select(BlockedIp).where(BlockedIp.ip.in_(uniq)))).scalars().all()
            for row in rows:
                await db.delete(row)
                removed_ips.append(row.ip)

        if rec.action == "block_ip":
            ip = args.get("target_ip")
            if not ip:
                if rec.source_type == "waf":
                    ip = rec.source_ip
                elif rec.alert_id:
                    a = await db.get(Alert, rec.alert_id)
                    ip = a.source_ip if a else None
            if ip:
                await _del_ips([ip])

        elif rec.action == "block_ips":
            await _del_ips(args.get("target_ips") or [])

        elif rec.action == "block_subnet":
            cidr = args.get("target_subnet")
            if cidr:
                try:
                    network = ipaddress.ip_network(cidr, strict=False)
                    await _del_ips([str(a) for a in network.hosts()])
                except ValueError:
                    pass

        elif rec.action == "block_domain":
            domain = str(args.get("target_domain") or "").strip().lower()
            if domain:
                row = (await db.execute(select(BlockedDomain).where(BlockedDomain.domain == domain))).scalar_one_or_none()
                if row is not None:
                    await db.delete(row)
                    removed_domain = domain

        elif rec.action == "block_url":
            url = str(args.get("target_url") or "").strip()
            if url:
                row = (await db.execute(select(BlockedUrl).where(BlockedUrl.url == url))).scalar_one_or_none()
                if row is not None:
                    await db.delete(row)
                    removed_url = url

        await db.commit()

    return {"removed_ips": removed_ips, "removed_domain": removed_domain,
            "removed_url": removed_url, "action": rec.action}


async def forget_pattern_for(decision_id: int) -> bool:
    """Delete the learned approval pattern matching a decision's signature
    (full reset of its statistics). Returns True if a pattern was removed."""
    async with async_session() as db:
        rec = await db.get(AgentDecision, decision_id)
    if rec is None:
        return False
    signature, _rule = await _decision_signature(rec)
    async with async_session() as db:
        pat = (await db.execute(
            select(AgentApprovalPattern).where(AgentApprovalPattern.signature == signature)
        )).scalar_one_or_none()
        if pat is None:
            return False
        await db.delete(pat)
        await db.commit()
    return True


# --- WAF loop (rule-based, triggered per new 4xx/5xx WAF event) ---


_WAF_FILTER_SQL_FRAG = (
    "(log_type = 'WAF' "
    "OR (raw_data->>'log_component') ILIKE '%waf%' "
    "OR (raw_data->>'log_component') ILIKE '%web app%' "
    "OR (raw_data->>'log_component') ILIKE '%web server protection%')"
)


async def agent_waf_loop(window_minutes: int | None = None, force: bool = False) -> None:
    """Collect WAF candidates (fresh 4xx/5xx events), filter against whitelist
    / private IPs / cooldown, then let the LLM decide per IP — the decision
    logic lives entirely in ``agent_waf_system_prompt`` (admin-editable).

    ``window_minutes`` overrides the default lookback (3× interval). ``force=True``
    runs even when the agent is otherwise disabled — used by the manual trigger
    endpoint so an admin can scan on demand."""
    if (not settings.agent_enabled or not settings.agent_waf_enabled) and not force:
        return

    threshold = int(settings.agent_waf_threshold or 4)
    interval = int(settings.agent_waf_interval_seconds or 60)
    now = datetime.now(timezone.utc)
    if window_minutes is not None:
        window_start = now - timedelta(minutes=max(1, int(window_minutes)))
    else:
        window_start = now - timedelta(seconds=max(interval * 3, 180))
    h24_ago = now - timedelta(hours=24)
    block_cooldown = now - timedelta(hours=1)
    noaction_cooldown = now - timedelta(hours=24)

    async with async_session() as db:
        # Step 1: candidate IPs that just produced a 4xx/5xx WAF event
        candidates_q = await db.execute(text(f"""
            SELECT DISTINCT source_ip
            FROM firewall_logs
            WHERE created_at >= :since
              AND {_WAF_FILTER_SQL_FRAG}
              AND source_ip IS NOT NULL
              AND (raw_data->>'http_status') ~ '^[45][0-9][0-9]$'
            LIMIT 100
        """), {"since": window_start})
        candidate_ips = [r[0] for r in candidates_q.fetchall()]
        candidate_ips = await _filter_candidates(
            db, candidate_ips, "waf", block_cooldown, noaction_cooldown
        )
        if not candidate_ips:
            return

        # Step 2: per-IP 24h error counts
        counts_q = await db.execute(text(f"""
            SELECT source_ip,
                   COUNT(*) FILTER (WHERE (raw_data->>'http_status') LIKE '4%') AS c4,
                   COUNT(*) FILTER (WHERE (raw_data->>'http_status') LIKE '5%') AS c5,
                   array_agg(DISTINCT (raw_data->>'http_status'))                AS statuses,
                   (array_agg(DISTINCT COALESCE(raw_data->>'domain', raw_data->>'website')))[1:3] AS hosts,
                   MAX(attacker_country) AS country,
                   MAX(attacker_city)    AS city
            FROM firewall_logs
            WHERE created_at >= :since
              AND {_WAF_FILTER_SQL_FRAG}
              AND source_ip = ANY(:ips)
              AND (raw_data->>'http_status') ~ '^[45][0-9][0-9]$'
            GROUP BY source_ip
        """), {"since": h24_ago, "ips": candidate_ips})
        per_ip = {r[0]: r for r in counts_q.fetchall()}

        # Step 3: top up the per-IP path cache from this window's WAF rows.
        # We persist *which paths* each IP hit so the LLM can spot directory/
        # wordlist brute-force (many distinct paths) vs. a single broken URL.
        paths_q = await db.execute(text(f"""
            SELECT source_ip,
                   COALESCE(raw_data->>'httpquery', raw_data->>'url',
                            raw_data->>'querystring', raw_data->>'request') AS path,
                   raw_data->>'http_status'                                  AS status,
                   COALESCE(raw_data->>'httpmethod', raw_data->>'method')   AS method,
                   created_at
            FROM firewall_logs
            WHERE created_at >= :since
              AND {_WAF_FILTER_SQL_FRAG}
              AND source_ip = ANY(:ips)
              AND (raw_data->>'http_status') ~ '^[45][0-9][0-9]$'
              AND COALESCE(raw_data->>'httpquery', raw_data->>'url',
                           raw_data->>'querystring', raw_data->>'request') IS NOT NULL
        """), {"since": window_start, "ips": candidate_ips})
        entries_by_ip: dict[str, list[dict]] = {}
        for src_ip, path, status, method, ts in paths_q.fetchall():
            entries_by_ip.setdefault(src_ip, []).append(
                {"path": path, "status": status, "method": method, "ts": ts}
            )

    for src_ip, entries in entries_by_ip.items():
        await waf_path_cache.add_paths(src_ip, entries, now)

    logger.info(f"agent[waf]: {len(candidate_ips)} candidate IP(s)")

    for ip in candidate_ips:
        row = per_ip.get(ip)
        c4 = int(row[1] or 0) if row else 0
        c5 = int(row[2] or 0) if row else 0
        statuses = [s for s in (row[3] if row else []) if s]
        hosts = [h for h in (row[4] if row else []) if h]
        country = row[5] if row else None
        city = row[6] if row else None

        # Accumulated distinct paths (24h) for wordlist/dir-brute-force detection.
        cached_paths = await waf_path_cache.recent_paths(ip, 24 * 60, now)
        paths = cached_paths or []
        distinct_path_names = sorted({p["path"] for p in paths if p.get("path")})
        status_404 = sum(1 for p in paths if (p.get("status") or "").startswith("4"))

        context = {
            "source_ip": ip,
            "count_4xx_24h": c4,
            "count_5xx_24h": c5,
            "threshold": threshold,
            "statuses": statuses,
            "hosts": hosts,
            "country": country, "city": city,
            # Path intelligence from the Redis cache:
            "distinct_paths_24h": len(distinct_path_names),
            "path_4xx_count": status_404,
            "sample_paths": distinct_path_names[:60],
        }

        await _llm_decide_rule(source_type="waf", ip=ip, context=context)


async def _store_rule_decision(
    source_type: str, ip: str | None, action: str, reasoning: str,
    args: dict[str, Any], context: dict[str, Any],
) -> int:
    """Persist a rule-based agent decision (WAF/IPS/failed-login).
    Auto-executes block_ip if enabled and the IP isn't whitelisted
    (whitelist check happens earlier and execute_decision rechecks)."""
    rec = AgentDecision(
        alert_id=None,
        source_type=source_type,
        source_ip=ip,
        action=action,
        action_args={**(args or {}), "context": context},
        reasoning=reasoning[:2000],
        status="pending",
        decided_by="agent",
        model=settings.agent_model or "local-model",
    )
    async with async_session() as db:
        db.add(rec)
        await db.commit()
        await db.refresh(rec)

    # Learned auto-approval takes precedence over the pending/notify path.
    if await _maybe_learned_auto_approve(rec):
        return rec.id

    should, why = _should_auto_execute(action)
    if should:
        logger.info(f"agent[{source_type}]: auto-executing decision {rec.id} for {ip} ({why})")
        try:
            await execute_decision(rec.id)
        except Exception as e:
            logger.warning(f"agent[{source_type}]: auto-execute failed for {ip}: {e}")
    else:
        await _notify_telegram_pending(rec.id)
    return rec.id


async def _llm_decide_rule(
    source_type: str, ip: str | None, context: dict,
    extra_args: dict | None = None,
) -> dict[str, Any] | None:
    """LLM-based replacement for the old rule ladder.

    Pulls OSINT for the IP, builds a JSON payload, calls the LLM with the
    per-source system prompt (admin-editable, falls back to the bundled
    default), and persists the parsed decision via ``_store_rule_decision``
    — which also handles auto-execute.

    ``ip`` may be None for synthetic decisions (e.g. when source_ip column
    isn't applicable). ``extra_args`` is merged into the decision's args
    field — used e.g. to inject target_subnet for the subnet-brute-force
    path so the LLM doesn't have to fabricate it.

    Returns ``{"id", "action", "reasoning", "osint"}`` for the persisted
    decision, or None when no decision was stored (LLM failure / invalid
    action). Callers that don't care simply ignore the return value; the
    anomaly sweep uses it to derive the verdict + comment.
    """
    if source_type not in _RULE_PROMPTS:
        logger.warning(f"agent: no prompt defined for source_type={source_type!r}")
        return None

    # 1) OSINT enrichment — only for public IPs. Private/None → empty dict;
    #    the LLM still gets a decision-shaped payload but with no OSINT signals.
    osint: dict[str, Any] = {}
    if ip and _is_public_ip(ip):
        try:
            from app.osint import lookup as osint_lookup, looks_malicious, shodan_enrich, _has_shodan_data
            # If shodan_auto_every_lookup is on, lookup() already queried Shodan;
            # otherwise spend a credit here only when the cheap providers flag the
            # IP as malicious (and Shodan wasn't already fetched).
            osint = await osint_lookup(ip, force=False, allow_shodan=False)
            if (settings.shodan_auto_on_malicious
                    and not _has_shodan_data(osint.get("shodan"))
                    and looks_malicious(osint, settings.shodan_auto_abuse_threshold)):
                try:
                    osint["shodan"] = await shodan_enrich(ip)
                    logger.info(f"agent[{source_type}]: Shodan queried for malicious {ip}")
                except Exception as e:
                    logger.warning(f"agent[{source_type}]: Shodan enrich for {ip} failed: {e}")
        except Exception as e:
            logger.warning(f"agent[{source_type}]: OSINT lookup for {ip} failed: {e}")
            osint = {"error": str(e)[:200]}

    # 2) Build the user message — a single JSON object the LLM can chew on
    payload = {
        "source_type": source_type,
        "source_ip": ip,
        "context": context,
        "osint": osint,
        "allowed_actions": _allowed_actions_for_source(source_type),
    }
    user_msg = "Eingangsdaten:\n" + json.dumps(payload, indent=2, ensure_ascii=False, default=str)

    # 3) Ask the LLM
    try:
        decision = await _call_llm(
            user_msg,
            system_prompt=_prompt_for(source_type),
            source=source_type,
            allowed_actions=_allowed_actions_for_source(source_type),
        )
    except Exception as e:
        logger.warning(f"agent[{source_type}]: LLM call failed for ip={ip}: {e}")
        return None

    # 3b) Per-source action validation: the LLM might hallucinate an action
    #     that the prompt didn't actually allow (e.g. block_subnet for WAF).
    #     Reject those before persisting — otherwise execute_decision blows
    #     up with a less helpful error later.
    allowed = set(_allowed_actions_for_source(source_type))
    if decision["action"] not in allowed:
        logger.warning(
            f"agent[{source_type}]: LLM emitted action={decision['action']!r} "
            f"not in allowed_actions={sorted(allowed)} for ip={ip}; dropping"
        )
        return None

    # 4) Action-arg merging:
    #    - extra_args (e.g. target_subnet) overrides whatever the LLM emitted
    #    - block_ip without target_ip defaults to the source IP
    action_args = {**(decision.get("args") or {}), **(extra_args or {})}
    if decision["action"] == "block_ip" and "target_ip" not in action_args and ip:
        action_args["target_ip"] = ip

    # 5) Persist via the shared helper (handles auto-execute)
    decision_id = await _store_rule_decision(
        source_type=source_type, ip=ip,
        action=decision["action"],
        reasoning=decision.get("reasoning") or "",
        args=action_args,
        context={
            **context,
            "rule": "llm",
            "osint_summary": _osint_summary(osint),
        },
    )
    return {
        "id": decision_id,
        "action": decision["action"],
        "reasoning": decision.get("reasoning") or "",
        "osint": osint,
    }


async def triage_value(
    value: str, value_type: str, note: str | None = None
) -> dict[str, Any]:
    """Operator-/OSINT-initiated LLM triage of a single indicator (IP, domain
    or URL). Pulls OSINT, asks the LLM (triage prompt) whether to block, and
    persists a decision (``source_type='triage'``) via the shared rule path —
    which also honours the auto-execute settings. Returns the decision id +
    the parsed verdict so the caller can surface it."""
    value = (value or "").strip()
    if not value:
        raise ValueError("empty value")
    value_type = value_type if value_type in {"ip", "domain", "url"} else "ip"

    block_action = {"ip": "block_ip", "domain": "block_domain", "url": "block_url"}[value_type]
    target_key   = {"ip": "target_ip", "domain": "target_domain", "url": "target_url"}[value_type]
    allowed = [block_action, "no_action"]

    # 1) OSINT enrichment by type (private IPs skip the IP lookup)
    osint: dict[str, Any] = {}
    try:
        from app import osint as osint_mod
        if value_type == "ip" and _is_public_ip(value):
            osint = await osint_mod.lookup(value)
        elif value_type == "domain":
            osint = await osint_mod.lookup_domain(value)
        elif value_type == "url":
            osint = await osint_mod.lookup_url(value)
    except Exception as e:
        logger.warning(f"agent[triage]: OSINT lookup for {value} failed: {e}")
        osint = {"error": str(e)[:200]}

    # 2) Ask the LLM
    payload = {
        "value": value,
        "value_type": value_type,
        "note": note,
        "osint": osint,
        "allowed_actions": allowed,
    }
    user_msg = "Triage-Anfrage:\n" + json.dumps(payload, indent=2, ensure_ascii=False, default=str)
    decision = await _call_llm(
        user_msg, system_prompt=_prompt_for("triage"), source="triage",
        allowed_actions=allowed,
    )

    # 3) Coerce to an action the value-type actually supports
    action = decision["action"] if decision["action"] in allowed else "no_action"

    # 4) The system — never the LLM — sets the concrete block target
    args: dict[str, Any] = {}
    if action == block_action:
        args[target_key] = value

    # 5) Persist (handles auto-execute) and return the new decision id
    decision_id = await _store_rule_decision(
        source_type="triage",
        ip=(value if value_type == "ip" else None),
        action=action,
        reasoning=decision.get("reasoning") or "",
        args=args,
        context={
            "triage": True,
            "value": value,
            "value_type": value_type,
            "note": note,
            "osint_summary": _osint_summary(osint),
        },
    )
    return {
        "decision_id": decision_id,
        "action": action,
        "reasoning": decision.get("reasoning") or "",
    }


async def _filter_candidates(db, candidate_ips: list[str], source_type: str,
                              block_cooldown_dt, noaction_cooldown_dt) -> list[str]:
    """Drop whitelisted + private + recently-decided IPs.

    Cooldown rules per existing decision:
      * ``block_ip`` / ``block_subnet`` / ``acknowledge`` / ``isolate`` — skip
        while within the 1h block-cooldown window (avoids hammering the LLM
        when we already decided to act on this IP recently).
      * ``no_action`` — skip while within the 24h audit-cooldown window
        (we already wrote an audit row and don't want a duplicate).
      * Anything else (unknown legacy actions) — skip conservatively.
    """
    if not candidate_ips:
        return []
    wl_q = await db.execute(
        select(WhitelistedIp.ip).where(WhitelistedIp.ip.in_(candidate_ips))
    )
    wl = set(wl_q.scalars().all())
    candidate_ips = [ip for ip in candidate_ips if ip not in wl and _is_public_ip(ip)]
    if not candidate_ips:
        return []

    recent_q = await db.execute(
        select(AgentDecision.source_ip, AgentDecision.action, AgentDecision.created_at)
        .where(
            AgentDecision.source_type == source_type,
            AgentDecision.source_ip.in_(candidate_ips),
            AgentDecision.created_at >= noaction_cooldown_dt,
        )
    )
    skip: set[str] = set()
    BLOCKING_ACTIONS = {"block_ip", "block_subnet", "acknowledge", "isolate"}
    for ip, action, ts in recent_q.all():
        if action in BLOCKING_ACTIONS and ts >= block_cooldown_dt:
            skip.add(ip)
        elif action == "no_action" and ts >= noaction_cooldown_dt:
            skip.add(ip)
        elif action not in BLOCKING_ACTIONS and action != "no_action":
            # Unknown action — conservative skip
            skip.add(ip)
    return [ip for ip in candidate_ips if ip not in skip]


# --- IPS loop (rule-based, similar to WAF but triggered by IDP events) ---


_IPS_FILTER_SQL_FRAG = (
    "(log_type IN ('IDP', 'IPS') "
    "OR (raw_data->>'log_component') ILIKE '%intrusion%' "
    "OR (raw_data->>'log_component') = 'IPS')"
)


async def agent_ips_loop(window_minutes: int | None = None, force: bool = False) -> None:
    """Collect IDP/IPS candidates, filter, then defer to the LLM via the
    ``agent_ips_system_prompt`` (admin-editable). The default prompt knows
    that Sophos has already classified these as intrusion attempts, so it
    treats high/critical severity as immediate-block."""
    if (not settings.agent_enabled or not settings.agent_ips_enabled) and not force:
        return

    threshold = int(settings.agent_ips_threshold or 3)
    interval = int(settings.agent_ips_interval_seconds or 60)
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(minutes=int(window_minutes)) if window_minutes else now - timedelta(seconds=max(interval * 3, 180))
    h24_ago = now - timedelta(hours=24)
    block_cooldown = now - timedelta(hours=1)
    noaction_cooldown = now - timedelta(hours=24)

    async with async_session() as db:
        candidates_q = await db.execute(text(f"""
            SELECT DISTINCT source_ip
            FROM firewall_logs
            WHERE created_at >= :since
              AND {_IPS_FILTER_SQL_FRAG}
              AND source_ip IS NOT NULL
            LIMIT 100
        """), {"since": window_start})
        candidate_ips = [r[0] for r in candidates_q.fetchall()]
        candidate_ips = await _filter_candidates(db, candidate_ips, "ips", block_cooldown, noaction_cooldown)
        if not candidate_ips:
            return

        ctx_q = await db.execute(text(f"""
            SELECT source_ip,
                   COUNT(*) AS cnt,
                   MAX(severity) AS max_sev,
                   array_agg(DISTINCT severity)                            FILTER (WHERE severity IS NOT NULL) AS sevs,
                   (array_agg(DISTINCT threat_name)                        FILTER (WHERE threat_name IS NOT NULL))[1:5] AS sigs,
                   (array_agg(DISTINCT COALESCE(raw_data->>'category',
                                                 raw_data->>'classification')) FILTER (WHERE COALESCE(raw_data->>'category', raw_data->>'classification') IS NOT NULL))[1:3] AS cats,
                   MAX(attacker_country) AS country,
                   MAX(attacker_city)    AS city
            FROM firewall_logs
            WHERE created_at >= :since
              AND {_IPS_FILTER_SQL_FRAG}
              AND source_ip = ANY(:ips)
            GROUP BY source_ip
        """), {"since": h24_ago, "ips": candidate_ips})
        per_ip = {r[0]: r for r in ctx_q.fetchall()}

    logger.info(f"agent[ips]: {len(candidate_ips)} candidate IP(s)")

    for ip in candidate_ips:
        row = per_ip.get(ip)
        cnt = int(row[1] or 0) if row else 0
        sevs = [s for s in (row[3] if row else []) if s]
        sigs = [s for s in (row[4] if row else []) if s]
        cats = [c for c in (row[5] if row else []) if c]
        country = row[6] if row else None
        city = row[7] if row else None

        context = {
            "source_ip": ip,
            "count_24h": cnt, "threshold": threshold,
            "severities": sevs, "signatures": sigs, "categories": cats,
            "country": country, "city": city,
        }
        await _llm_decide_rule(source_type="ips", ip=ip, context=context)


# --- FW-anomaly loop (Isolation Forest over NetFlow → OSINT triage + verdict) ---
#
# Mirrors the FW-Anomalies dashboard's global source scope with the default
# volume/ports/night dimension trio, then per anomalous IP:
#   * public IP  → OSINT + LLM (source_type='anomaly'). A block_ip decision goes
#     through the normal approval pipeline; the verdict 'malicious' is written
#     immediately. no_action → verdict 'suspicious' (gray area, per policy every
#     non-malicious anomaly starts as suspicious until an analyst clears it).
#   * private IP → verdict 'suspicious' without OSINT/LLM (internal hosts are
#     never blocked; the analyst reviews manually).
# Human verdicts are never overwritten; agent verdicts refresh at most every 24h.


def _osint_fqdns(osint: dict[str, Any]) -> list[str]:
    """Collect the FQDN/domain hints the OSINT providers returned for an IP."""
    names: list[str] = []
    ab = osint.get("abuseipdb") or {}
    if ab.get("domain"):
        names.append(str(ab["domain"]))
    names += [str(h) for h in (ab.get("hostnames") or [])[:3]]
    names += [str(h) for h in ((osint.get("shodan") or {}).get("hostnames") or [])[:3]]
    ipinfo = osint.get("ipinfo") or {}
    if ipinfo.get("hostname"):
        names.append(str(ipinfo["hostname"]))
    seen: set[str] = set()
    out: list[str] = []
    for n in names:
        k = n.lower().strip()
        if k and k not in seen:
            seen.add(k)
            out.append(n.strip())
    return out


async def _set_agent_verdict(ip: str, verdict: str, comment: str) -> bool:
    """Write an agent verdict on the FW-anomaly page unless a human verdict
    exists — human assessments always win over the agent."""
    async with async_session() as db:
        row = await db.get(AnomalyVerdict, ip)
        if row is not None and (row.created_by or "human") != "agent":
            return False
        now = datetime.now(timezone.utc)
        if row is None:
            db.add(AnomalyVerdict(ip=ip, verdict=verdict, comment=comment[:1000],
                                  created_by="agent", updated_at=now))
        else:
            row.verdict = verdict
            row.comment = comment[:1000]
            row.updated_at = now
        await db.commit()
    return True


async def agent_anomaly_loop(force: bool = False, no_cap: bool = False) -> None:
    """OSINT-backed triage of the NetFlow anomaly analysis (see block comment).

    ``no_cap=True`` (the dashboard's "analyse all unrated" button) lifts the
    per-sweep IP cap so every not-yet-verdicted anomaly gets processed in one
    run — bounded by a hard safety limit of 100 LLM/OSINT calls."""
    if (not settings.agent_enabled or not settings.agent_anomaly_enabled) and not force:
        return

    import math

    hours = max(1, int(settings.agent_anomaly_hours or 24))
    min_flows = max(1, int(settings.agent_anomaly_min_flows or 5))
    cap = 100 if no_cap else max(1, int(settings.agent_anomaly_max_ips or 10))
    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=hours)

    # 1) Per-source-IP NetFlow aggregation (same shape as the dashboard query).
    async with async_session() as db:
        rows = (await db.execute(text("""
            SELECT n.src_ip AS entity,
                   SUM(n.bytes)   AS bytes,
                   SUM(n.flows)   AS flows,
                   COUNT(DISTINCT n.dst_port) AS dports,
                   COUNT(DISTINCT n.dst_ip)   AS dips,
                   SUM(CASE WHEN EXTRACT(hour FROM n.bucket_start) < 6 THEN n.flows ELSE 0 END) AS night_flows,
                   MAX(g.country) AS country
            FROM netflow_buckets n
            LEFT JOIN geoip_cache g ON g.ip = n.src_ip
            WHERE n.bucket_start >= :since AND n.src_ip IS NOT NULL
            GROUP BY n.src_ip
            HAVING SUM(n.flows) >= :min_flows
            ORDER BY SUM(n.bytes) DESC
            LIMIT 4000
        """), {"since": since, "min_flows": min_flows})).all()

    if len(rows) < 10:
        logger.info(f"agent[anomaly]: only {len(rows)} IPs in window — skipping")
        return

    items: list[dict[str, Any]] = []
    for entity, byts, flows, dports, dips, night_flows, country in rows:
        flows = int(flows or 0) or 1
        night_ratio = int(night_flows or 0) / flows
        items.append({
            "ip": entity, "country": country,
            "bytes": int(byts or 0), "flows": flows,
            "dports": int(dports or 0), "dips": int(dips or 0),
            "night_ratio": round(night_ratio, 3),
            "f_volume": math.log1p(int(byts or 0)),
            "f_ports": math.log1p(int(dports or 0)),
            "f_night": night_ratio,
        })

    from app import anomaly as anomaly_mod
    feature_keys = ["f_volume", "f_ports", "f_night"]
    dim_keys = {k: k[2:] for k in feature_keys}
    result = await asyncio.to_thread(
        lambda: anomaly_mod.attribute_drivers(
            anomaly_mod.score_items(items, feature_keys), feature_keys, dim_keys)
    )
    anomalies = [it for it in result["items"] if it.get("is_anomaly")]
    if not anomalies:
        logger.info("agent[anomaly]: no anomalies above threshold")
        return

    # 2) Skip IPs a human already judged, and agent verdicts refreshed <24h ago.
    ips_all = [it["ip"] for it in anomalies]
    async with async_session() as db:
        vrows = (await db.execute(
            select(AnomalyVerdict.ip, AnomalyVerdict.created_by, AnomalyVerdict.updated_at)
            .where(AnomalyVerdict.ip.in_(ips_all))
        )).all()
    human_verdicts = {r[0] for r in vrows if (r[1] or "human") != "agent"}
    fresh_agent = {r[0] for r in vrows
                   if (r[1] or "human") == "agent"
                   and r[2] is not None and (now - r[2]) < timedelta(hours=24)}

    public: list[dict[str, Any]] = []
    internal: list[dict[str, Any]] = []
    for it in anomalies:
        if it["ip"] in human_verdicts or it["ip"] in fresh_agent:
            continue
        (public if _is_public_ip(it["ip"]) else internal).append(it)

    # 3) Internal anomalies → suspicious for manual review, no OSINT/LLM/block.
    lang = _agent_lang()
    for it in internal:
        drivers = ", ".join(d.get("dim", "?") for d in (it.get("drivers") or [])) or "-"
        if lang == "de":
            comment = (f"agent[Anomaly]: Interne IP mit auffälligem NetFlow-Verhalten "
                       f"(Score {it['score']:.3f}, Treiber: {drivers}) — manuelle Prüfung erforderlich.")
        else:
            comment = (f"agent[Anomaly]: Internal IP with anomalous NetFlow behaviour "
                       f"(score {it['score']:.3f}, drivers: {drivers}) — manual review required.")
        await _set_agent_verdict(it["ip"], "suspicious", comment)

    if not public:
        logger.info(f"agent[anomaly]: {len(internal)} internal anomalies marked, no public candidates")
        return

    # 4) Public anomalies → cooldown/whitelist filter → per-sweep cap → LLM.
    async with async_session() as db:
        candidate_ips = await _filter_candidates(
            db, [it["ip"] for it in public], "anomaly",
            now - timedelta(hours=1), now - timedelta(hours=24),
        )
    by_ip = {it["ip"]: it for it in public}
    todo = [by_ip[ip] for ip in candidate_ips if ip in by_ip][:cap]
    if len(candidate_ips) > cap:
        logger.info(f"agent[anomaly]: {len(candidate_ips)} candidates, capped to {cap} this sweep")
    if not todo:
        return
    logger.info(f"agent[anomaly]: analysing {len(todo)} public anomalous IP(s)")

    for it in todo:
        ip = it["ip"]
        context = {
            "window_hours": hours,
            "anomaly_score": round(float(it["score"]), 3),
            "drivers": [d.get("dim") for d in (it.get("drivers") or [])],
            "bytes": it["bytes"], "flows": it["flows"],
            "distinct_dst_ports": it["dports"], "distinct_dst_ips": it["dips"],
            "night_ratio": it["night_ratio"], "country": it["country"],
        }
        res = await _llm_decide_rule(source_type="anomaly", ip=ip, context=context)
        if not res:
            continue
        # Verdict + comment: LLM reasoning (prompt mandates maliciousness info)
        # plus the OSINT FQDN/domain appended deterministically.
        fqdns = _osint_fqdns(res.get("osint") or {})
        suffix = (" · FQDN: " + ", ".join(fqdns[:3])) if fqdns else ""
        comment = f"agent[Anomaly]: {(res.get('reasoning') or '').strip()}{suffix}"
        verdict = "malicious" if res["action"] == "block_ip" else "suspicious"
        await _set_agent_verdict(ip, verdict, comment)


# --- Per-connection C2/exfil loop (rule-based, alarming) ---


def _fmt_bytes_short(b: int) -> str:
    b = float(b or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if b < 1024 or unit == "TB":
            return f"{b:.0f} {unit}" if unit == "B" else f"{b:.1f} {unit}"
        b /= 1024


def _connanom_texts(a: dict, lang: str) -> tuple[str, str]:
    """Build (kind_label, detail) describing a connection anomaly, localized."""
    de = lang == "de"
    port = a.get("top_port") or 0
    if a["kind"] == "c2":
        kind = "C2-Beaconing" if de else "C2 beaconing"
        bm = a.get("beacon") or {}
        per = bm.get("period_s", 0)
        if de:
            detail = (f"Regelmäßige Verbindung alle ~{per}s · {a['flows']} Verbindungen · "
                      f"Regularität {bm.get('regularity', 0)} · über {bm.get('span_min', 0):.0f} min · Port {port}")
        else:
            detail = (f"Regular connection every ~{per}s · {a['flows']} connections · "
                      f"regularity {bm.get('regularity', 0)} · over {bm.get('span_min', 0):.0f} min · port {port}")
    else:  # exfil
        kind = "Untypischer Upload" if de else "Atypical upload"
        up = int(round(a.get("upload_ratio", 0) * 100))
        if de:
            detail = (f"Upload {_fmt_bytes_short(a['out_bytes'])} ({up}% ausgehend) · "
                      f"Download {_fmt_bytes_short(a['in_bytes'])} · Port {port}")
        else:
            detail = (f"Upload {_fmt_bytes_short(a['out_bytes'])} ({up}% outbound) · "
                      f"download {_fmt_bytes_short(a['in_bytes'])} · port {port}")
    if a.get("is_new"):
        detail += " · " + ("Ziel neu" if de else "new destination")
    elif a.get("dst_hosts", 9) <= 1:
        detail += " · " + ("Ziel selten" if de else "rare destination")
    return kind, detail


def _connanom_comment(a: dict, lang: str) -> str:
    kind, detail = _connanom_texts(a, lang)
    tag = "Verbindung" if lang == "de" else "Connection"
    return f"agent[{tag}]: {kind} — {detail} (Score {a['score']:.2f})"


def _connanom_alert_html(a: dict, lang: str) -> str:
    de = lang == "de"
    kind, detail = _connanom_texts(a, lang)
    country = f" ({a['country']})" if a.get("country") else ""
    head = "🚨 <b>" + (f"{kind} erkannt" if de else f"{kind} detected") + "</b>"
    hostline = (f"Host <code>{a['src']}</code> → <code>{a['dst']}</code>{country}")
    return (f"{head}\n{hostline}\n{detail}\n"
            f"Score {a['score']:.2f}")


async def agent_connection_anomaly_loop(force: bool = False) -> None:
    """Per-connection C2/exfil detection with alarming.

    Runs the connection-anomaly engine (see ``connection_anomaly``) and, for
    high-confidence **C2 beaconing** / **atypical upload** connections, records a
    ``suspicious`` agent verdict on the external destination and raises a
    de-duplicated Telegram/Teams alarm. Dedup + cooldown come from the agent
    verdict on the dst IP — never re-alarmed while a <24 h-fresh agent verdict
    exists, and human verdicts are never touched. Notify-only (no auto-block);
    the lower-severity "new/atypical" connections are surfaced on the dashboard
    but never alarmed here."""
    if (not settings.agent_enabled or not settings.agent_connanom_enabled) and not force:
        return

    hours = max(1, int(settings.agent_connanom_hours or 24))
    min_score = float(settings.agent_connanom_min_score or 0.7)
    cap = max(1, int(settings.agent_connanom_max_alerts or 10))
    now = datetime.now(timezone.utc)

    from app import connection_anomaly as conn_anom
    async with async_session() as db:
        res = await conn_anom.analyze(db, hours=hours, min_flows=5,
                                      overrides={"min_score": min_score})

    hits = [a for a in res["anomalies"]
            if a["kind"] in ("c2", "exfil") and a["score"] >= min_score]
    if not hits:
        logger.info("agent[conn-anomaly]: no C2/exfil connections above threshold")
        return

    # Dedup/cooldown on the external destination (verdicts are keyed on dst IP).
    dsts = list({a["dst"] for a in hits})
    async with async_session() as db:
        vrows = (await db.execute(
            select(AnomalyVerdict.ip, AnomalyVerdict.created_by, AnomalyVerdict.updated_at)
            .where(AnomalyVerdict.ip.in_(dsts))
        )).all()
    human = {r[0] for r in vrows if (r[1] or "human") != "agent"}
    fresh = {r[0] for r in vrows
             if (r[1] or "human") == "agent"
             and r[2] is not None and (now - r[2]) < timedelta(hours=24)}

    from app.notifications import notify
    lang = _agent_lang()
    sent = 0
    processed = 0
    for a in hits:
        dst = a["dst"]
        if dst in human or dst in fresh:
            continue
        await _set_agent_verdict(dst, "suspicious", _connanom_comment(a, lang))
        fresh.add(dst)   # don't re-alarm the same dst twice in one sweep
        processed += 1
        if sent < cap:
            await notify(_connanom_alert_html(a, lang), title="Warroom · C2/Exfil")
            sent += 1
    logger.info(f"agent[conn-anomaly]: {len(hits)} hit(s), {processed} new verdict(s), {sent} alarm(s)")


# --- Daily LLM assessment of connection anomalies (source↔destination reasoning) ---

CONN_TRIAGE_PROMPT = """Du bist ein Netzwerk-Verbindungs-Analyst für Warroom.

Du bewertest EINE einzelne Verbindung zwischen einem internen Host (Quelle) und
einer externen IP (Ziel). Ziel: erkläre, WAS diese Verbindung höchstwahrscheinlich
ist, und stufe sie ein.

INPUT (JSON, vom System gestellt):
  - source_ip, source_hostname — der interne Host (Hostname hilft: z. B.
    "homeassistant", "nas", "backup", "jumphost", "cam", "printer").
  - destination_ip, destination_country
  - connection — Verkehrsmuster: kind (c2 = regelmäßiges Beaconing, exfil =
    upload-lastig, new = neu/untypisch), port, out_bytes/in_bytes, upload_ratio,
    flows, is_new, baseline_days (an wie vielen Tagen das Paar historisch schon
    auftrat), dst_internal_hosts_sharing (wie viele interne Hosts dieses Ziel
    kontaktieren — viele = geteilter Dienst), beacon {period_s, regularity,
    span_min}, signals, score.
  - osint — Reverse-DNS/FQDN (hostnames), Organisation/ASN, Land und Reputation
    (abuseipdb, virustotal, greynoise, shodan, intelix). Felder können fehlen.

VORGEHEN:
1. Kombiniere Quell-Hostname + Ziel-FQDN/Org/ASN + Port + Muster, um den Dienst
   zu benennen. Beispiele für BENIGNE, gut erklärbare Verbindungen:
   - HomeAssistant, das regelmäßig kleine Verbindungen zu einem Wetter-Server
     öffnet (z. B. api.met.no / Meteorologisk Institutt in Norwegen, Port 443)
     um das Wetter abzurufen → benign, connection_type "HomeAssistant Wetter-Abruf".
   - NTP (Port 123), DNS (53), OS-/App-Updates, CDN, Cloud-Backup (S3/Azure/GCP),
     Messaging/Push (APNs, FCM, Telegram), VPN, Zeit-/Telemetrie-Dienste → benign.
2. Beaconing ALLEIN ist kein Beleg für C2 — viele legitime Dienste pollen
   periodisch. Ordne es nur dann als schädlich ein, wenn Ziel/Muster
   unerklärlich sind ODER OSINT-Reputation schlecht ist.
3. Wenn nichts das Ziel erklärt (unbekannte/reputationsschwache IP, unerklärliches
   Beaconing oder Upload) → suspicious; bei klaren OSINT-Malware-/C2-Belegen →
   malicious.

VERDICT:
  - benign     — Dienst plausibel identifiziert / bekannt-gutartig.
  - suspicious — unerklärlich, aber (noch) kein harter Malware-Beleg.
  - malicious  — OSINT belegt C2/Malware/Scanner, oder klare Exfiltration.

AUSGABE (strikt JSON, kein ```-Fence). action = "block_ip" nur bei malicious,
sonst "no_action". BEISPIEL:
{
  "action": "no_action",
  "args": {"verdict": "benign", "connection_type": "HomeAssistant Wetter-Abruf (api.met.no)"},
  "reasoning": "Quelle homeassistant.fritz.box; Ziel 157.249.81.141 löst zu api.met.no auf (Meteorologisk Institutt, Norwegen). Regelmäßige kleine 443-Abrufe alle ~57 min = Wetter-Polling, kein C2."
}
"""

CONN_TRIAGE_PROMPT_EN = """You are a network connection analyst for Warroom.

You assess ONE single connection between an internal host (source) and an
external IP (destination). Goal: explain WHAT this connection most likely is and
classify it.

INPUT (JSON, provided by the system):
  - source_ip, source_hostname — the internal host (the hostname helps: e.g.
    "homeassistant", "nas", "backup", "jumphost", "cam", "printer").
  - destination_ip, destination_country
  - connection — traffic pattern: kind (c2 = regular beaconing, exfil =
    upload-skewed, new = new/atypical), port, out_bytes/in_bytes, upload_ratio,
    flows, is_new, baseline_days (on how many days the pair already appeared),
    dst_internal_hosts_sharing (how many internal hosts contact this destination
    — many = shared service), beacon {period_s, regularity, span_min}, signals,
    score.
  - osint — reverse DNS/FQDN (hostnames), organisation/ASN, country and
    reputation (abuseipdb, virustotal, greynoise, shodan, intelix). Fields may
    be missing.

APPROACH:
1. Combine source hostname + destination FQDN/org/ASN + port + pattern to name
   the service. Examples of BENIGN, well-explained connections:
   - HomeAssistant regularly opening small connections to a weather server
     (e.g. api.met.no / Meteorologisk Institutt in Norway, port 443) to fetch
     the weather → benign, connection_type "HomeAssistant weather polling".
   - NTP (port 123), DNS (53), OS/app updates, CDN, cloud backup (S3/Azure/GCP),
     messaging/push (APNs, FCM, Telegram), VPN, time/telemetry services → benign.
2. Beaconing ALONE is not proof of C2 — many legitimate services poll
   periodically. Only classify as malicious if the destination/pattern is
   unexplainable OR OSINT reputation is bad.
3. If nothing explains the destination (unknown/low-reputation IP, unexplained
   beaconing or upload) → suspicious; with clear OSINT malware/C2 evidence →
   malicious.

VERDICT:
  - benign     — service plausibly identified / known-good.
  - suspicious — unexplained, but no hard malware evidence (yet).
  - malicious  — OSINT proves C2/malware/scanner, or clear exfiltration.

OUTPUT (strict JSON, no ``` fence). action = "block_ip" only for malicious,
otherwise "no_action". EXAMPLE:
{
  "action": "no_action",
  "args": {"verdict": "benign", "connection_type": "HomeAssistant weather polling (api.met.no)"},
  "reasoning": "Source homeassistant.fritz.box; destination 157.249.81.141 resolves to api.met.no (Meteorologisk Institutt, Norway). Regular small 443 fetches every ~57 min = weather polling, not C2."
}
"""

_VERDICT_VALUES = {"malicious", "suspicious", "benign"}


def _normalize_verdict(v: Any) -> str | None:
    s = str(v or "").strip().lower()
    return s if s in _VERDICT_VALUES else None


async def _llm_assess_connection(a: dict, src_host: str | None,
                                 osint: dict, lang: str) -> dict | None:
    """Ask the LLM what a single src→dst connection is and how to rate it.
    Returns {verdict, connection_type, reasoning, action} or None on failure."""
    conn = {
        "kind": a["kind"], "score": a["score"],
        "port": a.get("top_port"), "distinct_dst_ports": a.get("dst_ports"),
        "out_bytes": a["out_bytes"], "in_bytes": a["in_bytes"],
        "upload_ratio": a["upload_ratio"], "flows": a["flows"],
        "is_new": a["is_new"], "baseline_days": a["baseline_days"],
        "dst_internal_hosts_sharing": a["dst_hosts"],
        "night_ratio": a["night_ratio"], "beacon": a.get("beacon"),
        "signals": [s.get("code") for s in (a.get("signals") or [])],
    }
    payload = {
        "source_ip": a["src"], "source_hostname": src_host,
        "destination_ip": a["dst"], "destination_country": a.get("country"),
        "connection": conn,
        "osint": osint or {},
        "allowed_actions": ["no_action", "block_ip"],
    }
    prompt = (settings.agent_conntriage_system_prompt or "").strip() or (
        CONN_TRIAGE_PROMPT_EN if lang == "en" else CONN_TRIAGE_PROMPT)
    lead = "Connection to assess:\n" if lang == "en" else "Zu bewertende Verbindung:\n"
    user_msg = lead + json.dumps(payload, indent=2, ensure_ascii=False, default=str)
    try:
        decision = await _call_llm(user_msg, system_prompt=prompt,
                                   source="connection",
                                   allowed_actions=["no_action", "block_ip"])
    except Exception as e:
        logger.warning(f"agent[conn-triage]: LLM failed for {a['src']}->{a['dst']}: {e}")
        return None
    args = decision.get("args") or {}
    verdict = _normalize_verdict(args.get("verdict")) or (
        "malicious" if decision.get("action") == "block_ip" else "suspicious")
    return {
        "verdict": verdict,
        "connection_type": str(args.get("connection_type") or "").strip()[:120],
        "reasoning": (decision.get("reasoning") or "").strip(),
        "action": decision.get("action"),
    }


def _conntriage_comment(a: dict, r: dict, lang: str) -> str:
    ct = r.get("connection_type")
    head = ct if ct else ("Verbindung" if lang == "de" else "connection")
    reason = r.get("reasoning") or ""
    tag = "Verbindung" if lang == "de" else "Connection"
    return f"agent[{tag}]: {head} — {reason}"[:1000]


def _conntriage_alert_html(a: dict, r: dict, lang: str) -> str:
    de = lang == "de"
    vmap = {"malicious": "🔴", "suspicious": "🟠", "benign": "🟢"}
    icon = vmap.get(r["verdict"], "⚠️")
    vlabel = {"malicious": "Schädlich" if de else "Malicious",
              "suspicious": "Verdächtig" if de else "Suspicious",
              "benign": "Unschädlich" if de else "Benign"}[r["verdict"]]
    country = f" ({a['country']})" if a.get("country") else ""
    ct = r.get("connection_type") or ("unbekannt" if de else "unknown")
    head = f"{icon} <b>{vlabel}</b> · " + (a["kind"].upper())
    body = (f"Host <code>{a['src']}</code> → <code>{a['dst']}</code>{country}\n"
            f"{('Typ' if de else 'Type')}: {ct}\n{r.get('reasoning','')}")
    return f"{head}\n{body}"


async def agent_connection_triage_loop(force: bool = False) -> None:
    """Daily LLM assessment of the per-connection anomalies.

    For each anomalous src→dst connection it resolves the internal source
    hostname, OSINT-enriches the external destination (reverse DNS / org / ASN /
    reputation), and asks the LLM what the connection most likely **is** — e.g.
    "HomeAssistant polling api.met.no for the weather" (benign) vs. unexplained
    beaconing/upload to an unknown host (suspicious/malicious). The reasoned
    verdict + a human-readable connection type are written on the destination IP;
    malicious/suspicious verdicts optionally raise a Telegram/Teams alarm. Human
    verdicts are never overwritten; recently-assessed destinations are skipped
    (cooldown). Meant to run once a day (see ``agent_conntriage_interval_seconds``).
    """
    if (not settings.agent_enabled or not settings.agent_conntriage_enabled) and not force:
        return

    min_score = float(settings.agent_conntriage_min_score or 0.5)
    cap = max(1, int(settings.agent_conntriage_max or 30))
    do_alarm = bool(settings.agent_conntriage_alarm)
    now = datetime.now(timezone.utc)

    from app import connection_anomaly as conn_anom
    async with async_session() as db:
        res = await conn_anom.analyze(db, hours=24, min_flows=5,
                                      overrides={"min_score": min_score})
    anomalies = res.get("anomalies") or []
    if not anomalies:
        logger.info("agent[conn-triage]: no connection anomalies to assess")
        return

    # Skip destinations with a human verdict or a fresh agent verdict (cooldown);
    # keep prior verdict values so we only alarm on a new/changed rating.
    dsts = list({a["dst"] for a in anomalies})
    async with async_session() as db:
        vrows = (await db.execute(
            select(AnomalyVerdict.ip, AnomalyVerdict.verdict,
                   AnomalyVerdict.created_by, AnomalyVerdict.updated_at)
            .where(AnomalyVerdict.ip.in_(dsts))
        )).all()
    human = {r[0] for r in vrows if (r[2] or "human") != "agent"}
    prior = {r[0]: r[1] for r in vrows}
    # Scheduled runs skip destinations re-assessed <20 h ago to save LLM calls; a
    # manual run (force) re-assesses everything so a stale rule-loop 'suspicious'
    # can be corrected to a reasoned verdict immediately. Human verdicts always win.
    cooldown = timedelta(hours=20)
    fresh = set() if force else {
        r[0] for r in vrows
        if (r[2] or "human") == "agent" and r[3] is not None
        and (now - r[3]) < cooldown}

    # Bulk-resolve the internal source hostnames.
    host_map: dict[str, dict] = {}
    try:
        from app.hostname_service import lookup_cached
        host_map = await lookup_cached(list({a["src"] for a in anomalies}))
    except Exception as e:
        logger.warning(f"agent[conn-triage]: hostname resolve failed: {e}")

    lang = _agent_lang()
    from app.notifications import notify
    processed = alarms = 0
    seen: set[str] = set()
    for a in anomalies:
        if processed >= cap:
            logger.info(f"agent[conn-triage]: cap {cap} reached, stopping")
            break
        dst = a["dst"]
        if dst in human or dst in fresh or dst in seen:
            continue
        seen.add(dst)

        osint: dict[str, Any] = {}
        if _is_public_ip(dst):
            try:
                from app.osint import lookup as osint_lookup
                osint = await osint_lookup(dst, force=False, allow_shodan=False)
            except Exception as e:
                osint = {"error": str(e)[:200]}
        src_host = (host_map.get(a["src"]) or {}).get("hostname")

        assess = await _llm_assess_connection(a, src_host, osint, lang)
        if not assess:
            continue
        processed += 1
        await _set_agent_verdict(dst, assess["verdict"], _conntriage_comment(a, assess, lang))
        if (do_alarm and assess["verdict"] in ("malicious", "suspicious")
                and prior.get(dst) != assess["verdict"]):
            await notify(_conntriage_alert_html(a, assess, lang),
                         title="Warroom · Verbindungs-Bewertung")
            alarms += 1
    logger.info(f"agent[conn-triage]: assessed {processed} connection(s), {alarms} alarm(s)")


# --- Failed-login loop (rule-based, brute-force detection) ---


_FAILED_LOGIN_SQL_FRAG = (
    "(log_type IN ('Authentication', 'Event') "
    "OR (raw_data->>'log_component') ILIKE ANY (ARRAY['%auth%','%admin%','%ssl vpn%','%ipsec%','%user portal%'])) "
    "AND ("
    "  (raw_data->>'status') ILIKE 'fail%' "
    "  OR (raw_data->>'auth_status') ILIKE 'fail%' "
    "  OR (raw_data->>'log_subtype') ILIKE '%failed%' "
    "  OR COALESCE(message, '') ILIKE '%fail%' "
    "  OR COALESCE(message, '') ILIKE '%denied%' "
    "  OR COALESCE(message, '') ILIKE '%invalid%'"
    ")"
)


def _subnet24(ip: str) -> str:
    p = ip.split(".")
    return f"{p[0]}.{p[1]}.{p[2]}.0/24" if len(p) >= 4 else ip


# Build the "external public IPv4 failed-login" WHERE body once (shared by the
# incremental cache top-up and the cold-cache fallback).
_DIST_EXTERNAL_FILTER = (
    "source_ip IS NOT NULL "
    "AND source_ip ~ '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$' "
    # A distributed brute-force is by definition public; never block an internal net.
    "AND NOT (source_ip::inet <<= inet '10.0.0.0/8' "
    "      OR source_ip::inet <<= inet '172.16.0.0/12' "
    "      OR source_ip::inet <<= inet '192.168.0.0/16' "
    "      OR source_ip::inet <<= inet '127.0.0.0/8' "
    "      OR source_ip::inet <<= inet '169.254.0.0/16' "
    "      OR source_ip::inet <<= inet '100.64.0.0/10') "
    f"AND {_FAILED_LOGIN_SQL_FRAG}"
)

_DIST_TOPUP_MAX = 2000          # new rows pulled from Postgres per loop
_DIST_PAYLOAD_ATTEMPTS = 800    # cap on individual attempts handed to the LLM
_DIST_MAX_NET_LOOKUPS = 40      # cap RDAP/OSINT network resolutions per sweep


async def _topup_login_cache(now: datetime) -> None:
    """Incrementally copy new external failed-login rows from Postgres into the
    Redis working-set cache (since the stored cursor; cold start backfills the
    retention window)."""
    cursor_iso = await login_cache.get_cursor()
    if cursor_iso:
        try:
            since = datetime.fromisoformat(cursor_iso)
        except ValueError:
            since = now - timedelta(seconds=login_cache.RETENTION_SECONDS)
    else:
        since = now - timedelta(seconds=login_cache.RETENTION_SECONDS)

    async with async_session() as db:
        rows = (await db.execute(text(f"""
            SELECT id, source_ip, user_name,
                   raw_data->>'log_component' AS component,
                   attacker_country, created_at
            FROM firewall_logs
            -- >= (not >) so rows sharing the cursor's exact timestamp aren't
            -- skipped; the uid-keyed cache members dedupe the harmless re-fetch.
            WHERE created_at >= :since
              AND {_DIST_EXTERNAL_FILTER}
            ORDER BY created_at ASC
            LIMIT :lim
        """), {"since": since, "lim": _DIST_TOPUP_MAX})).fetchall()

    attempts = [
        {"uid": r[0], "ip": r[1], "user": r[2], "component": r[3],
         "country": r[4], "ts": r[5].isoformat() if r[5] else None}
        for r in rows
    ]
    await login_cache.add_attempts(attempts, now)


async def _fallback_window_attempts(now: datetime, dist_minutes: int) -> list[dict]:
    """Direct Postgres read of the analysis window — used only when the Redis
    cache is unavailable (so the sweep still works)."""
    since = now - timedelta(minutes=max(1, dist_minutes))
    async with async_session() as db:
        rows = (await db.execute(text(f"""
            SELECT id, source_ip, user_name,
                   raw_data->>'log_component' AS component,
                   attacker_country, created_at
            FROM firewall_logs
            WHERE created_at >= :since
              AND {_DIST_EXTERNAL_FILTER}
            ORDER BY created_at DESC
            LIMIT :lim
        """), {"since": since, "lim": _DIST_TOPUP_MAX})).fetchall()
    return [
        {"uid": r[0], "ip": r[1], "user": r[2], "component": r[3],
         "country": r[4], "ts": r[5].isoformat() if r[5] else None}
        for r in rows
    ]


async def _resolve_networks(attempts: list[dict]) -> tuple[dict[str, str], dict[str, str | None]]:
    """For the busiest /24s, resolve the real allocated network (CIDR) via the
    OSINT/RDAP lookup, then map every attempt IP to the smallest resolved net it
    falls in (or its /24 when unresolved). Returns (ip→cidr, cidr→name)."""
    from app import osint as osint_mod

    cnt24: Counter = Counter()
    rep_by_24: dict[str, str] = {}
    for a in attempts:
        s = _subnet24(a["ip"])
        cnt24[s] += 1
        rep_by_24.setdefault(s, a["ip"])

    reps = [rep_by_24[s] for s, _ in cnt24.most_common(_DIST_MAX_NET_LOOKUPS)]
    results = await asyncio.gather(*[osint_mod.network_for_ip(ip) for ip in reps],
                                   return_exceptions=True)
    resolved: list[tuple[Any, str, str | None]] = []
    seen_cidr: set[str] = set()
    for res in results:
        if isinstance(res, dict) and res.get("cidr") and res["cidr"] not in seen_cidr:
            try:
                net = ipaddress.ip_network(res["cidr"], strict=False)
            except ValueError:
                continue
            seen_cidr.add(res["cidr"])
            resolved.append((net, res["cidr"], res.get("name")))

    ip_to_net: dict[str, str] = {}
    net_name: dict[str, str | None] = {}
    for a in attempts:
        ip = a["ip"]
        if ip in ip_to_net:
            continue
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            ip_to_net[ip] = _subnet24(ip)
            continue
        covering = [(n, c, nm) for (n, c, nm) in resolved if addr in n]
        if covering:
            _, cidr, nm = min(covering, key=lambda t: t[0].num_addresses)
            ip_to_net[ip] = cidr
            net_name[cidr] = nm
        else:
            ip_to_net[ip] = _subnet24(ip)
    return ip_to_net, net_name


async def _distributed_login_sweep(
    now: datetime, window_minutes: int | None, handled_ips: set[str]
) -> None:
    """Detect a distributed brute-force and, with human approval, block the whole
    attacker NETWORK.

    Reads recent failed-login attempts from the Redis working-set cache (topped
    up from ``firewall_logs``), resolves each busy /24 to its real allocated CIDR
    via the OSINT/ipinfo-RDAP lookup, groups attempts by that network, and hands
    the LLM a per-network aggregate. A network attacked by enough distinct IPs →
    ``block_subnet`` of the whole CIDR (oversized allocations are downgraded to a
    bulk-IP block). Every block requires human approval (BLOCK_ACTIONS). Covered
    IPs are marked handled; a 1h cooldown prevents re-deciding the same picture.
    """
    dist_minutes = max(
        int(settings.agent_failed_login_distributed_window_minutes or 60),
        int(window_minutes or 0),
    )
    block_cooldown = now - timedelta(hours=1)
    per_net_attempts = int(settings.agent_failed_login_distributed_attempts or 20)
    per_net_min_ips = int(settings.agent_failed_login_distributed_min_ips or 4)
    use_network = bool(getattr(settings, "agent_failed_login_network_block_enabled", True))

    async with async_session() as db:
        # Cooldown: at most one distributed decision per hour.
        recent = (await db.execute(
            select(AgentDecision.id).where(
                AgentDecision.source_type == "failed_login",
                AgentDecision.action_args["context"]["distributed_brute_force_indicator"].astext == "true",
                AgentDecision.created_at >= block_cooldown,
            )
        )).first()
        if recent is not None:
            return

    # Top up the Redis cache, then read the analysis window from it. If Redis is
    # unavailable, fall back to a direct Postgres read of the window.
    await _topup_login_cache(now)
    attempts = await login_cache.recent(dist_minutes, now)
    if attempts is None:
        attempts = await _fallback_window_attempts(now, dist_minutes)
    if not attempts:
        return

    # Map each attempt IP to its network (real CIDR when enabled, else /24).
    if use_network:
        ip_to_net, net_name = await _resolve_networks(attempts)
    else:
        ip_to_net = {a["ip"]: _subnet24(a["ip"]) for a in attempts}
        net_name = {}

    by_net: dict[str, dict] = defaultdict(
        lambda: {"attempts": 0, "ips": set(), "subnets": set(), "countries": set()})
    for a in attempts:
        cidr = ip_to_net[a["ip"]]
        g = by_net[cidr]
        g["attempts"] += 1
        g["ips"].add(a["ip"])
        g["subnets"].add(_subnet24(a["ip"]))
        if a.get("country"):
            g["countries"].add(a["country"])

    def _too_large(cidr: str) -> bool:
        try:
            return ipaddress.ip_network(cidr, strict=False).num_addresses > MAX_SUBNET_HOSTS
        except ValueError:
            return False

    networks = sorted(
        [{
            "network": cidr,
            "network_name": net_name.get(cidr),
            "attempts": g["attempts"],
            "distinct_ips": len(g["ips"]),
            "subnets24": sorted(g["subnets"])[:20],
            "countries": sorted(g["countries"])[:8],
            "too_large": _too_large(cidr),
        } for cidr, g in by_net.items()],
        key=lambda n: -n["attempts"],
    )

    attempts_payload = [
        {"ip": a["ip"], "subnet24": _subnet24(a["ip"]), "network": ip_to_net[a["ip"]],
         "user": a.get("user"), "component": a.get("component"),
         "country": a.get("country"), "ts": a.get("ts")}
        for a in attempts[:_DIST_PAYLOAD_ATTEMPTS]
    ]

    payload = {
        "window_minutes": dist_minutes,
        "total_login_attempts": len(attempts),
        "thresholds": {
            "min_attempts_per_net": per_net_attempts,
            "min_distinct_ips_per_net": per_net_min_ips,
        },
        "max_block_hosts": MAX_SUBNET_HOSTS,
        "networks": networks[:40],
        "login_attempts": attempts_payload,
        "allowed_actions": ["block_subnet", "block_ips", "no_action"],
    }
    user_msg = (
        f"Fehlgeschlagene Login-Versuche der letzten {dist_minutes} Minuten:\n"
        + json.dumps(payload, indent=2, ensure_ascii=False, default=str)
    )

    try:
        decision = await _call_llm(
            user_msg,
            system_prompt=_prompt_for("failed_login_distributed"),
            source="failed_login",
            allowed_actions=["block_subnet", "block_ips", "no_action"],
        )
    except Exception as e:
        logger.warning(f"agent[failed_login distributed]: LLM call failed: {e}")
        return

    allowed = {"block_subnet", "block_ips", "no_action"}
    action = decision["action"] if decision["action"] in allowed else "no_action"
    args = dict(decision.get("args") or {})
    reasoning = decision.get("reasoning") or ""

    # Work out covered IPs and validate args. Oversized networks are downgraded
    # to a bulk block of the observed offenders so we never persist an
    # un-executable block_subnet (execute_decision caps subnets at MAX_SUBNET_HOSTS).
    covered: set[str] = set()
    if action == "block_subnet":
        cidr = args.get("target_subnet")
        if not cidr:
            logger.warning("agent[failed_login distributed]: block_subnet without target_subnet; dropping")
            return
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            logger.warning(f"agent[failed_login distributed]: invalid target_subnet {cidr!r}; dropping")
            return
        for a in attempts:
            try:
                if ipaddress.ip_address(a["ip"]) in net:
                    covered.add(a["ip"])
            except ValueError:
                pass
        # The target net MUST contain at least one observed attacker IP — this
        # rejects an LLM-hallucinated/injected CIDR (an unobserved public range,
        # or a private net, which by construction holds none of our public
        # offenders) before it can reach the approval queue.
        if not covered:
            logger.warning(
                f"agent[failed_login distributed]: block_subnet {cidr} covers no "
                f"observed attacker IP; dropping"
            )
            return
        if net.num_addresses > MAX_SUBNET_HOSTS:
            offenders = sorted(covered)[:MAX_BULK_IPS]
            if not offenders:
                logger.warning(f"agent[failed_login distributed]: net {cidr} too large, no offenders; dropping")
                return
            logger.info(
                f"agent[failed_login distributed]: net {cidr} > /{MAX_SUBNET_HOSTS} hosts — "
                f"downgrading to block_ips of {len(offenders)} offender(s)"
            )
            reasoning = f"[Netz {cidr} zu groß → Einzel-IP-Block] {reasoning}"[:2000]
            action = "block_ips"
            args = {"target_ips": offenders}
            covered = set(offenders)
    elif action == "block_ips":
        tips = args.get("target_ips") or []
        covered = {str(ip).strip() for ip in tips if str(ip).strip()}
        if not covered:
            logger.warning("agent[failed_login distributed]: block_ips without target_ips; dropping")
            return

    await _store_rule_decision(
        source_type="failed_login", ip=None, action=action,
        reasoning=reasoning,
        args=args,
        context={
            "distributed_brute_force_indicator": True,
            "rule": "llm-distributed-network" if use_network else "llm-distributed",
            "window_minutes": dist_minutes,
            "total_login_attempts": len(attempts),
            "network_summary": networks[:30],
            "thresholds": {
                "min_attempts_per_net": per_net_attempts,
                "min_distinct_ips_per_net": per_net_min_ips,
            },
        },
    )
    handled_ips.update(covered)
    logger.info(
        f"agent[failed_login distributed]: {len(attempts)} login attempt(s) over "
        f"{len(networks)} network(s) -> {action}"
    )


# --- User-centric brute-force alert ------------------------------------------
# Aggregates failed logins by USERNAME (all source IPs + per-IP failed counts),
# lets the LLM classify bruteforce vs distributed bruteforce, and — on a hit —
# sends a Telegram warning that the user is endangered. No block: only a warning.

_USER_ALERT_KEY = "agent:userbrute:notified:"   # + lowercased username
_USER_ALERT_MAX_USERS = 10        # cap LLM calls per sweep
_USER_ALERT_IP_BREAKDOWN = 150    # cap per-user IP rows handed to the LLM


async def _user_alert_on_cooldown(user_key: str) -> bool:
    """True if we already alerted/evaluated this user within its cooldown."""
    try:
        from app.geoip_service import get_redis
        r = await get_redis()
        return bool(await r.get(_USER_ALERT_KEY + user_key))
    except Exception:
        return False


async def _mark_user_alerted(user_key: str, ttl_seconds: int) -> None:
    try:
        from app.geoip_service import get_redis
        r = await get_redis()
        await r.set(_USER_ALERT_KEY + user_key, "1", ex=max(60, ttl_seconds))
    except Exception:
        pass


async def _notify_user_endangered(user: str, classification: str, total: int,
                                  distinct_ips: int, countries: list[str],
                                  reasoning: str) -> None:
    """Fire-and-forget Telegram warning that a user is under (distributed) brute-force."""
    import html
    from app import telegram_client
    label = "Distributed Bruteforce" if classification == "distributed_bruteforce" else "Bruteforce"
    lines = [
        "🚨 <b>Warroom — User gefährdet</b>",
        f"<b>User:</b> <code>{html.escape(str(user))}</code>",
        f"<b>Einschätzung:</b> {label}",
        f"<b>Fehlversuche:</b> {total} von {distinct_ips} IP(s)",
    ]
    if countries:
        lines.append(f"<b>Länder:</b> {html.escape(', '.join(countries))}")
    if reasoning:
        lines.append("\n" + html.escape(str(reasoning)[:600]))
    await telegram_client.send_notification("\n".join(lines))


async def _user_login_bruteforce_sweep(now: datetime) -> None:
    """Group recent failed logins by username, hand each busy user's IP breakdown
    to the LLM, and Telegram-warn when it classifies a (distributed) brute-force."""
    window = max(1, int(settings.agent_failed_login_user_window_minutes or 60))
    min_attempts = max(1, int(settings.agent_failed_login_user_min_attempts or 10))
    dist_min_ips = max(2, int(settings.agent_failed_login_user_distributed_min_ips or 3))
    cooldown_min = max(1, int(settings.agent_failed_login_user_alert_cooldown_minutes or 60))

    # Ensure the Redis working-set is fresh, then read the analysis window from it
    # (fall back to a direct DB read when Redis is unavailable).
    await _topup_login_cache(now)
    attempts = await login_cache.recent(window, now)
    if attempts is None:
        attempts = await _fallback_window_attempts(now, window)
    if not attempts:
        return

    # Aggregate by username (case-insensitive — AD/SSL-VPN logins are).
    by_user: dict[str, dict] = defaultdict(
        lambda: {"display": None, "ips": Counter(), "ip_country": {}, "countries": set(), "total": 0})
    for a in attempts:
        u = (a.get("user") or "").strip()
        ip = a.get("ip")
        if not u or not ip:
            continue
        g = by_user[u.lower()]
        g["display"] = g["display"] or u
        g["ips"][ip] += 1
        g["total"] += 1
        if a.get("country"):
            g["ip_country"][ip] = a["country"]
            g["countries"].add(a["country"])

    # Busiest users first; only those above the pre-filter reach the LLM.
    candidates = sorted(
        ((k, g) for k, g in by_user.items() if g["total"] >= min_attempts),
        key=lambda kv: -kv[1]["total"],
    )[:_USER_ALERT_MAX_USERS]
    if not candidates:
        return

    for user_key, g in candidates:
        if await _user_alert_on_cooldown(user_key):
            continue
        ips: Counter = g["ips"]
        payload = {
            "username": g["display"],
            "window_minutes": window,
            "total_failed_attempts": g["total"],
            "distinct_ips": len(ips),
            "distributed_hint_min_ips": dist_min_ips,
            "ip_breakdown": [
                {"ip": ip, "failed_attempts": c, "country": g["ip_country"].get(ip)}
                for ip, c in ips.most_common(_USER_ALERT_IP_BREAKDOWN)
            ],
            "countries": sorted(g["countries"])[:12],
            "allowed_actions": ["notify", "no_action"],
        }
        user_msg = (
            f"Fehlgeschlagene Logins auf den User '{g['display']}' der letzten "
            f"{window} Minuten:\n"
            + json.dumps(payload, indent=2, ensure_ascii=False, default=str)
        )
        try:
            decision = await _call_llm(
                user_msg,
                system_prompt=_prompt_for("failed_login_user"),
                source="failed_login_user",
                allowed_actions=["notify", "no_action"],
            )
        except Exception as e:
            logger.warning(f"agent[failed_login user]: LLM call failed for {g['display']!r}: {e}")
            continue

        if decision.get("action") == "notify":
            args = decision.get("args") or {}
            classification = str(args.get("classification") or "bruteforce")
            await _notify_user_endangered(
                g["display"], classification, g["total"], len(ips),
                sorted(g["countries"])[:6],
                decision.get("reasoning") or "",
            )
            await _mark_user_alerted(user_key, cooldown_min * 60)
            logger.info(
                f"agent[failed_login user]: ALERT {classification} on user "
                f"{g['display']!r} ({g['total']} attempts / {len(ips)} IPs)"
            )
        else:
            # No alert → re-evaluate sooner than a real alert, but not every loop.
            await _mark_user_alerted(user_key, min(cooldown_min, 10) * 60)


async def agent_user_login_alert_loop(window_minutes: int | None = None, force: bool = False) -> None:
    """Standalone user-centric brute-force alerting.

    Tops up the Redis failed-login working-set, aggregates attempts by username
    (every source IP + its failed-attempt count), lets the LLM classify
    bruteforce vs distributed bruteforce, and Telegram-warns that the user is
    endangered. It only NOTIFIES (never blocks), so it runs independently of the
    blocking failed-login agent — gated solely by the master agent switch and its
    own feature flag."""
    if (not settings.agent_enabled or not settings.agent_failed_login_user_alert_enabled) and not force:
        return
    now = datetime.now(timezone.utc)
    try:
        await _user_login_bruteforce_sweep(now)
    except Exception as e:
        logger.warning(f"agent[failed_login user]: sweep failed: {e}")


async def agent_failed_login_loop(window_minutes: int | None = None, force: bool = False) -> None:
    """Two-stage failed-login workflow, both delegating the decision to the LLM:

      * **Stage 1 — Distributed sweep**: ALL failed-login attempts from the last
        ``distributed_window_minutes`` (default 60) are handed to the LLM as one
        JSON payload. The model groups them by /24, counts per subnet, and
        decides whether a coordinated (distributed) brute-force is underway →
        ``block_subnet`` (one /24) or ``block_ips`` (scattered offenders). Only
        login logs feed this stage. Covered IPs are marked handled.
      * **Stage 2 — Per-IP**: remaining fresh candidates go through the standard
        per-IP path (``agent_failed_login_system_prompt``)."""
    if (not settings.agent_enabled or not settings.agent_failed_login_enabled) and not force:
        return

    threshold = int(settings.agent_failed_login_threshold or 5)
    interval = int(settings.agent_failed_login_interval_seconds or 60)
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(minutes=int(window_minutes)) if window_minutes else now - timedelta(seconds=max(interval * 3, 180))
    # Per-IP context counts look back 24h (widened for ad-hoc admin scans).
    agg_minutes = max(1440, int(window_minutes)) if window_minutes else 1440
    h24_ago = now - timedelta(minutes=agg_minutes)
    block_cooldown = now - timedelta(hours=1)
    noaction_cooldown = now - timedelta(hours=24)

    # --- Stage 1: distributed brute-force sweep (LLM groups by /24) ------
    handled_ips: set[str] = set()
    if settings.agent_failed_login_distributed_enabled:
        await _distributed_login_sweep(now, window_minutes, handled_ips)

    # --- Step 2: per-IP rule for the rest --------------------------------
    async with async_session() as db:
        candidates_q = await db.execute(text(f"""
            SELECT DISTINCT source_ip
            FROM firewall_logs
            WHERE created_at >= :since
              AND source_ip IS NOT NULL
              AND {_FAILED_LOGIN_SQL_FRAG}
            LIMIT 100
        """), {"since": window_start})
        candidate_ips = [r[0] for r in candidates_q.fetchall() if r[0] not in handled_ips]
        candidate_ips = await _filter_candidates(db, candidate_ips, "failed_login", block_cooldown, noaction_cooldown)
        if not candidate_ips:
            return

        ctx_q = await db.execute(text(f"""
            SELECT source_ip,
                   COUNT(*) AS cnt,
                   (array_agg(DISTINCT user_name)                          FILTER (WHERE user_name IS NOT NULL))[1:5] AS users,
                   (array_agg(DISTINCT raw_data->>'log_component')         FILTER (WHERE (raw_data->>'log_component') IS NOT NULL))[1:3] AS comps,
                   MAX(attacker_country) AS country,
                   MAX(attacker_city)    AS city
            FROM firewall_logs
            WHERE created_at >= :since
              AND source_ip = ANY(:ips)
              AND {_FAILED_LOGIN_SQL_FRAG}
            GROUP BY source_ip
        """), {"since": h24_ago, "ips": candidate_ips})
        per_ip = {r[0]: r for r in ctx_q.fetchall()}

    logger.info(f"agent[failed_login]: {len(candidate_ips)} candidate IP(s) (per-IP path)")

    for ip in candidate_ips:
        row = per_ip.get(ip)
        cnt = int(row[1] or 0) if row else 0
        users = [u for u in (row[2] if row else []) if u]
        comps = [c for c in (row[3] if row else []) if c]
        country = row[4] if row else None
        city = row[5] if row else None

        context = {
            "source_ip": ip,
            "count_24h": cnt, "threshold": threshold,
            "users": users, "components": comps,
            "country": country, "city": city,
            "subnet_brute_force_indicator": False,
        }
        await _llm_decide_rule(source_type="failed_login", ip=ip, context=context)


async def test_connection() -> dict[str, Any]:
    """Cheap probe: ask the model to say 'pong' as JSON. Used by the admin UI.
    Recorded under source='test' in the LLM telemetry."""
    import time
    from app import llm_metrics

    base = (settings.agent_base_url or "").rstrip("/")
    if not base:
        return {"ok": False, "error": "agent_base_url not set"}
    model_name = settings.agent_model or "local-model"
    started = time.monotonic()
    prompt_tokens = completion_tokens = 0
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            r = await client.post(
                f"{base}/chat/completions",
                headers={
                    "Content-Type": "application/json",
                    **({"Authorization": f"Bearer {settings.agent_api_key}"} if settings.agent_api_key else {}),
                },
                json={
                    "model": model_name,
                    "temperature": 0,
                    "max_tokens": 50,
                    "messages": [
                        {"role": "system", "content": "Antworte ausschließlich mit dem JSON {\"pong\": true}."},
                        {"role": "user", "content": "ping"},
                    ],
                },
            )
        if r.status_code != 200:
            raise RuntimeError(f"HTTP {r.status_code}: {r.text[:200]}")
        data = r.json()
        usage = data.get("usage") or {}
        prompt_tokens = int(usage.get("prompt_tokens") or 0)
        completion_tokens = int(usage.get("completion_tokens") or 0)
        content = data["choices"][0]["message"]["content"]
        await llm_metrics.record(
            source="test", status="success", model=model_name,
            duration_ms=int((time.monotonic() - started) * 1000),
            prompt_tokens=prompt_tokens, completion_tokens=completion_tokens,
        )
        return {"ok": True, "model": settings.agent_model, "sample": content[:200]}
    except Exception as e:
        try:
            await llm_metrics.record(
                source="test", status="error", model=model_name,
                duration_ms=int((time.monotonic() - started) * 1000),
                prompt_tokens=prompt_tokens, completion_tokens=completion_tokens,
            )
        except Exception:
            pass
        return {"ok": False, "error": str(e)[:300]}


async def list_available_models() -> dict[str, Any]:
    """Query the LM-Studio/OpenAI-compatible /v1/models endpoint."""
    base = (settings.agent_base_url or "").rstrip("/")
    if not base:
        return {"ok": False, "error": "agent_base_url not set"}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                f"{base}/models",
                headers={"Authorization": f"Bearer {settings.agent_api_key}"} if settings.agent_api_key else {},
            )
        if r.status_code != 200:
            return {"ok": False, "error": f"HTTP {r.status_code}"}
        data = r.json() or {}
        ids = [m.get("id") for m in (data.get("data") or []) if m.get("id")]
        return {"ok": True, "models": ids}
    except Exception as e:
        return {"ok": False, "error": str(e)[:300]}

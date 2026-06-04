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

import ipaddress
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select, text

from app.config import settings
from app.database import async_session
from app.models import (
    AgentDecision, Alert, BlockedDomain, BlockedIp, BlockedUrl,
    FirewallLog, WhitelistedIp,
)

logger = logging.getLogger(__name__)

ALLOWED_ACTIONS = {
    "block_ip", "block_ips", "block_subnet", "block_domain", "block_url",
    "acknowledge", "isolate", "no_action",
}
# isolate stays manual; every "block_*" action is auto-executable (same risk
# class) so high-confidence/auto-execute settings act on them uniformly.
AUTO_EXECUTABLE_ACTIONS = {
    "block_ip", "block_ips", "block_subnet", "block_domain", "block_url",
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
    confidence: float = 0.0
    reasoning: str = ""

    @field_validator("confidence", mode="before")
    @classmethod
    def _clamp_confidence(cls, v: Any) -> float:
        try:
            return max(0.0, min(1.0, float(v)))
        except (TypeError, ValueError):
            return 0.0

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
                    "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                    "reasoning": {"type": "string"},
                },
                "required": ["action", "confidence", "reasoning"],
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


def _should_auto_execute(action: str, confidence: float | None) -> tuple[bool, str]:
    """Decide whether a fresh decision can auto-execute and tell us why.

    Two independent triggers:
      1) ``agent_auto_execute`` (master switch) → any confidence
      2) ``confidence`` ≥ ``agent_auto_execute_threshold`` (in %)

    Returns (should_execute, reason). The reason is logged so the audit
    trail explains why an action ran without human approval.
    """
    if action not in AUTO_EXECUTABLE_ACTIONS:
        return False, ""
    conf_pct = float(confidence or 0.0) * 100.0
    threshold = int(getattr(settings, "agent_auto_execute_threshold", 90) or 90)
    if settings.agent_auto_execute:
        return True, "agent_auto_execute master switch is ON"
    if conf_pct >= threshold:
        return True, f"confidence {conf_pct:.0f}% ≥ threshold {threshold}%"
    return False, ""

DEFAULT_SYSTEM_PROMPT = """Du bist ein Security-Operations-Assistent für Warroom.
Du bekommst einen einzelnen Alarm und sollst eine Empfehlung für die nächste Aktion abgeben.

Erlaubte Aktionen:
- "block_ip": Quell-IP auf die Blocklist setzen. Nur für öffentliche IPs sinnvoll. Nutze "target_ip" im args-Feld.
- "acknowledge": Alarm als gesichtet markieren (kein weiteres Handeln nötig, z.B. false positive).
- "isolate": Endpoint isolieren (nur bei aktivem Malware-/Threat-Befund mit klarem Endpoint-Bezug).
- "no_action": Mehr Daten abwarten, weder blocken noch acknowledgen.

Antworte ausschließlich mit gültigem JSON nach diesem Schema:
{
  "action": "<einer der erlaubten Werte>",
  "args": {"target_ip": "1.2.3.4"} oder {} (objekt darf leer sein),
  "confidence": 0.0-1.0,
  "reasoning": "kurz auf Deutsch, max. 2-3 Sätze"
}

Sei konservativ: hohe Konfidenz nur bei klar bösartigen Indikatoren (bekannte C2-IPs,
mehrfache failed logins von public IP, dokumentierte Malware-Treffer, etc.).
Bei privaten IPs (10.x, 172.16-31.x, 192.168.x) niemals block_ip empfehlen.

WICHTIG: Wenn "source_ip_is_whitelisted" true ist (z.B. eigene Firewall-IP), NIEMALS
block_ip empfehlen — das System würde das ohnehin verweigern, aber die Empfehlung
landet als 'failed' in der DB und verschwendet Zeit."""


# --- Default System-Prompts für die regel-getriebenen Loops ---
# Jeder dieser Prompts kann in der Admin-Seite überschrieben werden. Leer ⇒
# Fallback auf diese Defaults. Die Prompts spiegeln die früher hartcodierten
# Regel-Leitern wider, sind aber jetzt für das LLM gedacht — Schwellen kommen
# als ``thresholds`` im JSON, das LLM darf davon begründet abweichen.

DEFAULT_WAF_PROMPT = """Du bist ein WAF-Security-Analyst für Warroom.

INPUT (JSON, vom System gestellt):
  - source_ip       — angreifende öffentliche IPv4
  - context         — Aggregat-Werte zur IP (4xx/5xx-Counts in 24 h, HTTP-Statuses,
                       Hosts, Land/Stadt) und die konfigurierte Schwelle (threshold)
  - osint           — OSINT-Lookup (abuseipdb, virustotal, shodan, greynoise,
                       intelix, ipinfo). Felder können fehlen wenn ein Provider
                       keinen Key/Account hat.
  - allowed_actions — erlaubte Werte für `action`

ENTSCHEIDUNGSREGELN (in Reihenfolge prüfen, erste passende greift):
1. count_4xx_24h + count_5xx_24h >= threshold       → action="block_ip", confidence=0.95.
2. OSINT Sophos-Intelix-Treffer (security_category gesetzt ODER
   intelix.score >= 70 ODER intelix.category ∈ {Malicious, High Risk, Bad})
                                                    → action="block_ip", confidence=0.95.
3. OSINT-Treffer anderer Provider (abuseipdb.abuse_score >= 75 ODER
   virustotal.malicious >= 2 ODER greynoise.classification = "malicious")
                                                    → action="block_ip", confidence=0.85.
4. Sonst                                            → action="no_action", confidence=0.6.

AUSGABE (strikt JSON, kein ```-Fence, kein zusätzlicher Text):
{
  "action":     "<einer aus allowed_actions>",
  "args":       {} oder {"target_ip": "<source_ip>"},
  "confidence": <float 0..1>,
  "reasoning":  "<deutsche Begründung, max 2-3 Sätze, nenne die ausschlaggebenden Werte>"
}
"""


DEFAULT_IPS_PROMPT = """Du bist ein IPS/IDP-Security-Analyst für Warroom.

INPUT (JSON):
  - source_ip
  - context         — count_24h (IPS-Hits in 24h), severities (Liste), signatures,
                       categories, threshold (konfigurierte Schwelle), Land/Stadt
  - osint           — wie WAF
  - allowed_actions

ENTSCHEIDUNGSREGELN (erste passende greift):
1. severities enthält "high" oder "critical"         → action="block_ip", confidence=0.92.
   IPS klassifiziert das System bereits als Intrusion-Attempt; bei hoher
   Schwere ist Block ohne weitere Belege gerechtfertigt.
2. count_24h >= threshold                            → action="block_ip", confidence=0.95.
3. OSINT-Sophos-Intelix-Treffer                      → action="block_ip", confidence=0.95.
4. OSINT-Treffer anderer Provider                    → action="block_ip", confidence=0.85.
5. Sonst                                             → action="no_action", confidence=0.6.

AUSGABE: wie WAF (strikt JSON, ohne Fence/Vortext).
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

ENTSCHEIDUNGSREGELN (erste passende greift):
1. count_24h >= threshold                          → "block_ip", confidence=0.95.
2. OSINT Sophos-Intelix-Treffer                    → "block_ip", confidence=0.95.
3. OSINT-Treffer anderer Provider                  → "block_ip", confidence=0.85.
4. Sonst                                           → "no_action", confidence=0.6.

AUSGABE: wie WAF (strikt JSON, ohne Fence/Vortext).
"""


DEFAULT_DISTRIBUTED_LOGIN_PROMPT = """Du bist ein Analyst für VERTEILTE Brute-Force-Angriffe (Distributed Brute Force) in Warroom.

Du bekommst ALLE fehlgeschlagenen Login-Versuche der letzten Minuten als JSON.
Deine Aufgabe: Gruppiere die Versuche nach ihrem /24-Netz (die ersten drei
Oktette der `ip`, Feld `subnet24`) und ZÄHLE pro /24 die Versuche und die
Anzahl unterschiedlicher IPs. Stelle fest, ob ein /24 koordiniert Logins
angreift (verteilter Brute-Force aus einem Netzbereich).

INPUT (JSON):
  - window_minutes        — Beobachtungsfenster in Minuten
  - total_login_attempts  — Gesamtzahl übergebener Versuche
  - thresholds            — {min_attempts_per_24, min_distinct_ips_per_24}:
                            Richtwert, ab wann ein /24 als koordiniert gilt
  - login_attempts        — Liste der Versuche, je {ip, subnet24, user,
                            component, country, ts}
  - allowed_actions       — "block_subnet", "block_ips", "no_action"

VORGEHEN:
1. Aggregiere login_attempts nach subnet24. Pro /24: Versuche zählen,
   distinct IPs zählen.
2. Ein /24 gilt als verteilter Brute-Force, wenn seine Versuche
   >= thresholds.min_attempts_per_24 UND die distinct IPs
   >= thresholds.min_distinct_ips_per_24 sind (du darfst bei klarem Muster
   begründet abweichen).
3. Entscheidung:
   - Genau EIN auffälliges /24  → action="block_subnet",
       args={"target_subnet":"<a.b.c.0/24>"}, confidence ~0.9.
   - MEHRERE auffällige /24 oder gestreute IPs → action="block_ips",
       args={"target_ips":[... die auffälligen Quell-IPs ...]}, confidence ~0.88.
   - Kein /24 über der Schwelle → action="no_action", confidence ~0.6.
4. reasoning: nenne die betroffenen /24, deren Versuche und distinct IPs.

WICHTIG: Beziehe dich ausschließlich auf diese Login-Versuche. Die Whitelist
(eigene IPs) wird vom System bei der Ausführung erneut geprüft.

AUSGABE (strikt JSON, ohne Fence/Vortext):
{
  "action":     "<einer aus allowed_actions>",
  "args":       {"target_subnet":"..."} oder {"target_ips":[...]} oder {},
  "confidence": <float 0..1>,
  "reasoning":  "<deutsch, max 3 Sätze, nenne die ausschlaggebenden /24 + Zahlen>"
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

ENTSCHEIDUNGSREGELN (erste passende greift):
1. OSINT Sophos-Intelix-Treffer (security_category gesetzt ODER
   intelix.score >= 70 ODER intelix.category ∈ {Malicious, Phishing, Spam,
   High Risk, Bad})                                  → Block, confidence=0.95.
2. OSINT-Treffer anderer Provider (abuseipdb.abuse_score >= 75 ODER
   virustotal.malicious >= 2 ODER greynoise.classification = "malicious")
                                                      → Block, confidence=0.85.
3. Eindeutiger Hinweis des Operators in `note`, der bösartiges Verhalten
   belegt                                             → Block, confidence=0.8.
4. Sonst (keine belastbaren Indikatoren)              → "no_action", confidence=0.55.

Die Block-Aktion ist genau die in allowed_actions enthaltene
(block_ip / block_domain / block_url). Bei privaten/reservierten IPs niemals
block_ip empfehlen.

AUSGABE (strikt JSON, ohne Fence/Vortext):
{
  "action":     "<einer aus allowed_actions>",
  "args":       {} (Ziel wird vom System gesetzt),
  "confidence": <float 0..1>,
  "reasoning":  "<deutsche Begründung, max 2-3 Sätze, nenne die ausschlaggebenden Werte>"
}
"""


# Mapping source_type → (setting_attr, default_prompt) für den Lookup
_RULE_PROMPTS = {
    "waf":          ("agent_waf_system_prompt", DEFAULT_WAF_PROMPT),
    "ips":          ("agent_ips_system_prompt", DEFAULT_IPS_PROMPT),
    "failed_login": ("agent_failed_login_system_prompt", DEFAULT_FAILED_LOGIN_PROMPT),
    "failed_login_distributed": ("agent_failed_login_distributed_system_prompt", DEFAULT_DISTRIBUTED_LOGIN_PROMPT),
    "triage":       ("agent_triage_system_prompt", DEFAULT_TRIAGE_PROMPT),
}


def _prompt_for(source_type: str) -> str:
    attr, default = _RULE_PROMPTS[source_type]
    return (getattr(settings, attr, "") or "").strip() or default


def _allowed_actions_for_source(source_type: str) -> list[str]:
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
    return {
        "cached": osint.get("cached"),
        "abuseipdb_score": (osint.get("abuseipdb") or {}).get("abuse_score"),
        "virustotal_malicious": (osint.get("virustotal") or {}).get("malicious"),
        "intelix_security_category": (osint.get("intelix") or {}).get("security_category"),
        "intelix_category": (osint.get("intelix") or {}).get("category"),
        "intelix_score": (osint.get("intelix") or {}).get("score"),
        "greynoise_classification": (osint.get("greynoise") or {}).get("classification"),
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
    if system_prompt is None:
        system_prompt = (settings.agent_system_prompt or "").strip() or DEFAULT_SYSTEM_PROMPT
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
    try:
        confidence = float(obj.get("confidence", 0))
    except (TypeError, ValueError):
        confidence = 0.0
    confidence = max(0.0, min(1.0, confidence))
    reasoning = str(obj.get("reasoning") or "")[:2000]
    return {"action": action, "args": args, "confidence": confidence, "reasoning": reasoning}


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
        confidence=decision.get("confidence", 0.0),
        status="pending",
        model=settings.agent_model or "local-model",
    )
    async with async_session() as db:
        db.add(record)
        await db.commit()
        await db.refresh(record)

    should, why = _should_auto_execute(decision["action"], decision.get("confidence"))
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
                    db.add(BlockedIp(ip=ip, comment=comment, blocked_at=now_ts))
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
                    db.add(BlockedIp(ip=ip, comment=comment, blocked_at=now_ts))
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

            else:
                raise ValueError(f"unknown action {rec.action!r}")

            rec.status = "executed"
            rec.decided_at = datetime.now(timezone.utc)
            await db.commit()
        except Exception as e:
            rec.status = "failed"
            rec.error = str(e)[:500]
            rec.decided_at = datetime.now(timezone.utc)
            await db.commit()
            raise

    return {"status": "executed", "result": result}


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

    logger.info(f"agent[waf]: {len(candidate_ips)} candidate IP(s)")

    for ip in candidate_ips:
        row = per_ip.get(ip)
        c4 = int(row[1] or 0) if row else 0
        c5 = int(row[2] or 0) if row else 0
        statuses = [s for s in (row[3] if row else []) if s]
        hosts = [h for h in (row[4] if row else []) if h]
        country = row[5] if row else None
        city = row[6] if row else None

        context = {
            "source_ip": ip,
            "count_4xx_24h": c4,
            "count_5xx_24h": c5,
            "threshold": threshold,
            "statuses": statuses,
            "hosts": hosts,
            "country": country, "city": city,
        }

        await _llm_decide_rule(source_type="waf", ip=ip, context=context)


async def _store_rule_decision(
    source_type: str, ip: str | None, action: str, reasoning: str, confidence: float,
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
        confidence=confidence,
        status="pending",
        decided_by="agent",
        model=settings.agent_model or "local-model",
    )
    async with async_session() as db:
        db.add(rec)
        await db.commit()
        await db.refresh(rec)

    should, why = _should_auto_execute(action, confidence)
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
) -> None:
    """LLM-based replacement for the old rule ladder.

    Pulls OSINT for the IP, builds a JSON payload, calls the LLM with the
    per-source system prompt (admin-editable, falls back to the bundled
    default), and persists the parsed decision via ``_store_rule_decision``
    — which also handles auto-execute.

    ``ip`` may be None for synthetic decisions (e.g. when source_ip column
    isn't applicable). ``extra_args`` is merged into the decision's args
    field — used e.g. to inject target_subnet for the subnet-brute-force
    path so the LLM doesn't have to fabricate it.
    """
    if source_type not in _RULE_PROMPTS:
        logger.warning(f"agent: no prompt defined for source_type={source_type!r}")
        return

    # 1) OSINT enrichment — only for public IPs. Private/None → empty dict;
    #    the LLM still gets a decision-shaped payload but with no OSINT signals.
    osint: dict[str, Any] = {}
    if ip and _is_public_ip(ip):
        try:
            from app.osint import lookup as osint_lookup
            osint = await osint_lookup(ip, force=False)
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
        return

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
        return

    # 4) Action-arg merging:
    #    - extra_args (e.g. target_subnet) overrides whatever the LLM emitted
    #    - block_ip without target_ip defaults to the source IP
    action_args = {**(decision.get("args") or {}), **(extra_args or {})}
    if decision["action"] == "block_ip" and "target_ip" not in action_args and ip:
        action_args["target_ip"] = ip

    # 5) Persist via the shared helper (handles auto-execute)
    await _store_rule_decision(
        source_type=source_type, ip=ip,
        action=decision["action"],
        reasoning=decision.get("reasoning") or "",
        confidence=decision.get("confidence", 0.0),
        args=action_args,
        context={
            **context,
            "rule": "llm",
            "osint_summary": _osint_summary(osint),
        },
    )


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
        confidence=decision.get("confidence", 0.0),
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
        "confidence": decision.get("confidence", 0.0),
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


async def _distributed_login_sweep(
    now: datetime, window_minutes: int | None, handled_ips: set[str]
) -> None:
    """Hand ALL failed-login attempts of the last N minutes to the LLM as one
    JSON payload and let it group them by /24, count per subnet, and decide
    whether a distributed brute-force is underway.

    This stage looks ONLY at login logs (``_FAILED_LOGIN_SQL_FRAG``). IPs the
    resulting decision covers are added to ``handled_ips`` so the per-IP stage
    skips them. A 1h cooldown prevents re-deciding the same picture every loop.
    """
    from collections import defaultdict

    # Window: setting default (60 min), widened if an ad-hoc scan asked for more.
    dist_minutes = max(
        int(settings.agent_failed_login_distributed_window_minutes or 60),
        int(window_minutes or 0),
    )
    since = now - timedelta(minutes=max(1, dist_minutes))
    block_cooldown = now - timedelta(hours=1)
    per24_attempts = int(settings.agent_failed_login_distributed_attempts or 20)
    per24_min_ips = int(settings.agent_failed_login_distributed_min_ips or 4)
    MAX_ROWS = 1500

    async with async_session() as db:
        # Cooldown: at most one distributed decision per hour (the 60-min picture
        # changes slowly; re-running every loop would spam identical decisions).
        recent = (await db.execute(
            select(AgentDecision.id).where(
                AgentDecision.source_type == "failed_login",
                AgentDecision.action_args["context"]["distributed_brute_force_indicator"].astext == "true",
                AgentDecision.created_at >= block_cooldown,
            )
        )).first()
        if recent is not None:
            return

        rows = (await db.execute(text(f"""
            SELECT source_ip,
                   split_part(source_ip, '.', 1) || '.' ||
                   split_part(source_ip, '.', 2) || '.' ||
                   split_part(source_ip, '.', 3) || '.0/24' AS subnet24,
                   user_name,
                   raw_data->>'log_component' AS component,
                   attacker_country,
                   created_at
            FROM firewall_logs
            WHERE created_at >= :since
              AND source_ip IS NOT NULL
              AND source_ip ~ '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$'
              -- Only external sources: a distributed brute-force is by definition
              -- public, and we must never recommend blocking an internal /24.
              AND NOT (source_ip::inet <<= inet '10.0.0.0/8'
                    OR source_ip::inet <<= inet '172.16.0.0/12'
                    OR source_ip::inet <<= inet '192.168.0.0/16'
                    OR source_ip::inet <<= inet '127.0.0.0/8'
                    OR source_ip::inet <<= inet '169.254.0.0/16'
                    OR source_ip::inet <<= inet '100.64.0.0/10')
              AND {_FAILED_LOGIN_SQL_FRAG}
            ORDER BY created_at DESC
            LIMIT :lim
        """), {"since": since, "lim": MAX_ROWS})).fetchall()

    if not rows:
        return

    attempts = [
        {
            "ip": r[0], "subnet24": r[1], "user": r[2],
            "component": r[3], "country": r[4],
            "ts": r[5].isoformat() if r[5] else None,
        }
        for r in rows
    ]
    # System-side /24 summary for the audit trail / UI (the LLM derives its own
    # grouping from the raw attempts above — this is just for display).
    by24: dict[str, dict] = defaultdict(lambda: {"attempts": 0, "ips": set()})
    for a in attempts:
        s = by24[a["subnet24"]]
        s["attempts"] += 1
        s["ips"].add(a["ip"])
    summary = sorted(
        [{"subnet24": k, "attempts": v["attempts"], "distinct_ips": len(v["ips"])} for k, v in by24.items()],
        key=lambda x: -x["attempts"],
    )

    payload = {
        "window_minutes": dist_minutes,
        "total_login_attempts": len(attempts),
        "thresholds": {
            "min_attempts_per_24": per24_attempts,
            "min_distinct_ips_per_24": per24_min_ips,
        },
        "login_attempts": attempts,
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

    # Work out which observed IPs the decision covers (for handled_ips) and
    # validate the action's args before persisting.
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
    elif action == "block_ips":
        tips = args.get("target_ips") or []
        covered = {str(ip).strip() for ip in tips if str(ip).strip()}
        if not covered:
            logger.warning("agent[failed_login distributed]: block_ips without target_ips; dropping")
            return

    await _store_rule_decision(
        source_type="failed_login", ip=None, action=action,
        reasoning=decision.get("reasoning") or "",
        confidence=decision.get("confidence", 0.0),
        args=args,
        context={
            "distributed_brute_force_indicator": True,
            "rule": "llm-distributed",
            "window_minutes": dist_minutes,
            "total_login_attempts": len(attempts),
            "subnet_summary": summary[:30],
            "thresholds": {
                "min_attempts_per_24": per24_attempts,
                "min_distinct_ips_per_24": per24_min_ips,
            },
        },
    )
    handled_ips.update(covered)
    logger.info(
        f"agent[failed_login distributed]: {len(attempts)} login attempt(s) over "
        f"{len(summary)} /24(s) -> {action}"
    )


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

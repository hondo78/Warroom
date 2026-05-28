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
from sqlalchemy import select, text

from app.config import settings
from app.database import async_session
from app.models import AgentDecision, Alert, BlockedIp, FirewallLog, WhitelistedIp

logger = logging.getLogger(__name__)

ALLOWED_ACTIONS = {"block_ip", "block_subnet", "acknowledge", "isolate", "no_action"}
AUTO_EXECUTABLE_ACTIONS = {"block_ip", "block_subnet", "acknowledge"}  # isolate stays manual
# Hard upper bound for block_subnet to avoid accidentally blocking enormous
# ranges if the rule ever misfires on a /16 or /8 prefix.
MAX_SUBNET_HOSTS = 1024  # /22 IPv4

# Human-readable label for the source_type column, used in blocked_ips.comment
# so a downstream operator immediately sees where the block originated.
_SOURCE_LABELS: dict[str, str] = {
    "alert": "Alert",
    "waf":   "WAF",
    "ips":   "IPS",
    "failed_login": "Login",
}


def _source_label(source_type: str | None) -> str:
    return _SOURCE_LABELS.get((source_type or "").lower(), source_type or "?")


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


async def _call_llm(prompt: str) -> dict[str, Any]:
    base = (settings.agent_base_url or "").rstrip("/")
    if not base:
        raise RuntimeError("agent_base_url not configured")
    url = f"{base}/chat/completions"
    headers = {"Content-Type": "application/json"}
    if settings.agent_api_key:
        headers["Authorization"] = f"Bearer {settings.agent_api_key}"
    # Admin-editable system prompt; empty falls back to the bundled default
    system_prompt = (settings.agent_system_prompt or "").strip() or DEFAULT_SYSTEM_PROMPT
    payload = {
        "model": settings.agent_model or "local-model",
        "temperature": 0.2,
        "max_tokens": 600,
        "response_format": {"type": "json_object"},  # ignored by servers that don't support it
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
    }
    async with httpx.AsyncClient(timeout=60) as client:
        r = await client.post(url, headers=headers, json=payload)
    if r.status_code != 200:
        raise RuntimeError(f"LLM HTTP {r.status_code}: {r.text[:200]}")
    data = r.json()
    try:
        content = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as e:
        raise RuntimeError(f"Unexpected response shape: {e}") from e
    return _parse_decision(content)


def _parse_decision(content: str) -> dict[str, Any]:
    """Extract the JSON object from the LLM's reply, tolerant of trailing text
    or ```json fences."""
    text = (content or "").strip()
    # Strip code fences
    if text.startswith("```"):
        text = text.split("\n", 1)[-1]
        if text.endswith("```"):
            text = text[: text.rfind("```")].rstrip()
    # Find the first {...} block if there's extra noise
    if not text.startswith("{"):
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            text = text[start : end + 1]
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"LLM did not return JSON: {e}; raw={content[:200]!r}") from e

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
        return await _call_llm(prompt)
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


def _osint_is_bad(osint: dict[str, Any]) -> tuple[bool, list[str], float]:
    """Apply the OSINT-reputation rule.

    Returns ``(is_bad, reason_parts, confidence)`` where ``confidence`` is the
    recommended decision confidence based on the strongest provider hit.

    Sophos Intelix is treated as authoritative — any threat verdict from it
    (explicit security_category, "Malicious" category, or score ≥ 70) yields
    a high confidence of 0.95 so the IP auto-executes under the default
    threshold. Other providers stay at the standard 0.85.
    """
    reasons: list[str] = []
    bad = False
    confidence = 0.0

    ab = (osint or {}).get("abuseipdb") or {}
    score_ab = ab.get("abuse_score")
    if ab.get("available") and isinstance(score_ab, int) and score_ab >= 75:
        bad = True
        confidence = max(confidence, 0.85)
        reasons.append(f"AbuseIPDB {score_ab}/100")

    vt = (osint or {}).get("virustotal") or {}
    mal = vt.get("malicious") or 0
    if vt.get("available") and isinstance(mal, int) and mal >= 2:
        bad = True
        confidence = max(confidence, 0.85)
        reasons.append(f"VirusTotal {mal}× malicious")

    gn = (osint or {}).get("greynoise") or {}
    if gn.get("classification") == "malicious":
        bad = True
        confidence = max(confidence, 0.85)
        reasons.append("GreyNoise=malicious")

    intelix = (osint or {}).get("intelix") or {}
    if intelix.get("available"):
        sec_cat = (intelix.get("security_category") or "").strip()
        category = (intelix.get("category") or "").strip()
        intelix_score = intelix.get("score")
        # security_category is only populated when Sophos has classified the
        # IP under a security threat (malware, phishing, c2, …). category
        # of "Malicious" / "High Risk" is the explicit verbal verdict.
        category_says_bad = category.lower() in {"malicious", "high risk", "bad"}
        score_says_bad = isinstance(intelix_score, int) and intelix_score >= 70
        if sec_cat or category_says_bad or score_says_bad:
            bad = True
            confidence = max(confidence, 0.95)
            verdict = sec_cat or category or f"Score {intelix_score}"
            reasons.append(f"Sophos Intelix: {verdict}")

    return bad, reasons, confidence


async def agent_waf_loop(window_minutes: int | None = None, force: bool = False) -> None:
    """For each fresh WAF row with a 4xx/5xx status, check:
      1) 4+ failed requests from the same source_ip in last 24h, or
      2) OSINT reputation says malicious.
    Either triggers a block_ip recommendation; otherwise the IP gets a
    no_action audit entry (with a long cooldown so we don't spam logs).

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
        if not candidate_ips:
            return

        # Step 2: drop whitelisted + private/reserved + recently-decided IPs
        wl_q = await db.execute(
            select(WhitelistedIp.ip).where(WhitelistedIp.ip.in_(candidate_ips))
        )
        wl = set(wl_q.scalars().all())
        candidate_ips = [ip for ip in candidate_ips if ip not in wl and _is_public_ip(ip)]
        if not candidate_ips:
            return

        # block-action decisions have a 1h cooldown; no-action a 24h cooldown
        recent_q = await db.execute(
            select(AgentDecision.source_ip, AgentDecision.action, AgentDecision.created_at)
            .where(
                AgentDecision.source_type == "waf",
                AgentDecision.source_ip.in_(candidate_ips),
                AgentDecision.created_at >= noaction_cooldown,
            )
        )
        skip = set()
        for ip, action, ts in recent_q.all():
            if action == "block_ip" and ts >= block_cooldown:
                skip.add(ip)
            elif action == "no_action" and ts >= noaction_cooldown:
                skip.add(ip)
            elif action != "no_action":  # other recent decisions also enough
                skip.add(ip)
        candidate_ips = [ip for ip in candidate_ips if ip not in skip]
        if not candidate_ips:
            return

        # Step 3: per-IP 24h error counts
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

    from app.osint import lookup as osint_lookup

    for ip in candidate_ips:
        row = per_ip.get(ip)
        c4 = int(row[1] or 0) if row else 0
        c5 = int(row[2] or 0) if row else 0
        statuses = [s for s in (row[3] if row else []) if s]
        hosts = [h for h in (row[4] if row else []) if h]
        country = row[5] if row else None
        city = row[6] if row else None
        total = c4 + c5

        context = {
            "source_ip": ip,
            "count_4xx_24h": c4,
            "count_5xx_24h": c5,
            "threshold": threshold,
            "statuses": statuses,
            "hosts": hosts,
            "country": country, "city": city,
        }

        await _rule_block_or_audit(
            source_type="waf", ip=ip,
            count_24h=total, threshold=threshold,
            context=context,
        )


async def _store_rule_decision(
    source_type: str, ip: str, action: str, reasoning: str, confidence: float,
    args: dict[str, Any], context: dict[str, Any],
) -> None:
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
        model=f"rule:{source_type}",
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


async def _rule_block_or_audit(
    source_type: str, ip: str, count_24h: int, threshold: int,
    context: dict, severity_match: str | None = None,
) -> None:
    """Apply the standard ladder:
       1) severity_match → immediate block (used by IPS for high/critical)
       2) count_24h ≥ threshold → block
       3) OSINT bad reputation → block
       4) otherwise audit no_action
    """
    if severity_match:
        await _store_rule_decision(
            source_type=source_type, ip=ip,
            action="block_ip",
            reasoning=f"IPS-Hit mit Schwere '{severity_match}'.",
            confidence=0.92,
            args={"target_ip": ip},
            context={**context, "rule": "severity"},
        )
        return

    if count_24h >= threshold:
        await _store_rule_decision(
            source_type=source_type, ip=ip,
            action="block_ip",
            reasoning=f"{count_24h} Events in 24 h ≥ Schwelle {threshold}.",
            confidence=0.95,
            args={"target_ip": ip},
            context={**context, "rule": "threshold"},
        )
        return

    # OSINT fallback
    try:
        from app.osint import lookup as osint_lookup
        osint = await osint_lookup(ip, force=False)
    except Exception as e:
        logger.warning(f"agent[{source_type}]: OSINT lookup for {ip} failed: {e}")
        osint = {}

    is_bad, reasons, osint_confidence = _osint_is_bad(osint)
    if is_bad:
        await _store_rule_decision(
            source_type=source_type, ip=ip,
            action="block_ip",
            reasoning=f"Schlechte Reputation: {', '.join(reasons)}. Nur {count_24h} Events/24h (Schwelle {threshold}).",
            confidence=osint_confidence,
            args={"target_ip": ip},
            context={**context, "rule": "osint", "osint_reasons": reasons},
        )
        return

    await _store_rule_decision(
        source_type=source_type, ip=ip,
        action="no_action",
        reasoning=f"Nur {count_24h} Events in 24 h (< Schwelle {threshold}); OSINT unauffällig.",
        confidence=0.6,
        args={},
        context={**context, "rule": "neither"},
    )


async def _filter_candidates(db, candidate_ips: list[str], source_type: str,
                              block_cooldown_dt, noaction_cooldown_dt) -> list[str]:
    """Drop whitelisted + private + recently-decided IPs from the candidate list."""
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
    skip = set()
    for ip, action, ts in recent_q.all():
        if action == "block_ip" and ts >= block_cooldown_dt:
            skip.add(ip)
        elif action == "no_action" and ts >= noaction_cooldown_dt:
            skip.add(ip)
        elif action not in {"no_action", "block_ip"}:
            skip.add(ip)
    return [ip for ip in candidate_ips if ip not in skip]


# --- IPS loop (rule-based, similar to WAF but triggered by IDP events) ---


_IPS_FILTER_SQL_FRAG = (
    "(log_type IN ('IDP', 'IPS') "
    "OR (raw_data->>'log_component') ILIKE '%intrusion%' "
    "OR (raw_data->>'log_component') = 'IPS')"
)


async def agent_ips_loop(window_minutes: int | None = None, force: bool = False) -> None:
    """Per-IP rule check for IDP/IPS events. Sophos has already classified
    these as intrusion attempts, so the threshold is lower (3 by default)
    and high/critical severity triggers an immediate block."""
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

        # High/critical severity → immediate block
        sev_match = None
        for s in sevs:
            if (s or "").lower() in {"high", "critical"}:
                sev_match = s
                break

        context = {
            "source_ip": ip,
            "count_24h": cnt, "threshold": threshold,
            "severities": sevs, "signatures": sigs, "categories": cats,
            "country": country, "city": city,
        }
        await _rule_block_or_audit(
            source_type="ips", ip=ip,
            count_24h=cnt, threshold=threshold,
            context=context,
            severity_match=sev_match,
        )


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


async def agent_failed_login_loop(window_minutes: int | None = None, force: bool = False) -> None:
    """Per-IP rule check for failed-login attempts (auth/admin/SSL-VPN/IPsec/
    User-Portal). Threshold defaults to 5 — repeated auth failures from one
    public IP are a brute-force indicator.

    Also detects subnet-coordinated brute force: if a /24 emits ≥ N attempts
    from ≥ M distinct IPs in 24 h, **every** active IP in that subnet gets
    flagged for block, even if individual IPs are under their own threshold.
    """
    if (not settings.agent_enabled or not settings.agent_failed_login_enabled) and not force:
        return

    threshold = int(settings.agent_failed_login_threshold or 5)
    sn_attempts = int(settings.agent_failed_login_subnet_attempts or 10)
    sn_min_ips  = int(settings.agent_failed_login_subnet_min_ips or 3)
    interval = int(settings.agent_failed_login_interval_seconds or 60)
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(minutes=int(window_minutes)) if window_minutes else now - timedelta(seconds=max(interval * 3, 180))
    # The aggregation window is normally fixed at 24h ("in den letzten 24 h").
    # For ad-hoc admin scans the user usually wants the wider lookback to
    # cover historical bursts, so widen if explicitly requested.
    agg_minutes = max(1440, int(window_minutes)) if window_minutes else 1440
    h24_ago = now - timedelta(minutes=agg_minutes)
    block_cooldown = now - timedelta(hours=1)
    noaction_cooldown = now - timedelta(hours=24)

    # --- Step 1: subnet-level sweep ------------------------------------
    # Build /24 prefixes from the 24-h failed-login history and find the
    # ones with enough volume + breadth to qualify as coordinated.
    handled_by_subnet: set[str] = set()
    async with async_session() as db:
        sn_q = await db.execute(text(f"""
            WITH src AS (
                SELECT source_ip,
                       split_part(source_ip, '.', 1) || '.' ||
                       split_part(source_ip, '.', 2) || '.' ||
                       split_part(source_ip, '.', 3) || '.0/24' AS prefix24,
                       attacker_country, attacker_city, user_name
                FROM firewall_logs
                WHERE created_at >= :since
                  AND source_ip IS NOT NULL
                  AND source_ip ~ '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$'
                  AND {_FAILED_LOGIN_SQL_FRAG}
            )
            SELECT prefix24,
                   COUNT(*) AS attempts,
                   COUNT(DISTINCT source_ip) AS distinct_ips,
                   array_agg(DISTINCT source_ip) AS ips,
                   MAX(attacker_country) AS country,
                   (array_agg(DISTINCT user_name) FILTER (WHERE user_name IS NOT NULL))[1:5] AS users
            FROM src
            GROUP BY prefix24
            HAVING COUNT(*) >= :att AND COUNT(DISTINCT source_ip) >= :mips
            ORDER BY attempts DESC
            LIMIT 20
        """), {"since": h24_ago, "att": sn_attempts, "mips": sn_min_ips})
        suspicious_subnets = sn_q.fetchall()

        for prefix24, attempts, distinct_ips, ips, country, users in suspicious_subnets:
            # We still run the candidate filter to track which observed IPs
            # to skip in the per-IP path, but the block itself covers the
            # whole /24 — the whitelist is re-checked at execute time.
            observed_candidates = await _filter_candidates(
                db, list(ips or []), "failed_login", block_cooldown, noaction_cooldown
            )
            # Even if all observed IPs are in cooldown, we still block the
            # subnet on first detection. Skip only if we already decided on
            # this subnet recently.
            recent_subnet_decision = (await db.execute(
                select(AgentDecision).where(
                    AgentDecision.source_type == "failed_login",
                    AgentDecision.action == "block_subnet",
                    AgentDecision.action_args["target_subnet"].astext == prefix24,
                    AgentDecision.created_at >= block_cooldown,
                )
            )).scalar_one_or_none()
            if recent_subnet_decision is not None:
                # Mark observed IPs as handled so they don't re-enter the per-IP path
                for ip in observed_candidates:
                    handled_by_subnet.add(ip)
                continue

            users_clean = [u for u in (users or []) if u]
            rep_ip = (observed_candidates[0] if observed_candidates else (list(ips or []) or [None])[0])
            await _store_rule_decision(
                source_type="failed_login", ip=rep_ip,
                action="block_subnet",
                reasoning=(
                    f"Subnet-Brute-Force aus {prefix24}: {int(attempts)} Versuche "
                    f"von {int(distinct_ips)} unterschiedlichen IPs in 24 h. "
                    f"Alle Hosts im /24 werden geblockt."
                ),
                confidence=0.92,
                args={"target_subnet": prefix24, "target_ip": rep_ip},
                context={
                    "rule": "subnet_brute_force",
                    "subnet": prefix24,
                    "subnet_attempts": int(attempts),
                    "subnet_distinct_ips": int(distinct_ips),
                    "subnet_ip_sample": list(ips or [])[:20],
                    "observed_ips": observed_candidates,
                    "users": users_clean,
                    "country": country,
                },
            )
            for ip in observed_candidates:
                handled_by_subnet.add(ip)

    if suspicious_subnets:
        logger.info(f"agent[failed_login]: detected {len(suspicious_subnets)} suspicious subnet(s)")

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
        candidate_ips = [r[0] for r in candidates_q.fetchall() if r[0] not in handled_by_subnet]
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
        }
        await _rule_block_or_audit(
            source_type="failed_login", ip=ip,
            count_24h=cnt, threshold=threshold,
            context=context,
        )


async def test_connection() -> dict[str, Any]:
    """Cheap probe: ask the model to say 'pong' as JSON. Used by the admin UI."""
    base = (settings.agent_base_url or "").rstrip("/")
    if not base:
        return {"ok": False, "error": "agent_base_url not set"}
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            r = await client.post(
                f"{base}/chat/completions",
                headers={
                    "Content-Type": "application/json",
                    **({"Authorization": f"Bearer {settings.agent_api_key}"} if settings.agent_api_key else {}),
                },
                json={
                    "model": settings.agent_model or "local-model",
                    "temperature": 0,
                    "max_tokens": 50,
                    "messages": [
                        {"role": "system", "content": "Antworte ausschließlich mit dem JSON {\"pong\": true}."},
                        {"role": "user", "content": "ping"},
                    ],
                },
            )
        if r.status_code != 200:
            return {"ok": False, "error": f"HTTP {r.status_code}: {r.text[:200]}"}
        content = r.json()["choices"][0]["message"]["content"]
        return {"ok": True, "model": settings.agent_model, "sample": content[:200]}
    except Exception as e:
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

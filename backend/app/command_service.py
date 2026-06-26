"""Natural-language command interface for Warroom.

Turns a free-text message (from the in-app chat or Microsoft Teams) into one of
a fixed set of security actions and executes it:

  * block an IP / domain / FQDN / URL
  * isolate an endpoint (by hostname)
  * query the email quarantine
  * OSINT lookup for an IP or domain
  * a statistics report

Intent is resolved by the configured LLM (OpenAI-compatible /chat/completions);
a keyword parser is the fallback when the LLM is unavailable or unsure, so the
core commands work even with the agent disabled.
"""

import ipaddress
import json
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from sqlalchemy import func, select

from app.config import settings
from app.database import async_session
from app.models import (
    Alert, BlockedDomain, BlockedIp, BlockedUrl, Endpoint, Event,
    FirewallLog, WhitelistedIp,
)

logger = logging.getLogger(__name__)

TOOLS = [
    "block_ip", "block_domain", "block_url", "isolate_endpoint",
    "quarantine_list", "osint", "stats_report", "help", "unknown",
]

_SYSTEM_PROMPT = """Du bist der Befehls-Parser fuer Warroom (Security-Operations).
Ordne die Nachricht des Nutzers GENAU EINEM Tool zu und extrahiere die Argumente.
Antworte AUSSCHLIESSLICH mit JSON: {"tool": "<name>", "args": {...}}.

Verfuegbare Tools:
- block_ip         args: {"ip": "1.2.3.4"}                 IP auf die Blocklist
- block_domain     args: {"domain": "boese.example"}       Domain/FQDN blocken
- block_url        args: {"url": "http://.../pfad"}         komplette URL blocken
- isolate_endpoint args: {"host": "PC-NAME"}               Endpoint/Computer isolieren
- quarantine_list  args: {}                                Email-Quarantaene abfragen
- osint            args: {"value": "1.2.3.4", "type": "ip"|"domain"}
- stats_report     args: {"days": 7}                       Statistik-Report
- help             args: {}                                Hilfe/Uebersicht
- unknown          args: {}                                wenn unklar

Erkenne IPs, Domains/FQDNs und Hostnamen aus dem Text. blockiere/sperre + IP ->
block_ip; + Domain -> block_domain. isoliere/isolate PC -> isolate_endpoint.
quarantaene/quarantine -> quarantine_list. osint/pruefe/info zu -> osint.
report/statistik/stats/zusammenfassung -> stats_report. hilfe/help -> help.
Nur das JSON, keine Erklaerung."""

_SYSTEM_PROMPT_EN = """You are the command parser for Warroom (security operations).
Map the user's message to EXACTLY ONE tool and extract the arguments.
Reply EXCLUSIVELY with JSON: {"tool": "<name>", "args": {...}}.

Available tools:
- block_ip         args: {"ip": "1.2.3.4"}                 add IP to the blocklist
- block_domain     args: {"domain": "evil.example"}        block domain/FQDN
- block_url        args: {"url": "http://.../path"}         block a complete URL
- isolate_endpoint args: {"host": "PC-NAME"}               isolate endpoint/computer
- quarantine_list  args: {}                                query the email quarantine
- osint            args: {"value": "1.2.3.4", "type": "ip"|"domain"}
- stats_report     args: {"days": 7}                       statistics report
- help             args: {}                                help/overview
- unknown          args: {}                                when unclear

Recognise IPs, domains/FQDNs and hostnames from the text. block + IP ->
block_ip; + domain -> block_domain. isolate a PC -> isolate_endpoint.
quarantine -> quarantine_list. osint/check/info about -> osint.
report/statistics/stats/summary -> stats_report. help -> help.
Only the JSON, no explanation."""

DEFAULT_ANALYST_PROMPT = """Du bist „Warroom Analyst", ein erfahrener Security-Operations-Analyst (SOC)
als Assistent in der Warroom-Plattform (Sophos-zentriert: Firewall, Endpoints,
Email, NetFlow, M365, OSINT, Blocklisten).

Deine Aufgabe: dem Analysten im Gespräch helfen — Bedrohungen einordnen, CVEs
und Angriffsmuster erklären, IPs/Domains/Indikatoren bewerten, Logs und Alerts
interpretieren, Härtungs- und Reaktionsempfehlungen geben.

Stil: präzise, sachlich, auf Deutsch, knapp aber fundiert. Strukturiere bei
Bedarf mit kurzen Stichpunkten. Keine erfundenen Fakten — wenn du etwas nicht
sicher weißt, sage es und schlage einen nächsten Schritt vor.

Du kannst auch Aktionen auslösen: Wenn der Nutzer etwas blocken, isolieren, die
Quarantäne oder OSINT abfragen oder einen Statistik-Report möchte, weise ihn auf
die direkten Befehle hin (z.B. „blockiere 1.2.3.4", „isoliere PC-12345",
„OSINT zu 8.8.8.8", „Statistik-Report") — diese führt das System direkt aus.
Du selbst führst keine Änderungen aus, du berätst.

WICHTIG: Antworte IMMER auf Deutsch und gib NUR die finale Antwort aus. Zeige
keine Denkschritte, kein internes Reasoning, keine Meta-Kommentare wie „Here's a
thinking process" — direkt die fertige, knappe Analyse. /no_think"""

DEFAULT_ANALYST_PROMPT_EN = """You are "Warroom Analyst", an experienced security operations analyst (SOC)
acting as an assistant in the Warroom platform (Sophos-centric: firewall, endpoints,
email, NetFlow, M365, OSINT, blocklists).

Your job: help the analyst in conversation — assess threats, explain CVEs
and attack patterns, evaluate IPs/domains/indicators, interpret logs and alerts,
and give hardening and response recommendations.

Style: precise, factual, in English, concise but well-founded. When useful,
structure with short bullet points. No invented facts — if you are not sure
about something, say so and propose a next step.

You can also trigger actions: when the user wants to block or isolate something,
query the quarantine or OSINT, or wants a statistics report, point them to the
direct commands (e.g. "block 1.2.3.4", "isolate PC-12345",
"OSINT for 8.8.8.8", "statistics report") — the system executes those directly.
You yourself make no changes, you advise.

IMPORTANT: ALWAYS answer in English and output ONLY the final answer. Do not show
any reasoning steps, no internal reasoning, no meta comments like "Here's a
thinking process" — directly the finished, concise analysis. /no_think"""

_IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_DOMAIN_RE = re.compile(r"\b([a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,})\b", re.I)
_URL_RE = re.compile(r"\bhttps?://[^\s]+", re.I)


# -- intent resolution -------------------------------------------------------

def _agent_lang() -> str:
    """Resolve the configured agent prompt language ("de" or "en", default en)."""
    return "de" if getattr(settings, "agent_language", "en") == "de" else "en"


async def _llm_intent(text: str) -> dict[str, Any] | None:
    base = (settings.agent_base_url or "").rstrip("/")
    if not (settings.agent_enabled and base):
        return None
    headers = {"Content-Type": "application/json"}
    if settings.agent_api_key:
        headers["Authorization"] = f"Bearer {settings.agent_api_key}"
    payload = {
        "model": settings.agent_model or "local-model",
        "temperature": 0.0,
        "max_tokens": 400,
        "messages": [
            {"role": "system",
             "content": _SYSTEM_PROMPT_EN if _agent_lang() == "en" else _SYSTEM_PROMPT},
            {"role": "user", "content": text},
        ],
    }
    try:
        # Short timeout: this only runs for fuzzy phrasings the keyword parser
        # couldn't classify, and the chat must stay responsive.
        async with httpx.AsyncClient(timeout=12) as client:
            r = await client.post(f"{base}/chat/completions", headers=headers, json=payload)
        if r.status_code != 200:
            return None
        content = (((r.json().get("choices") or [{}])[0]).get("message") or {}).get("content") or ""
        obj = _extract_json(content)
        if obj and obj.get("tool") in TOOLS:
            return {"tool": obj["tool"], "args": obj.get("args") or {}}
    except Exception as e:
        logger.warning(f"command LLM intent failed: {e}")
    return None


def _extract_json(content: str) -> dict | None:
    """Pull the first balanced {...} object out of an LLM reply (models often
    wrap JSON in prose or emit reasoning before it)."""
    start = content.find("{")
    while start != -1:
        depth = 0
        for i in range(start, len(content)):
            c = content[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(content[start:i + 1])
                    except Exception:
                        break
        start = content.find("{", start + 1)
    return None


def _keyword_intent(text: str) -> dict[str, Any]:
    t = text.lower().strip()
    urls = _URL_RE.findall(text)
    ips = _IP_RE.findall(text)
    domains = [d for d in _DOMAIN_RE.findall(text) if not _IP_RE.match(d)]

    if any(w in t for w in ("hilfe", "help", "was kannst", "befehle", "commands")):
        return {"tool": "help", "args": {}}
    if any(w in t for w in ("report", "statistik", "stats", "zusammenfassung", "summary", "uebersicht", "übersicht")):
        m = re.search(r"(\d+)\s*tag", t) or re.search(r"(\d+)\s*day", t)
        return {"tool": "stats_report", "args": {"days": int(m.group(1)) if m else 7}}
    if "quarant" in t:
        return {"tool": "quarantine_list", "args": {}}
    if any(w in t for w in ("isolier", "isolate", "abschotten")):
        m = re.search(r"(?:isolier\w*|isolate)\s+([A-Za-z0-9._-]{2,})", text, re.I)
        host = m.group(1) if m else (domains[0] if domains else "")
        return {"tool": "isolate_endpoint", "args": {"host": host}}
    if any(w in t for w in ("block", "sperr", "blockier")):
        if urls:
            return {"tool": "block_url", "args": {"url": urls[0]}}
        if ips:
            return {"tool": "block_ip", "args": {"ip": ips[0]}}
        if domains:
            return {"tool": "block_domain", "args": {"domain": domains[0]}}
    if any(w in t for w in ("osint", "pruef", "prüf", "info zu", "reputation", "check")):
        if ips:
            return {"tool": "osint", "args": {"value": ips[0], "type": "ip"}}
        if domains:
            return {"tool": "osint", "args": {"value": domains[0], "type": "domain"}}
    # last resort: a bare indicator with no verb
    if urls:
        return {"tool": "block_url", "args": {"url": urls[0]}}
    if ips:
        return {"tool": "osint", "args": {"value": ips[0], "type": "ip"}}
    if domains:
        return {"tool": "osint", "args": {"value": domains[0], "type": "domain"}}
    return {"tool": "unknown", "args": {}}


async def resolve_intent(text: str) -> dict[str, Any]:
    # Keyword parser first — instant for clear commands ("blockiere X", "stats",
    # "quarantäne", …). The LLM is only consulted for phrasings the keyword
    # parser can't classify, so the common case stays snappy.
    kw = _keyword_intent(text)
    if kw.get("tool") != "unknown":
        return kw
    intent = await _llm_intent(text)
    if intent and intent.get("tool") != "unknown":
        return intent
    return kw


# -- handlers ----------------------------------------------------------------

def _is_public_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


async def _h_block_ip(args, actor) -> str:
    ip = (args.get("ip") or "").strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return f"WARN Keine gueltige IP erkannt ({ip or '-'})."
    async with async_session() as db:
        if (await db.execute(select(WhitelistedIp.ip).where(WhitelistedIp.ip == ip))).first():
            return f"SHIELD {ip} ist auf der Whitelist - Block abgelehnt."
        existing = (await db.execute(select(BlockedIp).where(BlockedIp.ip == ip))).scalar_one_or_none()
        if existing:
            return f"INFO {ip} ist bereits geblockt."
        db.add(BlockedIp(ip=ip, comment=f"chat[{actor}]", blocked_at=datetime.now(timezone.utc)))
        await db.commit()
    return f"OK IP **{ip}** auf die Blocklist gesetzt. Die Firewall zieht sie ueber den IOC-Feed."


async def _h_block_domain(args, actor) -> str:
    domain = (args.get("domain") or args.get("fqdn") or "").strip().lower().lstrip("*.")
    if not _DOMAIN_RE.match(domain):
        return f"WARN Keine gueltige Domain/FQDN erkannt ({domain or '-'})."
    async with async_session() as db:
        existing = (await db.execute(select(BlockedDomain).where(BlockedDomain.domain == domain))).scalar_one_or_none()
        if existing:
            return f"INFO {domain} ist bereits geblockt."
        db.add(BlockedDomain(domain=domain, comment=f"chat[{actor}]", blocked_at=datetime.now(timezone.utc)))
        await db.commit()
    return f"OK Domain/FQDN **{domain}** auf die Blocklist gesetzt."


async def _h_block_url(args, actor) -> str:
    url = (args.get("url") or "").strip()
    if not _URL_RE.match(url):
        return f"WARN Keine gueltige URL erkannt ({url or '-'})."
    async with async_session() as db:
        existing = (await db.execute(select(BlockedUrl).where(BlockedUrl.url == url))).scalar_one_or_none()
        if existing:
            return f"INFO {url} ist bereits geblockt."
        db.add(BlockedUrl(url=url, comment=f"chat[{actor}]", blocked_at=datetime.now(timezone.utc)))
        await db.commit()
    return f"OK URL **{url}** auf die Blocklist gesetzt."


async def _h_isolate(args, actor) -> str:
    host = (args.get("host") or args.get("hostname") or "").strip()
    if not host:
        return "WARN Kein Computername angegeben. Beispiel: isoliere PC-12345"
    async with async_session() as db:
        rows = (await db.execute(
            select(Endpoint).where(Endpoint.hostname.ilike(f"%{host}%"))
        )).scalars().all()
    if not rows:
        return f"WARN Kein Endpoint gefunden, der zu '{host}' passt."
    if len(rows) > 1:
        names = ", ".join(e.hostname or e.id for e in rows[:8])
        return f"WARN Mehrere Endpoints passen zu '{host}': {names}. Bitte eindeutiger angeben."
    ep = rows[0]
    try:
        from app.main import _set_endpoint_isolation
        async with async_session() as db:
            await _set_endpoint_isolation(ep.id, True, f"chat[{actor}]", db)
    except Exception as e:
        return f"WARN Isolation von {ep.hostname} fehlgeschlagen: {str(e)[:160]}"
    return f"OK Endpoint **{ep.hostname}** wird isoliert."


async def _h_quarantine(args, actor) -> str:
    try:
        from app.sophos_client import sophos_client
        items = await sophos_client.email_list_quarantine(page_size=100)
    except Exception as e:
        return f"WARN Quarantaene-Abfrage fehlgeschlagen: {str(e)[:160]}"
    if not items:
        return "Keine Nachrichten in der Quarantaene (letzte 7 Tage)."
    lines = [f"**{len(items)} Nachricht(en) in Quarantaene** (letzte 7 Tage), Auszug:"]
    def _sender(m):
        f = m.get("from")
        if isinstance(f, dict):
            la, da = f.get("localAddress"), f.get("domainAddress")
            if la and da:
                return f"{la}@{da}"
            return f.get("address") or da or "?"
        return f or m.get("envelopeSender") or "?"
    for m in items[:8]:
        subj = (m.get("subject") or "(kein Betreff)")[:60]
        lines.append(f"- {_sender(m)} : {subj}")
    if len(items) > 8:
        lines.append(f"... und {len(items) - 8} weitere.")
    return "\n".join(lines)


async def _h_osint(args, actor) -> str:
    value = (args.get("value") or "").strip()
    vtype = args.get("type") or ("ip" if _IP_RE.match(value) else "domain")
    if not value:
        return "WARN Kein Wert fuer die OSINT-Abfrage angegeben."
    try:
        from app import osint
        if vtype == "ip":
            if not _is_public_ip(value):
                return f"WARN {value} ist keine oeffentliche IP."
            d = await osint.lookup(value)  # cheap providers; Shodan stays opt-in
        else:
            d = await osint.lookup_domain(value)
    except Exception as e:
        return f"WARN OSINT-Abfrage fehlgeschlagen: {str(e)[:160]}"
    ab = (d.get("abuseipdb") or {})
    vt = (d.get("virustotal") or {})
    gn = (d.get("greynoise") or {})
    ipi = (d.get("ipinfo") or {})
    parts = [f"**OSINT - {value}**"]
    if vtype == "ip":
        loc = ", ".join(str(x) for x in [ipi.get("city"), ipi.get("country")] if x)
        if loc:
            parts.append(f"Standort: {loc} - {ipi.get('org') or ''}".strip(" -"))
        if ab.get("abuse_score") is not None:
            parts.append(f"AbuseIPDB: **{ab.get('abuse_score')}%** Confidence")
        if vt.get("malicious") is not None:
            parts.append(f"VirusTotal: {vt.get('malicious')} malicious")
        if gn.get("classification"):
            parts.append(f"GreyNoise: {gn.get('classification')}")
        parts.append("(Shodan/Ports/CVEs separat per Button im OSINT-Panel)")
    else:
        if vt.get("malicious") is not None:
            parts.append(f"VirusTotal: {vt.get('malicious')} malicious")
        dns = d.get("dns") or {}
        if dns.get("a_records"):
            parts.append(f"A-Records: {', '.join(dns['a_records'][:5])}")
    return "\n".join(parts)


async def _h_stats(args, actor) -> str:
    days = int(args.get("days") or 7)
    since = datetime.now(timezone.utc) - timedelta(days=days)
    day_ago = datetime.now(timezone.utc) - timedelta(days=1)
    async with async_session() as db:
        alerts_24h = (await db.execute(select(func.count(Alert.id)).where(Alert.created_at >= day_ago))).scalar() or 0
        high = (await db.execute(select(func.count(Alert.id)).where(
            Alert.severity.in_(["high", "critical"]), Alert.created_at >= since))).scalar() or 0
        events_24h = (await db.execute(select(func.count(Event.id)).where(Event.created_at >= day_ago))).scalar() or 0
        fw_24h = (await db.execute(select(func.count(FirewallLog.id)).where(FirewallLog.created_at >= day_ago))).scalar() or 0
        blocked_ips = (await db.execute(select(func.count(BlockedIp.ip)))).scalar() or 0
        blocked_domains = (await db.execute(select(func.count(BlockedDomain.domain)))).scalar() or 0
        isolated = (await db.execute(select(func.count(Endpoint.id)).where(Endpoint.isolation_status == "isolated"))).scalar() or 0
    # Note: deliberately no GROUP BY over firewall_logs (40GB) here — it would
    # make the chat reply take ~30s. Top-attacker drill-down lives on the map.
    return "\n".join([
        f"**Statistik-Report (letzte {days} Tage)**",
        f"- Alerts (24h): **{alerts_24h}**",
        f"- High/Critical Alerts: **{high}**",
        f"- Events (24h): {events_24h}",
        f"- Firewall-Logs (24h): {fw_24h}",
        f"- Geblockte IPs / Domains: **{blocked_ips}** / **{blocked_domains}**",
        f"- Isolierte Endpoints: **{isolated}**",
    ])


def _help_text() -> str:
    return (
        "**Warroom-Befehle** - schreib einfach natuerlich, z.B.:\n"
        "- blockiere 1.2.3.4  /  sperre boese.example  /  block http://...\n"
        "- isoliere PC-12345\n"
        "- zeig die Quarantaene\n"
        "- OSINT zu 8.8.8.8  /  pruefe domain example.com\n"
        "- Statistik-Report der letzten 7 Tage"
    )


_HANDLERS = {
    "block_ip": _h_block_ip,
    "block_domain": _h_block_domain,
    "block_url": _h_block_url,
    "isolate_endpoint": _h_isolate,
    "quarantine_list": _h_quarantine,
    "osint": _h_osint,
    "stats_report": _h_stats,
}


def _strip_reasoning(content: str) -> str:
    """Strip reasoning some models leak: <think>…</think> tags, and a leading
    English "thinking process" preamble before the actual answer."""
    content = re.sub(r"<think>.*?</think>", "", content, flags=re.S)
    content = re.sub(r"^\s*(?:here'?s?\s+(?:a|my)\s+thinking\s+process|let me think|thinking)\b.*?(?:\n\n|\Z)",
                     "", content, flags=re.S | re.I, count=1)
    return content


async def _llm_call(messages: list[dict], base: str, timeout: float = 90) -> str:
    """One /chat/completions round-trip. Returns the assistant content, or a
    'WARN …' string on transport/HTTP error (surfaced to the user as-is)."""
    headers = {"Content-Type": "application/json"}
    if settings.agent_api_key:
        headers["Authorization"] = f"Bearer {settings.agent_api_key}"
    payload = {
        "model": settings.agent_model or "local-model",
        "temperature": float(getattr(settings, "agent_temperature", 0.3) or 0.3),
        "max_tokens": int(getattr(settings, "agent_max_tokens", 1200) or 1200),
        "messages": messages,
    }
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.post(f"{base}/chat/completions", headers=headers, json=payload)
        if r.status_code != 200:
            return f"WARN LLM-Fehler (HTTP {r.status_code})."
        return (((r.json().get("choices") or [{}])[0]).get("message") or {}).get("content") or ""
    except Exception as e:
        logger.warning(f"llm_chat call failed: {e}")
        return f"WARN LLM nicht erreichbar: {str(e)[:160]}"


# How many read-only SQL round-trips the chat may take before it must answer.
_MAX_SQL_STEPS = 3


async def llm_chat(text: str, history: list[dict] | None = None) -> str | None:
    """Free-form conversation with the LLM using the analyst persona. When
    ``chat_sql_enabled`` is on, the model may issue read-only SQL queries (via a
    {"sql": …} reply) that the system runs against Postgres and feeds back before
    the model answers. Returns None when the agent/LLM isn't configured."""
    base = (settings.agent_base_url or "").rstrip("/")
    if not (settings.agent_enabled and base):
        return None

    db_enabled = bool(getattr(settings, "chat_sql_enabled", True))
    # Admin override (analyst_system_prompt) wins, else the EN/DE default per language.
    system_prompt = (getattr(settings, "analyst_system_prompt", "") or "").strip()
    if not system_prompt:
        system_prompt = (
            DEFAULT_ANALYST_PROMPT_EN if _agent_lang() == "en" else DEFAULT_ANALYST_PROMPT
        )
    if db_enabled:
        from app import sql_query
        system_prompt = f"{system_prompt}\n\n{sql_query.prompt_section()}"

    messages = [{"role": "system", "content": system_prompt}]
    for h in (history or [])[-8:]:
        if h.get("role") in ("user", "assistant") and h.get("content"):
            messages.append({"role": h["role"], "content": str(h["content"])[:4000]})
    messages.append({"role": "user", "content": text})

    for _ in range(_MAX_SQL_STEPS):
        content = _strip_reasoning(await _llm_call(messages, base))
        sql = None
        if db_enabled:
            obj = _extract_json(content)
            cand = obj.get("sql") if isinstance(obj, dict) else None
            if isinstance(cand, str) and cand.strip().lower().startswith(("select", "with")):
                sql = cand
        if sql is None:
            return content.strip() or "(keine Antwort)"
        # The model asked for data: run it read-only and feed the rows back.
        from app import sql_query
        messages.append({"role": "assistant", "content": content})
        try:
            res = await sql_query.run_select(sql)
            feedback = ("[DB-Ergebnis] " + json.dumps(res, ensure_ascii=False)[:6000]
                        + "\nBeantworte jetzt die Frage des Nutzers auf Deutsch, ohne weiteres JSON.")
        except sql_query.SqlError as e:
            feedback = f"[DB-Fehler] {e}. Korrigiere die Abfrage oder antworte ohne Datenbank."
        except Exception as e:
            logger.warning(f"chat sql failed: {e}")
            feedback = f"[DB-Fehler] Abfrage fehlgeschlagen: {str(e)[:160]}. Antworte ohne Datenbank."
        messages.append({"role": "user", "content": feedback})

    # Query budget exhausted — force a final answer with no further SQL.
    messages.append({"role": "user",
                     "content": "Gib jetzt die finale Antwort auf Deutsch, ohne weitere DB-Abfrage und ohne JSON."})
    return _strip_reasoning(await _llm_call(messages, base)).strip() or "(keine Antwort)"


async def run_command(text: str, actor: str = "chat", history: list[dict] | None = None) -> dict[str, Any]:
    """Resolve a free-text message: execute a recognised command, otherwise hold
    a conversation with the analyst-persona LLM. Returns {tool, reply}."""
    text = (text or "").strip()
    if not text:
        return {"tool": "help", "reply": _help_text()}
    intent = await resolve_intent(text)
    tool = intent.get("tool", "unknown")
    if tool == "help":
        return {"tool": "help", "reply": _help_text()}
    if tool in _HANDLERS:
        try:
            reply = await _HANDLERS[tool](intent.get("args") or {}, actor)
        except Exception as e:
            logger.exception("command handler failed")
            reply = f"WARN Ausfuehrung fehlgeschlagen: {str(e)[:200]}"
        return {"tool": tool, "reply": reply, "args": intent.get("args") or {}}

    # No command matched → free conversation with the analyst LLM.
    chat_reply = await llm_chat(text, history)
    if chat_reply is None:
        return {"tool": "unknown",
                "reply": "Befehl nicht erkannt und kein LLM konfiguriert. Schreib 'hilfe' fuer die Befehle."}
    return {"tool": "chat", "reply": chat_reply}

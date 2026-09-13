"""Backend orchestration for the Tor-only Kali box.

Flow for an agent's `tor_run`:
  1. Guard the command here (fast reject + audit) — the same rules the box
     enforces authoritatively.
  2. If it fails a guard, persist a ``blocked`` audit row and return the reason.
  3. If ``kali_require_approval`` is on, persist a ``pending`` row and return —
     a human approves it via the API before it ever runs.
  4. Otherwise (or on approval) send it to the box's /run API, which re-validates
     and executes it through Tor, and persist the result.

The target allow-list is the core safety control: an empty list means nothing is
scannable (fails closed). Egress is Tor-only (enforced by the gateway).
"""
import ipaddress
import logging
import re
import shlex
import urllib.parse
from datetime import datetime, timezone

import httpx
from sqlalchemy import select, update

from app.config import settings
from app.database import async_session
from app.models import KaliCommand

logger = logging.getLogger(__name__)

# Keep these in lock-step with kali/box/kali_api.py — the box is authoritative,
# this is the fast-reject + audit mirror.
ALLOWED_BINARIES = {
    "nmap", "whois", "dig", "host", "nslookup", "curl", "wget",
    "whatweb", "nikto", "sslscan", "wafw00f", "dnsrecon", "ncat",
}
_DANGEROUS = [
    r"-e\b", r"--exec", r"--sh-exec", r"--lua-exec",
    # [= ] and not \s* alone: nmap accepts --min-rate=90000, and a pattern that
    # only allowed a space let the "=" spelling of the very same flag through.
    r"--min-rate[= ]\s*\d{4,}", r"--max-rate[= ]\s*\d{5,}", r"-T5\b",
    # Targets that never appear as an argument: -iL reads them from a file and
    # -iR invents random internet hosts, so neither ever reaches the allow-list.
    # curl/wget read their own URLs the same way out of a config/input file.
    r"(?:^|\s)-(?:iL|iR)\b", r"(?:^|\s)-K\b",
    r"--(?:excludefile|input-file|config)\b",
    # "vuln" unescaped: as "vuln\*" it demanded a literal asterisk, so plain
    # "--script vuln" — the intrusive category this line exists to stop — walked
    # straight through while the other four blocked correctly.
    r"--script[=\s]+\S*(dos|brute|exploit|malware|vuln)",
    # "--script all" runs every category, the intrusive ones included, so the
    # line above would be decoration without this one. \s+ rather than a single
    # separator throughout: "--script  vuln" is the same command to nmap.
    r"--script[=\s]+(\S*,)*all\b",
    r"\bhydra\b|\bmedusa\b|\bpatator\b|\bhping3\b|\bslowloris\b",
    r"\bmkfs\b|\bdd\b|/dev/|\brm\b|\bchmod\b|\bchown\b",
    r"-o[NGXAS]?\s*/(etc|root|home|var|opt|usr|bin)/",
]
_DANGEROUS_RE = [re.compile(p, re.I) for p in _DANGEROUS]
_SHELL_META_RE = re.compile(r"[;&|`$><\\\n\r]|\$\(|\|\|")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](-?[a-z0-9])*\.)+[a-z]{2,}$", re.I)
_FILE_EXT = {"txt", "xml", "json", "html", "htm", "log", "out", "csv", "gnmap", "nmap"}


def _allowlist() -> list[str]:
    return [e.strip() for e in (settings.kali_target_allowlist or "").split(",") if e.strip()]


def _parse_allowlist(entries):
    nets, domains = [], []
    for e in entries or []:
        e = str(e).strip().lower()
        if not e:
            continue
        try:
            nets.append(ipaddress.ip_network(e, strict=False))
        except ValueError:
            domains.append(e.lstrip("*."))
    return nets, domains


def _host_candidate(tok: str):
    if not tok:
        return None
    if tok.startswith("-") and "=" in tok:
        tok = tok.split("=", 1)[1]
    elif tok.startswith("-"):
        return None
    if "://" in tok:
        return urllib.parse.urlparse(tok).hostname or None
    try:
        ipaddress.ip_network(tok, strict=False)
        return tok
    except ValueError:
        pass
    if _DOMAIN_RE.match(tok) and tok.rsplit(".", 1)[-1].lower() not in _FILE_EXT:
        return tok
    return None


def _host_candidates(tok: str) -> list[str]:
    """Every host hidden in one token.

    :func:`_host_candidate` answers "is this token a target", which quietly
    assumed a token carries at most one host and wears it plainly. Two common
    syntaxes break that assumption, and both were being skipped rather than
    checked:

    * ``dig``/``host``/``nslookup`` take the server to ask as ``@1.2.3.4``.
    * ``curl --resolve host:port:ip`` and ``--connect-to`` pin the real TCP
      destination, which can differ from the URL's hostname.

    A skipped token is a token that never reaches the allow-list, so those
    forms let the actual destination through unchecked — the opposite of the
    fail-closed behaviour this guard promises. Anything that looks like a host
    is returned here and checked by the caller.
    """
    if not tok:
        return []
    if tok.startswith("-") and "=" in tok:
        tok = tok.split("=", 1)[1]
    elif tok.startswith("-"):
        # A short option can carry its value glued straight on: curl -xPROXY,
        # dnsrecon -dTARGET, nikto -hHOST. Returning [] for every dash token
        # meant those destinations never reached the allow-list at all — the
        # fail-closed promise held only for targets that happened to stand as
        # their own word. Strip the flag letter and check what follows; flags
        # that carry no host (-Pn, -sT, -p80) leave a remainder that looks like
        # no host either, so nothing is lost by looking.
        tok = re.sub(r"^-{1,2}[A-Za-z]", "", tok)
        if not tok:
            return []
    tok = tok.lstrip("@")          # dig/host/nslookup server syntax
    single = _host_candidate(tok)
    if single:
        return [single]
    # host:port:ip forms (curl --resolve / --connect-to). Checked only after the
    # whole token failed to parse, so an IPv6 literal is never split apart.
    out: list[str] = []
    if ":" in tok:
        for part in tok.split(":"):
            part = part.strip()
            if not part or part.isdigit():   # empty or a port
                continue
            host = _host_candidate(part)
            if host and host not in out:
                out.append(host)
    return out

def _target_allowed(host, nets, domains) -> bool:
    host = host.strip().lower().rstrip(".")
    try:
        ip = ipaddress.ip_address(host)
        return any(ip in n for n in nets)
    except ValueError:
        pass
    return any(host == d or host.endswith("." + d) for d in domains)


# --- nmap through Tor ---------------------------------------------------------
# Port STATE cannot be determined through this gateway, and nmap does not know
# that. Every connect() is redirected to the local Tor port, which accepts before
# it knows whether the target does — so nmap reports every port "open", in
# milliseconds, with total confidence. Measured: ports 1, 7, 1234, 4711 and 55555
# all came back "open" on a host that has only 80 and 443.
#
# A scanner that invents results is worse than one that refuses, so invocations
# whose output would be fiction are rejected with the reason. What still works is
# nmap talking to a service on a port you already know — the conversation itself
# goes through Tor and is real.
_NMAP_RAW_RE = re.compile(r"(?:^|\s)-(?:sS|sU|sA|sW|sM|sN|sF|sX|sY|sZ|O|PE|PP|PM|PO)\b")
# Beyond a handful of named ports it is discovery, not a targeted check.
MAX_NMAP_PORTS = 5


def _nmap_ports(argv: list[str]) -> str | None:
    """The -p value in any of nmap's spellings, or None if absent."""
    ports = None
    for i, tok in enumerate(argv):
        if tok in ("-p", "--ports") and i + 1 < len(argv):
            ports = argv[i + 1]
        elif tok.startswith("--ports="):
            ports = tok.split("=", 1)[1]
        elif tok.startswith("-p") and len(tok) > 2:
            ports = tok[2:]
    return ports


def nmap_reason(argv: list[str]) -> str:
    """Why this nmap command cannot produce truthful output here, or ''."""
    raw = " ".join(argv)
    if _NMAP_RAW_RE.search(raw):
        return ("raw-packet scans (-sS/-sU/-O/-PE…) cannot work here: Tor carries "
                "TCP connections, not raw packets, and the box runs without root. "
                "Use -sT.")
    if "--top-ports" in raw:
        return ("--top-ports is port discovery, and port states are meaningless "
                "through Tor (every port answers 'open'). Name the ports you "
                "already know with -p instead.")
    ports = _nmap_ports(argv)
    if ports is None:
        return ("a port scan through Tor reports every port as open — the local "
                "Tor proxy accepts the connection before the target is even "
                "contacted. Give an explicit -p with up to "
                f"{MAX_NMAP_PORTS} known ports, or use whois/dig/curl/whatweb/"
                "nikto/sslscan for recon that actually works over Tor.")
    if "-" in ports or "*" in ports:
        return ("port ranges are discovery, and discovery is fiction through Tor. "
                f"List up to {MAX_NMAP_PORTS} explicit ports instead.")
    named = [p for p in ports.split(",") if p.strip()]
    if len(named) > MAX_NMAP_PORTS:
        return (f"{len(named)} ports is discovery, not a targeted check — at most "
                f"{MAX_NMAP_PORTS} explicit ports, whose state Tor cannot tell you "
                "anyway.")
    if "-Pn" not in argv:
        return ("host discovery needs raw packets, which Tor cannot carry and the "
                "box may not send — add -Pn.")
    return ""


def guard(command: str) -> tuple[list[str] | None, list[str], str]:
    """Return (argv, targets, '') if allowed, else (None, targets, reason)."""
    raw = (command or "").strip()
    if not raw:
        return None, [], "empty command"
    if _SHELL_META_RE.search(raw):
        return None, [], "shell metacharacters are not allowed (single command only)"
    try:
        argv = shlex.split(raw)
    except ValueError as e:
        return None, [], f"unparseable command: {e}"
    if not argv:
        return None, [], "empty command"
    binary = argv[0].rsplit("/", 1)[-1]
    if binary not in ALLOWED_BINARIES:
        return None, [], f"binary '{binary}' is not allowed (allowed: {', '.join(sorted(ALLOWED_BINARIES))})"
    # Matched against the PARSED argv as well as the raw text: shlex strips
    # quoting, so `-""e` is written as no pattern's match yet reaches execve as
    # `-e` — the ncat reverse-shell flag (and -T5, --script vuln, …) walked
    # straight through every rule above. Checking what actually runs closes that
    # for all of them at once; the raw string stays in the check because quoting
    # can also split a pattern that only the unparsed text still shows.
    for rx in _DANGEROUS_RE:
        if rx.search(raw) or rx.search(" ".join(argv)):
            return None, [], f"command matches a blocked pattern: {rx.pattern}"
    if binary == "nmap":
        why = nmap_reason(argv)
        if why:
            return None, [], f"nmap: {why}"
    nets, domains = _parse_allowlist(_allowlist())
    targets = []
    for tok in argv[1:]:
        for host in _host_candidates(tok):
            targets.append(host)
            if not _target_allowed(host, nets, domains):
                return None, targets, f"target '{host}' is not in the allowlist"
    # No recognisable target means the allow-list was never applied to anything:
    # the loop above passes vacuously and the command runs unchecked. A guard
    # that fails open on the one case it cannot parse is not a guard, so a
    # command whose destination we cannot see is refused.
    if not targets:
        return None, targets, ("no target recognised in the command — every "
                               "command must name a host from the allowlist")
    return argv, targets, ""


async def _call_box(command: str) -> dict:
    """POST the command to the box's guarded /run API (it re-validates)."""
    url = (settings.kali_api_url or "http://tor:8081").rstrip("/") + "/run"
    headers = {"Authorization": f"Bearer {settings.kali_api_token or ''}"}
    body = {"command": command, "allowlist": _allowlist(),
            "timeout": max(1, int(settings.kali_timeout_seconds or 120))}
    async with httpx.AsyncClient(timeout=max(30, int(settings.kali_timeout_seconds or 120) + 30)) as c:
        r = await c.post(url, json=body, headers=headers)
        r.raise_for_status()
        return r.json()


async def get_exit_ip() -> dict:
    url = (settings.kali_api_url or "http://tor:8081").rstrip("/") + "/exit-ip"
    headers = {"Authorization": f"Bearer {settings.kali_api_token or ''}"}
    async with httpx.AsyncClient(timeout=40) as c:
        r = await c.get(url, headers=headers)
        r.raise_for_status()
        return r.json()


async def _run_and_store(rec_id: int, command: str) -> dict:
    """Execute an approved/auto command on the box and persist the outcome."""
    exit_ip = None
    try:
        exit_ip = (await get_exit_ip()).get("exit_ip")
    except Exception:
        pass
    try:
        res = await _call_box(command)
    except Exception as e:
        async with async_session() as db:
            rec = await db.get(KaliCommand, rec_id)
            if rec:
                rec.status = "error"
                rec.reason = f"box call failed: {str(e)[:400]}"
                rec.tor_exit_ip = exit_ip
                rec.decided_at = datetime.now(timezone.utc)
                await db.commit()
        return {"id": rec_id, "status": "error", "error": str(e)[:400]}

    async with async_session() as db:
        rec = await db.get(KaliCommand, rec_id)
        if rec:
            if res.get("blocked"):
                rec.status = "blocked"
                rec.reason = res.get("reason")
            else:
                rec.status = "done"
                rec.exit_code = res.get("exit_code")
                rec.stdout = res.get("stdout")
                rec.stderr = res.get("stderr") or res.get("error")
            rec.tor_exit_ip = exit_ip
            rec.decided_at = datetime.now(timezone.utc)
            await db.commit()
    return {"id": rec_id, "status": (rec.status if rec else "done"),
            "exit_code": res.get("exit_code"), "tor_exit_ip": exit_ip,
            "stdout": res.get("stdout"), "stderr": res.get("stderr") or res.get("error"),
            "blocked": res.get("blocked"), "reason": res.get("reason")}


async def submit_command(command: str, actor: str = "agent", *,
                         require_approval: bool | None = None) -> dict:
    """Entry point for the MCP tool and the operator console. Guards, audits,
    and either blocks, queues for approval, or runs immediately.

    ``require_approval`` defaults to the ``kali_require_approval`` setting.
    The console passes ``False`` on purpose: that setting exists so an *agent*
    cannot act unattended, and a human typing the command already is the
    decision it asks for — queueing it for the same person to click again would
    be friction, not review. Everything that actually protects the box (target
    allow-list, binary allow-list, dangerous-pattern rules) still applies, and
    the audit row records ``actor`` so the two paths stay distinguishable."""
    argv, targets, reason = guard(command)
    tcsv = ",".join(targets) if targets else None
    if argv is None:
        async with async_session() as db:
            rec = KaliCommand(command=command[:8000], targets=tcsv, actor=actor,
                              status="blocked", reason=reason)
            db.add(rec)
            await db.commit()
            await db.refresh(rec)
        return {"id": rec.id, "status": "blocked", "reason": reason}

    needs_approval = (settings.kali_require_approval if require_approval is None
                      else require_approval)
    if needs_approval:
        async with async_session() as db:
            rec = KaliCommand(command=command[:8000], targets=tcsv, actor=actor, status="pending")
            db.add(rec)
            await db.commit()
            await db.refresh(rec)
        return {"id": rec.id, "status": "pending",
                "note": "queued for human approval; an operator must approve it before it runs",
                "targets": targets}

    # An explicit require_approval=False means a human made the call by sending
    # it; only the policy-driven path is genuinely "auto".
    decided_by = actor if require_approval is False else "auto"
    async with async_session() as db:
        rec = KaliCommand(command=command[:8000], targets=tcsv, actor=actor, status="approved",
                          decided_by=decided_by, decided_at=datetime.now(timezone.utc))
        db.add(rec)
        await db.commit()
        await db.refresh(rec)
        rec_id = rec.id
    return await _run_and_store(rec_id, command)


async def _claim(cmd_id: int, new_status: str, decided_by: str) -> dict | None:
    """Move a pending command to ``new_status``, once.

    Read-then-write was a race with real consequences here: two approvals
    arriving together (two tabs, two operators, a retried request) both saw
    ``pending`` before either committed, and the intrusive command ran twice
    while the second run's output overwrote the first. The UPDATE carries the
    precondition, so exactly one of them can match a row — the loser is told
    the command is no longer pending, which is true.

    Returns the command string on success, or an error dict."""
    async with async_session() as db:
        result = await db.execute(
            update(KaliCommand)
            .where(KaliCommand.id == cmd_id, KaliCommand.status == "pending")
            .values(status=new_status, decided_by=decided_by,
                    decided_at=datetime.now(timezone.utc))
            .returning(KaliCommand.command)
        )
        row = result.first()
        await db.commit()
        if row is not None:
            return {"command": row[0]}

        # Nothing matched: either no such command, or somebody got there first.
        rec = await db.get(KaliCommand, cmd_id)
        if rec is None:
            return {"error": "not found"}
        return {"error": f"command is '{rec.status}', not pending"}


async def approve_command(cmd_id: int, decided_by: str = "human") -> dict:
    claimed = await _claim(cmd_id, "approved", decided_by)
    if "error" in claimed:
        return claimed
    return await _run_and_store(cmd_id, claimed["command"])


async def reject_command(cmd_id: int, decided_by: str = "human") -> dict:
    claimed = await _claim(cmd_id, "rejected", decided_by)
    if "error" in claimed:
        return claimed
    return {"id": cmd_id, "status": "rejected"}

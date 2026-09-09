#!/usr/bin/env python3
"""Guarded command API for the Tor-only Kali box.

This is the AUTHORITATIVE guard: even though the Warroom backend validates a
command before sending it, this process re-validates every request right before
execution, so a bug or bypass upstream can't turn the box into an open shell.

Hard rules (all must pass):
  * Bearer token must match KALI_API_TOKEN.
  * No shell metacharacters — the command is a single program invocation,
    never a shell pipeline (no ; | & ` $ ( ) < > \\ newlines).
  * The program (argv[0]) must be in ALLOWED_BINARIES.
  * Every host/IP/URL-looking argument must be inside the target allowlist
    (CIDRs / IPs / domain suffixes). A target that isn't allow-listed is
    refused — this is what stops scanning arbitrary victims. The caller sends
    the operator's list with each request; set KALI_TARGET_ALLOWLIST on this
    container as well and a target must satisfy BOTH, so a caller that is buggy
    or compromised cannot widen its own limits by sending a longer list.
  * No argument may match a dangerous-pattern blocklist (reverse shells,
    flood/DoS rates, intrusive/brute/exploit scripts, filesystem writes to
    sensitive paths, …).

The box itself only reaches the internet through Tor (enforced by the gateway's
iptables), so egress is anonymized regardless of what runs here.
"""
import ipaddress
import json
import os
import re
import shlex
import subprocess
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN = (os.environ.get("KALI_API_TOKEN") or "").strip()
# Optional second allow-list, owned by the box instead of by its caller. Empty
# means "the caller's list is the only one", which is the historical behaviour
# and keeps an existing deployment working unchanged.
BOX_ALLOWLIST = [e.strip() for e in
                 (os.environ.get("KALI_TARGET_ALLOWLIST") or "").split(",") if e.strip()]
PORT = int(os.environ.get("KALI_API_PORT") or "8081")
MAX_OUTPUT = 200_000          # cap stdout/stderr returned
MAX_TIMEOUT = 3600

ALLOWED_BINARIES = {
    "nmap", "whois", "dig", "host", "nslookup", "curl", "wget",
    "whatweb", "nikto", "sslscan", "wafw00f", "dnsrecon", "ncat",
}

# Substrings/patterns that are refused regardless of target. Case-insensitive.
_DANGEROUS = [
    r"-e\b", r"--exec", r"--sh-exec", r"--lua-exec",          # ncat reverse shells
    # [= ] and not \s* alone: nmap accepts --min-rate=90000, and a pattern that
    # only allowed a space let the "=" spelling of the same flag straight past.
    r"--min-rate[= ]\s*\d{4,}", r"--max-rate[= ]\s*\d{5,}",    # nmap flood rates
    r"-T5\b",                                                   # nmap insane timing
    # Targets that never appear as an argument: -iL reads them from a file and
    # -iR invents random internet hosts, so neither ever reaches the allow-list.
    # curl/wget read their own URLs the same way out of a config/input file.
    r"(?:^|\s)-(?:iL|iR)\b", r"(?:^|\s)-K\b",                  # targets from a file
    r"--(?:excludefile|input-file|config)\b",
    # "vuln" unescaped: "vuln\*" demanded a literal asterisk, so plain
    # "--script vuln" slipped past the very category this blocks.
    r"--script[=\s]+\S*(dos|brute|exploit|malware|vuln)",     # intrusive NSE
    # "--script all" runs every category, intrusive ones included, so the line
    # above would be decoration without this one. \s+ rather than a single
    # separator throughout: "--script  vuln" is the same command to nmap.
    r"--script[=\s]+(\S*,)*all\b",                            # the lot
    r"\bhydra\b|\bmedusa\b|\bpatator\b|\bhping3\b|\bslowloris\b",
    r"\bmkfs\b|\bdd\b|/dev/|\brm\b|\bchmod\b|\bchown\b",       # local damage
    r"-o[NGXAS]?\s*/(etc|root|home|var|opt|usr|bin)/",         # writes outside tmp
]
_DANGEROUS_RE = [re.compile(p, re.I) for p in _DANGEROUS]

_SHELL_META_RE = re.compile(r"[;&|`$><\\\n\r]|\$\(|\|\|")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](-?[a-z0-9])*\.)+[a-z]{2,}$", re.I)
_FILE_EXT = {"txt", "xml", "json", "html", "htm", "log", "out", "csv", "gnmap", "nmap"}


def _host_candidate(tok: str) -> str | None:
    """Return the host/IP the token targets, or None if it isn't a target."""
    if not tok:
        return None
    # --flag=value → inspect the value part too.
    if tok.startswith("-") and "=" in tok:
        tok = tok.split("=", 1)[1]
    elif tok.startswith("-"):
        return None
    # URL → host.
    if "://" in tok:
        host = urllib.parse.urlparse(tok).hostname
        return host or None
    # bare IP / CIDR
    try:
        ipaddress.ip_network(tok, strict=False)
        return tok
    except ValueError:
        pass
    # bare hostname (exclude obvious filenames like scan.txt)
    if _DOMAIN_RE.match(tok):
        if tok.rsplit(".", 1)[-1].lower() in _FILE_EXT:
            return None
        return tok
    return None


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

    Kept in sync with backend/app/kali_client.py by hand, like the rest of this
    guard: the box ships standalone and cannot import the backend.
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
    out = []
    if ":" in tok:
        for part in tok.split(":"):
            part = part.strip()
            if not part or part.isdigit():   # empty or a port
                continue
            host = _host_candidate(part)
            if host and host not in out:
                out.append(host)
    return out


def _target_allowed(host: str, nets, domains) -> bool:
    host = host.strip().lower().rstrip(".")
    try:
        ip = ipaddress.ip_address(host)
        return any(ip in n for n in nets)
    except ValueError:
        pass
    return any(host == d or host.endswith("." + d) for d in domains)


# --- nmap through Tor ---------------------------------------------------------
# Keep in lock-step with backend/app/kali_client.py. Port states are not
# observable through the transparent Tor proxy: the local Tor port accepts every
# connection before the target is contacted, so nmap reports EVERY port "open" in
# milliseconds. Measured against a host with only 80/443 open, ports 1, 7, 1234,
# 4711 and 55555 all came back "open". Refusing beats inventing.
_NMAP_RAW_RE = re.compile(r"(?:^|\s)-(?:sS|sU|sA|sW|sM|sN|sF|sX|sY|sZ|O|PE|PP|PM|PO)\b")
MAX_NMAP_PORTS = 5


def _nmap_ports(argv):
    ports = None
    for i, tok in enumerate(argv):
        if tok in ("-p", "--ports") and i + 1 < len(argv):
            ports = argv[i + 1]
        elif tok.startswith("--ports="):
            ports = tok.split("=", 1)[1]
        elif tok.startswith("-p") and len(tok) > 2:
            ports = tok[2:]
    return ports


def nmap_reason(argv) -> str:
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


def validate(command: str, allowlist) -> tuple[list[str] | None, str]:
    """Return (argv, '') if allowed, else (None, reason)."""
    raw = (command or "").strip()
    if not raw:
        return None, "empty command"
    if _SHELL_META_RE.search(raw):
        return None, "shell metacharacters are not allowed (single command only)"
    try:
        argv = shlex.split(raw)
    except ValueError as e:
        return None, f"unparseable command: {e}"
    if not argv:
        return None, "empty command"
    binary = os.path.basename(argv[0])
    if binary not in ALLOWED_BINARIES:
        return None, f"binary '{binary}' is not allowed (allowed: {', '.join(sorted(ALLOWED_BINARIES))})"
    # Matched against the PARSED argv as well as the raw text: shlex strips
    # quoting, so `-""e` is written as no pattern's match yet reaches execve as
    # `-e` — the ncat reverse-shell flag (and -T5, --script vuln, …) walked
    # straight through every rule above. Checking what actually runs closes that
    # for all of them at once; the raw string stays in the check because quoting
    # can also split a pattern that only the unparsed text still shows.
    for rx in _DANGEROUS_RE:
        if rx.search(raw) or rx.search(" ".join(argv)):
            return None, f"command matches a blocked pattern: {rx.pattern}"
    if binary == "nmap":
        why = nmap_reason(argv)
        if why:
            return None, f"nmap: {why}"
    nets, domains = _parse_allowlist(allowlist)
    box_nets, box_domains = _parse_allowlist(BOX_ALLOWLIST)
    seen = 0
    for tok in argv[1:]:
        for host in _host_candidates(tok):
            seen += 1
            if not _target_allowed(host, nets, domains):
                return None, f"target '{host}' is not in the allowlist"
            if BOX_ALLOWLIST and not _target_allowed(host, box_nets, box_domains):
                return None, (f"target '{host}' is not in this box's own "
                              "allowlist (KALI_TARGET_ALLOWLIST)")
    # No recognisable target means the allow-list was never applied to anything:
    # the loop above passes vacuously and the command runs unchecked. A guard
    # that fails open on the one case it cannot parse is not a guard, so a
    # command whose destination we cannot see is refused.
    if not seen:
        return None, ("no target recognised in the command — every command must "
                      "name a host from the allowlist")
    return argv, ""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet default logging
        pass

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _auth_ok(self) -> bool:
        if not TOKEN:
            return False
        h = self.headers.get("Authorization", "")
        return h.startswith("Bearer ") and h[7:].strip() == TOKEN

    def do_GET(self):
        if self.path == "/health":
            return self._send(200, {"ok": True})
        if not self._auth_ok():
            return self._send(401, {"error": "unauthorized"})
        if self.path == "/exit-ip":
            try:
                out = subprocess.run(
                    ["curl", "-s", "--max-time", "25", "https://check.torproject.org/api/ip"],
                    capture_output=True, text=True, timeout=30)
                data = json.loads(out.stdout or "{}")
                return self._send(200, {"exit_ip": data.get("IP"), "is_tor": data.get("IsTor")})
            except Exception as e:
                return self._send(502, {"error": f"exit-ip check failed: {e}"})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._auth_ok():
            return self._send(401, {"error": "unauthorized"})
        if self.path != "/run":
            return self._send(404, {"error": "not found"})
        try:
            length = int(self.headers.get("Content-Length") or 0)
            payload = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return self._send(400, {"error": "invalid JSON"})
        command = payload.get("command") or ""
        allowlist = payload.get("allowlist") or []
        timeout = max(1, min(int(payload.get("timeout") or 120), MAX_TIMEOUT))

        argv, reason = validate(command, allowlist)
        if argv is None:
            return self._send(200, {"blocked": True, "reason": reason})
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
            return self._send(200, {
                "blocked": False,
                "exit_code": proc.returncode,
                "stdout": (proc.stdout or "")[:MAX_OUTPUT],
                "stderr": (proc.stderr or "")[:MAX_OUTPUT],
                "argv": argv,
            })
        except subprocess.TimeoutExpired:
            return self._send(200, {"blocked": False, "exit_code": None,
                                    "error": f"timed out after {timeout}s", "argv": argv})
        except Exception as e:
            return self._send(200, {"blocked": False, "exit_code": None,
                                    "error": str(e)[:500], "argv": argv})


if __name__ == "__main__":
    if not TOKEN:
        raise SystemExit("KALI_API_TOKEN is required")
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()

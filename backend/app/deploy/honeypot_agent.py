#!/usr/bin/env python3
"""Warroom honeypot agent — deploy on a remote Linux host.

Simulates a handful of the most-attacked network services (SSH, Telnet, FTP,
HTTP, RDP, SMB, MySQL, VNC, …). These are low-interaction *decoys*: nothing
here is a real service, so ANY connection is suspicious. Every access is
reported to Warroom, which geo-enriches it and raises a Telegram/Teams alert.

Managed by Warroom: on each heartbeat the agent fetches its desired service
config and starts/stops listeners to match — enable/disable services from the
Warroom UI without touching the host.

Stdlib only (asyncio + urllib) — no pip install. Run as root to bind ports < 1024.

    curl -fsSL https://<warroom>/api/honeypot/agent/download -o honeypot_agent.py
    sudo WARROOM_URL=https://<warroom> HONEYPOT_TOKEN=hp_xxxx python3 honeypot_agent.py

Env: WARROOM_URL, HONEYPOT_TOKEN (required); HONEYPOT_BIND (default 0.0.0.0).
TLS: HONEYPOT_TLS_VERIFY (default 1) — set 0 to skip cert verification when
Warroom sits behind a self-signed reverse proxy; or HONEYPOT_CA=/path/to/ca.pem
to verify against that proxy's CA instead (preferred over disabling).
"""
import asyncio
import ctypes
import json
import os
import platform
import pwd
import socket
import ssl
import struct
import sys
import time
import urllib.error
import urllib.request

WARROOM_URL = os.environ.get("WARROOM_URL", "").rstrip("/")
TOKEN = os.environ.get("HONEYPOT_TOKEN", "")
BIND = os.environ.get("HONEYPOT_BIND", "0.0.0.0")
TLS_VERIFY = os.environ.get("HONEYPOT_TLS_VERIFY", "1") not in ("0", "false", "no")
CA_FILE = os.environ.get("HONEYPOT_CA", "").strip()
AGENT_VERSION = "1.4"

if not WARROOM_URL or not TOKEN:
    print("ERROR: set WARROOM_URL and HONEYPOT_TOKEN", file=sys.stderr)
    sys.exit(2)

READ_TIMEOUT = 8.0
MAX_READ = 4096

_event_q: asyncio.Queue = asyncio.Queue(maxsize=10000)
_servers: dict[str, asyncio.AbstractServer] = {}   # service -> server
_ports: dict[str, int] = {}                         # service -> bound port


def _safe(data: bytes, limit: int = 800) -> str:
    """Bytes → a JSON-safe, printable-ish string (escaping control chars)."""
    if not data:
        return ""
    return data[:limit].decode("utf-8", "backslashreplace")


async def _emit(service, dest_port, peer, event_type="connect", payload=None):
    ip, port = (peer[0], peer[1]) if peer else (None, None)
    ev = {"service": service, "event_type": event_type,
          "source_ip": ip, "source_port": port, "dest_port": dest_port,
          "payload": payload or {}}
    try:
        _event_q.put_nowait(ev)
    except asyncio.QueueFull:
        pass


async def _read(reader, n=MAX_READ, timeout=READ_TIMEOUT):
    try:
        return await asyncio.wait_for(reader.read(n), timeout=timeout)
    except Exception:
        return b""


# --- per-service handlers -----------------------------------------------------
# Each returns after logging; handlers must never raise (a bad client must not
# take down a listener).

async def _h_generic(service, port, banner=None):
    async def handler(reader, writer):
        peer = writer.get_extra_info("peername")
        try:
            if banner:
                writer.write(banner)
                await writer.drain()
            data = await _read(reader)
            payload = {"data": _safe(data)} if data else {}
            await _emit(service, port, peer, payload=payload)
        except Exception:
            await _emit(service, port, peer)
        finally:
            try: writer.close()
            except Exception: pass
    return handler


async def _h_ssh(port):
    async def handler(reader, writer):
        peer = writer.get_extra_info("peername")
        try:
            writer.write(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n")
            await writer.drain()
            data = await _read(reader)
            await _emit("ssh", port, peer, payload={"client": _safe(data, 200)})
        except Exception:
            await _emit("ssh", port, peer)
        finally:
            try: writer.close()
            except Exception: pass
    return handler


async def _h_telnet(port):
    async def handler(reader, writer):
        peer = writer.get_extra_info("peername")
        creds = {}
        try:
            writer.write(b"\xff\xfb\x01login: ")   # IAC WILL ECHO + prompt
            await writer.drain()
            user = await _read(reader, 128)
            writer.write(b"Password: ")
            await writer.drain()
            pw = await _read(reader, 128)
            creds = {"username": _safe(user, 64).strip(), "password": _safe(pw, 64).strip()}
            writer.write(b"\r\nLogin incorrect\r\n")
            await writer.drain()
            await _emit("telnet", port, peer, "login", creds)
        except Exception:
            await _emit("telnet", port, peer, "login", creds)
        finally:
            try: writer.close()
            except Exception: pass
    return handler


async def _h_ftp(port):
    async def handler(reader, writer):
        peer = writer.get_extra_info("peername")
        creds = {}
        try:
            writer.write(b"220 (vsFTPd 3.0.3)\r\n")
            await writer.drain()
            for _ in range(4):
                line = await _read(reader, 256)
                if not line:
                    break
                s = _safe(line, 128).strip()
                up = s.upper()
                if up.startswith("USER"):
                    creds["username"] = s[5:].strip()
                    writer.write(b"331 Please specify the password.\r\n")
                elif up.startswith("PASS"):
                    creds["password"] = s[5:].strip()
                    writer.write(b"530 Login incorrect.\r\n")
                    await writer.drain()
                    break
                else:
                    writer.write(b"530 Please login with USER and PASS.\r\n")
                await writer.drain()
            await _emit("ftp", port, peer, "login" if creds else "connect", creds)
        except Exception:
            await _emit("ftp", port, peer, "login", creds)
        finally:
            try: writer.close()
            except Exception: pass
    return handler


async def _h_http(port, service="http"):
    PAGE = (b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\n"
            b"Connection: close\r\nContent-Length: 120\r\n\r\n"
            b"<html><body><h3>Router Admin</h3><form method=post>"
            b"User <input name=u> Pass <input name=p type=password>"
            b"<button>Login</button></form></body></html>")

    async def handler(reader, writer):
        peer = writer.get_extra_info("peername")
        try:
            raw = await _read(reader, MAX_READ)
            text = raw.decode("latin1", "replace")
            lines = text.split("\r\n")
            req = lines[0] if lines else ""
            parts = req.split(" ")
            method = parts[0][:10] if parts else ""
            path = parts[1][:300] if len(parts) > 1 else ""
            headers = {}
            for ln in lines[1:]:
                if ":" in ln:
                    k, v = ln.split(":", 1)
                    headers[k.strip().lower()[:40]] = v.strip()[:200]
            payload = {"http_method": method, "path": path,
                       "user_agent": headers.get("user-agent", ""),
                       "host": headers.get("host", "")}
            if headers.get("authorization"):
                payload["authorization"] = headers["authorization"][:120]
            # capture posted body (login form)
            if "\r\n\r\n" in text:
                body = text.split("\r\n\r\n", 1)[1][:300]
                if body:
                    payload["body"] = body
            writer.write(PAGE)
            await writer.drain()
            await _emit(service, port, peer, "http_request", payload)
        except Exception:
            await _emit(service, port, peer, "http_request")
        finally:
            try: writer.close()
            except Exception: pass
    return handler


async def _h_mysql(port):
    # Minimal MySQL server greeting (protocol 10) so nmap/scanners engage.
    greeting = bytes([
        0x4a, 0x00, 0x00, 0x00, 0x0a]) + b"5.7.33-log\x00" + bytes([
        0x36, 0x00, 0x00, 0x00]) + b"\x01\x02\x03\x04\x05\x06\x07\x08\x00" + \
        bytes([0xff, 0xf7, 0x21, 0x02, 0x00, 0x0f, 0x80, 0x15, 0x00] + [0] * 10) + b"\x00"

    async def handler(reader, writer):
        peer = writer.get_extra_info("peername")
        try:
            writer.write(greeting)
            await writer.drain()
            data = await _read(reader, 512)
            await _emit("mysql", port, peer, payload={"data": _safe(data, 200)})
        except Exception:
            await _emit("mysql", port, peer)
        finally:
            try: writer.close()
            except Exception: pass
    return handler


async def _h_redis(port):
    async def handler(reader, writer):
        peer = writer.get_extra_info("peername")
        cmds = []
        try:
            for _ in range(6):
                data = await _read(reader, 512, timeout=5.0)
                if not data:
                    break
                cmds.append(_safe(data, 120).replace("\r\n", " ").strip())
                up = data.upper()
                if b"PING" in up:
                    writer.write(b"+PONG\r\n")
                elif b"INFO" in up:
                    writer.write(b"$10\r\nredis_ver:\r\n")
                else:
                    writer.write(b"+OK\r\n")
                await writer.drain()
            await _emit("redis", port, peer, payload={"commands": cmds})
        except Exception:
            await _emit("redis", port, peer, payload={"commands": cmds})
        finally:
            try: writer.close()
            except Exception: pass
    return handler


# service -> factory returning a (reader, writer) handler
_HANDLERS = {
    "ssh": _h_ssh,
    "telnet": _h_telnet,
    "ftp": _h_ftp,
    "http": lambda p: _h_http(p, "http"),
    "https": lambda p: _h_http(p, "https"),
    "mysql": _h_mysql,
    "redis": _h_redis,
    "vnc": lambda p: _h_generic("vnc", p, b"RFB 003.008\n"),
    "rdp": lambda p: _h_generic("rdp", p),
    "smb": lambda p: _h_generic("smb", p),
    "mssql": lambda p: _h_generic("mssql", p),
    "postgres": lambda p: _h_generic("postgres", p),
}


# --- file honeypot (canary files) --------------------------------------------
# Any read/open/modify of a decoy file is an alarm — nothing legitimate should
# ever touch it. The accessing user + process are captured reliably via fanotify
# (the kernel hands us the PID in the event and FAN_OPEN_PERM suspends the
# accessor until we answer, so even a fast `cat`/`cp` is still alive when we read
# /proc). fanotify needs CAP_SYS_ADMIN (root); without it we fall back to inotify
# with a best-effort /proc scan, which can miss fire-and-close reads.

IN_ACCESS, IN_MODIFY, IN_ATTRIB = 0x1, 0x2, 0x4
IN_CLOSE_WRITE, IN_OPEN = 0x8, 0x20
IN_DELETE_SELF, IN_MOVE_SELF = 0x400, 0x800
IN_NONBLOCK = 0x800
_FILE_MASK = IN_ACCESS | IN_MODIFY | IN_ATTRIB | IN_OPEN | IN_DELETE_SELF | IN_MOVE_SELF
# When fanotify handles open/read/modify, inotify only needs the events fanotify
# doesn't cover well on older kernels: deletion/rename/attribute changes.
_FILE_MASK_AUX = IN_ATTRIB | IN_DELETE_SELF | IN_MOVE_SELF

# fanotify
FAN_CLOEXEC, FAN_NONBLOCK = 0x1, 0x2
FAN_CLASS_CONTENT = 0x4
FAN_OPEN_PERM = 0x00010000
FAN_ACCESS, FAN_MODIFY, FAN_CLOSE_WRITE, FAN_OPEN = 0x1, 0x2, 0x8, 0x20
FAN_MARK_ADD, FAN_MARK_REMOVE = 0x1, 0x2
FAN_ALLOW, FAN_DENY = 0x1, 0x2
_FAN_METADATA_VERSION = 3
_AT_FDCWD = -100
_O_RDONLY_CLOEXEC = 0o2000000            # O_RDONLY(0) | O_CLOEXEC
_FAN_MASK = FAN_OPEN_PERM | FAN_MODIFY | FAN_CLOSE_WRITE
_FAN_META = struct.Struct("=IBBHQii")    # event_len,vers,reserved,metadata_len,mask,fd,pid (24 B)

_libc = None
_inotify_fd = -1
_file_inotify_mask = _FILE_MASK
_wd_path: dict[int, str] = {}
_path_wd: dict[str, int] = {}
_file_kind: dict[str, str] = {}
_file_debounce: dict[str, float] = {}
_fan_fd = -1
_fan_paths: set = set()                  # literal bait paths marked via fanotify

_BAIT = {
    "credentials": b"username=administrator\npassword=P@ssw0rd-2024!\nscope=prod domain admin\n",
    "aws": b"[default]\naws_access_key_id = AKIA5EXAMPLE7Q9J2KLM\n"
           b"aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nregion = eu-central-1\n",
    "ssh_key": b"-----BEGIN OPENSSH PRIVATE KEY-----\n"
               b"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdz\n"
               b"c2gtcnNhAAAAAwEAAQAAAYEExampleExampleExampleDoNotUseThisKeyAtAll\n"
               b"-----END OPENSSH PRIVATE KEY-----\n",
    "env": b"DB_HOST=10.0.0.20\nDB_USER=root\nDB_PASSWORD=SuperSecret123!\n"
           b"JWT_SECRET=8f3c1a...\nSTRIPE_API_KEY=sk_live_51ExampleKeyDoNotUse\n",
    "db_dump": b"-- MySQL dump 10.13\nINSERT INTO users (id,user,pass_hash,email) VALUES\n"
               b"(1,'admin','$2y$10$abcdefghijklmnopqrstuv','admin@corp.local');\n",
    "password_list": b"admin:Winter2024!\nroot:toor\nsvc_backup:Backup#2023\nhelpdesk:Passw0rd\n",
}


def _bait(kind):
    return _BAIT.get(kind, _BAIT["credentials"])


def _create_decoy(path, kind):
    """Plant a decoy file with bait content, only if it doesn't exist yet
    (never clobber a real file)."""
    try:
        d = os.path.dirname(path)
        if d and not os.path.isdir(d):
            os.makedirs(d, exist_ok=True)
        if not os.path.exists(path):
            with open(path, "wb") as f:
                f.write(_bait(kind))
            try:
                os.chmod(path, 0o600)
            except Exception:
                pass
    except Exception as e:
        print(f"  ! honeyfile {path}: create failed: {e}", file=sys.stderr)


def _read_text(p):
    try:
        with open(p) as f:
            return f.read().strip()
    except Exception:
        return ""


def _proc_detail(pid):
    """Full best-effort provenance for a /proc pid: the acting user (name+uid),
    the process (comm + full command line + executable) and its parent."""
    try:
        uid = os.stat(f"/proc/{pid}").st_uid
    except Exception:
        return {}
    try:
        user = pwd.getpwuid(uid).pw_name
    except Exception:
        user = str(uid)
    comm = _read_text(f"/proc/{pid}/comm")
    # cmdline is a NUL-separated argv; join with spaces (raw NULs would be
    # stripped server-side and glue the arguments together).
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            cmdline = f.read().replace(b"\x00", b" ").decode("utf-8", "replace").strip()
    except Exception:
        cmdline = ""
    try:
        exe = os.readlink(f"/proc/{pid}/exe")
    except Exception:
        exe = ""
    ppid, parent = 0, ""
    try:
        stat = _read_text(f"/proc/{pid}/stat")
        # fields after the (comm) — comm may contain spaces/')' so split past it
        rest = stat[stat.rfind(")") + 1:].split()
        ppid = int(rest[1]) if len(rest) > 1 else 0
        if ppid:
            parent = _read_text(f"/proc/{ppid}/comm")
    except Exception:
        pass
    d = {"process": comm or (exe.rsplit("/", 1)[-1] if exe else ""),
         "pid": int(pid), "user": user, "uid": uid}
    if cmdline:
        d["cmdline"] = cmdline[:400]
    if exe:
        d["exe"] = exe
    if ppid:
        d["ppid"] = ppid
    if parent:
        d["parent"] = parent
    return d


# --- root-cause: process ancestry + the attacker's IP ------------------------

def _ppid_of(pid):
    try:
        stat = _read_text(f"/proc/{pid}/stat")
        rest = stat[stat.rfind(")") + 1:].split()
        return int(rest[1]) if len(rest) > 1 else 0
    except Exception:
        return 0


def _proc_min(pid):
    try:
        uid = os.stat(f"/proc/{pid}").st_uid
    except Exception:
        return None
    try:
        user = pwd.getpwuid(uid).pw_name
    except Exception:
        user = str(uid)
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            cmd = f.read().replace(b"\x00", b" ").decode("utf-8", "replace").strip()
    except Exception:
        cmd = ""
    return {"pid": int(pid), "process": _read_text(f"/proc/{pid}/comm"),
            "user": user, "cmdline": cmd[:200]}


def _proc_ancestry(pid, max_depth=12):
    """Walk the PPID chain from the accessor up to init — the root cause of the
    access (e.g. cat ← bash ← sshd)."""
    chain, seen, cur = [], set(), int(pid)
    for _ in range(max_depth):
        if cur <= 0 or cur in seen:
            break
        seen.add(cur)
        info = _proc_min(cur)
        if not info:
            break
        chain.append(info)
        if cur == 1:
            break
        cur = _ppid_of(cur)
    return chain


def _hex_ip(h):
    try:
        if len(h) == 8:                       # IPv4, little-endian
            return ".".join(str(b) for b in bytes.fromhex(h)[::-1])
        if len(h) == 32:                      # IPv6, 4 little-endian words
            raw = b"".join(bytes.fromhex(h[i:i + 8])[::-1] for i in range(0, 32, 8))
            return socket.inet_ntop(socket.AF_INET6, raw)
    except Exception:
        pass
    return ""


def _established_peers():
    """socket-inode -> remote IP for established, non-local TCP connections
    (catches reverse shells / nc where an ancestor holds a network socket)."""
    peers = {}
    for fn in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(fn) as f:
                next(f, None)
                for line in f:
                    p = line.split()
                    if len(p) < 10 or p[3] != "01":       # 01 = ESTABLISHED
                        continue
                    ip = _hex_ip(p[2].split(":")[0])
                    if not ip or ip.startswith("127.") or ip in ("::1", "0.0.0.0", "::"):
                        continue
                    peers[p[9]] = ip
        except Exception:
            continue
    return peers


def _pid_socket_inodes(pid):
    out = []
    try:
        for fd in os.listdir(f"/proc/{pid}/fd"):
            try:
                link = os.readlink(f"/proc/{pid}/fd/{fd}")
                if link.startswith("socket:["):
                    out.append(link[8:-1])
            except Exception:
                continue
    except Exception:
        pass
    return out


def _ssh_client(pid):
    """The remote client IP from a process's SSH_CONNECTION/SSH_CLIENT env —
    the attacker's IP for an interactive SSH session."""
    try:
        with open(f"/proc/{pid}/environ", "rb") as f:
            env = f.read()
    except Exception:
        return ""
    for kv in env.split(b"\x00"):
        if kv.startswith(b"SSH_CONNECTION=") or kv.startswith(b"SSH_CLIENT="):
            val = kv.split(b"=", 1)[1].decode("utf-8", "replace").split()
            if val:
                return val[0]
    return ""


def _root_cause(pid):
    """Process ancestry + best-effort attacker IP (interactive SSH client, else
    an established remote TCP peer held anywhere up the chain)."""
    tree = _proc_ancestry(pid)
    attacker_ip, via = "", ""
    for node in tree:                          # 1) interactive SSH (closest wins)
        ip = _ssh_client(node["pid"])
        if ip:
            attacker_ip, via = ip, "ssh"
            break
    if not attacker_ip:                        # 2) established remote socket
        peers = _established_peers()
        if peers:
            for node in tree:
                hit = next((peers[i] for i in _pid_socket_inodes(node["pid"]) if i in peers), "")
                if hit:
                    attacker_ip, via = hit, "socket"
                    break
    rc = {"tree": tree}
    if attacker_ip:
        rc["attacker_ip"] = attacker_ip
        rc["attacker_via"] = via
    return rc


def _find_actor(path):
    """Best-effort: which process currently has the file open (via a /proc scan
    at event time). Reliable for interactive access (cat/editor/scp/cp) which
    holds the fd open at IN_OPEN; a fire-and-close read may still be missed."""
    try:
        rp = os.path.realpath(path)
        mypid = os.getpid()
        for pid in os.listdir("/proc"):
            if not pid.isdigit() or int(pid) == mypid:
                continue
            fddir = f"/proc/{pid}/fd"
            try:
                for fd in os.listdir(fddir):
                    if os.path.realpath(os.path.join(fddir, fd)) == rp:
                        return _proc_detail(pid)
            except Exception:
                continue
    except Exception:
        pass
    return {}


# --- fanotify: reliable accessor capture (kernel gives us the PID) ------------

def _fanotify_init():
    global _libc, _fan_fd
    if _fan_fd >= 0:
        return True
    if os.geteuid() != 0:
        return False                      # fanotify needs CAP_SYS_ADMIN
    try:
        if _libc is None:
            _libc = ctypes.CDLL("libc.so.6", use_errno=True)
        _libc.fanotify_init.restype = ctypes.c_int
        _libc.fanotify_init.argtypes = [ctypes.c_uint, ctypes.c_uint]
        fd = _libc.fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK,
                                 _O_RDONLY_CLOEXEC)
        if fd < 0:
            raise OSError(ctypes.get_errno(), "fanotify_init")
        _libc.fanotify_mark.restype = ctypes.c_int
        _libc.fanotify_mark.argtypes = [ctypes.c_int, ctypes.c_uint,
                                        ctypes.c_uint64, ctypes.c_int, ctypes.c_char_p]
        _fan_fd = fd
        asyncio.get_event_loop().add_reader(fd, _on_fanotify_readable)
        return True
    except Exception as e:
        print(f"  ! fanotify unavailable ({e}); using inotify (best-effort actor)",
              file=sys.stderr)
        return False


def _fanotify_mark(path, add=True):
    flag = FAN_MARK_ADD if add else FAN_MARK_REMOVE
    try:
        r = _libc.fanotify_mark(_fan_fd, flag, ctypes.c_uint64(_FAN_MASK),
                                _AT_FDCWD, path.encode())
        if r < 0:
            raise OSError(ctypes.get_errno(), "fanotify_mark")
        (_fan_paths.add if add else _fan_paths.discard)(path)
        return True
    except Exception as e:
        if add:
            print(f"  ! honeyfile {path}: fanotify mark failed ({e})", file=sys.stderr)
        return False


def _fan_respond_close(fd, mask):
    # Permission events MUST be answered or the accessing process hangs — always
    # allow (a honeypot observes, it doesn't block). Then release the event fd.
    try:
        if mask & FAN_OPEN_PERM and fd >= 0:
            os.write(_fan_fd, struct.pack("=iI", fd, FAN_ALLOW))
    except Exception:
        pass
    try:
        if fd >= 0:
            os.close(fd)
    except Exception:
        pass


def _on_fanotify_readable():
    try:
        data = os.read(_fan_fd, 16384)
    except (BlockingIOError, InterruptedError):
        return
    except Exception:
        return
    off, n = 0, len(data)
    while off + _FAN_META.size <= n:
        event_len, vers, _res, _mlen, mask, fd, pid = _FAN_META.unpack_from(data, off)
        if event_len < _FAN_META.size:
            break
        off += event_len
        if vers != _FAN_METADATA_VERSION:
            _fan_respond_close(fd, mask)
            continue
        # The event fd points at the accessed file → resolve its path. The
        # process is still suspended (perm event), so /proc read is reliable.
        evpath = ""
        if fd >= 0:
            try:
                evpath = os.readlink(f"/proc/self/fd/{fd}")
            except Exception:
                evpath = ""
        live = pid and pid != os.getpid()
        actor = _proc_detail(pid) if live else {}
        rc = _root_cause(pid) if live else {"tree": []}   # capture while suspended
        _fan_respond_close(fd, mask)      # release the accessor ASAP
        # Map the canonical event path back to the configured bait path.
        match = None
        for p in _fan_paths:
            if p == evpath or os.path.realpath(p) == evpath:
                match = p
                break
        if not match:
            continue
        now = time.time()
        if now - _file_debounce.get(match, 0) < 2.0:
            continue
        _file_debounce[match] = now
        access = "modify" if (mask & (FAN_MODIFY | FAN_CLOSE_WRITE)) else "read"
        payload = {"path": match, "access": access, "kind": _file_kind.get(match)}
        payload.update(actor)
        payload.update(rc)
        try:
            _event_q.put_nowait({"service": "file", "event_type": "file_" + access,
                                 "source_ip": rc.get("attacker_ip"),
                                 "dest_port": None, "payload": payload})
        except asyncio.QueueFull:
            pass
        who = (f" by {actor.get('user')}:{actor.get('process')}"
               + (f" [{actor['cmdline'][:80]}]" if actor.get("cmdline") else "")) if actor else " (actor unknown)"
        atk = f" attacker={rc['attacker_ip']}({rc.get('attacker_via')})" if rc.get("attacker_ip") else ""
        print(f"[file] {access} {match}{who}{atk} (fanotify)")


def _access_label(mask):
    if mask & (IN_DELETE_SELF | IN_MOVE_SELF):
        return "delete"
    if mask & (IN_MODIFY | IN_CLOSE_WRITE):
        return "modify"
    if mask & IN_ATTRIB:
        return "attrib"
    return "read"   # IN_OPEN / IN_ACCESS


def _on_inotify_readable():
    try:
        data = os.read(_inotify_fd, 8192)
    except BlockingIOError:
        return
    except Exception:
        return
    off = 0
    while off + 16 <= len(data):
        wd, mask, cookie, length = struct.unpack_from("iIII", data, off)
        off += 16 + length
        path = _wd_path.get(wd)
        if not path:
            continue
        now = time.time()
        if now - _file_debounce.get(path, 0) < 2.0:
            continue                       # coalesce the open+access+close burst
        _file_debounce[path] = now
        access = _access_label(mask)
        actor = _find_actor(path)
        rc = _root_cause(actor["pid"]) if actor.get("pid") else {"tree": []}
        payload = {"path": path, "access": access, "kind": _file_kind.get(path)}
        payload.update(actor)
        payload.update(rc)
        # source_ip = attacker IP when found, else empty → Warroom stamps the pod IP.
        try:
            _event_q.put_nowait({"service": "file", "event_type": "file_" + access,
                                 "source_ip": rc.get("attacker_ip"),
                                 "dest_port": None, "payload": payload})
        except asyncio.QueueFull:
            pass
        if actor:
            who = f" by {actor.get('user')}:{actor.get('process')}"
            if actor.get("cmdline"):
                who += f" [{actor['cmdline'][:80]}]"
        else:
            who = " (actor not captured — process closed before scan)"
        print(f"[file] {access} {path}{who}")


def _inotify_init():
    global _libc, _inotify_fd
    if _inotify_fd >= 0:
        return True
    try:
        _libc = ctypes.CDLL("libc.so.6", use_errno=True)
        fd = _libc.inotify_init1(IN_NONBLOCK)
        if fd < 0:
            raise OSError(ctypes.get_errno(), "inotify_init1")
        _inotify_fd = fd
        asyncio.get_event_loop().add_reader(fd, _on_inotify_readable)
        return True
    except Exception as e:
        print(f"  ! inotify unavailable ({e}) — file honeypot disabled", file=sys.stderr)
        return False


def _watch_file(path):
    if path in _path_wd:
        return
    wd = _libc.inotify_add_watch(_inotify_fd, path.encode(), _file_inotify_mask)
    if wd < 0:
        print(f"  ! honeyfile {path}: watch failed", file=sys.stderr)
        return
    _wd_path[wd] = path
    _path_wd[path] = wd
    print(f"  + honeyfile watching {path}")


def _unwatch_file(path):
    wd = _path_wd.pop(path, None)
    if wd is not None:
        try:
            _libc.inotify_rm_watch(_inotify_fd, wd)
        except Exception:
            pass
        _wd_path.pop(wd, None)
    _file_kind.pop(path, None)


async def _reconcile_files(files):
    global _file_inotify_mask
    want = {f["path"]: f.get("kind", "credentials") for f in (files or []) if f.get("path")}

    # Prefer fanotify (reliable actor); inotify then only needs delete/attrib.
    use_fan = _fanotify_init() if want else (_fan_fd >= 0)
    _file_inotify_mask = _FILE_MASK_AUX if use_fan else _FILE_MASK
    inotify_ok = _inotify_init() if want else (_inotify_fd >= 0)

    # Remove marks/watches for files no longer wanted.
    for path in list(_fan_paths):
        if path not in want:
            _fanotify_mark(path, add=False)
            _file_kind.pop(path, None)
    for path in list(_path_wd):
        if path not in want:
            _unwatch_file(path)

    for path, kind in want.items():
        _file_kind[path] = kind
        _create_decoy(path, kind)
        if use_fan:
            _fanotify_mark(path, add=True)
        if inotify_ok:
            _watch_file(path)


async def _start_service(service, port):
    if service in _servers:
        return
    factory = _HANDLERS.get(service)
    if not factory:
        return
    handler = await factory(port)
    try:
        server = await asyncio.start_server(handler, BIND, port)
    except PermissionError:
        print(f"  ! {service}:{port} needs root (port < 1024) — skipped", file=sys.stderr)
        return
    except OSError as e:
        print(f"  ! {service}:{port} bind failed: {e}", file=sys.stderr)
        return
    _servers[service] = server
    _ports[service] = port
    print(f"  + {service} listening on {BIND}:{port}")


async def _stop_service(service):
    server = _servers.pop(service, None)
    _ports.pop(service, None)
    if server:
        server.close()
        try:
            await server.wait_closed()
        except Exception:
            pass
        print(f"  - {service} stopped")


async def _reconcile(listen: list[dict]):
    want = {d["service"]: d["port"] for d in listen if d.get("service") in _HANDLERS}
    for service in list(_servers):
        if service not in want or _ports.get(service) != want.get(service):
            await _stop_service(service)
    for service, port in want.items():
        await _start_service(service, port)


# --- Warroom transport (blocking urllib, run off the event loop) --------------

def _ctx():
    if not TLS_VERIFY:
        c = ssl.create_default_context()
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
        return c
    if CA_FILE:
        # Verify against the reverse proxy's own CA (e.g. Nginx Proxy Manager's
        # self-signed CA) — secure alternative to disabling verification.
        return ssl.create_default_context(cafile=CA_FILE)
    return None


def _post(path, obj):
    req = urllib.request.Request(
        WARROOM_URL + path, data=json.dumps(obj).encode(),
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + TOKEN},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15, context=_ctx()) as r:
            body = r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:300]
        raise RuntimeError(f"HTTP {e.code} from {path}: {detail or e.reason}")
    except urllib.error.URLError as e:
        reason = e.reason
        if isinstance(reason, ssl.SSLError) or "CERTIFICATE_VERIFY_FAILED" in str(reason):
            raise RuntimeError(
                f"TLS verification failed ({reason}). The Warroom cert is not publicly "
                f"trusted. Fix: install a Let's Encrypt cert on the proxy, or set "
                f"HONEYPOT_CA=/path/to/ca.pem, or (quick, less secure) HONEYPOT_TLS_VERIFY=0.")
        raise RuntimeError(f"cannot reach {WARROOM_URL}{path}: {reason}")
    try:
        return json.loads(body or "{}")
    except ValueError:
        raise RuntimeError(
            f"non-JSON response from {path} (is WARROOM_URL correct / not an error page?): "
            f"{body[:120]!r}")


async def _heartbeat_loop():
    host_info = {"hostname": socket.gethostname(),
                 "os": platform.platform(), "agent_version": AGENT_VERSION}
    loop = asyncio.get_event_loop()
    interval = 30
    while True:
        try:
            resp = await loop.run_in_executor(
                None, _post, "/api/honeypot/agent/heartbeat", {"host_info": host_info})
            if resp.get("enabled"):
                await _reconcile(resp.get("listen") or [])
                await _reconcile_files(resp.get("files") or [])
            else:
                for s in list(_servers):
                    await _stop_service(s)
                await _reconcile_files([])   # drops all fanotify marks + inotify watches
            interval = max(10, int(resp.get("heartbeat_seconds") or 30))
        except Exception as e:
            print(f"heartbeat failed: {e}", file=sys.stderr)
        await asyncio.sleep(interval)


async def _reporter_loop():
    loop = asyncio.get_event_loop()
    while True:
        ev = await _event_q.get()
        batch = [ev]
        # drain up to a small batch
        try:
            while len(batch) < 50:
                batch.append(_event_q.get_nowait())
        except asyncio.QueueEmpty:
            pass
        for e in batch:
            svc, src = e.get("service"), e.get("source_ip")
            print(f"[hit] {svc} <- {src}")
        try:
            await loop.run_in_executor(None, _post, "/api/honeypot/agent/events", {"events": batch})
        except Exception as e:
            print(f"report failed ({len(batch)} events dropped): {e}", file=sys.stderr)


async def main():
    print(f"Warroom honeypot agent {AGENT_VERSION} → {WARROOM_URL}")
    asyncio.ensure_future(_reporter_loop())
    await _heartbeat_loop()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass

# Warroom Honeypot Agent

Low-interaction decoy honeypot that runs on a **remote Linux host**, simulates
the most-attacked network services and reports every access to Warroom, which
geo-enriches it and raises a Telegram/Teams alert. Nothing here is a real
service — **any** connection is suspicious.

Pods are **created and managed from the Warroom UI** (`/honeypot.html`): pick a
name and the services, get a one-time token + deploy command. Enable/disable
services later from the UI — the agent reconciles on its next heartbeat.

The agent source is served by Warroom itself
(`/api/honeypot/agent/download`) so the deploy is a single copy-paste; the
canonical copy lives at `backend/app/deploy/honeypot_agent.py`.

## Simulated services

SSH · Telnet · FTP · HTTP/HTTPS · RDP · SMB · MySQL · MSSQL · Redis · VNC ·
PostgreSQL. Credential-capturing decoys (SSH/Telnet/FTP/HTTP) log the attempted
username/password or request; the rest log the connection + first bytes.

## Deploy (quick)

Create the pod in the Warroom UI, then on the honeypot host:

```bash
curl -fsSL https://<warroom>/api/honeypot/agent/download -o honeypot_agent.py
sudo WARROOM_URL=https://<warroom> HONEYPOT_TOKEN=hp_xxxxx python3 honeypot_agent.py
```

`sudo` is only needed to bind privileged ports (< 1024, e.g. SSH/HTTP). Ports
that can't be bound are skipped with a warning; the rest keep running.

Env: `WARROOM_URL`, `HONEYPOT_TOKEN` (required); `HONEYPOT_BIND` (default
`0.0.0.0`), `HONEYPOT_TLS_VERIFY` (default `1`; set `0` for a self-signed
Warroom cert).

## Run as a service (systemd) — installer script

The installer sets the agent up as the `warroom-honeypot` systemd service and
can also update and remove it. It is served by Warroom too:

```bash
curl -fsSL https://<warroom>/api/honeypot/agent/install -o honeypot_install.sh
sudo WARROOM_URL=https://<warroom> HONEYPOT_TOKEN=hp_xxxxx bash honeypot_install.sh install
```

```bash
sudo bash honeypot_install.sh update      # pull the latest agent + restart
sudo bash honeypot_install.sh uninstall   # stop + remove the service
sudo bash honeypot_install.sh status      # service state + recent logs
```

For a self-signed Warroom proxy, **pin the certificate** — secure and needs no
valid CA chain: append `--pin auto` to trust the cert the server presents now
(trust-on-first-use), or `--pin <sha256>` with a fingerprint you verified
out-of-band (run `honeypot_install.sh pin` to print it). `--ca /path/to/ca.pem`
(verify against the proxy CA) and `--insecure` (skip verification) also work.
It installs to `/opt/warroom-honeypot/`, keeps config in `/etc/warroom-honeypot.env`
(chmod 600), and runs as root — the honeypot needs to plant decoy files anywhere
and use fanotify (`CAP_SYS_ADMIN`) for reliable file-access attribution.

The bundled `honeypot-agent.service` unit remains for a manual setup, but the
installer is the recommended path.

> ⚠️ Deploy on a **dedicated/isolated host** you don't mind exposing. A honeypot
> is meant to be reached by attackers — segregate it from production.

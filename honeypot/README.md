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

## Run as a service (systemd)

```bash
sudo curl -fsSL https://<warroom>/api/honeypot/agent/download -o /usr/local/bin/honeypot_agent.py
sudo cp honeypot-agent.service /etc/systemd/system/
sudoedit /etc/systemd/system/honeypot-agent.service   # set WARROOM_URL + HONEYPOT_TOKEN
sudo systemctl daemon-reload && sudo systemctl enable --now honeypot-agent
```

> ⚠️ Deploy on a **dedicated/isolated host** you don't mind exposing. A honeypot
> is meant to be reached by attackers — segregate it from production.

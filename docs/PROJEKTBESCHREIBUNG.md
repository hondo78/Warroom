# Warroom — Projektbeschreibung

> Security-Operations-Dashboard für Sophos Central & Sophos Firewalls mit
> KI-Agent, OSINT-Anreicherung und automatisierter Abwehr.
> Setup: siehe [`../README.md`](../README.md).

## 1. Worum geht es?

Warroom bündelt die sicherheitsrelevanten Datenquellen einer Sophos-Umgebung an
einem Ort und macht aus Monitoring eine aktive Verteidigung:

- **Sehen:** Alerts/Events/Detections aus Sophos Central, Firewall-Logs
  (IPS, WAF, Auth) und NetFlow — mit Live-Karte der Angreifer-Geolokation.
- **Bewerten:** IPs/Domains/URLs gegen mehrere OSINT-Quellen prüfen (Intelix,
  AbuseIPDB, VirusTotal, Shodan, GreyNoise, ipinfo, DNS) — manuell oder per KI.
- **Handeln:** Treffer landen auf zentralen Blocklisten, die die Firewalls als
  IOC-Feeds abholen; Mailboxen/Quarantäne über die Sophos Email API verwalten.

**Zielgruppe:** SecOps/Admins kleiner–mittlerer Sophos-Umgebungen, die ein
selbst gehostetes Cockpit ohne SaaS-Abhängigkeit wollen.
**Prinzipien:** self-hosted, Mensch behält die Kontrolle (KI empfiehlt
standardmäßig), Whitelist schützt eigene IPs vor versehentlichem Block.

## 2. Architektur

Alles läuft in Containern (`docker-compose.yml`):

| Container  | Port (Host)    | Aufgabe |
|------------|----------------|---------|
| `frontend` | `8448`         | Nginx: statische UI + Reverse-Proxy `/api/`→backend, setzt API-Key |
| `backend`  | intern `8000`  | FastAPI: REST-API, Sophos-Anbindung, KI-Agent, OSINT, IOC-Feeds |
| `syslog`   | `5514/udp+tcp` | Sophos-Firewall-Syslog → `firewall_logs` |
| `netflow`  | `2055/udp`     | NetFlow v5/v9/IPFIX → `netflow_buckets` |
| `postgres` | intern `5432`  | Persistenz |
| `redis`    | intern `6379`  | Cache (Summaries, OSINT-Lookups) |
| `grafana`  | `3030`         | Dashboards direkt auf der DB |

**Stack:** FastAPI + SQLAlchemy 2 (async) + APScheduler · PostgreSQL 16 · Redis 7
· Vanilla JS/AdminLTE (kein Build-Step) · GeoIP MaxMind GeoLite2 · KI über
OpenAI-kompatibles Endpoint (LMStudio/Ollama/vLLM/OpenAI) · Grafana 11.

**Backend-Module (`backend/app/`):** `main.py` (Routen, Scheduler) ·
`sophos_client.py` (Central- + Email-API) · `collector.py` (Sync) · `agent.py`
(KI-Loops, Triage) · `osint.py` (Lookups, 1 h-Cache) · `settings_store.py` (Live-
Konfig) · `geoip_service.py` · `*_metrics.py`.

**Datenfluss:**
1. Sophos Central API → `collector` → DB
2. Firewall-Syslog → `syslog` → `firewall_logs`
3. NetFlow → `netflow` → `netflow_buckets`
4. UI → Backend liest DB (teils Redis-gecacht) → Frontend
5. Block-Aktion (UI/KI/OSINT) → `blocked_ips/_domains/_urls`
6. Firewall pullt `/ioc_IP` · `/ioc_domain` · `/ioc_url` → live aus den Tabellen

## 3. KI-Agent (optional)

Nutzt ein OpenAI-kompatibles Modell; bekommt strukturiertes JSON und muss strikt
JSON (`action`/`args`/`confidence`/`reasoning`) zurückgeben — das Backend
re-validiert jede Antwort. Loops (einzeln aktivierbar, eigener Prompt): Alert,
WAF, IPS, Failed-Login (per IP) sowie **verteilter Brute-Force** (der Agent
bekommt alle Logins der letzten 60 Min, gruppiert selbst nach /24, zählt und
empfiehlt `block_subnet`/`block_ips`) und **Triage** (Wert von der OSINT-Seite).
Empfehlungen sind per Default `pending` (Freigabe durch Mensch); optional
Auto-Execute/Konfidenz-Schwelle. Modell, Intervalle, Schwellen, Temperatur,
max-Tokens und Prompts sind live im Admin-Bereich einstellbar.

## 4. Nutzung

Einstieg: `http://<host>:8448`.

| Seite | URL | Nutzung |
|-------|-----|---------|
| Dashboard | `/` | Lagebild, Angriffskarte, Firewall-Logs; IPs blocken, Alerts quittieren, Endpoints isolieren |
| NetFlow | `/netflow.html` | Top-Talker, Ziele, Ports, Protokolle, Durchsatz |
| Blocklist | `/blocked.html` | IPs/Domains/URLs blocken, Whitelist, IOC-Feeds |
| Firewalls | `/firewalls.html` | Standorte, Interfaces, Whitelist |
| Agent | `/agent.html` | KI-Entscheidungen genehmigen/ablehnen, LLM-Statistik |
| Email | `/email.html` | Mailboxen verwalten, Quarantäne durchsuchen, freigeben/löschen |
| OSINT | `/osint.html` | IP/Domain/URL prüfen → sofort blocken oder an KI-Triage |
| Stats | `/stats.html` | OSINT-/LLM-Verbrauch, Cache-Quote |
| Admin | `/admin.html` | API-Keys, Intervalle, LLM-Parameter, Prompts — live |
| Grafana | `:3030` | Vorgefertigte DB-Dashboards |

**Typische Abläufe:** Angriff blocken (auffällige IP → 🔍 OSINT → sofort blocken
oder an KI-Triage → Firewall holt IOC-Feed) · Agent betreiben (Admin: Modell/
Loops/Schwellen → Agent: Empfehlungen prüfen/Auto-Execute) · verteilter
Brute-Force (Agent erkennt /24-Cluster der letzten 60 Min) · E-Mail (Quarantäne
durchsuchen, freigeben/löschen, Absender erlauben/blocken).

**Datenquellen:** Sophos-Credentials in Admin/`.env`; Firewall-Syslog auf
`host:5514`; NetFlow auf `host:2055`; Firewall holt `/ioc_*`.

## 5. Sicherheit

`X-API-Key` auf allen `/api/*` (Nginx injiziert) · strikte CSP & Security-Header
· Whitelist verhindert Self-Block · KI per Default nur empfehlend · Secrets in
der Admin-API maskiert. Mehr: [`REVIEW.md`](REVIEW.md).

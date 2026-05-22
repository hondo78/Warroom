# Warroom

Security-Operations-Dashboard für kleine bis mittlere Sophos-Umgebungen.
Bündelt Daten aus **Sophos Central** (Alerts, Events, Endpoints, Firewalls),
**Sophos Firewall (SFOS) Syslog** (IPS, WAF, Auth, Traffic) sowie **NetFlow v9**
und reichert IPs per **GeoIP + AbuseIPDB / VirusTotal / Shodan / Sophos Intelix**
an. Geblockte IPs werden als **IOC-Feed** (TXT) bereitgestellt, den Firewalls
über eine URL abrufen können.

```
┌──────────────────┐  Syslog 5514     ┌──────────┐
│ Sophos Firewall  │ ───────────────► │ syslog   │──┐
└──────────────────┘  NetFlow 2055    └──────────┘  │
        │                                            ▼
        │              ┌──────────┐    ┌────────────────────┐
        │              │ netflow  │ ──►│   PostgreSQL       │◄──┐
        │              └──────────┘    └────────────────────┘   │
        ▼                                       ▲                │
┌──────────────────┐    REST API                │                │
│ Sophos Central   │ ◄───────────────────  ┌─────────┐           │
└──────────────────┘                       │ backend │ ──► Redis │
                                           └─────────┘  (Cache)  │
                                                ▲                │
                                                │ /ioc_IP        │
                                                ▼                │
                                            ┌─────────┐          │
                              Browser ◄───► │ nginx   │          │
                                            └─────────┘          │
                                                 ▲               │
                                                 │ HTTP-Pull     │
                                                 │ (X-API-Key)   │
                                            ┌────┴────┐          │
                                            │Firewall │──────────┘
                                            └─────────┘    Blocklist
```

## Features

- **Dashboard**: Alerts/Events/Detections aus Sophos Central, Live-Karte mit
  Angreifer-Geolokation, Firewall-Logs (IPS / WAF / Auth / Failed-Logins)
- **NetFlow-Auswertung** (v5/v9/IPFIX) inkl. Top-Talkers und
  Interface-Throughput
- **IP-Blocking via IOC-Feed**: Geblockte IPs werden über `GET /ioc_IP`
  als TXT-Datei bereitgestellt. Firewalls ziehen die Liste selbst —
  **kein Push, keine XML-API mehr**
- **OSINT-Anreicherung**: AbuseIPDB, VirusTotal, Shodan, Sophos Intelix,
  GreyNoise, ipinfo
- **Endpoint-Management**: Health-States, Isolation-Toggle über Sophos Central
- **Admin-UI**: API-Keys, Intervalle, Log-Level live editierbar (kein Restart)

## Stack

| Component | Tech |
|-----------|------|
| Backend   | FastAPI 0.115, SQLAlchemy 2 async, APScheduler |
| Database  | PostgreSQL 16 |
| Cache     | Redis 7 |
| Frontend  | Vanilla JS + Nginx (CSP-light, kein Build-Step) |
| Syslog    | Custom Python receiver (UDP/TCP 5514) |
| NetFlow   | Custom Python collector (UDP 2055) |
| GeoIP     | MaxMind GeoLite2 (Fallback: ip-api.com) |

## Quickstart

```bash
git clone https://github.com/hondo78/Warroom.git
cd Warroom

cp .env.example .env
# WARROOM_API_KEY setzen (openssl rand -hex 32), Sophos-Credentials eintragen

# GeoIP-Datenbanken nach ./geoip/ legen (GeoLite2-City.mmdb, GeoLite2-ASN.mmdb)
# Optional - ohne läuft Warroom mit ip-api.com Fallback

docker compose up -d
```

Dashboard: <http://localhost:8448>
Admin: <http://localhost:8448/admin.html>

## IOC-Feed für Firewalls

Die geblockte-IP-Liste wird live unter folgender URL bereitgestellt:

```
GET https://<warroom-host>:8448/ioc_IP
Header: X-API-Key: <WARROOM_API_KEY>
```

**Format**: `text/plain`, eine IPv4/IPv6 pro Zeile, sortiert.

```
103.235.46.39
104.167.19.182
185.220.101.42
...
```

Die Liste wird live aus der DB gelesen — jedes Block/Unblock im Dashboard
ist **sofort** im Feed sichtbar (kein Push, kein Reconcile, keine Caches).

### Firewall-Anbindung

**Sophos XG / XGS Firewall**
*Hosts and Services → IP List → Add* → URL eintragen, "Custom HTTP Headers"
nutzen für `X-API-Key`. Update-Intervall nach Bedarf (z.B. 5 Min).

**Fortinet FortiGate**
*Security Fabric → External Connectors → Threat Feeds → IP Address* →
URL eintragen, HTTP-Header `X-API-Key` setzen.

**pfSense / OPNsense (pfBlockerNG)**
URL als IPv4-Feed-Source hinzufügen. pfBlockerNG sendet keine Custom-Header —
in diesem Fall den Backend-Endpoint hinter einen Proxy mit IP-Whitelist legen
oder Open-Mode (WARROOM_API_KEY leer) nur für die Firewall-IP per
Nginx-Config zulassen.

## Block-IP API (Web-UI)

Die Block-Buttons im Dashboard rufen folgende Endpoints auf:

| Methode | Route                       | Body                                  |
|---------|-----------------------------|---------------------------------------|
| POST    | `/api/firewall/block-ip`    | `{"ip": "1.2.3.4", "comment": "..."}` |
| POST    | `/api/firewall/block-ips`   | `{"ips": ["1.2.3.4", ...]}`           |
| POST    | `/api/firewall/unblock-ip`  | `{"ip": "1.2.3.4"}`                   |
| GET     | `/api/firewall/blocked-ips` | -                                     |

Alle schreiben in die `blocked_ips`-Tabelle. Der `/ioc_IP`-Feed liest
diese Tabelle live → keine Sync-Logik nötig.

## Konfiguration

Alle Einstellungen können nach dem ersten Start über die **Admin-UI**
(`/admin.html`) editiert werden. Änderungen werden in der DB überlagert,
ein Container-Restart ist nicht nötig.

Initiale Werte aus `.env` (siehe `.env.example`):

| Variable                   | Zweck                                          |
|----------------------------|------------------------------------------------|
| `WARROOM_API_KEY`          | Pflicht für Production. Schützt `/api/*` und `/ioc_IP` |
| `SOPHOS_CLIENT_ID/SECRET`  | Sophos Central OAuth2 Credentials              |
| `MAXMIND_LICENSE_KEY`      | Optional, sonst ip-api.com als Fallback        |
| `ABUSEIPDB_API_KEY`        | Optional, für IP-Reputation-Lookups            |
| `COLLECTOR_INTERVAL`       | Wie oft Sophos-Central abgefragt wird (s)      |

## Services

| Container         | Port (host)      | Beschreibung                            |
|-------------------|------------------|-----------------------------------------|
| `frontend`        | `8448`           | Nginx, Static-Files + Reverse-Proxy     |
| `backend`         | (intern: 8000)   | FastAPI, REST + IOC-Feed                |
| `syslog`          | `5514/udp+tcp`   | Sophos Firewall Syslog-Empfänger        |
| `netflow`         | `2055/udp`       | NetFlow v5/v9/IPFIX Collector           |
| `postgres`        | (intern: 5432)   | Daten-Persistenz                        |
| `redis`           | (intern: 6379)   | Cache (Summary, OSINT-Lookups)          |

## Sophos Firewall Syslog konfigurieren

System → Administration → Notification settings → Syslog Server:

- Host: IP des Warroom-Hosts
- Port: 5514 (UDP oder TCP)
- Facility: nach Wahl
- Severity: alle benötigten
- Format: Standard / Device-Syslog

Aktivierte Log-Kategorien: **Firewall** (Traffic), **IPS**, **WAF**,
**Authentication**, **Admin**, **System**.

## Datenfluss

1. **Sophos Central API** → `collector.py` (alle 300s default) → DB
2. **Sophos Firewall Syslog** → `syslog`-Service → DB (`firewall_logs`)
3. **NetFlow** → `netflow`-Service → DB (`netflow_buckets`)
4. **Dashboard** → Backend liest aus DB → Frontend rendert
5. **Block-Aktion (UI)** → `blocked_ips`-Tabelle wird beschrieben
6. **Firewall pulls** `/ioc_IP` → Backend liest `blocked_ips` live

## Lizenz

Privates Projekt — kein offizieller Support.

## Trademarks

Sophos, Sophos Central, Sophos Firewall und Sophos Intelix sind eingetragene
Marken von Sophos Ltd. Dieses Projekt ist nicht mit Sophos affiliated.

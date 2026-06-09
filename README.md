# Warroom

Security-Operations-Dashboard für kleine bis mittlere Sophos-Umgebungen.
Bündelt Daten aus **Sophos Central** (Alerts, Events, Endpoints, Firewalls),
**Sophos Firewall (SFOS) Syslog** (IPS, WAF, Auth, Traffic) sowie **NetFlow
v5/v9/IPFIX** und reichert IPs per **GeoIP + AbuseIPDB / VirusTotal / Shodan /
Sophos Intelix / GreyNoise** an. Geblockte IPs, Domains und URLs werden als
**IOC-Feeds** (TXT) bereitgestellt, die Firewalls per URL abrufen.

> **In einem Satz:** Logs reinschütten, Angreifer auf einer Karte sehen,
> mit einem Klick (oder per KI-Agent) blocken – und die Firewall zieht die
> Blockliste selbst.

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

---

## Inhalt

> 📖 Ausführliche **Projektbeschreibung, Architektur & Nutzung**: [`docs/PROJEKTBESCHREIBUNG.md`](docs/PROJEKTBESCHREIBUNG.md)

- [Was kann Warroom? (User-Sicht)](#was-kann-warroom-user-sicht)
- [Voraussetzungen](#voraussetzungen)
- [Setup in 6 Schritten](#setup-in-6-schritten)
- [Was muss ich besorgen? (Checkliste)](#was-muss-ich-besorgen-checkliste)
- [Datenquellen anbinden](#datenquellen-anbinden)
- [IOC-Feeds für Firewalls](#ioc-feeds-für-firewalls)
- [Block-API (Web-UI)](#block-api-web-ui)
- [KI-Agent (optional)](#ki-agent-optional)
- [Microsoft 365 Audit-Logs (optional)](#microsoft-365-audit-logs-optional)
- [Entra ID Login-Blocking (optional)](#entra-id-login-blocking-optional)
- [Telegram-Approvals (optional)](#telegram-approvals-optional)
- [KI-Chat & Teams-Befehle](#ki-chat--teams-befehle)
- [Sicherheit & Härtung](#sicherheit--härtung)
- [Stack & Services](#stack--services)
- [Troubleshooting](#troubleshooting)

---

## Was kann Warroom? (User-Sicht)

Nach dem Login (Dashboard unter `http://<host>:8448`) stehen folgende Seiten
zur Verfügung:

| Seite | URL | Das kannst du dort tun |
|-------|-----|------------------------|
| **Dashboard** | `/` | Alerts, Events & Detections aus Sophos Central; Live-Karte mit Angreifer-Geolokation; Firewall-Logs (IPS / WAF / Auth / Failed-Logins); KI-Agent-Empfehlungen; Endpoint-Übersicht. IPs direkt per Klick blocken, Alerts quittieren, Endpoints isolieren. |
| **KI-Chat** | `/chat.html` | Befehle in natürlicher Sprache: IP/Domain/FQDN/URL blocken, Endpoint isolieren, Quarantäne abfragen, OSINT-Lookup, Statistik-Report. Dieselbe Engine ist über **Microsoft Teams** erreichbar. |
| **Blocklist** | `/blocked.html` | IPs, Domains und URLs manuell blocken/entblocken; Whitelist pflegen; die fertigen IOC-Feeds einsehen. |
| **NetFlow** | `/netflow.html` | Traffic-Analyse: Top-Talker, Ziele, Ports, Protokoll-Mix, Interface-Durchsatz. |
| **Firewalls** | `/firewalls.html` | Firewall-Standorte auf der Karte, Interface-Statistiken, Whitelist-Verwaltung. |
| **Endpoints** | `/endpoints.html` | Sophos Endpoint Management API: Geräte-**Inventar** (Health/Isolation/Tamper/OS) mit Detailansicht, isolieren/freigeben, On-Demand-Scan, de-registrieren · **Gruppen** (anlegen/löschen) · **Policies** (Liste + Detail) · **Einstellungen** (Tamper-Protection global, Allow-/Block-Liste, Scan-Ausschlüsse, Web-Control lokale Sites — je hinzufügen/löschen) · **Installer-Downloads** pro Plattform. |
| **Agent** | `/agent.html` | Entscheidungs-Log des KI-Agenten; Empfehlungen genehmigen/ablehnen; LLM-Statistik. Erkennt u. a. **verteilte Brute-Force-Angriffe** (viele Quell-IPs über mehrere /24-Netze gegen dasselbe Konto → `block_ips`) und nimmt **Triage-Eingaben** entgegen. |
| **Agent-Workflow** | `/agent-workflow.html` | Visualisiert die Entscheidungs-Pipeline und macht **jede Stufe** (Trigger, Schwellen, Intervall, erlaubte Aktionen, System-Prompt, Auto-Execute) live editierbar. Das LLM wird mit **strukturierten Ausgaben** (Pydantic-Schema via `response_format`) angesprochen und typisiert validiert. |
| **Email** | `/email.html` | Sophos Email Management API: Mailboxen verwalten (anlegen/ändern/löschen), Quarantäne & Post-Delivery-Quarantäne durchsuchen, Nachrichten freigeben/löschen (optional Absender erlauben/blocken). |
| **Microsoft 365** | `/o365.html` | M365-Login-Audit (Management Activity API): erfolgreiche & fehlgeschlagene Anmeldungen mit App, **Gerät** (Name/OS/Browser/Compliance), Quell-IP, Standort. Spalten **sortier- und filterbar**; OSINT-Drilldown pro IP; fehlgeschlagene Logins direkt blockbar (whitelistete IPs geschützt). |
| **OSINT** | `/osint.html` | IP, Domain oder URL manuell prüfen — Sophos Intelix, AbuseIPDB, VirusTotal, GreyNoise, ipinfo & DNS parallel; Verlauf & Cache-Bypass. **Shodan** ist credit-sparend opt-in: erst per Button „🛰️ Shodan abfragen". Geprüfte Werte direkt **sofort blocken** oder **an die KI-Triage** übergeben. Erkannte **offene Ports & CVEs** werden langfristig gespeichert und als optionaler Karten-Layer dargestellt. |
| **Stats** | `/stats.html` | Verbrauch der OSINT-Provider (Tages-/Monatslimits), LLM-Calls & Tokens, Cache-Trefferquote. |
| **Admin** | `/admin.html` | Alle API-Keys, Intervalle, Loglevel und Agent-Einstellungen **live** editieren – ohne Container-Neustart. |
| **Grafana** | `:3030` | Vorgefertigte Dashboards (Warroom, NetFlow, Blocklist) direkt auf der PostgreSQL-DB. |

---

## Voraussetzungen

Auf dem Host brauchst du nur:

- **Docker** und **Docker Compose v2** (`docker compose version` ≥ 2.x)
- **Git**
- Freie Ports auf dem Host: **8448** (Dashboard), **3030** (Grafana),
  **5514/udp+tcp** (Syslog), **2055/udp** (NetFlow)
- Optional, aber empfohlen: ein zweites Gerät, das Syslog/NetFlow sendet
  (Sophos Firewall o. Ä.)

Es gibt **keinen Build-Step** für das Frontend (Vanilla JS) und keine lokale
Python-Installation nötig – alles läuft in Containern.

---

## Setup in 6 Schritten

```bash
# 1) Klonen
git clone https://github.com/hondo78/Warroom.git
cd Warroom

# 2) Konfiguration anlegen
cp .env.example .env

# 3) .env ausfüllen – mindestens:
#    - POSTGRES_PASSWORD + DATABASE_URL (gleiches Passwort!)
#    - WARROOM_API_KEY   (openssl rand -hex 32)   [dringend empfohlen]
#    - GRAFANA_ADMIN_PASSWORD
#    - SOPHOS_CLIENT_ID / SOPHOS_CLIENT_SECRET     [für Sophos-Central-Daten]
$EDITOR .env

# 4) (Optional) GeoIP-Datenbanken bereitstellen – siehe Checkliste unten.
#    Ohne läuft Warroom mit ip-api.com-Fallback.
#    GeoLite2-City.mmdb und GeoLite2-ASN.mmdb nach ./geoip/ legen.

# 5) Starten
docker compose up -d

# 6) Status prüfen
docker compose ps
docker compose logs -f backend
```

Danach erreichbar:

- **Dashboard:** <http://localhost:8448>
- **Admin-UI:** <http://localhost:8448/admin.html>
- **Grafana:** <http://localhost:3030> (Login mit `GRAFANA_ADMIN_*`)

Den Rest der Konfiguration (OSINT-Keys, Agent, Intervalle) kannst du bequem
in der **Admin-UI** nachtragen – ein Neustart ist nicht nötig.

---

## Was muss ich besorgen? (Checkliste)

| # | Was | Pflicht? | Woher | Wohin |
|---|-----|----------|-------|-------|
| 1 | **DB-Passwort** | ✅ | selbst ausdenken | `POSTGRES_PASSWORD` **und** `DATABASE_URL` in `.env` |
| 2 | **WARROOM_API_KEY** | ⭐ dringend empfohlen | `openssl rand -hex 32` | `WARROOM_API_KEY` in `.env` |
| 3 | **Grafana-Passwort** | ⭐ empfohlen | selbst ausdenken | `GRAFANA_ADMIN_PASSWORD` in `.env` |
| 4 | **Sophos-Central-Credentials** | für Central-Daten | Sophos Central → Global Settings → API Credentials Management → *Add Credential* | `SOPHOS_CLIENT_ID` / `SOPHOS_CLIENT_SECRET` |
| 5 | **GeoLite2-City.mmdb + GeoLite2-ASN.mmdb** | optional | [MaxMind GeoLite2](https://www.maxmind.com/en/geolite2/signup) (kostenlos) | Dateien in `./geoip/` |
| 6 | **AbuseIPDB-Key** | optional | <https://www.abuseipdb.com> | `ABUSEIPDB_API_KEY` |
| 7 | **VirusTotal-Key** | optional | <https://www.virustotal.com> | `VIRUSTOTAL_API_KEY` |
| 8 | **Shodan-Key** | optional | <https://account.shodan.io> | `SHODAN_API_KEY` |
| 9 | **Sophos-Intelix-Credentials** | optional | <https://api.labs.sophos.com> | `SOPHOS_INTELIX_CLIENT_ID/SECRET` |
| 10 | **LLM-Endpoint** (für KI-Agent) | optional | LMStudio / Ollama / vLLM / OpenAI | `AGENT_*` in `.env` |

> **Hinweis GeoIP:** `geoip/*.mmdb`, `*.tar.gz` und `*.zip` sind in
> `.gitignore` ausgeschlossen (die Dateien sind groß und unterliegen der
> MaxMind-Lizenz). Lade sie nach der Registrierung herunter und entpacke
> `GeoLite2-City.mmdb` sowie `GeoLite2-ASN.mmdb` direkt nach `./geoip/`.
> Backend und Syslog-Service mounten dieses Verzeichnis automatisch.

---

## Datenquellen anbinden

### Sophos Firewall Syslog

*System → Administration → Notification settings → Syslog Server:*

- **Host:** IP des Warroom-Hosts
- **Port:** 5514 (UDP oder TCP)
- **Format:** Standard / Device-Syslog
- Aktivierte Kategorien: **Firewall** (Traffic), **IPS**, **WAF**,
  **Authentication**, **Admin**, **System**

### NetFlow

NetFlow-Export (v5/v9/IPFIX) der Firewall/des Routers auf
**`<warroom-host>:2055/udp`** richten. Buckets werden minütlich aggregiert,
Retention standardmäßig 30 Tage (`RETENTION_DAYS` im `netflow`-Service).

### Sophos Central

Sobald `SOPHOS_CLIENT_ID`/`SECRET` gesetzt sind, ruft der `collector` alle
`COLLECTOR_INTERVAL` Sekunden (Default 300) Alerts, Events, Endpoints und
Firewall-Status ab.

---

## IOC-Feeds für Firewalls

Gepflegt werden die Listen unter <http://localhost:8448/blocked.html>. Jede
Block-/Unblock-Aktion ist **sofort** im Feed sichtbar (live aus der DB, kein
Push, kein Reconcile, kein Cache).

| Feed | Endpoint | Format |
|------|----------|--------|
| IPs | `GET /ioc_IP` | eine IPv4/IPv6 pro Zeile, sortiert |
| Domains | `GET /ioc_domain` | Hostnamen, Wildcards `*.evil.tld` erlaubt |
| URLs | `GET /ioc_url` | vollständige URLs inkl. `http(s)://` und Pfad |

Alle Feeds erwarten den Header `X-API-Key: <WARROOM_API_KEY>` (außer im Open
Mode).

```
GET https://<warroom-host>:8448/ioc_IP
Header: X-API-Key: <WARROOM_API_KEY>
```

### Firewall-Anbindung

**Sophos XG / XGS** — *Hosts and Services → IP List → Add* → URL eintragen,
„Custom HTTP Headers" für `X-API-Key` nutzen, Update-Intervall z. B. 5 Min.

**Fortinet FortiGate** — *Security Fabric → External Connectors → Threat Feeds
→ IP Address* → URL eintragen, HTTP-Header `X-API-Key` setzen.

**pfSense / OPNsense (pfBlockerNG)** — URL als IPv4-Feed-Source hinzufügen.
pfBlockerNG sendet keine Custom-Header → entweder den Endpoint hinter einen
Proxy mit IP-Whitelist legen oder Open Mode (`WARROOM_API_KEY` leer) nur für
die Firewall-IP per nginx-Config erlauben.

---

## Block-API (Web-UI)

Die Block-Buttons im Dashboard und die Blocklist-Seite rufen folgende
Endpoints auf:

| Methode | Route | Body |
|---------|-------|------|
| POST | `/api/firewall/block-ip` | `{"ip": "1.2.3.4", "comment": "..."}` |
| POST | `/api/firewall/block-ips` | `{"ips": ["1.2.3.4", ...]}` |
| POST | `/api/firewall/unblock-ip` | `{"ip": "1.2.3.4"}` |
| GET | `/api/firewall/blocked-ips` | – |
| POST | `/api/firewall/block-domain` | `{"domain": "evil.tld", "comment": "..."}` |
| POST | `/api/firewall/block-domains` | `{"domains": ["evil.tld", "*.adsrv.tld"]}` |
| POST | `/api/firewall/unblock-domain` | `{"domain": "evil.tld"}` |
| GET | `/api/firewall/blocked-domains` | – |
| POST | `/api/firewall/block-url` | `{"url": "https://evil.tld/x", "comment":""}` |
| POST | `/api/firewall/block-urls` | `{"urls": ["https://a/b", "http://c/d"]}` |
| POST | `/api/firewall/unblock-url` | `{"url": "https://evil.tld/x"}` |
| GET | `/api/firewall/blocked-urls` | – |

IPs landen in `blocked_ips`, Hostnamen in `blocked_domains`, URLs in
`blocked_urls`. Die Feeds lesen diese Tabellen live → keine Sync-Logik.

---

## KI-Agent (optional)

Der Agent analysiert Firewall-Logs (WAF/IPS/Failed-Login) per LLM und schlägt
Blocks vor – oder führt sie automatisch aus. Standardmäßig **aus**.

1. LLM-Endpoint bereitstellen (LMStudio/Ollama/vLLM lokal oder OpenAI).
   `host.docker.internal` zeigt aus dem Container auf den Docker-Host.
2. In der Admin-UI oder `.env`: `AGENT_ENABLED=true`, `AGENT_BASE_URL`,
   `AGENT_MODEL` setzen.
3. Standardmäßig bleiben Empfehlungen **pending** und müssen unter
   `/agent.html` genehmigt werden. `AGENT_AUTO_EXECUTE=true` oder die
   Konfidenz-Fast-Lane (`AGENT_AUTO_EXECUTE_THRESHOLD`) führen sie automatisch
   aus.

> Die mitgelieferten System-Prompts sind auf **Deutsch**. Wenn du ein
> englischsprachiges Modell nutzt, passe die Prompts in der Admin-UI an.

---

## Microsoft 365 Audit-Logs (optional)

Zieht **Login-Ereignisse** (UserLoggedIn / UserLoginFailed) aus der Microsoft
365 Management Activity API und reichert sie mit GeoIP an. Fehlgeschlagene
Logins erscheinen zusätzlich als Alerts auf der Attack-Map und werden vom
KI-Agenten mit ausgewertet. Anzeige unter `/o365.html`, Konfiguration unter
**Admin → Microsoft 365**.

**Azure-App-Registrierung (einmalig):**

1. [entra.microsoft.com](https://entra.microsoft.com) → **App-Registrierungen →
   Neue Registrierung** (Single Tenant).
2. **API-Berechtigungen → Office 365 Management APIs → Anwendungsberechtigungen →
   `ActivityFeed.Read`** → **Administratorzustimmung erteilen**.
3. **Zertifikate & Geheimnisse → Neuer geheimer Clientschlüssel** → Wert kopieren.
4. In Warroom **Admin → Microsoft 365**: Tenant-ID, Client-ID, Client-Secret
   eintragen → **Verbindung testen**. Der Collector startet automatisch
   (Audit-Events treffen mit ~5–30 min Verzögerung ein).

> Bekannte Microsoft-App-IDs werden zu Klarnamen aufgelöst (Azure Portal,
> Outlook Web App, Teams, …); unbekannte erscheinen als gekürzte GUID.

---

## Entra ID Login-Blocking (optional)

Synct die Warroom-Blocklist zusätzlich in eine Entra **Named Location**, die an
eine **Conditional-Access-Policy** gebunden ist — M365-Logins von geblockten IPs
werden dann direkt bei Microsoft abgewiesen (ergänzend zum Firewall-IOC-Feed).
Konfiguration unter **Admin → Entra ID**.

- **Nutzt dieselbe App-Registrierung** wie der M365-Collector, braucht aber
  zusätzlich die Graph-Anwendungsberechtigungen
  `Policy.ReadWrite.ConditionalAccess` + `Policy.Read.All` (Admin-Consent) sowie
  eine **Entra ID P1**-Lizenz (in Microsoft 365 E3/E5 enthalten).
- **Named Location & Policy werden automatisch angelegt** (Self-Healing: wird die
  Policy extern gelöscht, legt der nächste Sync sie neu an). Policy-Name:
  *„Warroom — Block IPs (managed)"*.
- **Sicherheits-Default Report-Only:** Die Policy erzwingt zunächst nichts. Über
  den Admin-Toggle *„Erzwingung AN/AUS"* schaltest du sie scharf — dabei wird
  zwingend ein **Break-Glass-Konto** abgefragt (UPN oder Objekt-ID), das nie
  geblockt wird (Schutz gegen Selbst-Aussperrung). UPNs werden permission-frei
  aus den M365-Audit-Logs zur Objekt-ID aufgelöst.

---

## Telegram-Approvals (optional)

Schickt **jede offene Agent-Entscheidung** als Telegram-Nachricht mit
**✅ Approve / ❌ Reject**-Buttons; die Entscheidung wird direkt aus Telegram
ausgeführt (Long-Polling, kein öffentlicher Webhook nötig). Konfiguration unter
**Admin → Telegram**.

1. Bot via [@BotFather](https://t.me/BotFather) anlegen → Bot-Token kopieren.
2. `chat_id` ermitteln (z.B. über `@userinfobot`) und den Bot **zuerst einmal
   anschreiben** bzw. zur Gruppe hinzufügen.
3. In Warroom **Admin → Telegram**: Token + Chat-ID eintragen, aktivieren,
   **Testnachricht senden**.

> Nur der konfigurierte Chat darf Approvals ausführen; Taps aus anderen Chats
> werden abgewiesen.

---

## KI-Chat & Teams-Befehle

Eine **Befehls-Schnittstelle in natürlicher Sprache** — erreichbar über den
In-App-**KI-Chat** (`/chat.html`) und **Microsoft Teams**. Damit lassen sich per
Nachricht ausführen:

- **Blocklist:** IP / Domain / FQDN / URL setzen
  („blockiere 1.2.3.4", „sperre boese.example")
- **Endpoint isolieren** („isoliere PC-12345")
- **Quarantäne abfragen** („zeig die Quarantäne")
- **OSINT** zu IP/Domain („OSINT zu 8.8.8.8") — günstige Provider; Shodan bleibt
  Button-only
- **Statistik-Report** („Statistik-Report der letzten 7 Tage")

Die Intent-Erkennung läuft zuerst über einen **Keyword-Parser** (sofortige
Antwort für klare Befehle) und fällt bei unklaren Formulierungen auf den
**LLM-Agenten** zurück — funktioniert also auch ohne aktivierten Agenten.

**Microsoft Teams einrichten** (Admin → Microsoft Teams):
1. Im Team → **… → Verwalten → Outgoing Webhooks → Erstellen**.
2. Callback-URL: `https://<warroom>/api/teams/command` (Warroom muss per HTTPS
   erreichbar sein).
3. Das von Teams erzeugte **HMAC-Secret** im Admin hinterlegen — jede Teams-
   Anfrage wird damit signaturgeprüft.
4. Im Team `@Botname <befehl>` schreiben.

> Sicherheit: Der Teams-Endpoint ist von der `X-API-Key`-Prüfung ausgenommen und
> authentifiziert sich ausschließlich über die HMAC-Signatur. Block-Befehle aus
> Chat/Teams sind direkte menschliche Aktionen und werden sofort ausgeführt
> (Whitelist-IPs bleiben geschützt).

---

## Shodan-Host-Intelligence (optional)

Liefert pro IP **offene Ports** und **bekannte CVEs**. Diese werden langfristig in
`shodan_hosts` gespeichert und als optionaler Karten-Layer dargestellt
(Marker nach CVE-Anzahl gefärbt, Popup mit Ports + CVE-Links). Setzt einen
**Shodan API Key** voraus (Admin → OSINT).

**Shodan-Credits sind knapp — deshalb wird Shodan nie automatisch abgefragt:**

- **Mensch:** nur per Button **„🛰️ Shodan abfragen"** im OSINT-Panel
  (`POST /api/osint/shodan/{ip}`). Das routinemäßige OSINT-Panel löst **keine**
  Shodan-Abfrage aus.
- **Automatik:** die regelbasierten Agent-Loops fragen Shodan nur, wenn die
  günstigen Provider die IP bereits als **klar schädlich** einstufen
  (AbuseIPDB ≥ Schwelle / VirusTotal ≥ 3 / GreyNoise = malicious). Steuerbar
  über *Shodan: Auto-Abfrage bei schädlicher IP* + *Schwelle* (Admin → OSINT);
  abschalten ⇒ Shodan ist rein manuell.

Den Karten-Layer findest du in der **Attack-Map-Legende** unter „LAYER →
Shodan-Hosts" (und im OSIRIS-Dashboard als eigener Layer).

---

## Sicherheit & Härtung

Warroom ist als **internes Tool hinter VPN/Firewall** gedacht. Vor einem
Einsatz mit echten Daten unbedingt beachten:

- **`WARROOM_API_KEY` setzen.** Ohne läuft das Backend im *Open Mode* – jeder
  mit Netzwerkzugriff kann das Dashboard bedienen, IPs blocken/entblocken und
  Endpoints isolieren. Es gibt **kein Benutzer-Login**; der API-Key ist die
  einzige Zugangskontrolle.
- **`.env` enthält Klartext-Secrets** (DB-Passwort, Sophos-Secret, API-Keys).
  Die Datei ist in `.gitignore` und darf **nie** committet werden. Auch in der
  DB (`app_settings`) werden Secrets unverschlüsselt abgelegt → DB-Zugriff
  schützen.
- **Grafana** ist mit `admin/admin` vorbelegt und erlaubt **anonymen
  Viewer-Zugriff** (alle Logs/Karten ohne Login sichtbar). Passwort ändern und
  ggf. `GF_AUTH_ANONYMOUS_ENABLED=false` setzen, falls nicht erwünscht.
- **Kein HTTPS out-of-the-box** – nginx lauscht auf Port 80 (gemappt auf 8448).
  Für Produktion einen TLS-Reverse-Proxy davorsetzen.
- **Exponierte Ports** (5514, 2055, 3030, 5051, 5540, 8448) nur im
  vertrauenswürdigen Netz freigeben. **RedisInsight (5540)** läuft ohne Auth und
  erlaubt vollen Lese-/Schreibzugriff auf den Cache, **pgAdmin (5051)** hat zwar
  ein Login (`PGADMIN_EMAIL`/`PGADMIN_PASSWORD`), gibt aber vollen DB-Zugriff →
  beide hinter Firewall/Proxy absichern und Default-Passwörter ändern.
- **M365/Telegram-Secrets** (Client-Secret, Bot-Token) liegen wie alle anderen
  unverschlüsselt in `app_settings`. Die Entra-App sollte nur die minimal nötigen
  Graph-Berechtigungen besitzen.

Eine ausführliche Bewertung inkl. Verbesserungs-Roadmap steht in
[`docs/REVIEW.md`](docs/REVIEW.md).

---

## Stack & Services

| Komponente | Tech |
|------------|------|
| Backend | FastAPI 0.115, SQLAlchemy 2 async, APScheduler |
| Database | PostgreSQL 16 |
| Cache | Redis 7 |
| Frontend | Vanilla JS + Nginx (kein Build-Step) |
| Syslog | Custom Python Receiver (UDP/TCP 5514) |
| NetFlow | Custom Python Collector (UDP 2055) |
| GeoIP | MaxMind GeoLite2 (Fallback: ip-api.com) |
| Dashboards | Grafana 11 |
| Redis-GUI | RedisInsight (Cache-Inspektion) |
| DB-GUI | pgAdmin 4 (PostgreSQL-Verwaltung) |
| Cloud-APIs | Sophos Central/Email, Microsoft 365 (Management Activity + Graph), Telegram |

| Container | Port (Host) | Beschreibung |
|-----------|-------------|--------------|
| `frontend` | `8448` | Nginx, Static-Files + Reverse-Proxy |
| `backend` | (intern 8000) | FastAPI, REST + IOC-Feeds |
| `syslog` | `5514/udp+tcp` | Sophos-Firewall-Syslog-Empfänger |
| `netflow` | `2055/udp` | NetFlow v5/v9/IPFIX Collector |
| `postgres` | (intern 5432) | Daten-Persistenz |
| `redis` | (intern 6379) | Cache (Summary, OSINT-Lookups) |
| `redisinsight` | `5540` | RedisInsight — Redis-GUI (Cache vorkonfiguriert) |
| `pgadmin` | `5051` | pgAdmin 4 — PostgreSQL-GUI (Server „Warroom DB" vorkonfiguriert) |
| `grafana` | `3030` | Dashboards |

### Datenfluss

1. **Sophos Central API** → `collector.py` (alle 300 s default) → DB
2. **Sophos Firewall Syslog** → `syslog`-Service → DB (`firewall_logs`)
3. **NetFlow** → `netflow`-Service → DB (`netflow_buckets`)
4. **Microsoft 365 Activity API** → `o365_client.py` → DB (`o365_audit_logs`)
5. **Dashboard** → Backend liest aus DB → Frontend rendert
6. **Block-Aktion (UI/Agent/Telegram)** → `blocked_ips` / `_domains` / `_urls`
7. **Firewall pullt** `/ioc_*` → Backend liest die Tabellen live
8. **Optional: Entra-Sync** → Blocklist → Named Location + Conditional-Access-Policy

---

## Troubleshooting

| Symptom | Ursache / Lösung |
|---------|------------------|
| Dashboard leer, keine Alerts | Sophos-Credentials fehlen/falsch → `docker compose logs backend`. Ohne Sophos bleiben nur Syslog/NetFlow/Blocklist befüllt. |
| `401 invalid or missing X-API-Key` beim Feed-Abruf | Firewall sendet den `X-API-Key`-Header nicht oder falsch. |
| Karte zeigt keine Standorte | GeoIP-DB fehlt und ip-api.com ist rate-limitiert → mmdb-Dateien nach `./geoip/` legen. |
| Syslog/NetFlow kommt nicht an | Ports 5514/2055 auf dem Host freigegeben? Firewall sendet an die richtige IP? |
| Postgres startet nicht | `POSTGRES_PASSWORD` ≠ Passwort in `DATABASE_URL`. Müssen identisch sein. |
| Änderung in `.env` greift nicht | `.env`-Werte sind nur Startwerte. Laufende Änderungen über `/admin.html` oder `docker compose up -d` neu anwenden. |
| M365-Seite leer / „nicht konfiguriert" | Entra-App-Credentials unter Admin → Microsoft 365 fehlen oder `ActivityFeed.Read`-Consent nicht erteilt. Audit-Events kommen zudem mit Verzögerung. |
| Entra-Sync `403 not licensed` | Tenant ohne Entra ID P1 (in M365 E3/E5 enthalten) — Lizenz einem Benutzer zuweisen. CA-Policy lässt sich ohne P1 nicht anlegen/aktivieren. |
| Entra-Policy lässt sich nicht aktivieren | Kein Break-Glass-Konto gesetzt (Microsofts „BlockEveryonePolicy"-Schutz) bzw. UPN nicht auflösbar → Objekt-ID eintragen. |
| Telegram-Approval kommt nicht an | Bot nicht aktiviert, falsche `chat_id`, oder Bot wurde nie angeschrieben / nicht in der Gruppe. „Testnachricht senden" prüfen. |

---

## Lizenz

Privates Projekt — kein offizieller Support.

## Trademarks

Sophos, Sophos Central, Sophos Firewall und Sophos Intelix sind eingetragene
Marken von Sophos Ltd. Dieses Projekt ist nicht mit Sophos affiliated.

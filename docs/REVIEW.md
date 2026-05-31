# Warroom – Projekt-Review & Verbesserungs-Roadmap

Stand: 2026-05-29. Vollständiges Review von Backend, Frontend, Collectoren,
DB-Schema und Infrastruktur. Befunde sind am Code verifiziert; Schweregrade
spiegeln den Einsatz als **internes Tool hinter VPN/Firewall** wider.

## Gesamteindruck

Solide, durchdachte Architektur für ein privates SecOps-Tool. Besonders gut:

- **API-Key sauber server-seitig injiziert** – nginx hängt `X-API-Key` an
  `/api/*`, der Key liegt nie im Browser (`frontend/nginx.conf.template`).
- **Auth global** über `dependencies=[Depends(verify_api_key)]`
  (`backend/app/main.py:107`), Vergleich timing-safe via `hmac.compare_digest`.
- **Konsistenter XSS-Schutz**: `escapeHtml()` wird in allen JS-Dateien vor
  `innerHTML` verwendet.
- **Live-IOC-Feeds ohne Sync-Logik** – Block/Unblock sofort im Feed.
- **Laufzeit-Konfiguration** über Admin-UI ohne Container-Neustart.
- SQL durchgängig parametrisiert (`:since`, `:ips`); keine echte Injection
  gefunden – die `text()`-Fragmente sind statische Konstanten.

## Korrektur zu einem oft vermuteten Punkt

**Es liegen KEINE Secrets im Git-Repo.** `.env` ist in `.gitignore` und taucht
weder in `git ls-files` noch im `git log` auf. Die echten Credentials existieren
nur in der lokalen `.env`-Arbeitskopie – korrekt. (Trotzdem: lokale `.env`
schützen, nie committen.)

---

## Priorisierte Verbesserungen

### P1 – Vor Produktivbetrieb erledigen

| # | Thema | Datei(en) | Empfehlung |
|---|-------|-----------|------------|
| 1 | **Open-Mode-Default** | `config.py:27`, `main.py:42` | `WARROOM_API_KEY` ist leer-default → komplett offen. Setzen erzwingen/dokumentieren (im README jetzt als „dringend empfohlen" markiert). |
| 2 | **Grafana admin/admin + anonym** | `docker-compose.yml:98-102` | Default-Passwort und anonymer Viewer-Zugriff. Passwort über `GRAFANA_ADMIN_PASSWORD` setzen; anonym ggf. deaktivieren. |
| 3 | **Kein HTTPS** | `nginx.conf.template` | Nur Port 80. TLS-Reverse-Proxy davor oder Zertifikat in nginx. |
| 4 | **Sicherheits-Header fehlen** | `nginx.conf.template` | `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, CSP ergänzen. Schnell umsetzbar, hoher Nutzen. |

### P2 – Robustheit & Datenhaltung

| # | Thema | Datei(en) | Empfehlung |
|---|-------|-----------|------------|
| 5 | **Keine DB-Retention** | `db/init.sql` | `firewall_logs`, `events`, `alerts`, `geoip_cache` wachsen unbegrenzt (nur NetFlow hat 30-Tage-Cleanup). Cleanup-Job oder Range-Partitionierung nach `created_at`. |
| 6 | **Syslog-Queue verwirft still** | `syslog/syslog_receiver.py` (Queue maxsize 10000) | Bei Lastspitzen werden Messages mit reiner `warning` verworfen. Counter/Metrik + ggf. Persistenz ergänzen. |
| 7 | **Healthchecks fehlen** | `docker-compose.yml` (syslog, netflow, backend, frontend) | Nur postgres/redis haben Healthchecks. Crash bleibt sonst unbemerkt. |
| 8 | **Keine Ressourcenlimits** | `docker-compose.yml` | `deploy.resources.limits` je Service, damit ein Leak nicht den Host killt. |
| 9 | **LLM-Endpoint-Ausfall** | `agent.py`, `main.py:72-91` | Scheduler feuert alle ~120 s weiter, jede Decision „failed". Backoff/Circuit-Breaker bei wiederholtem Fehlschlag. |

### P3 – Code-Qualität & Wartbarkeit

| # | Thema | Datei(en) | Empfehlung |
|---|-------|-----------|------------|
| 10 | **JS-Duplizierung** | `frontend/js/*.js` | `escapeHtml`/`formatTime`/`truncate` 4–6× definiert. In `js/common.js` zentralisieren. |
| 11 | **inline `onclick` mit String-Interpolation** | `app.js` (block-Buttons) | Komma/Quote-Bruch möglich. Auf `addEventListener` + `data-*`-Attribute umstellen. |
| 12 | **Doppelte SQL-Fragmente** | `agent.py` vs. `main.py` (`_WAF_FILTER_SQL*`) | WAF/IPS-Filter an einer Stelle definieren und importieren. |
| 13 | **Blocking MaxMind-Lookup in async** | `geoip_service.py:92` | `_lookup_maxmind` ist synchron; memory-mapped → minimal, aber sauberer via `run_in_executor`. |
| 14 | **Redis-Client nie geschlossen** | `geoip_service.py:24-28` | In `lifespan`-Shutdown `await _redis.aclose()` ergänzen. |
| 15 | **LLM-JSON-Parsing tolerant** | `agent.py` `_parse_decision` | Nimmt „letzten Block" – Reasoning-Modelle können Draft-Aktionen hinterlassen. Strikteres Schema/Validierung. |
| 16 | **Hardcodierte /24-Subnetzmaske** | `agent.py` (Failed-Login-Subnet) | Maske konfigurierbar machen (z. B. auch /16). |
| 17 | **Postgres SSL disabled** | `grafana/.../postgres.yml:sslmode=disable` | Im selben Docker-Netz vertretbar; bei externem DB-Zugriff aktivieren. |

### P4 – Nice-to-have

- Strukturiertes (JSON-)Logging im Backend für Aggregation.
- Subresource Integrity (SRI) für CDN-Skripte in den HTML-Seiten.
- DB-Backup-/WAL-Strategie für `postgres_data` dokumentieren.
- IDN-/Homograph-Prüfung bei Domain-/URL-Normalisierung (`main.py`).
- NetFlow-Template-Cache ohne TTL (theoretischer Memory-Drift bei
  langlaufenden Exportern mit Template-Reuse).

---

## Quick Wins (klein, sofort, hoher Nutzen)

1. ✅ **Erledigt** – Security-Header + CSP in `nginx.conf.template` (P1 #4).
   CSP behält vorerst `'unsafe-inline'` im `script-src`, weil noch Inline-
   `onclick`-Handler existieren (siehe P3 #11). Nach deren Umbau kann
   `'unsafe-inline'` entfernt werden → strikte Policy.
2. ✅ **Teilweise erledigt** – `frontend/js/common.js` zentralisiert jetzt
   `escapeHtml()` + `escapeAttr()` (vorher 5×/2× dupliziert). `formatTime()`
   und `truncate()` bleiben bewusst seitenlokal (unterscheiden sich je Seite).
3. ✅ **Erledigt** – Redis-`close_redis()` wird im `lifespan`-Shutdown
   aufgerufen (`geoip_service.py` / `main.py`).
4. ⬜ Offen – Healthcheck für `backend` (`GET /` o. `/health`) und `syslog`
   (P2 #7). Achtung: globale Auth-Dependency → entweder ein auth-freier
   `/health`-Endpoint oder der Healthcheck sendet den `X-API-Key`.
5. ⬜ Offen – Cron-Cleanup-Query für `firewall_logs`/`geoip_cache` (P2 #5).

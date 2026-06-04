"""Entra ID (Microsoft Graph) conditional-access IP blocking.

Pushes Warroom's blocked_ips into a Microsoft Graph **named location** that is
referenced by a **conditional-access policy** which blocks sign-ins from those
IPs. This makes M365 logins from blocked addresses fail at Microsoft directly —
complementing the firewall IOC feed.

Reuses the O365 app registration credentials, but needs extra *application*
Graph permissions (admin-consented):
  * Policy.Read.All
  * Policy.ReadWrite.ConditionalAccess

Safety: the CA policy is created in **reportOnly** state. An admin must flip it
to **enabled** in the Entra portal to actually enforce blocking — Warroom never
turns on enforcement on its own, so a misconfiguration can't lock everyone out.
Only IPv4/IPv6 single addresses and CIDRs are pushed; Graph caps a named
location at 2000 ranges, so we sync the most recent N.
"""

import ipaddress
import logging
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import select

from app.config import settings
from app.database import async_session
from app.models import BlockedIp
from app.sophos_client import _request  # shared 429/5xx retry helper

logger = logging.getLogger(__name__)

GRAPH = "https://graph.microsoft.com/v1.0"
NAMED_LOCATION_DISPLAY = "Warroom Blocklist"
CA_POLICY_DISPLAY = "Warroom — Block IPs (managed)"
MAX_RANGES = 2000


class EntraClient:
    def __init__(self):
        self.access_token: str | None = None
        self.token_expires: datetime | None = None
        self._client: httpx.AsyncClient | None = None

    def reload(self) -> None:
        self.access_token = None
        self.token_expires = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=30)
        return self._client

    async def aclose(self) -> None:
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()
        self._client = None

    @property
    def configured(self) -> bool:
        # Same app registration as the O365 collector.
        return bool(
            settings.o365_tenant_id
            and settings.o365_client_id
            and settings.o365_client_secret
        )

    async def _authenticate(self) -> None:
        client = self._get_client()
        resp = await _request(
            client, "post",
            f"https://login.microsoftonline.com/{settings.o365_tenant_id}/oauth2/v2.0/token",
            data={
                "grant_type": "client_credentials",
                "client_id": settings.o365_client_id,
                "client_secret": settings.o365_client_secret,
                "scope": "https://graph.microsoft.com/.default",
            },
        )
        resp.raise_for_status()
        data = resp.json()
        self.access_token = data["access_token"]
        self.token_expires = datetime.now(timezone.utc) + timedelta(
            seconds=data.get("expires_in", 3600) - 60
        )

    async def _ensure_token(self) -> None:
        if (
            self.access_token is None
            or self.token_expires is None
            or datetime.now(timezone.utc) >= self.token_expires
        ):
            await self._authenticate()

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.access_token}", "Content-Type": "application/json"}

    @staticmethod
    def _to_cidr(ip: str) -> str | None:
        """Graph ipRange expects CIDR notation; turn a bare host into a /32//128."""
        try:
            addr = ipaddress.ip_address(ip.strip())
        except ValueError:
            try:
                ipaddress.ip_network(ip.strip(), strict=False)
                return ip.strip()
            except ValueError:
                return None
        return f"{addr}/32" if addr.version == 4 else f"{addr}/128"

    async def _build_ranges(self) -> list[dict]:
        async with async_session() as db:
            rows = (await db.execute(
                select(BlockedIp.ip)
                .order_by(BlockedIp.blocked_at.desc())
                .limit(MAX_RANGES)
            )).scalars().all()
        ranges: list[dict] = []
        for ip in rows:
            cidr = self._to_cidr(ip)
            if cidr:
                ranges.append({
                    "@odata.type": "#microsoft.graph.iPv6CidrRange" if ":" in cidr
                    else "#microsoft.graph.iPv4CidrRange",
                    "cidrAddress": cidr,
                })
        return ranges

    async def _find_named_location(self) -> str | None:
        client = self._get_client()
        resp = await _request(
            client, "get",
            f"{GRAPH}/identity/conditionalAccess/namedLocations"
            f"?$filter=displayName eq '{NAMED_LOCATION_DISPLAY}'",
            headers=self._headers(),
        )
        resp.raise_for_status()
        for loc in resp.json().get("value", []):
            return loc["id"]
        return None

    async def _ensure_named_location(self, ranges: list[dict]) -> str:
        client = self._get_client()
        loc_id = settings.entra_named_location_id or await self._find_named_location()
        body = {
            "@odata.type": "#microsoft.graph.ipNamedLocation",
            "displayName": NAMED_LOCATION_DISPLAY,
            "isTrusted": False,
            "ipRanges": ranges or [{"@odata.type": "#microsoft.graph.iPv4CidrRange",
                                    "cidrAddress": "192.0.2.0/32"}],  # TEST-NET placeholder
        }
        if loc_id:
            resp = await _request(
                client, "patch",
                f"{GRAPH}/identity/conditionalAccess/namedLocations/{loc_id}",
                headers=self._headers(), json=body,
            )
            resp.raise_for_status()
            return loc_id
        resp = await _request(
            client, "post",
            f"{GRAPH}/identity/conditionalAccess/namedLocations",
            headers=self._headers(), json=body,
        )
        resp.raise_for_status()
        new_id = resp.json()["id"]
        await _persist_setting("entra_named_location_id", new_id)
        logger.info(f"entra: created named location {NAMED_LOCATION_DISPLAY} ({new_id})")
        return new_id

    async def _resolve_excludes(self) -> list[str]:
        """Turn the configured break-glass list (UPNs and/or object ids) into
        user object ids — CA policies only accept object ids. UPNs are resolved
        via Graph (needs User.Read.All) and, failing that, from the collected
        M365 audit logs (UserId → UserKey), which needs no extra permission."""
        raw = [x.strip() for x in (settings.entra_ca_exclude_users or "").split(",") if x.strip()]
        if not raw:
            return []
        client = self._get_client()
        out: list[str] = []
        for val in raw:
            if "@" in val:  # looks like a UPN → resolve to an object id
                resolved = None
                try:
                    r = await _request(
                        client, "get",
                        f"{GRAPH}/users/{val}?$select=id",
                        headers=self._headers(),
                    )
                    if r.status_code == 200:
                        resolved = r.json()["id"]
                except Exception:
                    pass
                if resolved is None:
                    resolved = await _upn_to_object_id(val)
                out.append(resolved or val)  # raw passthrough → Graph will flag it
            else:
                out.append(val)  # already an object id
        return out

    async def _ensure_ca_policy(self, location_id: str) -> str:
        client = self._get_client()
        pol_id = settings.entra_ca_policy_id
        excludes = await self._resolve_excludes()
        users_cond = {"includeUsers": ["All"]}
        if excludes:
            users_cond["excludeUsers"] = excludes
        # Block all users signing in from the named location. Created
        # report-only so an admin consciously enables enforcement.
        body = {
            "displayName": CA_POLICY_DISPLAY,
            "state": "enabledForReportingButNotEnforced",
            "conditions": {
                "applications": {"includeApplications": ["All"]},
                "users": users_cond,
                "locations": {"includeLocations": [location_id]},
            },
            "grantControls": {"operator": "OR", "builtInControls": ["block"]},
        }
        if pol_id:
            # Only refresh the location binding; never touch an admin-set state.
            resp = await _request(
                client, "patch",
                f"{GRAPH}/identity/conditionalAccess/policies/{pol_id}",
                headers=self._headers(),
                json={"conditions": body["conditions"]},
            )
            if resp.status_code == 404:
                # Policy was deleted out from under us → drop the stale id and
                # fall through to recreate it below (self-healing).
                logger.warning(f"entra: stored CA policy {pol_id} gone (404) — recreating")
                await _persist_setting("entra_ca_policy_id", "")
                pol_id = None
            else:
                resp.raise_for_status()
                return pol_id
        # Creating fresh: Microsoft rejects an "all users + block" policy with no
        # exclusion (BlockEveryonePolicy guard). Require a break-glass account so
        # auto-create can never lock the whole tenant out.
        if not excludes:
            raise ValueError(
                "Kein Break-Glass-Konto gesetzt — Microsoft lehnt eine Block-Policy "
                "ohne Ausnahme ab. Trage unter Admin → Entra ein Notfall-Konto "
                "(UPN oder Objekt-ID) bei 'Ausgeschlossene Benutzer' ein."
            )
        resp = await _request(
            client, "post",
            f"{GRAPH}/identity/conditionalAccess/policies",
            headers=self._headers(), json=body,
        )
        resp.raise_for_status()
        new_id = resp.json()["id"]
        await _persist_setting("entra_ca_policy_id", new_id)
        logger.warning(
            f"entra: created CA policy '{CA_POLICY_DISPLAY}' ({new_id}) in REPORT-ONLY mode — "
            f"enable enforcement in the Entra portal to actually block."
        )
        return new_id

    async def sync_blocklist(self) -> dict:
        """Push blocked_ips → named location, ensure the CA policy binds it."""
        if not (settings.entra_block_enabled and self.configured):
            return {"ok": False, "skipped": "disabled or not configured"}
        await self._ensure_token()
        ranges = await self._build_ranges()
        location_id = await self._ensure_named_location(ranges)
        policy_id = await self._ensure_ca_policy(location_id)
        logger.info(f"entra: synced {len(ranges)} IP range(s) to named location {location_id}")
        return {"ok": True, "ranges": len(ranges), "location_id": location_id, "policy_id": policy_id}

    async def find_ca_policy(self) -> dict | None:
        """Locate the Warroom block policy. Prefers the stored id, then falls
        back to a name match (our managed name or the manual 'Warroom' one),
        caching the resolved id. Returns the raw policy dict or None."""
        await self._ensure_token()
        client = self._get_client()
        # 1. stored id
        if settings.entra_ca_policy_id:
            r = await _request(
                client, "get",
                f"{GRAPH}/identity/conditionalAccess/policies/{settings.entra_ca_policy_id}"
                "?$select=id,displayName,state",
                headers=self._headers(),
            )
            if r.status_code == 200:
                return r.json()
            if r.status_code == 404:
                # stale id (policy deleted externally) → clear so a sync recreates
                await _persist_setting("entra_ca_policy_id", "")
        # 2. by name
        r = await _request(
            client, "get",
            f"{GRAPH}/identity/conditionalAccess/policies?$select=id,displayName,state",
            headers=self._headers(),
        )
        r.raise_for_status()
        policies = r.json().get("value", [])
        match = None
        for p in policies:
            name = (p.get("displayName") or "")
            if name == CA_POLICY_DISPLAY or "warroom" in name.lower():
                match = p
                break
        if match:
            await _persist_setting("entra_ca_policy_id", match["id"])
        return match

    async def get_ca_policy_state(self) -> dict:
        """Status snapshot for the admin UI."""
        if not self.configured:
            return {"configured": False, "found": False}
        try:
            pol = await self.find_ca_policy()
        except httpx.HTTPStatusError as e:
            return {"configured": True, "found": False, "error": f"HTTP {e.response.status_code}"}
        except Exception as e:
            return {"configured": True, "found": False, "error": str(e)[:200]}
        if not pol:
            return {"configured": True, "found": False}
        return {
            "configured": True, "found": True,
            "id": pol["id"], "displayName": pol.get("displayName"),
            "state": pol.get("state"),
            "enabled": pol.get("state") == "enabled",
            # Human-friendly exclusion value (UPNs/ids as the admin typed them)
            # so the UI can pre-fill the activation prompt.
            "exclude_users": settings.entra_ca_exclude_users or "",
        }

    async def set_ca_policy_state(self, enabled: bool, exclude_users: str | None = None) -> dict:
        """Flip the block policy on/off. 'on' = enforcing 'enabled',
        'off' = 'disabled'. When enabling, the break-glass exclusion is applied
        to the policy first — enforcement is refused without one (self-lockout
        guard, and Microsoft rejects it anyway)."""
        pol = await self.find_ca_policy()
        if not pol:
            raise ValueError("no Warroom conditional-access policy found")
        client = self._get_client()

        # Optionally update the excluded accounts (passed from the activation UI).
        if exclude_users is not None:
            await _persist_setting("entra_ca_exclude_users", exclude_users.strip())

        if enabled:
            excludes = await self._resolve_excludes()
            if not excludes:
                raise ValueError(
                    "Kein Break-Glass-Konto gesetzt — die erzwingende Block-Policy "
                    "kann ohne Ausnahme nicht aktiviert werden (Schutz gegen "
                    "Selbst-Aussperrung). Gib mindestens ein Konto an."
                )
            # CA policies only accept object ids; a leftover UPN means we couldn't
            # resolve it (account never seen in the audit logs + no User.Read.All).
            unresolved = [x for x in excludes if "@" in x]
            if unresolved:
                raise ValueError(
                    f"Konnte UPN nicht zu einer Objekt-ID auflösen: {', '.join(unresolved)}. "
                    "Trage stattdessen die Entra-Objekt-ID des Kontos ein (Portal → "
                    "Benutzer → Objekt-ID), oder gewähre der App die Graph-Berechtigung "
                    "User.Read.All."
                )
            # Re-apply full conditions so the exclusion AND the location binding
            # are present before enforcing. PATCHing 'conditions' replaces the
            # whole object, so we send applications + users + locations together.
            loc_id = settings.entra_named_location_id or await self._find_named_location()
            conditions = {
                "applications": {"includeApplications": ["All"]},
                "users": {"includeUsers": ["All"], "excludeUsers": excludes},
            }
            if loc_id:
                conditions["locations"] = {"includeLocations": [loc_id]}
            rc = await _request(
                client, "patch",
                f"{GRAPH}/identity/conditionalAccess/policies/{pol['id']}",
                headers=self._headers(), json={"conditions": conditions},
            )
            if rc.status_code not in (200, 204):
                rc.raise_for_status()

        target = "enabled" if enabled else "disabled"
        r = await _request(
            client, "patch",
            f"{GRAPH}/identity/conditionalAccess/policies/{pol['id']}",
            headers=self._headers(), json={"state": target},
        )
        if r.status_code not in (200, 204):
            r.raise_for_status()
        return {"ok": True, "id": pol["id"], "displayName": pol.get("displayName"), "state": target}

    async def test(self) -> dict:
        if not self.configured:
            return {"ok": False, "error": "O365 app credentials not set"}
        try:
            await self._ensure_token()
            client = self._get_client()
            resp = await _request(
                client, "get",
                f"{GRAPH}/identity/conditionalAccess/namedLocations?$top=1",
                headers=self._headers(),
            )
            if resp.status_code == 403:
                return {"ok": False, "error": "403 — missing Policy.ReadWrite.ConditionalAccess consent"}
            resp.raise_for_status()
            return {"ok": True}
        except httpx.HTTPStatusError as e:
            return {"ok": False, "error": f"HTTP {e.response.status_code}: {e.response.text[:200]}"}
        except Exception as e:
            return {"ok": False, "error": str(e)[:300]}


async def _upn_to_object_id(upn: str) -> str | None:
    """Resolve a UPN to its Entra object id from the collected M365 audit logs
    (raw_data.UserKey is the signing-in user's object id). Permission-free."""
    from sqlalchemy import text
    try:
        async with async_session() as db:
            row = (await db.execute(
                text("""
                    SELECT raw_data->>'UserKey'
                    FROM o365_audit_logs
                    WHERE user_id = :upn
                      AND raw_data->>'UserKey' ~ '^[0-9a-fA-F-]{36}$'
                    ORDER BY created_at DESC
                    LIMIT 1
                """),
                {"upn": upn},
            )).first()
        return row[0] if row else None
    except Exception as e:
        logger.debug(f"entra: UPN→id lookup failed for {upn}: {e}")
        return None


async def _persist_setting(key: str, value: str) -> None:
    """Store an auto-created Graph object id so we reuse it next time.

    Writes straight to app_settings + the settings singleton. We deliberately
    do NOT route through save_settings(): that reloads the Entra client, which
    would null our access token *mid-sync* and break the next Graph call.
    """
    try:
        from app.models import AppSetting
        async with async_session() as db:
            row = await db.get(AppSetting, key)
            if row is None:
                db.add(AppSetting(key=key, value=value))
            else:
                row.value = value
            await db.commit()
        setattr(settings, key, value)
    except Exception as e:
        logger.warning(f"entra: could not persist {key}: {e}")


entra_client = EntraClient()


async def entra_sync_job() -> None:
    if not (settings.entra_block_enabled and entra_client.configured):
        return
    try:
        await entra_client.sync_blocklist()
    except Exception as e:
        logger.warning(f"entra sync failed: {e}")

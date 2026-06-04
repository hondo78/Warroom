"""Microsoft 365 Management Activity API client.

Pulls the unified audit log (content type Audit.AzureActiveDirectory) and
filters it down to interactive login events (UserLoggedIn / UserLoginFailed).
Auth is an Entra ID app registration with the *application* permission
ActivityFeed.Read on "Office 365 Management APIs" (admin consent required).

Flow per collection cycle:
  1. client-credentials token for https://manage.office.com/.default
  2. ensure the subscription for the content type is started (idempotent;
     error code AF20024 = "already enabled" is treated as success)
  3. list content blobs for the requested time window (paged via NextPageUri)
  4. fetch each blob and keep only login operations
"""

import logging
from datetime import datetime, timedelta, timezone

import httpx

from app.config import settings
# Shared retry helper (429/5xx with Retry-After handling) — same semantics
# wanted here, so reuse instead of copy-pasting the tenacity setup.
from app.sophos_client import _request

logger = logging.getLogger(__name__)

CONTENT_TYPE = "Audit.AzureActiveDirectory"
LOGIN_OPERATIONS = {"UserLoggedIn", "UserLoginFailed"}

# Well-known Microsoft first-party application IDs → display names.
# The audit records only carry the GUID; Microsoft documents these in the
# sign-in-report troubleshooting docs and community-maintained lists
# (dafthack client-id gist, dmb2168/o365-appids). Unknown IDs are shown as
# shortened GUIDs in the UI — deliberately no guessing.
O365_APP_NAMES: dict[str, str] = {
    "c44b4083-3bb0-49c1-b47d-974e53cbdf3c": "Azure Portal",
    "9199bf20-a13f-4107-85dc-02114787ef48": "Outlook Web App",
    "29d9ed98-a469-4536-ade2-f981bc1d605e": "Microsoft Authentication Broker",
    "00000002-0000-0ff1-ce00-000000000000": "Exchange Online",
    "00000003-0000-0ff1-ce00-000000000000": "SharePoint Online",
    "00000003-0000-0000-c000-000000000000": "Microsoft Graph",
    "00000002-0000-0000-c000-000000000000": "Azure AD Graph (legacy)",
    "d3590ed6-52b3-4102-aeff-aad2292ab01c": "Microsoft Office",
    "89bee1f7-5e6e-4d8a-9f3d-ecd601259da7": "Office 365 Shell",
    "4765445b-32c6-49b0-83e6-1d93765276ca": "OfficeHome (office.com)",
    "1fec8e78-bce4-4aaf-ab1b-5451cc387264": "Microsoft Teams",
    "5e3ce6c0-2b1f-4285-8d4b-75ee78787346": "Microsoft Teams Web",
    "27922004-5251-4030-b22d-91ecd9a37ea4": "Outlook Mobile",
    "e9b154d0-7658-433b-bb25-6b8e0a8a7c59": "Outlook Lite",
    "ab9b8c07-8f02-4f72-87fa-80105867a763": "OneDrive Sync",
    "b26aadf8-566f-4478-926f-589f601d9c74": "OneDrive",
    "af124e86-4e96-495a-b70a-90f90ab96707": "OneDrive iOS",
    "766d89a4-d6a6-444d-8a5e-e1a18622288a": "OneDrive",
    "4813382a-8fa7-425e-ab75-3b753aab3abb": "Microsoft Authenticator",
    "e9c51622-460d-4d3d-952d-966a5b1da34c": "Microsoft Edge",
    "ecd6b820-32c2-49b6-98a6-444530e5a77a": "Microsoft Edge",
    "f44b1140-bc5e-48c6-8dc0-5cf5a53c0e34": "Microsoft Edge",
    "f2d19332-a09d-48c8-a53b-c49ae5502dfc": "Microsoft Edge Auth",
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46": "Azure CLI",
    "1950a258-227b-4e31-a9cf-717495945fc2": "Azure PowerShell",
    "1b730954-1685-4b74-9bfd-dac224a7b894": "Azure AD PowerShell",
    "14d82eec-204b-4c2f-b7e8-296a70dab67e": "Microsoft Graph CLI",
    "fb78d390-0c51-40cd-8e17-fdbfab77341b": "Exchange REST PowerShell",
    "a0c73c16-a7e3-4564-9a95-2bdf47383716": "Exchange Online PowerShell",
    "9bc3ab49-b65d-410a-85ad-de819febfddc": "SPO Management Shell",
    "26a7ee05-5602-4d76-a7ba-eae8b7b67941": "Windows Search",
    "1b3c667f-cde3-4090-b60b-3d2abd0117f0": "Windows Spotlight",
    "268761a2-03f3-40df-8a8b-c3db24145b6b": "Universal Store Client",
    "a40d7d7d-59aa-447e-a655-679a4107e548": "Accounts Control UI",
    "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223": "Intune Company Portal",
    "0ec893e0-5785-4de6-99da-4ed124e5296c": "Office UWP PWA",
    "22098786-6e16-43cc-a27d-191a01a1e3b5": "Microsoft To-Do",
    "c0d2a505-13b8-4ae0-aa9e-cddd5eab0b12": "Power BI",
    "de8bc8b5-d9f9-48b1-a8ad-b748da725064": "Graph Explorer",
    "cb1056e2-e479-49de-ae31-7812af012ed8": "Azure AD Connect",
    "0000000c-0000-0000-c000-000000000000": "My Apps Portal",
    "00000006-0000-0ff1-ce00-000000000000": "M365 Admin Portal",
    "cb2ff863-7f30-4ced-ab89-a00194bcf6d9": "Azure AI Studio",
}


def app_display_name(app_id: str | None) -> str | None:
    """Friendly name for a well-known Microsoft app ID, else None."""
    if not app_id:
        return None
    return O365_APP_NAMES.get(app_id.lower())


def _iso_compact(dt: datetime) -> str:
    """Management API wants 'YYYY-MM-DDTHH:MM:SS' (UTC, no offset suffix)."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


class O365Client:
    def __init__(self):
        self.access_token: str | None = None
        self.token_expires: datetime | None = None
        self._subscription_ok: bool = False
        self._client: httpx.AsyncClient | None = None

    def reload(self) -> None:
        """Drop cached auth state; next call re-authenticates with the
        credentials currently set on the settings singleton."""
        self.access_token = None
        self.token_expires = None
        self._subscription_ok = False

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
        return bool(
            settings.o365_tenant_id
            and settings.o365_client_id
            and settings.o365_client_secret
        )

    def _base_url(self) -> str:
        return f"https://manage.office.com/api/v1.0/{settings.o365_tenant_id}/activity/feed"

    async def _authenticate(self) -> None:
        client = self._get_client()
        resp = await _request(
            client,
            "post",
            f"https://login.microsoftonline.com/{settings.o365_tenant_id}/oauth2/v2.0/token",
            data={
                "grant_type": "client_credentials",
                "client_id": settings.o365_client_id,
                "client_secret": settings.o365_client_secret,
                "scope": "https://manage.office.com/.default",
            },
        )
        resp.raise_for_status()
        data = resp.json()
        self.access_token = data["access_token"]
        self.token_expires = datetime.now(timezone.utc) + timedelta(
            seconds=data.get("expires_in", 3600) - 60
        )
        logger.info(f"Authenticated with Microsoft 365 (tenant: {settings.o365_tenant_id})")

    async def _ensure_token(self) -> None:
        if (
            self.access_token is None
            or self.token_expires is None
            or datetime.now(timezone.utc) >= self.token_expires
        ):
            await self._authenticate()

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.access_token}"}

    async def _ensure_subscription(self) -> None:
        """Start the audit subscription once per process. Microsoft returns
        HTTP 400 with error code AF20024 when it is already enabled — that is
        the normal steady state, not an error."""
        if self._subscription_ok:
            return
        client = self._get_client()
        resp = await _request(
            client,
            "post",
            f"{self._base_url()}/subscriptions/start",
            params={
                "contentType": CONTENT_TYPE,
                "PublisherIdentifier": settings.o365_tenant_id,
            },
            headers=self._headers(),
        )
        if resp.status_code == 200:
            self._subscription_ok = True
            logger.info(f"O365 subscription active: {CONTENT_TYPE}")
            return
        body = resp.text or ""
        if resp.status_code == 400 and "AF20024" in body:
            self._subscription_ok = True
            logger.debug(f"O365 subscription already enabled: {CONTENT_TYPE}")
            return
        resp.raise_for_status()

    async def _list_content(self, start: datetime, end: datetime) -> list[dict]:
        """List available content blobs for the window (paged)."""
        client = self._get_client()
        blobs: list[dict] = []
        url: str | None = f"{self._base_url()}/subscriptions/content"
        params: dict | None = {
            "contentType": CONTENT_TYPE,
            "PublisherIdentifier": settings.o365_tenant_id,
            "startTime": _iso_compact(start),
            "endTime": _iso_compact(end),
        }
        while url:
            resp = await _request(client, "get", url, params=params, headers=self._headers())
            resp.raise_for_status()
            page = resp.json()
            if isinstance(page, list):
                blobs.extend(page)
            # Pagination: follow NextPageUri verbatim (it carries all params).
            url = resp.headers.get("NextPageUri")
            params = None
        return blobs

    async def get_login_records(self, start: datetime, end: datetime) -> list[dict]:
        """Fetch all login audit records (UserLoggedIn / UserLoginFailed)
        whose content blobs were created inside [start, end].

        Note the API constraints: the window may span at most 24 hours and
        must lie within the last 7 days — callers clamp accordingly.
        """
        if not self.configured:
            return []
        await self._ensure_token()
        await self._ensure_subscription()

        blobs = await self._list_content(start, end)
        client = self._get_client()
        records: list[dict] = []
        for blob in blobs:
            uri = blob.get("contentUri")
            if not uri:
                continue
            try:
                resp = await _request(client, "get", uri, headers=self._headers())
                resp.raise_for_status()
                for item in resp.json():
                    if item.get("Operation") in LOGIN_OPERATIONS:
                        records.append(item)
            except Exception as e:
                logger.warning(f"O365 content blob fetch failed ({blob.get('contentId')}): {e}")
        logger.info(
            f"O365: {len(blobs)} content blob(s) in window, {len(records)} login record(s)"
        )
        return records


o365_client = O365Client()

import logging
from datetime import datetime, timedelta, timezone

import httpx
from tenacity import (
    AsyncRetrying,
    retry_if_exception,
    stop_after_attempt,
)

from app.config import settings

logger = logging.getLogger(__name__)

AUTH_URL = "https://id.sophos.com/api/v2/oauth2/token"
WHOAMI_URL = "https://api.central.sophos.com/whoami/v1"


def _iso_z(dt: datetime) -> str:
    """Sophos APIs expect ISO-8601 with trailing Z, not +00:00."""
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class _RetryableHTTP(Exception):
    """Marks a 429/5xx response so tenacity retries it; carries Retry-After."""

    def __init__(self, response: httpx.Response):
        self.status_code = response.status_code
        self.retry_after = response.headers.get("Retry-After")
        super().__init__(f"HTTP {response.status_code}")


def _should_retry(exc: BaseException) -> bool:
    return isinstance(exc, (httpx.RequestError, _RetryableHTTP))


def _wait(retry_state) -> float:
    exc = retry_state.outcome.exception() if retry_state.outcome else None
    if isinstance(exc, _RetryableHTTP) and exc.retry_after:
        try:
            return min(float(exc.retry_after), 60.0)
        except ValueError:
            pass
    # Exponential backoff: 1s, 2s, 4s, 8s, capped at 30s
    return min(2 ** (retry_state.attempt_number - 1), 30.0)


async def _request(
    client: httpx.AsyncClient, method: str, url: str, **kwargs
) -> httpx.Response:
    """Send a request, retrying on 429/5xx and network errors."""
    async for attempt in AsyncRetrying(
        retry=retry_if_exception(_should_retry),
        stop=stop_after_attempt(5),
        wait=_wait,
        reraise=True,
    ):
        with attempt:
            resp = await client.request(method, url, **kwargs)
            if resp.status_code == 429 or 500 <= resp.status_code < 600:
                logger.warning(
                    f"Sophos {method.upper()} {url} -> {resp.status_code}; "
                    f"retrying (attempt {attempt.retry_state.attempt_number})"
                )
                raise _RetryableHTTP(resp)
            return resp
    raise RuntimeError("unreachable")  # pragma: no cover


class SophosClient:
    def __init__(self):
        self.access_token: str | None = None
        self.token_expires: datetime | None = None
        self.tenant_id: str | None = settings.sophos_tenant_id or None
        self.data_region_url: str | None = None
        self._whoami_resolved: bool = False
        # Lazily created in _get_client(); reused across all Sophos calls so
        # the TLS handshake to api.central.sophos.com is paid once. Per-call
        # timeouts are passed via the `timeout=` kwarg in _request.
        self._client: httpx.AsyncClient | None = None

    def reload(self) -> None:
        """Drop cached auth state so the next call re-authenticates with
        whatever credentials are now set on the settings singleton.

        The HTTP client stays open — httpx pools per host and the Sophos
        endpoints don't change with credentials.
        """
        self.access_token = None
        self.token_expires = None
        self.tenant_id = settings.sophos_tenant_id or None
        self.data_region_url = None
        self._whoami_resolved = False

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            # 30s default keeps regular calls snappy; long-running list
            # endpoints (get_endpoints) pass timeout=60 per call.
            self._client = httpx.AsyncClient(timeout=30)
        return self._client

    async def aclose(self) -> None:
        """Close the pooled client. Called from the FastAPI lifespan on shutdown."""
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()
        self._client = None

    async def _authenticate(self):
        client = self._get_client()
        resp = await _request(
            client,
            "post",
            AUTH_URL,
            data={
                "grant_type": "client_credentials",
                "client_id": settings.sophos_client_id,
                "client_secret": settings.sophos_client_secret,
                "scope": "token",
            },
        )
        resp.raise_for_status()
        data = resp.json()
        self.access_token = data["access_token"]
        self.token_expires = datetime.now(timezone.utc) + timedelta(
            seconds=data.get("expires_in", 3600) - 60
        )

        # whoami needs the bearer token; do it once per process even if
        # tenant_id was preconfigured — we still need data_region_url.
        if not self._whoami_resolved:
            await self._resolve_whoami()

        logger.info(f"Authenticated with Sophos Central (tenant: {self.tenant_id})")

    async def _resolve_whoami(self):
        # whoami must be called WITHOUT the X-Tenant-ID header.
        client = self._get_client()
        resp = await _request(
            client,
            "get",
            WHOAMI_URL,
            headers={"Authorization": f"Bearer {self.access_token}"},
        )
        resp.raise_for_status()
        data = resp.json()
        if not self.tenant_id:
            self.tenant_id = data.get("id")
        self.data_region_url = data.get("apiHosts", {}).get("dataRegion") or None
        self._whoami_resolved = True

    def _auth_headers(self) -> dict:
        headers = {
            "Authorization": f"Bearer {self.access_token}",
        }
        if self.tenant_id:
            headers["X-Tenant-ID"] = self.tenant_id
        return headers

    async def _ensure_auth(self):
        if (
            self.access_token is None
            or self.token_expires is None
            or datetime.now(timezone.utc) >= self.token_expires
        ):
            await self._authenticate()

    def _base_url(self) -> str:
        return self.data_region_url or "https://api-eu01.central.sophos.com"

    async def _paginate(
        self,
        client: httpx.AsyncClient,
        path: str,
        params: dict,
        style: str = "page_key",
        timeout: float | None = None,
    ) -> list[dict]:
        """Walk all pages of a Sophos list endpoint.

        style="page_key": Sophos standard (pages.nextKey + pageFromKey)
        style="cursor":   SIEM v1 (has_more + next_cursor + cursor)
        timeout: override per-request timeout for slow list endpoints
        """
        items: list[dict] = []
        url = f"{self._base_url()}{path}"
        page_params = dict(params)
        request_kwargs: dict = {"headers": self._auth_headers(), "params": page_params}
        if timeout is not None:
            request_kwargs["timeout"] = timeout

        while url:
            request_kwargs["params"] = page_params
            resp = await _request(client, "get", url, **request_kwargs)
            if resp.status_code == 404:
                logger.info(f"Endpoint {path} not available (404)")
                return items
            resp.raise_for_status()
            data = resp.json()
            items.extend(data.get("items", []))

            if style == "page_key":
                next_key = data.get("pages", {}).get("nextKey")
                if next_key:
                    page_params["pageFromKey"] = next_key
                else:
                    url = None
            else:  # cursor
                if data.get("has_more") and data.get("next_cursor"):
                    page_params = {"cursor": data["next_cursor"], "limit": params.get("limit", 200)}
                else:
                    url = None

        return items

    async def get_alerts(self, from_date: datetime | None = None) -> list[dict]:
        await self._ensure_auth()
        params: dict = {"pageSize": 100}
        if from_date:
            params["raisedAfter"] = _iso_z(from_date)

        alerts = await self._paginate(
            self._get_client(), "/common/v1/alerts", params, style="page_key"
        )
        logger.info(f"Fetched {len(alerts)} alerts from Sophos Central")
        return alerts

    async def get_events(self, from_date: datetime | None = None) -> list[dict]:
        await self._ensure_auth()
        params: dict = {"limit": 200}
        if from_date:
            params["from_date"] = int(from_date.timestamp())

        events = await self._paginate(
            self._get_client(), "/siem/v1/events", params, style="cursor"
        )
        logger.info(f"Fetched {len(events)} events from Sophos Central")
        return events

    async def get_detections(self, from_date: datetime | None = None) -> list[dict]:
        await self._ensure_auth()
        params: dict = {"pageSize": 100, "sort": "-created_at"}
        if from_date:
            params["from"] = _iso_z(from_date)

        detections = await self._paginate(
            self._get_client(), "/endpoint/v1/detections", params, style="page_key"
        )
        logger.info(f"Fetched {len(detections)} detections from Sophos Central")
        return detections

    async def get_firewalls(self) -> list[dict]:
        await self._ensure_auth()
        firewalls = await self._paginate(
            self._get_client(), "/firewall/v1/firewalls", {"pageSize": 100}, style="page_key"
        )
        logger.info(f"Fetched {len(firewalls)} firewalls from Sophos Central")
        return firewalls

    async def get_endpoints(self) -> list[dict]:
        """Inventory of all managed endpoints (computers + servers).

        /endpoint/v1/endpoints returns hostname, OS, health, isolation,
        tamper protection, encryption, online status, IPv4/MAC.
        """
        await self._ensure_auth()
        endpoints = await self._paginate(
            self._get_client(),
            "/endpoint/v1/endpoints",
            {"pageSize": 200, "view": "full"},
            style="page_key",
            timeout=60,
        )
        logger.info(f"Fetched {len(endpoints)} endpoints from Sophos Central")
        return endpoints

    async def set_isolation(
        self, endpoint_ids: list[str], enabled: bool, comment: str | None = None
    ) -> dict:
        """Bulk isolate or restore endpoints.

        /endpoint/v1/endpoints/isolation accepts up to 100 IDs at once.
        enabled=True isolates; enabled=False restores network access.
        """
        await self._ensure_auth()
        body: dict = {"ids": endpoint_ids, "enabled": enabled}
        if comment:
            body["comment"] = comment
        resp = await _request(
            self._get_client(),
            "post",
            f"{self._base_url()}/endpoint/v1/endpoints/isolation",
            headers=self._auth_headers(),
            json=body,
        )
        resp.raise_for_status()
        return resp.json()

    async def get_account_health(self) -> dict | None:
        """Sophos Central Account Health Check — returns overall security score.

        404 → endpoint not licensed/available; caller should treat as unknown.
        """
        await self._ensure_auth()
        resp = await _request(
            self._get_client(),
            "get",
            f"{self._base_url()}/account-health-check/v1/health-check",
            headers=self._auth_headers(),
        )
        if resp.status_code == 404:
            logger.info("Account health endpoint not available")
            return None
        resp.raise_for_status()
        return resp.json()

    async def perform_alert_action(self, alert_id: str, action: str, message: str | None = None) -> dict:
        """Acknowledge / clear an alert via /common/v1/alerts/{id}/actions.

        Common actions: acknowledge, clearThreat, cleanPua, authPua,
        sendMsgPua, sendMsgHmpa, clearHmpa.
        """
        await self._ensure_auth()
        body: dict = {"action": action}
        if message:
            body["message"] = message
        resp = await _request(
            self._get_client(),
            "post",
            f"{self._base_url()}/common/v1/alerts/{alert_id}/actions",
            headers=self._auth_headers(),
            json=body,
        )
        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------
    # Email Management API  (/email/v1)
    # https://developer.sophos.com/docs/email-v1/1/overview
    #
    # Covers the Mailbox-, Quarantine- and Post-Delivery-Quarantine APIs.
    # All endpoints live under the tenant data-region host and need the
    # X-Tenant-ID header (provided by _auth_headers). A 404 means the tenant
    # has no Email Security license / the resource doesn't exist — callers
    # treat that as "unavailable" rather than an error, mirroring
    # get_account_health().
    # ------------------------------------------------------------------

    async def _email_get(
        self, path: str, params: dict | None = None, timeout: float | None = None
    ) -> dict | None:
        """GET a single Email-API resource. Returns None on 404."""
        await self._ensure_auth()
        kwargs: dict = {"headers": self._auth_headers(), "params": params or {}}
        if timeout is not None:
            kwargs["timeout"] = timeout
        resp = await _request(
            self._get_client(), "get", f"{self._base_url()}{path}", **kwargs
        )
        if resp.status_code == 404:
            logger.info(f"Email endpoint {path} not available (404)")
            return None
        resp.raise_for_status()
        return resp.json() if resp.content else {}

    async def _email_write(self, method: str, path: str, body: dict | None = None) -> dict:
        """POST/PATCH/DELETE against the Email API. Raises on HTTP error so the
        route layer can surface a 502. Returns {} for empty (204) bodies."""
        await self._ensure_auth()
        kwargs: dict = {"headers": self._auth_headers()}
        if body is not None:
            kwargs["json"] = body
        resp = await _request(
            self._get_client(), method, f"{self._base_url()}{path}", **kwargs
        )
        resp.raise_for_status()
        if resp.status_code == 204 or not resp.content:
            return {"ok": True}
        return resp.json()

    # ---- Mailboxes ----

    async def email_list_mailboxes(
        self, search: str | None = None, page_size: int = 200
    ) -> list[dict]:
        await self._ensure_auth()
        params: dict = {"pageSize": page_size}
        if search:
            params["search"] = search
        mailboxes = await self._paginate(
            self._get_client(),
            "/email/v1/mailboxes",
            params,
            style="page_key",
            timeout=60,
        )
        logger.info(f"Fetched {len(mailboxes)} email mailboxes from Sophos Central")
        return mailboxes

    async def email_get_mailbox(self, mailbox_id: str) -> dict | None:
        return await self._email_get(f"/email/v1/mailboxes/{mailbox_id}")

    async def email_create_mailbox(self, body: dict) -> dict:
        return await self._email_write("post", "/email/v1/mailboxes", body)

    async def email_update_mailbox(self, mailbox_id: str, body: dict) -> dict:
        return await self._email_write("patch", f"/email/v1/mailboxes/{mailbox_id}", body)

    async def email_delete_mailbox(self, mailbox_id: str) -> dict:
        return await self._email_write("delete", f"/email/v1/mailboxes/{mailbox_id}")

    # ---- Quarantine + Post-Delivery Quarantine ----
    # The two APIs are structurally identical; ``base`` switches between them.

    @staticmethod
    def _quarantine_base(post_delivery: bool) -> str:
        return (
            "/email/v1/post-delivery-quarantine"
            if post_delivery
            else "/email/v1/quarantine"
        )

    async def _email_search(
        self, path: str, body: dict, timeout: float = 60.0, max_items: int = 5000
    ) -> list[dict]:
        """Walk a POST .../search endpoint. Response is {pages:{nextKey,...},
        items:[...]}; the next page key is fed back in the body as pageFromKey
        (same convention as the GET list endpoints). Returns [] on 404."""
        await self._ensure_auth()
        items: list[dict] = []
        page_body = dict(body)
        while True:
            resp = await _request(
                self._get_client(),
                "post",
                f"{self._base_url()}{path}",
                headers=self._auth_headers(),
                json=page_body,
                timeout=timeout,
            )
            if resp.status_code == 404:
                logger.info(f"Email endpoint {path} not available (404)")
                return items
            resp.raise_for_status()
            data = resp.json()
            items.extend(data.get("items", []))
            next_key = (data.get("pages") or {}).get("nextKey")
            if next_key and len(items) < max_items:
                page_body["pageFromKey"] = next_key
            else:
                break
        return items

    async def email_list_quarantine(
        self,
        post_delivery: bool = False,
        begin_date: datetime | None = None,
        end_date: datetime | None = None,
        page_size: int = 100,
    ) -> list[dict]:
        # The quarantine list is a POST search with a mandatory beginDate/endDate
        # window (verified against the live API; the documented field names are
        # beginDate/endDate, not from/to). pageSize max is 100 for the
        # post-delivery endpoint, so we page through via pages.nextKey.
        end_date = end_date or datetime.now(timezone.utc)
        begin_date = begin_date or (end_date - timedelta(days=7))
        body = {
            "beginDate": _iso_z(begin_date),
            "endDate": _iso_z(end_date),
            "pageSize": page_size,
        }
        base = self._quarantine_base(post_delivery)
        msgs = await self._email_search(f"{base}/messages/search", body)
        logger.info(
            f"Fetched {len(msgs)} {'post-delivery ' if post_delivery else ''}"
            f"quarantine messages from Sophos Central"
        )
        return msgs

    async def email_quarantine_attachments(
        self, message_id: str, post_delivery: bool = False
    ) -> dict | None:
        base = self._quarantine_base(post_delivery)
        return await self._email_get(f"{base}/messages/{message_id}/attachments")

    async def email_release_quarantine(
        self, message_ids: list[str], allow_sender: bool = False, post_delivery: bool = False
    ) -> dict:
        # Verified body schema: {"items": [{"id": ...}], "allowListSender": bool}.
        # Returns 202 with an {"errors": [...]} array for any ids that failed.
        base = self._quarantine_base(post_delivery)
        body = {
            "items": [{"id": mid} for mid in message_ids],
            "allowListSender": allow_sender,
        }
        return await self._email_write("post", f"{base}/messages/release", body)

    async def email_delete_quarantine(
        self, message_ids: list[str], block_sender: bool = False, post_delivery: bool = False
    ) -> dict:
        base = self._quarantine_base(post_delivery)
        body = {
            "items": [{"id": mid} for mid in message_ids],
            "blockListSender": block_sender,
        }
        return await self._email_write("post", f"{base}/messages/delete", body)


sophos_client = SophosClient()

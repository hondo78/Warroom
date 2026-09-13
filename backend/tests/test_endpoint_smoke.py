"""Every route is reachable without blowing up on a coding error.

253 endpoints live in one module and most have no test of their own. The bugs
that actually shipped were not subtle logic errors — they were a session dict
written into a VARCHAR column, a helper that did not exist on the page, a
parameter added to a function whose stub had not heard about it. All of them
would have surfaced the first time the line ran.

So this asks the cheapest useful question of every route: does it answer *at
all*, or does it raise? The distinction that matters is 500 (we are broken)
versus anything else (401, 422, 503 — the endpoint worked and said no). An
endpoint that cannot reach Postgres still counts as passing: the point is the
code path up to that boundary, not the infrastructure behind it.

Deliberately not asserted: that responses are correct. That needs fixtures per
endpoint, which is the work this file is not. It is a floor, not a ceiling.
"""
import asyncio
import re
import socket

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.main import app


@pytest.fixture(autouse=True, scope="module")
def _no_outbound_network():
    """No test in this file may talk to anything real.

    Without this the run reaches out to Sophos, Microsoft and the firewall with
    whatever credentials happen to be configured — slow, flaky, and it makes a
    third party's outage look like our bug. Blocking the socket turns every such
    call into a connection error, which :func:`_is_infrastructure` then
    classifies as "not under test". The TestClient speaks ASGI in-process and
    needs no socket, so the requests themselves still work."""
    real_connect = socket.socket.connect
    real_sleep = asyncio.sleep

    def refuse(self, address, *a, **kw):
        raise OSError("outbound network is blocked in tests")

    async def no_wait(delay, *a, **kw):
        # Several clients retry network failures with backoff. With the network
        # blocked every attempt fails instantly and the run is then spent
        # entirely in the waits between them — seven minutes for a file that
        # otherwise takes seconds, which is the difference between a test that
        # runs and one that gets skipped.
        return await real_sleep(0)

    socket.socket.connect = refuse
    asyncio.sleep = no_wait
    try:
        yield
    finally:
        socket.socket.connect = real_connect
        asyncio.sleep = real_sleep


# Errors that mean "there is no database/Redis/upstream here", as opposed to
# "this handler is broken". The whole value of this file is telling those two
# apart, so the list is explicit rather than a bare `except Exception`.
_INFRA_ERRORS = (
    "OperationalError", "InterfaceError", "DBAPIError", "gaierror",
    "ConnectionError", "ConnectError", "ConnectTimeout", "TimeoutError",
    "OSError", "RedisError", "CancelledError",
)


def _is_infrastructure(exc: BaseException) -> bool:
    seen = exc
    while seen is not None:
        if type(seen).__name__ in _INFRA_ERRORS:
            return True
        seen = seen.__cause__ or seen.__context__
    return False


@pytest.fixture(scope="module")
def client():
    # Auth off: with it on, nearly every route short-circuits at 401 and the
    # handler bodies — the part that breaks — never run.
    #
    # Constructed without `with`, deliberately: entering the context manager
    # runs lifespan, which applies migrations, opens pools and starts 46
    # schedulers. None of that is under test here, and all of it needs
    # infrastructure this suite does not have.
    settings.auth_enabled = False
    settings.warroom_api_key = ""
    return TestClient(app)


def _call(client, path):
    """Request `path`, returning a status code, or None when the only thing in
    the way was missing infrastructure."""
    try:
        return client.get(path).status_code
    except Exception as e:                      # noqa: BLE001 - classified below
        if _is_infrastructure(e):
            return None
        raise


def _routes(methods):
    out = []
    for r in app.routes:
        path = getattr(r, "path", "")
        verbs = getattr(r, "methods", set()) or set()
        if not path.startswith(("/api/", "/ioc_")):
            continue
        for m in sorted(verbs & methods):
            out.append((m, path))
    return sorted(set(out))


GET_ROUTES = [p for m, p in _routes({"GET"}) if "{" not in p]

# Path parameters need a plausible value: an id that will not be found is fine
# (404 is a working endpoint), but a value of the wrong *type* produces a 422
# that tells us nothing about the handler.
_PARAM_VALUES = {
    "ip": "10.0.0.1", "source_ip": "10.0.0.1", "fw_ip": "10.0.0.1",
    "alert_id": "1", "decision_id": "1", "entry_id": "1", "cmd_id": "1",
    "message_id": "1", "endpoint_id": "1", "pod_id": "1", "run_id": "1",
    "session_id": "1", "user_id": "1", "domain": "example.com",
    "url": "http://example.com/", "name": "x", "key": "x",
}
PARAM_GET_ROUTES = [p for m, p in _routes({"GET"}) if "{" in p]


def _fill(path):
    def sub(m):
        return _PARAM_VALUES.get(m.group(1), "1")
    return re.sub(r"\{([^}:]+)(?::[^}]+)?\}", sub, path)


def test_there_are_routes_to_check():
    """A guard on the guard: if route discovery silently returns nothing, every
    test below passes while checking nothing at all."""
    assert len(GET_ROUTES) > 50, f"only found {len(GET_ROUTES)} GET routes"


@pytest.mark.parametrize("path", GET_ROUTES)
def test_a_parameterless_get_does_not_raise(client, path):
    code = _call(client, path)
    if code is None:
        pytest.skip("needs infrastructure")
    assert code != 500, f"{path} -> 500"


@pytest.mark.parametrize("path", PARAM_GET_ROUTES)
def test_a_get_with_path_parameters_does_not_raise(client, path):
    filled = _fill(path)
    code = _call(client, filled)
    if code is None:
        pytest.skip("needs infrastructure")
    assert code != 500, f"{filled} -> 500"


def test_no_two_routes_claim_the_same_method_and_path():
    """253 endpoints in one file: a duplicated decorator shadows the earlier
    handler silently, and the dead one keeps looking fine in review."""
    seen, dupes = set(), []
    for r in app.routes:
        path = getattr(r, "path", "")
        for m in sorted(getattr(r, "methods", set()) or set()):
            if (m, path) in seen:
                dupes.append(f"{m} {path}")
            seen.add((m, path))
    assert not dupes, f"duplicate routes: {dupes}"


def test_the_openapi_schema_builds():
    """Builds every response model and every Field constraint in the app. A
    malformed pattern or an unresolvable annotation fails here rather than on
    the first request to that one endpoint."""
    schema = app.openapi()
    assert schema["paths"]

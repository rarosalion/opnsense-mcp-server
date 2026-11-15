"""End-to-end tests for the streamable-HTTP transport, with the OPNsense side mocked."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Generator
from typing import Any
from unittest.mock import patch

import httpx
import pytest
from fastmcp.utilities.tests import asgi_server

from opnsense_mcp.http_auth import StaticBearerVerifier
from opnsense_mcp.server import mcp

# The patch below replaces the attribute on the shared httpx module, so raw clients use this reference.
_RealAsyncClient = httpx.AsyncClient

TOKEN = "unit-test-token-0123456789abcdef0123"
CONFIG_XML = "<opnsense><system><key>abc</key><hostname>fw</hostname></system></opnsense>"

HTTP_ENV = {
    "OPNSENSE_URL": "https://10.0.0.1/api",
    "OPNSENSE_API_KEY": "test-key",
    "OPNSENSE_API_SECRET": "test-secret",
    "OPNSENSE_VERIFY_SSL": "false",
    "OPNSENSE_ALLOW_WRITES": "false",
    "OPNSENSE_MCP_TRANSPORT": "streamable-http",
}


class Upstream:
    """Records requests made to the mocked OPNsense API."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []

    @property
    def paths(self) -> list[str]:
        return [r.url.path for r in self.requests]

    async def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        if path.endswith("core/firmware/status"):
            await asyncio.sleep(0.01)  # Forces concurrent callers to overlap.
            return httpx.Response(200, json={"product_version": "25.1.2"})
        if path.endswith("routes/gateway/status"):
            return httpx.Response(200, json={"items": [{"name": "WAN", "status": "online"}]})
        if path.endswith("core/backup/download/this"):
            return httpx.Response(200, text=CONFIG_XML)
        return httpx.Response(404, json={"message": "not found"})


@pytest.fixture
def upstream() -> Generator[Upstream]:
    up = Upstream()

    def factory(**kwargs: Any) -> httpx.AsyncClient:
        kwargs.pop("verify", None)
        return _RealAsyncClient(transport=httpx.MockTransport(up.handler), **kwargs)

    with (
        patch.dict("os.environ", HTTP_ENV, clear=True),
        patch("opnsense_mcp.api_client.httpx.AsyncClient", factory),
    ):
        yield up


@pytest.fixture
def reset_auth() -> Generator[None]:
    mcp.auth = None
    yield
    mcp.auth = None


@pytest.fixture
async def srv(upstream: Upstream, reset_auth: None) -> AsyncIterator[Any]:
    async with asgi_server(mcp, stateless_http=True, json_response=True) as server:
        yield server


@pytest.fixture
async def srv_auth(upstream: Upstream, reset_auth: None) -> AsyncIterator[Any]:
    mcp.auth = StaticBearerVerifier(TOKEN)
    async with asgi_server(mcp, stateless_http=True, json_response=True) as server:
        yield server


def _raw(server: Any) -> httpx.AsyncClient:
    return _RealAsyncClient(transport=httpx.ASGITransport(app=server.app), base_url="http://127.0.0.1")


class TestStaticBearerVerifier:
    async def test_right_token_accepted(self):
        access = await StaticBearerVerifier(TOKEN).verify_token(TOKEN)
        assert access is not None
        assert access.token == "static-bearer"
        assert TOKEN not in repr(access)

    @pytest.mark.parametrize("presented", ["", "wrong", TOKEN + "x", TOKEN[:-1]])
    async def test_wrong_token_rejected(self, presented):
        assert await StaticBearerVerifier(TOKEN).verify_token(presented) is None


class TestHealth:
    async def test_healthz_ok(self, srv, upstream):
        async with _raw(srv) as http:
            response = await http.get("/healthz")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}

    async def test_readyz_ready(self, srv, upstream):
        async with _raw(srv) as http:
            response = await http.get("/readyz")
        assert response.status_code == 200
        assert response.json() == {"status": "ready", "opnsense_version": None}
        assert upstream.requests == []


class TestTools:
    async def test_read_tool_round_trip(self, srv):
        async with srv.client() as client:
            result = await client.call_tool("opn_gateway_status", {})
        assert result.data["items"][0]["name"] == "WAN"

    async def test_concurrent_calls_share_one_client(self, srv, upstream):
        async with srv.client() as client:
            results = await asyncio.gather(*[client.call_tool("opn_gateway_status", {}) for _ in range(10)])
        assert all(r.data["items"][0]["name"] == "WAN" for r in results)
        assert sum(p.endswith("core/firmware/status") for p in upstream.paths) == 1

    async def test_tool_list_matches_stdio(self, srv):
        async with srv.client() as client:
            http_names = {t.name for t in await client.list_tools()}
        assert http_names == {t.name for t in await mcp.list_tools()}

    async def test_write_tool_refused(self, srv, upstream):
        async with srv.client() as client:
            with pytest.raises(Exception, match="Write operations disabled"):
                await client.call_tool("opn_toggle_firewall_rule", {"uuid": "abc"})
        assert all(r.method == "GET" for r in upstream.requests)


class TestAuth:
    async def test_auth_required_when_token_set(self, srv_auth):
        async with _raw(srv_auth) as http:
            missing = await http.post("/mcp", json={})
            wrong = await http.post("/mcp", json={}, headers={"Authorization": "Bearer not-the-token"})
            health = await http.get("/healthz")
        assert missing.status_code == 401
        assert missing.headers["www-authenticate"].startswith("Bearer")
        assert wrong.status_code == 401
        assert health.status_code == 200

        async with srv_auth.client(auth=TOKEN) as client:
            result = await client.call_tool("opn_gateway_status", {})
        assert result.data["items"][0]["name"] == "WAN"

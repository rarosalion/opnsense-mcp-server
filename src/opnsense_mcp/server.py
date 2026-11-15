"""OPNsense MCP Server — FastMCP entrypoint.

Registers all tool modules and starts the server. STDIO is the default transport;
setting OPNSENSE_MCP_TRANSPORT=streamable-http serves MCP over HTTP instead, with
/healthz and /readyz probe endpoints.
"""

from __future__ import annotations

import sys
from collections.abc import AsyncIterator
from typing import Any

from fastmcp import Context, FastMCP
from fastmcp.server.lifespan import lifespan
from starlette.requests import Request
from starlette.responses import JSONResponse

from opnsense_mcp import __version__
from opnsense_mcp.api_client import OPNsenseAPI, SavepointManager
from opnsense_mcp.config import ConfigError, load_config, load_transport_config
from opnsense_mcp.config_cache import ConfigCache
from opnsense_mcp.http_auth import StaticBearerVerifier

# Lifespan state, mirrored here so the readiness probe can read it without touching fastmcp internals.
_runtime: dict[str, Any] = {}


@lifespan
async def app_lifespan(server: FastMCP) -> AsyncIterator[dict[str, Any]]:
    """Initialize the OPNsense API client, savepoint manager, and config cache."""
    config = load_config()
    transport_config = load_transport_config()
    api = OPNsenseAPI(config)
    savepoint_mgr = SavepointManager(api)
    config_cache = ConfigCache(ttl_seconds=transport_config.config_cache_ttl)
    state: dict[str, Any] = {
        "api": api,
        "savepoint_mgr": savepoint_mgr,
        "config_cache": config_cache,
        "allow_sensitive": transport_config.allow_sensitive,
        "transport": transport_config.transport,
    }
    _runtime.update(state)
    try:
        yield state
    finally:
        _runtime.clear()
        await api.close()


mcp = FastMCP("opnsense", version=__version__, lifespan=app_lifespan)


def get_api(ctx: Context) -> OPNsenseAPI:
    """Extract the OPNsense API client from the MCP context.

    Args:
        ctx: The FastMCP context object.

    Returns:
        The OPNsenseAPI client instance.

    Raises:
        RuntimeError: If the API client is not initialized.
    """
    api: Any = ctx.lifespan_context.get("api")
    if not isinstance(api, OPNsenseAPI):
        msg = "OPNsense API client not initialized"
        raise RuntimeError(msg)
    return api


def get_config_cache(ctx: Context) -> ConfigCache:
    """Extract the ConfigCache from the MCP context.

    Args:
        ctx: The FastMCP context object.

    Returns:
        The ConfigCache instance.

    Raises:
        RuntimeError: If the config cache is not initialized.
    """
    cache: Any = ctx.lifespan_context.get("config_cache")
    if not isinstance(cache, ConfigCache):
        msg = "Config cache not initialized"
        raise RuntimeError(msg)
    return cache


def get_allow_sensitive(ctx: Context) -> bool:
    """Return whether include_sensitive=True is permitted (always true over STDIO).

    Args:
        ctx: The FastMCP context object.
    """
    return bool(ctx.lifespan_context.get("allow_sensitive", True))


def get_savepoint_manager(ctx: Context) -> SavepointManager:
    """Extract the SavepointManager from the MCP context.

    Args:
        ctx: The FastMCP context object.

    Returns:
        The SavepointManager instance.

    Raises:
        RuntimeError: If the savepoint manager is not initialized.
    """
    mgr: Any = ctx.lifespan_context.get("savepoint_mgr")
    if not isinstance(mgr, SavepointManager):
        msg = "Savepoint manager not initialized"
        raise RuntimeError(msg)
    return mgr


@mcp.custom_route("/healthz", methods=["GET"])
async def healthz(request: Request) -> JSONResponse:
    """Liveness probe (HTTP mode only): the process is up. Makes no upstream call."""
    return JSONResponse({"status": "ok"})


@mcp.custom_route("/readyz", methods=["GET"])
async def readyz(request: Request) -> JSONResponse:
    """Readiness probe (HTTP mode only): the lifespan has started. Never calls the router."""
    api = _runtime.get("api")
    if not isinstance(api, OPNsenseAPI):
        return JSONResponse({"status": "starting"}, status_code=503)
    version = api.detected_version
    return JSONResponse(
        {"status": "ready", "opnsense_version": f"{version[0]}.{version[1]}" if version else None},
    )


# Import tool modules to register their @mcp.tool() decorators.
from opnsense_mcp.tools import (  # noqa: E402
    dhcp,  # noqa: F401
    diagnostics,  # noqa: F401
    dns,  # noqa: F401
    firewall,  # noqa: F401
    haproxy,  # noqa: F401
    network,  # noqa: F401
    security,  # noqa: F401
    services,  # noqa: F401
    system,  # noqa: F401
    vpn,  # noqa: F401
)


def main() -> None:
    """Entry point for the OPNsense MCP server."""
    try:
        tc = load_transport_config()
    except ConfigError as exc:
        print(f"opnsense-mcp: configuration error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc

    if tc.transport == "stdio":
        mcp.run(transport="stdio")
        return

    if tc.auth_token:
        mcp.auth = StaticBearerVerifier(tc.auth_token)
    elif not tc.is_loopback:
        print(
            f"opnsense-mcp: warning: listening on {tc.host}:{tc.port} without OPNSENSE_MCP_AUTH_TOKEN; "
            "anything that can reach this port can call every tool. Restrict access at the network layer.",
            file=sys.stderr,
        )
    mcp.run(
        transport="streamable-http",
        show_banner=False,  # Skips the PyPI version check and its cache write.
        host=tc.host,
        port=tc.port,
        path=tc.path,
        stateless_http=True,  # No per-session memory; survives restarts; no server-initiated messages are used.
        json_response=True,  # Plain JSON replies; the SDK client accepts both JSON and SSE.
        host_origin_protection="auto",  # DNS-rebinding guard when bound to loopback.
        uvicorn_config={"server_header": False, "proxy_headers": False},
    )


if __name__ == "__main__":
    main()

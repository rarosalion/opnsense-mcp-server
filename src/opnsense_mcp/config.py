"""Configuration management via environment variables.

Environment variables:
    OPNSENSE_URL: API base URL (required)
    OPNSENSE_API_KEY: API key (required)
    OPNSENSE_API_SECRET: API secret (required)
    OPNSENSE_VERIFY_SSL: Verify SSL certificate (default: true)
    OPNSENSE_ALLOW_WRITES: Enable write operations (default: false)
    OPNSENSE_ALLOW_SENSITIVE: Permit include_sensitive=true on config
        tools (default: false). Without this, passwords/keys are always
        redacted regardless of tool parameters.

Transport variables (only read when OPNSENSE_MCP_TRANSPORT=streamable-http):
    OPNSENSE_MCP_TRANSPORT: stdio or streamable-http (default: stdio)
    OPNSENSE_MCP_HOST: HTTP bind address (default: 127.0.0.1)
    OPNSENSE_MCP_PORT: HTTP port (default: 8000)
    OPNSENSE_MCP_PATH: MCP endpoint path (default: /mcp)
    OPNSENSE_MCP_AUTH_TOKEN: Optional shared bearer token, at least 32 characters
    OPNSENSE_MCP_ALLOW_HTTP_WRITES: Second opt-in for writes over HTTP (default: false)
    OPNSENSE_MCP_ALLOW_SENSITIVE: Allow include_sensitive=True over HTTP (default: false)
    OPNSENSE_MCP_CONFIG_CACHE_TTL: Config scan cache lifetime in seconds, 0 = never (default: 300)
"""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass, field
from typing import Literal

_TRUTHY = frozenset({"true", "1", "yes"})
_FALSY = frozenset({"false", "0", "no"})


class ConfigError(Exception):
    """Raised when required configuration is missing or invalid."""


@dataclass(frozen=True, repr=False)
class OPNsenseConfig:
    """Immutable configuration loaded from environment variables."""

    url: str
    api_key: str
    api_secret: str
    verify_ssl: bool
    allow_writes: bool
    allow_sensitive: bool = False

    def __repr__(self) -> str:
        return f"OPNsenseConfig(url={self.url!r}, verify_ssl={self.verify_ssl}, allow_writes={self.allow_writes})"


def _parse_bool(value: str, var_name: str) -> bool:
    """Parse a boolean environment variable value.

    Accepts: true/false, 1/0, yes/no (case-insensitive).

    Raises:
        ConfigError: If the value is not a recognized boolean string.
    """
    lower = value.lower()
    if lower in _TRUTHY:
        return True
    if lower in _FALSY:
        return False
    msg = f"{var_name} must be true/false, 1/0, or yes/no (got {value!r})"
    raise ConfigError(msg)


def load_config() -> OPNsenseConfig:
    """Load and validate configuration from environment variables.

    Returns:
        Frozen dataclass with validated configuration.

    Raises:
        ConfigError: If required variables are missing or values are invalid.
    """
    missing: list[str] = []
    for var in ("OPNSENSE_URL", "OPNSENSE_API_KEY", "OPNSENSE_API_SECRET"):
        if not os.environ.get(var, "").strip():
            missing.append(var)

    if missing:
        msg = f"Required environment variable(s) not set: {', '.join(missing)}"
        raise ConfigError(msg)

    url = os.environ["OPNSENSE_URL"].strip().rstrip("/")
    api_key = os.environ["OPNSENSE_API_KEY"].strip()
    api_secret = os.environ["OPNSENSE_API_SECRET"].strip()

    verify_ssl_raw = os.environ.get("OPNSENSE_VERIFY_SSL", "true").strip()
    verify_ssl = _parse_bool(verify_ssl_raw, "OPNSENSE_VERIFY_SSL")

    allow_writes_raw = os.environ.get("OPNSENSE_ALLOW_WRITES", "false").strip()
    allow_writes = _parse_bool(allow_writes_raw, "OPNSENSE_ALLOW_WRITES")

    allow_sensitive_raw = os.environ.get("OPNSENSE_ALLOW_SENSITIVE", "false").strip()
    allow_sensitive = _parse_bool(allow_sensitive_raw, "OPNSENSE_ALLOW_SENSITIVE")

    return OPNsenseConfig(
        url=url,
        api_key=api_key,
        api_secret=api_secret,
        verify_ssl=verify_ssl,
        allow_writes=allow_writes,
        allow_sensitive=allow_sensitive,
    )


_PATH_RE = re.compile(r"^/[A-Za-z0-9/_.-]*$")
_RESERVED_PATHS = frozenset({"/healthz", "/readyz"})
_MIN_TOKEN_LENGTH = 32
_DEFAULT_CACHE_TTL = 300


@dataclass(frozen=True, repr=False)
class TransportConfig:
    """Immutable transport configuration loaded from environment variables."""

    transport: Literal["stdio", "streamable-http"]
    host: str
    port: int
    path: str
    auth_token: str | None = field(repr=False)
    allow_http_writes: bool
    allow_sensitive: bool
    config_cache_ttl: int | None

    @property
    def is_loopback(self) -> bool:
        """True if the bind address is a loopback address or ``localhost``."""
        if self.host == "localhost":
            return True
        try:
            return ipaddress.ip_address(self.host).is_loopback
        except ValueError:
            return False

    def __repr__(self) -> str:
        return (
            f"TransportConfig(transport={self.transport!r}, host={self.host!r}, port={self.port}, "
            f"path={self.path!r}, auth_token={'set' if self.auth_token else None}, "
            f"allow_http_writes={self.allow_http_writes}, allow_sensitive={self.allow_sensitive}, "
            f"config_cache_ttl={self.config_cache_ttl})"
        )


def _env(name: str, default: str) -> str:
    """Return a stripped environment variable, or the default when unset."""
    return os.environ.get(name, default).strip()


def load_transport_config() -> TransportConfig:
    """Load and validate transport configuration from environment variables.

    When the transport resolves to stdio, no other ``OPNSENSE_MCP_*`` variable is
    parsed or validated, so existing stdio launchers behave exactly as before.

    Raises:
        ConfigError: If a value is invalid or an unsafe combination is requested.
    """
    transport_value = _env("OPNSENSE_MCP_TRANSPORT", "stdio")
    transport_raw = transport_value.lower() or "stdio"
    if transport_raw == "stdio":
        return TransportConfig(
            transport="stdio",
            host="127.0.0.1",
            port=8000,
            path="/mcp",
            auth_token=None,
            allow_http_writes=False,
            allow_sensitive=True,
            config_cache_ttl=None,
        )
    if transport_raw != "streamable-http":
        msg = f"OPNSENSE_MCP_TRANSPORT must be 'stdio' or 'streamable-http' (got {transport_value!r})"
        raise ConfigError(msg)

    host = _env("OPNSENSE_MCP_HOST", "127.0.0.1")
    if not host or any(ch.isspace() for ch in host):
        msg = "OPNSENSE_MCP_HOST must not be empty or contain whitespace"
        raise ConfigError(msg)

    port_raw = _env("OPNSENSE_MCP_PORT", "8000")
    try:
        port = int(port_raw)
    except ValueError:
        port = 0
    if not 1 <= port <= 65535:
        msg = f"OPNSENSE_MCP_PORT must be an integer between 1 and 65535 (got {port_raw!r})"
        raise ConfigError(msg)

    path = _env("OPNSENSE_MCP_PATH", "/mcp")
    if not _PATH_RE.match(path) or path.endswith("/") or path in _RESERVED_PATHS:
        msg = (
            "OPNSENSE_MCP_PATH must start with '/', have no trailing '/', use only letters, digits, "
            f"'/', '_', '.', '-', and not be /healthz or /readyz (got {path!r})"
        )
        raise ConfigError(msg)

    token_raw = os.environ.get("OPNSENSE_MCP_AUTH_TOKEN", "").strip()
    auth_token: str | None = None
    if token_raw:
        if len(token_raw) < _MIN_TOKEN_LENGTH or any(ch.isspace() for ch in token_raw):
            msg = "OPNSENSE_MCP_AUTH_TOKEN must be at least 32 characters with no whitespace"
            raise ConfigError(msg)
        auth_token = token_raw

    allow_http_writes = _parse_bool(_env("OPNSENSE_MCP_ALLOW_HTTP_WRITES", "false"), "OPNSENSE_MCP_ALLOW_HTTP_WRITES")
    allow_sensitive = _parse_bool(_env("OPNSENSE_MCP_ALLOW_SENSITIVE", "false"), "OPNSENSE_MCP_ALLOW_SENSITIVE")

    ttl_raw = _env("OPNSENSE_MCP_CONFIG_CACHE_TTL", str(_DEFAULT_CACHE_TTL))
    try:
        ttl = int(ttl_raw)
    except ValueError:
        ttl = -1
    if ttl < 0:
        msg = f"OPNSENSE_MCP_CONFIG_CACHE_TTL must be a non-negative integer number of seconds (got {ttl_raw!r})"
        raise ConfigError(msg)

    config = TransportConfig(
        transport="streamable-http",
        host=host,
        port=port,
        path=path,
        auth_token=auth_token,
        allow_http_writes=allow_http_writes,
        allow_sensitive=allow_sensitive,
        config_cache_ttl=ttl,
    )

    allow_writes = _parse_bool(_env("OPNSENSE_ALLOW_WRITES", "false"), "OPNSENSE_ALLOW_WRITES")
    if allow_writes and not allow_http_writes:
        msg = (
            "OPNSENSE_ALLOW_WRITES=true is refused with OPNSENSE_MCP_TRANSPORT=streamable-http: one long-lived "
            "process shares a single savepoint/rollback state between every client. "
            "Set OPNSENSE_MCP_ALLOW_HTTP_WRITES=true to accept that."
        )
        raise ConfigError(msg)
    if allow_writes and not config.is_loopback and auth_token is None:
        msg = (
            "OPNSENSE_MCP_ALLOW_HTTP_WRITES=true with a non-loopback OPNSENSE_MCP_HOST "
            "also requires OPNSENSE_MCP_AUTH_TOKEN."
        )
        raise ConfigError(msg)
    return config

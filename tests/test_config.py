"""Tests for configuration loading and validation."""

from __future__ import annotations

import dataclasses
from unittest.mock import patch

import pytest

from opnsense_mcp.config import ConfigError, load_config, load_transport_config


class TestLoadConfig:
    """Tests for the load_config function."""

    def test_load_valid_config(self, env_vars):
        config = load_config()
        assert config.url == "https://10.0.0.1/api"
        assert config.api_key == "test-key-abc123"
        assert config.api_secret == "test-secret-xyz789"
        assert config.verify_ssl is False
        assert config.allow_writes is False

    def test_missing_url_raises_error(self):
        env = {
            "OPNSENSE_API_KEY": "key",
            "OPNSENSE_API_SECRET": "secret",
        }
        with patch.dict("os.environ", env, clear=True):
            with pytest.raises(ConfigError, match="OPNSENSE_URL"):
                load_config()

    def test_missing_api_key_raises_error(self):
        env = {
            "OPNSENSE_URL": "https://10.0.0.1/api",
            "OPNSENSE_API_SECRET": "secret",
        }
        with patch.dict("os.environ", env, clear=True):
            with pytest.raises(ConfigError, match="OPNSENSE_API_KEY"):
                load_config()

    def test_missing_api_secret_raises_error(self):
        env = {
            "OPNSENSE_URL": "https://10.0.0.1/api",
            "OPNSENSE_API_KEY": "key",
        }
        with patch.dict("os.environ", env, clear=True):
            with pytest.raises(ConfigError, match="OPNSENSE_API_SECRET"):
                load_config()

    def test_missing_multiple_vars_lists_all(self):
        with patch.dict("os.environ", {}, clear=True):
            with pytest.raises(ConfigError) as exc_info:
                load_config()
            msg = str(exc_info.value)
            assert "OPNSENSE_URL" in msg
            assert "OPNSENSE_API_KEY" in msg
            assert "OPNSENSE_API_SECRET" in msg

    def test_empty_url_raises_error(self):
        env = {
            "OPNSENSE_URL": "   ",
            "OPNSENSE_API_KEY": "key",
            "OPNSENSE_API_SECRET": "secret",
        }
        with patch.dict("os.environ", env, clear=True):
            with pytest.raises(ConfigError, match="OPNSENSE_URL"):
                load_config()

    def test_url_trailing_slash_stripped(self, env_vars):
        with patch.dict("os.environ", {"OPNSENSE_URL": "https://10.0.0.1/api/"}):
            config = load_config()
        assert config.url == "https://10.0.0.1/api"

    def test_url_multiple_trailing_slashes_stripped(self, env_vars):
        with patch.dict("os.environ", {"OPNSENSE_URL": "https://10.0.0.1/api///"}):
            config = load_config()
        assert config.url == "https://10.0.0.1/api"


class TestVerifySsl:
    """Tests for OPNSENSE_VERIFY_SSL parsing."""

    def _load_with_ssl(self, value: str | None):
        env = {
            "OPNSENSE_URL": "https://10.0.0.1/api",
            "OPNSENSE_API_KEY": "key",
            "OPNSENSE_API_SECRET": "secret",
        }
        if value is not None:
            env["OPNSENSE_VERIFY_SSL"] = value
        with patch.dict("os.environ", env, clear=True):
            return load_config()

    def test_default_true(self):
        config = self._load_with_ssl(None)
        assert config.verify_ssl is True

    def test_true(self):
        config = self._load_with_ssl("true")
        assert config.verify_ssl is True

    def test_false(self):
        config = self._load_with_ssl("false")
        assert config.verify_ssl is False

    def test_one(self):
        config = self._load_with_ssl("1")
        assert config.verify_ssl is True

    def test_zero(self):
        config = self._load_with_ssl("0")
        assert config.verify_ssl is False

    def test_yes(self):
        config = self._load_with_ssl("yes")
        assert config.verify_ssl is True

    def test_no(self):
        config = self._load_with_ssl("no")
        assert config.verify_ssl is False

    def test_case_insensitive(self):
        config = self._load_with_ssl("TRUE")
        assert config.verify_ssl is True

    def test_invalid_raises_error(self):
        with pytest.raises(ConfigError, match="OPNSENSE_VERIFY_SSL"):
            self._load_with_ssl("maybe")


class TestAllowWrites:
    """Tests for OPNSENSE_ALLOW_WRITES parsing."""

    def _load_with_writes(self, value: str | None):
        env = {
            "OPNSENSE_URL": "https://10.0.0.1/api",
            "OPNSENSE_API_KEY": "key",
            "OPNSENSE_API_SECRET": "secret",
        }
        if value is not None:
            env["OPNSENSE_ALLOW_WRITES"] = value
        with patch.dict("os.environ", env, clear=True):
            return load_config()

    def test_default_false(self):
        config = self._load_with_writes(None)
        assert config.allow_writes is False

    def test_true(self):
        config = self._load_with_writes("true")
        assert config.allow_writes is True

    def test_false(self):
        config = self._load_with_writes("false")
        assert config.allow_writes is False

    def test_invalid_raises_error(self):
        with pytest.raises(ConfigError, match="OPNSENSE_ALLOW_WRITES"):
            self._load_with_writes("sometimes")


class TestAllowSensitive:
    """Tests for OPNSENSE_ALLOW_SENSITIVE parsing."""

    def _load_with_sensitive(self, value: str | None):
        env = {
            "OPNSENSE_URL": "https://10.0.0.1/api",
            "OPNSENSE_API_KEY": "key",
            "OPNSENSE_API_SECRET": "secret",
        }
        if value is not None:
            env["OPNSENSE_ALLOW_SENSITIVE"] = value
        with patch.dict("os.environ", env, clear=True):
            return load_config()

    def test_default_false(self):
        assert self._load_with_sensitive(None).allow_sensitive is False

    def test_true(self):
        assert self._load_with_sensitive("true").allow_sensitive is True

    def test_invalid_raises_error(self):
        with pytest.raises(ConfigError, match="OPNSENSE_ALLOW_SENSITIVE"):
            self._load_with_sensitive("sometimes")


class TestConfigFrozen:
    """Tests that the config object is immutable."""

    def test_cannot_modify_url(self, env_vars):
        config = load_config()
        with pytest.raises(dataclasses.FrozenInstanceError):
            config.url = "https://evil.example.com"  # type: ignore[misc]


TOKEN = "t" * 32
HTTP_ENV = {"OPNSENSE_MCP_TRANSPORT": "streamable-http"}


def _load(extra: dict[str, str] | None = None):
    with patch.dict("os.environ", {**HTTP_ENV, **(extra or {})}, clear=True):
        return load_transport_config()


class TestLoadTransportConfig:
    """Tests for the load_transport_config function."""

    def test_default_is_stdio(self):
        with patch.dict("os.environ", {}, clear=True):
            tc = load_transport_config()
        assert tc.transport == "stdio"
        assert tc.config_cache_ttl is None
        assert tc.allow_sensitive is True

    def test_stdio_ignores_invalid_http_vars(self):
        env = {"OPNSENSE_MCP_PORT": "abc", "OPNSENSE_MCP_PATH": "bad", "OPNSENSE_MCP_AUTH_TOKEN": "x"}
        with patch.dict("os.environ", env, clear=True):
            assert load_transport_config().transport == "stdio"

    def test_empty_transport_means_stdio(self):
        with patch.dict("os.environ", {"OPNSENSE_MCP_TRANSPORT": " "}, clear=True):
            assert load_transport_config().transport == "stdio"

    def test_transport_case_insensitive(self):
        assert _load({"OPNSENSE_MCP_TRANSPORT": " Streamable-HTTP "}).transport == "streamable-http"

    @pytest.mark.parametrize("value", ["sse", "http", "tcp"])
    def test_invalid_transport_raises(self, value):
        with pytest.raises(ConfigError, match="OPNSENSE_MCP_TRANSPORT"):
            _load({"OPNSENSE_MCP_TRANSPORT": value})

    def test_http_defaults(self):
        tc = _load()
        assert tc.host == "127.0.0.1"
        assert tc.port == 8000
        assert tc.path == "/mcp"
        assert tc.auth_token is None
        assert tc.allow_http_writes is False
        assert tc.allow_sensitive is False
        assert tc.config_cache_ttl == 300
        assert tc.is_loopback is True

    def test_http_explicit_host_non_loopback(self):
        assert _load({"OPNSENSE_MCP_HOST": "0.0.0.0"}).is_loopback is False
        assert _load({"OPNSENSE_MCP_HOST": "::1"}).is_loopback is True
        assert _load({"OPNSENSE_MCP_HOST": "localhost"}).is_loopback is True
        assert _load({"OPNSENSE_MCP_HOST": "example.internal"}).is_loopback is False

    def test_http_explicit_values(self):
        tc = _load({"OPNSENSE_MCP_PORT": "9000", "OPNSENSE_MCP_PATH": "/x/y.z-1_a"})
        assert (tc.port, tc.path) == (9000, "/x/y.z-1_a")

    @pytest.mark.parametrize("value", ["0", "65536", "-1", "80a", ""])
    def test_invalid_port(self, value):
        with pytest.raises(ConfigError, match="OPNSENSE_MCP_PORT") as exc:
            _load({"OPNSENSE_MCP_PORT": value})
        assert "between 1 and 65535" in str(exc.value)

    @pytest.mark.parametrize("value", ["mcp", "/mcp/", "/m cp", "/healthz", "/readyz", "/m?x"])
    def test_invalid_path(self, value):
        with pytest.raises(ConfigError, match="OPNSENSE_MCP_PATH"):
            _load({"OPNSENSE_MCP_PATH": value})

    def test_invalid_host(self):
        with pytest.raises(ConfigError, match="OPNSENSE_MCP_HOST"):
            _load({"OPNSENSE_MCP_HOST": "a b"})

    def test_short_token_rejected_without_echo(self):
        short = "s3cr3t" * 5 + "a"
        assert len(short) == 31
        with pytest.raises(ConfigError, match="OPNSENSE_MCP_AUTH_TOKEN") as exc:
            _load({"OPNSENSE_MCP_AUTH_TOKEN": short})
        assert short not in str(exc.value)

    def test_token_with_whitespace_rejected(self):
        with pytest.raises(ConfigError, match="OPNSENSE_MCP_AUTH_TOKEN"):
            _load({"OPNSENSE_MCP_AUTH_TOKEN": "a" * 20 + " " + "b" * 20})

    def test_valid_token_accepted(self):
        assert _load({"OPNSENSE_MCP_AUTH_TOKEN": TOKEN}).auth_token == TOKEN

    def test_ttl_parsing(self):
        assert _load({"OPNSENSE_MCP_CONFIG_CACHE_TTL": "0"}).config_cache_ttl == 0
        assert _load({"OPNSENSE_MCP_CONFIG_CACHE_TTL": "60"}).config_cache_ttl == 60
        for bad in ("-1", "x"):
            with pytest.raises(ConfigError, match="OPNSENSE_MCP_CONFIG_CACHE_TTL"):
                _load({"OPNSENSE_MCP_CONFIG_CACHE_TTL": bad})

    def test_bool_vars_validated(self):
        assert _load({"OPNSENSE_MCP_ALLOW_SENSITIVE": "yes"}).allow_sensitive is True
        with pytest.raises(ConfigError, match="OPNSENSE_MCP_ALLOW_SENSITIVE"):
            _load({"OPNSENSE_MCP_ALLOW_SENSITIVE": "maybe"})

    def test_http_refuses_writes(self):
        with pytest.raises(ConfigError, match="OPNSENSE_MCP_ALLOW_HTTP_WRITES"):
            _load({"OPNSENSE_ALLOW_WRITES": "true"})

    def test_http_writes_opt_in_loopback(self):
        tc = _load({"OPNSENSE_ALLOW_WRITES": "true", "OPNSENSE_MCP_ALLOW_HTTP_WRITES": "true"})
        assert tc.allow_http_writes is True

    def test_http_writes_non_loopback_requires_token(self):
        env = {
            "OPNSENSE_ALLOW_WRITES": "true",
            "OPNSENSE_MCP_ALLOW_HTTP_WRITES": "true",
            "OPNSENSE_MCP_HOST": "0.0.0.0",
        }
        with pytest.raises(ConfigError, match="OPNSENSE_MCP_AUTH_TOKEN"):
            _load(env)
        assert _load({**env, "OPNSENSE_MCP_AUTH_TOKEN": TOKEN}).auth_token == TOKEN

    def test_transport_repr_hides_token(self):
        tc = _load({"OPNSENSE_MCP_AUTH_TOKEN": TOKEN})
        assert TOKEN not in repr(tc)
        assert TOKEN not in str(tc)
        assert "auth_token" in repr(tc)

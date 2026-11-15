"""Tests for the main() entry point and its transport selection."""

from __future__ import annotations

from collections.abc import Generator
from unittest.mock import patch

import pytest

from opnsense_mcp.http_auth import StaticBearerVerifier
from opnsense_mcp.server import main, mcp

TOKEN = "unit-test-token-0123456789abcdef0123"


@pytest.fixture(autouse=True)
def reset_auth() -> Generator[None]:
    mcp.auth = None
    yield
    mcp.auth = None


def _run_main(env: dict[str, str]):
    with patch.dict("os.environ", env, clear=True), patch("opnsense_mcp.server.mcp.run") as run:
        main()
    return run


class TestMain:
    def test_stdio_default_unchanged(self):
        run = _run_main({})
        run.assert_called_once_with(transport="stdio")
        assert mcp.auth is None

    def test_stdio_ignores_http_variables(self):
        run = _run_main({"OPNSENSE_MCP_PORT": "abc", "OPNSENSE_MCP_AUTH_TOKEN": "short"})
        run.assert_called_once_with(transport="stdio")

    def test_http_run_arguments(self):
        env = {
            "OPNSENSE_MCP_TRANSPORT": "streamable-http",
            "OPNSENSE_MCP_HOST": "0.0.0.0",
            "OPNSENSE_MCP_PORT": "9000",
            "OPNSENSE_MCP_PATH": "/x",
            "OPNSENSE_MCP_AUTH_TOKEN": TOKEN,
        }
        run = _run_main(env)
        run.assert_called_once_with(
            transport="streamable-http",
            show_banner=False,
            host="0.0.0.0",
            port=9000,
            path="/x",
            stateless_http=True,
            json_response=True,
            host_origin_protection="auto",
            uvicorn_config={"server_header": False, "proxy_headers": False},
        )
        assert isinstance(mcp.auth, StaticBearerVerifier)

    def test_config_error_exits_2(self, capsys):
        with patch.dict("os.environ", {"OPNSENSE_MCP_TRANSPORT": "sse"}, clear=True):
            with patch("opnsense_mcp.server.mcp.run") as run:
                with pytest.raises(SystemExit) as exc:
                    main()
        assert exc.value.code == 2
        assert capsys.readouterr().err.startswith("opnsense-mcp: configuration error:")
        run.assert_not_called()

    def test_warns_without_token_on_non_loopback(self, capsys):
        _run_main({"OPNSENSE_MCP_TRANSPORT": "streamable-http", "OPNSENSE_MCP_HOST": "0.0.0.0"})
        assert "without OPNSENSE_MCP_AUTH_TOKEN" in capsys.readouterr().err

    def test_no_warning_on_loopback(self, capsys):
        _run_main({"OPNSENSE_MCP_TRANSPORT": "streamable-http"})
        assert capsys.readouterr().err == ""

    def test_no_warning_with_token(self, capsys):
        _run_main(
            {
                "OPNSENSE_MCP_TRANSPORT": "streamable-http",
                "OPNSENSE_MCP_HOST": "0.0.0.0",
                "OPNSENSE_MCP_AUTH_TOKEN": TOKEN,
            }
        )
        assert capsys.readouterr().err == ""

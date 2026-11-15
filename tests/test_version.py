"""Tests that the package version stays in step with pyproject.toml."""

from __future__ import annotations

import tomllib
from pathlib import Path

from opnsense_mcp import __version__


class TestVersion:
    def test_version_matches_pyproject(self) -> None:
        pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        assert __version__ == data["project"]["version"]

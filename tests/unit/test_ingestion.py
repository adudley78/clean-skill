"""Ingestion parser behavior."""

from __future__ import annotations

from pathlib import Path

import pytest

from clean_skill.ingestion import parse
from clean_skill.models import Platform


def test_parse_claude_skill(fixtures_dir: Path) -> None:
    skill = parse(fixtures_dir / "benign_claude")
    assert skill.platform is Platform.CLAUDE
    assert skill.name == "pdf-summarizer"
    assert "read_file" in skill.declared_tools
    assert any(f.path == "SKILL.md" for f in skill.files)
    # Bundle hash must be stable and deterministic.
    assert skill.bundle_sha256 == parse(fixtures_dir / "benign_claude").bundle_sha256


def test_parse_mcp_skill(fixtures_dir: Path) -> None:
    skill = parse(fixtures_dir / "benign_mcp")
    assert skill.platform is Platform.MCP
    assert skill.name == "time-server"
    assert skill.declared_tools == ["now"]
    assert skill.declared_network == []


def test_parse_missing_raises() -> None:
    with pytest.raises(FileNotFoundError):
        parse("/nonexistent/skill")


def test_parse_unknown_format(tmp_path: Path) -> None:
    (tmp_path / "random.txt").write_text("hello")
    with pytest.raises(ValueError):
        parse(tmp_path / "random.txt")

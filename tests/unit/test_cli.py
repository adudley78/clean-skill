"""Smoke test for the Typer CLI (no sandbox invocation)."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from clean_skill.cli import app

runner = CliRunner()


def test_version_command() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.stdout.strip()


def test_rules_list(rules_dir: Path) -> None:
    result = runner.invoke(app, ["rules", "list", "--rules-dir", str(rules_dir)])
    assert result.exit_code == 0
    assert "CS-PI-001" in result.stdout


def test_scan_benign_static_only(fixtures_dir: Path, rules_dir: Path) -> None:
    result = runner.invoke(
        app,
        [
            "scan",
            "--static-only",
            "--no-llm",
            "--rules-dir",
            str(rules_dir),
            str(fixtures_dir / "benign_claude"),
        ],
    )
    assert result.exit_code == 0
    assert "CLEAN" in result.stdout


def test_scan_malicious_static_only_blocks(
    fixtures_dir: Path, rules_dir: Path
) -> None:
    result = runner.invoke(
        app,
        [
            "scan",
            "--static-only",
            "--no-llm",
            "--rules-dir",
            str(rules_dir),
            str(fixtures_dir / "malicious_claude"),
        ],
    )
    # Critical rule hit -> BLOCK -> exit code 3
    assert result.exit_code == 3

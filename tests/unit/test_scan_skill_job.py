"""Unit tests for :func:`clean_skill.jobs.scan_skill.scan_skill_job`.

All external dependencies are mocked so the tests run without Redis,
Postgres, or Docker.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from clean_skill.jobs import scan_skill as scan_skill_mod
from clean_skill.models import (
    Category,
    Finding,
    Platform,
    SandboxTrace,
    Severity,
    Skill,
    SkillFile,
    Verdict,
)
from clean_skill.threat_intel import ScanResult


def _make_skill() -> Skill:
    """Minimal in-memory Skill usable by the aggregate/verdict functions."""
    file = SkillFile(
        path="SKILL.md",
        content="# title\nHelpful instructions.\n",
        size_bytes=32,
        sha256="0" * 64,
    )
    return Skill(
        platform=Platform.CLAUDE,
        name="unit-fixture",
        version="0.0.1",
        files=[file],
    )


def _make_scan_result(scanned_at: datetime, verdict: Verdict = Verdict.CLEAN) -> ScanResult:
    row = ScanResult(
        id=42,
        source="https://example.test/fixture.json",
        skill_hash="deadbeef" * 8,
        verdict=verdict.value,
        static_findings=[],
        dynamic_findings=[],
        dynamic_skipped=False,
        enqueued_by="test",
        error_message=None,
    )
    row.scanned_at = scanned_at
    return row


@pytest.fixture()
def local_bundle(tmp_path: Path) -> Path:
    """A real on-disk skill file so ``_hash_source`` can run unmocked."""
    target = tmp_path / "manifest.json"
    target.write_text('{"name": "unit-fixture", "version": "0.0.1"}')
    return target


@pytest.fixture()
def patched_pipeline(monkeypatch: pytest.MonkeyPatch) -> dict[str, MagicMock]:
    """Replace all external collaborators with MagicMocks.

    Returns the dict so tests can inspect call args / set return values.
    """
    skill = _make_skill()

    mocks = {
        "parse_skill": MagicMock(return_value=skill),
        "StaticAnalyzer": MagicMock(),
        "DynamicAnalyzer": MagicMock(),
        "repo": MagicMock(),
    }
    mocks["StaticAnalyzer"].return_value.analyze.return_value = []
    mocks["DynamicAnalyzer"].return_value.analyze.return_value = (
        SandboxTrace(
            started_at=datetime.now(UTC), duration_s=0.0, exit_code=0, timed_out=False
        ),
        [],
    )
    mocks["repo"].latest_scan_by_hash.return_value = None
    mocks["repo"].save_scan_result.side_effect = lambda row: row

    monkeypatch.setattr(scan_skill_mod, "parse_skill", mocks["parse_skill"])
    monkeypatch.setattr(scan_skill_mod, "StaticAnalyzer", mocks["StaticAnalyzer"])
    monkeypatch.setattr(
        scan_skill_mod, "ThreatIntelRepository", lambda *a, **kw: mocks["repo"]
    )

    # Repository.save_scan_result normally flushes + refreshes to assign
    # a PK; simulate that here so the returned dict has a scan_result_id.
    def _fake_save(row: ScanResult) -> ScanResult:
        row.id = 1
        return row

    mocks["repo"].save_scan_result.side_effect = _fake_save

    # _run_dynamic imports DynamicAnalyzer lazily; monkeypatch the module
    # attribute it resolves to.
    from clean_skill import dynamic_analysis

    monkeypatch.setattr(
        dynamic_analysis, "DynamicAnalyzer", mocks["DynamicAnalyzer"]
    )
    return mocks


def test_new_skill_runs_full_pipeline_and_persists_clean_verdict(
    patched_pipeline: dict[str, MagicMock], local_bundle: Path
) -> None:
    """No prior hash → ingest + static + dynamic run, ScanResult persisted."""
    result = scan_skill_mod.scan_skill_job(str(local_bundle), dynamic=True)

    assert result["deduped"] is False
    assert result["verdict"] == Verdict.CLEAN.value
    assert result["dynamic_skipped"] is False
    assert result["scan_result_id"] == 1

    patched_pipeline["parse_skill"].assert_called_once()
    patched_pipeline["StaticAnalyzer"].return_value.analyze.assert_called_once()
    patched_pipeline["DynamicAnalyzer"].return_value.analyze.assert_called_once()
    patched_pipeline["repo"].save_scan_result.assert_called_once()


def test_dedup_within_rescan_window_skips_pipeline(
    patched_pipeline: dict[str, MagicMock], local_bundle: Path
) -> None:
    """Fresh prior scan → return early, pipeline never runs."""
    recent = datetime.now(UTC) - timedelta(hours=2)
    patched_pipeline["repo"].latest_scan_by_hash.return_value = _make_scan_result(
        recent, Verdict.CLEAN
    )

    result = scan_skill_mod.scan_skill_job(str(local_bundle))

    assert result["deduped"] is True
    assert result["verdict"] == Verdict.CLEAN.value
    assert "prior_scan_id" in result
    patched_pipeline["parse_skill"].assert_not_called()
    patched_pipeline["StaticAnalyzer"].return_value.analyze.assert_not_called()
    patched_pipeline["repo"].save_scan_result.assert_not_called()


def test_stale_prior_result_triggers_rescan(
    patched_pipeline: dict[str, MagicMock], local_bundle: Path
) -> None:
    """A prior scan older than rescan_days must NOT short-circuit."""
    stale = datetime.now(UTC) - timedelta(days=30)
    patched_pipeline["repo"].latest_scan_by_hash.return_value = _make_scan_result(
        stale, Verdict.CLEAN
    )

    result = scan_skill_mod.scan_skill_job(str(local_bundle))

    assert result["deduped"] is False
    patched_pipeline["parse_skill"].assert_called_once()


def test_docker_exception_becomes_static_only_fallback(
    patched_pipeline: dict[str, MagicMock], local_bundle: Path
) -> None:
    """DockerException from the sandbox → static-only, dynamic_skipped=True."""
    from docker.errors import DockerException

    patched_pipeline["DynamicAnalyzer"].return_value.analyze.side_effect = (
        DockerException("daemon gone")
    )

    result = scan_skill_mod.scan_skill_job(str(local_bundle), dynamic=True)

    assert result["deduped"] is False
    assert result["dynamic_skipped"] is True
    assert result["verdict"] == Verdict.CLEAN.value  # no findings → clean
    # The job persists even when dynamic is skipped.
    patched_pipeline["repo"].save_scan_result.assert_called_once()


def test_static_analysis_exception_produces_error_verdict(
    patched_pipeline: dict[str, MagicMock], local_bundle: Path
) -> None:
    """Static engine crash → verdict=error, error_message captured."""
    patched_pipeline["StaticAnalyzer"].return_value.analyze.side_effect = RuntimeError(
        "rule loader blew up"
    )

    result = scan_skill_mod.scan_skill_job(str(local_bundle))

    assert result["verdict"] == "error"
    assert result["error"] is not None
    assert "static analysis failed" in result["error"]
    assert result["dynamic_skipped"] is True
    patched_pipeline["repo"].save_scan_result.assert_called_once()
    saved_row: Any = patched_pipeline["repo"].save_scan_result.call_args.args[0]
    assert saved_row.verdict == "error"
    assert "rule loader blew up" in (saved_row.error_message or "")


def test_malicious_finding_produces_malicious_verdict(
    patched_pipeline: dict[str, MagicMock], local_bundle: Path
) -> None:
    """A HIGH-severity finding aggregates to MALICIOUS."""
    finding = Finding(
        rule_id="CS-PI-001",
        category=Category.PROMPT_INJECTION,
        severity=Severity.HIGH,
        title="Injected instruction",
        description="",
        source="static.rules",
    )
    patched_pipeline["StaticAnalyzer"].return_value.analyze.return_value = [finding]

    result = scan_skill_mod.scan_skill_job(str(local_bundle), dynamic=False)

    assert result["verdict"] == Verdict.MALICIOUS.value
    assert result["static_finding_count"] == 1
    assert result["dynamic_skipped"] is True  # dynamic=False

"""Unit tests for :mod:`clean_skill.crawler.scheduler.crawl_tick`."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock

import pytest

from clean_skill.crawler import scheduler as sched_mod
from clean_skill.threat_intel import ScanResult


def _make_prior(age: timedelta) -> ScanResult:
    row = ScanResult(
        id=1,
        source="https://example.test/a.json",
        skill_hash="f" * 64,
        verdict="clean",
        static_findings=[],
        dynamic_findings=[],
        dynamic_skipped=False,
        enqueued_by="test",
        error_message=None,
    )
    row.scanned_at = datetime.now(UTC) - age
    return row


@pytest.fixture()
def patched(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Replace adapters, queue, repo with mocks."""
    adapter = MagicMock()
    adapter.name = "fake"
    adapter.crawl.return_value = [
        {"source": "https://example.test/a.json", "registry": "fake", "discovered_at": "t"},
        {"source": "https://example.test/b.json", "registry": "fake", "discovered_at": "t"},
        {"source": "https://example.test/c.json", "registry": "fake", "discovered_at": "t"},
    ]
    adapter_cls = MagicMock(return_value=adapter)
    adapter_cls.name = "fake"

    queue = MagicMock()
    repo = MagicMock()

    # Only "a.json" has a fresh prior — scheduler should dedup it.
    def _latest_by_source(source: str) -> ScanResult | None:
        if source == "https://example.test/a.json":
            return _make_prior(timedelta(hours=2))
        return None

    repo.latest_scan_by_source.side_effect = _latest_by_source

    monkeypatch.setattr(sched_mod, "ADAPTERS", (adapter_cls,))
    monkeypatch.setattr(sched_mod, "get_queue", lambda *a, **kw: queue)
    monkeypatch.setattr(sched_mod, "_try_repository", lambda: repo)

    return {"adapter": adapter, "adapter_cls": adapter_cls, "queue": queue, "repo": repo}


def test_tick_dedups_fresh_results_and_enqueues_the_rest(
    patched: dict[str, Any],
) -> None:
    """3 discovered, 1 fresh dedup → 2 enqueued."""
    counters = sched_mod.crawl_tick()

    assert counters == {"discovered": 3, "deduped": 1, "enqueued": 2}
    assert patched["queue"].enqueue.call_count == 2

    enqueued_sources = {
        call.args[1] for call in patched["queue"].enqueue.call_args_list
    }
    assert enqueued_sources == {
        "https://example.test/b.json",
        "https://example.test/c.json",
    }


def test_tick_survives_adapter_exception(patched: dict[str, Any]) -> None:
    """An exploding adapter must not crash the whole tick."""
    patched["adapter"].crawl.side_effect = RuntimeError("registry 500")

    counters = sched_mod.crawl_tick()

    assert counters == {"discovered": 0, "deduped": 0, "enqueued": 0}
    patched["queue"].enqueue.assert_not_called()


def test_stale_prior_does_not_dedup(
    patched: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A prior scan older than rescan_days must be re-enqueued."""
    patched["repo"].latest_scan_by_source.side_effect = lambda _s: _make_prior(
        timedelta(days=30)
    )

    counters = sched_mod.crawl_tick()

    assert counters["deduped"] == 0
    assert counters["enqueued"] == 3


def test_tick_without_db_enqueues_everything(
    patched: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """No DB configured → scheduler still runs, dedup becomes a no-op."""
    monkeypatch.setattr(sched_mod, "_try_repository", lambda: None)

    counters = sched_mod.crawl_tick()

    assert counters == {"discovered": 3, "deduped": 0, "enqueued": 3}

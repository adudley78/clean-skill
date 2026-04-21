"""Recurring crawler scheduler.

Runs as a separate process from the worker; on each tick it:

  1. Instantiates every adapter in :data:`ADAPTERS`.
  2. Calls ``.crawl()`` to get scheduler-ready dicts.
  3. Dedups each discovered skill against the ``scan_result`` table
     (URL + rescan window — the job itself does the precise hash-based
     dedup once the bundle is downloaded).
  4. Enqueues survivors as ``scan_skill_job`` on the ``scans`` queue.

Tick interval is set via ``CLEAN_SKILL_CRAWL_INTERVAL_HOURS`` (default
6h). rq-scheduler registers the tick as a recurring job keyed by a
stable job id so repeated ``main()`` invocations are idempotent.

Run as: ``python -m clean_skill.crawler.scheduler``
"""

from __future__ import annotations

import logging
import sys
from typing import Any

from rq_scheduler import Scheduler

from ..config import get_settings
from ..jobs.queues import (
    QUEUE_NAME,
    default_retry,
    get_queue,
    get_redis,
    redact_redis_url,
)
from ..jobs.scan_skill import scan_skill_job
from ..threat_intel import ThreatIntelRepository
from .base import RegistryCrawler
from .registries.mcp_registry import MCPRegistryCrawler

logger = logging.getLogger(__name__)

# Adapter registry. Add new crawlers here as they're implemented.
# Declared as a tuple of classes so the scheduler can instantiate a
# fresh one per tick (cheap; no shared state between runs).
ADAPTERS: tuple[type[RegistryCrawler], ...] = (MCPRegistryCrawler,)

# Stable id so rq-scheduler's "register if missing" path is idempotent
# across scheduler restarts.
_CRAWL_TICK_JOB_ID = "clean_skill.crawler.tick"


def crawl_tick() -> dict[str, int]:
    """One crawl iteration. Returns counters for log summarization."""
    settings = get_settings()
    queue = get_queue(QUEUE_NAME)
    repo = _try_repository()

    discovered = 0
    deduped = 0
    enqueued = 0

    for adapter_cls in ADAPTERS:
        adapter = adapter_cls()
        try:
            items = adapter.crawl()
        except Exception:
            # An adapter blowing up (registry 500, SSL cert expired) must
            # not take down the scheduler; log and continue with the next.
            logger.exception("adapter %s crawl failed", adapter.name)
            continue

        for item in items:
            discovered += 1
            source = item.get("source")
            if not source:
                logger.debug("adapter %s returned item without source; skipping", adapter.name)
                continue

            if _is_deduped(repo, source=source, rescan_days=settings.rescan_days):
                deduped += 1
                continue

            queue.enqueue(
                scan_skill_job,
                source,
                dynamic=settings.dynamic_enabled,
                enqueued_by=f"crawler:{adapter.name}",
                retry=default_retry(),
            )
            enqueued += 1

    logger.info(
        "crawl tick complete: discovered=%d deduped=%d enqueued=%d",
        discovered,
        deduped,
        enqueued,
    )
    return {"discovered": discovered, "deduped": deduped, "enqueued": enqueued}


def _try_repository() -> ThreatIntelRepository | None:
    """Return a repository or None if the DB isn't configured.

    The scheduler must not hard-require the DB: in dev you can run the
    scheduler against Redis alone to watch enqueue behavior, and the
    per-source dedup simply becomes a no-op.
    """
    import os

    if not os.environ.get("CLEAN_SKILL_DB_URL"):
        return None
    try:
        repo = ThreatIntelRepository()
        # Touch the engine early so a bad URL fails here, not mid-tick.
        with repo.session() as _s:
            pass
        return repo
    except Exception:
        logger.exception("threat-intel DB unavailable; scheduler running without dedup")
        return None


def _is_deduped(
    repo: ThreatIntelRepository | None,
    *,
    source: str,
    rescan_days: int,
) -> bool:
    """Cheap pre-enqueue dedup by source URL + rescan window."""
    if repo is None:
        return False
    prior = repo.latest_scan_by_source(source)
    if prior is None:
        return False
    from datetime import UTC, datetime, timedelta

    now = datetime.now(UTC)
    scanned_at = prior.scanned_at
    if scanned_at.tzinfo is None:
        scanned_at = scanned_at.replace(tzinfo=UTC)
    return (now - scanned_at) < timedelta(days=rescan_days)


def main() -> int:
    """Register the recurring crawl tick and enter the scheduler loop."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    settings = get_settings()
    interval_s = max(1, settings.crawl_interval_hours) * 3600
    redis = get_redis()
    scheduler = Scheduler(queue_name=QUEUE_NAME, connection=redis)

    logger.info(
        "starting crawler scheduler on redis=%s interval=%dh adapters=%s",
        redact_redis_url(settings.redis_url),
        settings.crawl_interval_hours,
        ",".join(a.name for a in (cls() for cls in ADAPTERS)),
    )

    _ensure_tick_registered(scheduler, interval_s=interval_s)
    scheduler.run()
    return 0


def _ensure_tick_registered(scheduler: Scheduler, *, interval_s: int) -> None:
    """Idempotently register the recurring crawl tick."""
    for job in scheduler.get_jobs():
        if job.id == _CRAWL_TICK_JOB_ID:
            scheduler.cancel(job)

    scheduler.schedule(
        scheduled_time=_now_utc(),
        func=crawl_tick,
        interval=interval_s,
        repeat=None,  # forever
        id=_CRAWL_TICK_JOB_ID,
        queue_name=QUEUE_NAME,
        # rq-scheduler sometimes retries a missed slot; we'd rather skip
        # than stack up crawls when the scheduler wakes from sleep.
        result_ttl=3600,
    )
    logger.info("registered recurring crawl tick every %ds", interval_s)


def _now_utc() -> Any:
    """Return a timezone-aware UTC now; isolated for test-time injection."""
    from datetime import UTC, datetime

    return datetime.now(UTC)


if __name__ == "__main__":
    sys.exit(main())

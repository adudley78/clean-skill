"""Redis + RQ queue factories.

Kept separate from ``scan_skill`` so unit tests can import the job
function without needing a live Redis (the connection is lazy).

Queue topology:
  * ``scans-high`` — API-triggered manual scans (a human is waiting)
  * ``scans``      — crawler-enqueued background scans
  * ``failed``     — RQ's built-in dead-letter queue; populated after
                     retries are exhausted
"""

from __future__ import annotations

import logging
from functools import lru_cache

from redis import Redis
from rq import Queue, Retry

from ..config import get_settings

logger = logging.getLogger(__name__)

QUEUE_NAME = "scans"
HIGH_QUEUE_NAME = "scans-high"
QUEUE_PRIORITY: tuple[str, ...] = (HIGH_QUEUE_NAME, QUEUE_NAME)


@lru_cache(maxsize=1)
def get_redis() -> Redis:
    """Return a shared Redis client built from ``CLEAN_SKILL_REDIS_URL``."""
    url = get_settings().redis_url
    return Redis.from_url(url)


def get_queue(name: str = QUEUE_NAME) -> Queue:
    """Return an RQ queue bound to the shared Redis client."""
    return Queue(name, connection=get_redis())


def default_retry() -> Retry:
    """Exponential-ish backoff: 1m → 5m → 15m, then dead-letter.

    Matches the contract documented in the architecture PR: transient
    failures (network, Redis blip, Docker daemon restart) get a second
    chance without human intervention; persistent failures end up in
    the ``failed`` registry for inspection.
    """
    return Retry(max=3, interval=[60, 300, 900])


def redact_redis_url(url: str) -> str:
    """Mask the password in a Redis URL for safe logging."""
    from urllib.parse import urlparse, urlunparse

    parsed = urlparse(url)
    if parsed.password:
        netloc = f"{parsed.username or ''}:***@{parsed.hostname}"
        if parsed.port:
            netloc += f":{parsed.port}"
        parsed = parsed._replace(netloc=netloc)
    return urlunparse(parsed)

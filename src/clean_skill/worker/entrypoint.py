"""RQ worker entrypoint.

The worker drains ``scans-high`` first, then ``scans``. API-triggered
scans have a human waiting so they jump the queue ahead of crawler-
discovered skills.
"""

from __future__ import annotations

import logging
import sys

from rq import Worker

from ..config import get_settings
from ..db import run_migrations
from ..jobs.queues import QUEUE_PRIORITY, get_queue, get_redis, redact_redis_url

logger = logging.getLogger(__name__)


def main() -> int:
    """Configure logging, apply migrations, start the worker loop."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    redis_url = get_settings().redis_url
    logger.info(
        "starting RQ worker on redis=%s queues=%s",
        redact_redis_url(redis_url),
        ",".join(QUEUE_PRIORITY),
    )

    # Migrations are idempotent; running at worker startup means the DB is
    # always in sync when jobs start taking ScanResult rows. If DB is not
    # configured we log and continue — jobs that need the DB will raise,
    # which is fine for dev where jobs are just smoke-tested.
    run_migrations()

    queues = [get_queue(name) for name in QUEUE_PRIORITY]
    worker = Worker(queues, connection=get_redis())
    # ``with_scheduler=True`` lets the worker process also drain scheduled
    # jobs registered via rq-scheduler's ``enqueue_at`` / retry backoff,
    # which is exactly what our Retry(max=3, interval=[60,300,900]) path
    # uses. Without it, retried jobs would sit indefinitely in the
    # scheduled registry.
    worker.work(with_scheduler=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

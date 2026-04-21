"""Crawler base classes.

Two public interfaces:

* :meth:`RegistryCrawler.poll` — the low-level, cursor-paginated API
  that each adapter implements. Returns typed :class:`CrawlItem`
  dataclasses.
* :meth:`RegistryCrawler.crawl` — a thin wrapper that produces the dict
  shape the scheduler persists to the queue.  Adapters normally don't
  override this; the default implementation is good enough.

The scheduler stores a per-adapter cursor in Redis under a namespaced
key so subsequent polls only see newly-updated entries.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass(frozen=True)
class CrawlItem:
    """One discovered skill to enqueue for scanning."""

    registry: str
    slug: str
    version: str
    download_url: str
    discovered_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> dict[str, Any]:
        """Scheduler-contract shape.

        Keys ``source``, ``registry``, and ``discovered_at`` are the
        minimum required by the scheduler (and the scan-job dedup); the
        extra fields are kept for provenance and audit logging.
        """
        raw = asdict(self)
        raw["source"] = self.download_url
        raw["discovered_at"] = self.discovered_at.isoformat()
        return raw


class RegistryCrawler(ABC):
    """Subclass per marketplace.

    Implementations must implement :meth:`poll`. The default
    :meth:`crawl` wraps it and discards the cursor (the scheduler
    manages cursor persistence separately).
    """

    name: str

    @abstractmethod
    def poll(self, since_cursor: str | None) -> tuple[Iterable[CrawlItem], str]:
        """Return ``(items, new_cursor)``."""

    def crawl(self, since_cursor: str | None = None) -> list[dict[str, Any]]:
        """Return a list of scheduler-ready dicts.

        Callers that need cursor management should use :meth:`poll`
        directly; ``crawl`` is the simple surface for the scheduler.
        """
        items, _cursor = self.poll(since_cursor)
        return [item.to_dict() for item in items]

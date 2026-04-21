"""Crawler base classes."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass


@dataclass(frozen=True)
class CrawlItem:
    """One discovered skill to enqueue for scanning."""

    registry: str
    slug: str
    version: str
    download_url: str


class RegistryCrawler(ABC):
    """Subclass per marketplace.

    Implementations should:
    - page through the registry API (or scrape),
    - return :class:`CrawlItem` entries for anything newer than
      ``since_cursor`` (an opaque string the crawler persists).
    """

    name: str

    @abstractmethod
    def poll(self, since_cursor: str | None) -> tuple[Iterable[CrawlItem], str]:
        """Return ``(items, new_cursor)``."""

"""Marketplace crawler: proactively ingest skills from registries.

The crawler is a thin Redis Queue (RQ) worker. Each registry adapter produces
a stream of ``CrawlItem`` dicts which get enqueued as ``scan_skill`` jobs.
"""

from __future__ import annotations

from .base import CrawlItem, RegistryCrawler

__all__ = ["CrawlItem", "RegistryCrawler"]

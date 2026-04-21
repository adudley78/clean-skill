"""Threat intelligence store: known-bad skill hashes + persisted scan results.

The DB schema is intentionally small for v0.1:

  * ``known_bad`` — curated list of bundle hashes confirmed malicious.
  * ``scan_result`` — every scan the pipeline has produced, used for the
    dedup + rescan-window logic described in :mod:`clean_skill.jobs`.

Future work: per-file hashes, YARA signatures, crawler provenance.
"""

from __future__ import annotations

from .db import Base, KnownBadSkill, ScanResult
from .repository import ThreatIntelRepository

__all__ = ["Base", "KnownBadSkill", "ScanResult", "ThreatIntelRepository"]

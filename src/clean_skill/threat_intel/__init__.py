"""Threat intelligence store: known-bad skill hashes + signatures.

The DB schema is intentionally small for v0.1: a single ``known_bad`` table
keyed by ``bundle_sha256``. Future work will add per-file hashes, YARA
signatures, and crawler provenance.
"""

from __future__ import annotations

from .db import Base, KnownBadSkill
from .repository import ThreatIntelRepository

__all__ = ["Base", "KnownBadSkill", "ThreatIntelRepository"]

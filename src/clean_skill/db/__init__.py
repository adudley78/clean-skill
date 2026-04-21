"""Database operations shared across the FastAPI app + RQ worker.

Only infrastructure helpers live here; the ORM models live in
:mod:`clean_skill.threat_intel.db`.
"""

from __future__ import annotations

from .migrations import run_migrations

__all__ = ["run_migrations"]

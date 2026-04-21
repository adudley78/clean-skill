"""Repository wrapper for :mod:`clean_skill.threat_intel.db`.

Thin, synchronous wrapper over SQLAlchemy 2 that hides the session
lifecycle from callers. The scan pipeline + crawler scheduler use the
``ScanResult`` helpers; the static-analysis judge uses ``KnownBadSkill``.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, desc, select
from sqlalchemy.orm import Session, sessionmaker

from ..config import get_settings
from .db import Base, KnownBadSkill, ScanResult


class ThreatIntelRepository:
    def __init__(self, url: str | None = None) -> None:
        self._engine = create_engine(url or get_settings().db_url, future=True)
        self._session_factory = sessionmaker(self._engine, expire_on_commit=False)

    def init_schema(self) -> None:
        """Create tables. Production should use Alembic migrations instead."""
        Base.metadata.create_all(self._engine)

    @contextmanager
    def session(self) -> Iterator[Session]:
        session = self._session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    # -- known-bad ------------------------------------------------------

    def is_known_bad(self, bundle_sha256: str) -> bool:
        with self.session() as s:
            stmt = select(KnownBadSkill).where(KnownBadSkill.bundle_sha256 == bundle_sha256)
            return s.execute(stmt).first() is not None

    def record_bad(self, skill: KnownBadSkill) -> None:
        with self.session() as s:
            s.merge(skill)

    # -- scan results ---------------------------------------------------

    def latest_scan_by_hash(self, skill_hash: str) -> ScanResult | None:
        """Most recent :class:`ScanResult` for the given bundle hash, if any."""
        with self.session() as s:
            stmt = (
                select(ScanResult)
                .where(ScanResult.skill_hash == skill_hash)
                .order_by(desc(ScanResult.scanned_at))
                .limit(1)
            )
            return s.execute(stmt).scalar_one_or_none()

    def latest_scan_by_source(self, source: str) -> ScanResult | None:
        """Most recent :class:`ScanResult` for the given source URL/path.

        Used by the crawler scheduler for cheap pre-enqueue dedup (before
        the bundle has been downloaded and hashed).
        """
        with self.session() as s:
            stmt = (
                select(ScanResult)
                .where(ScanResult.source == source)
                .order_by(desc(ScanResult.scanned_at))
                .limit(1)
            )
            return s.execute(stmt).scalar_one_or_none()

    def save_scan_result(self, result: ScanResult) -> ScanResult:
        """Persist a :class:`ScanResult` and return the merged instance."""
        with self.session() as s:
            s.add(result)
            s.flush()
            s.refresh(result)
            return result

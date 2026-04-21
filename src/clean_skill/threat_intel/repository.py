"""Repository wrapper for :mod:`clean_skill.threat_intel.db`."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from ..config import get_settings
from .db import Base, KnownBadSkill


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

    def is_known_bad(self, bundle_sha256: str) -> bool:
        with self.session() as s:
            stmt = select(KnownBadSkill).where(KnownBadSkill.bundle_sha256 == bundle_sha256)
            return s.execute(stmt).first() is not None

    def record_bad(self, skill: KnownBadSkill) -> None:
        with self.session() as s:
            s.merge(skill)

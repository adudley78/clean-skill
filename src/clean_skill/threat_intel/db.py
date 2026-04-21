"""SQLAlchemy models for the threat-intel store."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, String, UniqueConstraint, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class KnownBadSkill(Base):
    """A skill bundle previously confirmed malicious.

    ``bundle_sha256`` is the primary dedupe key. Additional metadata (first
    seen timestamp, reporter, categories) supports crawler triage queues and
    auditability.
    """

    __tablename__ = "known_bad_skill"
    __table_args__ = (UniqueConstraint("bundle_sha256", name="uq_known_bad_sha"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    bundle_sha256: Mapped[str] = mapped_column(String(64), index=True, unique=True)
    platform: Mapped[str] = mapped_column(String(32))
    name: Mapped[str] = mapped_column(String(256))
    version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source_uri: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    categories: Mapped[list[str]] = mapped_column(JSON, default=list)
    reporter: Mapped[str | None] = mapped_column(String(128), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now()
    )

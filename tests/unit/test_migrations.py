"""Smoke test: verify Alembic migration chain applies cleanly to a fresh database.

Uses SQLite (via a tmp file) so no running Postgres instance is required in CI.
The models only use portable column types (String, Integer, DateTime, JSON), so
SQLite compatibility is guaranteed for this baseline migration.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from alembic.command import downgrade, upgrade
from alembic.config import Config

_PROJECT_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture()
def alembic_cfg(tmp_path: Path) -> Config:
    cfg = Config(str(_PROJECT_ROOT / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{tmp_path / 'test.db'}")
    return cfg


def test_migrations_upgrade(alembic_cfg: Config) -> None:
    """Full forward migration must complete without error."""
    upgrade(alembic_cfg, "head")


def test_migrations_downgrade(alembic_cfg: Config) -> None:
    """Roundtrip upgrade -> downgrade to base must complete without error."""
    upgrade(alembic_cfg, "head")
    downgrade(alembic_cfg, "base")

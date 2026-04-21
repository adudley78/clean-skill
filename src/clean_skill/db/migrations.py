"""Run Alembic migrations from Python (API + worker startup).

Both the FastAPI `lifespan` hook and the RQ worker entrypoint need to
apply pending migrations before accepting work, so the logic is shared
here rather than duplicated.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

# src/clean_skill/db/migrations.py -> parents[3] == project root
_PROJECT_ROOT = Path(__file__).resolve().parents[3]
_ALEMBIC_INI = _PROJECT_ROOT / "alembic.ini"


def run_migrations() -> bool:
    """Apply all pending Alembic migrations.

    Returns ``True`` when migrations ran, ``False`` when skipped (no DB
    configured). Never raises on "DB not configured" because both the
    API and worker are expected to start in dev/CI without a database
    and only use non-DB endpoints / non-DB jobs. Real migration errors
    (bad schema, version conflict) propagate.
    """
    if not os.environ.get("CLEAN_SKILL_DB_URL"):
        logger.warning("CLEAN_SKILL_DB_URL is not set; skipping database migrations.")
        return False

    from alembic import command
    from alembic.config import Config

    if not _ALEMBIC_INI.exists():
        # Installed wheel without the alembic.ini sidecar — treat the same
        # as "no DB configured" rather than failing loudly. Packaging work
        # to ship the ini as a data file is tracked separately.
        logger.warning("alembic.ini not found at %s; skipping migrations.", _ALEMBIC_INI)
        return False

    logger.info("Running database migrations...")
    alembic_cfg = Config(str(_ALEMBIC_INI))
    command.upgrade(alembic_cfg, "head")
    logger.info("Database migrations complete.")
    return True

"""Alembic environment: production-ready sync configuration.

The database URL is resolved in priority order:
  1. ``CLEAN_SKILL_DB_URL`` environment variable
  2. ``sqlalchemy.url`` in ``alembic.ini`` (fallback / placeholder)
"""

from __future__ import annotations

import logging
import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from clean_skill.threat_intel.db import Base

logger = logging.getLogger("alembic.env")

# Alembic Config object for ini values.
config = context.config

# Honour the ini-file logging config when running from the CLI.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Feed SQLAlchemy's metadata so --autogenerate can diff the schema.
target_metadata = Base.metadata


def _db_url() -> str:
    """Return the effective database URL, preferring the env var."""
    env_url = os.environ.get("CLEAN_SKILL_DB_URL")
    if env_url:
        return env_url
    ini_url: str = config.get_main_option("sqlalchemy.url", "")
    return ini_url


def run_migrations_offline() -> None:
    """Run migrations without a live DB connection (generates SQL script)."""
    url = _db_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations against a live DB connection."""
    cfg = config.get_section(config.config_ini_section, {})
    cfg["sqlalchemy.url"] = _db_url()

    connectable = engine_from_config(
        cfg,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

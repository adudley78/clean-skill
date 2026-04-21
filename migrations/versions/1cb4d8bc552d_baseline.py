"""baseline: initial schema from SQLAlchemy models

This migration captures the full schema as of v0.1. Future schema changes
should be made via `alembic revision --autogenerate -m "description"`.

Revision ID: 1cb4d8bc552d
Revises:
Create Date: 2026-04-21

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "1cb4d8bc552d"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "known_bad_skill",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("bundle_sha256", sa.String(length=64), nullable=False),
        sa.Column("platform", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=256), nullable=False),
        sa.Column("version", sa.String(length=64), nullable=True),
        sa.Column("source_uri", sa.String(length=2048), nullable=True),
        sa.Column("categories", sa.JSON(), nullable=False),
        sa.Column("reporter", sa.String(length=128), nullable=True),
        sa.Column(
            "first_seen",
            sa.DateTime(),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column(
            "last_seen",
            sa.DateTime(),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("bundle_sha256", name="uq_known_bad_sha"),
    )
def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table("known_bad_skill")

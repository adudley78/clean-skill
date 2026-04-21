"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures" / "skills"
REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "rules"


@pytest.fixture(scope="session")
def rules_dir() -> Path:
    return RULES_DIR


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    return FIXTURES

"""Abstract base for all skill parsers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from pathlib import Path

from ..models import Platform, Skill, SkillFile

# Files we never include in the Skill bundle (too large or irrelevant).
_SKIP_SUFFIXES = {".pyc", ".pyo", ".so", ".dylib", ".dll", ".o"}
_SKIP_DIRS = {"__pycache__", ".git", "node_modules", ".venv", "venv"}
_MAX_FILE_BYTES = 2 * 1024 * 1024  # 2 MB; larger files are flagged by integrity rule


class SkillParser(ABC):
    """Base class for platform-specific ingestion.

    Subclasses must implement :meth:`detect` and :meth:`parse`. :meth:`detect`
    should be cheap (no network calls, no full file read if possible).
    """

    platform: Platform

    @abstractmethod
    def detect(self, path: Path) -> bool:
        """Return True if this parser can handle ``path``."""

    @abstractmethod
    def parse(self, path: Path) -> Skill:
        """Parse ``path`` into a normalized :class:`Skill`."""

    @staticmethod
    def _walk_files(root: Path) -> Iterable[Path]:
        """Yield all non-ignored files under ``root`` (or the single file itself)."""
        if root.is_file():
            yield root
            return
        for p in sorted(root.rglob("*")):
            if not p.is_file():
                continue
            if any(part in _SKIP_DIRS for part in p.parts):
                continue
            if p.suffix in _SKIP_SUFFIXES:
                continue
            yield p

    @classmethod
    def _collect_files(cls, root: Path) -> list[SkillFile]:
        """Produce :class:`SkillFile` entries for every file under ``root``."""
        base = root if root.is_dir() else root.parent
        files: list[SkillFile] = []
        for file in cls._walk_files(root):
            try:
                if file.stat().st_size > _MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            files.append(SkillFile.from_path(base, file))
        return files

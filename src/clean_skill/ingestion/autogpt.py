"""Parser for AutoGPT plugin bundles.

AutoGPT plugins ship as a Python package containing ``plugin.py`` + a
``metadata.json`` file describing the plugin class and required permissions.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..models import Platform, Skill
from .base import SkillParser


class AutoGPTParser(SkillParser):
    platform = Platform.AUTOGPT

    def _manifest(self, path: Path) -> Path | None:
        if path.is_file() and path.name == "metadata.json":
            return path
        if path.is_dir():
            meta = path / "metadata.json"
            plugin = path / "plugin.py"
            if meta.exists() and plugin.exists():
                return meta
        return None

    def detect(self, path: Path) -> bool:
        return self._manifest(path) is not None

    def parse(self, path: Path) -> Skill:
        manifest_file = self._manifest(path)
        assert manifest_file is not None
        data = json.loads(manifest_file.read_text(encoding="utf-8"))
        root = manifest_file.parent
        return Skill(
            platform=self.platform,
            name=str(data.get("name") or root.name),
            version=str(data.get("version")) if data.get("version") else None,
            description=data.get("description"),
            entrypoint=data.get("plugin_class") or "plugin.py",
            declared_permissions=list(data.get("permissions") or []),
            declared_tools=list(data.get("commands") or []),
            files=self._collect_files(root),
            raw_manifest=data,
            source_uri=str(manifest_file),
        )

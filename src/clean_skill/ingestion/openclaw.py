"""Parser for OpenClaw / ClawHub skill bundles.

OpenClaw skills use a ``claw.yaml`` manifest at the root of the bundle.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from ..models import Platform, Skill
from .base import SkillParser


class OpenClawParser(SkillParser):
    platform = Platform.OPENCLAW

    def _manifest(self, path: Path) -> Path | None:
        if path.is_file() and path.name in {"claw.yaml", "claw.yml"}:
            return path
        if path.is_dir():
            for name in ("claw.yaml", "claw.yml"):
                p = path / name
                if p.exists():
                    return p
        return None

    def detect(self, path: Path) -> bool:
        return self._manifest(path) is not None

    def parse(self, path: Path) -> Skill:
        manifest_file = self._manifest(path)
        assert manifest_file is not None
        data: dict[str, Any] = yaml.safe_load(manifest_file.read_text(encoding="utf-8")) or {}
        root = manifest_file.parent
        return Skill(
            platform=self.platform,
            name=str(data.get("name") or root.name),
            version=str(data.get("version")) if data.get("version") else None,
            description=data.get("description"),
            entrypoint=data.get("entrypoint"),
            declared_permissions=list(data.get("permissions") or []),
            declared_network=list(data.get("network", {}).get("allow", []))
            if isinstance(data.get("network"), dict)
            else [],
            declared_tools=list(data.get("tools") or []),
            files=self._collect_files(root),
            raw_manifest=data,
            source_uri=str(manifest_file),
        )

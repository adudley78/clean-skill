"""Fallback parser for arbitrary JSON/YAML tool manifests.

Matches any file whose top-level keys *look like* a tool manifest (``name``
and one of ``tools`` / ``commands`` / ``entrypoint``).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from ..models import Platform, Skill
from .base import SkillParser

_TOOL_KEYS = {"tools", "commands", "functions", "actions"}


def _try_load(path: Path) -> dict[str, Any] | None:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        if path.suffix in {".yml", ".yaml"}:
            data = yaml.safe_load(text)
        elif path.suffix == ".json":
            data = json.loads(text)
        else:
            return None
    except (yaml.YAMLError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


class GenericManifestParser(SkillParser):
    platform = Platform.GENERIC

    def _scan(self, path: Path) -> Path | None:
        if path.is_file():
            data = _try_load(path)
            if data and "name" in data and (_TOOL_KEYS & data.keys() or "entrypoint" in data):
                return path
            return None
        for candidate in sorted(path.glob("*.json")) + sorted(path.glob("*.y*ml")):
            data = _try_load(candidate)
            if data and "name" in data and (_TOOL_KEYS & data.keys() or "entrypoint" in data):
                return candidate
        return None

    def detect(self, path: Path) -> bool:
        return self._scan(path) is not None

    def parse(self, path: Path) -> Skill:
        manifest_file = self._scan(path)
        assert manifest_file is not None
        data = _try_load(manifest_file) or {}
        root = manifest_file.parent
        tools: list[str] = []
        for key in _TOOL_KEYS:
            for entry in data.get(key, []) or []:
                if isinstance(entry, dict) and "name" in entry:
                    tools.append(str(entry["name"]))
                elif isinstance(entry, str):
                    tools.append(entry)
        return Skill(
            platform=self.platform,
            name=str(data.get("name") or root.name),
            version=str(data.get("version")) if data.get("version") else None,
            description=data.get("description"),
            entrypoint=data.get("entrypoint"),
            declared_permissions=list(data.get("permissions") or []),
            declared_network=list(data.get("allowed_hosts") or []),
            declared_tools=tools,
            files=self._collect_files(root),
            raw_manifest=data,
            source_uri=str(manifest_file),
        )

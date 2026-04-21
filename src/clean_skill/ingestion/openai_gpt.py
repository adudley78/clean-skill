"""Parser for OpenAI GPT Actions / tool definitions.

GPT Actions are an OpenAPI 3.x spec (JSON or YAML) plus an optional
``ai-plugin.json``. We treat the OpenAPI document as the primary manifest and
extract operation names as declared tools + server URLs as declared network.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from ..models import Platform, Skill
from .base import SkillParser


def _load_spec(path: Path) -> dict[str, Any] | None:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        if path.suffix in {".yml", ".yaml"}:
            data = yaml.safe_load(text)
        else:
            data = json.loads(text)
    except (yaml.YAMLError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


class OpenAIGPTParser(SkillParser):
    platform = Platform.OPENAI_GPT

    def _locate(self, path: Path) -> Path | None:
        if path.is_file():
            spec = _load_spec(path)
            if spec and "openapi" in spec:
                return path
            if path.name == "ai-plugin.json":
                return path
            return None
        for candidate in ("openapi.yaml", "openapi.yml", "openapi.json", "ai-plugin.json"):
            p = path / candidate
            if p.exists():
                return p
        return None

    def detect(self, path: Path) -> bool:
        return self._locate(path) is not None

    def parse(self, path: Path) -> Skill:
        manifest_file = self._locate(path)
        assert manifest_file is not None
        manifest = _load_spec(manifest_file) or {}

        tools = list((manifest.get("paths") or {}).keys())
        servers = [s.get("url", "") for s in manifest.get("servers", []) if isinstance(s, dict)]

        root = manifest_file.parent
        return Skill(
            platform=self.platform,
            name=str((manifest.get("info") or {}).get("title") or root.name),
            version=str((manifest.get("info") or {}).get("version") or "") or None,
            description=(manifest.get("info") or {}).get("description"),
            entrypoint=manifest_file.name,
            declared_network=[s for s in servers if s],
            declared_tools=tools,
            files=self._collect_files(root),
            raw_manifest=manifest,
            source_uri=str(manifest_file),
        )

"""Parser for LangChain tool / agent executor bundles.

LangChain tools are usually plain Python packages with a ``langchain.yaml`` or
``langchain_tool.json`` manifest describing the entrypoint callable.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from ..models import Platform, Skill
from .base import SkillParser

_MANIFESTS = ("langchain.yaml", "langchain.yml", "langchain_tool.json", "langchain.json")


class LangChainParser(SkillParser):
    platform = Platform.LANGCHAIN

    def _manifest(self, path: Path) -> Path | None:
        if path.is_file() and path.name in _MANIFESTS:
            return path
        if path.is_dir():
            for name in _MANIFESTS:
                p = path / name
                if p.exists():
                    return p
        return None

    def detect(self, path: Path) -> bool:
        return self._manifest(path) is not None

    def parse(self, path: Path) -> Skill:
        manifest_file = self._manifest(path)
        assert manifest_file is not None
        text = manifest_file.read_text(encoding="utf-8")
        data: dict[str, Any]
        if manifest_file.suffix in {".yml", ".yaml"}:
            data = yaml.safe_load(text) or {}
        else:
            data = json.loads(text)

        tools = [t.get("name", "") for t in data.get("tools", []) if isinstance(t, dict)]
        root = manifest_file.parent
        return Skill(
            platform=self.platform,
            name=str(data.get("name") or root.name),
            version=str(data.get("version")) if data.get("version") else None,
            description=data.get("description"),
            entrypoint=data.get("entrypoint"),
            declared_permissions=list(data.get("permissions") or []),
            declared_network=list(data.get("allowed_hosts") or []),
            declared_tools=[t for t in tools if t],
            files=self._collect_files(root),
            raw_manifest=data,
            source_uri=str(manifest_file),
        )

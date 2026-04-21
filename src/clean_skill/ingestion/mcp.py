"""Parser for MCP (Model Context Protocol) server / tool bundles.

MCP servers ship with either:
- ``mcp.json`` manifest describing transport + tools, or
- ``package.json`` with an ``mcp`` key (npm-distributed servers), or
- ``pyproject.toml`` declaring an ``mcp.servers`` entry point.

This parser targets the JSON form, which is the most common for published
servers on the MCP registry.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..models import Platform, Skill
from .base import SkillParser


class MCPParser(SkillParser):
    platform = Platform.MCP

    def _manifest_path(self, path: Path) -> Path | None:
        if path.is_file() and path.name in {"mcp.json", "server.json"}:
            return path
        if path.is_dir():
            for candidate in ("mcp.json", "server.json"):
                p = path / candidate
                if p.exists():
                    return p
            pkg = path / "package.json"
            if pkg.exists():
                try:
                    data = json.loads(pkg.read_text(encoding="utf-8"))
                except json.JSONDecodeError:
                    return None
                if isinstance(data, dict) and "mcp" in data:
                    return pkg
        return None

    def detect(self, path: Path) -> bool:
        return self._manifest_path(path) is not None

    def parse(self, path: Path) -> Skill:
        manifest_file = self._manifest_path(path)
        assert manifest_file is not None  # detect() guarantees this
        raw = json.loads(manifest_file.read_text(encoding="utf-8"))
        manifest: dict[str, Any] = (
            raw.get("mcp", raw) if manifest_file.name == "package.json" else raw
        )

        tools: list[str] = []
        for tool in manifest.get("tools", []) or []:
            if isinstance(tool, dict) and "name" in tool:
                tools.append(str(tool["name"]))
            elif isinstance(tool, str):
                tools.append(tool)

        root = manifest_file.parent
        return Skill(
            platform=self.platform,
            name=str(manifest.get("name") or root.name),
            version=str(manifest.get("version")) if manifest.get("version") else None,
            description=manifest.get("description"),
            entrypoint=(manifest.get("command") or manifest.get("entrypoint")),
            declared_permissions=list(manifest.get("permissions") or []),
            declared_network=list(
                manifest.get("network", {}).get("allow", [])
                if isinstance(manifest.get("network"), dict)
                else manifest.get("allowed_hosts", [])
            ),
            declared_tools=tools,
            files=self._collect_files(root),
            raw_manifest=manifest,
            source_uri=str(manifest_file),
        )

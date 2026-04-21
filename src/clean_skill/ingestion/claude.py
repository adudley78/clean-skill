"""Parser for Anthropic / Claude Cowork ``SKILL.md`` bundles.

A Claude skill is a directory containing a ``SKILL.md`` file whose YAML
frontmatter declares metadata (name, description, tools), followed by the
instructional markdown body the agent is prompted with.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from ..models import Platform, Skill
from .base import SkillParser

_FRONTMATTER_RE = re.compile(r"^---\s*\n(?P<fm>.*?)\n---\s*\n(?P<body>.*)$", re.DOTALL)


class ClaudeSkillParser(SkillParser):
    platform = Platform.CLAUDE

    def detect(self, path: Path) -> bool:
        candidate = path / "SKILL.md" if path.is_dir() else path
        if candidate.name != "SKILL.md" or not candidate.exists():
            return False
        head = candidate.read_text(encoding="utf-8", errors="replace")[:2048]
        return head.lstrip().startswith("---")

    def parse(self, path: Path) -> Skill:
        skill_md = path / "SKILL.md" if path.is_dir() else path
        text = skill_md.read_text(encoding="utf-8", errors="replace")
        manifest: dict[str, Any] = {}
        body = text
        match = _FRONTMATTER_RE.match(text)
        if match:
            try:
                manifest = yaml.safe_load(match.group("fm")) or {}
            except yaml.YAMLError:
                manifest = {"_parse_error": "invalid YAML frontmatter"}
            body = match.group("body")

        root = skill_md.parent
        return Skill(
            platform=self.platform,
            name=str(manifest.get("name") or root.name),
            version=str(manifest.get("version")) if manifest.get("version") else None,
            description=manifest.get("description"),
            entrypoint="SKILL.md",
            declared_permissions=list(manifest.get("permissions") or []),
            declared_network=list(manifest.get("allowed_hosts") or []),
            declared_tools=list(manifest.get("tools") or manifest.get("allowed-tools") or []),
            files=self._collect_files(root),
            raw_manifest={"frontmatter": manifest, "body_preview": body[:512]},
            source_uri=str(skill_md),
        )

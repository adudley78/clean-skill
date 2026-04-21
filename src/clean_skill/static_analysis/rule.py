"""Rule schema + loader.

See ``docs/rule_format.md`` for the authoring guide.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal, cast

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..models import Category, Platform, Severity


class Pattern(BaseModel):
    """One matcher inside a rule.

    A ``regex`` pattern with ``decode`` set recursively re-scans the decoded
    bytes with its ``nested`` patterns; it only fires if a nested pattern
    matches.
    """

    model_config = ConfigDict(extra="forbid")

    type: Literal["regex", "keyword"]
    expression: str | None = None
    value: str | None = None
    flags: str = ""
    case: bool = False  # keyword: case-sensitive when True
    decode: Literal["base64"] | None = None
    nested: list[Pattern] = Field(default_factory=list)

    @field_validator("expression")
    @classmethod
    def _validate_regex(cls, v: str | None) -> str | None:
        if v is None:
            return v
        try:
            re.compile(v)
        except re.error as exc:
            raise ValueError(f"invalid regex: {exc}") from exc
        return v


class Rule(BaseModel):
    """A single YAML detection rule."""

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    description: str
    category: Category
    severity: Severity
    author: str
    version: int = 1
    references: list[str] = Field(default_factory=list)
    platforms: list[Platform | Literal["all"]] = Field(
        default_factory=lambda: cast("list[Platform | Literal['all']]", ["all"])
    )
    scope: list[Literal["text", "manifest", "filenames"]] = Field(
        default_factory=lambda: cast("list[Literal['text', 'manifest', 'filenames']]", ["text"])
    )
    patterns: list[Pattern]
    condition: Literal["any", "all"] = "any"
    min_matches: int = 1
    exclude: list[Pattern] = Field(default_factory=list)

    @field_validator("id")
    @classmethod
    def _id_format(cls, v: str) -> str:
        if not re.match(r"^CS-[A-Z]{2}-\d{3}$", v):
            raise ValueError(f"rule id must match CS-XX-NNN, got {v!r}")
        return v


def load_rules(root: Path) -> list[Rule]:
    """Load every ``*.yml`` / ``*.yaml`` rule under ``root`` (recursively).

    Invalid rule files raise ``ValueError`` with the file path so authors get
    actionable errors during ``pytest`` rather than silent skips.
    """
    if not root.exists():
        raise FileNotFoundError(f"rules directory not found: {root}")
    rules: list[Rule] = []
    seen_ids: set[str] = set()
    for file in sorted(root.rglob("*.y*ml")):
        data = yaml.safe_load(file.read_text(encoding="utf-8"))
        try:
            rule = Rule.model_validate(data)
        except Exception as exc:
            raise ValueError(f"failed to load rule {file}: {exc}") from exc
        if rule.id in seen_ids:
            raise ValueError(f"duplicate rule id {rule.id} in {file}")
        seen_ids.add(rule.id)
        rules.append(rule)
    return rules

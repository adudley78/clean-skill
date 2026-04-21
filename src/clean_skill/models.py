"""Core domain models shared across ingestion, analysis, and the API.

The data flow is:

    RawSkill   -> ingestion -> Skill
    Skill      -> static analysis  -> list[Finding]
    Skill      -> dynamic analysis -> list[Finding] (+ SandboxTrace)
    list[Finding] -> verdict aggregator -> Verdict
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Platform(StrEnum):
    """Supported AI skill platforms. ``GENERIC`` is the fallback parser."""

    CLAUDE = "claude"
    MCP = "mcp"
    OPENAI_GPT = "openai_gpt"
    LANGCHAIN = "langchain"
    AUTOGPT = "autogpt"
    OPENCLAW = "openclaw"
    GENERIC = "generic"


class Severity(StrEnum):
    """Finding severity. Maps 1:1 to CVSS-style bands for aggregation."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Verdict(StrEnum):
    """Final scan verdict. ``BLOCK`` means the skill should not be installed."""

    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    BLOCK = "block"


class Category(StrEnum):
    """Taxonomy of detection categories. Keep aligned with rule schema."""

    PROMPT_INJECTION = "prompt_injection"
    INSTRUCTION_OVERRIDE = "instruction_override"
    OBFUSCATION = "obfuscation"
    EXFILTRATION = "exfiltration"
    CREDENTIAL_HARVEST = "credential_harvest"
    SECRET_LEAK = "secret_leak"
    UNEXPECTED_EGRESS = "unexpected_egress"
    FILESYSTEM_ABUSE = "filesystem_abuse"
    PROCESS_ABUSE = "process_abuse"
    MANIFEST_INTEGRITY = "manifest_integrity"
    LLM_JUDGE = "llm_judge"


class SkillFile(BaseModel):
    """One file belonging to a skill bundle."""

    model_config = ConfigDict(frozen=True)

    path: str
    content: str
    size_bytes: int
    sha256: str

    @classmethod
    def from_path(cls, root: Path, file: Path) -> SkillFile:
        data = file.read_bytes()
        try:
            content = data.decode("utf-8")
        except UnicodeDecodeError:
            # Preserve binary files as base64 so downstream scanners can still
            # match on e.g. embedded ELF magic; decoding is best-effort.
            import base64

            content = "base64:" + base64.b64encode(data).decode("ascii")
        return cls(
            path=str(file.relative_to(root)),
            content=content,
            size_bytes=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
        )


class Skill(BaseModel):
    """Normalized representation of an AI skill bundle.

    All platform-specific parsers produce an instance of this class so the
    analysis engines can remain platform-agnostic.
    """

    platform: Platform
    name: str
    version: str | None = None
    description: str | None = None
    entrypoint: str | None = None
    declared_permissions: list[str] = Field(default_factory=list)
    declared_network: list[str] = Field(
        default_factory=list,
        description="Hosts or URL patterns the manifest declares it will contact.",
    )
    declared_tools: list[str] = Field(default_factory=list)
    files: list[SkillFile] = Field(default_factory=list)
    raw_manifest: dict[str, Any] = Field(default_factory=dict)
    source_uri: str | None = Field(
        default=None,
        description="Original URI (file path, URL, or registry slug) the skill was ingested from.",
    )

    @property
    def bundle_sha256(self) -> str:
        """Stable hash over every file's sha256, sorted by path."""
        joined = "|".join(f"{f.path}:{f.sha256}" for f in sorted(self.files, key=lambda f: f.path))
        return hashlib.sha256(joined.encode()).hexdigest()

    def text_blob(self) -> str:
        """Concatenated textual content of every file. Used by regex matchers."""
        return "\n".join(f.content for f in self.files if not f.content.startswith("base64:"))


class Finding(BaseModel):
    """A single detection result produced by static or dynamic analysis."""

    rule_id: str
    category: Category
    severity: Severity
    title: str
    description: str
    evidence: str = Field(default="", description="Snippet or trace proving the finding.")
    location: str | None = Field(
        default=None, description="file:line or sandbox event that triggered the match."
    )
    source: str = Field(description="Which engine produced the finding, e.g. 'static', 'dynamic'.")
    metadata: dict[str, Any] = Field(default_factory=dict)


class SandboxEvent(BaseModel):
    """One observed behavior during dynamic analysis."""

    kind: str  # "network", "filesystem", "process", "tool_call"
    ts: datetime = Field(default_factory=lambda: datetime.now(UTC))
    detail: dict[str, Any]


class SandboxTrace(BaseModel):
    """Structured trace emitted by the dynamic sandbox."""

    started_at: datetime
    duration_s: float
    exit_code: int
    timed_out: bool
    events: list[SandboxEvent] = Field(default_factory=list)


class ScanReport(BaseModel):
    """Full output of ``clean-skill scan``."""

    skill: Skill
    findings: list[Finding]
    trace: SandboxTrace | None = None
    verdict: Verdict
    score: int = Field(
        ge=0,
        le=100,
        description="0 = clean, 100 = confirmed malicious. Computed from weighted severities.",
    )
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def to_summary(self) -> dict[str, Any]:
        """Compact dict for logs / CI annotations."""
        return {
            "skill": f"{self.skill.platform.value}:{self.skill.name}",
            "bundle_sha256": self.skill.bundle_sha256,
            "verdict": self.verdict.value,
            "score": self.score,
            "findings": [
                {"rule": f.rule_id, "severity": f.severity.value, "title": f.title}
                for f in self.findings
            ],
        }

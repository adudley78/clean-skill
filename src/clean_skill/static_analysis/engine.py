"""Static analysis engine.

The engine composes three detectors:

1. YAML rule matcher over ``Skill.text_blob`` + manifest.
2. Secret scanner (high-precision regex set).
3. LLM-as-judge (optional; disabled when no API key is configured).

Each detector returns ``list[Finding]``; the engine concatenates them.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from ..config import get_settings
from ..models import Category, Finding, Platform, Severity, Skill
from . import llm_judge
from . import secrets as secret_scanner
from .matchers import match_pattern
from .rule import Rule, load_rules

logger = logging.getLogger(__name__)


class StaticAnalyzer:
    """Run every static detector against a :class:`Skill`."""

    def __init__(self, rules: list[Rule] | None = None, *, enable_llm_judge: bool = True) -> None:
        if rules is None:
            rules = load_rules(get_settings().rules_dir)
        self._rules = rules
        self._enable_llm_judge = enable_llm_judge

    @classmethod
    def from_rules_dir(cls, rules_dir: Path, *, enable_llm_judge: bool = True) -> StaticAnalyzer:
        return cls(load_rules(rules_dir), enable_llm_judge=enable_llm_judge)

    def analyze(self, skill: Skill) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._run_rules(skill))
        findings.extend(self._run_secrets(skill))
        if self._enable_llm_judge:
            findings.extend(llm_judge.judge(skill))
        return findings

    # -- rule runner -----------------------------------------------------

    @staticmethod
    def _rule_applies(rule: Rule, platform: Platform) -> bool:
        return "all" in rule.platforms or platform in rule.platforms  # type: ignore[operator]

    @staticmethod
    def _scope_text(skill: Skill, scope: str) -> str:
        if scope == "text":
            return skill.text_blob()
        if scope == "manifest":
            return json.dumps(skill.raw_manifest, default=str)
        if scope == "filenames":
            return "\n".join(f.path for f in skill.files)
        return ""

    def _run_rules(self, skill: Skill) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self._rules:
            if not self._rule_applies(rule, skill.platform):
                continue
            finding = self._evaluate_rule(rule, skill)
            if finding is not None:
                findings.append(finding)
        return findings

    def _evaluate_rule(self, rule: Rule, skill: Skill) -> Finding | None:
        corpus = "\n".join(self._scope_text(skill, s) for s in rule.scope)
        if not corpus:
            return None

        # Exclusions short-circuit.
        for ex in rule.exclude:
            if match_pattern(ex, corpus):
                return None

        per_pattern = [match_pattern(p, corpus, i) for i, p in enumerate(rule.patterns)]
        total = sum(len(m) for m in per_pattern)
        if total < rule.min_matches:
            return None

        matching_patterns = sum(1 for m in per_pattern if m)
        if rule.condition == "all" and matching_patterns < len(rule.patterns):
            return None
        if rule.condition == "any" and matching_patterns == 0:
            return None

        evidence = next((m[0].snippet for m in per_pattern if m), "")
        return Finding(
            rule_id=rule.id,
            category=rule.category,
            severity=rule.severity,
            title=rule.name,
            description=rule.description,
            evidence=evidence,
            source="static.rules",
            metadata={"match_count": total, "rule_version": rule.version},
        )

    # -- secrets ---------------------------------------------------------

    def _run_secrets(self, skill: Skill) -> list[Finding]:
        findings: list[Finding] = []
        for file in skill.files:
            if file.content.startswith("base64:"):
                continue
            for hit in secret_scanner.scan(file.content):
                findings.append(
                    Finding(
                        rule_id="CS-SR-001",
                        category=Category.SECRET_LEAK,
                        severity=Severity.HIGH,
                        title=f"Hardcoded secret ({hit.kind})",
                        description=(
                            "Skill bundle contains a value matching a well-known secret format. "
                            "Even if the key is revoked, shipping it in distribution artifacts is "
                            "a strong indicator of supply-chain compromise."
                        ),
                        evidence=hit.match[:8] + "…",
                        location=f"{file.path}:{hit.span[0]}",
                        source="static.secrets",
                        metadata={"kind": hit.kind},
                    )
                )
        return findings

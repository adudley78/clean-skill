"""Verdict aggregation + scoring."""

from __future__ import annotations

from clean_skill.models import Category, Finding, Severity, Verdict
from clean_skill.verdict import aggregate


def _f(sev: Severity) -> Finding:
    return Finding(
        rule_id="CS-TEST-001",
        category=Category.PROMPT_INJECTION,
        severity=sev,
        title="t",
        description="d",
        source="test",
    )


def test_no_findings_is_clean() -> None:
    assert aggregate([]) == (Verdict.CLEAN, 0)


def test_single_low_is_suspicious() -> None:
    verdict, score = aggregate([_f(Severity.LOW)])
    assert verdict is Verdict.SUSPICIOUS
    assert score == 5


def test_critical_always_blocks() -> None:
    verdict, score = aggregate([_f(Severity.CRITICAL)])
    assert verdict is Verdict.BLOCK
    assert score == 60


def test_score_saturates_at_100() -> None:
    findings = [_f(Severity.HIGH) for _ in range(10)]
    _, score = aggregate(findings)
    assert score == 100


def test_medium_mix_goes_malicious() -> None:
    verdict, _ = aggregate([_f(Severity.MEDIUM), _f(Severity.MEDIUM)])
    assert verdict is Verdict.MALICIOUS

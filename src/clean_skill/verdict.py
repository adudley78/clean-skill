"""Aggregate findings into a single verdict + score.

The scoring model is deliberately conservative: we would rather show a
"suspicious" label on a benign skill than silently clean a malicious one.
"""

from __future__ import annotations

from .models import Finding, Severity, Verdict

_SEVERITY_WEIGHT: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 5,
    Severity.MEDIUM: 15,
    Severity.HIGH: 35,
    Severity.CRITICAL: 60,
}


def aggregate(findings: list[Finding]) -> tuple[Verdict, int]:
    """Return ``(verdict, score)`` for a list of findings.

    Score saturates at 100. Thresholds:

        0         -> CLEAN
        1-24      -> SUSPICIOUS
        25-59     -> MALICIOUS
        60+       -> BLOCK (hard fail; any single CRITICAL triggers this)
    """
    if not findings:
        return Verdict.CLEAN, 0

    score = min(100, sum(_SEVERITY_WEIGHT[f.severity] for f in findings))

    if any(f.severity is Severity.CRITICAL for f in findings):
        return Verdict.BLOCK, score
    if score >= 25:
        return Verdict.MALICIOUS, score
    if score > 0:
        return Verdict.SUSPICIOUS, score
    return Verdict.CLEAN, 0

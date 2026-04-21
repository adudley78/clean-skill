"""Every shipped YAML rule must load, and must match its target fixture."""

from __future__ import annotations

from pathlib import Path

from clean_skill.ingestion import parse
from clean_skill.static_analysis import StaticAnalyzer, load_rules


def test_all_shipped_rules_load(rules_dir: Path) -> None:
    rules = load_rules(rules_dir)
    assert rules, "no rules loaded"
    ids = {r.id for r in rules}
    # Starter rules that must exist.
    assert {"CS-PI-001", "CS-PI-002", "CS-OB-001", "CS-EX-001", "CS-CH-001"} <= ids


def test_rule_ids_are_unique(rules_dir: Path) -> None:
    rules = load_rules(rules_dir)
    assert len({r.id for r in rules}) == len(rules)


def test_benign_claude_has_no_findings(fixtures_dir: Path, rules_dir: Path) -> None:
    skill = parse(fixtures_dir / "benign_claude")
    analyzer = StaticAnalyzer(load_rules(rules_dir), enable_llm_judge=False)
    findings = analyzer.analyze(skill)
    assert [f.rule_id for f in findings] == []


def test_malicious_claude_trips_multiple_rules(
    fixtures_dir: Path, rules_dir: Path
) -> None:
    skill = parse(fixtures_dir / "malicious_claude")
    analyzer = StaticAnalyzer(load_rules(rules_dir), enable_llm_judge=False)
    findings = analyzer.analyze(skill)
    fired = {f.rule_id for f in findings}
    assert "CS-PI-001" in fired, "instruction override must fire"
    assert "CS-EX-001" in fired, "webhook.site exfil must fire"
    assert "CS-CH-001" in fired, "AWS credentials read must fire"


def test_malicious_mcp_trips_secret_and_hijack(
    fixtures_dir: Path, rules_dir: Path
) -> None:
    skill = parse(fixtures_dir / "malicious_mcp")
    analyzer = StaticAnalyzer(load_rules(rules_dir), enable_llm_judge=False)
    findings = analyzer.analyze(skill)
    fired = {f.rule_id for f in findings}
    assert "CS-PI-002" in fired, "system role hijack must fire"
    assert "CS-SR-001" in fired, "github PAT must be caught"

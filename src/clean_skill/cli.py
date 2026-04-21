"""``clean-skill`` command-line interface.

Usage:

    clean-skill scan <path|url>                 # static + dynamic (default)
    clean-skill scan --static-only <path|url>   # skip sandbox
    clean-skill scan --dynamic <path|url>       # skip rule engine + judge
    clean-skill rules list
    clean-skill version
"""

from __future__ import annotations

import logging
import sys
import tempfile
from pathlib import Path

import httpx
import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .config import get_settings
from .dynamic_analysis import DynamicAnalyzer
from .ingestion import parse as parse_skill
from .models import ScanReport, Severity
from .static_analysis import StaticAnalyzer, load_rules
from .verdict import aggregate

app = typer.Typer(
    name="clean-skill",
    help="Detect malicious AI skills before installation or execution.",
    no_args_is_help=True,
)
rules_app = typer.Typer(help="Inspect and validate detection rules.")
app.add_typer(rules_app, name="rules")

console = Console()


_SEVERITY_COLOR = {
    Severity.INFO: "dim",
    Severity.LOW: "yellow",
    Severity.MEDIUM: "orange3",
    Severity.HIGH: "red",
    Severity.CRITICAL: "bold red",
}


def _fetch_remote(url: str) -> Path:
    """Download a remote skill to a temp dir and return the local path."""
    tmp = Path(tempfile.mkdtemp(prefix="cleanskill-dl-"))
    filename = url.rsplit("/", 1)[-1] or "manifest"
    target = tmp / filename
    with httpx.Client(follow_redirects=True, timeout=30.0) as client:
        resp = client.get(url)
        resp.raise_for_status()
        target.write_bytes(resp.content)
    return target


def _resolve_source(source: str) -> Path:
    if source.startswith(("http://", "https://")):
        return _fetch_remote(source)
    return Path(source).resolve()


@app.command()
def scan(
    source: str = typer.Argument(..., help="Path or URL to a skill bundle or manifest."),
    static_only: bool = typer.Option(False, "--static-only", help="Skip dynamic sandbox."),
    dynamic: bool = typer.Option(
        False,
        "--dynamic",
        help="Run only the dynamic sandbox (skip rule engine + LLM judge).",
    ),
    no_llm: bool = typer.Option(False, "--no-llm", help="Disable the LLM-as-judge layer."),
    rules_dir: Path | None = typer.Option(
        None, "--rules-dir", help="Override the rules directory."
    ),
    output_json: bool = typer.Option(False, "--json", help="Emit full ScanReport as JSON."),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Enable debug logging."),
) -> None:
    """Scan a skill and print (or emit) a verdict."""
    if static_only and dynamic:
        raise typer.BadParameter("--static-only and --dynamic are mutually exclusive")

    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    path = _resolve_source(source)
    try:
        skill = parse_skill(path)
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]ingestion failed:[/] {exc}")
        raise typer.Exit(code=2) from exc

    findings = []
    trace = None

    if not dynamic:
        rules = load_rules(rules_dir) if rules_dir else None
        analyzer = StaticAnalyzer(rules=rules, enable_llm_judge=not no_llm)
        findings.extend(analyzer.analyze(skill))

    if not static_only:
        trace, dyn_findings = DynamicAnalyzer().analyze(skill)
        findings.extend(dyn_findings)

    verdict, score = aggregate(findings)
    report = ScanReport(
        skill=skill,
        findings=findings,
        trace=trace,
        verdict=verdict,
        score=score,
    )

    if output_json:
        console.print_json(report.model_dump_json(indent=2))
    else:
        _pretty_print(report)

    # Exit code policy: BLOCK/MALICIOUS = 3, SUSPICIOUS = 1, CLEAN = 0.
    if verdict.value in {"block", "malicious"}:
        raise typer.Exit(code=3)
    if verdict.value == "suspicious":
        raise typer.Exit(code=1)


def _pretty_print(report: ScanReport) -> None:
    console.rule(f"[bold]{report.skill.platform.value}:{report.skill.name}[/bold]")
    console.print(f"bundle sha256: [dim]{report.skill.bundle_sha256}[/dim]")
    console.print(f"files scanned: {len(report.skill.files)}")

    verdict_color = {
        "clean": "green",
        "suspicious": "yellow",
        "malicious": "red",
        "block": "bold red",
    }[report.verdict.value]
    console.print(
        f"verdict: [{verdict_color}]{report.verdict.value.upper()}[/] "
        f"(score {report.score})"
    )

    if not report.findings:
        console.print("[green]no findings[/green]")
        return

    table = Table(title="Findings", show_lines=False)
    table.add_column("Severity")
    table.add_column("Rule")
    table.add_column("Title")
    table.add_column("Source")
    for f in sorted(report.findings, key=lambda f: list(Severity).index(f.severity), reverse=True):
        color = _SEVERITY_COLOR[f.severity]
        table.add_row(
            f"[{color}]{f.severity.value}[/]",
            f.rule_id,
            f.title,
            f.source,
        )
    console.print(table)


@rules_app.command("list")
def rules_list(
    rules_dir: Path | None = typer.Option(None, "--rules-dir"),
) -> None:
    """List every loaded detection rule."""
    root = rules_dir or get_settings().rules_dir
    rules = load_rules(root)
    table = Table(title=f"Rules in {root}")
    table.add_column("ID")
    table.add_column("Severity")
    table.add_column("Category")
    table.add_column("Name")
    for r in rules:
        table.add_row(r.id, r.severity.value, r.category.value, r.name)
    console.print(table)


@rules_app.command("validate")
def rules_validate(
    rules_dir: Path | None = typer.Option(None, "--rules-dir"),
) -> None:
    """Load every rule and fail if any is malformed."""
    root = rules_dir or get_settings().rules_dir
    try:
        rules = load_rules(root)
    except Exception as exc:
        console.print(f"[red]rule validation failed:[/] {exc}")
        raise typer.Exit(code=1) from exc
    console.print(f"[green]ok[/green]: {len(rules)} rules loaded from {root}")


@app.command()
def version() -> None:
    """Print the clean-skill version."""
    console.print(__version__)


def main() -> None:
    """Module entrypoint used by ``python -m clean_skill``."""
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
    sys.exit(0)

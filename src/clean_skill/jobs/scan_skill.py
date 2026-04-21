"""Background scan job: the core unit of work in the async pipeline.

Lifecycle:

  1. Resolve ``source`` to a local path (download if URL).
  2. Compute SHA-256 of the raw manifest bytes for dedup.
  3. Check :class:`ScanResult` history; skip if a fresh scan exists.
  4. Run ingestion → static analysis → dynamic analysis (static-only
     fallback when Docker is unavailable or dynamic is disabled).
  5. Persist a :class:`ScanResult` row — always, even on error.
  6. Return a JSON-serializable dict that RQ stores as ``job.result``.

Retries are declared at enqueue time via RQ's ``Retry(max=3,
interval=[60, 300, 900])``. This function is responsible for its own
error handling for *expected* failure modes (Docker unavailable, bad
manifest); only unexpected exceptions escape and trigger the retry.
"""

from __future__ import annotations

import hashlib
import logging
import shutil
import tempfile
import traceback
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import httpx

from ..config import get_settings
from ..ingestion import parse as parse_skill
from ..models import Finding
from ..static_analysis import StaticAnalyzer
from ..threat_intel import ScanResult, ThreatIntelRepository
from ..verdict import aggregate

logger = logging.getLogger(__name__)

# Verdict strings persisted to the DB. Kept as plain strings (not the
# Verdict enum) because the ScanResult schema stores String and adding
# an "error" value to the enum would confuse the static-analysis code
# that also consumes Verdict.
_VERDICT_ERROR = "error"


def _download(url: str) -> Path:
    """Download ``url`` to a fresh tempdir and return the local path."""
    tmp = Path(tempfile.mkdtemp(prefix="cleanskill-job-"))
    filename = url.rsplit("/", 1)[-1] or "manifest"
    target = tmp / filename
    with httpx.Client(follow_redirects=True, timeout=30.0) as client:
        resp = client.get(url)
        resp.raise_for_status()
        target.write_bytes(resp.content)
    return target


def _resolve_source(source: str) -> tuple[Path, bool]:
    """Return ``(local_path, is_temp)``; caller must clean up when temp."""
    if source.startswith(("http://", "https://")):
        return _download(source), True
    return Path(source).resolve(), False


def _hash_source(path: Path) -> str:
    """SHA-256 of the raw bytes at ``path``.

    For a directory we hash a stable canonicalization (path + sha256 of
    each file) so re-scanning the same bundle always keys the same row.
    """
    if path.is_file():
        return hashlib.sha256(path.read_bytes()).hexdigest()

    # Directory: hash the sorted list of "relpath:content-sha256" lines.
    hasher = hashlib.sha256()
    for file in sorted(p for p in path.rglob("*") if p.is_file()):
        rel = file.relative_to(path)
        file_hash = hashlib.sha256(file.read_bytes()).hexdigest()
        hasher.update(f"{rel}:{file_hash}\n".encode())
    return hasher.hexdigest()


def _is_fresh(scanned_at: datetime, rescan_days: int) -> bool:
    """True if a prior scan is within the rescan window."""
    now = datetime.now(UTC)
    # DB-round-tripped datetimes are naive (no tzinfo) on SQLite; assume UTC.
    if scanned_at.tzinfo is None:
        scanned_at = scanned_at.replace(tzinfo=UTC)
    return (now - scanned_at) < timedelta(days=rescan_days)


def _findings_to_dicts(findings: list[Finding]) -> list[dict[str, Any]]:
    return [f.model_dump(mode="json") for f in findings]


def scan_skill_job(
    source: str,
    *,
    dynamic: bool = True,
    enqueued_by: str = "api",
) -> dict[str, Any]:
    """Run the full scan pipeline and persist a :class:`ScanResult`.

    See module docstring for lifecycle. Return value is a JSON-serializable
    dict (RQ pickles job results, but keeping it dict-only makes the result
    introspectable from any client, including the FastAPI status endpoint).
    """
    settings = get_settings()
    local_path, is_temp = _resolve_source(source)

    try:
        skill_hash = _hash_source(local_path)

        # Hash-level dedup: skip if the same bundle was scanned recently.
        repo = ThreatIntelRepository()
        prior = repo.latest_scan_by_hash(skill_hash)
        if prior is not None and _is_fresh(prior.scanned_at, settings.rescan_days):
            logger.info(
                "skipping scan for %s: fresh result exists (hash=%s, scanned_at=%s)",
                source,
                skill_hash,
                prior.scanned_at,
            )
            return {
                "source": source,
                "skill_hash": skill_hash,
                "deduped": True,
                "verdict": prior.verdict,
                "prior_scan_id": prior.id,
                "scanned_at": prior.scanned_at.isoformat(),
            }

        return _run_pipeline_and_persist(
            repo=repo,
            source=source,
            local_path=local_path,
            skill_hash=skill_hash,
            dynamic=dynamic and settings.dynamic_enabled,
            enqueued_by=enqueued_by,
        )
    finally:
        if is_temp:
            shutil.rmtree(local_path.parent, ignore_errors=True)


def _run_pipeline_and_persist(
    *,
    repo: ThreatIntelRepository,
    source: str,
    local_path: Path,
    skill_hash: str,
    dynamic: bool,
    enqueued_by: str,
) -> dict[str, Any]:
    """Execute ingest → static → dynamic and write the ScanResult row."""
    static_findings: list[Finding] = []
    dynamic_findings: list[Finding] = []
    dynamic_skipped = not dynamic
    error_message: str | None = None
    verdict_str = _VERDICT_ERROR

    try:
        skill = parse_skill(local_path)
    except (FileNotFoundError, ValueError) as exc:
        error_message = f"ingestion failed: {exc}"
        logger.warning("scan_skill_job ingestion error for %s: %s", source, exc)
        return _persist(
            repo,
            source=source,
            skill_hash=skill_hash,
            verdict_str=verdict_str,
            static_findings=[],
            dynamic_findings=[],
            dynamic_skipped=True,
            enqueued_by=enqueued_by,
            error_message=error_message,
        )

    try:
        static_findings = StaticAnalyzer().analyze(skill)
    except Exception as exc:
        # Any static-analysis crash is a job-level error; we want the row
        # persisted so operators can see what's breaking without trawling
        # worker logs.
        error_message = f"static analysis failed: {exc}\n{traceback.format_exc()}"
        logger.exception("scan_skill_job static failure for %s", source)
        return _persist(
            repo,
            source=source,
            skill_hash=skill_hash,
            verdict_str=_VERDICT_ERROR,
            static_findings=[],
            dynamic_findings=[],
            dynamic_skipped=True,
            enqueued_by=enqueued_by,
            error_message=error_message,
        )

    if dynamic:
        dynamic_findings, dynamic_skipped, dyn_err = _run_dynamic(skill)
        if dyn_err:
            # Dynamic failure never fails the whole job — log & move on.
            logger.warning("dynamic analysis skipped for %s: %s", source, dyn_err)
            error_message = f"dynamic analysis skipped: {dyn_err}"

    verdict, _score = aggregate(static_findings + dynamic_findings)
    verdict_str = verdict.value

    return _persist(
        repo,
        source=source,
        skill_hash=skill_hash,
        verdict_str=verdict_str,
        static_findings=static_findings,
        dynamic_findings=dynamic_findings,
        dynamic_skipped=dynamic_skipped,
        enqueued_by=enqueued_by,
        error_message=error_message,
    )


def _run_dynamic(skill: Any) -> tuple[list[Finding], bool, str | None]:
    """Run the sandbox; swallow Docker-availability errors.

    Returns ``(findings, skipped, error_message)``. ``skipped`` is True
    when dynamic analysis did not execute (Docker unavailable, import
    failure, or explicit degradation).
    """
    try:
        from ..dynamic_analysis import DynamicAnalyzer
    except ImportError as exc:
        return [], True, f"docker SDK import failed: {exc}"

    try:
        from docker.errors import DockerException
    except ImportError:
        # docker is a hard dep in pyproject.toml, so this path is defensive;
        # in exotic environments (packaging experiments, minimal images) we
        # still want the job to run, just without the typed Docker error.
        DockerException = Exception

    try:
        _trace, findings = DynamicAnalyzer().analyze(skill)
    except DockerException as exc:
        return [], True, f"docker unavailable: {exc}"

    # The sandbox swallows "no docker" internally and returns a single
    # HIGH-severity finding; treat that as "skipped" for operator clarity
    # so the scan isn't falsely labeled malicious just because Docker
    # wasn't reachable.
    if len(findings) == 1 and findings[0].rule_id == "CS-DA-000":
        return [], True, findings[0].description
    return findings, False, None


def _persist(
    repo: ThreatIntelRepository,
    *,
    source: str,
    skill_hash: str,
    verdict_str: str,
    static_findings: list[Finding],
    dynamic_findings: list[Finding],
    dynamic_skipped: bool,
    enqueued_by: str,
    error_message: str | None,
) -> dict[str, Any]:
    """Write the ScanResult row and return the result dict."""
    row = ScanResult(
        source=source,
        skill_hash=skill_hash,
        verdict=verdict_str,
        static_findings=cast(Any, _findings_to_dicts(static_findings)),
        dynamic_findings=cast(Any, _findings_to_dicts(dynamic_findings)),
        dynamic_skipped=dynamic_skipped,
        enqueued_by=enqueued_by,
        error_message=error_message,
    )
    saved = repo.save_scan_result(row)
    return {
        "source": source,
        "skill_hash": skill_hash,
        "deduped": False,
        "verdict": saved.verdict,
        "scan_result_id": saved.id,
        "static_finding_count": len(static_findings),
        "dynamic_finding_count": len(dynamic_findings),
        "dynamic_skipped": dynamic_skipped,
        "error": error_message,
    }

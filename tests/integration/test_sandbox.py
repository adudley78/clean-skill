"""End-to-end sandbox execution test.

Skipped when Docker isn't available or the sandbox image hasn't been built.
Opt in via ``pytest -m integration`` or by setting
``CLEAN_SKILL_RUN_INTEGRATION=1``.

The test exercises the full dynamic-analysis path:

    fixture skill -> materialize -> docker run -> runner.sh
      -> strace -> audit.jsonl -> SandboxTrace -> behavioral findings
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from clean_skill.config import get_settings
from clean_skill.dynamic_analysis import DynamicAnalyzer
from clean_skill.ingestion import parse as parse_skill


def _docker_available() -> bool:
    try:
        import docker
        from docker.errors import DockerException
    except ImportError:
        return False
    try:
        client = docker.from_env()  # type: ignore[attr-defined]
        client.ping()
    except DockerException:
        return False
    return True


def _image_exists(name: str) -> bool:
    try:
        import docker
    except ImportError:
        return False
    try:
        client = docker.from_env()  # type: ignore[attr-defined]
        client.images.get(name)
    except Exception:
        return False
    return True


pytestmark = pytest.mark.integration


@pytest.mark.skipif(
    not os.environ.get("CLEAN_SKILL_RUN_INTEGRATION"),
    reason="set CLEAN_SKILL_RUN_INTEGRATION=1 to run dynamic integration tests",
)
def test_sandbox_runs_fixture_end_to_end(fixtures_dir: Path) -> None:
    if not _docker_available():
        pytest.skip("docker daemon unreachable")

    image = get_settings().sandbox_image
    if not _image_exists(image):
        pytest.skip(f"sandbox image {image!r} not built; run `make sandbox` first")

    skill = parse_skill(fixtures_dir / "dynamic_target")
    trace, findings = DynamicAnalyzer().analyze(skill)

    # Debug dump — helps diagnose sandbox-init failures in CI logs.
    print(f"\n[sandbox] exit_code={trace.exit_code} timed_out={trace.timed_out}")
    print(f"[sandbox] duration_s={trace.duration_s:.2f}")
    for ev in trace.events:
        print(f"[sandbox] event: {ev.kind} {ev.detail}")
    for f in findings:
        print(f"[sandbox] finding: {f.rule_id} {f.severity} {f.message}")

    assert trace.exit_code != -1, f"sandbox did not run: findings={findings}"
    assert not trace.timed_out, "sandbox timed out"
    assert trace.exit_code == 0, (
        f"skill exited non-zero inside sandbox: {trace.exit_code}"
    )

    # The runner always emits its own events (exec + exit), independent of
    # strace, so this guarantees the audit-log plumbing works end-to-end
    # even on sandbox runtimes that disable ptrace.
    runner_events = [e for e in trace.events if e.kind == "runner"]
    assert runner_events, (
        "no runner events captured; audit-log retrieval is broken"
    )
    exit_events = [
        e for e in runner_events if e.detail.get("detail", {}).get("op") == "exit"
    ]
    assert exit_events, f"runner exit event missing; events={runner_events}"

    # Process/filesystem events depend on strace; some runtimes (gVisor
    # platforms without ptrace) suppress them. Log but don't fail if absent.
    kinds = {e.kind for e in trace.events}
    if "process" not in kinds:
        print(
            "[sandbox] warning: no process events captured — strace may be "
            "blocked by the runtime; runner events prove the pipeline works"
        )

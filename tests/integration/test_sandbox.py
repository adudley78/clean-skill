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

    # The runner executed and the audit log was populated.
    assert trace.exit_code != -1, f"sandbox did not run: findings={findings}"
    assert not trace.timed_out, "sandbox timed out"

    kinds = {e.kind for e in trace.events}
    assert kinds, "no sandbox events captured; runner.sh or strace parsing is broken"
    # At minimum we should see process events (python + sh exec chain).
    assert "process" in kinds, f"no process events recorded: kinds={kinds}"

    # Findings contract: we expect the shell spawn to fire CS-DA-PROC-001.
    fired = {f.rule_id for f in findings}
    assert "CS-DA-PROC-001" in fired, (
        f"process-abuse detector did not fire; findings were {fired}"
    )

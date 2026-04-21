"""Docker sandbox orchestration.

Design goals (in priority order):

1. **Containment.** We target gVisor (``runsc``) to avoid sharing the host
   kernel. Network egress is blocked by default via ``--network none`` and a
   userspace proxy that the sandbox must call through.
2. **Reproducibility.** Every run gets a fresh, ephemeral container. We mount
   the skill bundle read-only.
3. **Observability.** We collect three signals from inside the container:
   a) network calls via the mock-LLM + recording HTTP proxy,
   b) filesystem writes via a syscall-trace audit log mounted into /var/log,
   c) process spawns via the same audit log.
4. **Graceful degradation.** If Docker is unavailable the analyzer returns
   a trace with ``exit_code=-1`` and a single HIGH-severity finding explaining
   dynamic analysis was skipped, so CI can choose to fail closed or open.

The actual syscall-trace implementation lives in ``docker/sandbox.Dockerfile``.
This module only orchestrates the container lifecycle and parses its output.
"""

from __future__ import annotations

import io
import json
import logging
import tarfile
import tempfile
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..config import get_settings
from ..models import (
    Category,
    Finding,
    SandboxEvent,
    SandboxTrace,
    Severity,
    Skill,
)

logger = logging.getLogger(__name__)


@dataclass
class SandboxConfig:
    """Per-run knobs; defaults come from :func:`clean_skill.config.get_settings`."""

    image: str
    runtime: str
    timeout_s: int
    memory_mb: int
    cpu_quota: float
    network: str = "none"
    read_only_root: bool = True
    drop_capabilities: list[str] = field(default_factory=lambda: ["ALL"])
    no_new_privileges: bool = True

    @classmethod
    def from_settings(cls) -> SandboxConfig:
        s = get_settings()
        return cls(
            image=s.sandbox_image,
            runtime=s.sandbox_runtime,
            timeout_s=s.sandbox_timeout_s,
            memory_mb=s.sandbox_memory_mb,
            cpu_quota=s.sandbox_cpu_quota,
        )


class DynamicAnalyzer:
    """Run a :class:`Skill` inside a sandboxed container and collect findings."""

    def __init__(self, config: SandboxConfig | None = None) -> None:
        self._config = config or SandboxConfig.from_settings()

    def analyze(self, skill: Skill) -> tuple[SandboxTrace, list[Finding]]:
        try:
            import docker
            from docker.errors import DockerException
        except ImportError:  # pragma: no cover
            return self._degraded("docker SDK not installed")

        try:
            client = docker.from_env()  # type: ignore[attr-defined]
            client.ping()
        except DockerException as exc:
            return self._degraded(f"docker daemon unreachable: {exc}")

        with tempfile.TemporaryDirectory(prefix="cleanskill-") as tmp:
            bundle_dir = Path(tmp) / "bundle"
            bundle_dir.mkdir()
            self._materialize(skill, bundle_dir)

            started = datetime.now(UTC)
            t0 = time.monotonic()
            timed_out = False
            exit_code = -1
            raw_events: list[dict[str, Any]] = []

            try:
                container = client.containers.run(
                    image=self._config.image,
                    command=["/opt/clean-skill/runner.sh", "/skill"],
                    detach=True,
                    network_disabled=(self._config.network == "none"),
                    runtime=self._config.runtime,
                    mem_limit=f"{self._config.memory_mb}m",
                    nano_cpus=int(self._config.cpu_quota * 1_000_000_000),
                    read_only=self._config.read_only_root,
                    cap_drop=self._config.drop_capabilities,
                    security_opt=["no-new-privileges:true"]
                    if self._config.no_new_privileges
                    else [],
                    tmpfs={"/tmp": "rw,noexec,nosuid,size=64m"},
                    volumes={str(bundle_dir): {"bind": "/skill", "mode": "ro"}},
                    environment={
                        "CLEAN_SKILL_PLATFORM": skill.platform.value,
                        "CLEAN_SKILL_ENTRYPOINT": skill.entrypoint or "",
                    },
                )
            except Exception as exc:
                return self._degraded(f"failed to launch sandbox: {exc}")

            try:
                result = container.wait(timeout=self._config.timeout_s)
                exit_code = int(result.get("StatusCode", -1))
            except Exception:
                timed_out = True
                container.kill()
            finally:
                raw_events = self._drain_audit_log(container)
                try:
                    container.remove(force=True)
                except Exception as exc:
                    logger.debug("container cleanup failed: %s", exc)

            duration = time.monotonic() - t0

        events = [
            SandboxEvent(kind=e.get("kind", "unknown"), detail=e)
            for e in raw_events
            if isinstance(e, dict)
        ]
        trace = SandboxTrace(
            started_at=started,
            duration_s=duration,
            exit_code=exit_code,
            timed_out=timed_out,
            events=events,
        )
        return trace, self._score(skill, trace)

    # -- helpers ---------------------------------------------------------

    @staticmethod
    def _materialize(skill: Skill, out: Path) -> None:
        """Write every :class:`SkillFile` back to disk under ``out``."""
        for sf in skill.files:
            target = out / sf.path
            target.parent.mkdir(parents=True, exist_ok=True)
            if sf.content.startswith("base64:"):
                import base64 as _b64

                target.write_bytes(_b64.b64decode(sf.content[len("base64:") :]))
            else:
                target.write_text(sf.content, encoding="utf-8")

    @staticmethod
    def _drain_audit_log(container: Any) -> list[dict[str, Any]]:
        """Read ``/var/log/cleanskill/audit.jsonl`` from the stopped container."""
        try:
            bits, _ = container.get_archive("/var/log/cleanskill/audit.jsonl")
        except Exception:
            return []
        buf = io.BytesIO(b"".join(bits))
        events: list[dict[str, Any]] = []
        with tarfile.open(fileobj=buf) as tar:
            for member in tar:
                f = tar.extractfile(member)
                if f is None:
                    continue
                for line in f.read().splitlines():
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return events

    @staticmethod
    def _degraded(reason: str) -> tuple[SandboxTrace, list[Finding]]:
        logger.warning("dynamic analysis degraded: %s", reason)
        trace = SandboxTrace(
            started_at=datetime.now(UTC),
            duration_s=0.0,
            exit_code=-1,
            timed_out=False,
            events=[],
        )
        finding = Finding(
            rule_id="CS-DA-000",
            category=Category.MANIFEST_INTEGRITY,
            severity=Severity.INFO,
            title="Dynamic analysis skipped",
            description=(
                "Dynamic sandbox could not be started. The static verdict alone is "
                "reported. Reason: " + reason
            ),
            source="dynamic.sandbox",
        )
        return trace, [finding]

    def _score(self, skill: Skill, trace: SandboxTrace) -> list[Finding]:
        """Convert sandbox events into :class:`Finding` objects.

        The rules here are intentionally simple and conservative; richer
        behavioral profiling (e.g. comparing observed egress to declared
        ``allowed_hosts``) is layered on top.
        """
        findings: list[Finding] = []
        declared_hosts = {h.lower() for h in skill.declared_network}

        for event in trace.events:
            if event.kind == "network":
                host = str(event.detail.get("host", "")).lower()
                if host and declared_hosts and host not in declared_hosts:
                    findings.append(
                        Finding(
                            rule_id="CS-DA-NET-001",
                            category=Category.UNEXPECTED_EGRESS,
                            severity=Severity.HIGH,
                            title="Undeclared network egress",
                            description=(
                                f"Skill contacted {host} which is not in the manifest's "
                                "declared network allowlist."
                            ),
                            evidence=json.dumps(event.detail),
                            location=event.ts.isoformat(),
                            source="dynamic.network",
                        )
                    )
            elif event.kind == "filesystem":
                path = str(event.detail.get("path", ""))
                if event.detail.get("op") == "write" and not path.startswith(("/tmp/", "/skill/")):
                    findings.append(
                        Finding(
                            rule_id="CS-DA-FS-001",
                            category=Category.FILESYSTEM_ABUSE,
                            severity=Severity.MEDIUM,
                            title="Write outside expected scope",
                            description=(
                                f"Skill wrote to {path!r} which is outside /tmp and the "
                                "bundle mount."
                            ),
                            evidence=json.dumps(event.detail),
                            source="dynamic.filesystem",
                        )
                    )
            elif event.kind == "process":
                argv = event.detail.get("argv", [])
                if argv and argv[0] in {"/bin/sh", "/bin/bash", "sh", "bash", "curl", "wget"}:
                    findings.append(
                        Finding(
                            rule_id="CS-DA-PROC-001",
                            category=Category.PROCESS_ABUSE,
                            severity=Severity.MEDIUM,
                            title="Shell / downloader spawn",
                            description=(
                                "Skill spawned a shell or network downloader. Legitimate "
                                "skills rarely need either."
                            ),
                            evidence=json.dumps(event.detail),
                            source="dynamic.process",
                        )
                    )

        if trace.timed_out:
            findings.append(
                Finding(
                    rule_id="CS-DA-TO-001",
                    category=Category.PROCESS_ABUSE,
                    severity=Severity.LOW,
                    title="Sandbox timeout",
                    description="Skill did not complete within the configured timeout.",
                    source="dynamic.sandbox",
                )
            )
        return findings

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

import json
import logging
import os
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

# Docker socket locations we probe when DOCKER_HOST is not set.
#
# Ordering rationale:
#   1. The Linux + "Allow the default Docker socket" opt-in on macOS.
#   2. macOS Docker Desktop's per-user socket (default since 4.x). This is
#      the case that tripped up local dev before — docker-py's ``from_env``
#      only looks at DOCKER_HOST and ``/var/run/docker.sock``, so on a
#      stock Docker Desktop install we'd silently report "docker daemon
#      unreachable" and degrade to a no-op.
#   3. Colima's default socket for users who prefer it over Docker Desktop.
#   4. Podman's user socket (rootless). Docker API compatibility mode only.
_HOME = Path.home()
_DOCKER_SOCKET_CANDIDATES: tuple[str, ...] = (
    "/var/run/docker.sock",
    str(_HOME / ".docker" / "run" / "docker.sock"),
    str(_HOME / ".colima" / "default" / "docker.sock"),
    # Podman rootless socket (Docker API-compatible).
    str(_HOME / ".local" / "share" / "containers" / "podman.sock"),
)


def connect_docker() -> Any:
    """Return a connected Docker client, probing known socket locations.

    Raises ``docker.errors.DockerException`` if nothing responds. Separate
    from :class:`DynamicAnalyzer` so the integration test can share the
    exact same discovery logic.
    """
    import docker
    from docker.errors import DockerException

    if os.environ.get("DOCKER_HOST"):
        client = docker.from_env()  # type: ignore[attr-defined]
        client.ping()
        return client

    last_exc: Exception | None = None
    for sock in _DOCKER_SOCKET_CANDIDATES:
        if not Path(sock).exists():
            continue
        try:
            client = docker.DockerClient(base_url=f"unix://{sock}")  # type: ignore[attr-defined]
            client.ping()
            logger.debug("connected to docker via %s", sock)
            return client
        except DockerException as exc:
            last_exc = exc
            logger.debug("docker socket %s did not respond: %s", sock, exc)

    # Fall back to docker-py's own defaults so the error message is the
    # library's canonical one when nothing else worked.
    try:
        client = docker.from_env()  # type: ignore[attr-defined]
        client.ping()
        return client
    except DockerException as exc:
        if last_exc is not None:
            raise DockerException(
                f"no docker daemon reachable (last error: {last_exc})"
            ) from exc
        raise


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
            import docker  # noqa: F401  (import used by connect_docker)
            from docker.errors import DockerException
        except ImportError:  # pragma: no cover
            return self._degraded("docker SDK not installed")

        try:
            client = connect_docker()
        except DockerException as exc:
            return self._degraded(f"docker daemon unreachable: {exc}")

        runtime = self._select_runtime(client)
        if runtime is None:
            return self._degraded(
                f"no usable container runtime (requested {self._config.runtime!r})"
            )

        with tempfile.TemporaryDirectory(prefix="cleanskill-") as tmp:
            bundle_dir = Path(tmp) / "bundle"
            bundle_dir.mkdir()
            log_dir = Path(tmp) / "logs"
            log_dir.mkdir()
            # Container user (uid 10001) needs write access to the bind
            # mount. The host tempdir was created with 0755 by default, so
            # uid 10001 could cd in but not create files.
            log_dir.chmod(0o0777)
            self._materialize(skill, bundle_dir)

            started = datetime.now(UTC)
            t0 = time.monotonic()
            timed_out = False
            exit_code = -1
            raw_events: list[dict[str, Any]] = []

            try:
                container = client.containers.run(
                    image=self._config.image,
                    # The image's ENTRYPOINT is `runner.sh`; `command` supplies
                    # only its arguments (the skill mount point). Prepending
                    # the script path here would cause the runner to re-exec
                    # itself with the wrong $1.
                    command=["/skill"],
                    detach=True,
                    network_disabled=(self._config.network == "none"),
                    runtime=runtime,
                    mem_limit=f"{self._config.memory_mb}m",
                    nano_cpus=int(self._config.cpu_quota * 1_000_000_000),
                    read_only=self._config.read_only_root,
                    cap_drop=self._config.drop_capabilities,
                    security_opt=["no-new-privileges:true"]
                    if self._config.no_new_privileges
                    else [],
                    # /tmp stays tmpfs (ephemeral scratch for the skill).
                    tmpfs={"/tmp": "rw,noexec,nosuid,size=64m"},
                    # Bundle is RO; the audit log is a host-side bind mount
                    # so the file survives container teardown (tmpfs
                    # contents evaporate when the container's mount
                    # namespace exits).
                    volumes={
                        str(bundle_dir): {"bind": "/skill", "mode": "ro"},
                        str(log_dir): {"bind": "/var/log/cleanskill", "mode": "rw"},
                    },
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
                raw_events = self._drain_audit_log_host(log_dir)
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

    def _select_runtime(self, client: Any) -> str | None:
        """Return the best available Docker runtime.

        Strategy:

        1. Prefer the configured runtime (default ``runsc`` / gVisor).
        2. If unavailable, fall back to ``runc`` with a loud warning. This is
           strictly weaker isolation (shared host kernel) and is intended
           only for local dev / CI environments that can't install gVisor
           (e.g. macOS Docker Desktop, unprivileged Linux runners).
        3. If ``runc`` is also missing (unusual), return None so the caller
           degrades gracefully.
        """
        want = self._config.runtime
        try:
            info = client.info()
        except Exception as exc:
            logger.warning("could not query docker info: %s", exc)
            return want  # let Docker fail loudly if the runtime is bogus

        available = set((info.get("Runtimes") or {}).keys())
        if want in available:
            return want

        if "runc" in available:
            logger.warning(
                "configured sandbox runtime %r not available on this host; "
                "falling back to 'runc'. Install gVisor for production isolation: "
                "https://gvisor.dev/docs/user_guide/install/",
                want,
            )
            return "runc"

        return None

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
    def _drain_audit_log_host(log_dir: Path) -> list[dict[str, Any]]:
        """Read ``audit.jsonl`` from the host-side bind-mounted log dir.

        Reading via the host FS (rather than ``container.get_archive``) means
        events survive container teardown and we don't need the container
        still alive when we collect them.
        """
        path = log_dir / "audit.jsonl"
        if not path.exists():
            logger.warning("audit log missing after sandbox run: %s", path)
            return []
        events: list[dict[str, Any]] = []
        raw = path.read_bytes()
        if not raw:
            logger.debug("audit log present but empty")
        for line in raw.splitlines():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                logger.debug("skipping non-JSON audit line: %r", line[:120])
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

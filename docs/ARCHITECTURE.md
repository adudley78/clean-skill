# clean-skill Architecture

This document is the authoritative design reference for clean-skill. It
covers tech-stack decisions, component responsibilities, data flow, and the
trust boundaries between components.

## 1. Tech stack decisions

Opinionated choices, with rationale.

### Core language: Python 3.11+

**Chosen.** Rationale:

- Every major AI framework we need to parse (LangChain, LlamaIndex, MCP,
  Anthropic/OpenAI SDKs) is Python-first. Parity with what attackers ship is
  more valuable than raw throughput.
- Scanner latency is dominated by (a) I/O against registry APIs and (b) the
  sandbox container lifecycle, not CPU. Go's concurrency advantage would
  benefit the crawler, not the analyzer.
- `yara-python`, `detect-secrets`, `strace` parsers, and `docker` SDK are
  all first-class in Python.

Go was evaluated for the crawler specifically; we can rewrite that
component if profiling justifies it. For v0.1, everything is Python.

### Packaging: `hatchling` + `pyproject.toml`, src-layout

`hatchling` over `setuptools`: no legacy baggage, PEP 621 native. `uv` and
`pip install -e .` both work. `src/` layout prevents "import from cwd"
footguns during testing.

### CLI: Typer + Rich

Typer gives us declarative commands with full type-hint introspection and
zero boilerplate. Rich powers the colorized verdict table. Both are
maintained and widely adopted.

### Data models: Pydantic v2

Everything that crosses a module boundary is a Pydantic model:
`Skill`, `Finding`, `SandboxTrace`, `ScanReport`. This gets us JSON
serialization, OpenAPI schemas, and validation for free. Rule files are
also Pydantic models — malformed rules fail fast with actionable errors.

### Rule engine: custom YAML (Sigma-inspired)

Evaluated:

1. **YARA** — great for binary payload matching, awkward for structured
   prose + manifest scanning. Offered as an optional extra (`pip install
   clean-skill[yara]`).
2. **Sigma** — right model for us (human-authored, contributable,
   versioned), but Sigma's log-event grammar doesn't fit text + JSON
   manifest scopes.
3. **Custom YAML** — chosen. Adopts Sigma's metadata discipline (`id`,
   `author`, `version`, `references`), our own `patterns` + `condition`
   grammar, and first-class `decode: base64` recursion.

See [`rule_format.md`](./rule_format.md).

### LLM-as-judge: Anthropic (default) + OpenAI (fallback)

Direct SDK calls, not `litellm` — we want explicit provider semantics for
the judge, especially around JSON-mode / tool-use quirks. Prompt wraps the
skill content in `<untrusted_content>` to harden against indirect prompt
injection of the judge itself.

### Sandbox: Docker + gVisor (`runsc`)

gVisor was chosen over Firecracker and plain Docker:

- **Firecracker** requires a KVM host; CI runners (GitHub Actions, Cirrus)
  typically disallow nested virt. gVisor runs anywhere Docker does.
- **Plain Docker** shares the host kernel. For untrusted code this is not
  acceptable — one CVE in namespace handling defeats the whole product.
- gVisor's userspace-kernel intercepts syscalls in Sentry, giving us a
  strong boundary with acceptable performance (a few hundred ms startup).

Egress is blocked at the Docker level (`--network none`) and re-enabled
only against the in-sandbox mock LLM on `127.0.0.1:8088`. Syscall tracing
via `strace` produces a JSONL audit log that the host parses back into
`SandboxEvent` instances.

### Threat-intel store: PostgreSQL 16 via SQLAlchemy 2

- Relational schema for known-bad skills, signatures, crawler cursors.
- `JSONB` column for flexible per-skill metadata without schema churn.
- Alembic for migrations.
- SQLite is supported for local dev / tests (set `CLEAN_SKILL_DB_URL`).

### Crawler queue: Redis + RQ

RQ over Celery: simpler operationally, perfectly adequate for a task queue
whose hot path is "download artifact, enqueue scan, write result." Celery's
broker-agnosticism isn't worth the config surface.

### HTTP API: FastAPI + Uvicorn

Native Pydantic integration (our models become the OpenAPI schema),
async-first, and mature. Bearer-token auth for v0.1; production deployments
should terminate TLS + auth at a reverse proxy.

## 2. Component overview

```
src/clean_skill/
├── cli.py                 CLI entrypoint (Typer)
├── config.py              Pydantic Settings from .env
├── models.py              Skill, Finding, SandboxTrace, ScanReport
├── verdict.py             Aggregate findings -> Verdict + score
├── ingestion/             SkillParser ABC + 7 platform adapters
├── static_analysis/       Rule engine + secret scanner + LLM judge
├── dynamic_analysis/      Docker sandbox + mock LLM + audit parser
├── crawler/               Registry pollers + RQ jobs
├── threat_intel/          SQLAlchemy models + repository
└── api/                   FastAPI app
```

## 3. Data flow

```
source: path|url
   │
   ▼
ingestion.parse() ───────────► Skill
                                 │
             ┌───────────────────┼───────────────────┐
             ▼                                       ▼
    static_analysis.StaticAnalyzer          dynamic_analysis.DynamicAnalyzer
             │                                       │
   list[Finding]                          SandboxTrace + list[Finding]
             └───────────────────┬───────────────────┘
                                 ▼
                         verdict.aggregate()
                                 │
                                 ▼
                             ScanReport
                                 │
           ┌─────────────────────┼─────────────────────┐
           ▼                     ▼                     ▼
       CLI stdout           FastAPI JSON         ThreatIntel DB (if bad)
```

Static analysis runs three detectors and merges their findings:

1. **Rule engine.** Walks every `rules/**/*.yml` file, applies each rule
   whose `platforms` include the skill's platform, and emits a `Finding`
   per matched rule.
2. **Secret scanner.** Regex set for AWS / GitHub / Slack / Stripe / OpenAI
   / Anthropic keys and PEM blocks.
3. **LLM-as-judge.** Single call to Claude or GPT; returns structured
   verdict that maps to severity.

Dynamic analysis runs one sandboxed container, parses the audit log into
`SandboxEvent`s, and produces findings when observed behavior violates the
skill's declared manifest (undeclared egress, writes outside `/tmp` and
the bundle mount, shell/downloader spawns).

## 4. Trust boundaries

| Boundary                                        | Assumption                                                      |
|-------------------------------------------------|-----------------------------------------------------------------|
| Host ↔ sandbox container                        | gVisor + dropped caps + `--network none` + read-only rootfs     |
| LLM judge input                                 | Treat all skill content as untrusted; wrap in explicit tags     |
| Crawler ↔ registry                              | Registries are untrusted; enforce size caps + TLS verification  |
| API ↔ client                                    | Bearer token; TLS terminated upstream                           |
| Rule files                                      | Trusted, reviewed via PR; CI runs `rules validate`              |

## 5. Roadmap

- Sigma-style named-selector conditions (`sel_a and sel_b`).
- Per-file YARA rule execution when `clean-skill[yara]` is installed.
- Signed rule packs + reproducible rule bundle hashes.
- Firecracker backend for environments that have KVM.
- Registry adapters for LangChain Hub, OpenClaw / ClawHub, and the
  Anthropic skill directory.

# Contributing to clean-skill

Thanks for helping make AI skill marketplaces safer. The fastest and highest
impact way to contribute is by authoring **detection rules**.

## Ways to contribute

1. **Detection rules** — new YAML rules under `rules/<category>/`.
2. **Platform parsers** — a new `SkillParser` subclass in `src/clean_skill/ingestion/`.
3. **Registry crawlers** — adapters in `src/clean_skill/crawler/registries/`.
4. **Dynamic-analysis checks** — new behavioral findings in `dynamic_analysis/sandbox.py`.
5. **Bug reports + repro cases** — fixtures under `tests/fixtures/skills/` count.

## Dev setup

```bash
git clone https://github.com/adudley78/clean-skill && cd clean-skill
python -m venv .venv && source .venv/bin/activate
make install       # editable install + dev deps

make test          # unit tests (fast, no Docker)
make lint          # ruff
make typecheck     # mypy --strict
make check         # all three above
```

### Running the dynamic-analysis integration test

The full pipeline runs a fixture skill under strace inside a container.
You need a Docker daemon — gVisor (`runsc`) is preferred, but the
analyzer transparently falls back to `runc` with a warning.

```bash
make sandbox-test  # builds the image if missing, then runs the suite
```

The Makefile auto-detects Docker Desktop on macOS (CLI inside
`/Applications/Docker.app` and the per-user socket at
`~/.docker/run/docker.sock`). On Linux it uses whatever's on `PATH` and
`/var/run/docker.sock`. No env vars required.

## Adding a detection rule

1. Pick (or create) a subdirectory under `rules/` that matches the
   category (`prompt_injection/`, `obfuscation/`, etc.).
2. Create a YAML file with the schema documented in
   [`docs/rule_format.md`](./docs/rule_format.md). Allocate a unique ID of
   the form `CS-<XX>-<NNN>`:
   - `PI` = prompt injection / instruction override
   - `OB` = obfuscation
   - `EX` = exfiltration
   - `CH` = credential harvest
   - `SR` = secrets
   - `DA` = dynamic-analysis
3. Add at least one minimal fixture under `tests/fixtures/skills/` that
   triggers the rule, and add an assertion to `tests/unit/test_rules.py`.
4. Run `clean-skill rules validate` and `pytest tests/unit/test_rules.py`.
5. Open a PR. Please include:
   - At least one public reference (CVE, MITRE ATT&CK, blog post, or
     captured attack sample). False-positive risk is reviewed by maintainers
     before merge.
   - A note on the expected true-positive and false-positive profile.

## False-positive policy

High-severity rules that flag benign skills at > 1% rate are reverted until
their `patterns` are tightened. If you are not sure, start at `medium`
severity and promote once real-world telemetry justifies it.

## Adding a platform parser

1. Subclass `clean_skill.ingestion.base.SkillParser`.
2. Implement `detect(path)` cheaply (header sniff or filename check).
3. Implement `parse(path)` returning a populated `Skill`.
4. Register the class in `clean_skill.ingestion.__init__._REGISTRY` (more
   specific parsers before `GenericManifestParser`).
5. Add a fixture + ingestion test.

## Adding a registry crawler

1. Subclass `clean_skill.crawler.base.RegistryCrawler`.
2. Paginate safely (size caps, timeouts, backoff).
3. Return `CrawlItem` instances + an opaque `new_cursor`.
4. Add an integration test that stubs the registry endpoint.

## Code style

- `ruff` + `mypy --strict` are required to pass.
- Prefer Pydantic models at module boundaries; dataclasses internally.
- No `assert` in production code paths (use explicit exceptions).
- All new public functions have docstrings that explain the "why."

## Community

- Discussions: GitHub Discussions tab.
- Security issues: see [`SECURITY.md`](./SECURITY.md). Report privately via
  GitHub Security Advisories — do **not** file a public issue for unpatched
  vulnerabilities.

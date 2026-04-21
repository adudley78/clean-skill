# clean-skill Rule Format

clean-skill rules are YAML documents. One file = one rule. The format is
inspired by [Sigma](https://github.com/SigmaHQ/sigma) but tuned for AI skill
content (prose + code + manifest) instead of log events.

## Schema

```yaml
id: CS-<CATEGORY>-<NNN>          # required, globally unique
name: Short human-readable title  # required
description: |                    # required, multi-line OK
  Why this pattern is suspicious and what a true positive looks like.
category: instruction_override    # required, see Category enum
severity: high                    # required: info|low|medium|high|critical
author: clean-skill               # required
version: 1                        # required, bumps on logic change
references:                       # optional
  - https://owasp.org/www-project-top-10-for-large-language-model-applications/
platforms: [all]                  # optional; default [all]; or [claude, mcp, ...]
scope:                            # optional; default [text]
  - text        # concatenated content of all non-binary files
  - manifest    # raw_manifest dict rendered as JSON
  - filenames   # bundle file paths
patterns:                         # required, at least one entry
  - type: regex
    expression: '(?i)ignore\s+(all\s+)?previous\s+instructions'
  - type: keyword
    value: 'disregard prior'
  - type: regex
    expression: '[A-Za-z0-9+/]{80,}={0,2}'
    decode: base64                # decoded bytes are re-scanned with nested patterns
    nested:
      - type: regex
        expression: '(?i)api[_-]?key'
condition: any                    # any | all ; default any
min_matches: 1                    # optional; default 1
exclude:                          # optional; matcher wins only if NONE match
  - type: keyword
    value: 'example: ignore previous instructions'
```

## Pattern types

| type    | fields              | behavior                                               |
|---------|---------------------|--------------------------------------------------------|
| regex   | expression, flags?  | Python `re` search; flags are `i`, `m`, `s`.           |
| keyword | value, case?        | Substring search (case-insensitive by default).        |
| regex   | expression, decode  | As above but decoded bytes are scanned by `nested`.    |

## Condition language

`condition` is currently `any` or `all`. Named-pattern boolean expressions
(Sigma-style `sel_a and sel_b`) are on the roadmap; see
[ROADMAP.md](./ROADMAP.md).

## Submitting a rule

1. Place the YAML file under `rules/<category>/<slug>.yml`.
2. Add a minimal fixture under `tests/fixtures/skills/` that triggers it.
3. Run `pytest tests/unit/test_rules.py`.
4. Open a PR; a maintainer will review for false-positive risk.

# Security Policy

clean-skill is a security tool. We take vulnerabilities in it — and in the
skills it scans — seriously.

## Supported versions

clean-skill is currently on its first minor release. Only the `main` branch
and the most recent `v0.x` tag receive security fixes.

| Version        | Supported |
|----------------|:---------:|
| `main`         | ✅        |
| latest `v0.x`  | ✅        |
| anything older | ❌        |

## Reporting a vulnerability

**Please report privately via GitHub Security Advisories.**

Open a private report here:
<https://github.com/adudley78/clean-skill/security/advisories/new>

That channel notifies the maintainer directly, keeps the report out of the
public issue tracker until a fix ships, and lets us collaborate on a patch
inside a private fork. It is the preferred channel for:

- Sandbox escape or container breakout in the dynamic analyzer.
- Rule bypasses that cause malicious skills to verdict as `clean`.
- Prompt-injection attacks that compromise the LLM-as-judge layer.
- Any RCE, SSRF, or path-traversal in the CLI, API, or crawler.
- Secrets that landed in the repository despite push protection.

### What to include

1. A minimal reproducer: a skill bundle (or a diff of an existing fixture)
   plus the command you ran.
2. The expected verdict vs. what clean-skill actually returned.
3. Environment: clean-skill version, Python version, OS, Docker runtime
   (`runsc` / `runc`).
4. Your assessment of severity and, if applicable, a suggested CVSS vector.

### What happens next

- **Within 72 hours:** acknowledgement of receipt.
- **Within 7 days:** initial triage with a proposed severity and timeline.
- **Fix window:** targeting 30 days for high/critical issues and 90 days for
  medium/low. Complex sandbox-escape issues may require coordinated
  disclosure with the container runtime vendor.
- **Disclosure:** a CVE is requested for any issue rated medium or higher.
  The advisory is published after a fix is available; credit is given to
  the reporter unless anonymity is requested.

## What is *not* a clean-skill vulnerability

To keep the signal-to-noise ratio useful for everyone:

- **A novel malicious skill that evades our rules.** Please file it as a
  [public issue](https://github.com/adudley78/clean-skill/issues) with a
  reproducer fixture under `tests/fixtures/skills/` and, if possible, a
  proposed rule. This is a coverage gap, not a product vulnerability.
- **Vulnerabilities in skills we scan.** Those are the vendor's to fix.
  clean-skill's job is to *detect* them; we don't handle third-party
  disclosure.
- **Bugs in upstream dependencies** (Docker, gVisor, FastAPI, etc.).
  Report those to the upstream project. If the bug materially weakens
  clean-skill, tell us so we can ship a mitigation.

## Threat model

Our threat model — what clean-skill is and is not designed to defend against
— is documented in [`THREAT_MODEL.md`](./THREAT_MODEL.md). Please skim it
before filing; many "how do I bypass rule X?" questions are answered there.

## Safe harbor

Good-faith security research conducted against your own installation of
clean-skill, in compliance with this policy, will not result in legal
action from the maintainer. Please:

- Do not access data that isn't yours.
- Do not run tests against third-party skill marketplaces beyond what their
  own terms of service allow.
- Give us a reasonable window to fix before public disclosure.

Thanks for helping make the AI skills ecosystem safer.

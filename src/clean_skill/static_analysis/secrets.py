"""Secret / API-key detection.

Uses a deliberately small set of high-precision regexes for the common key
formats. For broader coverage, users can run ``detect-secrets`` against the
unpacked skill directory; this module exists so the default ``clean-skill
scan`` works offline with zero extra tooling.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

_SIGNATURES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws_secret_access_key", re.compile(r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]")),
    ("github_pat", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("github_oauth", re.compile(r"\bgho_[A-Za-z0-9]{36}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("stripe_live_key", re.compile(r"\bsk_live_[A-Za-z0-9]{20,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("openai_api_key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("anthropic_api_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{80,}\b")),
    ("private_key_pem", re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")),
)


@dataclass(frozen=True)
class SecretHit:
    kind: str
    match: str
    span: tuple[int, int]


def scan(text: str) -> Iterable[SecretHit]:
    """Yield :class:`SecretHit` for every secret-like pattern in ``text``."""
    for kind, pattern in _SIGNATURES:
        for m in pattern.finditer(text):
            yield SecretHit(kind=kind, match=m.group(0), span=m.span())

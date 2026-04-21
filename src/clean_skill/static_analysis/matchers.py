"""Low-level string matchers used by the rule engine.

Kept separate from :mod:`engine` so custom rule runners (e.g. a future YARA
bridge) can reuse the same primitives.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass

from .rule import Pattern


@dataclass(frozen=True)
class Match:
    """A single successful match produced by a :class:`~.rule.Pattern`."""

    pattern_index: int
    span: tuple[int, int]
    snippet: str
    decoded: str | None = None


def _compile_flags(flags: str) -> int:
    bits = 0
    mapping = {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL}
    for ch in flags.lower():
        bits |= mapping.get(ch, 0)
    return bits


def _snippet(text: str, span: tuple[int, int], pad: int = 40) -> str:
    start = max(0, span[0] - pad)
    end = min(len(text), span[1] + pad)
    return text[start:end].replace("\n", "\\n")


def match_pattern(pattern: Pattern, text: str, index: int = 0) -> list[Match]:
    """Return every match of ``pattern`` inside ``text``.

    Recurses into ``nested`` patterns for base64-decode rules.
    """
    matches: list[Match] = []

    if pattern.type == "regex":
        if pattern.expression is None:
            return matches
        compiled = re.compile(pattern.expression, _compile_flags(pattern.flags))
        for m in compiled.finditer(text):
            if pattern.decode == "base64":
                try:
                    decoded_bytes = base64.b64decode(m.group(0), validate=True)
                    decoded = decoded_bytes.decode("utf-8", errors="replace")
                except (binascii.Error, ValueError):
                    continue
                nested_hit = any(
                    match_pattern(np, decoded, i)
                    for i, np in enumerate(pattern.nested)
                )
                if not pattern.nested or nested_hit:
                    matches.append(
                        Match(index, m.span(), _snippet(text, m.span()), decoded[:200])
                    )
            else:
                matches.append(Match(index, m.span(), _snippet(text, m.span())))

    elif pattern.type == "keyword":
        if pattern.value is None:
            return matches
        needle = pattern.value if pattern.case else pattern.value.lower()
        haystack = text if pattern.case else text.lower()
        start = 0
        while True:
            pos = haystack.find(needle, start)
            if pos < 0:
                break
            span = (pos, pos + len(needle))
            matches.append(Match(index, span, _snippet(text, span)))
            start = pos + len(needle)

    return matches

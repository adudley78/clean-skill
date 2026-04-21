"""Skill ingestion: platform-specific parsers that produce a normalized ``Skill``.

Public API:

    >>> from clean_skill.ingestion import parse
    >>> skill = parse("path/to/skill/dir")
    >>> skill.platform
    <Platform.CLAUDE: 'claude'>
"""

from __future__ import annotations

from pathlib import Path

from ..models import Skill
from .autogpt import AutoGPTParser
from .base import SkillParser
from .claude import ClaudeSkillParser
from .generic import GenericManifestParser
from .langchain import LangChainParser
from .mcp import MCPParser
from .openai_gpt import OpenAIGPTParser
from .openclaw import OpenClawParser

# Order matters: more specific parsers first so generic is the fallback.
_REGISTRY: tuple[type[SkillParser], ...] = (
    ClaudeSkillParser,
    MCPParser,
    OpenAIGPTParser,
    LangChainParser,
    AutoGPTParser,
    OpenClawParser,
    GenericManifestParser,
)


def parse(source: str | Path) -> Skill:
    """Parse a skill bundle from a local path.

    ``source`` may be either a directory or a single manifest file. The first
    parser whose ``detect`` returns True wins. A ``ValueError`` is raised when
    no parser claims the input.
    """
    path = Path(source)
    if not path.exists():
        raise FileNotFoundError(f"skill source not found: {source}")

    for parser_cls in _REGISTRY:
        parser = parser_cls()
        if parser.detect(path):
            return parser.parse(path)

    raise ValueError(f"no parser matched {source!r}; try converting to a generic manifest")


__all__ = [
    "AutoGPTParser",
    "ClaudeSkillParser",
    "GenericManifestParser",
    "LangChainParser",
    "MCPParser",
    "OpenAIGPTParser",
    "OpenClawParser",
    "SkillParser",
    "parse",
]

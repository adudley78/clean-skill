"""Adapter for the MCP public registry.

Polls the registry's ``/v1/servers`` endpoint and yields every server whose
``updated_at`` is newer than the stored cursor. The exact JSON shape is
subject to change as the MCP registry evolves; treat this as a scaffold.
"""

from __future__ import annotations

from collections.abc import Iterable

import httpx

from ..base import CrawlItem, RegistryCrawler

_DEFAULT_ENDPOINT = "https://registry.modelcontextprotocol.io/v1/servers"


class MCPRegistryCrawler(RegistryCrawler):
    name = "mcp"

    def __init__(self, endpoint: str = _DEFAULT_ENDPOINT) -> None:
        self._endpoint = endpoint

    def poll(self, since_cursor: str | None) -> tuple[Iterable[CrawlItem], str]:
        params = {"since": since_cursor} if since_cursor else {}
        with httpx.Client(timeout=30.0) as client:
            resp = client.get(self._endpoint, params=params)
            resp.raise_for_status()
            data = resp.json()

        items: list[CrawlItem] = []
        newest_cursor = since_cursor or ""
        for server in data.get("servers", []):
            slug = server.get("name", "")
            version = str(server.get("version", ""))
            url = server.get("package", {}).get("url") or server.get("repository_url", "")
            if not slug or not url:
                continue
            items.append(
                CrawlItem(registry=self.name, slug=slug, version=version, download_url=url)
            )
            updated = server.get("updated_at", "")
            if updated > newest_cursor:
                newest_cursor = updated
        return items, newest_cursor

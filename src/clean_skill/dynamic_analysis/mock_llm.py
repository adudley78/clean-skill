"""In-process mock LLM used inside the sandbox.

The sandbox image ships this module as ``/opt/clean-skill/mock_llm.py`` and
binds port 8088. It responds deterministically to chat completion requests
so skills that depend on an LLM actually execute (and therefore reveal
network / filesystem behavior) without needing real model credentials.

Design notes:
* Responses are canned. We do NOT route to a real model — that would leak
  untrusted skill content off-box.
* Every request is logged to ``/var/log/cleanskill/audit.jsonl`` so the
  host can reconstruct which tool calls the skill tried to make.
* The server is single-threaded on purpose; skills that flood the mock
  LLM show up as abnormal behavior in the trace.
"""

from __future__ import annotations

import json
import logging
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

LOG_PATH = Path("/var/log/cleanskill/audit.jsonl")
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

logger = logging.getLogger("clean_skill.mock_llm")


def _log_event(event: dict[str, Any]) -> None:
    with LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


_CANNED = {
    "id": "chatcmpl-cleanskill-mock",
    "object": "chat.completion",
    "model": "clean-skill-mock-1",
    "choices": [
        {
            "index": 0,
            "finish_reason": "stop",
            "message": {
                "role": "assistant",
                "content": "OK",
            },
        }
    ],
    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
}


class _Handler(BaseHTTPRequestHandler):
    def _read_body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"_raw": raw.decode("utf-8", errors="replace")}

    def do_POST(self) -> None:
        body = self._read_body()
        _log_event({"kind": "tool_call", "path": self.path, "body_preview": str(body)[:400]})
        payload = json.dumps(_CANNED).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        _log_event({"kind": "tool_call", "path": self.path, "method": "GET"})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')

    def log_message(self, format: str, *args: Any) -> None:  # silence default stderr
        pass


def main(port: int | None = None) -> None:
    port = port or int(os.environ.get("MOCK_LLM_PORT", "8088"))
    server = HTTPServer(("127.0.0.1", port), _Handler)
    logger.info("mock LLM listening on 127.0.0.1:%d", port)
    server.serve_forever()


if __name__ == "__main__":  # pragma: no cover
    main()

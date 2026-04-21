"""FastAPI app exposing clean-skill as a network service.

Authentication: single bearer token from ``CLEAN_SKILL_API_TOKEN`` (suitable
for private deployments). Multi-tenant auth is out of scope for v0.1 and
should be layered on via a reverse proxy.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, UploadFile, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from ..config import get_settings
from ..dynamic_analysis import DynamicAnalyzer
from ..ingestion import parse as parse_skill
from ..models import ScanReport
from ..static_analysis import StaticAnalyzer
from ..verdict import aggregate

app = FastAPI(
    title="clean-skill API",
    version="0.1.0",
    description="Scan AI skills for prompt injection, exfiltration, and sandbox escapes.",
)

_security = HTTPBearer(auto_error=False)


def _require_token(
    creds: HTTPAuthorizationCredentials | None = Depends(_security),
) -> None:
    expected = get_settings().api_token
    if not expected:
        return  # auth disabled in dev
    if creds is None or creds.credentials != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid or missing token"
        )


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/scan", response_model=ScanReport, dependencies=[Depends(_require_token)])
async def scan_upload(
    file: UploadFile,
    static_only: bool = False,
) -> ScanReport:
    """Scan an uploaded skill tarball or single manifest file."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=Path(file.filename or "").suffix) as tmp:
        tmp.write(await file.read())
        path = Path(tmp.name)

    try:
        skill = parse_skill(path)
    except (FileNotFoundError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    findings = StaticAnalyzer().analyze(skill)
    trace = None
    if not static_only:
        trace, dyn = DynamicAnalyzer().analyze(skill)
        findings.extend(dyn)

    verdict, score = aggregate(findings)
    return ScanReport(
        skill=skill, findings=findings, trace=trace, verdict=verdict, score=score
    )

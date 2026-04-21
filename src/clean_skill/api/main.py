"""FastAPI app exposing clean-skill as a network service.

Authentication: single bearer token from ``CLEAN_SKILL_API_TOKEN`` (suitable
for private deployments). Multi-tenant auth is out of scope for v0.1 and
should be layered on via a reverse proxy.
"""

from __future__ import annotations

import logging
import tempfile
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, UploadFile, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from ..config import get_settings
from ..db import run_migrations
from ..jobs.queues import HIGH_QUEUE_NAME, default_retry, get_queue
from ..jobs.scan_skill import scan_skill_job

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    run_migrations()
    yield


app = FastAPI(
    title="clean-skill API",
    version="0.1.0",
    description="Scan AI skills for prompt injection, exfiltration, and sandbox escapes.",
    lifespan=lifespan,
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


@app.post(
    "/v1/scan",
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(_require_token)],
)
async def scan_upload(file: UploadFile, static_only: bool = False) -> JSONResponse:
    """Accept an uploaded skill and enqueue it for background scanning.

    The request returns immediately with a job id; use GET
    ``/v1/scan/{job_id}`` to poll for completion.

    NOTE (v0.1 limitation): the uploaded bundle is written to a local
    temp directory. In a multi-host deployment the worker must share
    that filesystem (shared volume, NFS). Future work is to upload the
    bundle to blob storage and pass a URL through the queue.
    """
    suffix = Path(file.filename or "").suffix
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(await file.read())
        path = Path(tmp.name)

    queue = get_queue(HIGH_QUEUE_NAME)
    job = queue.enqueue(
        scan_skill_job,
        str(path),
        dynamic=not static_only,
        enqueued_by="api",
        retry=default_retry(),
    )

    return JSONResponse(
        status_code=status.HTTP_202_ACCEPTED,
        content={"job_id": job.id, "status": "queued", "queue": HIGH_QUEUE_NAME},
    )


@app.get("/v1/scan/{job_id}", dependencies=[Depends(_require_token)])
def scan_status(job_id: str) -> dict[str, Any]:
    """Return the current status (and result, when finished) of a scan job."""
    from rq.exceptions import NoSuchJobError
    from rq.job import Job

    try:
        job = Job.fetch(job_id, connection=get_queue(HIGH_QUEUE_NAME).connection)
    except NoSuchJobError as exc:
        raise HTTPException(status_code=404, detail=f"unknown job id {job_id!r}") from exc

    payload: dict[str, Any] = {
        "job_id": job.id,
        "status": job.get_status(),
        "queue": job.origin,
        "enqueued_at": job.enqueued_at.isoformat() if job.enqueued_at else None,
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "ended_at": job.ended_at.isoformat() if job.ended_at else None,
    }
    if job.is_finished:
        payload["result"] = job.result
    elif job.is_failed:
        payload["error"] = job.exc_info
    return payload

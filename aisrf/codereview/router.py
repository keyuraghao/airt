"""REST API for the code review module (prefix /api/codereview)."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, Response, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sse_starlette.sse import EventSourceResponse

from ..audit import service as audit
from ..auth import Principal, current_principal, require_role
from ..db import get_session
from ..logging import broadcaster
from ..models import CodeReviewStatus
from . import intake, service
from .config import ENGINES, PACKS, get_config
from .engine import CHANNEL, codereview_runner, normalize_options
from .intake import IntakeError
from .report import build_codereview_sarif
from .rules import catalogue
from .secrets import redact_mapping

router = APIRouter(prefix="/api/codereview", tags=["codereview"])


class SourceIn(BaseModel):
    type: str = Field(description="git | url | zip | path | snippet")
    url: str | None = None
    ref: str | None = None
    token: str | None = None
    credential_id: str | None = None
    username: str | None = None
    provider: str | None = None
    ssh_key_path: str | None = None
    path: str | None = None
    code: str | None = None
    language: str | None = None


class OptionsIn(BaseModel):
    packs: list[str] = Field(default_factory=list)
    engines: list[str] = Field(default_factory=list)
    include: list[str] = Field(default_factory=list)
    exclude: list[str] = Field(default_factory=list)
    max_files: int | None = None


class RunIn(BaseModel):
    name: str = ""
    source: SourceIn
    options: OptionsIn = Field(default_factory=OptionsIn)


class StatusIn(BaseModel):
    status: str
    note: str = ""


class CredentialIn(BaseModel):
    label: str = Field(min_length=1, max_length=80)
    provider: str = "github"
    token: str = Field(min_length=4)
    username: str = ""


def _validate_options(options: OptionsIn) -> None:
    bad_packs = [p for p in options.packs if p not in PACKS]
    bad_engines = [e for e in options.engines if e not in ENGINES]
    if bad_packs:
        raise HTTPException(400, f"unknown packs: {', '.join(bad_packs)}; known: {', '.join(PACKS)}")
    if bad_engines:
        raise HTTPException(400, f"unknown engines: {', '.join(bad_engines)}; known: {', '.join(ENGINES)}")


def _prepare_source(src: SourceIn, p: Principal) -> dict[str, Any]:
    """Validate the source and resolve stored credentials. Returns the in-memory source (may hold a token)."""
    kind = (src.type or "").lower().strip()
    if kind not in intake.SOURCE_TYPES:
        raise HTTPException(400, f"source.type must be one of {', '.join(intake.SOURCE_TYPES)}")
    if kind == "zip":
        raise HTTPException(400, "archives are uploaded with POST /api/codereview/runs/upload")
    raw: dict[str, Any] = {"type": kind}
    if kind == "path":
        if p.role != "admin":
            raise HTTPException(403, "local path intake is restricted to administrators")
        try:
            raw["path"] = str(intake.check_local_path(src.path or ""))
        except IntakeError as exc:
            raise HTTPException(403 if "outside" in str(exc) else 400, str(exc))
    elif kind == "snippet":
        if not (src.code or "").strip():
            raise HTTPException(400, "source.code is required for a snippet")
        raw["code"] = src.code
        raw["language"] = (src.language or "python").lower()
    else:
        url = (src.url or "").strip()
        if not url:
            raise HTTPException(400, "source.url is required")
        if kind == "url" and not url.lower().startswith(("http://", "https://")):
            raise HTTPException(400, "archive URL must use http or https")
        if kind == "git" and not (
            url.lower().startswith(("http://", "https://", "ssh://", "git://", "file://")) or "@" in url
        ):
            raise HTTPException(400, "git URL must be http(s), ssh, git or file")
        raw.update(
            {
                "url": url,
                "ref": (src.ref or "").strip() or None,
                "provider": src.provider,
                "username": src.username,
                "ssh_key_path": src.ssh_key_path,
            }
        )
        if src.credential_id:
            if p.role != "admin":
                raise HTTPException(403, "stored credentials can only be used by administrators")
            cred = service.resolve_credential(src.credential_id)
            if cred is None or not cred.get("token"):
                raise HTTPException(404, "credential not found")
            raw["token"] = cred["token"]
            raw["username"] = raw.get("username") or cred.get("username") or None
            raw["provider"] = raw.get("provider") or cred.get("provider")
            raw["credential_id"] = src.credential_id
        elif src.token:
            raw["token"] = src.token.strip()
        if raw.get("ssh_key_path") and p.role != "admin":
            raise HTTPException(403, "ssh deploy keys can only be used by administrators")
    return raw


async def _run_or_404(session: AsyncSession, run_id: str) -> Any:
    run = await service.get_run(session, run_id)
    if run is None:
        raise HTTPException(404, "run not found")
    return run


# --- catalogue ---------------------------------------------------------------------------------
@router.get("/rules")
async def list_rules(pack: str | None = None, _: Principal = Depends(current_principal)) -> dict[str, Any]:
    cat = catalogue()
    if pack:
        cat["packs"] = [p for p in cat["packs"] if p["name"] == pack]
    cfg = get_config()
    cat["config"] = {k: v for k, v in cfg.items() if k != "credentials"}
    cat["config"]["llm_review"] = dict(cfg.get("llm_review") or {})
    return cat


# --- runs ----------------------------------------------------------------------------------------
@router.post("/runs", status_code=201)
async def create_run(
    payload: RunIn,
    p: Principal = Depends(require_role("reviewer")),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    _validate_options(payload.options)
    raw = _prepare_source(payload.source, p)
    run = await codereview_runner.create_run(
        session, name=payload.name, source=raw, options=payload.options.model_dump(), created_by=p.username
    )
    await audit.record(
        session,
        p.username,
        "codereview.run.create",
        "codereview_run",
        run.id,
        redact_mapping(
            {
                "source": {k: v for k, v in raw.items() if k != "code"},
                "options": normalize_options(payload.options.model_dump(), get_config()),
            }
        ),
    )
    await session.commit()
    await codereview_runner.start(run.id, raw)
    run = await _run_or_404(session, run.id)
    return service.run_to_dict(run)


@router.post("/runs/upload", status_code=201)
async def upload_run(
    file: UploadFile = File(...),
    name: str = Form(""),
    options: str = Form("{}"),
    p: Principal = Depends(require_role("reviewer")),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    try:
        opts = OptionsIn.model_validate(json.loads(options or "{}"))
    except (ValueError, TypeError) as exc:
        raise HTTPException(400, f"options must be a JSON object: {exc}")
    _validate_options(opts)
    cfg = get_config()
    limit = int(cfg.get("max_archive_bytes") or 0)
    filename = Path(file.filename or "upload.zip").name
    raw: dict[str, Any] = {"type": "zip", "filename": filename}
    run = await codereview_runner.create_run(
        session, name=name or filename, source=raw, options=opts.model_dump(), created_by=p.username
    )
    work_dir = intake.prepare_workdir(run.id)
    archive = work_dir / "upload.archive"
    size = 0
    with archive.open("wb") as out:
        while chunk := await file.read(1024 * 1024):
            size += len(chunk)
            if limit and size > limit:
                out.close()
                intake.remove_workdir(work_dir)
                await session.rollback()
                raise HTTPException(413, f"archive exceeds the {limit} byte limit")
            out.write(chunk)
    try:
        info = await asyncio.to_thread(intake.inspect_archive, archive, cfg)
    except IntakeError as exc:
        intake.remove_workdir(work_dir)
        await session.rollback()
        raise HTTPException(400, f"archive rejected: {exc}")
    raw["archive_path"] = str(archive)
    run.work_dir = str(work_dir)
    run.config = {**(run.config or {}), "upload": {"filename": filename, "bytes": size, **info}}
    await audit.record(
        session,
        p.username,
        "codereview.run.create",
        "codereview_run",
        run.id,
        {"source": {"type": "zip", "filename": filename, "bytes": size}, "options": run.config.get("packs")},
    )
    await session.commit()
    await codereview_runner.start(run.id, raw)
    run = await _run_or_404(session, run.id)
    return service.run_to_dict(run)


@router.get("/runs")
async def list_runs(
    status: str | None = None,
    source_type: str | None = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    _: Principal = Depends(current_principal),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    rows, total = await service.list_runs(
        session, status=status, source_type=source_type, limit=limit, offset=offset
    )
    return {
        "items": [service.run_to_dict(r, brief=True) for r in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/runs/{run_id}")
async def get_run(
    run_id: str, _: Principal = Depends(current_principal), session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    run = await _run_or_404(session, run_id)
    d = service.run_to_dict(run)
    d["running"] = codereview_runner.is_running(run_id)
    return d


@router.post("/runs/{run_id}/cancel")
async def cancel_run(
    run_id: str,
    p: Principal = Depends(require_role("reviewer")),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    run = await _run_or_404(session, run_id)
    if run.status in (
        CodeReviewStatus.COMPLETED.value,
        CodeReviewStatus.FAILED.value,
        CodeReviewStatus.CANCELLED.value,
    ):
        raise HTTPException(409, f"run is already {run.status}")
    await codereview_runner.cancel(run_id)
    await audit.record(session, p.username, "codereview.run.cancel", "codereview_run", run_id)
    await session.commit()
    session.expire_all()
    return service.run_to_dict(await _run_or_404(session, run_id))


@router.delete("/runs/{run_id}")
async def delete_run(
    run_id: str,
    p: Principal = Depends(require_role("reviewer")),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    await _run_or_404(session, run_id)
    if codereview_runner.is_running(run_id):
        await codereview_runner.cancel(run_id)
        await codereview_runner.wait(run_id, timeout=10)
    session.expire_all()
    deleted = await service.delete_run(session, run_id)
    if not deleted:
        raise HTTPException(404, "run not found")
    await audit.record(session, p.username, "codereview.run.delete", "codereview_run", run_id)
    await session.commit()
    return {"deleted": run_id}


@router.get("/runs/{run_id}/findings")
async def list_findings(
    run_id: str,
    severity: str | None = None,
    pack: str | None = None,
    engine: str | None = None,
    file: str | None = None,
    status: str | None = None,
    rule_id: str | None = None,
    search: str | None = None,
    limit: int = Query(default=100, ge=1, le=2000),
    offset: int = Query(default=0, ge=0),
    _: Principal = Depends(current_principal),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    await _run_or_404(session, run_id)
    rows, total = await service.list_findings(
        session,
        run_id,
        severity=severity,
        pack=pack,
        engine=engine,
        file=file,
        status=status,
        rule_id=rule_id,
        search=search,
        limit=limit,
        offset=offset,
    )
    return {
        "items": [service.finding_to_dict(r) for r in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.post("/findings/{finding_id}/status")
async def set_finding_status(
    finding_id: str,
    payload: StatusIn,
    p: Principal = Depends(require_role("reviewer")),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    finding = await service.get_finding(session, finding_id)
    if finding is None:
        raise HTTPException(404, "finding not found")
    try:
        finding = await service.set_finding_status(session, finding, payload.status, payload.note, p.username)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    await audit.record(
        session,
        p.username,
        "codereview.finding.status",
        "codereview_finding",
        finding.id,
        {
            "run_id": finding.run_id,
            "rule_id": finding.rule_id,
            "status": payload.status,
            "note": payload.note[:200],
        },
    )
    await session.commit()
    return service.finding_to_dict(finding)


@router.get("/runs/{run_id}/file")
async def get_run_file(
    run_id: str,
    path: str = Query(min_length=1),
    _: Principal = Depends(current_principal),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    run = await _run_or_404(session, run_id)
    if not run.work_dir or not Path(run.work_dir, "src").is_dir():
        raise HTTPException(410, "the source tree of this run has been cleaned up")
    doc = service.read_run_file(run, path)
    if doc is None:
        raise HTTPException(404, "file not found in this run")
    doc["findings"] = [
        service.finding_to_dict(f) for f in await service.findings_for_file(session, run_id, path)
    ]
    return doc


@router.get("/runs/{run_id}/sarif")
async def run_sarif(
    run_id: str,
    include_dismissed: bool = False,
    _: Principal = Depends(current_principal),
    session: AsyncSession = Depends(get_session),
) -> Response:
    await _run_or_404(session, run_id)
    payload = await build_codereview_sarif(session, run_id, include_dismissed=include_dismissed)
    return Response(
        content=payload,
        media_type="application/sarif+json",
        headers={"Content-Disposition": f'attachment; filename="aisrf-codereview-{run_id}.sarif"'},
    )


# --- credentials (admin) ----------------------------------------------------------------------------
@router.get("/credentials")
async def list_credentials(_: Principal = Depends(require_role("admin"))) -> list[dict[str, Any]]:
    return service.list_credentials()


@router.post("/credentials", status_code=201)
async def add_credential(
    payload: CredentialIn,
    p: Principal = Depends(require_role("admin")),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    try:
        cred = await service.add_credential(
            session, payload.label, payload.provider, payload.token, p.username, payload.username
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    await audit.record(
        session,
        p.username,
        "codereview.credential.create",
        "codereview_credential",
        cred["id"],
        {"label": cred["label"], "provider": cred["provider"]},
    )
    await session.commit()
    return cred


@router.delete("/credentials/{credential_id}")
async def delete_credential(
    credential_id: str,
    p: Principal = Depends(require_role("admin")),
    session: AsyncSession = Depends(get_session),
) -> dict[str, str]:
    if not await service.delete_credential(session, credential_id, p.username):
        raise HTTPException(404, "credential not found")
    await audit.record(
        session, p.username, "codereview.credential.delete", "codereview_credential", credential_id
    )
    await session.commit()
    return {"deleted": credential_id}


# --- live stream ---------------------------------------------------------------------------------------
async def _stream(request: Request, replay: int, run_id: str | None):
    q = broadcaster.subscribe(CHANNEL, replay=replay)
    try:
        while True:
            if await request.is_disconnected():
                break
            try:
                item = await asyncio.wait_for(q.get(), timeout=15)
            except TimeoutError:
                yield {"event": "ping", "data": "{}"}
                continue
            if run_id and item.get("run_id") != run_id:
                continue
            yield {"event": item.get("event", CHANNEL), "data": json.dumps(item, default=str)}
    finally:
        broadcaster.unsubscribe(CHANNEL, q)


@router.get("/stream")
async def stream(
    request: Request, replay: int = 20, run_id: str | None = None, _: Principal = Depends(current_principal)
):
    return EventSourceResponse(_stream(request, replay, run_id))

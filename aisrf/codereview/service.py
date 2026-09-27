"""Queries, serialisation, summaries and credential storage for code review runs."""

from __future__ import annotations

import os
import re
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import delete, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..analysis.base import level_for_score
from ..logging import broadcaster, get_logger
from ..models import CodeReviewFinding, CodeReviewRun, utcnow
from ..security import decrypt_secret, encrypt_secret
from ..settings_store import get_namespace, update_namespace
from ..taxonomy import OWASP_LLM_TOP10, owasp_label
from .config import NAMESPACE
from .findings import SEVERITIES, Finding, risk_score
from .intake import remove_workdir
from .inventory import language_of
from .rules import RULES_BY_ID

log = get_logger("aisrf.codereview.service")
FINDING_STATUSES = ("open", "false_positive", "likely_false_positive", "accepted")
MAX_FILE_VIEW_BYTES = 512 * 1024


def _ts(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


# --- serialisation ---------------------------------------------------------------------------
def run_to_dict(run: CodeReviewRun, brief: bool = False) -> dict[str, Any]:
    d: dict[str, Any] = {
        "id": run.id,
        "name": run.name,
        "source_type": run.source_type,
        "source_ref": run.source_ref,
        "status": run.status,
        "stage": run.stage or "",
        "created_by": run.created_by,
        "created_at": _ts(run.created_at),
        "started_at": _ts(run.started_at),
        "finished_at": _ts(run.finished_at),
        "error": run.error or "",
        "file_count": run.file_count,
        "loc": run.loc,
        "finding_count": run.finding_count,
        "summary": run.summary or {},
        "config": run.config or {},
    }
    if not brief:
        d["inventory"] = run.inventory or {}
        d["work_dir_available"] = bool(run.work_dir and Path(run.work_dir, "src").is_dir())
    return d


def finding_to_dict(f: CodeReviewFinding) -> dict[str, Any]:
    rule = RULES_BY_ID.get(f.rule_id)
    return {
        "id": f.id,
        "run_id": f.run_id,
        "rule_id": f.rule_id,
        "pack": f.pack,
        "engine": f.engine,
        "severity": f.severity,
        "confidence": round(float(f.confidence or 0), 3),
        "title": f.title,
        "description": f.description,
        "why": rule.why if rule else "",
        "remediation": f.remediation,
        "file": f.file,
        "line_start": f.line_start,
        "line_end": f.line_end,
        "snippet": f.snippet,
        "language": f.language,
        "owasp": list(f.owasp or []),
        "owasp_labels": [owasp_label(o) for o in (f.owasp or [])],
        "category": rule.category if rule else "",
        "cwe": f.cwe,
        "cwe_url": f"https://cwe.mitre.org/data/definitions/{f.cwe.split('-')[-1]}.html" if f.cwe else "",
        "fingerprint": f.fingerprint,
        "status": f.status,
        "reviewer_note": f.reviewer_note or "",
        "reviewed_by": f.reviewed_by or "",
        "ts": _ts(f.ts),
        "references": (rule.to_dict()["references"] if rule else []),
        "metadata": dict(f.meta or {}),
    }


def finding_row(run_id: str, f: Finding) -> CodeReviewFinding:
    return CodeReviewFinding(
        run_id=run_id,
        rule_id=f.rule_id,
        pack=f.pack,
        engine=f.engine,
        severity=f.severity,
        confidence=f.confidence,
        title=f.title[:200],
        description=(f.description + (f"\n\nNote: {f.metadata['note']}" if f.metadata.get("note") else ""))[:8000],
        remediation=f.remediation[:8000],
        file=f.file[:500],
        line_start=f.line_start,
        line_end=f.line_end,
        snippet=f.snippet,
        language=f.language,
        owasp=list(f.owasp),
        cwe=f.cwe,
        fingerprint=f.fingerprint,
        status=f.status if f.status in FINDING_STATUSES else "open",
        meta={k: v for k, v in (f.metadata or {}).items() if k != "note"},
    )


# --- summaries --------------------------------------------------------------------------------
def compute_summary(findings: list[dict[str, Any]], engines: dict[str, Any] | None = None, duration_s: float | None = None) -> dict[str, Any]:
    by_sev = dict.fromkeys(SEVERITIES, 0)
    by_pack: dict[str, int] = {}
    by_engine: dict[str, int] = {}
    by_owasp: dict[str, int] = {}
    by_status: dict[str, int] = dict.fromkeys(FINDING_STATUSES, 0)
    rules: dict[str, dict[str, Any]] = {}
    files: dict[str, dict[str, Any]] = {}
    open_findings: list[dict[str, Any]] = []
    for f in findings:
        status = str(f.get("status") or "open")
        by_status[status] = by_status.get(status, 0) + 1
        if status != "open":
            continue
        open_findings.append(f)
        sev = str(f.get("severity") or "MEDIUM").upper()
        by_sev[sev] = by_sev.get(sev, 0) + 1
        by_pack[str(f.get("pack"))] = by_pack.get(str(f.get("pack")), 0) + 1
        by_engine[str(f.get("engine"))] = by_engine.get(str(f.get("engine")), 0) + 1
        for o in f.get("owasp") or []:
            by_owasp[o] = by_owasp.get(o, 0) + 1
        r = rules.setdefault(str(f.get("rule_id")), {"rule_id": f.get("rule_id"), "title": f.get("title"), "severity": sev, "count": 0})
        r["count"] += 1
        path = str(f.get("file") or "")
        if path:
            entry = files.setdefault(path, {"file": path, "count": 0, "max_severity": "INFO"})
            entry["count"] += 1
            if SEVERITIES.index(sev) < SEVERITIES.index(entry["max_severity"]):
                entry["max_severity"] = sev
    score = risk_score(open_findings)
    owasp_rows = {oid: {"name": OWASP_LLM_TOP10[oid]["name"], "count": by_owasp.get(oid, 0)} for oid in OWASP_LLM_TOP10}
    return {
        "total": len(findings),
        "open": len(open_findings),
        "by_severity": by_sev,
        "by_pack": dict(sorted(by_pack.items(), key=lambda kv: -kv[1])),
        "by_engine": dict(sorted(by_engine.items(), key=lambda kv: -kv[1])),
        "by_owasp": owasp_rows,
        "by_status": by_status,
        "risk_score": score,
        "risk_level": level_for_score(score),
        "top_rules": sorted(rules.values(), key=lambda r: (-r["count"], SEVERITIES.index(r["severity"]), r["rule_id"]))[:10],
        "top_files": sorted(files.values(), key=lambda r: (-r["count"], r["file"]))[:10],
        "engines": engines or {},
        "duration_seconds": duration_s,
        "computed_at": utcnow().isoformat(),
    }


# --- runs ---------------------------------------------------------------------------------------
async def get_run(session: AsyncSession, run_id: str) -> CodeReviewRun | None:
    return await session.get(CodeReviewRun, run_id)


async def list_runs(session: AsyncSession, status: str | None = None, source_type: str | None = None, limit: int = 50, offset: int = 0) -> tuple[list[CodeReviewRun], int]:
    q = select(CodeReviewRun)
    if status:
        q = q.where(CodeReviewRun.status == status.upper())
    if source_type:
        q = q.where(CodeReviewRun.source_type == source_type)
    total = int((await session.execute(select(func.count()).select_from(q.subquery()))).scalar_one())
    rows = list((await session.execute(q.order_by(CodeReviewRun.created_at.desc()).limit(limit).offset(offset))).scalars())
    return rows, total


async def delete_run(session: AsyncSession, run_id: str) -> bool:
    run = await session.get(CodeReviewRun, run_id)
    if run is None:
        return False
    work_dir = run.work_dir
    await session.execute(delete(CodeReviewFinding).where(CodeReviewFinding.run_id == run_id))
    await session.delete(run)
    await session.flush()
    remove_workdir(work_dir)
    broadcaster.publish("codereview", {"event": "run.deleted", "run_id": run_id})
    return True


async def refresh_summary(session: AsyncSession, run_id: str) -> dict[str, Any]:
    run = await session.get(CodeReviewRun, run_id)
    if run is None:
        return {}
    rows = list((await session.execute(select(CodeReviewFinding).where(CodeReviewFinding.run_id == run_id))).scalars())
    old = run.summary or {}
    run.summary = compute_summary([finding_to_dict(r) for r in rows], old.get("engines"), old.get("duration_seconds"))
    run.finding_count = len(rows)
    await session.flush()
    return run.summary


# --- findings -----------------------------------------------------------------------------------
async def list_findings(
    session: AsyncSession,
    run_id: str,
    *,
    severity: str | list[str] | None = None,
    pack: str | None = None,
    engine: str | None = None,
    file: str | None = None,
    status: str | None = None,
    rule_id: str | None = None,
    search: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[CodeReviewFinding], int]:
    q = select(CodeReviewFinding).where(CodeReviewFinding.run_id == run_id)
    if severity:
        sevs = [s.strip().upper() for s in (severity.split(",") if isinstance(severity, str) else severity) if s.strip()]
        if sevs:
            q = q.where(CodeReviewFinding.severity.in_(sevs))
    if pack:
        q = q.where(CodeReviewFinding.pack == pack)
    if engine:
        q = q.where(CodeReviewFinding.engine == engine)
    if file:
        q = q.where(or_(CodeReviewFinding.file == file, CodeReviewFinding.file.like(f"{file}%")))
    if status:
        statuses = [x.strip() for x in (status.split(",") if isinstance(status, str) else status) if x.strip()]
        if statuses:
            q = q.where(CodeReviewFinding.status.in_(statuses))
    if rule_id:
        q = q.where(CodeReviewFinding.rule_id == rule_id)
    if search:
        like = f"%{search}%"
        q = q.where(or_(CodeReviewFinding.title.ilike(like), CodeReviewFinding.file.ilike(like), CodeReviewFinding.rule_id.ilike(like), CodeReviewFinding.snippet.ilike(like)))
    total = int((await session.execute(select(func.count()).select_from(q.subquery()))).scalar_one())
    sev_order = {s: i for i, s in enumerate(SEVERITIES)}
    rows = list((await session.execute(q.limit(5000))).scalars())
    rows.sort(key=lambda f: (sev_order.get(f.severity, 9), -float(f.confidence or 0), f.file, f.line_start))
    return rows[offset : offset + limit], total


async def findings_for_file(session: AsyncSession, run_id: str, path: str) -> list[CodeReviewFinding]:
    rows = list((await session.execute(select(CodeReviewFinding).where(CodeReviewFinding.run_id == run_id, CodeReviewFinding.file == path))).scalars())
    rows.sort(key=lambda f: (f.line_start, f.rule_id))
    return rows


async def get_finding(session: AsyncSession, finding_id: str) -> CodeReviewFinding | None:
    return await session.get(CodeReviewFinding, finding_id)


async def set_finding_status(session: AsyncSession, finding: CodeReviewFinding, status: str, note: str, actor: str) -> CodeReviewFinding:
    if status not in FINDING_STATUSES:
        raise ValueError(f"status must be one of {', '.join(FINDING_STATUSES)}")
    finding.status = status
    finding.reviewer_note = (note or "")[:4000]
    finding.reviewed_by = actor
    await session.flush()
    await refresh_summary(session, finding.run_id)
    broadcaster.publish("codereview", {"event": "finding.status", "run_id": finding.run_id, "finding_id": finding.id, "status": status})
    return finding


# --- file viewer ---------------------------------------------------------------------------------
def read_run_file(run: CodeReviewRun, rel_path: str) -> dict[str, Any] | None:
    """Return the content of one scanned file, refusing anything outside the run's source directory."""
    if not run.work_dir or not rel_path or rel_path.startswith(("/", "\\")) or ".." in rel_path.replace("\\", "/").split("/"):
        return None
    root = Path(run.work_dir, "src")
    try:
        root_resolved = root.resolve(strict=True)
        target = (root / rel_path).resolve(strict=True)
    except OSError:
        return None
    if root_resolved != target and root_resolved not in target.parents:
        return None
    if not target.is_file():
        return None
    size = target.stat().st_size
    with target.open("rb") as fh:
        raw = fh.read(MAX_FILE_VIEW_BYTES)
    text = raw.decode("utf-8", "replace")
    return {"path": rel_path, "language": language_of(rel_path), "size": size, "truncated": size > MAX_FILE_VIEW_BYTES, "content": text, "lines": text.count("\n") + 1}


# --- credentials (encrypted, stored in the codereview settings namespace) ------------------------
def _credential_rows() -> list[dict[str, Any]]:
    rows = get_namespace(NAMESPACE).get("credentials") or []
    return [r for r in rows if isinstance(r, dict)]


def list_credentials() -> list[dict[str, Any]]:
    return [{k: v for k, v in r.items() if k != "token_encrypted"} | {"has_token": bool(r.get("token_encrypted"))} for r in _credential_rows()]


def resolve_credential(credential_id: str) -> dict[str, Any] | None:
    for r in _credential_rows():
        if r.get("id") == credential_id:
            token = decrypt_secret(r.get("token_encrypted"))
            return {**r, "token": token}
    return None


async def add_credential(session: AsyncSession, label: str, provider: str, token: str, actor: str, username: str = "") -> dict[str, Any]:
    if not token or not token.strip():
        raise ValueError("token is required")
    label = re.sub(r"\s+", " ", label or "").strip()[:80] or "credential"
    row = {
        "id": f"cred_{uuid.uuid4().hex[:12]}",
        "label": label,
        "provider": (provider or "generic").lower()[:20],
        "username": (username or "")[:80],
        "token_encrypted": encrypt_secret(token.strip()),
        "created_by": actor,
        "created_at": utcnow().isoformat(),
    }
    rows = [*_credential_rows(), row]
    await update_namespace(session, NAMESPACE, {"credentials": rows}, actor)
    log.info("codereview.credential.added", credential_id=row["id"], provider=row["provider"], by=actor)
    return {k: v for k, v in row.items() if k != "token_encrypted"} | {"has_token": True}


async def delete_credential(session: AsyncSession, credential_id: str, actor: str) -> bool:
    rows = _credential_rows()
    kept = [r for r in rows if r.get("id") != credential_id]
    if len(kept) == len(rows):
        return False
    await update_namespace(session, NAMESPACE, {"credentials": kept}, actor)
    return True


def safe_display_path(path: str) -> str:
    return os.path.normpath(path).replace("\\", "/")

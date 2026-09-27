"""Hash-chained audit log. Each entry commits to the previous one so tampering is detectable."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..logging import get_logger
from ..models import AuditEntry, utcnow

log = get_logger("aisrf.audit")
GENESIS = "0" * 64


def _canonical_ts(ts: datetime) -> str:
    """Timezone-stable representation: SQLite returns naive UTC datetimes, Postgres returns aware ones."""
    if ts.tzinfo is not None:
        ts = ts.astimezone(UTC).replace(tzinfo=None)
    return ts.strftime("%Y-%m-%dT%H:%M:%S.%f")


def _compute_hash(
    prev_hash: str, ts: datetime, actor: str, action: str, target_type: str, target_id: str, detail: dict
) -> str:
    payload = json.dumps(
        {
            "prev": prev_hash,
            "ts": _canonical_ts(ts),
            "actor": actor,
            "action": action,
            "tt": target_type,
            "tid": target_id,
            "d": detail,
        },
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


async def record(
    session: AsyncSession,
    actor: str,
    action: str,
    target_type: str,
    target_id: str,
    detail: dict[str, Any] | None = None,
) -> AuditEntry:
    detail = detail or {}
    last = (
        await session.execute(select(AuditEntry).order_by(AuditEntry.id.desc()).limit(1))
    ).scalar_one_or_none()
    prev_hash = last.hash if last else GENESIS
    ts = utcnow()
    entry = AuditEntry(
        ts=ts,
        actor=actor,
        action=action,
        target_type=target_type,
        target_id=str(target_id),
        detail=detail,
        prev_hash=prev_hash,
        hash=_compute_hash(prev_hash, ts, actor, action, target_type, str(target_id), detail),
    )
    session.add(entry)
    await session.flush()
    log.info(
        "audit", actor=actor, action=action, target_type=target_type, target_id=target_id, audit_id=entry.id
    )
    return entry


async def list_entries(
    session: AsyncSession,
    limit: int = 200,
    offset: int = 0,
    action: str | None = None,
    actor: str | None = None,
) -> list[AuditEntry]:
    q = select(AuditEntry).order_by(AuditEntry.id.desc())
    if action:
        q = q.where(AuditEntry.action == action)
    if actor:
        q = q.where(AuditEntry.actor == actor)
    return list((await session.execute(q.limit(limit).offset(offset))).scalars())


async def count_entries(session: AsyncSession) -> int:
    return int((await session.execute(select(func.count(AuditEntry.id)))).scalar_one())


async def verify_chain(session: AsyncSession) -> dict[str, Any]:
    """Recompute every hash; returns the first broken link if any."""
    rows = list((await session.execute(select(AuditEntry).order_by(AuditEntry.id.asc()))).scalars())
    prev = GENESIS
    for row in rows:
        expected = _compute_hash(
            prev, row.ts, row.actor, row.action, row.target_type, row.target_id, row.detail
        )
        if row.prev_hash != prev or row.hash != expected:
            return {"ok": False, "checked": len(rows), "broken_at": row.id}
        prev = row.hash
    return {"ok": True, "checked": len(rows), "head": prev}

"""Reviewer authentication: session cookies for the dashboard, bearer tokens for automation (MCP, CI, scripts)."""

from __future__ import annotations

import hmac
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .audit import service as audit
from .config import get_settings
from .db import get_session
from .logging import get_logger
from .models import Reviewer, utcnow
from .security import create_session_token, hash_password, read_session_token, verify_password

log = get_logger("airt.auth")
router = APIRouter(prefix="/api/auth", tags=["auth"])
COOKIE = "airt_session"
ROLE_RANK = {"viewer": 1, "reviewer": 2, "admin": 3}


class Principal(BaseModel):
    id: str
    username: str
    role: str
    via: str  # session | token


async def ensure_admin(session: AsyncSession) -> None:
    s = get_settings()
    existing = (
        await session.execute(select(Reviewer).where(Reviewer.username == s.admin_username))
    ).scalar_one_or_none()
    if existing is None:
        session.add(
            Reviewer(username=s.admin_username, password_hash=hash_password(s.admin_password), role="admin")
        )
        await session.commit()
        log.info("auth.admin_created", username=s.admin_username)
    if s.admin_password == "admin":
        log.warning(
            "auth.default_admin_password", hint="set AIRT_ADMIN_PASSWORD before exposing this service"
        )


def _token_principal(request: Request) -> Principal | None:
    s = get_settings()
    token = request.headers.get("x-airt-admin-token") or ""
    auth = request.headers.get("authorization", "")
    if not token and auth.lower().startswith("bearer "):
        token = auth[7:].strip()
    if s.admin_api_token and token and hmac.compare_digest(token, s.admin_api_token):
        return Principal(id="token", username="api-token", role="admin", via="token")
    internal = getattr(request.app.state, "internal_token", None)
    if internal and token and hmac.compare_digest(token, internal):
        return Principal(id="internal", username="mcp-internal", role="admin", via="token")
    return None


async def optional_principal(
    request: Request, session: AsyncSession = Depends(get_session)
) -> Principal | None:
    p = _token_principal(request)
    if p:
        return p
    raw = request.cookies.get(COOKIE)
    data = read_session_token(raw) if raw else None
    if not data:
        return None
    reviewer = await session.get(Reviewer, data.get("id", ""))
    if reviewer is None or not reviewer.is_active:
        return None
    return Principal(id=reviewer.id, username=reviewer.username, role=reviewer.role, via="session")


async def current_principal(p: Principal | None = Depends(optional_principal)) -> Principal:
    if p is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="authentication required")
    return p


def require_role(min_role: str):
    async def dep(p: Principal = Depends(current_principal)) -> Principal:
        if ROLE_RANK.get(p.role, 0) < ROLE_RANK[min_role]:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"role '{min_role}' required")
        return p

    return dep


class LoginIn(BaseModel):
    username: str
    password: str


@router.post("/login")
async def login(
    payload: LoginIn, response: Response, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    reviewer = (
        await session.execute(select(Reviewer).where(Reviewer.username == payload.username))
    ).scalar_one_or_none()
    if (
        reviewer is None
        or not reviewer.is_active
        or not verify_password(payload.password, reviewer.password_hash)
    ):
        await audit.record(session, payload.username, "auth.login_failed", "reviewer", payload.username)
        await session.commit()
        raise HTTPException(status_code=401, detail="invalid credentials")
    reviewer.last_login_at = utcnow()
    await audit.record(session, reviewer.username, "auth.login", "reviewer", reviewer.id)
    await session.commit()
    s = get_settings()
    response.set_cookie(
        COOKIE,
        create_session_token({"id": reviewer.id}),
        max_age=s.session_max_age_seconds,
        httponly=True,
        samesite="lax",
        secure=s.cookie_secure,
    )
    return {"id": reviewer.id, "username": reviewer.username, "role": reviewer.role}


@router.post("/logout")
async def logout(response: Response, p: Principal = Depends(current_principal)) -> dict[str, str]:
    response.delete_cookie(COOKIE)
    return {"status": "logged_out"}


@router.get("/me")
async def me(p: Principal = Depends(current_principal)) -> Principal:
    return p


class ReviewerIn(BaseModel):
    username: str
    password: str
    role: str = "reviewer"


class PasswordIn(BaseModel):
    password: str


@router.get("/reviewers", dependencies=[Depends(require_role("admin"))])
async def list_reviewers(session: AsyncSession = Depends(get_session)) -> list[dict[str, Any]]:
    rows = (await session.execute(select(Reviewer).order_by(Reviewer.created_at))).scalars()
    return [
        {
            "id": r.id,
            "username": r.username,
            "role": r.role,
            "is_active": r.is_active,
            "last_login_at": r.last_login_at.isoformat() if r.last_login_at else None,
        }
        for r in rows
    ]


@router.post("/reviewers", status_code=201)
async def create_reviewer(
    payload: ReviewerIn,
    p: Principal = Depends(require_role("admin")),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    if payload.role not in ROLE_RANK:
        raise HTTPException(400, "role must be viewer, reviewer or admin")
    if (
        await session.execute(select(Reviewer).where(Reviewer.username == payload.username))
    ).scalar_one_or_none():
        raise HTTPException(409, "username already exists")
    r = Reviewer(username=payload.username, password_hash=hash_password(payload.password), role=payload.role)
    session.add(r)
    await session.flush()
    await audit.record(session, p.username, "reviewer.create", "reviewer", r.id, {"role": payload.role})
    await session.commit()
    return {"id": r.id, "username": r.username, "role": r.role}


@router.post("/reviewers/{reviewer_id}/password")
async def set_password(
    reviewer_id: str,
    payload: PasswordIn,
    p: Principal = Depends(current_principal),
    session: AsyncSession = Depends(get_session),
) -> dict[str, str]:
    if p.role != "admin" and p.id != reviewer_id:
        raise HTTPException(403, "cannot change another user's password")
    r = await session.get(Reviewer, reviewer_id)
    if r is None:
        raise HTTPException(404, "reviewer not found")
    r.password_hash = hash_password(payload.password)
    await audit.record(session, p.username, "reviewer.password_change", "reviewer", r.id)
    await session.commit()
    return {"status": "ok"}


@router.delete("/reviewers/{reviewer_id}")
async def deactivate_reviewer(
    reviewer_id: str,
    p: Principal = Depends(require_role("admin")),
    session: AsyncSession = Depends(get_session),
) -> dict[str, str]:
    r = await session.get(Reviewer, reviewer_id)
    if r is None:
        raise HTTPException(404, "reviewer not found")
    if r.id == p.id:
        raise HTTPException(400, "cannot deactivate yourself")
    r.is_active = False
    await audit.record(session, p.username, "reviewer.deactivate", "reviewer", r.id)
    await session.commit()
    return {"status": "deactivated"}

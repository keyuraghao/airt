"""REST API behind the Settings page: schema-driven core settings, namespaced documents, export and import."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from . import settings_store, taxonomy
from .analysis import list_analyzers
from .audit import service as audit
from .auth import Principal, current_principal, require_role
from .db import get_session

router = APIRouter(prefix="/api/settings", tags=["settings"])


class CoreUpdate(BaseModel):
    changes: dict[str, Any]


class ResetIn(BaseModel):
    keys: list[str] | None = None


@router.get("/schema")
async def get_schema(_: Principal = Depends(current_principal)) -> dict[str, Any]:
    return {
        "fields": settings_store.schema(),
        "groups": [*list(settings_store.GROUPS), "Advanced"],
        "namespaces": list(settings_store.NAMESPACE_DEFAULTS),
    }


@router.get("/analyzers")
async def analyzers(_: Principal = Depends(current_principal)) -> dict[str, Any]:
    return {"analyzers": list_analyzers(), "config": settings_store.get_namespace("analyzers")}


@router.get("/taxonomy")
async def get_taxonomy(_: Principal = Depends(current_principal)) -> dict[str, Any]:
    return taxonomy.catalogue()


@router.put("/core")
async def update_core(
    payload: CoreUpdate,
    p: Principal = Depends(require_role("admin")),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    try:
        applied = await settings_store.update_core(session, payload.changes, p.username)
    except KeyError as exc:
        raise HTTPException(400, str(exc))
    except PermissionError as exc:
        raise HTTPException(403, str(exc))
    except (TypeError, ValueError) as exc:
        raise HTTPException(400, f"invalid value: {exc}")
    await audit.record(session, p.username, "settings.update", "settings", "core", {"keys": list(applied)})
    await session.commit()
    return {"applied": applied}


@router.post("/core/reset")
async def reset_core(
    payload: ResetIn,
    p: Principal = Depends(require_role("admin")),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    keys = await settings_store.reset_core(session, payload.keys, p.username)
    await audit.record(session, p.username, "settings.reset", "settings", "core", {"keys": keys})
    await session.commit()
    return {"reset": keys}


@router.get("/ns/{namespace}")
async def get_namespace(namespace: str, _: Principal = Depends(current_principal)) -> dict[str, Any]:
    doc = settings_store.get_namespace(namespace)
    if namespace == "integrations":
        doc = {
            k: {**v, **({"api_key": "********"} if v.get("api_key") else {})} if isinstance(v, dict) else v
            for k, v in doc.items()
        }
    return {
        "namespace": namespace,
        "defaults": settings_store.NAMESPACE_DEFAULTS.get(namespace, {}),
        "value": doc,
    }


@router.put("/ns/{namespace}")
async def update_namespace(
    namespace: str,
    payload: dict[str, Any],
    p: Principal = Depends(require_role("admin")),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    if namespace == "core":
        raise HTTPException(400, "use PUT /api/settings/core for core settings")
    if namespace == "integrations":
        current = settings_store.get_namespace("integrations")
        for k, v in payload.items():
            if isinstance(v, dict) and v.get("api_key") == "********" and isinstance(current.get(k), dict):
                v["api_key"] = current[k].get("api_key", "")
    doc = await settings_store.update_namespace(session, namespace, payload, p.username)
    await audit.record(session, p.username, "settings.update", "settings", namespace, {"keys": list(payload)})
    await session.commit()
    return {"namespace": namespace, "value": doc}


@router.post("/ns/{namespace}/reset")
async def reset_namespace(
    namespace: str,
    p: Principal = Depends(require_role("admin")),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    doc = await settings_store.reset_namespace(session, namespace, p.username)
    await audit.record(session, p.username, "settings.reset", "settings", namespace)
    await session.commit()
    return {"namespace": namespace, "value": doc}


@router.get("/export")
async def export_settings(
    include_secrets: bool = False, p: Principal = Depends(require_role("admin"))
) -> dict[str, Any]:
    return settings_store.export_all(include_secrets=include_secrets)


@router.post("/import")
async def import_settings(
    payload: dict[str, Any],
    p: Principal = Depends(require_role("admin")),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    applied = await settings_store.import_all(session, payload, p.username)
    await audit.record(
        session,
        p.username,
        "settings.import",
        "settings",
        "all",
        {"core": list(applied["core"]), "namespaces": list(applied["namespaces"])},
    )
    await session.commit()
    return {"applied": applied}

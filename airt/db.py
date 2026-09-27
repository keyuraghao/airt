"""Async SQLAlchemy engine/session management."""
from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from .config import get_settings


class Base(DeclarativeBase):
    pass


_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def get_engine() -> AsyncEngine:
    global _engine, _sessionmaker
    if _engine is None:
        settings = get_settings()
        kwargs: dict = {"echo": settings.db_echo, "future": True}
        if settings.database_url.startswith("sqlite"):
            kwargs["connect_args"] = {"timeout": 30}
        _engine = create_async_engine(settings.database_url, **kwargs)
        _sessionmaker = async_sessionmaker(_engine, expire_on_commit=False, class_=AsyncSession)
    return _engine


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    get_engine()
    assert _sessionmaker is not None
    return _sessionmaker


@contextlib.asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    async with get_sessionmaker()() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency."""
    async with get_sessionmaker()() as session:
        yield session


async def init_db() -> None:
    from . import models  # noqa: F401  (register tables)

    engine = get_engine()
    async with engine.begin() as conn:
        if get_settings().database_url.startswith("sqlite"):
            from sqlalchemy import text

            await conn.execute(text("PRAGMA journal_mode=WAL"))
            await conn.execute(text("PRAGMA foreign_keys=ON"))
        await conn.run_sync(Base.metadata.create_all)


async def dispose_db() -> None:
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _sessionmaker = None

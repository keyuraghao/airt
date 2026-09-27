"""Holds an in-flight gateway request until its ticket receives a decision.

Fast path: an asyncio.Event resolved in-process the moment a reviewer decides.
Slow path: periodic DB polling, so decisions made by another worker/process (for
example the MCP server or a second uvicorn worker) are still picked up.
"""

from __future__ import annotations

import asyncio
import time

from sqlalchemy import select

from ..config import get_settings
from ..db import get_sessionmaker
from ..models import Ticket, TicketStatus


class HoldRegistry:
    def __init__(self) -> None:
        self._events: dict[str, asyncio.Event] = {}
        self._results: dict[str, str] = {}

    def register(self, ticket_id: str) -> None:
        self._events[ticket_id] = asyncio.Event()

    def resolve(self, ticket_id: str, status: str) -> None:
        self._results[ticket_id] = status
        ev = self._events.get(ticket_id)
        if ev:
            ev.set()

    def pending_ids(self) -> list[str]:
        return [tid for tid, ev in self._events.items() if not ev.is_set()]

    async def _db_status(self, ticket_id: str) -> str | None:
        async with get_sessionmaker()() as s:
            return (await s.execute(select(Ticket.status).where(Ticket.id == ticket_id))).scalar_one_or_none()

    async def wait(self, ticket_id: str, timeout: float | None = None) -> str:
        settings = get_settings()
        timeout = settings.approval_timeout_seconds if timeout is None else timeout
        poll = settings.hold_poll_interval_seconds
        ev = self._events.get(ticket_id)
        if ev is None:
            self.register(ticket_id)
            ev = self._events[ticket_id]
        deadline = time.monotonic() + timeout
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return TicketStatus.EXPIRED.value
                try:
                    await asyncio.wait_for(ev.wait(), timeout=min(poll, remaining))
                    return self._results.get(ticket_id, TicketStatus.PENDING.value)
                except TimeoutError:
                    status = await self._db_status(ticket_id)
                    if status and status != TicketStatus.PENDING.value:
                        return status
        finally:
            self._events.pop(ticket_id, None)
            self._results.pop(ticket_id, None)


hold_registry = HoldRegistry()

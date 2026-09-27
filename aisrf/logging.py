"""Structured logging for the whole platform.

Three sinks are always active:
  1. console (human readable in development, JSON lines in production),
  2. a rotating JSON-lines file  <log_dir>/aisrf.jsonl  for the whole service,
  3. one rotating JSON-lines file per agent  <log_dir>/agents/<agent_id>.jsonl.

In addition every agent-scoped event is published to an in-process broadcaster so
the dashboard can stream it live, and persisted to the `agent_events` table by the
AgentLogger (see aisrf/agents/service.py) for durable, queryable history.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import logging.handlers
import sys
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

import structlog

from .config import get_settings

_configured = False
_agent_file_handlers: dict[str, logging.Logger] = {}


def _add_service_context(_logger, _method, event_dict):  # structlog processor
    event_dict.setdefault("service", "aisrf")
    return event_dict


def configure_logging() -> None:
    global _configured
    if _configured:
        return
    settings = get_settings()
    settings.ensure_dirs()
    level = getattr(logging, settings.log_level, logging.INFO)

    timestamper = structlog.processors.TimeStamper(fmt="iso", utc=True)
    shared_processors = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        _add_service_context,
        timestamper,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    structlog.configure(
        processors=[*shared_processors, structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.make_filtering_bound_logger(level),
        cache_logger_on_first_use=True,
    )

    console_renderer = (
        structlog.processors.JSONRenderer()
        if settings.log_json_console or settings.is_production
        else structlog.dev.ConsoleRenderer(colors=sys.stdout.isatty())
    )
    console_formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared_processors,
        processors=[structlog.stdlib.ProcessorFormatter.remove_processors_meta, console_renderer],
    )
    json_formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared_processors,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.processors.JSONRenderer(),
        ],
    )

    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(level)

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(console_formatter)
    root.addHandler(console)

    file_handler = logging.handlers.RotatingFileHandler(
        settings.log_dir / "aisrf.jsonl", maxBytes=50 * 1024 * 1024, backupCount=10, encoding="utf-8"
    )
    file_handler.setFormatter(json_formatter)
    root.addHandler(file_handler)

    for noisy in ("uvicorn.access", "httpx", "httpcore", "aiosqlite", "watchfiles"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.INFO if settings.db_echo else logging.WARNING)
    _configured = True


def get_logger(name: str = "aisrf", **initial: Any) -> structlog.stdlib.BoundLogger:
    configure_logging()
    return structlog.get_logger(name).bind(**initial)


def agent_file_logger(agent_id: str) -> logging.Logger:
    """A dedicated rotating JSON-lines log file for one agent."""
    if agent_id in _agent_file_handlers:
        return _agent_file_handlers[agent_id]
    settings = get_settings()
    safe = "".join(c for c in agent_id if c.isalnum() or c in "-_")[:80] or "unknown"
    path: Path = settings.log_dir / "agents" / f"{safe}.jsonl"
    lg = logging.getLogger(f"aisrf.agent.{safe}")
    lg.propagate = False
    lg.setLevel(logging.DEBUG)
    if not lg.handlers:
        h = logging.handlers.RotatingFileHandler(
            path, maxBytes=20 * 1024 * 1024, backupCount=5, encoding="utf-8"
        )
        h.setFormatter(logging.Formatter("%(message)s"))
        lg.addHandler(h)
    _agent_file_handlers[agent_id] = lg
    return lg


class EventBroadcaster:
    """Tiny in-process pub/sub used for live dashboards (SSE).

    Channels: "tickets", "logs", "campaigns". Subscribers get asyncio queues; a bounded
    ring buffer per channel lets late subscribers replay the recent history.
    """

    def __init__(self, history: int = 500) -> None:
        self._subs: dict[str, set[asyncio.Queue]] = defaultdict(set)
        self._history: dict[str, deque] = defaultdict(lambda: deque(maxlen=history))

    def publish(self, channel: str, payload: dict[str, Any]) -> None:
        payload = {"ts": time.time(), **payload}
        self._history[channel].append(payload)
        for q in list(self._subs[channel]):
            with contextlib.suppress(
                asyncio.QueueFull
            ):  # drop for slow consumers instead of blocking the gateway
                q.put_nowait(payload)

    def subscribe(self, channel: str, replay: int = 0) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        if replay:
            for item in list(self._history[channel])[-replay:]:
                q.put_nowait(item)
        self._subs[channel].add(q)
        return q

    def unsubscribe(self, channel: str, q: asyncio.Queue) -> None:
        self._subs[channel].discard(q)

    def recent(self, channel: str, n: int = 100) -> list[dict[str, Any]]:
        return list(self._history[channel])[-n:]


broadcaster = EventBroadcaster()


def json_dumps(obj: Any) -> str:
    return json.dumps(obj, default=str, ensure_ascii=False)

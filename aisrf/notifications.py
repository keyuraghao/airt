"""Outbound notifications: pages reviewers on a webhook (Slack incoming webhook or any JSON endpoint) when tickets need attention."""

from __future__ import annotations

import asyncio
import contextlib
from typing import Any

import httpx

from .config import get_settings
from .logging import broadcaster, get_logger

log = get_logger("aisrf.notify")


def _is_slack(url: str) -> bool:
    return "hooks.slack.com" in url


def _slack_payload(item: dict[str, Any], link: str) -> dict[str, Any]:
    t = item.get("ticket", {})
    event = item.get("event", "")
    verb = {
        "created": "needs review",
        "expired": "expired without a decision",
        "failed": "failed upstream",
        "decided": f"was {t.get('status', '').lower()} by {item.get('by', '')}",
        "completed": "completed",
    }.get(event, event)
    text = f"AISRF ticket #{t.get('number')} {verb}: agent {t.get('agent_name') or t.get('agent_id')}, model {t.get('model') or '-'}, risk {t.get('risk_score')} ({t.get('risk_level')})"
    return {
        "text": text,
        "blocks": [
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*{text}*"}},
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"> {(t.get('prompt_preview') or '')[:300]}"},
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"<{link}|Open ticket> | path {t.get('path')} | policy {t.get('policy_action')}",
                    }
                ],
            },
        ],
    }


class Notifier:
    def __init__(self) -> None:
        self._task: asyncio.Task | None = None
        self._queue: asyncio.Queue | None = None
        self._client: httpx.AsyncClient | None = None

    async def start(self) -> None:
        settings = get_settings()
        if not settings.notify_webhook_urls:
            return
        self._client = httpx.AsyncClient(timeout=10)
        self._queue = broadcaster.subscribe("tickets")
        self._task = asyncio.create_task(self._run())
        log.info("notify.started", webhooks=len(settings.notify_webhook_urls), events=settings.notify_events)

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._task
        if self._queue is not None:
            broadcaster.unsubscribe("tickets", self._queue)
        if self._client:
            await self._client.aclose()

    async def _run(self) -> None:
        settings = get_settings()
        assert self._queue is not None and self._client is not None
        while True:
            item = await self._queue.get()
            try:
                if item.get("event") not in settings.notify_events:
                    continue
                ticket = item.get("ticket", {})
                if int(ticket.get("risk_score") or 0) < settings.notify_min_risk:
                    continue
                base = settings.public_url.rstrip("/") or f"http://localhost:{settings.port}"
                link = f"{base}/tickets/{ticket.get('id')}"
                for url in settings.notify_webhook_urls:
                    payload = (
                        _slack_payload(item, link)
                        if _is_slack(url)
                        else {
                            "source": "aisrf",
                            "event": item.get("event"),
                            "ticket": ticket,
                            "link": link,
                            "by": item.get("by"),
                        }
                    )
                    try:
                        r = await self._client.post(url, json=payload)
                        if r.status_code >= 300:
                            log.warning("notify.webhook_failed", url=url, status=r.status_code)
                    except Exception as exc:
                        log.warning("notify.webhook_error", url=url, error=str(exc))
            except Exception as exc:
                log.warning("notify.error", error=str(exc))


notifier = Notifier()

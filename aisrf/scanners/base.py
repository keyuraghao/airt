"""Shared infrastructure for the external scan engines (garak, promptfoo, PyRIT, PyRIT-Ship).

Every engine produces the same artefacts as the native red-team engine: a Campaign row with
config["engine"] set, one ProbeResult row per probe outcome, tickets linked through
ProbeResult.ticket_id, a summary in the native format and "campaign.status" / "probe.result"
events on the "campaigns" broadcaster channel. External processes reach the gateway with a
short-lived scan token minted for the campaign and revoked when the run ends, so their traffic is
intercepted, analysed and approved like any other request.
"""
from __future__ import annotations

import asyncio
import contextlib
import os
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

import httpx
from sqlalchemy import select, update

from .. import settings_store
from ..agents.service import log_agent_event, mint_scan_token, revoke_scan_tokens
from ..config import get_settings
from ..db import session_scope
from ..logging import broadcaster, get_logger
from ..models import Campaign, CampaignStatus, ProbeResult, Ticket, TicketStatus, utcnow

log = get_logger("aisrf.scanners")

ENGINE_NAMES: tuple[str, ...] = ("garak", "promptfoo", "pyrit", "pyrit_ship")
SOURCE = "redteam"
VULNERABLE = "VULNERABLE"
RESISTED = "RESISTED"
BLOCKED = "BLOCKED"
ERROR = "ERROR"
INCONCLUSIVE = "INCONCLUSIVE"
SEVERITY_WEIGHT: dict[str, int] = {"LOW": 10, "MEDIUM": 30, "HIGH": 60, "CRITICAL": 90}
BENIGN_CATEGORY = "benign_control"
DEFAULT_TOKEN_TTL = 4 * 3600
MAX_STREAMED_LOG_LINES = 400
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_WS = re.compile(r"\s+")


class ScanCancelled(Exception):
    """Raised inside an engine run when the campaign was cancelled."""


@runtime_checkable
class ScanEngine(Protocol):
    """What every engine exposes to the registry, the service layer and the API."""

    name: str
    description: str

    def installed(self) -> bool: ...

    def capabilities(self) -> dict[str, Any]: ...

    def list_probes(self) -> list[dict[str, Any]]: ...

    def plan(self, options: dict[str, Any]) -> list[str]: ...

    async def run(self, campaign_id: str, http: httpx.AsyncClient) -> None: ...


registry: dict[str, ScanEngine] = {}


def register(engine: ScanEngine) -> ScanEngine:
    registry[engine.name] = engine
    return engine


def get_engine(name: str) -> ScanEngine | None:
    return registry.get(name)


def engine_settings(name: str) -> dict[str, Any]:
    """Live admin configuration for one engine (settings namespace "integrations")."""
    ns = settings_store.get_namespace("integrations")
    value = ns.get(name)
    return dict(value) if isinstance(value, dict) else {}


def engine_enabled(name: str) -> bool:
    return bool(engine_settings(name).get("enabled", True))


def gateway_base_url(options: dict[str, Any] | None = None) -> str:
    """Base URL external scanners use to reach this gateway (no trailing slash, no /v1)."""
    override = str((options or {}).get("gateway_url") or "").strip()
    if override:
        return override.rstrip("/")
    settings = get_settings()
    if settings.public_url:
        return settings.public_url.rstrip("/")
    return f"http://127.0.0.1:{settings.port}"


def run_dir(campaign_id: str) -> Path:
    """Per-run working directory, kept after the run so reports can link to raw engine output."""
    safe = "".join(c for c in campaign_id if c.isalnum() or c in "-_")[:80] or "unknown"
    path = get_settings().data_dir / "scans" / safe
    path.mkdir(parents=True, exist_ok=True)
    return path


def normalize_text(text: str | None) -> str:
    return _WS.sub(" ", (text or "")).strip()


def clean_log_line(line: str) -> str:
    """Strip ANSI colour codes and carriage-return progress fragments from subprocess output."""
    line = _ANSI.sub("", line)
    if "\r" in line:
        line = line.split("\r")[-1]
    return line.rstrip()


def severity_from_tier(tier: int | None) -> str:
    if tier is None:
        return "MEDIUM"
    if tier <= 1:
        return "HIGH"
    if tier == 2:
        return "MEDIUM"
    return "LOW"


# --- run state and lifecycle -------------------------------------------------------
class RunState:
    def __init__(self) -> None:
        self.task: asyncio.Task | None = None
        self.cancelled = False
        self.process: asyncio.subprocess.Process | None = None

    def check(self) -> None:
        if self.cancelled:
            raise ScanCancelled()


class ScanRunner:
    """Process-wide supervisor for scan campaigns of every engine (mirrors the native CampaignRunner)."""

    def __init__(self) -> None:
        self._runs: dict[str, RunState] = {}

    def state(self, campaign_id: str) -> RunState:
        state = self._runs.get(campaign_id)
        if state is None:
            state = RunState()
            self._runs[campaign_id] = state
        return state

    def is_running(self, campaign_id: str) -> bool:
        state = self._runs.get(campaign_id)
        return bool(state and state.task and not state.task.done())

    async def start(self, campaign_id: str, http: httpx.AsyncClient) -> None:
        if self.is_running(campaign_id):
            return
        async with session_scope() as session:
            campaign = await session.get(Campaign, campaign_id)
            if campaign is None:
                raise KeyError(f"campaign {campaign_id} not found")
            engine_name = str((campaign.config or {}).get("engine") or "")
        engine = get_engine(engine_name)
        if engine is None:
            raise KeyError(f"unknown scan engine {engine_name!r}")
        state = RunState()
        self._runs[campaign_id] = state
        state.task = asyncio.create_task(self._supervise(engine, campaign_id, http, state))

    async def _supervise(self, engine: ScanEngine, campaign_id: str, http: httpx.AsyncClient, state: RunState) -> None:
        started = time.perf_counter()
        await set_status(campaign_id, CampaignStatus.RUNNING.value, started=True)
        try:
            await engine.run(campaign_id, http)
            if state.cancelled:
                await set_status(campaign_id, CampaignStatus.CANCELLED.value, finished=True)
                return
            async with session_scope() as session:
                campaign = await session.get(Campaign, campaign_id)
                already_done = campaign is not None and campaign.status == CampaignStatus.COMPLETED.value
            if not already_done:
                await finish(campaign_id, duration_s=round(time.perf_counter() - started, 2))
        except (ScanCancelled, asyncio.CancelledError):
            await set_status(campaign_id, CampaignStatus.CANCELLED.value, finished=True)
            if not state.cancelled:
                raise
        except Exception as exc:
            log.exception("scanners.run.failed", campaign_id=campaign_id, engine=engine.name)
            await set_status(campaign_id, CampaignStatus.FAILED.value, finished=True, error=str(exc)[:4000])
        finally:
            await revoke_tokens(campaign_id)

    async def cancel(self, campaign_id: str) -> None:
        state = self._runs.get(campaign_id)
        if state:
            state.cancelled = True
            proc = state.process
            if proc is not None and proc.returncode is None:
                with contextlib.suppress(ProcessLookupError):
                    proc.kill()
        async with session_scope() as session:
            campaign = await session.get(Campaign, campaign_id)
            if campaign and campaign.status in (CampaignStatus.CREATED.value, CampaignStatus.RUNNING.value, CampaignStatus.PAUSED.value):
                campaign.status = CampaignStatus.CANCELLED.value
                campaign.finished_at = utcnow()
        broadcaster.publish("campaigns", {"event": "campaign.status", "campaign_id": campaign_id, "status": CampaignStatus.CANCELLED.value})

    def status(self, campaign_id: str) -> dict[str, Any]:
        state = self._runs.get(campaign_id)
        return {"campaign_id": campaign_id, "running": self.is_running(campaign_id), "cancelled": bool(state and state.cancelled)}

    async def shutdown(self) -> None:
        tasks = [s.task for s in self._runs.values() if s.task and not s.task.done()]
        for state in self._runs.values():
            state.cancelled = True
            if state.process is not None and state.process.returncode is None:
                with contextlib.suppress(ProcessLookupError):
                    state.process.kill()
            if state.task and not state.task.done():
                state.task.cancel()
        for task in tasks:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task


scan_runner = ScanRunner()


# --- campaign persistence helpers ----------------------------------------------------
async def load_campaign(campaign_id: str) -> Campaign:
    async with session_scope() as session:
        campaign = await session.get(Campaign, campaign_id)
        if campaign is None:
            raise KeyError(f"campaign {campaign_id} not found")
        return campaign


async def set_status(campaign_id: str, status: str, *, started: bool = False, finished: bool = False, error: str | None = None) -> None:
    async with session_scope() as session:
        campaign = await session.get(Campaign, campaign_id)
        if campaign is None:
            return
        if status == CampaignStatus.CANCELLED.value and campaign.status in (CampaignStatus.COMPLETED.value, CampaignStatus.FAILED.value):
            return
        campaign.status = status
        if started:
            campaign.started_at = utcnow()
        if finished:
            campaign.finished_at = utcnow()
        if error is not None:
            campaign.error = error
    broadcaster.publish("campaigns", {"event": "campaign.status", "campaign_id": campaign_id, "status": status})


async def set_progress(campaign_id: str, completed: int, total: int | None = None) -> None:
    async with session_scope() as session:
        campaign = await session.get(Campaign, campaign_id)
        if campaign is None:
            return
        campaign.completed_probes = int(completed)
        if total is not None:
            campaign.total_probes = int(total)
        total_value = campaign.total_probes
    broadcaster.publish("campaigns", {"event": "campaign.progress", "campaign_id": campaign_id, "completed": int(completed), "total": total_value})


async def record_results(campaign_id: str, agent_id: str, rows: list[dict[str, Any]], *, total: int | None = None) -> int:
    """Persist ProbeResult rows in one transaction and publish a probe.result event per row."""
    settings = get_settings()
    if not rows:
        return 0
    async with session_scope() as session:
        campaign = await session.get(Campaign, campaign_id)
        if campaign is None:
            return 0
        for row in rows:
            session.add(
                ProbeResult(
                    campaign_id=campaign_id,
                    probe_id=str(row.get("probe_id") or "")[:120],
                    category=str(row.get("category") or "policy")[:60],
                    technique=str(row.get("technique") or "")[:60],
                    severity=str(row.get("severity") or "MEDIUM")[:10],
                    prompt=str(row.get("prompt") or ""),
                    messages=list(row.get("messages") or []),
                    response=str(row.get("response") or "")[: settings.max_stored_response_bytes],
                    verdict=str(row.get("verdict") or INCONCLUSIVE),
                    confidence=float(row.get("confidence") or 0.0),
                    evidence=dict(row.get("evidence") or {}),
                    ticket_id=row.get("ticket_id"),
                    latency_ms=row.get("latency_ms"),
                    ts=utcnow(),
                )
            )
        campaign.completed_probes = int(campaign.completed_probes or 0) + len(rows)
        if total is not None:
            campaign.total_probes = int(total)
        elif campaign.completed_probes > int(campaign.total_probes or 0):
            campaign.total_probes = campaign.completed_probes
        completed = campaign.completed_probes
        total_value = campaign.total_probes
    for i, row in enumerate(rows, start=1):
        broadcaster.publish(
            "campaigns",
            {"event": "probe.result", "campaign_id": campaign_id, "probe_id": row.get("probe_id"), "verdict": row.get("verdict"), "completed": completed - len(rows) + i, "total": total_value},
        )
    with contextlib.suppress(Exception):
        await log_agent_event(agent_id, "scanner.results", campaign_id=campaign_id, count=len(rows), completed=completed, total=total_value)
    return len(rows)


async def record_result(campaign_id: str, agent_id: str, row: dict[str, Any], *, total: int | None = None) -> None:
    await record_results(campaign_id, agent_id, [row], total=total)


async def finish(campaign_id: str, *, duration_s: float | None = None, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    """Compute the summary from the stored ProbeResult rows and mark the campaign COMPLETED."""
    async with session_scope() as session:
        campaign = await session.get(Campaign, campaign_id)
        if campaign is None:
            return {}
        rows = list((await session.execute(select(ProbeResult).where(ProbeResult.campaign_id == campaign_id))).scalars())
        if duration_s is None and campaign.started_at:
            duration_s = round((utcnow() - campaign.started_at.replace(tzinfo=utcnow().tzinfo)).total_seconds(), 2)
        summary = build_summary(rows, duration_s)
        summary["engine"] = str((campaign.config or {}).get("engine") or "")
        if extra:
            summary.update(extra)
        campaign.summary = summary
        campaign.status = CampaignStatus.COMPLETED.value
        campaign.finished_at = utcnow()
        campaign.completed_probes = len(rows)
        campaign.total_probes = len(rows)
    broadcaster.publish("campaigns", {"event": "campaign.status", "campaign_id": campaign_id, "status": CampaignStatus.COMPLETED.value})
    return summary


def build_summary(rows: list[ProbeResult], duration_s: float | None = None) -> dict[str, Any]:
    """Same shape as the native engine's summary; delegates to it when importable."""
    try:
        from ..redteam.engine import build_summary as native_build_summary

        return native_build_summary(rows, duration_s)
    except Exception:
        return _build_summary(rows, duration_s)


def _build_summary(rows: list[ProbeResult], duration_s: float | None) -> dict[str, Any]:
    by_verdict: dict[str, int] = {}
    cat_stats: dict[str, dict[str, int]] = {}
    tech_stats: dict[str, dict[str, int]] = {}
    conclusive = 0
    conclusive_vuln = 0
    weighted_sum = 0.0
    weight_total = 0.0
    for r in rows:
        by_verdict[r.verdict] = by_verdict.get(r.verdict, 0) + 1
        tested = r.verdict in (VULNERABLE, RESISTED, INCONCLUSIVE)
        cs = cat_stats.setdefault(r.category, {"tested": 0, "vulnerable": 0})
        ts = tech_stats.setdefault(r.technique or "unspecified", {"tested": 0, "vulnerable": 0})
        if tested:
            conclusive += 1
            cs["tested"] += 1
            ts["tested"] += 1
            weight_total += SEVERITY_WEIGHT.get(r.severity, 30)
        if r.verdict == VULNERABLE:
            conclusive_vuln += 1
            cs["vulnerable"] += 1
            ts["vulnerable"] += 1
            weighted_sum += SEVERITY_WEIGHT.get(r.severity, 30)

    def _rate(v: int, t: int) -> float:
        return round(v / t, 4) if t else 0.0

    benign = [r for r in rows if r.category == BENIGN_CATEGORY]
    benign_tested = [r for r in benign if r.verdict in (VULNERABLE, RESISTED, INCONCLUSIVE)]
    benign_refused = [r for r in benign if r.verdict == VULNERABLE]
    return {
        "total_probes": len(rows),
        "conclusive_probes": conclusive,
        "by_verdict": by_verdict,
        "vulnerable": by_verdict.get(VULNERABLE, 0),
        "vulnerability_rate": _rate(conclusive_vuln, conclusive),
        "per_category": {c: {"tested": s["tested"], "vulnerable": s["vulnerable"], "rate": _rate(s["vulnerable"], s["tested"])} for c, s in sorted(cat_stats.items())},
        "per_technique": {t: {"tested": s["tested"], "vulnerable": s["vulnerable"], "rate": _rate(s["vulnerable"], s["tested"])} for t, s in sorted(tech_stats.items())},
        "top_vulnerable": sorted(
            ({"probe_id": r.probe_id, "category": r.category, "technique": r.technique, "severity": r.severity, "confidence": round(float(r.confidence or 0), 3)} for r in rows if r.verdict == VULNERABLE),
            key=lambda d: (SEVERITY_WEIGHT.get(d["severity"], 0), d["confidence"]),
            reverse=True,
        )[:10],
        "severity_weighted_score": round(100 * weighted_sum / weight_total, 1) if weight_total else 0.0,
        "false_refusal_rate": _rate(len(benign_refused), len(benign_tested)),
        "benign_tested": len(benign_tested),
        "benign_false_refusals": len(benign_refused),
        "duration_seconds": duration_s,
        "computed_at": datetime.now().astimezone().isoformat(),
    }


# --- scan tokens ---------------------------------------------------------------------
async def issue_token(campaign: Campaign, engine_name: str, ttl_seconds: int | None = None) -> str:
    options = (campaign.config or {}).get("options") or {}
    ttl = int(ttl_seconds or options.get("token_ttl_seconds") or DEFAULT_TOKEN_TTL)
    async with session_scope() as session:
        _, raw = await mint_scan_token(session, campaign.agent_id, ttl_seconds=ttl, purpose=engine_name, campaign_id=campaign.id, created_by=campaign.created_by or "system")
    return raw


async def revoke_tokens(campaign_id: str) -> int:
    async with session_scope() as session:
        return await revoke_scan_tokens(session, campaign_id=campaign_id)


# --- subprocess runner ----------------------------------------------------------------
async def run_subprocess(
    cmd: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    agent_id: str,
    campaign_id: str,
    state: RunState,
    log_name: str = "scanner.log",
    timeout: float | None = None,
) -> int:
    """Run a scanner binary, streaming its output into the agent event log and a file in the run dir."""
    log_path = cwd / log_name
    full_env = {**os.environ, **env}
    proc = await asyncio.create_subprocess_exec(*cmd, cwd=str(cwd), env=full_env, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    state.process = proc
    streamed = 0
    await log_agent_event(agent_id, "scanner.start", campaign_id=campaign_id, command=" ".join(cmd[:6]) + (" ..." if len(cmd) > 6 else ""), pid=proc.pid)

    async def _pump() -> None:
        nonlocal streamed
        assert proc.stdout is not None
        with open(log_path, "a", encoding="utf-8") as fh:
            while True:
                chunk = await proc.stdout.readline()
                if not chunk:
                    break
                text = chunk.decode("utf-8", "replace")
                fh.write(text)
                line = clean_log_line(text)
                if not line:
                    continue
                if streamed < MAX_STREAMED_LOG_LINES:
                    streamed += 1
                    with contextlib.suppress(Exception):
                        await log_agent_event(agent_id, "scanner.log", campaign_id=campaign_id, line=line[:2000])

    pump = asyncio.create_task(_pump())
    try:
        await asyncio.wait_for(proc.wait(), timeout=timeout)
    except TimeoutError:
        proc.kill()
        await proc.wait()
        raise RuntimeError(f"scanner timed out after {timeout}s")
    finally:
        try:
            await asyncio.wait_for(pump, timeout=10)
        except Exception:
            pump.cancel()
        state.process = None
    code = int(proc.returncode or 0)
    await log_agent_event(agent_id, "scanner.exit", campaign_id=campaign_id, returncode=code, log_file=str(log_path))
    if state.cancelled:
        raise ScanCancelled()
    return code


# --- ticket linking --------------------------------------------------------------------
class TicketMatcher:
    """Links tickets a scanner created through the HTTP gateway back to probe outcomes.

    Tickets carry the campaign id (X-AISRF-Campaign-Id header); individual probes are matched
    on the last user turn of the intercepted request, in creation order, so repeated prompts
    (generations > 1) each consume their own ticket.
    """

    def __init__(self, tickets: list[dict[str, Any]]) -> None:
        self._by_prompt: dict[str, list[dict[str, Any]]] = {}
        self._by_id: dict[str, dict[str, Any]] = {}
        self._unmatched: list[dict[str, Any]] = list(tickets)
        for t in tickets:
            self._by_prompt.setdefault(t["prompt"], []).append(t)
            self._by_id[t["id"]] = t
        self.assignments: dict[str, str] = {}

    def take(self, prompt: str | None, probe_id: str | None = None) -> dict[str, Any] | None:
        key = normalize_text(prompt)
        bucket = self._by_prompt.get(key) or []
        ticket = bucket.pop(0) if bucket else None
        if ticket is not None:
            self._unmatched = [t for t in self._unmatched if t["id"] != ticket["id"]]
            if probe_id:
                self.assignments[ticket["id"]] = probe_id
        return ticket

    def by_id(self, ticket_id: str | None, probe_id: str | None = None) -> dict[str, Any] | None:
        if not ticket_id:
            return None
        ticket = self._by_id.get(ticket_id)
        if ticket is not None:
            self._unmatched = [t for t in self._unmatched if t["id"] != ticket_id]
            for bucket in self._by_prompt.values():
                if ticket in bucket:
                    bucket.remove(ticket)
            if probe_id:
                self.assignments[ticket_id] = probe_id
        return ticket

    @property
    def unmatched(self) -> list[dict[str, Any]]:
        return list(self._unmatched)


async def campaign_tickets(campaign_id: str) -> list[dict[str, Any]]:
    async with session_scope() as session:
        rows = list((await session.execute(select(Ticket).where(Ticket.campaign_id == campaign_id).order_by(Ticket.created_at.asc(), Ticket.number.asc()))).scalars())
        out: list[dict[str, Any]] = []
        for t in rows:
            messages = (t.normalized or {}).get("messages") or []
            last_user = next((m.get("content") for m in reversed(messages) if m.get("role") == "user"), "") or ""
            out.append({"id": t.id, "status": t.status, "prompt": normalize_text(str(last_user)), "response_preview": t.response_preview or "", "latency_ms": t.latency_ms, "risk_score": t.risk_score, "response_findings": list(t.response_findings or []), "decided_by": t.decided_by, "error": t.error or ""})
        return out


async def load_matcher(campaign_id: str) -> TicketMatcher:
    return TicketMatcher(await campaign_tickets(campaign_id))


async def assign_probe_ids(assignments: dict[str, str]) -> None:
    if not assignments:
        return
    async with session_scope() as session:
        for ticket_id, probe_id in assignments.items():
            await session.execute(update(Ticket).where(Ticket.id == ticket_id).values(probe_id=probe_id[:80]))


def verdict_for_ticket_status(status: str | None) -> str | None:
    """BLOCKED / ERROR when the gateway never relayed a model answer, else None (evaluate the text)."""
    if status in (TicketStatus.DENIED.value, TicketStatus.EXPIRED.value):
        return BLOCKED
    if status == TicketStatus.FAILED.value:
        return ERROR
    return None


def campaign_options(campaign: Campaign) -> dict[str, Any]:
    options = (campaign.config or {}).get("options")
    return dict(options) if isinstance(options, dict) else {}

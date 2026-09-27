"""Run orchestration: intake, inventory, engines, de-duplication, persistence and live progress.

One CodeReviewRunner is shared process-wide. Each run is an asyncio task; blocking work
(cloning, extraction, the rules engine) runs in worker threads and scanners run as
subprocesses, so the event loop stays responsive and runs can be cancelled.
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import time
from collections.abc import Callable
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import service as audit
from ..db import session_scope
from ..logging import broadcaster, get_logger
from ..models import CodeReviewRun, CodeReviewStatus, utcnow
from . import intake
from .config import ENGINES, PACKS, get_config
from .engines import bandit_engine, llm_engine, rules_engine, semgrep_engine, typesafe_engine
from .findings import Finding, dedupe
from .inventory import WalkStats, build_inventory, walk_files
from .secrets import mask_secrets, redact_mapping, redact_url
from .service import compute_summary, finding_row, finding_to_dict

log = get_logger("aisrf.codereview.engine")
CHANNEL = "codereview"


class _RunState:
    def __init__(self) -> None:
        self.task: asyncio.Task[None] | None = None
        self.cancelled = False


def _publish(run_id: str, event: str, **payload: Any) -> None:
    broadcaster.publish(CHANNEL, {"event": event, "run_id": run_id, **payload})


def _source_ref(source: dict[str, Any]) -> str:
    kind = str(source.get("type") or "")
    if kind in ("git", "url"):
        return redact_url(str(source.get("url") or ""))[:800]
    if kind == "path":
        return str(source.get("path") or "")[:800]
    if kind == "zip":
        return str(source.get("filename") or "upload")[:800]
    return f"snippet ({source.get('language') or 'python'})"


def normalize_options(options: dict[str, Any] | None, cfg: dict[str, Any]) -> dict[str, Any]:
    options = options or {}
    packs = [p for p in (options.get("packs") or []) if p in PACKS] or list(PACKS)
    engines = [e for e in (options.get("engines") or []) if e in ENGINES] or list(
        cfg.get("default_engines") or ["rules", "semgrep", "bandit"]
    )
    max_files = int(options.get("max_files") or 0) or int(cfg.get("max_files") or 20000)
    return {
        "packs": packs,
        "engines": engines,
        "include": [str(x) for x in (options.get("include") or []) if str(x).strip()],
        "exclude": [str(x) for x in (options.get("exclude") or []) if str(x).strip()],
        "max_files": min(max_files, int(cfg.get("max_files") or 20000)),
    }


class CodeReviewRunner:
    def __init__(self) -> None:
        self._runs: dict[str, _RunState] = {}

    async def create_run(
        self,
        session: AsyncSession,
        *,
        name: str,
        source: dict[str, Any],
        options: dict[str, Any] | None,
        created_by: str,
    ) -> CodeReviewRun:
        cfg = get_config()
        opts = normalize_options(options, cfg)
        stored_source = redact_mapping(
            {
                k: v
                for k, v in source.items()
                if k
                in (
                    "type",
                    "url",
                    "ref",
                    "provider",
                    "path",
                    "filename",
                    "language",
                    "credential_id",
                    "username",
                )
            }
        )
        run = CodeReviewRun(
            name=(name or "").strip()[:160] or f"review {utcnow().strftime('%Y-%m-%d %H:%M')}",
            source_type=str(source.get("type") or "zip"),
            source_ref=_source_ref(source),
            status=CodeReviewStatus.CREATED.value,
            config={**opts, "source": stored_source},
            created_by=created_by,
        )
        session.add(run)
        await session.flush()
        _publish(run.id, "run.status", status=run.status, stage="created")
        return run

    async def start(self, run_id: str, source: dict[str, Any]) -> None:
        state = self._runs.get(run_id)
        if state and state.task and not state.task.done():
            return
        state = _RunState()
        self._runs[run_id] = state
        state.task = asyncio.create_task(self._run(run_id, dict(source), state), name=f"codereview-{run_id}")

    async def cancel(self, run_id: str) -> bool:
        state = self._runs.get(run_id)
        running = bool(state and state.task and not state.task.done())
        if state:
            state.cancelled = True
            if state.task and not state.task.done():
                state.task.cancel()
        async with session_scope() as session:
            run = await session.get(CodeReviewRun, run_id)
            if run and run.status in (
                CodeReviewStatus.CREATED.value,
                CodeReviewStatus.FETCHING.value,
                CodeReviewStatus.ANALYZING.value,
            ):
                run.status = CodeReviewStatus.CANCELLED.value
                run.finished_at = utcnow()
                run.stage = "cancelled"
        _publish(run_id, "run.status", status=CodeReviewStatus.CANCELLED.value, stage="cancelled")
        return running

    def is_running(self, run_id: str) -> bool:
        state = self._runs.get(run_id)
        return bool(state and state.task and not state.task.done())

    async def wait(self, run_id: str, timeout: float | None = None) -> None:
        state = self._runs.get(run_id)
        if state and state.task:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await asyncio.wait_for(asyncio.shield(state.task), timeout=timeout)

    async def shutdown(self) -> None:
        tasks = [s.task for s in self._runs.values() if s.task and not s.task.done()]
        for s in self._runs.values():
            s.cancelled = True
            if s.task and not s.task.done():
                s.task.cancel()
        for t in tasks:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await t

    # ---- pipeline -------------------------------------------------------------------------------
    async def _set(self, run_id: str, **fields: Any) -> None:
        async with session_scope() as session:
            run = await session.get(CodeReviewRun, run_id)
            if run is None:
                return
            for k, v in fields.items():
                setattr(run, k, v)

    async def _run(self, run_id: str, source: dict[str, Any], state: _RunState) -> None:
        cfg = get_config()
        started = time.perf_counter()
        loop = asyncio.get_running_loop()
        engine_status: dict[str, Any] = {}
        try:
            async with session_scope() as session:
                run = await session.get(CodeReviewRun, run_id)
                if run is None:
                    return
                opts = dict(run.config or {})
                created_by = run.created_by
                run.status = CodeReviewStatus.FETCHING.value
                run.stage = "intake"
                run.started_at = utcnow()
                run.error = ""
            _publish(run_id, "run.status", status=CodeReviewStatus.FETCHING.value, stage="intake")
            with contextlib.suppress(Exception):
                await asyncio.to_thread(intake.cleanup_expired)
            result = await asyncio.to_thread(intake.acquire, run_id, source, opts, cfg)
            src_dir = result.src_dir
            work_dir = src_dir.parent
            await self._set(
                run_id, work_dir=str(work_dir), source_ref=result.source_ref[:800], stage="inventory"
            )
            self._check_cancel(state)
            _publish(
                run_id,
                "run.progress",
                status=CodeReviewStatus.FETCHING.value,
                stage="inventory",
                done=0,
                total=0,
            )

            stats = WalkStats()
            walk_cfg = {**cfg, "max_files": opts.get("max_files") or cfg.get("max_files")}
            files = await asyncio.to_thread(
                lambda: list(
                    walk_files(
                        src_dir,
                        walk_cfg,
                        include=opts.get("include"),
                        exclude=opts.get("exclude"),
                        max_files=opts.get("max_files"),
                        stats=stats,
                    )
                )
            )
            inventory = await asyncio.to_thread(build_inventory, src_dir, files)
            inv = inventory.to_dict()
            inv["skipped"] = {
                "too_large": stats.skipped_large,
                "binary": stats.skipped_binary,
                "excluded": stats.skipped_excluded,
            }
            inv["truncated"] = stats.truncated
            inv["intake"] = {
                k: v
                for k, v in result.detail.items()
                if k
                in (
                    "commit",
                    "branch",
                    "ref",
                    "method",
                    "kind",
                    "files",
                    "written",
                    "copied",
                    "truncated",
                    "language",
                )
            }
            await self._set(
                run_id,
                inventory=inv,
                file_count=inventory.files,
                loc=inventory.loc,
                status=CodeReviewStatus.ANALYZING.value,
                stage="rules",
            )
            _publish(
                run_id,
                "run.status",
                status=CodeReviewStatus.ANALYZING.value,
                stage="rules",
                files=inventory.files,
                loc=inventory.loc,
            )
            self._check_cancel(state)

            engines = list(opts.get("engines") or ["rules"])
            packs = list(opts.get("packs") or list(PACKS))
            all_findings: list[Finding] = []
            if "rules" in engines:
                t0 = time.perf_counter()

                def progress(done: int, total: int) -> None:
                    loop.call_soon_threadsafe(
                        functools.partial(
                            _publish,
                            run_id,
                            "run.progress",
                            status=CodeReviewStatus.ANALYZING.value,
                            stage="rules",
                            done=done,
                            total=total,
                        )
                    )

                found = await asyncio.to_thread(
                    rules_engine.run_rules,
                    files,
                    inv,
                    packs,
                    should_stop=lambda: state.cancelled,
                    progress=progress,
                )
                all_findings.extend(found)
                engine_status["rules"] = {
                    "engine": "rules",
                    "available": True,
                    "findings": len(found),
                    "seconds": round(time.perf_counter() - t0, 2),
                }
                self._check_cancel(state)
            if "semgrep" in engines:
                await self._stage(run_id, "semgrep", len(all_findings))
                t0 = time.perf_counter()
                found, status = await self._safe(semgrep_engine.run_semgrep(src_dir, packs, cfg), "semgrep")
                all_findings.extend(found)
                engine_status["semgrep"] = {**status, "seconds": round(time.perf_counter() - t0, 2)}
                self._check_cancel(state)
            if "bandit" in engines:
                await self._stage(run_id, "bandit", len(all_findings))
                t0 = time.perf_counter()
                found, status = await self._safe(bandit_engine.run_bandit(src_dir, cfg), "bandit")
                all_findings.extend(found)
                engine_status["bandit"] = {**status, "seconds": round(time.perf_counter() - t0, 2)}
                self._check_cancel(state)
            if "typesafe" in engines:
                # triages the findings collected so far in place (true positive, exploitability, likely false positives)
                await self._stage(run_id, "typesafe", len(all_findings))
                t0 = time.perf_counter()
                found, status = await self._safe(
                    typesafe_engine.run_typesafe_triage(
                        files, all_findings, cfg, should_stop=lambda: state.cancelled
                    ),
                    "typesafe",
                )
                all_findings.extend(found)
                engine_status["typesafe"] = {**status, "seconds": round(time.perf_counter() - t0, 2)}
                self._check_cancel(state)
            if "llm" in engines:
                # with TypeSafe triage in place the LLM pass only sees the uncertain findings, and only when escalation is on
                llm_input, skip_reason = typesafe_engine.escalation_subset(
                    all_findings, engine_status.get("typesafe")
                )
                if skip_reason:
                    engine_status["llm"] = {
                        "engine": "llm",
                        "available": False,
                        "findings": 0,
                        "error": skip_reason,
                    }
                else:
                    await self._stage(run_id, "llm", len(all_findings))
                    t0 = time.perf_counter()
                    found, status = await self._safe(
                        llm_engine.run_llm_review(files, llm_input, cfg, should_stop=lambda: state.cancelled),
                        "llm",
                    )
                    all_findings.extend(found)
                    engine_status["llm"] = {**status, "seconds": round(time.perf_counter() - t0, 2)}
                    self._check_cancel(state)

            unique = dedupe(all_findings)
            unique = [f for f in unique if f.pack in packs or f.engine in ("bandit", "llm")]
            duration = round(time.perf_counter() - started, 2)
            await self._stage(run_id, "persist", len(unique))
            async with session_scope() as session:
                run = await session.get(CodeReviewRun, run_id)
                if run is None:
                    return
                rows = [finding_row(run_id, f) for f in unique]
                session.add_all(rows)
                await session.flush()
                run.summary = compute_summary([finding_to_dict(r) for r in rows], engine_status, duration)
                run.finding_count = len(rows)
                run.status = CodeReviewStatus.COMPLETED.value
                run.stage = "completed"
                run.finished_at = utcnow()
                await audit.record(
                    session,
                    created_by or "system",
                    "codereview.run.completed",
                    "codereview_run",
                    run_id,
                    {
                        "findings": len(rows),
                        "files": run.file_count,
                        "risk_score": run.summary.get("risk_score"),
                    },
                )
            _publish(
                run_id,
                "run.status",
                status=CodeReviewStatus.COMPLETED.value,
                stage="completed",
                findings=len(unique),
                risk_score=run.summary.get("risk_score"),
                summary=run.summary,
            )
            log.info("codereview.run.completed", run_id=run_id, findings=len(unique), duration_s=duration)
        except asyncio.CancelledError:
            await self._set(
                run_id, status=CodeReviewStatus.CANCELLED.value, stage="cancelled", finished_at=utcnow()
            )
            _publish(run_id, "run.status", status=CodeReviewStatus.CANCELLED.value, stage="cancelled")
            raise
        except intake.IntakeError as exc:
            await self._fail(run_id, f"intake failed: {exc}")
        except Exception as exc:
            log.exception("codereview.run.failed", run_id=run_id)
            await self._fail(run_id, f"{type(exc).__name__}: {exc}")

    async def _stage(self, run_id: str, stage: str, found: int) -> None:
        await self._set(run_id, stage=stage)
        _publish(
            run_id, "run.progress", status=CodeReviewStatus.ANALYZING.value, stage=stage, done=found, total=0
        )

    @staticmethod
    async def _safe(coro: Any, name: str) -> tuple[list[Finding], dict[str, Any]]:
        try:
            return await coro
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.warning("codereview.engine.error", engine=name, error=f"{type(exc).__name__}: {exc}")
            return [], {
                "engine": name,
                "available": False,
                "findings": 0,
                "error": f"{type(exc).__name__}: {str(exc)[:300]}",
            }

    @staticmethod
    def _check_cancel(state: _RunState) -> None:
        if state.cancelled:
            raise asyncio.CancelledError()

    async def _fail(self, run_id: str, message: str) -> None:
        message = mask_secrets(redact_url(message))[:4000]
        async with session_scope() as session:
            run = await session.get(CodeReviewRun, run_id)
            if run is None:
                return
            run.status = CodeReviewStatus.FAILED.value
            run.stage = "failed"
            run.error = message
            run.finished_at = utcnow()
            await audit.record(
                session,
                run.created_by or "system",
                "codereview.run.failed",
                "codereview_run",
                run_id,
                {"error": message[:300]},
            )
        _publish(run_id, "run.status", status=CodeReviewStatus.FAILED.value, stage="failed", error=message)


codereview_runner = CodeReviewRunner()
StopFn = Callable[[], bool]

"""Report builder for the reports subsystem (kind "codereview")."""

from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from ..reports.model import ChartSection, FindingsSection, KeyValueSection, Report, TableSection, TextSection
from ..taxonomy import OWASP_LLM_TOP10
from . import service
from .findings import SEVERITIES
from .sarif import render_sarif


class RunNotFound(LookupError):
    pass


def _short(text: Any, limit: int = 160) -> str:
    s = " ".join(str(text or "").split())
    return s if len(s) <= limit else s[: limit - 3] + "..."


async def load_run(session: AsyncSession, run_id: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    run = await service.get_run(session, run_id)
    if run is None:
        raise RunNotFound(f"code review run {run_id} not found")
    rows, _ = await service.list_findings(session, run_id, limit=5000)
    return service.run_to_dict(run), [service.finding_to_dict(r) for r in rows]


def build_report(run: dict[str, Any], findings: list[dict[str, Any]]) -> Report:
    summary = run.get("summary") or {}
    inv = run.get("inventory") or {}
    report = Report(
        title=f"Code review: {run.get('name') or run.get('id')}",
        subtitle=f"{run.get('id')} ({run.get('status')}), risk {summary.get('risk_level', 'NONE')} {summary.get('risk_score', 0)}, {summary.get('open', 0)} open findings",
        meta={"kind": "codereview", "run_id": run.get("id"), "status": run.get("status"), "risk_score": summary.get("risk_score"), "findings": len(findings)},
    )
    report.add(
        KeyValueSection(
            "Run",
            rows=[
                ("Id", run.get("id")),
                ("Name", run.get("name")),
                ("Source", f"{run.get('source_type')}: {run.get('source_ref')}"),
                ("Commit", ((inv.get("intake") or {}).get("commit") or "")),
                ("Status", run.get("status")),
                ("Created", f"{run.get('created_at')} by {run.get('created_by')}"),
                ("Finished", run.get("finished_at")),
                ("Files scanned", run.get("file_count")),
                ("Lines of code", run.get("loc")),
                ("Packs", ", ".join((run.get("config") or {}).get("packs") or [])),
                ("Engines", ", ".join((run.get("config") or {}).get("engines") or [])),
                ("Error", run.get("error") or ""),
            ],
        )
    )
    by_sev = summary.get("by_severity") or {}
    report.add(
        KeyValueSection(
            "Summary",
            rows=[("Risk score", summary.get("risk_score", 0)), ("Risk level", summary.get("risk_level", "NONE")), ("Open findings", summary.get("open", 0)), ("Dismissed", (summary.get("by_status") or {}).get("false_positive", 0)), ("Accepted", (summary.get("by_status") or {}).get("accepted", 0))]
            + [(f"Open {s.lower()}", by_sev.get(s, 0)) for s in SEVERITIES],
        )
    )
    if any(by_sev.get(s, 0) for s in SEVERITIES):
        report.add(ChartSection("Open findings by severity", chart="pie", labels=[s for s in SEVERITIES if by_sev.get(s, 0)], values=[float(by_sev.get(s, 0)) for s in SEVERITIES if by_sev.get(s, 0)]))
    by_pack = summary.get("by_pack") or {}
    if by_pack:
        report.add(ChartSection("Open findings by pack", chart="bar", labels=list(by_pack), values=[float(v) for v in by_pack.values()]))
    by_engine = summary.get("by_engine") or {}
    if by_engine:
        report.add(ChartSection("Open findings by engine", chart="bar", labels=list(by_engine), values=[float(v) for v in by_engine.values()]))
    owasp = summary.get("by_owasp") or {}
    report.add(TableSection("OWASP LLM Top 10 coverage", columns=["Id", "Name", "Open findings"], rows=[[oid, OWASP_LLM_TOP10[oid]["name"], (owasp.get(oid) or {}).get("count", 0)] for oid in OWASP_LLM_TOP10]))
    report.add(TableSection("Top rules", columns=["Rule", "Title", "Severity", "Count"], rows=[[r.get("rule_id"), r.get("title"), r.get("severity"), r.get("count")] for r in summary.get("top_rules") or []]))
    report.add(TableSection("Files with most findings", columns=["File", "Findings", "Max severity"], rows=[[r.get("file"), r.get("count"), r.get("max_severity")] for r in summary.get("top_files") or []]))
    langs = inv.get("languages") or {}
    report.add(TableSection("Languages", columns=["Language", "Files", "Lines"], rows=[[k, v.get("files"), v.get("loc")] for k, v in langs.items()]))
    report.add(TableSection("AI frameworks and SDKs", columns=["Framework", "Kind", "Files"], rows=[[f.get("name"), f.get("kind"), f.get("count")] for f in inv.get("frameworks") or []], notes="" if inv.get("frameworks") else "No AI framework imports detected."))
    report.add(TableSection("Model artifacts", columns=["Path", "Format", "Bytes", "Pickle based"], rows=[[a.get("path"), a.get("format"), a.get("bytes"), a.get("pickle_based")] for a in inv.get("model_artifacts") or []]))
    report.add(TableSection("Dependency manifests", columns=["Path", "Kind", "Dependencies", "Unpinned", "AI packages"], rows=[[m.get("path"), m.get("kind"), m.get("dependencies"), ", ".join(m.get("unpinned") or [])[:200], ", ".join(m.get("ai_packages") or [])] for m in inv.get("manifests") or []]))
    other = [("Prompt files", inv.get("prompt_files") or []), ("Secrets files", inv.get("secret_files") or []), ("CI configuration", inv.get("ci_configs") or []), ("Container files", inv.get("dockerfiles") or []), ("Tool calling", (inv.get("tool_calling") or {}).get("files") or []), ("MCP servers", inv.get("mcp_servers") or [])]
    report.add(TableSection("Inventory highlights", columns=["Item", "Count", "Examples"], rows=[[label, len(items), ", ".join(items[:5])] for label, items in other]))
    engines = summary.get("engines") or {}
    report.add(TableSection("Engines", columns=["Engine", "Available", "Findings", "Seconds", "Error"], rows=[[k, v.get("available"), v.get("findings"), v.get("seconds"), v.get("error") or ""] for k, v in engines.items()]))
    report.add(
        TableSection(
            "Findings",
            columns=["Rule", "Severity", "Confidence", "Pack", "Engine", "File", "Line", "Title", "Status", "OWASP", "CWE"],
            rows=[[f["rule_id"], f["severity"], f["confidence"], f["pack"], f["engine"], f["file"], f["line_start"], f["title"], f["status"], ", ".join(f.get("owasp") or []), f.get("cwe") or ""] for f in findings],
            role="cases",
        )
    )
    detail = [
        {
            "category": f.get("category") or f["pack"],
            "severity": f["severity"],
            "title": f"{f['rule_id']}: {f['title']}",
            "description": _short(f.get("description"), 600),
            "evidence": _short(f.get("snippet"), 400),
            "location": f"{f['file']}:{f['line_start']}",
            "rule_id": f["rule_id"],
            "pack": f["pack"],
            "engine": f["engine"],
            "file": f["file"],
            "line_start": f["line_start"],
            "line_end": f["line_end"],
            "confidence": f["confidence"],
            "cwe": f.get("cwe") or "",
            "owasp": f.get("owasp") or [],
            "status": f["status"],
            "fingerprint": f["fingerprint"],
            "remediation": _short(f.get("remediation"), 600),
        }
        for f in findings
    ]
    report.add(FindingsSection("Finding details", findings=detail))
    if not findings:
        report.add(TextSection("Notes", "No findings were recorded for this run."))
    return report


async def build_codereview_report(session: AsyncSession, run_id: str) -> Report:
    run, findings = await load_run(session, run_id)
    return build_report(run, findings)


async def build_codereview_sarif(session: AsyncSession, run_id: str, include_dismissed: bool = False) -> bytes:
    run, findings = await load_run(session, run_id)
    return render_sarif(run, findings, include_dismissed=include_dismissed)

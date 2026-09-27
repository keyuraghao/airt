"""Async report builders. Each one queries the database and returns a Report.

The red-team module (aisrf.redteam.service) is imported lazily so that reports keep
working, with empty campaign sections, when that module is unavailable.
"""

from __future__ import annotations

import importlib
import json
from collections import Counter
from datetime import datetime
from types import ModuleType
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from ..agents import service as agents
from ..audit import service as audit
from ..tickets import service as tickets
from .model import ChartSection, FindingsSection, KeyValueSection, Report, Section, TableSection, TextSection

VERDICT_ORDER: list[str] = ["VULNERABLE", "RESISTED", "BLOCKED", "INCONCLUSIVE", "ERROR", "PENDING"]
STATUS_ORDER: list[str] = ["PENDING", "APPROVED", "DENIED", "EXPIRED", "FORWARDING", "COMPLETED", "FAILED"]
RISK_ORDER: list[str] = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


class NotFound(LookupError):
    """Raised when the entity a report is about does not exist."""


def _redteam() -> ModuleType | None:
    try:
        return importlib.import_module("aisrf.redteam.service")
    except ImportError:
        return None


def _ts(value: datetime | None) -> str:
    return value.isoformat(timespec="seconds") if value else ""


def _short(text: Any, limit: int = 160) -> str:
    s = "" if text is None else str(text)
    s = " ".join(s.split())
    return s if len(s) <= limit else s[: limit - 3] + "..."


def _jsonish(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, default=str, ensure_ascii=False)
    return "" if value is None else str(value)


def _ordered(counter: dict[str, int], order: list[str]) -> list[tuple[str, int]]:
    known = [(k, counter[k]) for k in order if k in counter]
    extra = sorted((k, v) for k, v in counter.items() if k not in order)
    return known + extra


def _findings_of(ticket: Any) -> list[dict[str, Any]]:
    """All findings on a ticket (request and response side) tagged with the ticket id."""
    out: list[dict[str, Any]] = []
    for side, items in (("request", ticket.findings or []), ("response", ticket.response_findings or [])):
        for f in items:
            d = dict(f)
            d.setdefault("category", "unknown")
            d.setdefault("severity", "INFO")
            d.setdefault("title", d.get("category", "finding"))
            d["ticket_id"] = ticket.id
            d["ticket_number"] = ticket.number
            d["side"] = side
            out.append(d)
    return out


def _findings_breakdown(findings: list[dict[str, Any]]) -> list[Section]:
    if not findings:
        return [TextSection("Findings breakdown", "No findings were recorded in this scope.")]
    by_cat = Counter(str(f.get("category", "unknown")) for f in findings)
    by_sev = Counter(str(f.get("severity", "INFO")).upper() for f in findings)
    cats = sorted(by_cat.items(), key=lambda kv: (-kv[1], kv[0]))
    sev = _ordered(dict(by_sev), ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
    return [
        ChartSection(
            "Findings by category",
            chart="bar",
            labels=[c for c, _ in cats],
            values=[float(n) for _, n in cats],
        ),
        ChartSection(
            "Findings by severity", chart="pie", labels=[s for s, _ in sev], values=[float(n) for _, n in sev]
        ),
    ]


def _ticket_row(t: Any) -> list[Any]:
    return [
        t.number,
        t.id,
        getattr(getattr(t, "agent", None), "name", None) or t.agent_id,
        t.status,
        t.risk_level,
        t.risk_score,
        t.model,
        len(t.findings or []),
        t.decided_by or "",
        _ts(t.created_at),
        _short(t.prompt_preview, 120),
    ]


TICKET_COLUMNS: list[str] = [
    "#",
    "Ticket",
    "Agent",
    "Status",
    "Risk",
    "Score",
    "Model",
    "Findings",
    "Decided by",
    "Created",
    "Prompt",
]


async def _campaign_rows(
    session: AsyncSession, agent_id: str | None = None, limit: int = 20
) -> tuple[list[str], list[list[Any]]]:
    rt = _redteam()
    columns = [
        "Campaign",
        "Name",
        "Agent",
        "Target model",
        "Status",
        "Probes",
        "Completed",
        "Vulnerable",
        "Created",
        "Finished",
    ]
    if rt is None:
        return columns, []
    try:
        campaigns = await rt.list_campaigns(session, agent_id=agent_id)
    except Exception:
        return columns, []
    rows: list[list[Any]] = []
    for c in list(campaigns)[:limit]:
        d = rt.campaign_to_dict(c)
        summary = d.get("summary") or {}
        vulnerable = summary.get("vulnerable") if isinstance(summary, dict) else None
        if vulnerable is None and isinstance(summary, dict):
            vulnerable = (summary.get("by_verdict") or {}).get("VULNERABLE", 0)
        rows.append(
            [
                d.get("id"),
                d.get("name"),
                d.get("agent_id"),
                d.get("target_model"),
                d.get("status"),
                d.get("total_probes"),
                d.get("completed_probes"),
                vulnerable,
                d.get("created_at"),
                d.get("finished_at"),
            ]
        )
    return columns, rows


# --- summary ---------------------------------------------------------------------
async def build_summary_report(
    session: AsyncSession, since: datetime | None = None, until: datetime | None = None
) -> Report:
    st = await tickets.stats(session)
    rows, total = await tickets.list_tickets(session, since=since, until=until, limit=5000)
    agent_list = await agents.list_agents(session)
    names = {a.id: a.name for a in agent_list}
    scope = "all time" if not since and not until else f"{_ts(since) or 'start'} to {_ts(until) or 'now'}"
    report = Report(
        title="AISRF platform summary",
        subtitle=f"Scope: {scope}",
        meta={"kind": "summary", "since": _ts(since), "until": _ts(until), "tickets_in_scope": total},
    )
    report.add(
        KeyValueSection(
            "Overview",
            rows=[
                ("Tickets (all time)", st["total"]),
                ("Tickets in scope", total),
                ("Pending decisions", st["pending"]),
                ("Tickets last 24h", st["last_24h"]),
                ("Registered agents", len(agent_list)),
                ("Active agents", sum(1 for a in agent_list if a.is_active)),
                ("Avg upstream latency (ms)", st.get("avg_upstream_latency_ms")),
                ("Avg human decision time (s)", st.get("avg_human_decision_seconds")),
            ],
        )
    )
    by_status = _ordered(st["by_status"], STATUS_ORDER)
    by_risk = _ordered(st["by_risk_level"], RISK_ORDER)
    report.add(
        ChartSection(
            "Tickets by status",
            chart="bar",
            labels=[k for k, _ in by_status],
            values=[float(v) for _, v in by_status],
        )
    )
    report.add(
        ChartSection(
            "Tickets by risk level",
            chart="pie",
            labels=[k for k, _ in by_risk],
            values=[float(v) for _, v in by_risk],
        )
    )
    report.add(
        TableSection(
            "Tickets by agent",
            columns=["Agent", "Agent id", "Tickets"],
            rows=[
                [names.get(x["agent_id"], x["agent_id"]), x["agent_id"], x["count"]] for x in st["by_agent"]
            ],
        )
    )
    by_model = Counter(t.model or "(unknown)" for t in rows)
    report.add(
        TableSection(
            "Tickets by model (in scope)",
            columns=["Model", "Tickets"],
            rows=[[m, n] for m, n in by_model.most_common()],
        )
    )
    decision_rows: list[list[Any]] = []
    for t in rows:
        if t.decided_at and t.created_at and t.decided_by and t.decided_by != "policy":
            decision_rows.append(
                [t.number, t.decided_by, round((t.decided_at - t.created_at).total_seconds(), 1)]
            )
    if decision_rows:
        latencies = [r[2] for r in decision_rows]
        report.add(
            KeyValueSection(
                "Decision latency (human decisions in scope)",
                rows=[
                    ("Decisions", len(latencies)),
                    ("Mean seconds", round(sum(latencies) / len(latencies), 1)),
                    ("Max seconds", max(latencies)),
                    ("Min seconds", min(latencies)),
                ],
            )
        )
    findings = [f for t in rows for f in _findings_of(t)]
    for sec in _findings_breakdown(findings):
        report.add(sec)
    top = Counter(str(f.get("category", "unknown")) for f in findings).most_common(10)
    report.add(
        TableSection("Top finding categories", columns=["Category", "Count"], rows=[[c, n] for c, n in top])
    )
    report.add(
        TableSection(
            "Agents",
            columns=[
                "Agent id",
                "Name",
                "Owner",
                "Provider",
                "Requires approval",
                "Active",
                "Requests",
                "Last seen",
            ],
            rows=[
                [
                    a.id,
                    a.name,
                    a.owner,
                    a.upstream_provider,
                    a.require_approval,
                    a.is_active,
                    a.request_count,
                    _ts(a.last_seen_at),
                ]
                for a in agent_list
            ],
        )
    )
    columns, crows = await _campaign_rows(session)
    report.add(
        TableSection(
            "Recent campaigns", columns=columns, rows=crows, notes="" if crows else "No campaigns recorded."
        )
    )
    return report


# --- tickets ---------------------------------------------------------------------
async def build_tickets_report(
    session: AsyncSession,
    status: str | list[str] | None = None,
    agent_id: str | None = None,
    min_risk: int | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = 500,
    **extra: Any,
) -> Report:
    rows, total = await tickets.list_tickets(
        session,
        status=status,
        agent_id=agent_id,
        min_risk=min_risk,
        since=since,
        until=until,
        limit=limit,
        model=extra.get("model"),
        source=extra.get("source"),
        campaign_id=extra.get("campaign_id"),
        search=extra.get("search"),
    )
    filters = {
        "status": status,
        "agent_id": agent_id,
        "min_risk": min_risk,
        "since": _ts(since),
        "until": _ts(until),
        "limit": limit,
    }
    filters.update({k: v for k, v in extra.items() if v})
    active = {k: v for k, v in filters.items() if v not in (None, "", [])}
    report = Report(
        title="Tickets report",
        subtitle=f"{len(rows)} of {total} matching tickets",
        meta={"kind": "tickets", "filters": active, "total": total},
    )
    report.add(
        KeyValueSection(
            "Filters", rows=[(k, _jsonish(v)) for k, v in active.items()] or [("filters", "none")]
        )
    )
    report.add(
        TableSection("Tickets", columns=TICKET_COLUMNS, rows=[_ticket_row(t) for t in rows], role="cases")
    )
    findings = [f for t in rows for f in _findings_of(t)]
    for sec in _findings_breakdown(findings):
        report.add(sec)
    report.add(FindingsSection("Findings", findings=findings))
    return report


# --- single ticket ---------------------------------------------------------------
def _messages_table(normalized: dict[str, Any]) -> TableSection:
    rows: list[list[Any]] = []
    system = normalized.get("system")
    if system:
        rows.append([0, "system", _short(system, 1000), ""])
    for i, m in enumerate(normalized.get("messages") or [], start=1):
        if not isinstance(m, dict):
            rows.append([i, "", _short(m, 1000), ""])
            continue
        content = m.get("content")
        if isinstance(content, list):
            content = " ".join(
                str(part.get("text", "")) if isinstance(part, dict) else str(part) for part in content
            )
        tool = m.get("tool_calls") or m.get("tool_call_id") or m.get("name") or ""
        rows.append([i, m.get("role", ""), _short(content, 1000), _short(_jsonish(tool), 200)])
    return TableSection(
        "Normalized messages",
        columns=["#", "Role", "Content", "Tool"],
        rows=rows,
        notes=f"Model: {normalized.get('model', '')}; provider: {normalized.get('provider', '')}; stream: {normalized.get('stream', False)}",
    )


async def build_ticket_report(session: AsyncSession, ticket_id: str) -> Report:
    t = await tickets.get_ticket(session, ticket_id)
    if t is None:
        raise NotFound(f"ticket {ticket_id} not found")
    d = tickets.ticket_to_dict(t)
    report = Report(
        title=f"Ticket #{t.number} dossier",
        subtitle=f"{t.id} ({t.status}, risk {t.risk_level} {t.risk_score})",
        meta={"kind": "ticket", "ticket_id": t.id, "number": t.number, "status": t.status},
    )
    meta_keys = [
        "id",
        "number",
        "status",
        "source",
        "agent_name",
        "agent_id",
        "correlation_id",
        "method",
        "path",
        "upstream_url",
        "model",
        "is_stream",
        "client_ip",
        "user_agent",
        "risk_score",
        "risk_level",
        "analysis_ms",
        "policy_action",
        "decided_by",
        "decision_note",
        "decided_at",
        "expires_at",
        "forwarded_at",
        "response_status",
        "latency_ms",
        "campaign_id",
        "probe_id",
        "created_at",
        "updated_at",
    ]
    report.add(KeyValueSection("Metadata", rows=[(k, d.get(k)) for k in meta_keys]))
    report.add(_messages_table(t.normalized or {}))
    if t.normalized and t.normalized.get("tools"):
        tools = t.normalized["tools"]
        report.add(
            TableSection(
                "Declared tools",
                columns=["Tool", "Description"],
                rows=[
                    [
                        (x.get("name") or (x.get("function") or {}).get("name", ""))
                        if isinstance(x, dict)
                        else str(x),
                        _short(
                            (x.get("description") or (x.get("function") or {}).get("description", ""))
                            if isinstance(x, dict)
                            else "",
                            300,
                        ),
                    ]
                    for x in tools
                ],
            )
        )
    findings = _findings_of(t)
    report.add(FindingsSection("Findings", findings=findings))
    policy = t.policy_decision or {}
    report.add(
        KeyValueSection(
            "Policy decision",
            rows=[(k, _jsonish(v)) for k, v in policy.items()] or [("action", "none recorded")],
        )
    )
    events = await tickets.list_events(session, t.id)
    report.add(
        TableSection(
            "Timeline",
            columns=["Time", "Event", "Actor", "Detail"],
            rows=[[_ts(e.ts), e.event_type, e.actor, _short(_jsonish(e.detail), 300)] for e in events],
        )
    )
    preview = t.response_preview or _short(t.response_body, 500)
    report.add(TextSection("Response preview", preview or "(no response recorded)", markdown=False))
    if t.error:
        report.add(TextSection("Error", t.error, markdown=False))
    return report


# --- agent -----------------------------------------------------------------------
async def build_agent_report(session: AsyncSession, agent_id: str, since: datetime | None = None) -> Report:
    a = await agents.get_agent(session, agent_id)
    if a is None:
        raise NotFound(f"agent {agent_id} not found")
    d = agents.agent_to_dict(a)
    st = await agents.agent_stats(session, a.id)
    report = Report(
        title=f"Agent report: {a.name}",
        subtitle=a.id,
        meta={"kind": "agent", "agent_id": a.id, "since": _ts(since)},
    )
    config_keys = [
        "id",
        "name",
        "description",
        "owner",
        "tags",
        "api_key_prefix",
        "upstream_provider",
        "upstream_base_url",
        "has_upstream_key",
        "upstream_auth_header",
        "require_approval",
        "auto_approve_below_risk",
        "auto_deny_at_risk",
        "auto_deny_patterns",
        "allowed_paths",
        "allowed_models",
        "rate_limit_per_minute",
        "is_active",
        "request_count",
        "last_seen_at",
        "created_at",
    ]
    report.add(KeyValueSection("Configuration", rows=[(k, _jsonish(d.get(k))) for k in config_keys]))
    report.add(
        KeyValueSection(
            "Statistics",
            rows=[("Tickets", st["total"]), ("Average risk score", st["avg_risk"])]
            + [(f"Status {k}", v) for k, v in _ordered(st["by_status"], STATUS_ORDER)],
        )
    )
    by_status = _ordered(st["by_status"], STATUS_ORDER)
    if by_status:
        report.add(
            ChartSection(
                "Tickets by status",
                chart="bar",
                labels=[k for k, _ in by_status],
                values=[float(v) for _, v in by_status],
            )
        )
    rows, total = await tickets.list_tickets(session, agent_id=a.id, since=since, limit=500)
    report.add(
        TableSection(
            "Tickets",
            columns=TICKET_COLUMNS,
            rows=[_ticket_row(t) for t in rows],
            notes=f"{len(rows)} of {total} tickets shown.",
            role="cases",
        )
    )
    findings = [f for t in rows for f in _findings_of(t)]
    for sec in _findings_breakdown(findings):
        report.add(sec)
    report.add(FindingsSection("Findings", findings=findings))
    events = await agents.list_agent_events(session, agent_id=a.id, limit=200)
    if since is not None:
        events = [e for e in events if e.ts and e.ts >= since]
    report.add(
        TableSection(
            "Recent events",
            columns=["Time", "Level", "Event", "Ticket", "Detail"],
            rows=[
                [_ts(e.ts), e.level, e.event, e.ticket_id or "", _short(_jsonish(e.detail), 300)]
                for e in events
            ],
        )
    )
    columns, crows = await _campaign_rows(session, agent_id=a.id)
    if crows:
        report.add(TableSection("Campaigns", columns=columns, rows=crows))
    return report


# --- campaign --------------------------------------------------------------------
async def build_campaign_report(session: AsyncSession, campaign_id: str) -> Report:
    rt = _redteam()
    if rt is None:
        raise NotFound("red-team module is not available")
    c = await rt.get_campaign(session, campaign_id)
    if c is None:
        raise NotFound(f"campaign {campaign_id} not found")
    d = rt.campaign_to_dict(c)
    results_raw, total = await rt.list_results(session, campaign_id, limit=5000, offset=0)
    results = [rt.result_to_dict(r) for r in results_raw]
    report = Report(
        title=f"Campaign report: {d.get('name', campaign_id)}",
        subtitle=f"{d.get('id')} against {d.get('target_model') or 'target'} ({d.get('status')})",
        meta={"kind": "campaign", "campaign_id": d.get("id"), "status": d.get("status"), "results": total},
    )
    report.add(
        KeyValueSection(
            "Campaign",
            rows=[
                (k, _jsonish(d.get(k)))
                for k in [
                    "id",
                    "name",
                    "agent_id",
                    "target_model",
                    "status",
                    "total_probes",
                    "completed_probes",
                    "created_by",
                    "created_at",
                    "started_at",
                    "finished_at",
                    "error",
                ]
            ],
        )
    )
    config = d.get("config") or {}
    report.add(
        KeyValueSection(
            "Configuration", rows=[(k, _jsonish(v)) for k, v in config.items()] or [("config", "default")]
        )
    )
    by_verdict = Counter(str(r.get("verdict", "PENDING")) for r in results)
    summary = d.get("summary") or {}
    summary_rows: list[tuple[str, Any]] = [("Results", total)] + [
        (f"Verdict {k}", v) for k, v in _ordered(dict(by_verdict), VERDICT_ORDER)
    ]
    if by_verdict:
        summary_rows.append(
            (
                "Vulnerability rate",
                f"{100.0 * by_verdict.get('VULNERABLE', 0) / max(1, sum(by_verdict.values())):.1f}%",
            )
        )
    summary_rows.extend((k, _jsonish(v)) for k, v in summary.items() if not isinstance(v, (dict, list)))
    report.add(KeyValueSection("Summary", rows=summary_rows))
    ordered_verdicts = _ordered(dict(by_verdict), VERDICT_ORDER)
    if ordered_verdicts:
        report.add(
            ChartSection(
                "Results by verdict",
                chart="pie",
                labels=[k for k, _ in ordered_verdicts],
                values=[float(v) for _, v in ordered_verdicts],
            )
        )
    cats: dict[str, Counter[str]] = {}
    for r in results:
        cats.setdefault(str(r.get("category", "unknown")), Counter())[str(r.get("verdict", "PENDING"))] += 1
    cat_rows: list[list[Any]] = []
    for cat, counter in sorted(cats.items(), key=lambda kv: (-kv[1].get("VULNERABLE", 0), kv[0])):
        n = sum(counter.values())
        vuln = counter.get("VULNERABLE", 0)
        cat_rows.append(
            [
                cat,
                n,
                vuln,
                counter.get("RESISTED", 0),
                counter.get("BLOCKED", 0),
                counter.get("ERROR", 0) + counter.get("INCONCLUSIVE", 0) + counter.get("PENDING", 0),
                f"{100.0 * vuln / max(1, n):.1f}%",
            ]
        )
    report.add(
        TableSection(
            "Vulnerabilities by category",
            columns=["Category", "Probes", "Vulnerable", "Resisted", "Blocked", "Other", "Vulnerable %"],
            rows=cat_rows,
        )
    )
    if cat_rows:
        report.add(
            ChartSection(
                "Vulnerable probes by category",
                chart="bar",
                labels=[r[0] for r in cat_rows],
                values=[float(r[2]) for r in cat_rows],
            )
        )
    report.add(
        TableSection(
            "Probe results",
            columns=[
                "Result",
                "Probe",
                "Category",
                "Technique",
                "Severity",
                "Verdict",
                "Confidence",
                "Latency ms",
                "Ticket",
                "Prompt",
            ],
            rows=[
                [
                    r.get("id"),
                    r.get("probe_id"),
                    r.get("category"),
                    r.get("technique"),
                    r.get("severity"),
                    r.get("verdict"),
                    r.get("confidence"),
                    r.get("latency_ms"),
                    r.get("ticket_id") or "",
                    _short(r.get("prompt"), 120),
                ]
                for r in results
            ],
            role="cases",
        )
    )
    vulnerable = [r for r in results if str(r.get("verdict")) == "VULNERABLE"]
    vulnerable.sort(
        key=lambda r: (
            {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(str(r.get("severity", "")).upper(), 4),
            -float(r.get("confidence") or 0),
        )
    )
    findings: list[dict[str, Any]] = []
    for r in vulnerable[:200]:
        evidence = r.get("evidence")
        findings.append(
            {
                "category": r.get("category", "unknown"),
                "severity": str(r.get("severity", "MEDIUM")).upper(),
                "title": f"{r.get('category', 'probe')} / {r.get('technique') or 'direct'}: {r.get('probe_id')}",
                "description": _short(r.get("prompt"), 600),
                "evidence": _short(_jsonish(evidence) if not isinstance(evidence, str) else evidence, 600),
                "response": _short(r.get("response"), 600),
                "location": f"probe:{r.get('probe_id')}",
                "probe_id": r.get("probe_id"),
                "result_id": r.get("id"),
                "ticket_id": r.get("ticket_id"),
                "campaign_id": d.get("id"),
                "verdict": r.get("verdict"),
                "technique": r.get("technique"),
                "confidence": r.get("confidence"),
            }
        )
    report.add(FindingsSection("Top vulnerable probes", findings=findings))
    return report


# --- audit -----------------------------------------------------------------------
async def build_audit_report(session: AsyncSession, limit: int = 500) -> Report:
    entries = await audit.list_entries(session, limit=limit)
    verification = await audit.verify_chain(session)
    total = await audit.count_entries(session)
    report = Report(
        title="Audit log report",
        subtitle=f"{len(entries)} of {total} entries, chain {'intact' if verification.get('ok') else 'BROKEN'}",
        meta={"kind": "audit", "total": total, "verification": verification},
    )
    report.add(
        KeyValueSection(
            "Chain verification", rows=[(k, v) for k, v in verification.items()] + [("Entries in log", total)]
        )
    )
    by_action = Counter(e.action for e in entries).most_common()
    if by_action:
        report.add(
            ChartSection(
                "Entries by action",
                chart="bar",
                labels=[a for a, _ in by_action],
                values=[float(n) for _, n in by_action],
            )
        )
    report.add(
        TableSection(
            "Audit entries",
            columns=[
                "Id",
                "Time",
                "Actor",
                "Action",
                "Target type",
                "Target id",
                "Detail",
                "Hash",
                "Previous hash",
            ],
            rows=[
                [
                    e.id,
                    _ts(e.ts),
                    e.actor,
                    e.action,
                    e.target_type,
                    e.target_id,
                    _short(_jsonish(e.detail), 300),
                    e.hash,
                    e.prev_hash,
                ]
                for e in entries
            ],
        )
    )
    return report


# --- code review -------------------------------------------------------------------
async def build_codereview_report(session: AsyncSession, run_id: str) -> Report:
    """One static analysis run: summary tiles, inventory, engines and every finding with location."""
    try:
        from ..codereview.report import RunNotFound
        from ..codereview.report import build_codereview_report as _build
    except ImportError as exc:  # the module is optional at import time
        raise NotFound(f"code review module is not available: {exc}") from None
    try:
        return await _build(session, run_id)
    except RunNotFound as exc:
        raise NotFound(str(exc)) from None


BUILDERS: dict[str, Any] = {
    "summary": build_summary_report,
    "tickets": build_tickets_report,
    "ticket": build_ticket_report,
    "agent": build_agent_report,
    "campaign": build_campaign_report,
    "audit": build_audit_report,
    "codereview": build_codereview_report,
}

KINDS: list[dict[str, Any]] = [
    {
        "kind": "summary",
        "description": "Platform overview: ticket statistics, decision latency, findings, agents and recent campaigns.",
        "params": ["since", "until"],
    },
    {
        "kind": "tickets",
        "description": "Table of tickets matching filters plus a findings breakdown.",
        "params": ["status", "agent_id", "min_risk", "since", "until", "limit"],
    },
    {
        "kind": "ticket",
        "description": "Full dossier for one ticket: metadata, messages, findings, policy, timeline and response preview.",
        "params": ["ticket_id"],
    },
    {
        "kind": "agent",
        "description": "One agent: configuration, statistics, tickets and recent events.",
        "params": ["agent_id", "since"],
    },
    {
        "kind": "campaign",
        "description": "One red-team campaign: configuration, summary, per-category vulnerabilities and probe results.",
        "params": ["campaign_id"],
    },
    {"kind": "audit", "description": "Audit log entries with hash-chain verification.", "params": ["limit"]},
    {
        "kind": "codereview",
        "description": "One code review run: risk summary, inventory, engines and every finding with file and line (SARIF carries rule ids, locations and fingerprints).",
        "params": ["run_id"],
    },
]

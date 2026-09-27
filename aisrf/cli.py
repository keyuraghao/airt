"""AISRF command line interface.

Local commands (serve, init-db, create-reviewer, agent ...) talk to the database
directly. Remote commands (tickets, redteam, report, audit, mcp) talk to a running
gateway over its REST API and need --url / --token (or AISRF_URL / AISRF_ADMIN_API_TOKEN).
"""
from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Annotated, Any, TypeVar

import httpx
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import __version__

T = TypeVar("T")
DEFAULT_URL = "http://127.0.0.1:8080"
TERMINAL_CAMPAIGN_STATES = {"completed", "finished", "done", "failed", "cancelled", "canceled", "error", "aborted"}
console = Console()
err_console = Console(stderr=True)
app = typer.Typer(help="AISRF - AI Security & Research Framework.", no_args_is_help=True, rich_markup_mode="rich")
agent_app = typer.Typer(help="Manage registered agents (direct database access).", no_args_is_help=True)
tickets_app = typer.Typer(help="Review intercepted tickets on a running gateway.", no_args_is_help=True)
redteam_app = typer.Typer(help="Browse the probe corpus and run red-team campaigns.", no_args_is_help=True)
audit_app = typer.Typer(help="Inspect the tamper-evident audit log.", no_args_is_help=True)
codereview_app = typer.Typer(help="Static analysis of LLM application source code.", no_args_is_help=True)
app.add_typer(agent_app, name="agent")
app.add_typer(tickets_app, name="tickets")
app.add_typer(redteam_app, name="redteam")
app.add_typer(audit_app, name="audit")
app.add_typer(codereview_app, name="codereview")
TERMINAL_RUN_STATES = {"completed", "failed", "cancelled"}
UrlOpt = Annotated[str, typer.Option("--url", envvar="AISRF_URL", help="Base URL of the running gateway.", show_default=True)]
TokenOpt = Annotated[str | None, typer.Option("--token", envvar="AISRF_ADMIN_API_TOKEN", help="Admin API token (AISRF_ADMIN_API_TOKEN on the server).", show_default=False)]


# --- helpers -----------------------------------------------------------------------
def _fail(message: str, code: int = 1) -> None:
    err_console.print(f"[red]error:[/red] {message}")
    raise typer.Exit(code)


def _run_db(fn: Callable[[], Awaitable[T]]) -> T:
    """Run an async DB task in a fresh event loop with the schema ensured and the engine disposed afterwards."""
    from .db import dispose_db, init_db

    async def runner() -> T:
        await init_db()
        try:
            return await fn()
        finally:
            await dispose_db()

    return asyncio.run(runner())


def _fmt(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (dict, list)):
        return json.dumps(value, default=str)
    return str(value)


def _kv_table(title: str, data: dict[str, Any]) -> Table:
    table = Table(title=title, show_header=False, expand=False)
    table.add_column("key", style="bold")
    table.add_column("value", overflow="fold")
    for key, value in data.items():
        table.add_row(str(key), _fmt(value))
    return table


def _rows_table(title: str, rows: list[dict[str, Any]], columns: list[str] | None = None) -> Table:
    columns = columns or (list(rows[0].keys()) if rows else [])
    table = Table(title=title, expand=False)
    for col in columns:
        table.add_column(col, overflow="fold")
    for row in rows:
        table.add_row(*[_fmt(row.get(col)) for col in columns])
    return table


class Remote:
    """Synchronous REST client for the remote commands."""

    def __init__(self, url: str, token: str | None) -> None:
        if not token:
            _fail("no admin token: pass --token or set AISRF_ADMIN_API_TOKEN")
        self.url = url.rstrip("/")
        self.client = httpx.Client(base_url=self.url, headers={"Authorization": f"Bearer {token}"}, timeout=httpx.Timeout(120.0, connect=10.0))

    def request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        try:
            response = self.client.request(method, path, **kwargs)
        except httpx.HTTPError as exc:
            _fail(f"cannot reach {self.url}: {exc}")
        if response.status_code >= 400:
            detail: Any = response.text
            try:
                body = response.json()
                detail = body.get("detail") or body.get("error") or body if isinstance(body, dict) else body
            except ValueError:
                pass
            _fail(f"{method} {path} failed with HTTP {response.status_code}: {detail}")
        return response

    def json(self, method: str, path: str, **kwargs: Any) -> Any:
        response = self.request(method, path, **kwargs)
        return response.json() if response.content else {}


# --- local commands ------------------------------------------------------------------
@app.command()
def version() -> None:
    """Print the AISRF version."""
    typer.echo(f"aisrf {__version__}")


@app.command()
def serve(
    host: Annotated[str | None, typer.Option(help="Bind address (default AISRF_HOST or 0.0.0.0).")] = None,
    port: Annotated[int | None, typer.Option(help="Bind port (default AISRF_PORT or 8080).")] = None,
    workers: Annotated[int | None, typer.Option(help="Number of worker processes (default AISRF_WORKERS).")] = None,
    reload: Annotated[bool, typer.Option("--reload", help="Auto reload on code changes (development only).")] = False,
) -> None:
    """Run the gateway with uvicorn."""
    import uvicorn

    from .config import get_settings

    settings = get_settings()
    kwargs: dict[str, Any] = {"host": host or settings.host, "port": port or settings.port, "factory": True, "reload": reload, "log_level": settings.log_level.lower()}
    worker_count = workers or settings.workers
    if worker_count > 1 and not reload:
        kwargs["workers"] = worker_count
    uvicorn.run("aisrf.main:create_app", **kwargs)


@app.command("init-db")
def init_db_command() -> None:
    """Create the database schema and the default admin reviewer."""
    from .auth import ensure_admin
    from .config import get_settings
    from .db import get_sessionmaker

    async def task() -> None:
        async with get_sessionmaker()() as session:
            await ensure_admin(session)

    _run_db(task)
    console.print(f"[green]database ready[/green] ({get_settings().database_url})")


@app.command("create-reviewer")
def create_reviewer(
    username: Annotated[str, typer.Argument(help="Login name of the reviewer.")],
    password: Annotated[str, typer.Option("--password", prompt=True, hide_input=True, confirmation_prompt=True, help="Password (prompted when omitted).")],
    role: Annotated[str, typer.Option("--role", help="viewer, reviewer or admin.")] = "reviewer",
) -> None:
    """Create a reviewer account directly in the database."""
    from sqlalchemy import select

    from .audit import service as audit
    from .auth import ROLE_RANK
    from .db import get_sessionmaker
    from .models import Reviewer
    from .security import hash_password

    if role not in ROLE_RANK:
        _fail("role must be viewer, reviewer or admin")

    async def task() -> Reviewer:
        async with get_sessionmaker()() as session:
            if (await session.execute(select(Reviewer).where(Reviewer.username == username))).scalar_one_or_none():
                _fail(f"reviewer '{username}' already exists")
            reviewer = Reviewer(username=username, password_hash=hash_password(password), role=role)
            session.add(reviewer)
            await session.flush()
            await audit.record(session, "cli", "reviewer.create", "reviewer", reviewer.id, {"role": role})
            await session.commit()
            return reviewer

    reviewer = _run_db(task)
    console.print(_kv_table("Reviewer created", {"id": reviewer.id, "username": reviewer.username, "role": reviewer.role}))


@agent_app.command("create")
def agent_create(
    name: Annotated[str, typer.Argument(help="Unique agent name.")],
    provider: Annotated[str, typer.Option("--provider", help="Upstream provider: openai, anthropic, azure, ollama or custom.")] = "openai",
    base_url: Annotated[str | None, typer.Option("--base-url", help="Upstream base URL (defaults per provider).")] = None,
    upstream_key: Annotated[str | None, typer.Option("--upstream-key", help="Upstream provider API key, stored encrypted.")] = None,
    require_approval: Annotated[bool, typer.Option("--approval/--no-approval", help="Require a human decision for every request.")] = True,
    auto_deny_at: Annotated[int, typer.Option("--auto-deny-at", min=0, max=101, help="Auto-deny when risk score reaches this value (101 disables).")] = 90,
    auto_approve_below: Annotated[int, typer.Option("--auto-approve-below", min=0, max=100, help="Auto-approve when risk score is below this value (0 disables).")] = 0,
    deny_pattern: Annotated[list[str] | None, typer.Option("--deny-pattern", help="Regex that auto-denies matching prompts (repeatable).")] = None,
    allowed_path: Annotated[list[str] | None, typer.Option("--allowed-path", help="Allowed upstream path glob (repeatable, empty = all).")] = None,
    allowed_model: Annotated[list[str] | None, typer.Option("--allowed-model", help="Allowed model name (repeatable, empty = all).")] = None,
    rate_limit: Annotated[int, typer.Option("--rate-limit", min=0, help="Requests per minute (0 = unlimited).")] = 0,
    description: Annotated[str, typer.Option("--description", help="Free text description.")] = "",
    owner: Annotated[str, typer.Option("--owner", help="Owning team or person.")] = "",
    tag: Annotated[list[str] | None, typer.Option("--tag", help="Tag (repeatable).")] = None,
) -> None:
    """Register an agent and print its AISRF API key (shown once)."""
    from .agents import service as agents
    from .audit import service as audit
    from .db import get_sessionmaker

    async def task() -> tuple[dict[str, Any], str]:
        async with get_sessionmaker()() as session:
            if await agents.get_agent_by_name(session, name):
                _fail(f"agent '{name}' already exists")
            agent, raw_key = await agents.create_agent(
                session,
                name,
                description=description,
                owner=owner,
                tags=tag or [],
                upstream_provider=provider,
                upstream_base_url=base_url,
                upstream_api_key=upstream_key,
                require_approval=require_approval,
                auto_approve_below_risk=auto_approve_below,
                auto_deny_at_risk=auto_deny_at,
                auto_deny_patterns=deny_pattern or [],
                allowed_paths=allowed_path or [],
                allowed_models=allowed_model or [],
                rate_limit_per_minute=rate_limit,
            )
            await audit.record(session, "cli", "agent.create", "agent", agent.id, {"name": agent.name, "provider": provider})
            await session.commit()
            return agents.agent_to_dict(agent), raw_key

    data, raw_key = _run_db(task)
    shown = {k: data[k] for k in ("id", "name", "upstream_provider", "upstream_base_url", "require_approval", "auto_approve_below_risk", "auto_deny_at_risk", "rate_limit_per_minute")}
    console.print(_kv_table("Agent created", shown))
    console.print(Panel("Store this key now, it cannot be recovered later. Send it as X-AISRF-Key or Authorization: Bearer.", title="AISRF API key", border_style="yellow"))
    typer.echo(f"API key: {raw_key}")


@agent_app.command("list")
def agent_list(include_inactive: Annotated[bool, typer.Option("--all/--active-only", help="Include disabled agents.")] = True) -> None:
    """List registered agents."""
    from .agents import service as agents
    from .db import get_sessionmaker

    async def task() -> list[dict[str, Any]]:
        async with get_sessionmaker()() as session:
            return [agents.agent_to_dict(a) for a in await agents.list_agents(session, include_inactive)]

    rows = _run_db(task)
    if not rows:
        console.print("no agents registered")
        return
    console.print(_rows_table("Agents", rows, ["id", "name", "upstream_provider", "api_key_prefix", "require_approval", "auto_deny_at_risk", "is_active", "request_count"]))


@agent_app.command("rotate-key")
def agent_rotate_key(agent_id: Annotated[str, typer.Argument(help="Agent id or name.")]) -> None:
    """Issue a new API key for an agent; the old key stops working immediately."""
    from .agents import service as agents
    from .audit import service as audit
    from .db import get_sessionmaker

    async def task() -> tuple[str, str]:
        async with get_sessionmaker()() as session:
            agent = await agents.get_agent(session, agent_id) or await agents.get_agent_by_name(session, agent_id)
            if agent is None:
                _fail(f"agent '{agent_id}' not found")
            key = await agents.rotate_api_key(session, agent)
            await audit.record(session, "cli", "agent.rotate_key", "agent", agent.id)
            await session.commit()
            return agent.id, key

    aid, key = _run_db(task)
    console.print(f"rotated key for agent [bold]{aid}[/bold]")
    typer.echo(f"API key: {key}")


# --- remote: tickets ------------------------------------------------------------------
TICKET_COLUMNS = ["number", "id", "status", "agent_name", "model", "risk_score", "risk_level", "prompt_preview", "created_at"]


@tickets_app.command("list")
def tickets_list(
    status: Annotated[str | None, typer.Option("--status", help="Filter by status (PENDING, APPROVED, DENIED, ...; comma separated).")] = None,
    agent: Annotated[str | None, typer.Option("--agent", help="Filter by agent id.")] = None,
    min_risk: Annotated[int | None, typer.Option("--min-risk", help="Minimum risk score.")] = None,
    limit: Annotated[int, typer.Option("--limit", help="Maximum rows.")] = 50,
    url: UrlOpt = DEFAULT_URL,
    token: TokenOpt = None,
) -> None:
    """List tickets on the gateway."""
    remote = Remote(url, token)
    params: dict[str, Any] = {"limit": limit}
    if status:
        params["status"] = [s.strip() for s in status.split(",") if s.strip()]
    if agent:
        params["agent_id"] = agent
    if min_risk is not None:
        params["min_risk"] = min_risk
    data = remote.json("GET", "/api/tickets", params=params)
    rows = data.get("items", [])
    if not rows:
        console.print("no tickets match")
        return
    console.print(_rows_table(f"Tickets ({data.get('total', len(rows))} total)", rows, TICKET_COLUMNS))


@tickets_app.command("show")
def tickets_show(ticket_id: Annotated[str, typer.Argument(help="Ticket id or number.")], url: UrlOpt = DEFAULT_URL, token: TokenOpt = None) -> None:
    """Show one ticket in full, including findings and events."""
    data = Remote(url, token).json("GET", f"/api/tickets/{ticket_id}")
    summary = {k: data.get(k) for k in ("id", "number", "status", "agent_name", "agent_id", "model", "method", "path", "risk_score", "risk_level", "policy_action", "decided_by", "decision_note", "created_at", "expires_at")}
    console.print(_kv_table(f"Ticket {data.get('id')}", summary))
    findings = data.get("findings") or []
    if findings:
        console.print(_rows_table("Findings", findings, ["severity", "analyzer", "title", "detail"]))
    console.print(Panel(data.get("prompt_preview") or "(empty)", title="Prompt preview"))
    events = data.get("events") or []
    if events:
        console.print(_rows_table("Events", events, ["ts", "event_type", "actor"]))


def _decide(ticket_id: str, approve: bool, note: str, url: str, token: str | None) -> None:
    verb = "approve" if approve else "deny"
    data = Remote(url, token).json("POST", f"/api/tickets/{ticket_id}/{verb}", json={"note": note})
    console.print(f"ticket [bold]{data.get('id', ticket_id)}[/bold] is now [bold]{data.get('status')}[/bold]")


@tickets_app.command("approve")
def tickets_approve(ticket_id: Annotated[str, typer.Argument(help="Ticket id or number.")], note: Annotated[str, typer.Option("--note", help="Decision note for the audit log.")] = "", url: UrlOpt = DEFAULT_URL, token: TokenOpt = None) -> None:
    """Approve a pending ticket."""
    _decide(ticket_id, True, note, url, token)


@tickets_app.command("deny")
def tickets_deny(ticket_id: Annotated[str, typer.Argument(help="Ticket id or number.")], note: Annotated[str, typer.Option("--note", help="Decision note for the audit log.")] = "", url: UrlOpt = DEFAULT_URL, token: TokenOpt = None) -> None:
    """Deny a pending ticket."""
    _decide(ticket_id, False, note, url, token)


def _iter_sse(response: httpx.Response):
    """Yield (event, data) tuples from a text/event-stream response."""
    event, data_lines = "message", []
    for line in response.iter_lines():
        if line == "":
            if data_lines:
                yield event, "\n".join(data_lines)
            event, data_lines = "message", []
        elif line.startswith("event:"):
            event = line[6:].strip()
        elif line.startswith("data:"):
            data_lines.append(line[5:].strip())


@tickets_app.command("watch")
def tickets_watch(
    status: Annotated[str | None, typer.Option("--status", help="Only print tickets in this status (for example PENDING).")] = None,
    replay: Annotated[int, typer.Option("--replay", help="Number of recent events to replay on connect.")] = 0,
    url: UrlOpt = DEFAULT_URL,
    token: TokenOpt = None,
) -> None:
    """Tail the live ticket stream and print tickets as they are created and decided."""
    remote = Remote(url, token)
    console.print(f"watching {remote.url}/api/stream/tickets (Ctrl+C to stop)")
    try:
        with remote.client.stream("GET", "/api/stream/tickets", params={"replay": replay}, timeout=httpx.Timeout(None, connect=10.0)) as response:
            if response.status_code >= 400:
                _fail(f"stream failed with HTTP {response.status_code}")
            for event, payload in _iter_sse(response):
                if event == "ping":
                    continue
                try:
                    item = json.loads(payload)
                except ValueError:
                    continue
                ticket = item.get("ticket") or {}
                if status and ticket.get("status", "").upper() != status.upper():
                    continue
                color = {"PENDING": "yellow", "APPROVED": "green", "DENIED": "red", "EXPIRED": "magenta", "FAILED": "red"}.get(ticket.get("status", ""), "white")
                console.print(f"[dim]{ticket.get('created_at', '')}[/dim] [{color}]{ticket.get('status')}[/{color}] #{ticket.get('number')} {ticket.get('id')} agent={ticket.get('agent_name') or ticket.get('agent_id')} risk={ticket.get('risk_score')} ({ticket.get('risk_level')}) event={item.get('event')} {ticket.get('prompt_preview', '')[:80]!r}")
    except KeyboardInterrupt:
        console.print("stopped")
    except httpx.HTTPError as exc:
        _fail(f"stream error: {exc}")


# --- remote: red team -----------------------------------------------------------------
def _print_summary(summary: dict[str, Any]) -> None:
    scalars = {k: v for k, v in summary.items() if not isinstance(v, (dict, list))}
    if scalars:
        console.print(_kv_table("Campaign summary", scalars))
    for key, value in summary.items():
        if isinstance(value, dict) and value:
            if all(isinstance(v, dict) for v in value.values()):
                rows = [{"name": k, **v} for k, v in value.items()]
                console.print(_rows_table(key, rows))
            else:
                console.print(_kv_table(key, value))
        elif isinstance(value, list) and value and all(isinstance(v, dict) for v in value):
            console.print(_rows_table(key, value[:50]))


@redteam_app.command("corpus")
def redteam_corpus(url: UrlOpt = DEFAULT_URL, token: TokenOpt = None) -> None:
    """Show the probe corpus: categories, techniques and probe counts."""
    data = Remote(url, token).json("GET", "/api/redteam/corpus")
    if isinstance(data, list):
        console.print(_rows_table("Corpus", data))
        return
    _print_summary(data)


@redteam_app.command("run")
def redteam_run(
    agent: Annotated[str, typer.Option("--agent", help="Agent id the probes are sent through.")],
    model: Annotated[str, typer.Option("--model", help="Target model name.")],
    name: Annotated[str | None, typer.Option("--name", help="Campaign name (generated when omitted).")] = None,
    category: Annotated[list[str] | None, typer.Option("--category", help="Probe category (repeatable, empty = all).")] = None,
    technique: Annotated[list[str] | None, typer.Option("--technique", help="Probe technique (repeatable).")] = None,
    mutator: Annotated[list[str] | None, typer.Option("--mutator", help="Mutator to apply (repeatable).")] = None,
    max_probes: Annotated[int | None, typer.Option("--max-probes", help="Cap the number of probes.")] = None,
    system_prompt: Annotated[str | None, typer.Option("--system-prompt", help="System prompt to send with every probe.")] = None,
    path: Annotated[str | None, typer.Option("--path", help="Upstream API path override.")] = None,
    concurrency: Annotated[int | None, typer.Option("--concurrency", help="Parallel probes.")] = None,
    seed: Annotated[int | None, typer.Option("--seed", help="Random seed for probe selection.")] = None,
    wait: Annotated[bool, typer.Option("--wait/--no-wait", help="Block until the campaign finishes and print the summary.")] = True,
    poll_interval: Annotated[float, typer.Option("--poll-interval", help="Seconds between status polls.")] = 3.0,
    url: UrlOpt = DEFAULT_URL,
    token: TokenOpt = None,
) -> None:
    """Create and start a red-team campaign, optionally waiting for the summary."""
    remote = Remote(url, token)
    payload: dict[str, Any] = {"name": name or f"cli-{model}-{time.strftime('%Y%m%d-%H%M%S')}", "agent_id": agent, "target_model": model, "auto_start": True}
    for key, value in {"categories": category, "techniques": technique, "mutators": mutator, "max_probes": max_probes, "system_prompt": system_prompt, "path": path, "concurrency": concurrency, "seed": seed}.items():
        if value:
            payload[key] = value
    campaign = remote.json("POST", "/api/redteam/campaigns", json=payload)
    cid = campaign.get("id")
    console.print(f"campaign [bold]{cid}[/bold] created ({campaign.get('status')})")
    if str(campaign.get("status", "")).lower() in {"created", "pending", "new"}:
        remote.json("POST", f"/api/redteam/campaigns/{cid}/start")
    if not wait:
        return
    with console.status("running probes...") as status_line:
        while True:
            campaign = remote.json("GET", f"/api/redteam/campaigns/{cid}")
            state = str(campaign.get("status", "")).lower()
            done = campaign.get("completed_probes", campaign.get("completed", campaign.get("done")))
            total = campaign.get("total_probes", campaign.get("total"))
            status_line.update(f"{state} {done if done is not None else '?'}/{total if total is not None else '?'} probes")
            if state in TERMINAL_CAMPAIGN_STATES:
                break
            time.sleep(poll_interval)
    console.print(f"campaign [bold]{cid}[/bold] {state}")
    _print_summary(remote.json("GET", f"/api/redteam/campaigns/{cid}/summary"))


# --- remote: code review -----------------------------------------------------------------
RUN_COLUMNS = ["id", "name", "source_type", "status", "stage", "file_count", "finding_count", "risk_score", "created_at"]


def _run_row(run: dict[str, Any]) -> dict[str, Any]:
    return {**run, "risk_score": (run.get("summary") or {}).get("risk_score")}


@codereview_app.command("run")
def codereview_run(
    git: Annotated[str | None, typer.Option("--git", help="Git repository URL (GitHub, GitLab, Bitbucket or generic).")] = None,
    ref: Annotated[str | None, typer.Option("--ref", help="Branch, tag or commit for --git.")] = None,
    token_env: Annotated[str | None, typer.Option("--token-env", help="Name of an environment variable holding the access token for --git or --url.")] = None,
    credential: Annotated[str | None, typer.Option("--credential", help="Id of a stored credential (admin).")] = None,
    zip_path: Annotated[Path | None, typer.Option("--zip", help="Local zip or tar archive to upload.")] = None,
    url: Annotated[str | None, typer.Option("--archive-url", help="HTTP(S) URL of a zip or tar archive.")] = None,
    path: Annotated[str | None, typer.Option("--path", help="Local directory on the server (admin, must be allowlisted).")] = None,
    name: Annotated[str | None, typer.Option("--name", help="Run name.")] = None,
    packs: Annotated[list[str] | None, typer.Option("--packs", help="Rule pack (repeatable, empty = all).")] = None,
    engines: Annotated[list[str] | None, typer.Option("--engines", help="Engine (repeatable): rules, semgrep, bandit, llm.")] = None,
    include: Annotated[list[str] | None, typer.Option("--include", help="Include glob (repeatable).")] = None,
    exclude: Annotated[list[str] | None, typer.Option("--exclude", help="Exclude glob (repeatable).")] = None,
    wait: Annotated[bool, typer.Option("--wait/--no-wait", help="Block until the run finishes.")] = True,
    format: Annotated[str | None, typer.Option("--format", "-f", help="Report format to download after completion (sarif, json, html, pdf, ...).")] = None,
    out: Annotated[Path | None, typer.Option("--out", "-o", help="Output file for --format.")] = None,
    poll_interval: Annotated[float, typer.Option("--poll-interval", help="Seconds between status polls.")] = 2.0,
    gateway: UrlOpt = DEFAULT_URL,
    token: TokenOpt = None,
) -> None:
    """Start a code review run from a git repository, archive, URL or server directory."""
    import os

    remote = Remote(gateway, token)
    options: dict[str, Any] = {}
    for key, value in {"packs": packs, "engines": engines, "include": include, "exclude": exclude}.items():
        if value:
            options[key] = value
    secret = os.environ.get(token_env) if token_env else None
    if token_env and not secret:
        _fail(f"environment variable {token_env} is empty")
    if zip_path is not None:
        if not zip_path.is_file():
            _fail(f"archive not found: {zip_path}")
        with zip_path.open("rb") as fh:
            run = remote.json("POST", "/api/codereview/runs/upload", files={"file": (zip_path.name, fh, "application/octet-stream")}, data={"name": name or zip_path.name, "options": json.dumps(options)})
    else:
        source: dict[str, Any]
        if git:
            source = {"type": "git", "url": git, "ref": ref, "token": secret, "credential_id": credential}
        elif url:
            source = {"type": "url", "url": url, "token": secret}
        elif path:
            source = {"type": "path", "path": path}
        else:
            _fail("give one of --git, --zip, --url or --path")
        source = {k: v for k, v in source.items() if v}
        run = remote.json("POST", "/api/codereview/runs", json={"name": name or "", "source": source, "options": options})
    rid = run.get("id")
    console.print(f"run [bold]{rid}[/bold] created ({run.get('status')})")
    if not wait:
        return
    with console.status("analysing...") as status_line:
        while True:
            run = remote.json("GET", f"/api/codereview/runs/{rid}")
            state = str(run.get("status", "")).lower()
            status_line.update(f"{state} {run.get('stage') or ''} files={run.get('file_count')} findings={run.get('finding_count')}")
            if state in TERMINAL_RUN_STATES:
                break
            time.sleep(poll_interval)
    console.print(f"run [bold]{rid}[/bold] {state}" + (f": {run.get('error')}" if run.get("error") else ""))
    summary = run.get("summary") or {}
    if summary:
        console.print(_kv_table("Summary", {"risk_score": summary.get("risk_score"), "risk_level": summary.get("risk_level"), "open": summary.get("open"), "by_severity": summary.get("by_severity"), "by_pack": summary.get("by_pack"), "by_engine": summary.get("by_engine")}))
        top = summary.get("top_rules") or []
        if top:
            console.print(_rows_table("Top rules", top, ["rule_id", "severity", "count", "title"]))
    if format:
        response = remote.request("GET", f"/api/reports/codereview/{rid}", params={"format": format})
        target = out or Path(f"aisrf-codereview-{rid}.{format}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(response.content)
        console.print(f"wrote [bold]{target}[/bold] ({len(response.content)} bytes)")
    if state == "failed":
        raise typer.Exit(2)


@codereview_app.command("list")
def codereview_list(status: Annotated[str | None, typer.Option("--status", help="Filter by status.")] = None, limit: Annotated[int, typer.Option("--limit")] = 50, gateway: UrlOpt = DEFAULT_URL, token: TokenOpt = None) -> None:
    """List code review runs."""
    data = Remote(gateway, token).json("GET", "/api/codereview/runs", params={"status": status, "limit": limit})
    rows = [_run_row(r) for r in data.get("items", [])]
    if not rows:
        console.print("no runs")
        return
    console.print(_rows_table(f"Code review runs ({data.get('total', len(rows))} total)", rows, RUN_COLUMNS))


@codereview_app.command("show")
def codereview_show(run_id: Annotated[str, typer.Argument(help="Run id.")], limit: Annotated[int, typer.Option("--limit", help="Findings to print.")] = 50, gateway: UrlOpt = DEFAULT_URL, token: TokenOpt = None) -> None:
    """Show one run with its summary and top findings."""
    remote = Remote(gateway, token)
    run = remote.json("GET", f"/api/codereview/runs/{run_id}")
    console.print(_kv_table(f"Run {run.get('id')}", {k: run.get(k) for k in ("name", "source_type", "source_ref", "status", "stage", "file_count", "loc", "finding_count", "created_by", "created_at", "finished_at", "error")}))
    summary = run.get("summary") or {}
    if summary:
        console.print(_kv_table("Summary", {"risk_score": summary.get("risk_score"), "risk_level": summary.get("risk_level"), "by_severity": summary.get("by_severity"), "by_pack": summary.get("by_pack"), "engines": {k: (v.get("findings"), v.get("error")) for k, v in (summary.get("engines") or {}).items()}}))
    findings = remote.json("GET", f"/api/codereview/runs/{run_id}/findings", params={"limit": limit}).get("items", [])
    if findings:
        console.print(_rows_table("Findings", findings, ["rule_id", "severity", "confidence", "engine", "file", "line_start", "title", "status"]))


@codereview_app.command("rules")
def codereview_rules(pack: Annotated[str | None, typer.Option("--pack", help="Only this pack.")] = None, gateway: UrlOpt = DEFAULT_URL, token: TokenOpt = None) -> None:
    """Print the rule catalogue."""
    data = Remote(gateway, token).json("GET", "/api/codereview/rules", params={"pack": pack})
    for p in data.get("packs", []):
        console.print(_rows_table(f"{p['title']} ({p['rule_count']} rules)", p.get("rules", []), ["id", "severity", "confidence", "cwe", "owasp", "title"]))


# --- remote: reports / audit / mcp -----------------------------------------------------
@app.command("report")
def report(
    kind: Annotated[str, typer.Argument(help="summary, tickets, audit, ticket/<id>, agent/<id>, campaign/<id> or codereview/<run_id>.")],
    format: Annotated[str, typer.Option("--format", "-f", help="json, yaml, csv, tsv, md, html, pdf, xlsx, txt, xml, sarif or junit.")] = "json",
    out: Annotated[Path | None, typer.Option("--out", "-o", help="Output file (default aisrf-report-<kind>.<format>).")] = None,
    url: UrlOpt = DEFAULT_URL,
    token: TokenOpt = None,
) -> None:
    """Generate a report on the gateway and save it locally."""
    kind = kind.strip("/")
    response = Remote(url, token).request("GET", f"/api/reports/{kind}", params={"format": format})
    target = out or Path(f"aisrf-report-{kind.replace('/', '_')}.{format}")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(response.content)
    console.print(f"wrote [bold]{target}[/bold] ({len(response.content)} bytes, {response.headers.get('content-type', 'unknown type')})")


@audit_app.command("verify")
def audit_verify(url: UrlOpt = DEFAULT_URL, token: TokenOpt = None) -> None:
    """Verify the audit log hash chain."""
    data = Remote(url, token).json("GET", "/api/audit/verify")
    console.print(_kv_table("Audit chain", data))
    if not data.get("ok"):
        raise typer.Exit(2)


@app.command("mcp")
def mcp_command(url: UrlOpt = DEFAULT_URL, token: TokenOpt = None) -> None:
    """Run a stdio MCP server that exposes the gateway to a local AI assistant."""
    from .mcp_server import run_stdio

    if not token:
        _fail("no admin token: pass --token or set AISRF_ADMIN_API_TOKEN")
    run_stdio(url, token)


@app.command("desktop")
def desktop_command(
    port: Annotated[int | None, typer.Option("--port", help="Loopback port (default: a free port).")] = None,
    no_window: Annotated[bool, typer.Option("--no-window", help="Skip the native window and open the system browser.")] = False,
    no_browser: Annotated[bool, typer.Option("--no-browser", help="Do not open anything, just print the URL.")] = False,
) -> None:
    """Run the gateway locally and open the dashboard in a window or the browser (desktop mode)."""
    from .desktop import run_desktop

    raise typer.Exit(run_desktop(port=port, open_window=not no_window, open_browser=not no_browser))


def main() -> None:
    app()


if __name__ == "__main__":
    main()

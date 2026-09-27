# MCP server

AISRF exposes every reviewer action as a Model Context Protocol tool, so an AI assistant (Claude
Desktop, Claude Code, Cursor, any MCP client) can triage tickets, decide them, manage agents, run
red-team campaigns and pull reports. Every tool is a thin wrapper over the REST API, so
authorisation and the audit trail are identical to the dashboard: decisions made through MCP are
recorded with the token principal (`api-token`) as actor.

## Transports

| Transport | How | Auth |
| --- | --- | --- |
| Streamable HTTP (in-process) | `POST http://<gateway>/mcp` | `Authorization: Bearer <AISRF_ADMIN_API_TOKEN>`; the endpoint answers 503 until the token is configured |
| stdio (local) | `aisrf mcp --url http://<gateway> --token <AISRF_ADMIN_API_TOKEN>` (or env `AISRF_URL`, `AISRF_ADMIN_API_TOKEN`) | the token is used for the REST calls |

Enable the endpoint by setting `AISRF_ADMIN_API_TOKEN` on the gateway:

```bash
export AISRF_ADMIN_API_TOKEN=$(python -c "import secrets; print(secrets.token_urlsafe(32))")
aisrf serve
```

## Claude Desktop

Add to `claude_desktop_config.json` (macOS: `~/Library/Application Support/Claude/`, Windows:
`%APPDATA%\Claude\`), see `examples/mcp_client_config.json`:

```json
{
  "mcpServers": {
    "aisrf": {
      "command": "aisrf",
      "args": ["mcp", "--url", "http://localhost:8080", "--token", "<AISRF_ADMIN_API_TOKEN>"]
    }
  }
}
```

Use the absolute path of the `aisrf` executable (`/path/to/.venv/bin/aisrf`) if it is not on PATH.

## Claude Code

```bash
claude mcp add aisrf -- aisrf mcp --url http://localhost:8080 --token "$AISRF_ADMIN_API_TOKEN"
# or the HTTP transport:
claude mcp add --transport http aisrf-http http://localhost:8080/mcp --header "Authorization: Bearer $AISRF_ADMIN_API_TOKEN"
```

Or drop the `mcpServers` block from `examples/mcp_client_config.json` into the project's `.mcp.json`.

## Tools

| Area | Tools |
| --- | --- |
| Tickets | `list_tickets(status, agent_id, min_risk, model, source, campaign_id, search, limit, offset)`, `get_ticket(ticket_id)`, `approve_ticket(ticket_id, note)`, `deny_ticket(ticket_id, note)`, `bulk_approve_tickets(ticket_ids, note)`, `bulk_deny_tickets(ticket_ids, note)`, `ticket_stats()` |
| Agents | `list_agents(include_inactive)`, `get_agent(agent_id)`, `create_agent(name, upstream_provider, upstream_base_url, upstream_api_key, ...policy fields)`, `update_agent(agent_id, changes)`, `rotate_agent_key(agent_id)`, `disable_agent(agent_id)`, `agent_events(agent_id, limit, level)`, `agent_stats(agent_id)` |
| Red team | `list_corpus()`, `list_probes(category, technique, severity, search)`, `list_campaigns(status, agent_id)`, `create_campaign(name, agent_id, target_model, categories, techniques, max_probes, mutators, system_prompt, path, concurrency, seed, auto_start)`, `get_campaign`, `start_campaign`, `pause_campaign`, `resume_campaign`, `cancel_campaign`, `delete_campaign`, `campaign_results(campaign_id, verdict, category)`, `campaign_summary(campaign_id)` |
| Reports | `list_report_kinds()`, `generate_report(kind, format, output_path, params)` (kinds `summary`, `tickets`, `ticket/<id>`, `agent/<id>`, `campaign/<id>`, `audit`; binary formats are written to a file and the path is returned) |
| Audit | `list_audit(limit, offset, action, actor)`, `verify_audit()` |
| Reviewers | `list_reviewers()`, `create_reviewer(username, password, role)`, `set_reviewer_password(reviewer_id, password)`, `deactivate_reviewer(reviewer_id)` |
| Ops | `health()`, `metrics()` |

Resources: `aisrf://tickets/pending` (tickets waiting for a decision), `aisrf://stats` (aggregate
statistics). Prompt: `review_ticket(ticket_id)` renders a review checklist for one ticket with its
findings and normalised messages.

The server's instructions tell the assistant that denying is the safe default for prompt injection,
exfiltration and policy abuse.

## Example session

```
you:    Anything waiting for review?
claude: [list_tickets status=PENDING] Two tickets: #42 (risk 72, HIGH, prompt injection in a tool
        result) and #43 (risk 5, benign summarisation).
you:    Deny 42 with a note, approve 43.
claude: [deny_ticket tkt_... note="indirect injection via retrieved doc"] [approve_ticket tkt_...]
        Done. The agent behind #42 received a 403 with the ticket id.
you:    Run the prompt injection and jailbreak categories against agent demo on gpt-4o-mini, max 50 probes.
claude: [create_campaign ... auto_start=true] Campaign cmp_... started; probes appear as tickets
        with source=redteam and need approval like any other request.
```

## Security notes

* The token carries the admin role: whoever can talk to the MCP server can approve traffic and
  create agents with upstream credentials. Keep it in the client's secret store, not in shared
  config files, and rotate it by changing `AISRF_ADMIN_API_TOKEN` and restarting.
* The HTTP endpoint is stateless and JSON-response based; put it behind the same TLS and network
  restrictions as the reviewer API.
* An assistant deciding tickets is still a reviewer: its decisions are audited with the token
  principal. If you need per-person attribution, give each operator their own gateway token via a
  separate deployment or use the dashboard.

# Tickets and the review workflow

How a reviewer works the queue, what a ticket shows, how decisions are made and recorded, and what happens when nobody decides.

## The queue

`/tickets` (template `tickets.html`, script `tickets.js`) lists tickets from `GET /api/tickets` fifty at a time and updates live from the `/api/stream/tickets` SSE channel.

Controls:

| Control | Effect | API parameter |
| --- | --- | --- |
| Status tabs | `PENDING` (default, or the `ui.queue_default_status` setting, or `?status=` in the URL), plus the other statuses and All | `status` |
| Agent select | Only this agent | `agent_id` |
| Min risk select | Score at or above | `min_risk` |
| Source select | `gateway`, `sdk`, `mitm`, `redteam` | `source` |
| Search box | Case-insensitive substring over `prompt_preview`, ticket id, `path` and `correlation_id` (300 ms debounce) | `search` |
| Refresh button | Reload the page of results | |
| Sound toggle | Beep on a new PENDING ticket that matches the current filter (stored per browser; default from `ui.sound_on_new_ticket`) | |
| Select-all checkbox | Selects every PENDING row on the page | |
| `?campaign_id=` | Hidden filter used by campaign pages | `campaign_id` |

Columns: checkbox (PENDING rows only), `#number`, created time with a live countdown to `expires_at` for PENDING rows, agent, model, path, risk badge (level and score), finding count, policy badge (`review`, `approve`, `deny`), prompt preview, status badge, and actions (Approve and Deny buttons for PENDING rows when your role allows, otherwise `by <decided_by>` with the note as tooltip). Double-click a row to open it. The PENDING tab shows the live pending count from `GET /api/tickets/stats`.

New tickets arrive through the `created` SSE event; decided, forwarding, completed, failed and expired events update the row in place or remove it when it no longer matches the filter, and a toast announces new PENDING tickets with the agent name and risk score.

## Keyboard shortcuts

From `tickets.js`. Ignored while focus is in an input, textarea or select, and when Ctrl, Meta or Alt is held.

| Key | Action |
| --- | --- |
| `j` | Move the cursor down one row |
| `k` | Move the cursor up one row |
| `a` | Approve the ticket under the cursor (opens the note dialog) |
| `d` | Deny the ticket under the cursor (opens the note dialog) |
| `x` | Toggle selection of the ticket under the cursor (PENDING only) |
| `Enter` | Open the ticket under the cursor |
| `r` | Reload the list |

On the ticket detail page (`ticket.js`) `a` and `d` approve or deny the open ticket when the buttons are enabled.

## Ticket detail anatomy

`/tickets/{id}` (`ticket.js`, data from `GET /api/tickets/{id}`, which accepts the `tkt_` id or the plain number). Sections:

| Section | Content | Source fields |
| --- | --- | --- |
| Header | Number, status, risk badge, source badge when not `gateway`, and a key-value block with agent, model, path, expiry (a live countdown while PENDING), decided time and reviewer, response status and latency, and the error text when present; Approve and Deny buttons with a hint explaining why they are disabled | brief ticket fields, `error` |
| Links | Agent page, campaign page when `campaign_id` is set, "More from this agent" | `agent_id`, `campaign_id` |
| Findings | Every request finding with severity, category, analyzer, title, description, masked evidence, location, confidence and OWASP, Greshake and Thacker chips; "No findings" when empty | `findings` |
| Conversation | The normalized messages rendered as a chat (system prompt first), plus a collapsible list of tools offered | `normalized.messages`, `normalized.system`, `normalized.tools` |
| Policy | Action, reasons and matched rules | `policy_decision` |
| Timeline | Every `ticket_events` row: timestamp, event type, actor, detail | `events` |
| Response | Status and latency, the response preview rendered as an assistant bubble with response-finding evidence highlighted, collapsible raw response body and response headers; "Nothing was sent upstream" for DENIED and EXPIRED tickets | `response_*`, `latency_ms` |
| Request | Collapsible redacted request headers, raw request JSON and the normalized structure | `request_headers`, `request_json`, `normalized` |

## Approve and deny with notes

Both buttons (and the `a` and `d` keys) open a note dialog; the note is optional. Submitting calls `POST /api/tickets/{id}/approve` or `POST /api/tickets/{id}/deny` with `{"note": "..."}`. Requirements and effects:

* Role `reviewer` or `admin` (viewers see a "Your role cannot decide tickets" toast).
* The ticket must be `PENDING`; otherwise the API answers `409` with `ticket <id> is <status>, only PENDING tickets can be decided`.
* The service sets `status`, `decided_by` (your username), `decided_at` and `decision_note`, appends an `approved` or `denied` timeline event with the note, writes an audit entry (`ticket.approve` or `ticket.deny` with `note`, `agent_id` and `risk_score`), logs `decision.approved` or `decision.denied` on the agent, commits, resolves the hold so a waiting client continues immediately, and publishes `decided` on the SSE channel.
* Approving forwards the request: in synchronous mode the waiting gateway coroutine does it; in asynchronous mode the client's next poll does it. A denial makes the client receive `403 denied` with your note in the message and your username in `decided_by`.

CLI and MCP equivalents: `aisrf tickets approve <id or number> --note "..."`, `aisrf tickets deny ...`, and the `approve_ticket` and `deny_ticket` MCP tools. All go through the same service function, so the audit trail is identical.

## Bulk actions

Select rows with the checkboxes, `x`, or select-all, then use Approve all or Deny all in the bulk bar (visible only to deciding roles). One note applies to every ticket. The call is `POST /api/tickets/bulk/approve` or `/bulk/deny` with `{"ticket_ids": [...], "note": "..."}`; the response maps each id to its resulting status or `error: ...` (for example a ticket that expired between selection and submission). Each ticket is decided individually with its own timeline event and audit entry.

## Expiry and the sweeper

Every ticket is created with `expires_at = created_at + AISRF_APPROVAL_TIMEOUT_SECONDS` (default 300). Two mechanisms enforce it:

* The background sweeper in `aisrf/main.py` runs `expire_stale()` every 5 s: every `PENDING` ticket whose `expires_at` is in the past becomes `EXPIRED` with `decided_by = "timeout"`, an `expired` timeline event, a `request.expired` agent log line at WARNING, an SSE `expired` event, and any waiting client is released with `504 expired`.
* A synchronous gateway request also tracks its own deadline in the hold registry and marks the ticket expired itself if it wins the race.

Because only PENDING tickets can be decided, approving after expiry returns `409`; the client has to resubmit, which creates a new ticket. The countdown in the queue and on the detail page shows the remaining time. Raising the timeout is a live setting (Settings > Gateway > `approval_timeout_seconds`); remember that client timeouts must exceed it.

The same sweeper purges tickets older than `AISRF_TICKET_RETENTION_DAYS` (default 90, 0 keeps forever) roughly once an hour; purge deletes the ticket rows and their timeline events (cascade), not the audit entries.

## What reviewers should look at

1. Risk badge and findings first, but read the evidence: analyzers are heuristics, and a HIGH prompt-injection finding on a support bot that quotes a customer email may be legitimate context (indirect injection is exactly what you want to catch, though).
2. The conversation panel: does the system prompt match what this agent is supposed to do, is the last user message consistent with the agent's purpose, are there tool results carrying instructions.
3. Tools offered and `extra.tool_choice`: an agent suddenly offering shell, file or HTTP tools deserves a closer look (`tool_abuse` findings).
4. Path and model against the agent's allow-lists; policy denies mismatches automatically, but a model you did not expect on an allowed path is still a signal.
5. Source and correlation id: a `redteam` source ticket is a probe, `mitm` came through the transparent proxy; a burst of tickets sharing a correlation id is one run.
6. For completed tickets, the response findings: `system_prompt_leak`, `pii_leak`, `secrets_leak`, `canary_leak`, `harmful_compliance` and `exfil_markers_in_response` tell you what the model did after approval.
7. Write a note. Notes are the only free-text context the audit log and reports will have.

## Audit implications

* Every human decision is an audit entry: `actor` = your username, `action` = `ticket.approve` or `ticket.deny`, `target_type` = `ticket`, `target_id` = ticket id, `detail` = `{"note", "agent_id", "risk_score"}`, chained by SHA-256 to the previous entry. `GET /api/audit?action=ticket.deny&actor=alice` filters it; `GET /api/audit/verify` recomputes the chain.
* Policy and timeout decisions are not audit entries (they are not privileged actions) but are fully recorded as timeline events with actor `policy` or `system` and as agent events.
* Bulk decisions create one entry per ticket, all carrying the same note.
* Decisions made through `AISRF_ADMIN_API_TOKEN` appear as actor `api-token`; through the in-process MCP transport as `mcp-internal`; through the CLI's direct database commands (agent creation) as `cli`. Use personal reviewer accounts for human decisions so the trail names a person.
* The ticket report (`GET /api/reports/ticket/{id}?format=pdf` and other formats) bundles findings, conversation, decision and timeline into a single dossier.

Related: [[Core-Concepts]], [[Policy-Engine]], [[Logging-Metrics-and-Audit]], [[Dashboard-Guide]], [[Notifications]].

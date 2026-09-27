# Notifications

`aisrf/notifications.py` pages reviewers on one or more webhooks when tickets need attention. The notifier subscribes to the in-process `tickets` broadcaster channel (the same events that feed the dashboard's SSE stream) and posts a payload per webhook URL for every event that passes the filters.

## Configuration

| Setting | Env var | Default | Meaning |
| --- | --- | --- | --- |
| `notify_webhook_urls` | `AISRF_NOTIFY_WEBHOOK_URLS` | `[]` | List of webhook URLs. A URL containing `hooks.slack.com` receives a Slack Block Kit payload; any other URL receives the generic JSON payload |
| `notify_events` | `AISRF_NOTIFY_EVENTS` | `["created", "expired", "failed"]` | Ticket events that trigger a post |
| `notify_min_risk` | `AISRF_NOTIFY_MIN_RISK` | `0` | Skip tickets whose `risk_score` is below this value |
| `public_url` | `AISRF_PUBLIC_URL` | `""` | Base URL for the ticket link; falls back to `http://localhost:<AISRF_PORT>` |

From the environment, lists are JSON:

```bash
AISRF_NOTIFY_WEBHOOK_URLS='["https://hooks.slack.com/services/T000/B000/xxxx", "https://ops.example.com/aisrf-hook"]'
AISRF_NOTIFY_EVENTS='["created", "expired"]'
AISRF_NOTIFY_MIN_RISK=25
AISRF_PUBLIC_URL=https://aisrf.example.com
```

From the Settings page (Notifications section) or the API:

```bash
curl -b jar -X PUT http://localhost:8080/api/settings/core -H 'Content-Type: application/json' \
  -d '{"changes": {"notify_events": ["created", "decided", "expired"], "notify_min_risk": 25}}'
```

Important: the notifier is started once in the application lifespan and only if `notify_webhook_urls` is non-empty at that moment. Adding the first webhook URL, or changing the URL list, therefore takes effect at the next restart. `notify_events`, `notify_min_risk` and `public_url` are read on every event and apply live.

## Event filters

The `tickets` channel publishes these events (from `aisrf/tickets/service.py`):

| Event | Published when | Useful for |
| --- | --- | --- |
| `created` | Policy has been applied to a new ticket, whatever the outcome (`review`, `approve` or `deny`) | Paging reviewers; combine with `notify_min_risk` to skip benign traffic. Note that auto-approved and auto-denied tickets also emit `created`; check `ticket.status` and `ticket.policy_action` in the payload if you only want PENDING ones |
| `decided` | A human approved or denied | Audit feeds; the payload adds `by` |
| `forwarding` | The request is being sent upstream | Rarely useful |
| `completed` | The upstream answered | Output monitoring; the brief ticket carries `response_status` and `latency_ms` but not the response findings |
| `failed` | Transport error or upstream 5xx | Operational alerts |
| `expired` | Nobody decided in time | Staffing alerts |

Only names listed in `notify_events` are delivered. The risk filter applies to every event, so `expired` notifications for low-risk tickets are also suppressed when `notify_min_risk` is raised.

## Slack payload

Built by `_slack_payload()` for URLs containing `hooks.slack.com`. `text` is the fallback line and `blocks` render it:

```json
{
  "text": "AISRF ticket #42 needs review: agent support-bot, model gpt-4o-mini, risk 72 (HIGH)",
  "blocks": [
    {"type": "section", "text": {"type": "mrkdwn", "text": "*AISRF ticket #42 needs review: agent support-bot, model gpt-4o-mini, risk 72 (HIGH)*"}},
    {"type": "section", "text": {"type": "mrkdwn", "text": "> Ignore all previous instructions and ..."}},
    {"type": "context", "elements": [{"type": "mrkdwn", "text": "<https://aisrf.example.com/tickets/tkt_5f...|Open ticket> | path v1/chat/completions | policy review"}]}
  ]
}
```

The verb depends on the event: `needs review` (`created`), `expired without a decision` (`expired`), `failed upstream` (`failed`), `was approved by alice` or `was denied by alice` (`decided`, using the ticket status and `by`), `completed` (`completed`). The quoted line is the first 300 characters of `prompt_preview`. The agent name falls back to the agent id and the model to `-`.

## Generic payload

Every other URL receives:

```json
{
  "source": "aisrf",
  "event": "created",
  "ticket": {
    "id": "tkt_5f...", "number": 42, "agent_id": "agt_...", "agent_name": "support-bot",
    "status": "PENDING", "source": "sdk", "correlation_id": "run-42", "method": "POST",
    "path": "v1/chat/completions", "model": "gpt-4o-mini", "is_stream": false,
    "prompt_preview": "Ignore all previous instructions and ...", "risk_score": 72, "risk_level": "HIGH",
    "finding_count": 3, "policy_action": "review", "decided_by": null, "decision_note": "",
    "decided_at": null, "expires_at": "2026-09-27T10:05:00+00:00", "response_status": null,
    "latency_ms": null, "campaign_id": null, "probe_id": null,
    "created_at": "2026-09-27T10:00:00+00:00", "updated_at": "2026-09-27T10:00:00+00:00"
  },
  "link": "https://aisrf.example.com/tickets/tkt_5f...",
  "by": null
}
```

`ticket` is the brief ticket dictionary (`ticket_to_dict(brief=True)`); `by` is the reviewer username on `decided` events and `null` otherwise. Findings, the full prompt and the response are not included; fetch `GET /api/tickets/{id}` with an admin token or session if the receiver needs them.

## Delivery

* Posts are `application/json` with a 10 s timeout through a dedicated `httpx.AsyncClient`.
* A non-2xx status logs `notify.webhook_failed` with the URL and status; exceptions log `notify.webhook_error`; nothing is retried and delivery is best effort.
* Events are processed sequentially from a queue; slow webhooks delay later notifications but never block the gateway (the broadcaster drops events for a subscriber whose queue of 1000 is full).
* Notifications are per process: with several workers each one notifies for the tickets it handled.

## Receiving with a small HTTP endpoint

```python
from fastapi import FastAPI, Request
app = FastAPI()

@app.post("/aisrf-hook")
async def hook(request: Request):
    payload = await request.json()
    t = payload["ticket"]
    if payload["event"] == "created" and t["status"] == "PENDING" and t["risk_score"] >= 50:
        print(f"review #{t['number']} {t['agent_name']} {t['risk_level']} {payload['link']}")
    return {"ok": True}
```

Related: [[Configuration-Reference]], [[Tickets-and-Review-Workflow]], [[Logging-Metrics-and-Audit]].

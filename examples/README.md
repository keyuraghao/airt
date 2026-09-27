# AISRF examples

All examples expect a running gateway and an agent key:

```bash
aisrf serve                                   # http://localhost:8080, log in with admin / admin
aisrf agent create demo --provider openai --upstream-key sk-...   # prints aisrf_... once
export AISRF_GATEWAY_URL=http://localhost:8080
export AISRF_AGENT_KEY=aisrf_...
```

While an example runs, open http://localhost:8080/tickets and approve or deny the pending ticket.
Agents default to `require_approval=true`, so every call waits for a human unless the agent's policy
auto-approves it (`auto_approve_below_risk`) or auto-denies it (`auto_deny_at_risk`, `auto_deny_patterns`).

| File | What it shows |
| --- | --- |
| `openai_sync.py` | Official `openai` SDK with `base_url=<gateway>/v1`. Blocks until the reviewer decides; prints the `X-AISRF-Ticket` id and handles 403/504 gateway errors. |
| `openai_async_mode.py` | `X-AISRF-Async: 1`: the gateway answers `202 {ticket_id, poll_url}` and the client polls `/gateway/tickets/{id}`. Shown with `AISRFClient` and with raw httpx. |
| `anthropic_client.py` | Official `anthropic` SDK with `base_url=<gateway>` (the SDK appends `/v1/messages`). Needs an agent with `upstream_provider=anthropic`. Optional streaming. |
| `langchain_example.py` | LangChain `ChatOpenAI` / `ChatAnthropic`: only `base_url` and `api_key` change. Each chain step is a ticket; a correlation id groups them. |
| `agent_loop_example.py` | A tool-using autonomous loop where every model call is ticketed. Contains a poisoned document so the indirect prompt injection shows up in the ticket findings; a reviewer can deny to stop the agent mid-run. |
| `curl.sh` | End to end with curl: log in, create an agent, submit in async mode, inspect the ticket, approve via the reviewer API, poll for the relayed answer. |
| `mcp_client_config.json` | Claude Desktop / Claude Code MCP config for `aisrf mcp` (stdio) and the streamable HTTP endpoint `/mcp`. |

Other interception modes that need no example code:

* `python -c "from aisrf.integrations import patch_httpx; patch_httpx('http://localhost:8080', 'aisrf_...')"` before importing any httpx based SDK rewrites provider hosts transparently (see `docs/INTEGRATIONS.md`).
* Node: `require("aisrf-intercept").install({ gatewayUrl, agentKey })` (see `sdk/node/README.md`).
* Anything else: `mitmdump -s aisrf/integrations/mitm_addon.py` with the mitmproxy CA trusted by the client.

Model names: set `MODEL=...` to override the defaults (`gpt-4o-mini`, `claude-3-5-haiku-latest`).

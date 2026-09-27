# External scan engines

AISRF wraps four industry red-team tools so they run *through the gateway* instead of hitting a
model directly. Every adversarial prompt a scanner sends becomes a ticket: it is analysed, policy
checked, held for human approval when the agent requires it, forwarded to the real upstream and
recorded. Each run is stored as a `Campaign` (with `config["engine"]`) plus one `ProbeResult` per
probe outcome, in the same shape as the native engine, so the existing dashboard, reports and MCP
tools show scan campaigns with no extra work.

| Engine | Transport | What it runs |
| --- | --- | --- |
| `garak` | subprocess | NVIDIA garak probe suite via its `openai.OpenAICompatible` generator |
| `promptfoo` | subprocess (node) | promptfoo `eval` of the native corpus, or `redteam` synthesised attacks |
| `pyrit` | in-process (or HTTP) | Microsoft PyRIT attacks with converters and scorers |
| `pyrit_ship` | HTTP surface + client | PyRIT-Ship compatible converter/scorer API and an external client |

Code lives under `aisrf/scanners/`:

- `base.py` shared infrastructure: the `ScanEngine` protocol, the `registry`, the gateway base-url
  helper, scan-token lifecycle, the subprocess runner that streams logs into per-agent events, the
  `ScanRunner` supervisor, result persistence and the native-shape summary, and the `TicketMatcher`
  that links a scanner's tickets back to probe outcomes.
- `garak.py`, `promptfoo.py`, `pyrit.py`, `pyrit_ship.py` the engines.
- `service.py` `create_scan_campaign`, `run_matrix`, `compare`.
- `router.py` the REST API and the PyRIT-Ship compatible routes.

## How traffic reaches the gateway

At the start of a run the engine mints a short-lived scan token bound to the campaign
(`agents.service.mint_scan_token`, purpose = engine name). Subprocess engines authenticate to the
gateway with `Authorization: Bearer <scan token>`; the in-process PyRIT target calls
`gateway.pipeline.submit` directly. Requests are tagged `X-AISRF-Source: redteam` and
`X-AISRF-Campaign-Id: <id>` so their tickets are attributed to the campaign. When the run ends the
token is revoked. Each run gets a working directory at `<data_dir>/scans/<campaign_id>/` that keeps
the generated config, raw engine output and streamed log for the report.

Point a scanner at a specific gateway URL with the `gateway_url` option; otherwise the engine uses
`settings.public_url`, falling back to `http://127.0.0.1:<port>`.

## REST API

Reads need a principal, mutations need the `reviewer` role. Every mutation writes an audit entry.

```
GET  /api/scanners                                  engines with installed / enabled / capabilities
GET  /api/scanners/{engine}/probes                  the engine's probe / plugin catalogue
POST /api/scanners/{engine}/campaigns               {name, agent_id, target_model, options, auto_start}
POST /api/scanners/{engine}/matrix                  {name, targets:[{agent_id,target_model}], options, auto_start}
GET  /api/scanners/groups/{group_id}                side-by-side matrix comparison
POST /api/scanners/campaigns/{id}/start
POST /api/scanners/campaigns/{id}/cancel
```

Scan campaigns are ordinary `Campaign` rows, so the native read endpoints work for them too:
`GET /api/redteam/campaigns/{id}`, `.../results`, `.../summary`, and the `campaigns` SSE stream.

```bash
# create and start a garak run against an agent, using a fast probe
curl -sX POST localhost:8080/api/scanners/garak/campaigns \
  -H 'Authorization: Bearer <reviewer token>' -H 'content-type: application/json' \
  -d '{"name":"nightly garak","agent_id":"agt_...","target_model":"gpt-4o-mini",
       "options":{"probes":["promptinject","encoding.InjectBase64"],"generations":1},
       "auto_start":true}'
```

## garak

garak runs as a subprocess (`python -m garak --config <generated>.yaml --spec probes.<...>`). The
generated config wires garak's `openai.OpenAICompatible` generator to `<gateway>/v1/` with the scan
token (passed through the `OPENAICOMPATIBLE_API_KEY` env var) and adds the source and campaign
headers via `extra_params.extra_headers`. garak writes a report JSONL in the run directory; AISRF
parses each `attempt` record into a `ProbeResult`: `VULNERABLE` when any detector score reaches the
eval threshold, `RESISTED` otherwise, `BLOCKED` / `ERROR` when the gateway never relayed an answer
(denied, expired, failed ticket). Tickets are linked to probes by matching the last user turn.

Key `options`: `probes` (module or class names; a bare module expands to its active classes),
`generations`, `parallel_attempts`, `eval_threshold`, `prompt_cap`, `max_tokens`,
`timeout_seconds`. Defaults for `probes` and `generations` come from
`settings integrations.garak`. Probe modules are mapped to AISRF taxonomy categories (and thus
OWASP) in `garak.py::MODULE_CATEGORY`.

## promptfoo

Two modes:

- **corpus** (default): the native attack corpus (`aisrf.redteam.corpus`) is written as promptfoo
  test cases. Each probe becomes a chat message array rendered with `{{ messages | dump }}`; the
  provider is `openai:chat` with `apiBaseUrl=<gateway>/v1`, `apiKey=<scan token>` and the source and
  campaign headers. promptfoo evaluates against the gateway; the verdict is computed by the native
  evaluators (regex indicators, canary leak, refusal, findings) so it matches a native campaign.
- **redteam**: `promptfoo redteam generate` synthesises attacks from its plugins and strategies,
  then `promptfoo eval` runs them. Generation needs an LLM (promptfoo cloud login or a
  `generation_provider` / `generation_api_key` option or setting). Verdicts come from promptfoo's
  own graders and are mapped to AISRF categories in `promptfoo.py::PLUGIN_CATEGORY`.

The gateway returns the ticket id in the `X-AISRF-Ticket` response header, which promptfoo records
under `response.metadata.http.headers`, so every result links to its exact ticket.

Key `options`: `mode`, corpus selection (`categories`, `techniques`, `severities`, `max_probes`,
`seed`), `system_prompt`, `plugins`, `strategies`, `num_tests`, `purpose`, `generation_provider`,
`concurrency`, `max_tokens`, `timeout_seconds`. The binary path is
`settings integrations.promptfoo.binary` (default `.venv/node_modules/.bin/promptfoo`).

## PyRIT

PyRIT drives the native corpus in-process by default. `AISRFGatewayTarget` is a `PromptChatTarget`
whose `send_prompt_async` renders the conversation (system prompt, prepended turns and the current
user turn) as an OpenAI chat body and pushes it through `gateway.pipeline.submit`, so there is no
HTTP hop and the ticket id is known immediately. PyRIT's memory is initialised lazily (InMemory by
default, or SQLite under `<data_dir>/pyrit` when `settings integrations.pyrit.memory` is `sqlite`).

- **converters** act as mutators on the final user turn (any argument-free text converter, e.g.
  `Base64Converter`, `ROT13Converter`, `LeetspeakConverter`); the mutated probe id is
  `<probe id>+<Converter>`.
- **scorers**: `CorpusIndicatorScorer` (canary + success-indicator regexes, the default),
  `SubStringScorer`, or `SelfAskRefusalScorer` when the LLM judge is configured
  (`AISRF_ENABLE_LLM_JUDGE` plus judge base url / key / model). The final verdict is always produced
  by the native evaluators for consistency across engines.

Set `options.mode` to `http` to instead use PyRIT's `OpenAIChatTarget` against `<gateway>/v1` with a
scan token; tickets are then linked to probes by prompt text after the run.

Key `options`: `mode`, `converters`, `scorer`, corpus selection, `system_prompt`, `concurrency`,
`max_tokens`, `path`, `extra_body`.

## PyRIT-Ship

[PyRIT-Ship](https://github.com/microsoft/PyRIT-Ship) exposes PyRIT converters, scorers and attacks
as a small REST API and ships a Burp Suite extension that calls it from Intruder. AISRF implements a
**compatible server surface** so that extension (and any PyRIT-Ship client) can point at AISRF
instead of a standalone PyRIT-Ship instance:

```
GET  /api/pyrit-ship/prompt/convert                       -> ["Base64Converter", "ROT13Converter", ...]
POST /api/pyrit-ship/prompt/convert/{converter}           {"text": "..[CONVERT]x[/CONVERT].."} -> {"converted_text": ".."}
POST /api/pyrit-ship/prompt/generate                      {"prompt_goal": ".."} -> {"prompt": ".."}
POST /api/pyrit-ship/prompt/score/SelfAskTrueFalseScorer  {scoring_true, scoring_false, prompt_response}
                                                          -> [{scoring_text, scoring_metadata, scoring_rationale}]
```

Converters run through PyRIT and honour the `[CONVERT]..[/CONVERT]` tag convention the Burp
extension uses. Scoring uses the configured LLM judge when available and a keyword heuristic
otherwise. If the caller presents a scan token (`Authorization: Bearer aisrf_scan_...`) or an
`X-AISRF-Campaign-Id` header, every converted prompt is also submitted through the gateway pipeline
as a ticket, so Burp-driven traffic is intercepted and human-approved like everything else; the
response then carries the `ticket_id`.

### Burp setup

1. Build the PyRIT-Ship Burp extension (`burp_extension`) and load the JAR into Burp
   (Extensions > Add > Java).
2. In the extension settings set **PyRIT Ship URL** to `http://<gateway host>:<port>/api/pyrit-ship`
   (default gateway port 8080). Leave the scorer as `SelfAskTrueFalseScorer` and pick a converter
   such as `ROT13Converter`.
3. To have Burp traffic ticketed, mint a scan token for the target agent and configure Burp to send
   `Authorization: Bearer <scan token>` on requests to the gateway.

An **external client** (`ShipClient`) can also call a *separate* PyRIT-Ship server configured in
`settings integrations.pyrit_ship` (`url`, `converter`, `scorer`, `timeout_seconds`);
`GET /api/pyrit-ship/external/health` reports whether it is reachable.

## Matrix runs and comparison

`POST /api/scanners/{engine}/matrix` runs the same scan spec against several targets concurrently as
sibling campaigns that share `config["group_id"]`. `GET /api/scanners/groups/{group_id}` returns a
side-by-side comparison built by `service.compare`: per-target vulnerability rates and
severity-weighted scores, a per-category vulnerability matrix (category x target), verdict totals
per target, and a ranking from most to least vulnerable.

```bash
curl -sX POST localhost:8080/api/scanners/promptfoo/matrix \
  -H 'Authorization: Bearer <reviewer token>' -H 'content-type: application/json' \
  -d '{"name":"model bake-off",
       "targets":[{"agent_id":"agt_a","target_model":"gpt-4o-mini"},
                  {"agent_id":"agt_b","target_model":"claude-3-5-haiku"}],
       "options":{"mode":"corpus","categories":["prompt_injection","jailbreak"],"max_probes":40},
       "auto_start":true}'
```

## Settings

Admins edit engine configuration live under the `integrations` settings namespace:
`garak` (`enabled`, `default_probes`, `generations`), `promptfoo` (`enabled`, `binary`,
`default_plugins`, `strategies`), `pyrit` (`enabled`, `default_converters`, `scorer`, `memory`) and
`pyrit_ship` (`url`, `converter`, `scorer` for the external client). Disabling an engine only hides
it from `GET /api/scanners`; `installed()` still reflects whether the tool is present.

## Limitations

- garak sends its own conversations, so a per-probe system prompt is not applied in garak runs; its
  tickets are linked to probes by prompt text after the run (the other engines link exactly).
- promptfoo regex success indicators are graded by the native evaluators, not by promptfoo
  assertions; `redteam` generation needs promptfoo cloud or a configured generation provider.
- PyRIT-Ship is a stateless converter/scorer/attack surface, not a batch scanner, so it has no
  campaign run of its own.
- Subprocess engines need their binaries present (garak importable, `promptfoo` on disk); the API
  reports `installed: false` when they are not.

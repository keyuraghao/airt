# Dashboard Guide

The reviewer dashboard is a server rendered shell (`aisrf/dashboard/router.py`, Jinja2 templates in `aisrf/dashboard/templates/`) whose pages load their data from the [[REST-API-Reference]] and the SSE streams through plain JavaScript (`aisrf/dashboard/static/*.js`, shared helpers in `app.js`). Nothing is cached server side; every view stays live without reloads.

## Access and roles

- Every page except `/login` requires a session. Without one the server answers `303` to `/login?next=<original path and query>`; after signing in the browser returns to that path (only relative paths are accepted).
- Roles ([[Security-Model]]): `viewer` sees everything read only; `reviewer` can decide tickets, run campaigns, groups and code review runs and change finding status; `admin` additionally manages agents, reviewers, settings, credentials and imports. Buttons that need a higher role are hidden or disabled, and the API enforces the same rules.
- A `401` from any API call redirects to the login page; other errors surface as red toasts.

## Shell (every page)

| Element | Behaviour |
| --- | --- |
| Navigation | Overview, Queue (with the pending counter pill), Agents, Logs, Red team, Code review, Reports, Audit, Settings. The active entry is highlighted; ticket, agent, campaign, group and run detail pages highlight their parent |
| Pending pill and title | Updated from `GET /api/tickets/stats` (debounced 300 ms) after every ticket event; the browser tab title becomes `(n) <page>` |
| Connection dot | `#nav-conn` shows whether the shared ticket stream is connected (tooltip `Live stream connected` or `Live stream disconnected, reconnecting`) |
| User area | username, role badge, `Theme` button (toggles light and dark, stored in `localStorage` under `aisrf.theme`, overrides the server default), `Logout` (calls `POST /api/auth/logout`) |
| Footer | app name, version, environment and the approval timeout in seconds |
| Toasts | bottom right, `ok`, `warn`, `error`; errors stay 6 s |
| Modals | `Escape` or a click on the backdrop closes; note dialogs submit with `Ctrl+Enter` (`Cmd+Enter` on macOS) |
| Relative times | `<time>` elements refresh every second; hovering shows the absolute timestamp. `date_format: absolute` in the UI settings inverts this |
| Countdowns | pending tickets show the time left until expiry; the last 60 seconds are highlighted |

### Live updates

`app.js` implements SSE with `fetch` and a streaming parser (so open ended event names work), automatic reconnect with exponential back off from 1 s to 15 s, pause and resume, and a per page status callback. The shared ticket stream (`/api/stream/tickets?replay=0`) is opened once per page and fanned out to page modules; pages that need campaign, log or code review events open their own stream.

### Theme and branding

The `ui` settings namespace ([[Settings-Center]]) is fetched on every page (`GET /api/settings/ns/ui`) and applied by `AISRF.applyUi`:

| Key | Default | Effect |
| --- | --- | --- |
| `theme` | `auto` | `auto` follows the operating system, `dark` or `light` forces it; the per browser `Theme` button wins |
| `brand_name` | `AISRF` | replaces the name in the navigation, the login card and the tab title suffix |
| `accent_color` | `""` | hex colour for the accent (buttons, active tabs, links); an empty value keeps the built in accent |
| `refresh_seconds` | 5 | fallback polling interval for stats on the overview when the stream is disconnected (0 disables) |
| `sound_on_new_ticket` | `true` | default for the audible alert on the queue; each browser can override it (`localStorage` `aisrf.sound`) |
| `queue_default_status` | `PENDING` | tab selected when the queue opens |
| `date_format` | `relative` | `relative` (`5m ago`) or `absolute` timestamps |
| `ticket_columns` | `[]` | reserved |

The last applied UI document is cached in `localStorage` (`aisrf.ui`) so branding appears before the API answers.

## Login (`/login`)

A single card with the brand mark, username and password fields, an inline error box and `Sign in`. Submits `POST /api/auth/login`; a 401 shows `Invalid username or password.` and refocuses the password field. A signed in user who opens `/login` is redirected to `next` or `/`. The version is printed under the form.

## Overview (`/`)

| Panel | Content |
| --- | --- |
| Header buttons | `Open review queue`, `Register agent`, `New campaign`, `Reports` |
| Tiles | `Pending review` (red `hot` style when non zero), `Total tickets`, `Denied`, `Last 24h`, `Avg decision time` (human reviewers), `Avg upstream latency` (forwarded requests) |
| Risk level distribution | stacked bar and legend over `NONE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` with counts and percentages |
| Status breakdown | stacked bar over `PENDING`, `APPROVED`, `FORWARDING`, `COMPLETED`, `DENIED`, `EXPIRED`, `FAILED` |
| Tickets per agent | table of agents sorted by ticket count: name (link), tickets, requests, last seen |
| Live ticket feed | newest first, up to 60 items: time, event badge, ticket link, agent, risk badge, prompt preview. Seeded with the last 15 tickets, then fed by the stream |
| Recent pending | the 8 newest `PENDING` tickets with risk badge, number, preview and age |

Stats and the pending list reload (debounced 800 ms) on every ticket event; when the stream is down they poll every `refresh_seconds`.

## Review queue (`/tickets`)

| Control | Behaviour |
| --- | --- |
| Status tabs | `Pending` (with live count pill), `All`, `Denied`, `Completed`, `Expired`, `Failed`. `?status=` in the URL or `queue_default_status` selects the initial tab; `?agent_id=` and `?campaign_id=` pre-filter |
| Filters | agent select, minimum risk (`10+`, `30+`, `60+`, `90+`), source (`gateway`, `mitm`, `sdk`, `redteam`), free text search over prompt, id, path and correlation id (debounced 300 ms) |
| `Sound` checkbox | audible beep on new pending tickets that match the current filters, plus a toast `New ticket #n from <agent> (risk r)` |
| `Refresh` | reloads the page of results |
| Select all | checks every pending row on the page; the bulk bar shows `n selected`, `Approve selected`, `Deny selected` (reviewer role) and asks for one note applied to every ticket |
| Table columns | checkbox, `#`, created (with expiry countdown for pending rows), agent (link), model, path, risk badge with score, findings count, policy badge, prompt preview, status badge, actions |
| Row actions | `Approve` and `Deny` buttons on pending rows (each opens a note dialog); decided rows show `by <reviewer>` with the note as tooltip. Single click selects the row (keyboard cursor), double click opens the ticket |
| Pager | `Prev`, `Page x of y (n total)`, `Next`, 50 rows per page |

Keyboard shortcuts (ignored while typing in a field):

| Key | Action |
| --- | --- |
| `j` / `k` | move the cursor down / up |
| `a` | approve the ticket under the cursor (note dialog) |
| `d` | deny it |
| `x` | toggle selection of the pending ticket under the cursor |
| `Enter` | open the ticket page |
| `r` | reload |

Live behaviour: every ticket event upserts the row in place (matching rows flash; rows that no longer match the filters disappear; new matching tickets are inserted at the top of the first page). Badges: status colours follow the lifecycle (`PENDING` amber, `COMPLETED` green, `DENIED` red, `EXPIRED` grey, `FAILED` dark red); risk badges use the level colour and show the numeric score; the policy badge shows the policy action (`review`, `auto_approve`, `auto_deny`, ...).

## Ticket detail (`/tickets/{id}`)

Header: `Queue` back link, `Ticket #n`, badges for status, risk (with score), policy action and source (when not `gateway`), links `Agent: <name>`, `Campaign` (when created by a campaign) and `More from this agent`. The tab title becomes `#n STATUS - AISRF`.

| Card | Content |
| --- | --- |
| Decision | note textarea, `Approve` and `Deny` (enabled only while `PENDING` and for reviewers), state text (`waiting for a decision` or `closed`), hint (`Your role can only view tickets`, or `This ticket is denied (by alice)`). Shortcuts `a` and `d` work here too |
| Conversation | one bubble per normalized message (`system`, `developer`, `user`, `assistant`, `tool`), evidence from findings highlighted inside the text, a collapsible `Tools offered (n)` chip list; meta shows message, tool and character counts |
| Response | `assistant (preview)` bubble with response finding evidence highlighted, collapsible raw response body (pretty printed JSON) and response headers; `Nothing was sent upstream` for denied or expired tickets |
| Request | collapsible redacted request headers, raw request JSON and the normalized request |
| Summary | id (click to copy), correlation id, agent, model, endpoint, upstream URL, provider, stream flag, client IP and user agent, created, expires (live countdown while pending), decided, decision note, forwarded, response status and latency, analysis time, error, probe id |
| Findings | cards sorted by severity: severity badge, title, analyzer and confidence, description, evidence, taxonomy chips (OWASP LLM Top 10, Greshake, Thacker; see [[Taxonomy-and-OWASP-Mapping]]) |
| Response findings | same layout for findings on the upstream response |
| Policy decision | action badge, matched rules, reasons |
| Timeline | every ticket event with actor, time and detail |
| Reports | one button per format for `ticket/<id>` |

The page reloads itself whenever a stream event concerns this ticket.

## Agents (`/agents`)

Table: name (link, with description), provider badge, upstream URL, approval (`required` or `auto`), thresholds (`approve <x, deny >=y, n/min`), requests, last seen, active badge, `Open`. `Show disabled` includes inactive agents. `Register agent` (admin only) reveals the creation form:

| Field | Maps to |
| --- | --- |
| Name, Owner, Description, Tags (comma separated) | `name`, `owner`, `description`, `tags` |
| Upstream provider (`openai`, `anthropic`, `custom`), Upstream base URL, Upstream API key (stored encrypted, never shown again), Custom auth header, Extra upstream headers (JSON object) | `upstream_*` |
| Auto approve below risk (0 disables), Auto deny at risk (101 disables) | `auto_approve_below_risk`, `auto_deny_at_risk` |
| Auto deny patterns, Allowed paths, Allowed models (one per line) | lists |
| Rate limit per minute (0 = unlimited) | `rate_limit_per_minute` |
| Require human approval, Inject canary word (Rebuff style) | `require_approval`, `inject_canary` ([[Canary-Words]]) |

After creation a modal shows the API key once with `Copy`, the warning that it cannot be recovered, and integration snippets (curl, OpenAI SDK, Anthropic SDK, LangChain) for the new agent; close it with `I stored the key`.

## Agent detail (`/agents/{id}`)

Header: back link, name, badges `active` or `disabled` and the provider, buttons `Rotate key` (confirmation, then the key modal), `Disable` (confirmation) or `Enable`, and `Report` (HTML report inline). Tiles: `Requests`, `Tickets`, `Pending`, `Completed`, `Denied`, `Avg risk`.

| Card | Content |
| --- | --- |
| Configuration | the same form as creation, pre-filled, `Save changes` sends `PATCH /api/agents/{id}` (an empty upstream key keeps the stored one) |
| Recent tickets | the 15 newest tickets of the agent, link `view in queue` |
| Identity | id, key prefix, owner, upstream key state (`stored (encrypted)` or `none, client must send its own`), created, last seen |
| Integration | snippet panel with tabs and `Copy` |
| Live log | `/api/stream/logs?agent_id=<id>&replay=50` console: level filter (`DEBUG`, `INFO`, `WARNING`, `ERROR`), `Pause` / `Resume`, `Clear`, `Load history` (last 300 events from `GET /api/agents/{id}/events`), `Download JSON`, status `live` or `reconnecting` |

Tickets and tiles refresh on ticket events for this agent.

## Logs (`/logs`)

A full height console of every agent event from `/api/stream/logs?replay=200` (up to 3000 records kept). Controls: agent select (`?agent_id=` pre-selects), minimum level, text filter (matches the JSON of the record), `Pause` / `Resume`, `Clear`, `Download JSON`, `Follow` (auto scroll) and the `live` / `reconnecting` status. Each line shows time, level, agent (link), event and ticket link when present.

## Red team (`/redteam`)

| Panel | Content |
| --- | --- |
| Campaigns | name (link), agent, target, status badge, progress bar, vulnerable count badge, created, by, `Open`; status `live` / `reconnecting` of the campaign stream |
| Comparison groups | name, targets, status badges with counts, created; `Open`, and for reviewers `Start` (when any campaign is `CREATED` or `PAUSED`), `Cancel` (when running), `Delete` (when not running), each with a confirmation |
| Create campaign form | opened with `New campaign`; tabs `Single target` and `Compare models` |
| Corpus browser | category select with counts, severity (`LOW` to `CRITICAL`), search, paginated probe table (ID, category, technique, severity badge, name, prompt) |

Campaign form fields: name, agent (single mode), target model, path (`/v1/chat/completions` placeholder), max probes (default 50, 0 = all), concurrency (1 to 32, default 4), seed, mutator chips, category checklist with search, `All` and `None`, technique chips, system prompt, extra request body (JSON), `Start immediately` (checked). The summary line shows `<n> categories, <m> probes in scope, sampled to <max>`. In compare mode a target list (agent, target model, optional label; minimum two, `Add target`, `Remove`) replaces the single agent and the submit button reads `Create comparison group`; the browser then opens the group page. See [[Red-Teaming]], [[Probe-Corpus]], [[Comparison-Groups]].

Live: `campaign.status`, `progress`, `result` and `completed` events on `/api/stream/campaigns` update the row and reload the tables (debounced).

## Campaign (`/redteam/{campaign_id}`)

Header: back link, name, status badge, `target: <label>` chip and `Open comparison group` when it belongs to a group. Controls (reviewer): `Start` (`CREATED`), `Pause` (`RUNNING`), `Resume` (`PAUSED`), `Cancel` (`CREATED`, `RUNNING`, `PAUSED`; confirmation `Stop the campaign and keep the results gathered so far?`), `Delete` (any state but `RUNNING`; confirmation). Tiles: `Vulnerable` (hot when non zero), `Resisted`, `Blocked`, `Errors`, `Vulnerability rate`, `Weighted score`.

| Card | Content |
| --- | --- |
| Progress | bar and `<done>/<total>` text, verdict distribution bar with legend |
| Vulnerability rate per category | horizontal bars |
| OWASP LLM Top 10 breakdown | id chip, name, tested, vulnerable, rate |
| Results | filters verdict (`VULNERABLE`, `RESISTED`, `BLOCKED`, `INCONCLUSIVE`, `ERROR`, `PENDING`) and category; table with expander (`+`), probe, category, technique, severity badge, verdict badge, confidence, latency, ticket link, time; the expander shows the prompt, the response and the evidence |
| Details | id, agent, target, status, counters, creator, timestamps, error |
| Configuration | the JSON config |
| Reports | one button per format for `campaign/<id>` |

Stream events for this campaign patch the header, tiles and progress immediately and reload results (debounced 1.2 s).

## Comparison group (`/redteam/groups/{group_id}`)

Header badges show the status counts of the member campaigns; controls: `Download comparison JSON`, and for reviewers `Start`, `Cancel`, `Delete` with confirmations.

| Card | Content |
| --- | --- |
| Ranking | podium ordered by severity weighted score (lower is better) with the vulnerability rate and status of each target |
| Progress per target | target label, agent, model, status, progress bar, stacked verdict bar, score, rate, report buttons |
| Vulnerability heatmap | rows are probe categories, columns the targets; cell colour follows the rate and the tooltip shows `vulnerable / tested` |
| OWASP LLM Top 10 coverage | chips `covered` or `uncovered` with the categories that exercise each item |
| Per-probe matrix | category filter, `Only probes that differ between targets`, one row per probe with the verdict per target; `+` loads each target's result (verdict, confidence, response, evidence, prompt text) |

Campaign stream events reload the comparison (debounced 1 s).

## Code review (`/codereview`)

`New run` opens the form with source tabs `Git repository` (URL, ref, access token used once and never stored, saved credential select for admins), `Archive URL` (URL, optional bearer token), `Upload archive` (zip, tar, gz, tgz, bz2, tbz2, xz, txz), `Local path` (admins only, directory under the data directory or the allowlist) and `Paste snippet` (language select from Python to Dockerfile and `Prompt text`, code textarea). Below: rule pack chips (`All`, `None`; none selected = all), engine chips (`AISRF rules`, `semgrep`, `bandit`, `LLM-assisted`), include and exclude globs, `Start review`; on success the browser opens the run page.

| Panel | Content |
| --- | --- |
| Runs | status filter (`CREATED`, `FETCHING`, `ANALYZING`, `COMPLETED`, `FAILED`, `CANCELLED`); table with name (link), source chip and ref, status badge, progress (stage and files), files, findings, risk badge, created, by; reviewers see `Cancel` on running rows and `Delete` |
| Saved credentials (admin) | label, provider, username, created, by, `Delete`; form with label, provider (`GitHub`, `GitLab`, `Bitbucket`, `Azure DevOps`, `Generic`), username, token, `Save credential`. Tokens are encrypted at rest and passed to git through an askpass helper |
| Rule catalogue | pack, severity and text filters; expandable rows with id, pack, severity, title, OWASP, CWE, engines and, when expanded, why it matters, remediation, confidence and languages |

`/api/codereview/stream` updates status, stage, progress and counters of the visible runs live.

## Code review run (`/codereview/{run_id}`)

Header: back link, name, status badge, commit chip; controls `Cancel run` (reviewer, while not terminal), `Download SARIF`, `Delete` (reviewer, confirmation). Tiles: `Risk score` (hot at 60 or above, with level), `Critical`, `High`, `Medium`, `Low and info`, `Files` (with skipped counts), `Lines of code`, `Languages`. The progress bar advances through the stages `created`, `intake`, `inventory`, `rules`, `semgrep`, `bandit`, `llm`, `persist`, `completed`; failures show the error box.

| Card | Content |
| --- | --- |
| Findings | filters severity, pack, engine (`rules`, `semgrep`, `bandit`, `llm`), status (`open`, `false positive`, `accepted`), file path, text search; table with expander, severity badge, rule, title, file, line, engine, confidence, status badge; the expander shows description, why it matters, remediation, chips (engine, confidence, fingerprint), reviewer note, and actions `Open file`, `False positive`, `Accept risk`, `Reopen` (each status change asks for a note) |
| File | source viewer with line numbers, lines with findings highlighted and the selected line focused; `Close` |
| Open findings | bars by severity and by pack |
| OWASP LLM Top 10 | chips with the count of open findings per item |
| Inventory | languages, frameworks, model artifacts, dependency manifests, intake details |
| Engines | engine, findings, seconds, note (`not installed` or errors) |
| Details | id, source, ref, status, stage, creator, timestamps |
| Reports | one button per format for `codereview/<id>` (SARIF for GitHub code scanning) |

`run.progress` events show `analysing, <stage> <done>/<total> files`; `finding.status` reloads the findings; `run.deleted` returns to the list.

## Reports (`/reports`)

Filters (`Since`, `Until`, `Agent`, `Campaign`, `Ticket status`, `Ticket id`) feed a matrix of report kinds (rows, with description and accepted params) by formats (columns). Each cell is a download button; `html` and `pdf` open inline in a new tab. Kinds that need a selection (`ticket`, `agent`, `campaign`) show `select ticket`, `select agent` or `select campaign` until the filter is set. The formats card lists every format with its media type. See [[Reports]].

## Audit (`/audit`)

Filters `action` (for example `ticket.approve`) and `actor` (Enter or `Apply`), `Verify chain` (shows `chain intact` with the number of entries checked, or `chain broken` with the raw result). Table: `#`, time, actor, action badge (last segment) with the full action, target (linked for tickets, agents and campaigns), detail (collapsible JSON), previous hash and hash (first 12 characters, click to copy the full hash). 100 rows per page. See [[Logging-Metrics-and-Audit]].

## Settings (`/settings`)

Left sub navigation (the last opened section is remembered in `localStorage`): `General`, `Gateway`, `Security`, `Notifications`, `Analysis`, `Red team`, `Advanced`, `UI`, `Policy`, `Rules`, `Analyzers`, `Integrations`, `Reviewers`, `Export / Import`, `About`. The header hint states the precedence `dashboard override > environment > default`, and the status line counts core settings and namespaces. Full semantics of every key are on [[Settings-Center]] and [[Configuration-Reference]].

| Section | Content and controls |
| --- | --- |
| General, Gateway, Security, Notifications, Analysis, Red team, Advanced | schema driven rows for the core settings of that group: control per type (text, number, toggle, list textarea, password with mask), the environment variable name, a lock icon for environment only keys (`database_url`, `host`, `port`, ...), per row `Reset`; admins get `Save <group>` and `Reset group to defaults`; other roles see everything read only |
| UI | theme (`auto`, `dark`, `light`), brand name, accent colour (live preview), refresh seconds, sound on new ticket, queue default status, date format; `Save UI`, `Preview reset`, raw JSON editor |
| Policy | global auto deny patterns (regex per line, with a live regex tester), global allowed paths, `block_on_canary_leak`, `quarantine_on_critical_response_finding`; `Save policy` validates every regex ([[Policy-Engine]]) |
| Rules | editable table of custom rules (id, name, pattern, category, severity, scope `request` / `response` / `both`, action `flag` / `deny`, enabled, ordering buttons, delete), a tester that runs every enabled rule in the browser, `Add rule`, `Save rules` (unique ids and valid patterns required) ([[Custom-Rules]]) |
| Analyzers | enable or disable each analyzer, severity override per analyzer and per category, confidence floor slider; `Save analyzers` ([[Analyzers]]) |
| Integrations | one card per integration (`llm_guard`, `nemo_guardrails`, `lakera`, `rebuff`, `garak`, `promptfoo`, `pyrit`, plus any extra): enabled toggle and typed controls for every key; api keys are masked and kept unless replaced; `Save <name>` per card ([[Guardrails]], [[Scanner-Engines]]) |
| Reviewers | admins: table (username, role badge, active, last login, `Password`, `Deactivate` except self) and a create form (username, password, role); everyone: current session (username, role, id, auth via), `Change my password`, and the gateway integration snippet with the OpenAI style, Anthropic style, generic proxy, async mode and automation hints |
| Export / Import | `Download settings.json` with `include secrets` checkbox, file picker with a preview of the core keys and namespaces, `Import` (confirmation; replaces existing overrides) |
| About | application, version, environment, approval timeout, links to `/api/docs`, `/metrics`, `/healthz`, and the taxonomy tables (OWASP LLM Top 10, category mapping, Greshake threats and delivery methods, Thacker techniques, references) |

Every namespace section also offers a `Raw JSON editor` (with `Format` and `Save raw document`) and, for admins, `Reset namespace`.

## Role differences at a glance

| Action | viewer | reviewer | admin |
| --- | --- | --- | --- |
| Browse tickets, agents, logs, campaigns, runs, reports, audit, settings | yes | yes | yes |
| Approve, deny, bulk decide | | yes | yes |
| Create, start, pause, resume, cancel, delete campaigns and groups | | yes | yes |
| Start, cancel, delete code review runs, change finding status | | yes | yes |
| Register, edit, rotate, disable agents | | | yes |
| Save settings, policy, rules, analyzers, integrations, UI | | | yes |
| Local path intake, stored credentials | | | yes |
| Manage reviewers, export and import settings | | | yes |
| Change own password | yes | yes | yes |

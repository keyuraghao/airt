# CLI Reference

The `aisrf` command is a [Typer](https://typer.tiangolo.com) application defined in `aisrf/cli.py` and installed as the console script `aisrf` (`pyproject.toml`, `[project.scripts]`). A second script, `aisrf-desktop`, is the entry point of [[Desktop-Mode]].

Two families of commands exist:

- Local commands (`serve`, `init-db`, `create-reviewer`, `agent ...`, `desktop`) open the database directly and read the same `AISRF_*` environment variables and `.env` file as the server ([[Configuration-Reference]]). They must run on the gateway host or against the same database.
- Remote commands (`tickets`, `redteam`, `audit`, `codereview`, `report`, `mcp`) talk to a running gateway over the [[REST-API-Reference]] with the admin token and can run anywhere.

```bash
aisrf --help
aisrf tickets list --help
```

Every command and group prints usage with `--help`; running a group without a subcommand also prints its help (`no_args_is_help`).

## Global options and environment variables

The root command has no global options apart from `--install-completion`, `--show-completion` and `--help`. Connection settings are per command:

| Option | Environment variable | Default | Used by |
| --- | --- | --- | --- |
| `--url <str>` | `AISRF_URL` | `http://127.0.0.1:8080` | every remote command |
| `--token <str>` | `AISRF_ADMIN_API_TOKEN` | none (required) | every remote command; the value is sent as `Authorization: Bearer` and must equal `AISRF_ADMIN_API_TOKEN` on the server |

Local commands honour the server configuration variables, in particular `AISRF_DATABASE_URL`, `AISRF_HOST`, `AISRF_PORT`, `AISRF_WORKERS`, `AISRF_LOG_LEVEL`, `AISRF_ADMIN_USERNAME` and `AISRF_ADMIN_PASSWORD`.

Terminal rendering uses [Rich](https://rich.readthedocs.io); `NO_COLOR=1` disables colour and `COLUMNS` controls the table width, which matters when piping output.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | success |
| 1 | any handled error: missing admin token, gateway unreachable, HTTP status >= 400 (message `error: GET /api/... failed with HTTP <status>: <detail>` on stderr), unknown agent or reviewer, invalid role, missing archive, empty `--token-env` variable, desktop server failed to start |
| 2 | usage error reported by Typer (unknown option, missing argument, value out of range); `audit verify` when the chain is broken; `codereview run` when the run ends in `FAILED`; `aisrf-desktop` with an unknown argument |

Errors are written to stderr as `error: <message>`; normal output goes to stdout.

## Output formats

- Tables and key value panels are rendered with Rich to stdout.
- Secrets that must be captured (agent API keys) are printed with a plain `API key: <value>` line so they can be grepped or piped even when Rich decoration is present.
- `report` and `codereview run --format` write the report bytes to a file and print the path, size and content type.
- `tickets watch` prints one line per event; `redteam run --wait` and `codereview run --wait` show a spinner status line while polling.
- There is no `--json` switch. For machine readable data call the REST API (or `report <kind> -f json`).

## Command index

| Command | Kind | Purpose |
| --- | --- | --- |
| `aisrf version` | local | print the version |
| `aisrf serve` | local | run the gateway with uvicorn |
| `aisrf init-db` | local | create the schema and the default admin |
| `aisrf create-reviewer` | local | create a reviewer account |
| `aisrf agent create` | local | register an agent and print its key |
| `aisrf agent list` | local | list agents |
| `aisrf agent rotate-key` | local | issue a new key |
| `aisrf tickets list` | remote | list tickets |
| `aisrf tickets show` | remote | one ticket in full |
| `aisrf tickets approve` | remote | approve a pending ticket |
| `aisrf tickets deny` | remote | deny a pending ticket |
| `aisrf tickets watch` | remote | tail the live ticket stream |
| `aisrf redteam corpus` | remote | show the probe corpus |
| `aisrf redteam run` | remote | create and start a campaign |
| `aisrf audit verify` | remote | verify the audit hash chain |
| `aisrf codereview run` | remote | start a code review run |
| `aisrf codereview list` | remote | list runs |
| `aisrf codereview show` | remote | one run with findings |
| `aisrf codereview rules` | remote | rule catalogue |
| `aisrf report` | remote | generate and save a report |
| `aisrf mcp` | remote | stdio MCP server |
| `aisrf desktop` | local | desktop mode |

## aisrf version

Prints `aisrf <version>`.

## aisrf serve

Run the gateway with uvicorn using the application factory `aisrf.main:create_app`.

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `--host` | str | `AISRF_HOST` or `0.0.0.0` | bind address |
| `--port` | int | `AISRF_PORT` or `8080` | bind port |
| `--workers` | int | `AISRF_WORKERS` (1) | worker processes; only applied when greater than 1 and `--reload` is off |
| `--reload` | flag | off | auto reload on code changes (development only) |

The log level comes from `AISRF_LOG_LEVEL`. In multi worker mode use an external database (see [[Deployment]]); the ticket hold registry and SSE broadcaster are per process.

```bash
aisrf serve --port 9000 --reload
AISRF_WORKERS=4 aisrf serve
```

## aisrf init-db

Creates the database schema and the default admin reviewer (`AISRF_ADMIN_USERNAME` / `AISRF_ADMIN_PASSWORD`, default `admin` / `admin`). Prints `database ready (<database url>)`. Idempotent; the server does the same at startup, so this is mainly for provisioning pipelines. A warning is logged when the password is still `admin`.

## aisrf create-reviewer

`aisrf create-reviewer USERNAME --password <pw> [--role reviewer]`

| Argument or option | Type | Default | Description |
| --- | --- | --- | --- |
| `username` | str | required | login name |
| `--password` | str | prompted (hidden, with confirmation) when omitted | password |
| `--role` | str | `reviewer` | `viewer`, `reviewer` or `admin` |

Fails with exit 1 when the role is unknown or the username exists. The creation is audited with actor `cli`.

```bash
aisrf create-reviewer alice --role admin
```

## aisrf agent

Direct database access; the gateway need not be running, but if it is the new agent is usable immediately.

### aisrf agent create

`aisrf agent create NAME [options]`. Registers an agent and prints its AISRF API key once (`API key: aisrf_...`) after a warning panel. Audited as `agent.create`.

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `name` (argument) | str | required | unique agent name |
| `--provider` | str | `openai` | upstream provider: `openai`, `anthropic`, `azure`, `ollama` or `custom` (any value accepted by the forwarder works) |
| `--base-url` | str | provider default | upstream base URL |
| `--upstream-key` | str | none | upstream provider API key, stored encrypted |
| `--approval` / `--no-approval` | flag | `--approval` | require a human decision for every request |
| `--auto-deny-at` | int 0 to 101 | 90 | auto deny at this risk score (101 disables) |
| `--auto-approve-below` | int 0 to 100 | 0 | auto approve below this score (0 disables) |
| `--deny-pattern` | str, repeatable | none | regex that auto denies matching prompts |
| `--allowed-path` | str, repeatable | none (all) | allowed upstream path glob |
| `--allowed-model` | str, repeatable | none (all) | allowed model name |
| `--rate-limit` | int >= 0 | 0 | requests per minute, 0 = unlimited |
| `--description` | str | `""` | free text |
| `--owner` | str | `""` | owning team or person |
| `--tag` | str, repeatable | none | tag |

`inject_canary`, `upstream_auth_header` and `upstream_extra_headers` are not exposed here; set them through the API or the dashboard.

```bash
aisrf agent create support-bot --provider openai --upstream-key "$OPENAI_API_KEY" \
  --auto-approve-below 20 --deny-pattern '(?i)ignore (all )?previous instructions' --allowed-model 'gpt-4o*' --tag prod
```

### aisrf agent list

| Option | Default | Description |
| --- | --- | --- |
| `--all` / `--active-only` | `--all` | include disabled agents |

Columns: `id`, `name`, `upstream_provider`, `api_key_prefix`, `require_approval`, `auto_deny_at_risk`, `is_active`, `request_count`. Prints `no agents registered` when empty.

### aisrf agent rotate-key

`aisrf agent rotate-key AGENT_ID` where the argument is an agent id or name. Prints `rotated key for agent <id>` and `API key: <new key>`. The old key stops working immediately. Audited as `agent.rotate_key`.

## aisrf tickets

All subcommands take `--url` and `--token`.

### aisrf tickets list

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `--status` | str | all | comma separated states (`PENDING`, `APPROVED`, `DENIED`, `EXPIRED`, `FORWARDING`, `COMPLETED`, `FAILED`) |
| `--agent` | str | | agent id |
| `--min-risk` | int | | minimum risk score |
| `--limit` | int | 50 | maximum rows (server cap 500) |

Columns: `number`, `id`, `status`, `agent_name`, `model`, `risk_score`, `risk_level`, `prompt_preview`, `created_at`. The table title shows the total count.

### aisrf tickets show

`aisrf tickets show TICKET_ID` (id or number). Prints a summary panel (`id`, `number`, `status`, `agent_name`, `agent_id`, `model`, `method`, `path`, `risk_score`, `risk_level`, `policy_action`, `decided_by`, `decision_note`, `created_at`, `expires_at`), the findings table (`severity`, `analyzer`, `title`, `detail`), the prompt preview and the event timeline (`ts`, `event_type`, `actor`).

### aisrf tickets approve and deny

`aisrf tickets approve TICKET_ID [--note TEXT]`, `aisrf tickets deny TICKET_ID [--note TEXT]`. Prints `ticket <id> is now APPROVED` (or `DENIED`). A ticket that is not `PENDING` yields HTTP 409 and exit 1.

### aisrf tickets watch

Tails `GET /api/stream/tickets` and prints one coloured line per event: created time, status, number, id, agent, risk score and level, event name and the first 80 characters of the prompt. `ping` events are skipped. Stop with Ctrl+C (prints `stopped`).

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `--status` | str | all | only print tickets in this status |
| `--replay` | int | 0 | recent events to replay on connect |

```bash
aisrf tickets watch --status PENDING --replay 10
```

## aisrf redteam

### aisrf redteam corpus

Prints the corpus (`GET /api/redteam/corpus`): scalar totals, a table of categories with technique lists and probe counts, and the mutator list.

### aisrf redteam run

Creates a campaign with `auto_start=true` (and calls `start` when the server left it in `CREATED`), then optionally polls until it finishes and prints the summary.

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `--agent` | str | required | agent id the probes are sent through |
| `--model` | str | required | target model |
| `--name` | str | `cli-<model>-<YYYYMMDD-HHMMSS>` | campaign name |
| `--category` | str, repeatable | all | probe category |
| `--technique` | str, repeatable | all | probe technique |
| `--mutator` | str, repeatable | none | mutator to apply |
| `--max-probes` | int | none | cap the probe count |
| `--system-prompt` | str | none | system prompt sent with every probe |
| `--path` | str | `v1/chat/completions` (server default) | upstream path override |
| `--concurrency` | int | server default | parallel probes |
| `--seed` | int | none | random seed for probe selection |
| `--wait` / `--no-wait` | flag | `--wait` | block until the campaign reaches `COMPLETED`, `FAILED` or `CANCELLED` and print the summary |
| `--poll-interval` | float | 3.0 | seconds between status polls |

With `--wait` the status line shows `<state> <done>/<total> probes`; afterwards the summary is printed as key value and per category tables.

```bash
aisrf redteam run --agent agt_demo --model gpt-4o-mini --category prompt_injection --category jailbreak --max-probes 50
aisrf report campaign/cmp_123 -f junit -o results.xml
```

## aisrf audit verify

Calls `GET /api/audit/verify` and prints the result (`ok`, `checked`, `head` or `broken_at`). Exit code 2 when `ok` is false, which makes it usable as a CI or cron check.

## aisrf codereview

### aisrf codereview run

Starts a run from exactly one source and, by default, waits for it. Exactly one of `--git`, `--zip`, `--url` or `--path` is required (`error: give one of --git, --zip, --url or --path`).

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `--git` | str | | git repository URL (GitHub, GitLab, Bitbucket or generic) |
| `--ref` | str | default branch | branch, tag or commit for `--git` |
| `--token-env` | str | | name of an environment variable holding the access token for `--git` or `--url` (the value is read locally and sent once; exit 1 when the variable is empty) |
| `--credential` | str | | id of a stored credential (admin token required) |
| `--zip` | path | | local zip or tar archive uploaded with `multipart/form-data` |
| `--archive-url` | str | | HTTP(S) URL of a zip or tar archive |
| `--path` | str | | directory on the server (admin only, must be allowlisted) |
| `--name` | str | archive name or `""` | run name |
| `--packs` | str, repeatable | all | rule pack |
| `--engines` | str, repeatable | server defaults | `rules`, `semgrep`, `bandit`, `llm` |
| `--include`, `--exclude` | str, repeatable | | file globs |
| `--wait` / `--no-wait` | flag | `--wait` | block until `COMPLETED`, `FAILED` or `CANCELLED` |
| `--format`, `-f` | str | none | report format to download after completion (`sarif`, `json`, `html`, `pdf`, ...) |
| `--out`, `-o` | path | `aisrf-codereview-<run id>.<format>` | output file for `--format` |
| `--poll-interval` | float | 2.0 | seconds between polls |
| `--url` | str | `AISRF_URL` | Base URL of the running gateway |
| `--token` | str | `AISRF_ADMIN_API_TOKEN` | admin token |

After completion the summary (`risk_score`, `risk_level`, `open`, `by_severity`, `by_pack`, `by_engine`) and the top rules are printed. Exit 2 when the run state is `FAILED`.

```bash
export GITHUB_TOKEN=ghp_...
AISRF_URL=http://localhost:8080 aisrf codereview run --git https://github.com/org/app.git --ref main --token-env GITHUB_TOKEN -f sarif -o app.sarif
aisrf codereview run --zip ./app.zip --engines rules --engines bandit --no-wait
```

### aisrf codereview list

| Option | Default | Description |
| --- | --- | --- |
| `--status` | all | `CREATED`, `FETCHING`, `ANALYZING`, `COMPLETED`, `FAILED`, `CANCELLED` |
| `--limit` | 50 | rows |

Columns: `id`, `name`, `source_type`, `status`, `stage`, `file_count`, `finding_count`, `risk_score`, `created_at`.

### aisrf codereview show

`aisrf codereview show RUN_ID [--limit 50]`. Prints the run (`name`, `source_type`, `source_ref`, `status`, `stage`, `file_count`, `loc`, `finding_count`, `created_by`, `created_at`, `finished_at`, `error`), the summary and up to `--limit` findings (`rule_id`, `severity`, `confidence`, `engine`, `file`, `line_start`, `title`, `status`).

### aisrf codereview rules

`aisrf codereview rules [--pack NAME]`. One table per pack with `id`, `severity`, `confidence`, `cwe`, `owasp`, `title`.

## aisrf report

`aisrf report KIND [-f FORMAT] [-o FILE]`

| Argument or option | Type | Default | Description |
| --- | --- | --- | --- |
| `kind` | str | required | `summary`, `tickets`, `audit`, `ticket/<id>`, `agent/<id>`, `campaign/<id>` or `codereview/<run_id>`; leading and trailing slashes are stripped |
| `--format`, `-f` | str | `json` | `json`, `yaml`, `csv`, `tsv`, `md`, `html`, `pdf`, `xlsx`, `txt`, `xml`, `sarif`, `junit` (aliases accepted by the server also work) |
| `--out`, `-o` | path | `aisrf-report-<kind with / replaced by _>.<format>` | output file; parent directories are created |

Prints `wrote <file> (<bytes> bytes, <content type>)`. Filters such as `since` or `min_risk` are not exposed as options; call the REST endpoint directly when you need them, or use the MCP `generate_report` tool with `params`.

```bash
aisrf report summary -f pdf -o weekly.pdf
aisrf report tickets -f sarif -o tickets.sarif
```

## aisrf mcp

`aisrf mcp [--url URL] [--token TOKEN]`. Runs a stdio MCP server whose tools call the gateway at `--url` with the token. Exit 1 with `error: no admin token` when the token is missing. Intended to be launched by an MCP client, not interactively. See [[MCP-Server]].

## aisrf desktop

`aisrf desktop [--port N] [--no-window] [--no-browser]` starts the gateway on the loopback interface with a per-user data directory and opens the dashboard.

| Option | Default | Description |
| --- | --- | --- |
| `--port` | a free port | loopback port |
| `--no-window` | off | skip the native window and open the system browser |
| `--no-browser` | off | open nothing, only print the URL |

It prints the app directory, the settings file (`.env`), the dashboard URL, the sign in hint and where the admin API token lives. Exit code is the desktop runner's result (1 when the server fails to start). The standalone `aisrf-desktop` script accepts the same flags (`--port N`, `--port=N`, `--no-window`, `--no-browser`) and exits 2 on an unknown argument. See [[Desktop-Mode]].

## Shell completion

`aisrf --install-completion` installs completion for the current shell; `aisrf --show-completion` prints it for manual installation.

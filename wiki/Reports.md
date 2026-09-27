# Reports

AISRF builds every report as a format agnostic document and renders it into any of 12 formats, so the same campaign looks consistent as a PDF for management, SARIF for a code scanning dashboard, JUnit for CI or CSV for a spreadsheet.

Source files: `aisrf/reports/model.py` (document model), `aisrf/reports/builders.py` (one builder per kind, `BUILDERS` and `KINDS`), `aisrf/reports/renderers.py` (`FORMATS`, `RENDERERS`, `render`, `negotiate`), `aisrf/reports/router.py` (REST), `aisrf/codereview/report.py` and `aisrf/codereview/sarif.py` (code review report and its dedicated SARIF).

## Document model

A `Report` has `title`, `subtitle`, `generated_at` (UTC), `generated_by` (`aisrf`), `meta` (a dict with at least `kind`) and an ordered list of sections. Every section has a `title` and a `kind` discriminator:

| Section class | `kind` | Content | Flattened as table |
| --- | --- | --- | --- |
| `KeyValueSection` | `keyvalue` | list of `(key, value)` rows | `Key`, `Value` |
| `TableSection` | `table` | `columns`, `rows`, optional `notes`, optional `role` (`cases` marks the table whose rows become JUnit test cases) | as is |
| `TextSection` | `text` | `text`, `markdown` flag | one row per non empty line |
| `FindingsSection` | `findings` | list of finding dicts (`severity`, `category`, `title`, `description`, `evidence`, `location`, `ticket_id`, `probe_id`, `verdict`, `confidence`, ...) | only the columns that carry values |
| `ChartSection` | `chart` | `chart` (`bar` or `pie`), `labels`, `values` | `Label`, `Value` |

`report_from_dict` and `section_from_dict` round trip the JSON output back into a `Report`, so a JSON export can be re-rendered later into another format.

## Report kinds

`GET /api/reports` returns `KINDS` (with accepted `params`) and `FORMATS`. Every report needs the viewer role or the admin token.

| Kind | Endpoint | Parameters |
| --- | --- | --- |
| `summary` | `GET /api/reports/summary` | `since`, `until` |
| `tickets` | `GET /api/reports/tickets` | `status` (repeatable), `agent_id`, `min_risk`, `since`, `until`, `limit` (500, max 5000) |
| `ticket` | `GET /api/reports/ticket/{ticket_id}` | path only |
| `agent` | `GET /api/reports/agent/{agent_id}` | `since` |
| `campaign` | `GET /api/reports/campaign/{campaign_id}` | path only |
| `audit` | `GET /api/reports/audit` | `limit` (500, max 10000) |
| `codereview` | `GET /api/reports/codereview/{run_id}` | `include_dismissed` (SARIF only) |

### summary

Title `AISRF platform summary`, subtitle `Scope: <since .. until or all time>`.

1. `Overview` (key value): tickets all time and in scope, pending, last 24 h, average upstream latency, average human decision time.
2. `Tickets by status` (bar chart) and `Tickets by risk level` (pie chart).
3. `Tickets by agent` (table: Agent, Agent id, Tickets) and `Tickets by model (in scope)`.
4. `Decision latency (human decisions in scope)` (key value: decisions, mean, max and min seconds), present when at least one human decision exists in scope.
5. `Top finding categories` (table), then the findings breakdown: `Findings by category` (bar), `Findings by severity` (pie), or a `Findings breakdown` text section when there are none.
6. `Agents` (table: Agent id, Name, Owner, Provider, Requires approval, Active, Requests, Last seen).
7. `Recent campaigns` (table, with a note when none exist).

### tickets

Title `Tickets report`, subtitle `<n> of <total> matching tickets`.

1. `Filters` (key value of the active filters, or `filters: none`).
2. `Tickets` (table with role `cases`: number, id, created, agent, model, path, risk, level, policy action, status, decided by, latency, prompt preview).
3. Findings breakdown charts (`Findings by category`, `Findings by severity`).
4. `Findings` (findings section, one entry per finding across the selected tickets, each with `ticket_id`).

### ticket

Title `Ticket #<number> dossier`, subtitle `<id> (<status>, risk <level> <score>)`.

1. `Metadata` (key value: id, number, status, agent, model, method, path, source, correlation id, risk, policy action, decision, timestamps, latency).
2. `Declared tools` (table: Tool, Description) when the request declared tools or functions.
3. `Normalized messages` (table: #, Role, Content, Tool; note with model, provider and stream flag).
4. `Findings` (request findings).
5. `Policy decision` (key value: action, matched rules, reasons).
6. `Timeline` (table: Time, Event, Actor, Detail).
7. `Response preview` (text) and `Error` (text) when present.

### agent

Title `Agent report: <name>`, subtitle `<agent id>`.

1. `Configuration` (key value of provider, base URL, approval settings, thresholds, allow-lists, rate limit, canary, tags, owner).
2. `Statistics` (tickets, average risk, count per status).
3. `Tickets by status` (bar chart) when there are tickets.
4. `Tickets` (table, role `cases`, note `<n> of <total> tickets shown`).
5. Findings breakdown charts and `Findings`.
6. `Recent events` (table: Time, Level, Event, Ticket, Detail).
7. `Campaigns` run through this agent, when any.

### campaign

Title `Campaign report: <name>`, subtitle `<id> against <target model> (<status>)`.

1. `Campaign` (id, name, agent, target model, status, probe counters, creator, timestamps, error).
2. `Configuration` (categories, techniques, mutators, max probes, concurrency, seed, path, system prompt, extra body).
3. `Summary` (verdict counts, vulnerability rate, weighted score).
4. `Results by verdict` (pie chart).
5. `Vulnerabilities by category` (table: Category, Probes, Vulnerable, Resisted, Blocked, Other, Vulnerable %) and `Vulnerable probes by category` (bar chart).
6. `Probe results` (table, role `cases`: Result, Probe, Category, Technique, Severity, Verdict, Confidence, Latency ms, Ticket, Prompt).
7. `Top vulnerable probes` (findings with `probe_id`, `verdict`, `evidence`, `confidence`, `technique`).

### audit

Title `Audit log report`, subtitle `<n> of <total> entries, chain intact` or `chain BROKEN`.

1. `Chain verification` (key value: `ok`, `checked`, `head` or `broken_at`, entries in log).
2. `Entries by action` (bar chart).
3. `Audit entries` (table: Id, Time, Actor, Action, Target type, Target id, Detail, Hash, Previous hash).

### codereview

Built by `aisrf/codereview/report.py`.

1. `Run` (id, name, source, commit, status, created by, engines, error).
2. Risk summary (key value: risk score and level, open findings, counts per severity).
3. `Open findings by severity`, `Open findings by pack`, `Open findings by engine` (charts).
4. `OWASP LLM Top 10 coverage`, `Top rules`, `Files with most findings` (tables).
5. Inventory tables: `Languages`, `AI frameworks and SDKs`, `Model artifacts`, `Dependency manifests`, `Inventory highlights`, `Engines` (availability, findings, seconds, note).
6. `Findings` (table, role `cases`: Rule, Severity, Confidence, Pack, Engine, File, Line, Title, Status, OWASP, CWE).
7. `Finding details` (findings with `location` as `file:line`, `rule_id`, `pack`, `engine`, `cwe`, `owasp`, `fingerprint`, `remediation`) or `Notes` when the run has no findings.

## Formats

`FORMATS` in `aisrf/reports/renderers.py`:

| Format | Media type | Extension | Renderer notes |
| --- | --- | --- | --- |
| `json` | `application/json` | `.json` | the document verbatim (`title`, `subtitle`, `generated_at`, `generated_by`, `meta`, `sections`) |
| `yaml` | `application/yaml` | `.yaml` | same document as YAML |
| `csv` | `text/csv` | `.csv` | one block per section: a title line, the header row, the rows, a blank line |
| `tsv` | `text/tab-separated-values` | `.tsv` | as CSV with tabs |
| `md` | `text/markdown` | `.md` | headings, pipe tables, charts as label/value tables |
| `html` | `text/html` | `.html` | self contained, printable, inline SVG bar and pie charts, light and dark palettes |
| `pdf` | `application/pdf` | `.pdf` | reportlab: A4 with header and footer (`Confidential - generated by AISRF`, page numbers), bar and pie charts, small sections kept together |
| `xlsx` | `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet` | `.xlsx` | openpyxl workbook, one sheet per section (sheet names shortened to 31 characters) |
| `txt` | `text/plain` | `.txt` | aligned tables for terminals and email, cells truncated at 40 characters |
| `xml` | `application/xml` | `.xml` | generic XML of the document (`<report><section kind="..."><row>...`) |
| `sarif` | `application/sarif+json` | `.sarif` | SARIF 2.1.0 (details below) |
| `junit` | `application/xml` | `.xml` | JUnit XML test suites (details below) |

Aliases accepted in `?format=` and the CLI: `yml` (yaml), `markdown` (md), `text` (txt), `excel` (xlsx), `junitxml` (junit), `sarif.json` (sarif). A leading dot is stripped and the value is case insensitive.

## Negotiation rules

`negotiate(accept_header, explicit_format)`:

1. An explicit `?format=` wins; an unknown value returns `400 unknown report format '<x>'; supported: json, yaml, ...`.
2. Otherwise the `Accept` header is parsed with quality values. Each media type is mapped through `MEDIA_TO_FORMAT` (`application/json`, `text/json`, `application/yaml`, `application/x-yaml`, `text/yaml`, `text/csv`, `text/tab-separated-values`, `text/markdown`, `text/html`, `application/xhtml+xml`, `application/pdf`, the xlsx media type, `application/vnd.ms-excel`, `text/plain`, `application/xml`, `text/xml`, `application/sarif+json`, `application/junit+xml`). `*/*` and `application/*` mean `json`, `text/*` means `txt`. Entries with `q=0` are ignored; the highest `q` wins and earlier entries win ties.
3. No header, or no recognised media type, means `json`.

Browsers send `text/html` first, so opening a report URL without `?format=` in a browser tab renders the HTML version.

## Inline versus attachment

Every response sets `Content-Disposition: attachment; filename="aisrf-<kind>-<YYYYMMDD-HHMMSS>.<ext>"` so browsers download the file. `?inline=true` (the dashboard uses `inline=1`) switches to `Content-Disposition: inline`, which displays HTML and PDF in the tab. The kind in the filename is specific: `ticket-<number>`, `agent-<id>`, `campaign-<id>`, `codereview-<run id>`. Two extra headers identify the payload: `X-Report-Kind` and `X-Report-Format`.

## SARIF structure

Two SARIF producers exist.

### Generic reports (`render_sarif`)

Used for every kind except code review. Every finding from all `FindingsSection`s becomes a `result`:

- `runs[0].tool.driver`: `name: "AISRF"`, `fullName`, `version`, `rules` (one rule per finding category, `id` equal to the category, `defaultConfiguration.level` from the first severity seen, tags `security`, `llm`, `<category>`).
- `result.ruleId` = category, `level` from `SEVERITY_TO_SARIF` (`CRITICAL` and `HIGH` = `error`, `MEDIUM` = `warning`, `LOW` and `INFO` = `note`, `NONE` = `none`), `message.text` = title plus description, `message.markdown` with the evidence when present.
- `locations[0].logicalLocations[0].name` = `location`, else `probe_id`, else `ticket_id` (kind `member`); there is no physical file location for gateway findings.
- `partialFingerprints["aisrf/v1"]` = `category|ticket_id|probe_id|title`.
- `properties` carries every other finding field plus `severity`.
- `automationDetails.id` = `aisrf/<kind>`, `invocations[0].endTimeUtc`, run level `properties` with title, subtitle and meta.

### Code review (`aisrf/codereview/sarif.py`)

`GET /api/reports/codereview/{run_id}?format=sarif` and `GET /api/codereview/runs/{run_id}/sarif` produce a code scanning ready document:

- `tool.driver.name: "AISRF Code Review"`, `rules` from the rule catalogue with `helpUri`, `defaultConfiguration.level`, `properties.precision` (`high` for confidence >= 0.7, `medium` >= 0.45, else `low`), `properties["security-severity"]` (CVSS style number used by GitHub to bucket severity), tags with the OWASP ids and CWE.
- `taxonomies`: `OWASP LLM Top 10 2025` with one taxon per item; each result references its taxa.
- `result.locations[0].physicalLocation`: `artifactLocation.uri` relative to `%SRCROOT%` (`originalUriBaseIds`), `region.startLine`, `endLine` and a `snippet` (max 2000 characters).
- `partialFingerprints`: `aisrf/v1` (the stable AISRF fingerprint) and `primaryLocationLineHash` (`<path>:<line>`), so GitHub deduplicates findings across uploads.
- Dismissed findings (`false_positive`, `accepted`) are omitted unless `include_dismissed=true`, in which case they carry `suppressions` with the reviewer note; `fixes` holds the remediation text.
- `versionControlProvenance` with the repository URL and commit for git sources; `invocations[0].executionSuccessful` is true only for `COMPLETED` runs.

### Uploading to GitHub code scanning

```yaml
- name: AISRF code review
  run: |
    aisrf codereview run --git "${{ github.server_url }}/${{ github.repository }}.git" --ref "${{ github.sha }}" \
      --token-env GITHUB_TOKEN -f sarif -o aisrf.sarif
  env:
    AISRF_URL: ${{ secrets.AISRF_URL }}
    AISRF_ADMIN_API_TOKEN: ${{ secrets.AISRF_ADMIN_API_TOKEN }}
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: aisrf.sarif
    category: aisrf-code-review
```

Gateway findings can be uploaded the same way (`aisrf report tickets -f sarif`); they appear with logical locations only.

## JUnit structure

`render_junit` turns the report into `<testsuites name="<title>">`:

- Suites come from every `TableSection` with `role="cases"` (the ticket tables of `tickets` and `agent`, `Probe results` of `campaign`, `Findings` of `codereview`). When no such table exists the `FindingsSection`s are used instead; when nothing yields cases a single passing placeholder case is emitted.
- Each row becomes `<testcase name="<probe, ticket, #, id or name column>" classname="aisrf.<kind>.<section slug>" time="<latency ms / 1000>">`.
- The row is a `<failure type="AssertionError">` when any of the columns `verdict`, `risk`, `risk_level`, `severity`, `status` or `level` contains `VULNERABLE`, `CRITICAL` or `HIGH`; an `<error type="Error">` for `ERROR` or `FAILED`; `<skipped message="pending">` for `pending`; otherwise the row detail goes to `<system-out>`.
- Findings based cases fail for `CRITICAL` or `HIGH` severity or verdict `VULNERABLE`.
- Suite and root elements carry `tests`, `failures`, `errors`, `skipped`, `timestamp` and `hostname="aisrf"`.

### Gating a pipeline

```bash
aisrf redteam run --agent agt_ci --model gpt-4o-mini --category prompt_injection --max-probes 40 --wait
aisrf report campaign/cmp_123 -f junit -o results.xml
```

Any CI system that ingests JUnit (GitHub Actions test reporters, GitLab `artifacts:reports:junit`, Jenkins) then fails the job when a probe was `VULNERABLE`. A ticket report (`aisrf report tickets -f junit`) fails on `HIGH` and `CRITICAL` tickets, and a code review report fails on `HIGH` and `CRITICAL` findings.

## Programmatic generation

Inside the process (for example in a scheduled task or a test):

```python
from aisrf.db import get_sessionmaker
from aisrf.reports import builders
from aisrf.reports.renderers import render

async with get_sessionmaker()() as session:
    report = await builders.BUILDERS["campaign"](session, campaign_id="cmp_123")
    payload, media_type, ext = render(report, "pdf")
    open(f"campaign.{ext}", "wb").write(payload)
```

Builders raise `builders.NotFound` for unknown ids (mapped to HTTP 404). Building your own document uses the model directly:

```python
from aisrf.reports.model import Report, TableSection
from aisrf.reports.renderers import render

r = Report(title="Custom", meta={"kind": "custom"})
r.add(TableSection("Cases", columns=["Probe", "Verdict"], rows=[["p1", "VULNERABLE"]], role="cases"))
xml, _, _ = render(r, "junit")
```

Over HTTP, `httpx.get(f"{url}/api/reports/summary", params={"format": "xlsx"}, headers={"Authorization": f"Bearer {token}"})` returns the bytes; the dashboard's report links are the same URLs.

## CLI and MCP usage

CLI ([[CLI-Reference]]):

```bash
aisrf report summary -f pdf -o weekly.pdf
aisrf report audit -f xlsx -o audit.xlsx
aisrf report ticket/tkt_5f3a -f md
aisrf codereview run --git https://github.com/org/app.git -f sarif -o app.sarif
```

MCP ([[MCP-Server]]): `generate_report(kind, format="json", output_path=None, params=None)` and `codereview_report(run_id, format="sarif", output_path=None)` download through the REST API and return `{"path", "media_type", "bytes"}`; `list_report_kinds()` mirrors `GET /api/reports`.

Dashboard ([[Dashboard-Guide]]): the Reports page shows a kind by format matrix with shared filters; ticket, agent, campaign and code review pages carry a `Reports` card with one button per format (`html` and `pdf` open inline in a new tab).

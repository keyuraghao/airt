# Reports

Reports are built from the database into a format-agnostic document (`aisrf/reports/model.py`:
`Report` with `KeyValueSection`, `TableSection`, `TextSection`, `FindingsSection`, `ChartSection`)
and rendered by `aisrf/reports/renderers.py` into any supported format. The same report therefore
looks consistent as a PDF for management, SARIF for a code scanning dashboard or CSV for a
spreadsheet.

## Kinds

| Kind | Endpoint | Content | Filters |
| --- | --- | --- | --- |
| `summary` | `GET /api/reports/summary` | totals by status and risk level, decision latency, top agents, findings breakdown, recent campaigns | `since`, `until` |
| `tickets` | `GET /api/reports/tickets` | one row per ticket with risk, policy action, decision, latency | `status` (repeatable), `agent_id`, `min_risk`, `since`, `until`, `limit` (<= 5000) |
| `ticket/{id}` | `GET /api/reports/ticket/{id}` | full ticket: metadata, normalised messages, request findings, response findings, timeline | none |
| `agent/{id}` | `GET /api/reports/agent/{id}` | agent configuration, usage stats, recent tickets, findings breakdown, campaigns | `since` |
| `campaign/{id}` | `GET /api/reports/campaign/{id}` | campaign config, verdict summary by category / technique / severity, vulnerable probes with evidence | none |
| `audit` | `GET /api/reports/audit` | audit entries with hashes and chain verification result | `limit` (<= 10000) |

`GET /api/reports` lists `kinds` and `formats`. All report endpoints need a reviewer session or the
admin bearer token (`viewer` role is enough).

## Formats

`?format=` (or an `Accept` header) selects one of:

| Format | Media type | Notes |
| --- | --- | --- |
| `json` | `application/json` | the report document verbatim |
| `yaml` | `application/yaml` | same document as YAML |
| `csv`, `tsv` | `text/csv`, `text/tab-separated-values` | one block per section, tables flattened |
| `md` | `text/markdown` | headings and pipe tables |
| `html` | `text/html` | self-contained, printable, inline SVG charts |
| `pdf` | `application/pdf` | reportlab, with bar and pie charts |
| `xlsx` | Excel | openpyxl workbook, one sheet per section |
| `txt` | `text/plain` | aligned tables for terminals and email |
| `xml` | `application/xml` | generic XML of the document |
| `sarif` | `application/sarif+json` | SARIF 2.1.0: findings and vulnerable probes as results |
| `junit` | `application/xml` | JUnit XML: each probe result or ticket is a test case |

Aliases: `yml`, `markdown`, `text`, `excel`, `junitxml`. Responses carry
`Content-Disposition: attachment; filename="aisrf-<kind>-<timestamp>.<ext>"` (`?inline=true` for
inline display), `X-Report-Kind` and `X-Report-Format`.

## Examples

```bash
# management summary of the last week as PDF
curl -b jar -o weekly.pdf "http://localhost:8080/api/reports/summary?format=pdf&since=2026-09-19T00:00:00Z"
# high risk tickets as SARIF for GitHub code scanning
curl -b jar "http://localhost:8080/api/reports/tickets?format=sarif&min_risk=60" > aisrf.sarif
# campaign as JUnit for CI gating
aisrf report campaign/cmp_123 --format junit --out results.xml --url http://localhost:8080 --token "$AISRF_ADMIN_API_TOKEN"
# audit trail as Excel
aisrf report audit -f xlsx -o audit.xlsx
```

From the dashboard: `/reports` offers every kind and format with the same filters. From MCP:
`generate_report(kind, format, output_path, params)`.

## CI integration

* `junit`: run `aisrf redteam run ... --wait` then `aisrf report campaign/<id> -f junit -o results.xml`;
  a `VULNERABLE` probe becomes a failed test case, so the pipeline fails when the model regresses.
* `sarif`: upload with `github/codeql-action/upload-sarif` to see findings in the Security tab.
* `json`: pipe into jq for thresholds (`.sections[] | select(.title == "Verdicts")`).

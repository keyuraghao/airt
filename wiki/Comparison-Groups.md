# Comparison Groups

A comparison group runs the same probe selection against several targets (agent and model pairs) as sibling campaigns and presents the outcomes side by side: a ranking, a category by target vulnerability heatmap, per-probe verdict alignment and OWASP coverage. Groups exist for the native red-team engine (`aisrf/redteam/engine.py`, `create_group` and `compare_group`) and, in a slightly different response shape, for the external scan engines (`aisrf/scanners/service.py`, `run_matrix` and `compare`, see [[Scanner-Engines]]). This page covers the native groups and notes the differences at the end.

## Multi-target groups

`POST /api/redteam/groups` (reviewer role) accepts `GroupIn`:

| Field | Type | Default | Meaning |
|---|---|---|---|
| `name` | string, 1 to 160 chars | required | Group name; each sibling campaign is named `<name> [<label>]`. |
| `targets` | list of `{agent_id, target_model, label}` (at least one) | required | Every `agent_id` must exist (404 otherwise). `target_model` defaults to `""`; `label` defaults to the model name or `target-<n>`. |
| `categories`, `techniques`, `max_probes`, `mutators`, `system_prompt`, `path`, `concurrency`, `seed`, `extra_body` | as for a campaign | see [[Red-Teaming]] | Shared by every sibling. |
| `auto_start` | bool | `false` | Start every sibling immediately. |

`create_group`:

1. If `seed` is null, draws a random seed in `[1, 2^31 - 1]` and stores it, so the sampled probe list is identical for every sibling even when `max_probes` truncates the selection.
2. Selects the probes once (`_select_probes`, including mutators) and mints one `group_id` of the form `grp_...`.
3. Materialises one campaign per target with `config` extended by `group_id`, `group_name` and `target_label`, all with the same `probes` list, so per-probe results line up by `probe_id`.

The response is `{"group_id": ..., "campaigns": [...]}` with the campaign dicts. Start, cancel and delete act on every sibling: `POST /api/redteam/groups/{group_id}/start` starts every campaign in status `CREATED` or `PAUSED`; `.../cancel` cancels all; `DELETE` cancels and deletes all campaigns with their results. Sibling campaigns run concurrently, each with its own concurrency semaphore, so a group of three targets with `concurrency: 4` can have twelve probes in flight and creates tickets for three agents at once (ticket numbering collisions are retried automatically).

`GET /api/redteam/groups` lists groups: `group_id`, `name`, `campaign_count`, `statuses` (count per campaign status) and `created_at`, newest first. `GET /api/redteam/campaigns?group_id=...` lists the members.

## Compare response

`GET /api/redteam/groups/{group_id}` returns `compare_group(...)`, or 404 when no campaign carries that group id. Campaigns are ordered by creation time. For members without a stored summary (still running or cancelled) a summary is computed on the fly from their probe results.

| Key | Content |
|---|---|
| `group_id` | The group id. |
| `name` | `config.group_name` of the first campaign. |
| `campaigns` | Full campaign dicts (`id`, `name`, `agent_id`, `target_model`, `status`, `config`, `group_id`, `target_label`, `summary`, `total_probes`, `completed_probes`, `progress`, timestamps, `error`), in creation order. |
| `matrix` | `{category: {campaign_id: {vulnerable, total, tested, rate}}}` for every category present in any member. `total` counts all probes of that category, `tested` those with verdict `VULNERABLE`, `RESISTED` or `INCONCLUSIVE`, `rate = vulnerable / tested` (0.0 when nothing was tested). |
| `verdict_totals` | `{campaign_id: {verdict: count}}` from each summary's `by_verdict`. |
| `weighted_scores` | `{campaign_id: severity_weighted_score}` (float, see [[Red-Teaming]] for the formula). |
| `vulnerability_rates` | `{campaign_id: vulnerability_rate}`. |
| `labels` | `{campaign_id: target_label}`. |
| `per_probe` | List of `{probe_id, category, technique, severity, verdicts: {campaign_id: verdict}}`, sorted by category then probe id. Because every sibling shares the probe list, each entry has one verdict per campaign (`PENDING` until run). |
| `ranking` | Campaign ids ordered from most robust to most vulnerable (see below). |
| `owasp_coverage` | `taxonomy.coverage(categories)` over the union of categories in the group: for each `LLM01` to `LLM10` the `name`, `covered` flag and contributing categories ([[Taxonomy-and-OWASP-Mapping]]). |

## Ranking rules

`ranking` sorts campaign ids ascending by the tuple `(severity_weighted_score, vulnerability_rate, vulnerable)`:

1. lower `severity_weighted_score` first (the share of severity weight the model failed, 0 to 100);
2. ties broken by lower `vulnerability_rate` (vulnerable divided by conclusive probes);
3. then by fewer absolute `vulnerable` probes.

The first id is therefore the most robust target and the last the most vulnerable. The dashboard shows `#1` for the first entry. Probes that were `BLOCKED` or `ERROR` do not count as tested, so a target whose agent denied most probes can rank well with very few conclusive results; always read the ranking together with `verdict_totals`.

## Heatmap semantics

The group page (`/redteam/groups/{group_id}`, `aisrf/dashboard/static/group.js`) renders `matrix` as a table with one row per category (with taxonomy chips) and one column per campaign, columns ordered by `ranking`. Each cell shows `vulnerable / tested` and is coloured by `rate`:

* untested cells (`tested == 0`) stay uncoloured and carry the class `untested`;
* otherwise the background is `hsl(h 60% 38%)` with hue `h = 120 - 120 * rate`, so a rate of 0 is green (hue 120), 0.5 is yellow (hue 60) and 1.0 is red (hue 0);
* the cell tooltip spells out `<category> on <label>: <vulnerable> vulnerable of <tested> tested`.

Below the heatmap, "OWASP LLM Top 10 coverage" renders one chip per id, `covered` or `uncovered`, with the contributing categories in the tooltip, and "Per-probe matrix" lists every probe with a verdict badge per target; rows whose verdicts differ between targets are marked `differs`, which is the quickest way to find probes that separate the models. Rows expand to show the probe details.

## Dashboard usage

1. On `/redteam` switch the create form to **Compare models**; the submit button reads "Create comparison group". Add one row per target (agent, model, optional label), pick categories, techniques, mutators, `max_probes`, system prompt and seed, then create. The page redirects to the group view.
2. The **Comparison groups** table on `/redteam` lists every group with its campaign count and status breakdown, plus Open, Start (when any member is startable), Cancel (while running) and Delete (with confirmation) buttons for reviewers. Campaign status events on the SSE stream refresh the table.
3. The group page shows: the **Ranking** strip (position, label, model, weighted score, percent vulnerable, status; first and last places highlighted), **Progress per target** (progress bar, stacked verdict bar, weighted score and rate per campaign), the **Vulnerability heatmap**, **OWASP LLM Top 10 coverage** and the **Per-probe matrix**. Start and Cancel act on the whole group; "Download comparison JSON" saves the compare response as `aisrf-comparison-<group_id>.json`.
4. Each campaign in the group links to its own `/redteam/{id}` page for results, tickets and reports ([[Reports]] can render a report per campaign).

## Scan engine matrix groups

`POST /api/scanners/{engine}/matrix` creates sibling scan campaigns (garak, promptfoo or pyrit) sharing a `group_id` in the same way, and `GET /api/scanners/groups/{group_id}` returns `service.compare`, whose shape differs from the native one: `group_id`, `engine`, `created_at`, `targets` (per campaign: `campaign_id`, `agent_id`, `agent_name`, `target_model`, `status`, `total_probes`, `completed_probes`, `vulnerable`, `vulnerability_rate`, `severity_weighted_score`, `false_refusal_rate`, `by_verdict`), `categories`, `verdict_keys`, `matrix` (`{category: {campaign_id: {tested, vulnerable, rate} | null}}`), `verdict_totals`, `ranking` (a list of target objects sorted **descending** by `(severity_weighted_score, vulnerability_rate)`, so the first entry is the most vulnerable), `most_vulnerable` and `least_vulnerable` campaign ids. See [[Scanner-Engines]].

## Related pages

* [[Red-Teaming]] for campaign options, verdicts and summary keys.
* [[Probe-Corpus]] for what the shared probe list contains.
* [[Dashboard-Guide]] for the red-team pages in context.

# Code Review Rules

The code review module ([[Code-Review]]) ships six packs of original AISRF rules, 92 rules in total, plus one semgrep rule file per pack under `aisrf/codereview/rules/semgrep/`. Rule ids are `AISRF-<PACK CODE>-<nnn>`. Every rule carries a severity, a default confidence, a taxonomy category (which gives the OWASP LLM Top 10 mapping through [[Taxonomy-and-OWASP-Mapping]]), a CWE, the languages it applies to, the engines that can report it, a description, why it matters and remediation steps. The catalogue is served by `GET /api/codereview/rules?pack=` (`aisrf.codereview.rules.catalogue()`), `aisrf codereview rules --pack <pack>` and the MCP tool `codereview_rules`; the dashboard's rule catalogue tab renders the same data with OWASP and CWE chips.

Semgrep findings that carry an `aisrf_rule` metadata key are mapped onto the same catalogue entry, so the dashboard, SARIF output and reports show one rule regardless of the engine that found it. Bandit findings keep their `BANDIT-Bxxx` ids and are mapped onto taxonomy categories; a bandit hit on the same line and CWE as a catalogue finding is merged into it. Confidence is adjusted per hit: matches inside decorated tool functions, request handlers or files that import an AI SDK are boosted, weak name-based matches are reduced. Lines that carry an `aisrf: ignore` or `nosec` marker are skipped by the rules engine.

## Packs

| Pack | Code | Rules | Semgrep file | Scope |
|---|---|---|---|---|
| `prompt_injection` | PI | 14 | `prompt_injection.yaml` | How untrusted text reaches the model: prompt assembly, system role hygiene, request pass-through, indirect channels and history replay. |
| `agent_tool_abuse` | AT | 20 | `agent_tool_abuse.yaml` | What the model is allowed to do: shell, code, file, network and SQL sinks in tools, confirmation gates, loop limits, dispatch safety and MCP exposure. |
| `llm_output` | LO | 14 | `llm_output.yaml` | Model output as untrusted input: HTML and DOM sinks, markdown rendering, code and SQL execution, paths and URLs, schema validation and chained prompts. |
| `model_supply_chain` | MS | 19 | `model_supply_chain.yaml` | Model files are code: pickle loaders, remote code, unpinned revisions and dependencies, transport and integrity, serving exposure, build hygiene and provenance. |
| `rag_poisoning_exfil` | RG | 14 | `rag_poisoning_exfil.yaml` | Every retrieved chunk is untrusted: ingestion sanitisation, tenant scoping, filters, vector store auth, prompt delimiters, markdown exfiltration, logging, caching and memory isolation. |
| `general` | GN | 11 | `general.yaml` | Credentials, debug exposure, CORS, rate limits, token and time limits, streaming, runtime key handling, tracing and transport security. |

Severity distribution across the catalogue:

| Severity | Rules |
|---|---|
| CRITICAL | 12 |
| HIGH | 31 |
| MEDIUM | 33 |
| LOW | 14 |
| INFO | 2 |

## Prompt injection (`prompt_injection`, 14 rules)

How untrusted text reaches the model: prompt assembly, system role hygiene, request pass-through, indirect channels and history replay.

| Id | Title | Severity | Confidence | Languages | Engines | OWASP | CWE |
|---|---|---|---|---|---|---|---|
| AISRF-PI-001 | Untrusted input interpolated into a prompt | HIGH | 0.55 | all code languages | rules, semgrep | LLM01 | CWE-74 |
| AISRF-PI-002 | Runtime data placed in the system role | HIGH | 0.65 | all code languages | rules, semgrep | LLM01 | CWE-74 |
| AISRF-PI-003 | HTTP request data passed straight to the model call | HIGH | 0.6 | all code languages | rules, semgrep | LLM01 | CWE-20 |
| AISRF-PI-004 | Prompt assembled by string concatenation | MEDIUM | 0.45 | all code languages | rules | LLM01 | CWE-74 |
| AISRF-PI-005 | Template engine compiles untrusted text as a prompt template | HIGH | 0.7 | all code languages | rules, semgrep | LLM01 | CWE-1336 |
| AISRF-PI-006 | No length limit on input before the model call | LOW | 0.35 | python, javascript, typescript | rules | LLM10 | CWE-770 |
| AISRF-PI-007 | Secrets or personal data embedded in the system prompt | HIGH | 0.6 | all code languages | rules | LLM02, LLM07 | CWE-200 |
| AISRF-PI-008 | Stored conversation history replayed into the prompt unchecked | MEDIUM | 0.4 | all code languages | rules | LLM01 | CWE-74 |
| AISRF-PI-009 | Fetched web or mailbox content summarised without isolation | MEDIUM | 0.45 | all code languages | rules | LLM01, LLM08 | CWE-74 |
| AISRF-PI-010 | External content processed with tools enabled and no confirmation | HIGH | 0.5 | all code languages | rules | LLM01, LLM08 | CWE-807 |
| AISRF-PI-011 | Prompt-only defence against injection | INFO | 0.5 | any file | rules | LLM01 | CWE-693 |
| AISRF-PI-012 | Client controls the whole message list | HIGH | 0.7 | all code languages | rules, semgrep | LLM01 | CWE-602 |
| AISRF-PI-013 | User input reaches the model without control-token or role-marker screening | LOW | 0.35 | python, javascript, typescript | rules | LLM01 | CWE-20 |
| AISRF-PI-014 | User-supplied images or files sent to a multimodal model | MEDIUM | 0.45 | all code languages | rules, semgrep | LLM01, LLM08 | CWE-20 |

### Prompt injection: descriptions and remediation

#### AISRF-PI-001 Untrusted input interpolated into a prompt

A prompt string is built with an f-string, format() call or template that interpolates values derived from users, requests or other untrusted sources. The model cannot tell the difference between the developer's instructions and the interpolated text, so the text can redirect the task, leak the system prompt or trigger tool calls.

Why it matters: Prompt injection is the top risk for LLM applications. Direct concatenation is the simplest and most common way attacker text gains the same authority as the developer's instructions.

Remediation:

* Keep instructions in the system message and pass untrusted text as a separate user (or structured) message.
* Wrap untrusted text in clearly labelled delimiters and instruct the model to treat it as data.
* Limit input length and screen it for override phrases before it reaches the model.
* Validate the model's output before rendering or acting on it; never rely on the prompt alone.

Metadata: category `prompt_injection`; scope `file`; tags `direct`, `sink:prompt`.

#### AISRF-PI-002 Runtime data placed in the system role

Content sent with the system or developer role is assembled at runtime from variables. Anything an attacker controls in that content inherits the highest instruction privilege the model recognises.

Why it matters: System messages are the last place untrusted text should appear: models weight them above user turns, so an injection there overrides every other safeguard.

Remediation:

* Make the system message a constant that contains behavioural rules only.
* Move per-request data (user profile, retrieved context, customer ids) into user messages or tool results, delimited and labelled.
* Look up sensitive per-user data through tools at call time instead of embedding it in instructions.

Metadata: category `prompt_injection`; scope `file`; tags `direct`, `sink:system-prompt`.

#### AISRF-PI-003 HTTP request data passed straight to the model call

Request parameters, form fields or the JSON body are handed to the model API without any intermediate validation, length limit or structuring.

Why it matters: A zero-hop path from the network to the model means every caller can inject instructions, exhaust token budgets or smuggle role markers.

Remediation:

* Parse the request into a typed schema (pydantic, zod) with explicit length limits.
* Build the message list server side from validated fields; never forward raw request objects.
* Apply rate limits and per-user quotas on the endpoint.

Metadata: category `prompt_injection`; scope `file`; tags `direct`, `source:http`.

#### AISRF-PI-004 Prompt assembled by string concatenation

Instruction text and runtime variables are glued together with '+' (or '%') into a single prompt string. There is no boundary the model can use to separate the two.

Why it matters: Concatenated prompts are hard to audit and impossible for the model to parse safely; injected text lands exactly where instructions live.

Remediation:

* Use structured chat messages with distinct roles instead of one flat string.
* If a single string is unavoidable, place data inside explicit delimiters and reference it by name in the instructions.

Metadata: category `prompt_injection`; scope `file`; tags `direct`, `sink:prompt`.

#### AISRF-PI-005 Template engine compiles untrusted text as a prompt template

A templating engine (Jinja2, Mako, string.Template, LangChain templates) is instantiated from a runtime string rather than a constant template. Template syntax inside that string is evaluated, which is server side template injection on top of prompt injection.

Why it matters: Template injection lets an attacker execute expressions in the server process, not just influence the model.

Remediation:

* Keep templates as constants in code or version-controlled prompt files.
* Pass untrusted values only as template variables, never as the template source.
* Use a sandboxed environment with autoescape when templates must be dynamic.

Metadata: category `prompt_injection`; scope `file`; tags `direct`, `ssti`.

#### AISRF-PI-006 No length limit on input before the model call

An HTTP handler forwards text to the model without any visible truncation or length check. Long inputs give attackers more room for injection payloads and drive up token cost.

Why it matters: Bounding input size is the cheapest defence-in-depth control against both injection and denial of wallet.

Remediation:

* Enforce a maximum character or token count on every text field before building the prompt.
* Reject or truncate over-sized inputs and log the event.

Metadata: category `denial_of_wallet`; scope `file`; tags `hardening`.

#### AISRF-PI-007 Secrets or personal data embedded in the system prompt

Credentials, connection strings, internal URLs or user PII are interpolated into the system prompt. System prompts are routinely extracted, so everything in them must be considered public.

Why it matters: 'Never reveal this' is not an access control. A single extraction prompt exposes the embedded values to any user.

Remediation:

* Keep credentials out of the model context entirely; call internal services from code.
* Provide user data through scoped tools that enforce authorisation per call.
* Treat the system prompt as public and design accordingly.

Metadata: category `secrets`; scope `file`; tags `system-prompt`, `secrets`.

#### AISRF-PI-008 Stored conversation history replayed into the prompt unchecked

Previous messages loaded from storage or the client are spliced back into the conversation. A payload planted in an earlier turn (or in another user's session) keeps executing on every later request.

Why it matters: Persistent injection through memory survives page reloads and can cross user boundaries when history is keyed incorrectly.

Remediation:

* Store history server side, keyed by user and session, and cap its length.
* Sanitise stored turns the same way as fresh input; strip role markers and control tokens.
* Never accept a full message list from the client.

Metadata: category `prompt_injection`; scope `file`; tags `persistence`.

#### AISRF-PI-009 Fetched web or mailbox content summarised without isolation

The same function downloads external content (web pages, feeds, emails) and passes it to the model. Hidden instructions in that content are executed with the application's privileges.

Why it matters: Indirect injection needs no access to the chat interface: the attacker only has to control a page or message the assistant will read.

Remediation:

* Strip hidden text, comments, scripts and zero-width characters before prompting.
* Place fetched content in a delimited data block and tell the model it is untrusted reference material.
* Process untrusted content with a quarantined model call that has no tools, then pass structured results onward.

Metadata: category `indirect_prompt_injection`; scope `file`; tags `indirect`, `source:web`.

#### AISRF-PI-010 External content processed with tools enabled and no confirmation

A model call that has tools attached is fed email, document, ticket or web content. An instruction hidden in that content can drive the tools (send, forward, delete, pay) without the user asking for it.

Why it matters: Indirect injection plus tool access is the confused deputy scenario: the assistant's authority is spent on the attacker's goals.

Remediation:

* Separate reading from acting: summarise untrusted content with a tool-less call, then decide actions from structured output.
* Require explicit human confirmation before tools with side effects run.
* Restrict tool availability per task and per user.

Metadata: category `indirect_prompt_injection`; scope `file`; tags `indirect`, `agency`.

#### AISRF-PI-011 Prompt-only defence against injection

The prompt asks the model to ignore instructions found in user or retrieved content. That wording is useful defence in depth but it is bypassed regularly; verify that structural controls (validation, tool gating, output checks) exist outside the model.

Why it matters: Instructions inside the context window compete with the injection on equal footing. Security must be enforced by code.

Remediation:

* Keep the defensive wording but add input screening, output validation and human approval for consequential actions.
* Test the assistant with a red-team campaign to measure how often the wording holds.

Metadata: category `prompt_injection`; scope `file`; tags `hardening`, `informational`.

#### AISRF-PI-012 Client controls the whole message list

The messages array sent to the model is taken directly from the request body. Callers can supply their own system message, forge assistant turns or replay tool results.

Why it matters: Letting the client author every role removes the only privilege boundary the chat API offers.

Remediation:

* Accept only the new user turn from the client; rebuild system and history messages server side.
* Validate role values and drop any system, developer or tool messages from client input.

Metadata: category `prompt_injection`; scope `file`; tags `direct`, `source:http`.

#### AISRF-PI-013 User input reaches the model without control-token or role-marker screening

An HTTP handler forwards text to a model and nothing in the module looks for chat-template control tokens, fake role markers or the usual override phrases first. Attackers use these markers to make their text look like a new system turn.

Why it matters: Screening does not stop injection, but it removes the cheapest tricks and gives you a signal to alert on. Its absence usually means no input hygiene at all.

Remediation:

* Reject or neutralise control tokens and role markers (special tokens, bracketed role labels, template delimiters) before building the prompt.
* Run an injection classifier or guardrail scanner on inputs and log hits for monitoring.
* Keep the check outside the model: a prompt instruction cannot enforce it.

Metadata: category `prompt_injection`; scope `file`; tags `hardening`, `input`.

#### AISRF-PI-014 User-supplied images or files sent to a multimodal model

Uploaded or user-referenced images, documents or audio are attached to the model request. Text hidden inside the media (near-invisible captions, comments in a PDF, a transcript) is read by the model as part of the prompt and can carry instructions.

Why it matters: Multimodal inputs bypass every text-only filter; the payload is only visible once the model has already read it.

Remediation:

* Fetch and re-encode media server side; never forward user URLs to the provider unchecked.
* Process media with a quarantined call that has no tools, then pass structured results onward.
* Limit accepted media types and sizes, and strip metadata before upload.

Metadata: category `indirect_prompt_injection`; scope `file`; tags `indirect`, `multimodal`.

## Agent and tool abuse (`agent_tool_abuse`, 20 rules)

What the model is allowed to do: shell, code, file, network and SQL sinks in tools, confirmation gates, loop limits, dispatch safety and MCP exposure.

| Id | Title | Severity | Confidence | Languages | Engines | OWASP | CWE |
|---|---|---|---|---|---|---|---|
| AISRF-AT-001 | Shell command executed with model-controlled arguments | CRITICAL | 0.65 | all code languages | rules, semgrep, bandit | LLM06, LLM05 | CWE-78 |
| AISRF-AT-002 | Dynamic code evaluation of tool or model data | CRITICAL | 0.65 | all code languages | rules, semgrep, bandit | LLM06, LLM05 | CWE-95 |
| AISRF-AT-003 | File system tool without path containment | HIGH | 0.55 | all code languages | rules, semgrep | LLM06, LLM05 | CWE-22 |
| AISRF-AT-004 | Outbound HTTP tool without a URL allowlist | HIGH | 0.55 | all code languages | rules, semgrep | LLM06, LLM05 | CWE-918 |
| AISRF-AT-005 | SQL statement built from tool or model data | CRITICAL | 0.65 | all code languages | rules, semgrep, bandit | LLM06, LLM05 | CWE-89 |
| AISRF-AT-006 | Over-broad tool description or capability | MEDIUM | 0.5 | all code languages | rules | LLM06 | CWE-250 |
| AISRF-AT-007 | Destructive or financial tool without a confirmation gate | HIGH | 0.5 | all code languages | rules | LLM06 | CWE-862 |
| AISRF-AT-008 | Agent loop without an iteration or cost limit | HIGH | 0.5 | all code languages | rules | LLM10 | CWE-835 |
| AISRF-AT-009 | Tool output returned to the model unsanitised | MEDIUM | 0.45 | all code languages | rules | LLM01, LLM08 | CWE-74 |
| AISRF-AT-010 | Model tool calls dispatched by name without an allowlist | HIGH | 0.6 | all code languages | rules, semgrep | LLM06 | CWE-470 |
| AISRF-AT-011 | MCP server exposes a dangerous capability | CRITICAL | 0.6 | all code languages | rules | LLM06 | CWE-749 |
| AISRF-AT-012 | Messaging or payment tool without a destination allowlist | HIGH | 0.5 | all code languages | rules | LLM02, LLM05 | CWE-284 |
| AISRF-AT-013 | Tool reads data without a user or tenant scope | MEDIUM | 0.35 | python, notebook | rules | LLM06 | CWE-639 |
| AISRF-AT-014 | Framework tool with code or shell execution enabled | CRITICAL | 0.8 | all code languages | rules, semgrep | LLM06, LLM05 | CWE-94 |
| AISRF-AT-015 | Tools attached without per-user permission scoping | MEDIUM | 0.35 | all code languages | rules | LLM06 | CWE-285 |
| AISRF-AT-016 | Tool arguments used without schema or value validation | MEDIUM | 0.4 | python, notebook | rules | LLM06, LLM05 | CWE-20 |
| AISRF-AT-017 | Tool execution without a per-session call budget | LOW | 0.35 | all code languages | rules | LLM10 | CWE-770 |
| AISRF-AT-018 | Agent-to-agent delegation without an allowlist, depth limit or message screening | MEDIUM | 0.45 | all code languages | rules, semgrep | LLM06 | CWE-284 |
| AISRF-AT-019 | Tool calls executed without an audit trail | LOW | 0.3 | all code languages | rules | LLM06 | CWE-778 |
| AISRF-AT-020 | Tool set combines file writes with command or code execution | HIGH | 0.45 | all code languages | rules | LLM06, LLM05 | CWE-94 |

### Agent and tool abuse: descriptions and remediation

#### AISRF-AT-001 Shell command executed with model-controlled arguments

A tool or agent helper runs a shell command whose text or arguments are produced at runtime, typically from model output or tool arguments. With shell=True (or os.system) metacharacters in the argument become new commands.

Why it matters: A prompt injection that reaches this tool is remote code execution on the host running the agent.

Remediation:

* Never build shell strings from model data; call the program with an argument list and shell=False.
* Validate arguments against a strict allowlist (hostnames, file names, enumerations) before use.
* Run tools in a sandbox with no credentials, no network egress and a read-only filesystem.
* Require human approval for any tool that executes commands.

Metadata: category `tool_abuse`; scope `file`; tags `sink:shell`.

#### AISRF-AT-002 Dynamic code evaluation of tool or model data

eval(), exec(), compile() or an in-process REPL is applied to runtime data in an AI component. Model-generated expressions are attacker-controlled once the prompt is compromised.

Why it matters: Code evaluation turns any injection into arbitrary code execution with the application's privileges.

Remediation:

* Replace eval-based calculators or interpreters with parsers that support only the needed grammar.
* If code execution is a feature, run it in an isolated sandbox (container, microVM or WebAssembly) with no secrets mounted.
* Log every executed snippet and cap runtime and memory.

Metadata: category `tool_abuse`; scope `file`; tags `sink:eval`.

#### AISRF-AT-003 File system tool without path containment

A tool opens, reads, writes or deletes a path derived from its arguments without resolving it and checking that it stays inside an allowed directory.

Why it matters: Path traversal through a model tool exposes configuration files, keys and other users' data, or lets the model overwrite code that later runs.

Remediation:

* Resolve the requested path and verify it is inside the tool's base directory before any I/O.
* Allowlist file extensions and reject absolute paths and '..' segments.
* Separate read-only and write tools; keep write targets away from anything executable.

Metadata: category `tool_abuse`; scope `file`; tags `sink:filesystem`.

#### AISRF-AT-004 Outbound HTTP tool without a URL allowlist

A tool fetches a URL supplied in its arguments without validating the destination host. The model can be steered to internal services (SSRF) or to an attacker's server, which also turns the tool into a data exfiltration channel.

Why it matters: Every outbound request a tool makes can carry context data in the path or query string, and can reach metadata endpoints or private networks.

Remediation:

* Allowlist destination hosts; resolve DNS and reject private or link-local addresses.
* Limit URL length and strip query parameters that could carry encoded data.
* Rate limit outbound calls per session and log them with the initiating conversation.

Metadata: category `tool_abuse`; scope `file`; tags `sink:http`, `ssrf`.

#### AISRF-AT-005 SQL statement built from tool or model data

A database call receives a query string assembled with f-strings, format() or concatenation inside an AI component. Tool arguments are written by the model from natural language and can contain SQL.

Why it matters: Second-order SQL injection through the model needs no special encoding: the attacker simply asks for the payload in plain language.

Remediation:

* Use parameterised queries or an ORM with bound parameters for every value.
* Give the tool a narrow, typed interface (enumerations, ids) instead of free text.
* Run tools with a database role limited to the tables and operations they need.

Metadata: category `tool_abuse`; scope `file`; tags `sink:sql`.

#### AISRF-AT-006 Over-broad tool description or capability

A tool advertises itself to the model as able to run any query, command, code or reach any address. The description is the model's contract: the broader it is, the more an injection can request.

Why it matters: Excessive agency starts with the tool schema. A search tool that can execute arbitrary SQL is a database admin console for whoever controls the prompt.

Remediation:

* Split broad tools into narrow, purpose-specific ones with typed parameters.
* Describe exactly what the tool does and refuses to do.
* Enforce the same limits in code; the description is not a control.

Metadata: category `excessive_agency`; scope `file`; tags `schema`.

#### AISRF-AT-007 Destructive or financial tool without a confirmation gate

A tool that refunds, deletes, pays, sends messages, deploys or otherwise changes the world is exposed to the model with no visible human approval, confirmation or ownership check.

Why it matters: Irreversible actions triggered by natural language are the highest-impact outcome of a compromised agent. Approval is the control that survives injection.

Remediation:

* Classify tools by risk and require explicit human approval for high and critical ones.
* Verify that the acting user owns the target resource and is allowed to perform the action.
* Prefer reversible designs (soft delete, holds, drafts) and keep an audit trail.

Metadata: category `excessive_agency`; scope `file`; tags `agency`, `hitl`.

#### AISRF-AT-008 Agent loop without an iteration or cost limit

The model is called repeatedly (while True, or a framework agent without max_iterations, recursion_limit or maxSteps) with no bound on steps, time or spend.

Why it matters: A confused or adversarial agent that never stops burns budget, hammers tools and can be used as a denial of service or denial of wallet primitive.

Remediation:

* Cap iterations, wall-clock time and token spend per run; stop with a clear error when reached.
* Set max_iterations / recursion_limit / maxSteps on framework agents.
* Alert on runs that hit the caps; they often indicate an injection loop.

Metadata: category `denial_of_wallet`; scope `file`; tags `limits`.

#### AISRF-AT-009 Tool output returned to the model unsanitised

Results of a tool call are appended to the conversation as-is. Tool results often contain third-party content (web pages, tickets, database rows) that can carry injected instructions.

Why it matters: Tool output is the classic indirect injection channel inside agent loops: the model asked for data and receives commands.

Remediation:

* Screen tool output for instruction-like patterns and control tokens, and truncate it.
* Wrap results in explicit delimiters and remind the model that the block is data.
* Return structured objects from tools instead of free text where possible.

Metadata: category `indirect_prompt_injection`; scope `file`; tags `indirect`, `loop`.

#### AISRF-AT-010 Model tool calls dispatched by name without an allowlist

The function to run is looked up dynamically (globals(), locals(), getattr, a module table) using the name the model returned. Any importable function becomes callable.

Why it matters: Dynamic dispatch removes the boundary between the tools you intended to expose and everything else in the process.

Remediation:

* Dispatch through an explicit registry dict of allowed tools; reject unknown names.
* Validate arguments against the tool's schema before invoking it.
* Scope the registry per user role and per session.

Metadata: category `excessive_agency`; scope `file`; tags `dispatch`.

#### AISRF-AT-011 MCP server exposes a dangerous capability

A Model Context Protocol tool executes commands, evaluates code, writes or deletes files, sends mail or talks to infrastructure APIs. Any client model connected to the server, and any injection reaching that model, inherits the capability.

Why it matters: MCP servers are reused across assistants and sessions; a dangerous tool in one server is a foothold for every agent that connects.

Remediation:

* Keep MCP tools narrow and read-mostly; move destructive operations behind explicit confirmation.
* Constrain paths, hosts and commands with allowlists inside the tool implementation.
* Run the server with minimal OS privileges and no long-lived credentials.

Metadata: category `excessive_agency`; scope `file`; tags `mcp`.

#### AISRF-AT-012 Messaging or payment tool without a destination allowlist

A tool sends email, chat messages, SMS or payments to a recipient taken from its arguments, with no check that the destination is verified or belongs to the current user.

Why it matters: Outbound messaging tools are the easiest exfiltration channel: a poisoned document only has to ask the assistant to forward the conversation somewhere.

Remediation:

* Only allow recipients that belong to the authenticated user or an approved list.
* Screen message bodies for sensitive data before sending.
* Require confirmation for every send that leaves the organisation.

Metadata: category `data_exfiltration`; scope `file`; tags `exfil`, `agency`.

#### AISRF-AT-013 Tool reads data without a user or tenant scope

A tool queries records by identifier with no reference to the requesting user, tenant or owner. The agent runs with a service account, so the model can be talked into fetching anyone's data.

Why it matters: Agents are confused deputies: they hold more authority than the user and take ownership claims at face value unless code enforces them.

Remediation:

* Inject the authenticated user's identity into every tool call and filter queries by it.
* Never accept the user id as a model-supplied argument.
* Use per-user database roles or row-level security where available.

Metadata: category `excessive_agency`; scope `file`; tags `authorization`.

#### AISRF-AT-014 Framework tool with code or shell execution enabled

A known dangerous framework component is in use: Python REPL or shell tools, agents that evaluate generated code, or flags that opt into unsafe behaviour (allow_dangerous_code, unsandboxed executors).

Why it matters: These components have a history of remote code execution advisories; they hand the model an interpreter.

Remediation:

* Remove the component or replace it with a sandboxed executor (container, microVM) that has no credentials.
* If it must stay, gate it behind human approval and restrict which users can trigger it.
* Pin the framework version and track its security advisories.

Metadata: category `tool_abuse`; scope `file`; tags `framework`.

#### AISRF-AT-015 Tools attached without per-user permission scoping

A fixed tool list is given to the agent and the file shows no sign of roles, permissions or an allowlist that varies by user. Every caller gets every tool.

Why it matters: Least privilege applies to tools: a support chatbot for anonymous users should not carry the same tools as an admin console.

Remediation:

* Build the tool list per request from the caller's role and the task at hand.
* Record which tools each session was granted for audit purposes.

Metadata: category `excessive_agency`; scope `file`; tags `authorization`, `hardening`.

#### AISRF-AT-016 Tool arguments used without schema or value validation

A function exposed to the model takes free-form arguments and passes them straight into calls without any type, format, range or allowlist check. The model writes these values from natural language, so an attacker who controls the conversation controls them too.

Why it matters: Argument validation is the tool equivalent of parameterised queries: it turns arbitrary attacker text into a small set of accepted values before it reaches a backend.

Remediation:

* Describe tool parameters with a strict schema (typed models, enumerations, length limits, patterns) and validate before executing.
* Prefer identifiers and enumerations over free text; resolve them server side.
* Reject invalid arguments with an error the model can recover from instead of coercing them.

Metadata: category `tool_abuse`; scope `file`; tags `schema`, `validation`.

#### AISRF-AT-017 Tool execution without a per-session call budget

Tool calls returned by the model are executed and the module shows no cap on how many times a tool may run per session or per time window.

Why it matters: Unlimited tool calls let a confused or hijacked agent hammer downstream APIs, run up provider bills and stage data exfiltration one request at a time.

Remediation:

* Count tool calls per session and per tool; stop with an explicit error when the budget is spent.
* Rate limit expensive or external tools separately and alert when limits are hit.

Metadata: category `denial_of_wallet`; scope `file`; tags `limits`.

#### AISRF-AT-018 Agent-to-agent delegation without an allowlist, depth limit or message screening

Agents hand tasks to other agents (supervisors, crews, group chats, handoffs) and the module shows no allowlist of who may delegate to whom, no maximum delegation depth and no screening of the messages passed between agents.

Why it matters: Delegation makes trust transitive: an injection that lands in the least privileged agent travels through every hop until it reaches one that can act on it.

Remediation:

* Declare which agents may delegate to which, and cap the delegation depth and round count.
* Give each agent its own tool subset; never share one registry across agents with different privileges.
* Screen inter-agent messages for instruction-like content the same way as tool output.

Metadata: category `excessive_agency`; scope `file`; tags `multi-agent`.

#### AISRF-AT-019 Tool calls executed without an audit trail

Model-chosen tool calls are executed and nothing in the module records which tool ran, with which arguments, for which user.

Why it matters: Without a per-call record you cannot detect an ongoing injection, reconstruct what an agent did or prove what it did not do.

Remediation:

* Log every tool invocation with user, session, tool name, argument digest, result size and outcome.
* Send the records to a tamper-evident store and alert on unusual tool sequences.

Metadata: category `excessive_agency`; scope `file`; tags `monitoring`.

#### AISRF-AT-020 Tool set combines file writes with command or code execution

The same agent exposes a tool that writes files and a tool that runs code or commands, with no sign of sandboxing. Individually each tool looks limited; together they let the model write a script and then run it.

Why it matters: Capability chaining is how agents get compromised in practice: read a secret, write it into a test file, run the tests.

Remediation:

* Keep write targets away from anything the execution tool can run, or execute only in a fresh sandbox with no access to written files.
* Require confirmation for the execution step and log the chain of calls.

Metadata: category `tool_abuse`; scope `file`; tags `chaining`.

## LLM output handling (`llm_output`, 14 rules)

Model output as untrusted input: HTML and DOM sinks, markdown rendering, code and SQL execution, paths and URLs, schema validation and chained prompts.

| Id | Title | Severity | Confidence | Languages | Engines | OWASP | CWE |
|---|---|---|---|---|---|---|---|
| AISRF-LO-001 | Model output rendered as HTML without escaping | CRITICAL | 0.6 | csharp, go, java, javascript, kotlin, php, python, ruby, rust, svelte, swift, typescript, vue, notebook, html, jinja | rules, semgrep | LLM05 | CWE-79 |
| AISRF-LO-002 | innerHTML or dangerouslySetInnerHTML with model text | CRITICAL | 0.7 | javascript, typescript, vue, svelte, html | rules, semgrep | LLM05 | CWE-79 |
| AISRF-LO-003 | Markdown rendered with raw HTML allowed or without sanitisation | HIGH | 0.55 | all code languages | rules | LLM05 | CWE-79 |
| AISRF-LO-004 | Model output executed as code or shell command | CRITICAL | 0.65 | all code languages | rules, semgrep | LLM05 | CWE-94 |
| AISRF-LO-005 | Model output used inside a SQL query | CRITICAL | 0.6 | all code languages | rules, semgrep | LLM05 | CWE-89 |
| AISRF-LO-006 | Model output used as a file path or fetch target | HIGH | 0.55 | all code languages | rules | LLM05 | CWE-73 |
| AISRF-LO-007 | Structured model output parsed without schema validation | MEDIUM | 0.5 | all code languages | rules | LLM05 | CWE-20 |
| AISRF-LO-008 | Generated code executed outside a sandbox | HIGH | 0.5 | all code languages | rules | LLM09, LLM05 | CWE-94 |
| AISRF-LO-009 | Model output chained into a further prompt without validation | MEDIUM | 0.4 | all code languages | rules | LLM01 | CWE-74 |
| AISRF-LO-010 | Model output returned to the client without output filtering | LOW | 0.35 | all code languages | rules | LLM02, LLM05 | CWE-200 |
| AISRF-LO-011 | Model-supplied URL used as a link, redirect or navigation target | HIGH | 0.55 | csharp, go, java, javascript, kotlin, php, python, ruby, rust, svelte, swift, typescript, vue, notebook, html, jinja | rules | LLM05 | CWE-601 |
| AISRF-LO-012 | Packages installed from model-suggested names | HIGH | 0.55 | all code languages | rules, semgrep | LLM03 | CWE-829 |
| AISRF-LO-013 | Structured output requested by prompt wording only | LOW | 0.4 | all code languages | rules | LLM05 | CWE-20 |
| AISRF-LO-014 | Model output placed in email or notification fields | MEDIUM | 0.45 | all code languages | rules | LLM05 | CWE-93 |

### LLM output handling: descriptions and remediation

#### AISRF-LO-001 Model output rendered as HTML without escaping

Text produced by the model is inserted into an HTML response or template as trusted markup (render_template_string, Markup, \|safe, raw HTTP responses). A prompt injection that makes the model emit a script tag becomes stored or reflected XSS.

Why it matters: The model is a proxy for the attacker's payload; whatever escaping rules apply to user input must apply to model output.

Remediation:

* HTML-encode model text before rendering, or render it as text nodes.
* If rich formatting is required, sanitise with an allowlist-based sanitiser (bleach, nh3, DOMPurify) and forbid scripts, event handlers and external images.
* Add a Content Security Policy as a backstop.

Metadata: category `output_handling`; scope `file`; tags `sink:html`, `xss`.

#### AISRF-LO-002 innerHTML or dangerouslySetInnerHTML with model text

A chat or assistant UI writes model text into the DOM with innerHTML, insertAdjacentHTML, document.write, dangerouslySetInnerHTML, v-html, [innerHTML] or {@html}. Any HTML the model emits executes in the user's browser.

Why it matters: Client-side rendering of raw model output is the most common LLM XSS; markdown-looking answers are still HTML to the browser.

Remediation:

* Render model text with textContent or framework text bindings.
* When HTML is needed, pass it through DOMPurify (or equivalent) with a strict allowlist first.
* Disable remote images and links to untrusted hosts in rendered answers.

Metadata: category `output_handling`; scope `file`; tags `sink:dom`, `xss`.

#### AISRF-LO-003 Markdown rendered with raw HTML allowed or without sanitisation

Model answers are converted from Markdown to HTML with a renderer that passes raw HTML through (marked without sanitize, markdown-it html:true, rehype-raw, allowDangerousHtml) and no sanitiser is applied afterwards.

Why it matters: Markdown renderers are HTML generators; inline HTML, javascript: links and remote images in the answer reach the DOM unchanged.

Remediation:

* Sanitise the rendered HTML with DOMPurify or rehype-sanitize using an allowlist.
* Disable raw HTML in the renderer and strip or proxy images.
* Use a component-based Markdown renderer that never emits raw HTML.

Metadata: category `output_handling`; scope `file`; tags `sink:markdown`, `xss`.

#### AISRF-LO-004 Model output executed as code or shell command

A variable holding model output flows into eval(), exec(), a subprocess or an in-process REPL. The model decides what code runs, and the prompt decides what the model says.

Why it matters: Executing generated code without isolation gives every prompt author code execution on the server.

Remediation:

* Do not execute model output in the application process; use an isolated sandbox with no secrets and no network.
* Constrain generated code to a small DSL that is parsed, not evaluated.
* Review and log generated code before it runs; require approval for anything with side effects.

Metadata: category `output_handling`; scope `file`; tags `sink:eval`, `sink:shell`.

#### AISRF-LO-005 Model output used inside a SQL query

Text returned by the model (a category, a filter, a whole statement) is formatted into a database query. Prompt injection becomes second-order SQL injection.

Why it matters: Natural language to SQL features are popular and dangerous: the model will happily write DROP TABLE when asked nicely.

Remediation:

* Bind model-derived values as parameters and validate them against expected enumerations.
* For text-to-SQL, run generated statements with a read-only role against a restricted schema and parse them before execution.
* Never concatenate model text into query strings.

Metadata: category `output_handling`; scope `file`; tags `sink:sql`.

#### AISRF-LO-006 Model output used as a file path or fetch target

A file is opened, a URL is fetched or a path is built from model output. The model can be steered to read secrets, overwrite files or reach internal services.

Why it matters: Model-chosen paths and URLs are attacker-chosen paths and URLs once the prompt is compromised.

Remediation:

* Map model output to an allowlist of known files or hosts; never use it verbatim.
* Resolve paths and enforce a base directory; resolve hosts and block private ranges.

Metadata: category `output_handling`; scope `file`; tags `sink:filesystem`, `sink:http`.

#### AISRF-LO-007 Structured model output parsed without schema validation

JSON (or YAML) produced by the model is parsed and used directly; nothing checks field names, types, ranges or lengths. Unexpected shapes crash the application or smuggle values into downstream calls.

Why it matters: Schema validation is the cheapest way to make model output safe to act on: it rejects injected keys, oversized strings and wrong types before they matter.

Remediation:

* Validate parsed output against a strict schema (pydantic, zod, JSON Schema) with explicit limits.
* Use the provider's structured output or JSON mode, then still validate.
* Treat validation failures as a refusal, not as free-form text to display.

Metadata: category `output_handling`; scope `file`; tags `validation`.

#### AISRF-LO-008 Generated code executed outside a sandbox

Generated code is written to disk and run with an interpreter, or handed to a REPL helper, and the file shows no sign of isolation (container, microVM, WebAssembly, seccomp).

Why it matters: Code interpreters are a legitimate feature only when the blast radius is contained; on the application host they are a backdoor.

Remediation:

* Execute generated code in an ephemeral sandbox with no credentials, no network and resource limits.
* Scan generated code for network and filesystem access before running it.
* Keep sandbox outputs (files, stdout) untrusted when they flow back into prompts.

Metadata: category `code_safety`; scope `file`; tags `sandbox`.

#### AISRF-LO-009 Model output chained into a further prompt without validation

The result of one model call is interpolated into the prompt of the next. Injected instructions survive the first hop and reach a call that may have more tools or a different system prompt.

Why it matters: Multi-step pipelines amplify injection: the second model trusts the first's output as if it were the developer's text.

Remediation:

* Pass intermediate results as delimited data with a fixed schema, not as free text in instructions.
* Validate or classify intermediate output before reuse; drop anything that looks like instructions.
* Give downstream calls only the tools they need.

Metadata: category `prompt_injection`; scope `file`; tags `chaining`.

#### AISRF-LO-010 Model output returned to the client without output filtering

An HTTP handler returns the raw completion and the file contains no output scanning (PII redaction, secret patterns, moderation, guardrails). System prompt fragments, PII from the context and harmful content reach users unchecked.

Why it matters: Output validation is the last line of defence when injection or memorisation puts sensitive data in the answer.

Remediation:

* Scan responses for secrets, PII and system prompt fragments before returning them.
* Run a moderation or guardrail pass for harmful content in user-facing products.
* Cap response length and log filter hits for monitoring.

Metadata: category `data_exfiltration`; scope `file`; tags `hardening`.

#### AISRF-LO-011 Model-supplied URL used as a link, redirect or navigation target

A URL produced by the model is rendered as a clickable link, assigned to window.location or used in a server-side redirect. Hallucinated or injected URLs lead users to phishing pages or exfiltrate query data.

Why it matters: Users trust links their assistant gives them; open redirects and javascript: URLs are trivial to induce through the prompt.

Remediation:

* Validate URLs against an allowlist of schemes and hosts before rendering or redirecting.
* Render untrusted links as plain text or route them through a warning interstitial.
* Strip markdown images and rewrite links in generated answers.

Metadata: category `output_handling`; scope `file`; tags `sink:url`, `phishing`.

#### AISRF-LO-012 Packages installed from model-suggested names

A package manager is invoked with a package name that is computed at runtime in a module that talks to a model, or a module is imported by a name held in a variable. Models routinely invent plausible package names, and those names get registered by attackers.

Why it matters: Installing what the model suggests turns a hallucination into a supply chain compromise on the machine running the agent.

Remediation:

* Install only packages from a reviewed allowlist or lockfile; never pass model text to a package manager.
* If dynamic installs are a feature, verify the package exists, is maintained and matches a pinned version and hash before installing, inside a sandbox.

Metadata: category `supply_chain`; scope `file`; tags `supply-chain`, `sink:install`.

#### AISRF-LO-013 Structured output requested by prompt wording only

The prompt asks the model to answer in JSON but the call does not use the provider's JSON mode, a response schema or a structured output helper, and the module has no parser that validates the result.

Why it matters: Prompt-only formatting fails under injection and under ordinary drift; the parser then receives free text with whatever the attacker put in it.

Remediation:

* Use the provider's structured output or JSON mode with an explicit schema, then validate the parsed object.
* Treat parsing failures as a refusal rather than falling back to displaying raw text.

Metadata: category `output_handling`; scope `file`; tags `validation`.

#### AISRF-LO-014 Model output placed in email or notification fields

Text produced by the model is used as an email subject, recipient, header or message body sent through a mail or chat API. Model text can carry line breaks, extra headers, phishing links or content addressed to the wrong person.

Why it matters: Mail and chat APIs are downstream interpreters too: header injection and attacker-authored messages sent from your domain are the result.

Remediation:

* Never let the model choose recipients or headers; set them from the authenticated context.
* Strip control characters and line breaks from any model text placed in a header and render bodies as plain text.
* Require confirmation before sending anything outside the organisation.

Metadata: category `output_handling`; scope `file`; tags `sink:email`.

## Model security and supply chain (`model_supply_chain`, 19 rules)

Model files are code: pickle loaders, remote code, unpinned revisions and dependencies, transport and integrity, serving exposure, build hygiene and provenance.

| Id | Title | Severity | Confidence | Languages | Engines | OWASP | CWE |
|---|---|---|---|---|---|---|---|
| AISRF-MS-001 | torch.load without weights_only=True | CRITICAL | 0.7 | python, notebook | rules, semgrep, bandit | LLM03 | CWE-502 |
| AISRF-MS-002 | Pickle-family deserialization of model or data files | CRITICAL | 0.7 | any file | rules, semgrep, bandit | LLM03 | CWE-502 |
| AISRF-MS-003 | trust_remote_code=True enabled | HIGH | 0.85 | any file | rules, semgrep | LLM03 | CWE-829 |
| AISRF-MS-004 | Hub artifact loaded without a pinned revision | MEDIUM | 0.55 | all code languages | rules | LLM03 | CWE-494 |
| AISRF-MS-005 | Model or weights fetched over plain HTTP | HIGH | 0.7 | any file | rules | LLM03 | CWE-319 |
| AISRF-MS-006 | Remote checkpoint downloaded without integrity verification | MEDIUM | 0.5 | csharp, go, java, javascript, kotlin, php, python, ruby, rust, svelte, swift, typescript, vue, notebook, shell, dockerfile, yaml | rules | LLM03 | CWE-494 |
| AISRF-MS-007 | Unpinned AI or ML dependency | MEDIUM | 0.6 | text, toml, json, config, ruby, xml, dockerfile, shell, yaml, notebook | rules | LLM03 | CWE-1104 |
| AISRF-MS-008 | Model serving endpoint without authentication | MEDIUM | 0.4 | python, javascript, typescript | rules | LLM10 | CWE-306 |
| AISRF-MS-009 | Model weights or data published with public access | HIGH | 0.55 | any file | rules | LLM03 | CWE-284 |
| AISRF-MS-010 | Unpinned base image or unverified download in a build | MEDIUM | 0.55 | dockerfile, yaml, shell, text | rules | LLM03 | CWE-494 |
| AISRF-MS-011 | Training or fine-tuning data ingested from untrusted sources | MEDIUM | 0.4 | python, notebook | rules | LLM08, LLM04 | CWE-345 |
| AISRF-MS-012 | Model artifacts without provenance metadata | INFO | 0.4 | any file | rules | LLM03 | CWE-1059 |
| AISRF-MS-013 | Pickle-based model artifact committed to the repository | LOW | 0.6 | any file | rules | LLM03 | CWE-502 |
| AISRF-MS-014 | Hub model loaded without forcing the safetensors format | LOW | 0.4 | python, notebook | rules, semgrep | LLM03 | CWE-502 |
| AISRF-MS-015 | Additional package index configured (dependency confusion exposure) | MEDIUM | 0.5 | text, toml, config, dockerfile, shell, yaml, notebook, json | rules | LLM03 | CWE-427 |
| AISRF-MS-016 | Model upload endpoint stores artifacts without format checks or review | HIGH | 0.45 | python, javascript, typescript | rules | LLM03 | CWE-434 |
| AISRF-MS-017 | Inference endpoint returns full probability vectors | LOW | 0.35 | python, javascript, typescript | rules | LLM02, LLM04 | CWE-200 |
| AISRF-MS-018 | Notebook committed with HTML or JavaScript cell outputs | MEDIUM | 0.6 | notebook | rules | LLM03 | CWE-79 |
| AISRF-MS-019 | Container image runs as root | LOW | 0.6 | dockerfile | rules | LLM03 | CWE-250 |

### Model security and supply chain: descriptions and remediation

#### AISRF-MS-001 torch.load without weights_only=True

torch.load() unpickles the checkpoint; without weights_only=True any object in the file, including one whose __reduce__ runs os.system, is executed at load time. Checkpoints from hubs, buckets, uploads or URLs are executable code from a stranger.

Why it matters: Loading a model file is functionally the same as running a downloaded binary. Trojanised checkpoints work perfectly and still steal credentials on load.

Remediation:

* Load state dicts with torch.load(path, weights_only=True, map_location='cpu') and define the architecture in your own code.
* Prefer safetensors for storage and distribution; refuse pickle-based formats at the registry.
* Verify a checksum or signature before loading anything obtained remotely and scan pickle files before use.

Metadata: category `supply_chain`; scope `file`; tags `sink:deserialize`, `pickle`.

#### AISRF-MS-002 Pickle-family deserialization of model or data files

pickle, joblib, dill, cloudpickle, shelve, marshal, numpy allow_pickle=True, torch.jit.load, Keras safe_mode=False, unsafe YAML loaders or framework flags such as allow_dangerous_deserialization=True are used. Each of these executes code embedded in the file.

Why it matters: Serialized models and vector indexes travel between teams, buckets and hubs; a malicious file needs no exploit, only a victim who loads it.

Remediation:

* Use code-free formats: safetensors, ONNX, GGUF, JSON metadata plus raw tensors.
* If a pickle-based format is unavoidable, verify integrity first and load inside an isolated sandbox.
* Never load serialized objects received from users or fetched from untrusted locations.

Metadata: category `supply_chain`; scope `file`; tags `sink:deserialize`, `pickle`.

#### AISRF-MS-003 trust_remote_code=True enabled

The hub loader is told to execute Python shipped inside the model repository. The maintainer of that repository, or anyone who compromises it, runs code in your process on every load.

Why it matters: Remote code is exactly what the name says; combined with unpinned revisions the code can change under you at any time.

Remediation:

* Prefer models whose architecture is in the framework and load them with trust_remote_code=False.
* If custom code is required, vendor it into your repository after review and pin the model to a commit hash.
* Run such loads in an isolated environment without production credentials.

Metadata: category `supply_chain`; scope `file`; tags `remote-code`.

#### AISRF-MS-004 Hub artifact loaded without a pinned revision

A model, tokenizer or dataset is fetched from a hub by name only (or by a branch name). Whatever the default branch points at tomorrow is what you will run; a hijacked account or a force push changes the weights silently.

Why it matters: Pinning to a commit hash is the model equivalent of a lockfile; without it, reproducibility and integrity are both gone.

Remediation:

* Pass revision='<commit sha>' to from_pretrained, hf_hub_download, snapshot_download and load_dataset.
* Mirror approved models into an internal registry and load from there.
* Record the resolved hash in your build metadata.

Metadata: category `supply_chain`; scope `file`; tags `pinning`.

#### AISRF-MS-005 Model or weights fetched over plain HTTP

Weights, checkpoints, wheels or archives are downloaded over an unencrypted http:// URL. Anyone on the path can replace the file.

Why it matters: A network attacker who swaps a pickle-based checkpoint gets code execution; even safe formats can be replaced with backdoored weights.

Remediation:

* Use https:// and verify the certificate.
* Pin the expected checksum and verify it after download.

Metadata: category `supply_chain`; scope `file`; tags `transport`.

#### AISRF-MS-006 Remote checkpoint downloaded without integrity verification

A model file is downloaded or pulled from a hub and used without any checksum, hash or signature check in the same module.

Why it matters: Integrity verification is what turns 'a file from the internet' into 'the file we reviewed'.

Remediation:

* Compare the download against a pinned SHA-256 (check_hash=True for torch.hub, explicit hashlib otherwise) before loading.
* Sign model artifacts in CI (for example with Sigstore) and verify signatures at deployment.
* Fail closed when verification is unavailable.

Metadata: category `supply_chain`; scope `file`; tags `integrity`.

#### AISRF-MS-007 Unpinned AI or ML dependency

An AI framework, SDK, vector store client or ML library is declared without an exact version (range, caret, wildcard or no version at all), or is installed in a container build without a pin. The next install can pull a compromised or breaking release.

Why it matters: ML dependency trees are deep and fast moving; typosquats, malicious updates and dependency confusion have all hit this ecosystem.

Remediation:

* Pin exact versions and use a lockfile; add hash verification (pip --require-hashes, npm ci) in CI.
* Pull from a private mirror that blocks external packages named like internal ones.
* Audit dependencies regularly (pip-audit, npm audit, OSV) and pin VCS dependencies to a commit.

Metadata: category `supply_chain`; scope `file`; tags `pinning`, `dependencies`.

#### AISRF-MS-008 Model serving endpoint without authentication

A prediction, generation, chat or embedding route is defined in a file that shows no authentication dependency, token check or auth middleware.

Why it matters: Unauthenticated inference endpoints invite model extraction, denial of wallet and abuse of your provider keys by third parties.

Remediation:

* Require authentication on every inference route (API keys, OAuth, session) and rate limit per identity.
* Return only the information the caller needs (no full probability vectors, no debug fields).
* Monitor query volume per client for extraction patterns.

Metadata: category `denial_of_wallet`; scope `file`; tags `auth`.

#### AISRF-MS-009 Model weights or data published with public access

Storage objects or buckets are configured world-readable or world-writable (public-read ACLs, allUsers grants, wildcard principals, disabled public access blocks). Weights, fine-tuning data and vector indexes stored there can be read or replaced by anyone.

Why it matters: Public buckets leak proprietary models and training data; writable ones let an attacker swap the artifact your service loads next.

Remediation:

* Remove public grants; serve artifacts through authenticated, signed URLs.
* Enable public access blocks and object versioning; verify hashes on load.
* Audit bucket policies as part of the ML release pipeline.

Metadata: category `supply_chain`; scope `file`; tags `storage`.

#### AISRF-MS-010 Unpinned base image or unverified download in a build

A Dockerfile or CI job uses a floating base image (latest or no digest), pipes a download straight into a shell, or fetches model files during the build without verifying them.

Why it matters: Build-time supply chain attacks land in every image you ship; ML images are large, long-lived and rarely rebuilt from verified inputs.

Remediation:

* Pin base images by digest (@sha256:...) and dependencies by hash.
* Copy verified artifacts from an internal registry instead of downloading at build time.
* Never pipe curl or wget into a shell; download, verify, then execute.

Metadata: category `supply_chain`; scope `file`; tags `build`, `ci`.

#### AISRF-MS-011 Training or fine-tuning data ingested from untrusted sources

Data used for training, fine-tuning or evaluation comes from a hub dataset without a pinned revision, a remote URL, or user uploads, and the module shows no validation, deduplication or provenance tracking.

Why it matters: Poisoning a small fraction of training data is enough to plant triggers; web-scale and user-generated corpora are cheap to poison.

Remediation:

* Pin dataset revisions and record content hashes; keep a provenance manifest per training run.
* Validate schema and label distributions, deduplicate and scan for trigger-like anomalies before training.
* Review user-contributed samples before they enter a fine-tuning set.

Metadata: category `rag_poisoning`; scope `file`; tags `training-data`.

#### AISRF-MS-012 Model artifacts without provenance metadata

The repository ships model artifacts but no model card and no SBOM or provenance attestation describing where the weights came from, how they were trained and how to verify them.

Why it matters: Without provenance nobody can answer 'is this the model we reviewed?' during an incident.

Remediation:

* Add a model card with source, training data summary, license and the SHA-256 of each artifact.
* Generate an SBOM or an attestation for the model in CI and store it next to the weights.

Metadata: category `supply_chain`; scope `inventory`; tags `provenance`.

#### AISRF-MS-013 Pickle-based model artifact committed to the repository

A .pt, .pth, .pkl, .ckpt, .joblib or .bin artifact is checked in. Anyone who can push to the repository can plant code that runs when the file is loaded, and reviewers cannot inspect binary diffs.

Why it matters: Binary model files bypass code review; pickle-based ones are executable.

Remediation:

* Convert artifacts to safetensors or ONNX and store them in an artifact registry with hashes, not in git.
* Scan any pickle-based file with a pickle scanner before use.

Metadata: category `supply_chain`; scope `inventory`; tags `pickle`, `repository`.

#### AISRF-MS-014 Hub model loaded without forcing the safetensors format

A transformers model is loaded from a hub repository without use_safetensors=True. If the repository only offers pickle-based weights, or an attacker adds them, the loader silently falls back to unpickling.

Why it matters: Forcing the safe format makes the loader fail closed instead of executing whatever is in a .bin file.

Remediation:

* Pass use_safetensors=True to from_pretrained and pipeline calls, and pin a revision.
* Mirror approved models in safetensors format in an internal registry.

Metadata: category `supply_chain`; scope `file`; tags `pickle`, `hardening`.

#### AISRF-MS-015 Additional package index configured (dependency confusion exposure)

An extra or alternative package index is configured for pip, poetry, uv or npm. With more than one index the resolver may pick a public package that shares the name of an internal one, and --trusted-host disables TLS verification for that index.

Why it matters: Dependency confusion needs nothing more than a public package with the right name and a resolver that consults two indexes.

Remediation:

* Use a single private index that proxies the public one and blocks external packages with internal names.
* Pin explicit sources per package (explicit priority in poetry or uv, scoped registries in npm) and never use --trusted-host.
* Register internal package names on the public index as placeholders.

Metadata: category `supply_chain`; scope `file`; tags `dependencies`, `pinning`.

#### AISRF-MS-016 Model upload endpoint stores artifacts without format checks or review

An HTTP handler accepts an uploaded model, checkpoint or weights file and stores it, and the module shows no file type restriction, no scan and no approval step before the artifact becomes loadable.

Why it matters: A registry that accepts pickle-based uploads and serves them to loaders is a code execution service for anyone with upload rights.

Remediation:

* Accept only code-free formats (safetensors, ONNX, GGUF) and verify the file structure, not just the extension.
* Scan pickle-based uploads, record a hash, and keep artifacts in a pending state until a second person approves them.
* Store uploads outside the web root with restrictive permissions.

Metadata: category `supply_chain`; scope `file`; tags `registry`, `upload`.

#### AISRF-MS-017 Inference endpoint returns full probability vectors

A prediction route returns raw probabilities, logits or per-class scores. Precise confidence values are the raw material for model extraction, membership inference and inversion attacks.

Why it matters: Callers rarely need more than the top labels; every extra decimal of confidence leaks information about the model and its training data.

Remediation:

* Return only the top-k labels with coarse confidence buckets.
* Rate limit per identity and monitor for extraction patterns (high volume, random-looking inputs).

Metadata: category `privacy_memorization`; scope `file`; tags `inference`, `extraction`.

#### AISRF-MS-018 Notebook committed with HTML or JavaScript cell outputs

A notebook in the repository contains rendered HTML or JavaScript outputs that include script tags, event handlers or network calls. Notebook front ends execute such outputs when the file is opened as trusted.

Why it matters: Shared notebooks are opened far more often than they are read as JSON; an output cell is a place to hide code that runs in the reviewer's session.

Remediation:

* Strip outputs before committing (a pre-commit hook or nbstripout) and review notebook JSON, not only the rendered view.
* Open notebooks from other people as untrusted and keep the notebook server on a separate identity.

Metadata: category `supply_chain`; scope `file`; tags `notebook`.

#### AISRF-MS-019 Container image runs as root

The Dockerfile never switches to an unprivileged user, so the training or serving process, and anything a malicious model or dependency executes inside it, runs as root.

Why it matters: Root inside an ML container turns a pickle payload into a full host or cluster compromise instead of a contained incident.

Remediation:

* Create a dedicated user in the image and add a USER instruction before the entrypoint.
* Drop capabilities, mount the filesystem read-only and set resource limits in the orchestrator.

Metadata: category `supply_chain`; scope `file`; tags `build`, `container`.

## RAG poisoning and data exfiltration (`rag_poisoning_exfil`, 14 rules)

Every retrieved chunk is untrusted: ingestion sanitisation, tenant scoping, filters, vector store auth, prompt delimiters, markdown exfiltration, logging, caching and memory isolation.

| Id | Title | Severity | Confidence | Languages | Engines | OWASP | CWE |
|---|---|---|---|---|---|---|---|
| AISRF-RG-001 | Documents indexed without content sanitisation or provenance | MEDIUM | 0.5 | all code languages | rules | LLM08, LLM04 | CWE-20 |
| AISRF-RG-002 | Retrieval without a tenant or user scope | HIGH | 0.5 | all code languages | rules, semgrep | LLM08, LLM04 | CWE-284 |
| AISRF-RG-003 | Metadata filter or namespace built from request data | HIGH | 0.65 | all code languages | rules, semgrep | LLM08, LLM04 | CWE-639 |
| AISRF-RG-004 | Vector database client connected without authentication | MEDIUM | 0.6 | all code languages | rules | LLM08, LLM04 | CWE-306 |
| AISRF-RG-005 | Retrieved chunks inlined into the prompt without delimiters or provenance | HIGH | 0.55 | all code languages | rules, semgrep | LLM01, LLM08 | CWE-74 |
| AISRF-RG-006 | Answers rendered as Markdown with images or external links allowed | HIGH | 0.55 | all code languages | rules | LLM02, LLM05 | CWE-200 |
| AISRF-RG-007 | Prompts or model responses written to logs | MEDIUM | 0.5 | all code languages | rules | LLM02 | CWE-532 |
| AISRF-RG-008 | Query results or prompts cached without a user scope | MEDIUM | 0.5 | all code languages | rules | LLM02, LLM05 | CWE-524 |
| AISRF-RG-009 | No PII scrubbing before indexing sensitive records | LOW | 0.35 | all code languages | rules | LLM02 | CWE-359 |
| AISRF-RG-010 | Vector store or embedding service credential hardcoded | HIGH | 0.8 | any file | rules | LLM02, LLM07 | CWE-798 |
| AISRF-RG-011 | Web crawl ingestion without a domain allowlist | MEDIUM | 0.5 | all code languages | rules | LLM08, LLM04 | CWE-345 |
| AISRF-RG-012 | Conversation memory shared across users | MEDIUM | 0.5 | all code languages | rules | LLM02, LLM05 | CWE-668 |
| AISRF-RG-013 | User uploads indexed into a shared collection | HIGH | 0.5 | all code languages | rules | LLM08, LLM04 | CWE-284 |
| AISRF-RG-014 | File names or document metadata interpolated into the prompt | MEDIUM | 0.45 | all code languages | rules | LLM01, LLM08 | CWE-74 |

### RAG poisoning and data exfiltration: descriptions and remediation

#### AISRF-RG-001 Documents indexed without content sanitisation or provenance

Text is chunked, embedded and written to the vector store with no visible cleaning step (HTML comments, hidden text, zero-width characters, control tokens) and no author, source or approval metadata.

Why it matters: Whatever is indexed is retrieved for every user asking a related question; one poisoned document steers answers at scale and the payload hides in comments or invisible spans.

Remediation:

* Strip comments, scripts, hidden styling and zero-width characters at ingestion; normalise whitespace.
* Scan chunks for instruction-like patterns and quarantine hits for review.
* Store source, author, classification and a content hash with every chunk and require approval before it becomes retrievable.

Metadata: category `rag_poisoning`; scope `file`; tags `ingestion`.

#### AISRF-RG-002 Retrieval without a tenant or user scope

Similarity search runs against the whole collection with no metadata filter, namespace or tenant argument. Any user's question can surface chunks from any other user's or department's documents.

Why it matters: Cross-tenant leakage through retrieval is the most reported RAG incident class: the LLM faithfully summarises documents the caller was never allowed to see.

Remediation:

* Filter every query by the caller's tenant, groups or document ACLs, enforced server side.
* Use per-tenant namespaces or collections in the vector store.
* Re-check each retrieved chunk against the caller's permissions before it enters the prompt.

Metadata: category `rag_poisoning`; scope `file`; tags `authorization`, `retrieval`.

#### AISRF-RG-003 Metadata filter or namespace built from request data

The filter, where clause, namespace or collection passed to the vector store comes from request parameters or a formatted string. Callers can widen the filter to other tenants or inject operators the store interprets.

Why it matters: A filter is an authorisation boundary only when the server writes it; user-controlled filters are the RAG version of IDOR.

Remediation:

* Derive tenant and permission filters from the authenticated session, never from the request body.
* Allowlist the few user-selectable filter fields and validate their values.
* Combine user selections with the mandatory tenant filter using AND semantics.

Metadata: category `rag_poisoning`; scope `file`; tags `authorization`, `source:http`.

#### AISRF-RG-004 Vector database client connected without authentication

A vector store client is created for a remote host without an API key, token or auth configuration. Anyone who can reach the service can read, insert or delete embeddings.

Why it matters: An open vector database is both a data breach and a poisoning primitive: write access to the index is write access to every future answer.

Remediation:

* Enable authentication on the vector service and pass credentials from a secret store.
* Restrict network access to the service and separate read and write credentials.
* Enable audit logging on the collection.

Metadata: category `rag_poisoning`; scope `file`; tags `auth`, `vector-store`.

#### AISRF-RG-005 Retrieved chunks inlined into the prompt without delimiters or provenance

Retrieved context is concatenated into the instruction text with no delimiter, no source label and no statement that it is reference data. Instructions hidden in a chunk read exactly like the developer's.

Why it matters: Delimiters do not stop injection, but without them the model has no cue at all to distinguish evidence from orders.

Remediation:

* Wrap retrieved content in a clearly labelled block with the source of each chunk and tell the model it is data.
* Scan chunks for injection patterns before they enter the prompt and drop suspicious ones.
* Keep instructions in the system message and context in a separate user or tool message.

Metadata: category `indirect_prompt_injection`; scope `file`; tags `indirect`, `sink:prompt`.

#### AISRF-RG-006 Answers rendered as Markdown with images or external links allowed

Assistant answers are rendered with a Markdown component that keeps images and arbitrary links. A poisoned document can make the model emit an image whose URL carries conversation data to an attacker; the browser fetches it with no click.

Why it matters: Markdown image exfiltration has been demonstrated against multiple production assistants; it needs only rendering, not code execution.

Remediation:

* Disallow img elements (or proxy images through your own domain) in rendered answers.
* Rewrite links to an allowlist of hosts and show the destination on hover.
* Strip URLs containing long encoded query strings from model output before rendering.

Metadata: category `data_exfiltration`; scope `file`; tags `exfil`, `markdown`.

#### AISRF-RG-007 Prompts or model responses written to logs

Full prompts, message lists, retrieved context or model responses are passed to a logger or printed. Logs are copied to systems with weaker access control than the application database.

Why it matters: Prompts carry PII, secrets pasted by users and retrieved confidential documents; logging them creates a second, less protected copy.

Remediation:

* Log identifiers, token counts, latency and guardrail verdicts instead of content.
* If content must be logged for debugging, redact PII and secrets first and restrict retention and access.
* Keep the debug flag off in production.

Metadata: category `pii`; scope `file`; tags `logging`, `pii`.

#### AISRF-RG-008 Query results or prompts cached without a user scope

Retrieval or completion results are memoised or cached keyed only by the query text (a cache decorator, a query-keyed cache entry or a global LLM cache). A privileged user's answer is served verbatim to the next caller with the same question.

Why it matters: Caches erase the authorisation that was applied when the first answer was produced.

Remediation:

* Include the user or tenant identity and the permission set in every cache key.
* Use short TTLs and never cache answers that included restricted documents.
* Disable global LLM caches in multi-tenant services.

Metadata: category `data_exfiltration`; scope `file`; tags `cache`.

#### AISRF-RG-009 No PII scrubbing before indexing sensitive records

Records that look personal (customers, patients, employees, tickets, mail) are embedded and indexed and the module shows no de-identification step.

Why it matters: Once personal data is embedded it is retrievable by anyone who phrases the right question, and it is hard to delete from an index.

Remediation:

* Detect and redact or pseudonymise PII before chunking (for example with a PII analyzer) and keep the mapping out of the index.
* Store classification metadata so retrieval can exclude sensitive chunks per caller.
* Implement deletion workflows for the index to honour erasure requests.

Metadata: category `pii`; scope `file`; tags `pii`, `ingestion`.

#### AISRF-RG-010 Vector store or embedding service credential hardcoded

An API key, token or password for a vector database or embedding service is written into source code or configuration instead of being read from a secret store.

Why it matters: Anyone with repository access owns the index: they can read every embedded document and poison future answers.

Remediation:

* Move the credential to environment variables or a secret manager and rotate it now.
* Use scoped keys (read-only for query paths) and enable audit logging on the service.

Metadata: category `secrets`; scope `file`; tags `secrets`.

#### AISRF-RG-011 Web crawl ingestion without a domain allowlist

Web pages are loaded into the knowledge base from URLs held in variables, and the module has no allowlist of trusted domains. Attackers only need to get a URL into the crawl list, or control a page that is already on it.

Why it matters: Crawled content is fully attacker controlled and is the cheapest way to plant persistent injections and phishing links.

Remediation:

* Restrict crawling to an explicit allowlist of domains and paths; validate every URL before fetching.
* Strip hidden content and scan pages for injection patterns before indexing.
* Re-crawl on a schedule and diff content to catch tampering.

Metadata: category `rag_poisoning`; scope `file`; tags `ingestion`, `source:web`.

#### AISRF-RG-012 Conversation memory shared across users

A conversation memory or message history object is created once (module level, singleton or per service instance) and the module never keys it by user, session or thread. Turns from one user become context for the next.

Why it matters: Shared memory leaks conversations across users and lets an injection planted by one user persist into everyone else's sessions.

Remediation:

* Create memory per user and session (or use thread ids with a checkpointer) and cap its size.
* Clear memory on logout and after inactivity.
* Sanitise turns before saving them back into memory.

Metadata: category `data_exfiltration`; scope `file`; tags `memory`, `isolation`.

#### AISRF-RG-013 User uploads indexed into a shared collection

Files uploaded through an HTTP handler are chunked and written to the vector store, and the module never scopes them by namespace, tenant or owner. Every user's questions can now retrieve every other user's uploads, and one upload can steer answers for everyone.

Why it matters: Upload plus shared index is the cheapest poisoning and cross-tenant leakage path there is: no insider access required.

Remediation:

* Index uploads into a per-user or per-tenant namespace and filter retrieval by the same key.
* Sanitise and scan uploaded content before indexing and keep it pending until reviewed if it is shared.
* Record the uploader and a content hash with every chunk.

Metadata: category `rag_poisoning`; scope `file`; tags `ingestion`, `authorization`.

#### AISRF-RG-014 File names or document metadata interpolated into the prompt

Titles, file names, authors, source URLs or other metadata fields are formatted into the prompt alongside the instructions. Metadata is attacker controlled just like the document body, and it is rarely sanitised.

Why it matters: A file name is a free text field that survives every content filter and lands right next to the instructions.

Remediation:

* Treat metadata as data: place it inside the same delimited block as the chunk text and truncate it.
* Allowlist characters and length for names and titles at ingestion time.

Metadata: category `indirect_prompt_injection`; scope `file`; tags `indirect`, `metadata`.

## General AI application hygiene (`general`, 11 rules)

Credentials, debug exposure, CORS, rate limits, token and time limits, streaming, runtime key handling, tracing and transport security.

| Id | Title | Severity | Confidence | Languages | Engines | OWASP | CWE |
|---|---|---|---|---|---|---|---|
| AISRF-GN-001 | Hardcoded AI provider credential | CRITICAL | 0.9 | any file | rules, semgrep | LLM02, LLM07 | CWE-798 |
| AISRF-GN-002 | Secret in a prompt, environment or configuration file | HIGH | 0.7 | dotenv, prompt, text, markdown, yaml, json, toml, jinja, config, xml | rules | LLM02, LLM07 | CWE-312 |
| AISRF-GN-003 | Debug mode or introspection endpoint enabled | MEDIUM | 0.6 | all code languages | rules | LLM07 | CWE-489 |
| AISRF-GN-004 | Permissive CORS on an AI API | MEDIUM | 0.7 | all code languages | rules | LLM02, LLM05 | CWE-942 |
| AISRF-GN-005 | Model endpoint without rate limiting | MEDIUM | 0.4 | python, javascript, typescript | rules | LLM10 | CWE-770 |
| AISRF-GN-006 | Model call without max_tokens or timeout | LOW | 0.5 | all code languages | rules | LLM10 | CWE-400 |
| AISRF-GN-007 | Streaming response without abort or timeout handling | LOW | 0.35 | all code languages | rules | LLM10 | CWE-400 |
| AISRF-GN-008 | API key handled unsafely at runtime | HIGH | 0.7 | all code languages | rules | LLM02, LLM07 | CWE-532 |
| AISRF-GN-009 | Verbose agent tracing enabled | LOW | 0.5 | all code languages | rules | LLM07 | CWE-532 |
| AISRF-GN-010 | TLS verification disabled for model or tool traffic | MEDIUM | 0.6 | any file | rules, bandit | LLM03 | CWE-295 |
| AISRF-GN-011 | Model name or provider endpoint controlled by the client | MEDIUM | 0.55 | all code languages | rules | LLM10 | CWE-20 |

### General AI application hygiene: descriptions and remediation

#### AISRF-GN-001 Hardcoded AI provider credential

A provider API key (OpenAI, Anthropic, Google, Hugging Face, Groq, xAI, Replicate, Pinecone, GitHub, Slack...) or a provider key variable assigned a literal value appears in the source.

Why it matters: Leaked model keys are monetised within minutes (denial of wallet) and can expose fine-tuned models, files and logs stored with the provider.

Remediation:

* Revoke the key now and issue a new one; assume it is compromised.
* Load keys from environment variables or a secret manager; add a pre-commit secret scanner.
* Scope keys per environment and set spend limits with the provider.

Metadata: category `secrets`; scope `file`; tags `secrets`.

#### AISRF-GN-002 Secret in a prompt, environment or configuration file

A committed .env, prompt, template, YAML, JSON or TOML file assigns a value to a key named like a secret (API key, token, password, private key).

Why it matters: Prompt and configuration files are copied into tickets, chats and model contexts far more often than code; secrets in them travel everywhere.

Remediation:

* Remove the value, rotate the credential and add the file pattern to .gitignore.
* Keep only placeholder examples (.env.example) in the repository.
* Reference secrets by name from a secret store at runtime.

Metadata: category `secrets`; scope `file`; tags `secrets`, `config`.

#### AISRF-GN-003 Debug mode or introspection endpoint enabled

The application runs with debug enabled or exposes routes that reveal prompts, configuration or environment (for example /debug, /prompt, /config, /env).

Why it matters: Debug consoles and prompt-dump endpoints hand attackers the system prompt, tool schemas and often credentials without any injection at all.

Remediation:

* Disable debug in production builds and gate any introspection route behind admin authentication.
* Never expose the raw system prompt or provider configuration through an API.

Metadata: category `system_prompt_leak`; scope `file`; tags `exposure`.

#### AISRF-GN-004 Permissive CORS on an AI API

Cross-origin requests are accepted from any origin (wildcard origins, CORS(app) defaults, cors() without options), on a service that talks to a model. With credentials allowed, any web page can drive the assistant as the logged-in user.

Why it matters: Wildcard CORS lets attacker sites spend your model budget and, with credentials, read other users' conversations through their browsers.

Remediation:

* Allowlist the exact origins of your front end.
* Never combine wildcard origins with allow_credentials.
* Rate limit and authenticate the model endpoints independently of CORS.

Metadata: category `data_exfiltration`; scope `file`; tags `cors`.

#### AISRF-GN-005 Model endpoint without rate limiting

An HTTP handler that calls a model shows no rate limiting, quota or budget control in the module.

Why it matters: Every unthrottled model endpoint is a metered resource that someone else can spend; extraction and denial of wallet both start here.

Remediation:

* Apply per-user and per-IP rate limits and daily token budgets on model endpoints.
* Set provider-side spend limits and alert on anomalies.
* Require authentication so limits can be attributed.

Metadata: category `denial_of_wallet`; scope `file`; tags `limits`.

#### AISRF-GN-006 Model call without max_tokens or timeout

A completion call sets no output token limit and the client has no timeout. A single adversarial prompt can produce the longest, most expensive response the provider allows and hold the worker for minutes.

Why it matters: Output limits and timeouts bound cost and latency per request; without them a small number of requests can exhaust the budget.

Remediation:

* Set max_tokens (or the provider equivalent) on every call and a timeout on the client.
* Track token usage per user and stop serving when a budget is exceeded.

Metadata: category `denial_of_wallet`; scope `file`; tags `limits`.

#### AISRF-GN-007 Streaming response without abort or timeout handling

Streamed completions are produced or relayed and the module shows no abort signal, disconnect check, deadline or token cap.

Why it matters: A client that disconnects should stop the upstream stream; otherwise abandoned generations keep billing and hold connections open.

Remediation:

* Propagate client disconnects (AbortController, request.is_disconnected) to the provider stream.
* Cap stream duration and total tokens; close idle streams.

Metadata: category `denial_of_wallet`; scope `file`; tags `limits`, `streaming`.

#### AISRF-GN-008 API key handled unsafely at runtime

A provider key is taken from a query string, written to logs or printed. Keys in URLs land in proxies and access logs; keys in application logs land everywhere logs go.

Why it matters: Runtime leakage defeats the secret store: the key is safe at rest and public in flight.

Remediation:

* Pass keys only in headers over TLS and never accept them from clients.
* Redact key-like values in logging formatters.

Metadata: category `secrets`; scope `file`; tags `secrets`, `logging`.

#### AISRF-GN-009 Verbose agent tracing enabled

Agents or chains run with verbose or debug tracing, which prints prompts, intermediate reasoning, tool arguments and tool results to stdout or logs.

Why it matters: Verbose traces are a full transcript of the system prompt and every tool call; in production they are a data leak and a debugging aid for attackers.

Remediation:

* Turn verbose and debug flags off outside development.
* Send traces to an access-controlled observability backend with redaction instead of stdout.

Metadata: category `system_prompt_leak`; scope `file`; tags `logging`.

#### AISRF-GN-010 TLS verification disabled for model or tool traffic

Certificate verification is switched off for HTTP clients (verify=False, rejectUnauthorized: false, NODE_TLS_REJECT_UNAUTHORIZED=0, curl -k). Prompts, responses and API keys can be intercepted or modified in transit.

Why it matters: Model traffic carries credentials and confidential prompts; a man in the middle can also inject instructions into responses.

Remediation:

* Enable certificate verification and trust the correct CA bundle.
* Pin certificates for internal model gateways where practical.

Metadata: category `supply_chain`; scope `file`; tags `transport`.

#### AISRF-GN-011 Model name or provider endpoint controlled by the client

The model identifier or the provider base URL is taken from the request. Callers can pick the most expensive model, route traffic to their own endpoint (leaking prompts and keys) or reach internal hosts.

Why it matters: Model selection is a cost and trust decision that belongs to the server.

Remediation:

* Map client choices to an allowlist of approved models; hardcode provider base URLs.
* Attach budgets to the allowed models and log which one served each request.

Metadata: category `denial_of_wallet`; scope `file`; tags `limits`, `ssrf`.

## Related pages

* [[Code-Review]] for intake, engines, findings, SARIF and the API.
* [[Taxonomy-and-OWASP-Mapping]] for the category to OWASP mapping used by every rule.
* [[Reports]] for the report formats that include the catalogue.

"""LLM output handling rule pack (AISRF-LO-*): model output is untrusted input for everything downstream."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from . import pyast
from .base import (
    CODE,
    JS,
    LLM_CALL,
    MODEL_OUTPUT,
    PROMPT_WORDS,
    WEB,
    FileContext,
    Match,
    Rule,
    absence,
    any_of,
    lines,
    near,
    node_match,
    py,
    rule,
)

PACK = "llm_output"
OUT = r"(response|completion|answer|output|reply|generated|generation|llm\w*|model_?\w*|assistant\w*|choices?|message\.content|content\[0\]|result|summary|suggestion|ai\w*|gpt\w*|claude\w*|bot\w*|stream\w*|delta|chunk)"
OUTPUT_EXPR = re.compile(
    r"(choices\[\d\]\.message\.content|content\[\d\]\.text|\.output_text|\.text\b|\.content\b|response\.text|completion\.content|\.candidates\[|generated_text|result\.text|\.choices\b)"
)
CODE_OUTPUT = re.compile(r"(?i)(code|command|cmd|script|sql|query|expression|expr|program|snippet|generated)")
EXEC_CALLS = re.compile(
    r"(^|\.)(eval|exec|compile|os\.system|os\.popen|subprocess\.(run|call|check_output|Popen|check_call)|PythonREPL\.run|python_repl\.run|run_code|execute_code|create_subprocess_shell)$"
)
PATH_OR_NET = re.compile(
    r"(^|\.)(open|Path|os\.path\.join|read_text|write_text|os\.remove|send_file|requests\.(get|post)|httpx\.(get|post)|urlopen|webbrowser\.open|fetch)$"
)
REDIRECTS = re.compile(r"(^|\.)(redirect|RedirectResponse|HttpResponseRedirect)$")
HTML_SINKS_PY = re.compile(
    r"(render_template_string|Markup|mark_safe|format_html|HTMLResponse|HttpResponse|Response)\s*\("
)


def _tainted_names(func: ast.AST) -> set[str]:
    """Variables assigned from a model call or from a completion attribute chain within a function."""
    tainted: set[str] = set()
    for node in ast.walk(func):
        if not isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            continue
        value = node.value
        if value is None:
            continue
        try:
            src = ast.unparse(value)
        except Exception:
            src = ""
        if (
            LLM_CALL.search(src + "(")
            or OUTPUT_EXPR.search(src)
            or any(n in tainted or n.split(".")[0] in tainted for n in pyast.names_in(value))
        ):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for t in targets:
                for n in pyast.names_in(t):
                    tainted.add(n.split(".")[0])
    return tainted


def _sink_of_output(
    ctx: FileContext,
    tree: ast.Module,
    sink: re.Pattern[str],
    note: str,
    *,
    fallback_names: re.Pattern[str] | None = None,
) -> Iterator[Match]:
    if not ctx.has_flag("ai"):
        return
    for func in pyast.iter_functions(tree):
        tainted = _tainted_names(func)
        for call in pyast.iter_calls(func):
            name = pyast.call_name(call)
            if not sink.search(name) or not call.args:
                continue
            arg = call.args[0]
            if pyast.is_constant(arg) and not pyast.is_dynamic_string(arg):
                continue
            refs = pyast.names_in(arg)
            roots = {r.split(".")[0] for r in refs}
            if roots & tainted:
                yield node_match(
                    ctx,
                    call,
                    boost=0.2,
                    note=f"{note}: {', '.join(sorted(roots & tainted)[:3])} holds model output",
                )
            elif fallback_names and any(fallback_names.search(r) and MODEL_OUTPUT.search(r) for r in refs):
                yield node_match(ctx, call, boost=-0.15, note=f"{note}: argument name suggests model output")


def _html_render_py(ctx: FileContext, tree: ast.Module) -> Iterator[Match]:
    if not ctx.has_flag("ai", "route"):
        return
    for func in pyast.iter_functions(tree):
        tainted = _tainted_names(func)
        for call in pyast.iter_calls(func):
            name = pyast.call_name(call)
            if not re.search(
                r"(^|\.)(render_template_string|Markup|mark_safe|format_html|HTMLResponse|HttpResponse)$",
                name,
            ):
                continue
            args = [*call.args, *[k.value for k in call.keywords if k.arg in ("content", None)]]
            for a in args:
                if pyast.is_constant(a) and not pyast.is_dynamic_string(a):
                    continue
                roots = {r.split(".")[0] for r in pyast.names_in(a)}
                if roots & tainted or (
                    pyast.is_dynamic_string(a) and any(MODEL_OUTPUT.search(r) for r in pyast.names_in(a))
                ):
                    yield node_match(ctx, call, note="model text is placed into HTML without escaping")
                    break


def _output_in_next_prompt(ctx: FileContext, tree: ast.Module) -> Iterator[Match]:
    if not ctx.has_flag("ai"):
        return
    for func in pyast.iter_functions(tree):
        tainted = _tainted_names(func)
        if not tainted:
            continue
        for node in ast.walk(func):
            if not pyast.is_dynamic_string(node) or not PROMPT_WORDS.search(pyast.literal_text(node)):
                continue
            roots = {n.split(".")[0] for n in pyast.interpolated(node)}
            hit = roots & tainted
            if hit:
                yield node_match(
                    ctx, node, note=f"{', '.join(sorted(hit)[:3])} came from a previous model call"
                )


def _json_without_schema(ctx: FileContext, tree: ast.Module) -> Iterator[Match]:
    if not ctx.has_flag("ai") or ctx.search(
        r"(model_validate|parse_obj|parse_raw|jsonschema|TypeAdapter|BaseModel|pydantic|marshmallow|response_format|structured_output|with_structured_output|instructor|Draft\d+Validator|validate\()"
    ):
        return
    for func in pyast.iter_functions(tree):
        tainted = _tainted_names(func)
        for call in pyast.iter_calls(func):
            if (
                pyast.call_name(call)
                not in (
                    "json.loads",
                    "loads",
                    "orjson.loads",
                    "ujson.loads",
                    "yaml.safe_load",
                    "ast.literal_eval",
                )
                or not call.args
            ):
                continue
            roots = {r.split(".")[0] for r in pyast.names_in(call.args[0])}
            if roots & tainted or any(MODEL_OUTPUT.search(r) for r in roots):
                yield node_match(ctx, call, note="parsed model output is used without schema validation")


RULES: list[Rule] = [
    rule(
        "AISRF-LO-001",
        PACK,
        "Model output rendered as HTML without escaping",
        severity="CRITICAL",
        confidence=0.6,
        category="output_handling",
        cwe="CWE-79",
        description="Text produced by the model is inserted into an HTML response or template as trusted markup (render_template_string, Markup, |safe, raw HTTP responses). A prompt injection that makes the model emit a script tag becomes stored or reflected XSS.",
        why="The model is a proxy for the attacker's payload; whatever escaping rules apply to user input must apply to model output.",
        remediation=(
            "HTML-encode model text before rendering, or render it as text nodes.",
            "If rich formatting is required, sanitise with an allowlist-based sanitiser (bleach, nh3, DOMPurify) and forbid scripts, event handlers and external images.",
            "Add a Content Security Policy as a backstop.",
        ),
        languages=(*CODE, "html", "jinja"),
        matcher=any_of(
            py(_html_render_py),
            lines(r"\{\{\s*" + OUT + r"[^}]*\|\s*safe\s*\}\}|\{\{\{\s*" + OUT, skip_comments=False),
            lines(
                r"res\.(send|write|end)\s*\(\s*(`[^`]*\$\{\s*" + OUT + r"|[^)]*\+\s*" + OUT + r")",
                flag=("ai", "route"),
            ),
        ),
        tags=("sink:html", "xss"),
        engines=("rules", "semgrep"),
    ),
    rule(
        "AISRF-LO-002",
        PACK,
        "innerHTML or dangerouslySetInnerHTML with model text",
        severity="CRITICAL",
        confidence=0.7,
        category="output_handling",
        cwe="CWE-79",
        description="A chat or assistant UI writes model text into the DOM with innerHTML, insertAdjacentHTML, document.write, dangerouslySetInnerHTML, v-html, [innerHTML] or {@html}. Any HTML the model emits executes in the user's browser.",
        why="Client-side rendering of raw model output is the most common LLM XSS; markdown-looking answers are still HTML to the browser.",
        remediation=(
            "Render model text with textContent or framework text bindings.",
            "When HTML is needed, pass it through DOMPurify (or equivalent) with a strict allowlist first.",
            "Disable remote images and links to untrusted hosts in rendered answers.",
        ),
        languages=WEB,
        matcher=lines(
            r"(\.innerHTML\s*[+]?=|\.outerHTML\s*=|insertAdjacentHTML\s*\(|document\.write(ln)?\s*\(|dangerouslySetInnerHTML\s*=\s*\{\{?\s*__html\s*:|v-html\s*=|\[innerHTML\]\s*=|\{@html\s)",
            unless=r"(DOMPurify|sanitize|purify|escapeHtml|xss\(|sanitizeHtml|=\s*['\"`][^$'\"`]*['\"`]\s*;?\s*$)",
            requires=r"(?i)(chat|llm|assistant|completion|openai|anthropic|\bai\b|gpt|claude|gemini|prompt|answer|bot)",
        ),
        tags=("sink:dom", "xss"),
        engines=("rules", "semgrep"),
    ),
    rule(
        "AISRF-LO-003",
        PACK,
        "Markdown rendered with raw HTML allowed or without sanitisation",
        severity="HIGH",
        confidence=0.55,
        category="output_handling",
        cwe="CWE-79",
        description="Model answers are converted from Markdown to HTML with a renderer that passes raw HTML through (marked without sanitize, markdown-it html:true, rehype-raw, allowDangerousHtml) and no sanitiser is applied afterwards.",
        why="Markdown renderers are HTML generators; inline HTML, javascript: links and remote images in the answer reach the DOM unchanged.",
        remediation=(
            "Sanitise the rendered HTML with DOMPurify or rehype-sanitize using an allowlist.",
            "Disable raw HTML in the renderer and strip or proxy images.",
            "Use a component-based Markdown renderer that never emits raw HTML.",
        ),
        languages=CODE,
        matcher=any_of(
            absence(
                [
                    r"(\bmarked(\.parse)?\s*\(|markdownit\s*\(|md\.render\s*\(|\bshowdown\b|\bremarkable\b|micromark\s*\()"
                ],
                [r"(DOMPurify|sanitize|rehype-sanitize|sanitizeHtml|xss\(|purify)"],
                anchor=r"(\bmarked(\.parse)?\s*\(|markdownit\s*\(|md\.render\s*\(|micromark\s*\()",
                flag=("ai", "frontend"),
            ),
            lines(
                r"(rehypeRaw|rehype-raw|allowDangerousHtml\s*:\s*true|html\s*:\s*true\s*[,}]|skipHtml\s*=\s*\{?false|unsafe\s*:\s*true)",
                requires=r"(?i)(markdown|marked|remark|md)",
            ),
            absence(
                [
                    r"(markdown\.markdown\s*\(|markdown2\.markdown\s*\(|mistune\.(html|markdown|create_markdown)\s*\(|commonmark\.commonmark\s*\()"
                ],
                [r"(bleach|nh3|escape\(|sanitiz|html\.escape|strip_tags)"],
                anchor=r"(markdown\.markdown\s*\(|markdown2\.markdown\s*\(|mistune\.(html|markdown|create_markdown)\s*\(|commonmark\.commonmark\s*\()",
                flag="ai",
            ),
        ),
        tags=("sink:markdown", "xss"),
    ),
    rule(
        "AISRF-LO-004",
        PACK,
        "Model output executed as code or shell command",
        severity="CRITICAL",
        confidence=0.65,
        category="output_handling",
        cwe="CWE-94",
        description="A variable holding model output flows into eval(), exec(), a subprocess or an in-process REPL. The model decides what code runs, and the prompt decides what the model says.",
        why="Executing generated code without isolation gives every prompt author code execution on the server.",
        remediation=(
            "Do not execute model output in the application process; use an isolated sandbox with no secrets and no network.",
            "Constrain generated code to a small DSL that is parsed, not evaluated.",
            "Review and log generated code before it runs; require approval for anything with side effects.",
        ),
        languages=CODE,
        matcher=any_of(
            py(
                lambda ctx, tree: _sink_of_output(
                    ctx, tree, EXEC_CALLS, "code execution", fallback_names=CODE_OUTPUT
                )
            ),
            lines(
                r"(\beval\s*\(|new\s+Function\s*\(|vm\.run\w*\s*\(|execSync\s*\(|exec\s*\(|spawn(Sync)?\s*\()\s*[^)]*\b"
                + OUT,
                flag="ai",
            ),
        ),
        tags=("sink:eval", "sink:shell"),
        engines=("rules", "semgrep"),
    ),
    rule(
        "AISRF-LO-005",
        PACK,
        "Model output used inside a SQL query",
        severity="CRITICAL",
        confidence=0.6,
        category="output_handling",
        cwe="CWE-89",
        description="Text returned by the model (a category, a filter, a whole statement) is formatted into a database query. Prompt injection becomes second-order SQL injection.",
        why="Natural language to SQL features are popular and dangerous: the model will happily write DROP TABLE when asked nicely.",
        remediation=(
            "Bind model-derived values as parameters and validate them against expected enumerations.",
            "For text-to-SQL, run generated statements with a read-only role against a restricted schema and parse them before execution.",
            "Never concatenate model text into query strings.",
        ),
        languages=CODE,
        matcher=any_of(
            py(
                lambda ctx, tree: _sink_of_output(
                    ctx,
                    tree,
                    re.compile(
                        r"(^|\.)(execute|executemany|executescript|exec_driver_sql|raw|query|run_query|run_sql|read_sql|read_sql_query|text)$"
                    ),
                    "SQL execution",
                    fallback_names=re.compile(
                        r"(?i)(sql|query|statement|generated|response|completion|answer|output)"
                    ),
                )
            ),
            lines(
                r"\.(query|execute|raw|\$queryRawUnsafe|\$executeRawUnsafe)\s*\(\s*(`[^`]*\$\{\s*"
                + OUT
                + r"|"
                + OUT
                + r"\w*\s*[,)]|[^)]*\+\s*"
                + OUT
                + r")",
                flag="ai",
            ),
        ),
        tags=("sink:sql",),
        engines=("rules", "semgrep"),
    ),
    rule(
        "AISRF-LO-006",
        PACK,
        "Model output used as a file path or fetch target",
        severity="HIGH",
        confidence=0.55,
        category="output_handling",
        cwe="CWE-73",
        description="A file is opened, a URL is fetched or a path is built from model output. The model can be steered to read secrets, overwrite files or reach internal services.",
        why="Model-chosen paths and URLs are attacker-chosen paths and URLs once the prompt is compromised.",
        remediation=(
            "Map model output to an allowlist of known files or hosts; never use it verbatim.",
            "Resolve paths and enforce a base directory; resolve hosts and block private ranges.",
        ),
        languages=CODE,
        matcher=any_of(
            py(
                lambda ctx, tree: _sink_of_output(
                    ctx,
                    tree,
                    PATH_OR_NET,
                    "file or network access",
                    fallback_names=re.compile(
                        r"(?i)(path|file|url|link|target|response|completion|answer|output)"
                    ),
                )
            ),
            lines(
                r"(fs\.(readFile|writeFile|unlink|readdir)\w*\s*\(|fetch\s*\(|axios(\.get|\.post)?\s*\(|got\s*\(|path\.join\s*\([^)]*)\s*[^)]*\b"
                + OUT,
                flag="ai",
                unless=r"fetch\s*\(\s*['\"`](/|https?://)[^$]",
            ),
        ),
        tags=("sink:filesystem", "sink:http"),
    ),
    rule(
        "AISRF-LO-007",
        PACK,
        "Structured model output parsed without schema validation",
        severity="MEDIUM",
        confidence=0.5,
        category="output_handling",
        cwe="CWE-20",
        description="JSON (or YAML) produced by the model is parsed and used directly; nothing checks field names, types, ranges or lengths. Unexpected shapes crash the application or smuggle values into downstream calls.",
        why="Schema validation is the cheapest way to make model output safe to act on: it rejects injected keys, oversized strings and wrong types before they matter.",
        remediation=(
            "Validate parsed output against a strict schema (pydantic, zod, JSON Schema) with explicit limits.",
            "Use the provider's structured output or JSON mode, then still validate.",
            "Treat validation failures as a refusal, not as free-form text to display.",
        ),
        languages=CODE,
        matcher=any_of(
            py(_json_without_schema),
            absence(
                [r"JSON\.parse\s*\([^)]*\b" + OUT],
                [
                    r"(zod|z\.object|safeParse|ajv|yup|joi|valibot|typebox|schema\.parse|validate\(|assertType|is[A-Z]\w+\()"
                ],
                flag="ai",
                anchor=r"JSON\.parse\s*\(",
            ),
        ),
        tags=("validation",),
    ),
    rule(
        "AISRF-LO-008",
        PACK,
        "Generated code executed outside a sandbox",
        severity="HIGH",
        confidence=0.5,
        category="code_safety",
        cwe="CWE-94",
        description="Generated code is written to disk and run with an interpreter, or handed to a REPL helper, and the file shows no sign of isolation (container, microVM, WebAssembly, seccomp).",
        why="Code interpreters are a legitimate feature only when the blast radius is contained; on the application host they are a backdoor.",
        remediation=(
            "Execute generated code in an ephemeral sandbox with no credentials, no network and resource limits.",
            "Scan generated code for network and filesystem access before running it.",
            "Keep sandbox outputs (files, stdout) untrusted when they flow back into prompts.",
        ),
        languages=CODE,
        matcher=any_of(
            absence(
                [
                    r"(PythonREPL|python_repl|exec_python|run_python|execute_code|run_code|subprocess\.run\(\s*\[\s*[\"'](python3?|node|bash|sh)[\"'][^\]]*(code|script|generated|program)|\.write_text\(\s*(code|generated|script)|\.write\(\s*(code|generated|script))"
                ],
                [
                    r"(?i)(docker|sandbox|e2b|firejail|gvisor|nsjail|modal\.|pyodide|wasm|isolated|container|seccomp|bubblewrap|microvm|firecracker)"
                ],
                flag="ai",
                anchor=r"(PythonREPL|python_repl|exec_python|run_python|execute_code|run_code|subprocess\.run\(|\.write_text\(|\.write\()",
            ),
            absence(
                [r"(execSync|spawnSync|exec)\s*\([^)]*(code|generated|script)"],
                [r"(?i)(docker|sandbox|isolated-vm|vm2|worker_threads|gvisor|firecracker|deno)"],
                flag="ai",
                anchor=r"(execSync|spawnSync|exec)\s*\(",
            ),
        ),
        tags=("sandbox",),
    ),
    rule(
        "AISRF-LO-009",
        PACK,
        "Model output chained into a further prompt without validation",
        severity="MEDIUM",
        confidence=0.4,
        category="prompt_injection",
        cwe="CWE-74",
        description="The result of one model call is interpolated into the prompt of the next. Injected instructions survive the first hop and reach a call that may have more tools or a different system prompt.",
        why="Multi-step pipelines amplify injection: the second model trusts the first's output as if it were the developer's text.",
        remediation=(
            "Pass intermediate results as delimited data with a fixed schema, not as free text in instructions.",
            "Validate or classify intermediate output before reuse; drop anything that looks like instructions.",
            "Give downstream calls only the tools they need.",
        ),
        languages=CODE,
        matcher=any_of(
            py(_output_in_next_prompt),
            lines(
                r"\$\{\s*(response|completion|answer|output|summary|generated|previous|draft|plan|reply)\w*\s*\}",
                requires=r"(?i)(you are|answer|summari[sz]e|instruction|prompt|context:|question:)",
                flag="ai",
            ),
        ),
        tags=("chaining",),
    ),
    rule(
        "AISRF-LO-010",
        PACK,
        "Model output returned to the client without output filtering",
        severity="LOW",
        confidence=0.35,
        category="data_exfiltration",
        cwe="CWE-200",
        description="An HTTP handler returns the raw completion and the file contains no output scanning (PII redaction, secret patterns, moderation, guardrails). System prompt fragments, PII from the context and harmful content reach users unchecked.",
        why="Output validation is the last line of defence when injection or memorisation puts sensitive data in the answer.",
        remediation=(
            "Scan responses for secrets, PII and system prompt fragments before returning them.",
            "Run a moderation or guardrail pass for harmful content in user-facing products.",
            "Cap response length and log filter hits for monitoring.",
        ),
        languages=CODE,
        matcher=absence(
            [
                r"(return\s+[^\n]*(choices\[0\]\.message\.content|content\[0\]\.text|\.output_text|response\.text|completion\.content|\.generated_text)|res\.(json|send)\([^)]*(completion|response\.choices|answer|\.content\b|\.text\b))"
            ],
            [
                r"(?i)(redact|filter|moderat|scrub|guardrail|sanitiz|validate_output|output_guard|allowlist|mask|pii|Guard\(|llm_guard|nemoguardrails|rebuff|check_output|scan_output|lakera|escape)"
            ],
            flag=("route", "ai"),
            anchor=r"(return\s+[^\n]*(choices\[0\]\.message\.content|content\[0\]\.text|\.output_text|response\.text|completion\.content|\.generated_text)|res\.(json|send)\()",
        ),
        tags=("hardening",),
    ),
    rule(
        "AISRF-LO-011",
        PACK,
        "Model-supplied URL used as a link, redirect or navigation target",
        severity="HIGH",
        confidence=0.55,
        category="output_handling",
        cwe="CWE-601",
        description="A URL produced by the model is rendered as a clickable link, assigned to window.location or used in a server-side redirect. Hallucinated or injected URLs lead users to phishing pages or exfiltrate query data.",
        why="Users trust links their assistant gives them; open redirects and javascript: URLs are trivial to induce through the prompt.",
        remediation=(
            "Validate URLs against an allowlist of schemes and hosts before rendering or redirecting.",
            "Render untrusted links as plain text or route them through a warning interstitial.",
            "Strip markdown images and rewrite links in generated answers.",
        ),
        languages=(*CODE, "html", "jinja"),
        matcher=any_of(
            py(
                lambda ctx, tree: _sink_of_output(
                    ctx,
                    tree,
                    REDIRECTS,
                    "redirect",
                    fallback_names=re.compile(r"(?i)(url|link|target|response|completion|answer|output)"),
                )
            ),
            lines(
                r"(href\s*=\s*\{?\s*"
                + OUT
                + r"|window\.location(\.href)?\s*=\s*"
                + OUT
                + r"|location\.(assign|replace)\s*\(\s*"
                + OUT
                + r"|<a[^>]*href\s*=\s*[\"']?\$\{|href=\"\{\{\s*"
                + OUT
                + r"|res\.redirect\s*\(\s*"
                + OUT
                + r")",
                flag=("ai", "frontend", "route"),
                skip_comments=False,
            ),
        ),
        tags=("sink:url", "phishing"),
    ),
]
_ = (JS, near, HTML_SINKS_PY)

PACKAGE_INSTALL = r"((pip3?|uv pip|pipx|npm|yarn|pnpm|cargo|gem|go)\s+(install|add|i|get)\b[^\n]*(\$\{|\{[a-z_]|\s\+\s*[A-Za-z_]|%s|\+\s*[A-Za-z_])|\[\s*['\"](pip3?|npm|uv|pipx)['\"]\s*,\s*(['\"](pip|-m)['\"]\s*,\s*)*['\"](install|add|i)['\"]\s*,\s*(?!['\"\]])[A-Za-z_(]|importlib\.import_module\s*\(\s*(?!['\"])[A-Za-z_])"
STRUCTURED_OUTPUT = r"(response_format|json_object|json_schema|with_structured_output|structured_output|response_model|instructor|output_schema|responseSchema|generateObject|tool_choice|function_call|response_mime_type|format\s*[=:]\s*['\"]json|outputParser|OutputParser|StructuredOutput|Output\()"
JSON_ASK = r"(?i)['\"`][^'\"`\n]*\b(return|respond|reply|answer|output|format)\b[^'\"`\n]{0,80}\bJSON\b|\bJSON\b[^'\"`\n]{0,40}\b(only|format|object)\b[^'\"`\n]*['\"`]"
EMAIL_SINK = re.compile(
    r"(^|\.)(send_mail|send_email|sendmail|send_message|EmailMessage|MIMEText|MIMEMultipart|EmailMultiAlternatives|SendGridAPIClient|Mail|chat_postMessage|publish|notify|send_sms|send_notification)$"
)


RULES += [
    rule(
        "AISRF-LO-012",
        PACK,
        "Packages installed from model-suggested names",
        severity="HIGH",
        confidence=0.55,
        category="supply_chain",
        cwe="CWE-829",
        description="A package manager is invoked with a package name that is computed at runtime in a module that talks to a model, or a module is imported by a name held in a variable. Models routinely invent plausible package names, and those names get registered by attackers.",
        why="Installing what the model suggests turns a hallucination into a supply chain compromise on the machine running the agent.",
        remediation=(
            "Install only packages from a reviewed allowlist or lockfile; never pass model text to a package manager.",
            "If dynamic installs are a feature, verify the package exists, is maintained and matches a pinned version and hash before installing, inside a sandbox.",
        ),
        languages=CODE,
        matcher=lines(PACKAGE_INSTALL, flag=("ai", "agent", "tool")),
        tags=("supply-chain", "sink:install"),
        engines=("rules", "semgrep"),
    ),
    rule(
        "AISRF-LO-013",
        PACK,
        "Structured output requested by prompt wording only",
        severity="LOW",
        confidence=0.4,
        category="output_handling",
        cwe="CWE-20",
        description="The prompt asks the model to answer in JSON but the call does not use the provider's JSON mode, a response schema or a structured output helper, and the module has no parser that validates the result.",
        why="Prompt-only formatting fails under injection and under ordinary drift; the parser then receives free text with whatever the attacker put in it.",
        remediation=(
            "Use the provider's structured output or JSON mode with an explicit schema, then validate the parsed object.",
            "Treat parsing failures as a refusal rather than falling back to displaying raw text.",
        ),
        languages=CODE,
        matcher=absence([JSON_ASK, LLM_CALL.pattern], [STRUCTURED_OUTPUT], anchor=JSON_ASK, flag="ai"),
        tags=("validation",),
    ),
    rule(
        "AISRF-LO-014",
        PACK,
        "Model output placed in email or notification fields",
        severity="MEDIUM",
        confidence=0.45,
        category="output_handling",
        cwe="CWE-93",
        description="Text produced by the model is used as an email subject, recipient, header or message body sent through a mail or chat API. Model text can carry line breaks, extra headers, phishing links or content addressed to the wrong person.",
        why="Mail and chat APIs are downstream interpreters too: header injection and attacker-authored messages sent from your domain are the result.",
        remediation=(
            "Never let the model choose recipients or headers; set them from the authenticated context.",
            "Strip control characters and line breaks from any model text placed in a header and render bodies as plain text.",
            "Require confirmation before sending anything outside the organisation.",
        ),
        languages=CODE,
        matcher=any_of(
            py(
                lambda ctx, tree: _sink_of_output(
                    ctx,
                    tree,
                    EMAIL_SINK,
                    "messaging",
                    fallback_names=re.compile(
                        r"(?i)(subject|body|recipient|to_addr|message|response|completion|answer|output|reply)"
                    ),
                )
            ),
            lines(
                r"(sendMail|transporter\.send|sgMail\.send|resend\.emails\.send|messages\.create|chat\.postMessage|postMessage)\s*\(\s*\{[^}]*\b(subject|to|text|html)\s*:\s*[^,}]*\b"
                + OUT,
                flag="ai",
            ),
            lines(
                r"(?i)\b(subject|to|recipient|recipients|cc|bcc|reply_to|from_email|headers\[[^\]]+\])\s*[=:]\s*[^\n=]*\b(response|completion|answer|output|reply|generated|llm\w*|model_?output|assistant\w*)\b",
                flag="ai",
                requires=r"(smtplib|sendmail|send_mail|send_email|EmailMessage|MIMEText|nodemailer|sendgrid|SendGrid|resend|twilio|mailgun|ses\.|postmark)",
            ),
        ),
        tags=("sink:email",),
    ),
]

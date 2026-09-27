"""Prompt injection rule pack (AISRF-PI-*): how untrusted text reaches the model."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from . import pyast
from .base import (
    ALL,
    CODE,
    LLM_CALL,
    PROMPT_WORDS,
    UNTRUSTED,
    UNTRUSTED_STRONG,
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

PACK = "prompt_injection"
SECRET_NAMES = re.compile(r"(?i)(api_?key|secret|password|passwd|token|credential|conn(ection)?_?str|dsn|private_key|ssn|balance|salary|account_?(no|number|id)|phone|email|address|customer_?id|user\.(email|role|id)|internal_url|admin_url)")
FETCH = re.compile(r"(requests\.(get|post|request)|httpx\.(get|post|Client|AsyncClient)|urlopen|aiohttp|BeautifulSoup|\.get_text\(|trafilatura|readability|playwright|selenium|imaplib|IMAP4|\.fetch\(|WebBaseLoader|scrape)")
EXTERNAL_CONTENT = re.compile(r"(?i)(email|inbox|attachment|webpage|web_page|html|page_content|document|pdf|calendar|ticket|issue|pull_request|comment|slack_message|transcript)")
MESSAGES_FROM_CLIENT = re.compile(r"(messages\s*=\s*(request\.(json|get_json\(\))|payload|body|data|req)\b[^\n]*(\[|\.get\()\s*[\"']messages[\"']|messages\s*[=:]\s*(req\.body|request\.body|body|payload)\.messages|(\"|')messages(\"|')\s*:\s*(req\.body|request\.body|body|payload)\.messages|messages\s*=\s*(payload|body|data)\.messages|messages=request\.json\[)")


def _dynamic_prompt_strings(tree: ast.Module) -> Iterator[ast.AST]:
    """Dynamic strings whose literal part reads like a prompt. Outermost node wins for '+' chains."""
    seen: set[int] = set()
    for node in ast.walk(tree):
        if not pyast.is_dynamic_string(node):
            continue
        start, _ = pyast.span(node)
        if start in seen:
            continue
        if not PROMPT_WORDS.search(pyast.literal_text(node)):
            continue
        seen.add(start)
        yield node


def _untrusted_prompt(ctx: FileContext, tree: ast.Module) -> Iterator[Match]:
    for node in _dynamic_prompt_strings(tree):
        names = pyast.interpolated(node)
        if not names:
            continue
        strong = [n for n in names if UNTRUSTED_STRONG.search(n)]
        weak = [n for n in names if UNTRUSTED.search(n) and n.upper() != n]
        if not strong and not weak:
            continue
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add) and not strong:
            continue  # plain concatenation is reported by AISRF-PI-004
        boost = 0.3 if strong else (0.1 if ctx.has_flag("ai", "route") else 0.0)
        yield node_match(ctx, node, boost=boost, note="interpolates " + ", ".join(sorted(strong or weak)[:4]))


def _concat_prompt(ctx: FileContext, tree: ast.Module) -> Iterator[Match]:
    for node in _dynamic_prompt_strings(tree):
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            names = pyast.interpolated(node)
            if names and any(n.upper() != n for n in names):
                yield node_match(ctx, node, note="concatenates " + ", ".join(sorted(names)[:4]))


def _system_role_dynamic(ctx: FileContext, tree: ast.Module) -> Iterator[Match]:
    for node in ast.walk(tree):
        content: ast.expr | None = None
        if isinstance(node, ast.Dict):
            role = pyast.dict_get(node, "role")
            if not (isinstance(role, ast.Constant) and role.value in ("system", "developer")):
                continue
            content = pyast.dict_get(node, "content")
        elif isinstance(node, ast.Call) and pyast.call_name(node).endswith(("SystemMessage", "SystemMessagePromptTemplate.from_template")):
            content = pyast.keyword(node, "content") or (node.args[0] if node.args else None)
        elif isinstance(node, ast.Call) and pyast.call_name(node).endswith("messages.create"):
            content = pyast.keyword(node, "system")
        if content is None:
            continue
        if pyast.is_dynamic_string(content):
            names = pyast.interpolated(content)
            strong = any(UNTRUSTED_STRONG.search(n) or UNTRUSTED.search(n) for n in names if n.upper() != n)
            yield node_match(ctx, content, boost=0.2 if strong else 0.0, note="system content is built at runtime")
        elif isinstance(content, ast.Name) and content.id.upper() != content.id and UNTRUSTED.search(content.id):
            yield node_match(ctx, content, confidence=0.4, note=f"system content comes from variable {content.id}")


def _request_to_model(ctx: FileContext, tree: ast.Module) -> Iterator[Match]:
    for call in pyast.iter_calls(tree):
        if not LLM_CALL.search(pyast.call_name(call) + "("):
            continue
        refs = set()
        for a in [*call.args, *[k.value for k in call.keywords]]:
            refs |= pyast.names_in(a)
        direct = sorted(r for r in refs if re.match(r"^(request|req|flask\.request|params|form|body|payload|query_params)(\.|$)", r))
        if direct:
            yield node_match(ctx, call, boost=0.2 if ctx.has_flag("route") else 0.0, note="passes " + ", ".join(direct[:3]))


def _secrets_in_system_prompt(ctx: FileContext, tree: ast.Module) -> Iterator[Match]:
    for node in ast.walk(tree):
        target: ast.AST | None = None
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and re.search(r"(?i)(system|prompt|instruction)", t.id) for t in node.targets):
            target = node.value
        elif isinstance(node, ast.Dict):
            role = pyast.dict_get(node, "role")
            if isinstance(role, ast.Constant) and role.value in ("system", "developer"):
                target = pyast.dict_get(node, "content")
        if target is None or not pyast.is_dynamic_string(target):
            continue
        leaked = sorted(n for n in pyast.interpolated(target) if SECRET_NAMES.search(n))
        if leaked:
            yield node_match(ctx, target, note="embeds " + ", ".join(leaked[:4]))


def _fetch_then_model(ctx: FileContext, tree: ast.Module) -> Iterator[Match]:
    for func in pyast.iter_functions(tree):
        text = pyast.func_text(func, ctx.lines)
        if not FETCH.search(text):
            continue
        for call in pyast.iter_calls(func):
            if LLM_CALL.search(pyast.call_name(call) + "("):
                if re.search(r"(?i)(sanitiz|strip_|clean_|<untrusted|<context>|<document|<web|delimit|quarantine|scan_)", text):
                    break
                yield node_match(ctx, call, note=f"function {func.name} fetches external content and prompts the model with it")
                break


def _external_content_with_tools(ctx: FileContext, tree: ast.Module) -> Iterator[Match]:
    for func in pyast.iter_functions(tree):
        text = pyast.func_text(func, ctx.lines)
        if not EXTERNAL_CONTENT.search(text) or re.search(r"(?i)(confirm|approv|human_in|hitl|allowlist|allow_list)", text):
            continue
        for call in pyast.iter_calls(func):
            if pyast.has_keyword(call, "tools") or pyast.has_keyword(call, "functions"):
                yield node_match(ctx, call, note=f"function {func.name} lets the model act on external content with tools enabled")
                break


def _client_messages(ctx: FileContext, tree: ast.Module) -> Iterator[Match]:
    for call in pyast.iter_calls(tree):
        if not LLM_CALL.search(pyast.call_name(call) + "("):
            continue
        msgs = pyast.keyword(call, "messages")
        if msgs is None:
            continue
        refs = pyast.names_in(msgs)
        if any(re.match(r"^(request|req|payload|body|data|params)(\.|$)", r) for r in refs) and not isinstance(msgs, (ast.List, ast.Tuple)):
            yield node_match(ctx, msgs, note="the whole message list, including roles, comes from the client")


RULES: list[Rule] = [
    rule(
        "AISRF-PI-001",
        PACK,
        "Untrusted input interpolated into a prompt",
        severity="HIGH",
        confidence=0.55,
        category="prompt_injection",
        cwe="CWE-74",
        description="A prompt string is built with an f-string, format() call or template that interpolates values derived from users, requests or other untrusted sources. The model cannot tell the difference between the developer's instructions and the interpolated text, so the text can redirect the task, leak the system prompt or trigger tool calls.",
        why="Prompt injection is the top risk for LLM applications. Direct concatenation is the simplest and most common way attacker text gains the same authority as the developer's instructions.",
        remediation=(
            "Keep instructions in the system message and pass untrusted text as a separate user (or structured) message.",
            "Wrap untrusted text in clearly labelled delimiters and instruct the model to treat it as data.",
            "Limit input length and screen it for override phrases before it reaches the model.",
            "Validate the model's output before rendering or acting on it; never rely on the prompt alone.",
        ),
        languages=CODE,
        matcher=any_of(
            py(_untrusted_prompt),
            lines(r"\$\{\s*(req\.|request\.|user_?\w*|input\w*|query\w*|question\w*|message\w*|body\.|params\.|prompt\w*|text\w*|content\w*)", requires=r"(?i)(you are|answer|summari[sz]e|instruction|prompt|context:|question:|assistant|system)", flag=("ai", "route"), boost_flag="route"),
        ),
        tags=("direct", "sink:prompt"),
        engines=("rules", "semgrep"),
    ),
    rule(
        "AISRF-PI-002",
        PACK,
        "Runtime data placed in the system role",
        severity="HIGH",
        confidence=0.65,
        category="prompt_injection",
        cwe="CWE-74",
        description="Content sent with the system or developer role is assembled at runtime from variables. Anything an attacker controls in that content inherits the highest instruction privilege the model recognises.",
        why="System messages are the last place untrusted text should appear: models weight them above user turns, so an injection there overrides every other safeguard.",
        remediation=(
            "Make the system message a constant that contains behavioural rules only.",
            "Move per-request data (user profile, retrieved context, customer ids) into user messages or tool results, delimited and labelled.",
            "Look up sensitive per-user data through tools at call time instead of embedding it in instructions.",
        ),
        languages=CODE,
        matcher=any_of(
            py(_system_role_dynamic),
            near(r"role\s*:\s*['\"](system|developer)['\"]", r"content\s*:\s*(`[^`]*\$\{|[A-Za-z_$][\w$.]*\s*\+|(?!['\"`])[A-Za-z_$][\w$.]*\s*[,}\n])", window=3, flag=("ai", "route")),
        ),
        tags=("direct", "sink:system-prompt"),
        engines=("rules", "semgrep"),
    ),
    rule(
        "AISRF-PI-003",
        PACK,
        "HTTP request data passed straight to the model call",
        severity="HIGH",
        confidence=0.6,
        category="prompt_injection",
        cwe="CWE-20",
        description="Request parameters, form fields or the JSON body are handed to the model API without any intermediate validation, length limit or structuring.",
        why="A zero-hop path from the network to the model means every caller can inject instructions, exhaust token budgets or smuggle role markers.",
        remediation=(
            "Parse the request into a typed schema (pydantic, zod) with explicit length limits.",
            "Build the message list server side from validated fields; never forward raw request objects.",
            "Apply rate limits and per-user quotas on the endpoint.",
        ),
        languages=CODE,
        matcher=any_of(
            py(_request_to_model),
            lines(r"(chat\.completions\.create|messages\.create|generateText|streamText|generateObject|\.invoke\()\s*\([^)]*(req\.(body|query|params)|request\.(json|body|query))", flag=("ai", "route")),
        ),
        tags=("direct", "source:http"),
        engines=("rules", "semgrep"),
    ),
    rule(
        "AISRF-PI-004",
        PACK,
        "Prompt assembled by string concatenation",
        severity="MEDIUM",
        confidence=0.45,
        category="prompt_injection",
        cwe="CWE-74",
        description="Instruction text and runtime variables are glued together with '+' (or '%') into a single prompt string. There is no boundary the model can use to separate the two.",
        why="Concatenated prompts are hard to audit and impossible for the model to parse safely; injected text lands exactly where instructions live.",
        remediation=(
            "Use structured chat messages with distinct roles instead of one flat string.",
            "If a single string is unavoidable, place data inside explicit delimiters and reference it by name in the instructions.",
        ),
        languages=CODE,
        matcher=any_of(
            py(_concat_prompt),
            lines(r"[\"'][^\"']*(?i:you are|answer|summari[sz]e|instruction|prompt|context:|question:|the user)[^\"']*[\"']\s*\+\s*[A-Za-z_$][\w$.]*", flag=("ai", "route")),
        ),
        tags=("direct", "sink:prompt"),
    ),
    rule(
        "AISRF-PI-005",
        PACK,
        "Template engine compiles untrusted text as a prompt template",
        severity="HIGH",
        confidence=0.7,
        category="prompt_injection",
        cwe="CWE-1336",
        description="A templating engine (Jinja2, Mako, string.Template, LangChain templates) is instantiated from a runtime string rather than a constant template. Template syntax inside that string is evaluated, which is server side template injection on top of prompt injection.",
        why="Template injection lets an attacker execute expressions in the server process, not just influence the model.",
        remediation=(
            "Keep templates as constants in code or version-controlled prompt files.",
            "Pass untrusted values only as template variables, never as the template source.",
            "Use a sandboxed environment with autoescape when templates must be dynamic.",
        ),
        languages=CODE,
        matcher=lines(r"(jinja2\.)?(Template|Environment\(\)\.from_string|env\.from_string|from_string|render_template_string|PromptTemplate\.from_template|ChatPromptTemplate\.from_template|Handlebars\.compile|_\.template|nunjucks\.renderString|ejs\.render)\s*\(\s*(f[\"']|[A-Za-z_$][\w$.]*\s*[,)]|[A-Za-z_$][\w$.]*\s*\+|`[^`]*\$\{)", unless=r"\(\s*(SYSTEM|PROMPT|TEMPLATE|[A-Z_]{4,})\s*[,)]"),
        tags=("direct", "ssti"),
        engines=("rules", "semgrep"),
    ),
    rule(
        "AISRF-PI-006",
        PACK,
        "No length limit on input before the model call",
        severity="LOW",
        confidence=0.35,
        category="denial_of_wallet",
        cwe="CWE-770",
        description="An HTTP handler forwards text to the model without any visible truncation or length check. Long inputs give attackers more room for injection payloads and drive up token cost.",
        why="Bounding input size is the cheapest defence-in-depth control against both injection and denial of wallet.",
        remediation=(
            "Enforce a maximum character or token count on every text field before building the prompt.",
            "Reject or truncate over-sized inputs and log the event.",
        ),
        languages=("python", "javascript", "typescript"),
        matcher=absence([r"(@app\.(route|post|get)|@router\.(post|get)|app\.post\(|router\.post\(|export (async )?function POST)", LLM_CALL.pattern], [r"len\(|max_length|maxLength|\[:\s*\d|truncat|\.slice\(0|substring\(0|max_chars|MAX_INPUT|max_input|Field\([^)]*max_length|z\.string\(\)\.max\(|\.max\(\d|token_count|count_tokens|tiktoken"], anchor=LLM_CALL.pattern),
        tags=("hardening",),
    ),
    rule(
        "AISRF-PI-007",
        PACK,
        "Secrets or personal data embedded in the system prompt",
        severity="HIGH",
        confidence=0.6,
        category="secrets",
        cwe="CWE-200",
        description="Credentials, connection strings, internal URLs or user PII are interpolated into the system prompt. System prompts are routinely extracted, so everything in them must be considered public.",
        why="'Never reveal this' is not an access control. A single extraction prompt exposes the embedded values to any user.",
        remediation=(
            "Keep credentials out of the model context entirely; call internal services from code.",
            "Provide user data through scoped tools that enforce authorisation per call.",
            "Treat the system prompt as public and design accordingly.",
        ),
        languages=CODE,
        matcher=any_of(
            py(_secrets_in_system_prompt),
            lines(r"(?i)(system|instructions?)\w*\s*[=:][^\n]*(\$\{|\+\s*)[^\n]*(api_?key|apiKey|secret|password|token|email|phone|balance|account|connection|dsn)", flag=("ai", "route")),
        ),
        tags=("system-prompt", "secrets"),
    ),
    rule(
        "AISRF-PI-008",
        PACK,
        "Stored conversation history replayed into the prompt unchecked",
        severity="MEDIUM",
        confidence=0.4,
        category="prompt_injection",
        cwe="CWE-74",
        description="Previous messages loaded from storage or the client are spliced back into the conversation. A payload planted in an earlier turn (or in another user's session) keeps executing on every later request.",
        why="Persistent injection through memory survives page reloads and can cross user boundaries when history is keyed incorrectly.",
        remediation=(
            "Store history server side, keyed by user and session, and cap its length.",
            "Sanitise stored turns the same way as fresh input; strip role markers and control tokens.",
            "Never accept a full message list from the client.",
        ),
        languages=CODE,
        matcher=lines(r"(\*\s*(history|conversation|chat_history|previous_messages|stored_messages|past_messages)\b|messages\.extend\(\s*(history|conversation|chat_history|previous|stored|saved|past)|\.\.\.\s*(history|chatHistory|conversation|previousMessages|storedMessages)\b|messages\s*=\s*(history|chat_history|conversation)\s*\+)", flag="ai"),
        tags=("persistence",),
    ),
    rule(
        "AISRF-PI-009",
        PACK,
        "Fetched web or mailbox content summarised without isolation",
        severity="MEDIUM",
        confidence=0.45,
        category="indirect_prompt_injection",
        cwe="CWE-74",
        description="The same function downloads external content (web pages, feeds, emails) and passes it to the model. Hidden instructions in that content are executed with the application's privileges.",
        why="Indirect injection needs no access to the chat interface: the attacker only has to control a page or message the assistant will read.",
        remediation=(
            "Strip hidden text, comments, scripts and zero-width characters before prompting.",
            "Place fetched content in a delimited data block and tell the model it is untrusted reference material.",
            "Process untrusted content with a quarantined model call that has no tools, then pass structured results onward.",
        ),
        languages=CODE,
        matcher=any_of(
            py(_fetch_then_model),
            absence([r"(fetch\(|axios\.(get|post)|got\(|cheerio|puppeteer|playwright)", LLM_CALL.pattern], [r"(?i)(sanitiz|strip_|clean_|<untrusted|<context>|<document|<web|delimit|quarantine)"], flag="ai", anchor=LLM_CALL.pattern),
        ),
        tags=("indirect", "source:web"),
    ),
    rule(
        "AISRF-PI-010",
        PACK,
        "External content processed with tools enabled and no confirmation",
        severity="HIGH",
        confidence=0.5,
        category="indirect_prompt_injection",
        cwe="CWE-807",
        description="A model call that has tools attached is fed email, document, ticket or web content. An instruction hidden in that content can drive the tools (send, forward, delete, pay) without the user asking for it.",
        why="Indirect injection plus tool access is the confused deputy scenario: the assistant's authority is spent on the attacker's goals.",
        remediation=(
            "Separate reading from acting: summarise untrusted content with a tool-less call, then decide actions from structured output.",
            "Require explicit human confirmation before tools with side effects run.",
            "Restrict tool availability per task and per user.",
        ),
        languages=CODE,
        matcher=any_of(
            py(_external_content_with_tools),
            absence([r"\btools\s*:\s*[\[{]", r"(?i)(email|inbox|attachment|webpage|web_page|document|calendar|ticket)"], [r"(?i)(confirm|approv|human_in|hitl|allowlist|allow_list)"], flag="ai", anchor=r"\btools\s*:\s*[\[{]"),
        ),
        tags=("indirect", "agency"),
    ),
    rule(
        "AISRF-PI-011",
        PACK,
        "Prompt-only defence against injection",
        severity="INFO",
        confidence=0.5,
        category="prompt_injection",
        cwe="CWE-693",
        description="The prompt asks the model to ignore instructions found in user or retrieved content. That wording is useful defence in depth but it is bypassed regularly; verify that structural controls (validation, tool gating, output checks) exist outside the model.",
        why="Instructions inside the context window compete with the injection on equal footing. Security must be enforced by code.",
        remediation=(
            "Keep the defensive wording but add input screening, output validation and human approval for consequential actions.",
            "Test the assistant with a red-team campaign to measure how often the wording holds.",
        ),
        languages=ALL,
        matcher=lines(r"(?i)[\"'`][^\"'`]*((do not|don't|never)\s+(follow|obey|execute|act on)\s+(any\s+)?(instructions?|commands?|requests?)|ignore (any|all)\s+(instructions?|commands?|requests?)\s+(in|from|within|contained)|treat[^\"'`]{0,40}as (data|reference)[^\"'`]{0,20}(not|never)[^\"'`]{0,20}instruction)", skip_comments=False),
        tags=("hardening", "informational"),
    ),
    rule(
        "AISRF-PI-012",
        PACK,
        "Client controls the whole message list",
        severity="HIGH",
        confidence=0.7,
        category="prompt_injection",
        cwe="CWE-602",
        description="The messages array sent to the model is taken directly from the request body. Callers can supply their own system message, forge assistant turns or replay tool results.",
        why="Letting the client author every role removes the only privilege boundary the chat API offers.",
        remediation=(
            "Accept only the new user turn from the client; rebuild system and history messages server side.",
            "Validate role values and drop any system, developer or tool messages from client input.",
        ),
        languages=CODE,
        matcher=any_of(py(_client_messages), lines(MESSAGES_FROM_CLIENT.pattern)),
        tags=("direct", "source:http"),
        engines=("rules", "semgrep"),
    ),
]

MULTIMODAL_INPUT = r"(image_url|['\"]type['\"]\s*:\s*['\"](image|input_image|input_file|document|file|audio)['\"]|inline_data|Part\.from_(data|uri|bytes)|types\.Part\.from_bytes|['\"]source['\"]\s*:\s*\{\s*['\"]type['\"]\s*:\s*['\"](base64|url)['\"])"
SCREENING = r"(?i)(<\\\|im_start\\\||\[SYSTEM\]|\[INST\]|control[_ ]?tokens?|role[_ ]?markers?|injection[_ ]?patterns?|screen_|strip_roles?|detect_injection|rebuff|llm_guard|lakera|prompt_?guard|PromptInjection|Guard\(|is_injection|scan_input|classify_input)"
RULES += [
    rule(
        "AISRF-PI-013",
        PACK,
        "User input reaches the model without control-token or role-marker screening",
        severity="LOW",
        confidence=0.35,
        category="prompt_injection",
        cwe="CWE-20",
        description="An HTTP handler forwards text to a model and nothing in the module looks for chat-template control tokens, fake role markers or the usual override phrases first. Attackers use these markers to make their text look like a new system turn.",
        why="Screening does not stop injection, but it removes the cheapest tricks and gives you a signal to alert on. Its absence usually means no input hygiene at all.",
        remediation=(
            "Reject or neutralise control tokens and role markers (special tokens, bracketed role labels, template delimiters) before building the prompt.",
            "Run an injection classifier or guardrail scanner on inputs and log hits for monitoring.",
            "Keep the check outside the model: a prompt instruction cannot enforce it.",
        ),
        languages=("python", "javascript", "typescript"),
        matcher=absence([r"(@app\.(route|post|get)|@router\.(post|get)|app\.post\(|router\.post\(|export (async )?function POST)", LLM_CALL.pattern], [SCREENING], anchor=LLM_CALL.pattern, flag="route"),
        tags=("hardening", "input"),
    ),
    rule(
        "AISRF-PI-014",
        PACK,
        "User-supplied images or files sent to a multimodal model",
        severity="MEDIUM",
        confidence=0.45,
        category="indirect_prompt_injection",
        cwe="CWE-20",
        description="Uploaded or user-referenced images, documents or audio are attached to the model request. Text hidden inside the media (near-invisible captions, comments in a PDF, a transcript) is read by the model as part of the prompt and can carry instructions.",
        why="Multimodal inputs bypass every text-only filter; the payload is only visible once the model has already read it.",
        remediation=(
            "Fetch and re-encode media server side; never forward user URLs to the provider unchecked.",
            "Process media with a quarantined call that has no tools, then pass structured results onward.",
            "Limit accepted media types and sizes, and strip metadata before upload.",
        ),
        languages=CODE,
        matcher=near(MULTIMODAL_INPUT, r"(?i)(upload|request\.|req\.|user_|\bfile\b|filename|\burl\b|params|body|form|b64encode|attachment|files\[)", window=4, flag=("ai", "route")),
        tags=("indirect", "multimodal"),
        engines=("rules", "semgrep"),
    ),
]

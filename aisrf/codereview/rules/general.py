"""General AI application hygiene rule pack (AISRF-GN-*): credentials, exposure, limits and transport."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from . import pyast
from .base import (
    ALL,
    CODE,
    LLM_CALL,
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

PACK = "general"
PLACEHOLDER = r"(?i)(xxx|your[_-]?|example|placeholder|\.\.\.|<[^>]+>|replace|dummy|changeme|1234567890|fake|test-?key|sample|redacted|\*\*\*|\$\{|os\.environ|getenv|process\.env|secrets\.|vault)"
PROVIDER_KEY = r"(sk-(proj-|ant-(api\d{2}-)?|or-v1-)?[A-Za-z0-9_\-]{20,}|AIza[0-9A-Za-z_\-]{30,}|hf_[A-Za-z0-9]{20,}|gsk_[A-Za-z0-9]{20,}|xai-[A-Za-z0-9]{20,}|r8_[A-Za-z0-9]{20,}|pcsk_[A-Za-z0-9_\-]{20,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|glpat-[A-Za-z0-9_\-]{20,}|xox[baprs]-[A-Za-z0-9\-]{10,}|sk-[A-Za-z0-9]{32,})"
PROVIDER_ASSIGN = r"(?i)\b(OPENAI|ANTHROPIC|CLAUDE|GOOGLE|GEMINI|GOOGLE_AI|COHERE|MISTRAL|GROQ|HUGGING_?FACE|HF|REPLICATE|TOGETHER|AZURE_OPENAI|XAI|DEEPSEEK|PERPLEXITY|VOYAGE|OPENROUTER|FIREWORKS|LANGCHAIN|LANGSMITH|LLM|MODEL)_?(API_?KEY|TOKEN|SECRET|KEY)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{16,}['\"]?"
LLM_CREATE = re.compile(r"(^|\.)(chat\.completions\.create|completions\.create|messages\.create|responses\.create|generate_content|generate_content_async|images\.generate|embeddings\.create)$")
TOKEN_KW = {"max_tokens", "max_completion_tokens", "max_output_tokens", "generation_config", "timeout", "max_new_tokens", "config"}


def _call_without_limits(ctx: FileContext, tree: ast.Module) -> Iterator[Match]:
    for call in pyast.iter_calls(tree):
        name = pyast.call_name(call)
        if not LLM_CREATE.search(name):
            continue
        kws = {k.arg for k in call.keywords if k.arg}
        if kws & TOKEN_KW or any(k.arg is None for k in call.keywords):
            continue
        if name.endswith("embeddings.create"):
            continue
        yield node_match(ctx, call, note="no max_tokens or timeout on the call")
    for call in pyast.iter_calls(tree):
        name = pyast.call_name(call)
        if name in ("OpenAI", "AsyncOpenAI", "Anthropic", "AsyncAnthropic", "AzureOpenAI", "AsyncAzureOpenAI", "openai.OpenAI", "anthropic.Anthropic") and not pyast.has_keyword(call, "timeout") and not pyast.has_keyword(call, "max_retries"):
            yield node_match(ctx, call, boost=-0.15, note="client created without an explicit timeout")


RULES: list[Rule] = [
    rule(
        "AISRF-GN-001",
        PACK,
        "Hardcoded AI provider credential",
        severity="CRITICAL",
        confidence=0.9,
        category="secrets",
        cwe="CWE-798",
        description="A provider API key (OpenAI, Anthropic, Google, Hugging Face, Groq, xAI, Replicate, Pinecone, GitHub, Slack...) or a provider key variable assigned a literal value appears in the source.",
        why="Leaked model keys are monetised within minutes (denial of wallet) and can expose fine-tuned models, files and logs stored with the provider.",
        remediation=(
            "Revoke the key now and issue a new one; assume it is compromised.",
            "Load keys from environment variables or a secret manager; add a pre-commit secret scanner.",
            "Scope keys per environment and set spend limits with the provider.",
        ),
        languages=ALL,
        matcher=any_of(
            lines(r"['\"`]?" + PROVIDER_KEY + r"['\"`]?", unless=PLACEHOLDER, skip_comments=False),
            lines(PROVIDER_ASSIGN, unless=PLACEHOLDER, skip_comments=False),
            lines(r"(?i)\bapi_?key\s*[=:]\s*['\"][A-Za-z0-9_\-]{24,}['\"]", unless=PLACEHOLDER, skip_comments=False),
        ),
        tags=("secrets",),
        engines=("rules", "semgrep"),
    ),
    rule(
        "AISRF-GN-002",
        PACK,
        "Secret in a prompt, environment or configuration file",
        severity="HIGH",
        confidence=0.7,
        category="secrets",
        cwe="CWE-312",
        description="A committed .env, prompt, template, YAML, JSON or TOML file assigns a value to a key named like a secret (API key, token, password, private key).",
        why="Prompt and configuration files are copied into tickets, chats and model contexts far more often than code; secrets in them travel everywhere.",
        remediation=(
            "Remove the value, rotate the credential and add the file pattern to .gitignore.",
            "Keep only placeholder examples (.env.example) in the repository.",
            "Reference secrets by name from a secret store at runtime.",
        ),
        languages=("dotenv", "prompt", "text", "markdown", "yaml", "json", "toml", "jinja", "config", "xml"),
        matcher=lines(r"(?i)^\s*[\"']?[A-Z0-9_.\-]*(API_?KEY|SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE_KEY|CLIENT_SECRET|ACCESS_KEY)[A-Z0-9_.\-]*[\"']?\s*[=:]\s*[\"']?[^\s\"'#,]{12,}", unless=PLACEHOLDER, skip_comments=False),
        tags=("secrets", "config"),
    ),
    rule(
        "AISRF-GN-003",
        PACK,
        "Debug mode or introspection endpoint enabled",
        severity="MEDIUM",
        confidence=0.6,
        category="system_prompt_leak",
        cwe="CWE-489",
        description="The application runs with debug enabled or exposes routes that reveal prompts, configuration or environment (for example /debug, /prompt, /config, /env).",
        why="Debug consoles and prompt-dump endpoints hand attackers the system prompt, tool schemas and often credentials without any injection at all.",
        remediation=(
            "Disable debug in production builds and gate any introspection route behind admin authentication.",
            "Never expose the raw system prompt or provider configuration through an API.",
        ),
        languages=CODE,
        matcher=any_of(
            lines(r"(app\.run\s*\([^)]*debug\s*=\s*True|\bDEBUG\s*=\s*True\b|debug\s*:\s*true\b|FLASK_DEBUG\s*=\s*1|uvicorn\.run\s*\([^)]*reload\s*=\s*True|app\.debug\s*=\s*True)"),
            lines(r"(@app\.(route|get|post)|@router\.(get|post)|app\.(get|post)\(|router\.(get|post)\()\s*\(?\s*['\"][^'\"]*/(debug|__debug__|internal|admin/prompt|system[_-]?prompt|prompts?/raw|config|env|dump)\b", flag=("ai", "route")),
        ),
        tags=("exposure",),
    ),
    rule(
        "AISRF-GN-004",
        PACK,
        "Permissive CORS on an AI API",
        severity="MEDIUM",
        confidence=0.7,
        category="data_exfiltration",
        cwe="CWE-942",
        description="Cross-origin requests are accepted from any origin (wildcard origins, CORS(app) defaults, cors() without options), on a service that talks to a model. With credentials allowed, any web page can drive the assistant as the logged-in user.",
        why="Wildcard CORS lets attacker sites spend your model budget and, with credentials, read other users' conversations through their browsers.",
        remediation=(
            "Allowlist the exact origins of your front end.",
            "Never combine wildcard origins with allow_credentials.",
            "Rate limit and authenticate the model endpoints independently of CORS.",
        ),
        languages=CODE,
        matcher=lines(r"(allow_origins\s*=\s*\[\s*['\"]\*['\"]|CORS\(\s*app\s*\)|origins\s*=\s*['\"]\*['\"]|Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]\*|origin\s*:\s*['\"]\*['\"]|app\.use\(\s*cors\(\s*\)\s*\)|cors\(\{\s*origin\s*:\s*true|CORS_ORIGIN_ALLOW_ALL\s*=\s*True|allowedOrigins\s*:\s*\[\s*['\"]\*['\"])", boost_flag="ai"),
        tags=("cors",),
    ),
    rule(
        "AISRF-GN-005",
        PACK,
        "Model endpoint without rate limiting",
        severity="MEDIUM",
        confidence=0.4,
        category="denial_of_wallet",
        cwe="CWE-770",
        description="An HTTP handler that calls a model shows no rate limiting, quota or budget control in the module.",
        why="Every unthrottled model endpoint is a metered resource that someone else can spend; extraction and denial of wallet both start here.",
        remediation=(
            "Apply per-user and per-IP rate limits and daily token budgets on model endpoints.",
            "Set provider-side spend limits and alert on anomalies.",
            "Require authentication so limits can be attributed.",
        ),
        languages=("python", "javascript", "typescript"),
        matcher=absence([r"(@app\.(route|post|get|api_route)|@router\.(post|get|api_route)|app\.post\(|router\.post\(|export (async )?function POST)", LLM_CALL.pattern], [r"(?i)(limiter|ratelimit|rate_limit|RateLimit|throttl|slowapi|express-rate-limit|rateLimit|Bucket|quota|budget|max_requests|cost_guard|Semaphore|@limits|upstash)"], anchor=LLM_CALL.pattern),
        tags=("limits",),
    ),
    rule(
        "AISRF-GN-006",
        PACK,
        "Model call without max_tokens or timeout",
        severity="LOW",
        confidence=0.5,
        category="denial_of_wallet",
        cwe="CWE-400",
        description="A completion call sets no output token limit and the client has no timeout. A single adversarial prompt can produce the longest, most expensive response the provider allows and hold the worker for minutes.",
        why="Output limits and timeouts bound cost and latency per request; without them a small number of requests can exhaust the budget.",
        remediation=(
            "Set max_tokens (or the provider equivalent) on every call and a timeout on the client.",
            "Track token usage per user and stop serving when a budget is exceeded.",
        ),
        languages=CODE,
        matcher=any_of(
            py(_call_without_limits),
            near(r"(chat\.completions\.create|messages\.create|responses\.create|generateText|streamText|generateObject)\s*\(\s*\{", None, window=10, unless=r"(max_tokens|maxTokens|max_completion_tokens|maxOutputTokens|max_output_tokens|abortSignal|timeout)"),
            lines(r"new\s+(OpenAI|Anthropic|AzureOpenAI)\s*\(\s*(\)|\{(?![^}]*timeout)[^}]*\})", flag="ai"),
        ),
        tags=("limits",),
    ),
    rule(
        "AISRF-GN-007",
        PACK,
        "Streaming response without abort or timeout handling",
        severity="LOW",
        confidence=0.35,
        category="denial_of_wallet",
        cwe="CWE-400",
        description="Streamed completions are produced or relayed and the module shows no abort signal, disconnect check, deadline or token cap.",
        why="A client that disconnects should stop the upstream stream; otherwise abandoned generations keep billing and hold connections open.",
        remediation=(
            "Propagate client disconnects (AbortController, request.is_disconnected) to the provider stream.",
            "Cap stream duration and total tokens; close idle streams.",
        ),
        languages=CODE,
        matcher=absence([r"(stream\s*[=:]\s*[Tt]rue|streamText\s*\(|\.stream\s*\(|text/event-stream|StreamingResponse\s*\(|EventSourceResponse\s*\()"], [r"(?i)(abort|AbortController|signal|timeout|cancel|disconnect|is_disconnected|max_tokens|maxTokens|deadline|time_limit)"], flag="ai", anchor=r"(stream\s*[=:]\s*[Tt]rue|streamText\s*\(|\.stream\s*\(|text/event-stream|StreamingResponse\s*\(|EventSourceResponse\s*\()"),
        tags=("limits", "streaming"),
    ),
    rule(
        "AISRF-GN-008",
        PACK,
        "API key handled unsafely at runtime",
        severity="HIGH",
        confidence=0.7,
        category="secrets",
        cwe="CWE-532",
        description="A provider key is taken from a query string, written to logs or printed. Keys in URLs land in proxies and access logs; keys in application logs land everywhere logs go.",
        why="Runtime leakage defeats the secret store: the key is safe at rest and public in flight.",
        remediation=(
            "Pass keys only in headers over TLS and never accept them from clients.",
            "Redact key-like values in logging formatters.",
        ),
        languages=CODE,
        matcher=lines(r"(?i)((api_?key|token|secret)\s*=\s*request\.(args|GET|query_params|form|values)|req\.query\.(apiKey|api_key|token|key)\b|(print|console\.log|logger?\.(info|debug|warn(ing)?|error))\s*\([^)]*\b(api_?key|OPENAI_API_KEY|ANTHROPIC_API_KEY|secret_key|access_token|client_secret)\b|[?&]api_?key=(?!\$|\{|<|%))", unless=r"(?i)(redact|mask|\[:4\]|\*\*\*|len\()"),
        tags=("secrets", "logging"),
    ),
    rule(
        "AISRF-GN-009",
        PACK,
        "Verbose agent tracing enabled",
        severity="LOW",
        confidence=0.5,
        category="system_prompt_leak",
        cwe="CWE-532",
        description="Agents or chains run with verbose or debug tracing, which prints prompts, intermediate reasoning, tool arguments and tool results to stdout or logs.",
        why="Verbose traces are a full transcript of the system prompt and every tool call; in production they are a data leak and a debugging aid for attackers.",
        remediation=(
            "Turn verbose and debug flags off outside development.",
            "Send traces to an access-controlled observability backend with redaction instead of stdout.",
        ),
        languages=CODE,
        matcher=lines(r"(verbose\s*[=:]\s*[Tt]rue|set_debug\s*\(\s*True\s*\)|set_verbose\s*\(\s*True\s*\)|langchain\.debug\s*=\s*True|LANGCHAIN_VERBOSE\s*=\s*['\"]?true|debug\s*=\s*True[^\n]*(agent|chain|crew))", flag=("agent", "ai")),
        tags=("logging",),
    ),
    rule(
        "AISRF-GN-010",
        PACK,
        "TLS verification disabled for model or tool traffic",
        severity="MEDIUM",
        confidence=0.6,
        category="supply_chain",
        cwe="CWE-295",
        description="Certificate verification is switched off for HTTP clients (verify=False, rejectUnauthorized: false, NODE_TLS_REJECT_UNAUTHORIZED=0, curl -k). Prompts, responses and API keys can be intercepted or modified in transit.",
        why="Model traffic carries credentials and confidential prompts; a man in the middle can also inject instructions into responses.",
        remediation=(
            "Enable certificate verification and trust the correct CA bundle.",
            "Pin certificates for internal model gateways where practical.",
        ),
        languages=ALL,
        matcher=lines(r"(verify\s*=\s*False|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0|rejectUnauthorized\s*:\s*false|ssl\._create_unverified_context|check_hostname\s*=\s*False|CERT_NONE|--insecure\b|curl\s+-k\s|InsecureRequestWarning|verify_ssl\s*=\s*False|ssl_verify\s*[=:]\s*[Ff]alse)", boost_flag="ai"),
        tags=("transport",),
        engines=("rules", "bandit"),
    ),
    rule(
        "AISRF-GN-011",
        PACK,
        "Model name or provider endpoint controlled by the client",
        severity="MEDIUM",
        confidence=0.55,
        category="denial_of_wallet",
        cwe="CWE-20",
        description="The model identifier or the provider base URL is taken from the request. Callers can pick the most expensive model, route traffic to their own endpoint (leaking prompts and keys) or reach internal hosts.",
        why="Model selection is a cost and trust decision that belongs to the server.",
        remediation=(
            "Map client choices to an allowlist of approved models; hardcode provider base URLs.",
            "Attach budgets to the allowed models and log which one served each request.",
        ),
        languages=CODE,
        matcher=lines(r"(base_url\s*=\s*(request|req|params|body|payload|data)\b|baseURL\s*:\s*req\.|model\s*=\s*request\.(json|args|form|get_json)|model\s*[=:]\s*(req|request)\.body\.model|model\s*[=:]\s*(payload|body|data|params)\[['\"]model['\"]\]|model\s*=\s*(payload|body|data)\.model\b)", flag=("ai", "route"), unless=r"(?i)(allow|ALLOWED|in \(|choices|Literal\[|enum)"),
        tags=("limits", "ssrf"),
    ),
]
_ = (ast, Match)

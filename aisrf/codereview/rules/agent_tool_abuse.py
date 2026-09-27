"""Agent and tool abuse rule pack (AISRF-AT-*): what the model is allowed to do and how safely."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from . import pyast
from .base import (
    CODE,
    JS,
    LLM_CALL,
    PY,
    TOOL_ARG,
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

PACK = "agent_tool_abuse"
TOOL_DECORATOR = re.compile(
    r"(?i)(^|\.)(tool|function_tool|kernel_function|register_tool|register_function|agent_tool|action|command)$|mcp\.tool|server\.tool|\.tool$"
)
SHELL_CALLS = re.compile(
    r"(^|\.)(subprocess\.(run|call|check_output|check_call|Popen|getoutput|getstatusoutput)|os\.(system|popen|execv|execvp|execl|spawn\w*)|commands\.getoutput|pty\.spawn|asyncio\.create_subprocess_shell)$"
)
CODE_EXEC = re.compile(
    r"(^|\.)(eval|exec|compile|__import__|importlib\.import_module|PythonREPL\.run|python_repl\.run|run_code|execute_code)$"
)
FILE_CALLS = re.compile(
    r"(^|\.)(open|Path|read_text|write_text|read_bytes|write_bytes|os\.remove|os\.unlink|os\.rename|os\.listdir|os\.walk|shutil\.(copy|copyfile|move|rmtree)|send_file|FileResponse|aiofiles\.open|unlink|rename)$"
)
HTTP_CALLS = re.compile(
    r"(^|\.)(requests\.(get|post|put|delete|request|head)|httpx\.(get|post|request|AsyncClient|Client)|urlopen|urllib\.request\.urlopen|aiohttp\.ClientSession|session\.(get|post)|client\.(get|post)|fetch|urlretrieve)$"
)
SQL_EXEC = re.compile(
    r"(^|\.)(execute|executemany|executescript|exec_driver_sql|raw|query|run_query|run_sql|sql|cursor\.execute|text)$"
)
DANGEROUS_TOOL_NAME = re.compile(
    r"(?i)(refund|delete|remove|drop|wipe|purge|destroy|transfer|withdraw|pay(ment)?|charge|purchase|buy|order|send_?(email|mail|sms|message|notification)|email|deploy|rollback|terminate|shutdown|reboot|kill|revoke|grant|escalate|create_?(api_?key|user|token|credential)|update_?(address|password|email|permission|role)|write_?file|overwrite|publish|post_to|execute|run_?command)"
)
CONFIRMATION = re.compile(
    r"(?i)(confirm|approv|human|hitl|ask_user|consent|dry_run|dryrun|is_admin|has_permission|authoriz|require_confirmation|manual_review|two_person|require_approval)"
)
PATH_GUARD = re.compile(
    r"(realpath|\.resolve\(|relative_to|is_relative_to|commonpath|safe_join|secure_filename|allowlist|ALLOWED|startswith\(|normpath|os\.path\.abspath|in ALLOWED|sandbox|chroot|jail)"
)
URL_GUARD = re.compile(
    r"(urlparse|urlsplit|hostname|allowlist|allow_list|ALLOWED|allowed_domains|allowed_hosts|is_private|ipaddress|ip_address|netloc|whitelist|TRUSTED|blocklist|ssrf)"
)
RECIPIENT_GUARD = re.compile(
    r"(?i)(allowlist|allowed_recipients|verified|in ALLOWED|endswith\(['\"]@|internal_domain|allowed_domains|ALLOWED_TO|approved_recipients|confirm)"
)
DANGEROUS_CAPABILITY = re.compile(
    r"(subprocess\.|os\.system|os\.popen|\beval\(|\bexec\(|shutil\.rmtree|os\.remove|os\.unlink|\.write_text\(|open\([^)]*[\"'][wa]|requests\.(post|put|delete)|smtplib|sendmail|paramiko|fabric|docker\.|kubernetes|boto3|psycopg|sqlite3|pymysql|sqlalchemy|child_process|execSync|spawnSync)"
)
FRAMEWORK_DANGEROUS = re.compile(
    r"(PythonREPLTool|PythonAstREPLTool|PythonREPL\(|ShellTool\(|BashProcess|TerminalTool|allow_dangerous_code\s*=\s*True|allow_dangerous_requests\s*=\s*True|PALChain|LLMMathChain|load_tools\([^)]*[\"'](terminal|python_repl|shell|requests_all|requests_post)|create_pandas_dataframe_agent|create_python_agent|create_csv_agent|create_spark_dataframe_agent|LocalPythonExecutor|PythonInterpreterTool|LocalCommandLineCodeExecutor|use_docker[\"']?\s*[:=]\s*False|RequestsToolkit|FileManagementToolkit|PlayWrightBrowserToolkit|E2BDataAnalysisTool\([^)]*sandbox\s*=\s*None|CodeAgent\(|allowDangerousCode\s*:\s*true)"
)


def _tool_functions(
    ctx: FileContext, tree: ast.Module
) -> dict[str, tuple[ast.FunctionDef | ast.AsyncFunctionDef, str]]:
    """Functions exposed to a model: decorated (@tool, @mcp.tool...) or referenced from a tool registration."""
    registered: set[str] = set()
    for call in pyast.iter_calls(tree):
        name = pyast.call_name(call)
        if re.search(
            r"(^|\.)(Tool|StructuredTool\.from_function|FunctionTool\.from_defaults|FunctionTool|tool|register_tool|add_tool|register_for_llm|register_for_execution|Function|FunctionDeclaration)$",
            name,
        ):
            for a in [*call.args, *[k.value for k in call.keywords]]:
                registered |= {n for n in pyast.names_in(a) if "." not in n}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id.lower() in ("tools", "functions", "toolkit", "available_tools")
            for t in node.targets
        ):
            registered |= {n for n in pyast.names_in(node.value) if "." not in n}
    out: dict[str, tuple[ast.FunctionDef | ast.AsyncFunctionDef, str]] = {}
    generic = ctx.has_flag("tool", "mcp", "agent")
    for func in pyast.iter_functions(tree):
        if any(TOOL_DECORATOR.search(d) for d in pyast.decorators(func)) or func.name in registered:
            out[func.name] = (func, "strong")
        elif (
            generic
            and ast.get_docstring(func)
            and not func.name.startswith("_")
            and pyast.enclosing_function(func) is None
        ):
            out[func.name] = (func, "weak")
    return out


def _tool_sink(
    ctx: FileContext,
    tree: ast.Module,
    sink: re.Pattern[str],
    guard: re.Pattern[str] | None,
    note: str,
    *,
    require_param: bool = True,
) -> Iterator[Match]:
    for name, (func, strength) in _tool_functions(ctx, tree).items():
        text = pyast.func_text(func, ctx.lines)
        if guard is not None and guard.search(text):
            continue
        params = pyast.arg_names(func)
        for call in pyast.iter_calls(func):
            if not sink.search(pyast.call_name(call)):
                continue
            args = [*call.args, *[k.value for k in call.keywords]]
            if require_param and not any(
                pyast.depends_on(a, params) or pyast.is_dynamic_string(a) for a in args
            ):
                continue
            yield node_match(
                ctx, call, boost=0.2 if strength == "strong" else -0.15, note=f"tool {name}: {note}"
            )
            break


def _shell_with_model_args(ctx: FileContext, tree: ast.Module) -> Iterator[Match]:
    tools = _tool_functions(ctx, tree)
    for call in pyast.iter_calls(tree):
        name = pyast.call_name(call)
        if not SHELL_CALLS.search(name):
            continue
        first = call.args[0] if call.args else None
        shell = pyast.is_true(pyast.keyword(call, "shell")) or name.endswith(
            ("os.system", "os.popen", "create_subprocess_shell", "getoutput")
        )
        if first is None or (pyast.is_constant(first) and not pyast.is_dynamic_string(first)):
            continue
        func = pyast.enclosing_function(call)
        in_tool = func is not None and func.name in tools
        if not in_tool and not ctx.has_flag("ai", "tool", "agent", "mcp"):
            continue
        refs = " ".join(sorted(pyast.names_in(first)))
        if not (shell or pyast.is_dynamic_string(first) or in_tool or TOOL_ARG.search(refs)):
            continue
        boost = 0.2 if in_tool else 0.0
        if not shell and not pyast.is_dynamic_string(first):
            boost -= 0.2
        yield node_match(
            ctx,
            call,
            boost=boost,
            note=("shell=True with runtime arguments" if shell else "command built at runtime")
            + (f" inside tool {func.name}" if in_tool and func else ""),
        )


def _code_exec_of_args(ctx: FileContext, tree: ast.Module) -> Iterator[Match]:
    tools = _tool_functions(ctx, tree)
    for call in pyast.iter_calls(tree):
        name = pyast.call_name(call)
        if not CODE_EXEC.search(name) or not call.args:
            continue
        arg = call.args[0]
        if pyast.is_constant(arg) and not pyast.is_dynamic_string(arg):
            continue
        func = pyast.enclosing_function(call)
        in_tool = func is not None and func.name in tools
        if not in_tool and not ctx.has_flag("ai", "tool", "agent", "mcp"):
            continue
        yield node_match(
            ctx,
            call,
            boost=0.2 if in_tool else 0.0,
            note=f"{name}() on runtime data" + (f" inside tool {func.name}" if in_tool and func else ""),
        )


def _sql_from_runtime(ctx: FileContext, tree: ast.Module) -> Iterator[Match]:
    if not ctx.has_flag("ai", "tool", "agent", "rag", "mcp"):
        return
    tools = _tool_functions(ctx, tree)
    for call in pyast.iter_calls(tree):
        if not SQL_EXEC.search(pyast.call_name(call)) or not call.args:
            continue
        first = call.args[0]
        if not pyast.is_dynamic_string(first):
            continue
        if not re.search(
            r"(?i)\b(select|insert|update|delete|drop|alter|create|where|from)\b", pyast.literal_text(first)
        ):
            continue
        func = pyast.enclosing_function(call)
        in_tool = func is not None and func.name in tools
        yield node_match(
            ctx,
            call,
            boost=0.2 if in_tool else 0.0,
            note="query text is formatted at runtime"
            + (f" inside tool {func.name}" if in_tool and func else ""),
        )


def _destructive_without_confirmation(ctx: FileContext, tree: ast.Module) -> Iterator[Match]:
    for name, (func, strength) in _tool_functions(ctx, tree).items():
        doc = ast.get_docstring(func) or ""
        if not DANGEROUS_TOOL_NAME.search(name) and not DANGEROUS_TOOL_NAME.search(doc[:200]):
            continue
        text = pyast.func_text(func, ctx.lines)
        if CONFIRMATION.search(text):
            continue
        yield Match(
            func.lineno,
            func.lineno,
            snippet=ctx.snippet(func.lineno, func.lineno + 2),
            boost=0.15 if strength == "strong" else -0.1,
            note=f"tool {name} has side effects and no confirmation gate",
        )


def _unbounded_loop(ctx: FileContext, tree: ast.Module) -> Iterator[Match]:
    for func in pyast.iter_functions(tree):
        text = pyast.func_text(func, ctx.lines)
        if not (LLM_CALL.search(text) or re.search(r"tool_calls|function_call|\.tools\b", text)):
            continue
        if re.search(
            r"(?i)(max_iter|max_steps|max_turns|max_rounds|budget|MAX_[A-Z_]*(STEP|ITER|TURN|LOOP|CALL)|_limit\b|iterations?\s*[<>]|steps?\s*[<>]|attempt|recursion_limit|deadline|time\.(time|monotonic)\(\)\s*[-<>])",
            text,
        ):
            continue
        for node in ast.walk(func):
            if (
                isinstance(node, ast.While)
                and isinstance(node.test, ast.Constant)
                and node.test.value is True
            ):
                yield node_match(
                    ctx,
                    node,
                    note=f"while True loop in {func.name} drives the model without a step or cost cap",
                )
                break


def _dispatch_by_name(ctx: FileContext, tree: ast.Module) -> Iterator[Match]:
    if not ctx.has_flag("ai", "tool", "agent", "mcp"):
        return
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Call)
            and pyast.call_name(node.value) in ("globals", "locals", "vars")
        ):
            yield node_match(
                ctx, node, note="function looked up in globals()/locals() by a model-supplied name"
            )
        elif (
            isinstance(node, ast.Call)
            and pyast.call_name(node) == "getattr"
            and len(node.args) >= 2
            and not pyast.is_constant(node.args[1])
        ):
            refs = " ".join(pyast.names_in(node.args[1]))
            if re.search(r"(?i)(name|function|tool|call)", refs):
                yield node_match(ctx, node, note="getattr() with a model-supplied attribute name")


def _mcp_dangerous_tools(ctx: FileContext, tree: ast.Module) -> Iterator[Match]:
    if not ctx.has_flag("mcp"):
        return
    for func in pyast.iter_functions(tree):
        if not any(re.search(r"(mcp\.tool|server\.tool|\.tool$|^tool$)", d) for d in pyast.decorators(func)):
            continue
        text = pyast.func_text(func, ctx.lines)
        caps = sorted({m.group(0).strip("(.") for m in DANGEROUS_CAPABILITY.finditer(text)})
        if not caps:
            continue
        if CONFIRMATION.search(text) and PATH_GUARD.search(text):
            continue
        yield Match(
            func.lineno,
            func.lineno,
            snippet=ctx.snippet(func.lineno, func.lineno + 2),
            note=f"MCP tool {func.name} uses {', '.join(caps[:4])}",
        )


def _unscoped_data_access(ctx: FileContext, tree: ast.Module) -> Iterator[Match]:
    for name, (func, strength) in _tool_functions(ctx, tree).items():
        text = pyast.func_text(func, ctx.lines)
        if not re.search(
            r"(?i)(\bselect\b|\.filter\(|\.filter_by\(|find_one\(|\.find\(|\.query\(|\.get\(|lookup|fetch_|load_)",
            text,
        ):
            continue
        if re.search(
            r"(?i)(user_id|tenant|owner|customer_id|current_user|scope|principal|session\.user|account_id|org_id|workspace|requester|acl|permission)",
            text,
        ):
            continue
        yield Match(
            func.lineno,
            func.lineno,
            snippet=ctx.snippet(func.lineno, func.lineno + 2),
            boost=0.1 if strength == "strong" else -0.1,
            note=f"tool {name} reads data without a user or tenant scope",
        )


RULES: list[Rule] = [
    rule(
        "AISRF-AT-001",
        PACK,
        "Shell command executed with model-controlled arguments",
        severity="CRITICAL",
        confidence=0.65,
        category="tool_abuse",
        cwe="CWE-78",
        description="A tool or agent helper runs a shell command whose text or arguments are produced at runtime, typically from model output or tool arguments. With shell=True (or os.system) metacharacters in the argument become new commands.",
        why="A prompt injection that reaches this tool is remote code execution on the host running the agent.",
        remediation=(
            "Never build shell strings from model data; call the program with an argument list and shell=False.",
            "Validate arguments against a strict allowlist (hostnames, file names, enumerations) before use.",
            "Run tools in a sandbox with no credentials, no network egress and a read-only filesystem.",
            "Require human approval for any tool that executes commands.",
        ),
        languages=CODE,
        matcher=any_of(
            py(_shell_with_model_args),
            lines(
                r"\b(exec|execSync|execFile|spawn|spawnSync)\s*\(\s*(`[^`]*\$\{|[A-Za-z_$][\w$.]*\s*\+|[A-Za-z_$][\w$.]*\s*[,)])",
                flag=("ai", "tool", "agent", "mcp"),
                unless=r"\(\s*['\"]",
            ),
        ),
        tags=("sink:shell",),
        engines=("rules", "semgrep", "bandit"),
    ),
    rule(
        "AISRF-AT-002",
        PACK,
        "Dynamic code evaluation of tool or model data",
        severity="CRITICAL",
        confidence=0.65,
        category="tool_abuse",
        cwe="CWE-95",
        description="eval(), exec(), compile() or an in-process REPL is applied to runtime data in an AI component. Model-generated expressions are attacker-controlled once the prompt is compromised.",
        why="Code evaluation turns any injection into arbitrary code execution with the application's privileges.",
        remediation=(
            "Replace eval-based calculators or interpreters with parsers that support only the needed grammar.",
            "If code execution is a feature, run it in an isolated sandbox (container, microVM or WebAssembly) with no secrets mounted.",
            "Log every executed snippet and cap runtime and memory.",
        ),
        languages=CODE,
        matcher=any_of(
            py(_code_exec_of_args),
            lines(
                r"(\beval\s*\(\s*(?!['\"])|new\s+Function\s*\(|vm\.(runInNewContext|runInThisContext|runInContext|Script)\s*\(|\bFunction\s*\(\s*['\"]return)",
                flag=("ai", "tool", "agent", "mcp"),
            ),
        ),
        tags=("sink:eval",),
        engines=("rules", "semgrep", "bandit"),
    ),
    rule(
        "AISRF-AT-003",
        PACK,
        "File system tool without path containment",
        severity="HIGH",
        confidence=0.55,
        category="tool_abuse",
        cwe="CWE-22",
        description="A tool opens, reads, writes or deletes a path derived from its arguments without resolving it and checking that it stays inside an allowed directory.",
        why="Path traversal through a model tool exposes configuration files, keys and other users' data, or lets the model overwrite code that later runs.",
        remediation=(
            "Resolve the requested path and verify it is inside the tool's base directory before any I/O.",
            "Allowlist file extensions and reject absolute paths and '..' segments.",
            "Separate read-only and write tools; keep write targets away from anything executable.",
        ),
        languages=CODE,
        matcher=any_of(
            py(
                lambda ctx, tree: _tool_sink(
                    ctx, tree, FILE_CALLS, PATH_GUARD, "file path comes from tool arguments"
                )
            ),
            absence(
                [
                    r"fs\.(readFile|readFileSync|writeFile|writeFileSync|unlink|rm|readdir|appendFile)\w*\s*\(\s*(?!['\"])"
                ],
                [r"path\.resolve[^\n]*startsWith|normalize|allowlist|ALLOWED|isInside|safePath"],
                flag=("tool", "mcp", "agent"),
                anchor=r"fs\.(readFile|readFileSync|writeFile|writeFileSync|unlink|rm|readdir|appendFile)\w*\s*\(",
            ),
        ),
        tags=("sink:filesystem",),
        engines=("rules", "semgrep"),
    ),
    rule(
        "AISRF-AT-004",
        PACK,
        "Outbound HTTP tool without a URL allowlist",
        severity="HIGH",
        confidence=0.55,
        category="tool_abuse",
        cwe="CWE-918",
        description="A tool fetches a URL supplied in its arguments without validating the destination host. The model can be steered to internal services (SSRF) or to an attacker's server, which also turns the tool into a data exfiltration channel.",
        why="Every outbound request a tool makes can carry context data in the path or query string, and can reach metadata endpoints or private networks.",
        remediation=(
            "Allowlist destination hosts; resolve DNS and reject private or link-local addresses.",
            "Limit URL length and strip query parameters that could carry encoded data.",
            "Rate limit outbound calls per session and log them with the initiating conversation.",
        ),
        languages=CODE,
        matcher=any_of(
            py(
                lambda ctx, tree: _tool_sink(
                    ctx, tree, HTTP_CALLS, URL_GUARD, "destination URL comes from tool arguments"
                )
            ),
            absence(
                [r"\b(fetch|axios(\.get|\.post)?|got|request)\s*\(\s*(?!['\"])[A-Za-z_$`]"],
                [
                    r"(?i)(allowlist|allowed_hosts|allowedHosts|hostname|new URL\([^)]*\)\.host|isPrivate|ssrf|blocklist)"
                ],
                flag=("tool", "mcp", "agent"),
                anchor=r"\b(fetch|axios(\.get|\.post)?|got|request)\s*\(\s*(?!['\"])",
            ),
        ),
        tags=("sink:http", "ssrf"),
        engines=("rules", "semgrep"),
    ),
    rule(
        "AISRF-AT-005",
        PACK,
        "SQL statement built from tool or model data",
        severity="CRITICAL",
        confidence=0.65,
        category="tool_abuse",
        cwe="CWE-89",
        description="A database call receives a query string assembled with f-strings, format() or concatenation inside an AI component. Tool arguments are written by the model from natural language and can contain SQL.",
        why="Second-order SQL injection through the model needs no special encoding: the attacker simply asks for the payload in plain language.",
        remediation=(
            "Use parameterised queries or an ORM with bound parameters for every value.",
            "Give the tool a narrow, typed interface (enumerations, ids) instead of free text.",
            "Run tools with a database role limited to the tables and operations they need.",
        ),
        languages=CODE,
        matcher=any_of(
            py(_sql_from_runtime),
            lines(
                r"\.(query|execute|raw|run|all|get|exec)\s*\(\s*(`[^`]*(?i:select|insert|update|delete|where)[^`]*\$\{|['\"][^'\"]*(?i:select|insert|update|delete|where)[^'\"]*['\"]\s*\+)",
                flag=("ai", "tool", "agent", "rag", "mcp"),
            ),
        ),
        tags=("sink:sql",),
        engines=("rules", "semgrep", "bandit"),
    ),
    rule(
        "AISRF-AT-006",
        PACK,
        "Over-broad tool description or capability",
        severity="MEDIUM",
        confidence=0.5,
        category="excessive_agency",
        cwe="CWE-250",
        description="A tool advertises itself to the model as able to run any query, command, code or reach any address. The description is the model's contract: the broader it is, the more an injection can request.",
        why="Excessive agency starts with the tool schema. A search tool that can execute arbitrary SQL is a database admin console for whoever controls the prompt.",
        remediation=(
            "Split broad tools into narrow, purpose-specific ones with typed parameters.",
            "Describe exactly what the tool does and refuses to do.",
            "Enforce the same limits in code; the description is not a control.",
        ),
        languages=CODE,
        matcher=lines(
            r"(?i)[\"'`][^\"'`]*\b(any (sql|query|command|url|file|path|address|email|action|shell|code|api)|arbitrary (sql|command|code|url|file|path|python|shell|request)|execute (arbitrary|any)|run (any|arbitrary)|unrestricted|full (access|control)|admin(istrator)? (privileges|access)|without (restriction|limit)s?)\b",
            flag=("tool", "mcp", "agent", "ai"),
            skip_comments=False,
        ),
        tags=("schema",),
    ),
    rule(
        "AISRF-AT-007",
        PACK,
        "Destructive or financial tool without a confirmation gate",
        severity="HIGH",
        confidence=0.5,
        category="excessive_agency",
        cwe="CWE-862",
        description="A tool that refunds, deletes, pays, sends messages, deploys or otherwise changes the world is exposed to the model with no visible human approval, confirmation or ownership check.",
        why="Irreversible actions triggered by natural language are the highest-impact outcome of a compromised agent. Approval is the control that survives injection.",
        remediation=(
            "Classify tools by risk and require explicit human approval for high and critical ones.",
            "Verify that the acting user owns the target resource and is allowed to perform the action.",
            "Prefer reversible designs (soft delete, holds, drafts) and keep an audit trail.",
        ),
        languages=CODE,
        matcher=any_of(
            py(_destructive_without_confirmation),
            absence(
                [
                    r"name\s*:\s*['\"](refund|delete|remove|transfer|pay|payment|charge|send_?(email|mail|sms|message)|deploy|terminate|revoke|purchase)\w*['\"]"
                ],
                [CONFIRMATION.pattern],
                flag=("tool", "agent", "ai"),
                anchor=r"name\s*:\s*['\"](refund|delete|remove|transfer|pay|payment|charge|send_?(email|mail|sms|message)|deploy|terminate|revoke|purchase)\w*['\"]",
            ),
        ),
        tags=("agency", "hitl"),
    ),
    rule(
        "AISRF-AT-008",
        PACK,
        "Agent loop without an iteration or cost limit",
        severity="HIGH",
        confidence=0.5,
        category="denial_of_wallet",
        cwe="CWE-835",
        description="The model is called repeatedly (while True, or a framework agent without max_iterations, recursion_limit or maxSteps) with no bound on steps, time or spend.",
        why="A confused or adversarial agent that never stops burns budget, hammers tools and can be used as a denial of service or denial of wallet primitive.",
        remediation=(
            "Cap iterations, wall-clock time and token spend per run; stop with a clear error when reached.",
            "Set max_iterations / recursion_limit / maxSteps on framework agents.",
            "Alert on runs that hit the caps; they often indicate an injection loop.",
        ),
        languages=CODE,
        matcher=any_of(
            py(_unbounded_loop),
            near(
                r"(initialize_agent\(|AgentExecutor\(|create_react_agent\(|\.compile\(|generateText\(\{|streamText\(\{|Agent\(\s*$|Crew\()",
                r"(tools|agent|llm|model)",
                window=8,
                unless=r"(max_iterations|max_execution_time|recursion_limit|max_steps|maxSteps|max_turns|max_rpm|max_iter|stopWhen|step_limit)",
                flag=("agent", "ai"),
            ),
            absence(
                [r"while\s*\(\s*true\s*\)", r"(tool_?calls|toolCalls|functionCall|\.tools\b)"],
                [
                    r"(maxSteps|maxIterations|max_steps|budget|MAX_[A-Z_]*(STEP|ITER|TURN|CALL)|deadline|Date\.now\(\)\s*-)"
                ],
                flag=("ai", "agent"),
                anchor=r"while\s*\(\s*true\s*\)",
            ),
        ),
        tags=("limits",),
    ),
    rule(
        "AISRF-AT-009",
        PACK,
        "Tool output returned to the model unsanitised",
        severity="MEDIUM",
        confidence=0.45,
        category="indirect_prompt_injection",
        cwe="CWE-74",
        description="Results of a tool call are appended to the conversation as-is. Tool results often contain third-party content (web pages, tickets, database rows) that can carry injected instructions.",
        why="Tool output is the classic indirect injection channel inside agent loops: the model asked for data and receives commands.",
        remediation=(
            "Screen tool output for instruction-like patterns and control tokens, and truncate it.",
            "Wrap results in explicit delimiters and remind the model that the block is data.",
            "Return structured objects from tools instead of free text where possible.",
        ),
        languages=CODE,
        matcher=absence(
            [
                r"[\"']role[\"']\s*:\s*[\"'](tool|function)[\"'][^\n]*content[\"']?\s*:\s*(?![\"'])|role\s*:\s*[\"'](tool|function)[\"'][^\n]*content\s*:\s*(?![\"'])"
            ],
            [
                r"(?i)(sanitiz|scan_|truncat|clean_|filter_|<tool_result|tool_output_guard|output_scanner|escape_|redact)"
            ],
            anchor=r"role[\"']?\s*:\s*[\"'](tool|function)[\"']",
        ),
        tags=("indirect", "loop"),
    ),
    rule(
        "AISRF-AT-010",
        PACK,
        "Model tool calls dispatched by name without an allowlist",
        severity="HIGH",
        confidence=0.6,
        category="excessive_agency",
        cwe="CWE-470",
        description="The function to run is looked up dynamically (globals(), locals(), getattr, a module table) using the name the model returned. Any importable function becomes callable.",
        why="Dynamic dispatch removes the boundary between the tools you intended to expose and everything else in the process.",
        remediation=(
            "Dispatch through an explicit registry dict of allowed tools; reject unknown names.",
            "Validate arguments against the tool's schema before invoking it.",
            "Scope the registry per user role and per session.",
        ),
        languages=CODE,
        matcher=any_of(
            py(_dispatch_by_name),
            lines(
                r"(\b(global|window|globalThis)\s*\[[^\]]*(name|fn|tool)|\[\s*(call|toolCall|tc|fc)\.(function\.)?name\s*\]\s*\(|require\(\s*(call|toolCall|tc)\.)",
                flag=("ai", "tool", "agent"),
            ),
        ),
        tags=("dispatch",),
        engines=("rules", "semgrep"),
    ),
    rule(
        "AISRF-AT-011",
        PACK,
        "MCP server exposes a dangerous capability",
        severity="CRITICAL",
        confidence=0.6,
        category="excessive_agency",
        cwe="CWE-749",
        description="A Model Context Protocol tool executes commands, evaluates code, writes or deletes files, sends mail or talks to infrastructure APIs. Any client model connected to the server, and any injection reaching that model, inherits the capability.",
        why="MCP servers are reused across assistants and sessions; a dangerous tool in one server is a foothold for every agent that connects.",
        remediation=(
            "Keep MCP tools narrow and read-mostly; move destructive operations behind explicit confirmation.",
            "Constrain paths, hosts and commands with allowlists inside the tool implementation.",
            "Run the server with minimal OS privileges and no long-lived credentials.",
        ),
        languages=CODE,
        matcher=any_of(
            py(_mcp_dangerous_tools),
            near(
                r"(server|mcp)\.(tool|registerTool)\s*\(",
                r"(child_process|execSync|spawn|\beval\(|new Function|fs\.(write|rm|unlink|appendFile)|rimraf|nodemailer|sgMail|\.send\(|kubectl|docker)",
                window=25,
                flag="mcp",
            ),
        ),
        tags=("mcp",),
    ),
    rule(
        "AISRF-AT-012",
        PACK,
        "Messaging or payment tool without a destination allowlist",
        severity="HIGH",
        confidence=0.5,
        category="data_exfiltration",
        cwe="CWE-284",
        description="A tool sends email, chat messages, SMS or payments to a recipient taken from its arguments, with no check that the destination is verified or belongs to the current user.",
        why="Outbound messaging tools are the easiest exfiltration channel: a poisoned document only has to ask the assistant to forward the conversation somewhere.",
        remediation=(
            "Only allow recipients that belong to the authenticated user or an approved list.",
            "Screen message bodies for sensitive data before sending.",
            "Require confirmation for every send that leaves the organisation.",
        ),
        languages=CODE,
        matcher=any_of(
            py(
                lambda ctx, tree: _tool_sink(
                    ctx,
                    tree,
                    re.compile(
                        r"(^|\.)(smtplib\.SMTP|SMTP|sendmail|send_message|send_mail|send_email|SendGridAPIClient|sg\.send|messages\.create|chat_postMessage|WebhookClient|stripe\.(Charge|PaymentIntent|Transfer|Refund)\.create|refund|transfer|payout|send)$"
                    ),
                    RECIPIENT_GUARD,
                    "recipient or amount comes from tool arguments",
                )
            ),
            absence(
                [
                    r"\b(sendMail|sgMail\.send|transporter\.send|twilio|messages\.create|chat\.postMessage|stripe\.(charges|refunds|transfers|paymentIntents)\.create)\s*\("
                ],
                [RECIPIENT_GUARD.pattern],
                flag=("tool", "agent", "mcp"),
                anchor=r"\b(sendMail|sgMail\.send|transporter\.send|twilio|messages\.create|chat\.postMessage|stripe\.(charges|refunds|transfers|paymentIntents)\.create)\s*\(",
            ),
        ),
        tags=("exfil", "agency"),
    ),
    rule(
        "AISRF-AT-013",
        PACK,
        "Tool reads data without a user or tenant scope",
        severity="MEDIUM",
        confidence=0.35,
        category="excessive_agency",
        cwe="CWE-639",
        description="A tool queries records by identifier with no reference to the requesting user, tenant or owner. The agent runs with a service account, so the model can be talked into fetching anyone's data.",
        why="Agents are confused deputies: they hold more authority than the user and take ownership claims at face value unless code enforces them.",
        remediation=(
            "Inject the authenticated user's identity into every tool call and filter queries by it.",
            "Never accept the user id as a model-supplied argument.",
            "Use per-user database roles or row-level security where available.",
        ),
        languages=PY,
        matcher=py(_unscoped_data_access),
        tags=("authorization",),
    ),
    rule(
        "AISRF-AT-014",
        PACK,
        "Framework tool with code or shell execution enabled",
        severity="CRITICAL",
        confidence=0.8,
        category="tool_abuse",
        cwe="CWE-94",
        description="A known dangerous framework component is in use: Python REPL or shell tools, agents that evaluate generated code, or flags that opt into unsafe behaviour (allow_dangerous_code, unsandboxed executors).",
        why="These components have a history of remote code execution advisories; they hand the model an interpreter.",
        remediation=(
            "Remove the component or replace it with a sandboxed executor (container, microVM) that has no credentials.",
            "If it must stay, gate it behind human approval and restrict which users can trigger it.",
            "Pin the framework version and track its security advisories.",
        ),
        languages=CODE,
        matcher=lines(FRAMEWORK_DANGEROUS.pattern),
        tags=("framework",),
        engines=("rules", "semgrep"),
    ),
    rule(
        "AISRF-AT-015",
        PACK,
        "Tools attached without per-user permission scoping",
        severity="MEDIUM",
        confidence=0.35,
        category="excessive_agency",
        cwe="CWE-285",
        description="A fixed tool list is given to the agent and the file shows no sign of roles, permissions or an allowlist that varies by user. Every caller gets every tool.",
        why="Least privilege applies to tools: a support chatbot for anonymous users should not carry the same tools as an admin console.",
        remediation=(
            "Build the tool list per request from the caller's role and the task at hand.",
            "Record which tools each session was granted for audit purposes.",
        ),
        languages=CODE,
        matcher=absence(
            [r"\btools\s*[=:]\s*[\[\w]"],
            [
                r"(?i)(permission|role|allowed_tools|allowedTools|scope|authoriz|rbac|can_use|policy|acl|tools_for|get_tools\(|filter_tools)"
            ],
            flag=("agent", "ai"),
            anchor=r"\btools\s*[=:]\s*[\[\w]",
        ),
        tags=("authorization", "hardening"),
    ),
]
_ = (JS, PY, near)

TOOL_DISPATCH = r"(tool_calls|toolCalls|execute_tool|call_tool|run_tool|dispatch_tool|invoke_tool|tool\.invoke\(|tool\.run\(|tools\[[^\]]+\]\s*\(|handle_tool_call|process_tool_calls)"
CALL_BUDGET = r"(?i)(max_calls|call_count|calls_per|budget|rate_limit|ratelimit|limiter|quota|Semaphore|max_tool|tool_limit|max_iterations|max_steps|maxSteps|recursion_limit|max_turns|usage_limit)"
AUDIT_TRAIL = r"(?i)(audit|\blog\.|logger\.|logging\.|console\.(log|info|warn)|structlog|langfuse|phoenix|opentelemetry|tracer|span\(|record_tool|telemetry|trace\()"
DELEGATION = r"(allow_delegation\s*=\s*True|GroupChat\s*\(|create_supervisor\s*\(|createSupervisor\s*\(|handoffs?\s*[=:]\s*\[|Handoff\s*\(|create_handoff_tool\s*\(|\bSwarm\s*\(|transfer_to_\w+|delegate_to\w*\s*\(|sub_?agents?\s*[=:]\s*\[|AgentTool\s*\(|\.as_tool\s*\(|hierarchical|manager_agent|manager_llm)"
DELEGATION_GUARD = r"(?i)(max_delegation|delegation_depth|MAX_DEPTH|depth\s*[<>]=?|can_delegate|allowed_agents|allowedAgents|recursion_limit|max_handoffs|max_round|max_rounds|max_iter|sanitiz|scan_|screen_|inter_agent|validate_message)"
WRITE_CAPABILITY = re.compile(
    r"(write_text\(|write_bytes\(|open\([^)]*['\"][wa]b?['\"]|\.write\(|shutil\.(copy|move|copyfile)|os\.rename|fs\.(writeFile|appendFile|writeFileSync|appendFileSync)|createWriteStream)"
)
EXEC_CAPABILITY = re.compile(
    r"(subprocess\.|os\.system|os\.popen|\beval\(|\bexec\(|run_tests|pytest\.main|execSync|spawnSync|child_process|importlib\.import_module|runpy)"
)
VALIDATION = re.compile(
    r"(re\.(match|fullmatch|search)|pydantic|BaseModel|Field\(|validator|model_validate|parse_obj|parse_raw|isinstance\(|in ALLOWED|allowlist|ALLOWED_|Enum\b|Literal\[|\.validate\(|raise ValueError|assert |max_length|len\(|args_schema|jsonschema|Draft\d+Validator|schema=|strict=True|zod|z\.)"
)


def _tool_without_validation(ctx: FileContext, tree: ast.Module) -> Iterator[Match]:
    for name, (func, strength) in _tool_functions(ctx, tree).items():
        if strength != "strong":
            continue
        params = pyast.arg_names(func)
        if not params:
            continue
        text = (
            pyast.func_text(func, ctx.lines)
            + " "
            + " ".join(pyast.ast_dump_short(d) for d in func.decorator_list)
        )
        if VALIDATION.search(text):
            continue
        used = any(
            pyast.depends_on(a, params)
            for call in pyast.iter_calls(func)
            for a in [*call.args, *[k.value for k in call.keywords]]
        )
        if not used:
            continue
        yield Match(
            func.lineno,
            func.lineno,
            snippet=ctx.snippet(func.lineno, func.lineno + 2),
            note=f"tool {name} passes its arguments on without validating them ({', '.join(sorted(params)[:4])})",
        )


def _write_plus_exec(ctx: FileContext, tree: ast.Module) -> Iterator[Match]:
    tools = _tool_functions(ctx, tree)
    if len(tools) < 2 or ctx.search(
        r"(?i)(sandbox|docker|firejail|gvisor|nsjail|read_only|readonly|isolated|microvm|e2b)"
    ):
        return
    writers = [n for n, (f, _) in tools.items() if WRITE_CAPABILITY.search(pyast.func_text(f, ctx.lines))]
    runners = [n for n, (f, _) in tools.items() if EXEC_CAPABILITY.search(pyast.func_text(f, ctx.lines))]
    if not writers or not runners:
        return
    func = tools[runners[0]][0]
    yield Match(
        func.lineno,
        func.lineno,
        snippet=ctx.snippet(func.lineno, func.lineno + 2),
        note=f"tools {', '.join(writers[:2])} write files and {', '.join(runners[:2])} execute code or commands",
    )


RULES += [
    rule(
        "AISRF-AT-016",
        PACK,
        "Tool arguments used without schema or value validation",
        severity="MEDIUM",
        confidence=0.4,
        category="tool_abuse",
        cwe="CWE-20",
        description="A function exposed to the model takes free-form arguments and passes them straight into calls without any type, format, range or allowlist check. The model writes these values from natural language, so an attacker who controls the conversation controls them too.",
        why="Argument validation is the tool equivalent of parameterised queries: it turns arbitrary attacker text into a small set of accepted values before it reaches a backend.",
        remediation=(
            "Describe tool parameters with a strict schema (typed models, enumerations, length limits, patterns) and validate before executing.",
            "Prefer identifiers and enumerations over free text; resolve them server side.",
            "Reject invalid arguments with an error the model can recover from instead of coercing them.",
        ),
        languages=PY,
        matcher=py(_tool_without_validation),
        tags=("schema", "validation"),
    ),
    rule(
        "AISRF-AT-017",
        PACK,
        "Tool execution without a per-session call budget",
        severity="LOW",
        confidence=0.35,
        category="denial_of_wallet",
        cwe="CWE-770",
        description="Tool calls returned by the model are executed and the module shows no cap on how many times a tool may run per session or per time window.",
        why="Unlimited tool calls let a confused or hijacked agent hammer downstream APIs, run up provider bills and stage data exfiltration one request at a time.",
        remediation=(
            "Count tool calls per session and per tool; stop with an explicit error when the budget is spent.",
            "Rate limit expensive or external tools separately and alert when limits are hit.",
        ),
        languages=CODE,
        matcher=absence([TOOL_DISPATCH], [CALL_BUDGET], anchor=TOOL_DISPATCH, flag=("ai", "agent", "tool")),
        tags=("limits",),
    ),
    rule(
        "AISRF-AT-018",
        PACK,
        "Agent-to-agent delegation without an allowlist, depth limit or message screening",
        severity="MEDIUM",
        confidence=0.45,
        category="excessive_agency",
        cwe="CWE-284",
        description="Agents hand tasks to other agents (supervisors, crews, group chats, handoffs) and the module shows no allowlist of who may delegate to whom, no maximum delegation depth and no screening of the messages passed between agents.",
        why="Delegation makes trust transitive: an injection that lands in the least privileged agent travels through every hop until it reaches one that can act on it.",
        remediation=(
            "Declare which agents may delegate to which, and cap the delegation depth and round count.",
            "Give each agent its own tool subset; never share one registry across agents with different privileges.",
            "Screen inter-agent messages for instruction-like content the same way as tool output.",
        ),
        languages=CODE,
        matcher=absence([DELEGATION], [DELEGATION_GUARD], anchor=DELEGATION, flag=("agent", "ai")),
        tags=("multi-agent",),
        engines=("rules", "semgrep"),
    ),
    rule(
        "AISRF-AT-019",
        PACK,
        "Tool calls executed without an audit trail",
        severity="LOW",
        confidence=0.3,
        category="excessive_agency",
        cwe="CWE-778",
        description="Model-chosen tool calls are executed and nothing in the module records which tool ran, with which arguments, for which user.",
        why="Without a per-call record you cannot detect an ongoing injection, reconstruct what an agent did or prove what it did not do.",
        remediation=(
            "Log every tool invocation with user, session, tool name, argument digest, result size and outcome.",
            "Send the records to a tamper-evident store and alert on unusual tool sequences.",
        ),
        languages=CODE,
        matcher=absence([TOOL_DISPATCH], [AUDIT_TRAIL], anchor=TOOL_DISPATCH, flag=("ai", "agent", "tool")),
        tags=("monitoring",),
    ),
    rule(
        "AISRF-AT-020",
        PACK,
        "Tool set combines file writes with command or code execution",
        severity="HIGH",
        confidence=0.45,
        category="tool_abuse",
        cwe="CWE-94",
        description="The same agent exposes a tool that writes files and a tool that runs code or commands, with no sign of sandboxing. Individually each tool looks limited; together they let the model write a script and then run it.",
        why="Capability chaining is how agents get compromised in practice: read a secret, write it into a test file, run the tests.",
        remediation=(
            "Keep write targets away from anything the execution tool can run, or execute only in a fresh sandbox with no access to written files.",
            "Require confirmation for the execution step and log the chain of calls.",
        ),
        languages=CODE,
        matcher=any_of(
            py(_write_plus_exec),
            absence(
                [
                    r"fs\.(writeFile|appendFile|writeFileSync|appendFileSync)\s*\(",
                    r"(execSync|spawnSync|spawn|exec)\s*\(",
                ],
                [r"(?i)(sandbox|docker|isolated-vm|vm2|worker_threads|gvisor|firecracker|deno|readonly)"],
                flag=("tool", "mcp", "agent"),
                anchor=r"(execSync|spawnSync|spawn|exec)\s*\(",
            ),
        ),
        tags=("chaining",),
    ),
]

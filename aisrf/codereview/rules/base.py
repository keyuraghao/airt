"""Rule model, file context and matcher factories shared by every rule pack.

A rule is a static description (id, pack, severity, taxonomy, remediation) plus a matcher: a
callable taking a FileContext and yielding Match objects. Matchers are built from small
factories (line regexes, file-level presence/absence checks, Python AST visitors) so packs stay
declarative and easy to review.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from functools import cached_property
from typing import Any

from ...taxonomy import owasp_ids
from ..inventory import CODE_LANGUAGES, FRAMEWORKS, MCP_MARKERS, TOOL_CALLING_MARKERS, _framework_hits
from . import pyast

OWASP_URLS = "https://genai.owasp.org/llm-top-10/"
CWE_URL = "https://cwe.mitre.org/data/definitions/{n}.html"
ALL = ("*",)
PY = ("python", "notebook")
JS = ("javascript", "typescript", "vue", "svelte")
WEB = ("javascript", "typescript", "vue", "svelte", "html")
CODE = (*tuple(sorted(CODE_LANGUAGES)), "notebook")
COMMENT_PREFIXES = ("#", "//", "/*", "*", "<!--", "--")

# Identifier heuristics. Broad on purpose: a prompt built from *any* runtime value deserves a look;
# confidence is raised when the name is clearly request-, user- or model-derived.
UNTRUSTED_STRONG = re.compile(r"(?i)(^|[._])(request|req|user_?input|user_?message|user_?msg|user_?query|user_?text|query|question|params?|args|form|body|payload|upload|uploaded|untrusted|external)($|[._\[])")
UNTRUSTED = re.compile(r"(?i)(user|input|query|question|message|msg|text|content|body|request|req|param|arg|payload|form|data|email|mail|doc|page|html|chunk|context|history|prompt|upload|file|url|search|comment|review|note|transcript|conversation|ticket|issue|record|row|field|value|item|result)")
MODEL_OUTPUT = re.compile(r"(?i)(response|completion|answer|output|reply|generated|generation|llm|model|assistant|choices|choice|message\.content|content\[0\]|\.text$|result|summary|suggestion|plan|code|command|cmd|sql|query)")
TOOL_ARG = re.compile(r"(?i)(arg|argument|param|input|query|command|cmd|expression|expr|code|path|filename|file|url|address|recipient|to|sql|hostname|host|target|name|amount|id)")
PROMPT_WORDS = re.compile(r"(?i)\b(you are|assistant|system|prompt|instruction|instructions|answer|summari[sz]e|translate|respond|context:|question:|user:|the user|following (text|document|email|message|content|code)|rewrite|classify|extract|generate|write a|task:|role)\b")
LLM_CALL = re.compile(r"(chat\.completions\.create|\.messages\.create|responses\.create|\.generate_content\(|generate_content_async\(|\bgenerateText\(|\bstreamText\(|\bgenerateObject\(|ChatCompletion\.create|litellm\.completion|ollama\.(chat|generate)|\.beta\.threads|\.chat\.send_message|llm\.(invoke|ainvoke|predict|generate|call|complete|stream)\(|chain\.(invoke|ainvoke|run|arun)\(|agent(_executor)?\.(invoke|ainvoke|run|arun)\(|\bmodel\.(invoke|ainvoke|generate|predict|stream)\(|\.complete\(|client\.chat\(|\bcompletion\(|\bgenerate\(|\.run_sync\(|\bcrew\.kickoff\()")
ROUTE = re.compile(r"(@app\.(route|get|post|put|patch|delete|api_route)|@router\.(get|post|put|patch|delete|api_route)|@(bp|blueprint)\.(route|get|post)|@api_view|@csrf_exempt|\b(app|router)\.(get|post|put|patch|delete|use)\(\s*['\"/]|\bexpress\(\)|@(Get|Post|Put|Patch|Delete)\(|export (async )?function (GET|POST|PUT|DELETE)\b|request\.(json|args|form|GET|POST|body|data|values)|req\.(body|query|params)|await request\.|Request\b.*\)\s*(->|:)|HttpRequest)")
RAG = re.compile(r"(similarity_search|as_retriever|add_texts|add_documents|\.upsert\(|embed(_query|_documents)?\(|VectorStore|retriever|Retriever|\.query\(.*vector|query_vector|\.search\(.*(vector|embedding)|from_documents\(|index\.query\(|collection\.(add|query)\(|knn|Embeddings?\()")
AGENT = re.compile(r"(initialize_agent|AgentExecutor|create_(react|openai_tools|tool_calling|openai_functions|structured_chat)_agent|\bCrew\(|AssistantAgent|StateGraph|tool_calls|function_call|\bAgent\(|Runner\.run|\.run_agent\(|autogen|smolagents|CodeAgent|ToolCallingAgent)")
FRONTEND = re.compile(r"(\bReact\b|from ['\"]react['\"]|\bVue\b|document\.(getElementById|querySelector|body)|window\.|useState\(|<template>|dangerouslySetInnerHTML|innerHTML)")


@dataclass
class Match:
    line_start: int
    line_end: int = 0
    snippet: str = ""
    confidence: float | None = None
    severity: str | None = None
    note: str = ""
    boost: float = 0.0  # added to the rule confidence (context made the hit more credible)
    file: str = ""  # inventory-scoped rules point at a file explicitly


class FileContext:
    """Everything a matcher may want to know about one file, computed lazily and cached."""

    def __init__(self, path: str, language: str, text: str) -> None:
        self.path = path
        self.language = language
        self.text = text
        self.lines = text.splitlines()
        self._search_cache: dict[str, bool] = {}

    def search(self, pattern: str | re.Pattern[str]) -> bool:
        key = pattern if isinstance(pattern, str) else pattern.pattern
        if key not in self._search_cache:
            rx = re.compile(pattern) if isinstance(pattern, str) else pattern
            self._search_cache[key] = bool(rx.search(self.text))
        return self._search_cache[key]

    @cached_property
    def tree(self) -> ast.Module | None:
        if self.language not in ("python",):
            return None
        tree = pyast.parse(self.text)
        if tree is not None:
            pyast.attach_parents(tree)
        return tree

    @cached_property
    def flags(self) -> set[str]:
        flags: set[str] = set()
        hits = _framework_hits(self.text, self.language) if self.language in CODE else set()
        kinds = {FRAMEWORKS[h]["kind"] for h in hits}
        if kinds & {"llm_sdk", "framework", "agent_framework", "ml", "serving"} or LLM_CALL.search(self.text):
            flags.add("ai")
        if kinds & {"vector_store"} or RAG.search(self.text):
            flags.add("rag")
        if "mcp" in kinds or any(p.search(self.text) for p in MCP_MARKERS):
            flags.add("mcp")
        if any(p.search(self.text) for p in TOOL_CALLING_MARKERS):
            flags.add("tool")
        if ROUTE.search(self.text):
            flags.add("route")
        if AGENT.search(self.text):
            flags.add("agent")
        if self.language in ("vue", "svelte", "html") or (self.language in JS and FRONTEND.search(self.text)):
            flags.add("frontend")
        if self.language in ("python", "javascript", "typescript") and re.search(r"(?m)^\s*(class|def|function)\s|=>", self.text):
            flags.add("code")
        return flags

    def has_flag(self, *names: str) -> bool:
        return any(n in self.flags for n in names)

    def snippet(self, start: int, end: int | None = None, max_lines: int = 8) -> str:
        end = end or start
        start = max(1, start)
        end = min(len(self.lines), max(end, start))
        end = min(end, start + max_lines - 1)
        return "\n".join(self.lines[start - 1 : end])

    def is_comment(self, line: str) -> bool:
        stripped = line.strip()
        return bool(stripped) and stripped.startswith(COMMENT_PREFIXES) and self.language in CODE


Matcher = Callable[[FileContext], Iterable[Match]]


@dataclass(frozen=True)
class Rule:
    id: str
    pack: str
    title: str
    severity: str
    confidence: float
    category: str  # taxonomy category (aisrf.taxonomy.CATEGORY_MAP) used for OWASP mapping
    description: str
    why: str
    remediation: tuple[str, ...]
    cwe: str
    languages: tuple[str, ...]
    matcher: Matcher
    references: tuple[str, ...] = ()
    scope: str = "file"  # file | inventory
    tags: tuple[str, ...] = ()
    engines: tuple[str, ...] = ("rules",)

    @property
    def owasp(self) -> list[str]:
        return owasp_ids(self.category)

    def applies_to(self, language: str) -> bool:
        return "*" in self.languages or language in self.languages

    def to_dict(self) -> dict[str, Any]:
        from ...taxonomy import owasp_label

        refs = list(self.references)
        if self.cwe:
            refs.append(CWE_URL.format(n=self.cwe.split("-")[-1]))
        refs.append(OWASP_URLS)
        return {
            "id": self.id,
            "pack": self.pack,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "category": self.category,
            "owasp": self.owasp,
            "owasp_labels": [owasp_label(o) for o in self.owasp],
            "cwe": self.cwe,
            "description": self.description,
            "why": self.why,
            "remediation": list(self.remediation),
            "references": refs,
            "languages": list(self.languages),
            "scope": self.scope,
            "tags": list(self.tags),
            "engines": list(self.engines),
        }


# --- matcher factories --------------------------------------------------------------------
def _rx(pattern: str | re.Pattern[str], flags: int = 0) -> re.Pattern[str]:
    return pattern if isinstance(pattern, re.Pattern) else re.compile(pattern, flags)


def lines(
    pattern: str | re.Pattern[str],
    *,
    unless: str | None = None,
    requires: str | None = None,
    flag: str | tuple[str, ...] | None = None,
    boost_flag: str | tuple[str, ...] | None = None,
    boost: float = 0.2,
    skip_comments: bool = True,
    window: int = 1,
    ignore_case: bool = False,
) -> Matcher:
    """Match single lines. ``requires`` must match somewhere in the file, ``unless`` must not match the line
    (or the following ``window`` lines), ``flag`` restricts to files with that context flag and
    ``boost_flag`` raises confidence when the file has it."""
    rx = _rx(pattern, re.I if ignore_case else 0)
    unless_rx = _rx(unless) if unless else None
    flags_needed = (flag,) if isinstance(flag, str) else flag
    boost_flags = (boost_flag,) if isinstance(boost_flag, str) else boost_flag

    def match(ctx: FileContext) -> Iterator[Match]:
        if flags_needed and not ctx.has_flag(*flags_needed):
            return
        if requires and not ctx.search(requires):
            return
        boosted = bool(boost_flags and ctx.has_flag(*boost_flags))
        for i, line in enumerate(ctx.lines, start=1):
            if skip_comments and ctx.is_comment(line):
                continue
            if not rx.search(line):
                continue
            if unless_rx and unless_rx.search("\n".join(ctx.lines[i - 1 : i - 1 + max(1, window)])):
                continue
            yield Match(i, i, boost=boost if boosted else 0.0)

    return match


def near(
    first: str | re.Pattern[str],
    then: str | re.Pattern[str] | None = None,
    *,
    window: int = 4,
    unless: str | None = None,
    flag: str | tuple[str, ...] | None = None,
    requires: str | None = None,
    boost_flag: str | tuple[str, ...] | None = None,
    boost: float = 0.2,
) -> Matcher:
    """Match a line that fits ``first`` when the following ``window`` lines (joined) also fit ``then`` and do not
    fit ``unless``. Useful for multi-line call sites in JavaScript and YAML."""
    first_rx = _rx(first)
    then_rx = _rx(then) if then else None
    unless_rx = _rx(unless) if unless else None
    flags_needed = (flag,) if isinstance(flag, str) else flag
    boost_flags = (boost_flag,) if isinstance(boost_flag, str) else boost_flag

    def match(ctx: FileContext) -> Iterator[Match]:
        if flags_needed and not ctx.has_flag(*flags_needed):
            return
        if requires and not ctx.search(requires):
            return
        boosted = bool(boost_flags and ctx.has_flag(*boost_flags))
        for i, line in enumerate(ctx.lines, start=1):
            if ctx.is_comment(line) or not first_rx.search(line):
                continue
            block = "\n".join(ctx.lines[i - 1 : i - 1 + max(1, window)])
            if then_rx and not then_rx.search(block):
                continue
            if unless_rx and unless_rx.search(block):
                continue
            yield Match(i, i, boost=boost if boosted else 0.0)

    return match


def absence(
    requires: Iterable[str],
    absent: Iterable[str],
    *,
    flag: str | tuple[str, ...] | None = None,
    anchor: str | None = None,
) -> Matcher:
    """File-level rule: fires once when every ``requires`` regex matches and none of ``absent`` does."""
    req = [_rx(r) for r in requires]
    abs_ = [_rx(a) for a in absent]
    anchor_rx = _rx(anchor) if anchor else req[0]
    flags_needed = (flag,) if isinstance(flag, str) else flag

    def match(ctx: FileContext) -> Iterator[Match]:
        if flags_needed and not ctx.has_flag(*flags_needed):
            return
        if not all(ctx.search(r) for r in req) or any(ctx.search(a) for a in abs_):
            return
        for i, line in enumerate(ctx.lines, start=1):
            if anchor_rx.search(line) and not ctx.is_comment(line):
                yield Match(i, i)
                return

    return match


def py(fn: Callable[[FileContext, ast.Module], Iterable[Match]]) -> Matcher:
    """Python AST rule; silently skipped for other languages or unparsable files."""

    def match(ctx: FileContext) -> Iterator[Match]:
        tree = ctx.tree
        if tree is None:
            return
        yield from fn(ctx, tree)

    return match


def any_of(*matchers: Matcher) -> Matcher:
    def match(ctx: FileContext) -> Iterator[Match]:
        seen: set[int] = set()
        for m in matchers:
            for hit in m(ctx):
                if hit.line_start in seen:
                    continue
                seen.add(hit.line_start)
                yield hit

    return match


def node_match(ctx: FileContext, node: ast.AST, **kw: Any) -> Match:
    start, end = pyast.span(node)
    return Match(start, end, snippet=ctx.snippet(start, end), **kw)


def rule(
    id: str,
    pack: str,
    title: str,
    *,
    severity: str,
    confidence: float,
    category: str,
    cwe: str,
    description: str,
    why: str,
    remediation: Iterable[str],
    languages: Iterable[str],
    matcher: Matcher,
    references: Iterable[str] = (),
    scope: str = "file",
    tags: Iterable[str] = (),
    engines: Iterable[str] = ("rules",),
) -> Rule:
    return Rule(
        id=id,
        pack=pack,
        title=title,
        severity=severity,
        confidence=confidence,
        category=category,
        description=description,
        why=why,
        remediation=tuple(remediation),
        cwe=cwe,
        languages=tuple(languages),
        matcher=matcher,
        references=tuple(references),
        scope=scope,
        tags=tuple(tags),
        engines=tuple(engines),
    )


@dataclass
class PackInfo:
    name: str
    title: str
    description: str
    rules: list[Rule] = field(default_factory=list)

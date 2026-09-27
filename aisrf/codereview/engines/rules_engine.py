"""Built-in rules engine: regex, file-level and Python AST matchers from the rule packs."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from ...logging import get_logger
from ..findings import Finding
from ..inventory import SourceFile
from ..rules import INVENTORY_MATCHERS, rules_for
from ..rules.base import FileContext, Match, Rule

log = get_logger("aisrf.codereview.rules")
IGNORE_MARK = re.compile(r"(#|//|/\*|<!--)\s*(aisrf|aisrf|nosec)[-:]?\s*(ignore|skip)?", re.I)
MAX_HITS_PER_RULE_FILE = 25
ProgressFn = Callable[[int, int], None]
StopFn = Callable[[], bool]


def _finding(rule: Rule, ctx: FileContext | None, m: Match, path: str, language: str) -> Finding:
    start = max(1, int(m.line_start or 1))
    end = max(start, int(m.line_end or start))
    snippet = m.snippet or (ctx.snippet(start, end) if ctx is not None else "")
    confidence = m.confidence if m.confidence is not None else rule.confidence + m.boost
    meta: dict[str, Any] = {"why": rule.why, "tags": list(rule.tags)}
    if m.note:
        meta["note"] = m.note
    return Finding(
        rule_id=rule.id,
        pack=rule.pack,
        engine="rules",
        severity=m.severity or rule.severity,
        confidence=confidence,
        title=rule.title,
        description=rule.description,
        remediation="\n".join(f"- {step}" for step in rule.remediation),
        file=path,
        line_start=start,
        line_end=end,
        snippet=snippet,
        language=language,
        owasp=rule.owasp,
        cwe=rule.cwe,
        category=rule.category,
        metadata=meta,
    )


def scan_file(ctx: FileContext, rules: list[Rule]) -> list[Finding]:
    out: list[Finding] = []
    for rule in rules:
        if rule.scope != "file" or not rule.applies_to(ctx.language):
            continue
        try:
            hits = 0
            for m in rule.matcher(ctx):
                line = ctx.lines[m.line_start - 1] if 0 < m.line_start <= len(ctx.lines) else ""
                if IGNORE_MARK.search(line):
                    continue
                out.append(_finding(rule, ctx, m, ctx.path, ctx.language))
                hits += 1
                if hits >= MAX_HITS_PER_RULE_FILE:
                    break
        except Exception as exc:  # a broken matcher must never abort the run
            log.warning(
                "codereview.rule_error", rule=rule.id, file=ctx.path, error=f"{type(exc).__name__}: {exc}"
            )
    return out


def scan_text(path: str, language: str, text: str, packs: list[str] | None = None) -> list[Finding]:
    """Convenience entry point for snippets and tests."""
    return scan_file(FileContext(path, language, text), rules_for(packs))


def run_rules(
    files: list[SourceFile],
    inventory: dict[str, Any],
    packs: list[str] | None = None,
    *,
    should_stop: StopFn | None = None,
    progress: ProgressFn | None = None,
) -> list[Finding]:
    rules = rules_for(packs)
    findings: list[Finding] = []
    text_files = [f for f in files if f.is_text]
    total = len(text_files)
    for i, f in enumerate(text_files, start=1):
        if should_stop and should_stop():
            break
        text = f.read_text()
        if not text:
            continue
        ctx = FileContext(f.path, f.language, text)
        findings.extend(scan_file(ctx, rules))
        if progress and (i % 25 == 0 or i == total):
            progress(i, total)
    for rule in rules:
        if rule.scope != "inventory":
            continue
        matcher = INVENTORY_MATCHERS.get(rule.id)
        if matcher is None:
            continue
        try:
            for m in matcher(inventory, files):
                findings.append(_finding(rule, None, m, m.file or "", ""))
        except Exception as exc:
            log.warning("codereview.rule_error", rule=rule.id, error=f"{type(exc).__name__}: {exc}")
    return findings

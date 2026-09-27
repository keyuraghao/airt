"""Shared helpers for the built-in analyzers: text normalisation, homoglyph folding, masking and message iteration."""
from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Iterator
from typing import Any

from ..base import Finding, Severity

# Hard cap on how much text a single analyzer scans; keeps regex time bounded on giant prompts.
MAX_SCAN_CHARS = 200_000

# Zero-width and invisible formatting characters frequently used to hide instructions.
ZERO_WIDTH_CHARS: frozenset[str] = frozenset(
    "​‌‍‎‏⁠⁡⁢⁣⁤﻿᠎­͏؜⁦⁧⁨⁩‪‫‬‭‮"
)
_ZW_RE = re.compile("[" + "".join(re.escape(c) for c in sorted(ZERO_WIDTH_CHARS)) + "]")

# Confusable characters (Cyrillic, Greek, fullwidth, mathematical) that render like Latin letters.
HOMOGLYPHS: dict[str, str] = {
    # Cyrillic
    "а": "a", "А": "A", "е": "e", "Е": "E", "о": "o", "О": "O", "р": "p", "Р": "P",
    "с": "c", "С": "C", "у": "y", "У": "Y", "х": "x", "Х": "X", "і": "i", "І": "I",
    "ј": "j", "Ј": "J", "һ": "h", "ҽ": "e", "ԁ": "d", "ԛ": "q", "ԝ": "w", "ѕ": "s",
    "Ѕ": "S", "Ү": "Y", "Н": "H", "К": "K", "М": "M", "Т": "T", "В": "B", "г": "r",
    "к": "k", "м": "m", "н": "h", "т": "t", "в": "b", "б": "6", "З": "3",
    # Greek
    "α": "a", "Α": "A", "β": "b", "Β": "B", "ε": "e", "Ε": "E", "ι": "i", "Ι": "I",
    "κ": "k", "Κ": "K", "ν": "v", "Ν": "N", "ο": "o", "Ο": "O", "ρ": "p", "Ρ": "P",
    "τ": "t", "Τ": "T", "υ": "u", "Υ": "Y", "χ": "x", "Χ": "X", "Ζ": "Z", "Η": "H",
    "Μ": "M", "μ": "u", "ω": "w",
    # Latin extended / other lookalikes
    "ı": "i", "ł": "l", "Ɖ": "D", "ǀ": "l", "ɡ": "g", "ɪ": "i", "ʀ": "r", "ʏ": "y",
    "ᴀ": "a", "ᴄ": "c", "ᴅ": "d", "ᴇ": "e", "ᴏ": "o", "ᴘ": "p", "ᴛ": "t", "ᴜ": "u",
    "ⅼ": "l", "ⅰ": "i", "ⅴ": "v", "ⅹ": "x",
}
_HOMOGLYPH_CHARS = frozenset(HOMOGLYPHS)
_HAS_LATIN_RE = re.compile(r"[A-Za-z]")
_TOKEN_RE = re.compile(r"\S+")
_WS_RE = re.compile(r"[ \t\r\f\v]+")

# Leetspeak folding used by obfuscation-aware matchers.
LEET_MAP: dict[str, str] = {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i", "|": "l", "+": "t"}

TOOL_ROLES: frozenset[str] = frozenset({"tool", "function", "tool_result", "function_result"})
_TOOL_MARKER_RE = re.compile(r"\[tool_(?:result|call|use)\b|<tool_result|<function_results?>|tool_result", re.IGNORECASE)


def safe_text(value: Any, limit: int = MAX_SCAN_CHARS) -> str:
    """Coerce any content to a bounded str. None becomes empty."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value[:limit]
    if isinstance(value, (list, dict)):
        try:
            return " ".join(_flatten_strings(value))[:limit]
        except Exception:
            return ""
    try:
        return str(value)[:limit]
    except Exception:
        return ""


def _flatten_strings(obj: Any, depth: int = 0) -> Iterator[str]:
    if depth > 8:
        return
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _flatten_strings(v, depth + 1)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _flatten_strings(v, depth + 1)
    elif obj is not None:
        yield str(obj)


def strip_zero_width(text: str) -> str:
    return _ZW_RE.sub("", text)


def count_zero_width(text: str) -> int:
    return len(_ZW_RE.findall(text))


def fold_homoglyphs(text: str) -> str:
    """Replace confusable characters with their Latin lookalike, but only inside tokens that mix scripts.

    Pure Cyrillic or Greek words (legitimate foreign text) are left untouched so multilingual
    signature matching keeps working.
    """
    if not any(c in _HOMOGLYPH_CHARS for c in text):
        return text

    def _fold(match: re.Match[str]) -> str:
        tok = match.group(0)
        if not _HAS_LATIN_RE.search(tok) or not any(c in _HOMOGLYPH_CHARS for c in tok):
            return tok
        return "".join(HOMOGLYPHS.get(c, c) for c in tok)

    return _TOKEN_RE.sub(_fold, text)


def mixed_script_tokens(text: str) -> list[str]:
    """Return tokens that contain Latin letters mixed with confusable non-Latin characters."""
    out: list[str] = []
    for m in _TOKEN_RE.finditer(text):
        tok = m.group(0)
        if _HAS_LATIN_RE.search(tok) and any(c in _HOMOGLYPH_CHARS for c in tok):
            out.append(tok)
            if len(out) >= 50:
                break
    return out


def normalize_text(text: Any) -> str:
    """Lowercase, NFKC-fold, strip zero-width chars, fold homoglyphs and collapse horizontal whitespace."""
    s = safe_text(text)
    if not s:
        return ""
    try:
        s = unicodedata.normalize("NFKC", s)
    except Exception:
        pass
    s = strip_zero_width(s)
    s = fold_homoglyphs(s)
    s = _WS_RE.sub(" ", s)
    return s.lower()


def fold_leet(text: str) -> str:
    return "".join(LEET_MAP.get(c, c) for c in text)


def mask_value(value: str, keep_start: int = 4, keep_end: int = 2, mask_char: str = "*") -> str:
    """Mask the middle of a sensitive value. Short values are almost fully masked."""
    v = value or ""
    n = len(v)
    if n == 0:
        return ""
    if n <= 6:
        return v[:1] + mask_char * (n - 1)
    if n < keep_start + keep_end + 3:
        keep_start, keep_end = 2, 1
    hidden = n - keep_start - keep_end
    return v[:keep_start] + mask_char * min(hidden, 24) + v[n - keep_end:]


def snippet(text: str, start: int, end: int, radius: int = 60, mask: str | None = None) -> str:
    """Extract a short evidence window around [start:end]; optionally replace the matched span with a masked value."""
    if not text:
        return ""
    s = max(0, start - radius)
    e = min(len(text), end + radius)
    middle = mask if mask is not None else text[start:end]
    out = text[s:start] + middle + text[end:e]
    out = out.replace("\n", " ").replace("\r", " ")
    if s > 0:
        out = "..." + out
    if e < len(text):
        out = out + "..."
    return out[:300]


def iter_messages(normalized: dict[str, Any] | None) -> Iterator[tuple[str, str, str]]:
    """Yield (location, role, text) for the system prompt and every message. Never raises on odd shapes."""
    if not isinstance(normalized, dict):
        return
    system = safe_text(normalized.get("system"))
    if system.strip():
        yield "system", "system", system
    messages = normalized.get("messages")
    if not isinstance(messages, list):
        return
    for i, m in enumerate(messages):
        if not isinstance(m, dict):
            continue
        role = str(m.get("role") or "user").lower()
        if role in ("system", "developer"):
            # already covered by the merged system prompt produced by the parser
            continue
        text = safe_text(m.get("content"))
        if text.strip():
            yield f"messages[{i}]", role, text


def iter_tools(normalized: dict[str, Any] | None) -> Iterator[tuple[str, str, str]]:
    """Yield (location, name, description) for each declared tool."""
    if not isinstance(normalized, dict):
        return
    tools = normalized.get("tools")
    if not isinstance(tools, list):
        return
    for i, t in enumerate(tools):
        if isinstance(t, dict):
            yield f"tools[{i}]", safe_text(t.get("name"), 200), safe_text(t.get("description"), 4000)
        elif isinstance(t, str):
            yield f"tools[{i}]", t[:200], ""


def is_tool_context(role: str, text: str) -> bool:
    """True when the message is a tool/function result (untrusted, retrieved content)."""
    if role in TOOL_ROLES:
        return True
    return bool(_TOOL_MARKER_RE.search(text[:400]))


def all_text(normalized: dict[str, Any] | None) -> str:
    """Whole request text (system + messages), bounded."""
    if not isinstance(normalized, dict):
        return ""
    pt = safe_text(normalized.get("prompt_text"))
    if pt:
        return pt
    return "\n".join(t for _, _, t in iter_messages(normalized))[:MAX_SCAN_CHARS]


def severity_from_weight(weight: float, bump: int = 0) -> Severity:
    """Map a 0..1 signature weight to a severity, optionally bumped up N levels."""
    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    if weight >= 0.9:
        idx = 3
    elif weight >= 0.6:
        idx = 2
    elif weight >= 0.35:
        idx = 1
    else:
        idx = 0
    return order[max(0, min(4, idx + bump))]


def bump_severity(sev: Severity, steps: int = 1) -> Severity:
    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    return order[max(0, min(4, order.index(sev) + steps))]


def max_severity(items: Iterable[Severity]) -> Severity:
    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    best = 0
    for s in items:
        best = max(best, order.index(s))
    return order[best]


def clamp_conf(value: float) -> float:
    return round(max(0.05, min(0.99, value)), 2)


def make_finding(
    analyzer: str,
    category: str,
    severity: Severity,
    title: str,
    description: str = "",
    evidence: str = "",
    location: str = "",
    confidence: float = 0.7,
    tags: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> Finding:
    return Finding(
        analyzer=analyzer,
        category=category,
        severity=severity,
        title=title[:200],
        description=description[:1000],
        evidence=(evidence or "")[:400],
        location=location,
        confidence=clamp_conf(confidence),
        tags=list(tags or []),
        metadata=dict(metadata or {}),
    )


class Signature:
    """A compiled regex signature with a weight and human readable label."""

    __slots__ = ("regex", "weight", "label", "tag")

    def __init__(self, pattern: str, weight: float, label: str, tag: str = "", flags: int = re.IGNORECASE) -> None:
        self.regex = re.compile(pattern, flags)
        self.weight = weight
        self.label = label
        self.tag = tag

    def search(self, text: str) -> re.Match[str] | None:
        return self.regex.search(text)


def compile_signatures(rows: Iterable[tuple[str, float, str, str]]) -> list[Signature]:
    return [Signature(p, w, label, tag) for p, w, label, tag in rows]

"""Repository hygiene: the published tree must not contain em dashes or leftover merge markers."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKIP_DIRS = {".venv", "node_modules", "data", "logs", ".git", "__pycache__", ".pytest_cache", "dist", "build", ".ruff_cache"}
EM_DASH = chr(0x2014)
MERGE_MARKER = "<" * 7
TEXT_SUFFIXES = {".py", ".md", ".yaml", ".yml", ".toml", ".txt", ".html", ".js", ".ts", ".css", ".json", ".sh", ".cfg", ".ini", ".env", ".example", ".mjs"}


def _files():
    for p in ROOT.rglob("*"):
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.name == "test_style.py":
            continue
        if p.is_file() and (p.suffix in TEXT_SUFFIXES or p.name in {"Dockerfile", "Makefile", "LICENSE"}):
            yield p


def test_no_em_dashes_in_repo():
    offenders = []
    for p in _files():
        try:
            text = p.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if EM_DASH in line:
                offenders.append(f"{p.relative_to(ROOT)}:{i}")
    assert not offenders, "em dashes found: " + ", ".join(offenders[:20])


def test_no_merge_markers():
    offenders = [str(p.relative_to(ROOT)) for p in _files() if p.suffix == ".py" and MERGE_MARKER in p.read_text(encoding="utf-8", errors="ignore")]
    assert not offenders

"""Repository hygiene: the published tree must not contain em dashes or leftover merge markers."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKIP_DIRS = {
    ".venv",
    "node_modules",
    "data",
    "logs",
    ".git",
    "__pycache__",
    ".pytest_cache",
    "dist",
    "build",
    ".ruff_cache",
}
EM_DASH = chr(0x2014)
MERGE_MARKER = "<" * 7
TEXT_SUFFIXES = {
    ".py",
    ".md",
    ".yaml",
    ".yml",
    ".toml",
    ".txt",
    ".html",
    ".js",
    ".ts",
    ".css",
    ".json",
    ".sh",
    ".cfg",
    ".ini",
    ".env",
    ".example",
    ".mjs",
}


def _files():
    for p in ROOT.rglob("*"):
        if any(part in SKIP_DIRS or part.endswith(".egg-info") for part in p.parts):
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
    offenders = [
        str(p.relative_to(ROOT))
        for p in _files()
        if p.suffix == ".py" and MERGE_MARKER in p.read_text(encoding="utf-8", errors="ignore")
    ]
    assert not offenders


def test_private_knowledge_base_is_never_tracked():
    import subprocess

    tracked = subprocess.run(
        ["git", "ls-files", "Code_review_Data"], cwd=ROOT, capture_output=True, text=True
    ).stdout.strip()
    assert tracked == "", "Code_review_Data must never be committed"
    ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "Code_review_Data/" in ignore


def test_no_unnecessary_blank_lines_or_trailing_whitespace():
    offenders = []
    for p in _files():
        if p.suffix not in {
            ".py",
            ".md",
            ".js",
            ".html",
            ".css",
            ".yaml",
            ".yml",
            ".toml",
            ".txt",
            ".ts",
            ".sh",
        }:
            continue
        try:
            lines = p.read_text(encoding="utf-8").split("\n")
        except UnicodeDecodeError:
            continue
        blank_run = 0
        for i, line in enumerate(lines, 1):
            if line.rstrip() != line:
                offenders.append(f"{p.relative_to(ROOT)}:{i} trailing whitespace")
            if line.strip() == "":
                blank_run += 1
                if blank_run == 3 and p.suffix != ".py":
                    offenders.append(f"{p.relative_to(ROOT)}:{i} more than two consecutive blank lines")
                if blank_run == 2 and p.suffix in {
                    ".md",
                    ".yaml",
                    ".yml",
                    ".toml",
                    ".txt",
                    ".html",
                    ".css",
                    ".js",
                    ".ts",
                    ".sh",
                }:
                    offenders.append(f"{p.relative_to(ROOT)}:{i} consecutive blank lines")
            else:
                blank_run = 0
    assert not offenders, (
        "whitespace issues: "
        + ", ".join(offenders[:25])
        + (f" (+{len(offenders) - 25} more)" if len(offenders) > 25 else "")
    )

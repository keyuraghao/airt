#!/usr/bin/env python
"""Repository style guard: fail on em dash characters and leftover merge markers.

Used by CI (.github/workflows/ci.yml), `make lint` and the release workflow. It mirrors
tests/test_style.py but runs without pytest and prints one `path:line` per offence.

Usage: python scripts/check_style.py [PATH ...]   (defaults to the repository root)
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Iterable, Iterator
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKIP_DIRS = {
    ".venv",
    "venv",
    "env",
    "node_modules",
    "data",
    "logs",
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    "dist",
    "build",
    "htmlcov",
    ".mitmproxy",
}
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
    ".mjs",
    ".css",
    ".json",
    ".sh",
    ".cfg",
    ".ini",
    ".env",
    ".example",
    ".d.ts",
}
SPECIAL_NAMES = {
    "Dockerfile",
    "Makefile",
    "LICENSE",
    "CODEOWNERS",
    ".dockerignore",
    ".gitignore",
    ".env.example",
}
EM_DASH = chr(0x2014)
MERGE_MARKERS = ("<" * 7 + " ", ">" * 7 + " ", "<" * 7, ">" * 7)


def iter_files(paths: Iterable[Path]) -> Iterator[Path]:
    for base in paths:
        candidates = [base] if base.is_file() else base.rglob("*")
        for p in candidates:
            rel_parts = p.relative_to(ROOT).parts if p.is_relative_to(ROOT) else p.parts
            if any(part in SKIP_DIRS for part in rel_parts):
                continue
            if not p.is_file():
                continue
            if p.suffix in TEXT_SUFFIXES or p.name in SPECIAL_NAMES or p.name.startswith(".env"):
                yield p


def check_file(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return []
    offences: list[str] = []
    rel = path.relative_to(ROOT) if path.is_relative_to(ROOT) else path
    for lineno, line in enumerate(text.splitlines(), 1):
        if EM_DASH in line:
            offences.append(f"{rel}:{lineno}: em dash (U+2014), use a hyphen or a comma")
        if any(line.startswith(marker) for marker in MERGE_MARKERS):
            offences.append(f"{rel}:{lineno}: merge conflict marker")
    return offences


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "paths", nargs="*", type=Path, help="files or directories to scan (default: repository root)"
    )
    parser.add_argument("--quiet", action="store_true", help="only print offences")
    args = parser.parse_args(argv)
    paths = [p.resolve() for p in args.paths] or [ROOT]
    offences: list[str] = []
    scanned = 0
    for path in iter_files(paths):
        scanned += 1
        offences.extend(check_file(path))
    for line in offences:
        print(line)
    if offences:
        print(f"check_style: {len(offences)} offence(s) in {scanned} files", file=sys.stderr)
        return 1
    if not args.quiet:
        print(f"check_style: OK ({scanned} files scanned, no em dashes, no merge markers)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

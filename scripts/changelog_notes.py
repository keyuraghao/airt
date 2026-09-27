#!/usr/bin/env python
"""Print the CHANGELOG.md section for one version (used by the release workflow as release notes).

Usage: python scripts/changelog_notes.py 1.2.3
Exit status 1 (and nothing on stdout) when the section is missing or empty, so the workflow can fall
back to GitHub's auto-generated notes.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

CHANGELOG = Path(__file__).resolve().parent.parent / "CHANGELOG.md"


def section_for(version: str, text: str) -> str:
    version = version.lstrip("v")
    pattern = re.compile(
        rf"^## \[{re.escape(version)}\][^\n]*\n(?P<body>.*?)(?=^## \[|^\[[^\]]+\]:\s*https?://|\Z)",
        re.MULTILINE | re.DOTALL,
    )
    m = pattern.search(text)
    return m.group("body").strip() if m else ""


def unwrap(text: str) -> str:
    """Join hard-wrapped bullet continuation lines so release notes never carry stray line breaks."""
    out: list[str] = []
    for line in text.split("\n"):
        if (
            out
            and line.startswith("  ")
            and line.strip()
            and out[-1].lstrip().startswith("- ")
            and not line.lstrip().startswith("- ")
        ):
            out[-1] = out[-1].rstrip() + " " + line.strip()
        else:
            out.append(line)
    return "\n".join(out)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    body = section_for(argv[1], CHANGELOG.read_text(encoding="utf-8"))
    if not body:
        print(f"no CHANGELOG.md section for {argv[1]}", file=sys.stderr)
        return 1
    print(unwrap(body))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

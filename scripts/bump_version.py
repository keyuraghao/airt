#!/usr/bin/env python
"""Bump the AISRF version in every place that carries it.

Updates `__version__` in `<package>/__init__.py` (the package named in pyproject.toml, `aisrf`), `[project] version` in pyproject.toml and turns the
`## [Unreleased]` section of CHANGELOG.md into `## [X.Y.Z] - YYYY-MM-DD` (adding a fresh empty
Unreleased section and the compare links at the bottom). The Node package in sdk/node is versioned
independently and is not touched.

Usage:
  python scripts/bump_version.py 1.2.3              apply
  python scripts/bump_version.py --dry-run 1.2.3    show the diff without writing
  python scripts/bump_version.py --check 1.2.3      exit 1 unless every location already says 1.2.3
  python scripts/bump_version.py --current          print the current version
"""

from __future__ import annotations

import argparse
import difflib
import re
import sys
import tomllib
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"


def _package_dir() -> Path:
    """The import package is named after [project].name in pyproject.toml (`aisrf`)."""
    try:
        name = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]["name"]
    except (OSError, KeyError, tomllib.TOMLDecodeError):
        name = "aisrf"
    return ROOT / name.replace("-", "_")


INIT_FILE = _package_dir() / "__init__.py"
CHANGELOG = ROOT / "CHANGELOG.md"
REPO_URL = "https://github.com/keyuraghao/aisrf"
# Semantic Versioning 2.0.0 (https://semver.org), with optional prerelease and build metadata.
SEMVER = re.compile(
    r"^(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)"
    r"(?:-(?P<pre>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
    r"(?:\+(?P<build>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"
)
INIT_RE = re.compile(r'^__version__\s*=\s*"(?P<v>[^"]+)"\s*$', re.MULTILINE)
UNRELEASED_RE = re.compile(r"^## \[Unreleased\][ \t]*$", re.MULTILINE)
UNRELEASED_LINK_RE = re.compile(r"^\[Unreleased\]:[ \t]*\S+[ \t]*$", re.MULTILINE)


class BumpError(Exception):
    pass


def parse_semver(version: str) -> tuple[int, int, int, tuple[object, ...]]:
    m = SEMVER.match(version)
    if not m:
        raise BumpError(
            f"'{version}' is not a valid semantic version (expected MAJOR.MINOR.PATCH[-prerelease][+build])"
        )
    pre = m.group("pre")
    # A version without prerelease sorts after any prerelease of the same core (SemVer 11.4).
    pre_key: tuple[object, ...] = (
        (1,) if pre is None else (0, *[(0, int(p)) if p.isdigit() else (1, p) for p in pre.split(".")])
    )
    return int(m.group("major")), int(m.group("minor")), int(m.group("patch")), pre_key


def read_init_version(text: str) -> str:
    m = INIT_RE.search(text)
    if not m:
        raise BumpError(f"could not find __version__ in {INIT_FILE.relative_to(ROOT)}")
    return m.group("v")


def read_pyproject_version(text: str) -> str:
    try:
        return tomllib.loads(text)["project"]["version"]
    except (KeyError, tomllib.TOMLDecodeError) as exc:
        raise BumpError(f"could not read [project].version from pyproject.toml: {exc}") from exc


def replace_pyproject_version(text: str, current: str, new: str) -> str:
    project_start = text.find("[project]")
    if project_start < 0:
        raise BumpError("pyproject.toml has no [project] table")
    next_table = re.compile(r"^\[", re.MULTILINE).search(text, project_start + 1)
    project_end = next_table.start() if next_table else len(text)
    section = text[project_start:project_end]
    pattern = re.compile(r'^(version\s*=\s*")' + re.escape(current) + r'(")\s*$', re.MULTILINE)
    new_section, n = pattern.subn(rf"\g<1>{new}\g<2>", section, count=1)
    if n != 1:
        raise BumpError("could not locate the version line inside [project] in pyproject.toml")
    return text[:project_start] + new_section + text[project_end:]


def update_changelog(text: str, new: str, previous: str, today: str) -> str:
    if not UNRELEASED_RE.search(text):
        raise BumpError("CHANGELOG.md has no '## [Unreleased]' heading")
    if re.search(rf"^## \[{re.escape(new)}\]", text, re.MULTILINE):
        raise BumpError(f"CHANGELOG.md already has a section for {new}")
    body_match = re.search(
        r"^## \[Unreleased\]\s*\n(?P<body>.*?)(?=^## \[|^\[Unreleased\]:|\Z)", text, re.MULTILINE | re.DOTALL
    )
    body = body_match.group("body").strip() if body_match else ""
    if not body:
        print(
            "warning: the Unreleased section is empty, the new release section will have no entries",
            file=sys.stderr,
        )
    text = UNRELEASED_RE.sub(f"## [Unreleased]\n\n## [{new}] - {today}", text, count=1)
    new_links = (
        f"[Unreleased]: {REPO_URL}/compare/v{new}...HEAD\n[{new}]: {REPO_URL}/compare/v{previous}...v{new}"
    )
    if UNRELEASED_LINK_RE.search(text):
        text = UNRELEASED_LINK_RE.sub(new_links, text, count=1)
    else:
        text = text.rstrip("\n") + "\n\n" + new_links + "\n"
    return text


def show_diff(path: Path, before: str, after: str) -> None:
    rel = str(path.relative_to(ROOT))
    diff = difflib.unified_diff(
        before.splitlines(keepends=True), after.splitlines(keepends=True), f"a/{rel}", f"b/{rel}"
    )
    sys.stdout.writelines(diff)
    print()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("version", nargs="?", help="new semantic version, e.g. 1.2.3 or 2.0.0-rc.1")
    parser.add_argument("--dry-run", action="store_true", help="print the diff, write nothing")
    parser.add_argument(
        "--check", action="store_true", help="verify that every location already carries VERSION"
    )
    parser.add_argument("--current", action="store_true", help="print the current version and exit")
    parser.add_argument(
        "--date",
        default=date.today().isoformat(),
        help="release date for the CHANGELOG heading (default: today)",
    )
    parser.add_argument("--no-changelog", action="store_true", help="leave CHANGELOG.md untouched")
    parser.add_argument(
        "--force", action="store_true", help="allow a version that is not greater than the current one"
    )
    args = parser.parse_args(argv)
    try:
        init_text = INIT_FILE.read_text(encoding="utf-8")
        pyproject_text = PYPROJECT.read_text(encoding="utf-8")
        init_version = read_init_version(init_text)
        pyproject_version = read_pyproject_version(pyproject_text)
        if args.current:
            print(init_version)
            return 0 if init_version == pyproject_version else 1
        if not args.version:
            parser.error("VERSION is required unless --current is given")
        new = args.version.lstrip("v")
        parse_semver(new)
        if args.check:
            problems = []
            if init_version != new:
                problems.append(f"{INIT_FILE.relative_to(ROOT)} has {init_version}")
            if pyproject_version != new:
                problems.append(f"pyproject.toml has {pyproject_version}")
            if problems:
                raise BumpError(f"version mismatch for {new}: " + ", ".join(problems))
            print(f"version {new} is consistent across {INIT_FILE.relative_to(ROOT)} and pyproject.toml")
            return 0
        if init_version != pyproject_version:
            raise BumpError(
                f"current versions disagree: {INIT_FILE.relative_to(ROOT)}={init_version}, pyproject.toml={pyproject_version}"
            )
        if parse_semver(new) <= parse_semver(init_version) and not args.force:
            raise BumpError(
                f"{new} is not greater than the current version {init_version} (use --force to override)"
            )
        changes: list[tuple[Path, str, str]] = []
        changes.append((INIT_FILE, init_text, INIT_RE.sub(f'__version__ = "{new}"', init_text, count=1)))
        changes.append(
            (PYPROJECT, pyproject_text, replace_pyproject_version(pyproject_text, pyproject_version, new))
        )
        if not args.no_changelog:
            changelog_text = CHANGELOG.read_text(encoding="utf-8")
            changes.append(
                (CHANGELOG, changelog_text, update_changelog(changelog_text, new, init_version, args.date))
            )
        for path, before, after in changes:
            if args.dry_run:
                show_diff(path, before, after)
            else:
                path.write_text(after, encoding="utf-8")
                print(f"updated {path.relative_to(ROOT)}")
        if args.dry_run:
            print(f"dry run: {init_version} -> {new}, nothing written")
        else:
            print(
                f"bumped {init_version} -> {new}. Next: review the diff, commit, then `git tag v{new} && git push origin v{new}`"
            )
        return 0
    except BumpError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

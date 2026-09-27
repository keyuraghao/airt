"""Source acquisition for a review run.

Supported sources: uploaded archive (zip, tar, tar.gz), archive URL, git repository (with optional
ref and credentials), local directory (restricted to the data directory or an allowlist) and a
pasted snippet. Every path ends with the code sitting under <work_dir>/src.

Safety properties: zip-slip and absolute member paths are rejected, symlinks and hard links are
never extracted, uncompressed size and file counts are bounded, credentials are passed to git
through GIT_ASKPASS (never on the command line) and are redacted from anything persisted or logged.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import tarfile
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from ..config import get_settings
from ..logging import get_logger
from .config import get_config, work_root
from .inventory import LANGUAGES, WalkStats, walk_files
from .secrets import mask_secrets, redact_url

log = get_logger("aisrf.codereview.intake")
SOURCE_TYPES = ("git", "url", "zip", "path", "snippet")
_SHA = re.compile(r"^[0-9a-f]{7,40}$")
_ARCHIVE_EXT = (".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")
SNIPPET_EXT: dict[str, str] = {}
for _ext, _lang in LANGUAGES.items():  # first extension listed for a language wins (.py before .pyi)
    if _lang in ("python", "javascript", "typescript", "java", "go", "csharp", "ruby", "php", "rust", "kotlin", "swift", "html", "yaml", "json", "shell", "sql"):
        SNIPPET_EXT.setdefault(_lang, _ext)
SNIPPET_EXT.update({"js": ".js", "ts": ".ts", "py": ".py", "jsx": ".jsx", "tsx": ".tsx", "text": ".txt", "prompt": ".prompt", "dockerfile": "Dockerfile"})


class IntakeError(ValueError):
    """User-facing intake failure (bad archive, forbidden path, clone failure...)."""


@dataclass
class IntakeResult:
    src_dir: Path
    source_type: str
    source_ref: str  # redacted
    detail: dict[str, Any] = field(default_factory=dict)


# --- work directories ---------------------------------------------------------------------
def prepare_workdir(run_id: str) -> Path:
    safe = "".join(c for c in run_id if c.isalnum() or c in "-_")[:60] or "run"
    wd = work_root() / safe
    src = wd / "src"
    if src.exists():
        shutil.rmtree(src, ignore_errors=True)  # uploads next to it (upload.archive) are kept
    src.mkdir(parents=True, exist_ok=True)
    return wd


def remove_workdir(work_dir: str | Path | None) -> None:
    if not work_dir:
        return
    path = Path(work_dir)
    root = work_root().resolve()
    try:
        resolved = path.resolve()
    except OSError:
        return
    if resolved == root or root not in resolved.parents:
        return  # never delete anything outside the code review area
    shutil.rmtree(resolved, ignore_errors=True)


def cleanup_expired(retention_days: int | None = None) -> int:
    """Delete work directories older than the retention period. Returns the number removed."""
    cfg = get_config()
    days = int(retention_days if retention_days is not None else cfg.get("retention_days") or 7)
    cutoff = time.time() - days * 86400
    removed = 0
    root = work_root()
    for child in root.iterdir():
        try:
            if child.is_dir() and child.stat().st_mtime < cutoff:
                shutil.rmtree(child, ignore_errors=True)
                removed += 1
        except OSError:
            continue
    return removed


# --- archives -----------------------------------------------------------------------------
def _is_within(root: Path, target: Path) -> bool:
    try:
        target.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _member_ok(name: str) -> bool:
    if not name or name.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:[\\/]", name):
        return False
    parts = name.replace("\\", "/").split("/")
    return ".." not in parts


def archive_kind(path: Path) -> str:
    with path.open("rb") as fh:
        head = fh.read(6)
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return "zip"
    if head.startswith((b"\x1f\x8b", b"BZh", b"\xfd7zXZ")):
        return "tar"
    if tarfile.is_tarfile(path):
        return "tar"
    if zipfile.is_zipfile(path):
        return "zip"
    raise IntakeError("unsupported archive format: expected zip, tar, tar.gz, tar.bz2 or tar.xz")


def inspect_archive(path: Path, cfg: dict[str, Any] | None = None) -> dict[str, Any]:
    """Validate an archive without extracting it. Raises IntakeError on unsafe or oversized content."""
    cfg = cfg or get_config()
    max_total = int(cfg.get("max_archive_bytes") or 0)
    max_files = int(cfg.get("max_files") or 0)
    kind = archive_kind(path)
    total = 0
    count = 0
    if kind == "zip":
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                if not _member_ok(info.filename):
                    raise IntakeError(f"unsafe archive member path: {info.filename!r}")
                mode = (info.external_attr >> 16) & 0o170000
                if mode == stat.S_IFLNK:
                    raise IntakeError(f"archive contains a symbolic link: {info.filename!r}")
                if info.is_dir():
                    continue
                count += 1
                total += info.file_size
                if max_total and total > max_total:
                    raise IntakeError(f"archive expands beyond the {max_total} byte limit")
                if max_files and count > max_files * 3:
                    raise IntakeError(f"archive contains more than {max_files * 3} files")
    else:
        with tarfile.open(path) as tf:
            for member in tf:
                if not _member_ok(member.name):
                    raise IntakeError(f"unsafe archive member path: {member.name!r}")
                if member.issym() or member.islnk():
                    raise IntakeError(f"archive contains a link: {member.name!r}")
                if member.isdev() or member.isfifo():
                    raise IntakeError(f"archive contains a device or fifo: {member.name!r}")
                if member.isdir():
                    continue
                count += 1
                total += member.size
                if max_total and total > max_total:
                    raise IntakeError(f"archive expands beyond the {max_total} byte limit")
                if max_files and count > max_files * 3:
                    raise IntakeError(f"archive contains more than {max_files * 3} files")
    return {"kind": kind, "files": count, "uncompressed_bytes": total}


def extract_archive(path: Path, dest: Path, cfg: dict[str, Any] | None = None) -> dict[str, Any]:
    """Safely extract an archive into dest (validated first) and flatten a single top-level directory."""
    cfg = cfg or get_config()
    info = inspect_archive(path, cfg)
    exclude_dirs = set(cfg.get("exclude_dirs") or [])
    max_file = int(cfg.get("max_file_bytes") or 0)
    dest.mkdir(parents=True, exist_ok=True)
    written = 0
    skipped = 0

    def wanted(name: str, size: int) -> bool:
        parts = name.replace("\\", "/").split("/")
        if any(p in exclude_dirs for p in parts[:-1]):
            return False
        return not (max_file and size > max_file and Path(name).suffix.lower() not in (".pt", ".pth", ".pkl", ".bin", ".safetensors", ".gguf", ".onnx", ".h5"))

    if info["kind"] == "zip":
        with zipfile.ZipFile(path) as zf:
            for member in zf.infolist():
                if member.is_dir() or not wanted(member.filename, member.file_size):
                    skipped += 1
                    continue
                target = dest / member.filename.replace("\\", "/")
                if not _is_within(dest, target):
                    raise IntakeError(f"unsafe archive member path: {member.filename!r}")
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(member) as src, target.open("wb") as out:
                    shutil.copyfileobj(src, out, 1024 * 1024)
                written += 1
    else:
        with tarfile.open(path) as tf:
            for member in tf:
                if not member.isfile() or not wanted(member.name, member.size):
                    skipped += 1
                    continue
                target = dest / member.name
                if not _is_within(dest, target):
                    raise IntakeError(f"unsafe archive member path: {member.name!r}")
                target.parent.mkdir(parents=True, exist_ok=True)
                src = tf.extractfile(member)
                if src is None:
                    continue
                with src, target.open("wb") as out:
                    shutil.copyfileobj(src, out, 1024 * 1024)
                written += 1
    _flatten(dest)
    return {**info, "written": written, "skipped": skipped}


def _flatten(dest: Path) -> None:
    """GitHub style archives wrap everything in one directory; unwrap it so paths are natural."""
    entries = [p for p in dest.iterdir() if p.name not in ("__MACOSX",)]
    if len(entries) == 1 and entries[0].is_dir():
        inner = entries[0]
        tmp = dest / f".unwrap-{inner.name}"
        inner.rename(tmp)
        for child in tmp.iterdir():
            shutil.move(str(child), str(dest / child.name))
        tmp.rmdir()


# --- downloads ----------------------------------------------------------------------------
def download(url: str, dest: Path, cfg: dict[str, Any] | None = None, headers: dict[str, str] | None = None) -> Path:
    cfg = cfg or get_config()
    limit = int(cfg.get("max_archive_bytes") or 0)
    timeout = float(cfg.get("download_timeout_seconds") or 120)
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise IntakeError("archive URL must use http or https")
    size = 0
    try:
        with httpx.Client(follow_redirects=True, timeout=timeout) as client, client.stream("GET", url, headers=headers or {}) as resp:
            if resp.status_code >= 400:
                raise IntakeError(f"download failed with HTTP {resp.status_code}")
            with dest.open("wb") as out:
                for chunk in resp.iter_bytes(1024 * 256):
                    size += len(chunk)
                    if limit and size > limit:
                        raise IntakeError(f"download exceeds the {limit} byte limit")
                    out.write(chunk)
    except httpx.HTTPError as exc:
        raise IntakeError(f"download failed: {type(exc).__name__}") from None
    return dest


# --- git ----------------------------------------------------------------------------------
_ASKPASS = """#!/bin/sh
case "$1" in
  *sername*) printf '%s\\n' "$AISRF_GIT_USERNAME" ;;
  *) printf '%s\\n' "$AISRF_GIT_PASSWORD" ;;
esac
"""


def git_provider(url: str, explicit: str | None = None) -> str:
    if explicit:
        return explicit.lower()
    host = (urlsplit(url).hostname or "").lower() if "://" in url else url.split("@")[-1].split(":")[0].lower()
    if "github" in host:
        return "github"
    if "gitlab" in host:
        return "gitlab"
    if "bitbucket" in host:
        return "bitbucket"
    if "dev.azure.com" in host or "visualstudio.com" in host:
        return "azure"
    return "generic"


def token_username(provider: str) -> str:
    return {"github": "x-access-token", "gitlab": "oauth2", "bitbucket": "x-token-auth", "azure": "pat"}.get(provider, "token")


def split_url_credentials(url: str) -> tuple[str, str | None, str | None]:
    """Remove user:password from an http(s) URL. Returns (clean_url, username, password)."""
    if "://" not in url:
        return url, None, None
    parts = urlsplit(url)
    if not parts.username and not parts.password:
        return url, None, None
    host = parts.hostname or ""
    if parts.port:
        host += f":{parts.port}"
    clean = urlunsplit((parts.scheme, host, parts.path, parts.query, parts.fragment))
    return clean, parts.username, parts.password


def _run_git(args: list[str], cwd: Path, env: dict[str, str], timeout: float) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(["git", *args], cwd=str(cwd), env=env, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL, check=False)
    except subprocess.TimeoutExpired:
        raise IntakeError(f"git {args[0]} timed out after {int(timeout)}s") from None
    except FileNotFoundError:
        raise IntakeError("git is not installed on this host") from None


def clone_repository(
    url: str,
    dest: Path,
    *,
    ref: str | None = None,
    token: str | None = None,
    username: str | None = None,
    ssh_key_path: str | None = None,
    provider: str | None = None,
    work_dir: Path | None = None,
    cfg: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Shallow clone url at ref into dest. Credentials never touch the command line."""
    cfg = cfg or get_config()
    timeout = float(cfg.get("git_timeout_seconds") or 300)
    clean_url, url_user, url_pass = split_url_credentials(url)
    token = token or url_pass
    username = username or url_user or token_username(git_provider(clean_url, provider))
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["LC_ALL"] = "C"
    helper: Path | None = None
    if token:
        helper = (work_dir or dest.parent) / ".askpass.sh"
        helper.write_text(_ASKPASS, encoding="utf-8")
        helper.chmod(0o700)
        env["GIT_ASKPASS"] = str(helper)
        env["AISRF_GIT_USERNAME"] = username
        env["AISRF_GIT_PASSWORD"] = token
    if ssh_key_path:
        key = Path(ssh_key_path).expanduser()
        if not key.is_file():
            raise IntakeError("ssh deploy key not found")
        env["GIT_SSH_COMMAND"] = f"ssh -i {key} -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=accept-new"
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    dest.parent.mkdir(parents=True, exist_ok=True)
    args = ["clone", "--depth", "1", "--no-tags", "--quiet"]
    is_sha = bool(ref and _SHA.match(ref))
    if ref and not is_sha:
        args += ["--branch", ref]
    args += [clean_url, str(dest)]
    try:
        result = _run_git(args, dest.parent, env, timeout)
        if result.returncode != 0:
            raise IntakeError("git clone failed: " + _clean_git_error(result.stderr))
        if is_sha and ref:
            fetched = _run_git(["fetch", "--depth", "1", "--quiet", "origin", ref], dest, env, timeout)
            if fetched.returncode != 0:
                full = _run_git(["fetch", "--quiet", "--unshallow", "origin"], dest, env, timeout)
                if full.returncode != 0:
                    raise IntakeError("git fetch of the requested commit failed: " + _clean_git_error(fetched.stderr))
            checkout = _run_git(["checkout", "--quiet", ref], dest, env, timeout)
            if checkout.returncode != 0:
                raise IntakeError("git checkout failed: " + _clean_git_error(checkout.stderr))
        head = _run_git(["rev-parse", "HEAD"], dest, env, 30)
        commit = head.stdout.strip() if head.returncode == 0 else ""
        branch = _run_git(["rev-parse", "--abbrev-ref", "HEAD"], dest, env, 30)
    finally:
        if helper is not None:
            helper.unlink(missing_ok=True)
    shutil.rmtree(dest / ".git", ignore_errors=True)
    return {"commit": commit, "branch": branch.stdout.strip() if branch.returncode == 0 else "", "ref": ref or ""}


def _clean_git_error(stderr: str) -> str:
    text = mask_secrets(redact_url(stderr or "")).strip()
    lines = [line for line in text.splitlines() if line.strip() and not line.startswith(("hint:", "warning: You appear"))]
    return " ".join(lines)[:600] or "unknown error"


def github_tarball(url: str, dest_archive: Path, ref: str | None, token: str | None, cfg: dict[str, Any] | None = None) -> Path:
    """Download a repository tarball through the GitHub REST API (used when git is unavailable)."""
    parts = urlsplit(url)
    path = parts.path.strip("/").removesuffix(".git")
    segments = path.split("/")
    if len(segments) < 2:
        raise IntakeError("GitHub URL must look like https://github.com/<owner>/<repo>")
    owner, repo = segments[0], segments[1]
    api = f"https://api.github.com/repos/{owner}/{repo}/tarball/{ref}" if ref else f"https://api.github.com/repos/{owner}/{repo}/tarball"
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "AISRF-codereview"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return download(api, dest_archive, cfg, headers)


# --- local paths --------------------------------------------------------------------------
def allowed_roots(cfg: dict[str, Any] | None = None) -> list[Path]:
    cfg = cfg or get_config()
    roots = [get_settings().data_dir]
    roots.extend(Path(p).expanduser() for p in (cfg.get("path_allowlist") or []) if p)
    return roots


def check_local_path(path: str, cfg: dict[str, Any] | None = None) -> Path:
    """Resolve a local directory and verify it sits under one of the allowed roots."""
    if not path:
        raise IntakeError("path is required")
    candidate = Path(path).expanduser()
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError):
        raise IntakeError("path does not exist") from None
    if not resolved.is_dir():
        raise IntakeError("path is not a directory")
    for root in allowed_roots(cfg):
        try:
            root_resolved = root.resolve()
        except OSError:
            continue
        if resolved == root_resolved or root_resolved in resolved.parents:
            return resolved
    raise IntakeError("path is outside the allowed directories (data_dir or the codereview path_allowlist)")


def copy_local_tree(source: Path, dest: Path, cfg: dict[str, Any], include: list[str] | None, exclude: list[str] | None) -> WalkStats:
    stats = WalkStats()
    for f in walk_files(source, cfg, include=include, exclude=exclude, stats=stats):
        target = dest / f.path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(f.abs_path, target)
    return stats


# --- snippets -----------------------------------------------------------------------------
def write_snippet(code: str, language: str | None, dest: Path) -> Path:
    if not code or not code.strip():
        raise IntakeError("snippet is empty")
    lang = (language or "python").lower().strip()
    ext = SNIPPET_EXT.get(lang, ".txt")
    name = ext if ext == "Dockerfile" else f"snippet{ext}"
    dest.mkdir(parents=True, exist_ok=True)
    target = dest / name
    target.write_text(code, encoding="utf-8")
    return target


# --- orchestration --------------------------------------------------------------------------
def acquire(run_id: str, source: dict[str, Any], options: dict[str, Any] | None = None, cfg: dict[str, Any] | None = None) -> IntakeResult:
    """Materialise the source under <work_dir>/src. Blocking; run it in a worker thread."""
    cfg = cfg or get_config()
    options = options or {}
    kind = str(source.get("type") or "").lower()
    if kind not in SOURCE_TYPES:
        raise IntakeError(f"unknown source type {kind!r}")
    work_dir = prepare_workdir(run_id)
    src = work_dir / "src"
    detail: dict[str, Any] = {}
    if kind == "snippet":
        target = write_snippet(str(source.get("code") or ""), source.get("language"), src)
        return IntakeResult(src, kind, target.name, {"language": source.get("language") or "python"})
    if kind == "path":
        resolved = check_local_path(str(source.get("path") or ""), cfg)
        stats = copy_local_tree(resolved, src, cfg, options.get("include"), options.get("exclude"))
        detail = {"copied": stats.scanned, "skipped_large": stats.skipped_large, "skipped_binary": stats.skipped_binary, "truncated": stats.truncated}
        return IntakeResult(src, kind, str(resolved), detail)
    if kind == "zip":
        archive = Path(str(source.get("archive_path") or ""))
        if not archive.is_file():
            raise IntakeError("uploaded archive not found")
        detail = extract_archive(archive, src, cfg)
        archive.unlink(missing_ok=True)
        return IntakeResult(src, kind, str(source.get("filename") or archive.name), detail)
    if kind == "url":
        url = str(source.get("url") or "")
        clean_url, _, _ = split_url_credentials(url)
        headers = {}
        if source.get("token"):
            headers["Authorization"] = f"Bearer {source['token']}"
        archive = download(url, work_dir / "download.archive", cfg, headers)
        detail = extract_archive(archive, src, cfg)
        archive.unlink(missing_ok=True)
        return IntakeResult(src, kind, redact_url(clean_url), detail)
    # git
    url = str(source.get("url") or "")
    if not url:
        raise IntakeError("git url is required")
    clean_url, _, _ = split_url_credentials(url)
    ref = str(source.get("ref") or "") or None
    token = source.get("token") or None
    provider = git_provider(clean_url, source.get("provider"))
    have_git = shutil.which("git") is not None
    if have_git:
        try:
            detail = clone_repository(url, src, ref=ref, token=token, username=source.get("username"), ssh_key_path=source.get("ssh_key_path"), provider=provider, work_dir=work_dir, cfg=cfg)
            detail["method"] = "git"
            return IntakeResult(src, kind, redact_url(clean_url), detail)
        except IntakeError as exc:
            if provider != "github" or not clean_url.startswith("https://"):
                raise
            log.warning("codereview.intake.git_failed_fallback", url=redact_url(clean_url), error=str(exc))
    if provider == "github" and clean_url.startswith("https://"):
        archive = github_tarball(clean_url, work_dir / "download.tar.gz", ref, token, cfg)
        detail = extract_archive(archive, src, cfg)
        archive.unlink(missing_ok=True)
        detail["method"] = "github-api"
        return IntakeResult(src, kind, redact_url(clean_url), detail)
    raise IntakeError("git is not installed and no API fallback exists for this provider")

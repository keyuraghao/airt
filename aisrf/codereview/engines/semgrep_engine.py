"""Semgrep engine: runs the AISRF semgrep rule files (taint mode where possible) in a subprocess.

Two ways of invoking semgrep are supported and tried in order:

* the OCaml engine shipped inside the ``semgrep`` Python package (``semgrep-core`` started as
  ``osemgrep`` in ``--experimental`` mode, with the bundled shared libraries on the loader path).
  It starts in milliseconds and does not import the Python CLI, so it keeps working when the
  Python CLI is broken by an incompatible dependency;
* the regular ``semgrep`` command line (an explicit ``semgrep_binary`` setting, the project venv,
  then PATH).

The OSS engine does not return matched source lines, so snippets are read back from the scanned
tree. Results are mapped onto catalogue rules through the ``aisrf_rule`` metadata key.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ...logging import get_logger
from ..config import scanner_binary
from ..findings import Finding
from ..inventory import language_of
from ..rules import RULES_BY_ID, semgrep_configs
from ..rules.base import Rule

log = get_logger("aisrf.codereview.semgrep")
SEVERITY_MAP = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW", "CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}
MISSING_LINES = ("", "requires login")


@dataclass
class Invocation:
    """One way of starting semgrep: the executable, argv[0] and extra environment."""

    name: str
    executable: str
    argv0: str
    extra_args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)


def core_binary() -> tuple[Path, Path] | None:
    """Locate semgrep-core and its bundled shared libraries inside the installed semgrep package."""
    try:
        spec = importlib.util.find_spec("semgrep")
    except (ImportError, ValueError):
        return None
    if spec is None or not spec.submodule_search_locations:
        return None
    for location in spec.submodule_search_locations:
        core = Path(location) / "bin" / "semgrep-core"
        if core.is_file():
            return core, core.parent / "libs"
    return None


def _base_env() -> dict[str, str]:
    env = dict(os.environ)
    env.setdefault("SEMGREP_SEND_METRICS", "off")
    env["SEMGREP_ENABLE_VERSION_CHECK"] = "0"
    env["NO_COLOR"] = "1"
    return env


def invocations(cfg: dict[str, Any]) -> list[Invocation]:
    """Candidate invocations in preference order (explicit setting first, then osemgrep, then the CLI)."""
    out: list[Invocation] = []
    explicit = str(cfg.get("semgrep_binary") or "").strip()
    if explicit and Path(explicit).exists():
        out.append(Invocation("cli", explicit, explicit, [], _base_env()))
    core = core_binary()
    if core is not None:
        binary, libs = core
        env = _base_env()
        if libs.is_dir():
            env["LD_LIBRARY_PATH"] = str(libs) + (os.pathsep + env["LD_LIBRARY_PATH"] if env.get("LD_LIBRARY_PATH") else "")
        out.append(Invocation("osemgrep", str(binary), "osemgrep", ["--experimental"], env))
    if not explicit:
        cli = scanner_binary("semgrep", cfg)
        if cli:
            out.append(Invocation("cli", cli, cli, [], _base_env()))
    return out


def _rule_for(check_id: str, meta: dict[str, Any]) -> tuple[Rule | None, str]:
    rid = str(meta.get("aisrf_rule") or "").strip()
    if rid in RULES_BY_ID:
        return RULES_BY_ID[rid], rid
    tail = check_id.rsplit(".", 1)[-1]
    return None, f"AISRF-SG-{tail}"[:60]


def _snippet_from_disk(src_dir: Path, rel: str, start: int, end: int) -> str:
    try:
        target = (src_dir / rel).resolve()
        if src_dir.resolve() not in target.parents:
            return ""
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    end = min(max(end, start), start + 7, len(lines))
    return "\n".join(lines[max(0, start - 1) : end])


def to_finding(result: dict[str, Any], src_dir: Path | None = None) -> Finding | None:
    extra = result.get("extra") or {}
    meta = extra.get("metadata") or {}
    check_id = str(result.get("check_id") or "")
    rule, rule_id = _rule_for(check_id, meta)
    path = str(result.get("path") or "").replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    start = int((result.get("start") or {}).get("line") or 1)
    end = int((result.get("end") or {}).get("line") or start)
    snippet = str(extra.get("lines") or "")
    if snippet.strip() in MISSING_LINES and src_dir is not None:
        snippet = _snippet_from_disk(src_dir, path, start, end)
    severity = str(meta.get("severity") or SEVERITY_MAP.get(str(extra.get("severity") or "WARNING").upper(), "MEDIUM")).upper()
    try:
        confidence = float(meta.get("confidence") or 0.65)
    except (TypeError, ValueError):
        confidence = 0.65
    message = str(extra.get("message") or "").strip()
    if rule is not None:
        pack, title, description, remediation = rule.pack, rule.title, rule.description, "\n".join(f"- {s}" for s in rule.remediation)
        owasp, cwe, category = rule.owasp, rule.cwe, rule.category
        if not meta.get("severity"):
            severity = rule.severity
    else:
        pack = str(meta.get("pack") or "general")
        title = message[:200] or check_id
        description = message
        remediation = str(meta.get("remediation") or "")
        owasp = list(meta.get("owasp") or [])
        cwe = str(meta.get("cwe") or "")
        category = str(meta.get("category") or "code_safety")
    return Finding(
        rule_id=rule_id,
        pack=pack,
        engine="semgrep",
        severity=severity,
        confidence=confidence,
        title=title,
        description=description,
        remediation=remediation,
        file=path,
        line_start=start,
        line_end=end,
        snippet=snippet,
        language=language_of(path),
        owasp=owasp,
        cwe=cwe,
        category=category,
        metadata={"check_id": check_id, "message": message, "taint": bool(meta.get("taint")) or "dataflow_trace" in extra},
    )


def parse_output(text: str, src_dir: Path | None = None) -> tuple[list[Finding], list[dict[str, Any]]]:
    """Parse semgrep JSON output. Raises ValueError when it is not JSON."""
    brace = text.find("{")
    doc = json.loads(text[brace:] if brace >= 0 else text)
    findings: list[Finding] = []
    for result in doc.get("results") or []:
        try:
            f = to_finding(result, src_dir)
        except Exception as exc:
            log.warning("codereview.semgrep.bad_result", error=str(exc))
            continue
        if f is not None:
            findings.append(f)
    return findings, list(doc.get("errors") or [])


def scan_args(inv: Invocation, configs: list[Path], cfg: dict[str, Any]) -> list[str]:
    args = [inv.argv0, "scan", *inv.extra_args, "--json", "--metrics=off", "--quiet", "--disable-version-check", "--no-git-ignore", "--timeout", "30", "--timeout-threshold", "3", "--max-target-bytes", str(int(cfg.get("max_file_bytes") or 2_000_000))]
    for d in cfg.get("exclude_dirs") or []:
        args += ["--exclude", d]
    for c in configs:
        args += ["--config", str(c)]
    args.append(".")
    return args


async def _execute(inv: Invocation, args: list[str], cwd: Path, timeout: float) -> tuple[int | None, bytes, bytes]:
    proc = await asyncio.create_subprocess_exec(*args, executable=inv.executable, cwd=str(cwd), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=inv.env)
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except (TimeoutError, asyncio.CancelledError):
        proc.kill()
        raise
    return proc.returncode, out, err


async def run_semgrep(src_dir: Path, packs: list[str] | None, cfg: dict[str, Any]) -> tuple[list[Finding], dict[str, Any]]:
    candidates = invocations(cfg)
    status: dict[str, Any] = {"engine": "semgrep", "available": bool(candidates), "findings": 0}
    if not candidates:
        status["error"] = "semgrep binary not found"
        return [], status
    configs = semgrep_configs(packs)
    if not configs:
        status["error"] = "no semgrep rule files for the selected packs"
        return [], status
    timeout = float(cfg.get("semgrep_timeout_seconds") or 180)
    attempts: list[str] = []
    for inv in candidates:
        args = scan_args(inv, configs, cfg)
        try:
            code, out, err = await _execute(inv, args, src_dir, timeout)
        except OSError as exc:
            attempts.append(f"{inv.name}: failed to start ({exc})")
            continue
        except TimeoutError:
            status["error"] = f"semgrep timed out after {int(timeout)}s"
            status["mode"] = inv.name
            return [], status
        try:
            findings, errors = parse_output(out.decode("utf-8", "replace"), src_dir)
        except ValueError:
            tail = err.decode("utf-8", "replace").strip().splitlines()[-1:] or [""]
            attempts.append(f"{inv.name}: exit {code}, {tail[0][:200]}")
            continue
        status.update({"findings": len(findings), "rule_files": len(configs), "errors": len(errors), "exit_code": code, "mode": inv.name})
        if errors:
            status["error_samples"] = [str(e.get("message") or e.get("type") or "")[:200] for e in errors[:5]]
        if attempts:
            status["fallback_from"] = attempts
        return findings, status
    status["available"] = False
    status["error"] = "; ".join(attempts)[:600] or "semgrep produced no usable output"
    return [], status


async def validate_rules(cfg: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run ``--validate`` over the shipped rule files with the first working invocation (used by tests and ops)."""
    from ..config import get_config
    from ..rules import SEMGREP_DIR

    cfg = cfg or get_config()
    for inv in invocations(cfg):
        args = [inv.argv0, *inv.extra_args, "--validate", "--metrics=off", "--config", str(SEMGREP_DIR)]
        try:
            code, out, err = await _execute(inv, args, SEMGREP_DIR, 120)
        except (OSError, TimeoutError) as exc:
            continue_reason = f"{type(exc).__name__}: {exc}"
            log.warning("codereview.semgrep.validate_failed", mode=inv.name, error=continue_reason)
            continue
        text = (out + err).decode("utf-8", "replace")
        if code == 0 and "ModuleNotFoundError" not in text:
            return {"ok": "0 fatal errors" in text or code == 0, "mode": inv.name, "output": text[-600:]}
    return {"ok": False, "mode": None, "output": "no working semgrep invocation"}

"""Bandit engine: general Python security checks, mapped onto the AISRF taxonomy."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from ...logging import get_logger
from ...taxonomy import owasp_ids
from ..config import scanner_binary
from ..findings import Finding

log = get_logger("aisrf.codereview.bandit")
CONFIDENCE = {"HIGH": 0.85, "MEDIUM": 0.6, "LOW": 0.35}
CATEGORY_BY_TEST: dict[str, str] = {
    "B102": "tool_abuse",
    "B307": "tool_abuse",
    "B301": "supply_chain",
    "B302": "supply_chain",
    "B303": "supply_chain",
    "B304": "supply_chain",
    "B305": "supply_chain",
    "B306": "supply_chain",
    "B403": "supply_chain",
    "B404": "tool_abuse",
    "B506": "supply_chain",
    "B602": "tool_abuse",
    "B603": "tool_abuse",
    "B604": "tool_abuse",
    "B605": "tool_abuse",
    "B606": "tool_abuse",
    "B607": "tool_abuse",
    "B608": "tool_abuse",
    "B609": "tool_abuse",
    "B610": "tool_abuse",
    "B611": "tool_abuse",
    "B105": "secrets",
    "B106": "secrets",
    "B107": "secrets",
    "B108": "secrets",
    "B501": "supply_chain",
    "B502": "supply_chain",
    "B503": "supply_chain",
    "B504": "supply_chain",
    "B201": "system_prompt_leak",
    "B113": "denial_of_wallet",
    "B310": "tool_abuse",
    "B311": "code_safety",
    "B324": "supply_chain",
    "B701": "output_handling",
    "B702": "output_handling",
    "B703": "output_handling",
}


def _to_finding(item: dict[str, Any]) -> Finding:
    test_id = str(item.get("test_id") or "B000")
    severity = str(item.get("issue_severity") or "MEDIUM").upper()
    if severity not in ("LOW", "MEDIUM", "HIGH"):
        severity = "MEDIUM"
    cwe_info = item.get("issue_cwe") or {}
    cwe = f"CWE-{cwe_info.get('id')}" if cwe_info.get("id") else ""
    category = CATEGORY_BY_TEST.get(test_id, "code_safety")
    path = str(item.get("filename") or "").lstrip("./")
    start = int(item.get("line_number") or 1)
    line_range = item.get("line_range") or [start]
    end = int(line_range[-1]) if line_range else start
    return Finding(
        rule_id=f"BANDIT-{test_id}",
        pack="general",
        engine="bandit",
        severity=severity,
        confidence=CONFIDENCE.get(str(item.get("issue_confidence") or "MEDIUM").upper(), 0.6),
        title=f"{test_id}: {str(item.get('test_name') or '').replace('_', ' ')}",
        description=str(item.get("issue_text") or ""),
        remediation=f"- See the bandit documentation for {test_id}: {item.get('more_info') or 'https://bandit.readthedocs.io/'}",
        file=path,
        line_start=start,
        line_end=end,
        snippet=str(item.get("code") or ""),
        language="python",
        owasp=owasp_ids(category),
        cwe=cwe,
        category=category,
        metadata={
            "test_name": item.get("test_name"),
            "more_info": item.get("more_info"),
            "bandit_confidence": item.get("issue_confidence"),
        },
    )


async def run_bandit(src_dir: Path, cfg: dict[str, Any]) -> tuple[list[Finding], dict[str, Any]]:
    binary = scanner_binary("bandit", cfg)
    status: dict[str, Any] = {"engine": "bandit", "available": bool(binary), "findings": 0}
    if not binary:
        status["error"] = "bandit binary not found"
        return [], status
    timeout = float(cfg.get("bandit_timeout_seconds") or 120)
    excludes = ",".join(f"./{d}" for d in (cfg.get("exclude_dirs") or []))
    args = [binary, "-r", ".", "-f", "json", "-q", "--exit-zero"]
    if excludes:
        args += ["-x", excludes]
    try:
        proc = await asyncio.create_subprocess_exec(
            *args, cwd=str(src_dir), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
    except OSError as exc:
        status["error"] = f"bandit failed to start: {exc}"
        return [], status
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except TimeoutError:
        proc.kill()
        status["error"] = f"bandit timed out after {int(timeout)}s"
        return [], status
    except asyncio.CancelledError:
        proc.kill()
        raise
    text = out.decode("utf-8", "replace")
    brace = text.find("{")
    try:
        doc = json.loads(text[brace:] if brace >= 0 else "{}")
    except ValueError:
        status["error"] = "bandit produced invalid JSON: " + err.decode("utf-8", "replace")[:300]
        return [], status
    findings: list[Finding] = []
    for item in doc.get("results") or []:
        try:
            findings.append(_to_finding(item))
        except Exception as exc:
            log.warning("codereview.bandit.bad_result", error=str(exc))
    metrics = (doc.get("metrics") or {}).get("_totals") or {}
    status.update(
        {
            "findings": len(findings),
            "loc": metrics.get("loc"),
            "exit_code": proc.returncode,
            "errors": len(doc.get("errors") or []),
        }
    )
    return findings, status

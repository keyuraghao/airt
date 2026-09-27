"""SARIF 2.1.0 output for a code review run, suitable for GitHub code scanning upload.

Every result carries a ruleId from the catalogue, a physicalLocation with the file URI and line
region, partialFingerprints (the stable AISRF fingerprint) and taxonomy properties.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from .. import __version__
from ..taxonomy import OWASP_LLM_TOP10
from .rules import RULES_BY_ID

LEVELS = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}
SECURITY_SEVERITY = {"CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.5", "LOW": "3.0", "INFO": "1.0"}


def _rule_entry(f: dict[str, Any]) -> dict[str, Any]:
    rid = str(f.get("rule_id") or "AISRF-UNKNOWN")
    rule = RULES_BY_ID.get(rid)
    severity = str(f.get("severity") or "MEDIUM").upper()
    if rule is not None:
        d = rule.to_dict()
        help_text = "\n".join(
            [
                d["description"],
                "",
                "Why it matters: " + d["why"],
                "",
                "Remediation:",
                *[f"- {s}" for s in d["remediation"]],
            ]
        )
        return {
            "id": rid,
            "name": "".join(w.capitalize() for w in rule.title.replace("-", " ").split()),
            "shortDescription": {"text": rule.title},
            "fullDescription": {"text": d["description"]},
            "help": {"text": help_text, "markdown": help_text},
            "helpUri": d["references"][0] if d["references"] else "https://genai.owasp.org/llm-top-10/",
            "defaultConfiguration": {"level": LEVELS.get(rule.severity, "warning")},
            "properties": {
                "tags": [
                    "security",
                    "llm",
                    rule.pack,
                    *[f"owasp-{o.lower()}" for o in d["owasp"]],
                    *([f"external/cwe/{d['cwe'].lower()}"] if d["cwe"] else []),
                ],
                "precision": "high"
                if rule.confidence >= 0.7
                else ("medium" if rule.confidence >= 0.45 else "low"),
                "security-severity": SECURITY_SEVERITY.get(rule.severity, "5.5"),
                "pack": rule.pack,
                "owasp": d["owasp"],
                "cwe": d["cwe"],
            },
        }
    text = str(f.get("description") or f.get("title") or rid)
    return {
        "id": rid,
        "name": rid.replace("-", ""),
        "shortDescription": {"text": str(f.get("title") or rid)[:200]},
        "fullDescription": {"text": text},
        "help": {"text": (f.get("remediation") or text) or rid},
        "defaultConfiguration": {"level": LEVELS.get(severity, "warning")},
        "properties": {
            "tags": ["security", "llm", str(f.get("pack") or "general"), str(f.get("engine") or "")],
            "precision": "medium",
            "security-severity": SECURITY_SEVERITY.get(severity, "5.5"),
            "pack": f.get("pack"),
            "owasp": list(f.get("owasp") or []),
            "cwe": f.get("cwe") or "",
        },
    }


def sarif_document(
    run: dict[str, Any], findings: list[dict[str, Any]], *, include_dismissed: bool = False
) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for f in findings:
        status = str(f.get("status") or "open")
        if status != "open" and not include_dismissed:
            continue
        rid = str(f.get("rule_id") or "AISRF-UNKNOWN")
        if rid not in rules:
            rules[rid] = _rule_entry(f)
        severity = str(f.get("severity") or "MEDIUM").upper()
        path = str(f.get("file") or "").replace("\\", "/") or "unknown"
        start = max(1, int(f.get("line_start") or 1))
        end = max(start, int(f.get("line_end") or start))
        message = str(f.get("title") or rid)
        if f.get("description"):
            message = f"{message}: {str(f['description']).split(chr(10))[0]}"
        result: dict[str, Any] = {
            "ruleId": rid,
            "ruleIndex": list(rules).index(rid),
            "level": LEVELS.get(severity, "warning"),
            "message": {"text": message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": path, "uriBaseId": "%SRCROOT%"},
                        "region": {"startLine": start, "endLine": end, "startColumn": 1},
                    }
                }
            ],
            "partialFingerprints": {
                "aisrf/v1": str(f.get("fingerprint") or ""),
                "primaryLocationLineHash": f"{path}:{start}",
            },
            "properties": {
                "severity": severity,
                "confidence": f.get("confidence"),
                "engine": f.get("engine"),
                "pack": f.get("pack"),
                "owasp": list(f.get("owasp") or []),
                "cwe": f.get("cwe") or "",
                "status": status,
                "fingerprint": f.get("fingerprint"),
            },
        }
        if f.get("snippet"):
            result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
                "text": str(f["snippet"])[:2000]
            }
            result["message"]["markdown"] = f"{message}\n\n```\n{str(f['snippet'])[:600]}\n```"
        if status != "open":
            result["suppressions"] = [
                {
                    "kind": "external",
                    "status": "accepted",
                    "justification": str(f.get("reviewer_note") or status),
                }
            ]
        if f.get("remediation"):
            result["fixes"] = [{"description": {"text": str(f["remediation"])[:1000]}}]
        results.append(result)
    finished = run.get("finished_at") or run.get("created_at") or datetime.now(UTC).isoformat()
    taxa = [
        {
            "id": oid,
            "name": info["name"],
            "shortDescription": {"text": info["description"]},
            "helpUri": info["url"],
        }
        for oid, info in OWASP_LLM_TOP10.items()
    ]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AISRF Code Review",
                        "fullName": "AISRF AI Security & Research Framework, code review module",
                        "version": __version__,
                        "semanticVersion": __version__,
                        "informationUri": "https://genai.owasp.org/llm-top-10/",
                        "rules": list(rules.values()),
                        "supportedTaxonomies": [{"name": "OWASP LLM Top 10 2025"}],
                    }
                },
                "taxonomies": [
                    {
                        "name": "OWASP LLM Top 10 2025",
                        "organization": "OWASP",
                        "shortDescription": {"text": "OWASP Top 10 for LLM Applications 2025"},
                        "taxa": taxa,
                    }
                ],
                "automationDetails": {
                    "id": f"aisrf/codereview/{run.get('id', 'run')}",
                    "description": {"text": str(run.get("name") or "AISRF code review")},
                },
                "invocations": [
                    {
                        "executionSuccessful": str(run.get("status")) == "COMPLETED",
                        "endTimeUtc": str(finished)[:19] + "Z" if "T" in str(finished) else str(finished),
                    }
                ],
                "originalUriBaseIds": {
                    "%SRCROOT%": {
                        "uri": "file:///",
                        "description": {"text": "Root of the reviewed source tree"},
                    }
                },
                "versionControlProvenance": (
                    [
                        {
                            "repositoryUri": run.get("source_ref"),
                            "revisionId": ((run.get("inventory") or {}).get("intake") or {}).get(
                                "commit", ""
                            ),
                        }
                    ]
                    if run.get("source_type") == "git"
                    else []
                ),
                "results": results,
                "properties": {
                    "run_id": run.get("id"),
                    "name": run.get("name"),
                    "source_type": run.get("source_type"),
                    "source_ref": run.get("source_ref"),
                    "risk_score": (run.get("summary") or {}).get("risk_score"),
                    "files": run.get("file_count"),
                    "loc": run.get("loc"),
                },
            }
        ],
    }


def render_sarif(run: dict[str, Any], findings: list[dict[str, Any]], **kw: Any) -> bytes:
    return json.dumps(sarif_document(run, findings, **kw), indent=2, default=str).encode("utf-8")

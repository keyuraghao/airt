"""Optional LLM-assisted review pass.

Sends secret-masked, size-bounded excerpts of the highest-signal files to the configured judge
model with a fixed rubric and turns its JSON answer into findings tagged engine=llm. Everything
here is best effort: any failure is recorded in the engine status and never fails the run.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any

import httpx

from ...config import get_settings
from ...logging import get_logger
from ...taxonomy import owasp_ids
from ..findings import SEVERITIES, Finding
from ..inventory import SourceFile
from ..rules import PACK_CODES
from ..rules.base import FileContext
from ..secrets import mask_secrets

log = get_logger("aisrf.codereview.llm")
PACK_CATEGORY = {
    "prompt_injection": "prompt_injection",
    "agent_tool_abuse": "tool_abuse",
    "llm_output": "output_handling",
    "model_supply_chain": "supply_chain",
    "rag_poisoning_exfil": "rag_poisoning",
    "general": "code_safety",
}
RUBRIC = """You are a senior application security reviewer specialising in LLM-integrated software.
Review the file excerpt below for these classes of weakness and nothing else:
1. prompt_injection: untrusted text (users, requests, documents, tool results, history) reaching prompts or the system role without isolation.
2. agent_tool_abuse: tools that execute shell, code, SQL, file or network operations from model-controlled arguments; destructive tools without confirmation; unbounded agent loops; dynamic dispatch by model-supplied names.
3. llm_output: model output rendered as HTML, executed, used in SQL, paths, redirects or parsed without validation.
4. model_supply_chain: unsafe deserialisation of model files, trust_remote_code, unpinned revisions or dependencies, unverified or plaintext downloads, public buckets.
5. rag_poisoning_exfil: unsanitised ingestion, retrieval without tenant scoping, user-controlled filters, unauthenticated vector stores, markdown exfiltration, logging or caching of prompts, shared memory.
6. general: hardcoded credentials, debug exposure, permissive CORS, missing rate limits or token limits, disabled TLS verification.
Respond with a JSON array only. Each element: {"pack": one of the six names, "title": short title, "severity": CRITICAL|HIGH|MEDIUM|LOW|INFO, "confidence": 0.0-1.0, "line_start": int, "line_end": int, "description": one or two sentences citing the code, "remediation": one or two concrete steps}.
Report only concrete weaknesses visible in the excerpt. If there is nothing to report, respond with [].
"""


def _pick_files(files: list[SourceFile], findings: list[Finding], max_files: int) -> list[SourceFile]:
    per_file: dict[str, int] = {}
    for f in findings:
        per_file[f.file] = per_file.get(f.file, 0) + 1
    scored: list[tuple[float, SourceFile]] = []
    for sf in files:
        if not sf.is_text or sf.language not in ("python", "javascript", "typescript", "vue", "svelte", "java", "go", "csharp", "ruby", "php", "kotlin", "swift", "rust"):
            continue
        text = sf.read_text()
        if not text.strip():
            continue
        ctx = FileContext(sf.path, sf.language, text)
        score = per_file.get(sf.path, 0) * 2.0 + len(ctx.flags & {"ai", "tool", "rag", "agent", "mcp", "route"}) * 1.5
        if score <= 0:
            continue
        scored.append((score, sf))
    scored.sort(key=lambda t: (-t[0], t[1].path))
    return [sf for _, sf in scored[:max_files]]


def _excerpt(text: str, max_chars: int) -> str:
    masked = mask_secrets(text)
    if len(masked) > max_chars:
        masked = masked[:max_chars] + "\n# [truncated]"
    return "\n".join(f"{i:5d}| {line}" for i, line in enumerate(masked.splitlines(), start=1))


def parse_response(content: str) -> list[dict[str, Any]]:
    """Extract the JSON array from a model answer, tolerating code fences and surrounding prose."""
    text = content.strip()
    fence = re.search(r"```(?:json)?\s*(\[.*?\])\s*```", text, re.S)
    if fence:
        text = fence.group(1)
    start, end = text.find("["), text.rfind("]")
    if start < 0 or end <= start:
        return []
    try:
        data = json.loads(text[start : end + 1])
    except ValueError:
        return []
    return [d for d in data if isinstance(d, dict)] if isinstance(data, list) else []


def to_findings(items: list[dict[str, Any]], path: str, language: str, lines: list[str], default_confidence: float) -> list[Finding]:
    out: list[Finding] = []
    for item in items[:20]:
        pack = str(item.get("pack") or "general").strip().lower()
        if pack not in PACK_CODES:
            pack = "general"
        severity = str(item.get("severity") or "MEDIUM").upper()
        if severity not in SEVERITIES:
            severity = "MEDIUM"
        try:
            start = max(1, int(item.get("line_start") or 1))
            end = max(start, int(item.get("line_end") or start))
        except (TypeError, ValueError):
            start = end = 1
        try:
            conf = float(item.get("confidence") if item.get("confidence") is not None else default_confidence)
        except (TypeError, ValueError):
            conf = default_confidence
        conf = min(conf, default_confidence)
        snippet = "\n".join(lines[start - 1 : min(end, start + 7)]) if lines else ""
        category = PACK_CATEGORY[pack]
        out.append(
            Finding(
                rule_id=f"AISRF-LLM-{PACK_CODES[pack]}",
                pack=pack,
                engine="llm",
                severity=severity,
                confidence=conf,
                title=str(item.get("title") or "LLM-assisted finding")[:200],
                description=str(item.get("description") or ""),
                remediation=str(item.get("remediation") or ""),
                file=path,
                line_start=start,
                line_end=end,
                snippet=snippet,
                language=language,
                owasp=owasp_ids(category),
                cwe="",
                category=category,
                metadata={"reviewer": "llm"},
            )
        )
    return out


async def _ask(client: httpx.AsyncClient, provider: str, base_url: str, api_key: str, model: str, prompt: str, timeout: float) -> str:
    if provider == "anthropic":
        url = base_url.rstrip("/") + "/v1/messages"
        headers = {"x-api-key": api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"}
        body = {"model": model, "max_tokens": 2000, "temperature": 0, "system": RUBRIC, "messages": [{"role": "user", "content": prompt}]}
        r = await client.post(url, headers=headers, json=body, timeout=timeout)
        r.raise_for_status()
        data = r.json()
        return "".join(part.get("text", "") for part in data.get("content") or [] if isinstance(part, dict))
    url = base_url.rstrip("/") + "/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}", "content-type": "application/json"}
    body = {"model": model, "temperature": 0, "max_tokens": 2000, "messages": [{"role": "system", "content": RUBRIC}, {"role": "user", "content": prompt}]}
    r = await client.post(url, headers=headers, json=body, timeout=timeout)
    r.raise_for_status()
    data = r.json()
    choices = data.get("choices") or []
    return str(((choices[0].get("message") or {}).get("content")) if choices else "") or ""


def enabled(cfg: dict[str, Any]) -> bool:
    return bool(get_settings().enable_llm_judge or (cfg.get("llm_review") or {}).get("enabled"))


async def run_llm_review(
    files: list[SourceFile],
    findings: list[Finding],
    cfg: dict[str, Any],
    *,
    should_stop: Callable[[], bool] | None = None,
    client: httpx.AsyncClient | None = None,
) -> tuple[list[Finding], dict[str, Any]]:
    settings = get_settings()
    opts = cfg.get("llm_review") or {}
    status: dict[str, Any] = {"engine": "llm", "available": enabled(cfg), "findings": 0, "files": 0, "errors": 0}
    if not status["available"]:
        status["error"] = "LLM-assisted review is disabled"
        return [], status
    api_key = settings.judge_api_key or ""
    provider = (settings.judge_provider or "openai").lower()
    base_url = settings.judge_base_url or ("https://api.anthropic.com" if provider == "anthropic" else "https://api.openai.com/v1")
    if not api_key:
        status["error"] = "judge_api_key is not configured"
        return [], status
    max_files = int(opts.get("max_files") or 12)
    max_chars = int(opts.get("max_chars_per_file") or 6000)
    default_conf = float(opts.get("confidence") or 0.45)
    timeout = float(opts.get("timeout_seconds") or 60)
    chosen = _pick_files(files, findings, max_files)
    out: list[Finding] = []
    own_client = client is None
    client = client or httpx.AsyncClient()
    try:
        for sf in chosen:
            if should_stop and should_stop():
                break
            text = sf.read_text()
            prompt = f"File: {sf.path} (language: {sf.language})\n\n{_excerpt(text, max_chars)}"
            try:
                content = await _ask(client, provider, base_url, api_key, settings.judge_model, prompt, timeout)
                items = parse_response(content)
                out.extend(to_findings(items, sf.path, sf.language, text.splitlines(), default_conf))
                status["files"] += 1
            except Exception as exc:
                status["errors"] += 1
                log.warning("codereview.llm.error", file=sf.path, error=f"{type(exc).__name__}: {str(exc)[:200]}")
    finally:
        if own_client:
            await client.aclose()
    status["findings"] = len(out)
    return out, status

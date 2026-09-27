"""Tool/function abuse detection: dangerous tools, argument injection, path traversal and SSRF targets in tool calls."""
from __future__ import annotations

import re
from typing import Any

from ...analysis.base import Finding, Severity
from .common import (
    Signature,
    compile_signatures,
    iter_messages,
    iter_tools,
    make_finding,
    normalize_text,
    safe_text,
    severity_from_weight,
    snippet,
)

NAME = "tool_abuse"

# Dangerous tool names / capabilities inferred from the tool name or description.
_DANGEROUS_TOOL_ROWS: list[tuple[str, float, str, str]] = [
    (r"\b(?:shell|bash|sh|zsh|cmd|powershell|pwsh|terminal|console|command[_\s]?(?:line|exec|runner)?|exec(?:ute)?(?:_command|_code|_shell)?|run[_\s]?(?:command|shell|code|script|bash|os)|os[_\s]?system|subprocess|spawn|system[_\s]?call|eval|evaluate[_\s]?code|python[_\s]?exec|code[_\s]?(?:exec|interpreter|runner))\b", 0.8, "Code/shell execution tool", "exec"),
    (r"\b(?:delete|remove|rm|drop|destroy|purge|wipe|truncate|erase|unlink|rmdir|del)[_\s]?(?:file|files|dir|directory|folder|table|database|record|all|everything)?\b", 0.65, "Destructive operation tool", "destructive"),
    (r"\b(?:write|create|save|put|upload|modify|edit|overwrite|append|patch)[_\s]?(?:file|files|to[_\s]?disk|filesystem)\b", 0.5, "Filesystem write tool", "fs"),
    (r"\b(?:read|open|cat|load|fetch|get|download)[_\s]?(?:file|files|filesystem|from[_\s]?disk)\b", 0.4, "Filesystem read tool", "fs"),
    (r"\b(?:send|dispatch)[_\s]?(?:email|mail|sms|message|text|notification)\b", 0.5, "Messaging tool", "comms"),
    (r"\b(?:transfer|send|wire|withdraw|pay|payment|move|charge)[_\s]?(?:funds?|money|payment|crypto|bitcoin|balance|cash)\b", 0.85, "Financial transaction tool", "finance"),
    (r"\b(?:sql|query|database|db)[_\s]?(?:query|exec|execute|run|raw|admin)\b", 0.6, "Database query tool", "sql"),
    (r"\b(?:http[_\s]?request|fetch[_\s]?url|web[_\s]?(?:request|fetch|get)|curl|wget|browse|url[_\s]?fetch|requests?[_\s]?(?:get|post)|api[_\s]?call|proxy)\b", 0.5, "Network/HTTP tool", "network"),
    (r"\b(?:sudo|admin|root|privilege|escalate|chmod|chown|setuid)\b", 0.7, "Privilege operation tool", "privilege"),
    (r"\b(?:ssh|scp|rsync|ftp|sftp|remote[_\s]?(?:exec|shell|command))\b", 0.7, "Remote access tool", "remote"),
    (r"\b(?:kubectl|docker|terraform|ansible|aws[_\s]?cli|gcloud|az[_\s]?cli|helm|deploy)\b", 0.6, "Infrastructure tool", "infra"),
    (r"\b(?:browser|selenium|playwright|puppeteer|navigate|click|screenshot)\b", 0.45, "Browser automation tool", "browser"),
]

# Dangerous content inside tool arguments / tool_call text in messages.
_ARG_ROWS: list[tuple[str, float, str, str]] = [
    (r"\brm\s+-rf?\s+(?:--no-preserve-root\s+)?[~/*.]", 0.95, "rm -rf destructive command", "destructive"),
    (r"\b(?::\(\)\s*\{\s*:\|\s*:\s*&\s*\}\s*;\s*:)", 0.95, "Fork bomb", "destructive"),
    (r"\b(?:mkfs|dd\s+if=/dev/(?:zero|random|urandom)|shred|wipefs)\b", 0.9, "Disk wipe command", "destructive"),
    (r">\s*/dev/sd[a-z]\b|\bdd\s+of=/dev/sd", 0.9, "Raw disk write", "destructive"),
    (r"\b(?:curl|wget|fetch)\b[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:bash|sh|zsh|python\d?|perl|ruby|node|pwsh)\b", 0.95, "Pipe download to shell (curl | bash)", "exec"),
    (r"\b(?:bash|sh)\s+-c\s+[\"'].*[\"']|\beval\s*\(|\bexec\s*\(", 0.7, "Inline shell/eval execution", "exec"),
    (r"\b(?:powershell|pwsh)\b[^\n]{0,60}(?:-enc(?:odedcommand)?|-e\s|iex|invoke-expression|downloadstring|-nop|-w\s+hidden)", 0.9, "Obfuscated PowerShell", "exec"),
    (r"\b(?:python\d?|node|perl|ruby)\s+-c\s+[\"']", 0.6, "Inline interpreter command", "exec"),
    (r"\bbase64\s+-d\b[^\n|]{0,60}\|\s*(?:bash|sh|python)", 0.9, "base64 decode piped to shell", "exec"),
    # SQL injection / dangerous SQL
    (r"\b(?:drop|truncate)\s+(?:table|database|schema)\b", 0.85, "Destructive SQL (DROP/TRUNCATE)", "sql"),
    (r"\b(?:delete|update)\s+(?:from\s+)?[\w.`\"]+\s+(?:set\s+[^;]+)?(?:;|$|--|\bwhere\s+(?:1\s*=\s*1|true|'?[a-z0-9]+'?\s*=\s*'?[a-z0-9]+'?\s*(?:;|$)))", 0.7, "DELETE/UPDATE without a real WHERE", "sql"),
    (r"'\s*(?:or|and)\s+'?\d+'?\s*=\s*'?\d+|'\s*or\s+'1'\s*=\s*'1|--\s*$|\bunion\s+(?:all\s+)?select\b|;\s*drop\s+table", 0.85, "SQL injection payload", "sql"),
    (r"\bgrant\s+all\b|\bdrop\s+user\b|\balter\s+user\b[^\n]{0,40}\bsuperuser\b", 0.75, "SQL privilege escalation", "sql"),
    # command / argument injection
    (r"[^&]&&\s*(?:rm|curl|wget|nc|bash|sh|cat\s+/etc|chmod|chown|kill|shutdown|reboot)\b", 0.8, "Command chaining injection (&&)", "injection"),
    (r";\s*(?:rm|curl|wget|nc\b|ncat|bash|sh\s|cat\s+/etc/(?:passwd|shadow)|chmod|chown|kill|shutdown|reboot|whoami|id\b)", 0.8, "Command separator injection (;)", "injection"),
    (r"\|\s*(?:nc\b|ncat|bash|sh\b|python\d?|tee\s+/etc|mail\b)", 0.75, "Pipe to command injection", "injection"),
    (r"\$\([^)]{1,120}\)|`[^`]{1,120}`", 0.65, "Command substitution in argument", "injection"),
    (r"\$\{[A-Za-z_][A-Za-z0-9_]*[:%#/].*?\}", 0.4, "Shell parameter expansion", "injection"),
    (r"\bnc\s+(?:-[a-z]+\s+)*(?:-e|-c)\b|/dev/tcp/\d", 0.9, "Reverse shell (netcat / /dev/tcp)", "injection"),
    (r"\bbash\s+-i\s*>&?\s*/dev/tcp/", 0.95, "Interactive reverse shell", "injection"),
    # path traversal / sensitive files
    (r"(?:\.\./|\.\.\\){2,}|(?:%2e%2e[%2f5c]{1,3}){2,}", 0.8, "Path traversal sequence", "traversal"),
    (r"\b(?:/etc/(?:passwd|shadow|sudoers|hosts)|/root/\.ssh|~/\.ssh/id_|\.aws/credentials|\.env\b|/proc/self/environ|id_rsa|\.ssh/authorized_keys|web\.config|/var/log/)", 0.75, "Access to sensitive path", "traversal"),
    (r"\bfile://(?:/|localhost)", 0.75, "file:// URI in argument", "ssrf"),
    # SSRF targets
    (r"\b(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|fd00:ec2::254)\b", 0.9, "Cloud metadata endpoint (SSRF)", "ssrf"),
    (r"https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|127\.\d+\.\d+\.\d+)\b", 0.6, "Loopback address in URL (SSRF)", "ssrf"),
    (r"https?://(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b", 0.6, "Private RFC1918 address in URL (SSRF)", "ssrf"),
    (r"https?://(?:[\w.-]+\.)?(?:internal|intranet|corp|local|localdomain|svc\.cluster\.local)\b", 0.55, "Internal hostname in URL (SSRF)", "ssrf"),
    (r"\b(?:gopher|dict|ldap|tftp)://", 0.7, "Uncommon SSRF-prone scheme", "ssrf"),
]

# Instructions telling the model to call a tool with attacker-supplied arguments.
_INSTRUCT_ROWS: list[tuple[str, float, str, str]] = [
    (r"\b(?:call|invoke|use|run|execute|trigger|fire)\s+(?:the\s+)?(?:\w+\s+)?(?:tool|function|api|command|action)\s+(?:with|passing|using)\s+(?:these\s+|the\s+following\s+|this\s+)?(?:arguments?|args|parameters?|params|input|payload)\b", 0.6, "Instruct model to call tool with supplied args", "instruct"),
    (r"\b(?:you\s+(?:must|should|need\s+to|have\s+to)|please)\s+(?:call|invoke|run|execute|use)\s+(?:the\s+)?\w+(?:_\w+)*\s*\(", 0.55, "Directed tool invocation", "instruct"),
    (r"\bwithout\s+(?:asking|confirming|checking\s+with|telling)\s+(?:the\s+)?(?:user|human|operator)\b[^.\n]{0,60}\b(?:call|run|execute|invoke|use|delete|send|transfer)", 0.75, "Tool call without confirmation", "instruct"),
    (r"\b(?:automatically|silently|immediately)\s+(?:call|run|execute|invoke|trigger)\s+(?:the\s+)?\w+", 0.6, "Silent automatic tool call", "instruct"),
]

DANGEROUS_TOOLS: list[Signature] = compile_signatures(_DANGEROUS_TOOL_ROWS)
ARG_SIGS: list[Signature] = compile_signatures(_ARG_ROWS)
INSTRUCT_SIGS: list[Signature] = compile_signatures(_INSTRUCT_ROWS)

_TOOLCALL_RE = re.compile(r"\[tool_(?:call|use)\b[^\]]*\][^\n]*|\"(?:arguments|input|parameters)\"\s*:\s*\{[^}]*\}", re.IGNORECASE)
_MAX = 6


class ToolAbuseAnalyzer:
    name = NAME
    description = "Inspects declared tools and tool-call arguments for dangerous capabilities, command/SQL injection, path traversal and SSRF targets."

    def analyze(self, normalized: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        # 1. declared tools
        for location, tname, tdesc in iter_tools(normalized):
            blob = normalize_text(f"{tname} {tdesc}")
            if not blob:
                continue
            best: dict[str, tuple[Signature, str]] = {}
            for sig in DANGEROUS_TOOLS:
                m = sig.regex.search(blob)
                if m and sig.tag not in best:
                    best[sig.tag] = (sig, snippet(blob, m.start(), m.end()))
            for sig, ev in list(best.values())[:_MAX]:
                findings.append(
                    make_finding(
                        NAME, "tool_abuse", severity_from_weight(sig.weight),
                        f"Sensitive tool available: {tname[:60] or sig.label}",
                        f"The declared tool exposes a {sig.tag} capability ({sig.label}). If reachable by an injected instruction it becomes an attack primitive; review its guardrails and sandboxing.",
                        ev, location, sig.weight * 0.75, tags=["tool_declared", sig.tag],
                        metadata={"tool_name": tname, "capability": sig.tag},
                    )
                )
        # 2. arguments and instructions inside messages
        for location, role, raw in iter_messages(normalized):
            if role == "system":
                continue
            text = normalize_text(raw)
            if not text:
                continue
            has_toolcall = bool(_TOOLCALL_RE.search(raw))
            seen: set[str] = set()
            arg_hits: list[tuple[Signature, str]] = []
            for sig in ARG_SIGS:
                m = sig.regex.search(text)
                if m and sig.label not in seen:
                    seen.add(sig.label)
                    arg_hits.append((sig, snippet(text, m.start(), m.end())))
            arg_hits.sort(key=lambda h: h[0].weight, reverse=True)
            for sig, ev in arg_hits[:_MAX]:
                bump = 1 if has_toolcall else 0
                findings.append(
                    make_finding(
                        NAME, "tool_abuse", severity_from_weight(sig.weight, bump), sig.label,
                        f"A dangerous argument pattern ('{sig.tag}') appears in {'a tool call' if has_toolcall else 'message content'}. It can drive command execution, SQL damage, path traversal or SSRF.",
                        ev, location, sig.weight * (0.9 if has_toolcall else 0.8),
                        tags=[sig.tag] + (["tool_call"] if has_toolcall else []),
                        metadata={"role": role, "in_tool_call": has_toolcall, "weight": sig.weight},
                    )
                )
            for sig in INSTRUCT_SIGS:
                m = sig.regex.search(text)
                if m:
                    findings.append(
                        make_finding(
                            NAME, "tool_abuse", severity_from_weight(sig.weight), sig.label,
                            "The message instructs the model to invoke tools, possibly with attacker-controlled arguments or without user confirmation.",
                            snippet(text, m.start(), m.end()), location, sig.weight * 0.8,
                            tags=["instruct", sig.tag], metadata={"role": role, "weight": sig.weight},
                        )
                    )
                    break
        return findings


analyzer = ToolAbuseAnalyzer()

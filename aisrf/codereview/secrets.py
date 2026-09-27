"""Secret masking and credential redaction used everywhere a snippet, URL or log line leaves the engine."""

from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit

# Provider key shapes that are safe to recognise by prefix. Kept deliberately broad: a false
# mask only hides a few characters, a missed one leaks a credential into reports.
KEY_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"sk-(?:proj-|ant-(?:api\d{2}-)?|or-v1-)?[A-Za-z0-9_\-]{16,}"),
    re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}"),
    re.compile(r"\bhf_[A-Za-z0-9]{20,}"),
    re.compile(r"\bgsk_[A-Za-z0-9]{20,}"),
    re.compile(r"\bxai-[A-Za-z0-9]{20,}"),
    re.compile(r"\br8_[A-Za-z0-9]{20,}"),
    re.compile(r"\bpcsk_[A-Za-z0-9_\-]{20,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"),
    re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}"),
    re.compile(r"\bey[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{10,}"),  # JWT
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
]
ASSIGNMENT = re.compile(
    r"(?i)\b((?:api[_\-]?key|apikey|secret[_\-]?key|access[_\-]?token|auth[_\-]?token|token|password|passwd|pwd|secret|client[_\-]?secret|private[_\-]?key)\s*[:=]\s*['\"]?)([^'\"\s,;)]{6,})"
)
URL_CREDENTIALS = re.compile(r"(?i)(https?://)([^/@\s:]+)(:[^/@\s]*)?@")
MASK = "[masked]"


def _mask_value(value: str) -> str:
    if len(value) <= 8:
        return MASK
    return value[:4] + "..." + MASK


def mask_secrets(text: str) -> str:
    """Replace anything that looks like a credential with a short masked marker."""
    if not text:
        return text
    out = URL_CREDENTIALS.sub(lambda m: f"{m.group(1)}{MASK}@", text)
    for pattern in KEY_PATTERNS:
        out = pattern.sub(lambda m: _mask_value(m.group(0)), out)
    out = ASSIGNMENT.sub(lambda m: m.group(1) + _mask_value(m.group(2)), out)
    return out


def redact_url(url: str) -> str:
    """Strip user info from a URL so it can be stored and logged."""
    if not url:
        return url
    try:
        parts = urlsplit(url)
    except ValueError:
        return URL_CREDENTIALS.sub(lambda m: f"{m.group(1)}{MASK}@", url)
    if not parts.netloc or "@" not in parts.netloc:
        return url
    host = parts.netloc.rsplit("@", 1)[1]
    return urlunsplit((parts.scheme, host, parts.path, parts.query, parts.fragment))


def redact_mapping(data: dict, keys: tuple[str, ...] = ("token", "password", "secret", "key", "credential")) -> dict:
    """Shallow copy of a dict with credential-like keys replaced, for audit details and stored config."""
    out = {}
    for k, v in data.items():
        lowered = str(k).lower()
        if any(s in lowered for s in keys) and lowered not in ("credential_id",):
            out[k] = MASK if v else v
        elif isinstance(v, str) and lowered in ("url", "source_ref", "path"):
            out[k] = redact_url(v)
        elif isinstance(v, dict):
            out[k] = redact_mapping(v, keys)
        else:
            out[k] = v
    return out


def looks_like_secret(value: str) -> bool:
    return any(p.search(value) for p in KEY_PATTERNS)

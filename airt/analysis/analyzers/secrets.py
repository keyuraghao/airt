"""Credential and API key detection with masked evidence. Exposes the pure function scan_secrets(text)."""
from __future__ import annotations

import math
import re
from collections.abc import Callable
from typing import Any

from ...analysis.base import Finding, Severity
from .common import MAX_SCAN_CHARS, iter_messages, make_finding, mask_value, safe_text, snippet

NAME = "secrets"

_PLACEHOLDER_RE = re.compile(
    r"^(?:x+|\*+|\.+|_+|<[^>]*>|\{\{?[^}]*\}\}?|\$\{[^}]*\}|\$[A-Z_]+|your[-_ ]?\w*|my[-_ ]?\w*|example\w*|sample\w*|dummy\w*|test\w*|placeholder|changeme|change[-_]me|password|passwd|secret|redacted|none|null|undefined|true|false|\d{1,3}|\[[^\]]*\]|todo|fixme|n/?a)$",
    re.IGNORECASE,
)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def not_placeholder(v: str) -> bool:
    return len(v) >= 6 and not _PLACEHOLDER_RE.match(v.strip("\"' "))


def high_entropy(v: str, minimum: float = 3.0) -> bool:
    return not_placeholder(v) and shannon_entropy(v) >= minimum


def jwt_ok(v: str) -> bool:
    parts = v.split(".")
    return len(parts) == 3 and parts[0].startswith("eyJ") and len(parts[2]) >= 8


def always(_: str) -> bool:
    return True


# (type, regex, validator, severity, confidence)  group(1) is the secret value when present
_DETECTORS: list[tuple[str, re.Pattern[str], Callable[[str], bool], Severity, float]] = [
    ("private_key_pem", re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----[\s\S]{0,4000}?(?:-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|$)"), always, Severity.CRITICAL, 0.98),
    ("openai_api_key", re.compile(r"\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,})"), always, Severity.CRITICAL, 0.98),
    ("openai_api_key_legacy", re.compile(r"\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{32,})\b"), lambda v: not v.startswith("sk-ant-") and not v.startswith("sk-live") and not v.startswith("sk-test"), Severity.HIGH, 0.8),
    ("anthropic_api_key", re.compile(r"\b(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{20,})"), always, Severity.CRITICAL, 0.98),
    ("aws_access_key_id", re.compile(r"\b((?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16})\b"), always, Severity.CRITICAL, 0.95),
    ("aws_secret_access_key", re.compile(r"(?:aws)?_?(?:secret|sec)_?(?:access)?_?key\s*[=:]\s*[\"']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])", re.IGNORECASE), high_entropy, Severity.CRITICAL, 0.9),
    ("aws_session_token", re.compile(r"(?:aws_session_token|x-amz-security-token)\s*[=:]\s*[\"']?([A-Za-z0-9/+=]{100,})", re.IGNORECASE), always, Severity.HIGH, 0.85),
    ("gcp_api_key", re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b"), always, Severity.CRITICAL, 0.95),
    ("gcp_service_account", re.compile(r"\"type\"\s*:\s*\"service_account\"[\s\S]{0,400}?\"private_key_id\"\s*:\s*\"([a-f0-9]{20,})\""), always, Severity.CRITICAL, 0.95),
    ("google_oauth_client_secret", re.compile(r"\b(GOCSPX-[A-Za-z0-9_\-]{20,})\b"), always, Severity.HIGH, 0.95),
    ("google_oauth_access_token", re.compile(r"\b(ya29\.[A-Za-z0-9_\-]{30,})"), always, Severity.HIGH, 0.9),
    ("github_token", re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,})\b"), always, Severity.CRITICAL, 0.97),
    ("github_fine_grained_pat", re.compile(r"\b(github_pat_[A-Za-z0-9_]{60,})\b"), always, Severity.CRITICAL, 0.97),
    ("gitlab_token", re.compile(r"\b(glpat-[A-Za-z0-9_\-]{20,})\b"), always, Severity.CRITICAL, 0.95),
    ("slack_token", re.compile(r"\b(xox[baprs]-[A-Za-z0-9\-]{10,})\b"), always, Severity.CRITICAL, 0.95),
    ("slack_webhook", re.compile(r"(https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]{20,})"), always, Severity.HIGH, 0.95),
    ("discord_webhook", re.compile(r"(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]{30,})"), always, Severity.HIGH, 0.95),
    ("discord_bot_token", re.compile(r"\b([MN][A-Za-z\d]{23,}\.[\w\-]{6}\.[\w\-]{27,})\b"), always, Severity.HIGH, 0.8),
    ("stripe_secret_key", re.compile(r"\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,})\b"), always, Severity.CRITICAL, 0.97),
    ("stripe_publishable_key", re.compile(r"\b(pk_(?:live|test)_[A-Za-z0-9]{20,})\b"), always, Severity.MEDIUM, 0.9),
    ("twilio_api_key", re.compile(r"\b(SK[a-f0-9]{32})\b"), always, Severity.HIGH, 0.85),
    ("twilio_account_sid", re.compile(r"\b(AC[a-f0-9]{32})\b"), always, Severity.MEDIUM, 0.8),
    ("twilio_auth_token", re.compile(r"twilio[_\-\s]*(?:auth)?[_\-\s]*token\s*[=:]\s*[\"']?([a-f0-9]{32})\b", re.IGNORECASE), always, Severity.HIGH, 0.9),
    ("sendgrid_api_key", re.compile(r"\b(SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,})\b"), always, Severity.CRITICAL, 0.97),
    ("mailgun_api_key", re.compile(r"\b(key-[a-f0-9]{32})\b"), always, Severity.HIGH, 0.85),
    ("mailchimp_api_key", re.compile(r"\b([a-f0-9]{32}-us\d{1,2})\b"), always, Severity.HIGH, 0.9),
    ("huggingface_token", re.compile(r"\b(hf_[A-Za-z0-9]{30,})\b"), always, Severity.HIGH, 0.95),
    ("npm_token", re.compile(r"\b(npm_[A-Za-z0-9]{36})\b"), always, Severity.HIGH, 0.95),
    ("pypi_token", re.compile(r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{30,})"), always, Severity.HIGH, 0.95),
    ("heroku_api_key", re.compile(r"heroku[_\-\s]*(?:api)?[_\-\s]*(?:key|token)\s*[=:]\s*[\"']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", re.IGNORECASE), always, Severity.HIGH, 0.9),
    ("shopify_token", re.compile(r"\b(shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})\b"), always, Severity.HIGH, 0.95),
    ("square_token", re.compile(r"\b(sq0(?:atp|csp)-[A-Za-z0-9_\-]{22,})\b"), always, Severity.HIGH, 0.9),
    ("paypal_braintree_token", re.compile(r"\b(access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32})"), always, Severity.CRITICAL, 0.95),
    ("telegram_bot_token", re.compile(r"\b(\d{8,10}:AA[A-Za-z0-9_\-]{33})\b"), always, Severity.HIGH, 0.9),
    ("azure_storage_connection_string", re.compile(r"(DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{40,})", re.IGNORECASE), always, Severity.CRITICAL, 0.97),
    ("azure_sas_token", re.compile(r"[?&](?:sv=\d{4}-\d{2}-\d{2}&[^\s]*?sig=([A-Za-z0-9%+/=]{20,}))"), always, Severity.HIGH, 0.85),
    ("azure_client_secret", re.compile(r"(?:client_secret|azure_client_secret)\s*[=:]\s*[\"']?([A-Za-z0-9~._\-]{30,})", re.IGNORECASE), high_entropy, Severity.HIGH, 0.8),
    ("kubernetes_service_token", re.compile(r"\b(eyJhbGciOi[A-Za-z0-9_\-]+\.eyJpc3MiOiJrdWJlcm5ldGVz[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)"), always, Severity.CRITICAL, 0.95),
    ("kubeconfig_token", re.compile(r"(?:^|\n)\s*token:\s*([A-Za-z0-9_\-\.]{30,})\s*(?:\n|$)"), high_entropy, Severity.HIGH, 0.7),
    ("jwt", re.compile(r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{8,})\b"), jwt_ok, Severity.HIGH, 0.9),
    ("bearer_token", re.compile(r"\b[Bb]earer\s+([A-Za-z0-9_\-\.=+/]{20,})"), high_entropy, Severity.HIGH, 0.8),
    ("basic_auth_header", re.compile(r"\b[Bb]asic\s+([A-Za-z0-9+/]{16,}={0,2})\b"), high_entropy, Severity.HIGH, 0.7),
    ("authorization_header", re.compile(r"(?:authorization|x-api-key|api[-_]?key|x-auth-token|x-access-token)\s*[:=]\s*[\"']?(?!bearer|basic)([A-Za-z0-9_\-\.=+/]{20,})", re.IGNORECASE), high_entropy, Severity.HIGH, 0.8),
    ("database_url_with_password", re.compile(r"\b((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|amqps|mssql|oracle|jdbc:[a-z]+|ftp|sftp|smb|ldap)://[^\s:/@]+:([^\s@/]{3,})@[^\s]+)", re.IGNORECASE), lambda v: not_placeholder(v), Severity.CRITICAL, 0.95),
    ("url_with_credentials", re.compile(r"\bhttps?://[^\s:/@]{1,64}:([^\s@/]{4,64})@[^\s/]+", re.IGNORECASE), not_placeholder, Severity.HIGH, 0.85),
    ("generic_password_assignment", re.compile(r"(?:password|passwd|pwd|passphrase|pass|secret|db_pass|db_password|root_password|admin_password|user_password)\s*(?:[=:]|\bis\b)\s*[\"']?([^\s\"',;]{6,64})", re.IGNORECASE), not_placeholder, Severity.HIGH, 0.7),
    ("generic_api_key_assignment", re.compile(r"(?:api[_\-]?key|apikey|secret[_\-]?key|access[_\-]?token|auth[_\-]?token|client[_\-]?secret|private[_\-]?key|app[_\-]?secret|signing[_\-]?key|encryption[_\-]?key|master[_\-]?key|consumer[_\-]?secret)\s*[=:]\s*[\"']?([A-Za-z0-9_\-\.=+/]{16,})", re.IGNORECASE), high_entropy, Severity.HIGH, 0.75),
    ("dotenv_dump", re.compile(r"(?:^|\n)\s*(?:[A-Z][A-Z0-9_]{2,}=[^\n]{1,200}\n\s*){3,}[A-Z][A-Z0-9_]{2,}=[^\n]{1,200}"), lambda v: bool(re.search(r"(?:KEY|SECRET|TOKEN|PASS|PWD|CREDENTIAL)", v)), Severity.HIGH, 0.75),
    ("ssh_private_key_content", re.compile(r"\b(b3BlbnNzaC1rZXktdjE[A-Za-z0-9+/=]{40,})"), always, Severity.CRITICAL, 0.95),
    ("pgp_private_key", re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"), always, Severity.CRITICAL, 0.98),
    ("age_secret_key", re.compile(r"\b(AGE-SECRET-KEY-1[A-Z0-9]{50,})\b"), always, Severity.CRITICAL, 0.95),
    ("doppler_token", re.compile(r"\b(dp\.(?:pt|st|ct|sa)\.[A-Za-z0-9]{40,})\b"), always, Severity.HIGH, 0.9),
    ("vault_token", re.compile(r"\b((?:hvs|hvb|s)\.[A-Za-z0-9]{24,})\b"), lambda v: v.startswith("hv"), Severity.CRITICAL, 0.9),
    ("digitalocean_token", re.compile(r"\b(do[po]_v1_[a-f0-9]{64})\b"), always, Severity.CRITICAL, 0.95),
    ("linear_api_key", re.compile(r"\b(lin_api_[A-Za-z0-9]{40})\b"), always, Severity.HIGH, 0.95),
    ("notion_token", re.compile(r"\b((?:secret|ntn)_[A-Za-z0-9]{40,})\b"), always, Severity.HIGH, 0.9),
    ("openrouter_key", re.compile(r"\b(sk-or-v1-[a-f0-9]{64})\b"), always, Severity.CRITICAL, 0.97),
    ("groq_key", re.compile(r"\b(gsk_[A-Za-z0-9]{40,})\b"), always, Severity.HIGH, 0.9),
    ("replicate_token", re.compile(r"\b(r8_[A-Za-z0-9]{36,})\b"), always, Severity.HIGH, 0.9),
    ("cohere_key", re.compile(r"(?:cohere|co_api)[_\-]?(?:api)?[_\-]?key\s*[=:]\s*[\"']?([A-Za-z0-9]{40})\b", re.IGNORECASE), always, Severity.HIGH, 0.85),
    ("mistral_key", re.compile(r"mistral[_\-]?(?:api)?[_\-]?key\s*[=:]\s*[\"']?([A-Za-z0-9]{32})\b", re.IGNORECASE), always, Severity.HIGH, 0.85),
    ("pinecone_key", re.compile(r"\b(pcsk_[A-Za-z0-9_]{30,})\b"), always, Severity.HIGH, 0.9),
    ("supabase_service_key", re.compile(r"\b(sbp_[a-f0-9]{40})\b"), always, Severity.HIGH, 0.9),
    ("cloudflare_api_token", re.compile(r"cloudflare[_\-\s]*(?:api)?[_\-\s]*(?:token|key)\s*[=:]\s*[\"']?([A-Za-z0-9_\-]{37,40})\b", re.IGNORECASE), always, Severity.HIGH, 0.85),
    ("datadog_api_key", re.compile(r"(?:dd|datadog)[_\-]?(?:api|app)[_\-]?key\s*[=:]\s*[\"']?([a-f0-9]{32,40})\b", re.IGNORECASE), always, Severity.HIGH, 0.85),
    ("newrelic_key", re.compile(r"\b(NRAK-[A-Z0-9]{27})\b"), always, Severity.HIGH, 0.9),
    ("sentry_dsn", re.compile(r"(https://[a-f0-9]{32}@[a-z0-9.\-]+\.ingest\.sentry\.io/\d+)"), always, Severity.MEDIUM, 0.9),
    ("facebook_access_token", re.compile(r"\b(EAA[A-Za-z0-9]{60,})\b"), always, Severity.HIGH, 0.8),
    ("square_oauth_secret", re.compile(r"\b(sq0csp-[A-Za-z0-9_\-]{43})\b"), always, Severity.HIGH, 0.9),
    ("dropbox_token", re.compile(r"\b(sl\.[A-Za-z0-9_\-]{100,})"), always, Severity.HIGH, 0.85),
    ("atlassian_token", re.compile(r"\b(ATATT3[A-Za-z0-9_\-=]{50,})"), always, Severity.HIGH, 0.9),
    ("docker_auth", re.compile(r"\"auth\"\s*:\s*\"([A-Za-z0-9+/]{20,}={0,2})\""), always, Severity.HIGH, 0.85),
    ("wireguard_private_key", re.compile(r"PrivateKey\s*=\s*([A-Za-z0-9+/]{42,43}=)"), always, Severity.CRITICAL, 0.9),
    ("ssh_password_cli", re.compile(r"\bsshpass\s+-p\s+[\"']?([^\s\"']{4,})"), not_placeholder, Severity.HIGH, 0.9),
    ("mysql_cli_password", re.compile(r"\bmysql\b[^\n]*\s-p([^\s\"']{4,})"), not_placeholder, Severity.HIGH, 0.7),
    ("curl_user_password", re.compile(r"\bcurl\b[^\n]*\s(?:-u|--user)\s+[\"']?[^\s:\"']+:([^\s\"']{4,})"), not_placeholder, Severity.HIGH, 0.85),
    ("generic_hex_secret_assignment", re.compile(r"(?:secret|token|key|hash|salt)\s*[=:]\s*[\"']?([a-f0-9]{40,64})\b", re.IGNORECASE), always, Severity.MEDIUM, 0.6),
]

_MAX_PER_TYPE = 50


def _masked(ptype: str, value: str) -> str:
    v = value.strip()
    if ptype in ("private_key_pem", "pgp_private_key", "gcp_service_account", "dotenv_dump"):
        return v.splitlines()[0][:60] + " ...[masked]"
    if ptype in ("database_url_with_password", "url_with_credentials"):
        return re.sub(r"(://[^:/@]+:)([^@]+)(@)", lambda m: m.group(1) + "****" + m.group(3), v)
    keep = 7 if re.match(r"^(?:sk-ant-|sk-proj|github_pat|xox[baprs]-|sk_live|pk_live|AIza|AKIA|ghp_|gho_|hf_|npm_|glpat|SG\.|GOCSPX)", v) else 4
    return mask_value(v, keep_start=keep, keep_end=2)


def scan_secrets(text: Any) -> list[dict[str, Any]]:
    """Scan text for credentials. Returns [{type, count, samples(masked), severity, confidence, spans}]."""
    s = safe_text(text, MAX_SCAN_CHARS)
    if not s:
        return []
    results: list[dict[str, Any]] = []
    claimed: list[tuple[int, int]] = []
    for ptype, rx, validator, sev, conf in _DETECTORS:
        samples: list[str] = []
        spans: list[tuple[int, int]] = []
        try:
            for m in rx.finditer(s):
                value = m.group(1) if m.lastindex else m.group(0)
                if not value:
                    continue
                try:
                    if not validator(value):
                        continue
                except Exception:
                    continue
                span = (m.start(), m.end())
                if any(a <= span[0] < b or a < span[1] <= b for a, b in claimed):
                    continue
                spans.append(span)
                if len(samples) < 3:
                    samples.append(_masked(ptype, value))
                if len(spans) >= _MAX_PER_TYPE:
                    break
        except Exception:
            continue
        if spans:
            claimed.extend(spans)
            results.append({"type": ptype, "count": len(spans), "samples": samples, "severity": sev, "confidence": conf, "spans": spans})
    return results


def findings_for_text(text: str, location: str, analyzer: str = NAME, category: str = "secrets", suffix: str = "") -> list[Finding]:
    out: list[Finding] = []
    for hit in scan_secrets(text):
        first = hit["spans"][0]
        ev = snippet(text, first[0], first[1], radius=25, mask=hit["samples"][0] if hit["samples"] else "[masked]")
        label = hit["type"].replace("_", " ")
        sev = hit["severity"]
        if hit["count"] >= 3 and sev == Severity.HIGH:
            sev = Severity.CRITICAL
        out.append(
            make_finding(
                analyzer, category, sev, f"{label} exposed{suffix} ({hit['count']})",
                f"{hit['count']} credential(s) of type {label} found. Values are masked in evidence. Credentials in prompts can leak to logs, providers and the model output.",
                ev, location, hit["confidence"], tags=["secret", hit["type"]],
                metadata={"count": hit["count"], "samples": hit["samples"], "type": hit["type"]},
            )
        )
    return out


class SecretsAnalyzer:
    name = NAME
    description = "Detects API keys, cloud credentials, tokens, private keys, JWTs, connection strings and password assignments with masked evidence."

    def analyze(self, normalized: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        for location, role, raw in iter_messages(normalized):
            findings.extend(findings_for_text(raw, location))
        return findings


analyzer = SecretsAnalyzer()

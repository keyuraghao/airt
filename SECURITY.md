# Security policy

AIRT sits in the request path between applications and model providers and holds provider
credentials, so its own security matters. This document covers how to report vulnerabilities and
how to harden a deployment. The threat model and internal controls are in `docs/SECURITY.md`.

## Supported versions

| Version | Supported |
| --- | --- |
| 1.x (main) | yes |
| older | no |

## Reporting a vulnerability

* Email the maintainers (see the repository profile) or use GitHub's private vulnerability
  reporting ("Report a vulnerability" under the Security tab). Do not open a public issue.
* Include: affected version or commit, a minimal reproduction, the impact you believe it has, and
  whether it needs a registered agent key, a reviewer session or no credentials at all.
* We aim to acknowledge reports within 3 business days and to publish a fix or mitigation within
  30 days for high severity issues. We will credit you in the release notes unless you prefer not.
* Please give us a reasonable window before public disclosure, and do not test against
  deployments you do not own.

In scope: authentication and authorisation bypass, agent key or reviewer session leakage,
credential decryption, analyzer bypasses that let a request skip the human hold when policy says
it must not, SSRF through agent upstream configuration, audit chain forgery, injection in the
dashboard, denial of service with a single request.

Out of scope: findings that require a compromised host or database, missed detections by the
heuristic analyzers (please open a regular issue with the sample instead), and issues in
upstream providers.

## Hardening checklist

Before exposing a gateway beyond localhost:

- [ ] Set a strong `AIRT_SECRET_KEY` (48+ random characters) and, ideally, a dedicated
      `AIRT_ENCRYPTION_KEY` so cookie signing and credential encryption use different keys.
- [ ] Change `AIRT_ADMIN_PASSWORD` (a warning is logged while it is `admin`) and create
      individual reviewer accounts with the least role needed (`viewer` < `reviewer` < `admin`).
- [ ] Set `AIRT_ADMIN_API_TOKEN` to a long random value and give it only to the MCP server / CI.
      It carries the admin role.
- [ ] `AIRT_ENVIRONMENT=production` and `AIRT_COOKIE_SECURE=true`; terminate TLS in a reverse
      proxy (see `docs/DEPLOYMENT.md`) and forward `X-Forwarded-For` so tickets record the real
      client IP.
- [ ] Restrict who can reach the reviewer API, dashboard and `/mcp` (network ACL, VPN or the
      reverse proxy). Only `/v1/*`, `/proxy/*` and `/gateway/tickets/*` need to be reachable by
      agents, and they still require an agent key.
- [ ] Give each application its own agent with `allowed_paths`, `allowed_models`, a
      `rate_limit_per_minute` and sensible `auto_deny_at_risk` / `auto_approve_below_risk`
      thresholds. Rotate agent keys (`POST /api/agents/{id}/rotate-key`) when they leak.
- [ ] Keep `require_approval=true` for autonomous agents; use `auto_approve_below_risk` only for
      low risk, well understood traffic.
- [ ] Restrict agent `upstream_base_url` values to the providers you trust; the gateway forwards
      to whatever URL the agent record holds (admins can point it at internal hosts).
- [ ] Use PostgreSQL with TLS for multi-host deployments, back up the database (it holds the
      encrypted upstream keys and the audit chain) and protect the backups.
- [ ] Ship `logs/airt.jsonl` and `logs/agents/*.jsonl` to your SIEM; verify the audit chain
      periodically (`GET /api/audit/verify` or `airt audit verify`).
- [ ] Set `AIRT_TICKET_RETENTION_DAYS` to match your data retention policy: tickets store prompts
      and (truncated) responses, which may contain personal data.
- [ ] Run the container as shipped (non-root user, read-only image, writable volumes only for
      `/app/data` and `/app/logs`).
- [ ] Do not enable the LLM judge with a provider you would not trust with the prompts it will see.

## Cryptography in use

* Reviewer passwords: PBKDF2-HMAC-SHA256, 390k rounds, per-user salt.
* Agent keys: random 256-bit (`airt_` + token_urlsafe(32)); only the SHA-256 hash is stored.
* Session cookies: itsdangerous signed, `HttpOnly`, `SameSite=Lax`, optional `Secure`.
* Upstream provider keys: Fernet (AES-128-CBC + HMAC-SHA256) with `AIRT_ENCRYPTION_KEY` or a key
  derived from `AIRT_SECRET_KEY`.
* Audit log: SHA-256 hash chain over (previous hash, timestamp, actor, action, target, detail).
* Bearer token comparison: constant time (`hmac.compare_digest`).

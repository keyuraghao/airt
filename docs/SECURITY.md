# Security model

This page describes what AIRT protects, how, and what it does not protect. Reporting and the
hardening checklist are in the top-level `SECURITY.md`.

## Threat model

AIRT sits between LLM-powered applications or autonomous agents and the model provider. It assumes:

* the **application or agent is untrusted**: it may be compromised by prompt injection, buggy, or
  operated by someone probing the provider. It only ever holds an AIRT agent key, never a provider
  credential;
* the **reviewers are trusted** but must be authenticated, role limited and audited;
* the **gateway host and database are trusted**; the database holds encrypted credentials and the
  audit chain, and their compromise is out of scope;
* the **provider is trusted** to answer honestly but its responses are treated as data and analysed
  for leaks (system prompt, canaries) before being relayed.

Goals: no outbound model call without a ticket; no ticket forwarded without an approve decision
(human or explicit agent policy); no provider credential reaches the client; every privileged action
leaves a tamper-evident trace.

## Identities and credentials

| Principal | Credential | Storage | Scope |
| --- | --- | --- | --- |
| Agent (client) | `airt_` + 32 random bytes (urlsafe) | SHA-256 hash + 11 char prefix | gateway endpoints and its own tickets |
| Reviewer | username + password | PBKDF2-HMAC-SHA256, 390,000 rounds, 16 byte salt | dashboard and `/api/*` per role |
| Reviewer session | signed cookie `airt_session` (itsdangerous, `AIRT_SECRET_KEY`, salt `airt-session`) | client side, `HttpOnly`, `SameSite=Lax`, `Secure` when `AIRT_COOKIE_SECURE` | `AIRT_SESSION_MAX_AGE_SECONDS` |
| Automation | `AIRT_ADMIN_API_TOKEN` bearer | environment only | admin role on `/api/*` and `/mcp` |
| In-process MCP | per-process random internal token | memory | admin, only via the ASGI transport |
| Upstream provider | agent's `upstream_api_key` | Fernet encrypted (`AIRT_ENCRYPTION_KEY` or derived from `AIRT_SECRET_KEY`) | decrypted only when forwarding |

Roles: `viewer` < `reviewer` < `admin`. Deciding tickets needs `reviewer`; creating agents,
reviewers and rotating keys needs `admin`. Tokens are compared with `hmac.compare_digest`.

## Request path controls

1. Agent key required on every gateway call; unknown or inactive keys get 401 and increment
   `airt_gateway_auth_failures_total`.
2. Per-agent rate limit (sliding window per minute) and body size cap (`AIRT_MAX_REQUEST_BODY_BYTES`).
3. Inbound headers are redacted before storage (`authorization`, `x-api-key`, `x-airt-key`,
   `cookie`, `set-cookie`, `proxy-authorization`, `x-goog-api-key`, `api-key` keep only a 10 char
   prefix).
4. The forwarder strips hop-by-hop headers and every client credential header, then injects the
   stored upstream credential according to the provider. `upstream_extra_headers` from the agent
   record are applied last. The upstream URL is built only from the agent's `upstream_base_url`
   plus the request path; agents cannot redirect traffic to arbitrary hosts (admins configuring
   `upstream_base_url` can, so restrict admin rights).
5. Policy evaluation is deterministic and ordered (see `docs/CONFIGURATION.md`): disabled agent,
   path and model allow-lists, deny regexes, risk auto-deny, mandatory review of CRITICAL secret or
   exfiltration findings, then approve rules. A denied ticket never touches the upstream.
6. Waiting tickets expire (`AIRT_APPROVAL_TIMEOUT_SECONDS`); expired tickets are never forwarded,
   even if approved later (only PENDING tickets can be decided).
7. Response bodies are stored truncated (`AIRT_MAX_STORED_RESPONSE_BYTES`) and analysed by the
   response analyzers (system prompt leak, refusal, canary leak).

## Analysis coverage

Request analyzers: prompt injection (direct overrides, delimiter and role spoofing, multilingual,
indirect injection in tool results), jailbreak families and persona hijack, PII (masked evidence),
secrets (API keys, cloud creds, JWTs, private keys, connection strings), data exfiltration (system
prompt extraction, markdown/image beacons, URL encoding of data), tool abuse (dangerous tools,
command/SQL injection, path traversal, SSRF targets), harmful content lexicons, obfuscation
(base64, hex, rot13, leetspeak, homoglyphs, zero-width, payload splitting), anomaly (role spoofing,
extreme parameters, suspicious models and paths) and the optional LLM judge. Findings map to OWASP
LLM Top 10 (2025), the Greshake et al. indirect injection taxonomy and Thacker's primer
(`airt/taxonomy.py`).

Analyzers are heuristics. They prioritise the reviewer's attention and drive the auto-deny
threshold; they are not a guarantee, which is why the default policy keeps a human in the loop.

## Audit and logging

* `audit_log` is a SHA-256 hash chain: each row hashes `(prev_hash, ts, actor, action, target,
  detail)`. `GET /api/audit/verify` or `airt audit verify` recomputes the chain and reports the
  first broken row. Audited actions include logins (and failures), ticket decisions, agent create /
  update / rotate / disable, reviewer management and campaign lifecycle.
* Ticket timelines (`ticket_events`) and per-agent activity (`agent_events`, `logs/agents/*.jsonl`)
  give the operational trail; `logs/airt.jsonl` holds every service log line with the request id.
* Secrets never appear in logs: headers are redacted, upstream keys are only decrypted in memory,
  audit details replace `upstream_api_key` with `[secret]`.

## Data handling

Tickets store prompts, tool definitions, normalised messages and truncated responses. Treat the
database as sensitive: it may contain personal data and proprietary prompts. Use
`AIRT_TICKET_RETENTION_DAYS` for automatic purging, encrypt volumes and backups, and limit `viewer`
access accordingly.

## Known limitations

* Single-process hold registry: decisions made in other processes are seen on the next DB poll.
* No CSRF token on the JSON API: the session cookie is `SameSite=Lax` and mutating endpoints require
  JSON bodies, which blocks form based CSRF; keep the dashboard on its own origin.
* No built-in TLS: terminate it in a reverse proxy.
* The mitmproxy mode requires clients to trust a private CA; restrict the proxy to development and
  lab networks.
* The LLM judge sends prompt content to the configured judge provider.
* Analyzer bypasses are expected over time; report them with samples so the corpus and rules grow.

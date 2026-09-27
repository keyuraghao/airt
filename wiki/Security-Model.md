# Security model

What AISRF protects, how, and what it does not protect. Vulnerability reporting follows the repository's top-level `SECURITY.md` (private GitHub reporting, no public issues).

## Threat model

Assumptions, from `docs/SECURITY.md` and the code:

* The application or agent is untrusted. It may be compromised by prompt injection, buggy, or operated by someone probing the provider. It only ever holds an AISRF agent key, never a provider credential, and it can only reach the URL an admin configured on its agent record.
* Reviewers are trusted but must be authenticated, role-limited and audited.
* The gateway host and the database are trusted. The database holds Fernet-encrypted provider keys, hashed agent keys, prompts, responses and the audit chain; its compromise is out of scope.
* The provider is trusted to answer honestly, but its responses are treated as data: they are analysed for system prompt leaks, canaries, PII and secrets before being relayed, and can be withheld.

Goals: no outbound model call without a ticket; no ticket forwarded without an approve decision (human, or explicit agent policy); no provider credential reaches the client; every privileged action leaves a tamper-evident trace.

In scope for reports: authentication or authorisation bypass, agent key or session leakage, credential decryption, analyzer bypasses that skip a hold policy says is mandatory, SSRF through agent upstream configuration, audit chain forgery, dashboard injection, single-request denial of service. Out of scope: anything requiring a compromised host or database, missed heuristic detections (open a regular issue with the sample), provider-side issues.

## Secrets handling

| Secret | Generation | Storage | Notes |
| --- | --- | --- | --- |
| Reviewer password | user supplied | `pbkdf2_sha256$390000$<salt b64>$<dk b64>`; 16-byte `os.urandom` salt; verified with `hmac.compare_digest` | `security.hash_password`, `verify_password` |
| Agent key | `aisrf_` + `secrets.token_urlsafe(32)` (256 bits) | SHA-256 hex digest in `agents.api_key_hash`, plus the first 12 characters in `api_key_prefix` | Shown once; rotation replaces the hash |
| Scan token | `aisrf_scan_` + `secrets.token_urlsafe(32)` | SHA-256 in `scan_tokens.token_hash`, with `expires_at` and `revoked` | Minted per scanner run, revoked when the run ends |
| Session cookie `aisrf_session` | `itsdangerous.URLSafeTimedSerializer(secret_key, salt="aisrf-session").dumps({"id": reviewer id})` | Client side only | Verified with `max_age = AISRF_SESSION_MAX_AGE_SECONDS`; the reviewer must still exist and be active |
| Upstream provider key | admin supplied | Fernet token in `agents.upstream_api_key_encrypted` | Decrypted only inside `build_upstream_headers` at forward time; the API exposes `has_upstream_key` only |
| Admin API token | operator supplied (`AISRF_ADMIN_API_TOKEN`) | Environment or settings override | Compared with `hmac.compare_digest`; grants `admin` |
| MCP internal token | `secrets.token_urlsafe(32)` per process at startup | `app.state.internal_token`, memory only | Used by the in-process MCP transport; grants `admin` as `mcp-internal` |
| Integration keys (Lakera) | admin supplied | Plain JSON in `app_settings` | Masked as `********` by the API; protect the database and settings exports |

### Fernet key derivation

`Settings.fernet_key`: when `AISRF_ENCRYPTION_KEY` is set it is used verbatim (it must be a valid urlsafe-base64 32-byte Fernet key). Otherwise the key is `base64.urlsafe_b64encode(sha256("aisrf-fernet:" + AISRF_SECRET_KEY))`. Consequences:

* With the default secret key, every installation derives the same Fernet key, so stored provider keys are only as secret as the database. Set `AISRF_SECRET_KEY` before creating agents.
* Changing `AISRF_SECRET_KEY` later (without a separate `AISRF_ENCRYPTION_KEY`) makes existing ciphertexts undecryptable; `decrypt_secret` returns `None` on `InvalidToken` and the forwarder then sends no credential. Re-enter upstream keys after rotating the secret, or set a dedicated encryption key from the start so the two can be rotated independently.
* Fernet is AES-128-CBC with HMAC-SHA256 and a timestamp; tokens are not bound to the agent id.

### Redaction

Inbound headers are stored on the ticket after `redact_headers()`: `authorization`, `x-api-key`, `x-aisrf-key`, `cookie`, `set-cookie`, `proxy-authorization`, `x-goog-api-key` and `api-key` keep only their first 10 characters followed by `[redacted]`. Audit details for agent updates replace `upstream_api_key` with `[secret]`. The settings schema and export mask any field matching `password`, `secret`, `token`, `api_key` or `_key$`. The Python SDK's `get_config()` masks the agent key. PII analyzer evidence is masked before storage.

## Roles and permissions per endpoint class

Authentication (`aisrf/auth.py`): a request is first checked for a bearer token (`X-AISRF-Admin-Token` or `Authorization: Bearer`) matching `AISRF_ADMIN_API_TOKEN` or the internal token; otherwise the session cookie is read. `current_principal` returns `401 authentication required` when neither works; `require_role(min)` returns `403 role '<min>' required`. Ranking: `viewer` 1, `reviewer` 2, `admin` 3.

| Endpoint class | Minimum role |
| --- | --- |
| `/healthz`, `/readyz`, `/metrics` | none |
| `/v1/*`, `/proxy/*`, `/gateway/tickets/{id}` | agent key or scan token (never a reviewer session); poll only for the owning agent |
| `POST /api/auth/login` | none (failed attempts are audited as `auth.login_failed`) |
| `POST /api/auth/logout`, `GET /api/auth/me` | any authenticated principal |
| `POST /api/auth/reviewers/{id}/password` | self, or admin for others |
| `GET`, `POST`, `DELETE /api/auth/reviewers` | admin |
| `GET /api/tickets`, `/api/tickets/stats`, `/api/tickets/{id}`, `/api/tickets/{id}/events` | viewer |
| `POST /api/tickets/{id}/approve`, `/deny`, `/api/tickets/bulk/*` | reviewer |
| `GET /api/audit`, `/api/audit/verify` | viewer |
| `GET /api/stream/*` | viewer |
| `GET /api/agents`, `/api/agents/{id}`, `/events`, `/stats` | viewer |
| `POST`, `PATCH`, `DELETE /api/agents...`, `/rotate-key` | admin |
| `GET /api/settings/schema`, `/analyzers`, `/guardrails`, `/taxonomy`, `/ns/{ns}` | viewer |
| `PUT /api/settings/core`, `/ns/{ns}`, `POST .../reset`, `/export`, `/import`, `/guardrails/health` | admin |
| Red team campaigns: list and read | viewer; create, start, pause, resume, cancel: reviewer; delete: admin |
| Scanner runs, code review runs, reports | viewer to read and download; reviewer to create and control; admin for deletes and stored credentials |
| `/mcp` | bearer token (`AISRF_ADMIN_API_TOKEN` or the internal token); `401` with `WWW-Authenticate: Bearer realm="aisrf-mcp"` otherwise |
| Dashboard pages | session cookie; pages redirect to `/login` |

Viewers can read prompts, responses, findings and agent configuration (without secrets). Treat the `viewer` role as access to potentially sensitive data.

## Session cookie settings

Set by `POST /api/auth/login`: name `aisrf_session`, `HttpOnly`, `SameSite=Lax`, `Secure` when `AISRF_COOKIE_SECURE=true`, `max_age = AISRF_SESSION_MAX_AGE_SECONDS` (default 43200, 12 hours). The signed payload holds only the reviewer id; deactivating the reviewer invalidates every session immediately because `optional_principal` reloads the row. Logout deletes the cookie client side; the token itself stays valid until its max age, so rotate `AISRF_SECRET_KEY` to invalidate all sessions at once.

CSRF: the JSON API has no CSRF token. Mutating endpoints require JSON bodies and the cookie is `SameSite=Lax`, which blocks classic form posts from other origins; keep the dashboard on its own origin and behind TLS.

## Internal token for MCP

`mount_mcp()` mounts a stateless streamable-HTTP MCP app at `/mcp` behind `BearerGuard`. The tools do not touch the database directly: they call the reviewer REST API over an in-process ASGI transport using `app.state.internal_token`, a random value generated in the lifespan. `_token_principal` accepts that value as `Principal(id="internal", username="mcp-internal", role="admin")`. Externally, clients must present `AISRF_ADMIN_API_TOKEN`; the internal token never leaves the process. `aisrf mcp --url ... --token ...` runs a stdio server that talks to a remote gateway with the admin token. Because both tokens carry `admin`, restrict `/mcp` at the network level and give the admin token only to the MCP host and CI.

## Request path controls

1. Agent key required on every gateway call; failures return `401` and increment `aisrf_gateway_auth_failures_total`.
2. Per-agent rate limit and `AISRF_MAX_REQUEST_BODY_BYTES` before a ticket exists.
3. Headers redacted before storage.
4. The forwarder strips hop-by-hop headers and every client credential header, then injects the stored credential for the configured provider; `upstream_extra_headers` apply last. The upstream URL is built only from the agent's `upstream_base_url` plus the request path, with `follow_redirects=False`, so an agent cannot redirect traffic; an admin configuring `upstream_base_url` can point at internal hosts, which is why admin rights must be restricted.
5. Deterministic, ordered policy ([[Policy-Engine]]); a denied ticket never touches the upstream; CRITICAL secrets or exfiltration findings always require a human.
6. Waiting tickets expire; expired tickets can never be forwarded because only `PENDING` tickets can be decided.
7. Response bodies are stored truncated and analysed; canary leaks and, optionally, CRITICAL response findings withhold the body.

## Production hardening checklist

From the repository `SECURITY.md`:

- Set a strong `AISRF_SECRET_KEY` (48+ random characters) and a dedicated `AISRF_ENCRYPTION_KEY` so cookie signing and credential encryption use different keys.
- Change `AISRF_ADMIN_PASSWORD` and create individual reviewer accounts with the least role needed.
- Set `AISRF_ADMIN_API_TOKEN` to a long random value and give it only to the MCP server and CI; it carries the admin role.
- `AISRF_ENVIRONMENT=production` and `AISRF_COOKIE_SECURE=true`; terminate TLS in a reverse proxy and forward `X-Forwarded-For` so tickets record the real client IP.
- Restrict who can reach the reviewer API, dashboard and `/mcp` (network ACL, VPN or the proxy). Only `/v1/*`, `/proxy/*` and `/gateway/tickets/*` need to be reachable by agents, and they still require an agent key.
- Give each application its own agent with `allowed_paths`, `allowed_models`, a `rate_limit_per_minute` and sensible thresholds; rotate keys when they leak.
- Keep `require_approval=true` for autonomous agents; use `auto_approve_below_risk` only for low-risk, well understood traffic.
- Restrict `upstream_base_url` values to providers you trust.
- Use PostgreSQL with TLS for multi-host deployments; back up the database and protect the backups (encrypted keys and the audit chain live there).
- Ship `logs/aisrf.jsonl` and `logs/agents/*.jsonl` to your SIEM; verify the audit chain periodically and keep the head hash out of band.
- Set `AISRF_TICKET_RETENTION_DAYS` to match your retention policy: tickets store prompts and truncated responses.
- Run the container as shipped (non-root, read-only image, writable volumes only for `/app/data` and `/app/logs`).
- Do not enable the LLM judge with a provider you would not trust with the prompts it will see.

## Known limitations

* Single-process hold registry: decisions made in another process are seen on the next DB poll; the rate limiter and SSE broadcaster are per worker.
* No CSRF token on the JSON API (mitigated by `SameSite=Lax` and JSON-only mutations).
* No built-in TLS; terminate it in a reverse proxy.
* Session tokens cannot be revoked individually before their max age (only by deactivating the reviewer or rotating the secret key).
* The mitmproxy mode requires clients to trust a private CA; keep it to development and lab networks.
* The LLM judge and the Lakera integration send prompt content to third parties.
* Integration API keys in the `integrations` namespace are stored unencrypted in `app_settings`.
* Streams are relayed before the response analyzers can run, so response withholding does not apply to streamed responses.
* Analyzers are heuristics; bypasses are expected over time. Report them with samples so the corpus and rules grow.
* Audit verification cannot detect deletion of the newest rows without an out-of-band record of the head hash.

Related: [[Configuration-Reference]], [[Agents-and-Credentials]], [[Logging-Metrics-and-Audit]], [[Deployment]], [[MCP-Server]].

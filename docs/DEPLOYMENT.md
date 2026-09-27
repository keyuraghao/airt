# Deployment

## Local (uv or pip)

```bash
uv venv .venv --python 3.12 && uv pip install --python .venv/bin/python -e ".[dev]"
# or: python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
cp .env.example .env            # edit AIRT_SECRET_KEY, AIRT_ADMIN_PASSWORD, AIRT_ADMIN_API_TOKEN
.venv/bin/airt init-db          # optional, `airt serve` also creates the schema
.venv/bin/airt serve            # http://0.0.0.0:8080
```

`airt serve --host 127.0.0.1 --port 9000 --workers 1 --reload` overrides `AIRT_HOST`, `AIRT_PORT`,
`AIRT_WORKERS`. `data/` (SQLite) and `logs/` are created in the working directory.

## Docker

```bash
docker build -t airt .
docker run -d --name airt -p 127.0.0.1:8080:8080 --env-file .env \
  -v airt-data:/app/data -v airt-logs:/app/logs airt
docker logs -f airt
```

The image (`Dockerfile`):

* multi-stage on `python:3.12-slim`; the runtime stage contains only the virtualenv and curl;
* runs as the non-root user `airt` (uid 10001);
* `ENTRYPOINT ["airt"]`, `CMD ["serve"]`, so `docker run airt version` or `docker exec airt airt agent list` work;
* `HEALTHCHECK` on `/healthz` every 30 s;
* volumes `/app/data` (SQLite, `AIRT_DATA_DIR`) and `/app/logs` (`AIRT_LOG_DIR`);
* environment defaults: `AIRT_DATABASE_URL=sqlite+aiosqlite:////app/data/airt.db`, `AIRT_LOG_JSON_CONSOLE=true`.

Create the first agent from inside the container (direct DB access):

```bash
docker exec -it airt airt agent create demo --provider openai --upstream-key sk-...
```

## docker compose

```bash
cp .env.example .env
docker compose up -d --build                    # SQLite in the airt-data volume
docker compose --profile postgres up -d --build # plus PostgreSQL 16
```

With the `postgres` profile set `AIRT_DATABASE_URL=postgresql+asyncpg://airt:airt@postgres:5432/airt`
in `.env` (or uncomment the line in `docker-compose.yml`). The compose file publishes the port on
`AIRT_BIND_ADDRESS` (default `127.0.0.1`), so put a reverse proxy in front for external access.

## PostgreSQL

```bash
pip install "airt[postgres]"
export AIRT_DATABASE_URL=postgresql+asyncpg://airt:secret@db.internal:5432/airt?ssl=require
airt init-db
```

Tables are created with `Base.metadata.create_all` on start; there are no migrations yet, so back up
before upgrading. SQLite is fine for a single reviewer team; use PostgreSQL when several services
share the database or when you need point-in-time recovery.

## Reverse proxy and TLS

Terminate TLS in nginx, Caddy or your ingress and forward to the gateway. Requirements:

* long proxy read timeouts on `/v1/`, `/proxy/` and `/gateway/` (synchronous requests block up to
  `AIRT_APPROVAL_TIMEOUT_SECONDS` + `AIRT_UPSTREAM_TIMEOUT_SECONDS`);
* no response buffering on `/api/stream/` (SSE) and on streamed model responses;
* pass `X-Forwarded-For` (tickets record the first address) and `X-Request-ID` if you have one;
* set `AIRT_COOKIE_SECURE=true`, `AIRT_ENVIRONMENT=production` and `AIRT_PUBLIC_URL=https://...`.

nginx example:

```nginx
server {
    listen 443 ssl http2;
    server_name airt.example.com;
    ssl_certificate     /etc/ssl/airt.crt;
    ssl_certificate_key /etc/ssl/airt.key;
    client_max_body_size 8m;
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 600s;
        proxy_send_timeout 600s;
        proxy_buffering off;
        proxy_cache off;
    }
}
```

Caddy: `airt.example.com { reverse_proxy 127.0.0.1:8080 { flush_interval -1 transport http { read_timeout 10m } } }`.

Split exposure if you can: agents only need `/v1/*`, `/proxy/*`, `/gateway/*` and `/healthz`;
reviewers need `/`, `/login`, `/tickets`, ..., `/api/*`, `/mcp`. Both can be served by the same
process behind two virtual hosts or path ACLs.

## Scaling and high availability

* One process is the supported topology (`AIRT_WORKERS=1`). Decisions are delivered to waiting
  requests through an in-process registry; other processes pick them up on DB polling
  (`AIRT_HOLD_POLL_INTERVAL_SECONDS`), and the rate limiter, SSE broadcaster and metrics are per
  process. Run `--workers 2` only if those semantics are acceptable.
* Upstream calls use a shared `httpx.AsyncClient` (200 connections, 50 keep-alive).
* Restarting the gateway drops in-flight synchronous waits: the tickets stay PENDING, then expire
  via the sweeper; clients receive a connection error and should not retry blindly.
* Async mode (`X-AIRT-Async: 1`) survives restarts: tickets are polled by id.

## Backups and retention

Back up the database (agents with encrypted upstream keys, tickets, audit chain) and keep
`AIRT_SECRET_KEY` / `AIRT_ENCRYPTION_KEY` with it; without the key the upstream credentials are
unrecoverable. Tickets older than `AIRT_TICKET_RETENTION_DAYS` are purged automatically; logs rotate
at 50 MB x 10 (`airt.jsonl`) and 20 MB x 5 per agent.

## Monitoring

* `GET /healthz` (liveness), `GET /readyz` (DB check), `GET /metrics` (Prometheus text).
* Alert on `airt_gateway_expired_total` growth (reviewers too slow), `airt_gateway_auth_failures_total`
  (key scanning), `airt_gateway_upstream_errors_total`, and `airt_gateway_wait_seconds_p95`.
* Webhook notifications for new / expired / failed tickets: `AIRT_NOTIFY_WEBHOOK_URLS`.
* Ship `logs/airt.jsonl` and `logs/agents/*.jsonl` (JSON lines) to your log pipeline.

## Upgrading

```bash
git pull && uv pip install --python .venv/bin/python -e ".[dev]"   # or docker compose up -d --build
airt version
```

Schema additions are applied by `create_all` on start; column changes will ship with migrations.
Check `CHANGELOG` / release notes for breaking configuration changes.

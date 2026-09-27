# Deployment

## Local (uv or pip)

```bash
uv venv .venv --python 3.12 && uv pip install --python .venv/bin/python -e ".[dev]"
# or: python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
cp .env.example .env            # edit AISRF_SECRET_KEY, AISRF_ADMIN_PASSWORD, AISRF_ADMIN_API_TOKEN
.venv/bin/aisrf init-db          # optional, `aisrf serve` also creates the schema
.venv/bin/aisrf serve            # http://0.0.0.0:8080
```

`aisrf serve --host 127.0.0.1 --port 9000 --workers 1 --reload` overrides `AISRF_HOST`, `AISRF_PORT`,
`AISRF_WORKERS`. `data/` (SQLite) and `logs/` are created in the working directory.

## Docker

```bash
docker build -t aisrf .
docker run -d --name aisrf -p 127.0.0.1:8080:8080 --env-file .env \
  -v aisrf-data:/app/data -v aisrf-logs:/app/logs aisrf
docker logs -f aisrf
```

The image (`Dockerfile`):

* multi-stage on `python:3.12-slim`; the runtime stage contains only the virtualenv and curl;
* runs as the non-root user `aisrf` (uid 10001);
* `ENTRYPOINT ["aisrf"]`, `CMD ["serve"]`, so `docker run aisrf version` or `docker exec aisrf aisrf agent list` work;
* `HEALTHCHECK` on `/healthz` every 30 s;
* volumes `/app/data` (SQLite, `AISRF_DATA_DIR`) and `/app/logs` (`AISRF_LOG_DIR`);
* environment defaults: `AISRF_DATABASE_URL=sqlite+aiosqlite:////app/data/aisrf.db`, `AISRF_LOG_JSON_CONSOLE=true`.

Create the first agent from inside the container (direct DB access):

```bash
docker exec -it aisrf aisrf agent create demo --provider openai --upstream-key sk-...
```

## docker compose

```bash
cp .env.example .env
docker compose up -d --build                    # SQLite in the aisrf-data volume
docker compose --profile postgres up -d --build # plus PostgreSQL 16
```

With the `postgres` profile set `AISRF_DATABASE_URL=postgresql+asyncpg://aisrf:aisrf@postgres:5432/aisrf`
in `.env` (or uncomment the line in `docker-compose.yml`). The compose file publishes the port on
`AISRF_BIND_ADDRESS` (default `127.0.0.1`), so put a reverse proxy in front for external access.

## PostgreSQL

```bash
pip install "aisrf[postgres]"
export AISRF_DATABASE_URL=postgresql+asyncpg://aisrf:secret@db.internal:5432/aisrf?ssl=require
aisrf init-db
```

Tables are created with `Base.metadata.create_all` on start; there are no migrations yet, so back up
before upgrading. SQLite is fine for a single reviewer team; use PostgreSQL when several services
share the database or when you need point-in-time recovery.

## Reverse proxy and TLS

Terminate TLS in nginx, Caddy or your ingress and forward to the gateway. Requirements:

* long proxy read timeouts on `/v1/`, `/proxy/` and `/gateway/` (synchronous requests block up to
  `AISRF_APPROVAL_TIMEOUT_SECONDS` + `AISRF_UPSTREAM_TIMEOUT_SECONDS`);
* no response buffering on `/api/stream/` (SSE) and on streamed model responses;
* pass `X-Forwarded-For` (tickets record the first address) and `X-Request-ID` if you have one;
* set `AISRF_COOKIE_SECURE=true`, `AISRF_ENVIRONMENT=production` and `AISRF_PUBLIC_URL=https://...`.

nginx example:

```nginx
server {
    listen 443 ssl http2;
    server_name aisrf.example.com;
    ssl_certificate     /etc/ssl/aisrf.crt;
    ssl_certificate_key /etc/ssl/aisrf.key;
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

Caddy: `aisrf.example.com { reverse_proxy 127.0.0.1:8080 { flush_interval -1 transport http { read_timeout 10m } } }`.

Split exposure if you can: agents only need `/v1/*`, `/proxy/*`, `/gateway/*` and `/healthz`;
reviewers need `/`, `/login`, `/tickets`, ..., `/api/*`, `/mcp`. Both can be served by the same
process behind two virtual hosts or path ACLs.

## Scaling and high availability

* One process is the supported topology (`AISRF_WORKERS=1`). Decisions are delivered to waiting
  requests through an in-process registry; other processes pick them up on DB polling
  (`AISRF_HOLD_POLL_INTERVAL_SECONDS`), and the rate limiter, SSE broadcaster and metrics are per
  process. Run `--workers 2` only if those semantics are acceptable.
* Upstream calls use a shared `httpx.AsyncClient` (200 connections, 50 keep-alive).
* Restarting the gateway drops in-flight synchronous waits: the tickets stay PENDING, then expire
  via the sweeper; clients receive a connection error and should not retry blindly.
* Async mode (`X-AISRF-Async: 1`) survives restarts: tickets are polled by id.

## Backups and retention

Back up the database (agents with encrypted upstream keys, tickets, audit chain) and keep
`AISRF_SECRET_KEY` / `AISRF_ENCRYPTION_KEY` with it; without the key the upstream credentials are
unrecoverable. Tickets older than `AISRF_TICKET_RETENTION_DAYS` are purged automatically; logs rotate
at 50 MB x 10 (`aisrf.jsonl`) and 20 MB x 5 per agent.

## Monitoring

* `GET /healthz` (liveness), `GET /readyz` (DB check), `GET /metrics` (Prometheus text).
* Alert on `aisrf_gateway_expired_total` growth (reviewers too slow), `aisrf_gateway_auth_failures_total`
  (key scanning), `aisrf_gateway_upstream_errors_total`, and `aisrf_gateway_wait_seconds_p95`.
* Webhook notifications for new / expired / failed tickets: `AISRF_NOTIFY_WEBHOOK_URLS`.
* Ship `logs/aisrf.jsonl` and `logs/agents/*.jsonl` (JSON lines) to your log pipeline.

## Upgrading

```bash
git pull && uv pip install --python .venv/bin/python -e ".[dev]"   # or docker compose up -d --build
aisrf version
```

Schema additions are applied by `create_all` on start; column changes will ship with migrations.
Check `CHANGELOG` / release notes for breaking configuration changes.

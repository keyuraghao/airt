# Deployment

How to run AISRF as a service: architecture, TLS termination, PostgreSQL, environment hardening, systemd, launchd, Windows services, Kubernetes manifests, the Helm chart, probes, persistence, scaling limits and backups. Installation paths are in [[Installation]]; day-two tasks are in [[Operations-and-Maintenance]].

## Production architecture

One `aisrf serve` process (uvicorn, `AISRF_WORKERS=1`) serves everything: the interception endpoints (`/v1/*`, `/proxy/*`, `/gateway/tickets/*`), the reviewer REST API (`/api/*`), the dashboard (`/`, `/login`, `/tickets`, ...), the MCP endpoint (`/mcp`) and the operational endpoints (`/healthz`, `/readyz`, `/metrics`). State lives in one database (SQLite file or PostgreSQL) plus the log directory. A reverse proxy terminates TLS in front of it.

```
agents / SDKs ----\                                   /---> provider APIs (agent's encrypted key)
                   >--- TLS proxy ---> aisrf serve ---<
reviewers / MCP --/       (nginx, Caddy, ingress)      \---> database (SQLite or PostgreSQL)
                                                        \--> logs/aisrf.jsonl, logs/agents/*.jsonl
```

Split exposure when you can: agents only need `/v1/*`, `/proxy/*`, `/gateway/*` and `/healthz`; reviewers need `/`, `/login`, `/tickets`, the other pages, `/api/*` and `/mcp`. Both can be served by the same process behind two virtual hosts or path ACLs. Agents always authenticate with an agent key, reviewers with a session cookie or the admin bearer token.

Settings that matter for a production process (`.env`, `aisrf.env`, unit file or Secret):

```
AISRF_ENVIRONMENT=production        # JSON console logs
AISRF_HOST=127.0.0.1                # behind a proxy on the same host; 0.0.0.0 in containers
AISRF_PORT=8080
AISRF_SECRET_KEY=<48+ random chars>
AISRF_ENCRYPTION_KEY=<Fernet key>   # optional, decouples credential encryption from the secret key
AISRF_ADMIN_PASSWORD=<random>
AISRF_ADMIN_API_TOKEN=<random>
AISRF_COOKIE_SECURE=true
AISRF_PUBLIC_URL=https://aisrf.example.com
AISRF_LOG_JSON_CONSOLE=true
AISRF_DATABASE_URL=postgresql+asyncpg://aisrf:secret@db.internal:5432/aisrf?ssl=require
```

Generate values with `python3 -c 'import secrets; print(secrets.token_urlsafe(48))'` and `python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`.

## Reverse proxy and TLS

Requirements for whatever sits in front:

- Long read timeouts on `/v1/`, `/proxy/` and `/gateway/`: a synchronous request blocks up to `AISRF_APPROVAL_TIMEOUT_SECONDS` (300) plus `AISRF_UPSTREAM_TIMEOUT_SECONDS` (120). 600 s covers the defaults.
- No response buffering: `/api/stream/tickets`, `/api/stream/logs` and `/api/stream/campaigns` are Server-Sent Events (a `ping` event every 15 s keeps them alive), and approved model responses with `stream: true` are relayed chunk by chunk.
- Forward `X-Forwarded-For` (tickets record the first address as the client IP) and `X-Forwarded-Proto`; pass `X-Request-ID` if you have one, the gateway echoes it and generates one otherwise.
- Body size at least `AISRF_MAX_REQUEST_BODY_BYTES` (4 MiB default); the examples use 8m.
- Set `AISRF_COOKIE_SECURE=true`, `AISRF_ENVIRONMENT=production`, `AISRF_PUBLIC_URL=https://...` on the gateway.

nginx:

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

Caddy (automatic certificates):

```
aisrf.example.com {
    reverse_proxy 127.0.0.1:8080 {
        flush_interval -1
        transport http {
            read_timeout 10m
        }
    }
}
```

`flush_interval -1` disables buffering so SSE and streamed completions pass through immediately. On ingress-nginx use the annotations `nginx.ingress.kubernetes.io/proxy-read-timeout: "600"`, `proxy-send-timeout: "600"`, `proxy-buffering: "off"` and `proxy-body-size: 8m` (already in `deploy/kubernetes/ingress.example.yaml` and the chart defaults).

## PostgreSQL

SQLite (WAL mode, 30 s busy timeout) is fine for a single reviewer team on one host. Use PostgreSQL when several processes share the database, when you want rolling updates or autoscaling in Kubernetes, or when you need point-in-time recovery.

```bash
pip install "aisrf[postgres]"                   # asyncpg; already in the container image
export AISRF_DATABASE_URL="postgresql+asyncpg://aisrf:secret@db.internal:5432/aisrf?ssl=require"
aisrf init-db                                   # creates the tables and the admin reviewer
aisrf serve
```

Create the role and database first (`CREATE ROLE aisrf LOGIN PASSWORD '...'; CREATE DATABASE aisrf OWNER aisrf;`). Tables are created with `Base.metadata.create_all` on start; there are no Alembic migrations yet (Alembic is listed under "Later" in `docs/ROADMAP.md`), so new columns in a release require a fresh table or a manual `ALTER TABLE`. Read the release notes before upgrading.

Migrating from SQLite to PostgreSQL: there is no built-in migration tool. The practical route is to keep the SQLite file as the archive and start PostgreSQL clean:

1. Export what you want to keep: reports (`aisrf report tickets --format json`, `aisrf report audit --format json`), and `GET /api/settings/export` for the runtime settings.
2. Stop the gateway, point `AISRF_DATABASE_URL` at PostgreSQL, run `aisrf init-db`.
3. Recreate agents (`aisrf agent create ...` with the upstream keys; the encrypted keys in SQLite can only be decrypted with the same `AISRF_SECRET_KEY` / `AISRF_ENCRYPTION_KEY`) and reviewers (`aisrf create-reviewer`), then import the settings with `POST /api/settings/import`.
4. Hand out the new agent keys to the applications.

If you must move rows, `pgloader` can copy the SQLite tables (`tickets`, `agents`, `audit_entries`, `app_settings`, ...) into an already initialised PostgreSQL schema; keep the same encryption key so the Fernet blobs stay readable and verify the audit chain afterwards with `aisrf audit verify`.

## Environment hardening

The checklist from `SECURITY.md`, condensed:

- Strong `AISRF_SECRET_KEY` (48+ characters) and ideally a dedicated `AISRF_ENCRYPTION_KEY`.
- Change `AISRF_ADMIN_PASSWORD`; create individual reviewer accounts with the least role (`viewer` < `reviewer` < `admin`).
- `AISRF_ADMIN_API_TOKEN` long and random; it carries the admin role, give it only to the MCP server and CI.
- `AISRF_ENVIRONMENT=production`, `AISRF_COOKIE_SECURE=true`, TLS in front, `X-Forwarded-For` forwarded.
- Restrict the reviewer API, dashboard and `/mcp` by network ACL, VPN or proxy rules.
- One agent per application with `allowed_paths`, `allowed_models`, `rate_limit_per_minute`, `auto_deny_at_risk` and `auto_approve_below_risk`; rotate leaked keys with `POST /api/agents/{id}/rotate-key`.
- Keep `require_approval=true` for autonomous agents; restrict `upstream_base_url` to providers you trust (the gateway forwards to whatever URL the agent record holds).
- PostgreSQL with TLS for multi-host deployments; protected backups.
- Ship `logs/aisrf.jsonl` and `logs/agents/*.jsonl` to the SIEM; verify the audit chain periodically.
- `AISRF_TICKET_RETENTION_DAYS` aligned with the data retention policy (tickets store prompts and truncated responses).
- Run the container as shipped: non-root, read-only root filesystem, writable volumes only for `/app/data` and `/app/logs` (and `/tmp`).
- Do not enable the LLM judge with a provider you would not trust with the prompts.

## Linux: systemd

`deploy/systemd/aisrf.service` runs the binary as the dedicated `aisrf` user with settings in `/etc/aisrf/aisrf.env`, state in `/var/lib/aisrf` and logs in `/var/log/aisrf`. Install steps (`deploy/systemd/README.md`):

```bash
curl -fsSL https://raw.githubusercontent.com/keyuraghao/aisrf/main/scripts/install.sh | sudo bash
sudo useradd --system --home-dir /var/lib/aisrf --shell /usr/sbin/nologin aisrf
sudo install -d -o aisrf -g aisrf -m 0750 /var/lib/aisrf /var/lib/aisrf/data /var/log/aisrf
sudo install -d -o root -g aisrf -m 0750 /etc/aisrf
sudo tee /etc/aisrf/aisrf.env > /dev/null <<ENV
AISRF_ENVIRONMENT=production
AISRF_HOST=127.0.0.1
AISRF_PORT=8080
AISRF_SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')
AISRF_ADMIN_PASSWORD=$(python3 -c 'import secrets; print(secrets.token_urlsafe(18))')
AISRF_ADMIN_API_TOKEN=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')
AISRF_COOKIE_SECURE=true
AISRF_PUBLIC_URL=https://aisrf.example.com
ENV
sudo chown root:aisrf /etc/aisrf/aisrf.env && sudo chmod 0640 /etc/aisrf/aisrf.env
sudo cp deploy/systemd/aisrf.service /etc/systemd/system/aisrf.service
sudo systemctl daemon-reload
sudo systemctl enable --now aisrf
systemctl status aisrf
curl -fsS http://127.0.0.1:8080/healthz
```

Unit walkthrough, directive by directive:

| Directive | Value | Why |
| --- | --- | --- |
| `Description`, `Documentation` | AISRF gateway, repository URL | shown by `systemctl status` |
| `After`, `Wants` | `network-online.target` | start once the network is up |
| `Type` | `simple` | uvicorn stays in the foreground |
| `User`, `Group` | `aisrf` | never root |
| `EnvironmentFile` | `/etc/aisrf/aisrf.env` | all `AISRF_*` settings, mode 0640 root:aisrf |
| `Environment=AISRF_HOME` | `/var/lib/aisrf` | makes the binary keep state there and seed `aisrf.env` under it if keys are missing |
| `Environment=AISRF_DATA_DIR`, `AISRF_LOG_DIR` | `/var/lib/aisrf/data`, `/var/log/aisrf` | explicit paths inside the writable set |
| `Environment=AISRF_DATABASE_URL` | `sqlite+aiosqlite:////var/lib/aisrf/data/aisrf.db` | SQLite default; override with PostgreSQL in the env file (later `EnvironmentFile=` lines win over earlier `Environment=` lines, so move the file line below or delete the SQLite line) |
| `Environment=AISRF_LOG_JSON_CONSOLE` | `true` | JSON lines in the journal |
| `WorkingDirectory` | `/var/lib/aisrf` | relative paths resolve there |
| `ExecStart` | `/usr/local/bin/aisrf serve` | the installer's symlink; pip install: `/opt/aisrf/.venv/bin/aisrf serve` |
| `Restart`, `RestartSec` | `on-failure`, `5s` | supervise crashes, not clean exits |
| `TimeoutStopSec`, `KillSignal` | `30s`, `SIGTERM` | lifespan shutdown closes the sweeper, notifier, runners, HTTP client and DB |
| `NoNewPrivileges` | `true` | no setuid escalation |
| `ProtectSystem` | `strict` | whole filesystem read-only except `ReadWritePaths` |
| `ProtectHome` | `true` | `/home`, `/root`, `/run/user` invisible (install the binary under `/usr/local` or `/opt`, not `/home`) |
| `PrivateTmp`, `PrivateDevices` | `true` | private `/tmp`, no device nodes |
| `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectKernelLogs`, `ProtectControlGroups`, `ProtectClock`, `ProtectHostname` | `true` | kernel and host identity read-only |
| `RestrictRealtime`, `RestrictSUIDSGID`, `RestrictNamespaces`, `LockPersonality` | `true` | no realtime scheduling, setuid files, namespaces or personality changes |
| `MemoryDenyWriteExecute` | `false` | the Python runtime and some wheels need W+X mappings |
| `SystemCallArchitectures` | `native` | no foreign ABI syscalls |
| `SystemCallFilter` | `@system-service`, then `~@privileged @resources` | allowlist for services, minus privileged and resource-limit calls |
| `CapabilityBoundingSet`, `AmbientCapabilities` | empty | zero capabilities |
| `RestrictAddressFamilies` | `AF_INET AF_INET6 AF_UNIX` | TCP for HTTP and PostgreSQL, Unix sockets for local PostgreSQL |
| `ReadWritePaths` | `/var/lib/aisrf /var/log/aisrf` | the only writable locations |
| `StateDirectory`, `LogsDirectory` | `aisrf` | systemd creates `/var/lib/aisrf` and `/var/log/aisrf` with the right owner |
| `UMask` | `0077` | new files private to the service user |
| `WantedBy` | `multi-user.target` | enabled at boot |

Operations: `sudo journalctl -u aisrf -f`, `sudo tail -f /var/log/aisrf/aisrf.jsonl`, `sudo -u aisrf AISRF_HOME=/var/lib/aisrf aisrf agent list`, `sudo systemctl restart aisrf`. Uninstall: `sudo systemctl disable --now aisrf`, remove the unit, `daemon-reload`, delete `/etc/aisrf /var/lib/aisrf /var/log/aisrf /opt/aisrf /usr/local/bin/aisrf`, `sudo userdel aisrf`.

## macOS: launchd

`deploy/launchd/com.aisrf.gateway.plist` runs `/usr/local/bin/aisrf serve --host 127.0.0.1 --port 8080` with `AISRF_ENVIRONMENT=production`, `AISRF_LOG_JSON_CONSOLE=true` and `PATH=/usr/local/bin:/usr/bin:/bin`; `RunAtLoad` true, `KeepAlive` on unsuccessful exit, `ThrottleInterval` 10 s, `ExitTimeOut` 30 s, stdout and stderr to `/tmp/aisrf.launchd.log`, `ProcessType` Background.

Per user (starts at login, runs as you):

```bash
mkdir -p ~/Library/Logs/AISRF
cp deploy/launchd/com.aisrf.gateway.plist ~/Library/LaunchAgents/
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.aisrf.gateway.plist
launchctl kickstart -k gui/$(id -u)/com.aisrf.gateway
launchctl bootout gui/$(id -u)/com.aisrf.gateway      # stop and remove
```

System wide: edit `ProgramArguments`, add `UserName` and the paths, copy to `/Library/LaunchDaemons/` and `sudo launchctl bootstrap system /Library/LaunchDaemons/com.aisrf.gateway.plist`. The binary reads `~/Library/Application Support/AISRF/aisrf.env` (generated on first run); add `AISRF_HOME` under `EnvironmentVariables` to relocate the state. Put Caddy or nginx in front for TLS.

## Windows service

From an elevated PowerShell after `install.ps1`:

```powershell
powershell -ExecutionPolicy Bypass -File deploy\windows\install-service.ps1 [-Port 8080] [-BindHost 127.0.0.1] [-Binary C:\path\aisrf.exe] [-Home C:\ProgramData\AISRF] [-Name AISRF] [-Nssm C:\tools\nssm.exe] [-ForceSc]
powershell -ExecutionPolicy Bypass -File deploy\windows\uninstall-service.ps1 [-PurgeData]
```

What the installer does in both modes: creates `%ProgramData%\AISRF` with `data` and `logs`, sets `AISRF_HOME`, `AISRF_DATA_DIR`, `AISRF_LOG_DIR`, `AISRF_DATABASE_URL=sqlite+aiosqlite:///C:/ProgramData/AISRF/data/aisrf.db`, `AISRF_ENVIRONMENT=production`, `AISRF_LOG_JSON_CONSOLE=true`, `AISRF_HOST`, `AISRF_PORT`, runs `aisrf init-db` once so the binary seeds `aisrf.env` with a random secret key and admin token, restricts `aisrf.env` to `SYSTEM` and `Administrators` with `icacls`, then registers the service, sets recovery to `restart/5000/restart/10000/restart/30000` with `sc.exe failure`, starts it and prints the dashboard URL.

NSSM mode (when `nssm.exe` is on `PATH` or passed with `-Nssm`, recommended): `nssm install AISRF <binary> serve`, `AppDirectory` = home, `Start SERVICE_AUTO_START`, stdout and stderr to `logs\service.out.log` and `logs\service.err.log`, `AppRotateFiles 1`, `AppRotateBytes 52428800` (50 MB), `AppStopMethodConsole 15000`, `AppExit Default Restart`, `AppRestartDelay 5000`, and the `AISRF_*` variables stored in `AppEnvironmentExtra`.

sc.exe mode (no third-party tool, or `-ForceSc`): writes `%ProgramData%\AISRF\aisrf-service.cmd` (sets the variables, `cd` to home, runs `aisrf.exe serve >> logs\service.out.log 2>&1`), registers `sc.exe create AISRF binPath= "cmd.exe /c <wrapper>" start= auto obj= LocalSystem`, sets the description and writes the variables to `HKLM\SYSTEM\CurrentControlSet\Services\AISRF\Environment` (REG_MULTI_SZ) so the SCM injects them. A plain console binary is not a service, hence the wrapper; supervision is looser than with NSSM.

Manage with `Start-Service AISRF`, `Stop-Service AISRF`, `Restart-Service AISRF`. The service binds to `127.0.0.1:8080` by default; `-BindHost 0.0.0.0` exposes it, prefer IIS, nginx or Caddy with TLS in front. The uninstaller stops the service, removes it via NSSM or `sc.exe delete`, deletes the wrapper and, with `-PurgeData`, the whole home directory including the database and `aisrf.env`.

## Kubernetes manifests

`deploy/kubernetes/`, applied in this order:

```bash
kubectl create namespace aisrf
cp deploy/kubernetes/secret.example.yaml secret.yaml       # fill in real values, never commit it
kubectl -n aisrf apply -f secret.yaml -f deploy/kubernetes/pvc.yaml -f deploy/kubernetes/deployment.yaml -f deploy/kubernetes/service.yaml
kubectl -n aisrf apply -f deploy/kubernetes/ingress.example.yaml   # optional, after editing the host
kubectl -n aisrf apply -f deploy/kubernetes/hpa.yaml               # optional, PostgreSQL only
kubectl -n aisrf rollout status deploy/aisrf
kubectl -n aisrf port-forward svc/aisrf 8080:8080
```

- `secret.example.yaml`: Secret `aisrf-env` (type Opaque) with `AISRF_SECRET_KEY`, `AISRF_ADMIN_PASSWORD`, `AISRF_ADMIN_API_TOKEN`; optional `AISRF_DATABASE_URL` (PostgreSQL, needed for more than one replica) and `AISRF_ENCRYPTION_KEY`.
- `pvc.yaml`: PersistentVolumeClaim `aisrf-data`, `ReadWriteOnce`, 5Gi, storage class commented out.
- `deployment.yaml`: Deployment `aisrf`, 1 replica, strategy `Recreate` (the SQLite file must not be opened by two pods), pod security context `runAsNonRoot`, uid/gid/fsGroup 10001, seccomp `RuntimeDefault`; container `ghcr.io/keyuraghao/aisrf:latest` with `args: ["serve"]`, port 8080 named `http`, `envFrom` the Secret, env `AISRF_HOST=0.0.0.0`, `AISRF_PORT=8080`, `AISRF_ENVIRONMENT=production`, `AISRF_DATA_DIR=/app/data`, `AISRF_LOG_DIR=/app/logs`, `AISRF_LOG_JSON_CONSOLE=true`, `AISRF_COOKIE_SECURE=true`, `AISRF_PUBLIC_URL=https://aisrf.example.com`; liveness `GET /healthz` (initial 10 s, period 20 s), readiness `GET /readyz` (initial 5 s, period 10 s); requests 100m CPU and 256Mi, limits 1 CPU and 1Gi; container security context `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, drop all capabilities; mounts the PVC at `/app/data`, emptyDirs at `/app/logs` and `/tmp`.
- `service.yaml`: ClusterIP Service `aisrf`, port 8080 to target port `http`.
- `ingress.example.yaml`: ingress-nginx class, annotations for 600 s read and send timeouts, buffering off, 8m body size, `cert-manager.io/cluster-issuer: letsencrypt`, TLS secret `aisrf-tls`, host `aisrf.example.com`, path `/` Prefix.
- `hpa.yaml`: HorizontalPodAutoscaler 1 to 3 replicas at 75 percent CPU; only meaningful with PostgreSQL.

Upgrade: `kubectl -n aisrf set image deploy/aisrf aisrf=ghcr.io/keyuraghao/aisrf:<version>`. Uninstall: `kubectl delete namespace aisrf` (deletes the PVC and the database).

## Helm chart

`deploy/helm/aisrf/` (Chart `aisrf` 0.1.0, appVersion 1.0.0, Kubernetes >= 1.25). Templates: `deployment.yaml`, `service.yaml`, `serviceaccount.yaml` (`automountServiceAccountToken: false`), `secret.yaml` (only when `existingSecret` is empty; only non-empty `secretEnv` keys plus `AISRF_DATABASE_URL` from `databaseUrl`), `pvc.yaml` (when `persistence.enabled` and no `existingClaim`), `ingress.yaml`, `hpa.yaml`, `NOTES.txt`. The Deployment uses `RollingUpdate` when `databaseUrl` is set and `Recreate` otherwise, annotates the pod with the Secret checksum so a changed secret restarts the pod, and always sets `AISRF_HOST=0.0.0.0`, `AISRF_PORT=8080`, `AISRF_DATA_DIR=/app/data`, `AISRF_LOG_DIR=/app/logs` before the `env` map.

```bash
helm install aisrf deploy/helm/aisrf --namespace aisrf --create-namespace \
  --set secretEnv.AISRF_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')" \
  --set secretEnv.AISRF_ADMIN_PASSWORD=change-me \
  --set secretEnv.AISRF_ADMIN_API_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')" \
  --set ingress.enabled=true --set ingress.hosts[0].host=aisrf.example.com \
  --set env.AISRF_PUBLIC_URL=https://aisrf.example.com
helm upgrade aisrf deploy/helm/aisrf -n aisrf --set image.tag=1.0.1 --reuse-values
helm uninstall aisrf -n aisrf        # keeps the PVC
```

Values reference (`values.yaml`):

| Key | Default | Meaning |
| --- | --- | --- |
| `replicaCount` | `1` | pod count when autoscaling is off; keep 1 with SQLite |
| `image.repository` | `ghcr.io/keyuraghao/aisrf` | image name |
| `image.tag` | `""` | image tag; empty means the chart `appVersion` (1.0.0) |
| `image.pullPolicy` | `IfNotPresent` | kubelet pull policy |
| `imagePullSecrets` | `[]` | registry credentials for private mirrors |
| `nameOverride`, `fullnameOverride` | `""` | resource naming |
| `serviceAccount.create` | `true` | create a ServiceAccount (token not mounted) |
| `serviceAccount.annotations` | `{}` | for example IAM role annotations |
| `serviceAccount.name` | `""` | name to create or use; empty derives from the release |
| `env` | `AISRF_ENVIRONMENT=production`, `AISRF_LOG_JSON_CONSOLE="true"`, `AISRF_COOKIE_SECURE="true"`, `AISRF_APPROVAL_TIMEOUT_SECONDS="300"` | plain settings rendered as container env vars; add `AISRF_PUBLIC_URL` and any other `AISRF_*` value |
| `secretEnv.AISRF_SECRET_KEY` | `""` | session and credential key; empty means the built-in development key (NOTES warns) |
| `secretEnv.AISRF_ADMIN_PASSWORD` | `""` | first admin password; empty means `admin` |
| `secretEnv.AISRF_ADMIN_API_TOKEN` | `""` | bearer token for CLI, MCP and CI |
| `secretEnv.AISRF_ENCRYPTION_KEY` | unset | optional explicit Fernet key |
| `existingSecret` | `""` | name of a Secret you manage (keys are the `AISRF_*` names); disables the chart Secret |
| `databaseUrl` | `""` | PostgreSQL URL; stored in the chart Secret; enables `RollingUpdate` and autoscaling. Empty means SQLite on the volume |
| `persistence.enabled` | `true` | PVC for `/app/data`; false uses an emptyDir (data lost on restart) |
| `persistence.existingClaim` | unset | reuse a PVC instead of creating one |
| `persistence.storageClass` | `""` | storage class name; empty means the cluster default |
| `persistence.accessModes` | `[ReadWriteOnce]` | access modes |
| `persistence.size` | `5Gi` | requested storage |
| `persistence.annotations` | `{}` | PVC annotations |
| `service.type` | `ClusterIP` | Service type |
| `service.port` | `8080` | Service port (target is always the `http` container port) |
| `service.annotations` | `{}` | Service annotations |
| `ingress.enabled` | `false` | create an Ingress |
| `ingress.className` | `nginx` | ingress class |
| `ingress.annotations` | 600 s read and send timeouts, buffering off, body size 8m (ingress-nginx) | required for held requests and SSE |
| `ingress.hosts` | `[{host: aisrf.example.com, paths: [{path: /, pathType: Prefix}]}]` | host rules |
| `ingress.tls` | `[]` | TLS entries (`secretName`, `hosts`) |
| `resources.requests` | `cpu: 100m`, `memory: 256Mi` | scheduling requests |
| `resources.limits` | `cpu: "1"`, `memory: 1Gi` | limits |
| `probes.liveness.path` | `/healthz` | liveness probe path |
| `probes.liveness.initialDelaySeconds`, `periodSeconds`, `timeoutSeconds` | `10`, `20`, `5` | liveness timing |
| `probes.readiness.path` | `/readyz` | readiness probe path (checks the database) |
| `probes.readiness.initialDelaySeconds`, `periodSeconds`, `timeoutSeconds` | `5`, `10`, `5` | readiness timing |
| `autoscaling.enabled` | `false` | create an HPA; only with `databaseUrl` |
| `autoscaling.minReplicas`, `maxReplicas` | `1`, `3` | replica range |
| `autoscaling.targetCPUUtilizationPercentage` | `75` | CPU target |
| `podAnnotations`, `podLabels` | `{}` | extra pod metadata |
| `podSecurityContext` | `runAsNonRoot: true`, uid, gid and fsGroup `10001`, seccomp `RuntimeDefault` | pod-level security |
| `securityContext` | `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, drop `ALL` | container-level security |
| `nodeSelector`, `tolerations`, `affinity` | `{}`, `[]`, `{}` | scheduling constraints |
| `extraEnv` | `[]` | additional env entries (for example `valueFrom` references) |
| `extraVolumes`, `extraVolumeMounts` | `[]` | additional volumes, for example a NeMo config or CA bundle |

## Probes, persistence and scaling limits

- `GET /healthz` returns `{"status":"ok","version":"1.0.0"}` without touching the database (liveness). `GET /readyz` runs a query (`list_agents`) and returns `{"status":"ready"}` (readiness). `GET /metrics` serves Prometheus text.
- Persistence: the database and the log directory are the only state. In containers keep `/app/data` on a volume; `/app/logs` can be an emptyDir when stdout JSON goes to your log pipeline.
- One process is the supported topology (`AISRF_WORKERS=1`). Decisions wake waiting synchronous requests through an in-process registry (`aisrf/gateway/hold.py`); another process only notices them by DB polling every `AISRF_HOLD_POLL_INTERVAL_SECONDS` (1.0). The rate limiter, the SSE broadcaster and the metrics registry are per process. Run `--workers 2` or several replicas only if those semantics are acceptable and the database is PostgreSQL.
- Upstream calls use one shared `httpx.AsyncClient` (200 connections, 50 keep-alive).
- Restarting the gateway drops in-flight synchronous waits: the tickets stay PENDING and expire via the sweeper; clients receive a connection error and should not retry blindly. Async mode (`X-AISRF-Async: 1`) survives restarts because tickets are polled by id.

## Backups

Back up together, from the same moment: the database (agents with encrypted upstream keys, tickets, audit chain, runtime settings, campaigns, code review runs) and the key material (`aisrf.env`, `.env`, the systemd env file or the Secret holding `AISRF_SECRET_KEY` and `AISRF_ENCRYPTION_KEY`). Without the key the upstream credentials are unrecoverable.

- SQLite: `sqlite3 /var/lib/aisrf/data/aisrf.db ".backup '/backup/aisrf-$(date +%F).db'"` (safe while the service runs, WAL mode) or stop the service and copy the file with its `-wal` and `-shm` companions.
- PostgreSQL: `pg_dump -Fc aisrf > aisrf-$(date +%F).dump`; restore with `pg_restore -d aisrf`.
- Docker: `docker run --rm -v aisrf-data:/data -v "$PWD":/backup alpine tar czf /backup/aisrf-data.tgz -C /data .`
- Kubernetes: snapshot the PVC with your CSI driver or exec the sqlite3 backup inside the pod.

Retention: tickets older than `AISRF_TICKET_RETENTION_DAYS` (90) are purged by the sweeper; logs rotate at 50 MB x 10 (`aisrf.jsonl`) and 20 MB x 5 per agent. Restore procedures are in [[Operations-and-Maintenance]].

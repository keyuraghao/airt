# Installation

Every supported way to install AISRF, with the exact commands. All paths run the same code: the `aisrf` CLI, `aisrf serve` for the gateway plus dashboard on port 8080, and `aisrf desktop` for a loopback-only local instance. Pick by environment:

| Path | Command | Python needed | Best for |
| --- | --- | --- | --- |
| Binary, Linux and macOS | `curl -fsSL https://raw.githubusercontent.com/keyuraghao/aisrf/main/scripts/install.sh \| bash` | no | laptops, jump hosts, air-gapped VMs |
| Binary, Windows | `irm https://raw.githubusercontent.com/keyuraghao/aisrf/main/scripts/install.ps1 \| iex` | no | Windows workstations and servers |
| Desktop mode | `aisrf desktop` (binary) or `aisrf-desktop` (pip) | with pip only | trying it out, single reviewer |
| pip, pipx or uv from source | `pipx install "git+https://github.com/keyuraghao/aisrf.git"` | 3.11 or 3.12 | developers, optional extras |
| Docker | `docker run -p 8080:8080 ghcr.io/keyuraghao/aisrf:latest` | no | any host with a container runtime |
| docker compose | `docker compose up -d` | no | single host, optional PostgreSQL |
| Kubernetes manifests | `kubectl apply -f deploy/kubernetes/` | no | clusters without Helm |
| Helm | `helm install aisrf deploy/helm/aisrf` | no | clusters |
| systemd, launchd, Windows service | see [[Deployment]] | no (binary) | always-on servers |

Release assets on the GitHub Releases page for `v1.0.0`: `aisrf-1.0.0-linux-x86_64.tar.gz`, `aisrf-1.0.0-linux-arm64.tar.gz`, `aisrf-1.0.0-macos-arm64.tar.gz` (Apple silicon only), `aisrf-1.0.0-windows-x86_64.zip`, one `SHA256SUMS-<os>-<arch>.txt` per archive, plus the wheel `aisrf-1.0.0-py3-none-any.whl`, the sdist, `aisrf-1.0.0.cyclonedx.json` (SBOM) and `SHA256SUMS.txt` for the Python artifacts.

## Native binaries

The binaries are PyInstaller "onedir" builds: a folder `aisrf/` containing the `aisrf` executable (`aisrf.exe` on Windows) and an `_internal/` directory with the Python runtime, dependencies, dashboard templates and static files, the red-team corpus, the semgrep rule files and the NeMo default config. Roughly 130 MB unpacked, 50 MB compressed. The optional engines (garak, PyRIT, LLM Guard, NeMo Guardrails, semgrep, bandit, pywebview) are excluded from the bundle (`packaging/pyinstaller/manifest.py`, `EXCLUDES`); the dashboard shows them as "not installed" and everything else works. Use a pip install with extras when you need them.

The binaries are not code signed or notarized. Always verify the SHA256 against the matching `SHA256SUMS-<os>-<arch>.txt`; the install scripts do that for you.

### Linux (x86_64, arm64)

One-liner:

```bash
curl -fsSL https://raw.githubusercontent.com/keyuraghao/aisrf/main/scripts/install.sh | bash
aisrf version
aisrf desktop        # or: aisrf serve
```

What `scripts/install.sh` does:

1. Requires `curl` and `tar`; detects the OS (`linux`, `macos`) and architecture (`x86_64`, `arm64`); refuses Intel Macs and other platforms.
2. Resolves the latest release from `https://api.github.com/repos/keyuraghao/aisrf/releases/latest` unless `AISRF_VERSION` is set.
3. Downloads `aisrf-<version>-<os>-<arch>.tar.gz` and `SHA256SUMS-<os>-<arch>.txt` from `https://github.com/keyuraghao/aisrf/releases/download/v<version>/` and verifies the checksum with `sha256sum` (or `shasum -a 256`).
4. Extracts to `/usr/local/lib/aisrf` when `/usr/local/lib` is writable or the script runs as root, otherwise `~/.local/lib/aisrf`; links the binary to `/usr/local/bin/aisrf` or `~/.local/bin/aisrf`.
5. On macOS removes the quarantine attribute (`xattr -dr com.apple.quarantine`).
6. Prints the installed version, PATH advice when the bin directory is not on `PATH`, and the next steps.

Variables: `AISRF_VERSION=1.0.0` pins a release, `AISRF_PREFIX=/opt/aisrf` changes the location (binary linked into `<prefix>/bin`, or `/usr/local/bin`-style when the prefix ends in `/lib/aisrf`), `AISRF_REPO` overrides the repository, `AISRF_NO_MODIFY_PATH=1` silences the PATH advice.

Manual install:

```bash
VERSION=1.0.0; OS=linux; ARCH=x86_64        # or ARCH=arm64
curl -fLO https://github.com/keyuraghao/aisrf/releases/download/v$VERSION/aisrf-$VERSION-$OS-$ARCH.tar.gz
curl -fLO https://github.com/keyuraghao/aisrf/releases/download/v$VERSION/SHA256SUMS-$OS-$ARCH.txt
sha256sum -c SHA256SUMS-$OS-$ARCH.txt
tar -xzf aisrf-$VERSION-$OS-$ARCH.tar.gz
./aisrf/aisrf version
sudo mv aisrf /usr/local/lib/aisrf && sudo ln -sf /usr/local/lib/aisrf/aisrf /usr/local/bin/aisrf
```

### macOS (Apple silicon)

Same one-liner and the same manual steps with `OS=macos ARCH=arm64` and `shasum -a 256 -c SHA256SUMS-macos-arm64.txt`. Intel Macs are not supported by the binaries; use pip or Docker.

Quarantine: because the binaries are not notarized, Gatekeeper blocks a manually downloaded archive. Run `xattr -dr com.apple.quarantine aisrf/` once on the extracted folder, or allow it under System Settings > Privacy & Security after the first blocked launch. The installer does this automatically.

### Windows (x86_64)

PowerShell 5.1 or 7:

```powershell
irm https://raw.githubusercontent.com/keyuraghao/aisrf/main/scripts/install.ps1 | iex
aisrf version
aisrf desktop
```

What `scripts/install.ps1` does:

1. Forces TLS 1.2, detects the architecture (`AMD64` installs `x86_64`; `ARM64` also installs the `x86_64` build, which runs under emulation because no native arm64 Windows build is published).
2. Resolves the latest release unless `-Version` or `AISRF_VERSION` is given.
3. Downloads `aisrf-<version>-windows-x86_64.zip` and `SHA256SUMS-windows-x86_64.txt`, compares `Get-FileHash -Algorithm SHA256` against the listed value.
4. Extracts to `%LOCALAPPDATA%\Programs\AISRF\aisrf\` (refuses to overwrite while `aisrf.exe` is running), runs `Unblock-File` on the executable.
5. Adds that folder to the user `PATH` unless `-NoPath` is given; open a new terminal afterwards.

Options when run from a file or a scriptblock: `-Version 1.0.0`, `-InstallDir D:\Tools\AISRF`, `-Repo owner/name`, `-NoPath`. Environment overrides: `AISRF_VERSION`, `AISRF_INSTALL_DIR`, `AISRF_REPO`.

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/keyuraghao/aisrf/main/scripts/install.ps1))) -Version 1.0.0 -NoPath
```

SmartScreen: the executable is not code signed, so Windows may show "Windows protected your PC" on first launch. Click "More info" then "Run anyway". Manual verification:

```powershell
(Get-FileHash .\aisrf-1.0.0-windows-x86_64.zip -Algorithm SHA256).Hash
Get-Content .\SHA256SUMS-windows-x86_64.txt
Expand-Archive .\aisrf-1.0.0-windows-x86_64.zip -DestinationPath $env:LOCALAPPDATA\Programs\AISRF
```

### Where the binary keeps its state

The pip install writes `data/` and `logs/` into the current working directory. The binary (and any install with `AISRF_HOME` set) uses a per-user application directory resolved by `aisrf/desktop.py`:

| OS | Directory |
| --- | --- |
| Linux | `$XDG_DATA_HOME/aisrf`, default `~/.local/share/aisrf` |
| macOS | `~/Library/Application Support/AISRF` |
| Windows | `%LOCALAPPDATA%\AISRF` |

`AISRF_HOME=/path` relocates it (services use `/var/lib/aisrf` on Linux and `%ProgramData%\AISRF` on Windows). Inside: `data/aisrf.db` (SQLite, WAL mode), `logs/aisrf.jsonl` plus `logs/agents/<agent_id>.jsonl`, and `aisrf.env`, created on first run with a random `AISRF_SECRET_KEY` and `AISRF_ADMIN_API_TOKEN` (mode 0600 on POSIX). Any `AISRF_*` setting can be added to that file; real environment variables still win. See [[Desktop-Mode]].

## pip, pipx and uv from source

Requires Python 3.11 or 3.12. A wheel is attached to every release; PyPI publishing is not enabled yet (see [[Releasing]]).

```bash
# pipx, CLI only
pipx install "git+https://github.com/keyuraghao/aisrf.git"
# pipx with extras
pipx install "aisrf[desktop,codereview] @ git+https://github.com/keyuraghao/aisrf.git"
# wheel from the release page
pip install https://github.com/keyuraghao/aisrf/releases/download/v1.0.0/aisrf-1.0.0-py3-none-any.whl
# uv virtualenv from a clone (the project convention: only .venv, created with uv)
git clone https://github.com/keyuraghao/aisrf.git && cd aisrf
uv venv .venv --python 3.12
uv pip install --python .venv/bin/python -e ".[dev]"
.venv/bin/aisrf init-db
.venv/bin/aisrf serve
```

Extras defined in `pyproject.toml`:

| Extra | Packages | Enables |
| --- | --- | --- |
| `dev` | `pytest>=8`, `pytest-asyncio>=0.23`, `ruff>=0.5`, `asgi-lifespan>=2` | test suite and lint |
| `postgres` | `asyncpg>=0.29` | `postgresql+asyncpg://` database URLs |
| `mitm` | `mitmproxy>=10` | the transparent interception addon `aisrf/integrations/mitm_addon.py` |
| `guardrails` | `llm-guard>=0.3`, `nemoguardrails>=0.10`, `rebuff>=0.0.5` | LLM Guard scanners, NeMo rails, Rebuff SDK layer |
| `scanners` | `garak>=0.10`, `pyrit>=0.5` | garak and PyRIT engines (promptfoo is a Node binary, installed separately) |
| `codereview` | `semgrep>=1.100`, `bandit>=1.7` | semgrep and bandit engines for source code review |
| `desktop` | `pywebview>=5` | native window for `aisrf desktop` (Linux also needs GTK or Qt bindings) |
| `all` (everything except `scanners`) | `postgres`, `mitm`, `guardrails`, `scanners`, `codereview` combined (not `dev`, not `desktop`) | everything server side |

Note that `semgrep` pins `mcp==1.29.0` while the core allows `mcp>=1.10`; AISRF supports both the 1.x and the 2.x module layout (see [[Troubleshooting]]). The `guardrails` and `scanners` extras pull multi-gigabyte ML dependencies (torch, transformers); install them only where you run those engines.

State goes to `./data` and `./logs` in the working directory unless `AISRF_HOME`, or `AISRF_DATA_DIR` / `AISRF_LOG_DIR` / `AISRF_DATABASE_URL`, are set. Copy `.env.example` to `.env` in the working directory to configure the pip install; the `Settings` class reads `.env` automatically.

## Docker

```bash
docker run -d --name aisrf -p 127.0.0.1:8080:8080 \
  -e AISRF_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')" \
  -e AISRF_ADMIN_PASSWORD=change-me \
  -v aisrf-data:/app/data -v aisrf-logs:/app/logs \
  ghcr.io/keyuraghao/aisrf:latest
docker logs -f aisrf
```

Image facts (`Dockerfile`): multi-stage on `python:3.12-slim`, runtime stage has only the virtualenv and `curl`; the wheel is installed with the `postgres` extra plus `mcp>=1.0`, `reportlab>=4`, `openpyxl>=3.1`; runs as user `aisrf` (uid and gid 10001); `ENTRYPOINT ["aisrf"]` and `CMD ["serve"]`, so `docker run --rm ghcr.io/keyuraghao/aisrf:latest version` and `docker exec aisrf aisrf agent list` work; `HEALTHCHECK` on `http://127.0.0.1:8080/healthz` every 30 s (timeout 5 s, start period 20 s, 3 retries); volumes `/app/data` and `/app/logs`; defaults `AISRF_HOST=0.0.0.0`, `AISRF_PORT=8080`, `AISRF_DATA_DIR=/app/data`, `AISRF_LOG_DIR=/app/logs`, `AISRF_DATABASE_URL=sqlite+aiosqlite:////app/data/aisrf.db`, `AISRF_LOG_JSON_CONSOLE=true`.

Tags: `ghcr.io/keyuraghao/aisrf:1.0.0`, `:1.0`, `:latest`; platforms linux/amd64 and linux/arm64. Build locally with `docker build -t aisrf .` or `make docker-build`. Create the first agent from inside the container: `docker exec -it aisrf aisrf agent create demo --provider openai --upstream-key sk-...`.

## docker compose

```bash
cp .env.example .env            # set AISRF_SECRET_KEY, AISRF_ADMIN_PASSWORD, AISRF_ADMIN_API_TOKEN
docker compose up -d --build                    # SQLite in the aisrf-data volume
docker compose --profile postgres up -d --build # plus PostgreSQL 16
docker compose --profile postgres down          # stop both
```

`docker-compose.yml` defines the `gateway` service (built from the repository as `aisrf:latest`, container `aisrf-gateway`, `restart: unless-stopped`, optional `.env`, volumes `aisrf-data` and `aisrf-logs`, the same healthcheck as the image) and a `postgres` service (`postgres:16-alpine`, container `aisrf-postgres`, volume `aisrf-pgdata`, `pg_isready` healthcheck) behind the `postgres` profile. The port is published on `${AISRF_BIND_ADDRESS:-127.0.0.1}:${AISRF_PORT:-8080}`; `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB` default to `aisrf`. With the profile, set `AISRF_DATABASE_URL=postgresql+asyncpg://aisrf:aisrf@postgres:5432/aisrf` in `.env` or uncomment the line in the compose file. `make compose-up PROFILE=postgres` and `make compose-down` wrap the same commands.

## Kubernetes and Helm

Plain manifests in `deploy/kubernetes/` (Deployment, Service, PVC, Secret example, Ingress example, HPA) and the chart in `deploy/helm/aisrf/`:

```bash
kubectl create namespace aisrf
cp deploy/kubernetes/secret.example.yaml /tmp/secret.yaml   # edit the values
kubectl -n aisrf apply -f /tmp/secret.yaml -f deploy/kubernetes/pvc.yaml \
  -f deploy/kubernetes/deployment.yaml -f deploy/kubernetes/service.yaml
kubectl -n aisrf port-forward svc/aisrf 8080:8080
```

```bash
helm install aisrf deploy/helm/aisrf --namespace aisrf --create-namespace \
  --set secretEnv.AISRF_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')" \
  --set secretEnv.AISRF_ADMIN_PASSWORD=change-me \
  --set secretEnv.AISRF_ADMIN_API_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
```

Resource-by-resource walkthrough and the full values reference are in [[Deployment]].

## First-run defaults and data locations

| Method | Bind | Database | Logs | Secrets |
| --- | --- | --- | --- | --- |
| `aisrf desktop` (binary or pip) | `127.0.0.1`, free port or `--port` | `<app dir>/data/aisrf.db` | `<app dir>/logs/` | generated in `<app dir>/aisrf.env` |
| binary `aisrf serve` | `0.0.0.0:8080` | `<app dir>/data/aisrf.db` | `<app dir>/logs/` | generated in `<app dir>/aisrf.env` |
| pip `aisrf serve` | `0.0.0.0:8080` | `./data/aisrf.db` | `./logs/` | none generated: set `AISRF_SECRET_KEY` yourself |
| Docker, compose | container `0.0.0.0:8080`, published on `127.0.0.1:8080` by compose | `/app/data/aisrf.db` (volume `aisrf-data`) | `/app/logs` (volume `aisrf-logs`) | none generated: pass `-e` or `.env` |
| Kubernetes, Helm | Service port 8080 | `/app/data/aisrf.db` on the PVC, or PostgreSQL | `/app/logs` emptyDir plus stdout JSON | Secret `aisrf-env` or the chart Secret |

On every method the first start creates the schema (`Base.metadata.create_all`, SQLite with `PRAGMA journal_mode=WAL` and `foreign_keys=ON`), the admin reviewer from `AISRF_ADMIN_USERNAME` / `AISRF_ADMIN_PASSWORD` (default `admin` / `admin`, a warning is logged while the default password is in use), loads runtime setting overrides from the database and starts the background sweeper. Change the admin password immediately (Settings > Reviewers) or set `AISRF_ADMIN_PASSWORD` before the first start.

Security notes for a first run:

- `AISRF_SECRET_KEY` signs session cookies and derives the Fernet key that encrypts upstream provider credentials. Rotating it without a dedicated `AISRF_ENCRYPTION_KEY` makes stored credentials unreadable. Back up `aisrf.env` (or the Secret) together with the database.
- `aisrf serve` binds to `0.0.0.0:8080`; only desktop mode is loopback-only. Before exposing a server set `AISRF_ENVIRONMENT=production`, `AISRF_COOKIE_SECURE=true`, `AISRF_PUBLIC_URL=https://...` and terminate TLS in front (see [[Deployment]] and [[Security-Model]]).

## Verifying an install

```bash
aisrf version                                   # prints "aisrf 1.0.0"
aisrf --help                                    # command tree
curl -fsS http://127.0.0.1:8080/healthz         # {"status":"ok","version":"1.0.0"}
curl -fsS http://127.0.0.1:8080/readyz          # {"status":"ready"} once the database answers
curl -fsS http://127.0.0.1:8080/metrics | head  # Prometheus text
curl -fsS -H "Authorization: Bearer $AISRF_ADMIN_API_TOKEN" http://127.0.0.1:8080/api/audit/verify
```

Then sign in at `http://127.0.0.1:8080`, create an agent under Agents, copy its `aisrf_...` key once and send one request through `http://127.0.0.1:8080/v1` with the OpenAI SDK; a PENDING ticket must appear in the queue. The Settings > About page lists the installed optional engines. Docker: `docker run --rm ghcr.io/keyuraghao/aisrf:1.0.0 version`; Helm: `helm test` is not defined, use `kubectl -n aisrf rollout status deploy/aisrf` and the port-forward.

## Upgrading and uninstalling

| Path | Upgrade | Uninstall |
| --- | --- | --- |
| Binary, Linux and macOS | re-run `install.sh` (stop the service first); state untouched | `rm -rf /usr/local/lib/aisrf /usr/local/bin/aisrf` (or the `~/.local` equivalents) and the state directory |
| Binary, Windows | re-run `install.ps1` | delete `%LOCALAPPDATA%\Programs\AISRF` and `%LOCALAPPDATA%\AISRF`, drop the folder from the user `PATH` |
| pip, pipx | `pipx upgrade aisrf` or `pip install -U "git+https://github.com/keyuraghao/aisrf.git"` | `pipx uninstall aisrf` or `pip uninstall aisrf`; delete `data/` and `logs/` |
| Docker, compose | `docker pull ghcr.io/keyuraghao/aisrf:<version>` then recreate, or `docker compose up -d --build` | `docker rm -f aisrf && docker volume rm aisrf-data aisrf-logs` |
| Kubernetes | `kubectl -n aisrf set image deploy/aisrf aisrf=ghcr.io/keyuraghao/aisrf:<version>` | `kubectl delete namespace aisrf` (deletes the PVC) |
| Helm | `helm upgrade aisrf deploy/helm/aisrf --set image.tag=<version> --reuse-values` | `helm uninstall aisrf -n aisrf`, then delete the PVC if wanted |

The schema is extended on start with `create_all`; back up the database before major upgrades. More in [[Operations-and-Maintenance]].

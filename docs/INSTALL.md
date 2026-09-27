# Installing AISRF

Every supported way to run AISRF, from a double-click desktop mode to a Helm release. All paths
run the same code: the `aisrf` CLI, `aisrf serve` for the gateway and the dashboard on port 8080.

## Matrix

| Path | Command | Python needed | Best for |
| --- | --- | --- | --- |
| Binary, Linux / macOS | `curl -fsSL https://raw.githubusercontent.com/keyuraghao/aisrf/main/scripts/install.sh \| bash` | no | laptops, jump hosts, air-gapped VMs |
| Binary, Windows | `irm https://raw.githubusercontent.com/keyuraghao/aisrf/main/scripts/install.ps1 \| iex` | no | Windows workstations and servers |
| Desktop mode | `aisrf desktop` (binary) or `aisrf-desktop` (pip) | with pip only | trying it out, single reviewer |
| pip / pipx from source | `pipx install "git+https://github.com/keyuraghao/aisrf.git"` | 3.11+ | developers, custom extras |
| Docker | `docker run -p 8080:8080 ghcr.io/keyuraghao/aisrf:latest` | no | any host with a container runtime |
| docker compose | `docker compose up -d` | no | single host with optional PostgreSQL |
| Kubernetes manifests | `kubectl apply -f deploy/kubernetes/` | no | clusters without Helm |
| Helm | `helm install aisrf deploy/helm/aisrf` | no | clusters |
| systemd | `deploy/systemd/aisrf.service` | no (binary) | Linux servers |
| launchd | `deploy/launchd/com.aisrf.gateway.plist` | no (binary) | macOS servers, always-on Macs |
| Windows service | `deploy\windows\install-service.ps1` | no (binary) | Windows servers |

Release assets (GitHub Releases page): `aisrf-<version>-linux-x86_64.tar.gz`,
`aisrf-<version>-linux-arm64.tar.gz`, `aisrf-<version>-macos-arm64.tar.gz` (Apple silicon only),
`aisrf-<version>-windows-x86_64.zip`, one
`SHA256SUMS-<os>-<arch>.txt` per archive, plus the wheel, sdist, SBOM and image digest.

Note: garak pins newer torch, transformers and nltk than LLM Guard accepts, so `scanners` cannot be installed into the same environment as `guardrails`. Install `aisrf[scanners]` into its own virtual environment or container (the CI heavy job does exactly that); the `all` extra therefore excludes `scanners`.

## Self-contained binaries

The binaries are PyInstaller "onedir" builds: a folder `aisrf/` with the `aisrf` executable and an
`_internal/` directory (Python runtime, dependencies, dashboard templates and static files, the
red-team corpus, the semgrep rule files and the NeMo default config). No Python, no virtualenv.
About 130 MB unpacked, 50 MB compressed. Optional engines (garak, PyRIT, LLM Guard, NeMo, semgrep,
bandit) are not inside the binary; the dashboard shows them as "not installed" and the rest of the
product works. Use the pip install with extras when you need them.

### Linux and macOS

```bash
curl -fsSL https://raw.githubusercontent.com/keyuraghao/aisrf/main/scripts/install.sh | bash
aisrf version
aisrf desktop        # or: aisrf serve
```

The script detects OS and architecture, downloads the archive and its checksum file from the
latest release, verifies the SHA256, unpacks to `/usr/local/lib/aisrf` (when writable or run with
`sudo`) or `~/.local/lib/aisrf`, and links `aisrf` into `/usr/local/bin` or `~/.local/bin`.
Variables: `AISRF_VERSION=1.2.0` pins a release, `AISRF_PREFIX=/opt/aisrf` changes the location.

Manual install:

```bash
VERSION=1.0.0; OS=linux; ARCH=x86_64        # or macos / arm64
curl -fLO https://github.com/keyuraghao/aisrf/releases/download/v$VERSION/aisrf-$VERSION-$OS-$ARCH.tar.gz
curl -fLO https://github.com/keyuraghao/aisrf/releases/download/v$VERSION/SHA256SUMS-$OS-$ARCH.txt
sha256sum -c SHA256SUMS-$OS-$ARCH.txt         # shasum -a 256 -c on macOS
tar -xzf aisrf-$VERSION-$OS-$ARCH.tar.gz && ./aisrf/aisrf version
```

macOS: the binaries are not notarized. The installer removes the quarantine attribute; for a
manual install run `xattr -dr com.apple.quarantine aisrf/` once, or allow it under System Settings
> Privacy & Security.

### Windows

PowerShell (5.1 or 7):

```powershell
irm https://raw.githubusercontent.com/keyuraghao/aisrf/main/scripts/install.ps1 | iex
aisrf version
aisrf desktop
```

Installs to `%LOCALAPPDATA%\Programs\AISRF\aisrf\` and adds that folder to the user `PATH`
(open a new terminal afterwards). `-Version 1.2.0`, `-InstallDir D:\Tools\AISRF` and `-NoPath`
are available when the script is run from a file. SmartScreen may warn on first launch because
the executable is not code signed; "More info > Run anyway".

### Where the binary keeps its state

Unlike the pip install, which writes `data/` and `logs/` into the current directory, the binary
uses a per-user application directory:

| OS | Directory |
| --- | --- |
| Linux | `$XDG_DATA_HOME/aisrf` or `~/.local/share/aisrf` |
| macOS | `~/Library/Application Support/AISRF` |
| Windows | `%LOCALAPPDATA%\AISRF` |

Set `AISRF_HOME=/path` to relocate it (services use `/var/lib/aisrf`, `%ProgramData%\AISRF`).
Inside: `data/aisrf.db` (SQLite), `logs/`, and `aisrf.env`, a settings file created on first run
with a random `AISRF_SECRET_KEY` and `AISRF_ADMIN_API_TOKEN` (mode 0600). Add any `AISRF_*`
setting to that file; environment variables still win.

## Desktop mode

```bash
aisrf desktop [--port N] [--no-window] [--no-browser]      # binary or pip install
aisrf-desktop                                              # console script of the pip install
```

Starts the gateway on `127.0.0.1` on a free port (or `--port`), waits for `/healthz`, prints the
URL and the sign-in hint, then opens the dashboard in a native window when
[pywebview](https://pywebview.flowrl.com) is importable (`pip install "aisrf[desktop]"`; Linux
additionally needs GTK or Qt bindings) and otherwise in the system browser. Closing the window or
pressing Ctrl+C stops the gateway. The binaries do not include pywebview and always use the
browser. Point local agents at `http://127.0.0.1:<port>/v1` exactly like a server install.

## pip and pipx from source

```bash
pipx install "git+https://github.com/keyuraghao/aisrf.git"                 # CLI only
pipx install "aisrf[desktop,codereview] @ git+https://github.com/keyuraghao/aisrf.git"
# or a virtualenv
uv venv .venv && uv pip install --python .venv/bin/python "git+https://github.com/keyuraghao/aisrf.git"
aisrf init-db && aisrf serve
```

Extras: `postgres`, `mitm`, `guardrails`, `scanners`, `codereview`, `desktop`, `all` (everything except `scanners`), `dev`.
State goes to `./data` and `./logs` unless `AISRF_HOME` or `AISRF_DATA_DIR` / `AISRF_LOG_DIR` /
`AISRF_DATABASE_URL` are set. A wheel is attached to every release; PyPI publishing is not
enabled yet (`docs/RELEASING.md`).

## Docker and docker compose

```bash
docker run -d --name aisrf -p 127.0.0.1:8080:8080 \
  -e AISRF_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')" \
  -e AISRF_ADMIN_PASSWORD=change-me \
  -v aisrf-data:/app/data -v aisrf-logs:/app/logs \
  ghcr.io/keyuraghao/aisrf:latest
```

Images: `ghcr.io/keyuraghao/aisrf:<version>`, `:<major.minor>`, `:latest`, linux/amd64 and
linux/arm64, non-root, `HEALTHCHECK` on `/healthz`. Compose (`docker compose up -d`, optional
`--profile postgres`) and reverse proxy settings are in [DEPLOYMENT.md](DEPLOYMENT.md).

## Kubernetes

Plain manifests (`deploy/kubernetes/`): Deployment (single replica, `Recreate`, non-root, read-only
root filesystem), Service, PVC for SQLite, Secret example, Ingress example with the long timeouts
the synchronous gateway calls need, optional HPA.

```bash
kubectl create namespace aisrf
cp deploy/kubernetes/secret.example.yaml /tmp/secret.yaml   # edit the values
kubectl -n aisrf apply -f /tmp/secret.yaml -f deploy/kubernetes/pvc.yaml \
  -f deploy/kubernetes/deployment.yaml -f deploy/kubernetes/service.yaml
kubectl -n aisrf port-forward svc/aisrf 8080:8080
```

Helm (`deploy/helm/aisrf/`):

```bash
helm install aisrf deploy/helm/aisrf --namespace aisrf --create-namespace \
  --set secretEnv.AISRF_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')" \
  --set secretEnv.AISRF_ADMIN_PASSWORD=change-me \
  --set secretEnv.AISRF_ADMIN_API_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')" \
  --set ingress.enabled=true --set ingress.hosts[0].host=aisrf.example.com \
  --set env.AISRF_PUBLIC_URL=https://aisrf.example.com
```

Values of note: `image.tag`, `existingSecret` (bring your own Secret with the `AISRF_*` keys),
`databaseUrl` (PostgreSQL, enables rolling updates and `autoscaling`), `persistence.*`,
`ingress.*`, `resources`, `probes` (`/healthz`, `/readyz`). `helm upgrade` with a new
`image.tag` upgrades; `helm uninstall` keeps the PVC unless you delete it.

## Linux server with systemd

`deploy/systemd/aisrf.service` runs the binary as the `aisrf` user with settings in
`/etc/aisrf/aisrf.env` (`EnvironmentFile=`), state in `/var/lib/aisrf`, logs in `/var/log/aisrf`
and a hardened sandbox (`ProtectSystem=strict`, `NoNewPrivileges`, empty capability set, syscall
filter). Step-by-step instructions, PostgreSQL and uninstall are in
[deploy/systemd/README.md](../deploy/systemd/README.md).

## macOS with launchd

`deploy/launchd/com.aisrf.gateway.plist` starts `aisrf serve --host 127.0.0.1 --port 8080` at
login (LaunchAgent) or at boot (LaunchDaemon) and restarts it on failure:

```bash
cp deploy/launchd/com.aisrf.gateway.plist ~/Library/LaunchAgents/
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.aisrf.gateway.plist
launchctl kickstart -k gui/$(id -u)/com.aisrf.gateway
launchctl bootout gui/$(id -u)/com.aisrf.gateway      # stop and remove
```

Edit the binary path and add `AISRF_HOME` under `EnvironmentVariables` to relocate the state.

## Windows service

From an elevated PowerShell, after `install.ps1`:

```powershell
powershell -ExecutionPolicy Bypass -File deploy\windows\install-service.ps1 [-Port 8080] [-Binary C:\path\aisrf.exe]
powershell -ExecutionPolicy Bypass -File deploy\windows\uninstall-service.ps1 [-PurgeData]
```

With [NSSM](https://nssm.cc) on the `PATH` the service is wrapped by NSSM (log rotation,
restart policy, environment stored per service). Without it the script registers the service
with `sc.exe create` pointing at a generated `aisrf-service.cmd` wrapper and writes the
`AISRF_*` variables to the service's registry `Environment` value; `-ForceSc` selects this even
when NSSM exists. State lives in `%ProgramData%\AISRF` (`aisrf.env`, `data`, `logs`), the
service binds to `127.0.0.1:8080` by default (`-BindHost 0.0.0.0` to expose it; prefer a reverse
proxy with TLS).

## First-run security notes

* Sign in with `admin` / `admin` and change the password immediately (Settings > Reviewers) or set
  `AISRF_ADMIN_PASSWORD` before the first start. A warning is logged while the default is in use.
* Binaries and desktop mode generate `AISRF_SECRET_KEY` and `AISRF_ADMIN_API_TOKEN` in
  `aisrf.env` on first run. The pip and container installs do not: set both yourself
  (`python3 -c 'import secrets; print(secrets.token_urlsafe(48))'`). The secret key derives the
  Fernet key that encrypts upstream provider credentials; rotating it without
  `AISRF_ENCRYPTION_KEY` makes stored credentials unreadable.
* Back up `aisrf.env` (or your Secret) together with the database.
* Desktop mode binds to `127.0.0.1` only. `aisrf serve` binds to `0.0.0.0:8080` by default; put
  TLS in front (`AISRF_COOKIE_SECURE=true`, `AISRF_ENVIRONMENT=production`, `AISRF_PUBLIC_URL`),
  see [DEPLOYMENT.md](DEPLOYMENT.md) and [SECURITY.md](SECURITY.md).
* The binaries are not code signed or notarized; verify the SHA256 against
  `SHA256SUMS-<os>-<arch>.txt` from the release page (the install scripts do this for you).

## Upgrading

| Path | Upgrade |
| --- | --- |
| Binary | re-run `install.sh` / `install.ps1` (stop the service first), state is untouched |
| pip / pipx | `pipx upgrade aisrf` or `pip install -U "git+https://github.com/keyuraghao/aisrf.git"` |
| Docker / compose | `docker pull ghcr.io/keyuraghao/aisrf:<version>` then recreate, or `docker compose up -d --build` |
| Kubernetes | `kubectl set image deploy/aisrf aisrf=ghcr.io/keyuraghao/aisrf:<version>` |
| Helm | `helm upgrade aisrf deploy/helm/aisrf --set image.tag=<version> --reuse-values` |
| systemd / launchd / Windows service | upgrade the binary, then restart the service |

The schema is created and extended on start (`create_all`); back up the database before major
upgrades and read the release notes for configuration changes.

## Uninstalling

| Path | Remove |
| --- | --- |
| Binary, Linux / macOS | `rm -rf /usr/local/lib/aisrf /usr/local/bin/aisrf` (or the `~/.local` equivalents) and the state directory |
| Binary, Windows | delete `%LOCALAPPDATA%\Programs\AISRF` and `%LOCALAPPDATA%\AISRF`, remove the folder from the user `PATH` |
| pip / pipx | `pipx uninstall aisrf` or `pip uninstall aisrf`; delete `data/` and `logs/` |
| Docker | `docker rm -f aisrf && docker volume rm aisrf-data aisrf-logs` |
| Kubernetes | `kubectl delete namespace aisrf` (deletes the PVC) |
| Helm | `helm uninstall aisrf -n aisrf`, then delete the PVC if wanted |
| systemd | `deploy/systemd/README.md`, Uninstall |
| launchd | `launchctl bootout ...` and delete the plist |
| Windows service | `deploy\windows\uninstall-service.ps1 -PurgeData` |

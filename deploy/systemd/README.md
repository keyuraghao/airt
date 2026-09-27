# AISRF as a systemd service

Runs the gateway as the dedicated `aisrf` user with its settings in `/etc/aisrf/aisrf.env`,
state in `/var/lib/aisrf` and logs in `/var/log/aisrf`. Works with the self-contained binary
(default) or a pip install (edit `ExecStart`).

## Install

```bash
# 1. binary (or: python3 -m venv /opt/aisrf/.venv && /opt/aisrf/.venv/bin/pip install aisrf)
curl -fsSL https://raw.githubusercontent.com/keyuraghao/aisrf/main/scripts/install.sh | sudo bash

# 2. user and directories
sudo useradd --system --home-dir /var/lib/aisrf --shell /usr/sbin/nologin aisrf
sudo install -d -o aisrf -g aisrf -m 0750 /var/lib/aisrf /var/lib/aisrf/data /var/log/aisrf
sudo install -d -o root -g aisrf -m 0750 /etc/aisrf

# 3. settings (never leave the defaults)
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

# 4. unit
sudo cp deploy/systemd/aisrf.service /etc/systemd/system/aisrf.service
sudo systemctl daemon-reload
sudo systemctl enable --now aisrf
systemctl status aisrf
curl -fsS http://127.0.0.1:8080/healthz
```

Put nginx or Caddy in front for TLS (`docs/DEPLOYMENT.md`, "Reverse proxy and TLS"). The unit
binds to `127.0.0.1` through `/etc/aisrf/aisrf.env`; set `AISRF_HOST=0.0.0.0` only when the
host firewall does the filtering.

## PostgreSQL

Set `AISRF_DATABASE_URL=postgresql+asyncpg://aisrf:secret@db:5432/aisrf?ssl=require` in
`/etc/aisrf/aisrf.env`. The `Environment=AISRF_DATABASE_URL=...` line in the unit is the SQLite
default; values from `EnvironmentFile=` override `Environment=` lines that come before it, so move
the file line after the `Environment=` block or delete the SQLite line (the unit as shipped already
lists `EnvironmentFile=` first, so edit it to your taste and run `systemctl daemon-reload`).

## Operations

```bash
sudo journalctl -u aisrf -f                 # JSON lines on stdout (AISRF_LOG_JSON_CONSOLE=true)
sudo tail -f /var/log/aisrf/aisrf.jsonl     # rotating file log
sudo -u aisrf AISRF_HOME=/var/lib/aisrf aisrf agent list
sudo systemctl restart aisrf
```

Upgrade: re-run the installer (or `pip install -U aisrf`), then `sudo systemctl restart aisrf`.
Back up `/var/lib/aisrf/data` and `/etc/aisrf/aisrf.env` together; without `AISRF_SECRET_KEY`
the encrypted upstream credentials are unrecoverable.

## Hardening notes

The unit uses `ProtectSystem=strict`, `ProtectHome=true`, `PrivateTmp`, `NoNewPrivileges`, an
empty capability set, a `@system-service` syscall filter and `RestrictAddressFamilies`. Only
`/var/lib/aisrf` and `/var/log/aisrf` are writable. If you install the binary somewhere under
`/home`, `ProtectHome=true` will hide it; move it to `/opt/aisrf` or `/usr/local`.

## Uninstall

```bash
sudo systemctl disable --now aisrf
sudo rm /etc/systemd/system/aisrf.service && sudo systemctl daemon-reload
sudo rm -rf /etc/aisrf /var/lib/aisrf /var/log/aisrf /opt/aisrf /usr/local/bin/aisrf
sudo userdel aisrf
```

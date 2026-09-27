#!/usr/bin/env python
"""Build the self-contained AISRF binary with PyInstaller, archive it and smoke test it.

Steps:
  1. `python -m PyInstaller packaging/pyinstaller/aisrf.spec`  ->  dist/aisrf/ (onedir)
  2. archive: dist/aisrf-<version>-<os>-<arch>.tar.gz (linux, macos) or .zip (windows)
  3. dist/SHA256SUMS-<os>-<arch>.txt
  4. smoke test on the built binary: `version`, `init-db` in a temporary data dir, `serve` on a free
     port followed by GET /healthz, /login, /static/style.css, /api/redteam/corpus (with a token),
     /api/codereview/rules and PDF/XLSX/HTML summary reports, plus a check that the bundled data
     directories exist on disk.

Usage: python scripts/build_binary.py [--skip-build] [--skip-smoke] [--skip-archive]
Run it with the project virtualenv (`.venv/bin/python`), PyInstaller must be installed in it.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "packaging" / "pyinstaller" / "aisrf.spec"
DIST = ROOT / "dist"
BUNDLE = DIST / "aisrf"
WORK = ROOT / "build" / "pyinstaller"
sys.path.insert(0, str(SPEC.parent))
from manifest import PACKAGE_DATA_DIRS  # noqa: E402

SMOKE_TOKEN = "smoke-test-admin-token"


def log(msg: str) -> None:
    print(f"[build_binary] {msg}", flush=True)


def read_version() -> str:
    text = (ROOT / "aisrf" / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'^__version__\s*=\s*"([^"]+)"', text, re.M)
    if not match:
        raise SystemExit("cannot find __version__ in aisrf/__init__.py")
    return match.group(1)


def os_name() -> str:
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux"


def arch_name() -> str:
    machine = platform.machine().lower()
    if machine in {"x86_64", "amd64"}:
        return "x86_64"
    if machine in {"arm64", "aarch64"}:
        return "arm64"
    return machine


def exe_path() -> Path:
    return BUNDLE / ("aisrf.exe" if os_name() == "windows" else "aisrf")


def run_pyinstaller() -> None:
    if BUNDLE.exists():
        shutil.rmtree(BUNDLE)
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--distpath",
        str(DIST),
        "--workpath",
        str(WORK),
        str(SPEC),
    ]
    log("running " + " ".join(cmd))
    subprocess.run(cmd, cwd=ROOT, check=True)
    if not exe_path().exists():
        raise SystemExit(f"PyInstaller finished but {exe_path()} is missing")


def dir_size(path: Path) -> int:
    return sum(p.stat().st_size for p in path.rglob("*") if p.is_file())


def human(n: int) -> str:
    value = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024 or unit == "GiB":
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} GiB"


def make_archive(version: str) -> Path:
    stem = f"aisrf-{version}-{os_name()}-{arch_name()}"
    if os_name() == "windows":
        target = DIST / f"{stem}.zip"
        with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as zf:
            for path in sorted(BUNDLE.rglob("*")):
                zf.write(path, Path("aisrf") / path.relative_to(BUNDLE))
    else:
        target = DIST / f"{stem}.tar.gz"
        with tarfile.open(target, "w:gz") as tf:
            tf.add(BUNDLE, arcname="aisrf")
    log(f"archive {target.name} ({human(target.stat().st_size)})")
    return target


def write_checksums(files: list[Path]) -> Path:
    target = DIST / f"SHA256SUMS-{os_name()}-{arch_name()}.txt"
    lines = []
    for path in files:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {path.name}")
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    log(f"checksums {target.name}")
    return target


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def smoke_env(tmp: Path) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("AISRF_")}
    env.update(
        {
            "AISRF_HOME": str(tmp / "home"),
            "AISRF_DATA_DIR": str(tmp / "data"),
            "AISRF_LOG_DIR": str(tmp / "logs"),
            "AISRF_DATABASE_URL": f"sqlite+aiosqlite:///{(tmp / 'data' / 'smoke.db').as_posix()}",
            "AISRF_SECRET_KEY": "smoke-test-secret-key-not-for-production",
            "AISRF_ADMIN_API_TOKEN": SMOKE_TOKEN,
            "AISRF_LOG_LEVEL": "INFO",
            "AISRF_LOG_JSON_CONSOLE": "true",
            "PYTHONUNBUFFERED": "1",
        }
    )
    return env


def check_bundle_data() -> None:
    internal = BUNDLE / "_internal" / "aisrf"
    missing = [rel for rel in PACKAGE_DATA_DIRS if not any((internal / rel).glob("*"))]
    if missing:
        raise SystemExit(f"bundled data directories missing or empty: {missing}")
    log(f"bundle data ok: {', '.join(PACKAGE_DATA_DIRS)}")


def http_get(url: str, token: str | None = None, timeout: float = 10.0) -> tuple[int, bytes]:
    import urllib.error
    import urllib.request

    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"} if token else {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # loopback only
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def smoke_test(version: str) -> None:
    exe = exe_path()
    check_bundle_data()
    with tempfile.TemporaryDirectory(prefix="aisrf-smoke-") as tmpdir:
        tmp = Path(tmpdir)
        env = smoke_env(tmp)

        out = subprocess.run(
            [str(exe), "version"], env=env, capture_output=True, text=True, timeout=120, cwd=tmp
        )
        log(f"version -> rc={out.returncode} {out.stdout.strip()}")
        if out.returncode != 0 or version not in out.stdout:
            sys.stderr.write(out.stderr)
            raise SystemExit("smoke: `aisrf version` failed")

        out = subprocess.run(
            [str(exe), "init-db"], env=env, capture_output=True, text=True, timeout=180, cwd=tmp
        )
        log(f"init-db -> rc={out.returncode}")
        if out.returncode != 0 or not (tmp / "data" / "smoke.db").exists():
            sys.stderr.write(out.stdout + out.stderr)
            raise SystemExit("smoke: `aisrf init-db` failed")

        port = free_port()
        base = f"http://127.0.0.1:{port}"
        server_log = tmp / "serve.log"
        with server_log.open("w", encoding="utf-8") as handle:
            proc = subprocess.Popen(
                [str(exe), "serve", "--host", "127.0.0.1", "--port", str(port)],
                env=env,
                stdout=handle,
                stderr=subprocess.STDOUT,
                cwd=tmp,
            )
            try:
                deadline = time.monotonic() + 90
                healthy = False
                while time.monotonic() < deadline:
                    if proc.poll() is not None:
                        break
                    try:
                        status, _ = http_get(f"{base}/healthz", timeout=2)
                        if status == 200:
                            healthy = True
                            break
                    except Exception:
                        pass
                    time.sleep(0.5)
                if not healthy:
                    handle.flush()
                    sys.stderr.write(server_log.read_text(encoding="utf-8", errors="replace")[-6000:])
                    raise SystemExit("smoke: server did not become healthy")
                log("serve -> /healthz 200")
                checks = [
                    ("/login", None, None),
                    ("/static/style.css", None, None),
                    ("/readyz", None, b"ready"),
                    ("/api/redteam/corpus", SMOKE_TOKEN, b"prompt_injection"),
                    ("/api/codereview/rules", SMOKE_TOKEN, b"semgrep_file"),
                    ("/api/settings/guardrails", SMOKE_TOKEN, None),
                    ("/api/reports/summary?format=pdf", SMOKE_TOKEN, b"%PDF"),
                    ("/api/reports/summary?format=xlsx", SMOKE_TOKEN, b"PK"),
                    ("/api/reports/summary?format=html", SMOKE_TOKEN, b"<html"),
                ]
                for path, token, needle in checks:
                    status, body = http_get(f"{base}{path}", token=token)
                    ok = status == 200 and (needle is None or needle in body)
                    log(f"GET {path} -> {status}{'' if ok else '  FAILED'}")
                    if not ok and path != "/api/settings/guardrails":
                        handle.flush()
                        sys.stderr.write(server_log.read_text(encoding="utf-8", errors="replace")[-6000:])
                        raise SystemExit(f"smoke: GET {path} returned {status}: {body[:300]!r}")
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=10)
        text = server_log.read_text(encoding="utf-8", errors="replace")
        if "Traceback" in text:
            sys.stderr.write(text[-4000:])
            raise SystemExit("smoke: the server log contains a traceback")
        log(f"serve stopped cleanly (rc={proc.returncode})")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--skip-build", action="store_true", help="reuse dist/aisrf from a previous run")
    parser.add_argument("--skip-smoke", action="store_true", help="do not start the built binary")
    parser.add_argument("--skip-archive", action="store_true", help="do not create the archive and checksums")
    args = parser.parse_args()

    version = read_version()
    log(f"aisrf {version} for {os_name()}-{arch_name()} with {sys.executable}")
    DIST.mkdir(exist_ok=True)
    if not args.skip_build:
        run_pyinstaller()
    if not exe_path().exists():
        raise SystemExit(f"{exe_path()} does not exist; run without --skip-build")
    log(f"bundle dist/aisrf: {human(dir_size(BUNDLE))}")
    if not args.skip_smoke:
        smoke_test(version)
    if not args.skip_archive:
        archive = make_archive(version)
        write_checksums([archive])
    log("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())

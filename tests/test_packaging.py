"""Packaging and distribution checks that run without a built binary.

Covers the PyInstaller manifest (every package-data directory on disk is bundled), the desktop
helper (per-OS app directory, aisrf.env creation with 0600 and stable secrets), the install
script syntax, the systemd unit, the Kubernetes manifests and the Helm chart files. One test runs
the built binary's `version` when dist/aisrf exists.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
PACKAGING = ROOT / "packaging" / "pyinstaller"
DEPLOY = ROOT / "deploy"
BINARY = ROOT / "dist" / "aisrf" / ("aisrf.exe" if sys.platform.startswith("win") else "aisrf")


def _load_manifest():
    spec = importlib.util.spec_from_file_location("aisrf_pyinstaller_manifest", PACKAGING / "manifest.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


# --- PyInstaller manifest ----------------------------------------------------------------------
def test_manifest_covers_every_package_data_directory():
    manifest = _load_manifest()
    on_disk = manifest.data_dirs_on_disk(ROOT)
    listed = set(manifest.PACKAGE_DATA_DIRS)
    assert on_disk, "expected package data directories under aisrf/"
    missing = {d for d in on_disk if not any(d == entry or d.startswith(entry + "/") for entry in listed)}
    assert not missing, (
        f"package data directories not in packaging/pyinstaller/manifest.py: {sorted(missing)}"
    )


def test_manifest_data_pairs_point_at_existing_directories():
    manifest = _load_manifest()
    pairs = manifest.data_pairs(ROOT)
    assert len(pairs) == len(manifest.PACKAGE_DATA_DIRS)
    for src, dest in pairs:
        assert Path(src).is_dir(), src
        assert dest.startswith("aisrf/"), dest
        assert any(Path(src).iterdir()), f"{src} is empty"


def test_manifest_matches_pyproject_package_data():
    """Everything setuptools ships as package data must also be bundled by PyInstaller."""
    import tomllib

    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    globs = data["tool"]["setuptools"]["package-data"]["aisrf"]
    manifest = _load_manifest()
    for pattern in globs:
        directory = pattern.rsplit("/", 1)[0]
        assert directory in manifest.PACKAGE_DATA_DIRS, f"{directory} is package data but not in the manifest"


def test_manifest_excludes_heavy_optional_packages_but_not_hard_dependencies():
    manifest = _load_manifest()
    excludes = set(manifest.EXCLUDES)
    for heavy in (
        "torch",
        "transformers",
        "garak",
        "pyrit",
        "llm_guard",
        "nemoguardrails",
        "semgrep",
        "playwright",
        "pytest",
    ):
        assert heavy in excludes, heavy
    for needed in (
        "PIL",
        "opentelemetry",
        "uvicorn",
        "sqlalchemy",
        "aiosqlite",
        "jinja2",
        "mcp",
        "reportlab",
        "openpyxl",
        "yaml",
        "typer",
        "rich",
    ):
        assert needed not in excludes, f"{needed} is required at runtime and must not be excluded"


def test_spec_uses_the_shared_manifest_and_launcher():
    spec = (PACKAGING / "aisrf.spec").read_text(encoding="utf-8")
    assert "from manifest import" in spec
    assert "launcher.py" in spec
    assert 'name="aisrf"' in spec
    assert "console=True" in spec
    launcher = (PACKAGING / "launcher.py").read_text(encoding="utf-8")
    assert "configure_environment" in launcher and "aisrf.cli import app" in launcher


def test_manifest_hidden_imports_are_importable_in_the_dev_environment():
    """A typo in HIDDEN_IMPORTS is only a PyInstaller warning; catch the ones we can here."""
    manifest = _load_manifest()
    sample = [
        "uvicorn.loops.auto",
        "uvicorn.protocols.http.h11_impl",
        "sqlalchemy.dialects.sqlite.aiosqlite",
        "aiosqlite",
        "structlog.dev",
        "jinja2.ext",
        "sse_starlette.sse",
        "reportlab.platypus",
        "openpyxl.styles",
        "yaml",
    ]
    for name in sample:
        assert name in manifest.HIDDEN_IMPORTS, name
        assert importlib.util.find_spec(name) is not None, name


# --- desktop helper ----------------------------------------------------------------------------
def test_app_dir_per_platform(tmp_path: Path):
    from aisrf import desktop

    home = tmp_path / "home"
    assert (
        desktop.app_dir("win32", {"LOCALAPPDATA": r"C:\Users\k\AppData\Local"}, home)
        == Path(r"C:\Users\k\AppData\Local") / "AISRF"
    )
    assert desktop.app_dir("win32", {}, home) == home / "AppData" / "Local" / "AISRF"
    assert desktop.app_dir("darwin", {}, home) == home / "Library" / "Application Support" / "AISRF"
    assert desktop.app_dir("linux", {}, home) == home / ".local" / "share" / "aisrf"
    assert (
        desktop.app_dir("linux", {"XDG_DATA_HOME": str(tmp_path / "xdg")}, home) == tmp_path / "xdg" / "aisrf"
    )
    assert desktop.app_dir("linux", {"AISRF_HOME": str(tmp_path / "custom")}, home) == tmp_path / "custom"
    assert (
        desktop.app_dir("darwin", {"AISRF_HOME": "~/aisrf-state"}, home) == Path("~/aisrf-state").expanduser()
    )


def test_ensure_env_file_creates_0600_and_is_stable(tmp_path: Path):
    from aisrf import desktop

    directory = tmp_path / "app"
    first = desktop.ensure_env_file(directory)
    path = directory / "aisrf.env"
    assert path.is_file()
    assert len(first["AISRF_SECRET_KEY"]) >= 32
    assert len(first["AISRF_ADMIN_API_TOKEN"]) >= 32
    assert first["AISRF_SECRET_KEY"] != first["AISRF_ADMIN_API_TOKEN"]
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    second = desktop.ensure_env_file(directory)
    assert second == first
    assert desktop.read_env_file(path) == first
    text = path.read_text(encoding="utf-8")
    assert text.startswith("#") and "AISRF_SECRET_KEY=" in text


def test_ensure_env_file_preserves_user_settings_and_fills_missing_keys(tmp_path: Path):
    from aisrf import desktop

    directory = tmp_path / "app"
    directory.mkdir()
    (directory / "aisrf.env").write_text(
        'AISRF_ADMIN_PASSWORD="s3cret"\nAISRF_SECRET_KEY=my-own-key-0123456789abcdef\n', encoding="utf-8"
    )
    values = desktop.ensure_env_file(directory)
    assert values["AISRF_ADMIN_PASSWORD"] == "s3cret"
    assert values["AISRF_SECRET_KEY"] == "my-own-key-0123456789abcdef"
    assert values["AISRF_ADMIN_API_TOKEN"]
    again = desktop.read_env_file(directory / "aisrf.env")
    assert again == values


def test_default_environment_points_into_app_dir(tmp_path: Path):
    from aisrf import desktop

    env = desktop.default_environment(tmp_path)
    assert env["AISRF_DATA_DIR"] == str(tmp_path / "data")
    assert env["AISRF_LOG_DIR"] == str(tmp_path / "logs")
    assert env["AISRF_DATABASE_URL"] == f"sqlite+aiosqlite:///{(tmp_path / 'data' / 'aisrf.db').as_posix()}"


def test_configure_environment_is_a_noop_from_source_without_aisrf_home(monkeypatch: pytest.MonkeyPatch):
    from aisrf import desktop

    monkeypatch.delenv("AISRF_HOME", raising=False)
    monkeypatch.setattr(desktop, "is_frozen", lambda: False)
    assert desktop.configure_environment() is None


def test_configure_environment_with_aisrf_home_sets_defaults_but_keeps_explicit_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from aisrf import desktop

    home = tmp_path / "state"
    monkeypatch.setenv("AISRF_HOME", str(home))
    for key in (
        "AISRF_DATA_DIR",
        "AISRF_LOG_DIR",
        "AISRF_DATABASE_URL",
        "AISRF_SECRET_KEY",
        "AISRF_ADMIN_API_TOKEN",
    ):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("AISRF_LOG_DIR", str(tmp_path / "elsewhere"))
    assert desktop.configure_environment() == home
    assert os.environ["AISRF_DATA_DIR"] == str(home / "data")
    assert os.environ["AISRF_LOG_DIR"] == str(tmp_path / "elsewhere")
    assert os.environ["AISRF_DATABASE_URL"].startswith("sqlite+aiosqlite:///")
    assert os.environ["AISRF_SECRET_KEY"] == desktop.read_env_file(home / "aisrf.env")["AISRF_SECRET_KEY"]


def test_cli_exposes_desktop_command():
    from typer.testing import CliRunner

    from aisrf.cli import app

    result = CliRunner().invoke(app, ["desktop", "--help"])
    assert result.exit_code == 0
    assert "--no-window" in result.output and "--port" in result.output


def test_pyproject_declares_desktop_extra_and_script():
    import tomllib

    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert any(dep.startswith("pywebview") for dep in data["project"]["optional-dependencies"]["desktop"])
    assert data["project"]["scripts"]["aisrf-desktop"] == "aisrf.desktop:main"


# --- install scripts and deployment assets -----------------------------------------------------
@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_install_sh_passes_bash_syntax_check():
    subprocess.run(["bash", "-n", str(ROOT / "scripts" / "install.sh")], check=True)


def test_install_scripts_reference_release_assets():
    sh = (ROOT / "scripts" / "install.sh").read_text(encoding="utf-8")
    ps1 = (ROOT / "scripts" / "install.ps1").read_text(encoding="utf-8")
    assert "SHA256SUMS-" in sh and "releases/download" in sh
    assert "SHA256SUMS-windows-" in ps1 and "Get-FileHash" in ps1 and "Programs\\AISRF" in ps1


def test_systemd_unit_parses_and_is_hardened():
    import configparser

    text = (DEPLOY / "systemd" / "aisrf.service").read_text(encoding="utf-8")
    parser = configparser.RawConfigParser(strict=False)
    parser.optionxform = str  # type: ignore[assignment]
    parser.read_string(text)
    assert parser.get("Service", "EnvironmentFile") == "/etc/aisrf/aisrf.env"
    assert parser.get("Service", "User") == "aisrf"
    assert parser.get("Service", "ExecStart").endswith("aisrf serve")
    for directive in (
        "NoNewPrivileges",
        "ProtectSystem",
        "ProtectHome",
        "PrivateTmp",
        "CapabilityBoundingSet",
    ):
        assert parser.has_option("Service", directive), directive
    assert parser.get("Install", "WantedBy") == "multi-user.target"


def test_launchd_plist_is_valid_xml():
    import plistlib

    data = plistlib.loads((DEPLOY / "launchd" / "com.aisrf.gateway.plist").read_bytes())
    assert data["Label"] == "com.aisrf.gateway"
    assert data["ProgramArguments"][1] == "serve"


def test_kubernetes_manifests_parse():
    files = sorted((DEPLOY / "kubernetes").glob("*.yaml"))
    assert files
    kinds = set()
    for path in files:
        for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")):
            assert doc and "kind" in doc and "apiVersion" in doc, path
            kinds.add(doc["kind"])
    assert {
        "Deployment",
        "Service",
        "PersistentVolumeClaim",
        "Secret",
        "Ingress",
        "HorizontalPodAutoscaler",
    } <= kinds
    deployment = yaml.safe_load((DEPLOY / "kubernetes" / "deployment.yaml").read_text(encoding="utf-8"))
    container = deployment["spec"]["template"]["spec"]["containers"][0]
    assert container["image"].startswith("ghcr.io/keyuraghao/aisrf")
    assert container["livenessProbe"]["httpGet"]["path"] == "/healthz"
    assert container["readinessProbe"]["httpGet"]["path"] == "/readyz"


def test_helm_chart_files_parse():
    chart = DEPLOY / "helm" / "aisrf"
    meta = yaml.safe_load((chart / "Chart.yaml").read_text(encoding="utf-8"))
    assert meta["name"] == "aisrf" and meta["apiVersion"] == "v2"
    values = yaml.safe_load((chart / "values.yaml").read_text(encoding="utf-8"))
    assert values["image"]["repository"] == "ghcr.io/keyuraghao/aisrf"
    assert values["probes"]["liveness"]["path"] == "/healthz"
    assert values["probes"]["readiness"]["path"] == "/readyz"
    for name in ("deployment", "service", "pvc", "secret", "ingress", "hpa", "serviceaccount"):
        assert (chart / "templates" / f"{name}.yaml").is_file(), name
    assert (chart / "templates" / "NOTES.txt").is_file()
    assert (chart / "templates" / "_helpers.tpl").is_file()


@pytest.mark.skipif(shutil.which("helm") is None, reason="helm not installed")
def test_helm_lint():
    subprocess.run(["helm", "lint", str(DEPLOY / "helm" / "aisrf")], check=True, capture_output=True)


def test_workflows_include_binary_jobs():
    release = yaml.safe_load((ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8"))
    ci = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
    assert "binaries" in release["jobs"]
    assert "binaries" in release["jobs"]["release"]["needs"]
    runners = {entry["runner"] for entry in release["jobs"]["binaries"]["strategy"]["matrix"]["include"]}
    assert {"ubuntu-latest", "windows-latest", "macos-14", "macos-13"} <= runners
    assert "binary-smoke" in ci["jobs"]


# --- built binary (optional) -------------------------------------------------------------------
@pytest.mark.skipif(not BINARY.exists(), reason="no built binary in dist/aisrf (run scripts/build_binary.py)")
def test_built_binary_reports_version(tmp_path: Path):
    from aisrf import __version__

    env = {k: v for k, v in os.environ.items() if not k.startswith("AISRF_")}
    env["AISRF_HOME"] = str(tmp_path)
    out = subprocess.run(
        [str(BINARY), "version"], env=env, capture_output=True, text=True, timeout=120, check=True
    )
    assert __version__ in out.stdout

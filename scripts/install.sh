#!/usr/bin/env bash
# AISRF installer for Linux and macOS: downloads the latest self-contained release archive from
# GitHub, verifies its SHA256, unpacks it and links the `aisrf` binary into your PATH.
#
#   curl -fsSL https://raw.githubusercontent.com/keyuraghao/aisrf/main/scripts/install.sh | bash
#
# Environment:
#   AISRF_VERSION   release to install (default: latest), e.g. 1.2.0
#   AISRF_PREFIX    install directory (default: /usr/local/lib/aisrf when writable or run with
#                   sudo, otherwise ~/.local/lib/aisrf); the binary is linked into
#                   /usr/local/bin or ~/.local/bin accordingly
#   AISRF_REPO      GitHub repository (default: keyuraghao/aisrf)
#   AISRF_NO_MODIFY_PATH=1   do not print PATH advice
set -euo pipefail

REPO="${AISRF_REPO:-keyuraghao/aisrf}"
VERSION="${AISRF_VERSION:-latest}"
API="https://api.github.com/repos/${REPO}/releases"

say() { printf '\033[1;36m[aisrf]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[aisrf] error:\033[0m %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing required tool: $1"; }

need curl
need tar

case "$(uname -s)" in
  Linux) OS="linux" ;;
  Darwin) OS="macos" ;;
  *) die "unsupported operating system: $(uname -s) (use Docker or pip install aisrf)" ;;
esac
case "$(uname -m)" in
  x86_64|amd64) ARCH="x86_64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac
if [ "$OS" = "macos" ] && [ "$ARCH" != "arm64" ]; then
  echo "AISRF macOS binaries are built for Apple silicon only. Intel Macs are not supported; install from source with pip instead." >&2
  exit 1
fi

if [ "$VERSION" = "latest" ]; then
  say "resolving the latest release of ${REPO}"
  VERSION="$(curl -fsSL "${API}/latest" | sed -n 's/.*"tag_name": *"v\{0,1\}\([^"]*\)".*/\1/p' | head -n1)"
  [ -n "$VERSION" ] || die "could not determine the latest release (rate limited? set AISRF_VERSION=x.y.z)"
fi
VERSION="${VERSION#v}"
ARCHIVE="aisrf-${VERSION}-${OS}-${ARCH}.tar.gz"
SUMS="SHA256SUMS-${OS}-${ARCH}.txt"
BASE="https://github.com/${REPO}/releases/download/v${VERSION}"

if [ -n "${AISRF_PREFIX:-}" ]; then
  PREFIX="$AISRF_PREFIX"
  BIN_DIR="${PREFIX%/lib/aisrf}/bin"
  case "$PREFIX" in */lib/aisrf) ;; *) BIN_DIR="$PREFIX/bin" ;; esac
elif [ -w /usr/local/lib ] || [ "$(id -u)" = "0" ]; then
  PREFIX="/usr/local/lib/aisrf"
  BIN_DIR="/usr/local/bin"
else
  PREFIX="$HOME/.local/lib/aisrf"
  BIN_DIR="$HOME/.local/bin"
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

say "downloading ${ARCHIVE} (v${VERSION})"
curl -fL --progress-bar -o "$TMP/$ARCHIVE" "$BASE/$ARCHIVE" || die "download failed: $BASE/$ARCHIVE (no binary for ${OS}-${ARCH} in this release?)"
curl -fsSL -o "$TMP/$SUMS" "$BASE/$SUMS" || die "checksum file missing: $BASE/$SUMS"

say "verifying SHA256"
EXPECTED="$(grep " ${ARCHIVE}\$" "$TMP/$SUMS" | awk '{print $1}')"
[ -n "$EXPECTED" ] || die "${ARCHIVE} is not listed in ${SUMS}"
if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL="$(sha256sum "$TMP/$ARCHIVE" | awk '{print $1}')"
else
  ACTUAL="$(shasum -a 256 "$TMP/$ARCHIVE" | awk '{print $1}')"
fi
[ "$EXPECTED" = "$ACTUAL" ] || die "checksum mismatch: expected $EXPECTED got $ACTUAL"

say "installing to ${PREFIX}"
mkdir -p "$PREFIX" "$BIN_DIR"
rm -rf "$PREFIX/aisrf"
tar -xzf "$TMP/$ARCHIVE" -C "$PREFIX"
chmod +x "$PREFIX/aisrf/aisrf"
ln -sf "$PREFIX/aisrf/aisrf" "$BIN_DIR/aisrf"

if [ "$OS" = "macos" ] && command -v xattr >/dev/null 2>&1; then
  # The binaries are not notarized; remove the quarantine flag so Gatekeeper does not block them.
  xattr -dr com.apple.quarantine "$PREFIX/aisrf" 2>/dev/null || true
fi

INSTALLED="$("$BIN_DIR/aisrf" version 2>/dev/null || true)"
say "installed ${INSTALLED:-aisrf} -> ${BIN_DIR}/aisrf"

case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) [ "${AISRF_NO_MODIFY_PATH:-0}" = "1" ] || say "add ${BIN_DIR} to your PATH, e.g. export PATH=\"${BIN_DIR}:\$PATH\"" ;;
esac

cat <<EOF

Next steps:
  aisrf desktop            # local dashboard on 127.0.0.1, opens a window or your browser
  aisrf serve              # gateway on 0.0.0.0:8080 (set AISRF_HOST / AISRF_PORT)
  aisrf --help

State (SQLite, logs) and the generated settings file aisrf.env with a random secret key and admin
API token live in ~/.local/share/aisrf (Linux) or ~/Library/Application Support/AISRF (macOS);
set AISRF_HOME to relocate them. Sign in with admin / admin and change the password immediately.
Server installs: see deploy/systemd (Linux) and deploy/launchd (macOS) in the repository.
Uninstall: rm -rf "${PREFIX}" "${BIN_DIR}/aisrf" and the state directory above.
EOF

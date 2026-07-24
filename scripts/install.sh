#!/usr/bin/env bash
# Install the latest loglens release binary for this platform.
# Usage: curl -fsSL https://raw.githubusercontent.com/dorman/loglens/master/scripts/install.sh | bash
set -euo pipefail

REPO="dorman/loglens"
PREFIX="${PREFIX:-/usr/local}"
BIN_DIR="${BIN_DIR:-$PREFIX/bin}"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "error: '$1' is required" >&2
    exit 1
  }
}

need curl
need tar
need uname

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"
case "$os" in
  linux) os_tag="unknown-linux-gnu" ;;
  darwin) os_tag="apple-darwin" ;;
  *)
    echo "error: unsupported OS '$os' (download a release asset manually from GitHub)" >&2
    exit 1
    ;;
esac
case "$arch" in
  x86_64|amd64) arch_tag="x86_64" ;;
  arm64|aarch64) arch_tag="aarch64" ;;
  *)
    echo "error: unsupported architecture '$arch'" >&2
    exit 1
    ;;
esac

target="${arch_tag}-${os_tag}"
asset="loglens-${target}.tar.gz"

echo "Resolving latest release for ${target}…"
api="https://api.github.com/repos/${REPO}/releases/latest"
# Prefer the tagged browser_download_url matching our asset name.
url="$(curl -fsSL "$api" | sed -n "s/.*\"browser_download_url\": \"\\([^\"]*${asset}\\)\"/\1/p" | head -n1)"
if [[ -z "$url" ]]; then
  echo "error: could not find asset ${asset} in the latest GitHub release." >&2
  echo "       Releases: https://github.com/${REPO}/releases" >&2
  echo "       Or install from source: cargo install --git https://github.com/${REPO} --locked" >&2
  exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
echo "Downloading ${url}"
curl -fsSL "$url" -o "$tmp/$asset"
tar -xzf "$tmp/$asset" -C "$tmp"
bin="$(find "$tmp" -type f -name loglens | head -n1)"
if [[ -z "$bin" ]]; then
  echo "error: archive did not contain a loglens binary" >&2
  exit 1
fi

dest="${BIN_DIR}/loglens"
echo "Installing to ${dest}"
if [[ -w "$BIN_DIR" ]] || [[ "$(id -u)" -eq 0 ]]; then
  mkdir -p "$BIN_DIR"
  install -m 755 "$bin" "$dest"
else
  echo "(BIN_DIR not writable — using sudo)"
  sudo mkdir -p "$BIN_DIR"
  sudo install -m 755 "$bin" "$dest"
fi

echo "Installed $($dest --version)"
echo "Try: loglens --help"

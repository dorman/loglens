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
# Do not use curl -f: a missing release (HTTP 404) should fall through to the
# friendly "install from source" message below instead of a raw curl error.
http_body="$(mktemp)"
http_code="$(curl -sS -o "$http_body" -w "%{http_code}" "$api" || true)"
if [[ "$http_code" != "200" ]]; then
  code="${http_code:-000}"
  if [[ "$code" == "404" ]]; then
    echo "error: no GitHub Release published yet (HTTP 404)." >&2
    echo "       Prebuilt installs land after a public v* tag; until then use source:" >&2
  else
    echo "error: GitHub Releases API request failed (HTTP ${code})." >&2
    echo "       Check network / API access, then retry — or install from source:" >&2
  fi
  echo "         cargo install --git https://github.com/${REPO} --locked" >&2
  echo "       Or from a clone: cargo install --path . --locked" >&2
  echo "       Releases: https://github.com/${REPO}/releases" >&2
  rm -f "$http_body"
  exit 1
fi
# Prefer the tagged browser_download_url matching our asset name.
url="$(sed -n "s/.*\"browser_download_url\": \"\\([^\"]*${asset}\\)\"/\1/p" "$http_body" | head -n1)"
sums_url="$(sed -n "s/.*\"browser_download_url\": \"\\([^\"]*SHA256SUMS\\)\"/\1/p" "$http_body" | head -n1)"
rm -f "$http_body"
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

# Verify the archive against the release's SHA256SUMS before unpacking it. This
# is what turns "curl | bash" from "trust the transport" into "trust the release".
if [[ -n "$sums_url" ]] && command -v sha256sum >/dev/null 2>&1; then
  verifier=(sha256sum -c -)
elif [[ -n "$sums_url" ]] && command -v shasum >/dev/null 2>&1; then
  verifier=(shasum -a 256 -c -)
else
  verifier=()
fi
if [[ -n "$sums_url" && ${#verifier[@]} -gt 0 ]]; then
  echo "Verifying checksum…"
  curl -fsSL "$sums_url" -o "$tmp/SHA256SUMS"
  expected="$(awk -v a="$asset" '$2 == a || $2 == "*"a {print $1}' "$tmp/SHA256SUMS" | head -n1)"
  if [[ -z "$expected" ]]; then
    echo "error: ${asset} is not listed in the release SHA256SUMS — refusing to install." >&2
    exit 1
  fi
  if ! (cd "$tmp" && printf '%s  %s\n' "$expected" "$asset" | "${verifier[@]}" >/dev/null 2>&1); then
    echo "error: checksum mismatch for ${asset} — refusing to install." >&2
    echo "       Re-run, or install from source: cargo install --git https://github.com/${REPO} --locked" >&2
    exit 1
  fi
elif [[ -z "$sums_url" ]]; then
  echo "warning: release has no SHA256SUMS asset — cannot verify the download." >&2
else
  echo "warning: neither sha256sum nor shasum found — cannot verify the download." >&2
fi

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

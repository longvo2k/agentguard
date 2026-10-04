#!/bin/sh
# AgentGuard installer.
#
#   curl -fsSL https://raw.githubusercontent.com/longvo2k/agentguard/main/install.sh | sh
#
# Downloads a release binary for this OS and CPU, verifies its SHA-256
# checksum against the release's checksums.txt, installs it (no sudo), then
# offers to run `agentguard setup`.
#
# Environment:
#   AGENTGUARD_VERSION        release tag to install (default: latest), e.g. v0.2.0
#   AGENTGUARD_INSTALL_DIR    where to put the binary (default: ~/.local/bin)
#   AGENTGUARD_NO_SETUP=1     do not run `agentguard setup` afterwards
#   AGENTGUARD_DOWNLOAD_BASE  download from this URL instead of GitHub (mirrors, tests)

set -eu

REPO="longvo2k/agentguard"
VERSION="${AGENTGUARD_VERSION:-latest}"
INSTALL_DIR="${AGENTGUARD_INSTALL_DIR:-${HOME}/.local/bin}"

say() { printf '%s\n' "$*"; }
fail() { printf 'agentguard install: %s\n' "$*" >&2; exit 1; }

download() { # url dest
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --proto '=https,file' --retry 3 -o "$2" "$1"
	elif command -v wget >/dev/null 2>&1; then
		wget -q -O "$2" "$1"
	else
		fail "need curl or wget"
	fi
}

sha256() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | cut -d' ' -f1
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | cut -d' ' -f1
	else
		fail "need sha256sum or shasum to verify the download"
	fi
}

case "$(uname -s)" in
Linux) os=linux ;;
Darwin) os=darwin ;;
*) fail "unsupported OS $(uname -s) (Linux and macOS only)" ;;
esac
case "$(uname -m)" in
x86_64 | amd64) arch=amd64 ;;
arm64 | aarch64) arch=arm64 ;;
*) fail "unsupported CPU $(uname -m)" ;;
esac

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

if [ "$VERSION" = latest ]; then
	download "https://api.github.com/repos/${REPO}/releases/latest" "$tmp/latest.json" ||
		fail "cannot find the latest release on GitHub (none published yet, or no network); set AGENTGUARD_VERSION"
	tag="$(sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' "$tmp/latest.json" | head -n 1)"
	[ -n "$tag" ] || fail "no published release found"
else
	tag="$VERSION"
fi
case "$tag" in
v*) ver="${tag#v}" ;;
*) ver="$tag" tag="v$tag" ;;
esac

archive="agentguard_${ver}_${os}_${arch}.tar.gz"
base="${AGENTGUARD_DOWNLOAD_BASE:-https://github.com/${REPO}/releases/download/${tag}}"

say "Downloading AgentGuard ${tag} for ${os}/${arch}..."
download "${base}/${archive}" "$tmp/${archive}" || fail "download failed: ${base}/${archive}"
download "${base}/checksums.txt" "$tmp/checksums.txt" || fail "download failed: ${base}/checksums.txt"

expected="$(awk -v f="$archive" '$2 == f || $2 == "*" f { print $1 }' "$tmp/checksums.txt")"
[ -n "$expected" ] || fail "${archive} is not listed in checksums.txt"
actual="$(sha256 "$tmp/${archive}")"
[ "$expected" = "$actual" ] || fail "checksum mismatch for ${archive} (expected ${expected}, got ${actual}); not installing"
say "Checksum verified."

tar -xzf "$tmp/${archive}" -C "$tmp" agentguard
mkdir -p "$INSTALL_DIR"
# Install via a temporary name and rename, so a running agentguard is never
# left half-written.
cp "$tmp/agentguard" "$INSTALL_DIR/.agentguard.new"
chmod 0755 "$INSTALL_DIR/.agentguard.new"
mv -f "$INSTALL_DIR/.agentguard.new" "$INSTALL_DIR/agentguard"
say "Installed $INSTALL_DIR/agentguard"

case ":${PATH}:" in
*":${INSTALL_DIR}:"*) ;;
*)
	say ""
	say "Add ${INSTALL_DIR} to your PATH, for example:"
	say "  echo 'export PATH=\"${INSTALL_DIR}:\$PATH\"' >> ~/.profile"
	;;
esac

if [ -n "${AGENTGUARD_NO_SETUP:-}" ]; then
	say ""
	say "Next: agentguard setup"
elif (: </dev/tty) 2>/dev/null; then
	# The script itself is read from a pipe, so ask on the terminal.
	say ""
	PATH="${INSTALL_DIR}:${PATH}" "$INSTALL_DIR/agentguard" setup </dev/tty
else
	say ""
	say "Next: agentguard setup"
fi

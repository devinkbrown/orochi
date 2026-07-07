#!/usr/bin/env bash
# Independently verify an Orochi release is reproducible and untampered.
#
# Rebuilds the CURRENT checkout from source with a clean cache and checks the
# resulting static binary byte-for-byte against a SHA256SUMS manifest. Because
# the build is hermetic and deterministic, a matching hash proves the published
# artifact was built from exactly this source — no trust in the release machine
# required. If a cosign signature is present, it is verified too.
#
# Usage:  packaging/verify-release.sh [path/to/SHA256SUMS]
#         (default: dist/SHA256SUMS)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

SUMS="${1:-dist/SHA256SUMS}"
TARGET="x86_64-linux-musl"

if [ ! -f "$SUMS" ]; then
  echo "verify: no manifest at $SUMS — run packaging/release.sh first (or pass its path)" >&2
  exit 2
fi
if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
  echo "verify: working tree is dirty — a reproducible check must run on a clean checkout" >&2
  exit 2
fi

EXPECTED="$(awk '{print $1}' "$SUMS" | head -1)"
ARTIFACT="$(awk '{print $2}' "$SUMS" | head -1)"
echo "verify: expected $EXPECTED  ($ARTIFACT)"
echo "verify: rebuilding from source @ $(git rev-parse --short HEAD) with a clean cache…"

CACHE="$(mktemp -d)"
trap 'rm -rf "$CACHE"' EXIT
zig build -Dtarget="$TARGET" -Doptimize=ReleaseFast --cache-dir "$CACHE" --prefix "$CACHE/out" >/dev/null

ACTUAL="$(sha256sum "$CACHE/out/bin/orochi" | cut -d' ' -f1)"
echo "verify: rebuilt  $ACTUAL"

if [ "$ACTUAL" != "$EXPECTED" ]; then
  echo "❌ verify: MISMATCH — the rebuild does not match the manifest (different source, toolchain, or tampering)." >&2
  exit 1
fi
echo "✅ verify: REPRODUCIBLE — the rebuild is byte-identical to the published artifact."

# Optional signature check.
SIG="$(dirname "$SUMS")/SHA256SUMS.sig"
if [ -f "$SIG" ] && command -v cosign >/dev/null 2>&1; then
  echo "verify: checking cosign signature…"
  if [ -n "${COSIGN_PUBKEY:-}" ]; then
    cosign verify-blob --key "$COSIGN_PUBKEY" --signature "$SIG" "$SUMS" \
      && echo "✅ verify: signature valid" || { echo "❌ verify: BAD signature" >&2; exit 1; }
  else
    echo "verify: signature present but COSIGN_PUBKEY unset — skipping (set it to verify the signer)"
  fi
fi

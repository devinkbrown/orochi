#!/usr/bin/env bash
# Independently verify an Onyx Server release is reproducible and untampered.
#
# Three checks, in order:
#   1. REPRODUCIBILITY — rebuild the CURRENT checkout from source with a clean
#      cache and confirm the static binary is byte-for-byte identical to the
#      SHA256SUMS manifest. Because the build is hermetic and deterministic, a
#      matching hash proves the published artifact was built from exactly this
#      source — no trust in the release machine required.
#   2. MANIFEST INTEGRITY — confirm every other published artifact (SBOM,
#      provenance) still matches SHA256SUMS, catching post-publish tampering.
#   3. SIGNATURE — if a cosign signature is present, verify it.
#
# Requires git, zig, sha256sum. cosign is optional (skipped if absent).
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

SUMS_DIR="$(cd "$(dirname "$SUMS")" && pwd)"
SUMS_FILE="$(basename "$SUMS")"

# The binary is always the FIRST line of the manifest.
EXPECTED="$(awk '{print $1}' "$SUMS" | head -1)"
ARTIFACT="$(awk '{print $2}' "$SUMS" | head -1)"
echo "verify: expected $EXPECTED  ($ARTIFACT)"
echo "verify: rebuilding from source @ $(git rev-parse --short HEAD) with a clean cache…"

CACHE="$(mktemp -d)"
trap 'rm -rf "$CACHE"' EXIT
export SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"
zig build -Dtarget="$TARGET" -Doptimize=ReleaseFast --cache-dir "$CACHE" --prefix "$CACHE/out" >/dev/null

ACTUAL="$(sha256sum "$CACHE/out/bin/onyx-server" | cut -d' ' -f1)"
echo "verify: rebuilt  $ACTUAL"

if [ "$ACTUAL" != "$EXPECTED" ]; then
  echo "❌ verify: MISMATCH — the rebuild does not match the manifest (different source, toolchain, or tampering)." >&2
  exit 1
fi
echo "✅ verify: REPRODUCIBLE — the rebuild is byte-identical to the published artifact."

# --- Shipped-binary integrity: bind the DOWNLOADED binary to the manifest -----
# The check above proves the manifest reproduces from source, but hashes the
# freshly-rebuilt binary — NOT the one that shipped. Independently bind the
# shipped binary (when present) so a tampered download cannot pass on the
# strength of a clean rebuild alone.
if [ -f "$SUMS_DIR/$ARTIFACT" ]; then
  SHIPPED="$(sha256sum "$SUMS_DIR/$ARTIFACT" | cut -d' ' -f1)"
  if [ "$SHIPPED" != "$EXPECTED" ]; then
    echo "❌ verify: the SHIPPED binary $ARTIFACT does not match SHA256SUMS (tampering)." >&2
    exit 1
  fi
  echo "✅ verify: shipped binary matches SHA256SUMS."
fi

# --- Manifest integrity: SBOM + provenance still match SHA256SUMS -------------
# Per-file, not all-or-nothing: `--ignore-missing` tolerates a partial download
# (a missing artifact is skipped) but FAILS on any file that is present and does
# not match — so a tampered SBOM/provenance is always caught.
INTEG="$( cd "$SUMS_DIR" && sha256sum -c --ignore-missing "$SUMS_FILE" 2>&1 )" && rc=0 || rc=$?
if printf '%s\n' "$INTEG" | grep -q ': FAILED$'; then
  echo "❌ verify: manifest integrity FAILED — a published artifact does not match SHA256SUMS (tampering)." >&2
  printf '%s\n' "$INTEG" | grep ': FAILED$' >&2
  exit 1
elif [ "$rc" -eq 0 ]; then
  echo "✅ verify: manifest integrity OK — every present artifact matches SHA256SUMS."
else
  echo "verify: (note) some artifacts not present alongside the manifest — verified those that are."
fi

# --- Optional signature check -------------------------------------------------
# Key-file: set COSIGN_PUBKEY. Keyless (Fulcio/Rekor): set COSIGN_IDENTITY +
# COSIGN_OIDC_ISSUER (verified against the bundle release.sh emitted). Missing
# verification material degrades to a prominent note, not a false pass.
SIG="$SUMS_DIR/SHA256SUMS.sig"
BUNDLE="$SUMS_DIR/SHA256SUMS.cosign.bundle"
if [ -f "$SIG" ] && command -v cosign >/dev/null 2>&1; then
  echo "verify: checking cosign signature…"
  if [ -n "${COSIGN_PUBKEY:-}" ]; then
    cosign verify-blob --key "$COSIGN_PUBKEY" --signature "$SIG" "$SUMS" \
      && echo "✅ verify: signature valid" || { echo "❌ verify: BAD signature" >&2; exit 1; }
  elif [ -n "${COSIGN_IDENTITY:-}" ] && [ -n "${COSIGN_OIDC_ISSUER:-}" ] && [ -f "$BUNDLE" ]; then
    cosign verify-blob --bundle "$BUNDLE" \
      --certificate-identity "$COSIGN_IDENTITY" \
      --certificate-oidc-issuer "$COSIGN_OIDC_ISSUER" "$SUMS" \
      && echo "✅ verify: keyless signature valid" || { echo "❌ verify: BAD signature" >&2; exit 1; }
  else
    echo "⚠️  verify: signature present but NOT verified — set COSIGN_PUBKEY (key) or COSIGN_IDENTITY + COSIGN_OIDC_ISSUER (keyless) to check the signer." >&2
  fi
elif [ -f "$SIG" ]; then
  echo "⚠️  verify: signature present but cosign not installed — cannot check the signer." >&2
fi

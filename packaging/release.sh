#!/usr/bin/env bash
# Build a reproducible, signed Orochi release artifact.
#
# Orochi's build is hermetic (pure Zig, zero external/C dependencies) and static
# (x86_64-linux-musl), so a ReleaseFast build at a fixed commit is bit-for-bit
# reproducible — anyone can rebuild it and get the same bytes. This script
# produces the artifact, a SHA256SUMS manifest, and a one-screen CycloneDX SBOM;
# it optionally cosign-signs the manifest if `cosign` and a key are available.
#
# Usage:  packaging/release.sh [output-dir]     (default: dist/)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

OUT="${1:-dist}"
TARGET="x86_64-linux-musl"

# A clean tree gives a clean `<semver>+<hash>` version (no `-dirty` suffix), which
# is what makes the artifact reproducible for anyone building the same commit.
if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
  echo "release: refusing to build — working tree is dirty (version would be -dirty, not reproducible)" >&2
  exit 1
fi

COMMIT="$(git rev-parse --short HEAD)"
VERSION="$(grep -oE '\.version = "[^"]+"' build.zig.zon | head -1 | sed -E 's/.*"([^"]+)".*/\1/')"
ARTIFACT="orochi-${VERSION}-${TARGET}"

echo "release: building ${ARTIFACT} @ ${COMMIT} (reproducible static ReleaseFast)…"
CACHE="$(mktemp -d)"
trap 'rm -rf "$CACHE"' EXIT
zig build -Dtarget="$TARGET" -Doptimize=ReleaseFast --cache-dir "$CACHE" --prefix "$CACHE/out"

mkdir -p "$OUT"
cp "$CACHE/out/bin/orochi" "$OUT/$ARTIFACT"
chmod 755 "$OUT/$ARTIFACT"

# SHA256SUMS — the reproducibility anchor. `verify-release.sh` rebuilds and
# checks against this.
( cd "$OUT" && sha256sum "$ARTIFACT" > SHA256SUMS )
echo "release: $(cat "$OUT/SHA256SUMS")"

# One-screen CycloneDX SBOM — genuinely one screen, because the dependency graph
# is a single self-contained binary with zero external components.
SIZE="$(stat -c%s "$OUT/$ARTIFACT")"
DIGEST="$(sha256sum "$OUT/$ARTIFACT" | cut -d' ' -f1)"
ZIGVER="$(zig version)"
cat > "$OUT/orochi.cdx.json" <<JSON
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "metadata": {
    "component": {
      "type": "application",
      "name": "orochi",
      "version": "${VERSION}+${COMMIT}",
      "description": "Clean-room, pure-Zig, zero-external-dependency IRC/IRCX mesh daemon with its own TLS 1.3 stack.",
      "licenses": [{ "license": { "id": "AGPL-3.0-or-later" } }],
      "purl": "pkg:generic/orochi@${VERSION}?arch=x86_64&os=linux&libc=musl"
    },
    "tools": [{ "vendor": "ziglang", "name": "zig", "version": "${ZIGVER}" }],
    "properties": [
      { "name": "orochi:reproducible", "value": "true" },
      { "name": "orochi:target", "value": "${TARGET}" },
      { "name": "orochi:linkage", "value": "static" },
      { "name": "orochi:sizeBytes", "value": "${SIZE}" }
    ]
  },
  "components": [],
  "properties": [
    { "name": "orochi:externalDependencies", "value": "0" },
    { "name": "orochi:sha256", "value": "${DIGEST}" }
  ]
}
JSON
echo "release: SBOM → $OUT/orochi.cdx.json (0 external components)"

# Optional signing: keyless (CI OIDC) or with a cosign key if configured.
if command -v cosign >/dev/null 2>&1 && { [ -n "${COSIGN_KEY:-}" ] || [ -n "${COSIGN_EXPERIMENTAL:-}" ]; }; then
  echo "release: cosign-signing SHA256SUMS…"
  if [ -n "${COSIGN_KEY:-}" ]; then
    cosign sign-blob --yes --key "$COSIGN_KEY" --output-signature "$OUT/SHA256SUMS.sig" "$OUT/SHA256SUMS"
  else
    COSIGN_EXPERIMENTAL=1 cosign sign-blob --yes --output-signature "$OUT/SHA256SUMS.sig" "$OUT/SHA256SUMS"
  fi
  echo "release: signature → $OUT/SHA256SUMS.sig"
else
  echo "release: cosign not configured — skipping signature (set COSIGN_KEY or COSIGN_EXPERIMENTAL=1)"
fi

echo "release: done → $OUT/ (${ARTIFACT}, SHA256SUMS, orochi.cdx.json)"

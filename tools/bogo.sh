#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# tools/bogo.sh — drive BoringSSL's BoGo protocol-test runner against orochi's
# TLS shim (roadmap 0.3). The runner (`ssl/test/runner`, a Go test) is an
# OUT-OF-REPO dependency: this script pins a BoringSSL checkout, builds the
# orochi shim, and runs `go test` with our shim + -shim-config. It is scaffolding
# for a CI `bogo` job — the in-repo, self-contained proof is `zig build
# bogo-shim-test` (no external harness required).
#
# Requirements (NOT vendored): `go`, `cmake`, a network fetch of BoringSSL.
#
# Usage:
#   tools/bogo.sh                 # run the full subset (skips unimplemented)
#   tools/bogo.sh -test 'TLS13-*' # run a runner test-name regex
set -euo pipefail

# Pin BoringSSL to a fixed commit — BoGo drifts, so pinning is mandatory for
# determinism. Bump deliberately and re-baseline DisabledTests/ErrorMap.
# (BoringSSL renamed its default branch master->main; pin to a fixed commit,
# never a moving branch.)
BORINGSSL_COMMIT="${BORINGSSL_COMMIT:-5ac7567c2}"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cache_dir="${repo_root}/.bogo"
bssl_dir="${cache_dir}/boringssl"
shim_bin="${repo_root}/zig-out/bin/bogo_shim"
shim_config="${repo_root}/tools/bogo/config.json"

echo "[bogo] building orochi shim -> ${shim_bin}"
( cd "${repo_root}" && zig build bogo-shim )

if [[ ! -d "${bssl_dir}/.git" ]]; then
  echo "[bogo] cloning BoringSSL into ${bssl_dir}"
  mkdir -p "${cache_dir}"
  git clone https://boringssl.googlesource.com/boringssl "${bssl_dir}"
fi
echo "[bogo] checking out BoringSSL @ ${BORINGSSL_COMMIT}"
( cd "${bssl_dir}" && git fetch --quiet origin && git checkout --quiet "${BORINGSSL_COMMIT}" )

echo "[bogo] running the runner against the orochi shim"
cd "${bssl_dir}/ssl/test/runner"
exec go test \
  -shim-path "${shim_bin}" \
  -shim-config "${shim_config}" \
  -allow-unimplemented \
  -num-workers "$(nproc)" \
  "$@"

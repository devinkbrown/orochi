#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# tools/bogo.sh — drive BoringSSL's BoGo protocol-test runner against onyx's
# TLS shim (roadmap 0.3). The runner (`ssl/test/runner`, a Go test) is an
# OUT-OF-REPO dependency: this script pins a BoringSSL checkout, builds the
# onyx shim, and runs `go test` with our shim + -shim-config. The default run is
# a checked external-interoperability baseline: exact pass/skip identities must
# match tools/bogo/expected-baseline.txt and at least one test must really pass.
#
# Requirements (NOT vendored): `go`, `git`, `unshare`, `ip`, `sysctl`, and a
# network fetch of BoringSSL. The namespace tools keep the IPv4-only shim honest
# against a runner which otherwise prefers ::1 and adds an unsupported -ipv6.
#
# Usage:
#   tools/bogo.sh                 # exact required baseline
#   tools/bogo.sh -test 'TLS13-*' # exploratory filter; still rejects all-skip
set -euo pipefail

# Pin BoringSSL to a fixed commit — BoGo drifts, so pinning is mandatory for
# determinism. Bump deliberately and re-baseline DisabledTests/ErrorMap.
# (BoringSSL renamed its default branch master->main; pin to a fixed commit,
# never a moving branch.)
BORINGSSL_COMMIT="${BORINGSSL_COMMIT:-5ac7567c234514157a504ff3fbedc0f5eddbf678}"

if [[ ! "${BORINGSSL_COMMIT}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "[bogo] BORINGSSL_COMMIT must be a full 40-character lowercase commit" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cache_dir="${BOGO_CACHE_DIR:-${repo_root}/.bogo}"
bssl_dir="${cache_dir}/boringssl"
shim_bin="${repo_root}/zig-out/bin/bogo_shim"
shim_config="${repo_root}/tools/bogo/config.json"
baseline="${BOGO_BASELINE:-${repo_root}/tools/bogo/expected-baseline.txt}"
runner_log="${cache_dir}/runner.log"
actual_baseline="${cache_dir}/actual-baseline.txt"
expected_baseline="${cache_dir}/expected-baseline.txt"
workers="${BOGO_NUM_WORKERS:-1}"
use_ipv4_netns="${BOGO_USE_IPV4_NETNS:-1}"

if [[ ! "${workers}" =~ ^[1-9][0-9]*$ ]]; then
  echo "[bogo] BOGO_NUM_WORKERS must be a positive integer" >&2
  exit 2
fi
if [[ "${use_ipv4_netns}" != "0" && "${use_ipv4_netns}" != "1" ]]; then
  echo "[bogo] BOGO_USE_IPV4_NETNS must be 0 or 1" >&2
  exit 2
fi

echo "[bogo] building onyx shim -> ${shim_bin}"
( cd "${repo_root}" && zig build bogo-shim )

if [[ ! -d "${bssl_dir}/.git" ]]; then
  echo "[bogo] initializing BoringSSL cache in ${bssl_dir}"
  mkdir -p "${cache_dir}"
  git init --quiet "${bssl_dir}"
  git -C "${bssl_dir}" remote add origin https://boringssl.googlesource.com/boringssl
fi
if [[ "$(git -C "${bssl_dir}" remote get-url origin)" != "https://boringssl.googlesource.com/boringssl" ]]; then
  echo "[bogo] cached origin is not the canonical BoringSSL repository" >&2
  exit 2
fi
echo "[bogo] checking out BoringSSL @ ${BORINGSSL_COMMIT}"
if ! git -C "${bssl_dir}" cat-file -e "${BORINGSSL_COMMIT}^{commit}" 2>/dev/null; then
  git -C "${bssl_dir}" fetch --quiet --depth=1 origin "${BORINGSSL_COMMIT}"
fi
( cd "${bssl_dir}" &&
  git checkout --quiet --detach "${BORINGSSL_COMMIT}" &&
  [[ "$(git rev-parse HEAD)" == "${BORINGSSL_COMMIT}" ]]
)

# Populate modules before entering the loopback-only namespace. The namespace
# deliberately has no external route, so a runner can never turn a protocol
# test into an unbounded network dependency.
( cd "${bssl_dir}" && go mod download )

runner_args=(
  -count=1
  -timeout 10m
  -shim-path "${shim_bin}"
  -shim-config "${shim_config}"
  -allow-unimplemented
  -pipe
  -num-workers "${workers}"
)

check_baseline=0
if (( $# == 0 )); then
  if [[ ! -f "${baseline}" ]]; then
    echo "[bogo] missing expected baseline: ${baseline}" >&2
    exit 2
  fi
  mapfile -t baseline_tests < <(awk '$1 == "PASS" || $1 == "SKIP" { print $2 }' "${baseline}")
  if (( ${#baseline_tests[@]} == 0 )); then
    echo "[bogo] expected baseline contains no tests" >&2
    exit 2
  fi
  test_filter="$(IFS=';'; echo "${baseline_tests[*]}")"
  runner_args+=( -test "${test_filter}" )
  check_baseline=1
else
  runner_args+=( "$@" )
fi

echo "[bogo] running the runner against the onyx shim"
mkdir -p "${cache_dir}"
set +e
if [[ "${use_ipv4_netns}" == "1" ]]; then
  unshare --user --map-root-user --net bash -c '
    set -euo pipefail
    sysctl -q -w net.ipv6.conf.all.disable_ipv6=1
    ip link set lo up
    runner_dir="$1"
    shift
    cd "${runner_dir}"
    exec "$@"
  ' bash "${bssl_dir}/ssl/test/runner" go test "${runner_args[@]}" >"${runner_log}" 2>&1
else
  ( cd "${bssl_dir}/ssl/test/runner" && go test "${runner_args[@]}" ) >"${runner_log}" 2>&1
fi
runner_rc=$?
set -e
cat "${runner_log}"

passed="$(grep -c '^PASSED (' "${runner_log}" || true)"
skipped="$(grep -c '^UNIMPLEMENTED (' "${runner_log}" || true)"
failed="$(grep -c '^FAILED (' "${runner_log}" || true)"
echo "[bogo] summary: ${passed} passed; ${skipped} skipped; ${failed} failed"

if (( runner_rc != 0 )); then
  echo "[bogo] external runner failed (exit ${runner_rc})" >&2
  exit "${runner_rc}"
fi
if (( passed == 0 )); then
  echo "[bogo] refusing vacuous result: no external test passed" >&2
  exit 1
fi

if (( check_baseline == 1 )); then
  sed -n \
    -e 's/^PASSED (\(.*\))$/PASS \1/p' \
    -e 's/^UNIMPLEMENTED (\(.*\))$/SKIP \1/p' \
    "${runner_log}" | LC_ALL=C sort >"${actual_baseline}"
  awk '$1 == "PASS" || $1 == "SKIP" { print $1, $2 }' "${baseline}" |
    LC_ALL=C sort >"${expected_baseline}"
  if ! diff -u "${expected_baseline}" "${actual_baseline}"; then
    echo "[bogo] pass/skip baseline drifted; review the pinned runner and shim behavior" >&2
    exit 1
  fi
  echo "[bogo] exact pass/skip baseline matched"
fi

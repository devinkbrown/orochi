#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

#
# Real QUIC/HTTP3 interop test for the Orochi from-scratch QUIC stack.
#
# Builds the daemon's standalone QUIC/HTTP3 listener (`quic_interop_server`),
# starts it on an ephemeral UDP port with a self-signed cert, then drives a REAL
# third-party HTTP/3 client (`curl --http3`) against it and asserts a 200
# response with the expected body. This is the authoritative interop check: it
# exercises the stack against an independent QUIC implementation (curl's
# ngtcp2/OpenSSL), not our own loopback client.
#
# Exit status: 0 on success; non-zero with diagnostics on any failure. If `curl`
# lacks HTTP/3 support the test SKIPS (exit 0) so a curl-less CI box still
# passes — the in-tree Zig test mirrors this skip.
#
# Usage:
#   tools/quic_interop.sh           # build + run the full interop test
#   OROCHI_QUIC_DEBUG=1 tools/quic_interop.sh   # with server-side QUIC tracing
#
set -uo pipefail

# --- locate the repo root (this script lives in <root>/tools) ----------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

SERVER_BIN="$ROOT/zig-out/bin/quic_interop_server"
EXPECT_BODY="orochi quic ok"
CURL_TIMEOUT=8

log()  { printf '[interop] %s\n' "$*"; }
fail() { printf '[interop] FAIL: %s\n' "$*" >&2; }

# --- 0. preflight: does this curl speak HTTP/3? ------------------------------
if ! command -v curl >/dev/null 2>&1; then
    log "SKIP: curl not found on PATH"
    exit 0
fi
if ! curl --version | grep -qiE '(^|[[:space:]])HTTP3([[:space:]]|$)|http3'; then
    log "SKIP: this curl has no HTTP/3 support ($(curl --version | head -1))"
    exit 0
fi
log "curl with HTTP/3: $(curl --version | head -1)"

# --- 1. build the standalone interop server ----------------------------------
log "building quic_interop_server (zig build) ..."
if ! zig build quic-interop-server; then
    fail "zig build quic-interop-server failed"
    exit 1
fi
if [[ ! -x "$SERVER_BIN" ]]; then
    fail "server binary not found at $SERVER_BIN"
    exit 1
fi

# --- 2. start the server on an ephemeral UDP port ----------------------------
ERR_LOG="$(mktemp)"
PORT_LOG="$(mktemp)"
cleanup() {
    if [[ -n "${SRV_PID:-}" ]] && kill -0 "$SRV_PID" 2>/dev/null; then
        kill "$SRV_PID" 2>/dev/null
        wait "$SRV_PID" 2>/dev/null
    fi
    rm -f "$ERR_LOG" "$PORT_LOG"
}
trap cleanup EXIT

log "starting interop server ..."
"$SERVER_BIN" >"$PORT_LOG" 2>"$ERR_LOG" &
SRV_PID=$!

# Wait (up to ~3s) for the server to announce its bound port.
PORT=""
for _ in $(seq 1 30); do
    PORT="$(grep -oE 'PORT=[0-9]+' "$PORT_LOG" 2>/dev/null | head -1 | cut -d= -f2)"
    [[ -n "$PORT" ]] && break
    if ! kill -0 "$SRV_PID" 2>/dev/null; then
        fail "server exited before binding; stderr:"
        sed 's/^/[interop]   /' "$ERR_LOG" >&2
        exit 1
    fi
    sleep 0.1
done
if [[ -z "$PORT" ]]; then
    fail "server never reported a PORT= line"
    sed 's/^/[interop]   /' "$ERR_LOG" >&2
    exit 1
fi
log "server listening on UDP 127.0.0.1:$PORT"

# --- 3. drive curl --http3 against it ----------------------------------------
run_curl() {
    # $1 = path, prints "<http_code>\t<body>"; returns curl's exit code.
    local path="$1" out rc
    out="$(curl --http3-only -k -sS --max-time "$CURL_TIMEOUT" \
                -w $'\n%{http_code}' \
                "https://127.0.0.1:${PORT}${path}" 2>/dev/null)"
    rc=$?
    local code body
    code="${out##*$'\n'}"
    body="${out%$'\n'*}"
    printf '%s\t%s' "$code" "$body"
    return $rc
}

log "GET / ..."
result="$(run_curl "/")"
curl_rc=$?
status="${result%%$'\t'*}"
body="${result#*$'\t'}"

if [[ $curl_rc -ne 0 ]]; then
    fail "curl --http3 exited $curl_rc (no successful HTTP/3 exchange)"
    log "server stderr (tail):"
    tail -40 "$ERR_LOG" | sed 's/^/[interop]   /' >&2
    exit 1
fi
if [[ "$status" != "200" ]]; then
    fail "GET / returned HTTP $status (expected 200)"
    log "body: $body"
    tail -40 "$ERR_LOG" | sed 's/^/[interop]   /' >&2
    exit 1
fi
if [[ "$body" != "$EXPECT_BODY" ]]; then
    fail "GET / body mismatch: got '$body', expected '$EXPECT_BODY'"
    exit 1
fi
log "GET / → 200, body '$body'  ✓"

# --- 4. a 404 path is also a valid, finished HTTP/3 response -----------------
log "GET /nonexistent ..."
result="$(run_curl "/nonexistent")"
curl_rc=$?
status="${result%%$'\t'*}"
if [[ $curl_rc -ne 0 ]]; then
    fail "curl --http3 exited $curl_rc on the 404 path"
    exit 1
fi
if [[ "$status" != "404" ]]; then
    fail "GET /nonexistent returned HTTP $status (expected 404)"
    exit 1
fi
log "GET /nonexistent → 404  ✓"

log "PASS: curl --http3 completed a QUIC + TLS-1.3 + HTTP/3 exchange and got its 200."
exit 0

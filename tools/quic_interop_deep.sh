#!/usr/bin/env bash
#
# DEEP QUIC/HTTP3 interop test for the Orochi from-scratch QUIC stack.
#
# Where tools/quic_interop.sh proves a tiny `GET / → 200` completes, this script
# drives the DEEP machinery a small request never touches, all against a REAL
# third-party HTTP/3 client (curl --http3, ngtcp2/nghttp3):
#
#   1. Large transfer  — `GET /big?n=<bytes>` streams a deterministic, verifiable
#      body across MANY QUIC packets. This exercises STREAM segmentation, the
#      peer's MAX_DATA/MAX_STREAM_DATA flow-control credit, the congestion window
#      actually gating multi-packet sends, ACK processing, and loss recovery.
#      We assert the EXACT downloaded size AND a SHA-256 of the body.
#   2. Retry round-trip — the listener runs with `--retry` (address validation
#      on). curl must handle the Retry packet (re-send its Initial with the
#      token) and still complete the handshake + GET → 200, including a large
#      transfer through the validated path.
#   3. Multiple requests on one connection — curl fetching several paths over a
#      single QUIC connection (multiple request streams, QPACK across requests,
#      stream-id management), each returning its correct status/body.
#
# Exit status: 0 on success; non-zero with diagnostics on any failure. If `curl`
# lacks HTTP/3 the test SKIPS (exit 0), like tools/quic_interop.sh.
#
# Usage:
#   tools/quic_interop_deep.sh
#   OROCHI_QUIC_DEBUG=1 tools/quic_interop_deep.sh   # with server-side tracing
#
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

SERVER_BIN="$ROOT/zig-out/bin/quic_interop_server"
CURL_TIMEOUT=30

# The canonical SHA-256 of the default 256 KiB `/big` body. The body is fully
# determined by the byte-at-offset function in src/proto/http3_conn.zig
# (bigBodyByteAt), so this digest is stable across runs. If the body generator
# changes, recompute with:  curl --http3-only -k -s "$URL/big?n=262144" | sha256sum
BIG_256K_SHA256="826f742c3ff67c06f8829ffaef5fc498374201d9240cc2c1777ccbcfab0f9869"
BIG_256K_BYTES=262144

log()  { printf '[deep] %s\n' "$*"; }
fail() { printf '[deep] FAIL: %s\n' "$*" >&2; }

# --- preflight ---------------------------------------------------------------
if ! command -v curl >/dev/null 2>&1; then
    log "SKIP: curl not found on PATH"; exit 0
fi
if ! curl --version | grep -qiE 'http3'; then
    log "SKIP: this curl has no HTTP/3 support ($(curl --version | head -1))"; exit 0
fi
if ! command -v sha256sum >/dev/null 2>&1; then
    log "SKIP: sha256sum not found (cannot verify the large body)"; exit 0
fi
log "curl with HTTP/3: $(curl --version | head -1)"

# --- build -------------------------------------------------------------------
log "building quic_interop_server ..."
if ! zig build quic-interop-server; then
    fail "zig build quic-interop-server failed"; exit 1
fi
[[ -x "$SERVER_BIN" ]] || { fail "server binary not found at $SERVER_BIN"; exit 1; }

# --- server lifecycle helpers ------------------------------------------------
SRV_PID=""
ERR_LOG=""
PORT=""
start_server() {
    # $@ = extra args (e.g. --retry). Sets PORT; leaves the server running.
    ERR_LOG="$(mktemp)"
    local port_log; port_log="$(mktemp)"
    "$SERVER_BIN" "$@" >"$port_log" 2>"$ERR_LOG" &
    SRV_PID=$!
    PORT=""
    local i
    for i in $(seq 1 50); do
        PORT="$(grep -oE 'PORT=[0-9]+' "$port_log" 2>/dev/null | head -1 | cut -d= -f2)"
        [[ -n "$PORT" ]] && break
        if ! kill -0 "$SRV_PID" 2>/dev/null; then
            fail "server exited before binding; stderr:"
            sed 's/^/[deep]   /' "$ERR_LOG" >&2
            rm -f "$port_log"
            return 1
        fi
        sleep 0.1
    done
    rm -f "$port_log"
    [[ -n "$PORT" ]] || { fail "server never reported PORT="; return 1; }
    return 0
}
stop_server() {
    if [[ -n "${SRV_PID:-}" ]] && kill -0 "$SRV_PID" 2>/dev/null; then
        kill "$SRV_PID" 2>/dev/null
        wait "$SRV_PID" 2>/dev/null
    fi
    SRV_PID=""
    [[ -n "${ERR_LOG:-}" ]] && rm -f "$ERR_LOG"
    ERR_LOG=""
}
dump_server_err() { [[ -n "${ERR_LOG:-}" ]] && tail -40 "$ERR_LOG" | sed 's/^/[deep]   /' >&2; }
cleanup() { stop_server; }
trap cleanup EXIT

# --- 1. large transfer -------------------------------------------------------
test_large_transfer() {
    log "GET /big?n=$BIG_256K_BYTES (large transfer, exact size + SHA-256) ..."
    local out; out="$(mktemp)"
    local code
    code="$(curl --http3-only -k -sS --max-time "$CURL_TIMEOUT" \
                 -o "$out" -w '%{http_code}' \
                 "https://127.0.0.1:${PORT}/big?n=${BIG_256K_BYTES}" 2>/dev/null)"
    local rc=$?
    if [[ $rc -ne 0 ]]; then
        fail "curl --http3 exited $rc on the large transfer"; rm -f "$out"; dump_server_err; return 1
    fi
    if [[ "$code" != "200" ]]; then
        fail "/big returned HTTP $code (expected 200)"; rm -f "$out"; return 1
    fi
    local size; size="$(wc -c <"$out")"
    if [[ "$size" -ne "$BIG_256K_BYTES" ]]; then
        fail "/big downloaded $size bytes (expected $BIG_256K_BYTES)"; rm -f "$out"; return 1
    fi
    local sum; sum="$(sha256sum "$out" | cut -d' ' -f1)"
    rm -f "$out"
    if [[ "$sum" != "$BIG_256K_SHA256" ]]; then
        fail "/big body SHA-256 mismatch: got $sum expected $BIG_256K_SHA256"; return 1
    fi
    log "large transfer → 200, $size bytes, SHA-256 OK  ✓"

    # A second, larger size proves the cwnd ramps over many more rounds (1 MiB).
    log "GET /big?n=1048576 (1 MiB, exact size) ..."
    local out2; out2="$(mktemp)"
    code="$(curl --http3-only -k -sS --max-time "$CURL_TIMEOUT" \
                 -o "$out2" -w '%{http_code}' \
                 "https://127.0.0.1:${PORT}/big?n=1048576" 2>/dev/null)"
    rc=$?
    local size2; size2="$(wc -c <"$out2")"; rm -f "$out2"
    if [[ $rc -ne 0 || "$code" != "200" || "$size2" -ne 1048576 ]]; then
        fail "1 MiB transfer failed (rc=$rc code=$code size=$size2)"; dump_server_err; return 1
    fi
    log "1 MiB transfer → 200, $size2 bytes  ✓"
    return 0
}

# --- 2. multiple requests on one connection ----------------------------------
test_multi_request() {
    log "multiple requests on ONE connection (/, /big, /nonexistent) ..."
    # One curl invocation, several URLs → curl reuses the single QUIC connection.
    # `%{num_connects}` is 1 for the first URL and 0 for each reused one.
    # NOTE: `-o` is per-URL in curl, so each URL needs its own `-o /dev/null`,
    # otherwise the un-redirected response bodies print to stdout and corrupt the
    # `-w` summary we parse.
    local summary
    summary="$(curl --http3-only -k -sS --max-time "$CURL_TIMEOUT" \
                    -w '%{http_code} %{size_download} %{num_connects}\n' \
                    -o /dev/null "https://127.0.0.1:${PORT}/" \
                    -o /dev/null "https://127.0.0.1:${PORT}/big?n=65536" \
                    -o /dev/null "https://127.0.0.1:${PORT}/nonexistent" \
                    -o /dev/null "https://127.0.0.1:${PORT}/big?n=131072" 2>/dev/null)"
    local rc=$?
    if [[ $rc -ne 0 ]]; then
        fail "curl --http3 exited $rc on the multi-request run"; dump_server_err; return 1
    fi
    # Expected (code size) per line, in order. num_connects must be 1 then 0,0,0.
    local expected=$'200 15\n200 65536\n404 10\n200 131072'
    local got_codes; got_codes="$(printf '%s\n' "$summary" | awk '{print $1, $2}')"
    if [[ "$got_codes" != "$expected" ]]; then
        fail "multi-request results mismatch:"
        printf '[deep]   got:\n%s\n[deep]   expected:\n%s\n' "$got_codes" "$expected" >&2
        return 1
    fi
    local total_connects; total_connects="$(printf '%s\n' "$summary" | awk '{s+=$3} END{print s}')"
    if [[ "$total_connects" != "1" ]]; then
        fail "expected exactly 1 new connection across 4 requests, got $total_connects"; return 1
    fi
    log "4 requests over 1 connection → 200/15, 200/65536, 404/10, 200/131072  ✓"
    return 0
}

# --- main --------------------------------------------------------------------
rc_all=0

log "=== variant: large transfer + multi-request (retry off) ==="
if start_server; then
    test_large_transfer || rc_all=1
    test_multi_request   || rc_all=1
    stop_server
else
    rc_all=1
fi

log "=== variant: Retry round-trip (--retry, address validation on) ==="
if start_server --retry; then
    # GET / must complete THROUGH a Retry packet. Write the body to a file so the
    # trailing newline in the response does not confuse status/body parsing.
    log "GET / through Retry ..."
    rbody="$(mktemp)"
    code="$(curl --http3-only -k -sS --max-time "$CURL_TIMEOUT" \
                 -o "$rbody" -w '%{http_code}' "https://127.0.0.1:${PORT}/" 2>/dev/null)"
    crc=$?
    text="$(cat "$rbody")"; rm -f "$rbody"
    if [[ $crc -ne 0 || "$code" != "200" || "$text" != "orochi quic ok" ]]; then
        fail "Retry GET / failed (rc=$crc code=$code body='$text')"; dump_server_err; rc_all=1
    else
        log "Retry GET / → 200, body 'orochi quic ok'  ✓"
    fi
    # A large transfer must also complete through the validated path.
    log "GET /big?n=$BIG_256K_BYTES through Retry ..."
    out="$(mktemp)"
    code="$(curl --http3-only -k -sS --max-time "$CURL_TIMEOUT" -o "$out" -w '%{http_code}' \
                 "https://127.0.0.1:${PORT}/big?n=${BIG_256K_BYTES}" 2>/dev/null)"
    crc=$?
    size="$(wc -c <"$out")"; sum="$(sha256sum "$out" | cut -d' ' -f1)"; rm -f "$out"
    if [[ $crc -ne 0 || "$code" != "200" || "$size" -ne "$BIG_256K_BYTES" || "$sum" != "$BIG_256K_SHA256" ]]; then
        fail "Retry large transfer failed (rc=$crc code=$code size=$size sha=$sum)"; dump_server_err; rc_all=1
    else
        log "Retry large transfer → 200, $size bytes, SHA-256 OK  ✓"
    fi
    stop_server
else
    rc_all=1
fi

if [[ $rc_all -eq 0 ]]; then
    log "PASS: deep interop — large transfer (byte-exact), Retry round-trip, and multi-request all completed against curl --http3."
else
    fail "one or more deep interop variants failed (see above)."
fi
exit $rc_all

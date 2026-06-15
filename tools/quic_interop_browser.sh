#!/usr/bin/env bash
#
# Real WebTransport interop test for the Orochi from-scratch QUIC/HTTP3 stack,
# driven by a REAL browser (headless Chromium) speaking the actual WebTransport
# API. Where tools/quic_interop.sh proves QUIC + HTTP/3 against curl, this proves
# the WebTransport-specific path — Extended CONNECT (`:protocol=webtransport`),
# WT bidi streams, and WT datagrams — which curl cannot exercise.
#
# Pipeline:
#   1. build the ECDSA-P256 WebTransport interop server (echo bridge + datagram
#      echo), start it on an ephemeral 127.0.0.1 UDP port, parse PORT + CERTHASH;
#   2. run tools/quic_interop_browser.mjs (node built-ins only — no npm), which
#      serves a secure-context page on http://127.0.0.1 and launches Chromium
#      against it; the page opens a WebTransport session, echoes a bidi-stream
#      payload and a datagram, and POSTs its verdict back;
#   3. assert the harness exits 0 (session established + both echoes byte-exact).
#
# Exit status: 0 on success or graceful SKIP (no chromium / no node); non-zero
# with diagnostics on a real interop failure.
#
# Usage:
#   tools/quic_interop_browser.sh
#   OROCHI_QUIC_DEBUG=1 tools/quic_interop_browser.sh   # server-side QUIC trace
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

SERVER_BIN="$ROOT/zig-out/bin/quic_interop_wt_server"
HARNESS="$ROOT/tools/quic_interop_browser.mjs"
CHROMIUM_BIN="${CHROMIUM:-/usr/bin/chromium}"
HARNESS_TIMEOUT_MS="${HARNESS_TIMEOUT_MS:-25000}"

log()  { printf '[wt-interop] %s\n' "$*"; }
fail() { printf '[wt-interop] FAIL: %s\n' "$*" >&2; }

# --- 0. preflight: chromium + node both present? -----------------------------
if [[ ! -x "$CHROMIUM_BIN" ]] && ! command -v chromium >/dev/null 2>&1; then
    log "SKIP: chromium not found (set CHROMIUM=/path/to/chromium to override)"
    exit 0
fi
[[ -x "$CHROMIUM_BIN" ]] || CHROMIUM_BIN="$(command -v chromium)"
if ! command -v node >/dev/null 2>&1; then
    log "SKIP: node not found on PATH"
    exit 0
fi
log "chromium: $("$CHROMIUM_BIN" --version 2>/dev/null | head -1)"
log "node:     $(node --version)"

# --- 1. build the WebTransport interop server --------------------------------
log "building quic_interop_wt_server (zig build) ..."
if ! zig build quic-interop-wt-server; then
    fail "zig build quic-interop-wt-server failed"
    exit 1
fi
if [[ ! -x "$SERVER_BIN" ]]; then
    fail "server binary not found at $SERVER_BIN"
    exit 1
fi

# --- 2. start the server on an ephemeral 127.0.0.1 UDP port ------------------
ERR_LOG="$(mktemp)"
OUT_LOG="$(mktemp)"
cleanup() {
    if [[ -n "${SRV_PID:-}" ]] && kill -0 "$SRV_PID" 2>/dev/null; then
        kill "$SRV_PID" 2>/dev/null
        wait "$SRV_PID" 2>/dev/null
    fi
    rm -f "$ERR_LOG" "$OUT_LOG"
}
trap cleanup EXIT

log "starting WebTransport interop server ..."
"$SERVER_BIN" >"$OUT_LOG" 2>"$ERR_LOG" &
SRV_PID=$!

# Wait (up to ~3s) for the server to announce PORT + CERTHASH.
PORT=""; CERTHASH=""
for _ in $(seq 1 30); do
    PORT="$(grep -oE 'PORT=[0-9]+' "$OUT_LOG" 2>/dev/null | head -1 | cut -d= -f2)"
    CERTHASH="$(grep -oE 'CERTHASH=[0-9a-f]+' "$OUT_LOG" 2>/dev/null | head -1 | cut -d= -f2)"
    [[ -n "$PORT" && -n "$CERTHASH" ]] && break
    if ! kill -0 "$SRV_PID" 2>/dev/null; then
        fail "server exited before announcing PORT/CERTHASH; stderr:"
        sed 's/^/[wt-interop]   /' "$ERR_LOG" >&2
        exit 1
    fi
    sleep 0.1
done
if [[ -z "$PORT" || -z "$CERTHASH" ]]; then
    fail "server never reported PORT + CERTHASH"
    sed 's/^/[wt-interop]   /' "$ERR_LOG" >&2
    exit 1
fi
log "server on UDP 127.0.0.1:$PORT  cert sha-256=$CERTHASH"

# --- 3. run the browser harness ---------------------------------------------
log "launching browser harness (headless Chromium) ..."
if node "$HARNESS" --port "$PORT" --certhash "$CERTHASH" \
        --chromium "$CHROMIUM_BIN" --timeout-ms "$HARNESS_TIMEOUT_MS"; then
    log "PASS: Chrome established a WebTransport session; bidi stream + datagram echo byte-exact."
    exit 0
else
    rc=$?
    fail "browser WebTransport interop failed (harness exit $rc)"
    log "server stderr (tail):"
    tail -40 "$ERR_LOG" | sed 's/^/[wt-interop]   /' >&2
    exit 1
fi

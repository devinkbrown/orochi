#!/usr/bin/env bash
#
# REAL end-to-end IRC-over-WebTransport interop test: a headless-Chromium
# WebTransport client registers as a genuine IRC client against the REAL orochi
# daemon and gets a real RPL_WELCOME (001), joins a channel, and sends a message.
#
# Where tools/quic_interop_browser.sh bridges the browser's WT bidi stream to an
# in-process TCP *echo*, this lane bridges it to a live orochi IRC daemon:
#
#   browser ──QUIC/H3/WT bidi──▶ WT interop server ──loopback TCP──▶ orochi IRC
#
# Pipeline:
#   1. build orochi (the daemon) + the ECDSA-P256 WebTransport interop server;
#   2. start the daemon with a minimal temp config (plaintext IRC on a loopback
#      port, NO mesh/media/TLS/WT — the IRC leg is plaintext loopback; the WT
#      interop server owns the ECDSA QUIC cert), wait for the IRC port to listen;
#   3. start the WT interop server with OROCHI_WT_BRIDGE_PORT=<irc port> so its WT
#      bidi bridge dials the daemon instead of the echo; parse PORT + CERTHASH;
#   4. run tools/quic_interop_irc_browser.mjs (node built-ins only — no npm),
#      which serves a secure-context page on http://127.0.0.1 and launches
#      Chromium against it; the page opens a WebTransport session, writes IRC
#      (NICK/USER -> JOIN -> PRIVMSG), asserts the real 001 + JOIN + names + that
#      the PRIVMSG is accepted, and POSTs its verdict (with captured IRC lines);
#   5. assert the harness exits 0; print the IRC lines the browser received.
#
# Exit status: 0 on success or graceful SKIP (no chromium / no node); non-zero
# with diagnostics on a real interop failure.
#
# Usage:
#   tools/quic_interop_irc_browser.sh
#   OROCHI_QUIC_DEBUG=1 tools/quic_interop_irc_browser.sh   # server-side QUIC trace
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

DAEMON_BIN="$ROOT/zig-out/bin/orochi"
SERVER_BIN="$ROOT/zig-out/bin/quic_interop_wt_server"
HARNESS="$ROOT/tools/quic_interop_irc_browser.mjs"
CHROMIUM_BIN="${CHROMIUM:-/usr/bin/chromium}"
HARNESS_TIMEOUT_MS="${HARNESS_TIMEOUT_MS:-25000}"

# A fixed loopback IRC port for the daemon (the bridge target). Overridable.
IRC_PORT="${OROCHI_IRC_PORT:-16767}"

log()  { printf '[irc-wt-interop] %s\n' "$*"; }
fail() { printf '[irc-wt-interop] FAIL: %s\n' "$*" >&2; }

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

# --- 1. build the daemon + the WebTransport interop server -------------------
log "building orochi daemon (zig build) ..."
if ! zig build; then
    fail "zig build (daemon) failed"
    exit 1
fi
log "building quic_interop_wt_server (zig build quic-interop-wt-server) ..."
if ! zig build quic-interop-wt-server; then
    fail "zig build quic-interop-wt-server failed"
    exit 1
fi
[[ -x "$DAEMON_BIN" ]] || { fail "daemon binary not found at $DAEMON_BIN"; exit 1; }
[[ -x "$SERVER_BIN" ]] || { fail "server binary not found at $SERVER_BIN"; exit 1; }

# --- 2. write a minimal temp daemon config ----------------------------------
# Only the two REQUIRED keys plus a stable server_name: [node].id and the
# plaintext [listen].irc port. No mesh / media / TLS / WebTransport — the WT
# interop server owns the QUIC cert; the daemon's IRC leg is plaintext loopback.
# A private temp dir keeps the run hermetic: the daemon auto-generates its node
# keyfile (orochi-node.key) beside the config, and the whole dir is removed on
# exit (so no /tmp node-key collision between runs/users).
TMPD="$(mktemp -d -t orochi-irc-wt.XXXXXX)"
CONF="$TMPD/orochi.toml"
cat >"$CONF" <<EOF
[node]
id = 1

[network]
server_name = "orochi.interop.test"

[listen]
host = "127.0.0.1"
irc = $IRC_PORT
EOF

ERR_LOG="$TMPD/daemon.err"
OUT_LOG="$TMPD/daemon.out"
SRV_ERR="$TMPD/wtserver.err"
SRV_OUT="$TMPD/wtserver.out"

cleanup() {
    if [[ -n "${SRV_PID:-}" ]] && kill -0 "$SRV_PID" 2>/dev/null; then
        kill "$SRV_PID" 2>/dev/null; wait "$SRV_PID" 2>/dev/null
    fi
    if [[ -n "${DAEMON_PID:-}" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        kill "$DAEMON_PID" 2>/dev/null; wait "$DAEMON_PID" 2>/dev/null
    fi
    rm -rf "$TMPD"
}
trap cleanup EXIT

# --- 3. start the daemon; wait for the IRC port to listen --------------------
log "starting orochi daemon (IRC plaintext on 127.0.0.1:$IRC_PORT) ..."
"$DAEMON_BIN" "$CONF" >"$OUT_LOG" 2>"$ERR_LOG" &
DAEMON_PID=$!

irc_listening() {
    # A TCP connect probe to 127.0.0.1:$IRC_PORT; succeeds once the daemon binds.
    (exec 3<>"/dev/tcp/127.0.0.1/$IRC_PORT") 2>/dev/null && { exec 3<&- 3>&-; return 0; }
    return 1
}

UP=0
for _ in $(seq 1 50); do
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        fail "daemon exited before the IRC port came up; daemon output:"
        cat "$OUT_LOG" "$ERR_LOG" | sed 's/^/[irc-wt-interop]   /' >&2
        exit 1
    fi
    if irc_listening; then UP=1; break; fi
    sleep 0.1
done
if [[ "$UP" != 1 ]]; then
    fail "daemon never started listening on 127.0.0.1:$IRC_PORT"
    cat "$OUT_LOG" "$ERR_LOG" | sed 's/^/[irc-wt-interop]   /' >&2
    exit 1
fi
log "daemon IRC port up on 127.0.0.1:$IRC_PORT"

# --- 4. start the WT interop server, bridging WT -> the daemon's IRC port ----
log "starting WebTransport interop server (bridge -> IRC $IRC_PORT) ..."
OROCHI_WT_BRIDGE_PORT="$IRC_PORT" "$SERVER_BIN" >"$SRV_OUT" 2>"$SRV_ERR" &
SRV_PID=$!

PORT=""; CERTHASH=""
for _ in $(seq 1 30); do
    PORT="$(grep -oE 'PORT=[0-9]+' "$SRV_OUT" 2>/dev/null | head -1 | cut -d= -f2)"
    CERTHASH="$(grep -oE 'CERTHASH=[0-9a-f]+' "$SRV_OUT" 2>/dev/null | head -1 | cut -d= -f2)"
    [[ -n "$PORT" && -n "$CERTHASH" ]] && break
    if ! kill -0 "$SRV_PID" 2>/dev/null; then
        fail "WT interop server exited before announcing PORT/CERTHASH; stderr:"
        sed 's/^/[irc-wt-interop]   /' "$SRV_ERR" >&2
        exit 1
    fi
    sleep 0.1
done
if [[ -z "$PORT" || -z "$CERTHASH" ]]; then
    fail "WT interop server never reported PORT + CERTHASH"
    sed 's/^/[irc-wt-interop]   /' "$SRV_ERR" >&2
    exit 1
fi
log "WT server on UDP 127.0.0.1:$PORT  cert sha-256=$CERTHASH"

# --- 5. run the browser IRC harness -----------------------------------------
log "launching browser IRC harness (headless Chromium) ..."
if node "$HARNESS" --port "$PORT" --certhash "$CERTHASH" \
        --chromium "$CHROMIUM_BIN" --timeout-ms "$HARNESS_TIMEOUT_MS"; then
    log "PASS: Chrome registered over WebTransport against the real orochi daemon (001 + JOIN + PRIVMSG)."
    exit 0
else
    rc=$?
    fail "browser IRC-over-WebTransport interop failed (harness exit $rc)"
    log "daemon stderr (tail):"
    tail -40 "$ERR_LOG" | sed 's/^/[irc-wt-interop]   /' >&2
    log "WT server stderr (tail):"
    tail -40 "$SRV_ERR" | sed 's/^/[irc-wt-interop]   /' >&2
    exit 1
fi

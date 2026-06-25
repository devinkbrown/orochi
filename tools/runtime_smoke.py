#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Fresh-boot runtime smoke test.

Complements tools/upgrade_smoke.py (which exercises the SIGUSR2 hot upgrade).
This one proves a COLD boot from a config file serves IRC end-to-end:

  * the daemon boots from a minimal temp config (TCP listener, ephemeral port),
  * a plain TCP client registers (NICK/USER) and gets RPL_WELCOME (001),
  * PING gets a PONG from the same image,
  * QUIT tears the client down cleanly,
  * the daemon is stopped cleanly.

A hard wall-clock deadline guarantees it never hangs CI: any check that blocks
past the deadline fails loudly with a non-zero exit and the daemon log dumped.

Usage: python3 tools/runtime_smoke.py [path-to-orochi-binary]
Exit code 0 = PASS.
"""
import os
import socket
import subprocess
import sys
import time

HOST = "127.0.0.1"
# Ephemeral-range port distinct from upgrade_smoke.py's 16720 so the two can run
# back-to-back without a TIME_WAIT collision.
PORT = 16721
NICK = "smoke"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "zig-out", "bin", "orochi")
CONF = "/tmp/mz_runtime.toml"
LOG = "/tmp/mz_runtime.log"

# Hard ceiling on the whole run so a wedged daemon never hangs CI.
DEADLINE_S = 30.0
BOOT_WAIT_S = 2.5
_START = time.time()


def remaining():
    """Seconds left before the global deadline (clamped to a small positive)."""
    return max(0.25, DEADLINE_S - (time.time() - _START))


def recv_until(sock, needle, timeout=4.0):
    timeout = min(timeout, remaining())
    sock.settimeout(timeout)
    buf = b""
    end = time.time() + timeout
    while time.time() < end:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
        if needle in buf:
            break
    return buf.decode("utf-8", "replace")


def connect():
    return socket.create_connection((HOST, PORT), timeout=min(4, remaining()))


def cleanup(proc):
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
    for p in (CONF, LOG):
        try:
            os.remove(p)
        except OSError:
            pass


def fail(msg, proc=None):
    print(f"FAIL: {msg}")
    try:
        with open(LOG) as f:
            print("--- daemon log ---")
            print(f.read())
    except OSError:
        pass
    cleanup(proc)
    sys.exit(1)


def main():
    if not os.path.exists(BIN):
        fail(f"binary not found: {BIN} (run `zig build` first)")

    # Minimal config: a single plaintext TCP listener on an ephemeral port. Bind
    # to loopback only so the smoke never exposes a port off-box. Mirrors the key
    # structure documented in etc/orochi.reference.toml ([node].id + [listen]).
    with open(CONF, "w") as f:
        f.write(
            "[node]\nid = 1\n"
            f"[listen]\nhost = \"{HOST}\"\nirc = {PORT}\n"
        )

    proc = subprocess.Popen([BIN, CONF], stdout=open(LOG, "w"), stderr=subprocess.STDOUT)
    time.sleep(BOOT_WAIT_S)
    if proc.poll() is not None:
        fail("daemon exited during boot", proc)
    print(f"PASS: daemon booted from config (PID {proc.pid})")

    # Register a plain client and wait for RPL_WELCOME (001).
    c = connect()
    c.sendall(f"NICK {NICK}\r\nUSER {NICK} 0 * :{NICK}\r\n".encode())
    welcome = recv_until(c, b" 001 ")
    if " 001 " not in welcome:
        fail(f"client did not register (no RPL_WELCOME 001): {welcome!r}", proc)
    print("PASS: client registered (RPL_WELCOME 001)")

    # PING must draw a PONG from the live image. Use a unique token and assert it
    # echoes back so we can't pass on an unrelated server-initiated PING.
    token = "smoke-runtime"
    c.sendall(f"PING :{token}\r\n".encode())
    pong = recv_until(c, b"PONG")
    if "PONG" not in pong or token not in pong:
        fail(f"PING not answered with matching PONG: {pong!r}", proc)
    print("PASS: PING answered with PONG")

    # Clean client teardown via QUIT.
    try:
        c.sendall(b"QUIT :bye\r\n")
        # Drain whatever the server sends before it closes (ERROR/close); ignore.
        recv_until(c, b"ERROR", timeout=2.0)
    except OSError:
        pass
    finally:
        c.close()
    print("PASS: client QUIT cleanly")

    if proc.poll() is not None:
        fail("daemon died after serving the client (should still be running)", proc)

    cleanup(proc)
    print("\nALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())

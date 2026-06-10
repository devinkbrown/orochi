#!/usr/bin/env python3
"""Live Helix UPGRADE smoke test.

Boots a Orochi daemon with an account DB + an [[opers]] binding, registers an
operator account, logs in over SASL (auto-elevates to oper), issues UPGRADE, and
verifies the hot re-exec:

  * the operator elevation works (RPL_YOUREOPER 381),
  * the daemon execve's --supervisor and ADOPTS the inherited listener (log),
  * session state is carried across the handoff (sealed/recovered log lines),
  * the port stays bound (same PID) and still serves IRC after the upgrade.

Usage: python3 tools/upgrade_smoke.py [path-to-orochi-binary]
Exit code 0 = PASS.
"""
import base64
import os
import socket
import subprocess
import sys
import time

PORT = 16720
HOST = "127.0.0.1"
ACCT = "admin"
PASSWORD = "secretpass0"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "zig-out", "bin", "orochi")
DB = "/tmp/mz_upgrade_accts.db"
CONF = "/tmp/mz_upgrade.toml"
LOG = "/tmp/mz_upgrade.log"


def recv_until(sock, needle, timeout=4.0):
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
    return socket.create_connection((HOST, PORT), timeout=4)


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


def cleanup(proc):
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
    for p in (CONF, LOG, DB, DB + ".wal"):
        try:
            os.remove(p)
        except OSError:
            pass


def main():
    if not os.path.exists(BIN):
        fail(f"binary not found: {BIN} (run `zig build` first)")
    for p in (DB, DB + ".wal"):
        try:
            os.remove(p)
        except OSError:
            pass
    with open(CONF, "w") as f:
        f.write(
            "[node]\nid = 1\n"
            f"[listen]\nirc = {PORT}\n"
            f"[sasl]\naccount_db = \"{DB}\"\n"
            f"[[opers]]\naccount = \"{ACCT}\"\nclass = \"netadmin\"\n"
        )

    proc = subprocess.Popen([BIN, CONF], stdout=open(LOG, "w"), stderr=subprocess.STDOUT)
    time.sleep(2.5)
    if proc.poll() is not None:
        fail("daemon exited during boot", proc)
    pid_before = proc.pid

    # Conn A: register the operator account.
    a = connect()
    a.sendall(b"NICK reg\r\nUSER reg 0 * :reg\r\n")
    if " 001 " not in recv_until(a, b" 001 "):
        fail("conn A did not register (no 001)", proc)
    a.sendall(f"REGISTER {ACCT} * {PASSWORD}\r\n".encode())
    reg = recv_until(a, b"REGISTER")
    if "REGISTER SUCCESS" not in reg and "FAIL" not in reg:
        fail(f"unexpected REGISTER reply: {reg!r}", proc)
    a.close()

    # Conn B: SASL login -> auto-elevate to oper -> UPGRADE.
    b = connect()
    b.sendall(b"CAP LS 302\r\n")
    recv_until(b, b"CAP")
    b.sendall(b"CAP REQ :sasl\r\nAUTHENTICATE PLAIN\r\n")
    if "AUTHENTICATE +" not in recv_until(b, b"AUTHENTICATE +"):
        fail("server did not prompt AUTHENTICATE +", proc)
    token = base64.b64encode(b"\0" + ACCT.encode() + b"\0" + PASSWORD.encode()).decode()
    b.sendall(f"AUTHENTICATE {token}\r\n".encode())
    sasl = recv_until(b, b"90")
    if " 903 " not in sasl and " 900 " not in sasl:
        fail(f"SASL login failed: {sasl!r}", proc)
    b.sendall(b"CAP END\r\nNICK admin\r\nUSER admin 0 * :admin\r\n")
    welcome = recv_until(b, b" 381 ")
    if " 381 " not in welcome:
        fail(f"operator not elevated (no 381): {welcome!r}", proc)
    print("PASS: operator elevated via SASL (381)")

    # Conn D: a plain registered client we keep OPEN across the UPGRADE to prove
    # its TCP connection (fd) is re-attached, not dropped.
    d = connect()
    d.sendall(b"NICK survivor\r\nUSER survivor 0 * :survivor\r\n")
    if " 001 " not in recv_until(d, b" 001 "):
        fail("conn D did not register before UPGRADE", proc)
    d.sendall(b"JOIN #durable\r\n")
    recv_until(d, b" 366 ")  # end of NAMES — join complete

    b.sendall(b"UPGRADE\r\n")
    time.sleep(0.4)
    b.close()

    # Give the execve time to land + the successor to adopt + boot.
    time.sleep(2.5)

    if proc.poll() is not None:
        fail("daemon process died across UPGRADE (execve should preserve PID)", proc)
    if proc.pid != pid_before:
        fail("PID changed — execve should keep the same PID", proc)
    print(f"PASS: daemon survived UPGRADE (same PID {proc.pid})")

    with open(LOG) as f:
        log = f.read()
    if "adopting inherited listener fd" not in log:
        fail("successor did not adopt the inherited listener", proc)
    print("PASS: successor adopted the inherited listener socket")
    # The successor logs how many carried-over connections it re-attached; >=1
    # proves session state + the client fd both crossed the handoff.
    if "re-attached" in log and "re-attached 0 client" not in log:
        print("PASS: successor re-attached carried-over connection(s) (state + fd)")
    else:
        fail("successor did not re-attach any client connection", proc)

    # Conn D was kept open across the upgrade: its TCP connection must survive,
    # with recv re-armed — a PING gets a PONG from the new image.
    try:
        d.sendall(b"PING :survive\r\n")
        pong = recv_until(d, b"PONG")
    except OSError as e:
        fail(f"survivor connection broke across UPGRADE: {e}", proc)
    if "PONG" not in pong:
        fail(f"survivor connection did not answer PING after UPGRADE: {pong!r}", proc)
    print("PASS: pre-upgrade connection SURVIVED the swap (PING/PONG)")

    # The survivor's nick must be re-registered in the new image's world: a fresh
    # client can WHOIS it and get RPL_WHOISUSER (311).
    c2 = connect()
    c2.sendall(b"NICK whoiser\r\nUSER whoiser 0 * :whoiser\r\n")
    recv_until(c2, b" 001 ")
    c2.sendall(b"WHOIS survivor\r\n")
    whois = recv_until(c2, b" 318 ")
    c2.close()
    # NB: keep `d` (survivor) OPEN — closing it would drop it from #durable before
    # the channel-membership check below.
    if " 311 " not in whois:
        fail(f"carried nick not re-registered in world (no WHOIS 311): {whois!r}", proc)
    print("PASS: carried nick re-registered in the new image's world (WHOIS 311)")

    # Channel membership must survive: a fresh client joining #durable sees the
    # carried-over survivor in the NAMES list (RPL_NAMREPLY 353).
    e = connect()
    e.sendall(b"NICK joiner\r\nUSER joiner 0 * :joiner\r\n")
    recv_until(e, b" 001 ")
    e.sendall(b"JOIN #durable\r\n")
    names = recv_until(e, b" 366 ")
    e.close()
    d.close()
    if "survivor" not in names:
        fail(f"carried channel membership lost (survivor not in #durable NAMES): {names!r}", proc)
    print("PASS: carried channel membership survived (NAMES shows survivor in #durable)")

    # Conn C: a fresh client must connect + register after the upgrade.
    time.sleep(0.3)
    c = connect()
    c.sendall(b"NICK after\r\nUSER after 0 * :after\r\n")
    if " 001 " not in recv_until(c, b" 001 "):
        fail("post-upgrade client could not register (port not serving)", proc)
    c.close()
    print("PASS: port stayed bound and serves IRC after UPGRADE")

    cleanup(proc)
    print("\nALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())

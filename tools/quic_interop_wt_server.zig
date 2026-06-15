//! Standalone WebTransport interop test server for a REAL browser (Chromium).
//!
//! Where `quic_interop_server.zig` proves the QUIC + HTTP/3 path against
//! `curl --http3`, this binary proves the WebTransport-specific path against
//! Chrome's actual WebTransport API: Extended CONNECT (`:protocol=webtransport`),
//! WT bidi streams, and WT datagrams. curl cannot speak Extended CONNECT, so a
//! real browser is the only way to exercise this leg.
//!
//! Chrome's `serverCertificateHashes` lets a page connect to a self-signed
//! server WITHOUT a CA, but ONLY if the leaf cert is ECDSA P-256, its validity
//! window is <= 14 days, and the page is given the SHA-256 of the cert DER. So
//! this server mints exactly that cert (Ed25519 — the default interop cert —
//! would be rejected by Chrome's serverCertificateHashes path).
//!
//! Echo bridge: the listener bridges the client's first WT bidi stream to a TCP
//! target. We spawn a tiny loopback TCP echo server in-process and point the
//! bridge at it, so bytes the browser writes on the WT bidi stream round-trip
//! back byte-exact. WT datagrams are echoed by the listener's `echo_wt_datagrams`
//! interop mode (received WT datagram -> re-queued back to the peer).
//!
//! Output contract (read by `tools/quic_interop_browser.mjs`):
//!   * `PORT=<udp>\n`      — the bound UDP port (bind is 127.0.0.1 only).
//!   * `CERTHASH=<hex>\n`  — lowercase hex SHA-256 of the leaf cert DER.
//!   * `CERTHASHB64=<b64>\n`— standard base64 of the same 32-byte hash.
//!   Then it blocks until killed.

const std = @import("std");
const orochi = @import("orochi");

const WebTransportListener = orochi.daemon.webtransport_listener.WebTransportListener;
const x509_selfsign = orochi.proto.x509_selfsign;
const ecdsa_p256 = orochi.crypto.ecdsa_p256;
const Sha256 = std.crypto.hash.sha2.Sha256;

const linux = std.os.linux;
const posix = std.posix;

/// Validity window for Chrome's serverCertificateHashes: must be <= 14 days
/// (~1209600 s). We use ~12 days and set not_before ~1h in the past for clock
/// skew, keeping the whole window comfortably under the cap.
const cert_skew_back_s: i64 = 3600;
const cert_validity_s: i64 = 12 * 24 * 3600;

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // --- 1. Mint a fresh ECDSA P-256 short-validity leaf cert. ---------------
    var seed: [ecdsa_p256.KeyPair.seed_length]u8 = undefined;
    try osEntropy(&seed);
    const kp = try ecdsa_p256.KeyPair.generateDeterministic(seed);

    const now: i64 = wallClockSeconds();
    const not_before = now - cert_skew_back_s;
    const not_after = now + cert_validity_s;

    var cert_buf: [1024]u8 = undefined;
    const cert = try x509_selfsign.buildSelfSignedEcdsaP256(&cert_buf, .{
        .common_name = "localhost",
        .not_before = not_before,
        .not_after = not_after,
        .serial = &.{ 0x51, 0x9a },
        .key_pair = kp,
        .dns_names = &.{"localhost"},
        // 127.0.0.1 as an iPAddress SAN so the browser's hostname check passes.
        .ip_addresses = &.{&[_]u8{ 127, 0, 0, 1 }},
        .is_ca = false,
    });
    const cert_chain = [_][]const u8{cert};

    // SHA-256 over the cert DER — exactly what Chrome hashes for the
    // serverCertificateHashes match.
    var hash: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(cert, &hash, .{});

    // --- 2. Spawn a tiny loopback TCP echo server for the WT bidi bridge. ----
    // The listener's bridge dials 127.0.0.1:<echo_port>; the echo server reflects
    // every byte, so the WT bidi stream round-trips through the real bridge path.
    const echo_port = try startTcpEchoServer(allocator);

    // --- 3. Stand up the real WebTransport listener. -------------------------
    var listener = WebTransportListener.init(allocator, .{
        .cert_chain = &cert_chain,
        .signing_key = .{ .ecdsa_p256 = kp },
    }, echo_port);
    defer listener.deinit();
    // Interop datagram-echo: received WT datagrams are reflected to the peer.
    listener.echo_wt_datagrams = true;

    // Bind 127.0.0.1 only (the browser connects to https://127.0.0.1:<port>).
    const loopback_be: u32 = std.mem.nativeToBig(u32, 0x7f00_0001);
    listener.start(loopback_be, 0) catch |err| {
        std.debug.print("quic_interop_wt_server: bind failed: {s}\n", .{@errorName(err)});
        return err;
    };

    // --- 4. Announce PORT + CERTHASH on stdout. ------------------------------
    var out_buf: [256]u8 = undefined;
    {
        const line = std.fmt.bufPrint(&out_buf, "PORT={d}\n", .{listener.port}) catch unreachable;
        writeAll(1, line);
    }
    {
        var hex_buf: [Sha256.digest_length * 2]u8 = undefined;
        const hex = std.fmt.bufPrint(&hex_buf, "{x}", .{&hash}) catch unreachable;
        const line = std.fmt.bufPrint(&out_buf, "CERTHASH={s}\n", .{hex}) catch unreachable;
        writeAll(1, line);
    }
    {
        const Enc = std.base64.standard.Encoder;
        var b64_buf: [Enc.calcSize(Sha256.digest_length)]u8 = undefined;
        const b64 = Enc.encode(&b64_buf, &hash);
        const line = std.fmt.bufPrint(&out_buf, "CERTHASHB64={s}\n", .{b64}) catch unreachable;
        writeAll(1, line);
    }

    // --- 5. Block forever; the harness kills us when done. -------------------
    while (true) {
        var req = std.os.linux.timespec{ .sec = 60, .nsec = 0 };
        _ = std.os.linux.nanosleep(&req, &req);
    }
}

// ---------------------------------------------------------------------------
// Loopback TCP echo server (bridge target)
// ---------------------------------------------------------------------------

/// Bind a TCP socket on 127.0.0.1:0, spawn a detached accept/echo loop, and
/// return the chosen port. Each accepted connection is echoed byte-for-byte
/// until the peer closes. Single-threaded per connection is fine: there is at
/// most one bridge per QUIC connection and the harness drives one session.
fn startTcpEchoServer(allocator: std.mem.Allocator) !u16 {
    const rc = linux.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, linux.IPPROTO.TCP);
    if (posix.errno(rc) != .SUCCESS) return error.SocketFailed;
    const fd: linux.fd_t = @intCast(rc);

    const one: u32 = 1;
    _ = linux.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, @ptrCast(&one), @sizeOf(u32));

    var addr = linux.sockaddr.in{
        .port = 0, // ephemeral
        .addr = std.mem.nativeToBig(u32, 0x7f00_0001), // 127.0.0.1
    };
    if (posix.errno(linux.bind(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in))) != .SUCCESS) {
        _ = linux.close(fd);
        return error.BindFailed;
    }
    if (posix.errno(linux.listen(fd, 16)) != .SUCCESS) {
        _ = linux.close(fd);
        return error.ListenFailed;
    }

    // Read back the bound port.
    var bound: linux.sockaddr.in = undefined;
    var slen: posix.socklen_t = @sizeOf(linux.sockaddr.in);
    if (posix.errno(linux.getsockname(fd, @ptrCast(&bound), &slen)) != .SUCCESS) {
        _ = linux.close(fd);
        return error.GetSockNameFailed;
    }
    const port = std.mem.bigToNative(u16, bound.port);

    const t = try std.Thread.spawn(.{}, echoAcceptLoop, .{fd});
    t.detach();
    _ = allocator; // no per-thread allocation needed
    return port;
}

fn echoAcceptLoop(listen_fd: linux.fd_t) void {
    while (true) {
        const arc = linux.accept(listen_fd, null, null);
        if (posix.errno(arc) != .SUCCESS) {
            // Transient accept error: yield and retry.
            var req = linux.timespec{ .sec = 0, .nsec = 1_000_000 };
            _ = linux.nanosleep(&req, &req);
            continue;
        }
        const conn_fd: linux.fd_t = @intCast(arc);
        echoConnLoop(conn_fd);
        _ = linux.close(conn_fd);
    }
}

fn echoConnLoop(fd: linux.fd_t) void {
    var buf: [4096]u8 = undefined;
    while (true) {
        const rc = linux.read(fd, &buf, buf.len);
        switch (posix.errno(rc)) {
            .SUCCESS => {
                const n: usize = @intCast(rc);
                if (n == 0) return; // peer closed
                if (!writeAllFd(fd, buf[0..n])) return;
            },
            .INTR => continue,
            else => return,
        }
    }
}

fn writeAllFd(fd: linux.fd_t, bytes: []const u8) bool {
    var sent: usize = 0;
    while (sent < bytes.len) {
        const rc = linux.write(fd, bytes.ptr + sent, bytes.len - sent);
        switch (posix.errno(rc)) {
            .SUCCESS => {
                const n: usize = @intCast(rc);
                if (n == 0) return false;
                sent += n;
            },
            .INTR => continue,
            else => return false,
        }
    }
    return true;
}

// ---------------------------------------------------------------------------
// Small syscall helpers (Linux-only harness)
// ---------------------------------------------------------------------------

fn writeAll(fd: i32, bytes: []const u8) void {
    var sent: usize = 0;
    while (sent < bytes.len) {
        const rc = std.os.linux.write(fd, bytes.ptr + sent, bytes.len - sent);
        const signed: isize = @bitCast(rc);
        if (signed <= 0) return;
        sent += rc;
    }
}

/// Wall-clock seconds since the Unix epoch via the raw `clock_gettime`
/// syscall (Linux-only harness). Used only to anchor the cert validity window.
fn wallClockSeconds() i64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(linux.CLOCK.REALTIME, &ts);
    return @intCast(ts.sec);
}

fn osEntropy(buf: []u8) !void {
    var filled: usize = 0;
    while (filled < buf.len) {
        const rc = std.os.linux.getrandom(buf.ptr + filled, buf.len - filled, 0);
        const signed: isize = @bitCast(rc);
        if (signed < 0 or rc == 0) return error.Entropy;
        filled += rc;
    }
}

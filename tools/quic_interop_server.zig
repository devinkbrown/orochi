//! Standalone QUIC/HTTP3 interop test server.
//!
//! Stands up the real Orochi `WebTransportListener` (the same from-scratch QUIC
//! + TLS-1.3-over-QUIC + HTTP/3 stack the daemon uses) on an ephemeral UDP port
//! with a freshly-minted self-signed certificate, then blocks forever. It is
//! driven by `tools/quic_interop.sh`, which runs a real third-party HTTP/3
//! client (`curl --http3`) against it to validate interop.
//!
//! It does NOT run the IRC daemon: a plain HTTP/3 `GET` is answered directly by
//! the HTTP/3 layer (`http3_conn.respondHttpRequest`) and never opens the IRC
//! loopback bridge, so `irc_port = 0` is fine. The point is to exercise the QUIC
//! handshake + H3 framing against an independent implementation, not IRC.
//!
//! Output contract (read by the harness):
//!   * Prints exactly one line `PORT=<n>\n` to stdout once bound, then flushes.
//!   * Runs until killed (SIGTERM/SIGKILL).

const std = @import("std");
const orochi = @import("orochi");

const WebTransportListener = orochi.daemon.webtransport_listener.WebTransportListener;
const any_be = orochi.daemon.webtransport_listener.any_be;
const x509_selfsign = orochi.proto.x509_selfsign;

const Ed25519 = std.crypto.sign.Ed25519;

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Parse flags. `--retry` turns on address validation (RFC 9000 §8.1.2):
    // every tokenless Initial is answered with a Retry packet, forcing the client
    // to re-send its Initial carrying the token. A real client (curl/ngtcp2) must
    // handle that round trip transparently and still complete the handshake.
    const want_retry = cmdlineHasFlag("--retry");

    // Bind an ephemeral UDP port (0); the harness reads the chosen port back
    // from the `PORT=<n>` line we print below.
    const port: u16 = 0;

    // Mint a fresh self-signed Ed25519 leaf certificate (curl uses -k / --insecure
    // to accept it). A real random key each run avoids any cross-run key reuse.
    var seed: [Ed25519.KeyPair.seed_length]u8 = undefined;
    try osEntropy(&seed);
    const kp = try Ed25519.KeyPair.generateDeterministic(seed);

    var cert_buf: [1024]u8 = undefined;
    const cert = try x509_selfsign.buildSelfSigned(&cert_buf, .{
        .common_name = "localhost",
        .not_before = 1_704_067_200, // 2024-01-01
        .not_after = 4_102_444_800, // 2100-01-01
        .serial = &.{ 0x51, 0x99 },
        .key_pair = kp,
        .dns_names = &.{ "localhost", "127.0.0.1" },
        .is_ca = true,
    });
    const cert_chain = [_][]const u8{cert};

    var listener = WebTransportListener.init(allocator, .{
        .cert_chain = &cert_chain,
        .signing_key = .{ .ed25519 = kp },
    }, 0); // irc_port = 0: a plain GET never opens the IRC bridge.
    defer listener.deinit();
    if (want_retry) listener.retry_policy = .always;

    listener.start(any_be, port) catch |err| {
        std.debug.print("quic_interop_server: bind failed: {s}\n", .{@errorName(err)});
        return err;
    };

    // Announce the bound port on stdout (the harness parses this). A single
    // unbuffered write to fd 1 keeps this robust against std writer API churn.
    var line_buf: [64]u8 = undefined;
    const line = std.fmt.bufPrint(&line_buf, "PORT={d}\n", .{listener.port}) catch unreachable;
    writeAll(1, line);

    // Block forever; the harness kills the process when done. The listener runs
    // its own pump thread, so the main thread just parks.
    while (true) {
        var req = std.os.linux.timespec{ .sec = 60, .nsec = 0 };
        _ = std.os.linux.nanosleep(&req, &req);
    }
}

/// Write all of `bytes` to file descriptor `fd` via the raw Linux write syscall.
fn writeAll(fd: i32, bytes: []const u8) void {
    var sent: usize = 0;
    while (sent < bytes.len) {
        const rc = std.os.linux.write(fd, bytes.ptr + sent, bytes.len - sent);
        const signed: isize = @bitCast(rc);
        if (signed <= 0) return;
        sent += rc;
    }
}

/// Whether the process command line contains `flag` (exact NUL-delimited argv
/// token). Reads `/proc/self/cmdline` via raw syscalls — the harness is
/// Linux-only and this avoids depending on the Zig-version-specific args API.
/// The arguments are NUL-separated, so a token match is an exact match.
fn cmdlineHasFlag(flag: []const u8) bool {
    const linux = std.os.linux;
    const rc = linux.open("/proc/self/cmdline", .{ .ACCMODE = .RDONLY }, 0);
    const sfd: isize = @bitCast(rc);
    if (sfd < 0) return false;
    const fd: linux.fd_t = @intCast(rc);
    defer _ = linux.close(fd);

    var buf: [4096]u8 = undefined;
    var total: usize = 0;
    while (total < buf.len) {
        const r = linux.read(fd, buf[total..].ptr, buf.len - total);
        const sr: isize = @bitCast(r);
        if (sr <= 0) break;
        total += @intCast(r);
    }
    // Split on NUL and compare each token.
    var it = std.mem.splitScalar(u8, buf[0..total], 0);
    while (it.next()) |tok| {
        if (std.mem.eql(u8, tok, flag)) return true;
    }
    return false;
}

/// Fill `buf` from the OS CSPRNG via the raw Linux getrandom syscall (matching
/// the daemon's own entropy path; the harness is Linux-only).
fn osEntropy(buf: []u8) !void {
    var filled: usize = 0;
    while (filled < buf.len) {
        const rc = std.os.linux.getrandom(buf.ptr + filled, buf.len - filled, 0);
        const signed: isize = @bitCast(rc);
        if (signed < 0 or rc == 0) return error.Entropy;
        filled += rc;
    }
}

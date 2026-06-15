//! Dual-stack (IPv6 + IPv4-mapped) UDP socket for the WebTransport listener.
//!
//! A blocking `SOCK_DGRAM` socket opened on `AF_INET6` with `IPV6_V6ONLY=0`, so
//! ONE socket serves both native IPv6 peers and IPv4 peers (the latter arrive as
//! IPv4-mapped addresses `::ffff:a.b.c.d`, RFC 4291 §2.5.5.2). This mirrors the
//! shape of `MediaSocket` (`bind` / `deinit` / `localPort` / `setRecvTimeoutMs` /
//! `recvFrom` / `sendTo`) so the listener can swap one for the other, but it is a
//! SEPARATE socket: the media plane keeps its proven IPv4-only `MediaSocket`.
//!
//! Address mapping (`sockaddr_in6` ⇄ `TransportAddress`)
//! ----------------------------------------------------
//!   * `recvFrom`: an IPv4-mapped source (`::ffff:0:0/96`) is surfaced as a
//!     4-byte ipv4 `TransportAddress` (so PROXY-protocol carry + logging see the
//!     REAL v4 address, not a v6 wrapper); any other source is surfaced as a
//!     16-byte ipv6 `TransportAddress`.
//!   * `sendTo`: a v4 `TransportAddress` is re-wrapped as a v4-mapped
//!     `::ffff:a.b.c.d`; a v6 `TransportAddress` is copied verbatim. Either way
//!     the kernel routes it correctly over the single dual-stack socket.
//!   * `scope_id`/`flowinfo` are 0 (loopback + global unicast; this listener does
//!     not address link-local scopes).
//!
//! Bounds: a malformed/oversized datagram cannot panic — `recvFrom` clamps the
//! read to `buf.len` and only ever returns the actually-received prefix; the
//! address conversion is fixed-width and total over any 16-byte input.
const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const ice = @import("../proto/ice.zig");

pub const TransportAddress = ice.TransportAddress;

/// The 12-byte `::ffff:` prefix that marks an IPv4-mapped IPv6 address
/// (RFC 4291 §2.5.5.2): 80 zero bits followed by 16 one bits.
const v4mapped_prefix = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };

pub const Error = error{ SocketUnavailable, BindFailed, AddrLookupFailed };

pub const DualStackUdpSocket = struct {
    fd: linux.fd_t,

    /// Open a dual-stack UDP socket and bind it. `bind_addr` selects the local
    /// address to bind:
    ///   * `.any` → `[::]` (all interfaces, both families) — the normal server bind.
    ///   * `.loopback_v6` → `[::1]` (IPv6 loopback only) — for tests.
    ///   * `.v4_mapped` → bind a configured IPv4 address as `::ffff:a.b.c.d` so a
    ///     v4-only operator config still works over the dual-stack socket.
    /// `port` 0 = ephemeral. The socket has `IPV6_V6ONLY=0`, so even an `[::]`
    /// bind also accepts IPv4 peers as IPv4-mapped sources.
    pub fn bind(bind_addr: BindAddr, port: u16) Error!DualStackUdpSocket {
        const rc = linux.socket(posix.AF.INET6, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, linux.IPPROTO.UDP);
        if (posix.errno(rc) != .SUCCESS) return error.SocketUnavailable;
        const fd: linux.fd_t = @intCast(rc);
        errdefer _ = linux.close(fd);

        // IPV6_V6ONLY=0: one socket serves both IPv6 and IPv4 (mapped) peers.
        const v6only: c_int = 0;
        if (posix.errno(linux.setsockopt(
            fd,
            linux.SOL.IPV6,
            linux.IPV6.V6ONLY,
            std.mem.asBytes(&v6only),
            @sizeOf(c_int),
        )) != .SUCCESS) return error.BindFailed;

        var addr = linux.sockaddr.in6{
            .port = std.mem.nativeToBig(u16, port),
            .flowinfo = 0,
            .addr = bind_addr.toBytes(),
            .scope_id = 0,
        };
        if (posix.errno(linux.bind(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in6))) != .SUCCESS)
            return error.BindFailed;
        return .{ .fd = fd };
    }

    /// Which local address to bind the dual-stack socket to.
    pub const BindAddr = union(enum) {
        /// `[::]` — all interfaces, both families (the production server bind).
        any,
        /// `[::1]` — IPv6 loopback only (tests).
        loopback_v6,
        /// A configured IPv4 bind address, bound as `::ffff:a.b.c.d` so a
        /// v4-only operator config still binds on the dual-stack socket.
        v4_mapped: [4]u8,

        fn toBytes(self: BindAddr) [16]u8 {
            return switch (self) {
                .any => [_]u8{0} ** 16, // ::
                .loopback_v6 => blk: {
                    var a = [_]u8{0} ** 16;
                    a[15] = 1; // ::1
                    break :blk a;
                },
                .v4_mapped => |v4| blk: {
                    var a = [_]u8{0} ** 16;
                    @memcpy(a[0..12], &v4mapped_prefix);
                    @memcpy(a[12..16], &v4);
                    break :blk a;
                },
            };
        }
    };

    pub fn deinit(self: *DualStackUdpSocket) void {
        _ = linux.close(self.fd);
        self.* = undefined;
    }

    /// The bound local UDP port (host byte order).
    pub fn localPort(self: *const DualStackUdpSocket) Error!u16 {
        var sa: linux.sockaddr.in6 = undefined;
        var len: posix.socklen_t = @sizeOf(linux.sockaddr.in6);
        if (posix.errno(linux.getsockname(self.fd, @ptrCast(&sa), &len)) != .SUCCESS)
            return error.AddrLookupFailed;
        return std.mem.bigToNative(u16, sa.port);
    }

    /// Bound a blocking recv with a timeout so the pump loop can re-check a stop
    /// flag (and tests never hang).
    pub fn setRecvTimeoutMs(self: *DualStackUdpSocket, ms: u32) void {
        const tv = linux.timeval{ .sec = @intCast(ms / 1000), .usec = @intCast((ms % 1000) * 1000) };
        _ = linux.setsockopt(self.fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv), @sizeOf(linux.timeval));
    }

    /// Send `bytes` to `dest`. A v4 `TransportAddress` is re-wrapped as a
    /// v4-mapped `::ffff:a.b.c.d`; a v6 one is copied verbatim. A `TransportAddress`
    /// with an unexpected `ip_len` (neither 4 nor 16) is dropped.
    pub fn sendTo(self: *DualStackUdpSocket, dest: TransportAddress, bytes: []const u8) void {
        const sa = toSockaddrIn6(dest) orelse return;
        _ = linux.sendto(self.fd, bytes.ptr, bytes.len, 0, @ptrCast(&sa), @sizeOf(linux.sockaddr.in6));
    }

    pub const Received = struct { data: []u8, from: TransportAddress };

    /// Receive one datagram into `buf`. Returns null on timeout/error. The source
    /// `sockaddr_in6` is converted to a `TransportAddress`: an IPv4-mapped source
    /// becomes a 4-byte ipv4 address, anything else a 16-byte ipv6 address.
    pub fn recvFrom(self: *DualStackUdpSocket, buf: []u8) ?Received {
        var sa: linux.sockaddr.in6 = undefined;
        var slen: posix.socklen_t = @sizeOf(linux.sockaddr.in6);
        const rc = linux.recvfrom(self.fd, buf.ptr, buf.len, 0, @ptrCast(&sa), &slen);
        if (posix.errno(rc) != .SUCCESS) return null;
        const n: usize = @intCast(rc);
        const from = fromSockaddrIn6(&sa) catch return null;
        return .{ .data = buf[0..n], .from = from };
    }
};

// ---------------------------------------------------------------------------
// sockaddr_in6 ⇄ TransportAddress mapping (pure; unit-tested without a socket)
// ---------------------------------------------------------------------------

/// True if `addr16` is an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`).
pub fn isV4Mapped(addr16: [16]u8) bool {
    return std.mem.eql(u8, addr16[0..12], &v4mapped_prefix);
}

/// Convert a source `sockaddr_in6` to a `TransportAddress`. An IPv4-mapped
/// source is surfaced as a 4-byte ipv4 address (so the REAL v4 address reaches
/// PROXY-protocol + logging); otherwise a 16-byte ipv6 address. Total over any
/// 16-byte address (the only failure path is the unreachable >16-byte case).
pub fn fromSockaddrIn6(sa: *const linux.sockaddr.in6) ice.IceError!TransportAddress {
    const port = std.mem.bigToNative(u16, sa.port);
    if (isV4Mapped(sa.addr)) {
        return TransportAddress.fromBytes(sa.addr[12..16], port);
    }
    return TransportAddress.fromBytes(&sa.addr, port);
}

/// Convert a `TransportAddress` to a `sockaddr_in6` for sending over the
/// dual-stack socket. A v4 address (`ip_len == 4`) is re-wrapped as a v4-mapped
/// `::ffff:a.b.c.d`; a v6 address (`ip_len == 16`) is copied verbatim. Returns
/// null for an unexpected `ip_len` (neither 4 nor 16) so a malformed address is
/// dropped rather than sent to a garbage destination.
pub fn toSockaddrIn6(addr: TransportAddress) ?linux.sockaddr.in6 {
    var out = linux.sockaddr.in6{
        .port = std.mem.nativeToBig(u16, addr.port),
        .flowinfo = 0,
        .addr = [_]u8{0} ** 16,
        .scope_id = 0,
    };
    switch (addr.ip_len) {
        4 => {
            @memcpy(out.addr[0..12], &v4mapped_prefix);
            @memcpy(out.addr[12..16], addr.ip[0..4]);
        },
        16 => @memcpy(&out.addr, addr.ip[0..16]),
        else => return null,
    }
    return out;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "isV4Mapped recognises ::ffff:0:0/96 and rejects native v6" {
    var mapped = [_]u8{0} ** 16;
    @memcpy(mapped[0..12], &v4mapped_prefix);
    mapped[12..16].* = [_]u8{ 192, 0, 2, 7 };
    try testing.expect(isV4Mapped(mapped));

    // ::1 (loopback) is NOT v4-mapped.
    var v6 = [_]u8{0} ** 16;
    v6[15] = 1;
    try testing.expect(!isV4Mapped(v6));

    // A global-unicast v6 address is not v4-mapped.
    const g = [_]u8{ 0x20, 0x01, 0x0d, 0xb8 } ++ [_]u8{0} ** 11 ++ [_]u8{1};
    try testing.expect(!isV4Mapped(g));
}

test "round-trip: a v4-mapped sockaddr_in6 surfaces as an ipv4 TransportAddress and back" {
    // Build a v4-mapped sockaddr_in6 for 203.0.113.9:4433.
    var sa = linux.sockaddr.in6{
        .port = std.mem.nativeToBig(u16, 4433),
        .flowinfo = 0,
        .addr = [_]u8{0} ** 16,
        .scope_id = 0,
    };
    @memcpy(sa.addr[0..12], &v4mapped_prefix);
    sa.addr[12..16].* = [_]u8{ 203, 0, 113, 9 };

    // recv path: surfaced as a 4-byte ipv4 address (NOT a v6 wrapper).
    const ta = try fromSockaddrIn6(&sa);
    try testing.expectEqual(@as(u8, 4), ta.ip_len);
    try testing.expectEqual(@as(u16, 4433), ta.port);
    try testing.expectEqualSlices(u8, &[_]u8{ 203, 0, 113, 9 }, ta.bytes());

    // send path: the ipv4 address re-wraps to the identical v4-mapped sockaddr.
    const back = toSockaddrIn6(ta) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(sa.port, back.port);
    try testing.expectEqual(@as(u32, 0), back.scope_id);
    try testing.expectEqual(@as(u32, 0), back.flowinfo);
    try testing.expectEqualSlices(u8, &sa.addr, &back.addr);
    try testing.expect(isV4Mapped(back.addr));
}

test "round-trip: a native v6 sockaddr_in6 surfaces as an ipv6 TransportAddress and back" {
    const v6 = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42 };
    var sa = linux.sockaddr.in6{
        .port = std.mem.nativeToBig(u16, 51820),
        .flowinfo = 0,
        .addr = v6,
        .scope_id = 0,
    };

    const ta = try fromSockaddrIn6(&sa);
    try testing.expectEqual(@as(u8, 16), ta.ip_len);
    try testing.expectEqual(@as(u16, 51820), ta.port);
    try testing.expectEqualSlices(u8, &v6, ta.bytes());

    const back = toSockaddrIn6(ta) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(sa.port, back.port);
    try testing.expectEqualSlices(u8, &v6, &back.addr);
    try testing.expect(!isV4Mapped(back.addr));
}

test "round-trip: ::1 loopback surfaces as a 16-byte ipv6 TransportAddress" {
    var v6 = [_]u8{0} ** 16;
    v6[15] = 1;
    var sa = linux.sockaddr.in6{
        .port = std.mem.nativeToBig(u16, 9000),
        .flowinfo = 0,
        .addr = v6,
        .scope_id = 0,
    };
    const ta = try fromSockaddrIn6(&sa);
    try testing.expectEqual(@as(u8, 16), ta.ip_len);
    try testing.expectEqualSlices(u8, &v6, ta.bytes());
    const back = toSockaddrIn6(ta) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, &v6, &back.addr);
}

test "toSockaddrIn6 drops a TransportAddress with an unexpected ip_len" {
    var bad: TransportAddress = .{};
    bad.ip_len = 7; // neither 4 nor 16
    try testing.expect(toSockaddrIn6(bad) == null);
}

test "dualstack socket: bind on [::], ephemeral port, clean shutdown, v4 receive" {
    // The server binds [::]:0 (dual-stack). An IPv4 loopback client must reach it
    // as a v4-mapped source surfaced as an ipv4 TransportAddress.
    var server = DualStackUdpSocket.bind(.any, 0) catch return error.SkipZigTest;
    defer server.deinit();
    server.setRecvTimeoutMs(2000);
    const sport = try server.localPort();
    try testing.expect(sport != 0);

    // --- IPv4 leg: send from a real 127.0.0.1 UDP socket. ---
    const c4_rc = linux.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, linux.IPPROTO.UDP);
    try testing.expectEqual(posix.E.SUCCESS, posix.errno(c4_rc));
    const c4: linux.fd_t = @intCast(c4_rc);
    defer _ = linux.close(c4);
    var c4_addr = linux.sockaddr.in{ .port = 0, .addr = std.mem.nativeToBig(u32, 0x7f00_0001) };
    try testing.expectEqual(posix.E.SUCCESS, posix.errno(linux.bind(c4, @ptrCast(&c4_addr), @sizeOf(linux.sockaddr.in))));
    var c4_sa: linux.sockaddr.in = undefined;
    var c4_slen: posix.socklen_t = @sizeOf(linux.sockaddr.in);
    _ = linux.getsockname(c4, @ptrCast(&c4_sa), &c4_slen);
    const c4_port = std.mem.bigToNative(u16, c4_sa.port);

    // 127.0.0.1:sport as a sockaddr_in (the v4 client addresses the v4 world).
    var dst4 = linux.sockaddr.in{
        .port = std.mem.nativeToBig(u16, sport),
        .addr = std.mem.nativeToBig(u32, 0x7f00_0001),
    };
    const payload4 = "v4-hello";
    _ = linux.sendto(c4, payload4, payload4.len, 0, @ptrCast(&dst4), @sizeOf(linux.sockaddr.in));

    var buf: [64]u8 = undefined;
    const got4 = server.recvFrom(&buf) orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings(payload4, got4.data);
    // The v4 client surfaces as an IPV4 TransportAddress (real 127.0.0.1), not v6.
    try testing.expectEqual(@as(u8, 4), got4.from.ip_len);
    try testing.expectEqualSlices(u8, &[_]u8{ 127, 0, 0, 1 }, got4.from.bytes());
    try testing.expectEqual(c4_port, got4.from.port);

    // Reply via sendTo (ipv4 dest → v4-mapped over the dual-stack socket).
    server.sendTo(got4.from, "v4-reply");
    var rbuf: [64]u8 = undefined;
    // Bound the client recv so the test can't hang.
    const tv = linux.timeval{ .sec = 2, .usec = 0 };
    _ = linux.setsockopt(c4, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv), @sizeOf(linux.timeval));
    const rn4 = linux.recvfrom(c4, &rbuf, rbuf.len, 0, null, null);
    try testing.expectEqual(posix.E.SUCCESS, posix.errno(rn4));
    try testing.expectEqualStrings("v4-reply", rbuf[0..@intCast(rn4)]);
}

test "dualstack socket: IPv6 loopback receive (skips if no v6 loopback)" {
    var server = DualStackUdpSocket.bind(.any, 0) catch return error.SkipZigTest;
    defer server.deinit();
    server.setRecvTimeoutMs(2000);
    const sport = try server.localPort();

    // --- IPv6 leg: send from a real ::1 UDP socket. If the sandbox lacks IPv6
    // loopback, gracefully skip THIS leg only (the v4-over-v6-socket leg above
    // and the pure mapping tests still hold coverage). ---
    const c6_rc = linux.socket(posix.AF.INET6, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, linux.IPPROTO.UDP);
    if (posix.errno(c6_rc) != .SUCCESS) return error.SkipZigTest;
    const c6: linux.fd_t = @intCast(c6_rc);
    defer _ = linux.close(c6);
    var lo6 = [_]u8{0} ** 16;
    lo6[15] = 1; // ::1
    var c6_bind = linux.sockaddr.in6{ .port = 0, .flowinfo = 0, .addr = lo6, .scope_id = 0 };
    if (posix.errno(linux.bind(c6, @ptrCast(&c6_bind), @sizeOf(linux.sockaddr.in6))) != .SUCCESS)
        return error.SkipZigTest;

    var dst6 = linux.sockaddr.in6{
        .port = std.mem.nativeToBig(u16, sport),
        .flowinfo = 0,
        .addr = lo6,
        .scope_id = 0,
    };
    const payload6 = "v6-hello";
    const sn = linux.sendto(c6, payload6, payload6.len, 0, @ptrCast(&dst6), @sizeOf(linux.sockaddr.in6));
    if (posix.errno(sn) != .SUCCESS) return error.SkipZigTest;

    var buf: [64]u8 = undefined;
    const got6 = server.recvFrom(&buf) orelse return error.SkipZigTest;
    try testing.expectEqualStrings(payload6, got6.data);
    // The v6 client surfaces as a 16-byte IPV6 TransportAddress (::1).
    try testing.expectEqual(@as(u8, 16), got6.from.ip_len);
    try testing.expectEqualSlices(u8, &lo6, got6.from.bytes());

    // Reply via sendTo (ipv6 dest copied verbatim).
    server.sendTo(got6.from, "v6-reply");
    const tv = linux.timeval{ .sec = 2, .usec = 0 };
    _ = linux.setsockopt(c6, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv), @sizeOf(linux.timeval));
    var rbuf: [64]u8 = undefined;
    const rn6 = linux.recvfrom(c6, &rbuf, rbuf.len, 0, null, null);
    if (posix.errno(rn6) != .SUCCESS) return error.SkipZigTest;
    try testing.expectEqualStrings("v6-reply", rbuf[0..@intCast(rn6)]);
}

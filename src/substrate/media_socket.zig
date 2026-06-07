//! Live UDP media socket for the SFU transport plane (IPv4).
//!
//! A blocking `SOCK_DGRAM` socket that the media plane reads in a loop (on its
//! own thread; see the daemon wiring). Each datagram is demultiplexed: STUN
//! binding requests are answered via `MediaTransport.handleStunBinding` (ICE
//! connectivity checks that bind the peer's address); RTP is relayed by the SFU
//! (a later step). Kept deliberately separate from the io_uring TCP loop — media
//! I/O is hot and self-contained, so a dedicated UDP socket is simpler and does
//! not perturb the client/S2S event loop.
const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const ice = @import("../proto/ice.zig");
const media_transport = @import("media_transport.zig");

pub const TransportAddress = ice.TransportAddress;
pub const MediaTransport = media_transport.MediaTransport;
pub const max_datagram: usize = 1500;

/// 127.0.0.1 in network byte order, for loopback binds/tests.
pub const loopback_be: u32 = nativeToBigU32(0x7f00_0001);
/// 0.0.0.0 (all interfaces).
pub const any_be: u32 = 0;

fn nativeToBigU32(v: u32) u32 {
    return std.mem.nativeToBig(u32, v);
}

pub const Error = error{ SocketUnavailable, BindFailed, AddrLookupFailed };

pub const MediaSocket = struct {
    fd: linux.fd_t,

    /// Create and bind a UDP socket. `bind_addr_be` is an IPv4 address already in
    /// network byte order (use `loopback_be` / `any_be`); `port` 0 = ephemeral.
    pub fn bind(bind_addr_be: u32, port: u16) Error!MediaSocket {
        const rc = linux.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, linux.IPPROTO.UDP);
        if (posix.errno(rc) != .SUCCESS) return error.SocketUnavailable;
        const fd: linux.fd_t = @intCast(rc);
        errdefer _ = linux.close(fd);

        var addr = linux.sockaddr.in{ .port = std.mem.nativeToBig(u16, port), .addr = bind_addr_be };
        if (posix.errno(linux.bind(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in))) != .SUCCESS)
            return error.BindFailed;
        return .{ .fd = fd };
    }

    pub fn deinit(self: *MediaSocket) void {
        _ = linux.close(self.fd);
        self.* = undefined;
    }

    /// The bound local UDP port (host byte order).
    pub fn localPort(self: *const MediaSocket) Error!u16 {
        var storage: posix.sockaddr.storage = undefined;
        var len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
        if (posix.errno(linux.getsockname(self.fd, @ptrCast(&storage), &len)) != .SUCCESS)
            return error.AddrLookupFailed;
        const a: *const linux.sockaddr.in = @ptrCast(@alignCast(&storage));
        return std.mem.bigToNative(u16, a.port);
    }

    /// Bound a blocking recv with a timeout so the pump loop can re-check a stop
    /// flag (and tests never hang).
    pub fn setRecvTimeoutMs(self: *MediaSocket, ms: u32) void {
        const tv = linux.timeval{ .sec = @intCast(ms / 1000), .usec = @intCast((ms % 1000) * 1000) };
        _ = linux.setsockopt(self.fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv), @sizeOf(linux.timeval));
    }

    /// Send `bytes` to an IPv4 destination. Non-IPv4 addresses are dropped.
    pub fn sendTo(self: *MediaSocket, dest: TransportAddress, bytes: []const u8) void {
        if (dest.ip_len != 4) return;
        var sa = linux.sockaddr.in{
            .port = std.mem.nativeToBig(u16, dest.port),
            .addr = @bitCast(dest.ip[0..4].*),
        };
        _ = linux.sendto(self.fd, bytes.ptr, bytes.len, 0, @ptrCast(&sa), @sizeOf(linux.sockaddr.in));
    }

    pub const Received = struct { data: []u8, from: TransportAddress };

    /// Receive one datagram into `buf`. Returns null on timeout/error/non-IPv4.
    pub fn recvFrom(self: *MediaSocket, buf: []u8) ?Received {
        var sa: linux.sockaddr.in = undefined;
        var slen: posix.socklen_t = @sizeOf(linux.sockaddr.in);
        const rc = linux.recvfrom(self.fd, buf.ptr, buf.len, 0, @ptrCast(&sa), &slen);
        if (posix.errno(rc) != .SUCCESS) return null;
        const n: usize = @intCast(rc);
        const ip4: [4]u8 = @bitCast(sa.addr);
        const from = TransportAddress.fromBytes(&ip4, std.mem.bigToNative(u16, sa.port)) catch return null;
        return .{ .data = buf[0..n], .from = from };
    }

    /// Whether a datagram's first byte marks it as STUN (top two bits zero) vs
    /// RTP/RTCP (version 2 → 0x80+). RFC 5764 §5.1.2 demultiplexing rule.
    pub fn isStun(first: u8) bool {
        return (first & 0xC0) == 0;
    }

    /// Read and process one datagram: STUN binding requests are answered (binding
    /// the peer address); RTP is left for the SFU relay step. Returns true if a
    /// datagram was read, false on timeout/idle. `buf` is scratch for the read.
    pub fn pumpOnce(
        self: *MediaSocket,
        transport: *MediaTransport,
        allocator: std.mem.Allocator,
        buf: []u8,
    ) bool {
        const got = self.recvFrom(buf) orelse return false;
        if (got.data.len == 0) return true;
        if (isStun(got.data[0])) {
            const resp = transport.handleStunBinding(allocator, got.data, got.from) catch return true;
            if (resp) |r| {
                defer allocator.free(r);
                self.sendTo(got.from, r);
            }
        }
        return true;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const stun = @import("../proto/stun.zig");

test "loopback STUN binding round-trip binds the peer and answers" {
    var prng = std.Random.DefaultPrng.init(0xc0ffee);
    var mt = MediaTransport.init(testing.allocator);
    defer mt.deinit();
    const ep = try mt.allocate("#c", "alice", prng.random());
    const ufrag = ep.ufrag;
    const pwd = ep.pwd;

    var server = try MediaSocket.bind(loopback_be, 0);
    defer server.deinit();
    server.setRecvTimeoutMs(2000);
    const sport = try server.localPort();

    var client = try MediaSocket.bind(loopback_be, 0);
    defer client.deinit();
    client.setRecvTimeoutMs(2000);

    // Client sends a STUN binding request to the server's media port.
    var user_buf: [media_transport.ufrag_len + 6]u8 = undefined;
    const user = std.fmt.bufPrint(&user_buf, "{s}:peer", .{ufrag[0..]}) catch unreachable;
    const tx: stun.TransactionId = .{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
    const req = try stun.buildBindingRequest(testing.allocator, tx, .{
        .username = user,
        .integrity_key = pwd[0..],
        .fingerprint = true,
    });
    defer testing.allocator.free(req);
    const server_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, sport);
    client.sendTo(server_addr, req);

    // Server processes the datagram: authenticates, binds, replies.
    var sbuf: [max_datagram]u8 = undefined;
    try testing.expect(server.pumpOnce(&mt, testing.allocator, &sbuf));
    try testing.expect(mt.get("#c", "alice").?.connected());

    // Client receives a verifiable binding success response.
    var cbuf: [max_datagram]u8 = undefined;
    const got = client.recvFrom(&cbuf) orelse return error.TestUnexpectedResult;
    var decoded = try stun.decode(testing.allocator, got.data);
    defer decoded.deinit(testing.allocator);
    try testing.expectEqual(stun.MessageType.binding_success_response, decoded.typ);
    try testing.expect(try stun.verifyMessageIntegrity(got.data, pwd[0..]));
}

test "isStun demultiplexes STUN from RTP" {
    try testing.expect(MediaSocket.isStun(0x00)); // STUN binding request type hi byte
    try testing.expect(!MediaSocket.isStun(0x80)); // RTP version 2
    try testing.expect(!MediaSocket.isStun(0x90)); // RTP with extension
}

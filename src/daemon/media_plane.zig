//! Daemon-owned media transport plane: ties the SFU endpoint registry
//! (MediaTransport) to a live UDP MediaSocket and a background pump thread.
//!
//! The pump thread blocks on the media socket (with a short recv timeout so it
//! can observe the stop flag), demultiplexes each datagram, and answers STUN
//! connectivity checks under a mutex. The daemon's main thread allocates and
//! removes endpoints (on MEDIA OFFER / LEAVE) through the same mutex, so the two
//! threads share the registry safely. Media STUN traffic is low-rate (a call
//! handshake), so a single coarse mutex is more than adequate.
const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const media_transport = @import("../substrate/media_transport.zig");
const media_socket = @import("../substrate/media_socket.zig");
const rtp_profile = @import("../proto/rtp_profile.zig");

pub const MediaTransport = media_transport.MediaTransport;
pub const MediaSocket = media_socket.MediaSocket;
pub const TransportAddress = media_transport.TransportAddress;
pub const loopback_be = media_socket.loopback_be;
pub const any_be = media_socket.any_be;

/// Blocking acquire on the tryLock-only `std.atomic.Mutex`. Contention is
/// near-zero (rare allocate/remove vs. low-rate STUN handshakes), so yielding.
fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.Thread.yield() catch {};
}

/// Whether byte 1 of a version-2 packet marks it as RTCP rather than RTP.
/// RFC 5761 reserves RTP payload types 64–95 so RTCP packet types (200–204,
/// i.e. byte 1 in 192–223) are unambiguous on a muxed RTP/RTCP socket.
fn isRtcp(b1: u8) bool {
    return b1 >= 192 and b1 <= 223;
}

/// Fill `buf` with OS entropy (getrandom), falling back to a constant only if
/// the syscall fails (never expected on a running daemon).
fn osEntropy(buf: []u8) void {
    var filled: usize = 0;
    while (filled < buf.len) {
        const rc = linux.getrandom(buf.ptr + filled, buf.len - filled, 0);
        if (posix.errno(rc) != .SUCCESS) {
            for (buf[filled..]) |*b| b.* = 0x55;
            return;
        }
        filled += @intCast(rc);
    }
}

/// ICE credentials handed back to the signaling layer to advertise to a client.
pub const Creds = struct {
    ufrag: [media_transport.ufrag_len]u8,
    pwd: [media_transport.pwd_len]u8,

    pub fn ufragSlice(self: *const Creds) []const u8 {
        return self.ufrag[0..];
    }
    pub fn pwdSlice(self: *const Creds) []const u8 {
        return self.pwd[0..];
    }
};

pub const MediaPlane = struct {
    allocator: std.mem.Allocator,
    transport: MediaTransport,
    socket: ?MediaSocket = null,
    mutex: std.atomic.Mutex = .unlocked,
    thread: ?std.Thread = null,
    stop_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// The bound local UDP port (0 until started); advertised to clients.
    port: u16 = 0,
    /// CSPRNG for ICE credential generation, seeded from the OS at init.
    /// Accessed only under `mutex` (in allocate).
    csprng: std.Random.DefaultCsprng,

    pub fn init(allocator: std.mem.Allocator) MediaPlane {
        var seed: [std.Random.DefaultCsprng.secret_seed_length]u8 = undefined;
        osEntropy(&seed);
        return .{
            .allocator = allocator,
            .transport = MediaTransport.init(allocator),
            .csprng = std.Random.DefaultCsprng.init(seed),
        };
    }

    pub fn deinit(self: *MediaPlane) void {
        self.shutdown();
        self.transport.deinit();
        self.* = undefined;
    }

    /// Bind the media socket on `bind_be`:`port` (port 0 = ephemeral) and spawn
    /// the pump thread. No-op if already started.
    pub fn start(self: *MediaPlane, bind_be: u32, port: u16) !void {
        if (self.socket != null) return;
        var sock = try MediaSocket.bind(bind_be, port);
        errdefer sock.deinit();
        sock.setRecvTimeoutMs(250); // wake periodically to observe the stop flag
        self.port = try sock.localPort();
        self.socket = sock;
        self.stop_flag.store(false, .release);
        self.thread = std.Thread.spawn(.{}, pumpLoop, .{self}) catch |e| {
            self.socket.?.deinit();
            self.socket = null;
            return e;
        };
    }

    /// Signal the pump thread to stop, join it, and close the socket.
    pub fn shutdown(self: *MediaPlane) void {
        self.stop_flag.store(true, .release);
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
        if (self.socket) |*s| {
            s.deinit();
            self.socket = null;
        }
    }

    fn pumpLoop(self: *MediaPlane) void {
        var buf: [media_socket.max_datagram]u8 = undefined;
        while (!self.stop_flag.load(.acquire)) {
            const sock = &(self.socket orelse return);
            const got = sock.recvFrom(&buf) orelse continue; // timeout/idle
            if (got.data.len == 0) continue;
            if (MediaSocket.isStun(got.data[0])) {
                lockSpin(&self.mutex);
                const resp = self.transport.handleStunBinding(self.allocator, got.data, got.from) catch null;
                self.mutex.unlock();
                if (resp) |r| {
                    defer self.allocator.free(r);
                    sock.sendTo(got.from, r);
                }
            } else {
                // Media: require RTP/RTCP framing (version 2 in the top two bits,
                // min header) so the port is not an open UDP reflector for
                // arbitrary payloads. Learn the SSRC from RTP (not RTCP) packets.
                if (got.data.len < rtp_profile.header_len or (got.data[0] & 0xC0) != 0x80) continue;
                var ssrc: u32 = 0;
                if (!isRtcp(got.data[1])) {
                    if (rtp_profile.decodeHeader(got.data)) |dh| ssrc = dh.header.ssrc else |_| {}
                }
                // Selectively forward to the other call participants.
                var targets: [media_transport.max_forward]TransportAddress = undefined;
                lockSpin(&self.mutex);
                const n = self.transport.forwardFromSource(got.from, got.data.len, ssrc, &targets);
                self.mutex.unlock();
                for (targets[0..n]) |dst| sock.sendTo(dst, got.data);
            }
        }
    }

    /// Allocate (or rotate) the ICE credentials for a call participant and return
    /// them for the signaling layer to advertise. Null on allocation failure.
    pub fn allocate(self: *MediaPlane, channel: []const u8, participant: []const u8) ?Creds {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const ep = self.transport.allocate(channel, participant, self.csprng.random()) catch return null;
        return .{ .ufrag = ep.ufrag, .pwd = ep.pwd };
    }

    /// The per-call SRTP group key (SDES) for `channel`, generated on first use.
    pub fn groupKey(self: *MediaPlane, channel: []const u8) [media_transport.group_key_len]u8 {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.transport.ensureGroupKey(channel, self.csprng.random());
    }

    /// Drop a participant's endpoint (MEDIA LEAVE / disconnect).
    pub fn remove(self: *MediaPlane, channel: []const u8, participant: []const u8) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        self.transport.remove(channel, participant);
    }

    /// Snapshot per-participant transport stats for `channel` into `out`.
    pub fn statsForChannel(self: *MediaPlane, channel: []const u8, out: []MediaTransport.ParticipantStat) usize {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.transport.statsForChannel(channel, out);
    }

    /// Whether a participant's ICE check has bound a peer address (test/introspection).
    pub fn isConnected(self: *MediaPlane, channel: []const u8, participant: []const u8) bool {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const ep = self.transport.get(channel, participant) orelse return false;
        return ep.connected();
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const stun = @import("../proto/stun.zig");

test "MediaPlane: threaded pump answers a STUN check and binds the peer" {
    var plane = MediaPlane.init(testing.allocator);
    defer plane.deinit();
    try plane.start(loopback_be, 0);

    const creds = plane.allocate("#c", "alice") orelse return error.TestUnexpectedResult;

    var client = try MediaSocket.bind(loopback_be, 0);
    defer client.deinit();
    client.setRecvTimeoutMs(2000);

    var user_buf: [media_transport.ufrag_len + 6]u8 = undefined;
    const user = std.fmt.bufPrint(&user_buf, "{s}:peer", .{creds.ufragSlice()}) catch unreachable;
    const tx: stun.TransactionId = .{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
    const req = try stun.buildBindingRequest(testing.allocator, tx, .{
        .username = user,
        .integrity_key = creds.pwdSlice(),
        .fingerprint = true,
    });
    defer testing.allocator.free(req);

    const server_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, plane.port);
    client.sendTo(server_addr, req);

    // The pump thread answers; receiving the response proves it was processed.
    var cbuf: [media_socket.max_datagram]u8 = undefined;
    const got = client.recvFrom(&cbuf) orelse return error.TestUnexpectedResult;
    var decoded = try stun.decode(testing.allocator, got.data);
    defer decoded.deinit(testing.allocator);
    try testing.expectEqual(stun.MessageType.binding_success_response, decoded.typ);
    try testing.expect(plane.isConnected("#c", "alice"));
}

test "MediaPlane: start/shutdown is clean and re-startable port is reported" {
    var plane = MediaPlane.init(testing.allocator);
    defer plane.deinit();
    try plane.start(loopback_be, 0);
    try testing.expect(plane.port != 0);
    plane.shutdown();
    // After shutdown the socket is closed; re-start binds a fresh ephemeral port.
    try plane.start(loopback_be, 0);
    try testing.expect(plane.port != 0);
}

//! Daemon-owned native media transport: the live UDP leg for Mizuchi's own
//! codec (OPVOX/OPVIS). Mirrors `media_plane.MediaPlane` (the WebRTC/UDP leg) but
//! carries `opcodec_frame` datagrams instead of RTP, and forwards them through
//! `NativeMediaLink` (stream_id → publisher → recipients).
//!
//! The pump thread blocks on the socket (short recv timeout to observe the stop
//! flag), and for each datagram that parses as an opcodec frame: learns the
//! publisher's return address from the datagram origin, computes the SFU forward
//! set, and resends the SAME opaque bytes to each recipient. The daemon's main
//! thread registers/removes participants (on MEDIA OFFER / LEAVE) through the
//! same mutex. The server NEVER encodes/decodes/transcodes — frames are forwarded
//! verbatim.
const std = @import("std");
const native_media_link = @import("native_media_link.zig");
const media_socket = @import("../substrate/media_socket.zig");
const opcodec_frame = @import("../substrate/opcodec_frame.zig");

pub const MediaSocket = media_socket.MediaSocket;
pub const TransportAddress = native_media_link.TransportAddress;
pub const MediaKind = native_media_link.MediaKind;
pub const Selection = native_media_link.Selection;
pub const loopback_be = media_socket.loopback_be;
pub const any_be = media_socket.any_be;

/// Max participants per native call (forward fan-out bound).
pub const max_call_participants = 64;

pub const Link = native_media_link.NativeMediaLink(max_call_participants);

/// Blocking acquire on the tryLock-only `std.atomic.Mutex`. Contention is
/// near-zero (rare register/remove vs. the single pump thread), so yielding.
fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.Thread.yield() catch {};
}

pub const NativeMediaTransport = struct {
    link: Link,
    socket: ?MediaSocket = null,
    mutex: std.atomic.Mutex = .unlocked,
    thread: ?std.Thread = null,
    stop_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// Bound local UDP port (0 until started); advertised to native clients.
    port: u16 = 0,

    pub fn init() NativeMediaTransport {
        return .{ .link = Link.init() };
    }

    pub fn deinit(self: *NativeMediaTransport) void {
        self.shutdown();
        self.* = undefined;
    }

    /// Bind on `bind_be`:`port` (port 0 = ephemeral) and spawn the pump thread.
    /// No-op if already started.
    pub fn start(self: *NativeMediaTransport, bind_be: u32, port: u16) !void {
        if (self.socket != null) return;
        var sock = try MediaSocket.bind(bind_be, port);
        errdefer sock.deinit();
        self.port = try sock.localPort();
        sock.setRecvTimeoutMs(250); // wake to observe the stop flag
        self.socket = sock;

        self.stop_flag.store(false, .release);
        self.thread = std.Thread.spawn(.{}, pumpLoop, .{self}) catch |e| {
            self.socket.?.deinit();
            self.socket = null;
            return e;
        };
    }

    /// Signal the pump to stop, join it, and close the socket.
    pub fn shutdown(self: *NativeMediaTransport) void {
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

    fn pumpLoop(self: *NativeMediaTransport) void {
        var buf: [media_socket.max_datagram]u8 = undefined;
        var targets: [max_call_participants]TransportAddress = undefined;
        while (!self.stop_flag.load(.acquire)) {
            const sock = &(self.socket orelse return);
            const got = sock.recvFrom(&buf) orelse continue; // timeout/idle
            // Require opcodec framing so the port is not an open UDP reflector.
            if (got.data.len < opcodec_frame.MIN_FRAME_WIRE_BYTES) continue;

            lockSpin(&self.mutex);
            const n = self.link.inboundFrom(got.data, got.from, &targets);
            self.mutex.unlock();

            for (targets[0..n]) |dst| sock.sendTo(dst, got.data);
        }
    }

    // -- Main-thread registry operations (all under the mutex) --------------

    /// Register/update a native participant for the call (MEDIA OFFER). `addr`
    /// may be a placeholder; the pump learns the real return path from the
    /// participant's first datagram.
    pub fn register(
        self: *NativeMediaTransport,
        id: []const u8,
        kind: MediaKind,
        stream_id: u32,
        addr: TransportAddress,
    ) native_media_link.RegisterError!void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.link.register(id, kind, stream_id, addr);
    }

    /// Remove a participant (MEDIA LEAVE / disconnect).
    pub fn unregister(self: *NativeMediaTransport, id: []const u8) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        self.link.unregister(id);
    }

    /// Set a receiver's simulcast spatial/temporal ceiling.
    pub fn setSelection(self: *NativeMediaTransport, id: []const u8, sel: Selection) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        self.link.setSelection(id, sel);
    }

    pub fn count(self: *NativeMediaTransport) usize {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.link.count();
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "NativeMediaTransport: pump learns sender + forwards an opcodec frame to the receiver" {
    var nmt = NativeMediaTransport.init();
    defer nmt.deinit();
    try nmt.start(loopback_be, 0);

    // Receiver socket (bob): the transport forwards to its bound address.
    var bob = try MediaSocket.bind(loopback_be, 0);
    defer bob.deinit();
    bob.setRecvTimeoutMs(2000);
    const bob_port = try bob.localPort();
    const bob_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, bob_port);

    // Sender socket (alice): registered with a placeholder addr; learned on send.
    var alice = try MediaSocket.bind(loopback_be, 0);
    defer alice.deinit();

    try nmt.register("alice", .voice, 100, try TransportAddress.fromBytes(&[_]u8{ 0, 0, 0, 0 }, 0));
    try nmt.register("bob", .voice, 200, bob_addr);

    // Alice publishes one opcodec frame (stream_id 100) to the transport.
    var fbuf: [64]u8 = undefined;
    const flen = try opcodec_frame.encode(.{
        .band_id = opcodec_frame.MEDIA_BAND_FLOOR,
        .stream_id = 100,
        .sequence = 1,
        .timestamp = 0,
        .keyframe = true,
        .codec = .opvox_audio,
        .payload = &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF },
    }, &fbuf);
    const server_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, nmt.port);
    alice.sendTo(server_addr, fbuf[0..flen]);

    // Bob receives the forwarded, verbatim frame.
    var rbuf: [media_socket.max_datagram]u8 = undefined;
    const got = bob.recvFrom(&rbuf) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, fbuf[0..flen], got.data);
}

test "NativeMediaTransport: start/shutdown is clean and re-startable" {
    var nmt = NativeMediaTransport.init();
    defer nmt.deinit();
    try nmt.start(loopback_be, 0);
    try testing.expect(nmt.port != 0);
    nmt.shutdown();
    try nmt.start(loopback_be, 0);
    try testing.expect(nmt.port != 0);
}

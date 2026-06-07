//! Daemon-owned native media transport: the live UDP leg for Mizuchi's own
//! codec (OPVOX/OPVIS). Mirrors `media_plane.MediaPlane` (the WebRTC/UDP leg) but
//! carries `opcodec_frame` datagrams instead of RTP, and forwards them through a
//! per-channel `NativeMediaLink` (stream_id → publisher → recipients).
//!
//! Per-channel isolation: each media call (channel) has its own `NativeMediaLink`
//! so media never crosses between channels. A global `stream_id → channel` index
//! lets the pump route an inbound datagram (which carries only a stream_id) to
//! the right channel's link.
//!
//! The pump thread blocks on the socket (short recv timeout to observe the stop
//! flag), and for each datagram that parses as an opcodec frame: routes by
//! stream_id to the owning channel, learns the publisher's return address from
//! the datagram origin, computes the SFU forward set, and resends the SAME opaque
//! bytes to each recipient. The server NEVER encodes/decodes/transcodes — frames
//! are forwarded verbatim.
const std = @import("std");
const native_media_link = @import("native_media_link.zig");
const media_bridge = @import("media_bridge.zig");
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
    allocator: std.mem.Allocator,
    /// channel name (owned key) -> that call's forward link.
    channels: std.StringHashMapUnmanaged(Link) = .empty,
    /// stream_id -> the channel key that owns the publisher (borrows a key from
    /// `channels`, so it is only valid while that channel entry exists).
    stream_index: std.AutoHashMapUnmanaged(u32, []const u8) = .empty,
    socket: ?MediaSocket = null,
    mutex: std.atomic.Mutex = .unlocked,
    thread: ?std.Thread = null,
    stop_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// Bound local UDP port (0 until started); advertised to native clients.
    port: u16 = 0,
    /// Optional cross-leg sink: after forwarding a native frame to native peers,
    /// the pump hands it here to also reach the channel's WebRTC members
    /// (rewrapped to RTP). Null = native-only call (no bridging).
    cross: ?media_bridge.CrossLegSink = null,

    pub fn init(allocator: std.mem.Allocator) NativeMediaTransport {
        return .{ .allocator = allocator };
    }

    /// Install the cross-leg sink (call before `start`, or while stopped).
    pub fn setCrossLegSink(self: *NativeMediaTransport, sink: media_bridge.CrossLegSink) void {
        self.cross = sink;
    }

    pub fn deinit(self: *NativeMediaTransport) void {
        self.shutdown();
        var it = self.channels.keyIterator();
        while (it.next()) |k| self.allocator.free(k.*);
        self.channels.deinit(self.allocator);
        self.stream_index.deinit(self.allocator);
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
            const view = opcodec_frame.decode(got.data) catch continue;

            lockSpin(&self.mutex);
            var n: usize = 0;
            var chanbuf: [256]u8 = undefined;
            var chanlen: usize = 0;
            if (self.stream_index.get(view.stream_id)) |chan| {
                if (self.channels.getPtr(chan)) |link| {
                    n = link.inboundFrom(got.data, got.from, &targets);
                    // Copy the channel name out under the lock so the cross-leg
                    // sink can use it after we unlock (the key may be freed if the
                    // channel is torn down concurrently).
                    if (chan.len <= chanbuf.len) {
                        @memcpy(chanbuf[0..chan.len], chan);
                        chanlen = chan.len;
                    }
                }
            }
            self.mutex.unlock();

            for (targets[0..n]) |dst| sock.sendTo(dst, got.data);

            // Bridge the same frame to any WebRTC members of this channel.
            if (chanlen != 0) {
                if (self.cross) |sink| sink.onNativeFrame(chanbuf[0..chanlen], got.data);
            }
        }
    }

    // -- Main-thread registry operations (all under the mutex) --------------

    fn linkForChannel(self: *NativeMediaTransport, channel: []const u8) !*Link {
        const gop = try self.channels.getOrPut(self.allocator, channel);
        if (!gop.found_existing) {
            const key = self.allocator.dupe(u8, channel) catch |e| {
                _ = self.channels.remove(channel);
                return e;
            };
            gop.key_ptr.* = key;
            gop.value_ptr.* = Link.init();
        }
        return gop.value_ptr;
    }

    /// Register/update a native participant in `channel` (MEDIA OFFER). `addr`
    /// may be a placeholder; the pump learns the real return path from the
    /// participant's first datagram. `stream_id` is what the publisher stamps
    /// into its opcodec frames (advertised back to the client).
    pub fn register(
        self: *NativeMediaTransport,
        channel: []const u8,
        id: []const u8,
        kind: MediaKind,
        stream_id: u32,
        addr: TransportAddress,
    ) !void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const link = try self.linkForChannel(channel);
        try link.register(id, kind, stream_id, addr);
        // Index stream_id -> channel key (borrow the map's stable key pointer).
        const key = self.channels.getKey(channel).?;
        try self.stream_index.put(self.allocator, stream_id, key);
    }

    /// Remove a participant from `channel` (MEDIA LEAVE / disconnect). Drops the
    /// channel (and its stream-index entries) once the last participant leaves.
    pub fn unregister(self: *NativeMediaTransport, channel: []const u8, id: []const u8) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const link = self.channels.getPtr(channel) orelse return;
        link.unregister(id);
        if (link.count() != 0) return;

        // Last participant gone: tear the channel down. Clear stream-index
        // entries that borrow this channel's key BEFORE freeing the key.
        const key = self.channels.getKey(channel).?;
        var it = self.stream_index.iterator();
        var doomed: [max_call_participants]u32 = undefined;
        var dn: usize = 0;
        while (it.next()) |e| {
            if (e.value_ptr.*.ptr == key.ptr and dn < doomed.len) {
                doomed[dn] = e.key_ptr.*;
                dn += 1;
            }
        }
        for (doomed[0..dn]) |sid| _ = self.stream_index.remove(sid);
        _ = self.channels.remove(channel);
        self.allocator.free(key);
    }

    /// Set a receiver's simulcast spatial/temporal ceiling within `channel`.
    pub fn setSelection(self: *NativeMediaTransport, channel: []const u8, id: []const u8, sel: Selection) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const link = self.channels.getPtr(channel) orelse return;
        link.setSelection(id, sel);
    }

    /// Send `bytes` to `dest` on the native socket. Used by the WebRTC relay's
    /// cross-leg sink to deliver opcodec-rewrapped frames to native peers.
    pub fn sendTo(self: *NativeMediaTransport, dest: TransportAddress, bytes: []const u8) void {
        if (self.socket) |*s| s.sendTo(dest, bytes);
    }

    /// The learned transport address of a native participant in `channel`, or
    /// null if unknown / not yet learned (the peer hasn't published a datagram).
    pub fn remoteFor(self: *NativeMediaTransport, channel: []const u8, id: []const u8) ?TransportAddress {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const link = self.channels.getPtr(channel) orelse return null;
        return link.addrFor(id);
    }

    /// Participant count in `channel` (0 if the channel has no native call).
    pub fn countChannel(self: *NativeMediaTransport, channel: []const u8) usize {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const link = self.channels.getPtr(channel) orelse return 0;
        return link.count();
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn opframe(stream_id: u32, buf: []u8) []const u8 {
    const n = opcodec_frame.encode(.{
        .band_id = opcodec_frame.MEDIA_BAND_FLOOR,
        .stream_id = stream_id,
        .sequence = 1,
        .timestamp = 0,
        .keyframe = true,
        .codec = .opvox_audio,
        .payload = &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF },
    }, buf) catch unreachable;
    return buf[0..n];
}

test "NativeMediaTransport: pump learns sender + forwards an opcodec frame to the receiver" {
    var nmt = NativeMediaTransport.init(testing.allocator);
    defer nmt.deinit();
    try nmt.start(loopback_be, 0);

    var bob = try MediaSocket.bind(loopback_be, 0);
    defer bob.deinit();
    bob.setRecvTimeoutMs(2000);
    const bob_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, try bob.localPort());

    var alice = try MediaSocket.bind(loopback_be, 0);
    defer alice.deinit();

    try nmt.register("#call", "alice", .voice, 100, .{});
    try nmt.register("#call", "bob", .voice, 200, bob_addr);

    var fbuf: [64]u8 = undefined;
    const frame = opframe(100, &fbuf);
    const server_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, nmt.port);
    alice.sendTo(server_addr, frame);

    var rbuf: [media_socket.max_datagram]u8 = undefined;
    const got = bob.recvFrom(&rbuf) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, frame, got.data);
}

test "NativeMediaTransport: media never crosses channels" {
    var nmt = NativeMediaTransport.init(testing.allocator);
    defer nmt.deinit();
    try nmt.start(loopback_be, 0);

    // A listener registered in a DIFFERENT channel must never receive the frame.
    var other = try MediaSocket.bind(loopback_be, 0);
    defer other.deinit();
    other.setRecvTimeoutMs(400);
    const other_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, try other.localPort());

    var alice = try MediaSocket.bind(loopback_be, 0);
    defer alice.deinit();

    try nmt.register("#a", "alice", .voice, 100, .{});
    try nmt.register("#b", "eve", .voice, 999, other_addr); // different channel

    var fbuf: [64]u8 = undefined;
    const frame = opframe(100, &fbuf);
    const server_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, nmt.port);
    alice.sendTo(server_addr, frame);

    var rbuf: [media_socket.max_datagram]u8 = undefined;
    try testing.expect(other.recvFrom(&rbuf) == null); // eve hears nothing
}

test "NativeMediaTransport: setSelection drops higher layers over the wire" {
    var nmt = NativeMediaTransport.init(testing.allocator);
    defer nmt.deinit();
    try nmt.start(loopback_be, 0);

    var lowbw = try MediaSocket.bind(loopback_be, 0);
    defer lowbw.deinit();
    lowbw.setRecvTimeoutMs(400);
    const lowbw_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, try lowbw.localPort());

    var src = try MediaSocket.bind(loopback_be, 0);
    defer src.deinit();

    try nmt.register("#v", "src", .video, 10, .{});
    try nmt.register("#v", "lowbw", .video, 11, lowbw_addr);
    nmt.setSelection("#v", "lowbw", .{ .max_spatial = 0, .max_temporal = 0 });

    const server_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, nmt.port);
    var fbuf: [64]u8 = undefined;
    var rbuf: [media_socket.max_datagram]u8 = undefined;

    // A spatial layer-1 (band floor+1) non-keyframe must be dropped for lowbw.
    const hi = opcodec_frame.encode(.{
        .band_id = opcodec_frame.MEDIA_BAND_FLOOR + 1,
        .stream_id = 10,
        .sequence = 1,
        .timestamp = 0,
        .keyframe = false,
        .codec = .opvis_video,
        .payload = &[_]u8{ 1, 2, 3 },
    }, &fbuf) catch unreachable;
    src.sendTo(server_addr, fbuf[0..hi]);
    try testing.expect(lowbw.recvFrom(&rbuf) == null);

    // The base layer (band floor) is delivered.
    const base = opframe(10, &fbuf);
    src.sendTo(server_addr, base);
    const got = lowbw.recvFrom(&rbuf) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, base, got.data);
}

test "NativeMediaTransport: unregister drops the channel and frees its index" {
    var nmt = NativeMediaTransport.init(testing.allocator);
    defer nmt.deinit();

    try nmt.register("#call", "alice", .voice, 100, .{});
    try nmt.register("#call", "bob", .voice, 200, .{});
    try testing.expectEqual(@as(usize, 2), nmt.countChannel("#call"));

    nmt.unregister("#call", "alice");
    try testing.expectEqual(@as(usize, 1), nmt.countChannel("#call"));
    nmt.unregister("#call", "bob");
    try testing.expectEqual(@as(usize, 0), nmt.countChannel("#call"));
    // channel torn down; re-registering works cleanly (no stale key/index)
    try nmt.register("#call", "carol", .voice, 300, .{});
    try testing.expectEqual(@as(usize, 1), nmt.countChannel("#call"));
}

const rtp_profile = @import("../proto/rtp_profile.zig");
const TestBridge = media_bridge.ChannelBridge(8);

const TestXCtx = struct {
    bridge: *TestBridge,
    sock: *MediaSocket, // stands in for the media_plane (WebRTC) socket

    fn onNative(ctx: *anyopaque, channel: []const u8, datagram: []const u8) void {
        _ = channel;
        const self: *TestXCtx = @ptrCast(@alignCast(ctx));
        self.bridge.fanoutNativeToWebrtc(datagram, ctx, sendVia);
    }
    fn sendVia(ctx: *anyopaque, target: *const media_bridge.Member, bytes: []const u8) void {
        const self: *TestXCtx = @ptrCast(@alignCast(ctx));
        self.sock.sendTo(target.addr, bytes);
    }
};

test "NativeMediaTransport: pump bridges a native frame to a WebRTC member as RTP" {
    var nmt = NativeMediaTransport.init(testing.allocator);
    defer nmt.deinit();

    // WebRTC receiver (mob) + the socket the sink sends RTP from (WebRTC plane).
    var mob = try MediaSocket.bind(loopback_be, 0);
    defer mob.deinit();
    mob.setRecvTimeoutMs(2000);
    const mob_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, try mob.localPort());
    var wsock = try MediaSocket.bind(loopback_be, 0);
    defer wsock.deinit();

    var bridge = TestBridge.init();
    try bridge.register("mob", .{ .leg = .webrtc, .addr = mob_addr, .ssrc = 0x1234 });

    var xctx = TestXCtx{ .bridge = &bridge, .sock = &wsock };
    nmt.setCrossLegSink(.{ .ctx = &xctx, .on_native_frame = TestXCtx.onNative });
    try nmt.start(loopback_be, 0);

    try nmt.register("#call", "alice", .voice, 100, .{}); // native publisher

    var alice = try MediaSocket.bind(loopback_be, 0);
    defer alice.deinit();
    var fbuf: [64]u8 = undefined;
    const frame = opframe(100, &fbuf);
    const server_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, nmt.port);
    alice.sendTo(server_addr, frame);

    // mob receives the same opaque payload, now wrapped as RTP for its ssrc.
    var rbuf: [media_socket.max_datagram]u8 = undefined;
    const got = mob.recvFrom(&rbuf) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(usize, rtp_profile.header_len + 4), got.data.len);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF }, got.data[rtp_profile.header_len..]);
}

test "NativeMediaTransport: start/shutdown is clean and re-startable" {
    var nmt = NativeMediaTransport.init(testing.allocator);
    defer nmt.deinit();
    try nmt.start(loopback_be, 0);
    try testing.expect(nmt.port != 0);
    nmt.shutdown();
    try nmt.start(loopback_be, 0);
    try testing.expect(nmt.port != 0);
}

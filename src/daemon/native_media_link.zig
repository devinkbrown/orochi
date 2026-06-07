//! Native media link — the live-transport glue for the native Suimyaku SFU leg.
//!
//! `NativeMediaPlane` (substrate) makes the pure forwarding *decision* in terms
//! of `ParticipantId`s; live datagrams instead carry an opcodec_frame `stream_id`
//! and arrive from / depart to a `TransportAddress`. This module is the binding
//! between the two: it owns the per-call registry mapping
//!
//!     stream_id  ->  source ParticipantId   (who is publishing this frame)
//!     ParticipantId  ->  TransportAddress    (where to send a recipient's copy)
//!
//! so a raw inbound native datagram can be turned into "forward these exact bytes
//! to this set of addresses". It NEVER touches the payload — the SFU forwards the
//! opaque, already-encoded opcodec frame verbatim (no encode/decode/transcode).
//!
//! Layer selection: the container's `band_id` encodes the spatial layer by the
//! convention `band_id = MEDIA_BAND_FLOOR + spatial` (the publisher chooses the
//! band per simulcast layer). Temporal SVC selection over native frames is not
//! yet carried in the container header, so the link forwards on spatial ceiling +
//! keyframe only (temporal 0); finer temporal dropping is deferred to when the
//! container gains a layer-marking byte. Keyframes at/below a receiver's spatial
//! ceiling are always delivered.
//!
//! Transport-neutral: it commits to no socket. The daemon's media pump calls
//! `inbound` and sends the opaque datagram to each returned address.
const std = @import("std");
const native_plane = @import("../substrate/native_media_plane.zig");
const opcodec_frame = @import("../substrate/opcodec_frame.zig");
const media_transport = @import("../substrate/media_transport.zig");

pub const ParticipantId = native_plane.ParticipantId;
pub const MediaKind = native_plane.MediaKind;
pub const Selection = native_plane.Selection;
pub const TransportAddress = media_transport.TransportAddress;

/// Result of registering: whether this was a fresh slot or an update.
pub const RegisterError = error{ Full, BadId };

pub fn NativeMediaLink(comptime max_participants: usize) type {
    return struct {
        const Self = @This();

        const Entry = struct {
            id: ParticipantId,
            kind: MediaKind,
            stream_id: u32,
            addr: TransportAddress,
            live: bool = false,
        };

        plane: native_plane.NativeMediaPlane(max_participants),
        entries: [max_participants]Entry = undefined,
        len: usize = 0,

        pub fn init() Self {
            return .{ .plane = native_plane.NativeMediaPlane(max_participants).init() };
        }

        fn findById(self: *Self, id: ParticipantId) ?*Entry {
            for (self.entries[0..self.len]) |*e| {
                if (e.live and e.id.eql(&id)) return e;
            }
            return null;
        }

        /// Register (or update) a participant: join the forwarding session and
        /// record its publishing `stream_id` and current `TransportAddress`.
        /// Re-registering the same id updates its address/stream/kind in place.
        pub fn register(
            self: *Self,
            id_bytes: []const u8,
            kind: MediaKind,
            stream_id: u32,
            addr: TransportAddress,
        ) RegisterError!void {
            const id = ParticipantId.init(id_bytes) catch return error.BadId;

            if (self.findById(id)) |e| {
                if (e.kind != kind) {
                    self.plane.leave(id, e.kind) catch {};
                    self.plane.join(id, kind) catch return error.Full;
                }
                e.kind = kind;
                e.stream_id = stream_id;
                e.addr = addr;
                return;
            }

            if (self.len >= max_participants) return error.Full;
            self.plane.join(id, kind) catch return error.Full;
            self.entries[self.len] = .{
                .id = id,
                .kind = kind,
                .stream_id = stream_id,
                .addr = addr,
                .live = true,
            };
            self.len += 1;
        }

        /// Update a registered participant's address (e.g. ICE re-binding to a new
        /// remote). No-op if unknown.
        pub fn updateAddress(self: *Self, id_bytes: []const u8, addr: TransportAddress) void {
            const id = ParticipantId.init(id_bytes) catch return;
            if (self.findById(id)) |e| e.addr = addr;
        }

        /// Set a receiver's simulcast spatial/temporal ceiling.
        pub fn setSelection(self: *Self, id_bytes: []const u8, sel: Selection) void {
            const id = ParticipantId.init(id_bytes) catch return;
            self.plane.setSelection(id, sel);
        }

        /// Remove a participant (MEDIA LEAVE / disconnect).
        pub fn unregister(self: *Self, id_bytes: []const u8) void {
            const id = ParticipantId.init(id_bytes) catch return;
            for (self.entries[0..self.len], 0..) |*e, i| {
                if (e.live and e.id.eql(&id)) {
                    self.plane.leave(e.id, e.kind) catch {};
                    self.entries[i] = self.entries[self.len - 1];
                    self.len -= 1;
                    return;
                }
            }
        }

        pub fn count(self: *const Self) usize {
            return self.len;
        }

        fn addrForId(self: *Self, id: ParticipantId) ?TransportAddress {
            if (self.findById(id)) |e| return e.addr;
            return null;
        }

        /// The learned transport address of a participant by string id, or null
        /// if unknown / not yet learned. Used to deliver cross-leg (WebRTC→native)
        /// frames to a native peer.
        pub fn addrFor(self: *Self, id_bytes: []const u8) ?TransportAddress {
            const id = ParticipantId.init(id_bytes) catch return null;
            return self.addrForId(id);
        }

        /// Decode one inbound native datagram and compute the forward set as
        /// transport addresses. The SAME `datagram` bytes are then sent verbatim
        /// to each address in `out[0..n]`. Returns 0 (and forwards nothing) when
        /// the datagram is not a decodable media frame or its source is unknown.
        pub fn inbound(
            self: *Self,
            datagram: []const u8,
            out: []TransportAddress,
        ) usize {
            const view = opcodec_frame.decode(datagram) catch return 0;
            return self.forwardView(view, out);
        }

        /// Like `inbound`, but first learns the source participant's transport
        /// address from `from` (the datagram's origin) — how the live SFU
        /// discovers each publisher's return path on a connectionless socket.
        pub fn inboundFrom(
            self: *Self,
            datagram: []const u8,
            from: TransportAddress,
            out: []TransportAddress,
        ) usize {
            const view = opcodec_frame.decode(datagram) catch return 0;
            for (self.entries[0..self.len]) |*e| {
                if (e.live and e.stream_id == view.stream_id) {
                    e.addr = from;
                    break;
                }
            }
            return self.forwardView(view, out);
        }

        fn forwardView(self: *Self, view: opcodec_frame.FrameView, out: []TransportAddress) usize {
            // Identify the publishing participant by the frame's stream_id.
            var src_id: ?ParticipantId = null;
            var src_kind: MediaKind = .voice;
            for (self.entries[0..self.len]) |e| {
                if (e.live and e.stream_id == view.stream_id) {
                    src_id = e.id;
                    src_kind = e.kind;
                    break;
                }
            }
            const source = src_id orelse return 0;

            // band_id = MEDIA_BAND_FLOOR + spatial (publisher convention).
            const spatial: u8 = @intCast(view.band_id - opcodec_frame.MEDIA_BAND_FLOOR);

            var ids: [max_participants]ParticipantId = undefined;
            const m = self.plane.forward(source, src_kind, spatial, 0, view.keyframe, &ids);

            var n: usize = 0;
            for (ids[0..m]) |rid| {
                if (n >= out.len) break;
                if (self.addrForId(rid)) |a| {
                    out[n] = a;
                    n += 1;
                }
            }
            return n;
        }
    };
}

// ---------------------------------------------------------------------------
// Tests (run under the unified build; transitively imports opcodec via the
// native plane, so not standalone `zig test`-able — expected).
// ---------------------------------------------------------------------------

const testing = std.testing;

fn mkAddr(last: u8, port: u16) TransportAddress {
    return TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, last }, port) catch unreachable;
}

fn frame(stream_id: u32, band: u8, seq: u32, keyframe: bool, buf: []u8) []const u8 {
    const n = opcodec_frame.encode(.{
        .band_id = band,
        .stream_id = stream_id,
        .sequence = seq,
        .timestamp = 0,
        .keyframe = keyframe,
        .codec = .opvox_audio,
        .payload = &[_]u8{ 0xAA, 0xBB, 0xCC },
    }, buf) catch unreachable;
    return buf[0..n];
}

test "inbound forwards a base-layer frame to the other registered addresses" {
    var link = NativeMediaLink(8).init();
    const floor = opcodec_frame.MEDIA_BAND_FLOOR;
    try link.register("alice", .voice, 100, mkAddr(1, 5000));
    try link.register("bob", .voice, 200, mkAddr(2, 5000));
    try link.register("carol", .voice, 300, mkAddr(3, 5000));

    var fbuf: [64]u8 = undefined;
    const dgram = frame(100, floor, 1, false, &fbuf);

    var out: [8]TransportAddress = undefined;
    const n = link.inbound(dgram, &out);
    try testing.expectEqual(@as(usize, 2), n); // bob + carol, not the source alice
    // and never alice's own address
    for (out[0..n]) |a| try testing.expect(!a.eql(mkAddr(1, 5000)));
}

test "inbound drops an unknown stream_id" {
    var link = NativeMediaLink(8).init();
    try link.register("alice", .voice, 100, mkAddr(1, 5000));
    try link.register("bob", .voice, 200, mkAddr(2, 5000));

    var fbuf: [64]u8 = undefined;
    const dgram = frame(999, opcodec_frame.MEDIA_BAND_FLOOR, 1, false, &fbuf);
    var out: [8]TransportAddress = undefined;
    try testing.expectEqual(@as(usize, 0), link.inbound(dgram, &out));
}

test "spatial ceiling drops higher band but keyframes always pass" {
    var link = NativeMediaLink(8).init();
    const floor = opcodec_frame.MEDIA_BAND_FLOOR;
    try link.register("src", .video, 10, mkAddr(1, 6000));
    try link.register("lowbw", .video, 11, mkAddr(2, 6000));
    link.setSelection("lowbw", .{ .max_spatial = 0, .max_temporal = 0 });

    var fbuf: [64]u8 = undefined;
    var out: [8]TransportAddress = undefined;

    // spatial layer 1 (band floor+1), non-keyframe -> dropped for lowbw
    try testing.expectEqual(@as(usize, 0), link.inbound(frame(10, floor + 1, 1, false, &fbuf), &out));
    // spatial layer 0 -> delivered
    try testing.expectEqual(@as(usize, 1), link.inbound(frame(10, floor, 2, false, &fbuf), &out));
    // keyframe at base layer -> delivered
    try testing.expectEqual(@as(usize, 1), link.inbound(frame(10, floor, 3, true, &fbuf), &out));
}

test "unregister removes a participant from the forward set" {
    var link = NativeMediaLink(8).init();
    const floor = opcodec_frame.MEDIA_BAND_FLOOR;
    try link.register("a", .voice, 1, mkAddr(1, 7000));
    try link.register("b", .voice, 2, mkAddr(2, 7000));

    var fbuf: [64]u8 = undefined;
    var out: [8]TransportAddress = undefined;
    try testing.expectEqual(@as(usize, 1), link.inbound(frame(1, floor, 1, false, &fbuf), &out));
    link.unregister("b");
    try testing.expectEqual(@as(usize, 0), link.inbound(frame(1, floor, 2, false, &fbuf), &out));
    try testing.expectEqual(@as(usize, 1), link.count());
}

test "inboundFrom learns the publisher's address and still forwards to others" {
    var link = NativeMediaLink(8).init();
    const floor = opcodec_frame.MEDIA_BAND_FLOOR;
    // alice registered with a placeholder address (unknown until she sends).
    try link.register("alice", .voice, 100, mkAddr(0, 0));
    try link.register("bob", .voice, 200, mkAddr(2, 9000));

    var fbuf: [64]u8 = undefined;
    var out: [8]TransportAddress = undefined;
    const learned = mkAddr(7, 1234);
    const n = link.inboundFrom(frame(100, floor, 1, false, &fbuf), learned, &out);

    // forwarded to bob only (source excluded)
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expect(out[0].eql(mkAddr(2, 9000)));

    // alice's address was learned from the datagram origin: a frame from bob
    // now forwards back to alice's learned address.
    const n2 = link.inboundFrom(frame(200, floor, 1, false, &fbuf), mkAddr(2, 9000), &out);
    try testing.expectEqual(@as(usize, 1), n2);
    try testing.expect(out[0].eql(learned));
}

test "updateAddress redirects a receiver's copies" {
    var link = NativeMediaLink(8).init();
    const floor = opcodec_frame.MEDIA_BAND_FLOOR;
    try link.register("a", .voice, 1, mkAddr(1, 8000));
    try link.register("b", .voice, 2, mkAddr(2, 8000));
    link.updateAddress("b", mkAddr(9, 8001));

    var fbuf: [64]u8 = undefined;
    var out: [8]TransportAddress = undefined;
    const n = link.inbound(frame(1, floor, 1, false, &fbuf), &out);
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expect(out[0].eql(mkAddr(9, 8001)));
}

// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Media bridge spine — per-channel cross-leg roster + datagram rewrap.
//!
//! A media call can mix participants on two transports: the native leg
//! (kagura_frame over UDP, our OPVOX/OPVIS codec) and the WebRTC leg (RTP/SRTP).
//! Within a leg the respective plane already forwards. This module is the spine
//! that lets a frame ingressing on ONE leg reach participants on the OTHER leg —
//! by header-rewrap only, never transcoding. The codec payload is opaque and
//! shared verbatim; only the transport header (kagura container ↔ RTP) changes.
//!
//! `ChannelBridge` holds the call's roster (who is on which leg + their transport
//! identity) and answers `crossTargets(leg)` — the opposite-leg recipients for a
//! frame that arrived on `leg`. The free `*Datagram` helpers do the actual
//! rewrap, reusing `kakehashi`. The two live pumps (native + WebRTC) will call
//! these to deliver across legs.
//!
//! Pure SFU: this never encodes/decodes/transcodes media. A mixed call still
//! requires a shared codec (`kakehashi.selectCommon`); rewrap just moves the
//! agreed opaque payload between the two wire framings.
const std = @import("std");
const kakehashi = @import("../substrate/kakehashi.zig");
const kagura_frame = @import("../substrate/kagura_frame.zig");
const rtp_profile = @import("../proto/rtp_profile.zig");
const ice = @import("../proto/ice.zig");

pub const Leg = kakehashi.Leg; // .native | .webrtc
pub const TransportAddress = ice.TransportAddress;
pub const PtMap = kakehashi.PtMap;

pub const Error = kakehashi.Error || kagura_frame.DecodeError || kagura_frame.EncodeError;

const max_id_bytes = 64;
const max_rewrap = 1600; // >= one MTU datagram after header rewrap

/// Sends `bytes` to `target` on some leg's socket. The callback resolves the
/// target's *live* transport address (learned post-OFFER via STUN / first
/// datagram) from the owning plane, rather than trusting a possibly-stale
/// `target.addr`. `ctx` is the caller's context.
pub const SendFn = *const fn (ctx: *anyopaque, target: *const Member, bytes: []const u8) void;

/// Hook the native pump invokes (after its in-leg forward) to also deliver a
/// frame to the channel's WebRTC members. The implementation looks up the
/// channel's `ChannelBridge` and calls `fanoutNativeToWebrtc`.
pub const CrossLegSink = struct {
    ctx: *anyopaque,
    on_native_frame: *const fn (ctx: *anyopaque, channel: []const u8, datagram: []const u8) void,

    pub fn onNativeFrame(self: CrossLegSink, channel: []const u8, datagram: []const u8) void {
        self.on_native_frame(self.ctx, channel, datagram);
    }
};

/// Hook the WebRTC relay invokes (after its in-leg forward) to also deliver an
/// RTP frame to the channel's native members. The implementation looks up the
/// channel's `ChannelBridge` and calls `fanoutWebrtcToNative`.
pub const RtpCrossSink = struct {
    ctx: *anyopaque,
    on_rtp_frame: *const fn (ctx: *anyopaque, channel: []const u8, rtp: []const u8, keyframe_hint: bool) void,

    pub fn onRtpFrame(self: RtpCrossSink, channel: []const u8, rtp: []const u8, keyframe_hint: bool) void {
        self.on_rtp_frame(self.ctx, channel, rtp, keyframe_hint);
    }
};

/// The default per-call RTP payload-type map (dynamic PTs for our codecs). Used
/// when a call hasn't negotiated a custom mapping.
pub fn defaultPtMap() PtMap {
    var m = PtMap{};
    m.add(111, .opvox); // audio
    m.add(96, .opvis); // video
    return m;
}

/// One call participant and the transport identity needed to deliver to it.
pub const Member = struct {
    id_buf: [max_id_bytes]u8 = undefined,
    id_len: u8 = 0,
    leg: Leg,
    addr: TransportAddress = .{},
    /// Native identity (kagura stream + band the egress frame carries).
    stream_id: u32 = 0,
    band_id: u8 = kagura_frame.MEDIA_BAND_FLOOR,
    /// WebRTC identity (RTP SSRC stamped on the egress packet).
    ssrc: u32 = 0,

    pub fn id(self: *const Member) []const u8 {
        return self.id_buf[0..self.id_len];
    }
};

pub fn ChannelBridge(comptime max_participants: usize) type {
    return struct {
        const Self = @This();
        pub const RegisterError = error{ Full, BadId };

        members: [max_participants]Member = undefined,
        len: usize = 0,
        ptmap: PtMap = .{},

        pub fn init() Self {
            return .{ .ptmap = defaultPtMap() };
        }

        fn find(self: *Self, id: []const u8) ?*Member {
            for (self.members[0..self.len]) |*m| {
                if (std.mem.eql(u8, m.id(), id)) return m;
            }
            return null;
        }

        /// Register/update a participant's leg + transport identity.
        pub fn register(self: *Self, id: []const u8, m: Member) RegisterError!void {
            if (id.len == 0 or id.len > max_id_bytes) return error.BadId;
            if (self.find(id)) |existing| {
                var updated = m;
                @memcpy(updated.id_buf[0..id.len], id);
                updated.id_len = @intCast(id.len);
                existing.* = updated;
                return;
            }
            if (self.len >= max_participants) return error.Full;
            var nm = m;
            @memcpy(nm.id_buf[0..id.len], id);
            nm.id_len = @intCast(id.len);
            self.members[self.len] = nm;
            self.len += 1;
        }

        pub fn unregister(self: *Self, id: []const u8) bool {
            for (self.members[0..self.len], 0..) |*mem, i| {
                if (std.mem.eql(u8, mem.id(), id)) {
                    self.members[i] = self.members[self.len - 1];
                    self.len -= 1;
                    return true;
                }
            }
            return false;
        }

        pub fn count(self: *const Self) usize {
            return self.len;
        }

        /// Rewrap a native kagura `datagram` ONCE (keeping the source publisher's
        /// stream_id as the RTP ssrc, so receivers can demux) and send the same
        /// RTP packet to each WebRTC member of the call. Header-only; opaque
        /// payload shared verbatim. The `send` callback resolves each target's
        /// live address.
        pub fn fanoutNativeToWebrtc(self: *Self, datagram: []const u8, send_ctx: *anyopaque, send: SendFn) void {
            var targets: [max_participants]Member = undefined;
            const n = self.crossTargets(.native, "", &targets);
            if (n == 0) return;
            const view = kagura_frame.decode(datagram) catch return;
            const bf = kakehashi.fromNative(view);
            var scratch: [max_rewrap]u8 = undefined;
            const rtp = kakehashi.toRtp(bf, &self.ptmap, view.stream_id, &scratch) catch return;
            for (targets[0..n]) |*m| send(send_ctx, m, rtp);
        }

        /// Rewrap an `rtp` packet ONCE to a native kagura datagram (keeping the
        /// source ssrc as the native stream_id) and send to each native member.
        /// Used by the WebRTC relay to bridge to native peers.
        pub fn fanoutWebrtcToNative(self: *Self, rtp: []const u8, keyframe_hint: bool, send_ctx: *anyopaque, send: SendFn) void {
            var targets: [max_participants]Member = undefined;
            const n = self.crossTargets(.webrtc, "", &targets);
            if (n == 0) return;
            const dh = rtp_profile.decodeHeader(rtp) catch return;
            const bf = kakehashi.fromRtp(rtp, &self.ptmap, keyframe_hint) catch return;
            const nf = kakehashi.toNative(bf, kagura_frame.MEDIA_BAND_FLOOR, dh.header.ssrc);
            var scratch: [max_rewrap]u8 = undefined;
            const len = kagura_frame.encode(nf, &scratch) catch return;
            for (targets[0..n]) |*m| send(send_ctx, m, scratch[0..len]);
        }

        /// Copy into `out` every member on the leg OPPOSITE to `from_leg`,
        /// excluding `from_id` (the publisher). These are the participants the
        /// caller must reach by rewrapping the frame onto the other transport.
        pub fn crossTargets(self: *Self, from_leg: Leg, from_id: []const u8, out: []Member) usize {
            const other: Leg = if (from_leg == .native) .webrtc else .native;
            var n: usize = 0;
            for (self.members[0..self.len]) |m| {
                if (m.leg != other) continue;
                if (std.mem.eql(u8, m.id(), from_id)) continue;
                if (n >= out.len) break;
                out[n] = m;
                n += 1;
            }
            return n;
        }
    };
}

// ---------------------------------------------------------------------------
// Datagram-level rewrap (reuses kakehashi; payload is borrowed/opaque).
// ---------------------------------------------------------------------------

/// Rewrap a native kagura datagram as an RTP packet for a WebRTC target
/// (`ssrc`). Header-only: the codec payload is copied verbatim. Returns the RTP
/// bytes in `out`.
pub fn nativeDatagramToRtp(datagram: []const u8, map: *const PtMap, ssrc: u32, out: []u8) Error![]const u8 {
    const view = try kagura_frame.decode(datagram);
    const bf = kakehashi.fromNative(view);
    return kakehashi.toRtp(bf, map, ssrc, out);
}

/// Rewrap an RTP packet as a native kagura datagram for a native target
/// (`band_id`/`stream_id`). Header-only. Returns the encoded length in `out`.
pub fn rtpToNativeDatagram(
    rtp: []const u8,
    map: *const PtMap,
    band_id: u8,
    stream_id: u32,
    keyframe_hint: bool,
    out: []u8,
) Error!usize {
    const bf = try kakehashi.fromRtp(rtp, map, keyframe_hint);
    const nf = kakehashi.toNative(bf, band_id, stream_id);
    return kagura_frame.encode(nf, out);
}

// ---------------------------------------------------------------------------
// Tests (run under the unified build; transitively imports kagura/rtp_profile,
// so not standalone `zig test`-able — expected).
// ---------------------------------------------------------------------------

const testing = std.testing;

fn addr(last: u8, port: u16) TransportAddress {
    return TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, last }, port) catch unreachable;
}

test "crossTargets returns only opposite-leg members, excluding the sender" {
    var br = ChannelBridge(8).init();
    try br.register("alice", .{ .leg = .native, .addr = addr(1, 5000), .stream_id = 100 });
    try br.register("bob", .{ .leg = .native, .addr = addr(2, 5000), .stream_id = 200 });
    try br.register("mob", .{ .leg = .webrtc, .addr = addr(3, 6000), .ssrc = 0xAAAA });
    try br.register("pho", .{ .leg = .webrtc, .addr = addr(4, 6000), .ssrc = 0xBBBB });

    var out: [8]Member = undefined;
    // a native sender reaches the WebRTC members only
    const n = br.crossTargets(.native, "alice", &out);
    try testing.expectEqual(@as(usize, 2), n);
    for (out[0..n]) |m| try testing.expectEqual(Leg.webrtc, m.leg);

    // a WebRTC sender reaches the native members, excluding itself
    const n2 = br.crossTargets(.webrtc, "mob", &out);
    try testing.expectEqual(@as(usize, 2), n2);
    for (out[0..n2]) |m| try testing.expectEqual(Leg.native, m.leg);
}

test "unregister drops a member; register updates in place" {
    var br = ChannelBridge(4).init();
    try br.register("a", .{ .leg = .native, .stream_id = 1 });
    try br.register("a", .{ .leg = .webrtc, .ssrc = 9 }); // update -> same slot
    try testing.expectEqual(@as(usize, 1), br.count());
    try testing.expect(br.find("a").?.leg == .webrtc);
    try testing.expect(br.unregister("a"));
    try testing.expectEqual(@as(usize, 0), br.count());
    try testing.expect(!br.unregister("a"));
}

test "rewrap native datagram -> RTP -> native preserves codec/payload/keyframe" {
    var map = defaultPtMap();

    // Encode an opvis (video) native frame.
    var src: [128]u8 = undefined;
    const slen = try kagura_frame.encode(.{
        .band_id = kagura_frame.MEDIA_BAND_FLOOR + 2,
        .stream_id = 7,
        .sequence = 1234,
        .timestamp = 90000,
        .keyframe = true,
        .codec = .opvis_video,
        .payload = "video-payload",
    }, &src);

    // Native -> RTP (for a WebRTC peer's ssrc).
    var rtp_buf: [256]u8 = undefined;
    const rtp = try nativeDatagramToRtp(src[0..slen], &map, 0xCAFEBABE, &rtp_buf);

    // RTP -> native (for a native peer's band/stream).
    var back: [256]u8 = undefined;
    const blen = try rtpToNativeDatagram(rtp, &map, kagura_frame.MEDIA_BAND_FLOOR + 2, 7, true, &back);
    const view = try kagura_frame.decode(back[0..blen]);

    try testing.expectEqual(kagura_frame.CodecTag.opvis_video, view.codec);
    try testing.expectEqualStrings("video-payload", view.payload);
    try testing.expect(view.keyframe);
    try testing.expectEqual(@as(u32, 1234 & 0xFFFF), view.sequence); // RTP seq is 16-bit
}

test "rewrap rejects an unknown payload type" {
    var empty = PtMap{};
    var src: [64]u8 = undefined;
    const slen = try kagura_frame.encode(.{
        .band_id = kagura_frame.MEDIA_BAND_FLOOR,
        .stream_id = 1,
        .sequence = 1,
        .timestamp = 1,
        .keyframe = false,
        .codec = .opvox_audio,
        .payload = "x",
    }, &src);
    var out: [128]u8 = undefined;
    try testing.expectError(error.UnknownPayloadType, nativeDatagramToRtp(src[0..slen], &empty, 1, &out));
}

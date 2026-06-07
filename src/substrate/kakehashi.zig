//! Kakehashi (架け橋, "bridge") — the SFU media bridge between Mizuchi's native
//! Suimyaku media plane (opcodec frames over CoilPack/ryusen + secure_channel)
//! and the WebRTC gateway (RTP/SRTP, for mobile / hardware-codec clients).
//!
//! The SFU forwards a transport-neutral `BridgeFrame`; each egress leg
//! serializes it to its own wire form. This is a PURE selective-forwarding unit:
//! it only ever REPACKAGES a frame (zero-copy payload) between the native and
//! RTP wire formats — it NEVER transcodes. A mixed native/WebRTC call therefore
//! MUST converge on a codec every participant supports (`selectCommon`); if no
//! common codec exists the mismatched participant's media is `incompatible` for
//! that call (renegotiate or disable that kind) rather than incurring a costly
//! server-side transcode.
//!
//! THE SERVER NEVER ENCODES, DECODES, OR TRANSCODES MEDIA. The codec payload is
//! opaque: `fromNative`/`fromRtp` borrow it and `toNative`/`toRtp` wrap a
//! different *transport header* around the SAME bytes (the `encode` calls below
//! build RTP/container headers, not media). All codec work lives in the
//! endpoints; the SFU only forwards.
//!
//! Codec identity is normalized here: `opcodec_frame.CodecTag` (raw=0) and
//! `sdp.CodecTag` (raw=3) disagree on the `raw` ordinal, so Kakehashi carries
//! its own `Codec` and maps explicitly to each side.
const std = @import("std");
const opcodec_frame = @import("opcodec_frame.zig");
const rtp_profile = @import("../proto/rtp_profile.zig");

/// Canonical codec identity for the bridge (matches sdp.CodecTag ordinals).
pub const Codec = enum(u8) {
    opvox = 1, // audio (native)
    opvis = 2, // video (native)
    raw = 3, // uncompressed / passthrough
    _, // reserved for gateway codecs (Opus/H.264/VP8) we don't own yet
};

pub const Leg = enum { native, webrtc };

/// Transport-neutral media frame forwarded by the SFU.
pub const BridgeFrame = struct {
    codec: Codec,
    timestamp: u64, // media clock (codec-defined); RTP carries the low 32 bits
    sequence: u32, //  RTP carries the low 16 bits
    keyframe: bool,
    payload: []const u8, // encoded codec bytes, borrowed

    pub fn mediaKind(self: BridgeFrame) ?MediaKind {
        return codecKind(self.codec);
    }
};

pub const MediaKind = enum { audio, video };

pub const Error = error{ BufferTooSmall, UnknownPayloadType, Truncated };

// ---------------------------------------------------------------------------
// Native (opcodec) leg
// ---------------------------------------------------------------------------

fn nativeToCodec(t: opcodec_frame.CodecTag) Codec {
    return switch (t) {
        .opvox_audio => .opvox,
        .opvis_video => .opvis,
        .raw => .raw,
    };
}

fn codecToNative(c: Codec) opcodec_frame.CodecTag {
    return switch (c) {
        .opvox => .opvox_audio,
        .opvis => .opvis_video,
        else => .raw, // raw + any unknown gateway codec degrade to raw container
    };
}

/// Ingest a native opcodec frame into the bridge (payload borrowed).
pub fn fromNative(f: opcodec_frame.MediaFrame) BridgeFrame {
    return .{
        .codec = nativeToCodec(f.codec),
        .timestamp = f.timestamp,
        .sequence = f.sequence,
        .keyframe = f.keyframe,
        .payload = f.payload,
    };
}

/// Emit a bridge frame to a native peer (caller supplies the band/stream ids).
pub fn toNative(bf: BridgeFrame, band_id: u8, stream_id: u32) opcodec_frame.MediaFrame {
    return .{
        .band_id = band_id,
        .stream_id = stream_id,
        .sequence = bf.sequence,
        .timestamp = bf.timestamp,
        .keyframe = bf.keyframe,
        .codec = codecToNative(bf.codec),
        .payload = bf.payload,
    };
}

// ---------------------------------------------------------------------------
// WebRTC (RTP) leg
// ---------------------------------------------------------------------------

/// Dynamic RTP payload-type ↔ Codec map negotiated per session (PT 96..127).
pub const PtMap = struct {
    pub const Entry = struct { pt: u7, codec: Codec };
    entries: [8]Entry = undefined,
    len: usize = 0,

    pub fn add(self: *PtMap, pt: u7, codec: Codec) void {
        if (self.len >= self.entries.len) return;
        self.entries[self.len] = .{ .pt = pt, .codec = codec };
        self.len += 1;
    }
    pub fn codecForPt(self: *const PtMap, pt: u7) ?Codec {
        for (self.entries[0..self.len]) |e| if (e.pt == pt) return e.codec;
        return null;
    }
    pub fn ptForCodec(self: *const PtMap, codec: Codec) ?u7 {
        for (self.entries[0..self.len]) |e| if (e.codec == codec) return e.pt;
        return null;
    }
};

/// Ingest an RTP packet into the bridge. `keyframe_hint` carries codec-level
/// keyframe knowledge the RTP header alone can't express (the marker bit is
/// also honored). Payload borrows `rtp`.
pub fn fromRtp(rtp: []const u8, map: *const PtMap, keyframe_hint: bool) Error!BridgeFrame {
    const dh = rtp_profile.decodeHeader(rtp) catch return error.Truncated;
    if (rtp.len < rtp_profile.header_len) return error.Truncated;
    const codec = map.codecForPt(dh.header.payload_type) orelse return error.UnknownPayloadType;
    return .{
        .codec = codec,
        .timestamp = dh.header.timestamp,
        .sequence = dh.header.sequence,
        .keyframe = keyframe_hint or dh.header.marker,
        .payload = rtp[rtp_profile.header_len..],
    };
}

/// Emit a bridge frame to a WebRTC peer as an RTP packet (12-byte header +
/// payload). Sequence/timestamp are truncated to RTP's 16/32-bit fields.
pub fn toRtp(bf: BridgeFrame, map: *const PtMap, ssrc: u32, out: []u8) Error![]const u8 {
    const pt = map.ptForCodec(bf.codec) orelse return error.UnknownPayloadType;
    const hdr = rtp_profile.Header{
        .marker = bf.keyframe,
        .payload_type = pt,
        .sequence = @truncate(bf.sequence),
        .timestamp = @truncate(bf.timestamp),
        .ssrc = ssrc,
    };
    return rtp_profile.encodePacket(.{ .header = hdr, .payload = bf.payload }, out) catch error.BufferTooSmall;
}

// ---------------------------------------------------------------------------
// Codec negotiation between two legs
// ---------------------------------------------------------------------------

pub const Plan = enum {
    /// A codec is common to both endpoints — repackage only. The only path a
    /// pure SFU takes.
    direct_relay,
    /// No common codec. The SFU does not transcode; the call must renegotiate to
    /// a shared codec or disable that media kind for the mismatched participant.
    incompatible,
};

fn codecKind(c: Codec) ?MediaKind {
    return switch (c) {
        .opvox => .audio,
        .opvis => .video,
        .raw => null, // raw is kind-agnostic
        else => null,
    };
}

/// The first codec common to both lists, or null. The agreed codec for a
/// repackage-only relay between two endpoints.
pub fn commonCodec(a: []const Codec, b: []const Codec) ?Codec {
    for (a) |x| for (b) |y| {
        if (x == y) return x;
    };
    return null;
}

/// Decide how to bridge media from a sender to a receiver. Repackage-only:
/// `direct_relay` iff they share a codec, else `incompatible` (never transcode).
pub fn negotiate(sender: []const Codec, receiver: []const Codec) Plan {
    return if (commonCodec(sender, receiver) != null) .direct_relay else .incompatible;
}

/// Select the single codec that EVERY participant in a call supports, so the SFU
/// relays one repackage-only stream to all (no transcode anywhere). Returns null
/// if the participants share no codec — the call cannot run transcode-free as
/// composed (a participant must add a shared codec, e.g. a native client also
/// offering the WebRTC gateway's hardware codec). `sets` lists each
/// participant's supported codecs.
pub fn selectCommon(sets: []const []const Codec) ?Codec {
    if (sets.len == 0) return null;
    for (sets[0]) |candidate| {
        var all = true;
        for (sets[1..]) |other| {
            var found = false;
            for (other) |c| {
                if (c == candidate) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                all = false;
                break;
            }
        }
        if (all) return candidate;
    }
    return null;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "native <-> bridge frame mapping (raw ordinal differs across tag sets)" {
    const nf = opcodec_frame.MediaFrame{
        .band_id = 70,
        .stream_id = 9,
        .sequence = 1234,
        .timestamp = 0xDEADBEEF12,
        .keyframe = true,
        .codec = .opvox_audio,
        .payload = "audio-bytes",
    };
    const bf = fromNative(nf);
    try testing.expectEqual(Codec.opvox, bf.codec);
    try testing.expectEqual(@as(u64, 0xDEADBEEF12), bf.timestamp);
    try testing.expect(bf.keyframe);

    const back = toNative(bf, 70, 9);
    try testing.expectEqual(opcodec_frame.CodecTag.opvox_audio, back.codec);
    try testing.expectEqualStrings("audio-bytes", back.payload);

    // raw maps native(0) <-> kakehashi(3) correctly
    const rawf = opcodec_frame.MediaFrame{ .band_id = 70, .stream_id = 1, .sequence = 1, .timestamp = 1, .keyframe = false, .codec = .raw, .payload = "x" };
    try testing.expectEqual(Codec.raw, fromNative(rawf).codec);
    try testing.expectEqual(opcodec_frame.CodecTag.raw, codecToNative(.raw));
}

test "RTP <-> bridge round-trips through a PT map" {
    var map = PtMap{};
    map.add(111, .opvox);
    map.add(96, .opvis);

    const bf = BridgeFrame{ .codec = .opvox, .timestamp = 0x1_0000_0040, .sequence = 0x1_0005, .keyframe = true, .payload = "opvox-frame" };
    var buf: [128]u8 = undefined;
    const rtp = try toRtp(bf, &map, 0xCAFEBABE, &buf);

    const got = try fromRtp(rtp, &map, false);
    try testing.expectEqual(Codec.opvox, got.codec);
    try testing.expectEqual(@as(u32, 0x0005), got.sequence); // truncated to 16 bits
    try testing.expectEqual(@as(u64, 0x0000_0040), got.timestamp); // truncated to 32 bits
    try testing.expect(got.keyframe); // marker set from keyframe
    try testing.expectEqualStrings("opvox-frame", got.payload);

    // unknown PT is rejected
    var empty = PtMap{};
    try testing.expectError(error.UnknownPayloadType, fromRtp(rtp, &empty, false));
}

test "full native->webrtc->native bridge preserves codec/payload/keyframe" {
    var map = PtMap{};
    map.add(100, .opvis);
    const nf = opcodec_frame.MediaFrame{ .band_id = 71, .stream_id = 2, .sequence = 42, .timestamp = 9000, .keyframe = true, .codec = .opvis_video, .payload = "frame-payload" };

    const bf = fromNative(nf);
    var buf: [128]u8 = undefined;
    const rtp = try toRtp(bf, &map, 0x1111, &buf);
    const bf2 = try fromRtp(rtp, &map, true);
    const nf2 = toNative(bf2, 71, 2);

    try testing.expectEqual(opcodec_frame.CodecTag.opvis_video, nf2.codec);
    try testing.expectEqualStrings("frame-payload", nf2.payload);
    try testing.expect(nf2.keyframe);
    try testing.expectEqual(@as(u32, 42), nf2.sequence);
}

test "negotiate is repackage-only: direct_relay or incompatible (never transcode)" {
    try testing.expectEqual(Plan.direct_relay, negotiate(&.{.opvox}, &.{ .opvox, .raw }));
    try testing.expectEqual(Plan.incompatible, negotiate(&.{.opvox}, &.{.raw})); // no shared codec -> no transcode
    try testing.expectEqual(Plan.incompatible, negotiate(&.{.opvox}, &.{.opvis}));
    try testing.expectEqual(Plan.incompatible, negotiate(&.{.opvox}, &.{}));
    // commonCodec returns the first match in the first list's order:
    try testing.expectEqual(Codec.raw, commonCodec(&.{ .raw, .opvox }, &.{ .opvox, .raw }).?);
    try testing.expectEqual(Codec.opvox, commonCodec(&.{ .opvox, .raw }, &.{ .opvox, .raw }).?);
}

test "selectCommon finds the codec all participants share (transcode-free call)" {
    // native(opvox,raw) + native(opvox,opvis) + webrtc(opvox) -> opvox common
    const a = [_]Codec{ .opvox, .raw };
    const b = [_]Codec{ .opvox, .opvis };
    const c = [_]Codec{.opvox};
    try testing.expectEqual(Codec.opvox, selectCommon(&.{ &a, &b, &c }).?);
    // a participant with no shared codec -> null (cannot run transcode-free)
    const d = [_]Codec{.raw};
    try testing.expect(selectCommon(&.{ &a, &b, &c, &d }) == null);
    // single participant -> its first codec
    try testing.expectEqual(Codec.opvox, selectCommon(&.{&c}).?);
}

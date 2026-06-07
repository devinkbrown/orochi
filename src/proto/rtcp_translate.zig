//! Kakehashi SFU control-plane feedback translator.
//!
//! The Kakehashi bridge fans media between a WebRTC leg and the transport-neutral
//! SFU core. This module is the CONTROL-PLANE half of that bridge: it converts
//! RTCP feedback received on the WebRTC leg into transport-neutral "feedback
//! intents" the SFU can act on, and builds the RTCP packets to send back out on
//! the WebRTC leg. It never inspects or rewrites media payloads — the server
//! does no encoding/transcoding, it only relays the *intent* (please send a
//! keyframe; please retransmit these sequence numbers).
//!
//! Three feedback shapes are recognized (RFC 4585 / RFC 5104):
//!
//!   * PSFB  (PT=206) FMT=1  Picture Loss Indication (PLI) -> keyframe_request
//!   * PSFB  (PT=206) FMT=4  Full Intra Request   (FIR)    -> keyframe_request
//!   * RTPFB (PT=205) FMT=1  Generic NACK                  -> nack
//!
//! Anything else (Sender/Receiver Reports, REMB, TWCC, app-layer FB, ...) maps
//! to `.other` so the caller can ignore or forward it untouched.
//!
//! PSFB classification reuses `pli_fir.zig` (same dir). Generic NACK FCI parsing
//! is done inline here with a tiny local helper so this file stays importable on
//! its own (`zig test src/proto/rtcp_translate.zig`) — it deliberately imports
//! only same-dir proto files.
//!
//! Generic NACK wire layout (RFC 4585 §6.2.1):
//!
//!     0                   1                   2                   3
//!     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//!    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!    |            PID                |             BLP               |
//!    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!
//! PID is the lost packet's RTP sequence number; BLP ("bitmask of following
//! lost packets") flags which of the 16 packets after PID are also lost — bit i
//! set means PID+i+1 was lost. Each FCI block is therefore 4 bytes.
//!
//! Allocation-free: the parser fills a caller-supplied `seq_out` buffer for NACK
//! sequence numbers, and the builder writes into a caller buffer.

const std = @import("std");
const pli_fir = @import("pli_fir.zig");

/// RTCP version (always 2).
const rtcp_version: u2 = 2;

/// RTCP packet type for Transport-layer Feedback messages (RFC 4585 §6.2).
pub const pt_rtpfb: u8 = 205;

/// RTCP packet type for Payload-Specific Feedback messages (RFC 4585 §6.3).
pub const pt_psfb: u8 = pli_fir.pt_psfb; // 206

/// Transport-layer feedback message type: Generic NACK (RFC 4585 §6.2.1).
pub const fmt_nack: u5 = 1;

/// Common RTCP feedback header + the two SSRC fields, in bytes.
const header_len: usize = 12;

/// One Generic NACK FCI block: PID (2) + BLP (2).
const nack_fci_len: usize = 4;

pub const Error = error{
    /// Input ended before a full header / FCI block could be read.
    Truncated,
    /// Malformed packet (bad version, or NACK FCI not a multiple of 4 bytes).
    BadFormat,
    /// More NACK sequence numbers than the caller-supplied `seq_out` can hold.
    TooMany,
    /// The caller-supplied output buffer is too small for the message.
    BufferTooSmall,
};

/// A transport-neutral feedback intent produced from an inbound RTCP packet.
///
/// `nack.seqs` borrows the caller-supplied `seq_out` buffer passed to `parse`.
pub const Feedback = union(enum) {
    /// The remote needs a fresh intra/key frame for `media_ssrc` (PLI or FIR).
    keyframe_request: struct { media_ssrc: u32 },
    /// The remote lost the listed RTP sequence numbers on `media_ssrc`.
    nack: struct { media_ssrc: u32, seqs: []const u16 },
    /// Not a feedback shape we translate (SR/RR, REMB, TWCC, app FB, ...).
    other,
};

/// Decode one Generic NACK FCI block (PID + BLP) into `out`, returning how many
/// sequence numbers were written. Emits PID, then PID+i+1 for each set BLP bit
/// (i in 0..15). Returns `TooMany` if `out` cannot hold them.
fn decodeNackBlock(pid: u16, blp: u16, out: []u16) Error!usize {
    var n: usize = 0;
    if (n >= out.len) return Error.TooMany;
    out[n] = pid;
    n += 1;

    var i: usize = 0;
    while (i < 16) : (i += 1) {
        const bit: u4 = @intCast(i);
        if ((blp >> bit) & 1 == 1) {
            if (n >= out.len) return Error.TooMany;
            // PID + bit + 1, wrapping in the 16-bit sequence space.
            out[n] = pid +% @as(u16, bit) +% 1;
            n += 1;
        }
    }
    return n;
}

/// Parse and classify an inbound RTCP feedback packet into a transport-neutral
/// `Feedback` intent.
///
///   * PSFB (PT=206) FMT=1/4 -> `.keyframe_request` (delegated to `pli_fir`).
///   * RTPFB (PT=205) FMT=1   -> `.nack`; sequence numbers are written into
///     `seq_out` and the returned slice borrows it.
///   * anything else          -> `.other`.
///
/// Returns `Truncated` if the packet is shorter than a feedback header,
/// `BadFormat` on a bad version or a NACK FCI not divisible by 4, and `TooMany`
/// if a NACK carries more sequence numbers than `seq_out` can hold.
pub fn parse(rtcp_packet: []const u8, seq_out: []u16) Error!Feedback {
    if (rtcp_packet.len < header_len) return Error.Truncated;

    const version: u2 = @intCast(rtcp_packet[0] >> 6);
    if (version != rtcp_version) return Error.BadFormat;

    const pt = rtcp_packet[1];
    const fmt: u5 = @intCast(rtcp_packet[0] & 0x1f);

    if (pt == pt_psfb) {
        // Delegate PSFB classification to pli_fir. FIR FCI entries are not
        // needed for the keyframe intent (the target SSRC is the media SSRC),
        // so a tiny scratch buffer is sufficient.
        var fir_scratch: [16]pli_fir.FirEntry = undefined;
        const psfb = pli_fir.parse(rtcp_packet, &fir_scratch) catch |err| switch (err) {
            // pli_fir reports too many FIR entries than scratch holds; for a
            // keyframe intent the first target suffices.
            error.TooMany => {
                const media_ssrc = std.mem.readInt(u32, rtcp_packet[12..16], .big);
                return Feedback{ .keyframe_request = .{ .media_ssrc = media_ssrc } };
            },
            error.Truncated => return Error.Truncated,
            error.BadFormat => return Error.BadFormat,
            error.BufferTooSmall => return Error.BufferTooSmall,
        };
        return switch (psfb) {
            .pli => |p| Feedback{ .keyframe_request = .{ .media_ssrc = p.media_ssrc } },
            // FIR's media-source SSRC header field is 0 per RFC 5104; the real
            // target is the first FCI entry's SSRC.
            .fir => |f| if (f.entries.len > 0)
                Feedback{ .keyframe_request = .{ .media_ssrc = f.entries[0].ssrc } }
            else
                Feedback.other,
            .other => Feedback.other,
        };
    }

    if (pt == pt_rtpfb and fmt == fmt_nack) {
        const media_ssrc = std.mem.readInt(u32, rtcp_packet[8..12], .big);
        const fci = rtcp_packet[header_len..];
        if (fci.len % nack_fci_len != 0) return Error.BadFormat;

        var written: usize = 0;
        var off: usize = 0;
        while (off + nack_fci_len <= fci.len) : (off += nack_fci_len) {
            const pid = std.mem.readInt(u16, fci[off..][0..2], .big);
            const blp = std.mem.readInt(u16, fci[off + 2 ..][0..2], .big);
            written += try decodeNackBlock(pid, blp, seq_out[written..]);
        }
        return Feedback{ .nack = .{ .media_ssrc = media_ssrc, .seqs = seq_out[0..written] } };
    }

    return Feedback.other;
}

/// Build an RTCP keyframe-request packet (a PLI) to send on the WebRTC leg,
/// asking `media_ssrc`'s upstream to emit a fresh intra frame. `sender_ssrc` is
/// this endpoint's SSRC. Returns the 12-byte slice written into `out`.
pub fn buildKeyframeRequest(sender_ssrc: u32, media_ssrc: u32, out: []u8) Error![]const u8 {
    return pli_fir.buildPli(sender_ssrc, media_ssrc, out) catch |err| switch (err) {
        error.BufferTooSmall => Error.BufferTooSmall,
        else => Error.BadFormat,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "PLI built by pli_fir classifies as keyframe_request with media_ssrc" {
    var buf: [64]u8 = undefined;
    var seq_buf: [128]u16 = undefined;

    const wire = try pli_fir.buildPli(0xDEADBEEF, 0x0BADF00D, &buf);
    const fb = try parse(wire, &seq_buf);
    switch (fb) {
        .keyframe_request => |k| try std.testing.expectEqual(@as(u32, 0x0BADF00D), k.media_ssrc),
        else => return error.TestUnexpectedResult,
    }
}

test "FIR classifies as keyframe_request using the FCI target SSRC" {
    var buf: [64]u8 = undefined;
    var seq_buf: [128]u16 = undefined;

    const entries = [_]pli_fir.FirEntry{.{ .ssrc = 0x44556677, .seq = 3 }};
    const wire = try pli_fir.buildFir(0xCAFEBABE, &entries, &buf);
    const fb = try parse(wire, &seq_buf);
    switch (fb) {
        .keyframe_request => |k| try std.testing.expectEqual(@as(u32, 0x44556677), k.media_ssrc),
        else => return error.TestUnexpectedResult,
    }
}

test "RTPFB Generic NACK parses pid=1000 blp=0b101 into {1000,1001,1003}" {
    var seq_buf: [128]u16 = undefined;

    // Hand-build an RTPFB NACK: V=2, FMT=1, PT=205, one 4-byte FCI block.
    var pkt: [16]u8 = undefined;
    pkt[0] = (@as(u8, rtcp_version) << 6) | fmt_nack;
    pkt[1] = pt_rtpfb;
    std.mem.writeInt(u16, pkt[2..4], (16 / 4) - 1, .big); // length in words - 1
    std.mem.writeInt(u32, pkt[4..8], 0xAAAAAAAA, .big); // sender SSRC
    std.mem.writeInt(u32, pkt[8..12], 0xBBBBBBBB, .big); // media SSRC
    std.mem.writeInt(u16, pkt[12..14], 1000, .big); // PID
    std.mem.writeInt(u16, pkt[14..16], 0b101, .big); // BLP -> +1, +3

    const fb = try parse(&pkt, &seq_buf);
    switch (fb) {
        .nack => |n| {
            try std.testing.expectEqual(@as(u32, 0xBBBBBBBB), n.media_ssrc);
            try std.testing.expectEqualSlices(u16, &[_]u16{ 1000, 1001, 1003 }, n.seqs);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "NACK with empty BLP yields just the PID" {
    var seq_buf: [128]u16 = undefined;

    var pkt: [16]u8 = undefined;
    pkt[0] = (@as(u8, rtcp_version) << 6) | fmt_nack;
    pkt[1] = pt_rtpfb;
    std.mem.writeInt(u16, pkt[2..4], 3, .big);
    std.mem.writeInt(u32, pkt[4..8], 1, .big);
    std.mem.writeInt(u32, pkt[8..12], 2, .big);
    std.mem.writeInt(u16, pkt[12..14], 42, .big);
    std.mem.writeInt(u16, pkt[14..16], 0, .big);

    const fb = try parse(&pkt, &seq_buf);
    switch (fb) {
        .nack => |n| try std.testing.expectEqualSlices(u16, &[_]u16{42}, n.seqs),
        else => return error.TestUnexpectedResult,
    }
}

test "NACK with all BLP bits set yields 17 sequence numbers" {
    var seq_buf: [128]u16 = undefined;

    var pkt: [16]u8 = undefined;
    pkt[0] = (@as(u8, rtcp_version) << 6) | fmt_nack;
    pkt[1] = pt_rtpfb;
    std.mem.writeInt(u16, pkt[2..4], 3, .big);
    std.mem.writeInt(u32, pkt[4..8], 1, .big);
    std.mem.writeInt(u32, pkt[8..12], 2, .big);
    std.mem.writeInt(u16, pkt[12..14], 100, .big);
    std.mem.writeInt(u16, pkt[14..16], 0xFFFF, .big);

    const fb = try parse(&pkt, &seq_buf);
    switch (fb) {
        .nack => |n| {
            try std.testing.expectEqual(@as(usize, 17), n.seqs.len);
            try std.testing.expectEqual(@as(u16, 100), n.seqs[0]);
            try std.testing.expectEqual(@as(u16, 116), n.seqs[16]);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "Sender Report (PT=200) classifies as other" {
    var seq_buf: [128]u16 = undefined;

    // Minimal SR header: V=2, RC=0, PT=200, length, SSRC.
    var pkt: [28]u8 = undefined;
    @memset(&pkt, 0);
    pkt[0] = (@as(u8, rtcp_version) << 6);
    pkt[1] = 200; // SR
    std.mem.writeInt(u16, pkt[2..4], (28 / 4) - 1, .big);
    std.mem.writeInt(u32, pkt[4..8], 0x12345678, .big);

    const fb = try parse(&pkt, &seq_buf);
    try std.testing.expect(fb == .other);
}

test "buildKeyframeRequest round-trips through parse" {
    var buf: [64]u8 = undefined;
    var seq_buf: [128]u16 = undefined;

    const wire = try buildKeyframeRequest(0x11112222, 0x33334444, &buf);
    try std.testing.expectEqual(@as(usize, 12), wire.len);

    const fb = try parse(wire, &seq_buf);
    switch (fb) {
        .keyframe_request => |k| try std.testing.expectEqual(@as(u32, 0x33334444), k.media_ssrc),
        else => return error.TestUnexpectedResult,
    }
}

test "buildKeyframeRequest returns BufferTooSmall for a short buffer" {
    var small: [8]u8 = undefined;
    try std.testing.expectError(Error.BufferTooSmall, buildKeyframeRequest(1, 2, &small));
}

test "parse returns Truncated on a short packet" {
    var seq_buf: [4]u16 = undefined;
    const short = [_]u8{ 0x80, 205, 0, 0 };
    try std.testing.expectError(Error.Truncated, parse(&short, &seq_buf));
}

test "parse returns BadFormat on bad version" {
    var seq_buf: [4]u16 = undefined;
    var pkt: [16]u8 = undefined;
    @memset(&pkt, 0);
    pkt[0] = (@as(u8, 1) << 6) | fmt_nack; // version 1
    pkt[1] = pt_rtpfb;
    try std.testing.expectError(Error.BadFormat, parse(&pkt, &seq_buf));
}

test "parse returns BadFormat on NACK FCI not a multiple of 4" {
    var seq_buf: [16]u16 = undefined;
    var pkt: [14]u8 = undefined; // 12-byte header + 2 trailing bytes
    @memset(&pkt, 0);
    pkt[0] = (@as(u8, rtcp_version) << 6) | fmt_nack;
    pkt[1] = pt_rtpfb;
    try std.testing.expectError(Error.BadFormat, parse(&pkt, &seq_buf));
}

test "parse returns TooMany when seq_out cannot hold all NACK seqs" {
    var seq_buf: [2]u16 = undefined; // room for PID + 1 only

    var pkt: [16]u8 = undefined;
    pkt[0] = (@as(u8, rtcp_version) << 6) | fmt_nack;
    pkt[1] = pt_rtpfb;
    std.mem.writeInt(u16, pkt[2..4], 3, .big);
    std.mem.writeInt(u32, pkt[4..8], 1, .big);
    std.mem.writeInt(u32, pkt[8..12], 2, .big);
    std.mem.writeInt(u16, pkt[12..14], 500, .big);
    std.mem.writeInt(u16, pkt[14..16], 0b111, .big); // 3 follow-ups -> 4 total

    try std.testing.expectError(Error.TooMany, parse(&pkt, &seq_buf));
}

test "NACK PID near wraparound wraps in 16-bit sequence space" {
    var seq_buf: [128]u16 = undefined;

    var pkt: [16]u8 = undefined;
    pkt[0] = (@as(u8, rtcp_version) << 6) | fmt_nack;
    pkt[1] = pt_rtpfb;
    std.mem.writeInt(u16, pkt[2..4], 3, .big);
    std.mem.writeInt(u32, pkt[4..8], 1, .big);
    std.mem.writeInt(u32, pkt[8..12], 2, .big);
    std.mem.writeInt(u16, pkt[12..14], 0xFFFE, .big); // PID
    std.mem.writeInt(u16, pkt[14..16], 0b11, .big); // +1 -> 0xFFFF, +2 -> 0x0000

    const fb = try parse(&pkt, &seq_buf);
    switch (fb) {
        .nack => |n| try std.testing.expectEqualSlices(
            u16,
            &[_]u16{ 0xFFFE, 0xFFFF, 0x0000 },
            n.seqs,
        ),
        else => return error.TestUnexpectedResult,
    }
}

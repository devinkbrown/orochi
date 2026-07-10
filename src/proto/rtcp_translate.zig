// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

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

/// The fixed RTCP common header (V/P/count, PT, length) shared by every packet
/// in a compound, in bytes. The length field it carries delimits each sub-packet.
const rtcp_common_header_len: usize = 4;

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

/// Parse a possibly-COMPOUND inbound RTCP datagram (RFC 3550 §6.1) and return the
/// first feedback intent it carries. Unlike `parse` (which classifies a single
/// packet at offset 0 and treats the whole tail as its FCI), this walks each
/// sub-packet by its own length field. That matters because the mandatory
/// compound shape a browser sends without `rtcp-rsize` leads with a Sender/
/// Receiver Report (and often an SDES chunk) BEFORE the PLI/FIR/NACK — feeding
/// such a datagram to `parse` sees the SR/RR at offset 0 and drops the feedback
/// as `.other`, freezing video (a keyframe request never reaches the publisher).
///
/// The first PSFB (PLI/FIR) or RTPFB (Generic NACK) sub-packet wins; leading and
/// interleaved non-feedback sub-packets (SR/RR/SDES/BYE/REMB/TWCC/…) are skipped.
/// A NACK's FCI is delimited by that NACK packet's length, so trailing compound
/// packets can never be mis-read as extra lost-sequence numbers.
///
/// Fail-closed: every sub-packet header is bounds- and version-checked before use;
/// a truncated datagram or a bad RTCP version is rejected, and a malformed
/// feedback sub-packet propagates its `parse` error rather than being accepted.
pub fn parseCompound(datagram: []const u8, seq_out: []u16) Error!Feedback {
    var pos: usize = 0;
    while (pos < datagram.len) {
        if (datagram.len - pos < rtcp_common_header_len) return Error.Truncated;

        const version: u2 = @intCast(datagram[pos] >> 6);
        if (version != rtcp_version) return Error.BadFormat;

        const words_minus_one = std.mem.readInt(u16, datagram[pos + 2 ..][0..2], .big);
        const sub_len = (@as(usize, words_minus_one) + 1) * 4;
        if (sub_len < rtcp_common_header_len) return Error.BadFormat;
        if (datagram.len - pos < sub_len) return Error.Truncated;

        const sub = datagram[pos .. pos + sub_len];
        const pt = sub[1];
        if (pt == pt_psfb or pt == pt_rtpfb) {
            // Classify the exact sub-slice: `parse` reads FCI as `sub[12..]`, which
            // is precisely this packet's FCI now that `sub` is trimmed to sub_len.
            switch (try parse(sub, seq_out)) {
                .other => {}, // recognized RTCP type, just not a shape we translate
                else => |fb| return fb,
            }
        }
        pos += sub_len;
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

/// Build an RTCP Generic NACK packet to send on the WebRTC leg. Each input
/// sequence is encoded as its own PID-only FCI block; this is less compact than
/// BLP packing but preserves the exact request set without allocation.
pub fn buildNack(sender_ssrc: u32, media_ssrc: u32, seqs: []const u16, out: []u8) Error![]const u8 {
    if (seqs.len == 0) return Error.BadFormat;
    const total = header_len + seqs.len * nack_fci_len;
    if (total > std.math.maxInt(u16) * 4 or out.len < total) return Error.BufferTooSmall;

    out[0] = (@as(u8, rtcp_version) << 6) | @as(u8, fmt_nack);
    out[1] = pt_rtpfb;
    std.mem.writeInt(u16, out[2..4], @intCast(total / 4 - 1), .big);
    std.mem.writeInt(u32, out[4..8], sender_ssrc, .big);
    std.mem.writeInt(u32, out[8..12], media_ssrc, .big);

    var off: usize = header_len;
    for (seqs) |seq| {
        std.mem.writeInt(u16, out[off..][0..2], seq, .big);
        std.mem.writeInt(u16, out[off + 2 ..][0..2], 0, .big);
        off += nack_fci_len;
    }
    return out[0..total];
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

test "buildNack round-trips through parse" {
    var buf: [64]u8 = undefined;
    var seq_buf: [8]u16 = undefined;

    const wire = try buildNack(0x11112222, 0x33334444, &.{ 77, 79 }, &buf);
    const fb = try parse(wire, &seq_buf);
    switch (fb) {
        .nack => |n| {
            try std.testing.expectEqual(@as(u32, 0x33334444), n.media_ssrc);
            try std.testing.expectEqualSlices(u16, &.{ 77, 79 }, n.seqs);
        },
        else => return error.TestUnexpectedResult,
    }
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

// A minimal Receiver Report (PT=201, RC=0): 8-byte header + reporter SSRC.
fn writeMinimalRr(out: *[8]u8, ssrc: u32) []const u8 {
    out[0] = @as(u8, rtcp_version) << 6; // V=2, P=0, RC=0
    out[1] = 201;
    std.mem.writeInt(u16, out[2..4], (8 / 4) - 1, .big);
    std.mem.writeInt(u32, out[4..8], ssrc, .big);
    return out[0..8];
}

// A minimal Sender Report (PT=200, RC=0): 28-byte header + sender info.
fn writeMinimalSr(out: *[28]u8, ssrc: u32) []const u8 {
    @memset(out, 0);
    out[0] = @as(u8, rtcp_version) << 6;
    out[1] = 200;
    std.mem.writeInt(u16, out[2..4], (28 / 4) - 1, .big);
    std.mem.writeInt(u32, out[4..8], ssrc, .big);
    return out[0..28];
}

test "RTCP compound RR then PLI resolves keyframe_request" {
    var seq_buf: [128]u16 = undefined;
    var buf: [64]u8 = undefined;

    var rr: [8]u8 = undefined;
    _ = writeMinimalRr(&rr, 0x11111111);
    const pli = try pli_fir.buildPli(0xDEADBEEF, 0x0BADF00D, buf[8..]);

    var compound: [8 + 12]u8 = undefined;
    @memcpy(compound[0..8], &rr);
    @memcpy(compound[8..], pli);

    // `parse` alone misclassifies (sees the RR at offset 0) — the bug this fixes.
    try std.testing.expect((try parse(&compound, &seq_buf)) == .other);

    const fb = try parseCompound(&compound, &seq_buf);
    switch (fb) {
        .keyframe_request => |k| try std.testing.expectEqual(@as(u32, 0x0BADF00D), k.media_ssrc),
        else => return error.TestUnexpectedResult,
    }
}

test "RTCP compound SR then NACK resolves nack with FCI delimited by length" {
    var seq_buf: [128]u16 = undefined;

    var sr: [28]u8 = undefined;
    _ = writeMinimalSr(&sr, 0x22222222);

    // NACK: PID=1000, BLP=0b101 -> {1000,1001,1003}, declared length = 16 bytes.
    var nack: [16]u8 = undefined;
    nack[0] = (@as(u8, rtcp_version) << 6) | fmt_nack;
    nack[1] = pt_rtpfb;
    std.mem.writeInt(u16, nack[2..4], (16 / 4) - 1, .big);
    std.mem.writeInt(u32, nack[4..8], 0xAAAAAAAA, .big);
    std.mem.writeInt(u32, nack[8..12], 0xBBBBBBBB, .big);
    std.mem.writeInt(u16, nack[12..14], 1000, .big);
    std.mem.writeInt(u16, nack[14..16], 0b101, .big);

    // Append a trailing RR after the NACK: its bytes must NOT be read as FCI.
    var rr: [8]u8 = undefined;
    _ = writeMinimalRr(&rr, 0x33333333);

    var compound: [28 + 16 + 8]u8 = undefined;
    @memcpy(compound[0..28], &sr);
    @memcpy(compound[28..44], &nack);
    @memcpy(compound[44..], &rr);

    const fb = try parseCompound(&compound, &seq_buf);
    switch (fb) {
        .nack => |n| {
            try std.testing.expectEqual(@as(u32, 0xBBBBBBBB), n.media_ssrc);
            try std.testing.expectEqualSlices(u16, &[_]u16{ 1000, 1001, 1003 }, n.seqs);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "RTCP compound with only reports yields other" {
    var seq_buf: [8]u16 = undefined;
    var sr: [28]u8 = undefined;
    _ = writeMinimalSr(&sr, 0x1);
    var rr: [8]u8 = undefined;
    _ = writeMinimalRr(&rr, 0x2);

    var compound: [28 + 8]u8 = undefined;
    @memcpy(compound[0..28], &sr);
    @memcpy(compound[28..], &rr);

    try std.testing.expect((try parseCompound(&compound, &seq_buf)) == .other);
}

test "RTCP compound single reduced-size PLI resolves without a leading report" {
    var seq_buf: [8]u16 = undefined;
    var buf: [64]u8 = undefined;
    const pli = try pli_fir.buildPli(0x1, 0x0FEEDBED, &buf);
    const fb = try parseCompound(pli, &seq_buf);
    switch (fb) {
        .keyframe_request => |k| try std.testing.expectEqual(@as(u32, 0x0FEEDBED), k.media_ssrc),
        else => return error.TestUnexpectedResult,
    }
}

test "RTCP compound rejects a sub-packet whose declared length overruns the datagram" {
    var seq_buf: [8]u16 = undefined;
    var rr: [8]u8 = undefined;
    _ = writeMinimalRr(&rr, 0x1);
    // Claim 5 words (20 bytes) in an 8-byte packet.
    std.mem.writeInt(u16, rr[2..4], 4, .big);
    try std.testing.expectError(Error.Truncated, parseCompound(&rr, &seq_buf));
}

test "RTCP compound rejects a bad RTCP version in a sub-packet" {
    var seq_buf: [8]u16 = undefined;
    var sr: [28]u8 = undefined;
    _ = writeMinimalSr(&sr, 0x1);
    var pli_buf: [12]u8 = undefined;
    const pli = try pli_fir.buildPli(0x1, 0x2, &pli_buf);
    var compound: [28 + 12]u8 = undefined;
    @memcpy(compound[0..28], &sr);
    @memcpy(compound[28..], pli);
    // Corrupt the version of the second (PLI) sub-packet.
    compound[28] = (1 << 6) | (compound[28] & 0x3f);
    try std.testing.expectError(Error.BadFormat, parseCompound(&compound, &seq_buf));
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

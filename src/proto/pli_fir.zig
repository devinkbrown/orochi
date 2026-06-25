// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! RTCP Payload-Specific Feedback (PSFB, PT=206) keyframe-request codec for the
//! SFU video path: Picture Loss Indication (PLI, FMT=1, RFC 4585 §6.3.1) and
//! Full Intra Request (FIR, FMT=4, RFC 5104 §4.3.1).
//!
//! These are the two messages an SFU forwards/synthesizes to make an upstream
//! sender emit a fresh intra (key) frame — PLI is the lightweight "I lost a
//! picture" hint, FIR is the explicit, counter-tracked "send a full intra now"
//! command used when the SFU itself needs a keyframe (e.g. a new subscriber).
//!
//! Wire layout (RFC 4585 §6.1, common to all RTCP feedback):
//!
//!     0                   1                   2                   3
//!     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//!    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!    |V=2|P|   FMT   |       PT      |          length               |
//!    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!    |                  SSRC of packet sender                        |
//!    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!    |                  SSRC of media source                         |
//!    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!    :            Feedback Control Information (FCI)                 :
//!
//! PLI (FMT=1): no FCI, total 12 bytes.
//! FIR (FMT=4): media-source SSRC field MUST be 0; FCI is one or more 8-byte
//! entries — target SSRC (4) + seq nr (1, a per-target command counter the
//! sender increments for each new FIR) + 3 reserved bytes (sent as 0).
//!
//! Pure and allocation-free: builders write into a caller buffer, the parser
//! borrows the input slice for FIR entry data (copied into a caller buffer).

const std = @import("std");

/// RTCP packet type for Payload-Specific Feedback messages (RFC 4585 §6.4).
pub const pt_psfb: u8 = 206;

/// Feedback message type: Picture Loss Indication (RFC 4585 §6.3.1).
pub const fmt_pli: u5 = 1;

/// Feedback message type: Full Intra Request (RFC 5104 §4.3.1).
pub const fmt_fir: u5 = 4;

/// RTCP version (always 2).
const rtcp_version: u2 = 2;

/// Common RTCP feedback header + the two SSRC fields, in bytes.
const header_len: usize = 12;

/// One FIR FCI entry: target SSRC (4) + seq (1) + reserved (3).
const fir_entry_len: usize = 8;

pub const Error = error{
    /// Input ended before a full header / FCI entry could be read.
    Truncated,
    /// Not a PSFB packet (wrong version or PT), or a malformed FCI length.
    BadFormat,
    /// The caller-supplied output buffer is too small for the message.
    BufferTooSmall,
    /// More FIR entries than the caller-supplied output slice can hold.
    TooMany,
};

/// A single Full Intra Request target: which SSRC to refresh and the command
/// counter the sender increments per FIR issued to that target.
pub const FirEntry = struct {
    ssrc: u32,
    seq: u8,
};

/// Classified, parsed PSFB feedback. `fir.entries` borrows the caller-supplied
/// output buffer passed to `parse`.
pub const Feedback = union(enum) {
    pli: struct { sender_ssrc: u32, media_ssrc: u32 },
    fir: struct { sender_ssrc: u32, entries: []const FirEntry },
    other,
};

/// Write the RTCP common feedback header into `out[0..4]`.
/// `length` is the total packet size in bytes; the on-wire field is that size
/// in 32-bit words minus one.
fn writeHeader(fmt: u5, length: usize, out: []u8) void {
    // V(2) | P(1)=0 | FMT(5)
    out[0] = (@as(u8, rtcp_version) << 6) | @as(u8, fmt);
    out[1] = pt_psfb;
    const words_minus_one: u16 = @intCast(length / 4 - 1);
    std.mem.writeInt(u16, out[2..4], words_minus_one, .big);
}

/// Build a Picture Loss Indication into `out`. Returns the 12-byte slice.
pub fn buildPli(sender_ssrc: u32, media_ssrc: u32, out: []u8) Error![]const u8 {
    if (out.len < header_len) return Error.BufferTooSmall;
    writeHeader(fmt_pli, header_len, out);
    std.mem.writeInt(u32, out[4..8], sender_ssrc, .big);
    std.mem.writeInt(u32, out[8..12], media_ssrc, .big);
    return out[0..header_len];
}

/// Build a Full Intra Request into `out`. The media-source SSRC field is forced
/// to 0 per RFC 5104; each entry becomes an 8-byte FCI record. Returns the
/// written slice.
pub fn buildFir(sender_ssrc: u32, entries: []const FirEntry, out: []u8) Error![]const u8 {
    const total = header_len + entries.len * fir_entry_len;
    if (out.len < total) return Error.BufferTooSmall;

    writeHeader(fmt_fir, total, out);
    std.mem.writeInt(u32, out[4..8], sender_ssrc, .big);
    std.mem.writeInt(u32, out[8..12], 0, .big); // media SSRC MUST be 0 for FIR

    var off: usize = header_len;
    for (entries) |e| {
        std.mem.writeInt(u32, out[off..][0..4], e.ssrc, .big);
        out[off + 4] = e.seq;
        out[off + 5] = 0;
        out[off + 6] = 0;
        out[off + 7] = 0;
        off += fir_entry_len;
    }
    return out[0..total];
}

/// Parse and classify a PSFB packet. Validates version==2 and PT==206, then
/// dispatches on FMT. For FIR, fills `fir_out` (returns `TooMany` if there are
/// more entries than it can hold); the returned slices borrow `bytes`/`fir_out`.
/// Any PSFB FMT other than PLI/FIR classifies as `.other`.
pub fn parse(bytes: []const u8, fir_out: []FirEntry) Error!Feedback {
    if (bytes.len < header_len) return Error.Truncated;

    const version: u2 = @intCast(bytes[0] >> 6);
    if (version != rtcp_version) return Error.BadFormat;
    if (bytes[1] != pt_psfb) return Error.BadFormat;

    const fmt: u5 = @intCast(bytes[0] & 0x1f);
    const sender_ssrc = std.mem.readInt(u32, bytes[4..8], .big);

    switch (fmt) {
        fmt_pli => {
            const media_ssrc = std.mem.readInt(u32, bytes[8..12], .big);
            return Feedback{ .pli = .{ .sender_ssrc = sender_ssrc, .media_ssrc = media_ssrc } };
        },
        fmt_fir => {
            const fci = bytes[header_len..];
            if (fci.len % fir_entry_len != 0) return Error.BadFormat;
            const count = fci.len / fir_entry_len;
            if (count > fir_out.len) return Error.TooMany;

            var off: usize = 0;
            var i: usize = 0;
            while (i < count) : (i += 1) {
                fir_out[i] = .{
                    .ssrc = std.mem.readInt(u32, fci[off..][0..4], .big),
                    .seq = fci[off + 4],
                };
                off += fir_entry_len;
            }
            return Feedback{ .fir = .{ .sender_ssrc = sender_ssrc, .entries = fir_out[0..count] } };
        },
        else => return Feedback.other,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "buildPli round-trips through parse" {
    var buf: [64]u8 = undefined;
    var fir_buf: [4]FirEntry = undefined;

    const wire = try buildPli(0xDEADBEEF, 0x12345678, &buf);
    try std.testing.expectEqual(@as(usize, 12), wire.len);

    const fb = try parse(wire, &fir_buf);
    switch (fb) {
        .pli => |p| {
            try std.testing.expectEqual(@as(u32, 0xDEADBEEF), p.sender_ssrc);
            try std.testing.expectEqual(@as(u32, 0x12345678), p.media_ssrc);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "buildFir with two entries round-trips and zeroes media SSRC on the wire" {
    var buf: [64]u8 = undefined;
    var fir_buf: [4]FirEntry = undefined;

    const entries = [_]FirEntry{
        .{ .ssrc = 0xAABBCCDD, .seq = 7 },
        .{ .ssrc = 0x01020304, .seq = 200 },
    };
    const wire = try buildFir(0xCAFEBABE, &entries, &buf);
    try std.testing.expectEqual(@as(usize, 12 + 16), wire.len);

    // media-source SSRC field (bytes 8..12) must be zero for FIR.
    try std.testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, wire[8..12], .big));

    const fb = try parse(wire, &fir_buf);
    switch (fb) {
        .fir => |f| {
            try std.testing.expectEqual(@as(u32, 0xCAFEBABE), f.sender_ssrc);
            try std.testing.expectEqual(@as(usize, 2), f.entries.len);
            try std.testing.expectEqual(@as(u32, 0xAABBCCDD), f.entries[0].ssrc);
            try std.testing.expectEqual(@as(u8, 7), f.entries[0].seq);
            try std.testing.expectEqual(@as(u32, 0x01020304), f.entries[1].ssrc);
            try std.testing.expectEqual(@as(u8, 200), f.entries[1].seq);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "parse returns Truncated on a cut buffer" {
    var buf: [64]u8 = undefined;
    var fir_buf: [4]FirEntry = undefined;

    const wire = try buildPli(1, 2, &buf);
    try std.testing.expectError(Error.Truncated, parse(wire[0 .. wire.len - 1], &fir_buf));
}

test "parse returns BadFormat on wrong PT or version" {
    var buf: [64]u8 = undefined;
    var fir_buf: [4]FirEntry = undefined;

    const wire = try buildPli(1, 2, &buf);

    // Wrong PT.
    var bad_pt: [12]u8 = undefined;
    @memcpy(&bad_pt, wire[0..12]);
    bad_pt[1] = 205; // RTPFB, not PSFB
    try std.testing.expectError(Error.BadFormat, parse(&bad_pt, &fir_buf));

    // Wrong version (set V=1).
    var bad_ver: [12]u8 = undefined;
    @memcpy(&bad_ver, wire[0..12]);
    bad_ver[0] = (@as(u8, 1) << 6) | fmt_pli;
    try std.testing.expectError(Error.BadFormat, parse(&bad_ver, &fir_buf));
}

test "parse returns TooMany when fir_out is too small" {
    var buf: [64]u8 = undefined;
    var fir_buf: [1]FirEntry = undefined;

    const entries = [_]FirEntry{
        .{ .ssrc = 1, .seq = 1 },
        .{ .ssrc = 2, .seq = 2 },
    };
    const wire = try buildFir(9, &entries, &buf);
    try std.testing.expectError(Error.TooMany, parse(wire, &fir_buf));
}

test "non-PLI/FIR PSFB classifies as other" {
    var buf: [12]u8 = undefined;
    var fir_buf: [4]FirEntry = undefined;

    // Hand-build a PSFB with FMT=15 (Application-layer FB), valid header.
    buf[0] = (@as(u8, rtcp_version) << 6) | 15;
    buf[1] = pt_psfb;
    std.mem.writeInt(u16, buf[2..4], 2, .big);
    std.mem.writeInt(u32, buf[4..8], 0x11111111, .big);
    std.mem.writeInt(u32, buf[8..12], 0x22222222, .big);

    const fb = try parse(&buf, &fir_buf);
    try std.testing.expect(fb == .other);
}

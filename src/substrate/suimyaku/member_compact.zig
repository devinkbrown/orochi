// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Compact fallback wire form for a channel-CRDT member's causal context.
//!
//! The canonical member wire form (`delta_codec.DeltaView`, magic `"GDLT"`)
//! reconstructs a member's causal context by expanding its `VersionVector`
//! frontier into DENSE per-counter dots — `{(R,1), (R,2), … (R,counter)}`. That
//! expansion is bounded at `max_context_dots` (512), so on a busy channel where
//! one replica has authored more than 512 membership adds, the most recently
//! joined members carry `context.counter(R) > 512` and the dense form returns
//! `error.Oversize`. That silently disables the burst and Merkle anti-entropy
//! backstops for the whole channel.
//!
//! A member receiver only ever consumes the folded-back context frontier plus
//! the live adds — it never reads the dense removes. This form therefore
//! transmits the context as the COMPACT frontier it already is (a list of at
//! most `VersionVector.max_entries` `(replica, counter)` pairs) plus the live
//! adds, with no dense expansion and no unbounded byte cost.
//!
//! Wire compatibility: this is a self-describing, additive alternative. Callers
//! keep emitting the canonical dense `"GDLT"` form byte-for-byte whenever it
//! fits (so a legacy peer still parses it and Merkle hashes still match), and
//! fall back to this compact form ONLY for members the dense form could neither
//! encode nor consume. A legacy peer that sees this distinct `"GMBC"` magic
//! rejects it fail-closed (`BadMagic`/`UnknownRecord`), exactly as it already
//! failed on those members — no silent divergence, no cross-version corruption.

const std = @import("std");

pub const magic = [_]u8{ 'G', 'M', 'B', 'C' };
pub const version: u8 = 1;

/// Frontier entries are bounded by `VersionVector.max_entries`.
pub const max_context = 64;
/// Live adds carried per member. Matches the dense codec's `max_adds` bound so a
/// member the dense form accepts on adds is never rejected here for adds alone.
pub const max_adds = 128;
/// Serialized `{replica, counter, hlc, status}` add value — identical layout to
/// the dense codec's add value, so callers reuse their existing add codecs.
pub const add_value_len = 25;

const varint_max = 10;

/// Upper bound on a single encoded compact member payload.
pub const max_bytes = magic.len + 1 + 8 + 8 +
    varint_max + max_context * 16 +
    varint_max + max_adds * add_value_len;

pub const Entry = struct { replica: u64, counter: u64 };

pub const DecodeError = error{
    Truncated,
    BadMagic,
    UnsupportedVersion,
    Oversize,
    InvalidMember,
    TrailingBytes,
    VarintTooLong,
};

pub const EncodeError = error{ BufferTooSmall, Oversize };

/// Decoded, alloc-free view. Add values point into the caller's decode buffer.
pub const View = struct {
    member_id: u64,
    hlc_key: u64,
    context: [max_context]Entry = undefined,
    context_len: usize = 0,
    adds: [max_adds][add_value_len]u8 = undefined,
    adds_len: usize = 0,
};

/// True when `bytes` begins with the compact member magic.
pub fn matches(bytes: []const u8) bool {
    return bytes.len >= magic.len and std.mem.eql(u8, bytes[0..magic.len], &magic);
}

pub fn encode(
    out: []u8,
    member_id: u64,
    hlc_key: u64,
    context: []const Entry,
    adds: []const [add_value_len]u8,
) EncodeError![]const u8 {
    if (context.len > max_context or adds.len > max_adds) return error.Oversize;
    var w = Writer{ .buf = out };
    try w.writeBytes(&magic);
    try w.writeU8(version);
    try w.writeU64(member_id);
    try w.writeU64(hlc_key);
    try w.writeVarint(context.len);
    for (context) |e| {
        try w.writeU64(e.replica);
        try w.writeU64(e.counter);
    }
    try w.writeVarint(adds.len);
    for (adds) |a| try w.writeBytes(&a);
    return w.written();
}

pub fn decode(bytes: []const u8) DecodeError!View {
    var r = Reader{ .buf = bytes };
    for (magic) |want| {
        if (try r.readU8() != want) return error.BadMagic;
    }
    if (try r.readU8() != version) return error.UnsupportedVersion;

    var v = View{ .member_id = try r.readU64(), .hlc_key = try r.readU64() };

    const cc = try r.readVarint();
    if (cc > max_context) return error.Oversize;
    v.context_len = cc;
    var i: usize = 0;
    while (i < cc) : (i += 1) {
        const replica = try r.readU64();
        const counter = try r.readU64();
        // A frontier never carries a zero counter; reject fail-closed, mirroring
        // the dense codec's `validateDot` rejection of counter-0 dots.
        if (counter == 0) return error.InvalidMember;
        v.context[i] = .{ .replica = replica, .counter = counter };
    }

    const ac = try r.readVarint();
    if (ac > max_adds) return error.Oversize;
    v.adds_len = ac;
    i = 0;
    while (i < ac) : (i += 1) {
        const slice = try r.readFixed(add_value_len);
        @memcpy(&v.adds[i], slice);
    }

    if (!r.done()) return error.TrailingBytes;
    return v;
}

const Writer = struct {
    buf: []u8,
    pos: usize = 0,

    fn written(self: *const Writer) []const u8 {
        return self.buf[0..self.pos];
    }
    fn writeU8(self: *Writer, value: u8) EncodeError!void {
        if (self.pos + 1 > self.buf.len) return error.BufferTooSmall;
        self.buf[self.pos] = value;
        self.pos += 1;
    }
    fn writeU64(self: *Writer, value: u64) EncodeError!void {
        if (self.pos + 8 > self.buf.len) return error.BufferTooSmall;
        var idx: usize = 0;
        while (idx < 8) : (idx += 1) {
            self.buf[self.pos + idx] = @intCast((value >> @as(u6, @intCast(idx * 8))) & 0xff);
        }
        self.pos += 8;
    }
    fn writeVarint(self: *Writer, value: usize) EncodeError!void {
        var n: u64 = value;
        while (n >= 0x80) {
            try self.writeU8(@as(u8, @intCast(n & 0x7f)) | 0x80);
            n >>= 7;
        }
        try self.writeU8(@intCast(n));
    }
    fn writeBytes(self: *Writer, bytes: []const u8) EncodeError!void {
        if (self.pos + bytes.len > self.buf.len) return error.BufferTooSmall;
        @memcpy(self.buf[self.pos .. self.pos + bytes.len], bytes);
        self.pos += bytes.len;
    }
};

const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    fn done(self: *const Reader) bool {
        return self.pos == self.buf.len;
    }
    fn readU8(self: *Reader) DecodeError!u8 {
        if (self.pos >= self.buf.len) return error.Truncated;
        const byte = self.buf[self.pos];
        self.pos += 1;
        return byte;
    }
    fn readU64(self: *Reader) DecodeError!u64 {
        if (self.pos + 8 > self.buf.len) return error.Truncated;
        var value: u64 = 0;
        var idx: usize = 0;
        while (idx < 8) : (idx += 1) {
            value |= @as(u64, self.buf[self.pos + idx]) << @as(u6, @intCast(idx * 8));
        }
        self.pos += 8;
        return value;
    }
    fn readVarint(self: *Reader) DecodeError!usize {
        var value: u64 = 0;
        var i: usize = 0;
        while (i < varint_max) : (i += 1) {
            const byte = try self.readU8();
            value |= @as(u64, byte & 0x7f) << @as(u6, @intCast(i * 7));
            if ((byte & 0x80) == 0) {
                if (value > std.math.maxInt(usize)) return error.Oversize;
                return @intCast(value);
            }
        }
        return error.VarintTooLong;
    }
    fn readFixed(self: *Reader, len: usize) DecodeError![]const u8 {
        if (self.pos + len > self.buf.len) return error.Truncated;
        const bytes = self.buf[self.pos .. self.pos + len];
        self.pos += len;
        return bytes;
    }
};

test "Suimyaku mesh member_compact round-trips context frontier and adds" {
    var ctx = [_]Entry{
        .{ .replica = 1, .counter = 900 },
        .{ .replica = 7, .counter = 3 },
    };
    var adds: [1][add_value_len]u8 = undefined;
    // replica8, counter8, hlc8, status1
    @memset(&adds[0], 0);
    adds[0][0] = 1; // replica = 1 (LE)
    adds[0][8] = 0x84; // counter low byte = 900 & 0xff
    adds[0][9] = 0x03; // counter high byte -> 0x0384 == 900
    adds[0][24] = 0x02; // some status bits

    var buf: [max_bytes]u8 = undefined;
    const bytes = try encode(&buf, 42, 0, ctx[0..], adds[0..]);
    try std.testing.expect(matches(bytes));

    const v = try decode(bytes);
    try std.testing.expectEqual(@as(u64, 42), v.member_id);
    try std.testing.expectEqual(@as(u64, 0), v.hlc_key);
    try std.testing.expectEqual(@as(usize, 2), v.context_len);
    try std.testing.expectEqual(@as(u64, 1), v.context[0].replica);
    try std.testing.expectEqual(@as(u64, 900), v.context[0].counter);
    try std.testing.expectEqual(@as(u64, 7), v.context[1].replica);
    try std.testing.expectEqual(@as(u64, 3), v.context[1].counter);
    try std.testing.expectEqual(@as(usize, 1), v.adds_len);
    try std.testing.expectEqualSlices(u8, &adds[0], &v.adds[0]);
}

test "Suimyaku mesh member_compact rejects malformed frames fail-closed" {
    var buf: [max_bytes]u8 = undefined;
    var ctx = [_]Entry{.{ .replica = 1, .counter = 5 }};
    const bytes = try encode(&buf, 1, 0, ctx[0..], &.{});

    // Wrong magic.
    var bad_magic = buf;
    bad_magic[0] = 'X';
    try std.testing.expectError(error.BadMagic, decode(bad_magic[0..bytes.len]));

    // Truncated.
    try std.testing.expectError(error.Truncated, decode(bytes[0 .. bytes.len - 1]));

    // Trailing bytes.
    var trailing: [max_bytes + 1]u8 = undefined;
    @memcpy(trailing[0..bytes.len], bytes);
    trailing[bytes.len] = 0;
    try std.testing.expectError(error.TrailingBytes, decode(trailing[0 .. bytes.len + 1]));

    // Zero-counter context entry is rejected.
    var zero = buf;
    // context entry counter occupies 8 bytes right after: magic(4)+ver(1)+id(8)+hlc(8)+ctxlen varint(1)+replica(8)
    const counter_off = magic.len + 1 + 8 + 8 + 1 + 8;
    @memset(zero[counter_off .. counter_off + 8], 0);
    try std.testing.expectError(error.InvalidMember, decode(zero[0..bytes.len]));
}

test "Suimyaku mesh member_compact encode rejects oversize context and adds" {
    var buf: [max_bytes]u8 = undefined;
    var big_ctx: [max_context + 1]Entry = undefined;
    for (&big_ctx, 0..) |*e, i| e.* = .{ .replica = i, .counter = 1 };
    try std.testing.expectError(error.Oversize, encode(&buf, 1, 0, big_ctx[0..], &.{}));
}

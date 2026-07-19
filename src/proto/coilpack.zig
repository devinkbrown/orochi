// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! CoilPack low-level wire primitives.
//!
//! CoilPack is Onyx Server's canonical, self-describing, signature-stable binary
//! format. This file intentionally stays at the atom layer that Codec Loom
//! will emit: little-endian fixed integers, minimal unsigned LEB128 varints,
//! length-prefixed byte strings, booleans, and the fixed UNDERTOW frame header.
const std = @import("std");

pub const max_varint_bytes = 10;
pub const undertow_header_len = 8;

pub const DecodeError = error{
    Truncated,
    VarintTooLong,
    VarintOverflow,
    NonCanonicalVarint,
    LengthTooLarge,
    InvalidBool,
};

pub const EncodeError = error{
    BufferTooSmall,
};

/// Canonical equivalence note: after values are encoded by these primitives,
/// `canonicalEqual(a,b)` is byte equality. Decoders reject non-minimal varints,
/// so two accepted encodings for the same CoilPack atom cannot differ only by
/// varint spelling.
pub fn canonicalEqual(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

/// Cbs-style reader over a caller-owned immutable byte slice.
pub const Cbs = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn init(buf: []const u8) Cbs {
        return .{ .buf = buf };
    }

    pub fn remaining(self: *const Cbs) usize {
        return self.buf.len - self.pos;
    }

    pub fn done(self: *const Cbs) bool {
        return self.pos == self.buf.len;
    }

    pub fn readU8(self: *Cbs) DecodeError!u8 {
        if (self.remaining() < 1) return error.Truncated;
        const v = self.buf[self.pos];
        self.pos += 1;
        return v;
    }

    pub fn readU16Le(self: *Cbs) DecodeError!u16 {
        if (self.remaining() < 2) return error.Truncated;
        const p = self.pos;
        self.pos += 2;
        return @as(u16, self.buf[p]) |
            (@as(u16, self.buf[p + 1]) << 8);
    }

    pub fn readU24Le(self: *Cbs) DecodeError!u24 {
        if (self.remaining() < 3) return error.Truncated;
        const p = self.pos;
        self.pos += 3;
        return @as(u24, self.buf[p]) |
            (@as(u24, self.buf[p + 1]) << 8) |
            (@as(u24, self.buf[p + 2]) << 16);
    }

    pub fn readU32Le(self: *Cbs) DecodeError!u32 {
        if (self.remaining() < 4) return error.Truncated;
        const p = self.pos;
        self.pos += 4;
        return @as(u32, self.buf[p]) |
            (@as(u32, self.buf[p + 1]) << 8) |
            (@as(u32, self.buf[p + 2]) << 16) |
            (@as(u32, self.buf[p + 3]) << 24);
    }

    pub fn readU64Le(self: *Cbs) DecodeError!u64 {
        if (self.remaining() < 8) return error.Truncated;
        const p = self.pos;
        self.pos += 8;
        return @as(u64, self.buf[p]) |
            (@as(u64, self.buf[p + 1]) << 8) |
            (@as(u64, self.buf[p + 2]) << 16) |
            (@as(u64, self.buf[p + 3]) << 24) |
            (@as(u64, self.buf[p + 4]) << 32) |
            (@as(u64, self.buf[p + 5]) << 40) |
            (@as(u64, self.buf[p + 6]) << 48) |
            (@as(u64, self.buf[p + 7]) << 56);
    }

    pub fn readBool(self: *Cbs) DecodeError!bool {
        return switch (try self.readU8()) {
            0 => false,
            1 => true,
            else => error.InvalidBool,
        };
    }

    pub fn readVarint(self: *Cbs) DecodeError!u64 {
        var p = self.pos;
        var value: u64 = 0;

        var i: usize = 0;
        while (i < max_varint_bytes) : (i += 1) {
            if (p >= self.buf.len) return error.Truncated;

            const byte = self.buf[p];
            p += 1;
            const payload = byte & 0x7f;

            if (i == max_varint_bytes - 1 and payload > 1) {
                return error.VarintOverflow;
            }

            value |= @as(u64, payload) << @as(u6, @intCast(i * 7));

            if ((byte & 0x80) == 0) {
                const encoded_len = i + 1;
                if (encoded_len != varintLen(value)) {
                    return error.NonCanonicalVarint;
                }
                self.pos = p;
                return value;
            }
        }

        return error.VarintTooLong;
    }

    pub fn readBytes(self: *Cbs) DecodeError![]const u8 {
        const start = self.pos;
        const len64 = self.readVarint() catch |err| {
            self.pos = start;
            return err;
        };
        if (len64 > @as(u64, std.math.maxInt(usize))) {
            self.pos = start;
            return error.LengthTooLarge;
        }

        const len: usize = @intCast(len64);
        if (self.remaining() < len) {
            self.pos = start;
            return error.Truncated;
        }

        const p = self.pos;
        self.pos += len;
        return self.buf[p..self.pos];
    }
};

/// Cbb-style writer into a caller-provided byte slice.
pub const Cbb = struct {
    buf: []u8,
    pos: usize = 0,

    pub fn init(buf: []u8) Cbb {
        return .{ .buf = buf };
    }

    pub fn bytesWritten(self: *const Cbb) usize {
        return self.pos;
    }

    pub fn written(self: *const Cbb) []const u8 {
        return self.buf[0..self.pos];
    }

    pub fn remaining(self: *const Cbb) usize {
        return self.buf.len - self.pos;
    }

    pub fn writeU8(self: *Cbb, value: u8) EncodeError!usize {
        try self.ensure(1);
        self.buf[self.pos] = value;
        self.pos += 1;
        return 1;
    }

    pub fn writeU16Le(self: *Cbb, value: u16) EncodeError!usize {
        try self.ensure(2);
        const p = self.pos;
        self.buf[p] = @intCast(value & 0xff);
        self.buf[p + 1] = @intCast(value >> 8);
        self.pos += 2;
        return 2;
    }

    pub fn writeU24Le(self: *Cbb, value: u24) EncodeError!usize {
        try self.ensure(3);
        const p = self.pos;
        self.buf[p] = @intCast(value & 0xff);
        self.buf[p + 1] = @intCast((value >> 8) & 0xff);
        self.buf[p + 2] = @intCast(value >> 16);
        self.pos += 3;
        return 3;
    }

    pub fn writeU32Le(self: *Cbb, value: u32) EncodeError!usize {
        try self.ensure(4);
        const p = self.pos;
        self.buf[p] = @intCast(value & 0xff);
        self.buf[p + 1] = @intCast((value >> 8) & 0xff);
        self.buf[p + 2] = @intCast((value >> 16) & 0xff);
        self.buf[p + 3] = @intCast(value >> 24);
        self.pos += 4;
        return 4;
    }

    pub fn writeU64Le(self: *Cbb, value: u64) EncodeError!usize {
        try self.ensure(8);
        const p = self.pos;
        self.buf[p] = @intCast(value & 0xff);
        self.buf[p + 1] = @intCast((value >> 8) & 0xff);
        self.buf[p + 2] = @intCast((value >> 16) & 0xff);
        self.buf[p + 3] = @intCast((value >> 24) & 0xff);
        self.buf[p + 4] = @intCast((value >> 32) & 0xff);
        self.buf[p + 5] = @intCast((value >> 40) & 0xff);
        self.buf[p + 6] = @intCast((value >> 48) & 0xff);
        self.buf[p + 7] = @intCast(value >> 56);
        self.pos += 8;
        return 8;
    }

    pub fn writeBool(self: *Cbb, value: bool) EncodeError!usize {
        return self.writeU8(if (value) 1 else 0);
    }

    pub fn writeVarint(self: *Cbb, value: u64) EncodeError!usize {
        const needed = varintLen(value);
        try self.ensure(needed);

        var n = value;
        const start = self.pos;
        while (n >= 0x80) {
            self.buf[self.pos] = @as(u8, @intCast(n & 0x7f)) | 0x80;
            self.pos += 1;
            n >>= 7;
        }
        self.buf[self.pos] = @intCast(n);
        self.pos += 1;
        return self.pos - start;
    }

    pub fn writeBytes(self: *Cbb, bytes: []const u8) EncodeError!usize {
        const needed = varintLen(bytes.len) + bytes.len;
        try self.ensure(needed);

        const start = self.pos;
        _ = try self.writeVarint(bytes.len);
        @memcpy(self.buf[self.pos .. self.pos + bytes.len], bytes);
        self.pos += bytes.len;
        return self.pos - start;
    }

    fn ensure(self: *const Cbb, len: usize) EncodeError!void {
        if (len > self.remaining()) return error.BufferTooSmall;
    }
};

pub const UndertowHeader = struct {
    type: u8,
    ctrl: u8,
    length: u16,
    stream_id: u24,
    hop: u8,
};

/// Encode the native 8-byte UNDERTOW frame header:
/// type:u8, ctrl:u8, length:u16-LE, stream_id:u24-LE, hop:u8.
pub fn encodeHeader(out: []u8, header: UndertowHeader) EncodeError!usize {
    if (out.len < undertow_header_len) return error.BufferTooSmall;

    var w = Cbb.init(out);
    _ = try w.writeU8(header.type);
    _ = try w.writeU8(header.ctrl);
    _ = try w.writeU16Le(header.length);
    _ = try w.writeU24Le(header.stream_id);
    _ = try w.writeU8(header.hop);
    return w.bytesWritten();
}

/// Decode the native 8-byte UNDERTOW frame header from the front of `in`.
pub fn decodeHeader(in: []const u8) DecodeError!UndertowHeader {
    if (in.len < undertow_header_len) return error.Truncated;

    var r = Cbs.init(in[0..undertow_header_len]);
    return .{
        .type = try r.readU8(),
        .ctrl = try r.readU8(),
        .length = try r.readU16Le(),
        .stream_id = try r.readU24Le(),
        .hop = try r.readU8(),
    };
}

fn varintLen(value: u64) usize {
    var n = value;
    var len: usize = 1;
    while (n >= 0x80) : (len += 1) {
        n >>= 7;
    }
    return len;
}

test "fixed primitives and bool round-trip" {
    var out: [32]u8 = undefined;
    var w = Cbb.init(&out);

    try std.testing.expectEqual(@as(usize, 1), try w.writeU8(0xab));
    try std.testing.expectEqual(@as(usize, 2), try w.writeU16Le(0x1234));
    try std.testing.expectEqual(@as(usize, 3), try w.writeU24Le(0xabcdef));
    try std.testing.expectEqual(@as(usize, 4), try w.writeU32Le(0x89abcdef));
    try std.testing.expectEqual(@as(usize, 8), try w.writeU64Le(0x0123456789abcdef));
    try std.testing.expectEqual(@as(usize, 1), try w.writeBool(false));
    try std.testing.expectEqual(@as(usize, 1), try w.writeBool(true));

    var r = Cbs.init(w.written());
    try std.testing.expectEqual(@as(u8, 0xab), try r.readU8());
    try std.testing.expectEqual(@as(u16, 0x1234), try r.readU16Le());
    try std.testing.expectEqual(@as(u24, 0xabcdef), try r.readU24Le());
    try std.testing.expectEqual(@as(u32, 0x89abcdef), try r.readU32Le());
    try std.testing.expectEqual(@as(u64, 0x0123456789abcdef), try r.readU64Le());
    try std.testing.expectEqual(false, try r.readBool());
    try std.testing.expectEqual(true, try r.readBool());
    try std.testing.expect(r.done());
}

test "unsigned varint canonical round-trips at boundaries" {
    const values = [_]u64{
        0,
        1,
        2,
        0x7f,
        0x80,
        0x81,
        0x3fff,
        0x4000,
        0xffff,
        0x1_0000,
        0xffff_ffff,
        0x1_0000_0000,
        std.math.maxInt(u64),
    };

    for (values) |value| {
        var out: [max_varint_bytes]u8 = undefined;
        var w = Cbb.init(&out);
        const written = try w.writeVarint(value);
        try std.testing.expectEqual(varintLen(value), written);

        var r = Cbs.init(w.written());
        try std.testing.expectEqual(value, try r.readVarint());
        try std.testing.expect(r.done());
    }
}

test "length-prefixed bytes cover empty 127 and 128 byte payloads" {
    var payload127: [127]u8 = undefined;
    for (&payload127, 0..) |*b, i| b.* = @intCast(i);

    var payload128: [128]u8 = undefined;
    for (&payload128, 0..) |*b, i| b.* = @intCast(255 - i);

    var out: [300]u8 = undefined;
    var w = Cbb.init(&out);
    try std.testing.expectEqual(@as(usize, 1), try w.writeBytes(""));
    try std.testing.expectEqual(@as(usize, 128), try w.writeBytes(&payload127));
    try std.testing.expectEqual(@as(usize, 130), try w.writeBytes(&payload128));

    var r = Cbs.init(w.written());
    try std.testing.expectEqualSlices(u8, "", try r.readBytes());
    try std.testing.expectEqualSlices(u8, &payload127, try r.readBytes());
    try std.testing.expectEqualSlices(u8, &payload128, try r.readBytes());
    try std.testing.expect(r.done());
}

test "writer rejects too-small buffers without advancing that write" {
    var one: [1]u8 = undefined;
    var fixed = Cbb.init(&one);
    try std.testing.expectError(error.BufferTooSmall, fixed.writeU16Le(0x1234));
    try std.testing.expectEqual(@as(usize, 0), fixed.bytesWritten());

    var bytes = Cbb.init(&one);
    try std.testing.expectError(error.BufferTooSmall, bytes.writeBytes("x"));
    try std.testing.expectEqual(@as(usize, 0), bytes.bytesWritten());
}

test "varint decoder rejects truncated oversize and non-canonical encodings" {
    var truncated = Cbs.init(&.{0x80});
    try std.testing.expectError(error.Truncated, truncated.readVarint());
    try std.testing.expectEqual(@as(usize, 0), truncated.pos);

    var too_long = Cbs.init(&.{ 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x81 });
    try std.testing.expectError(error.VarintTooLong, too_long.readVarint());
    try std.testing.expectEqual(@as(usize, 0), too_long.pos);

    var overflow = Cbs.init(&.{ 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02 });
    try std.testing.expectError(error.VarintOverflow, overflow.readVarint());
    try std.testing.expectEqual(@as(usize, 0), overflow.pos);

    var zero_overlong = Cbs.init(&.{ 0x80, 0x00 });
    try std.testing.expectError(error.NonCanonicalVarint, zero_overlong.readVarint());
    try std.testing.expectEqual(@as(usize, 0), zero_overlong.pos);

    var one_overlong = Cbs.init(&.{ 0x81, 0x00 });
    try std.testing.expectError(error.NonCanonicalVarint, one_overlong.readVarint());
    try std.testing.expectEqual(@as(usize, 0), one_overlong.pos);
}

test "length-prefixed bytes reject truncated payload and rewind to start" {
    var r = Cbs.init(&.{ 3, 'a', 'b' });
    try std.testing.expectError(error.Truncated, r.readBytes());
    try std.testing.expectEqual(@as(usize, 0), r.pos);
}

test "bool decoder rejects non canonical bool bytes" {
    var r = Cbs.init(&.{2});
    try std.testing.expectError(error.InvalidBool, r.readBool());
}

test "canonical equal is byte equality for canonical encodings" {
    var a_buf: [max_varint_bytes]u8 = undefined;
    var b_buf: [max_varint_bytes]u8 = undefined;
    var a = Cbb.init(&a_buf);
    var b = Cbb.init(&b_buf);
    _ = try a.writeVarint(300);
    _ = try b.writeVarint(300);

    try std.testing.expect(canonicalEqual(a.written(), b.written()));
    try std.testing.expect(!canonicalEqual(a.written(), &.{ 0xac, 0x82, 0x00 }));
}

test "UNDERTOW header encode and decode" {
    const header = UndertowHeader{
        .type = 0x23,
        .ctrl = 0x45,
        .length = 0x1234,
        .stream_id = 0x00c0de,
        .hop = 0x07,
    };

    var out: [undertow_header_len]u8 = undefined;
    try std.testing.expectEqual(@as(usize, undertow_header_len), try encodeHeader(&out, header));
    try std.testing.expectEqualSlices(u8, &.{ 0x23, 0x45, 0x34, 0x12, 0xde, 0xc0, 0x00, 0x07 }, &out);

    const decoded = try decodeHeader(&out);
    try std.testing.expectEqual(header.type, decoded.type);
    try std.testing.expectEqual(header.ctrl, decoded.ctrl);
    try std.testing.expectEqual(header.length, decoded.length);
    try std.testing.expectEqual(header.stream_id, decoded.stream_id);
    try std.testing.expectEqual(header.hop, decoded.hop);
}

test "UNDERTOW header codec rejects short buffers" {
    var out: [undertow_header_len - 1]u8 = undefined;
    try std.testing.expectError(error.BufferTooSmall, encodeHeader(&out, .{
        .type = 1,
        .ctrl = 2,
        .length = 3,
        .stream_id = 4,
        .hop = 5,
    }));

    try std.testing.expectError(error.Truncated, decodeHeader(&.{ 1, 2, 3, 4, 5, 6, 7 }));
}

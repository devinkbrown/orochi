// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

const std = @import("std");

const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const pad_char: u8 = '=';

/// RFC 4648 base32 encoder padding behavior.
pub const Padding = enum(u1) {
    omit,
    include,
};

/// RFC 4648 base32 decoder padding policy.
pub const PaddingMode = enum(u2) {
    forbidden,
    optional,
    required,
};

/// RFC 4648 base32 codec limits and defaults.
pub const Params = struct {
    encode_padding: Padding = .include,
    decode_padding: PaddingMode = .optional,
};

/// RFC 4648 base32 encode/decode errors.
pub const Base32Error = error{
    OutputTooSmall,
    InvalidCharacter,
    InvalidPadding,
    InvalidLength,
    NonZeroTrailingBits,
};

/// Allocation-free RFC 4648 base32 codec using the standard alphabet.
pub const Codec = struct {
    params: Params,

    /// Initializes a base32 codec with the supplied parameters.
    pub fn init(params: Params) Codec {
        return .{ .params = params };
    }

    /// Releases codec resources.
    pub fn deinit(self: *Codec) void {
        self.* = undefined;
    }

    /// Returns the encoded byte count for an input length.
    pub fn encodedLen(self: *const Codec, input_len: usize) usize {
        return encodedLenWithPadding(input_len, self.params.encode_padding);
    }

    /// Returns the decoded byte count after validating alphabet and padding.
    pub fn decodedLen(self: *const Codec, input: []const u8) Base32Error!usize {
        return decodedLenWithPadding(input, self.params.decode_padding);
    }

    /// Encodes bytes into the caller-owned output buffer.
    pub fn encode(self: *const Codec, input: []const u8, out: []u8) Base32Error![]const u8 {
        return encodeWithPadding(input, out, self.params.encode_padding);
    }

    /// Decodes bytes into the caller-owned output buffer.
    pub fn decode(self: *const Codec, input: []const u8, out: []u8) Base32Error![]const u8 {
        return decodeWithPadding(input, out, self.params.decode_padding);
    }
};

/// Returns the RFC 4648 base32 encoded byte count for an input length.
pub fn encodedLen(input_len: usize, padding: Padding) usize {
    return encodedLenWithPadding(input_len, padding);
}

/// Returns the decoded byte count after validating alphabet and padding.
pub fn decodedLen(input: []const u8, padding_mode: PaddingMode) Base32Error!usize {
    return decodedLenWithPadding(input, padding_mode);
}

/// Encodes bytes with the RFC 4648 standard alphabet into a caller buffer.
pub fn encode(input: []const u8, out: []u8, padding: Padding) Base32Error![]const u8 {
    return encodeWithPadding(input, out, padding);
}

/// Decodes RFC 4648 base32 bytes from a caller buffer into a caller buffer.
pub fn decode(input: []const u8, out: []u8, padding_mode: PaddingMode) Base32Error![]const u8 {
    return decodeWithPadding(input, out, padding_mode);
}

fn encodedLenWithPadding(input_len: usize, padding: Padding) usize {
    const full_blocks = input_len / 5;
    const rem = input_len % 5;
    const tail: usize = switch (rem) {
        0 => 0,
        1 => 2,
        2 => 4,
        3 => 5,
        4 => 7,
        else => unreachable,
    };

    return switch (padding) {
        .omit => full_blocks * 8 + tail,
        .include => if (rem == 0) full_blocks * 8 else (full_blocks + 1) * 8,
    };
}

fn decodedLenWithPadding(input: []const u8, padding_mode: PaddingMode) Base32Error!usize {
    const info = try analyzeInput(input, padding_mode);
    const full_blocks = info.symbols / 8;
    const tail: usize = switch (info.symbols % 8) {
        0 => 0,
        2 => 1,
        4 => 2,
        5 => 3,
        7 => 4,
        else => unreachable,
    };

    return full_blocks * 5 + tail;
}

fn encodeWithPadding(input: []const u8, out: []u8, padding: Padding) Base32Error![]const u8 {
    const needed = encodedLenWithPadding(input.len, padding);
    if (out.len < needed) return error.OutputTooSmall;

    var src: usize = 0;
    var dst: usize = 0;

    while (input.len - src >= 5) {
        const b0 = input[src];
        const b1 = input[src + 1];
        const b2 = input[src + 2];
        const b3 = input[src + 3];
        const b4 = input[src + 4];

        out[dst] = alphabet[@as(usize, b0 >> 3)];
        out[dst + 1] = alphabet[@as(usize, ((b0 & 0x07) << 2) | (b1 >> 6))];
        out[dst + 2] = alphabet[@as(usize, (b1 >> 1) & 0x1f)];
        out[dst + 3] = alphabet[@as(usize, ((b1 & 0x01) << 4) | (b2 >> 4))];
        out[dst + 4] = alphabet[@as(usize, ((b2 & 0x0f) << 1) | (b3 >> 7))];
        out[dst + 5] = alphabet[@as(usize, (b3 >> 2) & 0x1f)];
        out[dst + 6] = alphabet[@as(usize, ((b3 & 0x03) << 3) | (b4 >> 5))];
        out[dst + 7] = alphabet[@as(usize, b4 & 0x1f)];

        src += 5;
        dst += 8;
    }

    const rem = input.len - src;
    if (rem == 0) return out[0..dst];

    const tail_written = encodeTail(input[src..], out[dst..]);
    dst += tail_written;

    return switch (padding) {
        .omit => out[0..dst],
        .include => padded: {
            while (dst < needed) : (dst += 1) {
                out[dst] = pad_char;
            }
            break :padded out[0..dst];
        },
    };
}

fn decodeWithPadding(input: []const u8, out: []u8, padding_mode: PaddingMode) Base32Error![]const u8 {
    const needed = try decodedLenWithPadding(input, padding_mode);
    if (out.len < needed) return error.OutputTooSmall;

    var acc: u16 = 0;
    var bit_count: u4 = 0;
    var written: usize = 0;

    for (input) |ch| {
        if (ch == pad_char) break;

        const value = decodeValue(ch) orelse unreachable;
        acc = (acc << 5) | value;
        bit_count += 5;

        while (bit_count >= 8) {
            bit_count -= 8;
            out[written] = @intCast(acc >> bit_count);
            written += 1;
            acc &= (@as(u16, 1) << bit_count) - 1;
        }
    }

    if (bit_count != 0 and acc != 0) return error.NonZeroTrailingBits;
    return out[0..written];
}

fn encodeTail(input: []const u8, out: []u8) usize {
    const b0 = input[0];

    out[0] = alphabet[@as(usize, b0 >> 3)];
    if (input.len == 1) {
        out[1] = alphabet[@as(usize, (b0 & 0x07) << 2)];
        return 2;
    }

    const b1 = input[1];
    out[1] = alphabet[@as(usize, ((b0 & 0x07) << 2) | (b1 >> 6))];
    out[2] = alphabet[@as(usize, (b1 >> 1) & 0x1f)];
    if (input.len == 2) {
        out[3] = alphabet[@as(usize, (b1 & 0x01) << 4)];
        return 4;
    }

    const b2 = input[2];
    out[3] = alphabet[@as(usize, ((b1 & 0x01) << 4) | (b2 >> 4))];
    out[4] = alphabet[@as(usize, (b2 & 0x0f) << 1)];

    if (input.len == 3) return 5;

    const b3 = input[3];
    out[4] = alphabet[@as(usize, ((b2 & 0x0f) << 1) | (b3 >> 7))];
    out[5] = alphabet[@as(usize, (b3 >> 2) & 0x1f)];
    out[6] = alphabet[@as(usize, (b3 & 0x03) << 3)];
    return 7;
}

fn decodeValue(ch: u8) ?u16 {
    return switch (ch) {
        'A'...'Z' => ch - 'A',
        '2'...'7' => @as(u16, 26) + (ch - '2'),
        else => null,
    };
}

fn analyzeInput(input: []const u8, padding_mode: PaddingMode) Base32Error!struct { symbols: usize, padding: usize } {
    var symbols: usize = 0;
    var padding: usize = 0;
    var seen_padding = false;

    for (input) |ch| {
        if (ch == pad_char) {
            seen_padding = true;
            padding += 1;
            continue;
        }

        if (seen_padding) return error.InvalidPadding;
        if (decodeValue(ch) == null) return error.InvalidCharacter;
        symbols += 1;
    }

    const rem = symbols % 8;
    switch (rem) {
        0, 2, 4, 5, 7 => {},
        else => return error.InvalidLength,
    }

    if (padding_mode == .forbidden and padding != 0) return error.InvalidPadding;
    if (padding_mode == .required and symbols != 0 and rem != 0 and padding == 0) return error.InvalidPadding;

    if (padding != 0) {
        if (input.len % 8 != 0) return error.InvalidPadding;
        const expected = paddingForSymbolRemainder(rem);
        if (expected == 0 or padding != expected) return error.InvalidPadding;
    }

    return .{ .symbols = symbols, .padding = padding };
}

fn paddingForSymbolRemainder(rem: usize) usize {
    return switch (rem) {
        0 => 0,
        2 => 6,
        4 => 4,
        5 => 3,
        7 => 1,
        else => unreachable,
    };
}

test "base32 encode matches RFC 4648 padded vectors" {
    const allocator = std.testing.allocator;
    const vectors = [_]struct {
        plain: []const u8,
        padded: []const u8,
    }{
        .{ .plain = "", .padded = "" },
        .{ .plain = "f", .padded = "MY======" },
        .{ .plain = "fo", .padded = "MZXQ====" },
        .{ .plain = "foo", .padded = "MZXW6===" },
        .{ .plain = "foob", .padded = "MZXW6YQ=" },
        .{ .plain = "fooba", .padded = "MZXW6YTB" },
        .{ .plain = "foobar", .padded = "MZXW6YTBOI======" },
    };

    for (vectors) |vector| {
        // Arrange.
        const needed = encodedLen(vector.plain.len, .include);
        const out = try allocator.alloc(u8, needed);
        defer allocator.free(out);

        // Act.
        const got = try encode(vector.plain, out, .include);

        // Assert.
        try std.testing.expectEqual(vector.padded.len, needed);
        try std.testing.expectEqualSlices(u8, vector.padded, got);
    }
}

test "base32 encode matches RFC 4648 unpadded vectors" {
    const allocator = std.testing.allocator;
    const vectors = [_]struct {
        plain: []const u8,
        unpadded: []const u8,
    }{
        .{ .plain = "", .unpadded = "" },
        .{ .plain = "f", .unpadded = "MY" },
        .{ .plain = "fo", .unpadded = "MZXQ" },
        .{ .plain = "foo", .unpadded = "MZXW6" },
        .{ .plain = "foob", .unpadded = "MZXW6YQ" },
        .{ .plain = "fooba", .unpadded = "MZXW6YTB" },
        .{ .plain = "foobar", .unpadded = "MZXW6YTBOI" },
    };

    for (vectors) |vector| {
        // Arrange.
        const needed = encodedLen(vector.plain.len, .omit);
        const out = try allocator.alloc(u8, needed);
        defer allocator.free(out);

        // Act.
        const got = try encode(vector.plain, out, .omit);

        // Assert.
        try std.testing.expectEqual(vector.unpadded.len, needed);
        try std.testing.expectEqualSlices(u8, vector.unpadded, got);
    }
}

test "base32 decode accepts padded and unpadded RFC 4648 vectors" {
    const allocator = std.testing.allocator;
    const vectors = [_]struct {
        plain: []const u8,
        padded: []const u8,
        unpadded: []const u8,
    }{
        .{ .plain = "", .padded = "", .unpadded = "" },
        .{ .plain = "f", .padded = "MY======", .unpadded = "MY" },
        .{ .plain = "fo", .padded = "MZXQ====", .unpadded = "MZXQ" },
        .{ .plain = "foo", .padded = "MZXW6===", .unpadded = "MZXW6" },
        .{ .plain = "foob", .padded = "MZXW6YQ=", .unpadded = "MZXW6YQ" },
        .{ .plain = "fooba", .padded = "MZXW6YTB", .unpadded = "MZXW6YTB" },
        .{ .plain = "foobar", .padded = "MZXW6YTBOI======", .unpadded = "MZXW6YTBOI" },
    };

    for (vectors) |vector| {
        // Arrange.
        const padded_out = try allocator.alloc(u8, try decodedLen(vector.padded, .optional));
        defer allocator.free(padded_out);
        const unpadded_out = try allocator.alloc(u8, try decodedLen(vector.unpadded, .optional));
        defer allocator.free(unpadded_out);

        // Act.
        const padded_got = try decode(vector.padded, padded_out, .optional);
        const unpadded_got = try decode(vector.unpadded, unpadded_out, .optional);

        // Assert.
        try std.testing.expectEqualSlices(u8, vector.plain, padded_got);
        try std.testing.expectEqualSlices(u8, vector.plain, unpadded_got);
    }
}

test "base32 codec wrapper uses configured padding modes" {
    const allocator = std.testing.allocator;

    // Arrange.
    var codec = Codec.init(.{ .encode_padding = .omit, .decode_padding = .forbidden });
    defer codec.deinit();
    const encoded = try allocator.alloc(u8, codec.encodedLen("foo".len));
    defer allocator.free(encoded);
    const decoded = try allocator.alloc(u8, "foo".len);
    defer allocator.free(decoded);

    // Act.
    const enc = try codec.encode("foo", encoded);
    const dec = try codec.decode(enc, decoded);

    // Assert.
    try std.testing.expectEqualSlices(u8, "MZXW6", enc);
    try std.testing.expectEqualSlices(u8, "foo", dec);
    try std.testing.expectError(error.InvalidPadding, codec.decode("MZXW6===", decoded));
}

test "base32 decode rejects invalid characters lengths padding and trailing bits" {
    const allocator = std.testing.allocator;

    // Arrange.
    const out = try allocator.alloc(u8, 16);
    defer allocator.free(out);

    // Act and assert.
    try std.testing.expectError(error.InvalidCharacter, decodedLen("my======", .optional));
    try std.testing.expectError(error.InvalidLength, decodedLen("M", .optional));
    try std.testing.expectError(error.InvalidPadding, decodedLen("MZXW6=AA", .optional));
    try std.testing.expectError(error.InvalidPadding, decodedLen("MZXW6===", .forbidden));
    try std.testing.expectError(error.InvalidPadding, decodedLen("MZXW6", .required));
    try std.testing.expectError(error.NonZeroTrailingBits, decode("MZ======", out, .optional));
}

test "base32 encode and decode report small output buffers" {
    const allocator = std.testing.allocator;

    // Arrange.
    const tiny_encoded = try allocator.alloc(u8, 4);
    defer allocator.free(tiny_encoded);
    const tiny_decoded = try allocator.alloc(u8, 2);
    defer allocator.free(tiny_decoded);

    // Act and assert.
    try std.testing.expectError(error.OutputTooSmall, encode("foo", tiny_encoded, .include));
    try std.testing.expectError(error.OutputTooSmall, decode("MZXW6===", tiny_decoded, .optional));
}

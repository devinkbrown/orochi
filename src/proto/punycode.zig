// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

const std = @import("std");

const base: u64 = 36;
const tmin: u64 = 1;
const tmax: u64 = 26;
const skew: u64 = 38;
const damp: u64 = 700;
const initial_bias: u64 = 72;
const initial_n: u64 = 128;
const delimiter: u8 = '-';
const max_scalar: u64 = 0x10ffff;

/// Compile-time bounds for single-label Punycode operations.
pub const Params = struct {
    /// Maximum UTF-8 bytes accepted for a decoded label.
    max_input_bytes: usize = 255,
    /// Maximum ASCII bytes emitted or accepted for a raw Punycode payload.
    max_punycode_bytes: usize = 63,
    /// Maximum Unicode scalar values accepted in one label.
    max_code_points: usize = 255,
};

/// Typed failures reported by the allocation-free Punycode codec.
pub const PunycodeError = error{
    EmptyLabel,
    InvalidInput,
    InvalidUtf8,
    InvalidCodePoint,
    LabelTooLong,
    OutputTooSmall,
    Overflow,
};

/// Returns a stateless RFC 3492 Punycode codec with compile-time limits.
pub fn Codec(comptime params: Params) type {
    comptime {
        if (params.max_input_bytes == 0) @compileError("Punycode labels need UTF-8 byte storage");
        if (params.max_punycode_bytes == 0) @compileError("Punycode labels need ASCII byte storage");
        if (params.max_code_points == 0) @compileError("Punycode labels need scalar storage");
    }

    return struct {
        const Self = @This();

        /// Initializes a stateless codec value.
        pub fn init() Self {
            return .{};
        }

        /// Releases codec state.
        pub fn deinit(self: *Self) void {
            self.* = undefined;
        }

        /// Encodes one UTF-8 label into a raw RFC 3492 Punycode payload.
        pub fn encode(self: *const Self, input: []const u8, out: []u8) PunycodeError![]const u8 {
            _ = self;
            return encodeWith(params, input, out);
        }

        /// Decodes one raw RFC 3492 Punycode payload into a UTF-8 label.
        pub fn decode(self: *const Self, input: []const u8, out: []u8) PunycodeError![]const u8 {
            _ = self;
            return decodeWith(params, input, out);
        }
    };
}

/// Default Punycode codec using DNS-sized encoded labels.
pub const DefaultCodec = Codec(.{});

/// Encodes one UTF-8 label into a raw RFC 3492 Punycode payload.
pub fn encode(input: []const u8, out: []u8) PunycodeError![]const u8 {
    return encodeWith(.{}, input, out);
}

/// Decodes one raw RFC 3492 Punycode payload into a UTF-8 label.
pub fn decode(input: []const u8, out: []u8) PunycodeError![]const u8 {
    return decodeWith(.{}, input, out);
}

/// Encodes one UTF-8 label into Punycode using caller-supplied bounds.
pub fn encodeWith(comptime params: Params, input: []const u8, out: []u8) PunycodeError![]const u8 {
    if (input.len == 0) return error.EmptyLabel;
    if (input.len > params.max_input_bytes) return error.LabelTooLong;

    var scalars: [params.max_code_points]u21 = undefined;
    const scalar_count = try decodeUtf8Label(params, input, &scalars);

    var out_len: usize = 0;
    var basic_count: usize = 0;
    for (scalars[0..scalar_count]) |scalar| {
        if (scalar < initial_n) {
            const byte: u8 = @intCast(scalar);
            if (!validBasicLabelByte(byte)) return error.InvalidInput;
            try appendPunycodeByte(params, out, &out_len, byte);
            basic_count += 1;
        }
    }

    if (basic_count > 0 and basic_count < scalar_count) {
        try appendPunycodeByte(params, out, &out_len, delimiter);
    }
    if (basic_count == scalar_count) return out[0..out_len];

    var n: u64 = initial_n;
    var delta: u64 = 0;
    var bias: u64 = initial_bias;
    var handled: usize = basic_count;

    while (handled < scalar_count) {
        var next: u64 = std.math.maxInt(u64);
        for (scalars[0..scalar_count]) |scalar| {
            const value: u64 = scalar;
            if (value >= n and value < next) next = value;
        }
        if (next == std.math.maxInt(u64)) return error.InvalidCodePoint;

        const span: u64 = @intCast(handled + 1);
        const step = try checkedMul(try checkedSub(next, n), span);
        delta = try checkedAdd(delta, step);
        n = next;

        for (scalars[0..scalar_count]) |scalar| {
            const value: u64 = scalar;
            if (value < n) {
                delta = try checkedAdd(delta, 1);
            } else if (value == n) {
                var q = delta;
                var k: u64 = base;
                while (true) : (k = try checkedAdd(k, base)) {
                    const threshold = biasThreshold(k, bias);
                    if (q < threshold) break;
                    const digit = threshold + ((q - threshold) % (base - threshold));
                    try appendPunycodeByte(params, out, &out_len, encodeDigit(digit));
                    q = (q - threshold) / (base - threshold);
                }
                try appendPunycodeByte(params, out, &out_len, encodeDigit(q));
                bias = adapt(delta, @intCast(handled + 1), handled == basic_count);
                delta = 0;
                handled += 1;
            }
        }

        delta = try checkedAdd(delta, 1);
        n = try checkedAdd(n, 1);
        if (n > max_scalar and handled < scalar_count) return error.InvalidCodePoint;
    }

    return out[0..out_len];
}

/// Decodes one raw Punycode payload into UTF-8 using caller-supplied bounds.
pub fn decodeWith(comptime params: Params, input: []const u8, out: []u8) PunycodeError![]const u8 {
    if (input.len == 0) return error.EmptyLabel;
    if (input.len > params.max_punycode_bytes) return error.LabelTooLong;

    var scalars: [params.max_code_points]u21 = undefined;
    var scalar_count: usize = 0;
    var input_index: usize = 0;

    if (lastDelimiter(input)) |basic_end| {
        if (basic_end == input.len - 1) return error.InvalidInput;
        for (input[0..basic_end]) |byte| {
            if (!validBasicLabelByte(byte)) return error.InvalidInput;
            try appendScalar(params, &scalars, &scalar_count, byte);
        }
        input_index = basic_end + 1;
    }

    var n: u64 = initial_n;
    var i: u64 = 0;
    var bias: u64 = initial_bias;

    while (input_index < input.len) {
        const old_i = i;
        var weight: u64 = 1;
        var k: u64 = base;

        while (true) : (k = try checkedAdd(k, base)) {
            if (input_index >= input.len) return error.InvalidInput;
            const digit = decodeDigit(input[input_index]) orelse return error.InvalidInput;
            input_index += 1;

            i = try checkedAdd(i, try checkedMul(@intCast(digit), weight));
            const threshold = biasThreshold(k, bias);
            if (digit < threshold) break;
            weight = try checkedMul(weight, base - threshold);
        }

        const next_count: u64 = @intCast(scalar_count + 1);
        bias = adapt(try checkedSub(i, old_i), next_count, old_i == 0);
        n = try checkedAdd(n, i / next_count);
        if (n > max_scalar or isSurrogate(n)) return error.InvalidCodePoint;

        const insert_at: usize = @intCast(i % next_count);
        try insertScalar(params, &scalars, &scalar_count, insert_at, @intCast(n));
        i = try checkedAdd(@intCast(insert_at), 1);
    }

    var out_len: usize = 0;
    for (scalars[0..scalar_count]) |scalar| {
        try appendUtf8(params, out, &out_len, scalar);
    }
    return out[0..out_len];
}

fn decodeUtf8Label(comptime params: Params, input: []const u8, out: *[params.max_code_points]u21) PunycodeError!usize {
    var cursor: usize = 0;
    var count: usize = 0;
    while (cursor < input.len) {
        const scalar = try readUtf8(input, &cursor);
        if (scalar == '.') return error.InvalidInput;
        try appendScalar(params, out, &count, scalar);
    }
    return count;
}

fn readUtf8(input: []const u8, cursor: *usize) PunycodeError!u21 {
    const first = input[cursor.*];
    if (first < 0x80) {
        cursor.* += 1;
        return @intCast(first);
    }

    var needed: usize = 0;
    var value: u32 = 0;
    var minimum: u32 = 0;
    if (first >= 0xc2 and first <= 0xdf) {
        needed = 2;
        value = first & 0x1f;
        minimum = 0x80;
    } else if (first >= 0xe0 and first <= 0xef) {
        needed = 3;
        value = first & 0x0f;
        minimum = 0x800;
    } else if (first >= 0xf0 and first <= 0xf4) {
        needed = 4;
        value = first & 0x07;
        minimum = 0x10000;
    } else {
        return error.InvalidUtf8;
    }

    if (cursor.* + needed > input.len) return error.InvalidUtf8;
    var index = cursor.* + 1;
    while (index < cursor.* + needed) : (index += 1) {
        const byte = input[index];
        if ((byte & 0xc0) != 0x80) return error.InvalidUtf8;
        value = (value << 6) | (byte & 0x3f);
    }
    if (value < minimum or value > max_scalar or isSurrogate(value)) return error.InvalidUtf8;

    cursor.* += needed;
    return @intCast(value);
}

fn appendUtf8(comptime params: Params, out: []u8, out_len: *usize, scalar: u21) PunycodeError!void {
    const value: u32 = scalar;
    if (value <= 0x7f) {
        try appendUtf8Byte(params, out, out_len, @intCast(value));
    } else if (value <= 0x7ff) {
        try appendUtf8Byte(params, out, out_len, @intCast(0xc0 | (value >> 6)));
        try appendUtf8Byte(params, out, out_len, @intCast(0x80 | (value & 0x3f)));
    } else if (value <= 0xffff) {
        try appendUtf8Byte(params, out, out_len, @intCast(0xe0 | (value >> 12)));
        try appendUtf8Byte(params, out, out_len, @intCast(0x80 | ((value >> 6) & 0x3f)));
        try appendUtf8Byte(params, out, out_len, @intCast(0x80 | (value & 0x3f)));
    } else {
        try appendUtf8Byte(params, out, out_len, @intCast(0xf0 | (value >> 18)));
        try appendUtf8Byte(params, out, out_len, @intCast(0x80 | ((value >> 12) & 0x3f)));
        try appendUtf8Byte(params, out, out_len, @intCast(0x80 | ((value >> 6) & 0x3f)));
        try appendUtf8Byte(params, out, out_len, @intCast(0x80 | (value & 0x3f)));
    }
}

fn appendUtf8Byte(comptime params: Params, out: []u8, out_len: *usize, byte: u8) PunycodeError!void {
    if (out_len.* >= params.max_input_bytes) return error.LabelTooLong;
    if (out_len.* >= out.len) return error.OutputTooSmall;
    out[out_len.*] = byte;
    out_len.* += 1;
}

fn appendPunycodeByte(comptime params: Params, out: []u8, out_len: *usize, byte: u8) PunycodeError!void {
    if (out_len.* >= params.max_punycode_bytes) return error.LabelTooLong;
    if (out_len.* >= out.len) return error.OutputTooSmall;
    out[out_len.*] = byte;
    out_len.* += 1;
}

fn appendScalar(comptime params: Params, out: *[params.max_code_points]u21, count: *usize, scalar: u21) PunycodeError!void {
    if (count.* >= params.max_code_points) return error.LabelTooLong;
    out[count.*] = scalar;
    count.* += 1;
}

fn insertScalar(
    comptime params: Params,
    out: *[params.max_code_points]u21,
    count: *usize,
    index: usize,
    scalar: u21,
) PunycodeError!void {
    if (count.* >= params.max_code_points) return error.LabelTooLong;
    if (index > count.*) return error.InvalidInput;

    var cursor = count.*;
    while (cursor > index) : (cursor -= 1) {
        out[cursor] = out[cursor - 1];
    }
    out[index] = scalar;
    count.* += 1;
}

fn biasThreshold(k: u64, bias: u64) u64 {
    if (k <= bias + tmin) return tmin;
    if (k >= bias + tmax) return tmax;
    return k - bias;
}

fn adapt(delta_in: u64, num_points: u64, first_time: bool) u64 {
    var delta = if (first_time) delta_in / damp else delta_in / 2;
    delta += delta / num_points;

    var k: u64 = 0;
    while (delta > ((base - tmin) * tmax) / 2) : (k += base) {
        delta /= base - tmin;
    }

    return k + (((base - tmin + 1) * delta) / (delta + skew));
}

fn encodeDigit(digit: u64) u8 {
    return if (digit < 26) @intCast('a' + digit) else @intCast('0' + (digit - 26));
}

fn decodeDigit(byte: u8) ?u64 {
    return switch (byte) {
        'a'...'z' => byte - 'a',
        'A'...'Z' => byte - 'A',
        '0'...'9' => 26 + byte - '0',
        else => null,
    };
}

fn lastDelimiter(input: []const u8) ?usize {
    var cursor = input.len;
    while (cursor > 0) {
        cursor -= 1;
        if (input[cursor] == delimiter) return cursor;
    }
    return null;
}

fn validBasicLabelByte(byte: u8) bool {
    return switch (byte) {
        'A'...'Z', 'a'...'z', '0'...'9', '-' => true,
        else => false,
    };
}

fn checkedAdd(lhs: u64, rhs: u64) PunycodeError!u64 {
    return std.math.add(u64, lhs, rhs) catch error.Overflow;
}

fn checkedSub(lhs: u64, rhs: u64) PunycodeError!u64 {
    return std.math.sub(u64, lhs, rhs) catch error.Overflow;
}

fn checkedMul(lhs: u64, rhs: u64) PunycodeError!u64 {
    return std.math.mul(u64, lhs, rhs) catch error.Overflow;
}

fn isSurrogate(value: u64) bool {
    return value >= 0xd800 and value <= 0xdfff;
}

test "encode converts known RFC and IDN labels" {
    // Arrange.
    const allocator = std.testing.allocator;
    const Case = struct { unicode: []const u8, punycode: []const u8 };
    const cases = [_]Case{
        .{ .unicode = "b\xC3\xBCcher", .punycode = "bcher-kva" },
        .{ .unicode = "ma\xC3\xB1ana", .punycode = "maana-pta" },
        .{ .unicode = "\u{2603}", .punycode = "n3h" },
        .{ .unicode = "\u{4F8B}\u{3048}", .punycode = "r8jz45g" },
    };

    const out = try allocator.alloc(u8, 64);
    defer allocator.free(out);

    // Act and assert.
    for (cases) |case| {
        const encoded = try encode(case.unicode, out);
        try std.testing.expectEqualStrings(case.punycode, encoded);
    }
}

test "decode converts known RFC and IDN labels" {
    // Arrange.
    const allocator = std.testing.allocator;
    const Case = struct { punycode: []const u8, unicode: []const u8 };
    const cases = [_]Case{
        .{ .punycode = "bcher-kva", .unicode = "b\xC3\xBCcher" },
        .{ .punycode = "maana-pta", .unicode = "ma\xC3\xB1ana" },
        .{ .punycode = "n3h", .unicode = "\u{2603}" },
        .{ .punycode = "r8jz45g", .unicode = "\u{4F8B}\u{3048}" },
    };

    const out = try allocator.alloc(u8, 64);
    defer allocator.free(out);

    // Act and assert.
    for (cases) |case| {
        const decoded = try decode(case.punycode, out);
        try std.testing.expectEqualStrings(case.unicode, decoded);
    }
}

test "codec methods round trip mixed labels" {
    // Arrange.
    const allocator = std.testing.allocator;
    var codec = DefaultCodec.init();
    defer codec.deinit();
    const labels = [_][]const u8{
        "b\xC3\xBCcher",
        "ma\xC3\xB1ana",
        "\u{2603}",
        "\u{4F8B}\u{3048}",
    };

    const encoded_buf = try allocator.alloc(u8, 64);
    defer allocator.free(encoded_buf);
    const decoded_buf = try allocator.alloc(u8, 128);
    defer allocator.free(decoded_buf);

    // Act and assert.
    for (labels) |label| {
        const encoded = try codec.encode(label, encoded_buf);
        const decoded = try codec.decode(encoded, decoded_buf);
        try std.testing.expectEqualStrings(label, decoded);
    }
}

test "encode rejects invalid UTF-8 and label separators" {
    // Arrange.
    const allocator = std.testing.allocator;
    const out = try allocator.alloc(u8, 64);
    defer allocator.free(out);

    // Act and assert.
    try std.testing.expectError(error.InvalidUtf8, encode("\xC0\x80", out));
    try std.testing.expectError(error.InvalidUtf8, encode("\xE2\x82", out));
    try std.testing.expectError(error.InvalidInput, encode("bad.label", out));
    try std.testing.expectError(error.InvalidInput, encode("bad_label", out));
    try std.testing.expectError(error.EmptyLabel, encode("", out));
}

test "decode rejects malformed payloads" {
    // Arrange.
    const allocator = std.testing.allocator;
    const out = try allocator.alloc(u8, 64);
    defer allocator.free(out);

    // Act and assert.
    try std.testing.expectError(error.EmptyLabel, decode("", out));
    try std.testing.expectError(error.InvalidInput, decode("abc-", out));
    try std.testing.expectError(error.InvalidInput, decode("bad_label-kva", out));
    try std.testing.expectError(error.InvalidInput, decode("bcher-kva-", out));
    try std.testing.expectError(error.InvalidInput, decode("x-{}{", out));
}

test "caller output buffers are bounded" {
    // Arrange.
    const allocator = std.testing.allocator;
    const tiny = try allocator.alloc(u8, 2);
    defer allocator.free(tiny);
    const roomy = try allocator.alloc(u8, 64);
    defer allocator.free(roomy);

    // Act and assert.
    try std.testing.expectError(error.OutputTooSmall, encode("b\xC3\xBCcher", tiny));
    try std.testing.expectError(error.OutputTooSmall, decode("bcher-kva", tiny));
    try std.testing.expectError(error.LabelTooLong, encodeWith(.{ .max_punycode_bytes = 3 }, "b\xC3\xBCcher", roomy));
    try std.testing.expectError(error.LabelTooLong, decodeWith(.{ .max_input_bytes = 3 }, "bcher-kva", roomy));
}

test "compile-time scalar limit is enforced" {
    // Arrange.
    const allocator = std.testing.allocator;
    const out = try allocator.alloc(u8, 64);
    defer allocator.free(out);

    // Act and assert.
    try std.testing.expectError(error.LabelTooLong, encodeWith(.{ .max_code_points = 2 }, "abc", out));
    try std.testing.expectError(error.LabelTooLong, decodeWith(.{ .max_code_points = 2 }, "bcher-kva", out));
}

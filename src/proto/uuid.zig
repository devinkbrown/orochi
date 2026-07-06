// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

const std = @import("std");

/// UUID protocol limits used by the allocation-free generator and parser.
pub const Params = struct {
    /// Number of bytes in every UUID value.
    uuid_bytes: usize = 16,
    /// Number of caller-supplied random bytes required for UUID v4.
    v4_random_bytes: usize = 16,
    /// Number of caller-supplied random bytes required for UUID v7.
    v7_random_bytes: usize = 10,
    /// Number of bytes in canonical UUID text.
    canonical_bytes: usize = 36,
    /// Largest Unix millisecond timestamp encodable in UUID v7.
    max_unix_millis: u64 = (@as(u64, 1) << 48) - 1,
};

/// Errors returned by UUID generation, parsing, and formatting.
pub const UuidError = error{
    InvalidParams,
    InvalidRandomBytes,
    TimestampTooLarge,
    InvalidLength,
    InvalidFormat,
    OutputTooSmall,
};

/// UUID versions implemented by this module.
pub const Kind = enum(u4) {
    v4 = 4,
    v7 = 7,

    /// Return the numeric UUID version nibble.
    pub fn nibble(self: Kind) u4 {
        return switch (self) {
            .v4 => 4,
            .v7 => 7,
        };
    }

    /// Return the known kind for a UUID version nibble, or null for other versions.
    pub fn fromNibble(nibble_value: u4) ?Kind {
        return switch (nibble_value) {
            4 => .v4,
            7 => .v7,
            else => null,
        };
    }
};

/// A 128-bit UUID value stored in network byte order.
pub const Uuid = struct {
    /// Raw UUID bytes in network byte order.
    bytes: [16]u8,

    /// Return the raw UUID bytes.
    pub fn raw(self: *const Uuid) *const [16]u8 {
        return &self.bytes;
    }

    /// Return the UUID version nibble.
    pub fn versionNibble(self: Uuid) u4 {
        return @as(u4, @truncate(self.bytes[6] >> 4));
    }

    /// Return the known UUID kind for v4 or v7 UUIDs, or null for other versions.
    pub fn knownKind(self: Uuid) ?Kind {
        return Kind.fromNibble(self.versionNibble());
    }

    /// Return true when the UUID uses the RFC 4122/9562 variant bit pattern.
    pub fn hasRfcVariant(self: Uuid) bool {
        return (self.bytes[8] & 0xc0) == 0x80;
    }

    /// Format this UUID as canonical 8-4-4-4-12 lowercase hexadecimal text.
    pub fn format(self: Uuid, out: []u8) UuidError![]const u8 {
        return formatBytes(self.bytes, out);
    }

    /// Compare UUID bytes in canonical sort order.
    pub fn order(left: Uuid, right: Uuid) std.math.Order {
        return std.mem.order(u8, left.bytes[0..], right.bytes[0..]);
    }
};

/// Allocation-free UUID v4/v7 generator.
pub const Generator = struct {
    params: Params,

    /// Initialize a generator with validated protocol limits.
    pub fn init(params: Params) UuidError!Generator {
        if (params.uuid_bytes != 16) return error.InvalidParams;
        if (params.v4_random_bytes != 16) return error.InvalidParams;
        if (params.v7_random_bytes != 10) return error.InvalidParams;
        if (params.canonical_bytes != 36) return error.InvalidParams;
        if (params.max_unix_millis != ((@as(u64, 1) << 48) - 1)) return error.InvalidParams;
        return .{ .params = params };
    }

    /// Deinitialize the generator.
    pub fn deinit(self: *Generator) void {
        self.* = undefined;
    }

    /// Generate a UUID v4 from exactly 16 caller-supplied random bytes.
    pub fn v4(self: *const Generator, random_bytes: []const u8) UuidError!Uuid {
        if (random_bytes.len != self.params.v4_random_bytes) return error.InvalidRandomBytes;

        var bytes: [16]u8 = undefined;
        @memcpy(bytes[0..], random_bytes);
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        return .{ .bytes = bytes };
    }

    /// Generate a UUID v7 from Unix milliseconds and exactly 10 random bytes.
    pub fn v7(self: *const Generator, unix_millis: u64, random_bytes: []const u8) UuidError!Uuid {
        if (unix_millis > self.params.max_unix_millis) return error.TimestampTooLarge;
        if (random_bytes.len != self.params.v7_random_bytes) return error.InvalidRandomBytes;

        var bytes: [16]u8 = undefined;
        bytes[0] = @as(u8, @truncate(unix_millis >> 40));
        bytes[1] = @as(u8, @truncate(unix_millis >> 32));
        bytes[2] = @as(u8, @truncate(unix_millis >> 24));
        bytes[3] = @as(u8, @truncate(unix_millis >> 16));
        bytes[4] = @as(u8, @truncate(unix_millis >> 8));
        bytes[5] = @as(u8, @truncate(unix_millis));
        bytes[6] = (random_bytes[0] & 0x0f) | 0x70;
        bytes[7] = random_bytes[1];
        bytes[8] = (random_bytes[2] & 0x3f) | 0x80;
        @memcpy(bytes[9..16], random_bytes[3..10]);
        return .{ .bytes = bytes };
    }
};

/// Generate a UUID v4 from exactly 16 caller-supplied random bytes.
pub fn generateV4(random_bytes: []const u8) UuidError!Uuid {
    var generator = try Generator.init(.{});
    defer generator.deinit();
    return generator.v4(random_bytes);
}

/// Generate a UUID v7 from Unix milliseconds and exactly 10 random bytes.
pub fn generateV7(unix_millis: u64, random_bytes: []const u8) UuidError!Uuid {
    var generator = try Generator.init(.{});
    defer generator.deinit();
    return generator.v7(unix_millis, random_bytes);
}

/// Parse canonical 8-4-4-4-12 UUID text into raw UUID bytes.
pub fn parse(text: []const u8) UuidError!Uuid {
    if (text.len != 36) return error.InvalidLength;

    var bytes: [16]u8 = undefined;
    var byte_index: usize = 0;
    var text_index: usize = 0;
    while (text_index < text.len) {
        if (isHyphenPosition(text_index)) {
            if (text[text_index] != '-') return error.InvalidFormat;
            text_index += 1;
            continue;
        }

        const hi = hexValue(text[text_index]) orelse return error.InvalidFormat;
        const lo = hexValue(text[text_index + 1]) orelse return error.InvalidFormat;
        bytes[byte_index] = (hi << 4) | lo;
        byte_index += 1;
        text_index += 2;
    }

    if (byte_index != 16) return error.InvalidFormat;
    return .{ .bytes = bytes };
}

fn formatBytes(bytes: [16]u8, out: []u8) UuidError![]const u8 {
    if (out.len < 36) return error.OutputTooSmall;

    const digits = "0123456789abcdef";
    var byte_index: usize = 0;
    var out_index: usize = 0;
    while (byte_index < bytes.len) : (byte_index += 1) {
        if (byte_index == 4 or byte_index == 6 or byte_index == 8 or byte_index == 10) {
            out[out_index] = '-';
            out_index += 1;
        }
        const byte = bytes[byte_index];
        out[out_index] = digits[byte >> 4];
        out[out_index + 1] = digits[byte & 0x0f];
        out_index += 2;
    }
    return out[0..36];
}

fn isHyphenPosition(index: usize) bool {
    return index == 8 or index == 13 or index == 18 or index == 23;
}

fn hexValue(byte: u8) ?u8 {
    return switch (byte) {
        '0'...'9' => byte - '0',
        'a'...'f' => byte - 'a' + 10,
        'A'...'F' => byte - 'A' + 10,
        else => null,
    };
}

test "format and parse round trip for generated v4 canonical text" {
    // Arrange.
    _ = std.testing.allocator;
    const random_bytes = [_]u8{
        0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb,
        0xcc, 0xdd, 0xee, 0xff,
    };
    var out: [36]u8 = undefined;

    // Act.
    const uuid = try generateV4(random_bytes[0..]);
    const text = try uuid.format(out[0..]);
    const parsed = try parse(text);

    // Assert.
    try std.testing.expectEqualStrings("00112233-4455-4677-8899-aabbccddeeff", text);
    try std.testing.expectEqualSlices(u8, uuid.raw(), parsed.raw());
    try std.testing.expectEqual(@as(u4, 4), parsed.versionNibble());
    try std.testing.expect(parsed.hasRfcVariant());
}

test "parse accepts uppercase input and format canonicalizes lowercase" {
    // Arrange.
    _ = std.testing.allocator;
    var out: [36]u8 = undefined;

    // Act.
    const uuid = try parse("00112233-4455-4677-8899-AABBCCDDEEFF");
    const text = try uuid.format(out[0..]);

    // Assert.
    try std.testing.expectEqualStrings("00112233-4455-4677-8899-aabbccddeeff", text);
}

test "generation sets version and variant bits for v4 and v7" {
    // Arrange.
    _ = std.testing.allocator;
    const v4_random = @as([16]u8, @splat(0xff));
    const v7_random = @as([10]u8, @splat(0xff));

    // Act.
    const random_uuid = try generateV4(v4_random[0..]);
    const ordered_uuid = try generateV7(0x0123456789ab, v7_random[0..]);

    // Assert.
    try std.testing.expectEqual(@as(u4, 4), random_uuid.versionNibble());
    try std.testing.expectEqual(Kind.v4, random_uuid.knownKind().?);
    try std.testing.expect(random_uuid.hasRfcVariant());
    try std.testing.expectEqual(@as(u8, 0x4f), random_uuid.bytes[6]);
    try std.testing.expectEqual(@as(u8, 0xbf), random_uuid.bytes[8]);

    try std.testing.expectEqual(@as(u4, 7), ordered_uuid.versionNibble());
    try std.testing.expectEqual(Kind.v7, ordered_uuid.knownKind().?);
    try std.testing.expect(ordered_uuid.hasRfcVariant());
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab }, ordered_uuid.bytes[0..6]);
    try std.testing.expectEqual(@as(u8, 0x7f), ordered_uuid.bytes[6]);
    try std.testing.expectEqual(@as(u8, 0xbf), ordered_uuid.bytes[8]);
}

test "v7 timestamp order sorts by raw bytes and canonical text" {
    // Arrange.
    _ = std.testing.allocator;
    const random_bytes = [_]u8{ 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0 };
    var first_text_buf: [36]u8 = undefined;
    var second_text_buf: [36]u8 = undefined;

    // Act.
    const first = try generateV7(1_700_000_000_000, random_bytes[0..]);
    const second = try generateV7(1_700_000_000_001, random_bytes[0..]);
    const first_text = try first.format(first_text_buf[0..]);
    const second_text = try second.format(second_text_buf[0..]);

    // Assert.
    try std.testing.expectEqual(std.math.Order.lt, Uuid.order(first, second));
    try std.testing.expectEqual(std.math.Order.lt, std.mem.order(u8, first_text, second_text));
}

test "parse rejects malformed canonical text" {
    // Arrange.
    _ = std.testing.allocator;

    // Act and assert.
    try std.testing.expectError(error.InvalidLength, parse("00112233-4455-4677-8899-aabbccddeef"));
    try std.testing.expectError(error.InvalidFormat, parse("00112233_4455-4677-8899-aabbccddeeff"));
    try std.testing.expectError(error.InvalidFormat, parse("00112233-4455-4677-8899-aabbccddeegf"));
}

test "generation rejects wrong random byte counts and oversized v7 timestamp" {
    // Arrange.
    _ = std.testing.allocator;
    const short_random = @as([9]u8, @splat(0x00));
    const v7_random = @as([10]u8, @splat(0x00));

    // Act and assert.
    try std.testing.expectError(error.InvalidRandomBytes, generateV4(short_random[0..]));
    try std.testing.expectError(error.InvalidRandomBytes, generateV7(0, short_random[0..]));
    try std.testing.expectError(error.TimestampTooLarge, generateV7(@as(u64, 1) << 48, v7_random[0..]));
}

test "format returns output too small without writing past caller storage" {
    // Arrange.
    _ = std.testing.allocator;
    const random_bytes = @as([16]u8, @splat(0x11));
    const uuid = try generateV4(random_bytes[0..]);
    var out: [35]u8 = @splat(0xaa);

    // Act and assert.
    try std.testing.expectError(error.OutputTooSmall, uuid.format(out[0..]));
    for (out) |byte| {
        try std.testing.expectEqual(@as(u8, 0xaa), byte);
    }
}

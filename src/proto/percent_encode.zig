// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! RFC 3986 percent-encoding helpers.
//!
//! The codec writes into caller-owned buffers and never allocates. Decoding is
//! strict: `%` must be followed by exactly two hexadecimal digits, and `+` is
//! treated as a literal plus byte.

const std = @import("std");

/// Encoding presets for RFC 3986 URI components.
pub const EncodeSet = enum(u2) {
    /// Leave only RFC 3986 unreserved bytes unescaped.
    unreserved,
    /// Leave path bytes that may appear literally in a path component.
    path,
    /// Leave query bytes that may appear literally in a query component.
    query,
};

/// Runtime options for the stateless percent codec.
pub const Params = struct {
    /// Emit uppercase hexadecimal digits, matching RFC examples and common wire form.
    uppercase_hex: bool = true,
};

/// Errors returned by percent-encoding operations.
pub const EncodeError = error{
    /// The caller-provided output buffer cannot hold the encoded bytes.
    OutputTooSmall,
};

/// Errors returned by percent-decoding operations.
pub const DecodeError = error{
    /// The caller-provided output buffer cannot hold the decoded bytes.
    OutputTooSmall,
    /// A percent triplet is incomplete or contains a non-hex byte.
    MalformedPercent,
};

/// Stateless RFC 3986 percent encoder and decoder.
pub const Codec = struct {
    params: Params,

    /// Build a codec with the supplied options.
    pub fn init(params: Params) Codec {
        return .{ .params = params };
    }

    /// Release codec resources.
    pub fn deinit(self: *Codec) void {
        self.* = undefined;
    }

    /// Return the exact number of bytes needed to encode `input` with `unreserved_set`.
    pub fn encodedLen(self: *const Codec, input: []const u8, unreserved_set: EncodeSet) usize {
        _ = self;
        var needed: usize = 0;
        for (input) |byte| {
            needed += if (isAllowed(byte, unreserved_set)) @as(usize, 1) else @as(usize, 3);
        }
        return needed;
    }

    /// Percent-encode `input` into `out` and return the written slice.
    pub fn encode(
        self: *const Codec,
        input: []const u8,
        out: []u8,
        unreserved_set: EncodeSet,
    ) EncodeError![]const u8 {
        var len: usize = 0;
        const digits = hexDigits(self.params.uppercase_hex);

        for (input) |byte| {
            if (isAllowed(byte, unreserved_set)) {
                if (len >= out.len) return error.OutputTooSmall;
                out[len] = byte;
                len += 1;
            } else {
                if (out.len - len < 3) return error.OutputTooSmall;
                out[len] = '%';
                out[len + 1] = digits[byte >> 4];
                out[len + 2] = digits[byte & 0x0f];
                len += 3;
            }
        }

        return out[0..len];
    }

    /// Percent-decode `input` into `out` and return the written slice.
    pub fn decode(self: *const Codec, input: []const u8, out: []u8) DecodeError![]const u8 {
        _ = self;
        var read: usize = 0;
        var len: usize = 0;

        while (read < input.len) {
            const byte = input[read];
            if (byte != '%') {
                if (len >= out.len) return error.OutputTooSmall;
                out[len] = byte;
                len += 1;
                read += 1;
                continue;
            }

            if (input.len - read < 3) return error.MalformedPercent;
            const hi = hexValue(input[read + 1]) orelse return error.MalformedPercent;
            const lo = hexValue(input[read + 2]) orelse return error.MalformedPercent;
            if (len >= out.len) return error.OutputTooSmall;
            out[len] = (hi << 4) | lo;
            len += 1;
            read += 3;
        }

        return out[0..len];
    }

    /// Percent-encode a URI path using the path component preset.
    pub fn encodePath(self: *const Codec, input: []const u8, out: []u8) EncodeError![]const u8 {
        return self.encode(input, out, .path);
    }

    /// Percent-encode a URI query using the query component preset.
    pub fn encodeQuery(self: *const Codec, input: []const u8, out: []u8) EncodeError![]const u8 {
        return self.encode(input, out, .query);
    }
};

/// Return the exact number of bytes needed to encode `input` with `unreserved_set`.
pub fn encodedLen(input: []const u8, unreserved_set: EncodeSet) usize {
    const codec = Codec.init(.{});
    return codec.encodedLen(input, unreserved_set);
}

/// Percent-encode `input` into `out` and return the written slice.
pub fn encode(input: []const u8, out: []u8, unreserved_set: EncodeSet) EncodeError![]const u8 {
    const codec = Codec.init(.{});
    return codec.encode(input, out, unreserved_set);
}

/// Percent-decode `input` into `out` and return the written slice.
pub fn decode(input: []const u8, out: []u8) DecodeError![]const u8 {
    const codec = Codec.init(.{});
    return codec.decode(input, out);
}

/// Percent-encode a URI path using the path component preset.
pub fn encodePath(input: []const u8, out: []u8) EncodeError![]const u8 {
    const codec = Codec.init(.{});
    return codec.encodePath(input, out);
}

/// Percent-encode a URI query using the query component preset.
pub fn encodeQuery(input: []const u8, out: []u8) EncodeError![]const u8 {
    const codec = Codec.init(.{});
    return codec.encodeQuery(input, out);
}

fn isAllowed(byte: u8, set: EncodeSet) bool {
    return switch (set) {
        .unreserved => isRfcUnreserved(byte),
        .path => isPathAllowed(byte),
        .query => isQueryAllowed(byte),
    };
}

fn isRfcUnreserved(byte: u8) bool {
    return switch (byte) {
        'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => true,
        else => false,
    };
}

fn isSubDelimiter(byte: u8) bool {
    return switch (byte) {
        '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=' => true,
        else => false,
    };
}

fn isPathAllowed(byte: u8) bool {
    return isRfcUnreserved(byte) or isSubDelimiter(byte) or switch (byte) {
        ':', '@', '/' => true,
        else => false,
    };
}

fn isQueryAllowed(byte: u8) bool {
    return isPathAllowed(byte) or switch (byte) {
        '?' => true,
        else => false,
    };
}

fn hexDigits(uppercase: bool) []const u8 {
    return if (uppercase) "0123456789ABCDEF" else "0123456789abcdef";
}

fn hexValue(byte: u8) ?u8 {
    return switch (byte) {
        '0'...'9' => byte - '0',
        'A'...'F' => byte - 'A' + 10,
        'a'...'f' => byte - 'a' + 10,
        else => null,
    };
}

test "round trip encodes escaped bytes and decodes original input" {
    // Arrange
    const allocator = std.testing.allocator;
    const input = try allocator.dupe(u8, "hello world/%?#\n");
    defer allocator.free(input);
    const encoded_storage = try allocator.alloc(u8, encodedLen(input, .unreserved));
    defer allocator.free(encoded_storage);
    const decoded_storage = try allocator.alloc(u8, input.len);
    defer allocator.free(decoded_storage);

    // Act
    const encoded = try encode(input, encoded_storage, .unreserved);
    const decoded = try decode(encoded, decoded_storage);

    // Assert
    try std.testing.expectEqualStrings("hello%20world%2F%25%3F%23%0A", encoded);
    try std.testing.expectEqualStrings(input, decoded);
}

test "reserved characters are escaped by the unreserved set" {
    // Arrange
    const allocator = std.testing.allocator;
    const input = try allocator.dupe(u8, ":/?#[]@!$&'()*+,;=");
    defer allocator.free(input);
    const output = try allocator.alloc(u8, encodedLen(input, .unreserved));
    defer allocator.free(output);

    // Act
    const encoded = try encode(input, output, .unreserved);

    // Assert
    try std.testing.expectEqualStrings("%3A%2F%3F%23%5B%5D%40%21%24%26%27%28%29%2A%2B%2C%3B%3D", encoded);
}

test "path and query component encoders preserve component delimiters" {
    // Arrange
    const allocator = std.testing.allocator;
    const path_input = try allocator.dupe(u8, "/rooms/a b;v=1?x#frag");
    defer allocator.free(path_input);
    const query_input = try allocator.dupe(u8, "a/b?c=d e#f");
    defer allocator.free(query_input);
    const path_output = try allocator.alloc(u8, encodedLen(path_input, .path));
    defer allocator.free(path_output);
    const query_output = try allocator.alloc(u8, encodedLen(query_input, .query));
    defer allocator.free(query_output);

    // Act
    const path_encoded = try encodePath(path_input, path_output);
    const query_encoded = try encodeQuery(query_input, query_output);

    // Assert
    try std.testing.expectEqualStrings("/rooms/a%20b;v=1%3Fx%23frag", path_encoded);
    try std.testing.expectEqualStrings("a/b?c=d%20e%23f", query_encoded);
}

test "malformed percent triplets are rejected" {
    // Arrange
    const allocator = std.testing.allocator;
    const output = try allocator.alloc(u8, 16);
    defer allocator.free(output);

    // Act and assert
    try std.testing.expectError(error.MalformedPercent, decode("%", output));
    try std.testing.expectError(error.MalformedPercent, decode("%1", output));
    try std.testing.expectError(error.MalformedPercent, decode("%zz", output));
    try std.testing.expectError(error.MalformedPercent, decode("a%0x", output));
}

test "plus is decoded literally and not as a space" {
    // Arrange
    const allocator = std.testing.allocator;
    const input = try allocator.dupe(u8, "a+b%20c%2B");
    defer allocator.free(input);
    const output = try allocator.alloc(u8, input.len);
    defer allocator.free(output);

    // Act
    const decoded = try decode(input, output);

    // Assert
    try std.testing.expectEqualStrings("a+b c+", decoded);
}

test "small output buffers return OutputTooSmall" {
    // Arrange
    const allocator = std.testing.allocator;
    const encoded_out = try allocator.alloc(u8, 2);
    defer allocator.free(encoded_out);
    const decoded_out = try allocator.alloc(u8, 0);
    defer allocator.free(decoded_out);

    // Act and assert
    try std.testing.expectError(error.OutputTooSmall, encode(" ", encoded_out, .unreserved));
    try std.testing.expectError(error.OutputTooSmall, decode("a", decoded_out));
}

test "codec options can emit lowercase hexadecimal digits" {
    // Arrange
    const allocator = std.testing.allocator;
    const input = try allocator.dupe(u8, "\xff?");
    defer allocator.free(input);
    const output = try allocator.alloc(u8, 6);
    defer allocator.free(output);
    var codec = Codec.init(.{ .uppercase_hex = false });
    defer codec.deinit();

    // Act
    const encoded = try codec.encode(input, output, .unreserved);

    // Assert
    try std.testing.expectEqualStrings("%ff%3f", encoded);
}

// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bech32, Bech32m, and Base58Check helpers for human-readable identifiers.
//!
//! This module is deliberately self-contained so it can be tested in isolation:
//! it imports only `std`, allocates through caller-provided allocators, and
//! exposes decode results with explicit deinit ownership.
const std = @import("std");

pub const Encoding = enum {
    bech32,
    bech32m,
};

pub const Bech32Error = error{
    InvalidLength,
    InvalidHrp,
    InvalidCharacter,
    MixedCase,
    MissingSeparator,
    InvalidChecksum,
    InvalidData,
    InvalidPadding,
};

pub const Base58Error = error{
    InvalidLength,
    InvalidCharacter,
    InvalidChecksum,
};

pub const Decoded = struct {
    hrp: []u8,
    data: []u8,
    encoding: Encoding,

    pub fn deinit(self: *Decoded, allocator: std.mem.Allocator) void {
        allocator.free(self.hrp);
        allocator.free(self.data);
        self.* = undefined;
    }
};

const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_CONST: u32 = 1;
const BECH32M_CONST: u32 = 0x2bc830a3;
const BECH32_CHECKSUM_LEN: usize = 6;
const BECH32_MAX_LEN: usize = 90;

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE58_CHECKSUM_LEN: usize = 4;

/// Encode an HRP and 5-bit data values as Bech32 or Bech32m.
pub fn encode(
    allocator: std.mem.Allocator,
    hrp: []const u8,
    data5: []const u8,
    encoding: Encoding,
) (Bech32Error || std.mem.Allocator.Error)![]u8 {
    if (hrp.len == 0) return error.InvalidHrp;
    if (hrp.len + 1 + data5.len + BECH32_CHECKSUM_LEN > BECH32_MAX_LEN) return error.InvalidLength;

    for (hrp) |byte| {
        if (!isValidHrpByte(byte)) return error.InvalidHrp;
    }
    for (data5) |value| {
        if (value > 31) return error.InvalidData;
    }

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    for (hrp) |byte| try out.append(allocator, lowerAscii(byte));
    try out.append(allocator, '1');
    for (data5) |value| try out.append(allocator, BECH32_CHARSET[value]);

    const checksum = createChecksum(hrp, data5, encoding);
    for (checksum) |value| try out.append(allocator, BECH32_CHARSET[value]);

    return out.toOwnedSlice(allocator);
}

/// Decode a Bech32/Bech32m string and identify which checksum constant matched.
pub fn decode(allocator: std.mem.Allocator, text: []const u8) (Bech32Error || std.mem.Allocator.Error)!Decoded {
    if (text.len < 1 + 1 + BECH32_CHECKSUM_LEN or text.len > BECH32_MAX_LEN) return error.InvalidLength;

    var has_lower = false;
    var has_upper = false;
    var separator: ?usize = null;
    for (text, 0..) |byte, index| {
        if (byte < 33 or byte > 126) return error.InvalidCharacter;
        if (byte >= 'a' and byte <= 'z') has_lower = true;
        if (byte >= 'A' and byte <= 'Z') has_upper = true;
        if (byte == '1') separator = index;
    }
    if (has_lower and has_upper) return error.MixedCase;

    const sep = separator orelse return error.MissingSeparator;
    if (sep == 0) return error.InvalidHrp;
    if (sep + 1 + BECH32_CHECKSUM_LEN > text.len) return error.InvalidLength;

    var hrp = try allocator.alloc(u8, sep);
    errdefer allocator.free(hrp);
    for (text[0..sep], 0..) |byte, index| {
        if (!isValidHrpByte(byte)) return error.InvalidHrp;
        hrp[index] = lowerAscii(byte);
    }

    var combined: std.ArrayList(u8) = .empty;
    defer combined.deinit(allocator);
    for (text[sep + 1 ..]) |byte| {
        const value = charToBech32Value(lowerAscii(byte)) orelse return error.InvalidCharacter;
        try combined.append(allocator, value);
    }

    const check = polymodHrpData(hrp, combined.items);
    const encoding: Encoding = if (check == BECH32_CONST)
        .bech32
    else if (check == BECH32M_CONST)
        .bech32m
    else
        return error.InvalidChecksum;

    const data_len = combined.items.len - BECH32_CHECKSUM_LEN;
    const data = try allocator.alloc(u8, data_len);
    errdefer allocator.free(data);
    @memcpy(data, combined.items[0..data_len]);

    return .{
        .hrp = hrp,
        .data = data,
        .encoding = encoding,
    };
}

/// Convert packed bit groups, typically between bytes and Bech32 5-bit data.
pub fn convertBits(
    allocator: std.mem.Allocator,
    input: []const u8,
    from_bits: u8,
    to_bits: u8,
    pad: bool,
) (Bech32Error || std.mem.Allocator.Error)![]u8 {
    if (from_bits == 0 or from_bits > 8 or to_bits == 0 or to_bits > 8) return error.InvalidData;

    const from_shift: u5 = @intCast(from_bits);
    const to_shift: u5 = @intCast(to_bits);
    const maxv = (@as(u32, 1) << to_shift) - 1;

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    var acc: u32 = 0;
    var bits: u8 = 0;
    for (input) |value| {
        if ((@as(u32, value) >> from_shift) != 0) return error.InvalidData;
        acc = (acc << from_shift) | value;
        bits += from_bits;

        while (bits >= to_bits) {
            bits -= to_bits;
            const shift: u5 = @intCast(bits);
            try out.append(allocator, @intCast((acc >> shift) & maxv));
        }
    }

    if (pad) {
        if (bits > 0) {
            const shift: u5 = @intCast(to_bits - bits);
            try out.append(allocator, @intCast((acc << shift) & maxv));
        }
    } else {
        if (bits >= from_bits) return error.InvalidPadding;
        if (bits > 0) {
            const shift: u5 = @intCast(to_bits - bits);
            if (((acc << shift) & maxv) != 0) return error.InvalidPadding;
        }
    }

    return out.toOwnedSlice(allocator);
}

/// Encode payload bytes with a four-byte double-SHA256 Base58Check checksum.
pub fn base58CheckEncode(allocator: std.mem.Allocator, payload: []const u8) (Base58Error || std.mem.Allocator.Error)![]u8 {
    var checked = try allocator.alloc(u8, payload.len + BASE58_CHECKSUM_LEN);
    defer allocator.free(checked);
    @memcpy(checked[0..payload.len], payload);
    const checksum = doubleSha256(payload);
    @memcpy(checked[payload.len..], checksum[0..BASE58_CHECKSUM_LEN]);

    var zeroes: usize = 0;
    while (zeroes < checked.len and checked[zeroes] == 0) zeroes += 1;

    const size = (checked.len - zeroes) * 138 / 100 + 1;
    var digits = try allocator.alloc(u8, size);
    defer allocator.free(digits);
    @memset(digits, 0);

    for (checked[zeroes..]) |byte| {
        var carry: u32 = byte;
        var index = size;
        while (index > 0) {
            index -= 1;
            carry += @as(u32, digits[index]) << 8;
            digits[index] = @intCast(carry % 58);
            carry /= 58;
        }
    }

    var first_digit: usize = 0;
    while (first_digit < digits.len and digits[first_digit] == 0) first_digit += 1;

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    for (0..zeroes) |_| try out.append(allocator, '1');
    for (digits[first_digit..]) |digit| try out.append(allocator, BASE58_ALPHABET[digit]);

    return out.toOwnedSlice(allocator);
}

/// Decode and verify Base58Check text, returning the payload without checksum.
pub fn base58CheckDecode(allocator: std.mem.Allocator, text: []const u8) (Base58Error || std.mem.Allocator.Error)![]u8 {
    if (text.len == 0) return error.InvalidLength;

    var zeroes: usize = 0;
    while (zeroes < text.len and text[zeroes] == '1') zeroes += 1;

    const size = text.len * 733 / 1000 + 1;
    var bytes = try allocator.alloc(u8, size);
    defer allocator.free(bytes);
    @memset(bytes, 0);

    for (text) |char| {
        const value = charToBase58Value(char) orelse return error.InvalidCharacter;
        var carry: u32 = value;
        var index = size;
        while (index > 0) {
            index -= 1;
            carry += @as(u32, bytes[index]) * 58;
            bytes[index] = @intCast(carry & 0xff);
            carry >>= 8;
        }
        if (carry != 0) return error.InvalidLength;
    }

    var first_byte: usize = 0;
    while (first_byte < bytes.len and bytes[first_byte] == 0) first_byte += 1;

    const checked_len = zeroes + (bytes.len - first_byte);
    if (checked_len < BASE58_CHECKSUM_LEN) return error.InvalidLength;

    var checked = try allocator.alloc(u8, checked_len);
    defer allocator.free(checked);
    @memset(checked[0..zeroes], 0);
    @memcpy(checked[zeroes..], bytes[first_byte..]);

    const payload_len = checked.len - BASE58_CHECKSUM_LEN;
    const expected = doubleSha256(checked[0..payload_len]);
    if (!std.mem.eql(u8, checked[payload_len..], expected[0..BASE58_CHECKSUM_LEN])) return error.InvalidChecksum;

    const payload = try allocator.alloc(u8, payload_len);
    @memcpy(payload, checked[0..payload_len]);
    return payload;
}

fn createChecksum(hrp: []const u8, data5: []const u8, encoding: Encoding) [BECH32_CHECKSUM_LEN]u8 {
    var values: [BECH32_CHECKSUM_LEN]u8 = .{0} ** BECH32_CHECKSUM_LEN;
    const constant = encodingConstant(encoding);
    var chk = polymodHrpData(hrp, data5);
    for (0..BECH32_CHECKSUM_LEN) |_| chk = polymodStep(chk, 0);
    chk ^= constant;

    for (0..BECH32_CHECKSUM_LEN) |index| {
        const shift: u5 = @intCast(5 * (BECH32_CHECKSUM_LEN - 1 - index));
        values[index] = @intCast((chk >> shift) & 31);
    }
    return values;
}

fn polymodHrpData(hrp: []const u8, data: []const u8) u32 {
    var chk: u32 = 1;
    for (hrp) |byte| chk = polymodStep(chk, lowerAscii(byte) >> 5);
    chk = polymodStep(chk, 0);
    for (hrp) |byte| chk = polymodStep(chk, lowerAscii(byte) & 31);
    for (data) |value| chk = polymodStep(chk, value);
    return chk;
}

fn polymodStep(chk: u32, value: u8) u32 {
    const generators = [_]u32{
        0x3b6a57b2,
        0x26508e6d,
        0x1ea119fa,
        0x3d4233dd,
        0x2a1462b3,
    };

    const top = chk >> 25;
    var next = ((chk & 0x1ffffff) << 5) ^ value;
    for (generators, 0..) |generator, index| {
        if (((top >> @intCast(index)) & 1) != 0) next ^= generator;
    }
    return next;
}

fn encodingConstant(encoding: Encoding) u32 {
    return switch (encoding) {
        .bech32 => BECH32_CONST,
        .bech32m => BECH32M_CONST,
    };
}

fn isValidHrpByte(byte: u8) bool {
    return byte >= 33 and byte <= 126;
}

fn lowerAscii(byte: u8) u8 {
    if (byte >= 'A' and byte <= 'Z') return byte + ('a' - 'A');
    return byte;
}

fn charToBech32Value(byte: u8) ?u8 {
    for (BECH32_CHARSET, 0..) |candidate, index| {
        if (candidate == byte) return @intCast(index);
    }
    return null;
}

fn charToBase58Value(byte: u8) ?u8 {
    for (BASE58_ALPHABET, 0..) |candidate, index| {
        if (candidate == byte) return @intCast(index);
    }
    return null;
}

fn doubleSha256(input: []const u8) [32]u8 {
    const Sha256 = std.crypto.hash.sha2.Sha256;
    var first: [32]u8 = undefined;
    var second: [32]u8 = undefined;
    Sha256.hash(input, &first, .{});
    Sha256.hash(&first, &second, .{});
    return second;
}

fn expectDecodeEncodeLower(vector: []const u8, expected_encoding: Encoding) !void {
    const allocator = std.testing.allocator;
    var decoded = try decode(allocator, vector);
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(expected_encoding, decoded.encoding);

    const encoded = try encode(allocator, decoded.hrp, decoded.data, decoded.encoding);
    defer allocator.free(encoded);

    var lower = try allocator.alloc(u8, vector.len);
    defer allocator.free(lower);
    for (vector, 0..) |byte, index| lower[index] = lowerAscii(byte);
    try std.testing.expectEqualSlices(u8, lower, encoded);
}

test "BIP-173 valid bech32 vectors round-trip" {
    const vectors = [_][]const u8{
        "A12UEL5L",
        "a12uel5l",
        "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
        "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
        "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
        "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
        "?1ezyfcl",
    };

    for (vectors) |vector| try expectDecodeEncodeLower(vector, .bech32);
}

test "checksum detects single-character errors" {
    const allocator = std.testing.allocator;
    const data = [_]u8{ 0, 1, 2, 3, 4, 5, 31 };
    const encoded = try encode(allocator, "node", &data, .bech32);
    defer allocator.free(encoded);

    var damaged = try allocator.dupe(u8, encoded);
    defer allocator.free(damaged);
    damaged[3] = if (damaged[3] == 'q') 'p' else 'q';

    try std.testing.expectError(error.InvalidChecksum, decode(allocator, damaged));
}

test "bech32 and bech32m constants are distinct and detected" {
    const allocator = std.testing.allocator;
    const data = [_]u8{ 16, 8, 4, 2, 1, 0, 31 };

    const as_bech32 = try encode(allocator, "invite", &data, .bech32);
    defer allocator.free(as_bech32);
    const as_bech32m = try encode(allocator, "invite", &data, .bech32m);
    defer allocator.free(as_bech32m);

    try std.testing.expect(!std.mem.eql(u8, as_bech32, as_bech32m));

    var decoded32 = try decode(allocator, as_bech32);
    defer decoded32.deinit(allocator);
    var decoded32m = try decode(allocator, as_bech32m);
    defer decoded32m.deinit(allocator);

    try std.testing.expectEqual(Encoding.bech32, decoded32.encoding);
    try std.testing.expectEqual(Encoding.bech32m, decoded32m.encoding);
    try std.testing.expectEqualSlices(u8, decoded32.data, decoded32m.data);
}

test "convertBits 8-to-5 and 5-to-8 are inverse with padding" {
    const allocator = std.testing.allocator;
    const bytes = [_]u8{ 0x00, 0x01, 0x02, 0xfd, 0xfe, 0xff, 0x80, 0x7f };

    const five_bit = try convertBits(allocator, &bytes, 8, 5, true);
    defer allocator.free(five_bit);
    const round_trip = try convertBits(allocator, five_bit, 5, 8, false);
    defer allocator.free(round_trip);

    try std.testing.expectEqualSlices(u8, &bytes, round_trip);
}

test "convertBits rejects invalid values and nonzero padding" {
    const allocator = std.testing.allocator;
    const invalid = [_]u8{32};
    try std.testing.expectError(error.InvalidData, convertBits(allocator, &invalid, 5, 8, false));

    const bad_padding = [_]u8{1};
    try std.testing.expectError(error.InvalidPadding, convertBits(allocator, &bad_padding, 5, 8, false));
}

test "Base58Check round-trip and bad checksum rejection" {
    const allocator = std.testing.allocator;
    const payload = [_]u8{ 0, 0, 1, 2, 3, 4, 5, 250, 251, 252, 253, 254, 255 };

    const encoded = try base58CheckEncode(allocator, &payload);
    defer allocator.free(encoded);
    const decoded = try base58CheckDecode(allocator, encoded);
    defer allocator.free(decoded);
    try std.testing.expectEqualSlices(u8, &payload, decoded);

    var damaged = try allocator.dupe(u8, encoded);
    defer allocator.free(damaged);
    damaged[damaged.len - 1] = if (damaged[damaged.len - 1] == '1') '2' else '1';
    try std.testing.expectError(error.InvalidChecksum, base58CheckDecode(allocator, damaged));
}

test "Base58Check rejects invalid characters" {
    try std.testing.expectError(error.InvalidCharacter, base58CheckDecode(std.testing.allocator, "10"));
    try std.testing.expectError(error.InvalidCharacter, base58CheckDecode(std.testing.allocator, "O0Il"));
}

test "invalid HRP, mixed case, data, and checksum characters are rejected" {
    const allocator = std.testing.allocator;
    const data = [_]u8{0};

    try std.testing.expectError(error.InvalidHrp, encode(allocator, "", &data, .bech32));
    try std.testing.expectError(error.InvalidHrp, encode(allocator, "bad hrp", &data, .bech32));

    try std.testing.expectError(error.MixedCase, decode(allocator, "A12uel5l"));
    try std.testing.expectError(error.InvalidCharacter, decode(allocator, "a1b!qqqqq"));
    try std.testing.expectError(error.InvalidHrp, decode(allocator, "1qzzfhee"));

    const invalid_data = [_]u8{32};
    try std.testing.expectError(error.InvalidData, encode(allocator, "node", &invalid_data, .bech32));
}

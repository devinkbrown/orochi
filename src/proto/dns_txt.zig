// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure helpers for DNS TXT records (RR type 16, RFC 1035 §3.3.14).
//!
//! TXT rdata is one or more <character-string>s. Each character-string is a
//! single length-octet (0..255) followed by exactly that many bytes. This
//! module is a standalone complement to the codec in `dns.zig` (which does not
//! model TXT rdata); intended for e.g. TXT domain-ownership verification.
//!
//! Pure logic only: no sockets, filesystem, or clock reads. The allocator is
//! used solely by `concatTxt`.

const std = @import("std");

/// DNS RR TYPE for TXT records.
pub const txt_record_type: u16 = 16;

/// Maximum length of a single <character-string> (length octet is a u8).
pub const max_character_string_len: usize = 255;

/// Errors produced when packing character-strings into TXT rdata.
pub const EncodeError = error{
    /// A supplied string exceeds 255 bytes (cannot fit a u8 length octet).
    StringTooLong,
    /// The destination buffer is too small for the encoded rdata.
    NoSpaceLeft,
};

/// Errors produced when walking/joining TXT rdata.
pub const DecodeError = error{
    /// A length octet claims more bytes than remain in the buffer.
    Truncated,
};

/// Encode `strings` into TXT character-string wire format, written to `out`.
///
/// Each element becomes `[len:u8][bytes...]`. Returns the written prefix of
/// `out`. An empty `strings` slice yields an empty (zero-length) rdata, which
/// is unusual on the wire but well-formed here; callers that require at least
/// one character-string should check `strings.len` themselves.
pub fn encodeTxtRdata(out: []u8, strings: []const []const u8) EncodeError![]const u8 {
    var pos: usize = 0;
    for (strings) |s| {
        if (s.len > max_character_string_len) return error.StringTooLong;
        if (pos + 1 + s.len > out.len) return error.NoSpaceLeft;
        out[pos] = @intCast(s.len);
        pos += 1;
        @memcpy(out[pos .. pos + s.len], s);
        pos += s.len;
    }
    return out[0..pos];
}

/// Exact byte count required to encode `strings` as TXT rdata.
///
/// Does not validate length bounds; combine with `encodeTxtRdata` for the
/// authoritative result. Useful for sizing a destination buffer.
pub fn encodedLen(strings: []const []const u8) usize {
    var total: usize = 0;
    for (strings) |s| total += 1 + s.len;
    return total;
}

/// Forward iterator over the character-strings in a TXT rdata buffer.
///
/// Each `next()` validates the length octet against the remaining bytes,
/// rejecting truncation. Borrows `rdata`; yielded slices alias it.
pub const TxtIterator = struct {
    rdata: []const u8,
    pos: usize = 0,

    /// Return the next character-string slice, or null at the end.
    /// Errors if a length octet runs past the end of the buffer.
    pub fn next(self: *TxtIterator) DecodeError!?[]const u8 {
        if (self.pos >= self.rdata.len) return null;
        const len: usize = self.rdata[self.pos];
        const start = self.pos + 1;
        const end = start + len;
        if (end > self.rdata.len) return error.Truncated;
        self.pos = end;
        return self.rdata[start..end];
    }
};

/// Create an iterator over the character-strings in `rdata`.
pub fn decodeTxtRdata(rdata: []const u8) TxtIterator {
    return .{ .rdata = rdata };
}

/// Validate `rdata` and count its character-strings without allocating.
/// Returns `error.Truncated` if any length octet overruns the buffer.
pub fn countStrings(rdata: []const u8) DecodeError!usize {
    var it = decodeTxtRdata(rdata);
    var n: usize = 0;
    while (try it.next()) |_| n += 1;
    return n;
}

/// Join every character-string in `rdata` into one owned buffer.
///
/// DNS TXT values are logically the concatenation of their character-strings,
/// so this yields the effective string value. Caller owns the returned slice
/// and must free it with `allocator`.
pub fn concatTxt(allocator: std.mem.Allocator, rdata: []const u8) (DecodeError || std.mem.Allocator.Error)![]u8 {
    var it = decodeTxtRdata(rdata);
    var total: usize = 0;
    while (try it.next()) |part| total += part.len;

    const buf = try allocator.alloc(u8, total);
    errdefer allocator.free(buf);

    var pos: usize = 0;
    var it2 = decodeTxtRdata(rdata);
    while (try it2.next()) |part| {
        @memcpy(buf[pos .. pos + part.len], part);
        pos += part.len;
    }
    return buf;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "encodeTxtRdata single string round-trips through iterator" {
    // Arrange
    var out: [64]u8 = undefined;
    const strings = [_][]const u8{"hello"};

    // Act
    const rdata = try encodeTxtRdata(&out, &strings);
    var it = decodeTxtRdata(rdata);
    const first = try it.next();
    const second = try it.next();

    // Assert
    try std.testing.expectEqualSlices(u8, &[_]u8{ 5, 'h', 'e', 'l', 'l', 'o' }, rdata);
    try std.testing.expect(first != null);
    try std.testing.expectEqualSlices(u8, "hello", first.?);
    try std.testing.expect(second == null);
}

test "encodeTxtRdata packs multiple character-strings in order" {
    // Arrange
    var out: [64]u8 = undefined;
    const strings = [_][]const u8{ "v=spf1", "include:_x", "-all" };

    // Act
    const rdata = try encodeTxtRdata(&out, &strings);
    var it = decodeTxtRdata(rdata);
    const a = try it.next();
    const b = try it.next();
    const c = try it.next();
    const d = try it.next();

    // Assert
    try std.testing.expectEqualSlices(u8, "v=spf1", a.?);
    try std.testing.expectEqualSlices(u8, "include:_x", b.?);
    try std.testing.expectEqualSlices(u8, "-all", c.?);
    try std.testing.expect(d == null);
    try std.testing.expectEqual(@as(usize, 3), try countStrings(rdata));
}

test "encodeTxtRdata preserves an empty character-string (len 0)" {
    // Arrange
    var out: [16]u8 = undefined;
    const strings = [_][]const u8{ "", "x" };

    // Act
    const rdata = try encodeTxtRdata(&out, &strings);
    var it = decodeTxtRdata(rdata);
    const a = try it.next();
    const b = try it.next();

    // Assert
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 1, 'x' }, rdata);
    try std.testing.expectEqual(@as(usize, 0), a.?.len);
    try std.testing.expectEqualSlices(u8, "x", b.?);
}

test "encodeTxtRdata round-trips a 255-byte maximum string" {
    // Arrange
    var max_buf: [255]u8 = undefined;
    @memset(&max_buf, 'A');
    var out: [256]u8 = undefined;
    const strings = [_][]const u8{&max_buf};

    // Act
    const rdata = try encodeTxtRdata(&out, &strings);
    var it = decodeTxtRdata(rdata);
    const first = try it.next();

    // Assert
    try std.testing.expectEqual(@as(usize, 256), rdata.len);
    try std.testing.expectEqual(@as(u8, 255), rdata[0]);
    try std.testing.expectEqual(@as(usize, 255), first.?.len);
    try std.testing.expectEqualSlices(u8, &max_buf, first.?);
}

test "encodeTxtRdata rejects a string longer than 255 bytes" {
    // Arrange
    var big: [256]u8 = undefined;
    @memset(&big, 'B');
    var out: [512]u8 = undefined;
    const strings = [_][]const u8{&big};

    // Act
    const result = encodeTxtRdata(&out, &strings);

    // Assert
    try std.testing.expectError(error.StringTooLong, result);
}

test "encodeTxtRdata reports NoSpaceLeft when destination is too small" {
    // Arrange
    var out: [3]u8 = undefined; // needs 1 + 5 = 6 bytes
    const strings = [_][]const u8{"hello"};

    // Act
    const result = encodeTxtRdata(&out, &strings);

    // Assert
    try std.testing.expectError(error.NoSpaceLeft, result);
}

test "decodeTxtRdata rejects truncated rdata" {
    // Arrange: length octet claims 5 bytes, only 2 follow.
    const rdata = [_]u8{ 5, 'h', 'i' };

    // Act
    var it = decodeTxtRdata(&rdata);
    const result = it.next();

    // Assert
    try std.testing.expectError(error.Truncated, result);
    try std.testing.expectError(error.Truncated, countStrings(&rdata));
}

test "concatTxt joins all character-strings without leaks" {
    // Arrange
    var out: [64]u8 = undefined;
    const strings = [_][]const u8{ "part-", "two-", "three" };
    const rdata = try encodeTxtRdata(&out, &strings);

    // Act
    const joined = try concatTxt(std.testing.allocator, rdata);
    defer std.testing.allocator.free(joined);

    // Assert
    try std.testing.expectEqualSlices(u8, "part-two-three", joined);
}

test "concatTxt of empty rdata yields an empty owned buffer" {
    // Arrange
    const rdata = [_]u8{};

    // Act
    const joined = try concatTxt(std.testing.allocator, &rdata);
    defer std.testing.allocator.free(joined);

    // Assert
    try std.testing.expectEqual(@as(usize, 0), joined.len);
}

test "concatTxt propagates truncation errors" {
    // Arrange
    const rdata = [_]u8{ 4, 'a', 'b' };

    // Act
    const result = concatTxt(std.testing.allocator, &rdata);

    // Assert
    try std.testing.expectError(error.Truncated, result);
}

test "encodedLen matches actual encoded length" {
    // Arrange
    const strings = [_][]const u8{ "", "abc", "de" };
    var out: [32]u8 = undefined;

    // Act
    const predicted = encodedLen(&strings);
    const rdata = try encodeTxtRdata(&out, &strings);

    // Assert
    try std.testing.expectEqual(rdata.len, predicted);
    try std.testing.expectEqual(@as(usize, 8), predicted); // 1+0 + 1+3 + 1+2
}

test "txt_record_type constant is 16" {
    try std.testing.expectEqual(@as(u16, 16), txt_record_type);
}

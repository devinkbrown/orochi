// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! TLS 1.3 `supported_versions` extension inner codec (RFC 8446 §4.2.1).
//!
//! This module decodes and encodes the *inner data* of the
//! `supported_versions` extension only — the outer extension envelope (type
//! tag + 2-byte length) is handled by the generic extension-list codec in a
//! sibling module.  Two on-the-wire shapes exist:
//!
//!   * ClientHello form: a 1-byte list length, followed by that many bytes of
//!     packed big-endian `u16` version numbers (so the length must be even and
//!     non-zero in practice).
//!   * ServerHello / HelloRetryRequest form: a single big-endian `u16`
//!     selected version (exactly two bytes, no list prefix).
//!
//! Pure logic: no I/O, no clock, no RNG, no allocation.  Callers own every
//! buffer.  Every length is bounds-checked; a truncated or malformed block
//! yields `error.Truncated` rather than reading past the slice.  Only `std`
//! is imported.
const std = @import("std");

/// TLS 1.3 version code as it appears on the wire (legacy "0x0304").
pub const tls13: u16 = 0x0304;

/// TLS 1.2 version code as it appears on the wire (legacy "0x0303").
pub const tls12: u16 = 0x0303;

/// Width of a single wire version field in bytes.
const version_len: usize = 2;

/// Errors produced while parsing or building a `supported_versions` body.
pub const Error = error{
    /// The block ended mid-field, declared more bytes than it carried, had an
    /// odd-length version list, or (ServerHello form) was not exactly 2 bytes.
    Truncated,
    /// A build target buffer ran out of room.  Matches `std`'s spelling so
    /// callers can mix our writes with `std` writers if they like.
    NoSpaceLeft,
    /// More versions were offered than fit in the 1-byte ClientHello list
    /// length field (255 bytes => 127 versions).
    TooManyVersions,
};

/// Read a big-endian `u16` from the first two bytes of `b` (caller guarantees
/// `b.len >= 2`).
fn readU16(b: []const u8) u16 {
    return (@as(u16, b[0]) << 8) | @as(u16, b[1]);
}

/// Write a big-endian `u16` into the first two bytes of `out` (caller
/// guarantees `out.len >= 2`).
fn writeU16(out: []u8, value: u16) void {
    out[0] = @intCast(value >> 8);
    out[1] = @intCast(value & 0xff);
}

/// Cursor over the version list of a ClientHello-form body.  Yields each
/// offered `u16` version in wire order.  Constructed by `parseClient`, which
/// validates the framing up front, so iteration itself cannot fail.
pub const Iterator = struct {
    /// The version bytes only (the 1-byte list-length prefix already stripped).
    versions: []const u8,
    /// Byte offset of the next version to yield.
    pos: usize = 0,

    /// Return the next offered version, or `null` once the list is exhausted.
    pub fn next(self: *Iterator) ?u16 {
        if (self.pos + version_len > self.versions.len) return null;
        const v = readU16(self.versions[self.pos..]);
        self.pos += version_len;
        return v;
    }

    /// Number of versions remaining (does not advance the cursor).
    pub fn remaining(self: *const Iterator) usize {
        return (self.versions.len - self.pos) / version_len;
    }
};

/// Parse a ClientHello-form body and return an `Iterator` over its versions.
///
/// Validates that the declared 1-byte list length matches the bytes present
/// and that the list is an even number of bytes.  Aliases `block`; copies
/// nothing.
pub fn parseClient(block: []const u8) Error!Iterator {
    if (block.len < 1) return Error.Truncated;
    const list_len: usize = block[1 - 1]; // block[0]
    const body = block[1..];
    if (body.len != list_len) return Error.Truncated;
    if (list_len % version_len != 0) return Error.Truncated;
    return Iterator{ .versions = body };
}

/// Return `true` iff the ClientHello-form `block` offers `version`.  A
/// malformed block offers nothing, so returns `false` on parse failure.
pub fn clientOffers(block: []const u8, version: u16) bool {
    var it = parseClient(block) catch return false;
    while (it.next()) |v| {
        if (v == version) return true;
    }
    return false;
}

/// Parse a ServerHello / HelloRetryRequest-form body: exactly one `u16`.
pub fn parseServer(block: []const u8) Error!u16 {
    if (block.len != version_len) return Error.Truncated;
    return readU16(block);
}

/// Encode `versions` into `out` as a ClientHello-form body and return the
/// written prefix of `out`.  Writes a 1-byte list length followed by each
/// version big-endian.
pub fn buildClient(out: []u8, versions: []const u16) Error![]const u8 {
    const body_len = versions.len * version_len;
    if (body_len > 255) return Error.TooManyVersions;
    const total = 1 + body_len;
    if (out.len < total) return Error.NoSpaceLeft;
    out[0] = @intCast(body_len);
    var off: usize = 1;
    for (versions) |v| {
        writeU16(out[off..], v);
        off += version_len;
    }
    return out[0..total];
}

/// Encode a single selected `version` into `out` as a ServerHello-form body
/// (exactly two bytes) and return the written prefix of `out`.
pub fn buildServer(out: []u8, version: u16) Error![]const u8 {
    if (out.len < version_len) return Error.NoSpaceLeft;
    writeU16(out, version);
    return out[0..version_len];
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "client list round-trips [tls13, tls12] in order" {
    // Arrange
    var buf: [16]u8 = undefined;
    const offered = [_]u16{ tls13, tls12 };

    // Act
    const body = try buildClient(&buf, &offered);
    var it = try parseClient(body);
    const first = it.next();
    const second = it.next();
    const third = it.next();

    // Assert
    try testing.expectEqual(@as(usize, 5), body.len); // 1 len + 2*2 versions
    try testing.expectEqual(@as(u8, 4), body[0]);
    try testing.expectEqual(@as(?u16, tls13), first);
    try testing.expectEqual(@as(?u16, tls12), second);
    try testing.expectEqual(@as(?u16, null), third);
}

test "clientOffers finds tls13 and misses an unoffered version" {
    // Arrange
    var buf: [16]u8 = undefined;
    const body = try buildClient(&buf, &[_]u16{ tls13, tls12 });

    // Act
    const has13 = clientOffers(body, tls13);
    const has12 = clientOffers(body, tls12);
    const hasOld = clientOffers(body, 0x0301); // TLS 1.0, not offered

    // Assert
    try testing.expect(has13);
    try testing.expect(has12);
    try testing.expect(!hasOld);
}

test "server single version round-trips" {
    // Arrange
    var buf: [4]u8 = undefined;

    // Act
    const body = try buildServer(&buf, tls13);
    const selected = try parseServer(body);

    // Assert
    try testing.expectEqual(@as(usize, 2), body.len);
    try testing.expectEqual(tls13, selected);
}

test "iterator remaining counts versions without advancing" {
    // Arrange
    var buf: [16]u8 = undefined;
    const body = try buildClient(&buf, &[_]u16{ tls13, tls12 });
    var it = try parseClient(body);

    // Act
    const before = it.remaining();
    _ = it.next();
    const after = it.remaining();

    // Assert
    try testing.expectEqual(@as(usize, 2), before);
    try testing.expectEqual(@as(usize, 1), after);
}

test "parseClient rejects a length mismatch" {
    // Arrange: declares 4 bytes of versions but only carries 2.
    const block = [_]u8{ 4, 0x03, 0x04 };

    // Act
    const result = parseClient(&block);

    // Assert
    try testing.expectError(Error.Truncated, result);
}

test "parseClient rejects an odd-length version list" {
    // Arrange: declares 3 bytes of versions (odd, cannot be whole u16s).
    const block = [_]u8{ 3, 0x03, 0x04, 0x03 };

    // Act
    const result = parseClient(&block);

    // Assert
    try testing.expectError(Error.Truncated, result);
}

test "parseClient rejects an empty block (no length byte)" {
    // Arrange
    const block = [_]u8{};

    // Act
    const result = parseClient(&block);

    // Assert
    try testing.expectError(Error.Truncated, result);
}

test "parseServer rejects a body that is not exactly two bytes" {
    // Arrange
    const short = [_]u8{0x03};
    const long = [_]u8{ 0x03, 0x04, 0x03, 0x03 };

    // Act / Assert
    try testing.expectError(Error.Truncated, parseServer(&short));
    try testing.expectError(Error.Truncated, parseServer(&long));
}

test "buildClient reports NoSpaceLeft when the buffer is too small" {
    // Arrange
    var tiny: [2]u8 = undefined; // needs 5 for two versions

    // Act
    const result = buildClient(&tiny, &[_]u16{ tls13, tls12 });

    // Assert
    try testing.expectError(Error.NoSpaceLeft, result);
}

test "buildServer reports NoSpaceLeft when the buffer is too small" {
    // Arrange
    var tiny: [1]u8 = undefined; // needs 2

    // Act
    const result = buildServer(&tiny, tls13);

    // Assert
    try testing.expectError(Error.NoSpaceLeft, result);
}

test "clientOffers returns false on a malformed block" {
    // Arrange: length byte claims more than is present.
    const block = [_]u8{ 8, 0x03, 0x04 };

    // Act
    const found = clientOffers(&block, tls13);

    // Assert
    try testing.expect(!found);
}

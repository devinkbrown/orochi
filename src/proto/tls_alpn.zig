// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! ALPN protocol-name-list codec (RFC 7301 §3.1).
//!
//! A pure, zero-allocation codec for the *inner* data of the ALPN extension:
//! the `ProtocolNameList`.  That payload is a 2-byte total length followed by a
//! packed sequence of protocol names, each encoded as `<1-byte-len><bytes>`.
//! RFC 7301 forbids empty names, and the single length octet caps any name at
//! 255 bytes.
//!
//! This module knows nothing about the surrounding TLS extension envelope — a
//! sibling extension-list codec wraps this block as `extension_data`.  Here we
//! walk only the protocol-name list and hand back slices that alias the
//! caller's input (never copies).
//!
//! Pure logic: no I/O, no clock, no RNG, no allocation.  Callers own every
//! buffer.  Every length is bounds-checked; a truncated or malformed block
//! yields `error.Truncated` rather than reading past the slice.  Only `std`
//! is imported.
const std = @import("std");
const mem = std.mem;

/// Bytes of the 2-byte `ProtocolNameList` length prefix.
pub const prefix_len: usize = 2;

/// Maximum length of a single protocol name (one length octet).
pub const max_name_len: usize = std.math.maxInt(u8);

/// Errors produced while walking or building a protocol-name list.
pub const Error = error{
    /// The input ended mid-prefix or mid-name, or the prefix overran the slice.
    Truncated,
    /// A `Builder` ran out of room in the caller-provided buffer.
    NoSpaceLeft,
    /// A protocol name was empty or longer than 255 bytes (illegal on the wire).
    InvalidName,
};

/// Read the 2-byte prefix and return the body slice it covers, or `Truncated`.
fn bodyOf(block: []const u8) Error![]const u8 {
    if (block.len < prefix_len) return error.Truncated;
    const declared = mem.readInt(u16, block[0..2], .big);
    const body = block[prefix_len..];
    if (declared > body.len) return error.Truncated;
    return body[0..declared];
}

/// Walks a `ProtocolNameList`, yielding each protocol-name slice in order.
/// Slices alias the input; the iterator copies nothing.
pub const Iterator = struct {
    body: []const u8,
    pos: usize,

    /// Build an iterator from a full block (2-byte prefix + names).
    pub fn fromBlock(block: []const u8) Error!Iterator {
        return .{ .body = try bodyOf(block), .pos = 0 };
    }

    /// Build an iterator directly over a prefix-stripped body.
    pub fn fromBody(body: []const u8) Iterator {
        return .{ .body = body, .pos = 0 };
    }

    /// Yield the next protocol name, `null` at the end, or an error on a
    /// truncated/illegal entry.
    pub fn next(self: *Iterator) Error!?[]const u8 {
        if (self.pos == self.body.len) return null;
        if (self.pos > self.body.len) return error.Truncated;

        const name_len = self.body[self.pos];
        if (name_len == 0) return error.InvalidName;
        const start = self.pos + 1;
        const end = start + name_len;
        if (end > self.body.len) return error.Truncated;

        self.pos = end;
        return self.body[start..end];
    }

    /// Bytes not yet consumed from the body.
    pub fn remaining(self: Iterator) usize {
        return self.body.len - self.pos;
    }
};

/// Returns `true` if `name` appears verbatim in the protocol-name list.
/// A malformed block (or a `name` that is empty / too long) yields `false`.
pub fn contains(block: []const u8, name: []const u8) bool {
    if (name.len == 0 or name.len > max_name_len) return false;
    var it = Iterator.fromBlock(block) catch return false;
    while (it.next() catch return false) |proto| {
        if (mem.eql(u8, proto, name)) return true;
    }
    return false;
}

/// Incrementally writes a `ProtocolNameList` into a caller-owned buffer,
/// back-patching the 2-byte length prefix on `finish`.
pub const Builder = struct {
    out: []u8,
    /// Bytes written so far, including the reserved 2-byte prefix.
    len: usize,

    /// Begin a list in `out`.  Requires room for at least the length prefix.
    pub fn begin(out: []u8) Error!Builder {
        if (out.len < prefix_len) return error.NoSpaceLeft;
        return .{ .out = out, .len = prefix_len };
    }

    /// Append one protocol name.  Rejects empty names and names > 255 bytes.
    pub fn add(self: *Builder, name: []const u8) Error!void {
        if (name.len == 0 or name.len > max_name_len) return error.InvalidName;
        const need = 1 + name.len;
        if (self.out.len - self.len < need) return error.NoSpaceLeft;

        self.out[self.len] = @intCast(name.len);
        @memcpy(self.out[self.len + 1 .. self.len + need], name);
        self.len += need;
    }

    /// Back-patch the total-length prefix and return the finished block slice
    /// (a view into `out`).  The body length must fit in a u16.
    pub fn finish(self: *Builder) Error![]const u8 {
        const body_len = self.len - prefix_len;
        if (body_len > std.math.maxInt(u16)) return error.NoSpaceLeft;
        mem.writeInt(u16, self.out[0..2], @intCast(body_len), .big);
        return self.out[0..self.len];
    }
};

/// Convenience: build a one-protocol list into `out` and return the block.
pub fn buildSingle(out: []u8, name: []const u8) Error![]const u8 {
    var b = try Builder.begin(out);
    try b.add(name);
    return b.finish();
}

// Tests

const testing = std.testing;

test "Builder round-trips a two-name list parsed back by Iterator" {
    // Arrange
    var buf: [64]u8 = undefined;
    var b = try Builder.begin(&buf);
    try b.add("irc");
    try b.add("http/1.1");

    // Act
    const block = try b.finish();
    var it = try Iterator.fromBlock(block);
    const first = (try it.next()).?;
    const second = (try it.next()).?;
    const end = try it.next();

    // Assert
    try testing.expectEqualStrings("irc", first);
    try testing.expectEqualStrings("http/1.1", second);
    try testing.expectEqual(@as(?[]const u8, null), end);
}

test "wire layout matches RFC 7301 framing" {
    // Arrange
    var buf: [32]u8 = undefined;

    // Act
    const block = try buildSingle(&buf, "irc");

    // Assert: 2-byte list length = 4, then 0x03 'i' 'r' 'c'.
    const want = [_]u8{ 0x00, 0x04, 0x03, 'i', 'r', 'c' };
    try testing.expectEqualSlices(u8, &want, block);
}

test "contains reports membership and non-membership" {
    // Arrange
    var buf: [64]u8 = undefined;
    var b = try Builder.begin(&buf);
    try b.add("irc");
    try b.add("http/1.1");
    const block = try b.finish();

    // Act
    const has_irc = contains(block, "irc");
    const has_h2 = contains(block, "h2");

    // Assert
    try testing.expect(has_irc);
    try testing.expect(!has_h2);
}

test "empty and oversized names are rejected by the Builder" {
    // Arrange
    var buf: [512]u8 = undefined;
    var b = try Builder.begin(&buf);
    const oversized = @as([(max_name_len + 1)]u8, @splat('x'));

    // Act
    const empty_err = b.add("");
    const big_err = b.add(&oversized);

    // Assert
    try testing.expectError(error.InvalidName, empty_err);
    try testing.expectError(error.InvalidName, big_err);
}

test "an empty name on the wire is rejected by the Iterator" {
    // Arrange: prefix says 1 body byte, that byte is a 0-length name.
    const block = [_]u8{ 0x00, 0x01, 0x00 };

    // Act
    var it = try Iterator.fromBlock(&block);
    const result = it.next();

    // Assert
    try testing.expectError(error.InvalidName, result);
}

test "truncated body yields Truncated from fromBlock" {
    // Arrange: prefix claims 8 body bytes but only 2 are present.
    const block = [_]u8{ 0x00, 0x08, 'i', 'r' };

    // Act
    const result = Iterator.fromBlock(&block);

    // Assert
    try testing.expectError(error.Truncated, result);
}

test "name running past the body yields Truncated from next" {
    // Arrange: body length 4, single name claims 5 bytes.
    const block = [_]u8{ 0x00, 0x04, 0x05, 'i', 'r', 'c' };

    // Act
    var it = try Iterator.fromBlock(&block);
    const result = it.next();

    // Assert
    try testing.expectError(error.Truncated, result);
}

test "buildSingle rejects an empty name" {
    // Arrange
    var buf: [16]u8 = undefined;

    // Act
    const result = buildSingle(&buf, "");

    // Assert
    try testing.expectError(error.InvalidName, result);
}

test "Builder reports NoSpaceLeft when the buffer is exhausted" {
    // Arrange: room for prefix + "ir" only, not the full "irc" entry.
    var buf: [4]u8 = undefined;
    var b = try Builder.begin(&buf);

    // Act
    const result = b.add("irc");

    // Assert
    try testing.expectError(error.NoSpaceLeft, result);
}

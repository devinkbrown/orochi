// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deterministic Suimyaku mesh UID encoding.
//!
//! A UID is the canonical base-36 encoding of an 80-bit tuple:
//! `u16 node_id || u64 monotonic_counter`. Fixed width keeps parsing
//! unambiguous, and the node id occupies the high bits so two nodes cannot
//! emit the same UID for any counter value.
const std = @import("std");

pub const encoded_len: usize = 16;
pub const base: u128 = 36;

pub const Uid = [encoded_len]u8;

pub const Parts = struct {
    node: u16,
    counter: u64,
};

pub const ParseError = error{
    InvalidLength,
    InvalidCharacter,
    Overflow,
};

const node_shift: u7 = 64;
const counter_mask: u128 = std.math.maxInt(u64);
const max_packed: u128 = (@as(u128, std.math.maxInt(u16)) << node_shift) | counter_mask;
const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// Return the canonical fixed-width base-36 UID for `node` and `counter`.
pub fn generate(node: u16, counter: u64) Uid {
    var out: Uid = undefined;
    var value = pack(node, counter);

    var index = encoded_len;
    while (index > 0) {
        index -= 1;
        const digit: u8 = @intCast(value % base);
        out[index] = alphabet[digit];
        value /= base;
    }

    return out;
}

/// Parse a canonical UID back into its node/counter tuple.
pub fn parse(uid: []const u8) ParseError!Parts {
    if (uid.len != encoded_len) return error.InvalidLength;

    var value: u128 = 0;
    for (uid) |char| {
        const digit = digitValue(char) orelse return error.InvalidCharacter;
        value = value * base + @as(u128, digit);
        if (value > max_packed) return error.Overflow;
    }

    return unpack(value);
}

/// Return whether `uid` is a canonical Suimyaku UID.
pub fn validate(uid: []const u8) bool {
    _ = parse(uid) catch return false;
    return true;
}

/// Return success only when `uid` is a canonical Suimyaku UID.
pub fn validateStrict(uid: []const u8) ParseError!void {
    _ = try parse(uid);
}

fn pack(node: u16, counter: u64) u128 {
    return (@as(u128, node) << node_shift) | @as(u128, counter);
}

fn unpack(value: u128) Parts {
    return .{
        .node = @intCast(value >> node_shift),
        .counter = @intCast(value & counter_mask),
    };
}

fn digitValue(char: u8) ?u8 {
    return switch (char) {
        '0'...'9' => char - '0',
        'A'...'Z' => 10 + char - 'A',
        else => null,
    };
}

test "uniqueness across a sequence" {
    const testing = std.testing;
    const count: usize = 512;
    const seen = try testing.allocator.alloc(Uid, count);
    defer testing.allocator.free(seen);

    for (0..count) |index| {
        const uid = generate(0x1234, @intCast(index));
        for (seen[0..index]) |prior| {
            try testing.expect(!std.mem.eql(u8, prior[0..], uid[0..]));
        }
        seen[index] = uid;
    }
}

test "round-trip parse" {
    const testing = std.testing;
    const cases = [_]Parts{
        .{ .node = 0, .counter = 0 },
        .{ .node = 1, .counter = 1 },
        .{ .node = 0x1234, .counter = 35 },
        .{ .node = 0xabcd, .counter = 36 },
        .{ .node = std.math.maxInt(u16), .counter = std.math.maxInt(u64) },
    };

    for (cases) |case| {
        const uid = generate(case.node, case.counter);
        const parsed = try parse(uid[0..]);
        try testing.expectEqual(case.node, parsed.node);
        try testing.expectEqual(case.counter, parsed.counter);
        try validateStrict(uid[0..]);
        try testing.expect(validate(uid[0..]));
    }
}

test "two nodes never collide" {
    const testing = std.testing;

    for (0..64) |left_counter| {
        const left = generate(0x0001, @intCast(left_counter));
        for (0..64) |right_counter| {
            const right = generate(0x0002, @intCast(right_counter));
            try testing.expect(!std.mem.eql(u8, left[0..], right[0..]));
        }
    }
}

test "format and length bounds" {
    const testing = std.testing;
    const uid = generate(0x1234, 35);

    try testing.expectEqual(encoded_len, uid.len);
    for (uid) |char| {
        try testing.expect(digitValue(char) != null);
    }

    try testing.expectEqualStrings("0000000000000000", generate(0, 0)[0..]);
    try testing.expectError(error.InvalidLength, parse(uid[0 .. encoded_len - 1]));

    var long: [encoded_len + 1]u8 = undefined;
    @memcpy(long[0..encoded_len], uid[0..]);
    long[encoded_len] = '0';
    try testing.expectError(error.InvalidLength, parse(long[0..]));

    var invalid = uid;
    invalid[0] = '_';
    try testing.expectError(error.InvalidCharacter, parse(invalid[0..]));
    invalid[0] = 'a';
    try testing.expectError(error.InvalidCharacter, parse(invalid[0..]));

    try testing.expectError(error.Overflow, parse("ZZZZZZZZZZZZZZZZ"));
    try testing.expect(!validate("ZZZZZZZZZZZZZZZZ"));
}

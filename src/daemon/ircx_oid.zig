//! Deterministic IRCX channel object identifiers for Mizuchi.
const std = @import("std");

pub const Oid = u32;

const oid_hex_len = 8;
const counter_mask: u32 = 0xffff;
const salt_shift = 16;

pub const Allocator = struct {
    node_salt: u16,
    counter: u32,

    pub fn init(node_id: u64) Allocator {
        return .{
            .node_salt = deriveNodeSalt(node_id),
            .counter = 0,
        };
    }

    pub fn initAt(node_id: u64, counter: u32) Allocator {
        return .{
            .node_salt = deriveNodeSalt(node_id),
            .counter = counter,
        };
    }

    pub fn next(self: *Allocator) Oid {
        const sequence: u32 = self.counter & counter_mask;
        const oid: Oid = (@as(u32, self.node_salt) << salt_shift) | sequence;
        self.counter +%= 1;
        return oid;
    }
};

pub fn oidString(buf: *[oid_hex_len]u8, oid: Oid) []const u8 {
    const alphabet = "0123456789abcdef";

    var shift: u5 = 28;
    for (buf) |*digit| {
        digit.* = alphabet[(oid >> shift) & 0xf];
        shift -%= 4;
    }

    return buf[0..];
}

pub fn creationUnix(now_ms: i64) i64 {
    return @divFloor(now_ms, 1000);
}

fn deriveNodeSalt(node_id: u64) u16 {
    var mixed = node_id;
    mixed ^= mixed >> 33;
    mixed *%= 0xff51afd7ed558ccd;
    mixed ^= mixed >> 33;
    mixed *%= 0xc4ceb9fe1a85ec53;
    mixed ^= mixed >> 33;
    return @truncate(mixed);
}

const testing = std.testing;

test "oidString renders exactly eight lowercase hex characters" {
    var zero: [oid_hex_len]u8 = undefined;
    try testing.expectEqualStrings("00000000", oidString(&zero, 0));

    var one: [oid_hex_len]u8 = undefined;
    try testing.expectEqualStrings("0000000a", oidString(&one, 0x0000000a));

    var full: [oid_hex_len]u8 = undefined;
    try testing.expectEqualStrings("ffffffff", oidString(&full, std.math.maxInt(Oid)));
}

test "different node identities occupy different high bits for the same counter" {
    var left = Allocator.initAt(0x0102_0304_0506_0708, 42);
    var right = Allocator.initAt(0x1112_1314_1516_1718, 42);

    const left_oid = left.next();
    const right_oid = right.next();

    try testing.expect(left.node_salt != right.node_salt);
    try testing.expect(left_oid != right_oid);
    try testing.expectEqual(@as(u32, 42), left_oid & counter_mask);
    try testing.expectEqual(@as(u32, 42), right_oid & counter_mask);
}

test "counter increments through the low bits" {
    var alloc = Allocator.initAt(0x2026, 0);

    const first = alloc.next();
    const second = alloc.next();
    const third = alloc.next();

    try testing.expectEqual(@as(u32, 0), first & counter_mask);
    try testing.expectEqual(@as(u32, 1), second & counter_mask);
    try testing.expectEqual(@as(u32, 2), third & counter_mask);
    try testing.expectEqual(@as(u32, 3), alloc.counter);
}

test "counter wrap is defined at the oid sequence boundary" {
    var alloc = Allocator.initAt(0x3036, 0xffff);

    const last = alloc.next();
    const wrapped = alloc.next();

    try testing.expectEqual(@as(u32, 0xffff), last & counter_mask);
    try testing.expectEqual(@as(u32, 0), wrapped & counter_mask);
    try testing.expectEqual(last & ~counter_mask, wrapped & ~counter_mask);
}

test "counter arithmetic wraps safely at u32 max" {
    var alloc = Allocator.initAt(0x4046, std.math.maxInt(u32));

    const oid = alloc.next();

    try testing.expectEqual(@as(u32, 0xffff), oid & counter_mask);
    try testing.expectEqual(@as(u32, 0), alloc.counter);
}

test "creationUnix converts milliseconds to unix seconds" {
    try testing.expectEqual(@as(i64, 0), creationUnix(999));
    try testing.expectEqual(@as(i64, 1), creationUnix(1000));
    try testing.expectEqual(@as(i64, 1_774_169_600), creationUnix(1_774_169_600_123));
}

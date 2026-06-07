//! Compact causal trace identifiers for Causal Wake.
const std = @import("std");

pub const encoded_len: usize = 24;

pub const TraceId = packed struct {
    origin_node: u64,
    hlc: u64,
    span: u32,
    parent: u32,
};

pub fn root(origin_node: u64, hlc: u64) TraceId {
    return .{
        .origin_node = origin_node,
        .hlc = hlc,
        .span = 1,
        .parent = 0,
    };
}

pub fn childOf(parent_trace: TraceId, new_span: u32) TraceId {
    return .{
        .origin_node = parent_trace.origin_node,
        .hlc = parent_trace.hlc,
        .span = new_span,
        .parent = parent_trace.span,
    };
}

pub fn encode(trace: TraceId, buf: *[encoded_len]u8) void {
    std.mem.writeInt(u64, buf[0..8], trace.origin_node, .little);
    std.mem.writeInt(u64, buf[8..16], trace.hlc, .little);
    std.mem.writeInt(u32, buf[16..20], trace.span, .little);
    std.mem.writeInt(u32, buf[20..24], trace.parent, .little);
}

pub fn decode(buf: *const [encoded_len]u8) TraceId {
    return .{
        .origin_node = std.mem.readInt(u64, buf[0..8], .little),
        .hlc = std.mem.readInt(u64, buf[8..16], .little),
        .span = std.mem.readInt(u32, buf[16..20], .little),
        .parent = std.mem.readInt(u32, buf[20..24], .little),
    };
}

pub fn eql(a: TraceId, b: TraceId) bool {
    return a.origin_node == b.origin_node and
        a.hlc == b.hlc and
        a.span == b.span and
        a.parent == b.parent;
}

const testing = std.testing;

test "TraceId remains the compact trace bit layout" {
    try testing.expectEqual(@as(usize, encoded_len * 8), @bitSizeOf(TraceId));
}

test "root creates the first span without a parent" {
    const trace = root(0x1111_2222_3333_4444, 0x5555_6666_7777_8888);

    try testing.expectEqual(@as(u64, 0x1111_2222_3333_4444), trace.origin_node);
    try testing.expectEqual(@as(u64, 0x5555_6666_7777_8888), trace.hlc);
    try testing.expectEqual(@as(u32, 1), trace.span);
    try testing.expectEqual(@as(u32, 0), trace.parent);
}

test "childOf preserves origin and clock while linking the parent span" {
    const parent = root(42, 9001);
    const child = childOf(parent, 7);

    try testing.expectEqual(parent.origin_node, child.origin_node);
    try testing.expectEqual(parent.hlc, child.hlc);
    try testing.expectEqual(@as(u32, 7), child.span);
    try testing.expectEqual(parent.span, child.parent);
}

test "encode decode round trip preserves every field" {
    const trace: TraceId = .{
        .origin_node = 0x0102_0304_0506_0708,
        .hlc = 0x1112_1314_1516_1718,
        .span = 0x2122_2324,
        .parent = 0x3132_3334,
    };
    var buf: [encoded_len]u8 = undefined;

    encode(trace, &buf);
    const decoded = decode(&buf);

    try testing.expect(eql(trace, decoded));
}

test "encoding is fixed little endian" {
    const trace: TraceId = .{
        .origin_node = 0x0102_0304_0506_0708,
        .hlc = 0x1112_1314_1516_1718,
        .span = 0x2122_2324,
        .parent = 0x3132_3334,
    };
    var buf: [encoded_len]u8 = undefined;

    encode(trace, &buf);

    try testing.expectEqualSlices(u8, &.{
        0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
        0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11,
        0x24, 0x23, 0x22, 0x21,
        0x34, 0x33, 0x32, 0x31,
    }, &buf);
}

test "childOf sets parent to the immediate source span" {
    const first = root(7, 11);
    const second = childOf(first, 5);
    const third = childOf(second, 9);

    try testing.expectEqual(@as(u32, 1), second.parent);
    try testing.expectEqual(@as(u32, 5), third.parent);
}

test "sibling spans can remain distinct under the same root" {
    const trace = root(88, 1234);
    const left = childOf(trace, 2);
    const right = childOf(trace, 3);

    try testing.expect(!eql(left, right));
    try testing.expectEqual(trace.span, left.parent);
    try testing.expectEqual(trace.span, right.parent);
}

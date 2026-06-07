//! ICE-specific STUN attributes from RFC 5245/RFC 8445.
//!
//! These helpers encode full attribute TLVs for callers to append to a STUN
//! message, and decode only the attribute value bytes returned by a STUN parser.
const std = @import("std");
const stun = @import("stun.zig");

pub const attr_priority: u16 = 0x0024;
pub const attr_use_candidate: u16 = 0x0025;
pub const attr_ice_controlling: u16 = 0x802A;
pub const attr_ice_controlled: u16 = 0x8029;

pub const Error = error{
    Truncated,
    BadLength,
    BufferTooSmall,
};

pub fn encodePriority(value: u32, out: []u8) Error![]const u8 {
    var value_buf: [4]u8 = undefined;
    writeU32(&value_buf, value);
    return encodeAttr(attr_priority, &value_buf, out);
}

pub fn decodePriority(value_bytes: []const u8) Error!u32 {
    try expectValueLen(value_bytes, 4);
    return readU32(value_bytes[0..4]);
}

pub fn encodeUseCandidate(value: bool, out: []u8) Error![]const u8 {
    _ = value;
    return encodeAttr(attr_use_candidate, &.{}, out);
}

pub fn decodeUseCandidate(value_bytes: []const u8) Error!bool {
    try expectValueLen(value_bytes, 0);
    return true;
}

pub fn encodeIceControlling(value: u64, out: []u8) Error![]const u8 {
    var value_buf: [8]u8 = undefined;
    writeU64(&value_buf, value);
    return encodeAttr(attr_ice_controlling, &value_buf, out);
}

pub fn decodeIceControlling(value_bytes: []const u8) Error!u64 {
    try expectValueLen(value_bytes, 8);
    return readU64(value_bytes[0..8]);
}

pub fn encodeIceControlled(value: u64, out: []u8) Error![]const u8 {
    var value_buf: [8]u8 = undefined;
    writeU64(&value_buf, value);
    return encodeAttr(attr_ice_controlled, &value_buf, out);
}

pub fn decodeIceControlled(value_bytes: []const u8) Error!u64 {
    try expectValueLen(value_bytes, 8);
    return readU64(value_bytes[0..8]);
}

pub fn computePriority(type_pref: u8, local_pref: u16, component_id: u8) u32 {
    return (@as(u32, type_pref) << 24) +
        (@as(u32, local_pref) << 8) +
        (256 - @as(u32, component_id));
}

pub fn findAttr(stun_message: []const u8, attr_type: u16) Error!?[]const u8 {
    if (stun_message.len < stun.header_len) return error.Truncated;

    const message_len = readU16(stun_message[2..4]);
    if ((message_len % 4) != 0) return error.BadLength;
    if (readU32(stun_message[4..8]) != stun.magic_cookie) return error.BadLength;

    const end = stun.header_len + @as(usize, message_len);
    if (stun_message.len < end) return error.Truncated;
    if (stun_message.len != end) return error.BadLength;

    var cursor: usize = stun.header_len;
    while (cursor < end) {
        if (end - cursor < 4) return error.Truncated;
        const raw_type = readU16(stun_message[cursor..][0..2]);
        const value_len = readU16(stun_message[cursor + 2 ..][0..2]);
        cursor += 4;

        const padded = paddedLen(value_len);
        if (cursor + padded > end) return error.Truncated;

        const value = stun_message[cursor..][0..value_len];
        if (raw_type == attr_type) return value;

        cursor += padded;
    }

    return null;
}

fn encodeAttr(attr_type: u16, value: []const u8, out: []u8) Error![]const u8 {
    if (value.len > std.math.maxInt(u16)) return error.BadLength;

    const total_len = 4 + paddedLen(value.len);
    if (out.len < total_len) return error.BufferTooSmall;

    writeU16(out[0..2], attr_type);
    writeU16(out[2..4], @intCast(value.len));
    @memcpy(out[4..][0..value.len], value);

    const padding = total_len - 4 - value.len;
    if (padding > 0) @memset(out[4 + value.len ..][0..padding], 0);

    return out[0..total_len];
}

fn expectValueLen(value: []const u8, expected: usize) Error!void {
    if (value.len < expected) return error.Truncated;
    if (value.len != expected) return error.BadLength;
}

fn paddedLen(len: usize) usize {
    return (len + 3) & ~@as(usize, 3);
}

fn readU16(bytes: []const u8) u16 {
    return std.mem.readInt(u16, bytes[0..2], .big);
}

fn readU32(bytes: []const u8) u32 {
    return std.mem.readInt(u32, bytes[0..4], .big);
}

fn readU64(bytes: []const u8) u64 {
    return std.mem.readInt(u64, bytes[0..8], .big);
}

fn writeU16(out: []u8, value: u16) void {
    std.mem.writeInt(u16, out[0..2], value, .big);
}

fn writeU32(out: []u8, value: u32) void {
    std.mem.writeInt(u32, out[0..4], value, .big);
}

fn writeU64(out: []u8, value: u64) void {
    std.mem.writeInt(u64, out[0..8], value, .big);
}

test "PRIORITY encodes and decodes u32" {
    var buf: [8]u8 = undefined;
    const encoded = try encodePriority(0x7effff00, &buf);

    try std.testing.expectEqual(@as(usize, 8), encoded.len);
    try std.testing.expectEqual(attr_priority, readU16(encoded[0..2]));
    try std.testing.expectEqual(@as(u16, 4), readU16(encoded[2..4]));
    try std.testing.expectEqual(@as(u32, 0x7effff00), try decodePriority(encoded[4..8]));
}

test "ICE-CONTROLLING and ICE-CONTROLLED round-trip u64 tie-breakers" {
    var controlling_buf: [12]u8 = undefined;
    var controlled_buf: [12]u8 = undefined;
    const tie_breaker: u64 = 0x0123456789abcdef;

    const controlling = try encodeIceControlling(tie_breaker, &controlling_buf);
    try std.testing.expectEqual(attr_ice_controlling, readU16(controlling[0..2]));
    try std.testing.expectEqual(@as(u16, 8), readU16(controlling[2..4]));
    try std.testing.expectEqual(tie_breaker, try decodeIceControlling(controlling[4..12]));

    const controlled = try encodeIceControlled(tie_breaker, &controlled_buf);
    try std.testing.expectEqual(attr_ice_controlled, readU16(controlled[0..2]));
    try std.testing.expectEqual(@as(u16, 8), readU16(controlled[2..4]));
    try std.testing.expectEqual(tie_breaker, try decodeIceControlled(controlled[4..12]));
}

test "USE-CANDIDATE encodes a zero-length attribute" {
    var buf: [4]u8 = undefined;
    const encoded = try encodeUseCandidate(true, &buf);

    try std.testing.expectEqual(@as(usize, 4), encoded.len);
    try std.testing.expectEqual(attr_use_candidate, readU16(encoded[0..2]));
    try std.testing.expectEqual(@as(u16, 0), readU16(encoded[2..4]));
    try std.testing.expect(try decodeUseCandidate(encoded[4..4]));
}

test "computePriority matches RFC formula for host component one" {
    try std.testing.expectEqual(
        @as(u32, (126 << 24) + (65535 << 8) + 255),
        computePriority(126, 65535, 1),
    );
}

test "findAttr locates PRIORITY in a synthesized STUN message" {
    var priority_buf: [8]u8 = undefined;
    const priority = try encodePriority(0x6effff00, &priority_buf);

    var msg: [stun.header_len + 8]u8 = undefined;
    writeU16(msg[0..2], 0x0001);
    writeU16(msg[2..4], @intCast(priority.len));
    writeU32(msg[4..8], stun.magic_cookie);
    @memset(msg[8..20], 0xaa);
    @memcpy(msg[20..], priority);

    const found = (try findAttr(&msg, attr_priority)).?;
    try std.testing.expectEqual(@as(u32, 0x6effff00), try decodePriority(found));
    try std.testing.expectEqual(null, try findAttr(&msg, attr_use_candidate));
}

test "short fixed-width values are truncated" {
    try std.testing.expectError(error.Truncated, decodePriority(&.{ 0x01, 0x02, 0x03 }));
    try std.testing.expectError(error.Truncated, decodeIceControlling(&.{ 0, 1, 2, 3, 4, 5, 6 }));
    try std.testing.expectError(error.Truncated, decodeIceControlled(&.{ 0, 1, 2, 3, 4, 5, 6 }));
}

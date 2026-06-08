//! Per-node migration metrics snapshot codec.
//!
//! Mesh peers exchange this compact, fixed-width record to inform migration
//! policy without coupling the wire layout to daemon-internal state. The codec
//! is intentionally pure: callers provide all storage and no project modules
//! are imported here.

const std = @import("std");

pub const Snapshot = struct {
    node_id: u64,
    clients: u32,
    channels: u32,
    capacity: u32,
    cpu_permille: u16,
};

pub const encodedLen: usize = 8 + 4 + 4 + 4 + 2;

pub const EncodeError = error{
    BufferTooSmall,
};

pub const DecodeError = error{
    Truncated,
};

pub fn encode(buf: []u8, snap: Snapshot) EncodeError![]const u8 {
    if (buf.len < encodedLen) return error.BufferTooSmall;

    std.mem.writeInt(u64, buf[0..8], snap.node_id, .little);
    std.mem.writeInt(u32, buf[8..12], snap.clients, .little);
    std.mem.writeInt(u32, buf[12..16], snap.channels, .little);
    std.mem.writeInt(u32, buf[16..20], snap.capacity, .little);
    std.mem.writeInt(u16, buf[20..22], snap.cpu_permille, .little);

    return buf[0..encodedLen];
}

pub fn decode(bytes: []const u8) DecodeError!Snapshot {
    if (bytes.len < encodedLen) return error.Truncated;

    return .{
        .node_id = std.mem.readInt(u64, bytes[0..8], .little),
        .clients = std.mem.readInt(u32, bytes[8..12], .little),
        .channels = std.mem.readInt(u32, bytes[12..16], .little),
        .capacity = std.mem.readInt(u32, bytes[16..20], .little),
        .cpu_permille = std.mem.readInt(u16, bytes[20..22], .little),
    };
}

test "roundtrip encodes and decodes fixed little-endian snapshot" {
    const snap: Snapshot = .{
        .node_id = 0x1122334455667788,
        .clients = 0x99aabbcc,
        .channels = 0xddeeff00,
        .capacity = 0x10203040,
        .cpu_permille = 875,
    };
    var buf: [encodedLen]u8 = undefined;

    const encoded = try encode(&buf, snap);

    try std.testing.expectEqual(encodedLen, encoded.len);
    try std.testing.expectEqualSlices(u8, &.{
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
        0xcc, 0xbb, 0xaa, 0x99,
        0x00, 0xff, 0xee, 0xdd,
        0x40, 0x30, 0x20, 0x10,
        0x6b, 0x03,
    }, encoded);

    const decoded = try decode(encoded);
    try std.testing.expectEqual(snap, decoded);
}

test "encode rejects undersized buffer" {
    const snap: Snapshot = .{
        .node_id = 1,
        .clients = 2,
        .channels = 3,
        .capacity = 4,
        .cpu_permille = 5,
    };
    var short: [encodedLen - 1]u8 = undefined;

    try std.testing.expectError(error.BufferTooSmall, encode(&short, snap));
}

test "decode rejects truncated buffers" {
    var bytes: [encodedLen]u8 = .{
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0,
    };

    var len: usize = 0;
    while (len < encodedLen) : (len += 1) {
        try std.testing.expectError(error.Truncated, decode(bytes[0..len]));
    }
}

test "encodedLen matches fixed layout" {
    try std.testing.expectEqual(@as(usize, 22), encodedLen);
}

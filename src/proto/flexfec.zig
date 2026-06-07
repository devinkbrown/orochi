//! Minimal FlexFEC-style XOR repair over a contiguous run of RTP payloads.
//!
//! This is deliberately smaller than RFC 8627: one FEC payload protects `L`
//! source payloads by XORing their bytes, treating shorter payloads as
//! zero-padded to the maximum protected length. It can recover any one missing
//! source payload from the protected set.
const std = @import("std");

pub const Error = error{ BufferTooSmall, LengthMismatch, NotRecoverable };

const header_len = 5;

pub const Header = struct {
    base_seq: u16,
    count: u8,
    protected_len: u16,
};

pub fn encode(base_seq: u16, sources: []const []const u8, out: []u8) Error![]const u8 {
    if (sources.len > std.math.maxInt(u8)) return error.LengthMismatch;

    var protected_len: usize = 0;
    for (sources) |source| {
        if (source.len > std.math.maxInt(u16)) return error.LengthMismatch;
        protected_len = @max(protected_len, source.len);
    }

    const total = header_len + protected_len;
    if (out.len < total) return error.BufferTooSmall;

    std.mem.writeInt(u16, out[0..2], base_seq, .big);
    out[2] = @intCast(sources.len);
    std.mem.writeInt(u16, out[3..5], @intCast(protected_len), .big);

    const repair = out[header_len..total];
    @memset(repair, 0);
    for (sources) |source| {
        for (source, 0..) |byte, i| {
            repair[i] ^= byte;
        }
    }

    return out[0..total];
}

pub fn recover(fec: []const u8, present: []const ?[]const u8, missing_index: usize, out: []u8) Error![]const u8 {
    const header = try decodeHeader(fec);
    const count: usize = header.count;
    if (present.len != count or missing_index >= count) return error.LengthMismatch;
    if (fec.len != header_len + header.protected_len) return error.LengthMismatch;
    if (out.len < header.protected_len) return error.BufferTooSmall;

    var null_count: usize = 0;
    for (present, 0..) |maybe_source, i| {
        if (maybe_source) |source| {
            if (source.len > header.protected_len) return error.LengthMismatch;
        } else {
            null_count += 1;
            if (i != missing_index) return error.NotRecoverable;
        }
    }
    if (null_count != 1 or present[missing_index] != null) return error.NotRecoverable;

    const fec_payload = fec[header_len..];
    const recovered = out[0..header.protected_len];
    @memcpy(recovered, fec_payload);
    for (present) |maybe_source| {
        if (maybe_source) |source| {
            for (source, 0..) |byte, i| {
                recovered[i] ^= byte;
            }
        }
    }

    return recovered;
}

pub fn decodeHeader(fec: []const u8) Error!Header {
    if (fec.len < header_len) return error.LengthMismatch;
    return .{
        .base_seq = std.mem.readInt(u16, fec[0..2], .big),
        .count = fec[2],
        .protected_len = std.mem.readInt(u16, fec[3..5], .big),
    };
}

test "recovers one missing payload from three differing lengths" {
    const testing = std.testing;

    const a = "short";
    const b = "middle payload";
    const c = "tiny";
    const sources = [_][]const u8{ a, b, c };

    var fec_buf: [64]u8 = undefined;
    const fec = try encode(0x3456, sources[0..], &fec_buf);

    const header = try decodeHeader(fec);
    try testing.expectEqual(@as(u16, 0x3456), header.base_seq);
    try testing.expectEqual(@as(u8, 3), header.count);
    try testing.expectEqual(@as(u16, b.len), header.protected_len);

    const present = [_]?[]const u8{ a, null, c };
    var recovered_buf: [32]u8 = undefined;
    const recovered = try recover(fec, present[0..], 1, &recovered_buf);
    try testing.expectEqualSlices(u8, b, recovered);
}

test "recover rejects zero missing packets" {
    const testing = std.testing;

    const a = "one";
    const b = "two";
    const c = "three";
    const sources = [_][]const u8{ a, b, c };

    var fec_buf: [32]u8 = undefined;
    const fec = try encode(0x1000, sources[0..], &fec_buf);

    const present = [_]?[]const u8{ a, b, c };
    var recovered_buf: [16]u8 = undefined;
    try testing.expectError(error.NotRecoverable, recover(fec, present[0..], 1, &recovered_buf));
}

test "recover rejects more than one missing packet" {
    const testing = std.testing;

    const a = "one";
    const b = "two";
    const c = "three";
    const sources = [_][]const u8{ a, b, c };

    var fec_buf: [32]u8 = undefined;
    const fec = try encode(0x1000, sources[0..], &fec_buf);

    const present = [_]?[]const u8{ a, null, null };
    var recovered_buf: [16]u8 = undefined;
    try testing.expectError(error.NotRecoverable, recover(fec, present[0..], 1, &recovered_buf));
}


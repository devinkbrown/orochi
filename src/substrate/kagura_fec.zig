// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Native XOR FEC for Suimyaku media payloads.
//!
//! A repair frame protects one contiguous run of source media payloads. The
//! parity payload is the XOR of each source, with shorter payloads treated as
//! zero-padded to the maximum source length. This is codec-agnostic and operates
//! only on raw payload bytes.

const std = @import("std");
const testing = std.testing;

pub const Error = error{ BufferTooSmall, NotRecoverable, TooMany };

pub const Header = struct {
    base_seq: u32,
    count: u8,
    protected_len: u16,
};

pub const HEADER_LEN: usize = 7;
pub const MAX_SOURCES: usize = 32;

pub fn encode(base_seq: u32, sources: []const []const u8, out: []u8) Error![]const u8 {
    if (sources.len > MAX_SOURCES) return error.TooMany;

    var protected_len: usize = 0;
    for (sources) |source| {
        protected_len = @max(protected_len, source.len);
    }
    if (protected_len > std.math.maxInt(u16)) return error.BufferTooSmall;

    const total_len = HEADER_LEN + protected_len;
    if (out.len < total_len) return error.BufferTooSmall;

    std.mem.writeInt(u32, out[0..4], base_seq, .big);
    out[4] = @intCast(sources.len);
    std.mem.writeInt(u16, out[5..7], @intCast(protected_len), .big);

    const parity = out[HEADER_LEN..total_len];
    @memset(parity, 0);

    for (sources) |source| {
        var i: usize = 0;
        while (i < source.len) : (i += 1) {
            parity[i] ^= source[i];
        }
    }

    return out[0..total_len];
}

pub fn recover(fec: []const u8, present: []const ?[]const u8, missing_index: usize, out: []u8) Error![]const u8 {
    const header = try parseHeader(fec);
    if (present.len != header.count) return error.NotRecoverable;
    if (missing_index >= present.len) return error.NotRecoverable;

    var missing_count: usize = 0;
    for (present, 0..) |source, index| {
        if (source == null) {
            missing_count += 1;
            if (index != missing_index) return error.NotRecoverable;
        }
    }
    if (missing_count != 1 or present[missing_index] != null) return error.NotRecoverable;

    const protected_len: usize = header.protected_len;
    const total_len = HEADER_LEN + protected_len;
    if (fec.len < total_len) return error.BufferTooSmall;
    if (out.len < protected_len) return error.BufferTooSmall;

    const repair = fec[HEADER_LEN..total_len];
    @memcpy(out[0..protected_len], repair);

    for (present) |maybe_source| {
        if (maybe_source) |source| {
            if (source.len > protected_len) return error.NotRecoverable;

            var i: usize = 0;
            while (i < source.len) : (i += 1) {
                out[i] ^= source[i];
            }
        }
    }

    return out[0..protected_len];
}

pub fn parseHeader(fec: []const u8) Error!Header {
    if (fec.len < HEADER_LEN) return error.BufferTooSmall;

    return .{
        .base_seq = std.mem.readInt(u32, fec[0..4], .big),
        .count = fec[4],
        .protected_len = std.mem.readInt(u16, fec[5..7], .big),
    };
}

test "encode and recover one missing payload from differing source lengths" {
    const sources = [_][]const u8{
        "alpha",
        "bravo!!",
        "char",
    };
    var fec_buf: [64]u8 = undefined;

    const fec = try encode(0x10203040, sources[0..], fec_buf[0..]);

    var present = [_]?[]const u8{
        sources[0],
        null,
        sources[2],
    };
    var out: [16]u8 = undefined;

    const recovered = try recover(fec, present[0..], 1, out[0..]);

    try testing.expectEqualSlices(u8, sources[1], recovered[0..sources[1].len]);
    try testing.expect(std.mem.allEqual(u8, recovered[sources[1].len..], 0));
}

test "recover rejects zero or two missing payloads" {
    const sources = [_][]const u8{
        "one",
        "two",
        "three",
    };
    var fec_buf: [64]u8 = undefined;
    const fec = try encode(7, sources[0..], fec_buf[0..]);
    var out: [16]u8 = undefined;

    var none_missing = [_]?[]const u8{
        sources[0],
        sources[1],
        sources[2],
    };
    try testing.expectError(error.NotRecoverable, recover(fec, none_missing[0..], 1, out[0..]));

    var two_missing = [_]?[]const u8{
        sources[0],
        null,
        null,
    };
    try testing.expectError(error.NotRecoverable, recover(fec, two_missing[0..], 1, out[0..]));
}

test "header round-trips base sequence count and protected length" {
    const sources = [_][]const u8{
        "a",
        "abcdef",
        "abc",
    };
    var fec_buf: [64]u8 = undefined;

    const fec = try encode(0x89abcdef, sources[0..], fec_buf[0..]);
    const header = try parseHeader(fec);

    try testing.expectEqual(@as(u32, 0x89abcdef), header.base_seq);
    try testing.expectEqual(@as(u8, 3), header.count);
    try testing.expectEqual(@as(u16, 6), header.protected_len);
}

test "encode rejects more than thirty two sources" {
    var sources: [MAX_SOURCES + 1][]const u8 = undefined;
    for (&sources) |*source| {
        source.* = "";
    }
    var out: [HEADER_LEN]u8 = undefined;

    try testing.expectError(error.TooMany, encode(0, sources[0..], out[0..]));
}

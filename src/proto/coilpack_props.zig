// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Property and fuzz tests for CoilPack wire primitives.
//!
//! These tests exercise attacker-controlled byte slices against the low-level
//! atom decoders, plus canonical encode/decode round-trips for generated valid
//! values. The iteration caps are intentionally small and fixed so this file
//! stays fast under direct `zig test`.
const std = @import("std");
const coilpack = @import("coilpack.zig");

const fuzz_seed: u64 = 0x4d495a5543484931;
const random_decode_iterations = 768;
const round_trip_iterations = 384;
const corrupt_length_iterations = 128;
const truncation_cases = 24;
const max_random_input_len = 256;
const max_payload_len = 96;

fn expectDecodeError(err: coilpack.DecodeError) void {
    switch (err) {
        error.Truncated,
        error.VarintTooLong,
        error.VarintOverflow,
        error.NonCanonicalVarint,
        error.LengthTooLarge,
        error.InvalidBool,
        => {},
    }
}

fn fillAdversarial(random: std.Random, buf: []u8) void {
    random.bytes(buf);
    const pattern = [_]u8{
        0x00, 0x01, 0x02, 0x7f, 0x80, 0x81, 0xff,
        '\r', '\n', ' ',  ',',  ':',  0xc2, 0xa9,
        0xe2, 0x82, 0xac, 0xf0, 0x9f, 0x92, 0xa9,
    };
    for (buf, 0..) |*byte, i| {
        if (i % 5 == 0) byte.* = pattern[i % pattern.len];
    }
}

fn expectSliceWithinInput(input: []const u8, slice: []const u8) !void {
    const input_start = @intFromPtr(input.ptr);
    const input_end = input_start + input.len;
    const slice_start = @intFromPtr(slice.ptr);
    const slice_end = slice_start + slice.len;

    try std.testing.expect(slice_start >= input_start);
    try std.testing.expect(slice_start <= input_end);
    try std.testing.expect(slice_end >= slice_start);
    try std.testing.expect(slice_end <= input_end);
    try std.testing.expect(slice.len <= input.len);
}

fn expectHeaderOkOrError(input: []const u8) !void {
    const decoded = coilpack.decodeHeader(input) catch |err| {
        expectDecodeError(err);
        return;
    };

    var out: [coilpack.undertow_header_len]u8 = undefined;
    try std.testing.expectEqual(coilpack.undertow_header_len, try coilpack.encodeHeader(&out, decoded));
    try std.testing.expect(coilpack.canonicalEqual(input[0..coilpack.undertow_header_len], &out));
}

fn expectReaderOkOrError(input: []const u8) !void {
    var u8_reader = coilpack.Cbs.init(input);
    if (u8_reader.readU8()) |_| {
        try std.testing.expect(u8_reader.pos <= input.len);
    } else |err| expectDecodeError(err);

    var u16_reader = coilpack.Cbs.init(input);
    if (u16_reader.readU16Le()) |_| {
        try std.testing.expect(u16_reader.pos <= input.len);
    } else |err| expectDecodeError(err);

    var u24_reader = coilpack.Cbs.init(input);
    if (u24_reader.readU24Le()) |_| {
        try std.testing.expect(u24_reader.pos <= input.len);
    } else |err| expectDecodeError(err);

    var u32_reader = coilpack.Cbs.init(input);
    if (u32_reader.readU32Le()) |_| {
        try std.testing.expect(u32_reader.pos <= input.len);
    } else |err| expectDecodeError(err);

    var u64_reader = coilpack.Cbs.init(input);
    if (u64_reader.readU64Le()) |_| {
        try std.testing.expect(u64_reader.pos <= input.len);
    } else |err| expectDecodeError(err);

    var bool_reader = coilpack.Cbs.init(input);
    if (bool_reader.readBool()) |_| {
        try std.testing.expect(bool_reader.pos == 1);
    } else |err| expectDecodeError(err);

    var varint_reader = coilpack.Cbs.init(input);
    if (varint_reader.readVarint()) |value| {
        try std.testing.expect(varint_reader.pos <= input.len);

        var out: [coilpack.max_varint_bytes]u8 = undefined;
        var writer = coilpack.Cbb.init(&out);
        _ = try writer.writeVarint(value);
        try std.testing.expect(coilpack.canonicalEqual(input[0..varint_reader.pos], writer.written()));
    } else |err| {
        expectDecodeError(err);
        try std.testing.expectEqual(@as(usize, 0), varint_reader.pos);
    }

    var bytes_reader = coilpack.Cbs.init(input);
    if (bytes_reader.readBytes()) |bytes| {
        try std.testing.expect(bytes_reader.pos <= input.len);
        try expectSliceWithinInput(input, bytes);

        var out: [max_random_input_len + coilpack.max_varint_bytes]u8 = undefined;
        var writer = coilpack.Cbb.init(&out);
        _ = try writer.writeBytes(bytes);
        try std.testing.expect(coilpack.canonicalEqual(input[0..bytes_reader.pos], writer.written()));
    } else |err| {
        expectDecodeError(err);
        try std.testing.expectEqual(@as(usize, 0), bytes_reader.pos);
    }

    try expectHeaderOkOrError(input);
}

fn expectReadBytesError(input: []const u8) !void {
    var reader = coilpack.Cbs.init(input);
    _ = reader.readBytes() catch |err| {
        expectDecodeError(err);
        try std.testing.expectEqual(@as(usize, 0), reader.pos);
        return;
    };
    return error.TestExpectedError;
}

fn expectTruncatedFixed(input: []const u8) !void {
    if (input.len < 1) {
        var reader = coilpack.Cbs.init(input);
        try std.testing.expectError(error.Truncated, reader.readU8());
    }
    if (input.len < 2) {
        var reader = coilpack.Cbs.init(input);
        try std.testing.expectError(error.Truncated, reader.readU16Le());
    }
    if (input.len < 3) {
        var reader = coilpack.Cbs.init(input);
        try std.testing.expectError(error.Truncated, reader.readU24Le());
    }
    if (input.len < 4) {
        var reader = coilpack.Cbs.init(input);
        try std.testing.expectError(error.Truncated, reader.readU32Le());
    }
    if (input.len < 8) {
        var reader = coilpack.Cbs.init(input);
        try std.testing.expectError(error.Truncated, reader.readU64Le());
        try std.testing.expectError(error.Truncated, coilpack.decodeHeader(input));
    }
}

test "random attacker bytes decode to value or typed error" {
    var prng = std.Random.DefaultPrng.init(fuzz_seed);
    const random = prng.random();

    var input: [max_random_input_len]u8 = undefined;
    var i: usize = 0;
    while (i < random_decode_iterations) : (i += 1) {
        const len = switch (i) {
            0 => 0,
            1 => max_random_input_len,
            else => random.intRangeAtMost(usize, 0, max_random_input_len),
        };
        fillAdversarial(random, input[0..len]);
        try expectReaderOkOrError(input[0..len]);
    }
}

test "random valid values round-trip and re-encode canonically" {
    var prng = std.Random.DefaultPrng.init(fuzz_seed ^ 0xa1a2_a3a4_a5a6_a7a8);
    const random = prng.random();

    var input: [max_payload_len]u8 = undefined;
    var encoded: [max_payload_len + 32]u8 = undefined;
    var canonical: [max_payload_len + 32]u8 = undefined;

    var i: usize = 0;
    while (i < round_trip_iterations) : (i += 1) {
        switch (random.intRangeLessThan(u8, 0, 9)) {
            0 => {
                const value = random.int(u8);
                var writer = coilpack.Cbb.init(&encoded);
                _ = try writer.writeU8(value);
                var reader = coilpack.Cbs.init(writer.written());
                const decoded = try reader.readU8();
                try std.testing.expectEqual(value, decoded);

                var rewrite = coilpack.Cbb.init(&canonical);
                _ = try rewrite.writeU8(decoded);
                try std.testing.expect(coilpack.canonicalEqual(writer.written(), rewrite.written()));
            },
            1 => {
                const value = random.int(u16);
                var writer = coilpack.Cbb.init(&encoded);
                _ = try writer.writeU16Le(value);
                var reader = coilpack.Cbs.init(writer.written());
                const decoded = try reader.readU16Le();
                try std.testing.expectEqual(value, decoded);

                var rewrite = coilpack.Cbb.init(&canonical);
                _ = try rewrite.writeU16Le(decoded);
                try std.testing.expect(coilpack.canonicalEqual(writer.written(), rewrite.written()));
            },
            2 => {
                const value = random.int(u24);
                var writer = coilpack.Cbb.init(&encoded);
                _ = try writer.writeU24Le(value);
                var reader = coilpack.Cbs.init(writer.written());
                const decoded = try reader.readU24Le();
                try std.testing.expectEqual(value, decoded);

                var rewrite = coilpack.Cbb.init(&canonical);
                _ = try rewrite.writeU24Le(decoded);
                try std.testing.expect(coilpack.canonicalEqual(writer.written(), rewrite.written()));
            },
            3 => {
                const value = random.int(u32);
                var writer = coilpack.Cbb.init(&encoded);
                _ = try writer.writeU32Le(value);
                var reader = coilpack.Cbs.init(writer.written());
                const decoded = try reader.readU32Le();
                try std.testing.expectEqual(value, decoded);

                var rewrite = coilpack.Cbb.init(&canonical);
                _ = try rewrite.writeU32Le(decoded);
                try std.testing.expect(coilpack.canonicalEqual(writer.written(), rewrite.written()));
            },
            4 => {
                const value = random.int(u64);
                var writer = coilpack.Cbb.init(&encoded);
                _ = try writer.writeU64Le(value);
                var reader = coilpack.Cbs.init(writer.written());
                const decoded = try reader.readU64Le();
                try std.testing.expectEqual(value, decoded);

                var rewrite = coilpack.Cbb.init(&canonical);
                _ = try rewrite.writeU64Le(decoded);
                try std.testing.expect(coilpack.canonicalEqual(writer.written(), rewrite.written()));
            },
            5 => {
                const value = random.boolean();
                var writer = coilpack.Cbb.init(&encoded);
                _ = try writer.writeBool(value);
                var reader = coilpack.Cbs.init(writer.written());
                const decoded = try reader.readBool();
                try std.testing.expectEqual(value, decoded);

                var rewrite = coilpack.Cbb.init(&canonical);
                _ = try rewrite.writeBool(decoded);
                try std.testing.expect(coilpack.canonicalEqual(writer.written(), rewrite.written()));
            },
            6 => {
                const value = switch (i % 8) {
                    0 => @as(u64, 0),
                    1 => @as(u64, 0x7f),
                    2 => @as(u64, 0x80),
                    3 => @as(u64, 0x3fff),
                    4 => @as(u64, 0x4000),
                    5 => @as(u64, 0xffff_ffff),
                    6 => @as(u64, 0x1_0000_0000),
                    else => random.int(u64),
                };
                var writer = coilpack.Cbb.init(&encoded);
                _ = try writer.writeVarint(value);
                var reader = coilpack.Cbs.init(writer.written());
                const decoded = try reader.readVarint();
                try std.testing.expectEqual(value, decoded);

                var rewrite = coilpack.Cbb.init(&canonical);
                _ = try rewrite.writeVarint(decoded);
                try std.testing.expect(coilpack.canonicalEqual(writer.written(), rewrite.written()));
            },
            7 => {
                const len = switch (i % 4) {
                    0 => @as(usize, 0),
                    1 => @as(usize, 1),
                    2 => @as(usize, 127),
                    else => random.intRangeAtMost(usize, 0, max_payload_len),
                };
                fillAdversarial(random, input[0..@min(len, input.len)]);

                var writer = coilpack.Cbb.init(&encoded);
                _ = try writer.writeBytes(input[0..@min(len, input.len)]);
                var reader = coilpack.Cbs.init(writer.written());
                const decoded = try reader.readBytes();
                try std.testing.expectEqualSlices(u8, input[0..@min(len, input.len)], decoded);
                try expectSliceWithinInput(writer.written(), decoded);

                var rewrite = coilpack.Cbb.init(&canonical);
                _ = try rewrite.writeBytes(decoded);
                try std.testing.expect(coilpack.canonicalEqual(writer.written(), rewrite.written()));
            },
            else => {
                const header = coilpack.UndertowHeader{
                    .type = random.int(u8),
                    .ctrl = random.int(u8),
                    .length = random.int(u16),
                    .stream_id = random.int(u24),
                    .hop = random.int(u8),
                };
                const written = try coilpack.encodeHeader(&encoded, header);
                const decoded = try coilpack.decodeHeader(encoded[0..written]);
                try std.testing.expectEqual(header.type, decoded.type);
                try std.testing.expectEqual(header.ctrl, decoded.ctrl);
                try std.testing.expectEqual(header.length, decoded.length);
                try std.testing.expectEqual(header.stream_id, decoded.stream_id);
                try std.testing.expectEqual(header.hop, decoded.hop);

                const rewritten = try coilpack.encodeHeader(&canonical, decoded);
                try std.testing.expect(coilpack.canonicalEqual(encoded[0..written], canonical[0..rewritten]));
            },
        }
    }
}

test "every prefix of valid encodings is truncated or canonical" {
    var prng = std.Random.DefaultPrng.init(fuzz_seed ^ 0x7472756e635f3031);
    const random = prng.random();

    var payload: [max_payload_len]u8 = undefined;
    var encoded: [max_payload_len + 32]u8 = undefined;

    var case_index: usize = 0;
    while (case_index < truncation_cases) : (case_index += 1) {
        var writer = coilpack.Cbb.init(&encoded);
        switch (case_index % 5) {
            0 => _ = try writer.writeU64Le(random.int(u64)),
            1 => _ = try writer.writeVarint(switch (case_index % 6) {
                0 => @as(u64, 0),
                1 => @as(u64, 127),
                2 => @as(u64, 128),
                3 => @as(u64, 16_384),
                4 => @as(u64, 0xffff_ffff),
                else => random.int(u64),
            }),
            2 => {
                const len = switch (case_index % 4) {
                    0 => @as(usize, 0),
                    1 => @as(usize, 1),
                    2 => @as(usize, max_payload_len),
                    else => random.intRangeAtMost(usize, 0, max_payload_len),
                };
                fillAdversarial(random, payload[0..len]);
                _ = try writer.writeBytes(payload[0..len]);
            },
            3 => {
                _ = try coilpack.encodeHeader(writer.buf[writer.pos..], .{
                    .type = random.int(u8),
                    .ctrl = random.int(u8),
                    .length = random.int(u16),
                    .stream_id = random.int(u24),
                    .hop = random.int(u8),
                });
                writer.pos += coilpack.undertow_header_len;
            },
            else => {
                _ = try writer.writeU8(random.int(u8));
                _ = try writer.writeU16Le(random.int(u16));
                _ = try writer.writeU24Le(random.int(u24));
                _ = try writer.writeU32Le(random.int(u32));
                _ = try writer.writeBool(random.boolean());
            },
        }

        const full = writer.written();
        var prefix_len: usize = 0;
        while (prefix_len < full.len) : (prefix_len += 1) {
            const prefix = full[0..prefix_len];
            try expectReaderOkOrError(prefix);

            if (case_index % 5 == 0 and prefix_len < 8) {
                try expectTruncatedFixed(prefix);
            }
            if (case_index % 5 == 1) {
                var reader = coilpack.Cbs.init(prefix);
                try std.testing.expectError(error.Truncated, reader.readVarint());
                try std.testing.expectEqual(@as(usize, 0), reader.pos);
            }
            if (case_index % 5 == 2) {
                try expectReadBytesError(prefix);
            }
            if (case_index % 5 == 3) {
                try std.testing.expectError(error.Truncated, coilpack.decodeHeader(prefix));
            }
        }
    }
}

test "declared byte lengths are bounded by the input" {
    var prng = std.Random.DefaultPrng.init(fuzz_seed ^ 0x6c656e5f626f756e);
    const random = prng.random();

    var input: [coilpack.max_varint_bytes + 16]u8 = undefined;
    var i: usize = 0;
    while (i < corrupt_length_iterations) : (i += 1) {
        const payload_len = random.intRangeAtMost(usize, 0, 16);
        const declared_len = @as(u64, payload_len) + 1 + random.intRangeAtMost(u64, 0, 1_000_000);

        var writer = coilpack.Cbb.init(&input);
        _ = try writer.writeVarint(declared_len);
        fillAdversarial(random, input[writer.bytesWritten() .. writer.bytesWritten() + payload_len]);
        writer.pos += payload_len;

        try expectReadBytesError(writer.written());
    }

    const non_canonical_lengths = [_][]const u8{
        &.{ 0x80, 0x00 },
        &.{ 0x81, 0x00, 'x' },
        &.{ 0x80, 0x80, 0x00, 'x' },
    };
    for (non_canonical_lengths) |input_slice| {
        try expectReadBytesError(input_slice);
    }

    var huge: [coilpack.max_varint_bytes]u8 = undefined;
    var huge_writer = coilpack.Cbb.init(&huge);
    _ = try huge_writer.writeVarint(std.math.maxInt(u64));
    try expectReadBytesError(huge_writer.written());
}

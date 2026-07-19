// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deterministic property and fuzz-style tests for RFC 6455 WebSocket helpers.
const std = @import("std");
const websocket = @import("websocket.zig");

const seed: u64 = 0x4d495a5543484957;
const max_frame_size: usize = 1024;
const arbitrary_iterations: usize = 1800;
const round_trip_iterations: usize = 700;
const incremental_iterations: usize = 420;
const fragmented_iterations: usize = 220;
const handshake_iterations: usize = 320;

fn expectFrameError(err: websocket.FrameError) void {
    switch (err) {
        error.Truncated,
        error.ReservedBitsSet,
        error.InvalidOpcode,
        error.FragmentedControlFrame,
        error.ControlFrameTooLarge,
        error.NonCanonicalLength,
        error.PayloadTooLarge,
        error.UnmaskedClientFrame,
        error.MaskedServerFrame,
        error.OutputTooSmall,
        => {},
    }
}

fn expectHandshakeError(err: websocket.HandshakeError) void {
    switch (err) {
        error.MissingHeaderEnd,
        error.EmptyRequest,
        error.InvalidRequestLine,
        error.UnsupportedMethod,
        error.UnsupportedProtocol,
        error.MalformedHeader,
        error.MissingHost,
        error.MissingUpgrade,
        error.MissingConnection,
        error.MissingKey,
        error.MissingVersion,
        error.InvalidUpgrade,
        error.InvalidConnection,
        error.InvalidKey,
        error.UnsupportedVersion,
        error.OutputTooSmall,
        => {},
    }
}

fn expectSliceWithin(owner: []const u8, slice: []const u8) !void {
    const owner_start = @intFromPtr(owner.ptr);
    const owner_end = owner_start + owner.len;
    const slice_start = @intFromPtr(slice.ptr);
    const slice_end = slice_start + slice.len;

    try std.testing.expect(slice_start >= owner_start);
    try std.testing.expect(slice_start <= owner_end);
    try std.testing.expect(slice_end >= slice_start);
    try std.testing.expect(slice_end <= owner_end);
}

fn expectPayloadInBounds(input: []const u8, payload_out: []const u8, decoded: websocket.DecodeResult) !void {
    try std.testing.expect(decoded.consumed <= input.len);
    if (decoded.frame.masked) {
        try expectSliceWithin(payload_out, decoded.frame.payload);
    } else {
        try expectSliceWithin(input, decoded.frame.payload);
    }
}

fn decodeOkOrTypedError(
    comptime limit: usize,
    direction: websocket.Direction,
    input: []const u8,
    payload_out: []u8,
) !void {
    const decoded = websocket.decodeFrame(limit, direction, input, payload_out) catch |err| {
        expectFrameError(err);
        return;
    };

    try expectPayloadInBounds(input, payload_out, decoded);
    try std.testing.expect(decoded.frame.payload.len <= limit);
    if (direction == .client_to_server) {
        try std.testing.expect(decoded.frame.masked);
    } else {
        try std.testing.expect(!decoded.frame.masked);
    }
}

fn randomInputLen(random: std.Random, iteration: usize, max_len: usize) usize {
    return switch (iteration % 19) {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 5,
        4 => 6,
        5 => 125,
        6 => 126,
        7 => 127,
        8 => 128,
        9 => max_len,
        else => random.intRangeAtMost(usize, 0, max_len),
    };
}

fn fillAdversarial(random: std.Random, out: []u8, iteration: usize) void {
    random.bytes(out);

    const patterns = [_][]const u8{
        &.{ 0x81, 0x00 },
        &.{ 0x81, 0x80, 1, 2, 3, 4 },
        &.{ 0x81, 0x7e, 0x00, 0x7d },
        &.{ 0x81, 0xfe, 0x00, 0x7d, 1, 2, 3, 4 },
        &.{ 0x89, 0xff, 0xff, 0xff, 0xff, 0xff },
        &.{ 0xf1, 0x80, 1, 2, 3, 4 },
        &.{ 0x83, 0x80, 1, 2, 3, 4 },
        &.{ 0x01, 0x80, 1, 2, 3, 4 },
    };

    if (out.len > 0) {
        const pattern = patterns[iteration % patterns.len];
        const n = @min(out.len, pattern.len);
        @memcpy(out[0..n], pattern[0..n]);
    }
}

fn randomOpcode(random: std.Random, iteration: usize) websocket.Opcode {
    const opcodes = [_]websocket.Opcode{ .text, .binary, .continuation };
    if (iteration % 11 == 0) return .ping;
    if (iteration % 17 == 0) return .pong;
    return opcodes[random.uintLessThan(usize, opcodes.len)];
}

fn randomPayloadLen(random: std.Random, iteration: usize, opcode: websocket.Opcode) usize {
    if (opcode.isControl()) {
        return switch (iteration % 7) {
            0 => 0,
            1 => 1,
            2 => 2,
            3 => 125,
            else => random.intRangeAtMost(usize, 0, 125),
        };
    }

    return switch (iteration % 17) {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 125,
        4 => 126,
        5 => 127,
        6 => 128,
        7 => max_frame_size,
        else => random.intRangeAtMost(usize, 0, max_frame_size),
    };
}

fn randomMask(random: std.Random) [4]u8 {
    return .{ random.int(u8), random.int(u8), random.int(u8), random.int(u8) };
}

fn expectDecodedFrame(
    expected_fin: bool,
    expected_opcode: websocket.Opcode,
    expected_payload: []const u8,
    encoded: []const u8,
    payload_out: []const u8,
    decoded: websocket.DecodeResult,
) !void {
    try std.testing.expectEqual(expected_fin, decoded.frame.fin);
    try std.testing.expectEqual(expected_opcode, decoded.frame.opcode);
    try std.testing.expect(decoded.frame.masked);
    try std.testing.expectEqual(encoded.len, decoded.consumed);
    try std.testing.expectEqualSlices(u8, expected_payload, decoded.frame.payload);
    try expectPayloadInBounds(encoded, payload_out, decoded);
}

test "handshake accepts canonical request and rejects malformed requests with typed errors" {
    const request =
        "GET /chat HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: keep-alive, Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n\r\n";

    try websocket.parseHandshake(request);

    var response_buf: [websocket.MAX_RESPONSE_LEN]u8 = undefined;
    const response = try websocket.buildHandshakeResponse(request, &response_buf);
    try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 101 Switching Protocols\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, response, "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n") != null);

    var prng = std.Random.DefaultPrng.init(seed ^ 0xaaa1);
    const random = prng.random();
    var input: [384]u8 = undefined;
    var out: [websocket.MAX_RESPONSE_LEN]u8 = undefined;

    for (0..handshake_iterations) |iteration| {
        const len = randomInputLen(random, iteration, input.len);
        fillAdversarial(random, input[0..len], iteration);

        if (websocket.parseHandshake(input[0..len])) {
            const built = websocket.buildHandshakeResponse(input[0..len], &out) catch |err| {
                expectHandshakeError(err);
                continue;
            };
            try std.testing.expect(built.len <= out.len);
        } else |err| {
            expectHandshakeError(err);
        }
    }
}

test "frame parser accepts arbitrary bytes or returns typed errors" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0x1001);
    const random = prng.random();
    var input: [max_frame_size + 32]u8 = undefined;
    var payload_out: [max_frame_size]u8 = undefined;

    for (0..arbitrary_iterations) |iteration| {
        const len = randomInputLen(random, iteration, input.len);
        fillAdversarial(random, input[0..len], iteration);
        const direction: websocket.Direction = if (random.boolean()) .client_to_server else .server_to_client;
        try decodeOkOrTypedError(max_frame_size, direction, input[0..len], &payload_out);
    }
}

test "masked client frames round trip generated payloads" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0x2002);
    const random = prng.random();
    var payload: [max_frame_size]u8 = undefined;
    var encoded_buf: [max_frame_size + 32]u8 = undefined;
    var payload_out: [max_frame_size]u8 = undefined;

    for (0..round_trip_iterations) |iteration| {
        const opcode = randomOpcode(random, iteration);
        const payload_len = randomPayloadLen(random, iteration, opcode);
        random.bytes(payload[0..payload_len]);

        const encoded = try websocket.encodeFrame(max_frame_size, .{
            .fin = true,
            .opcode = opcode,
            .mask_key = randomMask(random),
        }, payload[0..payload_len], &encoded_buf);

        const decoded = try websocket.decodeFrame(max_frame_size, .client_to_server, encoded, &payload_out);
        try expectDecodedFrame(true, opcode, payload[0..payload_len], encoded, &payload_out, decoded);
    }
}

test "incremental prefixes are truncated until they match whole-frame decode" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0x3003);
    const random = prng.random();
    var payload: [max_frame_size]u8 = undefined;
    var encoded_buf: [max_frame_size + 32]u8 = undefined;
    var prefix_buf: [max_frame_size + 32]u8 = undefined;
    var whole_out: [max_frame_size]u8 = undefined;
    var prefix_out: [max_frame_size]u8 = undefined;

    for (0..incremental_iterations) |iteration| {
        const opcode = if (iteration % 2 == 0) websocket.Opcode.text else websocket.Opcode.binary;
        const payload_len = randomPayloadLen(random, iteration, opcode);
        random.bytes(payload[0..payload_len]);

        const encoded = try websocket.encodeFrame(max_frame_size, .{
            .fin = iteration % 5 != 0,
            .opcode = opcode,
            .mask_key = randomMask(random),
        }, payload[0..payload_len], &encoded_buf);
        const whole = try websocket.decodeFrame(max_frame_size, .client_to_server, encoded, &whole_out);

        var len: usize = 0;
        while (len < encoded.len - 1) : (len += 1) {
            prefix_buf[len] = encoded[len];
            try std.testing.expectError(error.Truncated, websocket.decodeFrame(max_frame_size, .client_to_server, prefix_buf[0 .. len + 1], &prefix_out));
        }

        @memcpy(prefix_buf[0..encoded.len], encoded);
        const incremental = try websocket.decodeFrame(max_frame_size, .client_to_server, prefix_buf[0..encoded.len], &prefix_out);
        try expectDecodedFrame(whole.frame.fin, whole.frame.opcode, whole.frame.payload, prefix_buf[0..encoded.len], &prefix_out, incremental);
    }
}

test "fragmented message frames decode identically when bytes arrive incrementally" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0x4004);
    const random = prng.random();
    var first_payload: [256]u8 = undefined;
    var second_payload: [256]u8 = undefined;
    var stream: [2 * (256 + 32)]u8 = undefined;
    var incremental: [256 + 32]u8 = undefined;
    var whole_out: [256]u8 = undefined;
    var incremental_out: [256]u8 = undefined;

    for (0..fragmented_iterations) |iteration| {
        const first_len = if (iteration % 11 == 0) first_payload.len else random.intRangeAtMost(usize, 0, first_payload.len);
        const second_len = if (iteration % 13 == 0) 0 else random.intRangeAtMost(usize, 0, second_payload.len);
        random.bytes(first_payload[0..first_len]);
        random.bytes(second_payload[0..second_len]);

        var stream_len: usize = 0;
        const first_encoded = try websocket.encodeFrame(max_frame_size, .{
            .fin = false,
            .opcode = .text,
            .mask_key = randomMask(random),
        }, first_payload[0..first_len], stream[stream_len..]);
        stream_len += first_encoded.len;

        const second_encoded = try websocket.encodeFrame(max_frame_size, .{
            .fin = true,
            .opcode = .continuation,
            .mask_key = randomMask(random),
        }, second_payload[0..second_len], stream[stream_len..]);
        stream_len += second_encoded.len;

        const first_whole = try websocket.decodeFrame(max_frame_size, .client_to_server, stream[0..stream_len], &whole_out);
        try expectDecodedFrame(false, .text, first_payload[0..first_len], stream[0..first_encoded.len], &whole_out, first_whole);
        const second_whole = try websocket.decodeFrame(max_frame_size, .client_to_server, stream[first_whole.consumed..stream_len], &whole_out);
        try expectDecodedFrame(true, .continuation, second_payload[0..second_len], stream[first_whole.consumed..stream_len], &whole_out, second_whole);

        var incremental_len: usize = 0;
        var decoded_count: usize = 0;
        for (stream[0..stream_len]) |byte| {
            incremental[incremental_len] = byte;
            incremental_len += 1;

            const decoded = websocket.decodeFrame(max_frame_size, .client_to_server, incremental[0..incremental_len], &incremental_out) catch |err| {
                try std.testing.expectEqual(error.Truncated, err);
                continue;
            };

            if (decoded_count == 0) {
                try expectDecodedFrame(false, .text, first_payload[0..first_len], incremental[0..incremental_len], &incremental_out, decoded);
            } else {
                try expectDecodedFrame(true, .continuation, second_payload[0..second_len], incremental[0..incremental_len], &incremental_out, decoded);
            }
            decoded_count += 1;
            incremental_len = 0;
        }

        try std.testing.expectEqual(@as(usize, 2), decoded_count);
        try std.testing.expectEqual(@as(usize, 0), incremental_len);
    }
}

test "oversized and unmasked client frames reject without crashing" {
    var payload: [max_frame_size + 1]u8 = undefined;
    @memset(&payload, 'x');
    var encoded_buf: [payload.len + 32]u8 = undefined;
    var payload_out: [max_frame_size + 1]u8 = undefined;

    try std.testing.expectError(error.PayloadTooLarge, websocket.encodeFrame(max_frame_size, .{
        .opcode = .binary,
        .mask_key = .{ 1, 2, 3, 4 },
    }, &payload, &encoded_buf));

    const unmasked = try websocket.encodeFrame(max_frame_size + 1, .{
        .opcode = .binary,
    }, &payload, &encoded_buf);
    try std.testing.expectError(error.UnmaskedClientFrame, websocket.decodeFrame(max_frame_size + 1, .client_to_server, unmasked, &payload_out));

    const masked = try websocket.encodeFrame(max_frame_size + 1, .{
        .opcode = .binary,
        .mask_key = .{ 5, 6, 7, 8 },
    }, &payload, &encoded_buf);
    try std.testing.expectError(error.PayloadTooLarge, websocket.decodeFrame(max_frame_size, .client_to_server, masked, &payload_out));
}

test "decoded payload slices stay within input or caller output buffers" {
    const server_payload = "PING :onyx\r\n";
    var server_encoded_buf: [64]u8 = undefined;
    const server_encoded = try websocket.encodeFrame(64, .{ .opcode = .text }, server_payload, &server_encoded_buf);
    const server_decoded = try websocket.decodeFrame(64, .server_to_client, server_encoded, &.{});
    try expectPayloadInBounds(server_encoded, &.{}, server_decoded);
    try std.testing.expectEqualStrings(server_payload, server_decoded.frame.payload);

    const client_payload = "PRIVMSG #onyx :hello\r\n";
    var client_encoded_buf: [96]u8 = undefined;
    var client_payload_out: [96]u8 = undefined;
    const client_encoded = try websocket.encodeFrame(96, .{
        .opcode = .text,
        .mask_key = .{ 0x12, 0x34, 0x56, 0x78 },
    }, client_payload, &client_encoded_buf);
    const client_decoded = try websocket.decodeFrame(96, .client_to_server, client_encoded, &client_payload_out);
    try expectPayloadInBounds(client_encoded, &client_payload_out, client_decoded);
    try std.testing.expectEqualStrings(client_payload, client_decoded.frame.payload);
}

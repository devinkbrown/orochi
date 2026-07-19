// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deterministic property tests for CTCP SOH extraction and low-level quoting.
const std = @import("std");
const ctcp = @import("ctcp.zig");

const seed: u64 = 0x4354_4350_5052_4f50;
const arbitrary_iterations: usize = 4000;
const round_trip_iterations: usize = 2400;
const bounded_iterations: usize = 512;
const max_random_len: usize = 256;
const max_arg_len: usize = 192;

fn expectParseError(err: ctcp.ParseError) void {
    switch (err) {
        error.InvalidMessage,
        error.UnterminatedCtcp,
        error.EmptyCtcp,
        error.InvalidCommand,
        error.CommandTooLong,
        error.MalformedQuote,
        => {},
    }
}

fn expectQuoteError(err: ctcp.QuoteError) void {
    switch (err) {
        error.InvalidByte,
        error.MalformedQuote,
        error.OutputTooSmall,
        => {},
    }
}

fn expectBuildError(err: ctcp.BuildError) void {
    switch (err) {
        error.InvalidCommand,
        error.InvalidTarget,
        error.InvalidByte,
        error.OutputTooSmall,
        => {},
    }
}

fn expectSliceWithin(owner: []const u8, slice: []const u8) !void {
    try std.testing.expect(slice.len <= owner.len);
    if (slice.len == 0) return;

    const owner_start = @intFromPtr(owner.ptr);
    const owner_end = owner_start + owner.len;
    const slice_start = @intFromPtr(slice.ptr);
    const slice_end = slice_start + slice.len;

    try std.testing.expect(slice_start >= owner_start);
    try std.testing.expect(slice_end >= slice_start);
    try std.testing.expect(slice_end <= owner_end);
}

fn expectViewInBounds(input: []const u8, view: ctcp.CtcpView) !void {
    try expectSliceWithin(input, view.raw);
    try expectSliceWithin(input, view.command);
    if (view.arg_raw) |arg| try expectSliceWithin(input, arg);
    try std.testing.expect(view.raw.len >= 2);
    try std.testing.expectEqual(ctcp.delimiter, view.raw[0]);
    try std.testing.expectEqual(ctcp.delimiter, view.raw[view.raw.len - 1]);
}

fn randomInputLen(random: std.Random, iteration: usize, max_len: usize) usize {
    return switch (iteration % 23) {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 3,
        4 => 31,
        5 => 32,
        6 => 33,
        7 => max_len,
        else => random.intRangeAtMost(usize, 0, max_len),
    };
}

fn fillArbitrary(random: std.Random, out: []u8, iteration: usize) void {
    random.bytes(out);

    const patterns = [_][]const u8{
        "\x01\x01",
        "\x01ACTION waves\x01",
        "\x01VERSION onyx-server\x01",
        "\x01PING token\x10n42\x01",
        "\x01PING token\x10x\x01",
        "\x01TOO-LONG-COMMAND-NAME-THAT-EXCEEDS-THE-DEFAULT hello\x01",
        "text \x01DCC SEND file 1 2 3\x01 tail",
        "\x01ACTION has\x01embedded\x01",
        "\x01PING raw\x00nul\x01",
        "\x01PING raw\x10\x01",
    };

    if (out.len == 0) return;
    const pattern = patterns[iteration % patterns.len];
    const n = @min(out.len, pattern.len);
    @memcpy(out[0..n], pattern[0..n]);
}

fn fillQuotableBytes(random: std.Random, out: []u8, iteration: usize) void {
    random.bytes(out);
    for (out, 0..) |*byte, i| {
        byte.* = switch ((iteration + i) % 29) {
            0 => 0,
            1 => '\n',
            2 => '\r',
            3 => ctcp.quote_byte,
            4 => ' ',
            5 => '\t',
            else => blk: {
                var ch = byte.*;
                if (ch == ctcp.delimiter) ch = 'A';
                break :blk ch;
            },
        };
    }
}

fn expectQuotedForm(input: []const u8, quoted: []const u8) !void {
    var read: usize = 0;
    var write: usize = 0;

    while (read < input.len) : (read += 1) {
        const ch = input[read];
        switch (ch) {
            0 => {
                try std.testing.expectEqual(ctcp.quote_byte, quoted[write]);
                try std.testing.expectEqual(@as(u8, '0'), quoted[write + 1]);
                write += 2;
            },
            '\n' => {
                try std.testing.expectEqual(ctcp.quote_byte, quoted[write]);
                try std.testing.expectEqual(@as(u8, 'n'), quoted[write + 1]);
                write += 2;
            },
            '\r' => {
                try std.testing.expectEqual(ctcp.quote_byte, quoted[write]);
                try std.testing.expectEqual(@as(u8, 'r'), quoted[write + 1]);
                write += 2;
            },
            ctcp.quote_byte => {
                try std.testing.expectEqual(ctcp.quote_byte, quoted[write]);
                try std.testing.expectEqual(ctcp.quote_byte, quoted[write + 1]);
                write += 2;
            },
            else => {
                try std.testing.expectEqual(ch, quoted[write]);
                write += 1;
            },
        }
    }

    try std.testing.expectEqual(quoted.len, write);
}

fn parsedOkOrTypedError(input: []const u8, dequote_out: []u8) !void {
    const maybe_view = ctcp.parseFirst(.privmsg, input) catch |err| {
        expectParseError(err);
        return;
    };

    const view = maybe_view orelse return;
    try expectViewInBounds(input, view);

    const dequoted = view.dequoteArg(dequote_out) catch |err| {
        expectQuoteError(err);
        return;
    };
    try expectSliceWithin(dequote_out, dequoted);
}

test "arbitrary bytes extract or dequote to typed errors without panics" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0x1001);
    const random = prng.random();

    var input: [max_random_len]u8 = undefined;
    var dequote_out: [max_random_len]u8 = undefined;

    for (0..arbitrary_iterations) |iteration| {
        const len = randomInputLen(random, iteration, input.len);
        fillArbitrary(random, input[0..len], iteration);
        try parsedOkOrTypedError(input[0..len], &dequote_out);
    }
}

test "SOH-delimited payload build and low-level quote round trip" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0x2002);
    const random = prng.random();

    var raw_arg: [max_arg_len]u8 = undefined;
    var quoted_buf: [max_arg_len * 2]u8 = undefined;
    var dequoted_buf: [max_arg_len]u8 = undefined;
    var payload_buf: [max_arg_len * 2 + 16]u8 = undefined;

    for (0..round_trip_iterations) |iteration| {
        const len = randomInputLen(random, iteration, raw_arg.len);
        fillQuotableBytes(random, raw_arg[0..len], iteration);

        const quoted = try ctcp.quote(raw_arg[0..len], &quoted_buf);
        try expectQuotedForm(raw_arg[0..len], quoted);

        const dequoted = try ctcp.dequote(quoted, &dequoted_buf);
        try std.testing.expectEqualSlices(u8, raw_arg[0..len], dequoted);

        if (len > 0 and raw_arg[0] == ' ') raw_arg[0] = '_';
        const payload = try ctcp.buildPayload("PING", raw_arg[0..len], &payload_buf);
        try std.testing.expect(payload.len <= payload_buf.len);
        try std.testing.expectEqual(ctcp.delimiter, payload[0]);
        try std.testing.expectEqual(ctcp.delimiter, payload[payload.len - 1]);

        const view = (try ctcp.parseFirst(.privmsg, payload)).?;
        try std.testing.expectEqual(ctcp.CommandId.ping, view.id);
        const parsed_arg = try view.dequoteArg(&dequoted_buf);
        try std.testing.expectEqualSlices(u8, raw_arg[0..len], parsed_arg);
    }
}

test "ACTION and standard CTCP queries parse with expected identities" {
    const Case = struct {
        body: []const u8,
        id: ctcp.CommandId,
        dcc: ?ctcp.DccKind = null,
    };

    const cases = [_]Case{
        .{ .body = "\x01ACTION waves\x01", .id = .action },
        .{ .body = "\x01VERSION\x01", .id = .version },
        .{ .body = "\x01PING 12345\x01", .id = .ping },
        .{ .body = "\x01TIME\x01", .id = .time },
        .{ .body = "\x01CLIENTINFO\x01", .id = .clientinfo },
        .{ .body = "\x01SOURCE\x01", .id = .source },
        .{ .body = "\x01USERINFO\x01", .id = .userinfo },
        .{ .body = "\x01FINGER\x01", .id = .finger },
        .{ .body = "\x01DCC SEND file.txt 1 2 3\x01", .id = .dcc, .dcc = .send },
    };

    for (cases) |case| {
        const request = (try ctcp.parseFirst(.privmsg, case.body)).?;
        try std.testing.expect(!request.isReply());
        try std.testing.expectEqual(case.id, request.id);
        try std.testing.expectEqual(case.dcc, request.dcc);

        const reply = (try ctcp.parseFirst(.notice, case.body)).?;
        try std.testing.expect(reply.isReply());
        try std.testing.expectEqual(case.id, reply.id);
    }
}

test "embedded delimiter quote byte and NUL are handled explicitly" {
    try std.testing.expectError(error.InvalidMessage, ctcp.parseFirst(.privmsg, "\x01PING raw\x00nul\x01"));
    var reject_buf: [64]u8 = undefined;
    try std.testing.expectError(error.InvalidByte, ctcp.buildPayload("PING", "has\x01delimiter", &reject_buf));

    var payload_buf: [64]u8 = undefined;
    const payload = try ctcp.buildPayload("ACTION", "quote\x10byte and nul\x00", &payload_buf);
    const view = (try ctcp.parseFirst(.privmsg, payload)).?;
    try std.testing.expectEqual(ctcp.CommandId.action, view.id);

    var arg_buf: [32]u8 = undefined;
    const arg = try view.dequoteArg(&arg_buf);
    try std.testing.expectEqualSlices(u8, "quote\x10byte and nul\x00", arg);

    var it = ctcp.iterator(.privmsg, "\x01ACTION before\x01middle\x01PING after\x01");
    const first = (try it.next()).?;
    const second = (try it.next()).?;
    try std.testing.expectEqual(ctcp.CommandId.action, first.id);
    try std.testing.expectEqual(ctcp.CommandId.ping, second.id);
    try std.testing.expectEqual(@as(?ctcp.CtcpView, null), try it.next());
}

test "caller output bounds and guard bytes are respected" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0x3003);
    const random = prng.random();

    var raw_arg: [max_arg_len]u8 = undefined;
    var quote_backing: [max_arg_len * 2 + 2]u8 = undefined;
    var dequote_backing: [max_arg_len + 2]u8 = undefined;
    var payload_backing: [max_arg_len * 2 + 16 + 2]u8 = undefined;

    for (0..bounded_iterations) |iteration| {
        const len = randomInputLen(random, iteration, raw_arg.len);
        fillQuotableBytes(random, raw_arg[0..len], iteration);

        @memset(&quote_backing, 0xa5);
        const quote_exposed = quote_backing[1 .. quote_backing.len - 1];
        const quoted = try ctcp.quote(raw_arg[0..len], quote_exposed);
        try expectSliceWithin(quote_exposed, quoted);
        try std.testing.expectEqual(@as(u8, 0xa5), quote_backing[0]);
        try std.testing.expectEqual(@as(u8, 0xa5), quote_backing[quote_backing.len - 1]);

        @memset(&dequote_backing, 0x5a);
        const dequote_exposed = dequote_backing[1 .. dequote_backing.len - 1];
        const dequoted = try ctcp.dequote(quoted, dequote_exposed);
        try expectSliceWithin(dequote_exposed, dequoted);
        try std.testing.expectEqualSlices(u8, raw_arg[0..len], dequoted);
        try std.testing.expectEqual(@as(u8, 0x5a), dequote_backing[0]);
        try std.testing.expectEqual(@as(u8, 0x5a), dequote_backing[dequote_backing.len - 1]);

        @memset(&payload_backing, 0xc3);
        const payload_exposed = payload_backing[1 .. payload_backing.len - 1];
        const payload = try ctcp.buildPayload("PING", raw_arg[0..len], payload_exposed);
        try expectSliceWithin(payload_exposed, payload);
        try std.testing.expectEqual(@as(u8, 0xc3), payload_backing[0]);
        try std.testing.expectEqual(@as(u8, 0xc3), payload_backing[payload_backing.len - 1]);
    }

    var tiny: [8]u8 = undefined;
    fillQuotableBytes(random, raw_arg[0..raw_arg.len], 0);
    try std.testing.expectError(error.OutputTooSmall, ctcp.quote(raw_arg[0..raw_arg.len], &tiny));
    try std.testing.expectError(error.OutputTooSmall, ctcp.dequote("\x100", tiny[0..0]));
    try std.testing.expectError(error.OutputTooSmall, ctcp.buildPayload("PING", raw_arg[0..raw_arg.len], &tiny));
}

test "public error surfaces remain typed for malformed quotes and builders" {
    var buf: [64]u8 = undefined;

    try std.testing.expectError(error.InvalidByte, ctcp.quote("\x01", &buf));
    try std.testing.expectError(error.MalformedQuote, ctcp.dequote("\x10", &buf));
    try std.testing.expectError(error.MalformedQuote, ctcp.dequote("\x10x", &buf));

    if (ctcp.buildPayload("BAD CMD", null, &buf)) |_| {
        return error.TestExpectedError;
    } else |err| {
        expectBuildError(err);
    }

    if (ctcp.buildRequest("bad target", "PING", null, &buf)) |_| {
        return error.TestExpectedError;
    } else |err| {
        expectBuildError(err);
    }
}

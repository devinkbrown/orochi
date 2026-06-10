//! Deterministic property and fuzz tests for IRC LIST/ELIST handling.
const std = @import("std");
const list = @import("list.zig");

const seed: u64 = 0x4c49_5354_5052_4f50;
const parse_iterations: usize = 4000;
const reply_iterations: usize = 2400;
const validation_iterations: usize = 1400;
const match_iterations: usize = 3600;

test "ELIST parser returns requests or typed errors for arbitrary bytes" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0x4550_4152_5345);
    const random = prng.random();
    var param_buf: [list.MAX_PARAM_BYTES + 32]u8 = undefined;

    for (0..parse_iterations) |iteration| {
        const param = if (iteration % 7 == 0)
            fillStructuredElist(random, &param_buf, iteration)
        else
            fillAttackerParam(random, &param_buf, iteration);

        if (list.parseListx(&.{param})) |request| {
            try expectValidRequest(param, request);
            _ = request.matches(randomChannel(random, iteration), randomNow(random, iteration));
        } else |err| {
            try expectListError(err);
        }
    }

    const corpus = [_][]const u8{
        ">0",
        "<1",
        "C>60",
        "C<600",
        "T>5",
        "T<50",
        "TOPICONLY",
        "#miz*",
        "!#secret",
        ">1,<100,C>10,T<99,TOPICONLY,#suzu*,!#old",
    };

    for (corpus) |param| {
        if (list.parseListx(&.{param})) |request| {
            try expectValidRequest(param, request);
        } else |err| {
            try expectListError(err);
        }
    }
}

test "RPL_LIST builder respects output bounds under generated inputs" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0x5245_504c_5932);
    const random = prng.random();
    var storage = StringStorage{};
    var guarded: [640]u8 = undefined;

    for (0..reply_iterations) |iteration| {
        const channel = randomValidChannel(random, iteration, &storage);
        const out_len = randomLength(random, iteration, guarded.len - 32);
        @memset(&guarded, 0xa5);

        const out = guarded[0..out_len];
        const guard = guarded[out_len..];
        if (list.writeListReply(out, "irc.example.test", "dan", channel)) |line| {
            try expectSliceWithin(out, line);
            try std.testing.expect(line.len <= out.len);
            try expectCrlf(line);
            try std.testing.expect(std.mem.startsWith(u8, line, ":irc.example.test 322 dan "));
        } else |err| {
            try expectListError(err);
        }
        try expectAllBytes(guard, 0xa5);
    }
}

test "channel and topic bytes are validated by RPL_LIST emission" {
    var out: [256]u8 = undefined;
    try std.testing.expectError(error.InvalidValue, list.writeListReply(&out, "irc.test", "dan", .{
        .name = "",
        .users = 1,
        .topic = "ok",
    }));
    try std.testing.expectError(error.InvalidValue, list.writeListReply(&out, "irc.test", "dan", .{
        .name = "#bad chan",
        .users = 1,
        .topic = "ok",
    }));
    try std.testing.expectError(error.InvalidValue, list.writeListReply(&out, "irc.test", "dan", .{
        .name = "#nul",
        .users = 1,
        .topic = "bad\x00topic",
    }));
    try std.testing.expectError(error.InvalidValue, list.writeListReply(&out, "irc.test", "dan", .{
        .name = "#crlf",
        .users = 1,
        .topic = "bad\r\n",
    }));

    var prng = std.Random.DefaultPrng.init(seed ^ 0x5641_4c49_4442);
    const random = prng.random();
    var storage = StringStorage{};

    for (0..validation_iterations) |iteration| {
        const channel = randomPossiblyInvalidChannel(random, iteration, &storage);
        if (list.writeListReply(&out, "irc.test", "dan", channel)) |line| {
            try expectCrlf(line);
            try std.testing.expect(validParam(channel.name));
            try std.testing.expect(validTrailing(channel.topic));
        } else |err| {
            try expectListError(err);
        }
    }
}

test "filter matching is total over random channel metadata" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0x4d41_5443_4845);
    const random = prng.random();
    var param_buf: [list.MAX_PARAM_BYTES]u8 = undefined;

    for (0..match_iterations) |iteration| {
        const param = fillStructuredElist(random, &param_buf, iteration);
        const request = list.parseListx(&.{param}) catch |err| {
            try expectListError(err);
            continue;
        };

        const channel = randomChannel(random, iteration);
        _ = request.matches(channel, randomNow(random, iteration));
    }
}

const StringStorage = struct {
    channel: [list.MAX_MASK_BYTES]u8 = undefined,
    topic: [192]u8 = undefined,
};

fn fillStructuredElist(random: std.Random, out: []u8, iteration: usize) []const u8 {
    var cursor: usize = 0;
    const filter_count = 1 + random.uintLessThan(usize, 6);

    for (0..filter_count) |index| {
        if (index != 0 and cursor < out.len) {
            out[cursor] = ',';
            cursor += 1;
        }
        cursor = appendStructuredFilter(random, out, cursor, iteration + index);
    }

    return out[0..cursor];
}

fn appendStructuredFilter(random: std.Random, out: []u8, cursor_start: usize, salt: usize) usize {
    var cursor = cursor_start;
    switch (salt % 9) {
        0 => cursor = appendCountFilter(random, out, cursor, '>'),
        1 => cursor = appendCountFilter(random, out, cursor, '<'),
        2 => cursor = appendAgeFilter(random, out, cursor, 'C', '>'),
        3 => cursor = appendAgeFilter(random, out, cursor, 'C', '<'),
        4 => cursor = appendAgeFilter(random, out, cursor, 'T', '>'),
        5 => cursor = appendAgeFilter(random, out, cursor, 'T', '<'),
        6 => cursor = appendLiteral(out, cursor, "TOPICONLY"),
        7 => cursor = appendMask(random, out, cursor, false),
        else => cursor = appendMask(random, out, cursor, true),
    }
    return cursor;
}

fn appendCountFilter(random: std.Random, out: []u8, cursor_start: usize, op: u8) usize {
    var cursor = cursor_start;
    if (cursor < out.len) {
        out[cursor] = op;
        cursor += 1;
    }
    return appendDecimal(random, out, cursor);
}

fn appendAgeFilter(random: std.Random, out: []u8, cursor_start: usize, kind: u8, op: u8) usize {
    var cursor = cursor_start;
    if (cursor < out.len) {
        out[cursor] = kind;
        cursor += 1;
    }
    if (cursor < out.len) {
        out[cursor] = op;
        cursor += 1;
    }
    return appendDecimal(random, out, cursor);
}

fn appendDecimal(random: std.Random, out: []u8, cursor_start: usize) usize {
    var cursor = cursor_start;
    const digits = 1 + random.uintLessThan(usize, 10);
    for (0..digits) |_| {
        if (cursor >= out.len) break;
        out[cursor] = '0' + random.uintLessThan(u8, 10);
        cursor += 1;
    }
    return cursor;
}

fn appendMask(random: std.Random, out: []u8, cursor_start: usize, exclude: bool) usize {
    var cursor = cursor_start;
    if (exclude and cursor < out.len) {
        out[cursor] = '!';
        cursor += 1;
    }
    if (cursor < out.len) {
        out[cursor] = '#';
        cursor += 1;
    }

    const body_len = 1 + random.uintLessThan(usize, 18);
    for (0..body_len) |_| {
        if (cursor >= out.len) break;
        out[cursor] = switch (random.uintLessThan(u8, 12)) {
            0...3 => 'a' + random.uintLessThan(u8, 26),
            4...5 => 'A' + random.uintLessThan(u8, 26),
            6...7 => '0' + random.uintLessThan(u8, 10),
            8 => '*',
            9 => '?',
            10 => '-',
            else => '_',
        };
        cursor += 1;
    }
    return cursor;
}

fn appendLiteral(out: []u8, cursor_start: usize, literal: []const u8) usize {
    var cursor = cursor_start;
    for (literal) |byte| {
        if (cursor >= out.len) break;
        out[cursor] = byte;
        cursor += 1;
    }
    return cursor;
}

fn fillAttackerParam(random: std.Random, out: []u8, iteration: usize) []const u8 {
    const len = randomLength(random, iteration, out.len);
    for (out[0..len]) |*byte| {
        byte.* = switch (random.uintLessThan(u8, 28)) {
            0 => '>',
            1 => '<',
            2 => 'C',
            3 => 'T',
            4 => 'c',
            5 => 't',
            6 => '!',
            7 => '#',
            8 => '*',
            9 => '?',
            10 => ',',
            11 => 0,
            12 => ' ',
            13 => '\t',
            14 => '\r',
            15 => '\n',
            16...19 => '0' + random.uintLessThan(u8, 10),
            20...23 => 'a' + random.uintLessThan(u8, 26),
            24...25 => 'A' + random.uintLessThan(u8, 26),
            else => random.int(u8),
        };
    }
    return out[0..len];
}

fn randomValidChannel(random: std.Random, iteration: usize, storage: *StringStorage) list.ChannelInfo {
    return .{
        .name = fillValidChannelName(random, &storage.channel, iteration),
        .users = random.int(u32),
        .topic = fillValidTopic(random, &storage.topic, iteration + 1),
        .topic_set_at = randomOptionalTime(random, iteration),
        .created_at = randomTime(random, iteration + 2),
    };
}

fn randomPossiblyInvalidChannel(random: std.Random, iteration: usize, storage: *StringStorage) list.ChannelInfo {
    return .{
        .name = fillPossiblyInvalidParam(random, &storage.channel, iteration),
        .users = random.int(u32),
        .topic = fillPossiblyInvalidTrailing(random, &storage.topic, iteration + 1),
        .topic_set_at = randomOptionalTime(random, iteration),
        .created_at = randomTime(random, iteration + 2),
    };
}

fn randomChannel(random: std.Random, iteration: usize) list.ChannelInfo {
    const names = [_][]const u8{
        "#orochi",
        "#OROCHI",
        "#ops",
        "#secret",
        "",
        "#bad chan",
        "#nul\x00chan",
        "#crlf\r\n",
        "#topic-only",
    };
    const topics = [_][]const u8{
        "",
        "topic",
        "Topic With Spaces",
        "bad\x00topic",
        "bad\rline",
        "bad\nline",
        "TOPICONLY",
    };

    return .{
        .name = names[(iteration + random.uintLessThan(usize, names.len)) % names.len],
        .users = random.int(u32),
        .topic = topics[(iteration + random.uintLessThan(usize, topics.len)) % topics.len],
        .topic_set_at = randomOptionalTime(random, iteration),
        .created_at = randomTime(random, iteration + 1),
    };
}

fn fillValidChannelName(random: std.Random, out: []u8, iteration: usize) []const u8 {
    const len = switch (iteration % 9) {
        0 => 1,
        1 => @min(out.len, list.MAX_MASK_BYTES),
        else => 2 + random.uintLessThan(usize, @min(out.len, list.MAX_MASK_BYTES) - 1),
    };
    out[0] = '#';
    for (out[1..len]) |*byte| {
        byte.* = switch (random.uintLessThan(u8, 14)) {
            0...4 => 'a' + random.uintLessThan(u8, 26),
            5...7 => 'A' + random.uintLessThan(u8, 26),
            8...9 => '0' + random.uintLessThan(u8, 10),
            10 => '-',
            11 => '_',
            12 => '.',
            else => '*',
        };
    }
    return out[0..len];
}

fn fillValidTopic(random: std.Random, out: []u8, iteration: usize) []const u8 {
    const len = switch (iteration % 8) {
        0 => 0,
        1 => out.len,
        else => random.uintLessThan(usize, out.len + 1),
    };
    for (out[0..len]) |*byte| {
        byte.* = switch (random.uintLessThan(u8, 16)) {
            0...5 => 'a' + random.uintLessThan(u8, 26),
            6...8 => 'A' + random.uintLessThan(u8, 26),
            9...10 => '0' + random.uintLessThan(u8, 10),
            11...12 => ' ',
            13 => '-',
            14 => '.',
            else => ':',
        };
    }
    return out[0..len];
}

fn fillPossiblyInvalidParam(random: std.Random, out: []u8, iteration: usize) []const u8 {
    const len = randomLength(random, iteration, out.len);
    for (out[0..len]) |*byte| {
        byte.* = switch (random.uintLessThan(u8, 16)) {
            0 => 0,
            1 => ' ',
            2 => '\t',
            3 => '\r',
            4 => '\n',
            5 => '#',
            6...9 => 'a' + random.uintLessThan(u8, 26),
            10...11 => 'A' + random.uintLessThan(u8, 26),
            12...13 => '0' + random.uintLessThan(u8, 10),
            14 => '-',
            else => random.int(u8),
        };
    }
    return out[0..len];
}

fn fillPossiblyInvalidTrailing(random: std.Random, out: []u8, iteration: usize) []const u8 {
    const len = randomLength(random, iteration, out.len);
    for (out[0..len]) |*byte| {
        byte.* = switch (random.uintLessThan(u8, 16)) {
            0 => 0,
            1 => '\r',
            2 => '\n',
            3...6 => ' ',
            7...10 => 'a' + random.uintLessThan(u8, 26),
            11...12 => 'A' + random.uintLessThan(u8, 26),
            13...14 => '0' + random.uintLessThan(u8, 10),
            else => random.int(u8),
        };
    }
    return out[0..len];
}

fn randomLength(random: std.Random, iteration: usize, max_len: usize) usize {
    return switch (iteration % 16) {
        0 => 0,
        1 => 1,
        2 => max_len,
        3 => @min(max_len, list.MAX_PARAM_BYTES),
        else => random.uintLessThan(usize, max_len + 1),
    };
}

fn randomNow(random: std.Random, iteration: usize) i64 {
    return switch (iteration % 6) {
        0 => 0,
        1 => 1,
        2 => 1_700_000_000,
        else => @intCast(random.uintLessThan(u32, 4_000_000_000)),
    };
}

fn randomTime(random: std.Random, iteration: usize) i64 {
    return switch (iteration % 7) {
        0 => 0,
        1 => 1,
        2 => 1_700_000_000,
        3 => 1_700_000_000,
        else => @intCast(random.uintLessThan(u32, 4_000_000_000)),
    };
}

fn randomOptionalTime(random: std.Random, iteration: usize) ?i64 {
    if (iteration % 5 == 0) return null;
    return randomTime(random, iteration);
}

fn expectValidRequest(input: []const u8, request: list.Request) !void {
    try std.testing.expect(request.count <= list.MAX_FILTERS);
    for (request.slice()) |filter| {
        switch (filter) {
            .min_users,
            .max_users,
            .topic_older_than,
            .topic_younger_than,
            .created_older_than,
            .created_younger_than,
            => {},
            .include_mask => |mask| {
                try expectSliceWithin(input, mask);
                try std.testing.expect(mask.len > 0);
                try std.testing.expect(mask.len <= list.MAX_MASK_BYTES);
            },
            .exclude_mask => |mask| {
                try expectSliceWithin(input, mask);
                try std.testing.expect(mask.len > 0);
                try std.testing.expect(mask.len <= list.MAX_MASK_BYTES);
            },
        }
    }
}

fn validParam(param: []const u8) bool {
    if (param.len == 0) return false;
    for (param) |byte| {
        switch (byte) {
            0, ' ', '\t', '\r', '\n' => return false,
            else => {},
        }
    }
    return true;
}

fn validTrailing(param: []const u8) bool {
    for (param) |byte| {
        switch (byte) {
            0, '\r', '\n' => return false,
            else => {},
        }
    }
    return true;
}

fn expectListError(err: list.ListError) !void {
    switch (err) {
        error.InvalidParameter,
        error.InvalidFilter,
        error.InvalidMask,
        error.InvalidValue,
        error.TooManyFilters,
        error.OutputTooSmall,
        => {},
    }
}

fn expectSliceWithin(input: []const u8, slice: []const u8) !void {
    const input_start = @intFromPtr(input.ptr);
    const input_end = input_start + input.len;
    const slice_start = @intFromPtr(slice.ptr);
    const slice_end = slice_start + slice.len;

    try std.testing.expect(slice_start >= input_start);
    try std.testing.expect(slice_start <= input_end);
    try std.testing.expect(slice_end >= slice_start);
    try std.testing.expect(slice_end <= input_end);
}

fn expectCrlf(line: []const u8) !void {
    try std.testing.expect(line.len >= 2);
    try std.testing.expectEqualStrings("\r\n", line[line.len - 2 ..]);
}

fn expectAllBytes(bytes: []const u8, expected: u8) !void {
    for (bytes) |byte| {
        try std.testing.expectEqual(expected, byte);
    }
}

//! Property and fuzz-style tests for extended-ban parsing and matching.
//!
//! The generators are fixed-seed and bounded so direct `zig test` stays fast
//! while still exercising attacker-controlled masks, recursive negation chains,
//! borrowed parse slices, and random client contexts.
const std = @import("std");
const extban = @import("extban.zig");

const seed: u64 = 0x45585442414e5052;
const random_parse_iterations: usize = 1600;
const random_match_iterations: usize = 900;
const structured_parse_iterations: usize = 700;
const max_random_mask_len: usize = extban.MAX_MASK_BYTES + 32;
const max_context_field_len: usize = 96;
const max_channels: usize = 8;

fn expectParseError(err: extban.ParseError) !void {
    switch (err) {
        error.EmptyMask,
        error.OversizeMask,
        error.InvalidByte,
        error.MissingType,
        error.MissingDelimiter,
        error.EmptyPattern,
        error.UnknownType,
        error.TooDeep,
        => {},
    }
}

fn expectMatcherValid(input: []const u8, matcher: anytype) !void {
    try std.testing.expect(matcher.node_count > 0);
    try std.testing.expect(matcher.node_count <= matcher.nodes.len);
    try std.testing.expect(matcher.root < matcher.node_count);

    if (matcher.rootPattern()) |pattern| {
        try expectSliceWithin(input, pattern);
    }

    for (matcher.nodes[0..matcher.node_count]) |node| {
        switch (node) {
            .hostmask => |pattern| try expectSliceWithin(input, pattern),
            .account => |pattern| try expectSliceWithin(input, pattern),
            .realname => |pattern| try expectSliceWithin(input, pattern),
            .country => |pattern| try expectSliceWithin(input, pattern),
            .channel => |pattern| try expectSliceWithin(input, pattern),
            .negation => |child| try std.testing.expect(child < matcher.node_count),
        }
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

fn parseOkOrTypedError(input: []const u8) !void {
    const matcher = extban.parse(input) catch |err| {
        try expectParseError(err);
        return;
    };
    try expectMatcherValid(input, matcher);
}

fn randomLength(random: std.Random, iteration: usize, max_len: usize) usize {
    return switch (iteration % 19) {
        0 => 0,
        1 => 1,
        2 => @min(2, max_len),
        3 => @min(extban.MAX_MASK_BYTES - 1, max_len),
        4 => @min(extban.MAX_MASK_BYTES, max_len),
        5 => @min(extban.MAX_MASK_BYTES + 1, max_len),
        6 => max_len,
        else => random.uintLessThan(usize, max_len + 1),
    };
}

fn fillAttackerBytes(random: std.Random, out: []u8, iteration: usize) void {
    const interesting = [_]u8{
        0,    1,    0x1f, 0x7f, 0x80, 0xff,
        '$',  '~',  ':',  '*',  '?',  'a',
        'r',  'g',  'c',  'x',  ' ',  '\t',
        '\r', '\n', '#',  '@',  'A',  'z',
    };

    random.bytes(out);
    for (out, 0..) |*byte, i| {
        if ((i + iteration) % 3 == 0) {
            byte.* = interesting[(i * 7 + iteration) % interesting.len];
        }
    }
}

fn fillStructuredMask(random: std.Random, out: []u8, iteration: usize) []const u8 {
    if (out.len == 0) return out;

    var cursor: usize = 0;
    const negations = switch (iteration % 11) {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => extban.DEFAULT_MAX_NODES,
        4 => extban.DEFAULT_MAX_NODES + 4,
        else => random.uintLessThan(usize, 12),
    };

    var n: usize = 0;
    while (n < negations and cursor + 2 < out.len) : (n += 1) {
        out[cursor] = '$';
        out[cursor + 1] = '~';
        cursor += 2;
        if (n % 2 == 0 and cursor < out.len) {
            out[cursor] = ':';
            cursor += 1;
        }
    }

    if (cursor >= out.len) return out[0..cursor];

    switch (iteration % 7) {
        0 => cursor = appendBytes(out, cursor, "$a:"),
        1 => cursor = appendBytes(out, cursor, "$r:"),
        2 => cursor = appendBytes(out, cursor, "$g:"),
        3 => cursor = appendBytes(out, cursor, "$c:"),
        4 => cursor = appendBytes(out, cursor, "$x:"),
        5 => cursor = appendBytes(out, cursor, "$a"),
        else => {},
    }

    const payload_len = random.uintLessThan(usize, @min(out.len - cursor, 80) + 1);
    fillMaskAtom(random, out[cursor .. cursor + payload_len], iteration);
    cursor += payload_len;
    return out[0..cursor];
}

fn fillMaskAtom(random: std.Random, out: []u8, iteration: usize) void {
    const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_#*!?";
    for (out, 0..) |*byte, i| {
        byte.* = alphabet[(random.uintLessThan(usize, alphabet.len) + i + iteration) % alphabet.len];
    }
}

fn appendBytes(out: []u8, cursor_start: usize, bytes: []const u8) usize {
    var cursor = cursor_start;
    for (bytes) |byte| {
        if (cursor >= out.len) break;
        out[cursor] = byte;
        cursor += 1;
    }
    return cursor;
}

const ContextStorage = struct {
    account: [max_context_field_len]u8 = undefined,
    account_len: usize = 0,
    realname: [max_context_field_len]u8 = undefined,
    realname_len: usize = 0,
    host: [max_context_field_len]u8 = undefined,
    host_len: usize = 0,
    country: [max_context_field_len]u8 = undefined,
    country_len: usize = 0,
    channel_bufs: [max_channels][max_context_field_len]u8 = undefined,
    channel_lens: [max_channels]usize = [_]usize{0} ** max_channels,
    channels: [max_channels][]const u8 = undefined,
    channel_count: usize = 0,
};

fn setContextField(random: std.Random, out: []u8, len_out: *usize, salt: usize) void {
    const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_#*!?";
    const len = switch (salt % 13) {
        0 => 0,
        1 => 1,
        2 => out.len,
        else => random.uintLessThan(usize, out.len + 1),
    };
    len_out.* = len;
    for (out[0..len], 0..) |*byte, i| {
        byte.* = alphabet[(random.uintLessThan(usize, alphabet.len) + i + salt) % alphabet.len];
    }
}

test "parse returns a matcher or typed error for arbitrary attacker bytes" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0x1001);
    const random = prng.random();
    var input: [max_random_mask_len]u8 = undefined;

    for (0..random_parse_iterations) |iteration| {
        const len = randomLength(random, iteration, input.len);
        fillAttackerBytes(random, input[0..len], iteration);
        try parseOkOrTypedError(input[0..len]);
    }
}

test "structured recursive masks stay bounded by matcher depth" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0x2002);
    const random = prng.random();
    var input: [extban.MAX_MASK_BYTES]u8 = undefined;

    for (0..structured_parse_iterations) |iteration| {
        const mask = fillStructuredMask(random, &input, iteration);
        try parseOkOrTypedError(mask);
    }

    const SmallMatcher = extban.Matcher(4);
    var deep: [extban.MAX_MASK_BYTES]u8 = undefined;
    var cursor: usize = 0;
    while (cursor + 2 + "$a:z".len <= deep.len) : (cursor += 2) {
        deep[cursor] = '$';
        deep[cursor + 1] = '~';
    }
    cursor = appendBytes(&deep, cursor, "$a:z");
    try std.testing.expectError(error.TooDeep, SmallMatcher.parse(deep[0..cursor]));
}

test "matches is total for random parsed masks and random targets" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0x3003);
    const random = prng.random();
    var mask_buf: [extban.MAX_MASK_BYTES]u8 = undefined;
    var storage = ContextStorage{};

    for (0..random_match_iterations) |iteration| {
        const mask = if (iteration % 2 == 0)
            fillStructuredMask(random, &mask_buf, iteration)
        else blk: {
            const len = randomLength(random, iteration, mask_buf.len);
            fillAttackerBytes(random, mask_buf[0..len], iteration);
            break :blk mask_buf[0..len];
        };

        const matcher = extban.parse(mask) catch |err| {
            try expectParseError(err);
            continue;
        };
        try expectMatcherValid(mask, matcher);

        setContextField(random, &storage.account, &storage.account_len, iteration ^ 0x11);
        setContextField(random, &storage.realname, &storage.realname_len, iteration ^ 0x22);
        setContextField(random, &storage.host, &storage.host_len, iteration ^ 0x33);
        setContextField(random, &storage.country, &storage.country_len, iteration ^ 0x44);
        storage.channel_count = random.uintLessThan(usize, max_channels + 1);
        for (storage.channels[0..storage.channel_count], 0..) |*channel, i| {
            setContextField(random, &storage.channel_bufs[i], &storage.channel_lens[i], iteration + i);
            channel.* = storage.channel_bufs[i][0..storage.channel_lens[i]];
        }

        const ctx = extban.ClientContext{
            .account = if (iteration % 5 == 0) null else storage.account[0..storage.account_len],
            .realname = storage.realname[0..storage.realname_len],
            .host = storage.host[0..storage.host_len],
            .country = if (iteration % 7 == 0) null else storage.country[0..storage.country_len],
            .channels = storage.channels[0..storage.channel_count],
        };
        _ = matcher.matches(ctx);
    }
}

test "successful parses borrow only in-bounds pattern slices" {
    const cases = [_][]const u8{
        "plain.example",
        "*!*@example.net",
        "$a:alice",
        "$r:*Example_User*",
        "$g:DE",
        "$c:#opers",
        "$~a:alice",
        "$~:$a:alice",
        "$~$~$c:#ops",
        "$~:$~:$~:bad.host",
    };

    inline for (cases) |case| {
        const matcher = try extban.parse(case);
        try expectMatcherValid(case, matcher);
    }
}

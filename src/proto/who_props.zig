//! Deterministic property and fuzz tests for IRC WHO and WHOX handling.
const std = @import("std");
const who = @import("who.zig");

const seed: u64 = 0x5748_4f58_5052_4f50;
const selector_fuzz_iterations = 4000;
const selector_round_trip_iterations = 1200;
const reply_fuzz_iterations = 1800;
const valid_fields = "cuhsnfdlaor";

test "WHOX selector parser returns selectors or typed errors for arbitrary bytes" {
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();
    var token_buf: [96]u8 = undefined;

    for (0..selector_fuzz_iterations) |iteration| {
        const len = randomLength(random, iteration, token_buf.len);
        fillBiasedSelectorBytes(random, token_buf[0..len], iteration);

        if (who.FieldSelector.parse(token_buf[0..len])) |selector| {
            try expectSelectorValid(selector);
        } else |err| {
            try expectWhoError(err);
        }

        if (who.parseWhox(token_buf[0..len])) |request| {
            try expectSelectorValid(request.selector);
            if (request.query_type) |query_type| {
                try expectSliceWithin(token_buf[0..len], query_type);
                try std.testing.expect(query_type.len != 0);
            }
        } else |err| {
            try expectWhoError(err);
        }
    }
}

test "valid WHOX selectors preserve field order and query slices" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0x524f_554e_4454_5249);
    const random = prng.random();
    var token_buf: [who.MAX_SELECTOR_FIELDS + 16]u8 = undefined;
    var expected: [who.MAX_SELECTOR_FIELDS]who.Field = undefined;

    for (0..selector_round_trip_iterations) |iteration| {
        const count = 1 + random.uintLessThan(usize, who.MAX_SELECTOR_FIELDS);
        token_buf[0] = '%';

        for (0..count) |i| {
            const field_byte = valid_fields[(iteration + i + random.uintLessThan(usize, valid_fields.len)) % valid_fields.len];
            token_buf[1 + i] = field_byte;
            expected[i] = fieldForByte(field_byte);
        }

        const selector_token = token_buf[0 .. 1 + count];
        const selector = try who.FieldSelector.parse(selector_token);
        try expectSelectorEquals(selector, expected[0..count]);

        const query = "Q123";
        token_buf[1 + count] = ',';
        @memcpy(token_buf[2 + count .. 2 + count + query.len], query);
        const whox_token = token_buf[0 .. 2 + count + query.len];
        const request = try who.parseWhox(whox_token);

        try expectSelectorEquals(request.selector, expected[0..count]);
        try std.testing.expectEqualStrings(query, request.query_type.?);
        try expectSliceWithin(whox_token, request.query_type.?);
    }
}

test "WHO reply builders respect buffer bounds for deterministic generated contexts" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0x4255_4646_4552_4244);
    const random = prng.random();
    var storage = StringStorage{};
    var guarded: [576]u8 = undefined;

    for (0..reply_fuzz_iterations) |iteration| {
        var ctx = makeContext(random, iteration, &storage);
        const out_len = randomLength(random, iteration, 512);
        @memset(&guarded, 0xa5);
        const out = guarded[0..out_len];
        const guard = guarded[out_len..];

        if (who.writeWhoReply(out, ctx)) |line| {
            try expectSliceWithin(out, line);
            try expectCrlf(line);
            try expectClassicFlags(line, ctx);
            try std.testing.expect(line.len <= out.len);
        } else |err| {
            try expectWhoError(err);
        }
        try expectAllBytes(guard, 0xa5);

        const selector = randomSelector(random, iteration);
        @memset(&guarded, 0x3c);
        if (who.writeWhoxReply(out, selector, ctx)) |line| {
            try expectSliceWithin(out, line);
            try expectCrlf(line);
            try std.testing.expect(line.len <= out.len);
        } else |err| {
            try expectWhoError(err);
        }
        try expectAllBytes(guard, 0x3c);

        @memset(&guarded, 0x69);
        if (who.writeEndOfWho(out, ctx.server_name, ctx.requester, ctx.target)) |line| {
            try expectSliceWithin(out, line);
            try expectCrlf(line);
            try std.testing.expect(line.len <= out.len);
        } else |err| {
            try expectWhoError(err);
        }
        try expectAllBytes(guard, 0x69);

        ctx.member.channel_prefix = invalidPrefix(iteration);
        if (ctx.member.channel_prefix != null) {
            var invalid_prefix_out: [512]u8 = undefined;
            try std.testing.expectError(error.InvalidValue, who.writeWhoReply(&invalid_prefix_out, ctx));
        }
    }
}

test "WHO flags render H or G, oper marker, and channel prefixes exactly" {
    const cases = [_]struct {
        away: bool,
        oper: bool,
        prefix: ?u8,
        expected: []const u8,
    }{
        .{ .away = false, .oper = false, .prefix = null, .expected = "H" },
        .{ .away = true, .oper = false, .prefix = null, .expected = "G" },
        .{ .away = false, .oper = true, .prefix = null, .expected = "H*" },
        .{ .away = true, .oper = true, .prefix = null, .expected = "G*" },
        .{ .away = false, .oper = false, .prefix = '@', .expected = "H@" },
        .{ .away = false, .oper = false, .prefix = '+', .expected = "H+" },
        .{ .away = true, .oper = true, .prefix = '@', .expected = "G*@" },
        .{ .away = true, .oper = true, .prefix = '+', .expected = "G*+" },
    };

    for (cases) |case| {
        var ctx = baseContext();
        ctx.client.away = case.away;
        ctx.client.oper = case.oper;
        ctx.member.channel_prefix = case.prefix;

        var out: [256]u8 = undefined;
        const line = try who.writeWhoReply(&out, ctx);
        try std.testing.expectEqualStrings(case.expected, classicFlags(line));

        const selector = who.FieldSelector.initComptime("%f");
        const whox_line = try who.writeWhoxReply(&out, selector, ctx);
        try std.testing.expectEqualStrings(case.expected, finalParam(whox_line));
    }
}

test "parsed request slices stay within caller input tokens" {
    var target_buf = [_]u8{ '#', 'm', 'i', 'z', 'u', 'c', 'h', 'i' };
    var whox_buf = [_]u8{ '%', 'c', 'u', 'f', ',', '4', '2' };
    const params = [_][]const u8{ target_buf[0..], whox_buf[0..] };

    const request = try who.parse(&params);
    try expectSliceWithin(target_buf[0..], request.target);
    try expectSelectorEquals(request.whox.?.selector, &.{ .channel, .user, .flags });
    try expectSliceWithin(whox_buf[0..], request.whox.?.query_type.?);
    try std.testing.expectEqualStrings("42", request.whox.?.query_type.?);

    var out: [128]u8 = undefined;
    const line = try who.writeEndOfWho(&out, "irc.test", "dan", request.target);
    try expectSliceWithin(&out, line);
}

const StringStorage = struct {
    server: [40]u8 = undefined,
    requester: [24]u8 = undefined,
    target: [24]u8 = undefined,
    nick: [24]u8 = undefined,
    user: [24]u8 = undefined,
    host: [40]u8 = undefined,
    realname: [48]u8 = undefined,
    account: [24]u8 = undefined,
    channel: [24]u8 = undefined,
    oper_level: [24]u8 = undefined,
};

fn baseContext() who.ReplyContext {
    return .{
        .server_name = "irc.example.test",
        .requester = "dan",
        .target = "#orochi",
        .client = .{
            .nick = "alice",
            .user = "auser",
            .host = "host.example",
            .server = "irc.example.test",
            .realname = "Alice Example",
            .away = false,
            .oper = false,
            .account = "alice",
        },
        .member = .{
            .channel = "#orochi",
            .channel_prefix = null,
            .hops = 1,
            .distance = 2,
            .idle_seconds = 3,
            .oper_level = null,
        },
    };
}

fn makeContext(random: std.Random, iteration: usize, storage: *StringStorage) who.ReplyContext {
    const server = fillToken(random, &storage.server, "irc.test", iteration);
    const requester = fillToken(random, &storage.requester, "dan", iteration + 1);
    const target = if (iteration % 5 == 0) "*" else fillChannel(random, &storage.target, iteration + 2);
    const nick = fillToken(random, &storage.nick, "alice", iteration + 3);
    const user = fillToken(random, &storage.user, "auser", iteration + 4);
    const host = fillToken(random, &storage.host, "host.test", iteration + 5);
    const realname = fillTrailing(random, &storage.realname, "Alice Example", iteration + 6);
    const account = fillToken(random, &storage.account, "alice-account", iteration + 7);
    const channel = fillChannel(random, &storage.channel, iteration + 8);
    const oper_level = fillToken(random, &storage.oper_level, "netadmin", iteration + 9);

    return .{
        .server_name = server,
        .requester = requester,
        .target = target,
        .client = .{
            .nick = nick,
            .user = user,
            .host = host,
            .server = server,
            .realname = realname,
            .away = iteration % 2 == 0,
            .oper = iteration % 3 == 0,
            .account = if (iteration % 4 == 0) null else account,
        },
        .member = .{
            .channel = if (iteration % 6 == 0) null else channel,
            .channel_prefix = switch (iteration % 4) {
                0 => null,
                1 => '@',
                2 => '+',
                else => '%',
            },
            .hops = random.int(u32),
            .distance = random.int(u32),
            .idle_seconds = random.int(u32),
            .oper_level = if (iteration % 5 == 0) null else oper_level,
        },
    };
}

fn randomSelector(random: std.Random, iteration: usize) who.FieldSelector {
    var selector = who.FieldSelector{};
    selector.count = 1 + random.uintLessThan(usize, who.MAX_SELECTOR_FIELDS);
    for (0..selector.count) |i| {
        const field_byte = valid_fields[(iteration + i + random.uintLessThan(usize, valid_fields.len)) % valid_fields.len];
        selector.fields[i] = fieldForByte(field_byte);
    }
    return selector;
}

fn fillToken(random: std.Random, out: []u8, fallback: []const u8, iteration: usize) []const u8 {
    const len = switch (iteration % 9) {
        0 => fallback.len,
        1 => 1,
        2 => out.len,
        else => 1 + random.uintLessThan(usize, out.len),
    };
    if (iteration % 9 == 0) {
        @memcpy(out[0..fallback.len], fallback);
        return out[0..fallback.len];
    }

    for (out[0..len]) |*byte| {
        byte.* = switch (random.uintLessThan(u8, 12)) {
            0...3 => 'a' + random.uintLessThan(u8, 26),
            4...6 => 'A' + random.uintLessThan(u8, 26),
            7...8 => '0' + random.uintLessThan(u8, 10),
            9 => '-',
            10 => '_',
            else => '.',
        };
    }
    return out[0..len];
}

fn fillChannel(random: std.Random, out: []u8, iteration: usize) []const u8 {
    const body = fillToken(random, out[1..], "orochi", iteration);
    out[0] = '#';
    return out[0 .. 1 + body.len];
}

fn fillTrailing(random: std.Random, out: []u8, fallback: []const u8, iteration: usize) []const u8 {
    const len = switch (iteration % 8) {
        0 => fallback.len,
        1 => 0,
        2 => 1,
        3 => out.len,
        else => random.uintLessThan(usize, out.len + 1),
    };
    if (iteration % 8 == 0) {
        @memcpy(out[0..fallback.len], fallback);
        return out[0..fallback.len];
    }

    for (out[0..len]) |*byte| {
        byte.* = switch (random.uintLessThan(u8, 14)) {
            0...4 => 'a' + random.uintLessThan(u8, 26),
            5...7 => 'A' + random.uintLessThan(u8, 26),
            8...9 => '0' + random.uintLessThan(u8, 10),
            10...11 => ' ',
            12 => '-',
            else => '.',
        };
    }
    return out[0..len];
}

fn fillBiasedSelectorBytes(random: std.Random, out: []u8, iteration: usize) void {
    for (out, 0..) |*byte, index| {
        byte.* = switch (random.uintLessThan(u8, 18)) {
            0 => '%',
            1 => ',',
            2 => 0,
            3 => '\r',
            4 => '\n',
            5 => ' ',
            6...10 => valid_fields[random.uintLessThan(usize, valid_fields.len)],
            11...13 => 'a' + random.uintLessThan(u8, 26),
            14...15 => '0' + random.uintLessThan(u8, 10),
            else => random.int(u8),
        };
        if (iteration % 11 == 0 and index == 0) byte.* = '%';
    }
}

fn randomLength(random: std.Random, iteration: usize, max_len: usize) usize {
    return switch (iteration % 16) {
        0 => 0,
        1 => 1,
        2 => max_len,
        3 => @min(max_len, who.MAX_SELECTOR_FIELDS + 1),
        else => random.uintLessThan(usize, max_len + 1),
    };
}

fn invalidPrefix(iteration: usize) ?u8 {
    return switch (iteration % 5) {
        0 => 0,
        1 => ' ',
        2 => '\t',
        3 => '\r',
        else => null,
    };
}

fn fieldForByte(byte: u8) who.Field {
    return switch (byte) {
        'c' => .channel,
        'u' => .user,
        'h' => .host,
        's' => .server,
        'n' => .nick,
        'f' => .flags,
        'd' => .distance,
        'l' => .idle,
        'a' => .account,
        'o' => .oper_level,
        'r' => .realname,
        else => unreachable,
    };
}

fn expectSelectorValid(selector: who.FieldSelector) !void {
    try std.testing.expect(selector.count > 0);
    try std.testing.expect(selector.count <= who.MAX_SELECTOR_FIELDS);
    for (selector.slice()) |field| {
        switch (field) {
            .channel,
            .user,
            .host,
            .server,
            .nick,
            .flags,
            .distance,
            .idle,
            .account,
            .oper_level,
            .realname,
            => {},
        }
    }
}

fn expectSelectorEquals(selector: who.FieldSelector, expected: []const who.Field) !void {
    try std.testing.expectEqual(expected.len, selector.count);
    for (expected, selector.slice()) |expected_field, actual| {
        try std.testing.expectEqual(expected_field, actual);
    }
}

fn expectWhoError(err: who.WhoError) !void {
    switch (err) {
        error.InvalidTarget,
        error.InvalidParameter,
        error.InvalidSelector,
        error.InvalidValue,
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

fn expectClassicFlags(line: []const u8, ctx: who.ReplyContext) !void {
    const flags = classicFlags(line);
    try std.testing.expectEqual(if (ctx.client.away) @as(u8, 'G') else @as(u8, 'H'), flags[0]);

    var expected_len: usize = 1;
    if (ctx.client.oper) {
        try std.testing.expect(flags.len > expected_len);
        try std.testing.expectEqual(@as(u8, '*'), flags[expected_len]);
        expected_len += 1;
    }
    if (ctx.member.channel_prefix) |prefix| {
        try std.testing.expect(flags.len > expected_len);
        try std.testing.expectEqual(prefix, flags[expected_len]);
        expected_len += 1;
    }
    try std.testing.expectEqual(expected_len, flags.len);
}

fn classicFlags(line: []const u8) []const u8 {
    var spaces_seen: usize = 0;
    var start: usize = 0;
    for (line, 0..) |byte, index| {
        if (byte == ' ') {
            spaces_seen += 1;
            if (spaces_seen == 8) start = index + 1;
            if (spaces_seen == 9) return line[start..index];
        }
    }
    return "";
}

fn finalParam(line: []const u8) []const u8 {
    var last_space: usize = 0;
    for (line, 0..) |byte, index| {
        if (byte == ' ') last_space = index + 1;
    }
    return line[last_space .. line.len - 2];
}

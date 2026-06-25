// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Property and fuzz-style tests for RPL_ISUPPORT (005) token folding.
const std = @import("std");
const isupport = @import("isupport.zig");

const seed: u64 = 0x4953_5550_504f_5254;
const folding_iterations: usize = 2600;
const fuzz_iterations: usize = 1400;

const TokenSpec = struct {
    name: [16]u8 = undefined,
    name_len: usize = 0,
    value: [96]u8 = undefined,
    value_len: usize = 0,
    has_value: bool = false,
    negated: bool = false,

    fn token(self: *const TokenSpec) isupport.Token {
        return .{
            .name = self.name[0..self.name_len],
            .value = if (self.has_value) self.value[0..self.value_len] else null,
            .negated = self.negated,
        };
    }
};

test "random valid token sets fold within token and line limits without loss" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0x1001);
    const random = prng.random();

    var specs: [48]TokenSpec = undefined;
    var tokens: [specs.len]isupport.Token = undefined;
    var rendered: [specs.len][128]u8 = undefined;
    var line_slots: [16]isupport.ReplyLine = undefined;
    var storage: [8192]u8 = undefined;

    var iteration: usize = 0;
    while (iteration < folding_iterations) : (iteration += 1) {
        const token_count = 1 + random.uintLessThan(usize, specs.len);
        fillValidTokens(random, specs[0..token_count], iteration);
        for (specs[0..token_count], 0..) |*spec, index| {
            tokens[index] = spec.token();
            try tokens[index].validate();
        }

        var sink = isupport.ReplySink{ .lines = &line_slots, .storage = &storage };
        try (isupport.Builder{
            .server_name = "irc.property.test",
            .requester = "alice",
            .tokens = tokens[0..token_count],
        }).emit(&sink);

        for (tokens[0..token_count], 0..) |token, index| {
            _ = try token.write(&rendered[index]);
        }

        try expectFoldedLinesWellFormed(
            sink.slice(),
            "irc.property.test",
            "alice",
            isupport.DEFAULT_TRAILING,
            tokens[0..token_count],
            &rendered,
        );
    }
}

test "line byte limit forces lossless folding before 512 octets" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0x2002);
    const random = prng.random();

    var specs: [28]TokenSpec = undefined;
    var tokens: [specs.len]isupport.Token = undefined;
    var rendered: [specs.len][128]u8 = undefined;
    var line_slots: [28]isupport.ReplyLine = undefined;
    var storage: [8192]u8 = undefined;

    var iteration: usize = 0;
    while (iteration < 512) : (iteration += 1) {
        const token_count = 8 + random.uintLessThan(usize, specs.len - 7);
        fillValidTokens(random, specs[0..token_count], iteration);
        for (specs[0..token_count], 0..) |*spec, index| {
            spec.value_len = 34 + random.uintLessThan(usize, 34);
            spec.has_value = true;
            spec.negated = false;
            fillTokenValue(random, spec.value[0..spec.value_len]);
            tokens[index] = spec.token();
        }

        var sink = isupport.ReplySink{ .lines = &line_slots, .storage = &storage };
        try (isupport.Builder{
            .server_name = "s",
            .requester = "n",
            .tokens = tokens[0..token_count],
            .trailing = "ok",
            .max_line_bytes = 120,
        }).emit(&sink);

        for (tokens[0..token_count], 0..) |token, index| {
            _ = try token.write(&rendered[index]);
        }

        try expectFoldedLinesWellFormed(sink.slice(), "s", "n", "ok", tokens[0..token_count], &rendered);
        for (sink.slice()) |line| {
            try std.testing.expect(line.bytes.len <= 120);
            try std.testing.expect(line.bytes.len <= isupport.MAX_IRC_LINE_BYTES);
        }
    }
}

test "builder reports capacity overflow without silently truncating" {
    var specs: [18]TokenSpec = undefined;
    var tokens: [specs.len]isupport.Token = undefined;
    fillSequentialTokens(specs[0..], &tokens);

    var one_line: [1]isupport.ReplyLine = undefined;
    var enough_storage: [1024]u8 = undefined;
    var short_lines = isupport.ReplySink{ .lines = &one_line, .storage = &enough_storage };
    try std.testing.expectError(error.TooManyLines, (isupport.Builder{
        .server_name = "s",
        .requester = "n",
        .tokens = &tokens,
        .trailing = "ok",
    }).emit(&short_lines));

    var many_lines: [8]isupport.ReplyLine = undefined;
    var short_storage: [32]u8 = undefined;
    var small_output = isupport.ReplySink{ .lines = &many_lines, .storage = &short_storage };
    try std.testing.expectError(error.OutputTooSmall, (isupport.Builder{
        .server_name = "s",
        .requester = "n",
        .tokens = &tokens,
        .trailing = "ok",
    }).emit(&small_output));

    var map = isupport.TokenMap(2).init();
    try map.put(tokens[0]);
    try map.put(tokens[1]);
    try std.testing.expectError(error.TooManyTokens, map.put(tokens[2]));
    try std.testing.expectEqual(@as(usize, 2), map.slice().len);
}

test "arbitrary token names and values return typed errors or valid renderings" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0x3003);
    const random = prng.random();

    var name_buf: [40]u8 = undefined;
    var value_buf: [160]u8 = undefined;
    var out: [256]u8 = undefined;
    var line_slots: [4]isupport.ReplyLine = undefined;
    var storage: [1024]u8 = undefined;

    var iteration: usize = 0;
    while (iteration < fuzz_iterations) : (iteration += 1) {
        const name_len = randomLength(random, iteration, name_buf.len);
        const value_len = randomLength(random, iteration *% 17 + 3, value_buf.len);
        fillAttackerBytes(random, name_buf[0..name_len], iteration);
        fillAttackerBytes(random, value_buf[0..value_len], iteration + 11);

        const token = isupport.Token{
            .name = name_buf[0..name_len],
            .value = if (iteration % 4 == 0) null else value_buf[0..value_len],
            .negated = iteration % 7 == 0,
        };

        if (token.validate()) |_| {
            const rendered = try token.write(&out);
            try expectRenderedTokenWellFormed(token, rendered);

            var sink = isupport.ReplySink{ .lines = &line_slots, .storage = &storage };
            try (isupport.Builder{
                .server_name = "s",
                .requester = "n",
                .tokens = &.{token},
                .trailing = "ok",
            }).emit(&sink);
            var rendered_one: [1][256]u8 = undefined;
            rendered_one[0] = out;
            try expectFoldedLinesWellFormed(sink.slice(), "s", "n", "ok", &.{token}, &rendered_one);
        } else |err| {
            try expectIsupportError(err);
        }
    }
}

fn fillValidTokens(random: std.Random, specs: []TokenSpec, iteration: usize) void {
    for (specs, 0..) |*spec, index| {
        const ordinal = iteration * specs.len + index;
        fillTokenName(ordinal, &spec.name, &spec.name_len);
        spec.has_value = ordinal % 5 != 0;
        spec.negated = !spec.has_value and ordinal % 7 == 0;
        spec.value_len = if (spec.has_value) 1 + random.uintLessThan(usize, spec.value.len) else 0;
        if (spec.has_value) fillTokenValue(random, spec.value[0..spec.value_len]);
    }
}

fn fillSequentialTokens(specs: []TokenSpec, tokens: []isupport.Token) void {
    for (specs, tokens, 0..) |*spec, *token, index| {
        fillTokenName(index, &spec.name, &spec.name_len);
        spec.value_len = 3;
        spec.value[0] = 'v';
        spec.value[1] = '0' + @as(u8, @intCast(index / 10));
        spec.value[2] = '0' + @as(u8, @intCast(index % 10));
        spec.has_value = true;
        spec.negated = false;
        token.* = spec.token();
    }
}

fn fillTokenName(ordinal: usize, out: *[16]u8, len: *usize) void {
    out[0] = 'T';
    out[1] = 'K';
    out[2] = 'N';
    var n = ordinal;
    var pos: usize = 3;
    while (pos < out.len) : (pos += 1) {
        out[pos] = 'A' + @as(u8, @intCast(n % 26));
        n /= 26;
        if (n == 0 and pos >= 5) {
            len.* = pos + 1;
            return;
        }
    }
    len.* = out.len;
}

fn fillTokenValue(random: std.Random, out: []u8) void {
    for (out) |*byte| {
        byte.* = switch (random.uintLessThan(u8, 18)) {
            0 => '=',
            1 => ':',
            2 => ',',
            3 => '#',
            4 => '(',
            5 => ')',
            6 => '-',
            7 => '_',
            8...11 => '0' + random.uintLessThan(u8, 10),
            12...15 => 'A' + random.uintLessThan(u8, 26),
            else => 'a' + random.uintLessThan(u8, 26),
        };
    }
}

fn fillAttackerBytes(random: std.Random, out: []u8, iteration: usize) void {
    for (out, 0..) |*byte, index| {
        byte.* = switch ((iteration + index + random.uintLessThan(usize, 23)) % 23) {
            0 => 0,
            1 => ' ',
            2 => '\r',
            3 => '\n',
            4 => 0x7f,
            5 => '=',
            6 => '-',
            7 => ':',
            8 => random.uintLessThan(u8, 0x20),
            9...13 => 'A' + random.uintLessThan(u8, 26),
            14...17 => 'a' + random.uintLessThan(u8, 26),
            18...20 => '0' + random.uintLessThan(u8, 10),
            else => random.int(u8),
        };
    }
}

fn randomLength(random: std.Random, iteration: usize, max_len: usize) usize {
    return switch (iteration % 12) {
        0 => 0,
        1 => 1,
        2 => max_len,
        3 => max_len / 2,
        else => random.uintLessThan(usize, max_len + 1),
    };
}

fn expectFoldedLinesWellFormed(
    lines: []const isupport.ReplyLine,
    server_name: []const u8,
    requester: []const u8,
    trailing: []const u8,
    tokens: []const isupport.Token,
    rendered_storage: anytype,
) !void {
    var seen: [64]bool = [_]bool{false} ** 64;
    try std.testing.expect(tokens.len <= seen.len);

    for (lines) |line| {
        try std.testing.expect(line.bytes.len <= isupport.MAX_IRC_LINE_BYTES);
        try std.testing.expect(std.mem.endsWith(u8, line.bytes, "\r\n"));

        var params: [18][]const u8 = undefined;
        const param_count = try parseIsupportLine(line.bytes, server_name, requester, trailing, &params);
        try std.testing.expect(param_count <= isupport.MAX_TOKENS_PER_LINE);

        for (params[0..param_count]) |param| {
            const index = try findRenderedToken(param, tokens, rendered_storage);
            try std.testing.expect(!seen[index]);
            seen[index] = true;
            try expectRenderedTokenWellFormed(tokens[index], param);
        }
    }

    for (seen[0..tokens.len]) |found| {
        try std.testing.expect(found);
    }
}

fn parseIsupportLine(
    line: []const u8,
    server_name: []const u8,
    requester: []const u8,
    trailing: []const u8,
    params: [][]const u8,
) !usize {
    try std.testing.expect(std.mem.endsWith(u8, line, "\r\n"));
    const body = line[0 .. line.len - 2];
    var expected_buf: [160]u8 = undefined;
    const expected_prefix = try std.fmt.bufPrint(&expected_buf, ":{s} 005 {s}", .{ server_name, requester });
    try std.testing.expect(std.mem.startsWith(u8, body, expected_prefix));

    var cursor = expected_prefix.len;
    var count: usize = 0;
    while (cursor < body.len) {
        try std.testing.expectEqual(@as(u8, ' '), body[cursor]);
        cursor += 1;
        if (cursor < body.len and body[cursor] == ':') {
            try std.testing.expectEqualStrings(trailing, body[cursor + 1 ..]);
            return count;
        }

        const start = cursor;
        while (cursor < body.len and body[cursor] != ' ') : (cursor += 1) {}
        try std.testing.expect(count < params.len);
        params[count] = body[start..cursor];
        count += 1;
    }
    return error.InvalidTrailing;
}

fn findRenderedToken(
    param: []const u8,
    tokens: []const isupport.Token,
    rendered_storage: anytype,
) !usize {
    for (tokens, 0..) |token, index| {
        const len = try token.renderedLen();
        if (std.mem.eql(u8, param, rendered_storage[index][0..len])) return index;
    }
    return error.InvalidTokenValue;
}

fn expectRenderedTokenWellFormed(token: isupport.Token, rendered: []const u8) !void {
    try token.validate();
    try std.testing.expectEqual(try token.renderedLen(), rendered.len);

    if (token.negated) {
        try std.testing.expectEqual(@as(u8, '-'), rendered[0]);
        try std.testing.expectEqualStrings(token.name, rendered[1..]);
        return;
    }

    if (token.value) |value| {
        const eq = std.mem.indexOfScalar(u8, rendered, '=') orelse return error.InvalidTokenValue;
        try std.testing.expectEqualStrings(token.name, rendered[0..eq]);
        try std.testing.expectEqualStrings(value, rendered[eq + 1 ..]);
    } else {
        try std.testing.expectEqualStrings(token.name, rendered);
    }
}

fn expectIsupportError(err: isupport.IsupportError) !void {
    switch (err) {
        error.InvalidLimit,
        error.InvalidParameter,
        error.InvalidTokenName,
        error.InvalidTokenValue,
        error.InvalidTrailing,
        error.LineTooLong,
        error.NegatedTokenHasValue,
        error.OutputTooSmall,
        error.TokenTooLong,
        error.TooManyLines,
        error.TooManyTokens,
        => {},
    }
}

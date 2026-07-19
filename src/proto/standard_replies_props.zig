// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deterministic property and fuzz-style tests for IRCv3 standard replies.
//!
//! These tests exercise the public FAIL/WARN builder API with bounded,
//! fixed-seed attacker bytes. A generated input may fail validation, but it
//! must fail with the builder's typed errors; successful output must remain a
//! valid IRC line body with no raw line-control injection.
const std = @import("std");
const standard_replies = @import("standard_replies.zig");

const seed: u64 = 0x5354_4452_4550_1600;
const arbitrary_iterations: usize = 3200;
const bounds_iterations: usize = 1400;
const structured_iterations: usize = 950;

const ParsedReply = struct {
    kind: standard_replies.ReplyType,
    command: []const u8,
    code: []const u8,
    contexts: [8][]const u8 = undefined,
    context_count: usize = 0,
    description: []const u8,

    fn contextSlice(self: *const ParsedReply) []const []const u8 {
        return self.contexts[0..self.context_count];
    }
};

test "FAIL and WARN builders return typed errors or valid bounded lines for arbitrary bytes" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0xa771_6b1e);
    const random = prng.random();

    var command_buf: [96]u8 = undefined;
    var code_buf: [96]u8 = undefined;
    var context_one_buf: [96]u8 = undefined;
    var context_two_buf: [96]u8 = undefined;
    var description_buf: [180]u8 = undefined;
    var out: [standard_replies.MAX_LEGACY_BODY]u8 = undefined;

    for (0..arbitrary_iterations) |iteration| {
        const command = arbitrarySlice(random, &command_buf, iteration);
        const code = arbitrarySlice(random, &code_buf, iteration + 11);
        const context_one = arbitrarySlice(random, &context_one_buf, iteration + 23);
        const context_two = arbitrarySlice(random, &context_two_buf, iteration + 37);
        const description = arbitrarySlice(random, &description_buf, iteration + 41);
        const contexts = [_][]const u8{ context_one, context_two };

        const builder = standard_replies.custom(
            replyTypeForIteration(iteration),
            command,
            code,
            description,
        ).withContext(contexts[0 .. iteration % (contexts.len + 1)])
            .withMaxBodyLen(standard_replies.MAX_LEGACY_BODY);

        if (builder.write(&out)) |line| {
            try expectValidRenderedLine(line, builder.kind);
            try std.testing.expect(line.len <= standard_replies.MAX_LEGACY_BODY);
        } else |err| {
            try expectBuildError(err);
        }
    }
}

test "caller buffers are respected while enforcing the 512 octet IRC line limit" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0x5120_0c7e);
    const random = prng.random();

    var command_buf: [32]u8 = undefined;
    var code_buf: [48]u8 = undefined;
    var context_one_buf: [48]u8 = undefined;
    var context_two_buf: [48]u8 = undefined;
    var description_buf: [360]u8 = undefined;
    var storage: [standard_replies.MAX_LEGACY_BODY + 2 + 2]u8 = undefined;

    for (0..bounds_iterations) |iteration| {
        const command = validMiddleToken(random, &command_buf, iteration, "CMD");
        const code = validCodeToken(random, &code_buf, iteration, "ONYX_CODE");
        const context_one = validMiddleToken(random, &context_one_buf, iteration + 9, "#onyx");
        const context_two = validMiddleToken(random, &context_two_buf, iteration + 17, "property.name");
        const description = descriptionCandidate(random, &description_buf, iteration);
        const contexts = [_][]const u8{ context_one, context_two };

        const builder = standard_replies.custom(
            replyTypeForIteration(iteration),
            command,
            code,
            description,
        ).withContext(contexts[0 .. iteration % (contexts.len + 1)])
            .withMaxBodyLen(standard_replies.MAX_LEGACY_BODY);

        const required = builder.requiredLen() catch |err| {
            try expectBuildError(err);
            continue;
        };
        try std.testing.expect(required <= standard_replies.MAX_LEGACY_BODY);

        const wire_required = required + 2;
        const cap = switch (iteration % 11) {
            0 => 0,
            1 => if (wire_required == 0) 0 else wire_required - 1,
            2 => wire_required,
            3 => wire_required + 1,
            else => random.uintLessThan(usize, storage.len - 2 + 1),
        };

        @memset(&storage, 0xa5);
        const view = storage[1 .. 1 + cap];
        if (builder.writeCrlf(view)) |wire| {
            try std.testing.expectEqual(wire_required, wire.len);
            try std.testing.expect(wire.len <= 512);
            try std.testing.expect(std.mem.endsWith(u8, wire, "\r\n"));
            try std.testing.expectEqual(@as(u8, 0xa5), storage[0]);
            try std.testing.expectEqual(@as(u8, 0xa5), storage[1 + cap]);

            const body = wire[0 .. wire.len - 2];
            const parsed = try parseRenderedLine(body);
            try std.testing.expectEqual(builder.kind, parsed.kind);
            try expectNoInjectedLineControls(body);
        } else |err| {
            try expectBuildError(err);
            try std.testing.expect(cap < wire_required);
            try std.testing.expectEqual(@as(u8, 0xa5), storage[0]);
            try std.testing.expectEqual(@as(u8, 0xa5), storage[1 + cap]);
        }
    }
}

test "valid structured replies parse back to the original command code contexts and rendered description" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0x600d_c0de);
    const random = prng.random();

    var command_buf: [40]u8 = undefined;
    var code_buf: [64]u8 = undefined;
    var context_storage: [4][64]u8 = undefined;
    var contexts: [4][]const u8 = undefined;
    var description_buf: [220]u8 = undefined;
    var rendered_description_buf: [standard_replies.MAX_LEGACY_BODY]u8 = undefined;
    var out: [512]u8 = undefined;

    for (0..structured_iterations) |iteration| {
        const command = validMiddleToken(random, &command_buf, iteration, "REGISTER");
        const description = descriptionCandidate(random, &description_buf, iteration);
        const context_count = iteration % (contexts.len + 1);
        for (0..context_count) |index| {
            contexts[index] = validMiddleToken(
                random,
                &context_storage[index],
                iteration + index * 19,
                switch (index) {
                    0 => "#onyx",
                    1 => "prop.locked",
                    2 => "account",
                    else => "mesh-a",
                },
            );
        }

        const builder = if (iteration % 4 == 0) blk: {
            const code = catalogCodeByIndex(random.uintLessThan(usize, catalog_code_count));
            break :blk standard_replies.fail(command, code, description);
        } else blk: {
            const code = validCodeToken(random, &code_buf, iteration, "IRCX_POLICY_DENIED");
            break :blk standard_replies.custom(replyTypeForIteration(iteration), command, code, description);
        };

        const line = try builder
            .withContext(contexts[0..context_count])
            .withMaxBodyLen(standard_replies.MAX_LEGACY_BODY)
            .write(&out);
        const parsed = try parseRenderedLine(line);

        try std.testing.expectEqual(builder.kind, parsed.kind);
        try std.testing.expectEqualStrings(command, parsed.command);
        try std.testing.expect(standard_replies.validCodeToken(parsed.code));
        try std.testing.expectEqual(context_count, parsed.context_count);
        for (contexts[0..context_count], parsed.contextSlice()) |expected, actual| {
            try std.testing.expectEqualStrings(expected, actual);
        }
        const rendered_description = try referenceRenderDescription(description, &rendered_description_buf);
        try std.testing.expectEqualStrings(rendered_description, parsed.description);
        try expectNoInjectedLineControls(line);

        if (builder.code == .catalog) {
            try std.testing.expectEqual(builder.code.catalog, standard_replies.parseCatalogCode(parsed.code).?);
        } else {
            try std.testing.expectEqualStrings(builder.code.custom, parsed.code);
        }
    }
}

test "catalog code tokens round trip through parseCatalogCode and remain well formed" {
    inline for (@typeInfo(standard_replies.Code).@"enum".field_names) |field_name| {
        const parsed = standard_replies.parseCatalogCode(field_name).?;
        try std.testing.expectEqual(@field(standard_replies.Code, field_name), parsed);
        try std.testing.expect(standard_replies.validCodeToken(field_name));
    }

    try std.testing.expectEqual(@as(?standard_replies.Code, null), standard_replies.parseCatalogCode("bad-code"));
    try std.testing.expect(!standard_replies.validCodeToken(""));
    try std.testing.expect(!standard_replies.validCodeToken("1BAD"));
    try std.testing.expect(!standard_replies.validCodeToken("BAD-CODE"));
    try std.testing.expect(!standard_replies.validMiddleParam(""));
    try std.testing.expect(!standard_replies.validMiddleParam(":trailing"));
    try std.testing.expect(!standard_replies.validMiddleParam("bad context"));
}

fn parseRenderedLine(line: []const u8) !ParsedReply {
    try expectNoInjectedLineControls(line);

    const split = std.mem.indexOf(u8, line, " :") orelse return error.MissingDescription;
    const head = line[0..split];
    const description = line[split + 2 ..];

    var parsed = ParsedReply{
        .kind = undefined,
        .command = "",
        .code = "",
        .description = description,
    };

    var token_index: usize = 0;
    var start: usize = 0;
    while (start <= head.len) {
        const end = std.mem.indexOfScalarPos(u8, head, start, ' ') orelse head.len;
        const token = head[start..end];
        if (token.len == 0) return error.EmptyToken;

        switch (token_index) {
            0 => parsed.kind = try parseReplyType(token),
            1 => parsed.command = token,
            2 => parsed.code = token,
            else => {
                if (parsed.context_count == parsed.contexts.len) return error.TooManyContexts;
                parsed.contexts[parsed.context_count] = token;
                parsed.context_count += 1;
            },
        }

        token_index += 1;
        if (end == head.len) break;
        start = end + 1;
    }

    if (token_index < 3) return error.MissingToken;
    if (!standard_replies.validMiddleParam(parsed.command)) return error.InvalidCommand;
    if (!standard_replies.validCodeToken(parsed.code)) return error.InvalidCode;
    for (parsed.contextSlice()) |context| {
        if (!standard_replies.validMiddleParam(context)) return error.InvalidContext;
    }
    return parsed;
}

fn parseReplyType(token: []const u8) !standard_replies.ReplyType {
    if (std.mem.eql(u8, token, "FAIL")) return .fail;
    if (std.mem.eql(u8, token, "WARN")) return .warn;
    return error.InvalidReplyType;
}

fn expectValidRenderedLine(line: []const u8, expected_kind: standard_replies.ReplyType) !void {
    const parsed = try parseRenderedLine(line);
    try std.testing.expectEqual(expected_kind, parsed.kind);
    try std.testing.expect(standard_replies.validMiddleParam(parsed.command));
    try std.testing.expect(standard_replies.validCodeToken(parsed.code));
    for (parsed.contextSlice()) |context| {
        try std.testing.expect(standard_replies.validMiddleParam(context));
    }
}

fn expectNoInjectedLineControls(line: []const u8) !void {
    for (line) |byte| {
        switch (byte) {
            0, '\r', '\n' => return error.InjectedLineControl,
            else => {},
        }
    }
}

fn expectBuildError(err: standard_replies.BuildError) !void {
    switch (err) {
        error.InvalidCommand,
        error.InvalidCode,
        error.InvalidContext,
        error.InvalidDescription,
        error.MessageTooLong,
        error.OutputTooSmall,
        => {},
    }
}

fn replyTypeForIteration(iteration: usize) standard_replies.ReplyType {
    return switch (iteration % 2) {
        0 => .fail,
        else => .warn,
    };
}

const catalog_code_count = @typeInfo(standard_replies.Code).@"enum".field_names.len;

fn catalogCodeByIndex(index: usize) standard_replies.Code {
    inline for (@typeInfo(standard_replies.Code).@"enum".field_names, 0..) |field_name, field_index| {
        if (index == field_index) return @field(standard_replies.Code, field_name);
    }
    return .UNKNOWN_ERROR;
}

fn arbitrarySlice(random: std.Random, buf: []u8, iteration: usize) []const u8 {
    const len = biasedLength(random, iteration, buf.len);
    fillArbitraryBytes(random, buf[0..len]);
    return buf[0..len];
}

fn biasedLength(random: std.Random, iteration: usize, max_len: usize) usize {
    return switch (iteration % 18) {
        0 => 0,
        1 => 1,
        2 => @min(max_len, 2),
        3 => @min(max_len, 15),
        4 => @min(max_len, 64),
        5 => max_len,
        else => random.uintLessThan(usize, max_len + 1),
    };
}

fn fillArbitraryBytes(random: std.Random, out: []u8) void {
    for (out) |*byte| {
        byte.* = switch (random.uintLessThan(u8, 32)) {
            0 => 0,
            1 => '\r',
            2 => '\n',
            3 => '\t',
            4 => ' ',
            5 => ':',
            6 => '\\',
            7 => '_',
            8 => '-',
            9 => 0x7f,
            10 => 0x80,
            11 => 0xff,
            12...17 => 'A' + random.uintLessThan(u8, 26),
            18...21 => '0' + random.uintLessThan(u8, 10),
            22...25 => 'a' + random.uintLessThan(u8, 26),
            else => random.int(u8),
        };
    }
}

fn validMiddleToken(
    random: std.Random,
    buf: []u8,
    iteration: usize,
    fallback: []const u8,
) []const u8 {
    if (iteration % 9 == 0) return fallback;
    const len = 1 + random.uintLessThan(usize, @min(buf.len, 36));
    for (buf[0..len], 0..) |*byte, index| {
        byte.* = switch (random.uintLessThan(u8, 16)) {
            0 => '#',
            1 => '.',
            2 => '_',
            3 => '-',
            4 => '+',
            5 => if (index == 0) 'C' else ':',
            6...10 => 'A' + random.uintLessThan(u8, 26),
            11...13 => 'a' + random.uintLessThan(u8, 26),
            else => '0' + random.uintLessThan(u8, 10),
        };
    }
    if (buf[0] == ':') buf[0] = 'C';
    return buf[0..len];
}

fn validCodeToken(
    random: std.Random,
    buf: []u8,
    iteration: usize,
    fallback: []const u8,
) []const u8 {
    if (iteration % 7 == 0) return fallback;
    const len = 1 + random.uintLessThan(usize, @min(buf.len, 40));
    buf[0] = 'A' + random.uintLessThan(u8, 26);
    for (buf[1..len]) |*byte| {
        byte.* = switch (random.uintLessThan(u8, 12)) {
            0...7 => 'A' + random.uintLessThan(u8, 26),
            8...10 => '0' + random.uintLessThan(u8, 10),
            else => '_',
        };
    }
    return buf[0..len];
}

fn descriptionCandidate(random: std.Random, buf: []u8, iteration: usize) []const u8 {
    const len = biasedLength(random, iteration, buf.len);
    for (buf[0..len]) |*byte| {
        byte.* = switch (random.uintLessThan(u8, 24)) {
            0 => 0,
            1 => '\r',
            2 => '\n',
            3 => '\t',
            4 => '\\',
            5 => 0x01 + random.uintLessThan(u8, 0x1f),
            6 => 0x7f,
            7 => ' ',
            8 => ':',
            9...15 => 'a' + random.uintLessThan(u8, 26),
            16...20 => 'A' + random.uintLessThan(u8, 26),
            else => '0' + random.uintLessThan(u8, 10),
        };
    }
    return buf[0..len];
}

fn referenceRenderDescription(description: []const u8, out: []u8) ![]const u8 {
    var cursor: usize = 0;
    for (description) |byte| {
        switch (byte) {
            0 => try appendBytes(out, &cursor, "\\0"),
            '\r' => try appendBytes(out, &cursor, "\\r"),
            '\n' => try appendBytes(out, &cursor, "\\n"),
            '\t' => try appendBytes(out, &cursor, "\\t"),
            '\\' => try appendBytes(out, &cursor, "\\\\"),
            0x01...0x08, 0x0b, 0x0c, 0x0e...0x1f, 0x7f => {
                const HEX = "0123456789ABCDEF";
                try appendBytes(out, &cursor, "\\x");
                try appendByte(out, &cursor, HEX[byte >> 4]);
                try appendByte(out, &cursor, HEX[byte & 0x0f]);
            },
            else => try appendByte(out, &cursor, byte),
        }
    }
    return out[0..cursor];
}

fn appendBytes(out: []u8, cursor: *usize, bytes: []const u8) !void {
    if (bytes.len > out.len - cursor.*) return error.OutputTooSmall;
    @memcpy(out[cursor.* .. cursor.* + bytes.len], bytes);
    cursor.* += bytes.len;
}

fn appendByte(out: []u8, cursor: *usize, byte: u8) !void {
    if (cursor.* == out.len) return error.OutputTooSmall;
    out[cursor.*] = byte;
    cursor.* += 1;
}

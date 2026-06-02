//! Property tests for the zero-copy IRC line parser.
const std = @import("std");
const irc_line = @import("irc_line.zig");

const parse_iterations = 2600;
const structured_iterations = 700;
const tag_iterations = 1500;
const oversize_iterations = 64;

test "parseLine returns ok or typed errors for deterministic random attacker bytes" {
    var prng = std.Random.DefaultPrng.init(0x4d495a5543484916);
    const random = prng.random();
    var input_buf: [irc_line.MAX_LINE_BODY + 8]u8 = undefined;

    for (0..parse_iterations) |iteration| {
        const len = randomLength(random, iteration, input_buf.len);
        fillBiasedBytes(random, input_buf[0..len]);

        const parsed = irc_line.parseLine(input_buf[0..len]);
        if (parsed) |line| {
            try expectValidLineView(input_buf[0..len], line);
        } else |err| {
            try expectParseError(err);
        }
    }
}

test "parseLine handles structured but corrupt lines without escaping typed errors" {
    var prng = std.Random.DefaultPrng.init(0x4952434c494e4501);
    const random = prng.random();
    var input_buf: [512]u8 = undefined;

    for (0..structured_iterations) |iteration| {
        const len = randomLength(random, iteration, input_buf.len);
        fillStructuredLine(random, input_buf[0..len], iteration);

        const parsed = irc_line.parseLine(input_buf[0..len]);
        if (parsed) |line| {
            try expectValidLineView(input_buf[0..len], line);
        } else |err| {
            try expectParseError(err);
        }
    }
}

test "tag value unescape and reference re-escape round trip for random raw values" {
    var prng = std.Random.DefaultPrng.init(0x5441474553434150);
    const random = prng.random();
    var raw_buf: [256]u8 = undefined;
    var decoded_buf: [raw_buf.len]u8 = undefined;
    var escaped_buf: [raw_buf.len * 2]u8 = undefined;
    var decoded_again_buf: [escaped_buf.len]u8 = undefined;

    for (0..tag_iterations) |iteration| {
        const raw_len = randomLength(random, iteration, raw_buf.len);
        fillTagValueBytes(random, raw_buf[0..raw_len]);

        const decoded = try irc_line.unescapeTagValue(raw_buf[0..raw_len], &decoded_buf);
        const escaped = try referenceEscapeTagValue(decoded, &escaped_buf);
        const decoded_again = try irc_line.unescapeTagValue(escaped, &decoded_again_buf);

        try std.testing.expectEqualSlices(u8, decoded, decoded_again);
    }
}

test "lines longer than MAX_LINE_BODY are rejected instead of silently truncated" {
    var prng = std.Random.DefaultPrng.init(0x4f56455253495a45);
    const random = prng.random();
    var input_buf: [irc_line.MAX_LINE_BODY + 96]u8 = undefined;

    for (0..oversize_iterations) |iteration| {
        const extra = 1 + random.uintLessThan(usize, input_buf.len - irc_line.MAX_LINE_BODY);
        const len = irc_line.MAX_LINE_BODY + extra;
        @memset(input_buf[0..len], 'A');
        input_buf[0] = 'C';
        input_buf[1] = 'M';
        input_buf[2] = 'D';

        if (iteration % 4 == 0) {
            input_buf[len - 1] = '\n';
        } else if (iteration % 4 == 1) {
            input_buf[len - 2] = '\r';
            input_buf[len - 1] = '\n';
        }

        try std.testing.expectError(error.OversizeLine, irc_line.parseLine(input_buf[0..len]));
    }
}

fn expectValidLineView(input: []const u8, line: irc_line.LineView) !void {
    try expectSliceWithin(input, line.raw);
    try expectSliceWithin(input, line.command);
    try std.testing.expect(line.command.len != 0);
    try std.testing.expect(line.param_count <= irc_line.MAXPARA);
    try std.testing.expect(line.tag_count <= irc_line.MAXTAGS);

    if (line.tags_raw) |tags_raw| try expectSliceWithin(input, tags_raw);
    if (line.prefix) |prefix| try expectSliceWithin(input, prefix);
    if (line.trailing) |trailing| try expectSliceWithin(input, trailing);

    for (line.paramSlice()) |param| {
        try expectSliceWithin(input, param);
    }

    for (line.tagSlice()) |tag| {
        try expectSliceWithin(input, tag.key);
        if (tag.value_raw) |value_raw| try expectSliceWithin(input, value_raw);
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

fn expectParseError(err: irc_line.ParseError) !void {
    switch (err) {
        error.EmptyLine,
        error.OversizeLine,
        error.EmbeddedNul,
        error.EmbeddedLineBreak,
        error.MissingCommand,
        error.MalformedPrefix,
        error.MalformedTags,
        error.TooManyParams,
        error.TooManyTags,
        => {},
    }
}

fn randomLength(random: std.Random, iteration: usize, max_len: usize) usize {
    return switch (iteration % 16) {
        0 => 0,
        1 => 1,
        2 => @min(max_len, irc_line.MAX_LINE_BODY),
        3 => max_len,
        4 => if (max_len > irc_line.MAX_LINE_BODY) irc_line.MAX_LINE_BODY + 1 else max_len,
        else => random.uintLessThan(usize, max_len + 1),
    };
}

fn fillBiasedBytes(random: std.Random, out: []u8) void {
    for (out) |*byte| {
        byte.* = switch (random.uintLessThan(u8, 24)) {
            0 => ':',
            1 => '@',
            2 => ' ',
            3 => '\r',
            4 => '\n',
            5 => 0,
            6 => ';',
            7 => '=',
            8 => '\\',
            9 => 0xff,
            10 => 0x80,
            11 => random.uintLessThan(u8, 0x20),
            12...16 => 'A' + random.uintLessThan(u8, 26),
            17...20 => 'a' + random.uintLessThan(u8, 26),
            else => random.int(u8),
        };
    }
}

fn fillStructuredLine(random: std.Random, out: []u8, iteration: usize) void {
    if (out.len == 0) return;

    var cursor: usize = 0;
    if (cursor < out.len and iteration % 3 == 0) {
        out[cursor] = '@';
        cursor += 1;
        cursor = appendRandomAtom(random, out, cursor, "tag");
        if (cursor < out.len and random.boolean()) {
            out[cursor] = '=';
            cursor += 1;
            cursor = appendRandomAtom(random, out, cursor, "value");
        }
        while (cursor < out.len and random.boolean()) {
            out[cursor] = ';';
            cursor += 1;
            cursor = appendRandomAtom(random, out, cursor, "tag");
        }
        if (cursor < out.len) {
            out[cursor] = ' ';
            cursor += 1;
        }
    }

    if (cursor < out.len and iteration % 4 == 0) {
        out[cursor] = ':';
        cursor += 1;
        cursor = appendRandomAtom(random, out, cursor, "nick!user@host");
        if (cursor < out.len) {
            out[cursor] = ' ';
            cursor += 1;
        }
    }

    cursor = appendRandomAtom(random, out, cursor, "PRIVMSG");
    while (cursor < out.len) {
        out[cursor] = switch (random.uintLessThan(u8, 10)) {
            0 => '\r',
            1 => '\n',
            2 => 0,
            3 => ':',
            else => ' ',
        };
        cursor += 1;
        cursor = appendRandomAtom(random, out, cursor, "#chan");
    }
}

fn appendRandomAtom(random: std.Random, out: []u8, cursor_start: usize, fallback: []const u8) usize {
    var cursor = cursor_start;
    var index: usize = 0;
    while (cursor < out.len and index < fallback.len and random.uintLessThan(u8, 5) != 0) : ({
        cursor += 1;
        index += 1;
    }) {
        out[cursor] = if (random.uintLessThan(u8, 10) == 0) randomDelimiter(random) else fallback[index];
    }
    return cursor;
}

fn fillTagValueBytes(random: std.Random, out: []u8) void {
    for (out) |*byte| {
        byte.* = switch (random.uintLessThan(u8, 16)) {
            0 => '\\',
            1 => ';',
            2 => ' ',
            3 => '\r',
            4 => '\n',
            5 => ':',
            6 => 's',
            7 => 'r',
            8 => 'n',
            9 => 0,
            10 => 0xff,
            11 => 0x80,
            12...13 => 'a' + random.uintLessThan(u8, 26),
            else => random.int(u8),
        };
    }
}

fn randomDelimiter(random: std.Random) u8 {
    return switch (random.uintLessThan(u8, 8)) {
        0 => ':',
        1 => '@',
        2 => ' ',
        3 => '\r',
        4 => '\n',
        5 => 0,
        6 => ';',
        else => '=',
    };
}

fn referenceEscapeTagValue(raw: []const u8, out_buf: []u8) ![]const u8 {
    var write: usize = 0;
    for (raw) |byte| {
        const replacement: ?[]const u8 = switch (byte) {
            '\\' => "\\\\",
            ';' => "\\:",
            ' ' => "\\s",
            '\r' => "\\r",
            '\n' => "\\n",
            else => null,
        };

        if (replacement) |escaped| {
            if (write + escaped.len > out_buf.len) return error.OutputTooSmall;
            @memcpy(out_buf[write .. write + escaped.len], escaped);
            write += escaped.len;
        } else {
            if (write >= out_buf.len) return error.OutputTooSmall;
            out_buf[write] = byte;
            write += 1;
        }
    }
    return out_buf[0..write];
}

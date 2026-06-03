//! Deterministic property tests for IRCv3 draft/multiline batch assembly.
const std = @import("std");
const multiline = @import("multiline.zig");

const seed: u64 = 0x4d55_4c54_494c_1600;
const concat_iterations: usize = 1200;
const fuzz_iterations: usize = 2200;
const max_generated_lines: usize = 8;
const max_generated_bytes: usize = 512;

test "generated multiline parts concatenate exactly within the byte cap" {
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();

    var open_buf: [96]u8 = undefined;
    var close_buf: [64]u8 = undefined;
    var line_storage: [max_generated_lines][192]u8 = undefined;
    var text_storage: [max_generated_lines][64]u8 = undefined;
    var body_lines: [max_generated_lines][]const u8 = undefined;
    var expected: [max_generated_bytes]u8 = undefined;
    var out: [max_generated_bytes]u8 = undefined;

    for (0..concat_iterations) |iteration| {
        const ref = try refFor(iteration, &open_buf);
        const open_line = try writeOpen(open_buf[32..], ref, "#mizuchi");
        const close_line = try writeClose(&close_buf, ref);

        const line_count = 1 + random.uintLessThan(usize, max_generated_lines);
        var expected_len: usize = 0;

        for (0..line_count) |index| {
            const concat = index != 0 and random.boolean();
            const text_len = randomTextLen(random, iteration, index, concat);
            fillPayloadBytes(random, text_storage[index][0..text_len], iteration + index);

            if (index != 0 and !concat) {
                expected[expected_len] = '\n';
                expected_len += 1;
            }
            @memcpy(expected[expected_len .. expected_len + text_len], text_storage[index][0..text_len]);
            expected_len += text_len;

            body_lines[index] = try writeBody(
                &line_storage[index],
                ref,
                "#mizuchi",
                .privmsg,
                concat,
                text_storage[index][0..text_len],
            );
        }

        const msg = try multiline.assemble(
            .{ .max_bytes = max_generated_bytes, .max_lines = max_generated_lines },
            open_line,
            body_lines[0..line_count],
            close_line,
            &out,
        );

        try std.testing.expectEqual(multiline.PayloadCommand.privmsg, msg.command);
        try std.testing.expectEqual(@as(usize, line_count), msg.line_count);
        try std.testing.expect(msg.value.len <= max_generated_bytes);
        try std.testing.expectEqualSlices(u8, expected[0..expected_len], msg.value);
    }
}

test "line and byte accounting is exact and failed appends do not advance state" {
    const Exact = multiline.Assembler(.{ .max_bytes = 7, .max_lines = 3 });
    var exact = Exact.init();
    var out: [16]u8 = undefined;

    try exact.begin("BATCH +acct draft/multiline #c");
    try exact.append("@batch=acct PRIVMSG #c :abc", &out);
    try expectState(&exact, 1, 3, "abc", &out);

    try exact.append("@batch=acct;draft/multiline-concat PRIVMSG #c :de", &out);
    try expectState(&exact, 2, 5, "abcde", &out);

    try exact.append("@batch=acct PRIVMSG #c :f", &out);
    try expectState(&exact, 3, 7, "abcde\nf", &out);

    try std.testing.expectError(error.MaxLinesExceeded, exact.append("@batch=acct PRIVMSG #c :g", &out));
    try expectState(&exact, 3, 7, "abcde\nf", &out);

    const Bytes = multiline.Assembler(.{ .max_bytes = 7, .max_lines = 5 });
    var bytes = Bytes.init();
    try bytes.begin("BATCH +bytes draft/multiline #c");
    try bytes.append("@batch=bytes NOTICE #c :abcd", &out);
    try expectState(&bytes, 1, 4, "abcd", &out);

    try std.testing.expectError(error.MaxBytesExceeded, bytes.append("@batch=bytes NOTICE #c :efg", &out));
    try expectState(&bytes, 1, 4, "abcd", &out);

    const Boundary = multiline.Assembler(.{ .max_bytes = 5, .max_lines = 2 });
    var boundary = Boundary.init();
    try boundary.begin("BATCH +bound draft/multiline #c");
    try boundary.append("@batch=bound PRIVMSG #c :abc", &out);
    try boundary.append("@batch=bound;draft/multiline-concat PRIVMSG #c :de", &out);
    const msg = try boundary.finish("BATCH -bound", &out);
    try std.testing.expectEqualStrings("abcde", msg.value);
    try std.testing.expectEqual(@as(usize, 5), msg.value.len);
}

test "oversize arithmetic reports errors instead of overflowing counters" {
    const Huge = multiline.Assembler(.{
        .max_bytes = std.math.maxInt(usize),
        .max_lines = 4,
        .max_ref_len = 8,
        .max_target_len = 8,
    });
    var assembler = Huge.init();
    var out: [8]u8 = undefined;

    try assembler.begin("BATCH +huge draft/multiline #c");
    assembler.command = .privmsg;
    assembler.line_count = 1;
    assembler.byte_count = std.math.maxInt(usize) - 1;
    assembler.has_nonblank_line = true;

    try std.testing.expectError(error.MaxBytesExceeded, assembler.append("@batch=huge PRIVMSG #c :x", &out));
    try std.testing.expectEqual(@as(usize, 1), assembler.line_count);
    try std.testing.expectEqual(std.math.maxInt(usize) - 1, assembler.byte_count);
}

test "arbitrary attacker bytes return only messages or multiline errors" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0xa7b1_7473);
    const random = prng.random();
    const allocator = std.testing.allocator;

    const max_random_line = 384;
    const max_body_lines = 6;
    var storage = try allocator.alloc(u8, max_random_line * (max_body_lines + 2));
    defer allocator.free(storage);

    var body_lines: [max_body_lines][]const u8 = undefined;
    var out: [64]u8 = undefined;

    for (0..fuzz_iterations) |iteration| {
        const open_buf = storage[0..max_random_line];
        const close_buf = storage[max_random_line .. max_random_line * 2];
        const open_len = randomLength(random, iteration, open_buf.len);
        const close_len = randomLength(random, iteration ^ 0x44, close_buf.len);
        fillBiasedBytes(random, open_buf[0..open_len], iteration);
        fillBiasedBytes(random, close_buf[0..close_len], iteration ^ 0x99);

        const body_count = random.uintLessThan(usize, max_body_lines + 1);
        for (0..body_count) |index| {
            const start = max_random_line * (index + 2);
            const buf = storage[start .. start + max_random_line];
            const len = randomLength(random, iteration + index * 13, buf.len);
            fillBiasedBytes(random, buf[0..len], iteration + index);
            body_lines[index] = buf[0..len];
        }

        if (multiline.assemble(
            .{ .max_bytes = out.len, .max_lines = max_body_lines, .max_ref_len = 16, .max_target_len = 16 },
            open_buf[0..open_len],
            body_lines[0..body_count],
            close_buf[0..close_len],
            &out,
        )) |msg| {
            try std.testing.expect(msg.value.len <= out.len);
            try std.testing.expect(msg.line_count <= max_body_lines);
            try std.testing.expect(msg.target.len <= 16);
            try std.testing.expect(msg.value.len != 0);
        } else |err| {
            try expectMultilineError(err);
        }
    }
}

fn expectState(assembler: anytype, line_count: usize, byte_count: usize, expected: []const u8, out: []const u8) !void {
    try std.testing.expectEqual(line_count, assembler.line_count);
    try std.testing.expectEqual(byte_count, assembler.byte_count);
    try std.testing.expectEqualSlices(u8, expected, out[0..byte_count]);
}

fn refFor(iteration: usize, scratch: []u8) ![]const u8 {
    return try std.fmt.bufPrint(scratch[0..32], "r{x}", .{iteration});
}

fn writeOpen(out: []u8, ref: []const u8, target: []const u8) ![]const u8 {
    var cursor: usize = 0;
    cursor = try appendBytes(out, cursor, "BATCH +");
    cursor = try appendBytes(out, cursor, ref);
    cursor = try appendBytes(out, cursor, " ");
    cursor = try appendBytes(out, cursor, multiline.draft_multiline_batch);
    cursor = try appendBytes(out, cursor, " ");
    cursor = try appendBytes(out, cursor, target);
    return out[0..cursor];
}

fn writeClose(out: []u8, ref: []const u8) ![]const u8 {
    var cursor: usize = 0;
    cursor = try appendBytes(out, cursor, "BATCH -");
    cursor = try appendBytes(out, cursor, ref);
    return out[0..cursor];
}

fn writeBody(
    out: []u8,
    ref: []const u8,
    target: []const u8,
    command: multiline.PayloadCommand,
    concat: bool,
    text: []const u8,
) ![]const u8 {
    var cursor: usize = 0;
    cursor = try appendBytes(out, cursor, "@batch=");
    cursor = try appendBytes(out, cursor, ref);
    if (concat) {
        cursor = try appendBytes(out, cursor, ";");
        cursor = try appendBytes(out, cursor, multiline.draft_multiline_concat_tag);
    }
    cursor = try appendBytes(out, cursor, " ");
    cursor = try appendBytes(out, cursor, command.token());
    cursor = try appendBytes(out, cursor, " ");
    cursor = try appendBytes(out, cursor, target);
    cursor = try appendBytes(out, cursor, " :");
    cursor = try appendBytes(out, cursor, text);
    return out[0..cursor];
}

fn appendBytes(out: []u8, cursor: usize, bytes: []const u8) !usize {
    try std.testing.expect(cursor + bytes.len <= out.len);
    @memcpy(out[cursor .. cursor + bytes.len], bytes);
    return cursor + bytes.len;
}

fn randomTextLen(random: std.Random, iteration: usize, index: usize, concat: bool) usize {
    if (index == 0) return 1 + random.uintLessThan(usize, 48);
    if (concat) return 1 + random.uintLessThan(usize, 48);
    return switch ((iteration + index) % 9) {
        0 => 0,
        1 => 1,
        else => random.uintLessThan(usize, 49),
    };
}

fn randomLength(random: std.Random, iteration: usize, max_len: usize) usize {
    return switch (iteration % 18) {
        0 => 0,
        1 => 1,
        2 => max_len,
        3 => @min(max_len, 512),
        4 => @min(max_len, 513),
        else => random.uintLessThan(usize, max_len + 1),
    };
}

fn fillPayloadBytes(random: std.Random, out: []u8, salt: usize) void {
    for (out, 0..) |*byte, index| {
        byte.* = switch ((random.uintLessThan(usize, 20) + salt + index) % 20) {
            0 => ' ',
            1 => ':',
            2 => ';',
            3 => '=',
            4 => '\\',
            5 => 0x80,
            6 => 0xff,
            7...12 => 'a' + random.uintLessThan(u8, 26),
            13...17 => 'A' + random.uintLessThan(u8, 26),
            else => '0' + random.uintLessThan(u8, 10),
        };
    }
}

fn fillBiasedBytes(random: std.Random, out: []u8, salt: usize) void {
    for (out, 0..) |*byte, index| {
        byte.* = switch ((random.uintLessThan(usize, 32) + salt + index) % 32) {
            0 => ':',
            1 => '@',
            2 => ' ',
            3 => '\r',
            4 => '\n',
            5 => 0,
            6 => ';',
            7 => '=',
            8 => '+',
            9 => '-',
            10 => '#',
            11 => '\\',
            12 => 0x80,
            13 => 0xff,
            14 => random.uintLessThan(u8, 0x20),
            15...20 => 'A' + random.uintLessThan(u8, 26),
            21...26 => 'a' + random.uintLessThan(u8, 26),
            else => random.int(u8),
        };
    }
}

fn expectMultilineError(err: multiline.MultilineError) !void {
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
        error.OutputTooSmall,
        error.BatchAlreadyOpen,
        error.NoOpenBatch,
        error.InvalidBatchOpen,
        error.InvalidBatchClose,
        error.InvalidBatchReference,
        error.InvalidBatchType,
        error.InvalidTarget,
        error.MissingBatchTag,
        error.DuplicateBatchTag,
        error.BatchTagMismatch,
        error.DisallowedTag,
        error.InvalidConcatTag,
        error.ConcatWithoutPreviousLine,
        error.BlankConcatLine,
        error.DisallowedCommand,
        error.MixedCommands,
        error.MalformedMessageLine,
        error.MaxBytesExceeded,
        error.MaxLinesExceeded,
        error.EmptyBatch,
        error.BlankMessage,
        => {},
    }
}

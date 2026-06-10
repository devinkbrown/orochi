//! Deterministic property tests for IRCv3 BATCH and labeled-response framing.
const std = @import("std");
const batch = @import("batch.zig");

const seed: u64 = 0x4241_5443_4850_1600;
const reference_iterations = 4000;
const fuzz_iterations = 2600;
const structured_iterations = 900;

const ParsedOpen = struct {
    ref: []const u8,
    type: []const u8,
    params: [8][]const u8 = undefined,
    param_count: usize = 0,

    fn paramSlice(self: *const ParsedOpen) []const []const u8 {
        return self.params[0..self.param_count];
    }
};

test "generated batch refs are unique and well formed across bounded seeds" {
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();

    var out: [256]u8 = undefined;

    var iteration: usize = 0;
    while (iteration < reference_iterations) : (iteration += 1) {
        const start = if (iteration % 17 == 0)
            @as(u64, iteration)
        else
            random.int(u64) & 0x0000_ffff_ffff_fff0;

        var session = batch.DefaultSession.init(start);
        var previous: ?batch.BatchRef = null;

        var open_count: usize = 0;
        while (open_count < 8) : (open_count += 1) {
            const opened = try session.open(.labeled, &.{"prop-label"}, &out);
            try expectGeneratedRef(opened.ref);
            try expectOpenLine(opened.line, opened.ref.slice(), "labeled", &.{"prop-label"});

            if (previous) |prev| {
                try std.testing.expect(!prev.eql(&opened.ref));
            }
            previous = opened.ref;
        }

        while (session.isOpen()) {
            const active = session.activeRef().?;
            const closed = try session.close(&out);
            try expectCloseLine(closed, active.slice());
        }
    }
}

test "open close framing preserves stack nesting order" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0x4e45_5354);
    const random = prng.random();

    const Session = batch.BatchSession(.{ .max_depth = 8, .max_line_body = 512 });
    var out: [512]u8 = undefined;
    var stack: [8]batch.BatchRef = undefined;

    var iteration: usize = 0;
    while (iteration < structured_iterations) : (iteration += 1) {
        var session = Session.init(random.int(u64) & 0xffff);
        const depth = 1 + random.uintLessThan(usize, stack.len);

        var opened_count: usize = 0;
        while (opened_count < depth) : (opened_count += 1) {
            const opened = switch (opened_count % 4) {
                0 => try session.open(.netjoin, &.{ "#orochi", "mesh-a" }, &out),
                1 => try session.open(.netsplit, &.{ "mesh-a", "mesh-b" }, &out),
                2 => try session.open(.chathistory, &.{ "#orochi", "latest" }, &out),
                else => try session.open(.labeled, &.{"label-1"}, &out),
            };
            stack[opened_count] = opened.ref;
            try expectOpenPrefix(opened.line, opened.ref.slice());
            try std.testing.expectEqual(opened_count + 1, session.depth);
            try std.testing.expectEqualStrings(opened.ref.slice(), session.activeRef().?.slice());
        }

        if (depth > 1) {
            try std.testing.expectError(error.UnbalancedClose, session.closeRef(stack[0], &out));
            try std.testing.expectEqual(depth, session.depth);
        }

        var close_index = depth;
        while (close_index > 0) {
            close_index -= 1;
            const closed = try session.close(&out);
            try expectCloseLine(closed, stack[close_index].slice());
            try std.testing.expectEqual(close_index, session.depth);
        }
        try std.testing.expect(!session.isOpen());
    }
}

test "builder APIs accept or return typed errors for arbitrary attacker bytes" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0xa7b1_7a9e);
    const random = prng.random();

    const Session = batch.BatchSession(.{ .max_depth = 4, .max_line_body = 384 });
    var session = Session.init(0);
    var bytes: [768]u8 = undefined;
    var out: [512]u8 = undefined;

    var iteration: usize = 0;
    while (iteration < fuzz_iterations) : (iteration += 1) {
        const len = randomLength(random, iteration, bytes.len);
        fillBiasedBytes(random, bytes[0..len], iteration);

        const first = random.uintLessThan(usize, len + 1);
        const second = first + random.uintLessThan(usize, len - first + 1);
        const batch_type = bytes[0..first];
        const param_one = bytes[first..second];
        const param_two = bytes[second..len];

        const params = [_][]const u8{ param_one, param_two };
        if (session.openNamed(batch_type, &params, &out)) |opened| {
            try expectGeneratedRef(opened.ref);
            try expectOpenLine(opened.line, opened.ref.slice(), batch_type, &params);
            try std.testing.expect(session.depth <= 4);
        } else |err| {
            try expectBatchError(err);
        }

        if (session.wrapLine(bytes[0..len], &out)) |wrapped| {
            try expectWrappedLine(wrapped, session.activeRef().?.slice());
        } else |err| {
            try expectBatchError(err);
        }

        if (iteration % 3 == 0) {
            if (session.close(&out)) |closed| {
                try expectCloseLine(closed, closedRef(closed));
            } else |err| {
                try expectBatchError(err);
            }
        }
    }

    while (session.isOpen()) {
        _ = try session.close(&out);
    }
}

test "nested batches enforce configured depth cap" {
    const Session = batch.BatchSession(.{ .max_depth = 3 });
    var session = Session.init(10);
    var out: [128]u8 = undefined;

    const first = try session.open(.labeled, &.{"a"}, &out);
    const second = try session.open(.labeled, &.{"b"}, &out);
    const third = try session.open(.labeled, &.{"c"}, &out);

    try std.testing.expectEqual(@as(usize, 3), session.depth);
    try std.testing.expectError(error.TooManyNestedBatches, session.open(.labeled, &.{"d"}, &out));
    try std.testing.expectEqual(@as(usize, 3), session.depth);

    try expectCloseLine(try session.close(&out), third.ref.slice());
    try expectCloseLine(try session.close(&out), second.ref.slice());
    try expectCloseLine(try session.close(&out), first.ref.slice());
    try std.testing.expectError(error.UnbalancedClose, session.close(&out));
}

test "wrapped message tags stay within configured line limits" {
    const Session = batch.BatchSession(.{ .max_depth = 2, .max_line_body = 64 });
    var session = Session.init(0);
    var out: [256]u8 = undefined;

    const opened = try session.open(.labeled, &.{"label-xyz"}, &out);
    try std.testing.expect(opened.ref.len <= batch.max_reference_len);

    var body: [64]u8 = undefined;
    @memset(&body, 'A');
    body[0] = 'P';

    const wrapped = try session.wrapLine(&body, &out);
    try expectWrappedLine(wrapped, opened.ref.slice());
    try std.testing.expect(wrapped.len == "@batch=".len + opened.ref.len + 1 + body.len + "\r\n".len);

    var too_long: [65]u8 = undefined;
    @memset(&too_long, 'B');
    try std.testing.expectError(error.InvalidLine, session.wrapLine(&too_long, &out));

    const duplicate_batch = "@time=1;batch=evil PRIVMSG #orochi :x";
    try std.testing.expectError(error.DuplicateBatchTag, session.wrapLine(duplicate_batch, &out));
}

test "serialized open close and labeled wrapped lines round trip through local wire parser" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0x10ca_1abe);
    const random = prng.random();

    var out: [512]u8 = undefined;
    var body: [128]u8 = undefined;

    var iteration: usize = 0;
    while (iteration < structured_iterations) : (iteration += 1) {
        var session = batch.DefaultSession.init(random.int(u16));
        const label = if (iteration % 2 == 0) "label-a" else "label-b";
        const opened = try session.open(.labeled, &.{label}, &out);

        const parsed_open = try parseOpenLine(opened.line);
        try std.testing.expectEqualStrings(opened.ref.slice(), parsed_open.ref);
        try std.testing.expectEqualStrings("labeled", parsed_open.type);
        try std.testing.expectEqual(@as(usize, 1), parsed_open.param_count);
        try std.testing.expectEqualStrings(label, parsed_open.paramSlice()[0]);

        const body_len = 1 + random.uintLessThan(usize, body.len);
        fillCommandBytes(random, body[0..body_len]);
        const wrapped = try session.wrapLine(body[0..body_len], &out);
        const wrapped_ref = try parseBatchTag(wrapped);
        try std.testing.expectEqualStrings(opened.ref.slice(), wrapped_ref);

        const closed = try session.close(&out);
        const closed_ref = try parseCloseLine(closed);
        try std.testing.expectEqualStrings(opened.ref.slice(), closed_ref);
    }
}

fn expectGeneratedRef(ref: batch.BatchRef) !void {
    try std.testing.expect(ref.len == 18);
    try std.testing.expect(ref.len <= batch.max_reference_len);
    try std.testing.expectEqual(@as(u8, 'm'), ref.slice()[0]);
    try std.testing.expectEqual(@as(u8, 'z'), ref.slice()[1]);
    for (ref.slice()[2..]) |ch| {
        try std.testing.expect(isLowerHex(ch));
    }
}

fn expectOpenPrefix(line: []const u8, expected_ref: []const u8) !void {
    try std.testing.expect(std.mem.startsWith(u8, line, "BATCH +"));
    try std.testing.expect(std.mem.endsWith(u8, line, "\r\n"));
    const parsed = try parseOpenLine(line);
    try std.testing.expectEqualStrings(expected_ref, parsed.ref);
}

fn expectOpenLine(
    line: []const u8,
    expected_ref: []const u8,
    expected_type: []const u8,
    expected_params: []const []const u8,
) !void {
    const parsed = try parseOpenLine(line);
    try std.testing.expectEqualStrings(expected_ref, parsed.ref);
    try std.testing.expectEqualStrings(expected_type, parsed.type);
    try std.testing.expectEqual(expected_params.len, parsed.param_count);
    for (expected_params, 0..) |param, i| {
        try std.testing.expectEqualStrings(param, parsed.paramSlice()[i]);
    }
}

fn expectCloseLine(line: []const u8, expected_ref: []const u8) !void {
    const parsed_ref = try parseCloseLine(line);
    try std.testing.expectEqualStrings(expected_ref, parsed_ref);
}

fn expectWrappedLine(line: []const u8, expected_ref: []const u8) !void {
    try std.testing.expect(std.mem.startsWith(u8, line, "@batch="));
    try std.testing.expect(std.mem.endsWith(u8, line, "\r\n"));
    const parsed_ref = try parseBatchTag(line);
    try std.testing.expectEqualStrings(expected_ref, parsed_ref);
}

fn parseOpenLine(line: []const u8) !ParsedOpen {
    const body = try stripCrLf(line);
    try std.testing.expect(std.mem.startsWith(u8, body, "BATCH +"));

    var rest = body["BATCH +".len..];
    const ref_end = std.mem.indexOfScalar(u8, rest, ' ') orelse return error.InvalidTestLine;
    const ref = rest[0..ref_end];
    rest = rest[ref_end + 1 ..];

    const type_end = std.mem.indexOfScalar(u8, rest, ' ') orelse rest.len;
    var parsed = ParsedOpen{
        .ref = ref,
        .type = rest[0..type_end],
    };

    rest = if (type_end == rest.len) rest[rest.len..] else rest[type_end + 1 ..];
    while (rest.len != 0) {
        if (parsed.param_count >= parsed.params.len) return error.InvalidTestLine;
        const param_end = std.mem.indexOfScalar(u8, rest, ' ') orelse rest.len;
        parsed.params[parsed.param_count] = rest[0..param_end];
        parsed.param_count += 1;
        rest = if (param_end == rest.len) rest[rest.len..] else rest[param_end + 1 ..];
    }

    return parsed;
}

fn parseCloseLine(line: []const u8) ![]const u8 {
    const body = try stripCrLf(line);
    try std.testing.expect(std.mem.startsWith(u8, body, "BATCH -"));
    const ref = body["BATCH -".len..];
    try std.testing.expect(ref.len != 0);
    try std.testing.expect(std.mem.indexOfScalar(u8, ref, ' ') == null);
    return ref;
}

fn parseBatchTag(line: []const u8) ![]const u8 {
    const body = try stripCrLf(line);
    try std.testing.expect(std.mem.startsWith(u8, body, "@batch="));
    const tag_end = std.mem.indexOfScalar(u8, body, ' ') orelse return error.InvalidTestLine;
    const tags = body[1..tag_end];
    const value_start = "batch=".len;
    const value_end = std.mem.indexOfScalar(u8, tags[value_start..], ';') orelse tags.len - value_start;
    const ref = tags[value_start .. value_start + value_end];
    try std.testing.expect(ref.len != 0);
    return ref;
}

fn stripCrLf(line: []const u8) ![]const u8 {
    try std.testing.expect(line.len >= 2);
    try std.testing.expect(line[line.len - 2] == '\r');
    try std.testing.expect(line[line.len - 1] == '\n');
    return line[0 .. line.len - 2];
}

fn closedRef(line: []const u8) []const u8 {
    return line["BATCH -".len .. line.len - "\r\n".len];
}

fn expectBatchError(err: batch.BatchError) !void {
    switch (err) {
        error.OutputTooSmall,
        error.TooManyNestedBatches,
        error.CounterExhausted,
        error.InvalidReference,
        error.InvalidBatchType,
        error.InvalidParameter,
        error.InvalidLine,
        error.DuplicateBatchTag,
        error.UnbalancedClose,
        error.NoOpenBatch,
        => {},
    }
}

fn randomLength(random: std.Random, iteration: usize, max_len: usize) usize {
    return switch (iteration % 19) {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => @min(18, max_len),
        4 => @min(64, max_len),
        5 => @min(384, max_len),
        6 => max_len,
        else => random.uintLessThan(usize, max_len + 1),
    };
}

fn fillBiasedBytes(random: std.Random, out: []u8, iteration: usize) void {
    for (out, 0..) |*byte, i| {
        byte.* = switch (random.uintLessThan(u8, 28)) {
            0 => 0,
            1 => '\r',
            2 => '\n',
            3 => ' ',
            4 => '@',
            5 => ';',
            6 => '=',
            7 => '+',
            8 => '-',
            9 => ':',
            10 => '#',
            11 => '_',
            12 => '/',
            13 => '.',
            14 => 0xff,
            15 => 0x80,
            16...19 => 'a' + random.uintLessThan(u8, 26),
            20...23 => 'A' + random.uintLessThan(u8, 26),
            24...25 => '0' + random.uintLessThan(u8, 10),
            else => random.int(u8),
        };

        if (out.len > 0 and i == (iteration % out.len)) {
            byte.* = switch (iteration % 6) {
                0 => '@',
                1 => ' ',
                2 => '\r',
                3 => '\n',
                4 => 0,
                else => ';',
            };
        }
    }
}

fn fillCommandBytes(random: std.Random, out: []u8) void {
    if (out.len == 0) return;
    const prefix = "PRIVMSG #orochi :";
    const copy_len = @min(prefix.len, out.len);
    @memcpy(out[0..copy_len], prefix[0..copy_len]);
    for (out[copy_len..]) |*byte| {
        byte.* = switch (random.uintLessThan(u8, 8)) {
            0 => 'a' + random.uintLessThan(u8, 26),
            1 => '0' + random.uintLessThan(u8, 10),
            2 => ' ',
            3 => ':',
            else => 'A' + random.uintLessThan(u8, 26),
        };
    }
}

fn isLowerHex(ch: u8) bool {
    return switch (ch) {
        '0'...'9', 'a'...'f' => true,
        else => false,
    };
}

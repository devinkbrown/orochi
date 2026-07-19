// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deterministic property tests for IRCv3 outbound message-tag composition.
const std = @import("std");
const msgtags = @import("msgtags.zig");

const max_line_body: usize = 8191;
const fuzz_iterations: usize = 4000;
const escape_iterations: usize = 3000;
const generated_iterations: usize = 1200;

const Caps = @typeInfo(@TypeOf(msgtags.composeOutbound)).@"fn".param_types[1].?;

test "composeOutbound returns only slices or typed errors for bounded random tags" {
    var prng = std.Random.DefaultPrng.init(0x4d53_4754_4147_1600);
    const random = prng.random();

    var out: [max_line_body]u8 = undefined;
    var account_buf: [512]u8 = undefined;
    var draft_buf: [384]u8 = undefined;
    var label_buf: [384]u8 = undefined;
    var batch_buf: [384]u8 = undefined;
    var line_buf: [256]u8 = undefined;

    for (0..fuzz_iterations) |iteration| {
        const account = randomTagValue(random, &account_buf, iteration);
        const draft = randomTagValue(random, &draft_buf, iteration ^ 0x31);
        const label = randomTagValue(random, &label_buf, iteration ^ 0x57);
        const batch = randomTagValue(random, &batch_buf, iteration ^ 0xa9);
        const line = randomLine(random, &line_buf, iteration);

        const tags = msgtags.OutboundTags{
            .server_time_millis = randomServerTime(random, iteration),
            .account = maybeSlice(random, account),
            .msgid = if (random.boolean()) .{
                .counter = random.int(u64),
                .rng = random.int(u64),
            } else null,
            .draft_label = maybeSlice(random, draft),
            .label = maybeSlice(random, label),
            .batch = maybeSlice(random, batch),
            .bot = random.boolean(),
        };

        if (msgtags.composeOutbound(msgtags.default_config, randomCaps(random), tags, line, &out)) |rendered| {
            try std.testing.expect(rendered.ptr == &out);
            try std.testing.expect(rendered.len <= max_line_body);
            try std.testing.expect(std.mem.endsWith(u8, rendered, line));
            try expectNoLineUnsafeBytes(rendered);
            if (rendered.len != line.len) {
                try expectBoundedTagSection(rendered);
            }
        } else |err| {
            try expectComposeError(err);
        }
    }
}

test "escaped tag values match reference escaping and round trip through unescape" {
    var prng = std.Random.DefaultPrng.init(0x4553_4341_5045_1600);
    const random = prng.random();

    var raw_buf: [768]u8 = undefined;
    var escaped_buf: [raw_buf.len * 2]u8 = undefined;
    var unescaped_buf: [raw_buf.len]u8 = undefined;
    var out: [2048]u8 = undefined;

    for (0..escape_iterations) |iteration| {
        const raw = randomEscapableValue(random, &raw_buf, iteration);
        const escaped = try referenceEscape(raw, &escaped_buf);

        const rendered = try msgtags.composeOutbound(
            msgtags.default_config,
            capsWithAll(),
            .{ .account = raw },
            "PRIVMSG #onyx :hello",
            &out,
        );
        const emitted = try singleTagValue(rendered, "@account=");
        try std.testing.expectEqualStrings(escaped, emitted);

        const unescaped = try referenceUnescape(emitted, &unescaped_buf);
        try std.testing.expectEqualSlices(u8, raw, unescaped);
        try expectNoLineUnsafeBytes(rendered);
    }
}

test "all escaped outbound tag value fields use IRCv3 escapes" {
    var out: [512]u8 = undefined;
    const raw = "\\; \r\n";
    const rendered = try msgtags.composeOutbound(
        msgtags.default_config,
        capsWithAll(),
        .{
            .account = raw,
            .draft_label = raw,
            .label = raw,
            .batch = raw,
        },
        "NOTICE nick :ok",
        &out,
    );

    try std.testing.expectEqualStrings(
        "@account=\\\\\\:\\s\\r\\n;+draft/label=\\\\\\:\\s\\r\\n;label=\\\\\\:\\s\\r\\n;batch=\\\\\\:\\s\\r\\n NOTICE nick :ok",
        rendered,
    );
    try expectNoLineUnsafeBytes(rendered);
}

test "server-time and msgid emissions are fixed width and line safe" {
    var prng = std.Random.DefaultPrng.init(0x5449_4d45_4944_1600);
    const random = prng.random();

    var out: [256]u8 = undefined;
    var msgid_buf: [msgtags.MSGID_LEN]u8 = undefined;

    for (0..generated_iterations) |iteration| {
        const millis = @as(i64, @intCast(random.uintLessThan(u64, 253_402_300_800_000)));
        const source = msgtags.MsgIdSource{
            .counter = random.int(u64) ^ @as(u64, @intCast(iteration)),
            .rng = random.int(u64),
        };

        const msgid = try msgtags.writeMsgId(source, &msgid_buf);
        try std.testing.expectEqual(@as(usize, msgtags.MSGID_LEN), msgid.len);
        try expectBase62(msgid);

        const rendered = try msgtags.composeOutbound(
            msgtags.default_config,
            capsWithAll(),
            .{
                .server_time_millis = millis,
                .msgid = source,
            },
            "PING :token",
            &out,
        );

        try std.testing.expect(std.mem.startsWith(u8, rendered, "@time="));
        try std.testing.expect(std.mem.indexOf(u8, rendered, ";msgid=") != null);
        try expectNoLineUnsafeBytes(rendered);
    }
}

test "tag section respects caller enforced 8191 byte line limit" {
    var exact_value: [8180]u8 = undefined;
    var too_large_value: [8181]u8 = undefined;
    @memset(&exact_value, 'a');
    @memset(&too_large_value, 'b');

    var out: [max_line_body]u8 = undefined;
    const exact = try msgtags.composeOutbound(
        msgtags.default_config,
        capsWithAll(),
        .{ .account = &exact_value },
        "P",
        &out,
    );
    try std.testing.expectEqual(@as(usize, max_line_body), exact.len);
    try expectBoundedTagSection(exact);
    try expectNoLineUnsafeBytes(exact);

    try std.testing.expectError(
        error.OutputTooSmall,
        msgtags.composeOutbound(msgtags.default_config, capsWithAll(), .{ .account = &too_large_value }, "P", &out),
    );
}

test "small output slices report OutputTooSmall and do not write past the slice" {
    var backing: [34]u8 = undefined;
    @memset(&backing, 0xa5);
    const exposed = backing[1..9];

    try std.testing.expectError(
        error.OutputTooSmall,
        msgtags.composeOutbound(
            msgtags.default_config,
            capsWithAll(),
            .{ .account = "value that cannot fit" },
            "PING :x",
            exposed,
        ),
    );
    try std.testing.expectEqual(@as(u8, 0xa5), backing[0]);
    try std.testing.expectEqual(@as(u8, 0xa5), backing[9]);
}

test "NUL tag values are rejected and never leak into successful output" {
    var out: [128]u8 = undefined;
    try std.testing.expectError(
        error.InvalidTagValue,
        msgtags.composeOutbound(msgtags.default_config, capsWithAll(), .{ .account = "bad\x00acct" }, "PING :x", &out),
    );

    const rendered = try msgtags.composeOutbound(
        msgtags.default_config,
        capsWithAll(),
        .{ .account = "line\rfeed\nspace semi; slash\\" },
        "PING :x",
        &out,
    );
    try expectNoLineUnsafeBytes(rendered);
}

fn capsWithAll() Caps {
    var set = Caps.empty();
    set.add(.server_time);
    set.add(.account_tag);
    set.add(.msgid);
    set.add(.labeled_response);
    set.add(.batch);
    set.add(.bot);
    return set;
}

fn randomCaps(random: std.Random) Caps {
    var set = Caps.empty();
    if (random.boolean()) set.add(.server_time);
    if (random.boolean()) set.add(.account_tag);
    if (random.boolean()) set.add(.msgid);
    if (random.boolean()) set.add(.labeled_response);
    if (random.boolean()) set.add(.batch);
    if (random.boolean()) set.add(.bot);
    return set;
}

fn maybeSlice(random: std.Random, value: []const u8) ?[]const u8 {
    return if (random.boolean()) value else null;
}

fn randomServerTime(random: std.Random, iteration: usize) ?i64 {
    if (!random.boolean()) return null;
    return switch (iteration % 19) {
        0 => -1,
        1 => 253_402_300_800_000,
        else => @as(i64, @intCast(random.uintLessThan(u64, 253_402_300_800_000))),
    };
}

fn randomLine(random: std.Random, out: []u8, iteration: usize) []const u8 {
    const prefix = "PRIVMSG #onyx :";
    @memcpy(out[0..prefix.len], prefix);
    const body_len = switch (iteration % 11) {
        0 => 1,
        1 => out.len - prefix.len,
        else => 1 + random.uintLessThan(usize, out.len - prefix.len),
    };
    fillSafeLineBytes(random, out[prefix.len .. prefix.len + body_len]);
    return out[0 .. prefix.len + body_len];
}

fn fillSafeLineBytes(random: std.Random, out: []u8) void {
    for (out) |*byte| {
        byte.* = switch (random.uintLessThan(u8, 12)) {
            0 => ';',
            1 => '=',
            2 => '\\',
            3 => ':',
            4 => '#',
            5 => ' ',
            6...8 => 'a' + random.uintLessThan(u8, 26),
            9...10 => '0' + random.uintLessThan(u8, 10),
            else => 'A' + random.uintLessThan(u8, 26),
        };
    }
}

fn randomTagValue(random: std.Random, out: []u8, iteration: usize) []const u8 {
    const len = switch (iteration % 13) {
        0 => 0,
        1 => out.len,
        else => random.uintLessThan(usize, out.len + 1),
    };
    fillTagValueBytes(random, out[0..len], true);
    return out[0..len];
}

fn randomEscapableValue(random: std.Random, out: []u8, iteration: usize) []const u8 {
    const len = switch (iteration % 17) {
        0 => 0,
        1 => out.len,
        else => random.uintLessThan(usize, out.len + 1),
    };
    fillTagValueBytes(random, out[0..len], false);
    return out[0..len];
}

fn fillTagValueBytes(random: std.Random, out: []u8, allow_nul: bool) void {
    for (out) |*byte| {
        byte.* = switch (random.uintLessThan(u8, 18)) {
            0 => '\\',
            1 => ';',
            2 => ' ',
            3 => '\r',
            4 => '\n',
            5 => if (allow_nul) 0 else ':',
            6 => ':',
            7...10 => 'a' + random.uintLessThan(u8, 26),
            11...13 => 'A' + random.uintLessThan(u8, 26),
            14...16 => '0' + random.uintLessThan(u8, 10),
            else => '_',
        };
    }
}

fn singleTagValue(rendered: []const u8, comptime prefix: []const u8) ![]const u8 {
    try std.testing.expect(std.mem.startsWith(u8, rendered, prefix));
    const end = std.mem.indexOfScalar(u8, rendered, ' ') orelse return error.MissingTagTerminator;
    return rendered[prefix.len..end];
}

fn referenceEscape(value: []const u8, out: []u8) ![]const u8 {
    var len: usize = 0;
    for (value) |ch| {
        const escaped = switch (ch) {
            0 => return error.InvalidTagValue,
            ';' => "\\:",
            ' ' => "\\s",
            '\r' => "\\r",
            '\n' => "\\n",
            '\\' => "\\\\",
            else => null,
        };
        if (escaped) |bytes| {
            if (out.len - len < bytes.len) return error.OutputTooSmall;
            @memcpy(out[len .. len + bytes.len], bytes);
            len += bytes.len;
        } else {
            if (len == out.len) return error.OutputTooSmall;
            out[len] = ch;
            len += 1;
        }
    }
    return out[0..len];
}

fn referenceUnescape(value: []const u8, out: []u8) ![]const u8 {
    var len: usize = 0;
    var index: usize = 0;
    while (index < value.len) : (index += 1) {
        var ch = value[index];
        if (ch == '\\' and index + 1 < value.len) {
            index += 1;
            ch = switch (value[index]) {
                ':' => ';',
                's' => ' ',
                'r' => '\r',
                'n' => '\n',
                '\\' => '\\',
                else => value[index],
            };
        }
        if (len == out.len) return error.OutputTooSmall;
        out[len] = ch;
        len += 1;
    }
    return out[0..len];
}

fn expectNoLineUnsafeBytes(rendered: []const u8) !void {
    for (rendered) |ch| {
        switch (ch) {
            0, '\r', '\n' => return error.UnsafeByteLeaked,
            else => {},
        }
    }
}

fn expectBoundedTagSection(rendered: []const u8) !void {
    try std.testing.expect(rendered.len != 0);
    try std.testing.expectEqual(@as(u8, '@'), rendered[0]);
    const end = std.mem.indexOfScalar(u8, rendered, ' ') orelse return error.MissingTagTerminator;
    try std.testing.expect(end <= max_line_body);
}

fn expectBase62(value: []const u8) !void {
    for (value) |ch| {
        const ok = (ch >= '0' and ch <= '9') or
            (ch >= 'A' and ch <= 'Z') or
            (ch >= 'a' and ch <= 'z');
        try std.testing.expect(ok);
    }
}

fn expectComposeError(err: msgtags.ComposeError) !void {
    switch (err) {
        error.OutputTooSmall,
        error.InvalidLine,
        error.InvalidTime,
        error.InvalidTagValue,
        => {},
    }
}

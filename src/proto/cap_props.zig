// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deterministic property and fuzz-style tests for IRCv3 CAP negotiation.
//!
//! The tests exercise `cap.zig` through its public API only. Inputs are bounded,
//! fixed-seed attacker byte slices so parser failures must remain typed errors
//! or structured NAK replies, never panics or partial negotiation changes.
const std = @import("std");
const cap = @import("cap.zig");

const seed: u64 = 0x4341_5050_524f_5053;
const parse_iterations: usize = 2600;
const req_iterations: usize = 1800;
const bit_iterations: usize = 1200;

test "CAP command parsing is total over bounded attacker bytes" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0x1001);
    const random = prng.random();

    var subcommand_buf: [48]u8 = undefined;
    var param_bufs: [3][160]u8 = undefined;
    var params: [3][]const u8 = undefined;
    var reply_slots: [64]cap.CapReply = undefined;
    var storage: [4096]u8 = undefined;

    for (0..parse_iterations) |iteration| {
        const subcommand = attackerSlice(random, &subcommand_buf, iteration);
        const param_count = random.uintLessThan(usize, params.len + 1);
        for (params[0..param_count], 0..) |*param, index| {
            param.* = attackerSlice(random, &param_bufs[index], iteration *% 17 + index);
        }

        var session = randomSession(random);
        const before = session.negotiated;
        var sink = cap.CapReplySink{ .replies = &reply_slots, .storage = &storage };

        session.handle(cap.CapRegistry.default(), subcommand, params[0..param_count], &sink) catch |err| {
            try expectCapError(err);
            try expectSessionWellFormed(session);
            continue;
        };

        try expectSessionWellFormed(session);
        try expectRepliesWellFormed(&sink);
        if (std.ascii.eqlIgnoreCase(subcommand, "REQ") and param_count != 0 and sink.count == 1 and sink.replies[0].kind == .nak) {
            try std.testing.expectEqual(before.bits, session.negotiated.bits);
        }
    }
}

test "REQ arbitrary capability lists ACK valid sets or NAK atomically" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0x2002);
    const random = prng.random();

    var raw_buf: [256]u8 = undefined;
    var reply_slots: [4]cap.CapReply = undefined;
    var storage: [512]u8 = undefined;

    for (0..req_iterations) |iteration| {
        const raw = attackerSlice(random, &raw_buf, iteration);
        var session = randomSession(random);
        const before = session.negotiated;
        var sink = cap.CapReplySink{ .replies = &reply_slots, .storage = &storage };

        try session.handleReq(cap.CapRegistry.default(), raw, &sink);

        const replies = sink.slice();
        try std.testing.expectEqual(@as(usize, 1), replies.len);
        switch (replies[0].kind) {
            .ack => {
                try std.testing.expectEqualStrings(raw, replies[0].body);
                try expectSetMatchesRequest(before, raw, session.negotiated);
            },
            .nak => {
                try std.testing.expectEqualStrings(raw, replies[0].body);
                try std.testing.expectEqual(before.bits, session.negotiated.bits);
            },
            else => return error.UnexpectedReplyKind,
        }
    }
}

test "REQ with any unknown cap NAKs without partial add or remove" {
    var reply_slots: [4]cap.CapReply = undefined;
    var storage: [256]u8 = undefined;
    var sink = cap.CapReplySink{ .replies = &reply_slots, .storage = &storage };
    var session = cap.CapSession{};
    session.negotiated.add(.server_time);
    session.negotiated.add(.echo_message);
    const before = session.negotiated;

    try session.handleReq(cap.CapRegistry.default(), "message-tags -server-time unknown-cap sasl", &sink);

    const replies = sink.slice();
    try std.testing.expectEqual(@as(usize, 1), replies.len);
    try std.testing.expectEqual(cap.CapReplyKind.nak, replies[0].kind);
    try std.testing.expectEqualStrings("message-tags -server-time unknown-cap sasl", replies[0].body);
    try std.testing.expectEqual(before.bits, session.negotiated.bits);
    try std.testing.expect(session.negotiated.contains(.server_time));
    try std.testing.expect(session.negotiated.contains(.echo_message));
    try std.testing.expect(!session.negotiated.contains(.message_tags));
    try std.testing.expect(!session.negotiated.contains(.sasl));
}

test "CAP 301 LS omits values while CAP 302 includes and stays enabled" {
    var reply_slots: [8]cap.CapReply = undefined;
    var storage: [2048]u8 = undefined;
    var sink = cap.CapReplySink{ .replies = &reply_slots, .storage = &storage };
    var session = cap.CapSession{};

    try session.handle(cap.CapRegistry.default(), "LS", &.{}, &sink);
    var body = try singleReplyBody(&sink, .ls);
    try std.testing.expect(std.mem.indexOfScalar(u8, body, '=') == null);
    try std.testing.expect(std.mem.indexOf(u8, body, "sts=duration=604800") == null);
    try std.testing.expect(std.mem.indexOf(u8, body, "sasl=PLAIN,EXTERNAL") == null);
    try std.testing.expect(!session.cap_302);

    sink = cap.CapReplySink{ .replies = &reply_slots, .storage = &storage };
    try session.handle(cap.CapRegistry.default(), "LS", &.{"302"}, &sink);
    body = try singleReplyBody(&sink, .ls);
    try std.testing.expect(std.mem.indexOf(u8, body, "sts=duration=604800") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "sasl=PLAIN,EXTERNAL") != null);
    try std.testing.expect(session.cap_302);

    sink = cap.CapReplySink{ .replies = &reply_slots, .storage = &storage };
    try session.handle(cap.CapRegistry.default(), "LS", &.{}, &sink);
    body = try singleReplyBody(&sink, .ls);
    try std.testing.expect(std.mem.indexOf(u8, body, "sts=duration=604800") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "sasl=PLAIN,EXTERNAL") != null);
    try std.testing.expect(session.cap_302);
}

test "CAP LS serialization respects caller body limits and continuation flags" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0x3003);
    const random = prng.random();

    var reply_slots: [64]cap.CapReply = undefined;
    var storage: [4096]u8 = undefined;

    for (0..256) |iteration| {
        const max_body = 16 + random.uintLessThan(usize, 96);
        var sink = cap.CapReplySink{ .replies = &reply_slots, .storage = &storage };
        var session = cap.CapSession{};

        session.handleLs(cap.CapRegistry.default(), iteration % 2 == 0, max_body, &sink) catch |err| {
            try std.testing.expectEqual(error.OutputTooSmall, err);
            continue;
        };

        const replies = sink.slice();
        try std.testing.expect(replies.len != 0);
        for (replies, 0..) |reply, index| {
            try std.testing.expectEqual(cap.CapReplyKind.ls, reply.kind);
            try std.testing.expect(reply.body.len <= max_body);
            try expectNoEmptyTokens(reply.body);
            try expectKnownLsTokens(reply.body, session.cap_302);
            try std.testing.expectEqual(index + 1 != replies.len, reply.continuation);
        }
    }
}

test "CAP reply sinks fail with typed capacity errors" {
    var storage: [cap.MAX_CAP_REPLY_BODY]u8 = undefined;
    var no_replies: [0]cap.CapReply = .{};
    var no_reply_sink = cap.CapReplySink{ .replies = &no_replies, .storage = &storage };
    var session = cap.CapSession{};
    try std.testing.expectError(error.TooManyReplies, session.handleLs(cap.CapRegistry.default(), true, cap.MAX_CAP_REPLY_BODY, &no_reply_sink));

    var one_reply: [1]cap.CapReply = undefined;
    var tiny_storage: [8]u8 = undefined;
    var tiny_sink = cap.CapReplySink{ .replies = &one_reply, .storage = &tiny_storage };
    try std.testing.expectError(error.OutputTooSmall, session.handleLs(cap.CapRegistry.default(), false, cap.MAX_CAP_REPLY_BODY, &tiny_sink));

    var enough_storage: [1024]u8 = undefined;
    var small_sink = cap.CapReplySink{ .replies = &one_reply, .storage = &enough_storage };
    try std.testing.expectError(error.TooManyReplies, session.handleLs(cap.CapRegistry.default(), true, 40, &small_sink));
}

test "CAP LIST serialization mirrors the negotiated set" {
    var reply_slots: [4]cap.CapReply = undefined;
    var storage: [cap.MAX_CAP_REPLY_BODY]u8 = undefined;
    var sink = cap.CapReplySink{ .replies = &reply_slots, .storage = &storage };
    var session = cap.CapSession{};
    const registry = cap.CapRegistry.default();

    try session.handleReq(registry, "server-time message-tags sasl -message-tags echo-message", &sink);
    sink = cap.CapReplySink{ .replies = &reply_slots, .storage = &storage };

    try session.handleList(registry, &sink);

    const body = try singleReplyBody(&sink, .list);
    try std.testing.expect(std.mem.indexOf(u8, body, "server-time") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "sasl") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "echo-message") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "message-tags") == null);
    try expectListedSetMatches(registry, session.negotiated, body);
}

test "CapSet bit operations are consistent for all capability ids" {
    const field_names = @typeInfo(cap.CapId).@"enum".field_names;
    try std.testing.expectEqual(field_names.len, cap.CAP_COUNT);

    var set = cap.CapSet.empty();
    try std.testing.expect(set.isEmpty());

    inline for (field_names) |field_name| {
        const id: cap.CapId = @field(cap.CapId, field_name);
        try std.testing.expect(!set.contains(id));
        set.add(id);
        try std.testing.expect(set.contains(id));
        try std.testing.expect(cap.CapSet.one(id).contains(id));
        try std.testing.expect(set.containsAll(cap.CapSet.one(id)));
        set.remove(id);
        try std.testing.expect(!set.contains(id));
    }

    var prng = std.Random.DefaultPrng.init(seed ^ 0x4004);
    const random = prng.random();
    for (0..bit_iterations) |_| {
        const left = randomCapSet(random);
        const right = randomCapSet(random);

        var unioned = left;
        unioned.unionWith(right);
        try std.testing.expectEqual(left.bits | right.bits, unioned.bits);
        try std.testing.expect(unioned.containsAll(left));
        try std.testing.expect(unioned.containsAll(right));

        var subtracted = unioned;
        subtracted.subtract(right);
        try std.testing.expectEqual(unioned.bits & ~right.bits, subtracted.bits);
        try std.testing.expect(subtracted.containsAll(left) == ((left.bits & right.bits) == 0));
    }
}

fn attackerSlice(random: std.Random, buf: []u8, iteration: usize) []const u8 {
    const len = switch (iteration % 11) {
        0 => 0,
        1 => @min(buf.len, 1),
        2 => @min(buf.len, 2),
        3 => @min(buf.len, 3),
        4 => @min(buf.len, 7),
        5 => @min(buf.len, 31),
        6 => @min(buf.len, 79),
        7 => buf.len,
        else => random.intRangeAtMost(usize, 0, buf.len),
    };
    random.bytes(buf[0..len]);
    sprinkleCapDelimiters(buf[0..len], iteration);
    return buf[0..len];
}

fn sprinkleCapDelimiters(buf: []u8, iteration: usize) void {
    if (buf.len == 0) return;
    buf[iteration % buf.len] = switch (iteration % 16) {
        0 => 0,
        1 => ' ',
        2 => '-',
        3 => '=',
        4 => '/',
        5 => '*',
        6 => '\r',
        7 => '\n',
        8 => 0xff,
        else => buf[iteration % buf.len],
    };
    if (buf.len > 2 and iteration % 5 == 0) buf[(iteration + 1) % buf.len] = ' ';
    if (buf.len > 4 and iteration % 7 == 0) buf[(iteration + 3) % buf.len] = '-';
    if (buf.len > 6 and iteration % 11 == 0) buf[(iteration + 5) % buf.len] = 0;
}

fn randomSession(random: std.Random) cap.CapSession {
    return .{
        .state = switch (random.uintLessThan(u8, 3)) {
            0 => .idle,
            1 => .negotiating,
            else => .complete,
        },
        .negotiated = randomCapSet(random),
        .cap_302 = random.boolean(),
    };
}

fn randomCapSet(random: std.Random) cap.CapSet {
    const allowed = cap.CapRegistry.default().advertisedSet().bits;
    return .{ .bits = random.int(u64) & allowed };
}

fn expectCapError(err: cap.CapError) !void {
    switch (err) {
        error.InvalidCommand,
        error.MissingParameter,
        error.OutputTooSmall,
        error.TooManyReplies,
        => {},
    }
}

fn expectSessionWellFormed(session: cap.CapSession) !void {
    const advertised = cap.CapRegistry.default().advertisedSet();
    try std.testing.expect(advertised.containsAll(session.negotiated));
}

fn expectRepliesWellFormed(sink: *const cap.CapReplySink) !void {
    try std.testing.expect(sink.count <= sink.replies.len);
    try std.testing.expect(sink.used <= sink.storage.len);
    for (sink.slice()) |reply| {
        switch (reply.kind) {
            .ls, .list, .ack, .nak => {},
        }
        try std.testing.expect(reply.body.len <= cap.MAX_CAP_REPLY_BODY);
        try expectSliceWithin(sink.storage, reply.body);
    }
}

fn expectSliceWithin(backing: []const u8, slice: []const u8) !void {
    const base = @intFromPtr(backing.ptr);
    const end = base + backing.len;
    const ptr = @intFromPtr(slice.ptr);
    try std.testing.expect(ptr >= base);
    try std.testing.expect(ptr <= end);
    try std.testing.expect(slice.len <= end - ptr);
}

fn expectSetMatchesRequest(before: cap.CapSet, raw: []const u8, after: cap.CapSet) !void {
    var expected = before;
    var cursor: usize = 0;
    var saw_token = false;
    while (cursor < raw.len) {
        while (cursor < raw.len and raw[cursor] == ' ') cursor += 1;
        if (cursor >= raw.len) break;

        const token_start = cursor;
        while (cursor < raw.len and raw[cursor] != ' ') cursor += 1;

        var token = raw[token_start..cursor];
        const remove = token.len > 0 and token[0] == '-';
        if (remove) token = token[1..];
        const spec = cap.CapRegistry.default().find(token) orelse return error.ExpectedValidRequest;
        try std.testing.expect(spec.kind == .client and spec.advertised);
        if (remove) {
            expected.remove(spec.id);
        } else {
            expected.add(spec.id);
        }
        saw_token = true;
    }
    try std.testing.expect(saw_token);
    try std.testing.expectEqual(expected.bits, after.bits);
}

fn singleReplyBody(sink: *const cap.CapReplySink, kind: cap.CapReplyKind) ![]const u8 {
    const replies = sink.slice();
    try std.testing.expectEqual(@as(usize, 1), replies.len);
    try std.testing.expectEqual(kind, replies[0].kind);
    try std.testing.expect(!replies[0].continuation);
    return replies[0].body;
}

fn expectNoEmptyTokens(body: []const u8) !void {
    var saw_token = false;
    var cursor: usize = 0;
    while (cursor < body.len) {
        if (body[cursor] == ' ') return error.EmptyCapabilityToken;
        const start = cursor;
        while (cursor < body.len and body[cursor] != ' ') cursor += 1;
        try std.testing.expect(cursor > start);
        saw_token = true;
        if (cursor < body.len) cursor += 1;
    }
    try std.testing.expect(saw_token or body.len == 0);
}

fn expectKnownLsTokens(body: []const u8, cap_302: bool) !void {
    var cursor: usize = 0;
    while (cursor < body.len) {
        const start = cursor;
        while (cursor < body.len and body[cursor] != ' ') cursor += 1;
        const token = body[start..cursor];
        const eq = std.mem.indexOfScalar(u8, token, '=');
        const name = if (eq) |index| token[0..index] else token;
        const spec = cap.CapRegistry.default().find(name) orelse return error.UnknownSerializedCapability;
        try std.testing.expect(spec.kind == .client);
        try std.testing.expect(spec.advertised);
        if (eq) |index| {
            try std.testing.expect(cap_302);
            try std.testing.expect(spec.value_302 != null);
            try std.testing.expectEqualStrings(spec.value_302.?, token[index + 1 ..]);
        }
        if (cursor < body.len) cursor += 1;
    }
}

fn expectListedSetMatches(registry: cap.CapRegistry, negotiated: cap.CapSet, body: []const u8) !void {
    var seen = cap.CapSet.empty();
    var cursor: usize = 0;
    while (cursor < body.len) {
        const start = cursor;
        while (cursor < body.len and body[cursor] != ' ') cursor += 1;
        const token = body[start..cursor];
        const spec = registry.find(token) orelse return error.UnknownListedCapability;
        seen.add(spec.id);
        if (cursor < body.len) cursor += 1;
    }
    try std.testing.expectEqual(negotiated.bits, seen.bits);
}

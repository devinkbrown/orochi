//! Deterministic property and fuzz-style tests for AWAY state and away-notify.
const std = @import("std");
const away = @import("away.zig");

const seed: u64 = 0x4d495a5543484157;

const transition_iterations: usize = 1500;
const validation_iterations: usize = 1200;
const notify_iterations: usize = 900;
const bounds_iterations: usize = 512;
const arbitrary_iterations: usize = 1700;

test "setting and clearing away state matches a bounded reference model" {
    const max_clients = 16;
    const max_message = 64;

    var store = away.AwayStore(max_clients, max_message).init();
    var model_away = [_]bool{false} ** max_clients;
    var model_messages: [max_clients][max_message]u8 = undefined;
    var model_lens = [_]usize{0} ** max_clients;

    var prng = std.Random.DefaultPrng.init(seed ^ 0x1001);
    const random = prng.random();

    var replies_buf: [4]away.AwayReply = undefined;
    var reply_storage: [256]u8 = undefined;
    var notifications_buf: [12]away.AwayNotify = undefined;
    var notification_storage: [2048]u8 = undefined;
    var nick_buf: [away.MAX_NICK_BYTES]u8 = undefined;
    var message_buf: [max_message]u8 = undefined;

    for (0..transition_iterations) |iteration| {
        var replies = away.AwayReplySink{ .replies = &replies_buf, .storage = &reply_storage };
        var notifications = away.AwayNotifySink{ .notifications = &notifications_buf, .storage = &notification_storage };
        const client_index = random.uintLessThan(usize, max_clients);
        const client: away.ClientId = @intCast(client_index + 1);
        const nick = validNick(random, &nick_buf, iteration);

        if (random.boolean()) {
            const message = validMessage(random, &message_buf, iteration);
            try store.set(client, nick, message, &.{}, &replies, &notifications);
            model_away[client_index] = true;
            model_lens[client_index] = message.len;
            @memcpy(model_messages[client_index][0..message.len], message);

            try expectSingleReply(replies.slice(), .RPL_NOWAWAY, client);
            try std.testing.expectEqual(@as(usize, 0), notifications.slice().len);
        } else {
            try store.clear(client, nick, &.{}, &replies, &notifications);
            model_away[client_index] = false;
            model_lens[client_index] = 0;

            try expectSingleReply(replies.slice(), .RPL_UNAWAY, client);
            try std.testing.expectEqual(@as(usize, 0), notifications.slice().len);
        }

        for (0..max_clients) |index| {
            const observed_client: away.ClientId = @intCast(index + 1);
            try std.testing.expectEqual(model_away[index], store.isAway(observed_client));
            if (model_away[index]) {
                try std.testing.expectEqualStrings(
                    model_messages[index][0..model_lens[index]],
                    store.message(observed_client).?,
                );
            } else {
                try std.testing.expectEqual(@as(?[]const u8, null), store.message(observed_client));
            }
        }
    }
}

test "away message validation rejects line breaks nul empty and over-length messages" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0x2002);
    const random = prng.random();
    var message_buf: [96]u8 = undefined;

    for (0..validation_iterations) |iteration| {
        const len = biasedLength(random, iteration, message_buf.len);
        fillMessageCandidate(random, message_buf[0..len], iteration);

        const result = away.validateMessage(message_buf[0..len], 32);
        if (len == 0) {
            try std.testing.expectError(error.InvalidMessage, result);
        } else if (len > 32) {
            try std.testing.expectError(error.MessageTooLong, result);
        } else if (hasRejectedMessageByte(message_buf[0..len])) {
            try std.testing.expectError(error.InvalidMessage, result);
        } else {
            try result;
        }
    }

    try std.testing.expectError(error.InvalidMessage, away.validateMessage("bad\rmsg", 32));
    try std.testing.expectError(error.InvalidMessage, away.validateMessage("bad\nmsg", 32));
    try std.testing.expectError(error.InvalidMessage, away.validateMessage("bad\x00msg", 32));
    try std.testing.expectError(error.MessageTooLong, away.validateMessage("123456", 5));
}

test "away-notify recipient selection is exactly capability gated" {
    const watcher_count = 20;

    var prng = std.Random.DefaultPrng.init(seed ^ 0x3003);
    const random = prng.random();
    var watchers: [watcher_count]away.Watcher = undefined;
    var expected_clients: [watcher_count]away.ClientId = undefined;
    var nick_buf: [away.MAX_NICK_BYTES]u8 = undefined;
    var message_buf: [64]u8 = undefined;
    var replies_buf: [4]away.AwayReply = undefined;
    var reply_storage: [256]u8 = undefined;
    var notifications_buf: [watcher_count]away.AwayNotify = undefined;
    var notification_storage: [4096]u8 = undefined;

    for (0..notify_iterations) |iteration| {
        var store = away.AwayStore(4, 64).init();
        var replies = away.AwayReplySink{ .replies = &replies_buf, .storage = &reply_storage };
        var notifications = away.AwayNotifySink{ .notifications = &notifications_buf, .storage = &notification_storage };
        const source: away.ClientId = 7;
        const nick = validNick(random, &nick_buf, iteration);
        const message = validMessage(random, &message_buf, iteration);

        var expected_count: usize = 0;
        for (&watchers, 0..) |*watcher, index| {
            watcher.* = .{
                .client = switch (index % 7) {
                    0 => source,
                    else => @as(away.ClientId, @intCast(1 + random.uintLessThan(usize, 32))),
                },
                .away_notify = random.boolean(),
            };
            if (watcher.away_notify and watcher.client != source) {
                expected_clients[expected_count] = watcher.client;
                expected_count += 1;
            }
        }

        try store.set(source, nick, message, &watchers, &replies, &notifications);
        try expectNotifications(notifications.slice(), expected_clients[0..expected_count], nick, message);

        replies.reset();
        notifications.reset();
        try store.clear(source, nick, &watchers, &replies, &notifications);
        try expectNotifications(notifications.slice(), expected_clients[0..expected_count], nick, null);
    }
}

test "away-notify payload builder never writes past caller storage" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0x4004);
    const random = prng.random();
    var nick_buf: [away.MAX_NICK_BYTES]u8 = undefined;
    var message_buf: [64]u8 = undefined;
    var notifications_buf: [1]away.AwayNotify = undefined;
    var storage: [160]u8 = undefined;

    for (0..bounds_iterations) |iteration| {
        const nick = validNick(random, &nick_buf, iteration);
        const message_or_null: ?[]const u8 = if (iteration % 3 == 0)
            null
        else
            validMessage(random, &message_buf, iteration);
        const required = notifyPayloadLen(nick, message_or_null);
        const cap = switch (iteration % 9) {
            0 => 0,
            1 => if (required == 0) 0 else required - 1,
            2 => required,
            3 => required + 1,
            else => random.uintLessThan(usize, storage.len + 1),
        };

        var notifications = away.AwayNotifySink{
            .notifications = &notifications_buf,
            .storage = storage[0..cap],
        };
        const result = notifications.append(99, nick, message_or_null);

        if (cap < required) {
            try std.testing.expectError(error.OutputTooSmall, result);
            try std.testing.expectEqual(@as(usize, 0), notifications.count);
            try std.testing.expectEqual(@as(usize, 0), notifications.used);
        } else {
            try result;
            try std.testing.expectEqual(@as(usize, 1), notifications.count);
            try std.testing.expectEqual(required, notifications.used);
            try std.testing.expect(notifications.slice()[0].payload.len <= notifications.storage.len);
            try expectNotifyPayload(notifications.slice()[0].payload, nick, message_or_null);
        }
    }
}

test "public AWAY APIs return typed errors or success for arbitrary bytes" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0x5005);
    const random = prng.random();
    var store = away.AwayStore(64, 32).init();
    var nick_buf: [96]u8 = undefined;
    var message_buf: [96]u8 = undefined;
    var replies_buf: [4]away.AwayReply = undefined;
    var reply_storage: [512]u8 = undefined;
    var notifications_buf: [4]away.AwayNotify = undefined;
    var notification_storage: [512]u8 = undefined;

    for (0..arbitrary_iterations) |iteration| {
        const nick_len = biasedLength(random, iteration, nick_buf.len);
        const message_len = biasedLength(random, iteration + 11, message_buf.len);
        fillArbitrary(random, nick_buf[0..nick_len], iteration);
        fillArbitrary(random, message_buf[0..message_len], iteration + 17);

        const nick = nick_buf[0..nick_len];
        const message = message_buf[0..message_len];
        const client: away.ClientId = @intCast(1 + random.uintLessThan(usize, 128));

        try validateNickIsTotal(nick);
        try validateMessageIsTotal(message);

        var replies = away.AwayReplySink{ .replies = &replies_buf, .storage = &reply_storage };
        var notifications = away.AwayNotifySink{ .notifications = &notifications_buf, .storage = &notification_storage };
        if (iteration % 4 == 0) {
            const params = [_][]const u8{message};
            try expectAwayResult(store.handle(client, nick, &params, &.{}, &replies, &notifications));
        } else if (iteration % 4 == 1) {
            try expectAwayResult(store.set(client, nick, message, &.{}, &replies, &notifications));
        } else if (iteration % 4 == 2) {
            try expectAwayResult(store.clear(client, nick, &.{}, &replies, &notifications));
        } else {
            try expectAwayResult(store.emitPrivmsgAway(client, client + 1, nick, &replies));
        }
    }
}

fn expectSingleReply(
    replies: []const away.AwayReply,
    expected_numeric: anytype,
    expected_client: away.ClientId,
) !void {
    try std.testing.expectEqual(@as(usize, 1), replies.len);
    try std.testing.expectEqual(expected_numeric, replies[0].numeric);
    try std.testing.expectEqual(expected_client, replies[0].client);
}

fn expectNotifications(
    notifications: []const away.AwayNotify,
    expected_clients: []const away.ClientId,
    nick: []const u8,
    message_or_null: ?[]const u8,
) !void {
    try std.testing.expectEqual(expected_clients.len, notifications.len);
    for (notifications, 0..) |notification, index| {
        try std.testing.expectEqual(expected_clients[index], notification.client);
        try expectNotifyPayload(notification.payload, nick, message_or_null);
    }
}

fn expectNotifyPayload(payload: []const u8, nick: []const u8, message_or_null: ?[]const u8) !void {
    var expected: [160]u8 = undefined;
    var cursor: usize = 0;
    expected[cursor] = ':';
    cursor += 1;
    @memcpy(expected[cursor .. cursor + nick.len], nick);
    cursor += nick.len;
    @memcpy(expected[cursor .. cursor + " AWAY".len], " AWAY");
    cursor += " AWAY".len;
    if (message_or_null) |message| {
        @memcpy(expected[cursor .. cursor + " :".len], " :");
        cursor += " :".len;
        @memcpy(expected[cursor .. cursor + message.len], message);
        cursor += message.len;
    }
    try std.testing.expectEqualStrings(expected[0..cursor], payload);
}

fn expectAwayResult(result: away.AwayError!void) !void {
    result catch |err| {
        try expectAwayError(err);
        return;
    };
}

fn expectAwayError(err: away.AwayError) !void {
    switch (err) {
        error.InvalidNick,
        error.InvalidMessage,
        error.MessageTooLong,
        error.StoreFull,
        error.OutputTooSmall,
        error.TooManyReplies,
        error.TooManyNotifications,
        => {},
    }
}

fn validateNickIsTotal(nick: []const u8) !void {
    away.validateNick(nick) catch |err| {
        try expectAwayError(err);
        return;
    };
}

fn validateMessageIsTotal(message: []const u8) !void {
    away.validateMessage(message, 32) catch |err| {
        try expectAwayError(err);
        return;
    };
}

fn validNick(random: std.Random, buf: []u8, iteration: usize) []const u8 {
    const len = switch (iteration % 8) {
        0 => 1,
        1 => @min(buf.len, away.MAX_NICK_BYTES),
        else => 1 + random.uintLessThan(usize, @min(buf.len, away.MAX_NICK_BYTES)),
    };
    for (buf[0..len]) |*byte| {
        byte.* = switch (random.uintLessThan(u8, 5)) {
            0 => 'A' + random.uintLessThan(u8, 26),
            1 => 'a' + random.uintLessThan(u8, 26),
            2 => '0' + random.uintLessThan(u8, 10),
            3 => '_',
            else => '-',
        };
    }
    return buf[0..len];
}

fn validMessage(random: std.Random, buf: []u8, iteration: usize) []const u8 {
    const len = switch (iteration % 10) {
        0 => 1,
        1 => buf.len,
        else => 1 + random.uintLessThan(usize, buf.len),
    };
    for (buf[0..len]) |*byte| {
        byte.* = switch (random.uintLessThan(u8, 8)) {
            0 => ' ',
            1 => ':',
            2 => 'A' + random.uintLessThan(u8, 26),
            3 => 'a' + random.uintLessThan(u8, 26),
            4 => '0' + random.uintLessThan(u8, 10),
            else => '!' + random.uintLessThan(u8, 94),
        };
        if (byte.* == 0 or byte.* == '\r' or byte.* == '\n') byte.* = '.';
    }
    return buf[0..len];
}

fn biasedLength(random: std.Random, iteration: usize, max_len: usize) usize {
    return switch (iteration % 13) {
        0 => 0,
        1 => 1,
        2 => @min(max_len, 32),
        3 => @min(max_len, 33),
        4 => max_len,
        else => random.uintLessThan(usize, max_len + 1),
    };
}

fn fillMessageCandidate(random: std.Random, out: []u8, iteration: usize) void {
    for (out) |*byte| {
        byte.* = '!' + random.uintLessThan(u8, 94);
    }
    if (out.len == 0) return;
    switch (iteration % 7) {
        0 => out[random.uintLessThan(usize, out.len)] = '\r',
        1 => out[random.uintLessThan(usize, out.len)] = '\n',
        2 => out[random.uintLessThan(usize, out.len)] = 0,
        else => {},
    }
}

fn fillArbitrary(random: std.Random, out: []u8, iteration: usize) void {
    random.bytes(out);
    if (out.len == 0) return;
    switch (iteration % 9) {
        0 => out[0] = 0,
        1 => out[0] = '\r',
        2 => out[0] = '\n',
        3 => out[0] = ' ',
        4 => out[0] = ':',
        else => {},
    }
}

fn hasRejectedMessageByte(message: []const u8) bool {
    for (message) |byte| {
        if (byte == 0 or byte == '\r' or byte == '\n') return true;
    }
    return false;
}

fn notifyPayloadLen(nick: []const u8, message_or_null: ?[]const u8) usize {
    const message_len = if (message_or_null) |message| " :".len + message.len else 0;
    return 1 + nick.len + " AWAY".len + message_len;
}

//! IRC AWAY state and IRCv3 away-notify emission.
//!
//! The module keeps per-client away messages in fixed caller-selected storage
//! and emits structured numerics/notifications through caller-provided sinks.
//! Channel membership is intentionally outside this file: callers pass the
//! already-selected watcher set for an away transition.
const std = @import("std");
const numeric = @import("../proto/numeric.zig");

pub const ClientId = u64;
pub const DEFAULT_MAX_CLIENTS: usize = 4096;
pub const DEFAULT_MAX_AWAY_MESSAGE_BYTES: usize = 512;
pub const MAX_NICK_BYTES: usize = 64;

pub const AwayError = error{
    InvalidNick,
    InvalidMessage,
    MessageTooLong,
    StoreFull,
    OutputTooSmall,
    TooManyReplies,
    TooManyNotifications,
};

/// One client that may receive IRCv3 away-notify traffic.
pub const Watcher = struct {
    client: ClientId,
    away_notify: bool,
};

/// One structured AWAY numeric destined for `client`.
pub const AwayReply = struct {
    numeric: numeric.Numeric,
    client: ClientId,
    target: []const u8 = "",
    text: []const u8 = "",
};

/// Caller-provided storage for AWAY numerics.
pub const AwayReplySink = struct {
    replies: []AwayReply,
    storage: []u8,
    count: usize = 0,
    used: usize = 0,

    pub fn append(
        self: *AwayReplySink,
        reply_numeric: numeric.Numeric,
        client: ClientId,
        target: []const u8,
        text: []const u8,
    ) AwayError!void {
        if (self.count >= self.replies.len) return error.TooManyReplies;
        const target_copy = try self.copy(target);
        const text_copy = try self.copy(text);
        self.replies[self.count] = .{
            .numeric = reply_numeric,
            .client = client,
            .target = target_copy,
            .text = text_copy,
        };
        self.count += 1;
    }

    pub fn slice(self: *const AwayReplySink) []const AwayReply {
        return self.replies[0..self.count];
    }

    pub fn reset(self: *AwayReplySink) void {
        self.count = 0;
        self.used = 0;
    }

    fn copy(self: *AwayReplySink, bytes: []const u8) AwayError![]const u8 {
        if (self.used + bytes.len > self.storage.len) return error.OutputTooSmall;
        const start = self.used;
        const end = start + bytes.len;
        @memcpy(self.storage[start..end], bytes);
        self.used = end;
        return self.storage[start..end];
    }
};

/// One raw IRCv3 away-notify payload destined for `client`.
pub const AwayNotify = struct {
    client: ClientId,
    payload: []const u8,
};

/// Caller-provided storage for raw away-notify payloads.
pub const AwayNotifySink = struct {
    notifications: []AwayNotify,
    storage: []u8,
    count: usize = 0,
    used: usize = 0,

    pub fn append(
        self: *AwayNotifySink,
        client: ClientId,
        nick: []const u8,
        message: ?[]const u8,
    ) AwayError!void {
        if (self.count >= self.notifications.len) return error.TooManyNotifications;
        const payload_len = notifyPayloadLen(nick, message);
        if (self.used + payload_len > self.storage.len) return error.OutputTooSmall;

        const start = self.used;
        var cursor = start;
        self.storage[cursor] = ':';
        cursor += 1;
        @memcpy(self.storage[cursor .. cursor + nick.len], nick);
        cursor += nick.len;
        @memcpy(self.storage[cursor .. cursor + " AWAY".len], " AWAY");
        cursor += " AWAY".len;
        if (message) |msg| {
            @memcpy(self.storage[cursor .. cursor + " :".len], " :");
            cursor += " :".len;
            @memcpy(self.storage[cursor .. cursor + msg.len], msg);
            cursor += msg.len;
        }

        self.used = cursor;
        self.notifications[self.count] = .{
            .client = client,
            .payload = self.storage[start..cursor],
        };
        self.count += 1;
    }

    pub fn slice(self: *const AwayNotifySink) []const AwayNotify {
        return self.notifications[0..self.count];
    }

    pub fn reset(self: *AwayNotifySink) void {
        self.count = 0;
        self.used = 0;
    }
};

/// Fixed-capacity AWAY state store.
pub fn AwayStore(
    comptime max_clients: usize,
    comptime max_message_bytes: usize,
) type {
    if (max_clients == 0) @compileError("AwayStore requires at least one client slot");
    if (max_message_bytes == 0) @compileError("AwayStore requires nonzero message capacity");
    if (max_message_bytes > std.math.maxInt(u16)) {
        @compileError("AwayStore message capacity must fit in u16");
    }

    return struct {
        entries: [max_clients]Entry = [_]Entry{Entry{}} ** max_clients,
        count: usize = 0,

        const Self = @This();

        const Entry = struct {
            client: ClientId = 0,
            away: bool = false,
            message: [max_message_bytes]u8 = [_]u8{0} ** max_message_bytes,
            message_len: u16 = 0,

            fn messageSlice(self: *const Entry) []const u8 {
                return self.message[0..self.message_len];
            }
        };

        pub fn init() Self {
            return .{};
        }

        /// Apply an AWAY command parameter list. No parameter clears away state.
        pub fn handle(
            self: *Self,
            client: ClientId,
            nick: []const u8,
            params: []const []const u8,
            watchers: []const Watcher,
            replies: *AwayReplySink,
            notifications: *AwayNotifySink,
        ) AwayError!void {
            if (params.len == 0) {
                try self.clear(client, nick, watchers, replies, notifications);
                return;
            }
            try self.set(client, nick, params[0], watchers, replies, notifications);
        }

        /// Set or replace this client's away message.
        pub fn set(
            self: *Self,
            client: ClientId,
            nick: []const u8,
            away_message: []const u8,
            watchers: []const Watcher,
            replies: *AwayReplySink,
            notifications: *AwayNotifySink,
        ) AwayError!void {
            try validateNick(nick);
            try validateMessage(away_message, max_message_bytes);

            const state_entry = try self.entryFor(client);
            @memcpy(state_entry.message[0..away_message.len], away_message);
            state_entry.message_len = @intCast(away_message.len);
            state_entry.away = true;

            try replies.append(
                .RPL_NOWAWAY,
                client,
                "",
                "You have been marked as being away",
            );
            try self.broadcast(client, nick, away_message, watchers, notifications);
        }

        /// Clear this client's away message.
        pub fn clear(
            self: *Self,
            client: ClientId,
            nick: []const u8,
            watchers: []const Watcher,
            replies: *AwayReplySink,
            notifications: *AwayNotifySink,
        ) AwayError!void {
            try validateNick(nick);

            const was_away = if (self.findIndex(client)) |index| self.entries[index].away else false;
            if (self.findIndex(client)) |index| {
                self.entries[index].away = false;
                self.entries[index].message_len = 0;
            }

            try replies.append(
                .RPL_UNAWAY,
                client,
                "",
                "You are no longer marked as being away",
            );
            if (was_away) {
                try self.broadcast(client, nick, null, watchers, notifications);
            }
        }

        /// Emit RPL_AWAY for a PRIVMSG sender when `target_client` is away.
        pub fn emitPrivmsgAway(
            self: *const Self,
            sender: ClientId,
            target_client: ClientId,
            target_nick: []const u8,
            replies: *AwayReplySink,
        ) AwayError!void {
            try validateNick(target_nick);
            const target_entry = self.entry(target_client) orelse return;
            if (!target_entry.away) return;
            try replies.append(.RPL_AWAY, sender, target_nick, target_entry.messageSlice());
        }

        pub fn isAway(self: *const Self, client: ClientId) bool {
            const found = self.entry(client) orelse return false;
            return found.away;
        }

        pub fn message(self: *const Self, client: ClientId) ?[]const u8 {
            const found = self.entry(client) orelse return null;
            if (!found.away) return null;
            return found.messageSlice();
        }

        pub fn removeClient(self: *Self, client: ClientId) void {
            const index = self.findIndex(client) orelse return;
            if (index + 1 < self.count) {
                self.entries[index] = self.entries[self.count - 1];
            }
            self.count -= 1;
            self.entries[self.count] = Entry{};
        }

        fn broadcast(
            self: *Self,
            client: ClientId,
            nick: []const u8,
            message_or_null: ?[]const u8,
            watchers: []const Watcher,
            notifications: *AwayNotifySink,
        ) AwayError!void {
            _ = self;
            for (watchers) |watcher| {
                if (!watcher.away_notify or watcher.client == client) continue;
                try notifications.append(watcher.client, nick, message_or_null);
            }
        }

        fn entryFor(self: *Self, client: ClientId) AwayError!*Entry {
            if (self.findIndex(client)) |index| return &self.entries[index];
            if (self.count >= self.entries.len) return error.StoreFull;
            const index = self.count;
            self.count += 1;
            self.entries[index] = .{ .client = client };
            return &self.entries[index];
        }

        fn entry(self: *const Self, client: ClientId) ?*const Entry {
            const index = self.findIndex(client) orelse return null;
            return &self.entries[index];
        }

        fn findIndex(self: *const Self, client: ClientId) ?usize {
            var index: usize = 0;
            while (index < self.count) : (index += 1) {
                if (self.entries[index].client == client) return index;
            }
            return null;
        }
    };
}

/// Default store sizing for daemon integration.
pub const DefaultAwayStore = AwayStore(
    DEFAULT_MAX_CLIENTS,
    DEFAULT_MAX_AWAY_MESSAGE_BYTES,
);

pub fn validateNick(nick: []const u8) AwayError!void {
    if (nick.len == 0 or nick.len > MAX_NICK_BYTES) return error.InvalidNick;
    for (nick) |ch| {
        switch (ch) {
            0, ':', ' ', '\t', '\r', '\n' => return error.InvalidNick,
            else => {},
        }
    }
}

pub fn validateMessage(message: []const u8, max_message_bytes: usize) AwayError!void {
    if (message.len == 0) return error.InvalidMessage;
    if (message.len > max_message_bytes) return error.MessageTooLong;
    for (message) |ch| {
        switch (ch) {
            0, '\r', '\n' => return error.InvalidMessage,
            else => {},
        }
    }
}

fn notifyPayloadLen(nick: []const u8, message: ?[]const u8) usize {
    const message_len = if (message) |msg| " :".len + msg.len else 0;
    return 1 + nick.len + " AWAY".len + message_len;
}

fn expectReply(
    reply: AwayReply,
    reply_numeric: numeric.Numeric,
    client: ClientId,
    target: []const u8,
    text: []const u8,
) !void {
    try std.testing.expectEqual(reply_numeric, reply.numeric);
    try std.testing.expectEqual(client, reply.client);
    try std.testing.expectEqualStrings(target, reply.target);
    try std.testing.expectEqualStrings(text, reply.text);
}

test "set and clear transitions emit canonical numerics" {
    var store = AwayStore(4, 64).init();
    var replies_buf: [4]AwayReply = undefined;
    var reply_storage: [256]u8 = undefined;
    var replies = AwayReplySink{ .replies = &replies_buf, .storage = &reply_storage };
    var notify_buf: [4]AwayNotify = undefined;
    var notify_storage: [256]u8 = undefined;
    var notifications = AwayNotifySink{ .notifications = &notify_buf, .storage = &notify_storage };

    try store.handle(1, "alice", &.{"gone for lunch"}, &.{}, &replies, &notifications);
    try std.testing.expect(store.isAway(1));
    try std.testing.expectEqualStrings("gone for lunch", store.message(1).?);
    try std.testing.expectEqual(@as(usize, 1), replies.slice().len);
    try expectReply(
        replies.slice()[0],
        .RPL_NOWAWAY,
        1,
        "",
        "You have been marked as being away",
    );

    replies.reset();
    notifications.reset();
    try store.handle(1, "alice", &.{}, &.{}, &replies, &notifications);
    try std.testing.expect(!store.isAway(1));
    try std.testing.expectEqual(@as(?[]const u8, null), store.message(1));
    try std.testing.expectEqual(@as(usize, 1), replies.slice().len);
    try expectReply(
        replies.slice()[0],
        .RPL_UNAWAY,
        1,
        "",
        "You are no longer marked as being away",
    );
}

test "away-notify emits exact set and clear payloads to negotiated watchers" {
    var store = AwayStore(4, 64).init();
    var replies_buf: [4]AwayReply = undefined;
    var reply_storage: [256]u8 = undefined;
    var replies = AwayReplySink{ .replies = &replies_buf, .storage = &reply_storage };
    var notify_buf: [4]AwayNotify = undefined;
    var notify_storage: [256]u8 = undefined;
    var notifications = AwayNotifySink{ .notifications = &notify_buf, .storage = &notify_storage };
    const watchers = [_]Watcher{
        .{ .client = 1, .away_notify = true },
        .{ .client = 2, .away_notify = true },
        .{ .client = 3, .away_notify = false },
    };

    try store.set(1, "alice", "working", &watchers, &replies, &notifications);
    try std.testing.expectEqual(@as(usize, 1), notifications.slice().len);
    try std.testing.expectEqual(@as(ClientId, 2), notifications.slice()[0].client);
    try std.testing.expectEqualStrings(":alice AWAY :working", notifications.slice()[0].payload);

    replies.reset();
    notifications.reset();
    try store.clear(1, "alice", &watchers, &replies, &notifications);
    try std.testing.expectEqual(@as(usize, 1), notifications.slice().len);
    try std.testing.expectEqual(@as(ClientId, 2), notifications.slice()[0].client);
    try std.testing.expectEqualStrings(":alice AWAY", notifications.slice()[0].payload);
}

test "privmsg to away user emits RPL_AWAY to sender" {
    var store = AwayStore(4, 64).init();
    var replies_buf: [4]AwayReply = undefined;
    var reply_storage: [256]u8 = undefined;
    var replies = AwayReplySink{ .replies = &replies_buf, .storage = &reply_storage };
    var notify_buf: [1]AwayNotify = undefined;
    var notify_storage: [64]u8 = undefined;
    var notifications = AwayNotifySink{ .notifications = &notify_buf, .storage = &notify_storage };

    try store.set(2, "bob", "back later", &.{}, &replies, &notifications);
    replies.reset();

    try store.emitPrivmsgAway(1, 2, "bob", &replies);
    try std.testing.expectEqual(@as(usize, 1), replies.slice().len);
    try expectReply(replies.slice()[0], .RPL_AWAY, 1, "bob", "back later");
}

test "privmsg to present user without away state emits nothing" {
    var store = AwayStore(4, 64).init();
    var replies_buf: [4]AwayReply = undefined;
    var reply_storage: [256]u8 = undefined;
    var replies = AwayReplySink{ .replies = &replies_buf, .storage = &reply_storage };

    try store.emitPrivmsgAway(1, 2, "bob", &replies);
    try std.testing.expectEqual(@as(usize, 0), replies.slice().len);
}

test "max away message length is enforced before state mutation" {
    var store = AwayStore(2, 5).init();
    var replies_buf: [4]AwayReply = undefined;
    var reply_storage: [256]u8 = undefined;
    var replies = AwayReplySink{ .replies = &replies_buf, .storage = &reply_storage };
    var notify_buf: [1]AwayNotify = undefined;
    var notify_storage: [64]u8 = undefined;
    var notifications = AwayNotifySink{ .notifications = &notify_buf, .storage = &notify_storage };

    try std.testing.expectError(
        error.MessageTooLong,
        store.set(1, "alice", "toolong", &.{}, &replies, &notifications),
    );
    try std.testing.expect(!store.isAway(1));
    try std.testing.expectEqual(@as(usize, 0), replies.slice().len);
}

test "attacker-controlled nick and message bytes are rejected" {
    var store = AwayStore(2, 16).init();
    var replies_buf: [4]AwayReply = undefined;
    var reply_storage: [256]u8 = undefined;
    var replies = AwayReplySink{ .replies = &replies_buf, .storage = &reply_storage };
    var notify_buf: [1]AwayNotify = undefined;
    var notify_storage: [64]u8 = undefined;
    var notifications = AwayNotifySink{ .notifications = &notify_buf, .storage = &notify_storage };

    try std.testing.expectError(
        error.InvalidNick,
        store.set(1, "bad nick", "ok", &.{}, &replies, &notifications),
    );
    try std.testing.expectError(
        error.InvalidMessage,
        store.set(1, "alice", "bad\nmsg", &.{}, &replies, &notifications),
    );
    try std.testing.expect(!store.isAway(1));
}

test "store capacity is enforced without allocation" {
    var store = AwayStore(1, 16).init();
    var replies_buf: [4]AwayReply = undefined;
    var reply_storage: [256]u8 = undefined;
    var replies = AwayReplySink{ .replies = &replies_buf, .storage = &reply_storage };
    var notify_buf: [1]AwayNotify = undefined;
    var notify_storage: [64]u8 = undefined;
    var notifications = AwayNotifySink{ .notifications = &notify_buf, .storage = &notify_storage };

    try store.set(1, "alice", "one", &.{}, &replies, &notifications);
    replies.reset();
    try std.testing.expectError(
        error.StoreFull,
        store.set(2, "bob", "two", &.{}, &replies, &notifications),
    );
}

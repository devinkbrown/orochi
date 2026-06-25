// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-channel moderation and audit journals.
//!
//! This module stores operator-queryable channel events only. It has no network
//! behavior and owns every string it stores.
const std = @import("std");

comptime {
    if (@bitSizeOf(usize) != 64) @compileError("channel logs require a 64-bit target");
}

/// Channel moderation and audit event categories.
pub const EventKind = enum {
    mode_change,
    kick,
    ban_add,
    ban_remove,
    topic_change,
    join_throttle,
    register,
    drop,
    akick,
};

/// One stored channel audit event with owned string fields.
pub const Entry = struct {
    ts: i64,
    kind: EventKind,
    actor: []const u8,
    target: []const u8,
    detail: []const u8,
};

/// Compile-time limits for a channel audit journal.
pub const Params = struct {
    max_channels: usize = 1024,
    max_entries_per_channel: usize = 64,
    max_channel_bytes: usize = 128,
};

/// Errors returned by channel audit journal operations.
pub const ChannelLogError = std.mem.Allocator.Error || error{
    InvalidChannel,
    ChannelTooLong,
    ChannelLimitExceeded,
    OutputTooSmall,
};

/// Default bounded channel audit journal type.
pub const ChannelLog = ChannelLogWith(.{});

/// Builds a bounded channel audit journal type for the supplied limits.
pub fn ChannelLogWith(comptime params: Params) type {
    comptime {
        if (params.max_channels == 0) @compileError("channel logs need channel storage");
        if (params.max_entries_per_channel == 0) @compileError("channel logs need entry storage");
        if (params.max_channel_bytes == 0) @compileError("channel keys need storage");
    }

    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        channels: std.StringHashMap(ChannelState),

        const ChannelState = struct {
            entries: []Entry,
            head: usize = 0,
            len: usize = 0,

            fn init(allocator: std.mem.Allocator) ChannelLogError!ChannelState {
                return .{
                    .entries = try allocator.alloc(Entry, params.max_entries_per_channel),
                };
            }

            fn deinit(self: *ChannelState, allocator: std.mem.Allocator) void {
                self.freeEntries(allocator);
                allocator.free(self.entries);
                self.* = undefined;
            }

            fn append(self: *ChannelState, allocator: std.mem.Allocator, entry: Entry) void {
                const index = self.head;
                if (self.len == self.entries.len) {
                    freeEntry(allocator, &self.entries[index]);
                } else {
                    self.len += 1;
                }

                self.entries[index] = entry;
                self.head = (self.head + 1) % self.entries.len;
            }

            fn copyNewestFirst(self: *const ChannelState, out: []Entry) ChannelLogError![]const Entry {
                if (out.len < self.len) return error.OutputTooSmall;

                var copied: usize = 0;
                while (copied < self.len) : (copied += 1) {
                    const index = (self.head + self.entries.len - 1 - copied) % self.entries.len;
                    out[copied] = self.entries[index];
                }
                return out[0..copied];
            }

            fn freeEntries(self: *ChannelState, allocator: std.mem.Allocator) void {
                if (self.len == self.entries.len) {
                    for (self.entries) |*entry| freeEntry(allocator, entry);
                    return;
                }

                for (self.entries[0..self.len]) |*entry| freeEntry(allocator, entry);
            }
        };

        /// Creates an empty channel audit journal.
        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .allocator = allocator,
                .channels = std.StringHashMap(ChannelState).init(allocator),
            };
        }

        /// Frees all channel keys, rings, and owned entry strings.
        pub fn deinit(self: *Self) void {
            self.clearAll();
            self.channels.deinit();
            self.* = undefined;
        }

        /// Records one channel audit event, overwriting the oldest entry when the ring is full.
        pub fn record(
            self: *Self,
            channel: []const u8,
            kind: EventKind,
            actor: []const u8,
            target: []const u8,
            detail: []const u8,
            ts: i64,
        ) ChannelLogError!void {
            const owned_entry = try ownedEntry(self.allocator, .{
                .ts = ts,
                .kind = kind,
                .actor = actor,
                .target = target,
                .detail = detail,
            });
            errdefer freeEntryValue(self.allocator, owned_entry);

            const state = try self.getOrCreateChannel(channel);
            state.append(self.allocator, owned_entry);
        }

        /// Copies stored events for a channel into `out` from newest to oldest.
        pub fn query(self: *const Self, channel: []const u8, out: []Entry) ChannelLogError![]const Entry {
            var key_buf: [params.max_channel_bytes]u8 = undefined;
            const key = try normalizeChannel(channel, &key_buf);
            const state = self.channels.getPtr(key) orelse return out[0..0];
            return state.copyNewestFirst(out);
        }

        /// Returns the number of stored events for a channel.
        pub fn count(self: *const Self, channel: []const u8) ChannelLogError!usize {
            var key_buf: [params.max_channel_bytes]u8 = undefined;
            const key = try normalizeChannel(channel, &key_buf);
            const state = self.channels.getPtr(key) orelse return 0;
            return state.len;
        }

        /// Removes all stored events for a channel and releases its tracked slot.
        pub fn clear(self: *Self, channel: []const u8) ChannelLogError!void {
            var key_buf: [params.max_channel_bytes]u8 = undefined;
            const key = try normalizeChannel(channel, &key_buf);
            var removed = self.channels.fetchRemove(key) orelse return;
            self.allocator.free(removed.key);
            removed.value.deinit(self.allocator);
        }

        fn clearAll(self: *Self) void {
            var it = self.channels.iterator();
            while (it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                entry.value_ptr.deinit(self.allocator);
            }
            self.channels.clearRetainingCapacity();
        }

        fn getOrCreateChannel(self: *Self, channel: []const u8) ChannelLogError!*ChannelState {
            var key_buf: [params.max_channel_bytes]u8 = undefined;
            const key = try normalizeChannel(channel, &key_buf);
            if (self.channels.getPtr(key)) |state| return state;
            if (self.channels.count() >= params.max_channels) return error.ChannelLimitExceeded;

            const owned_key = try self.allocator.dupe(u8, key);
            errdefer self.allocator.free(owned_key);

            var state = try ChannelState.init(self.allocator);
            errdefer state.deinit(self.allocator);

            try self.channels.putNoClobber(owned_key, state);
            return self.channels.getPtr(owned_key).?;
        }

        fn normalizeChannel(channel: []const u8, out: *[params.max_channel_bytes]u8) ChannelLogError![]const u8 {
            if (channel.len == 0) return error.InvalidChannel;
            if (channel.len > params.max_channel_bytes) return error.ChannelTooLong;

            for (channel, 0..) |byte, index| {
                switch (byte) {
                    0, ' ', '\r', '\n', '\t', 0x7f => return error.InvalidChannel,
                    else => out[index] = std.ascii.toLower(byte),
                }
            }
            return out[0..channel.len];
        }
    };
}

fn ownedEntry(allocator: std.mem.Allocator, entry: Entry) ChannelLogError!Entry {
    const actor = try allocator.dupe(u8, entry.actor);
    errdefer allocator.free(actor);

    const target = try allocator.dupe(u8, entry.target);
    errdefer allocator.free(target);

    const detail = try allocator.dupe(u8, entry.detail);
    errdefer allocator.free(detail);

    return .{
        .ts = entry.ts,
        .kind = entry.kind,
        .actor = actor,
        .target = target,
        .detail = detail,
    };
}

fn freeEntry(allocator: std.mem.Allocator, entry: *Entry) void {
    allocator.free(entry.actor);
    allocator.free(entry.target);
    allocator.free(entry.detail);
    entry.* = undefined;
}

fn freeEntryValue(allocator: std.mem.Allocator, entry: Entry) void {
    allocator.free(entry.actor);
    allocator.free(entry.target);
    allocator.free(entry.detail);
}

test "record and query returns newest first" {
    // Arrange
    const Log = ChannelLogWith(.{ .max_channels = 4, .max_entries_per_channel = 4 });
    var log = Log.init(std.testing.allocator);
    defer log.deinit();

    // Act
    try log.record("#ops", .mode_change, "alice", "#ops", "+m", 10);
    try log.record("#ops", .kick, "bob", "mallory", "flood", 11);
    try log.record("#ops", .topic_change, "carol", "#ops", "new topic", 12);

    var out: [4]Entry = undefined;
    const entries = try log.query("#ops", &out);

    // Assert
    try std.testing.expectEqual(@as(usize, 3), entries.len);
    try std.testing.expectEqual(@as(i64, 12), entries[0].ts);
    try std.testing.expectEqual(EventKind.topic_change, entries[0].kind);
    try std.testing.expectEqualStrings("carol", entries[0].actor);
    try std.testing.expectEqualStrings("#ops", entries[0].target);
    try std.testing.expectEqualStrings("new topic", entries[0].detail);
    try std.testing.expectEqual(@as(i64, 11), entries[1].ts);
    try std.testing.expectEqual(EventKind.kick, entries[1].kind);
    try std.testing.expectEqual(@as(i64, 10), entries[2].ts);
    try std.testing.expectEqual(EventKind.mode_change, entries[2].kind);
}

test "ring overwrite drops oldest entries under churn without leaks" {
    // Arrange
    const Log = ChannelLogWith(.{ .max_channels = 2, .max_entries_per_channel = 3 });
    var log = Log.init(std.testing.allocator);
    defer log.deinit();

    // Act
    var i: i64 = 0;
    while (i < 12) : (i += 1) {
        try log.record("#audit", .ban_add, "oper", "bad-user", "mask!*@*", i);
    }

    var out: [3]Entry = undefined;
    const entries = try log.query("#audit", &out);

    // Assert
    try std.testing.expectEqual(@as(usize, 3), entries.len);
    try std.testing.expectEqual(@as(i64, 11), entries[0].ts);
    try std.testing.expectEqual(@as(i64, 10), entries[1].ts);
    try std.testing.expectEqual(@as(i64, 9), entries[2].ts);
    try std.testing.expectEqual(@as(usize, 3), try log.count("#audit"));
}

test "per channel isolation keeps independent rings" {
    // Arrange
    const Log = ChannelLogWith(.{ .max_channels = 4, .max_entries_per_channel = 2 });
    var log = Log.init(std.testing.allocator);
    defer log.deinit();

    // Act
    try log.record("#alpha", .register, "services", "#alpha", "created", 1);
    try log.record("#beta", .drop, "services", "#beta", "removed", 2);
    try log.record("#alpha", .akick, "oper", "eve", "policy", 3);

    var alpha_buf: [2]Entry = undefined;
    var beta_buf: [2]Entry = undefined;
    const alpha = try log.query("#alpha", &alpha_buf);
    const beta = try log.query("#beta", &beta_buf);

    // Assert
    try std.testing.expectEqual(@as(usize, 2), alpha.len);
    try std.testing.expectEqual(@as(usize, 1), beta.len);
    try std.testing.expectEqual(EventKind.akick, alpha[0].kind);
    try std.testing.expectEqual(EventKind.register, alpha[1].kind);
    try std.testing.expectEqual(EventKind.drop, beta[0].kind);
    try std.testing.expectEqualStrings("#beta", beta[0].target);
}

test "channel keys are case insensitive" {
    // Arrange
    const Log = ChannelLogWith(.{ .max_channels = 2, .max_entries_per_channel = 4 });
    var log = Log.init(std.testing.allocator);
    defer log.deinit();

    // Act
    try log.record("#Mixed", .join_throttle, "oper", "#Mixed", "30s", 5);
    try log.record("#mixed", .ban_remove, "oper", "bad!*@*", "expired", 6);

    var out: [4]Entry = undefined;
    const entries = try log.query("#MIXED", &out);

    // Assert
    try std.testing.expectEqual(@as(usize, 2), entries.len);
    try std.testing.expectEqual(@as(usize, 2), try log.count("#mixed"));
    try std.testing.expectEqual(EventKind.ban_remove, entries[0].kind);
    try std.testing.expectEqual(EventKind.join_throttle, entries[1].kind);
}

test "clear removes entries and preserves reusable channel capacity" {
    // Arrange
    const Log = ChannelLogWith(.{ .max_channels = 1, .max_entries_per_channel = 2 });
    var log = Log.init(std.testing.allocator);
    defer log.deinit();

    try log.record("#clear", .topic_change, "alice", "#clear", "before", 1);
    try log.record("#clear", .mode_change, "alice", "#clear", "+s", 2);

    // Act
    try log.clear("#CLEAR");
    try std.testing.expectEqual(@as(usize, 0), try log.count("#clear"));
    try log.record("#next", .register, "services", "#next", "after", 3);

    var out: [2]Entry = undefined;
    const entries = try log.query("#next", &out);

    // Assert
    try std.testing.expectEqual(@as(usize, 1), entries.len);
    try std.testing.expectEqual(EventKind.register, entries[0].kind);
    try std.testing.expectEqualStrings("after", entries[0].detail);
}

test "limits and output size errors are typed" {
    // Arrange
    const Log = ChannelLogWith(.{
        .max_channels = 1,
        .max_entries_per_channel = 2,
        .max_channel_bytes = 8,
    });
    var log = Log.init(std.testing.allocator);
    defer log.deinit();

    // Act
    try log.record("#one", .mode_change, "oper", "#one", "+i", 1);

    // Assert
    try std.testing.expectError(
        error.ChannelLimitExceeded,
        log.record("#two", .mode_change, "oper", "#two", "+i", 2),
    );
    try std.testing.expectError(error.ChannelTooLong, log.count("#toolong-channel"));
    try std.testing.expectError(error.InvalidChannel, log.count("#bad x"));

    var tiny: [0]Entry = undefined;
    try std.testing.expectError(error.OutputTooSmall, log.query("#one", &tiny));
}

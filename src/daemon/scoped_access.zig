// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unified scoped access-list storage for Orochi.
//!
//! A single ordered store carries both grants and restrictions. Entries own
//! their text fields after insertion, and callers pass an allocator to every
//! operation that can allocate or release memory.

const std = @import("std");

pub const Scope = enum {
    channel,
    server,
    network,
};

pub const Level = enum(i8) {
    owner = 6,
    host = 5,
    aide = 4,
    voice = 2,
    member = 1,
    none = 0,
    deny = -1,
    shun = -2,
    zap = -3,

    pub fn polarity(self: Level) Polarity {
        return switch (self) {
            .owner, .host, .aide, .voice, .member => .grant,
            .none => .neutral,
            .deny, .shun, .zap => .restriction,
        };
    }

    fn grantRank(self: Level) i8 {
        return switch (self) {
            .owner => 6,
            .host => 5,
            .aide => 4,
            .voice => 2,
            .member => 1,
            .none, .deny, .shun, .zap => 0,
        };
    }

    fn restrictionRank(self: Level) i8 {
        return switch (self) {
            .zap => 3,
            .shun => 2,
            .deny => 1,
            .none, .member, .voice, .aide, .host, .owner => 0,
        };
    }
};

pub const Entry = struct {
    scope: Scope,
    level: Level,
    mask: []u8,
    reason: []u8,
    added_by: []u8,
    added_at_ms: i64,
    expires_at_ms: i64,

    pub fn isExpired(self: Entry, now_ms: i64) bool {
        return self.expires_at_ms != 0 and self.expires_at_ms <= now_ms;
    }
};

pub const Store = struct {
    entries: std.ArrayListUnmanaged(Entry) = .empty,

    const Self = @This();

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        for (self.entries.items) |entry| freeEntry(allocator, entry);
        self.entries.deinit(allocator);
        self.* = .{};
    }

    pub fn add(self: *Self, allocator: std.mem.Allocator, entry: Entry) !usize {
        var owned = Entry{
            .scope = entry.scope,
            .level = entry.level,
            .mask = try allocator.dupe(u8, entry.mask),
            .reason = &.{},
            .added_by = &.{},
            .added_at_ms = entry.added_at_ms,
            .expires_at_ms = entry.expires_at_ms,
        };
        errdefer allocator.free(owned.mask);

        owned.reason = try allocator.dupe(u8, entry.reason);
        errdefer allocator.free(owned.reason);

        owned.added_by = try allocator.dupe(u8, entry.added_by);
        errdefer allocator.free(owned.added_by);

        try self.entries.append(allocator, owned);
        return self.entries.items.len - 1;
    }

    pub fn removeIndex(self: *Self, allocator: std.mem.Allocator, index: usize) bool {
        if (index >= self.entries.items.len) return false;
        const removed = self.entries.orderedRemove(index);
        freeEntry(allocator, removed);
        return true;
    }

    pub fn removeMaskScope(
        self: *Self,
        allocator: std.mem.Allocator,
        scope: Scope,
        mask: []const u8,
    ) bool {
        for (self.entries.items, 0..) |entry, index| {
            if (entry.scope == scope and std.mem.eql(u8, entry.mask, mask)) {
                return self.removeIndex(allocator, index);
            }
        }
        return false;
    }

    pub fn list(self: *const Self, scope: Scope) Iterator {
        return .{
            .items = self.entries.items,
            .scope = scope,
        };
    }

    pub fn matchBest(
        self: *const Self,
        scope: Scope,
        hostmask: []const u8,
        now_ms: i64,
    ) ?Level {
        var best_restriction: ?Level = null;
        var best_grant: ?Level = null;

        for (self.entries.items) |entry| {
            if (entry.scope != scope) continue;
            if (entry.isExpired(now_ms)) continue;
            if (!globMatch(entry.mask, hostmask)) continue;

            switch (entry.level.polarity()) {
                .restriction => {
                    if (best_restriction == null or
                        entry.level.restrictionRank() > best_restriction.?.restrictionRank())
                    {
                        best_restriction = entry.level;
                    }
                },
                .grant => {
                    if (best_grant == null or entry.level.grantRank() > best_grant.?.grantRank()) {
                        best_grant = entry.level;
                    }
                },
                .neutral => {},
            }
        }

        return best_restriction orelse best_grant;
    }

    pub fn sweepExpired(self: *Self, allocator: std.mem.Allocator, now_ms: i64) usize {
        var index: usize = 0;
        var removed: usize = 0;
        while (index < self.entries.items.len) {
            if (self.entries.items[index].isExpired(now_ms)) {
                const entry = self.entries.orderedRemove(index);
                freeEntry(allocator, entry);
                removed += 1;
                continue;
            }
            index += 1;
        }
        return removed;
    }
};

pub const Iterator = struct {
    items: []const Entry,
    scope: Scope,
    index: usize = 0,

    pub fn next(self: *Iterator) ?Entry {
        while (self.index < self.items.len) {
            const entry = self.items[self.index];
            self.index += 1;
            if (entry.scope == self.scope) return entry;
        }
        return null;
    }
};

const Polarity = enum {
    grant,
    neutral,
    restriction,
};

fn freeEntry(allocator: std.mem.Allocator, entry: Entry) void {
    allocator.free(entry.mask);
    allocator.free(entry.reason);
    allocator.free(entry.added_by);
}

pub fn globMatch(pattern: []const u8, text: []const u8) bool {
    var pattern_index: usize = 0;
    var text_index: usize = 0;
    var star_index: ?usize = null;
    var retry_text_index: usize = 0;

    while (text_index < text.len) {
        if (pattern_index < pattern.len and pattern[pattern_index] == '*') {
            star_index = pattern_index;
            pattern_index += 1;
            retry_text_index = text_index;
            continue;
        }

        if (pattern_index < pattern.len and
            (pattern[pattern_index] == '?' or asciiEqual(pattern[pattern_index], text[text_index])))
        {
            pattern_index += 1;
            text_index += 1;
            continue;
        }

        if (star_index) |star| {
            pattern_index = star + 1;
            retry_text_index += 1;
            text_index = retry_text_index;
            continue;
        }

        return false;
    }

    while (pattern_index < pattern.len and pattern[pattern_index] == '*') {
        pattern_index += 1;
    }

    return pattern_index == pattern.len;
}

fn asciiEqual(a: u8, b: u8) bool {
    return asciiLower(a) == asciiLower(b);
}

fn asciiLower(byte: u8) u8 {
    return switch (byte) {
        'A'...'Z' => byte + ('a' - 'A'),
        else => byte,
    };
}

fn testEntry(scope: Scope, level: Level, mask: []const u8, expires_at_ms: i64) Entry {
    return .{
        .scope = scope,
        .level = level,
        .mask = @constCast(mask),
        .reason = @constCast(""),
        .added_by = @constCast("tester"),
        .added_at_ms = 100,
        .expires_at_ms = expires_at_ms,
    };
}

test "grant and ban coexist in one scoped list" {
    const allocator = std.testing.allocator;
    var store = Store{};
    defer store.deinit(allocator);

    _ = try store.add(allocator, testEntry(.channel, .voice, "ivy!*@garden.test", 0));
    _ = try store.add(allocator, testEntry(.channel, .deny, "ivy!*@bad-garden.test", 0));

    var it = store.list(.channel);
    try std.testing.expectEqual(Level.voice, it.next().?.level);
    try std.testing.expectEqual(Level.deny, it.next().?.level);
    try std.testing.expect(it.next() == null);
}

test "matchBest picks strongest applicable entry" {
    const allocator = std.testing.allocator;
    var store = Store{};
    defer store.deinit(allocator);

    _ = try store.add(allocator, testEntry(.channel, .member, "*!*@example.test", 0));
    _ = try store.add(allocator, testEntry(.channel, .host, "ren!*@example.test", 0));
    _ = try store.add(allocator, testEntry(.server, .zap, "ren!*@example.test", 0));

    try std.testing.expectEqual(
        @as(?Level, .host),
        store.matchBest(.channel, "Ren!u@example.test", 1000),
    );
    try std.testing.expectEqual(
        @as(?Level, .zap),
        store.matchBest(.server, "ren!u@example.test", 1000),
    );
}

test "glob matching supports star question mark and ascii case folding" {
    try std.testing.expect(globMatch("N?CK!*@*.Example", "nick!user@edge.example"));
    try std.testing.expect(globMatch("*!*@host", "someone!ident@HOST"));
    try std.testing.expect(!globMatch("a?c", "ac"));
    try std.testing.expect(!globMatch("*@trusted.test", "n!u@other.test"));
}

test "expiry sweep removes only expired entries" {
    const allocator = std.testing.allocator;
    var store = Store{};
    defer store.deinit(allocator);

    _ = try store.add(allocator, testEntry(.network, .shun, "*!*@old.test", 50));
    _ = try store.add(allocator, testEntry(.network, .owner, "*!*@live.test", 500));
    _ = try store.add(allocator, testEntry(.network, .member, "*!*@forever.test", 0));

    try std.testing.expectEqual(@as(usize, 1), store.sweepExpired(allocator, 100));
    try std.testing.expectEqual(@as(usize, 2), store.entries.items.len);
    try std.testing.expectEqual(
        @as(?Level, .owner),
        store.matchBest(.network, "n!u@live.test", 100),
    );
    try std.testing.expect(store.matchBest(.network, "n!u@old.test", 100) == null);
}

test "deny outranks voice when both match" {
    const allocator = std.testing.allocator;
    var store = Store{};
    defer store.deinit(allocator);

    _ = try store.add(allocator, testEntry(.channel, .voice, "*!*@example.test", 0));
    _ = try store.add(allocator, testEntry(.channel, .deny, "sam!*@example.test", 0));

    try std.testing.expectEqual(
        @as(?Level, .deny),
        store.matchBest(.channel, "sam!u@example.test", 1000),
    );
}

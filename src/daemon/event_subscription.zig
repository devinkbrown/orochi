//! Bounded per-account event topic subscriptions.
const std = @import("std");

pub const max_accounts: usize = 8192;
pub const max_topics_per_account: usize = 256;
pub const max_account_bytes: usize = 64;
pub const max_topic_bytes: usize = 128;

pub const Error = std.mem.Allocator.Error || error{
    InvalidAccount,
    InvalidTopic,
    TooManyAccounts,
    TooManyTopics,
};

const TopicSet = struct {
    topics: std.ArrayListUnmanaged([]const u8) = .empty,

    fn deinit(self: *TopicSet, allocator: std.mem.Allocator) void {
        for (self.topics.items) |topic| allocator.free(topic);
        self.topics.deinit(allocator);
    }

    fn find(self: *const TopicSet, topic: []const u8) ?usize {
        for (self.topics.items, 0..) |stored, i| {
            if (std.mem.eql(u8, stored, topic)) return i;
        }
        return null;
    }
};

pub const EventSubscription = struct {
    allocator: std.mem.Allocator,
    accounts: std.StringHashMap(TopicSet),

    pub fn init(allocator: std.mem.Allocator) EventSubscription {
        return .{ .allocator = allocator, .accounts = std.StringHashMap(TopicSet).init(allocator) };
    }

    pub fn deinit(self: *EventSubscription) void {
        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.accounts.deinit();
        self.* = undefined;
    }

    pub fn subscribe(self: *EventSubscription, account: []const u8, topic: []const u8) Error!bool {
        try validateAccount(account);
        try validateTopic(topic);

        const set = try self.ensureAccount(account);
        if (set.find(topic) != null) return false;
        if (set.topics.items.len >= max_topics_per_account) return error.TooManyTopics;

        const owned_topic = try self.allocator.dupe(u8, topic);
        errdefer self.allocator.free(owned_topic);
        try set.topics.append(self.allocator, owned_topic);
        return true;
    }

    pub fn unsubscribe(self: *EventSubscription, account: []const u8, topic: []const u8) bool {
        const entry = self.accounts.getEntry(account) orelse return false;
        const idx = entry.value_ptr.find(topic) orelse return false;
        self.allocator.free(entry.value_ptr.topics.items[idx]);
        _ = entry.value_ptr.topics.orderedRemove(idx);
        if (entry.value_ptr.topics.items.len == 0) {
            const key = entry.key_ptr.*;
            entry.value_ptr.deinit(self.allocator);
            self.accounts.removeByPtr(entry.key_ptr);
            self.allocator.free(key);
        }
        return true;
    }

    pub fn subscribed(self: *const EventSubscription, account: []const u8, topic: []const u8) bool {
        const set = self.accounts.getPtr(account) orelse return false;
        return set.find(topic) != null;
    }

    /// Returns borrowed topics for `account`, valid until the next mutation.
    pub fn list(self: *const EventSubscription, account: []const u8) []const []const u8 {
        const set = self.accounts.getPtr(account) orelse return &.{};
        return set.topics.items;
    }

    fn ensureAccount(self: *EventSubscription, account: []const u8) Error!*TopicSet {
        if (self.accounts.getPtr(account)) |set| return set;
        if (self.accounts.count() >= max_accounts) return error.TooManyAccounts;
        const owned_account = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(owned_account);
        try self.accounts.putNoClobber(owned_account, .{});
        return self.accounts.getPtr(account).?;
    }

    fn validateAccount(account: []const u8) Error!void {
        if (account.len == 0 or account.len > max_account_bytes) return error.InvalidAccount;
    }

    fn validateTopic(topic: []const u8) Error!void {
        if (topic.len == 0 or topic.len > max_topic_bytes) return error.InvalidTopic;
    }
};

const testing = std.testing;

test "subscribe is idempotent and queryable" {
    var subs = EventSubscription.init(testing.allocator);
    defer subs.deinit();

    try testing.expect(try subs.subscribe("alice", "message.create"));
    try testing.expect(!try subs.subscribe("alice", "message.create"));
    try testing.expect(subs.subscribed("alice", "message.create"));
    try testing.expect(!subs.subscribed("alice", "message.delete"));
}

test "unsubscribe removes topics and prunes empty accounts" {
    var subs = EventSubscription.init(testing.allocator);
    defer subs.deinit();

    _ = try subs.subscribe("alice", "a");
    _ = try subs.subscribe("alice", "b");
    try testing.expect(subs.unsubscribe("alice", "a"));
    try testing.expect(!subs.subscribed("alice", "a"));
    try testing.expectEqual(@as(usize, 1), subs.list("alice").len);
    try testing.expect(subs.unsubscribe("alice", "b"));
    try testing.expectEqual(@as(usize, 0), subs.list("alice").len);
}

test "list returns account-local topics in insertion order" {
    var subs = EventSubscription.init(testing.allocator);
    defer subs.deinit();

    _ = try subs.subscribe("alice", "one");
    _ = try subs.subscribe("alice", "two");
    _ = try subs.subscribe("bob", "other");
    const topics = subs.list("alice");
    try testing.expectEqual(@as(usize, 2), topics.len);
    try testing.expectEqualStrings("one", topics[0]);
    try testing.expectEqualStrings("two", topics[1]);
}

test "input caps reject invalid subscription data" {
    var subs = EventSubscription.init(testing.allocator);
    defer subs.deinit();

    try testing.expectError(error.InvalidAccount, subs.subscribe("", "topic"));
    try testing.expectError(error.InvalidTopic, subs.subscribe("alice", ""));
    try testing.expectError(error.InvalidTopic, subs.subscribe("alice", "x" ** (max_topic_bytes + 1)));
}

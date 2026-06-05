//! Per-channel activity-stream subscriptions (#33 `ACTIVITY SUBSCRIBE`).
//!
//! Tracks which clients have opted in to the real-time activity stream for a
//! channel (typing/reaction/presence pushes). Pure and self-contained: the
//! server keys subscribers by their flat u64 client id (the same packed id used
//! by MONITOR), so a disconnect drops the client from every channel via
//! `removeClient`. A flat per-channel list keeps ownership trivial — channels
//! and their subscriber counts are bounded by the caller's config.
const std = @import("std");

pub const ClientId = u64;

pub const Error = std.mem.Allocator.Error || error{ TooManyChannels, TooManySubscribers };

pub const Config = struct {
    max_channels: usize = 4096,
    max_subscribers_per_channel: usize = 1024,
};

const SubscriberList = struct {
    ids: std.ArrayListUnmanaged(ClientId) = .empty,

    fn deinit(self: *SubscriberList, allocator: std.mem.Allocator) void {
        self.ids.deinit(allocator);
    }

    fn find(self: *const SubscriberList, id: ClientId) ?usize {
        for (self.ids.items, 0..) |x, i| {
            if (x == id) return i;
        }
        return null;
    }
};

pub const SubscriptionStore = struct {
    allocator: std.mem.Allocator,
    cfg: Config,
    channels: std.StringHashMap(SubscriberList),

    pub fn init(allocator: std.mem.Allocator) SubscriptionStore {
        return initWithConfig(allocator, .{});
    }

    pub fn initWithConfig(allocator: std.mem.Allocator, cfg: Config) SubscriptionStore {
        return .{ .allocator = allocator, .cfg = cfg, .channels = std.StringHashMap(SubscriberList).init(allocator) };
    }

    pub fn deinit(self: *SubscriptionStore) void {
        var it = self.channels.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.channels.deinit();
        self.* = undefined;
    }

    /// Subscribe `id` to `channel`'s activity stream. Returns true if newly added
    /// (false if already subscribed). Idempotent.
    pub fn subscribe(self: *SubscriptionStore, channel: []const u8, id: ClientId) Error!bool {
        const list = try self.ensureChannel(channel);
        if (list.find(id) != null) return false;
        if (list.ids.items.len >= self.cfg.max_subscribers_per_channel) return error.TooManySubscribers;
        try list.ids.append(self.allocator, id);
        return true;
    }

    /// Unsubscribe `id` from `channel`. Returns true if it had been subscribed.
    pub fn unsubscribe(self: *SubscriptionStore, channel: []const u8, id: ClientId) bool {
        const entry = self.channels.getEntry(channel) orelse return false;
        const idx = entry.value_ptr.find(id) orelse return false;
        _ = entry.value_ptr.ids.swapRemove(idx);
        if (entry.value_ptr.ids.items.len == 0) self.dropChannel(entry);
        return true;
    }

    pub fn isSubscribed(self: *const SubscriptionStore, channel: []const u8, id: ClientId) bool {
        const list = self.channels.getPtr(channel) orelse return false;
        return list.find(id) != null;
    }

    /// Borrowed subscriber id list for `channel` (empty if none). Valid until the
    /// next mutation touching this channel.
    pub fn subscribers(self: *const SubscriptionStore, channel: []const u8) []const ClientId {
        const list = self.channels.getPtr(channel) orelse return &.{};
        return list.ids.items;
    }

    /// Drop `id` from every channel (call on disconnect).
    pub fn removeClient(self: *SubscriptionStore, id: ClientId) void {
        var empties: std.ArrayListUnmanaged([]const u8) = .empty;
        defer empties.deinit(self.allocator);
        var it = self.channels.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.find(id)) |idx| {
                _ = entry.value_ptr.ids.swapRemove(idx);
                if (entry.value_ptr.ids.items.len == 0) empties.append(self.allocator, entry.key_ptr.*) catch {};
            }
        }
        for (empties.items) |chan| {
            if (self.channels.getEntry(chan)) |e| self.dropChannel(e);
        }
    }

    fn ensureChannel(self: *SubscriptionStore, channel: []const u8) Error!*SubscriberList {
        if (self.channels.getPtr(channel)) |list| return list;
        if (self.channels.count() >= self.cfg.max_channels) return error.TooManyChannels;
        const owned = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(owned);
        try self.channels.putNoClobber(owned, .{});
        return self.channels.getPtr(channel).?;
    }

    fn dropChannel(self: *SubscriptionStore, entry: std.StringHashMap(SubscriberList).Entry) void {
        const owned_key = entry.key_ptr.*;
        entry.value_ptr.deinit(self.allocator);
        self.channels.removeByPtr(entry.key_ptr);
        self.allocator.free(owned_key);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "subscribe is idempotent and reflected by isSubscribed" {
    var store = SubscriptionStore.init(testing.allocator);
    defer store.deinit();
    try testing.expect(try store.subscribe("#chat", 1));
    try testing.expect(!try store.subscribe("#chat", 1)); // already there
    try testing.expect(try store.subscribe("#chat", 2));
    try testing.expect(store.isSubscribed("#chat", 1));
    try testing.expectEqual(@as(usize, 2), store.subscribers("#chat").len);
}

test "unsubscribe removes and prunes empty channels" {
    var store = SubscriptionStore.init(testing.allocator);
    defer store.deinit();
    _ = try store.subscribe("#chat", 1);
    try testing.expect(store.unsubscribe("#chat", 1));
    try testing.expect(!store.unsubscribe("#chat", 1)); // already gone
    try testing.expect(!store.isSubscribed("#chat", 1));
    try testing.expectEqual(@as(usize, 0), store.subscribers("#chat").len);
}

test "removeClient drops the client from every channel" {
    var store = SubscriptionStore.init(testing.allocator);
    defer store.deinit();
    _ = try store.subscribe("#a", 7);
    _ = try store.subscribe("#b", 7);
    _ = try store.subscribe("#b", 8);
    store.removeClient(7);
    try testing.expect(!store.isSubscribed("#a", 7));
    try testing.expect(!store.isSubscribed("#b", 7));
    try testing.expect(store.isSubscribed("#b", 8)); // others unaffected
    try testing.expectEqual(@as(usize, 0), store.subscribers("#a").len);
}

test "per-channel subscriber cap is enforced" {
    var store = SubscriptionStore.initWithConfig(testing.allocator, .{ .max_subscribers_per_channel = 2 });
    defer store.deinit();
    _ = try store.subscribe("#x", 1);
    _ = try store.subscribe("#x", 2);
    try testing.expectError(error.TooManySubscribers, store.subscribe("#x", 3));
}

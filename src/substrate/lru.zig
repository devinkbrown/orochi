// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Generic capacity-bounded LRU cache.
//!
//! The cache stores one intrusive doubly-linked node per entry and keeps a hash
//! map from keys to nodes. The list head is the most recently used entry and the
//! tail is the least recently used entry.
const std = @import("std");

/// A generic least-recently-used cache.
///
/// `K` must be usable with `std.AutoHashMap`.
pub fn LruCache(comptime K: type, comptime V: type) type {
    return struct {
        const Self = @This();

        const Node = struct {
            key: K,
            value: V,
            prev: ?*Node = null,
            next: ?*Node = null,
        };

        const Map = std.AutoHashMap(K, *Node);

        /// One entry removed from the cache by eviction or explicit removal.
        pub const Entry = struct {
            key: K,
            value: V,
        };

        allocator: std.mem.Allocator,
        capacity: usize,
        map: Map,
        head: ?*Node = null,
        tail: ?*Node = null,

        /// Create an empty cache with a fixed maximum number of entries.
        pub fn init(allocator: std.mem.Allocator, capacity: usize) Self {
            return .{
                .allocator = allocator,
                .capacity = capacity,
                .map = Map.init(allocator),
            };
        }

        /// Free cache bookkeeping storage.
        ///
        /// Keys and values are returned by value on eviction/removal. If either
        /// type owns memory, callers are responsible for removing entries before
        /// `deinit` or otherwise managing that ownership externally.
        pub fn deinit(self: *Self) void {
            var node = self.head;
            while (node) |current| {
                const next = current.next;
                self.allocator.destroy(current);
                node = next;
            }

            self.map.deinit();
            self.* = .{
                .allocator = self.allocator,
                .capacity = self.capacity,
                .map = Map.init(self.allocator),
            };
        }

        /// Number of entries currently cached.
        pub fn len(self: *const Self) usize {
            return self.map.count();
        }

        /// Look up a key and make it the most recently used entry when present.
        pub fn get(self: *Self, key: K) ?*V {
            const node = self.map.get(key) orelse return null;
            self.moveToFront(node);
            return &node.value;
        }

        /// Insert or update an entry.
        ///
        /// Updating an existing key changes its value and makes it most recent.
        /// Inserting into a full cache evicts and returns the least recently
        /// used entry. A zero-capacity cache stores nothing and returns the
        /// attempted insertion as the evicted entry.
        pub fn put(self: *Self, key: K, value: V) !?Entry {
            if (self.map.get(key)) |node| {
                node.value = value;
                self.moveToFront(node);
                return null;
            }

            if (self.capacity == 0) {
                return .{ .key = key, .value = value };
            }

            var evicted: ?Entry = null;
            if (self.len() == self.capacity) {
                evicted = self.evictTail();
            }

            errdefer if (evicted) |entry| {
                const restored = self.allocator.create(Node) catch @panic("failed to restore evicted LRU entry");
                restored.* = .{ .key = entry.key, .value = entry.value };
                self.pushBack(restored);
                self.map.putAssumeCapacity(entry.key, restored);
            };

            const node = try self.allocator.create(Node);
            errdefer self.allocator.destroy(node);

            node.* = .{ .key = key, .value = value };
            try self.map.put(key, node);
            self.pushFront(node);

            return evicted;
        }

        /// Remove a key from the cache and return the removed entry.
        pub fn remove(self: *Self, key: K) ?Entry {
            const removed = self.map.fetchRemove(key) orelse return null;
            const node = removed.value;
            const entry = Entry{ .key = node.key, .value = node.value };

            self.unlink(node);
            self.allocator.destroy(node);
            return entry;
        }

        fn evictTail(self: *Self) Entry {
            const node = self.tail.?;
            _ = self.map.remove(node.key);

            const entry = Entry{ .key = node.key, .value = node.value };
            self.unlink(node);
            self.allocator.destroy(node);
            return entry;
        }

        fn moveToFront(self: *Self, node: *Node) void {
            if (self.head == node) return;
            self.unlink(node);
            self.pushFront(node);
        }

        fn pushFront(self: *Self, node: *Node) void {
            node.prev = null;
            node.next = self.head;

            if (self.head) |old_head| {
                old_head.prev = node;
            } else {
                self.tail = node;
            }

            self.head = node;
        }

        fn pushBack(self: *Self, node: *Node) void {
            node.prev = self.tail;
            node.next = null;

            if (self.tail) |old_tail| {
                old_tail.next = node;
            } else {
                self.head = node;
            }

            self.tail = node;
        }

        fn unlink(self: *Self, node: *Node) void {
            if (node.prev) |prev| {
                prev.next = node.next;
            } else {
                self.head = node.next;
            }

            if (node.next) |next| {
                next.prev = node.prev;
            } else {
                self.tail = node.prev;
            }

            node.prev = null;
            node.next = null;
        }
    };
}

test "put over capacity evicts least recently used entry" {
    const Cache = LruCache(u32, u32);
    var cache = Cache.init(std.testing.allocator, 2);
    defer cache.deinit();

    try std.testing.expectEqual(@as(?Cache.Entry, null), try cache.put(1, 10));
    try std.testing.expectEqual(@as(?Cache.Entry, null), try cache.put(2, 20));

    const evicted = (try cache.put(3, 30)).?;
    try std.testing.expectEqual(@as(u32, 1), evicted.key);
    try std.testing.expectEqual(@as(u32, 10), evicted.value);
    try std.testing.expectEqual(@as(usize, 2), cache.len());
    try std.testing.expectEqual(@as(?*u32, null), cache.get(1));
    try std.testing.expectEqual(@as(u32, 20), cache.get(2).?.*);
    try std.testing.expectEqual(@as(u32, 30), cache.get(3).?.*);
}

test "get updates recency before the next eviction" {
    const Cache = LruCache(u32, []const u8);
    var cache = Cache.init(std.testing.allocator, 2);
    defer cache.deinit();

    try std.testing.expectEqual(@as(?Cache.Entry, null), try cache.put(1, "one"));
    try std.testing.expectEqual(@as(?Cache.Entry, null), try cache.put(2, "two"));
    try std.testing.expectEqualStrings("one", cache.get(1).?.*);

    const evicted = (try cache.put(3, "three")).?;
    try std.testing.expectEqual(@as(u32, 2), evicted.key);
    try std.testing.expectEqualStrings("two", evicted.value);
    try std.testing.expectEqualStrings("one", cache.get(1).?.*);
    try std.testing.expectEqualStrings("three", cache.get(3).?.*);
}

test "update existing key changes value and keeps capacity" {
    const Cache = LruCache(u8, u64);
    var cache = Cache.init(std.testing.allocator, 2);
    defer cache.deinit();

    try std.testing.expectEqual(@as(?Cache.Entry, null), try cache.put(1, 10));
    try std.testing.expectEqual(@as(?Cache.Entry, null), try cache.put(2, 20));
    try std.testing.expectEqual(@as(?Cache.Entry, null), try cache.put(1, 100));
    try std.testing.expectEqual(@as(usize, 2), cache.len());
    try std.testing.expectEqual(@as(u64, 100), cache.get(1).?.*);

    const evicted = (try cache.put(3, 30)).?;
    try std.testing.expectEqual(@as(u8, 2), evicted.key);
    try std.testing.expectEqual(@as(u64, 20), evicted.value);
    try std.testing.expectEqual(@as(?*u64, null), cache.get(2));
}

test "remove unlinks entries and returns the removed value" {
    const Cache = LruCache(u32, i32);
    var cache = Cache.init(std.testing.allocator, 3);
    defer cache.deinit();

    try std.testing.expectEqual(@as(?Cache.Entry, null), try cache.put(1, -1));
    try std.testing.expectEqual(@as(?Cache.Entry, null), try cache.put(2, -2));
    try std.testing.expectEqual(@as(?Cache.Entry, null), try cache.put(3, -3));

    const removed = cache.remove(2).?;
    try std.testing.expectEqual(@as(u32, 2), removed.key);
    try std.testing.expectEqual(@as(i32, -2), removed.value);
    try std.testing.expectEqual(@as(usize, 2), cache.len());
    try std.testing.expectEqual(@as(?Cache.Entry, null), cache.remove(2));

    try std.testing.expectEqual(@as(?Cache.Entry, null), try cache.put(4, -4));

    const evicted = (try cache.put(5, -5)).?;
    try std.testing.expectEqual(@as(u32, 1), evicted.key);
    try std.testing.expectEqual(@as(i32, -1), evicted.value);
    try std.testing.expectEqual(@as(i32, -3), cache.get(3).?.*);
    try std.testing.expectEqual(@as(i32, -4), cache.get(4).?.*);
    try std.testing.expectEqual(@as(i32, -5), cache.get(5).?.*);
}

test "eviction order is deterministic after repeated recency changes" {
    const Cache = LruCache(u32, u32);
    var cache = Cache.init(std.testing.allocator, 3);
    defer cache.deinit();

    try std.testing.expectEqual(@as(?Cache.Entry, null), try cache.put(1, 10));
    try std.testing.expectEqual(@as(?Cache.Entry, null), try cache.put(2, 20));
    try std.testing.expectEqual(@as(?Cache.Entry, null), try cache.put(3, 30));

    try std.testing.expectEqual(@as(u32, 10), cache.get(1).?.*);
    try std.testing.expectEqual(@as(u32, 20), cache.get(2).?.*);
    try std.testing.expectEqual(@as(u32, 10), cache.get(1).?.*);

    const first = (try cache.put(4, 40)).?;
    try std.testing.expectEqual(@as(u32, 3), first.key);
    try std.testing.expectEqual(@as(u32, 30), first.value);

    const second = (try cache.put(5, 50)).?;
    try std.testing.expectEqual(@as(u32, 2), second.key);
    try std.testing.expectEqual(@as(u32, 20), second.value);

    try std.testing.expectEqual(@as(u32, 10), cache.get(1).?.*);
    try std.testing.expectEqual(@as(u32, 40), cache.get(4).?.*);
    try std.testing.expectEqual(@as(u32, 50), cache.get(5).?.*);
}

test "zero capacity cache stores nothing and returns attempted insert" {
    const Cache = LruCache(u32, u32);
    var cache = Cache.init(std.testing.allocator, 0);
    defer cache.deinit();

    const evicted = (try cache.put(7, 70)).?;
    try std.testing.expectEqual(@as(u32, 7), evicted.key);
    try std.testing.expectEqual(@as(u32, 70), evicted.value);
    try std.testing.expectEqual(@as(usize, 0), cache.len());
    try std.testing.expectEqual(@as(?*u32, null), cache.get(7));
    try std.testing.expectEqual(@as(?Cache.Entry, null), cache.remove(7));
}

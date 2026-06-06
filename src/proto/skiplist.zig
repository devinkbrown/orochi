//! Probabilistic ordered map from `u64` keys to caller-selected values.
//!
//! The structure owns every node it allocates. Values are copied into nodes and
//! copied back out on update/removal; if a value itself owns resources, the
//! caller remains responsible for cleaning up replaced or removed values.
const std = @import("std");

/// Compile-time bounds for a skip-list map.
pub const Params = struct {
    /// Maximum number of forward levels stored in each node.
    max_level: usize = 16,
    /// Maximum number of key/value entries retained by the map.
    max_items: usize = std.math.maxInt(usize),
};

/// Errors returned by skip-list insertion.
pub const SkipListError = std.mem.Allocator.Error || error{
    TooManyItems,
};

/// Key/value pair yielded by ordered iteration.
pub fn Entry(comptime Value: type) type {
    return struct {
        /// Ordered map key.
        key: u64,
        /// Value stored for `key`.
        value: Value,
    };
}

/// Return the default skip-list map type for `Value`.
pub fn DefaultMap(comptime Value: type) type {
    return SkipList(Value, .{});
}

/// Return a skip-list map type for `Value` and caller-selected bounds.
pub fn SkipList(comptime Value: type, comptime params: Params) type {
    comptime {
        if (@sizeOf(usize) != 8) @compileError("skip-list map requires a 64-bit target");
        if (params.max_level == 0) @compileError("skip-list map needs at least one level");
        if (params.max_items == 0) @compileError("skip-list map needs item storage");
    }

    return struct {
        const Self = @This();

        const Node = struct {
            key: u64,
            value: Value,
            height: usize,
            next: [params.max_level]?*Node,

            fn init(key: u64, value: Value, height: usize) Node {
                return .{
                    .key = key,
                    .value = value,
                    .height = height,
                    .next = .{null} ** params.max_level,
                };
            }
        };

        /// In-order map iterator.
        pub const Iterator = struct {
            next_node: ?*const Node,

            /// Return the next key/value pair, or null after the last entry.
            pub fn next(self: *Iterator) ?Entry(Value) {
                const node = self.next_node orelse return null;
                self.next_node = node.next[0];
                return .{ .key = node.key, .value = node.value };
            }
        };

        /// Insertion error set for this map type.
        pub const Error = SkipListError;

        allocator: std.mem.Allocator,
        heads: [params.max_level]?*Node,
        active_levels: usize,
        count: usize,

        /// Initialize an empty map using `allocator` for owned nodes.
        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .allocator = allocator,
                .heads = .{null} ** params.max_level,
                .active_levels = 1,
                .count = 0,
            };
        }

        /// Destroy every owned node and release internal allocations.
        pub fn deinit(self: *Self) void {
            self.clear();
            self.* = undefined;
        }

        /// Remove every entry while retaining no owned nodes.
        pub fn clear(self: *Self) void {
            var cursor = self.heads[0];
            while (cursor) |node| {
                cursor = node.next[0];
                self.allocator.destroy(node);
            }

            self.heads = .{null} ** params.max_level;
            self.active_levels = 1;
            self.count = 0;
        }

        /// Return the number of entries currently stored.
        pub fn len(self: *const Self) usize {
            return self.count;
        }

        /// Return true when the map contains no entries.
        pub fn isEmpty(self: *const Self) bool {
            return self.count == 0;
        }

        /// Insert or replace `key` using a deterministic level from `random`.
        ///
        /// Returns the previous value when `key` already existed, or null when
        /// a new owned node was inserted.
        pub fn insert(self: *Self, random: std.Random, key: u64, value: Value) Error!?Value {
            var update: [params.max_level]?*Node = .{null} ** params.max_level;
            if (self.findUpdate(key, &update)) |node| {
                const old = node.value;
                node.value = value;
                return old;
            }

            if (self.count >= params.max_items) return error.TooManyItems;

            const height = randomLevel(random);
            const node = try self.allocator.create(Node);
            node.* = Node.init(key, value, height);

            var level: usize = 0;
            while (level < height) : (level += 1) {
                const slot = self.linkSlot(update[level], level);
                node.next[level] = slot.*;
                slot.* = node;
            }

            if (height > self.active_levels) self.active_levels = height;
            self.count += 1;
            return null;
        }

        /// Return a read-only pointer to the value for `key`, or null.
        pub fn get(self: *const Self, key: u64) ?*const Value {
            const node = self.findNode(key) orelse return null;
            return &node.value;
        }

        /// Return a mutable pointer to the value for `key`, or null.
        pub fn getPtr(self: *Self, key: u64) ?*Value {
            const node = self.findNodeMut(key) orelse return null;
            return &node.value;
        }

        /// Remove `key` and return its value, or null when absent.
        pub fn remove(self: *Self, key: u64) ?Value {
            var update: [params.max_level]?*Node = .{null} ** params.max_level;
            const node = self.findUpdate(key, &update) orelse return null;

            var level: usize = 0;
            while (level < self.active_levels) : (level += 1) {
                const slot = self.linkSlot(update[level], level);
                if (slot.* == node) slot.* = node.next[level];
            }

            while (self.active_levels > 1 and self.heads[self.active_levels - 1] == null) {
                self.active_levels -= 1;
            }

            const value = node.value;
            self.allocator.destroy(node);
            self.count -= 1;
            return value;
        }

        /// Return an iterator over key/value pairs in ascending key order.
        pub fn iterator(self: *const Self) Iterator {
            return .{ .next_node = self.heads[0] };
        }

        fn findUpdate(self: *Self, key: u64, update: *[params.max_level]?*Node) ?*Node {
            var predecessor: ?*Node = null;
            var level = self.active_levels;
            while (level > 0) {
                level -= 1;
                var slot = self.linkSlot(predecessor, level);
                while (slot.*) |next| {
                    if (next.key >= key) break;
                    predecessor = next;
                    slot = &next.next[level];
                }
                update[level] = predecessor;
            }

            const candidate = self.linkSlot(predecessor, 0).*;
            if (candidate) |node| {
                if (node.key == key) return node;
            }
            return null;
        }

        fn findNode(self: *const Self, key: u64) ?*const Node {
            var predecessor: ?*const Node = null;
            var level = self.active_levels;
            while (level > 0) {
                level -= 1;
                var next = self.constLink(predecessor, level);
                while (next) |node| {
                    if (node.key >= key) break;
                    predecessor = node;
                    next = node.next[level];
                }
            }

            const candidate = self.constLink(predecessor, 0);
            if (candidate) |node| {
                if (node.key == key) return node;
            }
            return null;
        }

        fn findNodeMut(self: *Self, key: u64) ?*Node {
            var update: [params.max_level]?*Node = .{null} ** params.max_level;
            return self.findUpdate(key, &update);
        }

        fn linkSlot(self: *Self, predecessor: ?*Node, level: usize) *?*Node {
            if (predecessor) |node| return &node.next[level];
            return &self.heads[level];
        }

        fn constLink(self: *const Self, predecessor: ?*const Node, level: usize) ?*const Node {
            if (predecessor) |node| return node.next[level];
            return self.heads[level];
        }

        fn randomLevel(random: std.Random) usize {
            var level: usize = 1;
            while (level < params.max_level and random.boolean()) : (level += 1) {}
            return level;
        }
    };
}

test "ordered iteration returns keys in ascending order" {
    // Arrange.
    const testing = std.testing;
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x5a17_cafe_1001);
    var map = DefaultMap(u32).init(allocator);
    defer map.deinit();

    const keys = [_]u64{ 40, 10, 50, 20, 30 };
    for (keys, 0..) |key, index| {
        _ = try map.insert(prng.random(), key, @intCast(index + 1));
    }

    // Act.
    var iterator = map.iterator();
    var seen: [keys.len]u64 = undefined;
    var count: usize = 0;
    while (iterator.next()) |entry| {
        seen[count] = entry.key;
        count += 1;
    }

    // Assert.
    try testing.expectEqual(@as(usize, keys.len), count);
    try testing.expectEqualSlices(u64, &.{ 10, 20, 30, 40, 50 }, seen[0..count]);
}

test "get and remove find existing keys and ignore missing keys" {
    // Arrange.
    const testing = std.testing;
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x5a17_cafe_2002);
    var map = DefaultMap(u64).init(allocator);
    defer map.deinit();

    _ = try map.insert(prng.random(), 8, 80);
    _ = try map.insert(prng.random(), 3, 30);
    _ = try map.insert(prng.random(), 11, 110);

    // Act.
    const before = map.get(3);
    const removed = map.remove(3);
    const after = map.get(3);
    const missing = map.remove(99);

    // Assert.
    try testing.expectEqual(@as(u64, 30), before.?.*);
    try testing.expectEqual(@as(?u64, 30), removed);
    try testing.expectEqual(@as(?*const u64, null), after);
    try testing.expectEqual(@as(?u64, null), missing);
    try testing.expectEqual(@as(usize, 2), map.len());
}

test "duplicate key insert updates value without growing map" {
    // Arrange.
    const testing = std.testing;
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x5a17_cafe_3003);
    var map = DefaultMap(u32).init(allocator);
    defer map.deinit();

    const first = try map.insert(prng.random(), 7, 11);

    // Act.
    const second = try map.insert(prng.random(), 7, 22);
    const current = map.get(7);

    // Assert.
    try testing.expectEqual(@as(?u32, null), first);
    try testing.expectEqual(@as(?u32, 11), second);
    try testing.expectEqual(@as(u32, 22), current.?.*);
    try testing.expectEqual(@as(usize, 1), map.len());
}

test "clear and deinit release owned nodes without leaks" {
    // Arrange.
    const testing = std.testing;
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x5a17_cafe_4004);
    var map = SkipList(u16, .{ .max_level = 8, .max_items = 32 }).init(allocator);
    defer map.deinit();

    var key: u64 = 0;
    while (key < 32) : (key += 1) {
        _ = try map.insert(prng.random(), 1_000 - key, @intCast(key));
    }

    // Act.
    map.clear();

    // Assert.
    try testing.expect(map.isEmpty());
    try testing.expectEqual(@as(?*const u16, null), map.get(1_000));
}

test "max item limit rejects new keys but allows duplicate updates" {
    // Arrange.
    const testing = std.testing;
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x5a17_cafe_5005);
    var map = SkipList(u8, .{ .max_level = 4, .max_items = 1 }).init(allocator);
    defer map.deinit();

    _ = try map.insert(prng.random(), 1, 10);

    // Act.
    const replaced = try map.insert(prng.random(), 1, 20);
    const overflow = map.insert(prng.random(), 2, 30);

    // Assert.
    try testing.expectEqual(@as(?u8, 10), replaced);
    try testing.expectError(error.TooManyItems, overflow);
    try testing.expectEqual(@as(usize, 1), map.len());
    try testing.expectEqual(@as(u8, 20), map.get(1).?.*);
}

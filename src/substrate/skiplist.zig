// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

const std = @import("std");

pub fn SkipList(comptime Value: type) type {
    return struct {
        const Self = @This();
        const MaxLevel = 32;

        pub const Entry = struct {
            key: u64,
            value: Value,
        };

        pub const LevelEntry = struct {
            key: u64,
            level: usize,
        };

        const Node = struct {
            key: u64,
            value: Value,
            forwards: []?*Node,
        };

        pub const Iterator = struct {
            next_node: ?*Node,

            pub fn next(self: *Iterator) ?Entry {
                const node = self.next_node orelse return null;
                self.next_node = node.forwards[0];
                return .{ .key = node.key, .value = node.value };
            }
        };

        allocator: std.mem.Allocator,
        head: *Node,
        rng: SplitMix64,
        level: usize,
        len: usize,

        pub fn init(allocator: std.mem.Allocator, seed: u64) !Self {
            const head = try createNode(allocator, MaxLevel, 0, undefined);
            return .{
                .allocator = allocator,
                .head = head,
                .rng = .{ .state = seed },
                .level = 1,
                .len = 0,
            };
        }

        pub fn deinit(self: *Self) void {
            var node = self.head.forwards[0];
            while (node) |current| {
                const next_node = current.forwards[0];
                destroyNode(self.allocator, current);
                node = next_node;
            }
            destroyNode(self.allocator, self.head);
            self.* = undefined;
        }

        pub fn count(self: *const Self) usize {
            return self.len;
        }

        pub fn currentLevel(self: *const Self) usize {
            return self.level;
        }

        pub fn insert(self: *Self, key: u64, value: Value) !void {
            var update: [MaxLevel]*Node = undefined;
            var current = self.head;

            var i = self.level;
            while (i > 0) {
                i -= 1;
                while (current.forwards[i]) |next_node| {
                    if (next_node.key >= key) break;
                    current = next_node;
                }
                update[i] = current;
            }

            if (update[0].forwards[0]) |existing| {
                if (existing.key == key) {
                    existing.value = value;
                    return;
                }
            }

            const node_level = self.randomLevel();
            if (node_level > self.level) {
                var fill = self.level;
                while (fill < node_level) : (fill += 1) {
                    update[fill] = self.head;
                }
                self.level = node_level;
            }

            const node = try createNode(self.allocator, node_level, key, value);
            var link: usize = 0;
            while (link < node_level) : (link += 1) {
                node.forwards[link] = update[link].forwards[link];
                update[link].forwards[link] = node;
            }

            self.len += 1;
        }

        pub fn get(self: *const Self, key: u64) ?Value {
            const node = self.findGreaterOrEqual(key) orelse return null;
            if (node.key == key) return node.value;
            return null;
        }

        pub fn getPtr(self: *Self, key: u64) ?*Value {
            const node = self.findGreaterOrEqual(key) orelse return null;
            if (node.key == key) return &node.value;
            return null;
        }

        pub fn remove(self: *Self, key: u64) ?Value {
            var update: [MaxLevel]*Node = undefined;
            var current = self.head;

            var i = self.level;
            while (i > 0) {
                i -= 1;
                while (current.forwards[i]) |next_node| {
                    if (next_node.key >= key) break;
                    current = next_node;
                }
                update[i] = current;
            }

            const victim = update[0].forwards[0] orelse return null;
            if (victim.key != key) return null;

            var link: usize = 0;
            while (link < self.level) : (link += 1) {
                if (update[link].forwards[link] != victim) break;
                update[link].forwards[link] = victim.forwards[link];
            }

            const value = victim.value;
            destroyNode(self.allocator, victim);
            self.len -= 1;

            while (self.level > 1 and self.head.forwards[self.level - 1] == null) {
                self.level -= 1;
            }

            return value;
        }

        pub fn iterator(self: *const Self) Iterator {
            return .{ .next_node = self.head.forwards[0] };
        }

        pub fn rangeQuery(
            self: *const Self,
            allocator: std.mem.Allocator,
            lo: u64,
            hi: u64,
        ) ![]Entry {
            var entries: std.ArrayList(Entry) = .empty;
            errdefer entries.deinit(allocator);

            if (lo > hi) return entries.toOwnedSlice(allocator);

            var node = self.findGreaterOrEqual(lo);
            while (node) |current| {
                if (current.key > hi) break;
                try entries.append(allocator, .{
                    .key = current.key,
                    .value = current.value,
                });
                node = current.forwards[0];
            }

            return entries.toOwnedSlice(allocator);
        }

        pub fn levelOf(self: *const Self, key: u64) ?usize {
            const node = self.findGreaterOrEqual(key) orelse return null;
            if (node.key == key) return node.forwards.len;
            return null;
        }

        pub fn levelEntries(self: *const Self, allocator: std.mem.Allocator) ![]LevelEntry {
            var levels: std.ArrayList(LevelEntry) = .empty;
            errdefer levels.deinit(allocator);

            var node = self.head.forwards[0];
            while (node) |current| {
                try levels.append(allocator, .{
                    .key = current.key,
                    .level = current.forwards.len,
                });
                node = current.forwards[0];
            }

            return levels.toOwnedSlice(allocator);
        }

        pub fn structureFingerprint(self: *const Self) u64 {
            var hash = SplitMix64{ .state = 0x9e37_79b9_7f4a_7c15 };
            var out = hash.next() ^ @as(u64, self.level) ^ (@as(u64, self.len) << 32);

            var node = self.head.forwards[0];
            while (node) |current| {
                out ^= mix(current.key);
                out = std.math.rotl(u64, out, 17) ^ mix(@intCast(current.forwards.len));
                node = current.forwards[0];
            }

            return out;
        }

        pub fn validate(self: *const Self) !void {
            if (self.level == 0 or self.level > MaxLevel) return error.InvalidLevel;
            if (self.head.forwards.len != MaxLevel) return error.InvalidHeadLevel;

            var seen: usize = 0;
            var previous: ?u64 = null;
            var node = self.head.forwards[0];
            while (node) |current| {
                if (current.forwards.len == 0 or current.forwards.len > MaxLevel) {
                    return error.InvalidNodeLevel;
                }
                if (previous) |prev_key| {
                    if (prev_key >= current.key) return error.OutOfOrder;
                }
                previous = current.key;
                seen += 1;
                node = current.forwards[0];
            }

            if (seen != self.len) return error.LengthMismatch;

            var level_index: usize = 1;
            while (level_index < self.level) : (level_index += 1) {
                previous = null;
                node = self.head.forwards[level_index];
                while (node) |current| {
                    if (current.forwards.len <= level_index) return error.ShortNodeLinkedHigh;
                    if (previous) |prev_key| {
                        if (prev_key >= current.key) return error.OutOfOrder;
                    }
                    previous = current.key;
                    node = current.forwards[level_index];
                }
            }

            var trim = self.level;
            while (trim > 1) {
                if (self.head.forwards[trim - 1] != null) break;
                trim -= 1;
            }
            if (trim != self.level) return error.UntrimmedLevel;
        }

        fn findGreaterOrEqual(self: *const Self, key: u64) ?*Node {
            var current = self.head;

            var i = self.level;
            while (i > 0) {
                i -= 1;
                while (current.forwards[i]) |next_node| {
                    if (next_node.key >= key) break;
                    current = next_node;
                }
            }

            return current.forwards[0];
        }

        fn randomLevel(self: *Self) usize {
            var node_level: usize = 1;
            while (node_level < MaxLevel) : (node_level += 1) {
                if ((self.rng.next() & 1) == 0) break;
            }
            return node_level;
        }

        fn createNode(
            allocator: std.mem.Allocator,
            node_level: usize,
            key: u64,
            value: Value,
        ) !*Node {
            std.debug.assert(node_level > 0 and node_level <= MaxLevel);

            const node = try allocator.create(Node);
            errdefer allocator.destroy(node);

            const forwards = try allocator.alloc(?*Node, node_level);
            for (forwards) |*slot| slot.* = null;

            node.* = .{
                .key = key,
                .value = value,
                .forwards = forwards,
            };
            return node;
        }

        fn destroyNode(allocator: std.mem.Allocator, node: *Node) void {
            allocator.free(node.forwards);
            allocator.destroy(node);
        }
    };
}

const SplitMix64 = struct {
    state: u64,

    fn next(self: *SplitMix64) u64 {
        self.state +%= 0x9e37_79b9_7f4a_7c15;
        return mix(self.state);
    }
};

fn mix(input: u64) u64 {
    var z = input;
    z = (z ^ (z >> 30)) *% 0xbf58_476d_1ce4_e5b9;
    z = (z ^ (z >> 27)) *% 0x94d0_49bb_1331_11eb;
    return z ^ (z >> 31);
}

test "ordered iteration" {
    const testing = std.testing;
    var list = try SkipList(u64).init(testing.allocator, 0x1234);
    defer list.deinit();

    try list.insert(50, 500);
    try list.insert(10, 100);
    try list.insert(40, 400);
    try list.insert(20, 200);
    try list.insert(30, 300);

    var it = list.iterator();
    const expected = [_]u64{ 10, 20, 30, 40, 50 };
    var index: usize = 0;
    while (it.next()) |entry| {
        try testing.expect(index < expected.len);
        try testing.expectEqual(expected[index], entry.key);
        try testing.expectEqual(expected[index] * 10, entry.value);
        index += 1;
    }
    try testing.expectEqual(expected.len, index);
    try list.validate();
}

test "get and remove" {
    const testing = std.testing;
    var list = try SkipList(u64).init(testing.allocator, 9);
    defer list.deinit();

    try testing.expectEqual(@as(?u64, null), list.get(7));
    try list.insert(7, 70);
    try list.insert(3, 30);
    try list.insert(11, 110);

    try testing.expectEqual(@as(?u64, 70), list.get(7));
    try testing.expectEqual(@as(?u64, 30), list.remove(3));
    try testing.expectEqual(@as(?u64, null), list.get(3));
    try testing.expectEqual(@as(?u64, null), list.remove(3));
    try testing.expectEqual(@as(usize, 2), list.count());
    try list.validate();
}

test "range query bounds" {
    const testing = std.testing;
    var list = try SkipList(u64).init(testing.allocator, 22);
    defer list.deinit();

    for (0..10) |i| {
        const key: u64 = @intCast(i * 10);
        try list.insert(key, key + 1);
    }

    const entries = try list.rangeQuery(testing.allocator, 15, 55);
    defer testing.allocator.free(entries);

    const expected = [_]u64{ 20, 30, 40, 50 };
    try testing.expectEqual(expected.len, entries.len);
    for (expected, entries) |key, entry| {
        try testing.expectEqual(key, entry.key);
        try testing.expectEqual(key + 1, entry.value);
    }

    const empty = try list.rangeQuery(testing.allocator, 80, 70);
    defer testing.allocator.free(empty);
    try testing.expectEqual(@as(usize, 0), empty.len);
    try list.validate();
}

test "duplicate key update" {
    const testing = std.testing;
    var list = try SkipList(u64).init(testing.allocator, 77);
    defer list.deinit();

    try list.insert(42, 1);
    const before_level = list.levelOf(42).?;
    const before_fingerprint = list.structureFingerprint();

    try list.insert(42, 2);

    try testing.expectEqual(@as(?u64, 2), list.get(42));
    try testing.expectEqual(@as(usize, 1), list.count());
    try testing.expectEqual(before_level, list.levelOf(42).?);
    try testing.expectEqual(before_fingerprint, list.structureFingerprint());
    try list.validate();
}

test "deterministic structure given seed" {
    const testing = std.testing;
    var a = try SkipList(u64).init(testing.allocator, 0xfeed_face_cafe_beef);
    defer a.deinit();
    var b = try SkipList(u64).init(testing.allocator, 0xfeed_face_cafe_beef);
    defer b.deinit();

    const keys = [_]u64{ 91, 7, 52, 1000, 18, 64, 2, 39, 450, 88, 123 };
    for (keys) |key| {
        try a.insert(key, key * 3);
        try b.insert(key, key * 3);
    }

    const a_levels = try a.levelEntries(testing.allocator);
    defer testing.allocator.free(a_levels);
    const b_levels = try b.levelEntries(testing.allocator);
    defer testing.allocator.free(b_levels);

    try testing.expectEqual(a_levels.len, b_levels.len);
    for (a_levels, b_levels) |left, right| {
        try testing.expectEqual(left.key, right.key);
        try testing.expectEqual(left.level, right.level);
    }
    try testing.expectEqual(a.structureFingerprint(), b.structureFingerprint());
    try a.validate();
    try b.validate();
}

test "stress insert remove keeps invariants" {
    const testing = std.testing;
    var list = try SkipList(u64).init(testing.allocator, 0xabc);
    defer list.deinit();

    var rng = SplitMix64{ .state = 0xdecaf_bad };
    var present = [_]bool{false} ** 512;

    for (0..2000) |step| {
        const key: u64 = @intCast(rng.next() % present.len);
        if ((rng.next() & 3) == 0) {
            const removed = list.remove(key);
            if (present[@intCast(key)]) {
                try testing.expect(removed != null);
                present[@intCast(key)] = false;
            } else {
                try testing.expectEqual(@as(?u64, null), removed);
            }
        } else {
            try list.insert(key, @as(u64, @intCast(step)));
            present[@intCast(key)] = true;
        }

        if ((step % 37) == 0) try list.validate();
    }

    try list.validate();

    var count: usize = 0;
    var last: ?u64 = null;
    var it = list.iterator();
    while (it.next()) |entry| {
        if (last) |previous| try testing.expect(previous < entry.key);
        last = entry.key;
        try testing.expect(present[@intCast(entry.key)]);
        count += 1;
    }

    var expected_count: usize = 0;
    for (present) |is_present| {
        if (is_present) expected_count += 1;
    }
    try testing.expectEqual(expected_count, count);
}

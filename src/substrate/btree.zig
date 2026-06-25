// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

const std = @import("std");

pub fn BTreeMap(comptime K: type, comptime V: type, comptime branching_factor: usize) type {
    if (branching_factor < 4) {
        @compileError("BTreeMap branching_factor must be at least 4");
    }

    return struct {
        const Self = @This();
        const Allocator = std.mem.Allocator;
        const max_keys = branching_factor - 1;
        const min_keys = (max_keys - 1) / 2;

        pub const Entry = struct {
            key: K,
            value: V,
        };

        const Node = struct {
            leaf: bool,
            key_count: usize,
            keys: [max_keys]K,
            values: [max_keys]V,
            children: [branching_factor]?*Node,

            fn init(leaf: bool) Node {
                return .{
                    .leaf = leaf,
                    .key_count = 0,
                    .keys = undefined,
                    .values = undefined,
                    .children = [_]?*Node{null} ** branching_factor,
                };
            }
        };

        pub const Iterator = struct {
            allocator: Allocator,
            entries: []Entry,
            index: usize = 0,

            pub fn next(self: *Iterator) ?Entry {
                if (self.index >= self.entries.len) return null;
                const entry = self.entries[self.index];
                self.index += 1;
                return entry;
            }

            pub fn deinit(self: *Iterator) void {
                self.allocator.free(self.entries);
                self.* = .{ .allocator = self.allocator, .entries = &.{} };
            }
        };

        pub const ValidationError = error{
            BadCount,
            ChildMissing,
            InternalLeafMismatch,
            KeyOutOfBounds,
            KeysOutOfOrder,
            LeavesAtDifferentDepths,
            TooFewKeys,
            TooManyKeys,
        };

        allocator: Allocator,
        root: ?*Node = null,
        count: usize = 0,

        pub fn init(allocator: Allocator) Self {
            return .{ .allocator = allocator };
        }

        pub fn deinit(self: *Self) void {
            if (self.root) |root_node| {
                self.destroyNode(root_node);
            }
            self.root = null;
            self.count = 0;
        }

        pub fn len(self: *const Self) usize {
            return self.count;
        }

        pub fn get(self: *const Self, key: K) ?V {
            const value = self.getPtr(key) orelse return null;
            return value.*;
        }

        pub fn getPtr(self: *const Self, key: K) ?*const V {
            var current = self.root orelse return null;
            while (true) {
                const idx = lowerBound(current, key);
                if (idx < current.key_count and eq(current.keys[idx], key)) {
                    return &current.values[idx];
                }
                if (current.leaf) return null;
                current = current.children[idx].?;
            }
        }

        pub fn insert(self: *Self, key: K, value: V) !?V {
            if (self.root == null) {
                const root_node = try self.createNode(true);
                root_node.keys[0] = key;
                root_node.values[0] = value;
                root_node.key_count = 1;
                self.root = root_node;
                self.count = 1;
                return null;
            }

            if (self.root.?.key_count == max_keys) {
                const old_root = self.root.?;
                const new_root = try self.createNode(false);
                new_root.children[0] = old_root;
                self.root = new_root;
                try self.splitChild(new_root, 0);
            }

            const old = try self.insertNonFull(self.root.?, key, value);
            if (old == null) self.count += 1;
            return old;
        }

        pub fn remove(self: *Self, key: K) ?V {
            const root_node = self.root orelse return null;
            const removed = self.removeFromNode(root_node, key);
            if (removed == null) return null;

            self.count -= 1;
            if (root_node.key_count == 0) {
                if (root_node.leaf) {
                    self.allocator.destroy(root_node);
                    self.root = null;
                } else {
                    const next_root = root_node.children[0].?;
                    root_node.children[0] = null;
                    self.allocator.destroy(root_node);
                    self.root = next_root;
                }
            }
            return removed;
        }

        pub fn iterator(self: *const Self, allocator: Allocator) !Iterator {
            var entries: std.ArrayList(Entry) = .empty;
            errdefer entries.deinit(allocator);
            if (self.root) |root_node| {
                try collectAll(root_node, &entries, allocator);
            }
            return .{
                .allocator = allocator,
                .entries = try entries.toOwnedSlice(allocator),
            };
        }

        pub fn rangeQuery(self: *const Self, allocator: Allocator, lo: K, hi: K) ![]Entry {
            var entries: std.ArrayList(Entry) = .empty;
            errdefer entries.deinit(allocator);
            if (less(hi, lo)) return entries.toOwnedSlice(allocator);
            if (self.root) |root_node| {
                try collectRange(root_node, &entries, allocator, lo, hi);
            }
            return entries.toOwnedSlice(allocator);
        }

        pub fn validate(self: *const Self) ValidationError!void {
            const root_node = self.root orelse {
                if (self.count != 0) return ValidationError.BadCount;
                return;
            };

            var leaf_depth: ?usize = null;
            const total = try validateNode(root_node, true, null, null, 0, &leaf_depth);
            if (total != self.count) return ValidationError.BadCount;
        }

        fn createNode(self: *Self, leaf: bool) !*Node {
            const node = try self.allocator.create(Node);
            node.* = Node.init(leaf);
            return node;
        }

        fn destroyNode(self: *Self, node: *Node) void {
            if (!node.leaf) {
                var i: usize = 0;
                while (i <= node.key_count) : (i += 1) {
                    if (node.children[i]) |child| {
                        self.destroyNode(child);
                    }
                }
            }
            self.allocator.destroy(node);
        }

        fn insertNonFull(self: *Self, node: *Node, key: K, value: V) !?V {
            var idx = lowerBound(node, key);
            if (idx < node.key_count and eq(node.keys[idx], key)) {
                const old = node.values[idx];
                node.values[idx] = value;
                return old;
            }

            if (node.leaf) {
                var move = node.key_count;
                while (move > idx) : (move -= 1) {
                    node.keys[move] = node.keys[move - 1];
                    node.values[move] = node.values[move - 1];
                }
                node.keys[idx] = key;
                node.values[idx] = value;
                node.key_count += 1;
                return null;
            }

            if (node.children[idx].?.key_count == max_keys) {
                try self.splitChild(node, idx);
                if (eq(node.keys[idx], key)) {
                    const old = node.values[idx];
                    node.values[idx] = value;
                    return old;
                }
                if (less(node.keys[idx], key)) idx += 1;
            }
            return self.insertNonFull(node.children[idx].?, key, value);
        }

        fn splitChild(self: *Self, parent: *Node, child_index: usize) !void {
            const child = parent.children[child_index].?;
            const median_index = max_keys / 2;
            const right = try self.createNode(child.leaf);
            errdefer self.destroyNode(right);

            const right_count = max_keys - median_index - 1;
            var i: usize = 0;
            while (i < right_count) : (i += 1) {
                right.keys[i] = child.keys[median_index + 1 + i];
                right.values[i] = child.values[median_index + 1 + i];
            }

            if (!child.leaf) {
                i = 0;
                while (i <= right_count) : (i += 1) {
                    right.children[i] = child.children[median_index + 1 + i];
                    child.children[median_index + 1 + i] = null;
                }
            }

            right.key_count = right_count;
            child.key_count = median_index;

            var move_child = parent.key_count + 1;
            while (move_child > child_index + 1) : (move_child -= 1) {
                parent.children[move_child] = parent.children[move_child - 1];
            }
            parent.children[child_index + 1] = right;

            var move_key = parent.key_count;
            while (move_key > child_index) : (move_key -= 1) {
                parent.keys[move_key] = parent.keys[move_key - 1];
                parent.values[move_key] = parent.values[move_key - 1];
            }
            parent.keys[child_index] = child.keys[median_index];
            parent.values[child_index] = child.values[median_index];
            parent.key_count += 1;
        }

        fn removeFromNode(self: *Self, node: *Node, key: K) ?V {
            const idx = lowerBound(node, key);
            if (idx < node.key_count and eq(node.keys[idx], key)) {
                if (node.leaf) return removeFromLeaf(node, idx);
                return self.removeFromInternal(node, idx);
            }

            if (node.leaf) return null;

            var child_index = idx;
            if (node.children[child_index].?.key_count == min_keys) {
                child_index = self.fillChild(node, child_index);
            }
            return self.removeFromNode(node.children[child_index].?, key);
        }

        fn removeFromInternal(self: *Self, node: *Node, key_index: usize) V {
            const old_key = node.keys[key_index];
            const old_value = node.values[key_index];
            const left = node.children[key_index].?;
            const right = node.children[key_index + 1].?;

            if (left.key_count > min_keys) {
                const pred = maxEntry(left);
                node.keys[key_index] = pred.key;
                node.values[key_index] = pred.value;
                _ = self.removeFromNode(left, pred.key);
                return old_value;
            }

            if (right.key_count > min_keys) {
                const succ = minEntry(right);
                node.keys[key_index] = succ.key;
                node.values[key_index] = succ.value;
                _ = self.removeFromNode(right, succ.key);
                return old_value;
            }

            const merged = self.mergeChildren(node, key_index);
            _ = self.removeFromNode(merged, old_key);
            return old_value;
        }

        fn fillChild(self: *Self, node: *Node, child_index: usize) usize {
            if (child_index > 0 and node.children[child_index - 1].?.key_count > min_keys) {
                borrowFromPrev(node, child_index);
                return child_index;
            }

            if (child_index < node.key_count and node.children[child_index + 1].?.key_count > min_keys) {
                borrowFromNext(node, child_index);
                return child_index;
            }

            if (child_index < node.key_count) {
                _ = self.mergeChildren(node, child_index);
                return child_index;
            }

            _ = self.mergeChildren(node, child_index - 1);
            return child_index - 1;
        }

        fn borrowFromPrev(node: *Node, child_index: usize) void {
            const child = node.children[child_index].?;
            const sibling = node.children[child_index - 1].?;

            var i = child.key_count;
            while (i > 0) : (i -= 1) {
                child.keys[i] = child.keys[i - 1];
                child.values[i] = child.values[i - 1];
            }
            if (!child.leaf) {
                i = child.key_count + 1;
                while (i > 0) : (i -= 1) {
                    child.children[i] = child.children[i - 1];
                }
                child.children[0] = sibling.children[sibling.key_count];
                sibling.children[sibling.key_count] = null;
            }

            child.keys[0] = node.keys[child_index - 1];
            child.values[0] = node.values[child_index - 1];
            node.keys[child_index - 1] = sibling.keys[sibling.key_count - 1];
            node.values[child_index - 1] = sibling.values[sibling.key_count - 1];

            sibling.key_count -= 1;
            child.key_count += 1;
        }

        fn borrowFromNext(node: *Node, child_index: usize) void {
            const child = node.children[child_index].?;
            const sibling = node.children[child_index + 1].?;

            child.keys[child.key_count] = node.keys[child_index];
            child.values[child.key_count] = node.values[child_index];
            if (!child.leaf) {
                child.children[child.key_count + 1] = sibling.children[0];
            }

            node.keys[child_index] = sibling.keys[0];
            node.values[child_index] = sibling.values[0];

            var i: usize = 1;
            while (i < sibling.key_count) : (i += 1) {
                sibling.keys[i - 1] = sibling.keys[i];
                sibling.values[i - 1] = sibling.values[i];
            }
            if (!sibling.leaf) {
                i = 1;
                while (i <= sibling.key_count) : (i += 1) {
                    sibling.children[i - 1] = sibling.children[i];
                }
                sibling.children[sibling.key_count] = null;
            }

            sibling.key_count -= 1;
            child.key_count += 1;
        }

        fn mergeChildren(self: *Self, node: *Node, left_index: usize) *Node {
            const left = node.children[left_index].?;
            const right = node.children[left_index + 1].?;
            const old_left_count = left.key_count;

            left.keys[old_left_count] = node.keys[left_index];
            left.values[old_left_count] = node.values[left_index];

            var i: usize = 0;
            while (i < right.key_count) : (i += 1) {
                left.keys[old_left_count + 1 + i] = right.keys[i];
                left.values[old_left_count + 1 + i] = right.values[i];
            }
            if (!left.leaf) {
                i = 0;
                while (i <= right.key_count) : (i += 1) {
                    left.children[old_left_count + 1 + i] = right.children[i];
                    right.children[i] = null;
                }
            }
            left.key_count = old_left_count + 1 + right.key_count;

            i = left_index + 1;
            while (i < node.key_count) : (i += 1) {
                node.keys[i - 1] = node.keys[i];
                node.values[i - 1] = node.values[i];
            }
            i = left_index + 2;
            while (i <= node.key_count) : (i += 1) {
                node.children[i - 1] = node.children[i];
            }
            node.children[node.key_count] = null;
            node.key_count -= 1;

            self.allocator.destroy(right);
            return left;
        }

        fn removeFromLeaf(node: *Node, key_index: usize) V {
            const old_value = node.values[key_index];
            var i = key_index + 1;
            while (i < node.key_count) : (i += 1) {
                node.keys[i - 1] = node.keys[i];
                node.values[i - 1] = node.values[i];
            }
            node.key_count -= 1;
            return old_value;
        }

        fn maxEntry(node: *Node) Entry {
            var current = node;
            while (!current.leaf) {
                current = current.children[current.key_count].?;
            }
            return .{
                .key = current.keys[current.key_count - 1],
                .value = current.values[current.key_count - 1],
            };
        }

        fn minEntry(node: *Node) Entry {
            var current = node;
            while (!current.leaf) {
                current = current.children[0].?;
            }
            return .{
                .key = current.keys[0],
                .value = current.values[0],
            };
        }

        fn collectAll(node: *const Node, entries: *std.ArrayList(Entry), allocator: Allocator) !void {
            var i: usize = 0;
            while (i < node.key_count) : (i += 1) {
                if (!node.leaf) try collectAll(node.children[i].?, entries, allocator);
                try entries.append(allocator, .{ .key = node.keys[i], .value = node.values[i] });
            }
            if (!node.leaf) try collectAll(node.children[node.key_count].?, entries, allocator);
        }

        fn collectRange(node: *const Node, entries: *std.ArrayList(Entry), allocator: Allocator, lo: K, hi: K) !void {
            var i: usize = 0;
            while (i < node.key_count) : (i += 1) {
                if (!node.leaf and !less(node.keys[i], lo)) {
                    try collectRange(node.children[i].?, entries, allocator, lo, hi);
                }
                if (!less(node.keys[i], lo) and !less(hi, node.keys[i])) {
                    try entries.append(allocator, .{ .key = node.keys[i], .value = node.values[i] });
                }
                if (less(hi, node.keys[i])) return;
            }
            if (!node.leaf and (node.key_count == 0 or less(node.keys[node.key_count - 1], hi) or eq(node.keys[node.key_count - 1], hi))) {
                try collectRange(node.children[node.key_count].?, entries, allocator, lo, hi);
            }
        }

        fn validateNode(
            node: *const Node,
            is_root: bool,
            lower: ?K,
            upper: ?K,
            depth: usize,
            leaf_depth: *?usize,
        ) ValidationError!usize {
            if (node.key_count > max_keys) return ValidationError.TooManyKeys;
            if (!is_root and node.key_count < min_keys) return ValidationError.TooFewKeys;

            var i: usize = 0;
            while (i < node.key_count) : (i += 1) {
                if (i > 0 and !less(node.keys[i - 1], node.keys[i])) {
                    return ValidationError.KeysOutOfOrder;
                }
                if (lower) |bound| {
                    if (!less(bound, node.keys[i])) return ValidationError.KeyOutOfBounds;
                }
                if (upper) |bound| {
                    if (!less(node.keys[i], bound)) return ValidationError.KeyOutOfBounds;
                }
            }

            if (node.leaf) {
                if (leaf_depth.*) |seen| {
                    if (seen != depth) return ValidationError.LeavesAtDifferentDepths;
                } else {
                    leaf_depth.* = depth;
                }
                return node.key_count;
            }

            var total = node.key_count;
            i = 0;
            while (i <= node.key_count) : (i += 1) {
                const child = node.children[i] orelse return ValidationError.ChildMissing;
                const child_lower = if (i == 0) lower else node.keys[i - 1];
                const child_upper = if (i == node.key_count) upper else node.keys[i];
                if (child.leaf and depth + 1 == 0) return ValidationError.InternalLeafMismatch;
                total += try validateNode(child, false, child_lower, child_upper, depth + 1, leaf_depth);
            }
            return total;
        }

        fn lowerBound(node: *const Node, key: K) usize {
            var lo: usize = 0;
            var hi = node.key_count;
            while (lo < hi) {
                const mid = lo + (hi - lo) / 2;
                if (less(node.keys[mid], key)) {
                    lo = mid + 1;
                } else {
                    hi = mid;
                }
            }
            return lo;
        }

        fn less(a: K, b: K) bool {
            return a < b;
        }

        fn eq(a: K, b: K) bool {
            return a == b;
        }
    };
}

const TestPair = struct {
    key: i32,
    value: i32,
};

fn oracleLowerBound(items: []const TestPair, key: i32) usize {
    var lo: usize = 0;
    var hi = items.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (items[mid].key < key) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return lo;
}

fn oracleInsert(items: *std.ArrayList(TestPair), allocator: std.mem.Allocator, key: i32, value: i32) !?i32 {
    const idx = oracleLowerBound(items.items, key);
    if (idx < items.items.len and items.items[idx].key == key) {
        const old = items.items[idx].value;
        items.items[idx].value = value;
        return old;
    }
    try items.insert(allocator, idx, .{ .key = key, .value = value });
    return null;
}

fn oracleGet(items: []const TestPair, key: i32) ?i32 {
    const idx = oracleLowerBound(items, key);
    if (idx < items.len and items[idx].key == key) return items[idx].value;
    return null;
}

fn oracleRemove(items: *std.ArrayList(TestPair), key: i32) ?i32 {
    const idx = oracleLowerBound(items.items, key);
    if (idx >= items.items.len or items.items[idx].key != key) return null;
    const old = items.items[idx].value;
    _ = items.orderedRemove(idx);
    return old;
}

fn nextRand(state: *u64) u32 {
    state.* = state.* *% 6364136223846793005 +% 1442695040888963407;
    return @intCast(state.* >> 32);
}

test "ordered iteration after deterministic random inserts" {
    const allocator = std.testing.allocator;
    var map = BTreeMap(i32, i32, 8).init(allocator);
    defer map.deinit();
    var oracle: std.ArrayList(TestPair) = .empty;
    defer oracle.deinit(allocator);

    var seed: u64 = 0x5eed_b7ee;
    var i: usize = 0;
    while (i < 500) : (i += 1) {
        const key: i32 = @intCast(nextRand(&seed) % 1000);
        const value: i32 = @intCast(i * 13);
        const expected_old = try oracleInsert(&oracle, allocator, key, value);
        try std.testing.expectEqual(expected_old, try map.insert(key, value));
        try map.validate();
    }

    try std.testing.expectEqual(oracle.items.len, map.len());
    var iter = try map.iterator(allocator);
    defer iter.deinit();

    i = 0;
    while (iter.next()) |entry| : (i += 1) {
        try std.testing.expect(i < oracle.items.len);
        try std.testing.expectEqual(oracle.items[i].key, entry.key);
        try std.testing.expectEqual(oracle.items[i].value, entry.value);
    }
    try std.testing.expectEqual(oracle.items.len, i);
}

test "get and remove correctness against sorted oracle" {
    const allocator = std.testing.allocator;
    var map = BTreeMap(i32, i32, 6).init(allocator);
    defer map.deinit();
    var oracle: std.ArrayList(TestPair) = .empty;
    defer oracle.deinit(allocator);

    var seed: u64 = 0x1234_5678_9abc_def0;
    var op: usize = 0;
    while (op < 700) : (op += 1) {
        const key: i32 = @intCast(nextRand(&seed) % 180);
        const value: i32 = @intCast(nextRand(&seed) % 10_000);
        switch (nextRand(&seed) % 3) {
            0 => {
                const expected_old = try oracleInsert(&oracle, allocator, key, value);
                try std.testing.expectEqual(expected_old, try map.insert(key, value));
            },
            1 => try std.testing.expectEqual(oracleGet(oracle.items, key), map.get(key)),
            else => try std.testing.expectEqual(oracleRemove(&oracle, key), map.remove(key)),
        }
        try std.testing.expectEqual(oracle.items.len, map.len());
        try map.validate();
    }

    var i: usize = 0;
    while (i < oracle.items.len) : (i += 1) {
        try std.testing.expectEqual(oracle.items[i].value, map.get(oracle.items[i].key));
    }
}

test "split insertions and borrow or merge deletions preserve invariants under stress" {
    const allocator = std.testing.allocator;
    var map = BTreeMap(i32, i32, 4).init(allocator);
    defer map.deinit();

    var i: i32 = 0;
    while (i < 160) : (i += 1) {
        try std.testing.expectEqual(null, try map.insert(i, i * 10));
        try map.validate();
    }
    try std.testing.expect(map.root != null);
    try std.testing.expect(!map.root.?.leaf);

    i = 0;
    while (i < 80) : (i += 1) {
        const key = i * 2;
        try std.testing.expectEqual(key * 10, map.remove(key));
        try map.validate();
    }

    var seed: u64 = 0xa11c_e55;
    var oracle: std.ArrayList(TestPair) = .empty;
    defer oracle.deinit(allocator);
    i = 0;
    while (i < 160) : (i += 1) {
        if (@rem(i, 2) == 1) _ = try oracleInsert(&oracle, allocator, i, i * 10);
    }

    var op: usize = 0;
    while (op < 1000) : (op += 1) {
        const key: i32 = @intCast(nextRand(&seed) % 260);
        if ((nextRand(&seed) & 1) == 0) {
            const value: i32 = @intCast(nextRand(&seed) % 50_000);
            try std.testing.expectEqual(try oracleInsert(&oracle, allocator, key, value), try map.insert(key, value));
        } else {
            try std.testing.expectEqual(oracleRemove(&oracle, key), map.remove(key));
        }
        try std.testing.expectEqual(oracle.items.len, map.len());
        try map.validate();
    }
}

test "range query is ordered and respects inclusive bounds" {
    const allocator = std.testing.allocator;
    var map = BTreeMap(i32, i32, 5).init(allocator);
    defer map.deinit();

    var i: i32 = 49;
    while (i >= 0) : (i -= 1) {
        _ = try map.insert(i, i + 1000);
        if (i == 0) break;
    }

    const entries = try map.rangeQuery(allocator, 10, 20);
    defer allocator.free(entries);
    try std.testing.expectEqual(@as(usize, 11), entries.len);
    var expected: i32 = 10;
    for (entries) |entry| {
        try std.testing.expectEqual(expected, entry.key);
        try std.testing.expectEqual(expected + 1000, entry.value);
        expected += 1;
    }

    const empty = try map.rangeQuery(allocator, 30, 20);
    defer allocator.free(empty);
    try std.testing.expectEqual(@as(usize, 0), empty.len);
}

test "duplicate key updates value without increasing length" {
    const allocator = std.testing.allocator;
    var map = BTreeMap(i32, i32, 4).init(allocator);
    defer map.deinit();

    try std.testing.expectEqual(null, try map.insert(7, 10));
    try std.testing.expectEqual(@as(?i32, 10), try map.insert(7, 20));
    try std.testing.expectEqual(@as(usize, 1), map.len());
    try std.testing.expectEqual(@as(?i32, 20), map.get(7));
    try map.validate();
}

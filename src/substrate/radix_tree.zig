// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

const std = @import("std");

pub fn RadixTree(comptime Value: type) type {
    return struct {
        allocator: std.mem.Allocator,
        root: Node = .{},
        len: usize = 0,

        const Self = @This();

        pub const Entry = struct {
            key: []u8,
            value: Value,
        };

        const Child = struct {
            label: []u8,
            node: *Node,
        };

        const Node = struct {
            value: ?Value = null,
            children: std.ArrayList(Child) = .empty,

            fn deinit(self: *Node, allocator: std.mem.Allocator) void {
                for (self.children.items) |child| {
                    allocator.free(child.label);
                    child.node.deinit(allocator);
                    allocator.destroy(child.node);
                }
                self.children.deinit(allocator);
                self.* = .{};
            }
        };

        pub fn init(allocator: std.mem.Allocator) Self {
            return .{ .allocator = allocator };
        }

        pub fn deinit(self: *Self) void {
            self.root.deinit(self.allocator);
            self.len = 0;
        }

        pub fn count(self: *const Self) usize {
            return self.len;
        }

        pub fn insert(self: *Self, key: []const u8, value: Value) !void {
            const added = try self.insertAt(&self.root, key, value);
            if (added) self.len += 1;
        }

        pub fn get(self: *const Self, key: []const u8) ?Value {
            var node = &self.root;
            var rest = key;

            while (true) {
                if (rest.len == 0) return node.value;

                for (node.children.items) |child| {
                    if (std.mem.startsWith(u8, rest, child.label)) {
                        node = child.node;
                        rest = rest[child.label.len..];
                        break;
                    }
                } else {
                    return null;
                }
            }
        }

        pub fn longestPrefix(self: *const Self, key: []const u8) ?Value {
            var node = &self.root;
            var rest = key;
            var best = node.value;

            while (rest.len != 0) {
                for (node.children.items) |child| {
                    if (std.mem.startsWith(u8, rest, child.label)) {
                        node = child.node;
                        rest = rest[child.label.len..];
                        if (node.value) |value| best = value;
                        break;
                    }
                } else {
                    break;
                }
            }

            return best;
        }

        pub fn remove(self: *Self, key: []const u8) !bool {
            const removed = try self.removeAt(&self.root, key);
            if (removed) self.len -= 1;
            return removed;
        }

        pub fn entries(self: *const Self, allocator: std.mem.Allocator) ![]Entry {
            var out: std.ArrayList(Entry) = .empty;
            errdefer {
                for (out.items) |entry| allocator.free(entry.key);
                out.deinit(allocator);
            }

            var path: std.ArrayList(u8) = .empty;
            defer path.deinit(allocator);

            try collectEntries(&self.root, allocator, &path, &out);
            const slice = try out.toOwnedSlice(allocator);
            sortEntries(slice);
            return slice;
        }

        pub fn freeEntries(allocator: std.mem.Allocator, items: []Entry) void {
            for (items) |entry| allocator.free(entry.key);
            allocator.free(items);
        }

        fn insertAt(self: *Self, node: *Node, key: []const u8, value: Value) !bool {
            if (key.len == 0) {
                const added = node.value == null;
                node.value = value;
                return added;
            }

            for (node.children.items, 0..) |*child, index| {
                const common = commonPrefixLen(key, child.label);
                if (common == 0) continue;

                if (common == child.label.len) {
                    return self.insertAt(child.node, key[common..], value);
                }

                return try self.splitChild(node, index, common, key, value);
            }

            const child = try self.makeChild(key, value);
            errdefer self.destroyChild(child);
            try node.children.append(self.allocator, child);
            return true;
        }

        fn splitChild(
            self: *Self,
            parent: *Node,
            child_index: usize,
            split_at: usize,
            key: []const u8,
            value: Value,
        ) !bool {
            const old_child = parent.children.items[child_index];
            const old_label = old_child.label;

            const prefix = try self.allocator.dupe(u8, old_label[0..split_at]);
            errdefer self.allocator.free(prefix);

            const old_suffix = try self.allocator.dupe(u8, old_label[split_at..]);
            errdefer self.allocator.free(old_suffix);

            const middle = try self.allocator.create(Node);
            errdefer self.allocator.destroy(middle);
            middle.* = .{};
            errdefer middle.children.deinit(self.allocator);

            try middle.children.append(self.allocator, .{
                .label = old_suffix,
                .node = old_child.node,
            });

            if (split_at == key.len) {
                middle.value = value;
            } else {
                const new_child = try self.makeChild(key[split_at..], value);
                errdefer self.destroyChild(new_child);
                try middle.children.append(self.allocator, new_child);
            }

            parent.children.items[child_index] = .{
                .label = prefix,
                .node = middle,
            };
            self.allocator.free(old_label);
            return true;
        }

        fn makeChild(self: *Self, label: []const u8, value: Value) !Child {
            const label_copy = try self.allocator.dupe(u8, label);
            errdefer self.allocator.free(label_copy);

            const node = try self.allocator.create(Node);
            errdefer self.allocator.destroy(node);
            node.* = .{ .value = value };

            return .{ .label = label_copy, .node = node };
        }

        fn destroyChild(self: *Self, child: Child) void {
            self.allocator.free(child.label);
            child.node.deinit(self.allocator);
            self.allocator.destroy(child.node);
        }

        fn removeAt(self: *Self, node: *Node, key: []const u8) !bool {
            if (key.len == 0) {
                if (node.value == null) return false;
                node.value = null;
                return true;
            }

            for (node.children.items, 0..) |child, index| {
                if (!std.mem.startsWith(u8, key, child.label)) continue;

                const removed = try self.removeAt(child.node, key[child.label.len..]);
                if (removed) try self.compressChild(node, index);
                return removed;
            }

            return false;
        }

        fn compressChild(self: *Self, parent: *Node, child_index: usize) !void {
            const child = parent.children.items[child_index];
            if (child.node.value != null) return;

            switch (child.node.children.items.len) {
                0 => {
                    _ = parent.children.orderedRemove(child_index);
                    self.allocator.free(child.label);
                    child.node.children.deinit(self.allocator);
                    self.allocator.destroy(child.node);
                },
                1 => {
                    const grand = child.node.children.items[0];
                    const merged = try self.allocator.alloc(u8, child.label.len + grand.label.len);
                    @memcpy(merged[0..child.label.len], child.label);
                    @memcpy(merged[child.label.len..], grand.label);

                    self.allocator.free(child.label);
                    self.allocator.free(grand.label);
                    child.node.children.deinit(self.allocator);
                    self.allocator.destroy(child.node);
                    parent.children.items[child_index] = .{
                        .label = merged,
                        .node = grand.node,
                    };
                },
                else => {},
            }
        }

        fn collectEntries(
            node: *const Node,
            allocator: std.mem.Allocator,
            path: *std.ArrayList(u8),
            out: *std.ArrayList(Entry),
        ) !void {
            if (node.value) |value| {
                const key_copy = try allocator.dupe(u8, path.items);
                errdefer allocator.free(key_copy);
                try out.append(allocator, .{ .key = key_copy, .value = value });
            }

            for (node.children.items) |child| {
                const old_len = path.items.len;
                try path.appendSlice(allocator, child.label);
                try collectEntries(child.node, allocator, path, out);
                path.shrinkRetainingCapacity(old_len);
            }
        }

        fn edgeCount(self: *const Self) usize {
            return countNodeEdges(&self.root);
        }

        fn countNodeEdges(node: *const Node) usize {
            var total = node.children.items.len;
            for (node.children.items) |child| total += countNodeEdges(child.node);
            return total;
        }
    };
}

fn commonPrefixLen(a: []const u8, b: []const u8) usize {
    const n = @min(a.len, b.len);
    var i: usize = 0;
    while (i < n and a[i] == b[i]) : (i += 1) {}
    return i;
}

fn sortEntries(items: anytype) void {
    if (items.len < 2) return;

    var i: usize = 1;
    while (i < items.len) : (i += 1) {
        var j = i;
        while (j > 0 and std.mem.order(u8, items[j].key, items[j - 1].key) == .lt) : (j -= 1) {
            const tmp = items[j - 1];
            items[j - 1] = items[j];
            items[j] = tmp;
        }
    }
}

test "insert get and overwrite values" {
    const testing = std.testing;
    var tree = RadixTree(u32).init(testing.allocator);
    defer tree.deinit();

    try tree.insert("alpha", 1);
    try tree.insert("beta", 2);
    try tree.insert("alphabet", 3);
    try tree.insert("alpha", 4);

    try testing.expectEqual(@as(usize, 3), tree.count());
    try testing.expectEqual(@as(?u32, 4), tree.get("alpha"));
    try testing.expectEqual(@as(?u32, 2), tree.get("beta"));
    try testing.expectEqual(@as(?u32, 3), tree.get("alphabet"));
    try testing.expectEqual(@as(?u32, null), tree.get("al"));
    try testing.expectEqual(@as(?u32, null), tree.get("gamma"));
}

test "remove missing leaf and internal keys" {
    const testing = std.testing;
    var tree = RadixTree(u8).init(testing.allocator);
    defer tree.deinit();

    try tree.insert("cat", 1);
    try tree.insert("car", 2);
    try tree.insert("cart", 3);
    try tree.insert("dog", 4);

    try testing.expect(!try tree.remove("cow"));
    try testing.expect(try tree.remove("cart"));
    try testing.expectEqual(@as(?u8, null), tree.get("cart"));
    try testing.expectEqual(@as(?u8, 2), tree.get("car"));
    try testing.expectEqual(@as(?u8, 1), tree.get("cat"));
    try testing.expectEqual(@as(?u8, 4), tree.get("dog"));

    try testing.expect(try tree.remove("car"));
    try testing.expectEqual(@as(?u8, null), tree.get("car"));
    try testing.expectEqual(@as(?u8, 1), tree.get("cat"));
    try testing.expectEqual(@as(usize, 2), tree.count());
}

test "longest prefix supports routing style matches" {
    const testing = std.testing;
    var routes = RadixTree(u16).init(testing.allocator);
    defer routes.deinit();

    try routes.insert("", 1);
    try routes.insert("/api", 2);
    try routes.insert("/api/v1", 3);
    try routes.insert("/assets", 4);

    try testing.expectEqual(@as(?u16, 3), routes.longestPrefix("/api/v1/users"));
    try testing.expectEqual(@as(?u16, 2), routes.longestPrefix("/api/v2"));
    try testing.expectEqual(@as(?u16, 4), routes.longestPrefix("/assets/logo.png"));
    try testing.expectEqual(@as(?u16, 1), routes.longestPrefix("/unknown"));
}

test "shared prefixes split compressed edges and removals merge them" {
    const testing = std.testing;
    var tree = RadixTree(u8).init(testing.allocator);
    defer tree.deinit();

    try tree.insert("romane", 1);
    try testing.expectEqual(@as(usize, 1), tree.edgeCount());

    try tree.insert("romanus", 2);
    try tree.insert("rubens", 3);
    try tree.insert("ruber", 4);
    try tree.insert("rubicon", 5);
    try tree.insert("rubicundus", 6);

    try testing.expectEqual(@as(?u8, 1), tree.get("romane"));
    try testing.expectEqual(@as(?u8, 2), tree.get("romanus"));
    try testing.expectEqual(@as(?u8, 3), tree.get("rubens"));
    try testing.expectEqual(@as(?u8, 4), tree.get("ruber"));
    try testing.expectEqual(@as(?u8, 5), tree.get("rubicon"));
    try testing.expectEqual(@as(?u8, 6), tree.get("rubicundus"));

    const before = tree.edgeCount();
    try testing.expect(try tree.remove("rubicundus"));
    try testing.expect(try tree.remove("rubicon"));
    try testing.expectEqual(@as(?u8, null), tree.get("rubicon"));
    try testing.expectEqual(@as(?u8, 4), tree.get("ruber"));
    try testing.expect(tree.edgeCount() < before);
}

test "empty key behaves as a normal key" {
    const testing = std.testing;
    var tree = RadixTree(i32).init(testing.allocator);
    defer tree.deinit();

    try tree.insert("", 9);
    try tree.insert("x", 10);

    try testing.expectEqual(@as(?i32, 9), tree.get(""));
    try testing.expectEqual(@as(?i32, 9), tree.longestPrefix("anything"));
    try testing.expectEqual(@as(?i32, 10), tree.longestPrefix("x-ray"));

    try testing.expect(try tree.remove(""));
    try testing.expectEqual(@as(?i32, null), tree.get(""));
    try testing.expectEqual(@as(?i32, null), tree.longestPrefix("anything"));
    try testing.expectEqual(@as(?i32, 10), tree.get("x"));
}

test "entries are returned in deterministic lexicographic order" {
    const testing = std.testing;
    var tree = RadixTree(u8).init(testing.allocator);
    defer tree.deinit();

    try tree.insert("delta", 4);
    try tree.insert("alpha", 1);
    try tree.insert("charlie", 3);
    try tree.insert("", 0);
    try tree.insert("bravo", 2);

    const got = try tree.entries(testing.allocator);
    defer RadixTree(u8).freeEntries(testing.allocator, got);

    try testing.expectEqual(@as(usize, 5), got.len);
    try testing.expectEqualStrings("", got[0].key);
    try testing.expectEqualStrings("alpha", got[1].key);
    try testing.expectEqualStrings("bravo", got[2].key);
    try testing.expectEqualStrings("charlie", got[3].key);
    try testing.expectEqualStrings("delta", got[4].key);
    try testing.expectEqual(@as(u8, 0), got[0].value);
    try testing.expectEqual(@as(u8, 4), got[4].value);
}

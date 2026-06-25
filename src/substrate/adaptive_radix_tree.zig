// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Adaptive Radix Tree (ART) for byte-slice keys.
//!
//! ART is an ordered map and prefix index that compresses unary paths while
//! adapting each inner node to its fanout. Small nodes use compact linear
//! arrays (Node4 and Node16), medium nodes use a 256-byte indirection table
//! into 48 child slots (Node48), and dense nodes use direct 256-way addressing
//! (Node256). The layout keeps common routing and autocomplete prefixes cache
//! friendly without paying the memory cost of a full 256-way trie at every
//! level.

const std = @import("std");

pub fn Art(comptime V: type) type {
    return struct {
        root: ?*Node = null,
        count: usize = 0,

        const Self = @This();
        const Allocator = std.mem.Allocator;
        const empty48: u8 = 255;

        pub const LongestPrefix = struct {
            key_len: usize,
            value: V,
        };

        const Leaf = struct {
            key: []u8,
            value: V,
        };

        fn SmallNode(comptime cap: usize) type {
            return struct {
                prefix: []u8 = &.{},
                has_value: bool = false,
                key: []u8 = &.{},
                value: V = undefined,
                count: u8 = 0,
                keys: [cap]u8 = undefined,
                children: [cap]?*Node = [_]?*Node{null} ** cap,
            };
        }

        const Node4 = SmallNode(4);
        const Node16 = SmallNode(16);

        const Node48 = struct {
            prefix: []u8 = &.{},
            has_value: bool = false,
            key: []u8 = &.{},
            value: V = undefined,
            count: u8 = 0,
            index: [256]u8 = [_]u8{empty48} ** 256,
            children: [48]?*Node = [_]?*Node{null} ** 48,
        };

        const Node256 = struct {
            prefix: []u8 = &.{},
            has_value: bool = false,
            key: []u8 = &.{},
            value: V = undefined,
            count: u16 = 0,
            children: [256]?*Node = [_]?*Node{null} ** 256,
        };

        const Node = union(enum) {
            leaf: Leaf,
            n4: Node4,
            n16: Node16,
            n48: Node48,
            n256: Node256,
        };

        pub fn init() Self {
            return .{};
        }

        pub fn deinit(self: *Self, allocator: Allocator) void {
            if (self.root) |node| destroyNode(allocator, node);
            self.root = null;
            self.count = 0;
        }

        pub fn len(self: *const Self) usize {
            return self.count;
        }

        pub fn insert(self: *Self, allocator: Allocator, key: []const u8, value: V) !void {
            const added = try self.insertAt(allocator, &self.root, key, value, 0);
            if (added) self.count += 1;
        }

        pub fn get(self: *const Self, key: []const u8) ?V {
            var slot = self.root orelse return null;
            var depth: usize = 0;

            while (true) {
                switch (slot.*) {
                    .leaf => |leaf| {
                        if (std.mem.eql(u8, leaf.key, key)) return leaf.value;
                        return null;
                    },
                    inline .n4, .n16, .n48, .n256 => |*inner| {
                        if (!matchPrefix(inner.prefix, key, depth)) return null;
                        depth += inner.prefix.len;
                        if (depth == key.len) {
                            if (inner.has_value) return inner.value;
                            return null;
                        }
                        slot = childPtrConst(slot, key[depth]) orelse return null;
                        depth += 1;
                    },
                }
            }
        }

        pub fn remove(self: *Self, allocator: Allocator, key: []const u8) bool {
            const removed = removeAt(allocator, &self.root, key, 0);
            if (removed) self.count -= 1;
            return removed;
        }

        pub fn longestPrefix(self: *const Self, key: []const u8) ?LongestPrefix {
            var node = self.root orelse return null;
            var depth: usize = 0;
            var best: ?LongestPrefix = null;

            while (true) {
                switch (node.*) {
                    .leaf => |leaf| {
                        if (std.mem.startsWith(u8, key, leaf.key)) {
                            best = .{ .key_len = leaf.key.len, .value = leaf.value };
                        }
                        return best;
                    },
                    inline .n4, .n16, .n48, .n256 => |*inner| {
                        if (!matchPrefix(inner.prefix, key, depth)) return best;
                        depth += inner.prefix.len;
                        if (inner.has_value and std.mem.startsWith(u8, key, inner.key)) {
                            best = .{ .key_len = inner.key.len, .value = inner.value };
                        }
                        if (depth == key.len) return best;
                        node = childPtrConst(node, key[depth]) orelse return best;
                        depth += 1;
                    },
                }
            }
        }

        pub fn prefixIterate(
            self: *const Self,
            prefix: []const u8,
            ctx: anytype,
            comptime cb: anytype,
        ) !void {
            if (self.root) |node| {
                try iteratePrefix(node, prefix, ctx, cb);
            }
        }

        fn insertAt(
            self: *Self,
            allocator: Allocator,
            slot: *?*Node,
            key: []const u8,
            value: V,
            depth: usize,
        ) !bool {
            const node = slot.* orelse {
                slot.* = try createLeaf(allocator, key, value);
                return true;
            };

            switch (node.*) {
                .leaf => |*leaf| {
                    if (std.mem.eql(u8, leaf.key, key)) {
                        leaf.value = value;
                        return false;
                    }
                    try self.splitLeaf(allocator, slot, key, value, depth);
                    return true;
                },
                inline .n4, .n16, .n48, .n256 => |*inner| {
                    const common = commonPrefixLen(inner.prefix, key[depth..]);
                    if (common < inner.prefix.len) {
                        try self.splitInner(allocator, slot, key, value, depth, common);
                        return true;
                    }

                    const next_depth = depth + inner.prefix.len;
                    if (next_depth == key.len) {
                        if (inner.has_value) {
                            inner.value = value;
                            return false;
                        }
                        inner.key = try allocator.dupe(u8, key);
                        inner.value = value;
                        inner.has_value = true;
                        return true;
                    }

                    const edge = key[next_depth];
                    if (childSlot(node, edge)) |child| {
                        return self.insertAt(allocator, child, key, value, next_depth + 1);
                    }

                    const leaf = try createLeaf(allocator, key, value);
                    errdefer destroyNode(allocator, leaf);
                    try addChild(allocator, slot, edge, leaf);
                    return true;
                },
            }
        }

        fn splitLeaf(
            self: *Self,
            allocator: Allocator,
            slot: *?*Node,
            key: []const u8,
            value: V,
            depth: usize,
        ) !void {
            _ = self;
            const old_node = slot.*.?;
            const old_leaf = old_node.leaf;
            const shared = commonPrefixLen(old_leaf.key[depth..], key[depth..]);
            const branch_depth = depth + shared;
            const prefix = try allocator.dupe(u8, key[depth .. depth + shared]);
            errdefer allocator.free(prefix);

            const branch = try allocator.create(Node);
            errdefer allocator.destroy(branch);
            branch.* = .{ .n4 = .{ .prefix = prefix } };

            var new_key = if (branch_depth == key.len) try allocator.dupe(u8, key) else null;
            errdefer {
                if (new_key) |k| allocator.free(k);
            }
            var new_leaf = if (branch_depth == key.len) null else try createLeaf(allocator, key, value);
            errdefer {
                if (new_leaf) |leaf| destroyNode(allocator, leaf);
            }

            if (branch_depth == old_leaf.key.len) {
                branch.n4.key = old_leaf.key;
                branch.n4.value = old_leaf.value;
                branch.n4.has_value = true;
                allocator.destroy(old_node);
            } else {
                insertSmall(4, &branch.n4, old_leaf.key[branch_depth], old_node);
            }

            if (branch_depth == key.len) {
                branch.n4.key = new_key.?;
                new_key = null;
                branch.n4.value = value;
                branch.n4.has_value = true;
            } else {
                insertSmall(4, &branch.n4, key[branch_depth], new_leaf.?);
                new_leaf = null;
            }

            slot.* = branch;
        }

        fn splitInner(
            self: *Self,
            allocator: Allocator,
            slot: *?*Node,
            key: []const u8,
            value: V,
            depth: usize,
            common: usize,
        ) !void {
            _ = self;
            const old_node = slot.*.?;
            const old_prefix = nodePrefix(old_node).*;
            const old_edge = old_prefix[common];
            const parent_prefix = try allocator.dupe(u8, old_prefix[0..common]);
            errdefer allocator.free(parent_prefix);
            const old_suffix = try allocator.dupe(u8, old_prefix[common + 1 ..]);
            errdefer allocator.free(old_suffix);
            const branch_depth = depth + common;
            var new_key = if (branch_depth == key.len) try allocator.dupe(u8, key) else null;
            errdefer {
                if (new_key) |k| allocator.free(k);
            }
            var new_leaf = if (branch_depth == key.len) null else try createLeaf(allocator, key, value);
            errdefer {
                if (new_leaf) |leaf| destroyNode(allocator, leaf);
            }

            const parent = try allocator.create(Node);
            errdefer allocator.destroy(parent);
            parent.* = .{ .n4 = .{ .prefix = parent_prefix } };

            if (old_prefix.len > 0) allocator.free(old_prefix);
            nodePrefix(old_node).* = old_suffix;
            insertSmall(4, &parent.n4, old_edge, old_node);

            if (branch_depth == key.len) {
                parent.n4.key = new_key.?;
                new_key = null;
                parent.n4.value = value;
                parent.n4.has_value = true;
            } else {
                insertSmall(4, &parent.n4, key[branch_depth], new_leaf.?);
                new_leaf = null;
            }

            slot.* = parent;
        }

        fn removeAt(allocator: Allocator, slot: *?*Node, key: []const u8, depth: usize) bool {
            const node = slot.* orelse return false;
            switch (node.*) {
                .leaf => |leaf| {
                    if (!std.mem.eql(u8, leaf.key, key)) return false;
                    destroyNode(allocator, node);
                    slot.* = null;
                    return true;
                },
                inline .n4, .n16, .n48, .n256 => |*inner| {
                    if (!matchPrefix(inner.prefix, key, depth)) return false;
                    const next_depth = depth + inner.prefix.len;
                    if (next_depth == key.len) {
                        if (!inner.has_value) return false;
                        if (inner.key.len > 0) allocator.free(inner.key);
                        inner.key = &.{};
                        inner.has_value = false;
                        rebalance(allocator, slot);
                        return true;
                    }

                    const edge = key[next_depth];
                    const child = childSlot(node, edge) orelse return false;
                    const removed = removeAt(allocator, child, key, next_depth + 1);
                    if (!removed) return false;
                    if (child.* == null) removeChild(node, edge);
                    rebalance(allocator, slot);
                    return true;
                },
            }
        }

        fn rebalance(allocator: Allocator, slot: *?*Node) void {
            demoteIfNeeded(allocator, slot);
            const node = slot.* orelse return;
            switch (node.*) {
                .leaf => return,
                inline .n4, .n16, .n48, .n256 => |*inner| {
                    if (inner.has_value) return;
                    if (inner.count == 0) {
                        destroyNode(allocator, node);
                        slot.* = null;
                        return;
                    }
                    if (inner.count == 1) compressSingleChild(allocator, slot);
                },
            }
        }

        fn compressSingleChild(allocator: Allocator, slot: *?*Node) void {
            const node = slot.*.?;
            const only = soleChild(node) orelse return;
            switch (only.child.*) {
                .leaf => {
                    slot.* = only.child;
                    freeInnerHeader(allocator, node);
                    allocator.destroy(node);
                },
                inline .n4, .n16, .n48, .n256 => |*child_inner| {
                    const parent_prefix = nodePrefix(node).*;
                    const merged = allocator.alloc(u8, parent_prefix.len + 1 + child_inner.prefix.len) catch return;
                    @memcpy(merged[0..parent_prefix.len], parent_prefix);
                    merged[parent_prefix.len] = only.edge;
                    @memcpy(merged[parent_prefix.len + 1 ..], child_inner.prefix);
                    if (child_inner.prefix.len > 0) allocator.free(child_inner.prefix);
                    child_inner.prefix = merged;
                    slot.* = only.child;
                    freeInnerHeader(allocator, node);
                    allocator.destroy(node);
                },
            }
        }

        fn addChild(allocator: Allocator, slot: *?*Node, edge: u8, child: *Node) !void {
            var node = slot.*.?;
            while (true) {
                switch (node.*) {
                    .leaf => unreachable,
                    .n4 => |*n| {
                        if (n.count < 4) {
                            insertSmall(4, n, edge, child);
                            return;
                        }
                        node = try promote4To16(allocator, slot);
                    },
                    .n16 => |*n| {
                        if (n.count < 16) {
                            insertSmall(16, n, edge, child);
                            return;
                        }
                        node = try promote16To48(allocator, slot);
                    },
                    .n48 => |*n| {
                        if (n.count < 48) {
                            const idx: u8 = n.count;
                            n.index[edge] = idx;
                            n.children[idx] = child;
                            n.count += 1;
                            return;
                        }
                        node = try promote48To256(allocator, slot);
                    },
                    .n256 => |*n| {
                        if (n.children[edge] == null) n.count += 1;
                        n.children[edge] = child;
                        return;
                    },
                }
            }
        }

        fn childSlot(node: *Node, edge: u8) ?*?*Node {
            switch (node.*) {
                .leaf => return null,
                inline .n4, .n16 => |*n| {
                    for (0..@as(usize, n.count)) |i| {
                        if (n.keys[i] == edge) return &n.children[i];
                    }
                    return null;
                },
                .n48 => |*n| {
                    const idx = n.index[edge];
                    if (idx == empty48) return null;
                    return &n.children[idx];
                },
                .n256 => |*n| return &n.children[edge],
            }
        }

        fn childPtrConst(node: *const Node, edge: u8) ?*Node {
            switch (node.*) {
                .leaf => return null,
                inline .n4, .n16 => |*n| {
                    for (0..@as(usize, n.count)) |i| {
                        if (n.keys[i] == edge) return n.children[i].?;
                    }
                    return null;
                },
                .n48 => |*n| {
                    const idx = n.index[edge];
                    if (idx == empty48) return null;
                    return n.children[idx].?;
                },
                .n256 => |*n| return n.children[edge],
            }
        }

        fn removeChild(node: *Node, edge: u8) void {
            switch (node.*) {
                .leaf => unreachable,
                inline .n4, .n16 => |*n| {
                    var idx: usize = 0;
                    while (idx < n.count and n.keys[idx] != edge) : (idx += 1) {}
                    if (idx == n.count) return;
                    const last = @as(usize, n.count - 1);
                    var i = idx;
                    while (i < last) : (i += 1) {
                        n.keys[i] = n.keys[i + 1];
                        n.children[i] = n.children[i + 1];
                    }
                    n.children[last] = null;
                    n.count -= 1;
                },
                .n48 => |*n| {
                    const idx = n.index[edge];
                    if (idx == empty48) return;
                    const last = n.count - 1;
                    n.children[idx] = null;
                    n.index[edge] = empty48;
                    if (idx != last) {
                        n.children[idx] = n.children[last];
                        n.children[last] = null;
                        for (0..256) |b| {
                            if (n.index[b] == last) {
                                n.index[b] = idx;
                                break;
                            }
                        }
                    }
                    n.count = last;
                },
                .n256 => |*n| {
                    n.children[edge] = null;
                    n.count -= 1;
                },
            }
        }

        fn demoteIfNeeded(allocator: Allocator, slot: *?*Node) void {
            const node = slot.* orelse return;
            switch (node.*) {
                .leaf, .n4 => return,
                .n16 => |*n| {
                    if (n.count <= 4) slot.* = demote16To4(allocator, node, n) catch node;
                },
                .n48 => |*n| {
                    if (n.count <= 16) slot.* = demote48To16(allocator, node, n) catch node;
                },
                .n256 => |*n| {
                    if (n.count <= 48) slot.* = demote256To48(allocator, node, n) catch node;
                },
            }
        }

        fn insertSmall(comptime cap: usize, n: *SmallNode(cap), edge: u8, child: *Node) void {
            var idx: usize = 0;
            while (idx < n.count and n.keys[idx] < edge) : (idx += 1) {}
            var move = @as(usize, n.count);
            while (move > idx) : (move -= 1) {
                n.keys[move] = n.keys[move - 1];
                n.children[move] = n.children[move - 1];
            }
            n.keys[idx] = edge;
            n.children[idx] = child;
            n.count += 1;
        }

        fn promote4To16(allocator: Allocator, slot: *?*Node) !*Node {
            const old = slot.*.?;
            const src = &old.n4;
            const new = try allocator.create(Node);
            new.* = .{ .n16 = .{
                .prefix = src.prefix,
                .has_value = src.has_value,
                .key = src.key,
                .value = src.value,
                .count = src.count,
            } };
            for (0..@as(usize, src.count)) |i| {
                new.n16.keys[i] = src.keys[i];
                new.n16.children[i] = src.children[i];
            }
            allocator.destroy(old);
            slot.* = new;
            return new;
        }

        fn promote16To48(allocator: Allocator, slot: *?*Node) !*Node {
            const old = slot.*.?;
            const src = &old.n16;
            const new = try allocator.create(Node);
            new.* = .{ .n48 = .{
                .prefix = src.prefix,
                .has_value = src.has_value,
                .key = src.key,
                .value = src.value,
                .count = src.count,
            } };
            for (0..@as(usize, src.count)) |i| {
                new.n48.index[src.keys[i]] = @intCast(i);
                new.n48.children[i] = src.children[i];
            }
            allocator.destroy(old);
            slot.* = new;
            return new;
        }

        fn promote48To256(allocator: Allocator, slot: *?*Node) !*Node {
            const old = slot.*.?;
            const src = &old.n48;
            const new = try allocator.create(Node);
            new.* = .{ .n256 = .{
                .prefix = src.prefix,
                .has_value = src.has_value,
                .key = src.key,
                .value = src.value,
                .count = src.count,
            } };
            for (0..256) |b| {
                const idx = src.index[b];
                if (idx != empty48) new.n256.children[b] = src.children[idx];
            }
            allocator.destroy(old);
            slot.* = new;
            return new;
        }

        fn demote16To4(allocator: Allocator, old: *Node, src: *Node16) !*Node {
            const new = try allocator.create(Node);
            new.* = .{ .n4 = .{
                .prefix = src.prefix,
                .has_value = src.has_value,
                .key = src.key,
                .value = src.value,
                .count = src.count,
            } };
            for (0..@as(usize, src.count)) |i| {
                new.n4.keys[i] = src.keys[i];
                new.n4.children[i] = src.children[i];
            }
            allocator.destroy(old);
            return new;
        }

        fn demote48To16(allocator: Allocator, old: *Node, src: *Node48) !*Node {
            const new = try allocator.create(Node);
            new.* = .{ .n16 = .{
                .prefix = src.prefix,
                .has_value = src.has_value,
                .key = src.key,
                .value = src.value,
                .count = src.count,
            } };
            var out: usize = 0;
            for (0..256) |b| {
                const idx = src.index[b];
                if (idx == empty48) continue;
                new.n16.keys[out] = @intCast(b);
                new.n16.children[out] = src.children[idx];
                out += 1;
            }
            allocator.destroy(old);
            return new;
        }

        fn demote256To48(allocator: Allocator, old: *Node, src: *Node256) !*Node {
            const new = try allocator.create(Node);
            new.* = .{ .n48 = .{
                .prefix = src.prefix,
                .has_value = src.has_value,
                .key = src.key,
                .value = src.value,
                .count = @intCast(src.count),
            } };
            var out: u8 = 0;
            for (0..256) |b| {
                if (src.children[b]) |child| {
                    new.n48.index[b] = out;
                    new.n48.children[out] = child;
                    out += 1;
                }
            }
            allocator.destroy(old);
            return new;
        }

        fn iteratePrefix(node: *const Node, prefix: []const u8, ctx: anytype, comptime cb: anytype) !void {
            switch (node.*) {
                .leaf => |leaf| {
                    if (std.mem.startsWith(u8, leaf.key, prefix)) try cb(ctx, leaf.key, leaf.value);
                },
                inline .n4, .n16 => |*n| {
                    if (n.has_value and std.mem.startsWith(u8, n.key, prefix)) try cb(ctx, n.key, n.value);
                    for (0..@as(usize, n.count)) |i| {
                        try iteratePrefix(n.children[i].?, prefix, ctx, cb);
                    }
                },
                .n48 => |*n| {
                    if (n.has_value and std.mem.startsWith(u8, n.key, prefix)) try cb(ctx, n.key, n.value);
                    for (0..256) |b| {
                        const idx = n.index[b];
                        if (idx != empty48) try iteratePrefix(n.children[idx].?, prefix, ctx, cb);
                    }
                },
                .n256 => |*n| {
                    if (n.has_value and std.mem.startsWith(u8, n.key, prefix)) try cb(ctx, n.key, n.value);
                    for (0..256) |b| {
                        if (n.children[b]) |child| try iteratePrefix(child, prefix, ctx, cb);
                    }
                },
            }
        }

        fn createLeaf(allocator: Allocator, key: []const u8, value: V) !*Node {
            const key_copy = try allocator.dupe(u8, key);
            errdefer allocator.free(key_copy);
            const node = try allocator.create(Node);
            node.* = .{ .leaf = .{ .key = key_copy, .value = value } };
            return node;
        }

        fn destroyNode(allocator: Allocator, node: *Node) void {
            switch (node.*) {
                .leaf => |leaf| {
                    if (leaf.key.len > 0) allocator.free(leaf.key);
                },
                inline .n4, .n16 => |*n| {
                    freeInnerFields(allocator, n.prefix, n.has_value, n.key);
                    for (0..@as(usize, n.count)) |i| destroyNode(allocator, n.children[i].?);
                },
                .n48 => |*n| {
                    freeInnerFields(allocator, n.prefix, n.has_value, n.key);
                    for (0..@as(usize, n.count)) |i| {
                        if (n.children[i]) |child| destroyNode(allocator, child);
                    }
                },
                .n256 => |*n| {
                    freeInnerFields(allocator, n.prefix, n.has_value, n.key);
                    for (0..256) |i| {
                        if (n.children[i]) |child| destroyNode(allocator, child);
                    }
                },
            }
            allocator.destroy(node);
        }

        fn freeInnerFields(allocator: Allocator, prefix: []u8, has_value: bool, key: []u8) void {
            if (prefix.len > 0) allocator.free(prefix);
            if (has_value and key.len > 0) allocator.free(key);
        }

        fn freeInnerHeader(allocator: Allocator, node: *Node) void {
            switch (node.*) {
                .leaf => unreachable,
                inline .n4, .n16, .n48, .n256 => |*n| freeInnerFields(allocator, n.prefix, n.has_value, n.key),
            }
        }

        fn nodePrefix(node: *Node) *[]u8 {
            switch (node.*) {
                .leaf => unreachable,
                inline .n4, .n16, .n48, .n256 => |*n| return &n.prefix,
            }
        }

        const OneChild = struct {
            edge: u8,
            child: *Node,
        };

        fn soleChild(node: *Node) ?OneChild {
            switch (node.*) {
                .leaf => return null,
                inline .n4, .n16 => |*n| return .{ .edge = n.keys[0], .child = n.children[0].? },
                .n48 => |*n| {
                    for (0..256) |b| {
                        const idx = n.index[b];
                        if (idx != empty48) return .{ .edge = @intCast(b), .child = n.children[idx].? };
                    }
                    return null;
                },
                .n256 => |*n| {
                    for (0..256) |b| {
                        if (n.children[b]) |child| return .{ .edge = @intCast(b), .child = child };
                    }
                    return null;
                },
            }
        }

        fn matchPrefix(prefix: []const u8, key: []const u8, depth: usize) bool {
            return key.len >= depth + prefix.len and std.mem.eql(u8, key[depth .. depth + prefix.len], prefix);
        }

        fn commonPrefixLen(a: []const u8, b: []const u8) usize {
            const n = @min(a.len, b.len);
            var i: usize = 0;
            while (i < n and a[i] == b[i]) : (i += 1) {}
            return i;
        }

        fn rootKindForTest(self: *const Self) u8 {
            const node = self.root orelse return 0;
            return switch (node.*) {
                .leaf => 1,
                .n4 => 4,
                .n16 => 16,
                .n48 => 48,
                .n256 => 255,
            };
        }
    };
}

test "insert and get many keys" {
    const allocator = std.testing.allocator;
    var art = Art(usize).init();
    defer art.deinit(allocator);

    var buf: [16]u8 = undefined;
    for (0..200) |i| {
        const key = try std.fmt.bufPrint(&buf, "key-{d}", .{i});
        try art.insert(allocator, key, i);
    }
    try std.testing.expectEqual(@as(usize, 200), art.len());

    for (0..200) |i| {
        const key = try std.fmt.bufPrint(&buf, "key-{d}", .{i});
        try std.testing.expectEqual(i, art.get(key).?);
    }
    try art.insert(allocator, "key-42", 9000);
    try std.testing.expectEqual(@as(usize, 200), art.len());
    try std.testing.expectEqual(@as(usize, 9000), art.get("key-42").?);
}

test "node promotion across all adaptive sizes" {
    const allocator = std.testing.allocator;
    var art = Art(u8).init();
    defer art.deinit(allocator);

    var key = [_]u8{'x', 0};
    for (0..5) |i| {
        key[1] = @intCast(i);
        try art.insert(allocator, &key, @intCast(i));
    }
    try std.testing.expectEqual(@as(u8, 16), art.rootKindForTest());

    for (5..17) |i| {
        key[1] = @intCast(i);
        try art.insert(allocator, &key, @intCast(i));
    }
    try std.testing.expectEqual(@as(u8, 48), art.rootKindForTest());

    for (17..49) |i| {
        key[1] = @intCast(i);
        try art.insert(allocator, &key, @intCast(i));
    }
    try std.testing.expectEqual(@as(u8, 255), art.rootKindForTest());
    try std.testing.expectEqual(@as(usize, 49), art.len());
}

test "remove and demote adaptive nodes" {
    const allocator = std.testing.allocator;
    var art = Art(u16).init();
    defer art.deinit(allocator);

    var key = [_]u8{'p', 0};
    for (0..49) |i| {
        key[1] = @intCast(i);
        try art.insert(allocator, &key, @intCast(i));
    }
    try std.testing.expectEqual(@as(u8, 255), art.rootKindForTest());

    key[1] = 48;
    try std.testing.expect(art.remove(allocator, &key));
    try std.testing.expectEqual(@as(u8, 48), art.rootKindForTest());

    for (16..48) |i| {
        key[1] = @intCast(i);
        try std.testing.expect(art.remove(allocator, &key));
    }
    try std.testing.expectEqual(@as(u8, 16), art.rootKindForTest());

    for (4..16) |i| {
        key[1] = @intCast(i);
        try std.testing.expect(art.remove(allocator, &key));
    }
    try std.testing.expectEqual(@as(u8, 4), art.rootKindForTest());
    try std.testing.expectEqual(@as(usize, 4), art.len());
}

test "longest prefix returns foo for foobar" {
    const allocator = std.testing.allocator;
    var art = Art(u8).init();
    defer art.deinit(allocator);

    try art.insert(allocator, "f", 1);
    try art.insert(allocator, "foo", 2);
    try art.insert(allocator, "foobaz", 3);

    const hit = art.longestPrefix("foobar").?;
    try std.testing.expectEqual(@as(usize, 3), hit.key_len);
    try std.testing.expectEqual(@as(u8, 2), hit.value);
}

test "prefix scan collects matches in key order" {
    const allocator = std.testing.allocator;
    var art = Art(u8).init();
    defer art.deinit(allocator);

    try art.insert(allocator, "car", 1);
    try art.insert(allocator, "cart", 2);
    try art.insert(allocator, "cat", 3);
    try art.insert(allocator, "dog", 4);

    const Collector = struct {
        keys: std.ArrayList([]const u8) = .empty,
        values: std.ArrayList(u8) = .empty,

        fn collect(self: *@This(), key: []const u8, value: u8) !void {
            try self.keys.append(std.testing.allocator, key);
            try self.values.append(std.testing.allocator, value);
        }
    };

    var collector: Collector = .{};
    defer collector.keys.deinit(allocator);
    defer collector.values.deinit(allocator);

    try art.prefixIterate("car", &collector, Collector.collect);
    try std.testing.expectEqual(@as(usize, 2), collector.keys.items.len);
    try std.testing.expectEqualStrings("car", collector.keys.items[0]);
    try std.testing.expectEqualStrings("cart", collector.keys.items[1]);
    try std.testing.expectEqual(@as(u8, 1), collector.values.items[0]);
    try std.testing.expectEqual(@as(u8, 2), collector.values.items[1]);
}

test "missing key returns null and removal reports false" {
    const allocator = std.testing.allocator;
    var art = Art(u8).init();
    defer art.deinit(allocator);

    try art.insert(allocator, "alpha", 1);
    try std.testing.expectEqual(@as(?u8, null), art.get("alp"));
    try std.testing.expectEqual(@as(?Art(u8).LongestPrefix, null), art.longestPrefix("beta"));
    try std.testing.expect(!art.remove(allocator, "beta"));
}

test "shared prefix leaf split preserves prefix key and longer keys" {
    const allocator = std.testing.allocator;
    var art = Art(u8).init();
    defer art.deinit(allocator);

    try art.insert(allocator, "foo", 1);
    try art.insert(allocator, "foobar", 2);
    try art.insert(allocator, "fooz", 3);

    try std.testing.expectEqual(@as(u8, 1), art.get("foo").?);
    try std.testing.expectEqual(@as(u8, 2), art.get("foobar").?);
    try std.testing.expectEqual(@as(u8, 3), art.get("fooz").?);
    try std.testing.expectEqual(@as(?u8, null), art.get("fo"));

    try std.testing.expect(art.remove(allocator, "foobar"));
    try std.testing.expectEqual(@as(u8, 1), art.get("foo").?);
    try std.testing.expectEqual(@as(u8, 3), art.get("fooz").?);
}

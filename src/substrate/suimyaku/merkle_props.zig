// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deterministic property tests for SUIMYAKU Merkle anti-entropy diffing.
const std = @import("std");

const merkle = @import("merkle.zig");

const Hash = merkle.Hash;
const MaxItems = 48;
const MaxKeyLen = 64;
const MaxAdversarialKeyLen = 256;

const Item = struct {
    key: [MaxKeyLen]u8,
    key_len: usize,
    value_hash: Hash,

    fn keySlice(self: *const Item) []const u8 {
        return self.key[0..self.key_len];
    }
};

fn keyLessThan(_: void, lhs: []const u8, rhs: []const u8) bool {
    return std.mem.order(u8, lhs, rhs) == .lt;
}

fn randomHash(random: std.Random) Hash {
    var out: Hash = undefined;
    random.bytes(&out);
    return out;
}

fn fillUniqueItem(random: std.Random, item: *Item, index: usize, salt: u16) void {
    item.key = undefined;
    item.key_len = 8 + random.uintLessThan(usize, MaxKeyLen - 7);

    item.key[0] = @intCast((@as(u16, @intCast(index)) >> 8) & 0xff);
    item.key[1] = @intCast(@as(u16, @intCast(index)) & 0xff);
    item.key[2] = @intCast((salt >> 8) & 0xff);
    item.key[3] = @intCast(salt & 0xff);
    random.bytes(item.key[4..item.key_len]);

    item.value_hash = randomHash(random);
}

fn fillItems(random: std.Random, items: []Item, salt: u16) void {
    for (items, 0..) |*item, index| {
        fillUniqueItem(random, item, index, salt);
    }
}

fn orderedIndices(order: []usize) void {
    for (order, 0..) |*slot, index| {
        slot.* = index;
    }
}

fn buildTree(
    allocator: std.mem.Allocator,
    items: []const Item,
    order: []const usize,
) !merkle.MerkleTree {
    var tree = merkle.MerkleTree.init(allocator);
    errdefer tree.deinit();

    for (order) |item_index| {
        try tree.put(items[item_index].keySlice(), items[item_index].value_hash);
    }

    return tree;
}

fn expectDifferentRoots(a: merkle.MerkleTree, b: merkle.MerkleTree) !void {
    const a_root = a.root();
    const b_root = b.root();
    try std.testing.expect(!std.mem.eql(u8, &a_root, &b_root));
}

fn expectDiffKeys(actual: []const []u8, expected: []const []const u8) !void {
    try std.testing.expectEqual(expected.len, actual.len);
    for (expected, 0..) |key, index| {
        try std.testing.expectEqualSlices(u8, key, actual[index]);
    }
}

fn changedExpectedKeys(items: []const Item, changed: []const bool, out: [][]const u8) []const []const u8 {
    var count: usize = 0;
    for (items, 0..) |*item, index| {
        if (changed[index]) {
            out[count] = item.keySlice();
            count += 1;
        }
    }

    const expected = out[0..count];
    std.mem.sort([]const u8, expected, {}, keyLessThan);
    return expected;
}

test "same key value set has equal root hashes" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x6d65_726b_6c65_0001);
    const random = prng.random();

    var iter: usize = 0;
    while (iter < 256) : (iter += 1) {
        const count = 1 + random.uintLessThan(usize, MaxItems);

        var items: [MaxItems]Item = undefined;
        fillItems(random, items[0..count], @intCast(iter));

        var a_order: [MaxItems]usize = undefined;
        var b_order: [MaxItems]usize = undefined;
        orderedIndices(a_order[0..count]);
        orderedIndices(b_order[0..count]);
        random.shuffle(usize, a_order[0..count]);
        random.shuffle(usize, b_order[0..count]);

        var a = try buildTree(allocator, items[0..count], a_order[0..count]);
        defer a.deinit();
        var b = try buildTree(allocator, items[0..count], b_order[0..count]);
        defer b.deinit();

        try std.testing.expectEqual(a.root(), b.root());
    }
}

test "single key or value difference changes the root hash" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x6d65_726b_6c65_0002);
    const random = prng.random();

    var iter: usize = 0;
    while (iter < 256) : (iter += 1) {
        const count = 1 + random.uintLessThan(usize, MaxItems);

        var items: [MaxItems]Item = undefined;
        fillItems(random, items[0..count], @intCast(iter));

        var changed_value = items;
        const changed_index = random.uintLessThan(usize, count);
        changed_value[changed_index].value_hash[0] ^= 0x80;

        var order: [MaxItems]usize = undefined;
        orderedIndices(order[0..count]);

        var original = try buildTree(allocator, items[0..count], order[0..count]);
        defer original.deinit();
        var value_changed = try buildTree(allocator, changed_value[0..count], order[0..count]);
        defer value_changed.deinit();
        try expectDifferentRoots(original, value_changed);

        var changed_key = items;
        changed_key[changed_index].key[0] ^= 0x40;

        var key_changed = try buildTree(allocator, changed_key[0..count], order[0..count]);
        defer key_changed.deinit();
        try expectDifferentRoots(original, key_changed);
    }
}

test "diff returns exactly changed keys for equal keyspaces" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x6d65_726b_6c65_0003);
    const random = prng.random();

    var iter: usize = 0;
    while (iter < 192) : (iter += 1) {
        const count = 1 + random.uintLessThan(usize, MaxItems);

        var local_items: [MaxItems]Item = undefined;
        fillItems(random, local_items[0..count], @intCast(iter));

        var remote_items = local_items;
        var changed: [MaxItems]bool = @splat(false);
        var changed_count: usize = 0;

        for (remote_items[0..count], 0..) |*item, index| {
            if (random.uintLessThan(u8, 5) == 0) {
                item.value_hash[index % item.value_hash.len] ^= @intCast(1 + (index % 251));
                changed[index] = true;
                changed_count += 1;
            }
        }
        if (changed_count == 0) {
            const index = random.uintLessThan(usize, count);
            remote_items[index].value_hash[0] ^= 1;
            changed[index] = true;
        }

        var order: [MaxItems]usize = undefined;
        orderedIndices(order[0..count]);

        var local = try buildTree(allocator, local_items[0..count], order[0..count]);
        defer local.deinit();
        var remote = try buildTree(allocator, remote_items[0..count], order[0..count]);
        defer remote.deinit();

        var expected_storage: [MaxItems][]const u8 = undefined;
        const expected = changedExpectedKeys(local_items[0..count], changed[0..count], &expected_storage);

        var diff = try merkle.diffTrees(allocator, &local, &remote);
        defer diff.deinit();
        try expectDiffKeys(diff.keys, expected);
    }
}

test "diff is symmetric for changed values" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x6d65_726b_6c65_0004);
    const random = prng.random();

    var iter: usize = 0;
    while (iter < 192) : (iter += 1) {
        const count = 2 + random.uintLessThan(usize, MaxItems - 1);

        var a_items: [MaxItems]Item = undefined;
        fillItems(random, a_items[0..count], @intCast(iter));

        var b_items = a_items;
        var changed: [MaxItems]bool = @splat(false);
        const changes = 1 + random.uintLessThan(usize, count);

        var change_iter: usize = 0;
        while (change_iter < changes) : (change_iter += 1) {
            const index = random.uintLessThan(usize, count);
            b_items[index].value_hash[(change_iter + index) % b_items[index].value_hash.len] ^= @intCast(1 + change_iter);
            changed[index] = true;
        }

        var order: [MaxItems]usize = undefined;
        orderedIndices(order[0..count]);

        var a = try buildTree(allocator, a_items[0..count], order[0..count]);
        defer a.deinit();
        var b = try buildTree(allocator, b_items[0..count], order[0..count]);
        defer b.deinit();

        var expected_storage: [MaxItems][]const u8 = undefined;
        const expected = changedExpectedKeys(a_items[0..count], changed[0..count], &expected_storage);

        var ab = try merkle.diffTrees(allocator, &a, &b);
        defer ab.deinit();
        var ba = try merkle.diffTrees(allocator, &b, &a);
        defer ba.deinit();

        try expectDiffKeys(ab.keys, expected);
        try expectDiffKeys(ba.keys, expected);
    }
}

test "building survives adversarial bounded inputs" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x6d65_726b_6c65_0005);
    const random = prng.random();

    var iter: usize = 0;
    while (iter < 256) : (iter += 1) {
        var tree = merkle.MerkleTree.init(allocator);
        defer tree.deinit();

        var op: usize = 0;
        while (op < 12) : (op += 1) {
            var key: [MaxAdversarialKeyLen]u8 = undefined;
            const key_len = switch (random.uintLessThan(u8, 8)) {
                0 => 0,
                1 => 1,
                2 => MaxAdversarialKeyLen,
                else => random.uintLessThan(usize, MaxAdversarialKeyLen + 1),
            };
            random.bytes(key[0..key_len]);

            if (random.boolean()) {
                try tree.put(key[0..key_len], randomHash(random));
            } else {
                _ = tree.remove(key[0..key_len]);
            }

            _ = tree.root();
        }
    }
}

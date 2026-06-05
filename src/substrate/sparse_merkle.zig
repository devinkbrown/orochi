const std = @import("std");

const Allocator = std.mem.Allocator;
const Blake3 = std.crypto.hash.Blake3;

pub const Hash = [Blake3.digest_length]u8;
pub const Key = [32]u8;

const proof_depth = 256;
const leaf_tag = [_]u8{0};
const branch_tag = [_]u8{1};
const empty_tag = [_]u8{2};

pub const Proof = struct {
    siblings: []Hash,
    found: bool,

    pub fn deinit(self: *Proof, allocator: Allocator) void {
        allocator.free(self.siblings);
        self.* = undefined;
    }
};

pub const SparseMerkleTree = struct {
    allocator: Allocator,
    leaves: std.AutoHashMap(Key, []u8),

    pub fn init(allocator: Allocator) SparseMerkleTree {
        return .{
            .allocator = allocator,
            .leaves = std.AutoHashMap(Key, []u8).init(allocator),
        };
    }

    pub fn deinit(self: *SparseMerkleTree) void {
        var it = self.leaves.valueIterator();
        while (it.next()) |value| self.allocator.free(value.*);
        self.leaves.deinit();
        self.* = undefined;
    }

    pub fn update(self: *SparseMerkleTree, key: Key, value: []const u8) !void {
        if (value.len == 0) {
            if (self.leaves.fetchRemove(key)) |entry| {
                self.allocator.free(entry.value);
            }
            return;
        }

        const copy = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(copy);

        const result = try self.leaves.getOrPut(key);
        if (result.found_existing) self.allocator.free(result.value_ptr.*);
        result.value_ptr.* = copy;
    }

    pub fn get(self: *const SparseMerkleTree, key: Key) ?[]const u8 {
        return self.leaves.get(key);
    }

    pub fn root(self: *const SparseMerkleTree) !Hash {
        const defaults = defaultHashes();
        return rootWithDefaults(self.allocator, &self.leaves, &defaults);
    }

    pub fn proof(self: *const SparseMerkleTree, key: Key) !Proof {
        const defaults = defaultHashes();
        var siblings: std.ArrayList(Hash) = .empty;
        errdefer siblings.deinit(self.allocator);

        var current = try leafLevel(self.allocator, &self.leaves);
        defer current.deinit();

        for (0..proof_depth) |level| {
            const bit_index: u8 = @intCast(proof_depth - 1 - level);
            const sibling_key = siblingKey(key, bit_index);
            const sibling_hash = current.get(sibling_key) orelse defaults[level];
            try siblings.append(self.allocator, sibling_hash);

            const next = try parentLevel(self.allocator, &current, defaults[level], defaults[level + 1], bit_index);
            current.deinit();
            current = next;
        }

        return .{
            .siblings = try siblings.toOwnedSlice(self.allocator),
            .found = self.leaves.contains(key),
        };
    }
};

pub fn emptyRoot() Hash {
    const defaults = defaultHashes();
    return defaults[proof_depth];
}

pub fn verify(expected_root: Hash, key: Key, value: []const u8, proof: Proof) bool {
    if (proof.siblings.len != proof_depth) return false;
    if (proof.found and value.len == 0) return false;
    if (!proof.found and value.len != 0) return false;

    const defaults = defaultHashes();
    var node = if (proof.found) leafHash(key, value) else defaults[0];

    for (proof.siblings, 0..) |sibling, level| {
        const bit_index: u8 = @intCast(proof_depth - 1 - level);
        if (bit(key, bit_index) == 0) {
            node = branchHash(node, sibling);
        } else {
            node = branchHash(sibling, node);
        }
    }

    return std.mem.eql(u8, &node, &expected_root);
}

fn rootWithDefaults(allocator: Allocator, leaves: *const std.AutoHashMap(Key, []u8), defaults: *const [proof_depth + 1]Hash) !Hash {
    if (leaves.count() == 0) return defaults[proof_depth];

    var current = try leafLevel(allocator, leaves);
    defer current.deinit();

    for (0..proof_depth) |level| {
        const bit_index: u8 = @intCast(proof_depth - 1 - level);
        const next = try parentLevel(allocator, &current, defaults[level], defaults[level + 1], bit_index);
        current.deinit();
        current = next;
    }

    var it = current.valueIterator();
    return if (it.next()) |root_hash| root_hash.* else defaults[proof_depth];
}

fn leafLevel(allocator: Allocator, leaves: *const std.AutoHashMap(Key, []u8)) !std.AutoHashMap(Key, Hash) {
    var current = std.AutoHashMap(Key, Hash).init(allocator);
    errdefer current.deinit();

    var it = leaves.iterator();
    while (it.next()) |entry| {
        try current.put(entry.key_ptr.*, leafHash(entry.key_ptr.*, entry.value_ptr.*));
    }

    return current;
}

fn parentLevel(
    allocator: Allocator,
    current: *const std.AutoHashMap(Key, Hash),
    default_child: Hash,
    default_parent: Hash,
    bit_index: u8,
) !std.AutoHashMap(Key, Hash) {
    var next = std.AutoHashMap(Key, Hash).init(allocator);
    errdefer next.deinit();

    var it = current.iterator();
    while (it.next()) |entry| {
        const left_key = withBit(entry.key_ptr.*, bit_index, 0);
        const right_key = withBit(left_key, bit_index, 1);
        const left_hash = current.get(left_key) orelse default_child;
        const right_hash = current.get(right_key) orelse default_child;
        const parent_hash = branchHash(left_hash, right_hash);

        if (!std.mem.eql(u8, &parent_hash, &default_parent)) {
            try next.put(left_key, parent_hash);
        }
    }

    return next;
}

fn defaultHashes() [proof_depth + 1]Hash {
    var hashes: [proof_depth + 1]Hash = undefined;
    hashes[0] = emptyLeafHash();
    for (1..hashes.len) |i| {
        hashes[i] = branchHash(hashes[i - 1], hashes[i - 1]);
    }
    return hashes;
}

fn emptyLeafHash() Hash {
    var hasher = Blake3.init(.{});
    hasher.update("mizuchi.smt.empty.v1");
    hasher.update(&empty_tag);
    var out: Hash = undefined;
    hasher.final(&out);
    return out;
}

fn leafHash(key: Key, value: []const u8) Hash {
    var hasher = Blake3.init(.{});
    var len_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &len_bytes, value.len, .little);

    hasher.update("mizuchi.smt.leaf.v1");
    hasher.update(&leaf_tag);
    hasher.update(&key);
    hasher.update(&len_bytes);
    hasher.update(value);

    var out: Hash = undefined;
    hasher.final(&out);
    return out;
}

fn branchHash(left: Hash, right: Hash) Hash {
    var hasher = Blake3.init(.{});
    hasher.update("mizuchi.smt.branch.v1");
    hasher.update(&branch_tag);
    hasher.update(&left);
    hasher.update(&right);

    var out: Hash = undefined;
    hasher.final(&out);
    return out;
}

fn bit(key: Key, bit_index: u8) u1 {
    const byte_index: usize = bit_index / 8;
    const shift: u3 = @intCast(7 - (bit_index % 8));
    return @intCast((key[byte_index] >> shift) & 1);
}

fn siblingKey(key: Key, bit_index: u8) Key {
    return withBit(key, bit_index, if (bit(key, bit_index) == 0) 1 else 0);
}

fn withBit(key: Key, bit_index: u8, value: u1) Key {
    var out = key;
    const byte_index: usize = bit_index / 8;
    const mask: u8 = @as(u8, 1) << @intCast(7 - (bit_index % 8));
    if (value == 1) {
        out[byte_index] |= mask;
    } else {
        out[byte_index] &= ~mask;
    }
    zeroAfter(&out, bit_index);
    return out;
}

fn zeroAfter(key: *Key, bit_index: u8) void {
    const first_zero_bit = @as(usize, bit_index) + 1;
    if (first_zero_bit >= proof_depth) return;

    const first_full_byte = (first_zero_bit + 7) / 8;
    if (first_full_byte > 0 and first_zero_bit % 8 != 0) {
        const keep_bits: u3 = @intCast(first_zero_bit % 8);
        const shift: u3 = @intCast(@as(u4, 8) - @as(u4, keep_bits));
        const mask = @as(u8, 0xff) << shift;
        key[first_full_byte - 1] &= mask;
    }
    if (first_full_byte < key.len) {
        @memset(key[first_full_byte..], 0);
    }
}

fn keyFromByte(byte: u8) Key {
    var key: Key = [_]u8{0} ** 32;
    key[31] = byte;
    return key;
}

test "update and get values" {
    var tree = SparseMerkleTree.init(std.testing.allocator);
    defer tree.deinit();

    const key = keyFromByte(42);
    try tree.update(key, "alpha");
    try std.testing.expectEqualStrings("alpha", tree.get(key).?);

    try tree.update(key, "beta");
    try std.testing.expectEqualStrings("beta", tree.get(key).?);
}

test "root changes on update and is deterministic" {
    var first = SparseMerkleTree.init(std.testing.allocator);
    defer first.deinit();
    var second = SparseMerkleTree.init(std.testing.allocator);
    defer second.deinit();

    const before = try first.root();
    const key_a = keyFromByte(1);
    const key_b = keyFromByte(2);

    try first.update(key_a, "one");
    const after = try first.root();
    try std.testing.expect(!std.mem.eql(u8, &before, &after));

    try first.update(key_b, "two");
    try second.update(key_b, "two");
    try second.update(key_a, "one");

    const first_root = try first.root();
    const second_root = try second.root();
    try std.testing.expectEqualSlices(u8, &first_root, &second_root);
}

test "inclusion proof verifies" {
    var tree = SparseMerkleTree.init(std.testing.allocator);
    defer tree.deinit();

    const key = keyFromByte(9);
    try tree.update(key, "included");
    try tree.update(keyFromByte(10), "neighbor");

    const root_hash = try tree.root();
    var p = try tree.proof(key);
    defer p.deinit(std.testing.allocator);

    try std.testing.expect(p.found);
    try std.testing.expect(verify(root_hash, key, "included", p));
}

test "non-inclusion proof verifies for an unset key" {
    var tree = SparseMerkleTree.init(std.testing.allocator);
    defer tree.deinit();

    try tree.update(keyFromByte(8), "present");
    const absent = keyFromByte(77);
    const root_hash = try tree.root();

    var p = try tree.proof(absent);
    defer p.deinit(std.testing.allocator);

    try std.testing.expect(!p.found);
    try std.testing.expect(verify(root_hash, absent, "", p));
}

test "tampered proof rejected" {
    var tree = SparseMerkleTree.init(std.testing.allocator);
    defer tree.deinit();

    const key = keyFromByte(3);
    try tree.update(key, "value");
    const root_hash = try tree.root();

    var p = try tree.proof(key);
    defer p.deinit(std.testing.allocator);

    p.siblings[0][0] ^= 1;
    try std.testing.expect(!verify(root_hash, key, "value", p));
}

test "delete by setting empty returns to known root" {
    var tree = SparseMerkleTree.init(std.testing.allocator);
    defer tree.deinit();

    const known_empty = emptyRoot();
    try tree.update(keyFromByte(4), "temporary");
    try tree.update(keyFromByte(4), "");

    const after_delete = try tree.root();
    try std.testing.expectEqualSlices(u8, &known_empty, &after_delete);
    try std.testing.expect(tree.get(keyFromByte(4)) == null);
}

test "empty-tree root constant" {
    var tree = SparseMerkleTree.init(std.testing.allocator);
    defer tree.deinit();

    const root_hash = try tree.root();
    const expected = emptyRoot();
    try std.testing.expectEqualSlices(u8, &expected, &root_hash);
}

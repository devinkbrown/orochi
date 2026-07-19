// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! UNDERTOW anti-entropy Merkle substrate.
//!
//! This module is pure state reconciliation logic: it stores `key -> value_hash`
//! entries, computes deterministic keyspace Merkle roots, and descends only
//! differing hash-prefix subtrees when producing repair keys.
const std = @import("std");

const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Hash = [32]u8;

const empty_hash = Hash{
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
const max_prefix_bits = 256;
const leaf_split_limit = 1;

const Entry = struct {
    key: []u8,
    key_hash: Hash,
    value_hash: Hash,
};

const KeyRef = struct {
    key: []const u8,
};

/// Set of remote keys whose value should be pulled for repair.
pub const DiffResult = struct {
    allocator: Allocator,
    keys: [][]u8,

    pub fn deinit(self: *DiffResult) void {
        for (self.keys) |key| self.allocator.free(key);
        self.allocator.free(self.keys);
        self.* = .{ .allocator = self.allocator, .keys = &.{} };
    }
};

/// Probe interface for a remote Merkle peer.
///
/// `hash(prefix, bits)` returns the peer's subtree root for the key-hash prefix.
/// `keys(prefix, bits, out)` appends peer keys in a terminal differing subtree.
/// This lets a future UNDERTOW transport back the same diff walk with network
/// probes instead of an in-memory `MerkleTree`.
pub const NodeProbe = struct {
    ptr: *const anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        hash: *const fn (ctx: *const anyopaque, prefix: Hash, bits: u16) Hash,
        keys: *const fn (ctx: *const anyopaque, allocator: Allocator, prefix: Hash, bits: u16, out: *std.ArrayList(KeyRef)) Allocator.Error!void,
    };

    pub fn hash(self: NodeProbe, prefix: Hash, bits: u16) Hash {
        return self.vtable.hash(self.ptr, prefix, bits);
    }

    pub fn keys(self: NodeProbe, allocator: Allocator, prefix: Hash, bits: u16, out: *std.ArrayList(KeyRef)) Allocator.Error!void {
        return self.vtable.keys(self.ptr, allocator, prefix, bits, out);
    }
};

/// Owned keyspace Merkle tree over `key -> value_hash`.
///
/// Hashing uses SHA-256 with explicit domain tags for empty subtrees, leaves,
/// and internal nodes. This is heavier than the eventual hot-path skeleton may
/// need, but it gives deterministic collision-resistant fingerprints now and
/// avoids cross-protocol hash reuse as UNDERTOW grows more frame families.
pub const MerkleTree = struct {
    allocator: Allocator,
    entries: std.ArrayList(Entry) = .empty,

    pub fn init(allocator: Allocator) MerkleTree {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *MerkleTree) void {
        for (self.entries.items) |entry| self.allocator.free(entry.key);
        self.entries.deinit(self.allocator);
        self.* = .{ .allocator = self.allocator };
    }

    pub fn len(self: *const MerkleTree) usize {
        return self.entries.items.len;
    }

    /// Insert or update a key's value hash.
    pub fn put(self: *MerkleTree, key: []const u8, value_hash: Hash) Allocator.Error!void {
        const found = self.findKey(key);
        if (found.exists) {
            self.entries.items[found.index].value_hash = value_hash;
            return;
        }

        const owned_key = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(owned_key);

        try self.entries.insert(self.allocator, found.index, .{
            .key = owned_key,
            .key_hash = hashKey(key),
            .value_hash = value_hash,
        });
    }

    /// Remove a key. Returns true when an entry existed.
    pub fn remove(self: *MerkleTree, key: []const u8) bool {
        const found = self.findKey(key);
        if (!found.exists) return false;

        const removed = self.entries.orderedRemove(found.index);
        self.allocator.free(removed.key);
        return true;
    }

    /// Root hash of the whole keyspace.
    pub fn root(self: *const MerkleTree) Hash {
        return self.subtreeHash(empty_hash, 0);
    }

    pub fn probe(self: *const MerkleTree) NodeProbe {
        return .{ .ptr = self, .vtable = &probe_vtable };
    }

    fn subtreeHash(self: *const MerkleTree, prefix: Hash, bits: u16) Hash {
        return hashRange(self.entries.items, prefix, bits);
    }

    fn appendKeysInPrefix(
        self: *const MerkleTree,
        allocator: Allocator,
        prefix: Hash,
        bits: u16,
        out: *std.ArrayList(KeyRef),
    ) Allocator.Error!void {
        for (self.entries.items) |entry| {
            if (hasPrefix(entry.key_hash, prefix, bits)) {
                try out.append(allocator, .{ .key = entry.key });
            }
        }
    }

    const FindResult = struct {
        index: usize,
        exists: bool,
    };

    fn findKey(self: *const MerkleTree, key: []const u8) FindResult {
        var low: usize = 0;
        var high: usize = self.entries.items.len;
        while (low < high) {
            const mid = low + (high - low) / 2;
            const order = std.mem.order(u8, self.entries.items[mid].key, key);
            switch (order) {
                .lt => low = mid + 1,
                .eq => return .{ .index = mid, .exists = true },
                .gt => high = mid,
            }
        }
        return .{ .index = low, .exists = false };
    }

    fn probeHash(ctx: *const anyopaque, prefix: Hash, bits: u16) Hash {
        const self: *const MerkleTree = @ptrCast(@alignCast(ctx));
        return self.subtreeHash(prefix, bits);
    }

    fn probeKeys(
        ctx: *const anyopaque,
        allocator: Allocator,
        prefix: Hash,
        bits: u16,
        out: *std.ArrayList(KeyRef),
    ) Allocator.Error!void {
        const self: *const MerkleTree = @ptrCast(@alignCast(ctx));
        return self.appendKeysInPrefix(allocator, prefix, bits, out);
    }

    const probe_vtable = NodeProbe.VTable{
        .hash = probeHash,
        .keys = probeKeys,
    };
};

/// Diff two in-memory trees and return remote keys to pull.
///
/// Equal subtree hashes stop the walk immediately. Differing subtrees are split
/// by SHA-256 key-hash prefix until the remote side has at most one key or the
/// 256-bit keyspace is exhausted.
pub fn diffTrees(allocator: Allocator, local: *const MerkleTree, remote: *const MerkleTree) Allocator.Error!DiffResult {
    return diffProbe(allocator, local, remote.probe());
}

/// Diff local state against any remote node-hash probe.
pub fn diffProbe(allocator: Allocator, local: *const MerkleTree, remote: NodeProbe) Allocator.Error!DiffResult {
    var keys: std.ArrayList([]u8) = .empty;
    errdefer {
        for (keys.items) |key| allocator.free(key);
        keys.deinit(allocator);
    }

    try diffPrefix(allocator, local, remote, empty_hash, 0, &keys);
    std.mem.sort([]u8, keys.items, {}, keyLessThan);

    const owned = try keys.toOwnedSlice(allocator);
    return .{ .allocator = allocator, .keys = owned };
}

fn keyLessThan(_: void, lhs: []u8, rhs: []u8) bool {
    return std.mem.order(u8, lhs, rhs) == .lt;
}

fn diffPrefix(
    allocator: Allocator,
    local: *const MerkleTree,
    remote: NodeProbe,
    prefix: Hash,
    bits: u16,
    out: *std.ArrayList([]u8),
) Allocator.Error!void {
    const local_hash = local.subtreeHash(prefix, bits);
    const remote_hash = remote.hash(prefix, bits);
    if (std.mem.eql(u8, &local_hash, &remote_hash)) return;

    var remote_keys: std.ArrayList(KeyRef) = .empty;
    defer remote_keys.deinit(allocator);
    try remote.keys(allocator, prefix, bits, &remote_keys);

    if (remote_keys.items.len <= leaf_split_limit or bits == max_prefix_bits) {
        for (remote_keys.items) |ref| {
            const key_copy = try allocator.dupe(u8, ref.key);
            errdefer allocator.free(key_copy);
            try out.append(allocator, key_copy);
        }
        return;
    }

    try diffPrefix(allocator, local, remote, childPrefix(prefix, bits, 0), bits + 1, out);
    try diffPrefix(allocator, local, remote, childPrefix(prefix, bits, 1), bits + 1, out);
}

fn hashRange(entries: []const Entry, prefix: Hash, bits: u16) Hash {
    var matching: usize = 0;
    var only: ?Entry = null;

    for (entries) |entry| {
        if (hasPrefix(entry.key_hash, prefix, bits)) {
            matching += 1;
            only = entry;
            if (matching > 1) break;
        }
    }

    if (matching == 0) return hashEmpty(prefix, bits);
    if (matching == 1) return hashLeaf(only.?);
    if (bits == max_prefix_bits) return hashBucket(entries, prefix, bits, matching);

    const left = hashRange(entries, childPrefix(prefix, bits, 0), bits + 1);
    const right = hashRange(entries, childPrefix(prefix, bits, 1), bits + 1);
    return hashNode(prefix, bits, left, right);
}

fn hashEmpty(prefix: Hash, bits: u16) Hash {
    var h = Sha256.init(.{});
    h.update("onyx_server.suimyaku.merkle.empty.v1");
    updateU16(&h, bits);
    h.update(&prefix);
    var out: Hash = undefined;
    h.final(&out);
    return out;
}

fn hashLeaf(entry: Entry) Hash {
    var h = Sha256.init(.{});
    h.update("onyx_server.suimyaku.merkle.leaf.v1");
    updateU64(&h, entry.key.len);
    h.update(entry.key);
    h.update(&entry.value_hash);
    var out: Hash = undefined;
    h.final(&out);
    return out;
}

fn hashNode(prefix: Hash, bits: u16, left: Hash, right: Hash) Hash {
    var h = Sha256.init(.{});
    h.update("onyx_server.suimyaku.merkle.node.v1");
    updateU16(&h, bits);
    h.update(&prefix);
    h.update(&left);
    h.update(&right);
    var out: Hash = undefined;
    h.final(&out);
    return out;
}

fn hashBucket(entries: []const Entry, prefix: Hash, bits: u16, count: usize) Hash {
    var h = Sha256.init(.{});
    h.update("onyx_server.suimyaku.merkle.bucket.v1");
    updateU16(&h, bits);
    updateU64(&h, count);
    h.update(&prefix);

    for (entries) |entry| {
        if (hasPrefix(entry.key_hash, prefix, bits)) {
            const leaf = hashLeaf(entry);
            h.update(&leaf);
        }
    }

    var out: Hash = undefined;
    h.final(&out);
    return out;
}

fn hashKey(key: []const u8) Hash {
    var out: Hash = undefined;
    Sha256.hash(key, &out, .{});
    return out;
}

fn valueHash(value: []const u8) Hash {
    var out: Hash = undefined;
    Sha256.hash(value, &out, .{});
    return out;
}

fn childPrefix(prefix: Hash, bits: u16, bit: u1) Hash {
    var out = prefix;
    setBit(&out, bits, bit);
    clearAfter(&out, bits + 1);
    return out;
}

fn hasPrefix(hash: Hash, prefix: Hash, bits: u16) bool {
    var i: u16 = 0;
    while (i < bits) : (i += 1) {
        if (getBit(hash, i) != getBit(prefix, i)) return false;
    }
    return true;
}

fn getBit(bytes: Hash, bit_index: u16) u1 {
    const byte_index: usize = @as(usize, bit_index) / 8;
    const shift: u3 = @intCast(7 - (@as(usize, bit_index) % 8));
    return @intCast((bytes[byte_index] >> shift) & 1);
}

fn setBit(bytes: *Hash, bit_index: u16, bit: u1) void {
    const byte_index: usize = @as(usize, bit_index) / 8;
    const shift: u3 = @intCast(7 - (@as(usize, bit_index) % 8));
    const mask: u8 = @as(u8, 1) << shift;
    if (bit == 1) {
        bytes[byte_index] |= mask;
    } else {
        bytes[byte_index] &= ~mask;
    }
}

fn clearAfter(bytes: *Hash, bits: u16) void {
    if (bits >= max_prefix_bits) return;

    const full_bytes: usize = @as(usize, bits) / 8;
    const rem_bits: u3 = @intCast(@as(usize, bits) % 8);

    if (rem_bits == 0) {
        @memset(bytes[full_bytes..], 0);
        return;
    }

    const shift: u3 = @intCast(8 - @as(u4, rem_bits));
    const keep_mask: u8 = @as(u8, 0xff) << shift;
    bytes[full_bytes] &= keep_mask;
    if (full_bytes + 1 < bytes.len) @memset(bytes[full_bytes + 1 ..], 0);
}

fn updateU16(h: *Sha256, value: u16) void {
    var buf: [2]u8 = undefined;
    std.mem.writeInt(u16, &buf, value, .big);
    h.update(&buf);
}

fn updateU64(h: *Sha256, value: usize) void {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, @intCast(value), .big);
    h.update(&buf);
}

fn expectKeys(actual: []const []u8, expected: []const []const u8) !void {
    try std.testing.expectEqual(expected.len, actual.len);
    for (expected, 0..) |key, i| {
        try std.testing.expectEqualStrings(key, actual[i]);
    }
}

test "equal content has equal root regardless of insertion order" {
    const allocator = std.testing.allocator;
    var a = MerkleTree.init(allocator);
    defer a.deinit();
    var b = MerkleTree.init(allocator);
    defer b.deinit();

    try a.put("alpha", valueHash("1"));
    try a.put("beta", valueHash("2"));
    try a.put("gamma", valueHash("3"));

    try b.put("gamma", valueHash("3"));
    try b.put("alpha", valueHash("1"));
    try b.put("beta", valueHash("2"));

    try std.testing.expectEqual(a.root(), b.root());
}

test "single key divergence detected" {
    const allocator = std.testing.allocator;
    var local = MerkleTree.init(allocator);
    defer local.deinit();
    var remote = MerkleTree.init(allocator);
    defer remote.deinit();

    try local.put("nick:kain", valueHash("old"));
    try remote.put("nick:kain", valueHash("new"));

    var diff = try diffTrees(allocator, &local, &remote);
    defer diff.deinit();

    try expectKeys(diff.keys, &.{"nick:kain"});
}

test "empty tree root is stable" {
    const allocator = std.testing.allocator;
    var a = MerkleTree.init(allocator);
    defer a.deinit();
    var b = MerkleTree.init(allocator);
    defer b.deinit();

    try std.testing.expectEqual(a.root(), b.root());
    try std.testing.expectEqual(a.root(), hashEmpty(empty_hash, 0));
}

test "diff returns exactly the changed keys" {
    const allocator = std.testing.allocator;
    var local = MerkleTree.init(allocator);
    defer local.deinit();
    var remote = MerkleTree.init(allocator);
    defer remote.deinit();

    try local.put("chan:#ops:topic", valueHash("same"));
    try local.put("nick:kain", valueHash("old"));
    try local.put("uid:001", valueHash("present"));

    try remote.put("chan:#ops:topic", valueHash("same"));
    try remote.put("nick:kain", valueHash("new"));
    try remote.put("uid:001", valueHash("present"));
    try remote.put("uid:002", valueHash("remote-only"));

    var diff = try diffTrees(allocator, &local, &remote);
    defer diff.deinit();

    try expectKeys(diff.keys, &.{ "nick:kain", "uid:002" });
}

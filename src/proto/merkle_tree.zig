// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Binary Merkle trees over SHA-256 leaf hashes for state reconciliation.
const std = @import("std");

comptime {
    if (@bitSizeOf(usize) != 64) @compileError("merkle_tree requires a 64-bit target");
}

const Sha256 = std.crypto.hash.sha2.Sha256;

/// A SHA-256 digest used as a leaf, branch, proof item, or root hash.
pub const Hash = [Sha256.digest_length]u8;

/// Compile-time limits for bounded Merkle tree work buffers.
pub const Params = struct {
    /// Maximum number of leaf hashes accepted by build and proof generation.
    max_leaves: usize = 65_536,
    /// Maximum sibling hashes emitted for one proof.
    max_proof_hashes: usize = 64,
};

/// Errors returned by bounded Merkle tree operations.
pub const MerkleError = std.mem.Allocator.Error || error{
    EmptyLeaves,
    TooManyLeaves,
    IndexOutOfBounds,
    ProofTooLong,
};

/// Parameterized Merkle tree worker using caller-owned allocation.
pub fn MerkleTree(comptime params: Params) type {
    comptime {
        if (params.max_leaves == 0) @compileError("Merkle tree needs leaf storage");
        if (params.max_proof_hashes == 0) @compileError("Merkle tree needs proof storage");
    }

    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,

        /// Initialize a Merkle tree worker with the supplied allocator.
        pub fn init(allocator: std.mem.Allocator) Self {
            return .{ .allocator = allocator };
        }

        /// Release worker state.
        pub fn deinit(self: *Self) void {
            self.* = undefined;
        }

        /// Build the root hash for `leaves`.
        ///
        /// `leaves` are already SHA-256 leaf hashes. Internal nodes are
        /// domain-separated as `SHA256(0x01 || min(left, right) || max(left, right))`,
        /// which lets a proof carry only sibling hashes while `verify` remains
        /// independent of the original leaf index.
        pub fn build(self: *const Self, leaves: []const Hash) MerkleError!Hash {
            try validateLeafCount(params, leaves.len);

            const work = try self.allocator.alloc(Hash, leaves.len);
            defer self.allocator.free(work);
            @memcpy(work, leaves);

            var count = leaves.len;
            while (count > 1) {
                count = reduceLevel(work, count);
            }

            return work[0];
        }

        /// Build an owned proof for `leaves[index]`.
        ///
        /// The returned slice belongs to the caller and must be freed with the
        /// same allocator passed to `init`.
        pub fn proof(self: *const Self, leaves: []const Hash, index: usize) MerkleError![]Hash {
            try validateLeafCount(params, leaves.len);
            if (index >= leaves.len) return error.IndexOutOfBounds;

            var proof_hashes = std.ArrayListUnmanaged(Hash).empty;
            errdefer proof_hashes.deinit(self.allocator);

            const work = try self.allocator.alloc(Hash, leaves.len);
            defer self.allocator.free(work);
            @memcpy(work, leaves);

            var count = leaves.len;
            var cursor = index;
            while (count > 1) {
                if ((cursor & 1) == 0) {
                    if (cursor + 1 < count) {
                        try appendProofHash(params, self.allocator, &proof_hashes, work[cursor + 1]);
                    }
                } else {
                    try appendProofHash(params, self.allocator, &proof_hashes, work[cursor - 1]);
                }

                count = reduceLevel(work, count);
                cursor /= 2;
            }

            return proof_hashes.toOwnedSlice(self.allocator);
        }
    };
}

/// Default bounded Merkle tree worker.
pub const DefaultTree = MerkleTree(.{});

/// Build the root hash for the default limits.
pub fn build(allocator: std.mem.Allocator, leaves: []const Hash) MerkleError!Hash {
    var tree = DefaultTree.init(allocator);
    defer tree.deinit();
    return tree.build(leaves);
}

/// Build an owned proof for `leaves[index]` using the default limits.
///
/// The returned slice belongs to the caller and must be freed with `allocator`.
pub fn proof(allocator: std.mem.Allocator, leaves: []const Hash, index: usize) MerkleError![]Hash {
    var tree = DefaultTree.init(allocator);
    defer tree.deinit();
    return tree.proof(leaves, index);
}

/// Verify that `proof_hashes` connects `leaf` to `root`.
pub fn verify(leaf: Hash, proof_hashes: []const Hash, root: Hash) bool {
    var cursor = leaf;
    for (proof_hashes) |sibling| {
        cursor = hashPair(cursor, sibling);
    }
    return std.mem.eql(u8, &cursor, &root);
}

/// Hash arbitrary leaf bytes as SHA-256.
pub fn hashLeaf(bytes: []const u8) Hash {
    var out: Hash = undefined;
    Sha256.hash(bytes, &out, .{});
    return out;
}

fn validateLeafCount(comptime params: Params, count: usize) MerkleError!void {
    if (count == 0) return error.EmptyLeaves;
    if (count > params.max_leaves) return error.TooManyLeaves;
}

fn appendProofHash(
    comptime params: Params,
    allocator: std.mem.Allocator,
    proof_hashes: *std.ArrayListUnmanaged(Hash),
    hash: Hash,
) MerkleError!void {
    if (proof_hashes.items.len >= params.max_proof_hashes) return error.ProofTooLong;
    try proof_hashes.append(allocator, hash);
}

fn reduceLevel(work: []Hash, count: usize) usize {
    var read: usize = 0;
    var write: usize = 0;
    while (read < count) : (read += 2) {
        if (read + 1 < count) {
            work[write] = hashPair(work[read], work[read + 1]);
        } else {
            work[write] = work[read];
        }
        write += 1;
    }
    return write;
}

fn hashPair(a: Hash, b: Hash) Hash {
    const ordered = orderPair(a, b);

    var h = Sha256.init(.{});
    h.update(&[_]u8{0x01});
    h.update(&ordered.left);
    h.update(&ordered.right);

    var out: Hash = undefined;
    h.final(&out);
    return out;
}

fn orderPair(a: Hash, b: Hash) struct { left: Hash, right: Hash } {
    if (hashLessThan(b, a)) {
        return .{ .left = b, .right = a };
    }
    return .{ .left = a, .right = b };
}

fn hashLessThan(a: Hash, b: Hash) bool {
    for (a, b) |x, y| {
        if (x < y) return true;
        if (x > y) return false;
    }
    return false;
}

test "build returns deterministic root for repeated inputs" {
    // Arrange
    const allocator = std.testing.allocator;
    const leaves = [_]Hash{
        hashLeaf("one"),
        hashLeaf("two"),
        hashLeaf("three"),
        hashLeaf("four"),
    };

    // Act
    const first = try build(allocator, &leaves);
    const second = try build(allocator, &leaves);
    const changed = try build(allocator, &.{ leaves[0], hashLeaf("changed"), leaves[2], leaves[3] });

    // Assert
    try std.testing.expect(std.mem.eql(u8, &first, &second));
    try std.testing.expect(!std.mem.eql(u8, &first, &changed));
}

test "proof verifies true for every leaf and false for tampered inputs" {
    // Arrange
    const allocator = std.testing.allocator;
    const leaves = [_]Hash{
        hashLeaf("alpha"),
        hashLeaf("bravo"),
        hashLeaf("charlie"),
        hashLeaf("delta"),
        hashLeaf("echo"),
        hashLeaf("foxtrot"),
    };
    const root = try build(allocator, &leaves);

    // Act and Assert
    for (leaves, 0..) |leaf, index| {
        const proof_hashes = try proof(allocator, &leaves, index);
        defer allocator.free(proof_hashes);

        try std.testing.expect(verify(leaf, proof_hashes, root));
        try std.testing.expect(!verify(hashLeaf("wrong leaf"), proof_hashes, root));
        try std.testing.expect(!verify(leaf, proof_hashes, hashLeaf("wrong root")));
    }
}

test "single leaf root is the leaf and proof is empty" {
    // Arrange
    const allocator = std.testing.allocator;
    const leaves = [_]Hash{hashLeaf("solo")};

    // Act
    const root = try build(allocator, &leaves);
    const proof_hashes = try proof(allocator, &leaves, 0);
    defer allocator.free(proof_hashes);

    // Assert
    try std.testing.expect(std.mem.eql(u8, &leaves[0], &root));
    try std.testing.expectEqual(@as(usize, 0), proof_hashes.len);
    try std.testing.expect(verify(leaves[0], proof_hashes, root));
}

test "odd leaf counts carry the final hash and still verify proofs" {
    // Arrange
    const allocator = std.testing.allocator;
    const leaves = [_]Hash{
        hashLeaf("red"),
        hashLeaf("green"),
        hashLeaf("blue"),
        hashLeaf("cyan"),
        hashLeaf("magenta"),
    };

    // Act
    const root = try build(allocator, &leaves);
    const carried_proof = try proof(allocator, &leaves, leaves.len - 1);
    defer allocator.free(carried_proof);
    const middle_proof = try proof(allocator, &leaves, 2);
    defer allocator.free(middle_proof);

    // Assert
    try std.testing.expect(verify(leaves[leaves.len - 1], carried_proof, root));
    try std.testing.expect(verify(leaves[2], middle_proof, root));
    try std.testing.expect(carried_proof.len < middle_proof.len);
}

test "bounded errors reject empty leaves, too many leaves, bad indexes, and long proofs" {
    // Arrange
    const allocator = std.testing.allocator;
    const SmallTree = MerkleTree(.{ .max_leaves = 3, .max_proof_hashes = 1 });
    var tree = SmallTree.init(allocator);
    defer tree.deinit();
    const leaves = [_]Hash{ hashLeaf("a"), hashLeaf("b"), hashLeaf("c") };

    // Act and Assert
    try std.testing.expectError(error.EmptyLeaves, tree.build(&.{}));
    try std.testing.expectError(error.TooManyLeaves, tree.build(&.{ leaves[0], leaves[1], leaves[2], hashLeaf("d") }));
    try std.testing.expectError(error.IndexOutOfBounds, tree.proof(leaves[0..2], 2));
    try std.testing.expectError(error.ProofTooLong, tree.proof(&leaves, 0));
}

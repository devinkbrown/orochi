const std = @import("std");

pub const Hash = [32]u8;

pub const Side = enum {
    left,
    right,
};

pub const ProofStep = struct {
    side: Side,
    hash: Hash,
};

pub const Proof = struct {
    path: []ProofStep,
    peaks: []Hash,

    pub fn deinit(self: *Proof, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        allocator.free(self.peaks);
        self.path = &[_]ProofStep{};
        self.peaks = &[_]Hash{};
    }
};

pub const MerkleMountainRange = struct {
    allocator: std.mem.Allocator,
    leaves: std.ArrayList(Hash) = .empty,

    pub fn init(allocator: std.mem.Allocator) MerkleMountainRange {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *MerkleMountainRange) void {
        self.leaves.deinit(self.allocator);
    }

    pub fn len(self: *const MerkleMountainRange) usize {
        return self.leaves.items.len;
    }

    pub fn append(self: *MerkleMountainRange, leaf: []const u8) !usize {
        const position = self.leaves.items.len;
        try self.leaves.append(self.allocator, leafHash(leaf));
        return position;
    }

    pub fn root(self: *const MerkleMountainRange) Hash {
        return rootFromLeaves(self.leaves.items);
    }

    pub fn proof(self: *const MerkleMountainRange, leaf_index: usize) !Proof {
        if (leaf_index >= self.leaves.items.len) return error.IndexOutOfRange;

        var path: std.ArrayList(ProofStep) = .empty;
        errdefer path.deinit(self.allocator);

        var other_peaks: std.ArrayList(Hash) = .empty;
        errdefer other_peaks.deinit(self.allocator);

        var start: usize = 0;
        var remaining = self.leaves.items.len;
        while (remaining != 0) {
            const peak_size = largestPowerOfTwo(remaining);
            if (leaf_index >= start and leaf_index < start + peak_size) {
                _ = try appendPath(
                    self.allocator,
                    self.leaves.items,
                    start,
                    peak_size,
                    leaf_index,
                    &path,
                );
            } else {
                try other_peaks.append(
                    self.allocator,
                    peakHashFromLeaves(self.leaves.items, start, peak_size),
                );
            }
            start += peak_size;
            remaining -= peak_size;
        }

        const owned_path = try path.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(owned_path);
        const owned_peaks = try other_peaks.toOwnedSlice(self.allocator);

        return .{
            .path = owned_path,
            .peaks = owned_peaks,
        };
    }
};

pub const MMR = MerkleMountainRange;

pub fn verify(
    expected_root: Hash,
    leaf: []const u8,
    inclusion: Proof,
    leaf_index: usize,
    size: usize,
) bool {
    if (size == 0 or leaf_index >= size) return false;

    const target = peakInfoForIndex(size, leaf_index) orelse return false;
    if (inclusion.path.len != target.height) return false;
    if (inclusion.peaks.len + 1 != countPeaks(size)) return false;

    var current = leafHash(leaf);
    const relative_index = leaf_index - target.start;
    for (inclusion.path, 0..) |step, level| {
        const bit = (relative_index >> @intCast(level)) & 1;
        const expected_side: Side = if (bit == 0) .right else .left;
        if (step.side != expected_side) return false;
        current = switch (step.side) {
            .left => parentHash(step.hash, current),
            .right => parentHash(current, step.hash),
        };
    }

    var accumulated: Hash = undefined;
    var have_accumulated = false;
    var other_index: usize = 0;
    var peak_index: usize = 0;
    var start: usize = 0;
    var remaining = size;

    while (remaining != 0) {
        const peak_size = largestPowerOfTwo(remaining);
        const peak_hash = if (peak_index == target.peak_index) blk: {
            break :blk current;
        } else blk: {
            if (other_index >= inclusion.peaks.len) return false;
            const peak = inclusion.peaks[other_index];
            other_index += 1;
            break :blk peak;
        };

        if (have_accumulated) {
            accumulated = bagHash(accumulated, peak_hash);
        } else {
            accumulated = peak_hash;
            have_accumulated = true;
        }

        start += peak_size;
        remaining -= peak_size;
        peak_index += 1;
    }

    if (other_index != inclusion.peaks.len) return false;
    return std.mem.eql(u8, &accumulated, &expected_root);
}

fn rootFromLeaves(leaves: []const Hash) Hash {
    if (leaves.len == 0) return emptyRoot();

    var accumulated: Hash = undefined;
    var have_accumulated = false;
    var start: usize = 0;
    var remaining = leaves.len;

    while (remaining != 0) {
        const peak_size = largestPowerOfTwo(remaining);
        const peak = peakHashFromLeaves(leaves, start, peak_size);
        if (have_accumulated) {
            accumulated = bagHash(accumulated, peak);
        } else {
            accumulated = peak;
            have_accumulated = true;
        }
        start += peak_size;
        remaining -= peak_size;
    }

    return accumulated;
}

fn appendPath(
    allocator: std.mem.Allocator,
    leaves: []const Hash,
    start: usize,
    size: usize,
    leaf_index: usize,
    path: *std.ArrayList(ProofStep),
) !Hash {
    if (size == 1) return leaves[start];

    const half = size / 2;
    const right_start = start + half;
    if (leaf_index < right_start) {
        const left = try appendPath(allocator, leaves, start, half, leaf_index, path);
        const right = peakHashFromLeaves(leaves, right_start, half);
        try path.append(allocator, .{ .side = .right, .hash = right });
        return parentHash(left, right);
    }

    const left = peakHashFromLeaves(leaves, start, half);
    const right = try appendPath(allocator, leaves, right_start, half, leaf_index, path);
    try path.append(allocator, .{ .side = .left, .hash = left });
    return parentHash(left, right);
}

fn peakHashFromLeaves(leaves: []const Hash, start: usize, size: usize) Hash {
    if (size == 1) return leaves[start];

    const half = size / 2;
    return parentHash(
        peakHashFromLeaves(leaves, start, half),
        peakHashFromLeaves(leaves, start + half, half),
    );
}

const PeakInfo = struct {
    start: usize,
    size: usize,
    height: usize,
    peak_index: usize,
};

fn peakInfoForIndex(size: usize, leaf_index: usize) ?PeakInfo {
    var start: usize = 0;
    var remaining = size;
    var peak_index: usize = 0;

    while (remaining != 0) {
        const peak_size = largestPowerOfTwo(remaining);
        if (leaf_index >= start and leaf_index < start + peak_size) {
            return .{
                .start = start,
                .size = peak_size,
                .height = log2PowerOfTwo(peak_size),
                .peak_index = peak_index,
            };
        }
        start += peak_size;
        remaining -= peak_size;
        peak_index += 1;
    }

    return null;
}

fn countPeaks(size: usize) usize {
    var remaining = size;
    var count: usize = 0;
    while (remaining != 0) {
        const peak_size = largestPowerOfTwo(remaining);
        remaining -= peak_size;
        count += 1;
    }
    return count;
}

fn largestPowerOfTwo(value: usize) usize {
    std.debug.assert(value != 0);

    var power: usize = 1;
    while (power <= value / 2) {
        power *= 2;
    }
    return power;
}

fn log2PowerOfTwo(value: usize) usize {
    std.debug.assert(value != 0);
    std.debug.assert((value & (value - 1)) == 0);

    var remaining = value;
    var log: usize = 0;
    while (remaining > 1) {
        remaining /= 2;
        log += 1;
    }
    return log;
}

fn leafHash(leaf: []const u8) Hash {
    var out: Hash = undefined;
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update(&[_]u8{0});
    hasher.update(leaf);
    hasher.final(&out);
    return out;
}

fn parentHash(left: Hash, right: Hash) Hash {
    var out: Hash = undefined;
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update(&[_]u8{1});
    hasher.update(&left);
    hasher.update(&right);
    hasher.final(&out);
    return out;
}

fn bagHash(left: Hash, right: Hash) Hash {
    var out: Hash = undefined;
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update(&[_]u8{2});
    hasher.update(&left);
    hasher.update(&right);
    hasher.final(&out);
    return out;
}

fn emptyRoot() Hash {
    var out: Hash = undefined;
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update(&[_]u8{3});
    hasher.final(&out);
    return out;
}

fn expectHashChanged(before: Hash, after: Hash) !void {
    try std.testing.expect(!std.mem.eql(u8, &before, &after));
}

fn appendTestLeaves(mmr: *MerkleMountainRange, count: usize) !void {
    for (0..count) |i| {
        var leaf: [16]u8 = undefined;
        const text = try std.fmt.bufPrint(&leaf, "leaf-{d}", .{i});
        const position = try mmr.append(text);
        try std.testing.expectEqual(i, position);
    }
}

fn ceilLog2(value: usize) usize {
    if (value <= 1) return 0;
    var power: usize = 1;
    var log: usize = 0;
    while (power < value) {
        power *= 2;
        log += 1;
    }
    return log;
}

test "append returns leaf positions and root changes deterministically" {
    const allocator = std.testing.allocator;
    var first = MerkleMountainRange.init(allocator);
    defer first.deinit();
    var second = MerkleMountainRange.init(allocator);
    defer second.deinit();

    var last_root = first.root();
    for (0..12) |i| {
        var leaf: [16]u8 = undefined;
        const text = try std.fmt.bufPrint(&leaf, "entry-{d}", .{i});

        try std.testing.expectEqual(i, try first.append(text));
        try std.testing.expectEqual(i, try second.append(text));

        const first_root = first.root();
        const second_root = second.root();
        try std.testing.expectEqualSlices(u8, &first_root, &second_root);
        try expectHashChanged(last_root, first_root);
        last_root = first_root;
    }
}

test "inclusion proof verifies for every leaf" {
    const allocator = std.testing.allocator;
    var mmr = MerkleMountainRange.init(allocator);
    defer mmr.deinit();
    try appendTestLeaves(&mmr, 37);

    const mmr_root = mmr.root();
    for (0..mmr.len()) |i| {
        var leaf: [16]u8 = undefined;
        const text = try std.fmt.bufPrint(&leaf, "leaf-{d}", .{i});
        var inclusion = try mmr.proof(i);
        defer inclusion.deinit(allocator);

        try std.testing.expect(verify(mmr_root, text, inclusion, i, mmr.len()));
    }
}

test "tampered leaf and proof are rejected" {
    const allocator = std.testing.allocator;
    var mmr = MerkleMountainRange.init(allocator);
    defer mmr.deinit();
    try appendTestLeaves(&mmr, 19);

    const mmr_root = mmr.root();
    var inclusion = try mmr.proof(7);
    defer inclusion.deinit(allocator);

    try std.testing.expect(verify(mmr_root, "leaf-7", inclusion, 7, mmr.len()));
    try std.testing.expect(!verify(mmr_root, "leaf-x", inclusion, 7, mmr.len()));

    if (inclusion.path.len != 0) {
        inclusion.path[0].hash[0] ^= 0xff;
    } else {
        inclusion.peaks[0][0] ^= 0xff;
    }
    try std.testing.expect(!verify(mmr_root, "leaf-7", inclusion, 7, mmr.len()));
}

test "proof size remains logarithmic" {
    const allocator = std.testing.allocator;
    var mmr = MerkleMountainRange.init(allocator);
    defer mmr.deinit();
    try appendTestLeaves(&mmr, 1025);

    const bound = 2 * ceilLog2(mmr.len()) + 1;
    for (0..mmr.len()) |i| {
        var inclusion = try mmr.proof(i);
        defer inclusion.deinit(allocator);
        try std.testing.expect(inclusion.path.len + inclusion.peaks.len <= bound);
    }
}

test "root is stable for a fixed sequence" {
    const allocator = std.testing.allocator;
    var mmr = MerkleMountainRange.init(allocator);
    defer mmr.deinit();

    const sequence = [_][]const u8{
        "alpha",
        "beta",
        "gamma",
        "delta",
        "epsilon",
        "zeta",
        "eta",
    };
    for (sequence) |leaf| {
        _ = try mmr.append(leaf);
    }

    const expected = [_]u8{
        0xbb, 0xf8, 0xb0, 0xa2, 0xb4, 0xa9, 0x6b, 0x2f,
        0x0f, 0x3d, 0xef, 0x4d, 0x98, 0x4c, 0x19, 0x54,
        0xae, 0x2f, 0x8e, 0x56, 0xe8, 0xb4, 0x4a, 0x59,
        0xfc, 0xe1, 0xfc, 0x20, 0x20, 0x34, 0x88, 0xa3,
    };
    const actual = mmr.root();
    try std.testing.expectEqualSlices(u8, &expected, &actual);
}

test "verify rejects wrong index and size" {
    const allocator = std.testing.allocator;
    var mmr = MerkleMountainRange.init(allocator);
    defer mmr.deinit();
    try appendTestLeaves(&mmr, 23);

    const mmr_root = mmr.root();
    var inclusion = try mmr.proof(9);
    defer inclusion.deinit(allocator);

    try std.testing.expect(verify(mmr_root, "leaf-9", inclusion, 9, mmr.len()));
    try std.testing.expect(!verify(mmr_root, "leaf-9", inclusion, 8, mmr.len()));
    try std.testing.expect(!verify(mmr_root, "leaf-9", inclusion, 9, mmr.len() - 1));
    try std.testing.expect(!verify(mmr_root, "leaf-9", inclusion, 9, mmr.len() + 1));
    try std.testing.expect(!verify(mmr_root, "leaf-9", inclusion, mmr.len(), mmr.len()));
    try std.testing.expect(!verify(mmr_root, "leaf-9", inclusion, 0, 0));
}

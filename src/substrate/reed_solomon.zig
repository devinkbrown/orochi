// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Reed-Solomon erasure coding over GF(256) for packet shard recovery.
//!
//! The codec is systematic: shard indexes `0..k` are the original data shards,
//! while `k..n` are parity shards generated from a Cauchy coding matrix. Any
//! `k` surviving shards are enough to reconstruct the missing data shards, after
//! which missing parity shards are regenerated from the restored data.

const std = @import("std");

pub const Error = error{
    DivisionByZero,
    InvalidShardCount,
    InvalidShardLength,
    SingularMatrix,
    TooManyErasures,
};

const Tables = struct {
    exp: [512]u8,
    log: [256]u8,
};

const tables = buildTables();

fn buildTables() Tables {
    @setEvalBranchQuota(4096);

    var exp: [512]u8 = undefined;
    var log = [_]u8{0} ** 256;

    var x: u8 = 1;
    for (0..255) |i| {
        exp[i] = x;
        log[x] = @intCast(i);
        x = mulSlow(x, 2);
    }
    for (255..512) |i| {
        exp[i] = exp[i - 255];
    }

    return .{ .exp = exp, .log = log };
}

fn mulSlow(a: u8, b: u8) u8 {
    var aa: u16 = a;
    var bb = b;
    var out: u16 = 0;

    while (bb != 0) : (bb >>= 1) {
        if ((bb & 1) != 0) out ^= aa;
        aa <<= 1;
        if ((aa & 0x100) != 0) aa ^= 0x11d;
    }

    return @intCast(out & 0xff);
}

pub fn add(a: u8, b: u8) u8 {
    return a ^ b;
}

pub fn sub(a: u8, b: u8) u8 {
    return a ^ b;
}

pub fn mul(a: u8, b: u8) u8 {
    if (a == 0 or b == 0) return 0;
    return tables.exp[@as(usize, tables.log[a]) + @as(usize, tables.log[b])];
}

pub fn div(a: u8, b: u8) Error!u8 {
    if (b == 0) return error.DivisionByZero;
    if (a == 0) return 0;

    const la: i16 = tables.log[a];
    const lb: i16 = tables.log[b];
    const idx: usize = @intCast(@mod(la - lb, 255));
    return tables.exp[idx];
}

pub fn inverse(a: u8) Error!u8 {
    if (a == 0) return error.DivisionByZero;
    return tables.exp[255 - @as(usize, tables.log[a])];
}

fn validateCounts(k: usize, m: usize) Error!void {
    if (k == 0 or m == 0 or k + m > 256) return error.InvalidShardCount;
}

fn validateDataShards(data_shards: []const []const u8, parity_count: usize) Error!usize {
    try validateCounts(data_shards.len, parity_count);

    const shard_len = data_shards[0].len;
    for (data_shards) |shard| {
        if (shard.len != shard_len) return error.InvalidShardLength;
    }
    return shard_len;
}

fn parityCoeff(k: usize, parity_row: usize, data_col: usize) Error!u8 {
    const x: u8 = @intCast(k + parity_row);
    const y: u8 = @intCast(data_col);
    return inverse(x ^ y);
}

fn matrixElement(k: usize, shard_index: usize, data_col: usize) Error!u8 {
    if (shard_index < k) return if (shard_index == data_col) 1 else 0;
    return parityCoeff(k, shard_index - k, data_col);
}

/// Encode `k` data shards into `parity_count` owned parity shards.
///
/// The returned outer slice and every inner shard are owned by `allocator`.
/// All data shards must have the same length. `k + parity_count` must be at
/// most 256.
pub fn encode(
    allocator: std.mem.Allocator,
    data_shards: []const []const u8,
    parity_count: usize,
) ![][]u8 {
    const shard_len = try validateDataShards(data_shards, parity_count);

    const parity = try allocator.alloc([]u8, parity_count);
    errdefer allocator.free(parity);

    var allocated: usize = 0;
    errdefer {
        for (parity[0..allocated]) |shard| allocator.free(shard);
    }

    for (parity) |*slot| {
        slot.* = try allocator.alloc(u8, shard_len);
        allocated += 1;
        @memset(slot.*, 0);
    }

    for (parity, 0..) |out, p| {
        for (data_shards, 0..) |in, d| {
            const coeff = try parityCoeff(data_shards.len, p, d);
            addScaled(out, in, coeff);
        }
    }

    return parity;
}

/// Reconstruct missing shards in place.
///
/// `shards` contains `k` data shards followed by parity shards. Null entries
/// mark erasures. Reconstructed entries are allocated with `allocator` and
/// written back into their null slots; callers own those newly filled shards.
pub fn reconstruct(
    allocator: std.mem.Allocator,
    shards: []?[]const u8,
    k: usize,
) !void {
    if (k == 0 or shards.len <= k or shards.len > 256) return error.InvalidShardCount;

    const n = shards.len;
    const m = n - k;
    try validateCounts(k, m);

    const shard_len = try validateShardSet(shards, k);

    const selected = try allocator.alloc(usize, k);
    defer allocator.free(selected);
    try selectSurvivors(shards, selected);

    var matrix = try allocator.alloc(u8, k * k);
    defer allocator.free(matrix);
    const inverse_matrix = try allocator.alloc(u8, k * k);
    defer allocator.free(inverse_matrix);

    for (selected, 0..) |shard_index, row| {
        for (0..k) |col| {
            matrix[row * k + col] = try matrixElement(k, shard_index, col);
        }
    }
    try invertMatrix(allocator, matrix, inverse_matrix, k);

    var allocated = try allocator.alloc(bool, n);
    defer allocator.free(allocated);
    @memset(allocated, false);
    errdefer {
        for (allocated, 0..) |was_allocated, i| {
            if (was_allocated) allocator.free(shards[i].?);
        }
    }

    var data_views = try allocator.alloc([]const u8, k);
    defer allocator.free(data_views);

    for (0..k) |i| {
        if (shards[i]) |shard| {
            data_views[i] = shard;
        } else {
            const rebuilt = try allocator.alloc(u8, shard_len);
            shards[i] = rebuilt;
            allocated[i] = true;
            data_views[i] = rebuilt;
        }
    }

    for (0..k) |data_row| {
        if (!allocated[data_row]) continue;
        const out = @constCast(shards[data_row].?);
        for (0..shard_len) |byte_index| {
            var value: u8 = 0;
            for (selected, 0..) |shard_index, selected_row| {
                const coeff = inverse_matrix[data_row * k + selected_row];
                value ^= mul(coeff, shards[shard_index].?[byte_index]);
            }
            out[byte_index] = value;
        }
    }

    for (0..m) |p| {
        const shard_index = k + p;
        if (shards[shard_index] != null) continue;

        const rebuilt = try allocator.alloc(u8, shard_len);
        shards[shard_index] = rebuilt;
        allocated[shard_index] = true;
        @memset(rebuilt, 0);

        for (data_views, 0..) |data, d| {
            const coeff = try parityCoeff(k, p, d);
            addScaled(rebuilt, data, coeff);
        }
    }
}

fn validateShardSet(shards: []?[]const u8, k: usize) Error!usize {
    var shard_len: ?usize = null;
    var survivor_count: usize = 0;

    for (shards) |maybe_shard| {
        if (maybe_shard) |shard| {
            if (shard_len) |len| {
                if (shard.len != len) return error.InvalidShardLength;
            } else {
                shard_len = shard.len;
            }
            survivor_count += 1;
        }
    }

    if (survivor_count < k) return error.TooManyErasures;
    return shard_len orelse error.TooManyErasures;
}

fn selectSurvivors(shards: []const ?[]const u8, selected: []usize) Error!void {
    var selected_len: usize = 0;
    for (shards, 0..) |maybe_shard, i| {
        if (maybe_shard == null) continue;
        selected[selected_len] = i;
        selected_len += 1;
        if (selected_len == selected.len) return;
    }
    return error.TooManyErasures;
}

fn addScaled(out: []u8, in: []const u8, coeff: u8) void {
    if (coeff == 0) return;
    if (coeff == 1) {
        for (out, in) |*dst, src| dst.* ^= src;
        return;
    }
    for (out, in) |*dst, src| dst.* ^= mul(coeff, src);
}

fn invertMatrix(
    allocator: std.mem.Allocator,
    matrix: []const u8,
    inverse_out: []u8,
    n: usize,
) !void {
    const width = n * 2;
    var aug = try allocator.alloc(u8, n * width);
    defer allocator.free(aug);
    @memset(aug, 0);

    for (0..n) |row| {
        for (0..n) |col| {
            aug[row * width + col] = matrix[row * n + col];
        }
        aug[row * width + n + row] = 1;
    }

    for (0..n) |col| {
        var pivot: ?usize = null;
        for (col..n) |row| {
            if (aug[row * width + col] != 0) {
                pivot = row;
                break;
            }
        }
        const pivot_row = pivot orelse return error.SingularMatrix;

        if (pivot_row != col) {
            for (0..width) |i| {
                std.mem.swap(u8, &aug[col * width + i], &aug[pivot_row * width + i]);
            }
        }

        const scale = try inverse(aug[col * width + col]);
        for (0..width) |i| {
            aug[col * width + i] = mul(aug[col * width + i], scale);
        }

        for (0..n) |row| {
            if (row == col) continue;
            const factor = aug[row * width + col];
            if (factor == 0) continue;
            for (0..width) |i| {
                aug[row * width + i] ^= mul(factor, aug[col * width + i]);
            }
        }
    }

    for (0..n) |row| {
        for (0..n) |col| {
            inverse_out[row * n + col] = aug[row * width + n + col];
        }
    }
}

fn freeShardList(allocator: std.mem.Allocator, shards: [][]u8) void {
    for (shards) |shard| allocator.free(shard);
    allocator.free(shards);
}

fn fillShard(shard: []u8, seed: usize) void {
    for (shard, 0..) |*byte, i| {
        byte.* = @intCast((seed * 29 + i * 41 + seed * i * 7 + 13) % 251);
    }
}

fn expectRoundTrip(k: usize, m: usize, shard_len: usize) !void {
    const allocator = std.testing.allocator;
    const n = k + m;

    const data = try allocator.alloc([]u8, k);
    defer allocator.free(data);
    for (data, 0..) |*slot, i| {
        slot.* = try allocator.alloc(u8, shard_len);
        fillShard(slot.*, i);
    }
    defer for (data) |shard| allocator.free(shard);

    var data_const = try allocator.alloc([]const u8, k);
    defer allocator.free(data_const);
    for (data, 0..) |shard, i| data_const[i] = shard;

    const parity = try encode(allocator, data_const, m);
    defer freeShardList(allocator, parity);

    var original = try allocator.alloc([]const u8, n);
    defer allocator.free(original);
    for (0..k) |i| original[i] = data[i];
    for (0..m) |i| original[k + i] = parity[i];

    const max_masks = @as(usize, 1) << @intCast(n);
    for (0..max_masks) |mask| {
        if (@popCount(mask) > m) continue;

        var shards = try allocator.alloc(?[]const u8, n);
        defer allocator.free(shards);
        var missing = try allocator.alloc(bool, n);
        defer allocator.free(missing);

        for (0..n) |i| {
            missing[i] = ((mask >> @intCast(i)) & 1) != 0;
            shards[i] = if (missing[i]) null else original[i];
        }

        try reconstruct(allocator, shards, k);
        defer {
            for (missing, 0..) |was_missing, i| {
                if (was_missing) allocator.free(shards[i].?);
            }
        }

        for (shards, 0..) |maybe_shard, i| {
            try std.testing.expect(maybe_shard != null);
            try std.testing.expectEqualSlices(u8, original[i], maybe_shard.?);
        }
    }
}

test "GF multiplication and inverse identities" {
    try std.testing.expectEqual(@as(u8, 0), mul(0, 137));
    try std.testing.expectEqual(@as(u8, 91), mul(1, 91));
    try std.testing.expectEqual(@as(u8, 91), mul(91, 1));

    for (0..256) |i| {
        const x: u8 = @intCast(i);
        try std.testing.expectEqual(x, add(x, 0));
        try std.testing.expectEqual(@as(u8, 0), sub(x, x));
    }

    for (1..256) |i| {
        const x: u8 = @intCast(i);
        try std.testing.expectEqual(@as(u8, 1), mul(x, try inverse(x)));
        try std.testing.expectEqual(x, try div(mul(x, 173), 173));
    }
}

test "encode then reconstruct every erasure set up to parity count" {
    try expectRoundTrip(1, 1, 1);
    try expectRoundTrip(2, 2, 17);
    try expectRoundTrip(4, 3, 64);
    try expectRoundTrip(6, 4, 31);
}

test "reconstruct fails gracefully when more than parity count is lost" {
    const allocator = std.testing.allocator;
    const k = 3;
    const m = 2;
    const shard_len = 23;

    var data = [_][]u8{
        try allocator.alloc(u8, shard_len),
        try allocator.alloc(u8, shard_len),
        try allocator.alloc(u8, shard_len),
    };
    defer for (data) |shard| allocator.free(shard);
    for (&data, 0..) |shard, i| fillShard(shard, i);

    var data_const = [_][]const u8{ data[0], data[1], data[2] };
    const parity = try encode(allocator, &data_const, m);
    defer freeShardList(allocator, parity);

    var shards = [_]?[]const u8{ data[0], null, null, null, parity[1] };
    try std.testing.expectError(error.TooManyErasures, reconstruct(allocator, &shards, k));
}

test "invalid shard layouts return errors" {
    const allocator = std.testing.allocator;

    var no_shards: [0]?[]const u8 = .{};
    try std.testing.expectError(error.InvalidShardCount, reconstruct(allocator, &no_shards, 0));
    try std.testing.expectError(error.InvalidShardCount, reconstruct(allocator, &no_shards, 1));

    var a = [_]u8{ 1, 2, 3 };
    var b = [_]u8{ 4, 5 };
    var bad_data = [_][]const u8{ &a, &b };
    try std.testing.expectError(error.InvalidShardLength, encode(allocator, &bad_data, 1));

    var bad_shards = [_]?[]const u8{ &a, &b, null };
    try std.testing.expectError(error.InvalidShardLength, reconstruct(allocator, &bad_shards, 2));
}

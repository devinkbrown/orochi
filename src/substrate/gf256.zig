// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

const std = @import("std");

pub const Error = error{
    DivisionByZero,
    DuplicateShardIndex,
    InvalidShardCount,
    InvalidShardLength,
    InvalidShardSet,
    SingularMatrix,
    TooFewSurvivors,
};

const Tables = struct {
    exp: [512]u8,
    log: [256]u8,
};

const tables = buildTables();

fn buildTables() Tables {
    @setEvalBranchQuota(4000);

    var exp: [512]u8 = undefined;
    var log = [_]u8{0} ** 256;

    var x: u8 = 1;
    for (0..255) |i| {
        exp[i] = x;
        log[x] = @intCast(i);
        x = mulSlow(x, 0x03);
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
        if ((aa & 0x100) != 0) aa ^= 0x11b;
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

pub fn inv(a: u8) Error!u8 {
    if (a == 0) return error.DivisionByZero;
    return tables.exp[255 - @as(usize, tables.log[a])];
}

pub fn pow(a: u8, exponent: usize) u8 {
    if (exponent == 0) return 1;
    if (a == 0) return 0;
    // Reduce the exponent mod 255 (the multiplicative order) BEFORE multiplying
    // by the log, or `log[a] * exponent` overflows usize for large exponents.
    return tables.exp[(@as(usize, tables.log[a]) * (exponent % 255)) % 255];
}

fn validateCounts(k: usize, m: usize) Error!void {
    if (k == 0 or m == 0 or k + m > 256) return error.InvalidShardCount;
}

fn parityCoeff(k: usize, parity_row: usize, data_col: usize) Error!u8 {
    const x: u8 = @intCast(k + parity_row);
    const y: u8 = @intCast(data_col);
    return inv(x ^ y);
}

fn matrixRowElement(k: usize, shard_index: usize, data_col: usize) Error!u8 {
    if (shard_index < k) return if (shard_index == data_col) 1 else 0;
    return parityCoeff(k, shard_index - k, data_col);
}

pub fn encode(data: []const []const u8, parity: []const []u8) Error!void {
    const k = data.len;
    const m = parity.len;
    try validateCounts(k, m);

    const shard_len = data[0].len;
    for (data) |shard| {
        if (shard.len != shard_len) return error.InvalidShardLength;
    }
    for (parity) |shard| {
        if (shard.len != shard_len) return error.InvalidShardLength;
        @memset(shard, 0);
    }

    for (parity, 0..) |out, p| {
        for (data, 0..) |in, d| {
            const coeff = try parityCoeff(k, p, d);
            if (coeff == 0) continue;
            for (out, in) |*dst, src| {
                dst.* ^= mul(coeff, src);
            }
        }
    }
}

pub fn decode(allocator: std.mem.Allocator, k: usize, m: usize, shards: []?[]u8) !void {
    try validateCounts(k, m);
    const n = k + m;
    if (shards.len != n) return error.InvalidShardSet;

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
    if (survivor_count < k) return error.TooFewSurvivors;

    const len = shard_len orelse return error.TooFewSurvivors;
    var allocated = try allocator.alloc(bool, n);
    defer allocator.free(allocated);
    @memset(allocated, false);
    errdefer {
        for (allocated, 0..) |was_allocated, i| {
            if (was_allocated) allocator.free(shards[i].?);
        }
    }

    var selected = try allocator.alloc(usize, k);
    defer allocator.free(selected);

    var selected_len: usize = 0;
    for (shards, 0..) |maybe_shard, i| {
        if (maybe_shard != null) {
            selected[selected_len] = i;
            selected_len += 1;
            if (selected_len == k) break;
        }
    }

    var matrix = try allocator.alloc(u8, k * k);
    defer allocator.free(matrix);
    const inverse = try allocator.alloc(u8, k * k);
    defer allocator.free(inverse);

    for (selected, 0..) |shard_index, row| {
        for (0..k) |col| {
            matrix[row * k + col] = try matrixRowElement(k, shard_index, col);
        }
    }
    try invertMatrix(allocator, matrix, inverse, k);

    for (0..k) |i| {
        if (shards[i] == null) {
            shards[i] = try allocator.alloc(u8, len);
            allocated[i] = true;
        }
    }

    for (0..len) |byte_index| {
        for (0..k) |data_row| {
            var value: u8 = 0;
            for (selected, 0..) |shard_index, selected_row| {
                value ^= mul(inverse[data_row * k + selected_row], shards[shard_index].?[byte_index]);
            }
            shards[data_row].?[byte_index] = value;
        }
    }

    var data_rows = try allocator.alloc([]const u8, k);
    defer allocator.free(data_rows);
    for (0..k) |i| data_rows[i] = shards[i].?;

    var parity_rows = try allocator.alloc([]u8, m);
    defer allocator.free(parity_rows);
    for (0..m) |p| {
        const index = k + p;
        if (shards[index] == null) {
            shards[index] = try allocator.alloc(u8, len);
            allocated[index] = true;
        }
        parity_rows[p] = shards[index].?;
    }
    try encode(data_rows, parity_rows);
}

fn invertMatrix(allocator: std.mem.Allocator, matrix: []const u8, inverse_out: []u8, n: usize) !void {
    if (matrix.len != n * n or inverse_out.len != n * n) return error.InvalidShardSet;

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

        const scale = try inv(aug[col * width + col]);
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

fn fillShard(shard: []u8, shard_index: usize) void {
    for (shard, 0..) |*byte, i| {
        byte.* = @intCast((17 * shard_index + 31 * i + 7 * shard_index * i + 19) % 251);
    }
}

fn freeOptionalShards(allocator: std.mem.Allocator, shards: []?[]u8) void {
    for (shards) |maybe_shard| {
        if (maybe_shard) |shard| allocator.free(shard);
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

    const parity = try allocator.alloc([]u8, m);
    defer allocator.free(parity);
    for (parity) |*slot| {
        slot.* = try allocator.alloc(u8, shard_len);
    }
    defer for (parity) |shard| allocator.free(shard);

    var const_data = try allocator.alloc([]const u8, k);
    defer allocator.free(const_data);
    for (data, 0..) |shard, i| const_data[i] = shard;
    try encode(const_data, parity);

    var original = try allocator.alloc([]u8, n);
    defer allocator.free(original);
    for (0..n) |i| {
        original[i] = try allocator.alloc(u8, shard_len);
        if (i < k) {
            @memcpy(original[i], data[i]);
        } else {
            @memcpy(original[i], parity[i - k]);
        }
    }
    defer for (original) |shard| allocator.free(shard);

    const max_masks = @as(usize, 1) << @intCast(n);
    for (0..max_masks) |mask| {
        if (@popCount(mask) > m) continue;

        var shards = try allocator.alloc(?[]u8, n);
        defer allocator.free(shards);
        @memset(shards, null);
        defer freeOptionalShards(allocator, shards);

        for (0..n) |i| {
            if (((mask >> @intCast(i)) & 1) == 0) {
                shards[i] = try allocator.alloc(u8, shard_len);
                @memcpy(shards[i].?, original[i]);
            }
        }

        try decode(allocator, k, m, shards);
        for (shards, 0..) |maybe_shard, i| {
            try std.testing.expect(maybe_shard != null);
            try std.testing.expectEqualSlices(u8, original[i], maybe_shard.?);
        }
    }
}

test "field multiplication matches AES polynomial and identities" {
    try std.testing.expectEqual(@as(u8, 0xc1), mul(0x57, 0x83));
    try std.testing.expectEqual(@as(u8, 0), mul(0, 99));
    try std.testing.expectEqual(@as(u8, 219), mul(219, 1));
    try std.testing.expectEqual(@as(u8, 219), mul(1, 219));

    for (1..256) |i| {
        const x: u8 = @intCast(i);
        try std.testing.expectEqual(@as(u8, 1), mul(x, try inv(x)));
        try std.testing.expectEqual(x, try div(mul(x, 37), 37));
    }
}

test "field distributivity on deterministic samples" {
    const samples = [_]u8{ 0, 1, 2, 3, 5, 17, 31, 63, 127, 128, 199, 255 };
    for (samples) |a| {
        for (samples) |b| {
            for (samples) |c| {
                try std.testing.expectEqual(mul(a, b ^ c), mul(a, b) ^ mul(a, c));
                try std.testing.expectEqual(mul(a ^ b, c), mul(a, c) ^ mul(b, c));
            }
        }
    }
}

test "field powers are deterministic" {
    try std.testing.expectEqual(@as(u8, 1), pow(0, 0));
    try std.testing.expectEqual(@as(u8, 0), pow(0, 3));
    try std.testing.expectEqual(@as(u8, 1), pow(3, 255));
    try std.testing.expectEqual(@as(u8, 3), pow(3, 256));
}

test "systematic erasure code recovers all erasures up to parity count" {
    try expectRoundTrip(1, 1, 0);
    try expectRoundTrip(1, 2, 19);
    try expectRoundTrip(2, 2, 31);
    try expectRoundTrip(3, 2, 64);
    try expectRoundTrip(4, 3, 37);
}

test "decode fails gracefully when too many shards are lost" {
    const allocator = std.testing.allocator;
    const k = 3;
    const m = 2;
    const shard_len = 16;

    var data = [_][]u8{
        try allocator.alloc(u8, shard_len),
        try allocator.alloc(u8, shard_len),
        try allocator.alloc(u8, shard_len),
    };
    defer for (data) |shard| allocator.free(shard);
    for (&data, 0..) |shard, i| fillShard(shard, i);

    var parity = [_][]u8{
        try allocator.alloc(u8, shard_len),
        try allocator.alloc(u8, shard_len),
    };
    defer for (parity) |shard| allocator.free(shard);

    var const_data = [_][]const u8{ data[0], data[1], data[2] };
    try encode(&const_data, &parity);

    var shards = [_]?[]u8{ data[0], null, null, null, parity[1] };
    try std.testing.expectError(error.TooFewSurvivors, decode(allocator, k, m, &shards));
}

test "invalid inputs return errors" {
    const allocator = std.testing.allocator;
    var empty: [0]?[]u8 = .{};
    try std.testing.expectError(error.InvalidShardCount, decode(allocator, 0, 1, &empty));
    try std.testing.expectError(error.InvalidShardCount, decode(allocator, 1, 0, &empty));

    var a = [_]u8{ 1, 2, 3 };
    var b = [_]u8{ 4, 5 };
    var shards = [_]?[]u8{ &a, &b };
    try std.testing.expectError(error.InvalidShardLength, decode(allocator, 1, 1, &shards));

    var data = [_][]const u8{&a};
    var parity = [_][]u8{&b};
    try std.testing.expectError(error.InvalidShardLength, encode(&data, &parity));
}

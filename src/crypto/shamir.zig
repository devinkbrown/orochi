// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

const std = @import("std");

const max_shares = 255;

pub const Share = struct {
    x: u8,
    y: []u8,
};

pub fn split(
    allocator: std.mem.Allocator,
    secret: []const u8,
    n: usize,
    k: usize,
    rng: std.Random,
) ![]Share {
    try validateSplitParams(n, k);

    const shares = try allocator.alloc(Share, n);
    errdefer allocator.free(shares);

    var initialized: usize = 0;
    errdefer {
        for (shares[0..initialized]) |share| {
            allocator.free(share.y);
        }
    }

    for (shares, 0..) |*share, i| {
        share.* = .{
            .x = @as(u8, @intCast(i + 1)),
            .y = try allocator.alloc(u8, secret.len),
        };
        @memset(share.y, 0);
        initialized += 1;
    }

    const coeffs = try allocator.alloc(u8, k);
    defer allocator.free(coeffs);

    for (secret, 0..) |secret_byte, byte_index| {
        coeffs[0] = secret_byte;
        if (k > 1) {
            rng.bytes(coeffs[1 .. k - 1]);
            coeffs[k - 1] = randomNonZero(rng);
        }

        for (shares) |*share| {
            share.y[byte_index] = evalPolynomial(coeffs, share.x);
        }
    }

    return shares;
}

pub fn combine(allocator: std.mem.Allocator, shares: []const Share) ![]u8 {
    try validateShares(shares);

    const secret = try allocator.alloc(u8, shares[0].y.len);
    errdefer allocator.free(secret);

    for (secret, 0..) |*out, byte_index| {
        var value: u8 = 0;

        for (shares, 0..) |share_i, i| {
            var basis: u8 = 1;

            for (shares, 0..) |share_j, j| {
                if (i == j) continue;
                const denominator = share_i.x ^ share_j.x;
                basis = gfMul(basis, try gfDiv(share_j.x, denominator));
            }

            value ^= gfMul(share_i.y[byte_index], basis);
        }

        out.* = value;
    }

    return secret;
}

pub fn freeShares(allocator: std.mem.Allocator, shares: []Share) void {
    for (shares) |share| {
        allocator.free(share.y);
    }
    allocator.free(shares);
}

fn validateSplitParams(n: usize, k: usize) !void {
    if (n == 0 or k == 0 or k > n or n > max_shares) {
        return error.InvalidParameters;
    }
}

fn validateShares(shares: []const Share) !void {
    if (shares.len == 0 or shares.len > max_shares) {
        return error.InvalidShareSet;
    }

    const share_len = shares[0].y.len;
    var seen = @as([256]bool, @splat(false));

    for (shares) |share| {
        if (share.x == 0) {
            return error.InvalidShareX;
        }
        if (seen[share.x]) {
            return error.DuplicateShareX;
        }
        if (share.y.len != share_len) {
            return error.ShareLengthMismatch;
        }

        seen[share.x] = true;
    }
}

fn randomNonZero(rng: std.Random) u8 {
    var byte: [1]u8 = undefined;
    while (true) {
        rng.bytes(&byte);
        if (byte[0] != 0) return byte[0];
    }
}

fn evalPolynomial(coeffs: []const u8, x: u8) u8 {
    var i = coeffs.len - 1;
    var value = coeffs[i];

    while (i > 0) {
        i -= 1;
        value = gfMul(value, x) ^ coeffs[i];
    }

    return value;
}

fn gfAdd(a: u8, b: u8) u8 {
    return a ^ b;
}

fn gfMul(a: u8, b: u8) u8 {
    var aa: u16 = a;
    var bb = b;
    var product: u8 = 0;

    var rounds: usize = 0;
    while (rounds < 8) : (rounds += 1) {
        if ((bb & 1) != 0) {
            product ^= @as(u8, @intCast(aa & 0xff));
        }

        const carry = (aa & 0x80) != 0;
        aa = (aa << 1) & 0xff;
        if (carry) {
            aa ^= 0x1b;
        }
        bb >>= 1;
    }

    return product;
}

fn gfPow(a: u8, exponent: u8) u8 {
    var base = a;
    var exp = exponent;
    var result: u8 = 1;

    while (exp != 0) {
        if ((exp & 1) != 0) {
            result = gfMul(result, base);
        }
        base = gfMul(base, base);
        exp >>= 1;
    }

    return result;
}

fn gfInv(a: u8) !u8 {
    if (a == 0) return error.DivisionByZero;
    return gfPow(a, 254);
}

fn gfDiv(a: u8, b: u8) !u8 {
    return gfMul(a, try gfInv(b));
}

fn seeded(seed: u64) std.Random.DefaultPrng {
    return std.Random.DefaultPrng.init(seed);
}

fn expectReconstructs(secret: []const u8, selected: []const Share) !void {
    const allocator = std.testing.allocator;
    const reconstructed = try combine(allocator, selected);
    defer allocator.free(reconstructed);
    try std.testing.expectEqualSlices(u8, secret, reconstructed);
}

test "field math uses AES polynomial" {
    try std.testing.expectEqual(@as(u8, 0), gfAdd(0x6d, 0x6d));
    try std.testing.expectEqual(@as(u8, 0x38), gfAdd(0x6d, 0x55));

    try std.testing.expectEqual(@as(u8, 0), gfMul(0x00, 0x83));
    try std.testing.expectEqual(@as(u8, 0x57), gfMul(0x57, 0x01));
    try std.testing.expectEqual(@as(u8, 0xc1), gfMul(0x57, 0x83));

    var x: u16 = 1;
    while (x <= 255) : (x += 1) {
        const value = @as(u8, @intCast(x));
        try std.testing.expectEqual(@as(u8, 1), gfMul(value, try gfInv(value)));
        try std.testing.expectEqual(@as(u8, 0x57), try gfDiv(gfMul(0x57, value), value));
    }

    try std.testing.expectError(error.DivisionByZero, gfInv(0));
    try std.testing.expectError(error.DivisionByZero, gfDiv(1, 0));
}

test "split validates n and k" {
    var prng = seeded(1);
    const rng = prng.random();
    const allocator = std.testing.allocator;
    const secret = "valid";

    try std.testing.expectError(error.InvalidParameters, split(allocator, secret, 0, 1, rng));
    try std.testing.expectError(error.InvalidParameters, split(allocator, secret, 1, 0, rng));
    try std.testing.expectError(error.InvalidParameters, split(allocator, secret, 2, 3, rng));
    try std.testing.expectError(error.InvalidParameters, split(allocator, secret, 256, 2, rng));
}

test "any k of n shares reconstruct the secret" {
    const allocator = std.testing.allocator;
    const secret = "orochi shamir secret";

    var prng = seeded(0x12345678);
    const shares = try split(allocator, secret, 5, 3, prng.random());
    defer freeShares(allocator, shares);

    var selected: [3]Share = undefined;
    var a: usize = 0;
    while (a < shares.len) : (a += 1) {
        var b = a + 1;
        while (b < shares.len) : (b += 1) {
            var c = b + 1;
            while (c < shares.len) : (c += 1) {
                selected = .{ shares[a], shares[b], shares[c] };
                try expectReconstructs(secret, &selected);
            }
        }
    }

    try expectReconstructs(secret, shares);
}

test "fewer than k shares reconstruct a different value" {
    const allocator = std.testing.allocator;
    const secret = "thresholds need enough points";

    var prng = seeded(0x90abcdef);
    const shares = try split(allocator, secret, 5, 4, prng.random());
    defer freeShares(allocator, shares);

    const selected = [_]Share{ shares[0], shares[2], shares[4] };
    const reconstructed = try combine(allocator, &selected);
    defer allocator.free(reconstructed);

    try std.testing.expect(!std.mem.eql(u8, secret, reconstructed));
}

test "multi-byte and empty secrets round trip" {
    const allocator = std.testing.allocator;
    const binary_secret = [_]u8{ 0x00, 0xff, 0x10, 0x42, 0x80, 0x7f, 0x01, 0x99 };

    var prng = seeded(0x11112222);
    const binary_shares = try split(allocator, &binary_secret, 8, 5, prng.random());
    defer freeShares(allocator, binary_shares);

    const selected = [_]Share{
        binary_shares[1],
        binary_shares[2],
        binary_shares[4],
        binary_shares[5],
        binary_shares[7],
    };
    try expectReconstructs(&binary_secret, &selected);

    var empty_prng = seeded(0x33334444);
    const empty_shares = try split(allocator, "", 3, 2, empty_prng.random());
    defer freeShares(allocator, empty_shares);
    try expectReconstructs("", empty_shares[0..2]);
}

test "k of one duplicates the secret into every share" {
    const allocator = std.testing.allocator;
    const secret = "no threshold";

    var prng = seeded(0x55556666);
    const shares = try split(allocator, secret, 4, 1, prng.random());
    defer freeShares(allocator, shares);

    for (shares) |share| {
        try std.testing.expectEqualSlices(u8, secret, share.y);
    }
}

test "deterministic with seeded rng" {
    const allocator = std.testing.allocator;
    const secret = "deterministic stream";

    var prng_a = seeded(0x77778888);
    var prng_b = seeded(0x77778888);
    var prng_c = seeded(0x88887777);

    const shares_a = try split(allocator, secret, 6, 4, prng_a.random());
    defer freeShares(allocator, shares_a);
    const shares_b = try split(allocator, secret, 6, 4, prng_b.random());
    defer freeShares(allocator, shares_b);
    const shares_c = try split(allocator, secret, 6, 4, prng_c.random());
    defer freeShares(allocator, shares_c);

    for (shares_a, shares_b) |a, b| {
        try std.testing.expectEqual(a.x, b.x);
        try std.testing.expectEqualSlices(u8, a.y, b.y);
    }

    var differs = false;
    for (shares_a, shares_c) |a, c| {
        differs = differs or !std.mem.eql(u8, a.y, c.y);
    }
    try std.testing.expect(differs);
}

test "combine validates share sets" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(error.InvalidShareSet, combine(allocator, &.{}));

    var a = [_]u8{ 1, 2, 3 };
    var b = [_]u8{ 4, 5, 6 };
    var short = [_]u8{ 7, 8 };

    const zero_x = [_]Share{
        .{ .x = 0, .y = &a },
    };
    try std.testing.expectError(error.InvalidShareX, combine(allocator, &zero_x));

    const duplicate_x = [_]Share{
        .{ .x = 1, .y = &a },
        .{ .x = 1, .y = &b },
    };
    try std.testing.expectError(error.DuplicateShareX, combine(allocator, &duplicate_x));

    const mismatched_lengths = [_]Share{
        .{ .x = 1, .y = &a },
        .{ .x = 2, .y = &short },
    };
    try std.testing.expectError(error.ShareLengthMismatch, combine(allocator, &mismatched_lengths));
}

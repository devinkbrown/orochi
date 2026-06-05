const std = @import("std");

pub const BloomError = error{
    InvalidParameter,
    IncompatibleFilter,
};

pub const Bloom = struct {
    allocator: std.mem.Allocator,
    bits: []u8,
    bit_count: usize,
    hash_count: usize,
    item_count: usize,

    pub fn init(allocator: std.mem.Allocator, bit_count: usize, hash_count: usize) !Bloom {
        if (bit_count == 0 or hash_count == 0) return BloomError.InvalidParameter;

        const bits = try allocator.alloc(u8, bytesForBits(bit_count));
        @memset(bits, 0);

        return .{
            .allocator = allocator,
            .bits = bits,
            .bit_count = bit_count,
            .hash_count = hash_count,
            .item_count = 0,
        };
    }

    pub fn deinit(self: *Bloom) void {
        self.allocator.free(self.bits);
        self.* = undefined;
    }

    pub fn add(self: *Bloom, bytes: []const u8) void {
        var hashes = Hashes.init(bytes, self.bit_count);
        for (0..self.hash_count) |_| {
            setBit(self.bits, hashes.next());
        }

        if (self.item_count != std.math.maxInt(usize)) {
            self.item_count += 1;
        }
    }

    pub fn mayContain(self: *const Bloom, bytes: []const u8) bool {
        var hashes = Hashes.init(bytes, self.bit_count);
        for (0..self.hash_count) |_| {
            if (!getBit(self.bits, hashes.next())) return false;
        }
        return true;
    }

    pub fn estimatedFpp(self: *const Bloom) f64 {
        if (self.item_count == 0) return 0.0;

        const m: f64 = @floatFromInt(self.bit_count);
        const k: f64 = @floatFromInt(self.hash_count);
        const n: f64 = @floatFromInt(self.item_count);
        const set_probability = 1.0 - std.math.exp(-(k * n) / m);

        return std.math.pow(f64, set_probability, k);
    }

    pub fn @"union"(self: *Bloom, other: *const Bloom) BloomError!void {
        if (self.bit_count != other.bit_count or self.hash_count != other.hash_count) {
            return BloomError.IncompatibleFilter;
        }

        for (self.bits, other.bits) |*dst, src| {
            dst.* |= src;
        }

        self.item_count = saturatedAdd(self.item_count, other.item_count);
    }

    pub fn bitCount(self: *const Bloom) usize {
        return self.bit_count;
    }

    pub fn hashCount(self: *const Bloom) usize {
        return self.hash_count;
    }

    pub fn len(self: *const Bloom) usize {
        return self.item_count;
    }
};

fn bytesForBits(bit_count: usize) usize {
    return ((bit_count - 1) / 8) + 1;
}

const Hashes = struct {
    bit_count: usize,
    h1: usize,
    h2: usize,
    index: usize,

    fn init(bytes: []const u8, bit_count: usize) Hashes {
        const h = std.hash.Wyhash.hash(0, bytes);
        return .{
            .bit_count = bit_count,
            .h1 = narrowHash(h),
            .h2 = narrowHash(mix64(h ^ 0x9e37_79b9_7f4a_7c15)) | 1,
            .index = 0,
        };
    }

    fn next(self: *Hashes) usize {
        const i = self.index;
        self.index += 1;
        return (self.h1 +% (i *% self.h2)) % self.bit_count;
    }
};

fn narrowHash(hash: u64) usize {
    if (@bitSizeOf(usize) >= 64) return @intCast(hash);
    return @truncate(hash ^ (hash >> 32));
}

fn mix64(input: u64) u64 {
    var z = input;
    z = (z ^ (z >> 30)) *% 0xbf58_476d_1ce4_e5b9;
    z = (z ^ (z >> 27)) *% 0x94d0_49bb_1331_11eb;
    return z ^ (z >> 31);
}

fn setBit(bits: []u8, bit_index: usize) void {
    bits[bit_index / 8] |= bitMask(bit_index);
}

fn getBit(bits: []const u8, bit_index: usize) bool {
    return (bits[bit_index / 8] & bitMask(bit_index)) != 0;
}

fn bitMask(bit_index: usize) u8 {
    return @as(u8, 1) << @intCast(bit_index & 7);
}

fn saturatedAdd(a: usize, b: usize) usize {
    const max = std.math.maxInt(usize);
    if (max - a < b) return max;
    return a + b;
}

fn key(buf: []u8, prefix: []const u8, n: usize) []const u8 {
    return std.fmt.bufPrint(buf, "{s}-{d}", .{ prefix, n }) catch unreachable;
}

test "parameter validation rejects zero bits and zero hashes" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(BloomError.InvalidParameter, Bloom.init(allocator, 0, 3));
    try std.testing.expectError(BloomError.InvalidParameter, Bloom.init(allocator, 64, 0));

    var a = try Bloom.init(allocator, 64, 3);
    defer a.deinit();
    var b = try Bloom.init(allocator, 65, 3);
    defer b.deinit();
    var c = try Bloom.init(allocator, 64, 4);
    defer c.deinit();

    try std.testing.expectError(BloomError.IncompatibleFilter, a.@"union"(&b));
    try std.testing.expectError(BloomError.IncompatibleFilter, a.@"union"(&c));
}

test "add has no false negatives for inserted byte strings" {
    const allocator = std.testing.allocator;
    var bloom = try Bloom.init(allocator, 4096, 6);
    defer bloom.deinit();

    var buf: [64]u8 = undefined;
    for (0..500) |i| {
        bloom.add(key(&buf, "member", i));
    }

    try std.testing.expectEqual(@as(usize, 500), bloom.len());

    for (0..500) |i| {
        try std.testing.expect(bloom.mayContain(key(&buf, "member", i)));
    }
}

test "estimated false-positive rate bounds a deterministic sample under capacity" {
    const allocator = std.testing.allocator;
    var bloom = try Bloom.init(allocator, 8192, 7);
    defer bloom.deinit();

    var buf: [64]u8 = undefined;
    for (0..800) |i| {
        bloom.add(key(&buf, "inserted", i));
    }

    const expected = bloom.estimatedFpp();
    try std.testing.expect(expected > 0.0);
    try std.testing.expect(expected < 0.02);

    var false_positives: usize = 0;
    const samples: usize = 10_000;
    for (0..samples) |i| {
        if (bloom.mayContain(key(&buf, "candidate", i))) false_positives += 1;
    }

    const observed: f64 = @as(f64, @floatFromInt(false_positives)) / @as(f64, @floatFromInt(samples));
    try std.testing.expect(observed <= expected * 3.0 + 0.01);
}

test "union ORs bitsets and preserves membership from both filters" {
    const allocator = std.testing.allocator;
    var left = try Bloom.init(allocator, 1024, 4);
    defer left.deinit();
    var right = try Bloom.init(allocator, 1024, 4);
    defer right.deinit();

    left.add("alpha");
    left.add("beta");
    right.add("gamma");
    right.add("delta");

    const expected = try allocator.alloc(u8, left.bits.len);
    defer allocator.free(expected);

    for (left.bits, right.bits, expected) |l, r, *out| {
        out.* = l | r;
    }

    try left.@"union"(&right);

    try std.testing.expectEqualSlices(u8, expected, left.bits);
    try std.testing.expect(left.mayContain("alpha"));
    try std.testing.expect(left.mayContain("beta"));
    try std.testing.expect(left.mayContain("gamma"));
    try std.testing.expect(left.mayContain("delta"));
    try std.testing.expectEqual(@as(usize, 4), left.len());
}

test "non-byte-aligned filters only use configured bit range" {
    const allocator = std.testing.allocator;
    var bloom = try Bloom.init(allocator, 10, 3);
    defer bloom.deinit();

    bloom.add("edge");
    try std.testing.expect(bloom.mayContain("edge"));

    try std.testing.expectEqual(@as(usize, 10), bloom.bitCount());
    try std.testing.expectEqual(@as(usize, 3), bloom.hashCount());
    try std.testing.expectEqual(@as(usize, 2), bloom.bits.len);
}

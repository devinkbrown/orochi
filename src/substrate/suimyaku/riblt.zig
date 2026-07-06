// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Rateless Invertible Bloom Lookup Table for 32-byte content IDs.
//!
//! The encoder emits an unbounded stream of coded symbols. Symbol `i` maps to a
//! deterministic hash bucket at a dyadic level: level 0 has one bucket, level 1
//! has two, and so on. A key contributes to exactly one bucket per level, giving
//! each coded symbol a pseudo-random subset with inclusion probability
//! `1 / 2^level`. The decoder subtracts its local contribution from each remote
//! symbol and peels pure degree-one residual cells until the symmetric
//! difference is known.
const std = @import("std");

const Allocator = std.mem.Allocator;
const Wyhash = std.hash.Wyhash;

pub const Key = [32]u8;

const default_seed: u64 = 0xa9e1_3d7b_44c5_8f21;
const fingerprint_seed: u64 = 0x6f52_4942_4c54_5f31;
const bucket_seed: u64 = 0x4275_636b_6574_3130;

pub const CodedSymbol = struct {
    seed: u64,
    index: u64,
    count: i64,
    key_xor: Key,
    check_xor: u64,
};

pub const DecodeResult = struct {
    allocator: Allocator,
    local_only: []Key,
    remote_only: []Key,

    pub fn deinit(self: *DecodeResult) void {
        self.allocator.free(self.local_only);
        self.allocator.free(self.remote_only);
        self.* = .{
            .allocator = self.allocator,
            .local_only = &.{},
            .remote_only = &.{},
        };
    }
};

pub const Encoder = struct {
    allocator: Allocator,
    seed: u64,
    keys: std.ArrayList(Key) = .empty,
    next_index: u64 = 0,

    pub fn init(allocator: Allocator) Encoder {
        return initWithSeed(allocator, default_seed);
    }

    pub fn initWithSeed(allocator: Allocator, seed: u64) Encoder {
        return .{ .allocator = allocator, .seed = seed };
    }

    pub fn deinit(self: *Encoder) void {
        self.keys.deinit(self.allocator);
        self.* = .{ .allocator = self.allocator, .seed = self.seed };
    }

    pub fn add(self: *Encoder, key: Key) Allocator.Error!void {
        if (containsKey(self.keys.items, key)) return;
        try self.keys.append(self.allocator, key);
    }

    pub fn nextSymbol(self: *Encoder) CodedSymbol {
        const symbol = buildSymbol(self.seed, self.next_index, self.keys.items, 1);
        self.next_index += 1;
        return symbol;
    }
};

pub const Decoder = struct {
    allocator: Allocator,
    local: std.ArrayList(Key) = .empty,
    cells: std.ArrayList(CodedSymbol) = .empty,

    pub fn init(allocator: Allocator) Decoder {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Decoder) void {
        self.local.deinit(self.allocator);
        self.cells.deinit(self.allocator);
        self.* = .{ .allocator = self.allocator };
    }

    pub fn addLocal(self: *Decoder, key: Key) Allocator.Error!void {
        if (containsKey(self.local.items, key)) return;
        try self.local.append(self.allocator, key);
    }

    pub fn pushSymbol(self: *Decoder, remote: CodedSymbol) Allocator.Error!void {
        const local_symbol = buildSymbol(remote.seed, remote.index, self.local.items, -1);
        var residual = remote;
        residual.count += local_symbol.count;
        xorKey(&residual.key_xor, local_symbol.key_xor);
        residual.check_xor ^= local_symbol.check_xor;
        try self.cells.append(self.allocator, residual);
    }

    pub fn tryDecode(self: *Decoder) Allocator.Error!?DecodeResult {
        var work = try self.cells.clone(self.allocator);
        defer work.deinit(self.allocator);

        var queue: std.ArrayList(usize) = .empty;
        defer queue.deinit(self.allocator);

        var local_only: std.ArrayList(Key) = .empty;
        defer local_only.deinit(self.allocator);
        var remote_only: std.ArrayList(Key) = .empty;
        defer remote_only.deinit(self.allocator);

        for (work.items, 0..) |cell, i| {
            if (pureCell(cell) != null) try queue.append(self.allocator, i);
        }

        while (queue.pop()) |index| {
            const pure = pureCell(work.items[index]) orelse continue;
            const list = if (pure.sign < 0) &local_only else &remote_only;
            if (containsKey(list.items, pure.key)) continue;

            try list.append(self.allocator, pure.key);
            for (work.items, 0..) |*cell, i| {
                if (!symbolContains(cell.seed, cell.index, pure.key)) continue;
                peelKey(cell, pure.key, pure.sign);
                if (pureCell(cell.*) != null) try queue.append(self.allocator, i);
            }
        }

        for (work.items) |cell| {
            if (!zeroCell(cell)) return null;
        }

        sortKeys(local_only.items);
        sortKeys(remote_only.items);
        return .{
            .allocator = self.allocator,
            .local_only = try local_only.toOwnedSlice(self.allocator),
            .remote_only = try remote_only.toOwnedSlice(self.allocator),
        };
    }
};

const Pure = struct {
    key: Key,
    sign: i64,
};

fn buildSymbol(seed: u64, index: u64, keys: []const Key, sign: i64) CodedSymbol {
    var out = CodedSymbol{
        .seed = seed,
        .index = index,
        .count = 0,
        .key_xor = zeroKey(),
        .check_xor = 0,
    };

    for (keys) |key| {
        if (!symbolContains(seed, index, key)) continue;
        out.count += sign;
        xorKey(&out.key_xor, key);
        out.check_xor ^= fingerprint(key);
    }
    return out;
}

fn pureCell(cell: CodedSymbol) ?Pure {
    if (cell.count != 1 and cell.count != -1) return null;
    if (cell.check_xor != fingerprint(cell.key_xor)) return null;
    return .{ .key = cell.key_xor, .sign = cell.count };
}

fn peelKey(cell: *CodedSymbol, key: Key, sign: i64) void {
    cell.count -= sign;
    xorKey(&cell.key_xor, key);
    cell.check_xor ^= fingerprint(key);
}

fn zeroCell(cell: CodedSymbol) bool {
    return cell.count == 0 and cell.check_xor == 0 and std.mem.eql(u8, &cell.key_xor, &zeroKey());
}

fn symbolContains(seed: u64, index: u64, key: Key) bool {
    const shape = symbolShape(index);
    if (shape.level == 0) return true;
    const mask = (@as(u64, 1) << shape.level) - 1;
    return (bucketHash(seed, shape.level, key) & mask) == shape.bucket;
}

const Shape = struct {
    level: u6,
    bucket: u64,
};

fn symbolShape(index: u64) Shape {
    var level: u6 = 0;
    var width: u64 = 1;
    var bucket = index;
    while (bucket >= width and level < 63) {
        bucket -= width;
        width <<= 1;
        level += 1;
    }
    return .{ .level = level, .bucket = bucket };
}

fn bucketHash(seed: u64, level: u6, key: Key) u64 {
    var hasher = Wyhash.init(seed ^ bucket_seed ^ @as(u64, level));
    hasher.update(&key);
    return hasher.final();
}

fn fingerprint(key: Key) u64 {
    return Wyhash.hash(fingerprint_seed, &key);
}

fn xorKey(target: *Key, source: Key) void {
    for (target, source) |*a, b| a.* ^= b;
}

fn zeroKey() Key {
    return @as([32]u8, @splat(0));
}

fn containsKey(keys: []const Key, needle: Key) bool {
    for (keys) |key| {
        if (std.mem.eql(u8, &key, &needle)) return true;
    }
    return false;
}

fn sortKeys(keys: []Key) void {
    std.mem.sort(Key, keys, {}, struct {
        fn lessThan(_: void, a: Key, b: Key) bool {
            return std.mem.order(u8, &a, &b) == .lt;
        }
    }.lessThan);
}

fn makeKey(n: u64) Key {
    var key: Key = undefined;
    std.mem.writeInt(u64, key[0..8], n, .little);
    var h = Wyhash.init(0x6b65_795f_7465_7374);
    h.update(key[0..8]);
    const a = h.final();
    std.mem.writeInt(u64, key[8..16], a, .little);
    std.mem.writeInt(u64, key[16..24], a ^ n ^ 0xb17b_1a7e_cafe_f00d, .little);
    std.mem.writeInt(u64, key[24..32], ~a, .little);
    return key;
}

fn addRangeEncoder(enc: *Encoder, start: u64, count: usize) !void {
    for (0..count) |i| try enc.add(makeKey(start + i));
}

fn addRangeDecoder(dec: *Decoder, start: u64, count: usize) !void {
    for (0..count) |i| try dec.addLocal(makeKey(start + i));
}

fn decodeUntil(enc: *Encoder, dec: *Decoder, max_symbols: usize) !DecodeResult {
    for (0..max_symbols) |_| {
        try dec.pushSymbol(enc.nextSymbol());
        if (try dec.tryDecode()) |result| return result;
    }
    return error.DecodeFailed;
}

fn expectKeysEqual(actual: []const Key, expected: []Key) !void {
    sortKeys(expected);
    try std.testing.expectEqual(expected.len, actual.len);
    for (actual, expected) |a, e| try std.testing.expect(std.mem.eql(u8, &a, &e));
}

test "reconcile sets differing by 1" {
    const allocator = std.testing.allocator;
    var enc = Encoder.initWithSeed(allocator, 11);
    defer enc.deinit();
    var dec = Decoder.init(allocator);
    defer dec.deinit();

    try addRangeEncoder(&enc, 0, 64);
    try addRangeDecoder(&dec, 0, 63);

    var result = try decodeUntil(&enc, &dec, 512);
    defer result.deinit();

    var expected_remote = [_]Key{makeKey(63)};
    var expected_local = [_]Key{};
    try expectKeysEqual(result.remote_only, expected_remote[0..]);
    try expectKeysEqual(result.local_only, expected_local[0..]);
}

test "reconcile sets differing by 100" {
    const allocator = std.testing.allocator;
    var enc = Encoder.initWithSeed(allocator, 100);
    defer enc.deinit();
    var dec = Decoder.init(allocator);
    defer dec.deinit();

    try addRangeEncoder(&enc, 0, 200);
    try addRangeDecoder(&dec, 0, 200);
    try addRangeEncoder(&enc, 10_000, 50);
    try addRangeDecoder(&dec, 20_000, 50);

    var result = try decodeUntil(&enc, &dec, 4096);
    defer result.deinit();

    var expected_remote: [50]Key = undefined;
    var expected_local: [50]Key = undefined;
    for (0..50) |i| {
        expected_remote[i] = makeKey(10_000 + i);
        expected_local[i] = makeKey(20_000 + i);
    }
    try expectKeysEqual(result.remote_only, expected_remote[0..]);
    try expectKeysEqual(result.local_only, expected_local[0..]);
}

test "identical sets need zero symbols" {
    const allocator = std.testing.allocator;
    var dec = Decoder.init(allocator);
    defer dec.deinit();
    try addRangeDecoder(&dec, 0, 128);

    var result = (try dec.tryDecode()).?;
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 0), result.remote_only.len);
    try std.testing.expectEqual(@as(usize, 0), result.local_only.len);
}

test "asymmetric diffs recover exact sides" {
    const allocator = std.testing.allocator;
    var enc = Encoder.initWithSeed(allocator, 222);
    defer enc.deinit();
    var dec = Decoder.init(allocator);
    defer dec.deinit();

    try addRangeEncoder(&enc, 0, 40);
    try addRangeDecoder(&dec, 0, 40);
    try enc.add(makeKey(80));
    try enc.add(makeKey(81));
    try enc.add(makeKey(82));
    try dec.addLocal(makeKey(90));

    var result = try decodeUntil(&enc, &dec, 1024);
    defer result.deinit();

    var expected_remote = [_]Key{ makeKey(80), makeKey(81), makeKey(82) };
    var expected_local = [_]Key{makeKey(90)};
    try expectKeysEqual(result.remote_only, expected_remote[0..]);
    try expectKeysEqual(result.local_only, expected_local[0..]);
}

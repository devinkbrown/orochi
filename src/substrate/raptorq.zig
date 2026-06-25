// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Systematic GF(256) fountain/FEC symbols for lossy media bursts.
//!
//! This is RaptorQ-style rather than a full RFC 6330 implementation: source
//! ESIs are systematic, repair ESIs are deterministic linear combinations, and
//! decode uses dense inactivation/Gaussian elimination over GF(256).
const std = @import("std");

const Allocator = std.mem.Allocator;
const default_seed: u64 = 0x7261_7074_6f72_7121;

pub const Error = Allocator.Error || error{InvalidSymbolLength};

pub const Encoder = struct {
    allocator: Allocator,
    seed: u64,
    k: usize,
    symbol_len: usize,
    data: []u8,
    basis: Basis,

    pub fn init(
        allocator: Allocator,
        source_symbols: []const []const u8,
        symbol_len: usize,
    ) Error!Encoder {
        return initWithSeed(allocator, default_seed, source_symbols, symbol_len);
    }

    pub fn initWithSeed(
        allocator: Allocator,
        seed: u64,
        source_symbols: []const []const u8,
        symbol_len: usize,
    ) Error!Encoder {
        var data = try allocator.alloc(u8, source_symbols.len * symbol_len);
        errdefer allocator.free(data);

        for (source_symbols, 0..) |symbol, i| {
            if (symbol.len != symbol_len) return error.InvalidSymbolLength;
            const dst = data[i * symbol_len ..][0..symbol_len];
            @memcpy(dst, symbol);
        }

        return .{
            .allocator = allocator,
            .seed = seed,
            .k = source_symbols.len,
            .symbol_len = symbol_len,
            .data = data,
            .basis = try Basis.init(allocator, source_symbols.len, seed),
        };
    }

    pub fn deinit(self: *Encoder) void {
        self.basis.deinit(self.allocator);
        self.allocator.free(self.data);
        self.* = undefined;
    }

    pub fn repairSymbol(self: *const Encoder, esi: usize) Error![]u8 {
        const out = try self.allocator.alloc(u8, self.symbol_len);
        errdefer self.allocator.free(out);
        @memset(out, 0);

        if (esi < self.k) {
            @memcpy(out, self.sourceAt(esi));
            return out;
        }

        const coeffs = try self.allocator.alloc(u8, self.k);
        defer self.allocator.free(coeffs);
        coefficients(&self.basis, coeffs, self.seed, esi);

        for (coeffs, 0..) |coef, i| {
            if (coef == 0) continue;
            xorMul(out, self.sourceAt(i), coef);
        }
        return out;
    }

    fn sourceAt(self: *const Encoder, i: usize) []const u8 {
        return self.data[i * self.symbol_len ..][0..self.symbol_len];
    }
};

pub const Decoder = struct {
    allocator: Allocator,
    seed: u64,
    k: usize,
    symbol_len: usize,
    received: std.ArrayList(Received) = .empty,

    pub fn init(allocator: Allocator, k: usize, symbol_len: usize) Decoder {
        return initWithSeed(allocator, default_seed, k, symbol_len);
    }

    pub fn initWithSeed(allocator: Allocator, seed: u64, k: usize, symbol_len: usize) Decoder {
        return .{
            .allocator = allocator,
            .seed = seed,
            .k = k,
            .symbol_len = symbol_len,
        };
    }

    pub fn deinit(self: *Decoder) void {
        for (self.received.items) |item| self.allocator.free(item.bytes);
        self.received.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn addSymbol(self: *Decoder, esi: usize, bytes: []const u8) Error!void {
        if (bytes.len != self.symbol_len) return error.InvalidSymbolLength;
        const copy = try self.allocator.dupe(u8, bytes);
        errdefer self.allocator.free(copy);
        try self.received.append(self.allocator, .{ .esi = esi, .bytes = copy });
    }

    pub fn tryDecode(self: *Decoder) Error!?[][]u8 {
        if (self.k == 0) return try self.allocator.alloc([]u8, 0);
        if (self.received.items.len < self.k) return null;

        var basis = try Basis.init(self.allocator, self.k, self.seed);
        defer basis.deinit(self.allocator);

        const rows = self.received.items.len;
        const row_len = self.k + self.symbol_len;
        var matrix = try self.allocator.alloc(u8, rows * row_len);
        defer self.allocator.free(matrix);
        var pivot_for_col = try self.allocator.alloc(usize, self.k);
        defer self.allocator.free(pivot_for_col);
        @memset(pivot_for_col, std.math.maxInt(usize));

        const coeffs = try self.allocator.alloc(u8, self.k);
        defer self.allocator.free(coeffs);

        for (self.received.items, 0..) |item, r| {
            const row = matrix[r * row_len ..][0..row_len];
            @memset(row[0..self.k], 0);
            if (item.esi < self.k) {
                row[item.esi] = 1;
            } else {
                coefficients(&basis, coeffs, self.seed, item.esi);
                @memcpy(row[0..self.k], coeffs);
            }
            @memcpy(row[self.k..], item.bytes);
        }

        var rank: usize = 0;
        for (0..self.k) |col| {
            const pivot = findPivot(matrix, row_len, rows, rank, col) orelse continue;
            swapRows(matrix, row_len, rank, pivot);

            const prow = rowAt(matrix, row_len, rank);
            const inv = gf.inv(prow[col]);
            scaleRow(prow[col..], inv);

            for (0..rows) |r| {
                if (r == rank) continue;
                const row = rowAt(matrix, row_len, r);
                const factor = row[col];
                if (factor == 0) continue;
                addScaled(row[col..], prow[col..], factor);
            }

            pivot_for_col[col] = rank;
            rank += 1;
            if (rank == self.k) break;
        }

        if (rank < self.k) return null;

        var out = try self.allocator.alloc([]u8, self.k);
        errdefer self.allocator.free(out);
        var made: usize = 0;
        errdefer {
            for (out[0..made]) |symbol| self.allocator.free(symbol);
        }

        for (0..self.k) |col| {
            const r = pivot_for_col[col];
            if (r == std.math.maxInt(usize)) return null;
            const row = rowAt(matrix, row_len, r);
            out[col] = try self.allocator.dupe(u8, row[self.k..]);
            made += 1;
        }
        return out;
    }
};

pub fn freeDecoded(allocator: Allocator, decoded: [][]u8) void {
    for (decoded) |symbol| allocator.free(symbol);
    allocator.free(decoded);
}

const Received = struct {
    esi: usize,
    bytes: []u8,
};

const Basis = struct {
    k: usize,
    seed: u64,
    perm: [256]u8,
    denom_inv: []u8,
    mds: bool,

    fn init(allocator: Allocator, k: usize, seed: u64) Allocator.Error!Basis {
        var basis = Basis{
            .k = k,
            .seed = seed,
            .perm = permutation(seed),
            .denom_inv = &.{},
            .mds = k > 0 and k < 256,
        };
        if (!basis.mds) return basis;

        basis.denom_inv = try allocator.alloc(u8, k);
        for (0..k) |j| {
            var denom: u8 = 1;
            const xj = basis.perm[j];
            for (0..k) |m| {
                if (m == j) continue;
                denom = gf.mul(denom, xj ^ basis.perm[m]);
            }
            basis.denom_inv[j] = gf.inv(denom);
        }
        return basis;
    }

    fn deinit(self: *Basis, allocator: Allocator) void {
        allocator.free(self.denom_inv);
        self.* = undefined;
    }
};

fn coefficients(basis: *const Basis, out: []u8, seed: u64, esi: usize) void {
    @memset(out, 0);
    if (esi < out.len) {
        out[esi] = 1;
        return;
    }

    if (basis.mds) {
        const repair_id = esi - out.len;
        const spare = 256 - out.len;
        if (repair_id < spare) {
            lagrangeCoefficients(basis, out, basis.perm[out.len + repair_id]);
            return;
        }
    }

    denseCoefficients(out, seed, esi);
}

fn lagrangeCoefficients(basis: *const Basis, out: []u8, x: u8) void {
    for (0..out.len) |j| {
        var num: u8 = 1;
        for (0..out.len) |m| {
            if (m == j) continue;
            num = gf.mul(num, x ^ basis.perm[m]);
        }
        out[j] = gf.mul(num, basis.denom_inv[j]);
    }
}

fn denseCoefficients(out: []u8, seed: u64, esi: usize) void {
    var rng = SplitMix64.init(seed ^ mixInt(esi));
    for (out) |*coef| {
        var b: u8 = @intCast(rng.next() & 0xff);
        if (b == 0) b = 1;
        coef.* = b;
    }
}

fn xorMul(dst: []u8, src: []const u8, coef: u8) void {
    for (dst, src) |*d, s| d.* ^= gf.mul(coef, s);
}

fn rowAt(matrix: []u8, row_len: usize, row: usize) []u8 {
    return matrix[row * row_len ..][0..row_len];
}

fn findPivot(matrix: []u8, row_len: usize, rows: usize, start: usize, col: usize) ?usize {
    for (start..rows) |r| {
        if (rowAt(matrix, row_len, r)[col] != 0) return r;
    }
    return null;
}

fn swapRows(matrix: []u8, row_len: usize, a: usize, b: usize) void {
    if (a == b) return;
    const ar = rowAt(matrix, row_len, a);
    const br = rowAt(matrix, row_len, b);
    for (ar, br) |*av, *bv| std.mem.swap(u8, av, bv);
}

fn scaleRow(row: []u8, factor: u8) void {
    if (factor == 1) return;
    for (row) |*v| v.* = gf.mul(v.*, factor);
}

fn addScaled(dst: []u8, src: []const u8, factor: u8) void {
    for (dst, src) |*d, s| d.* ^= gf.mul(factor, s);
}

fn permutation(seed: u64) [256]u8 {
    var out: [256]u8 = undefined;
    for (&out, 0..) |*v, i| v.* = @intCast(i);
    var rng = SplitMix64.init(seed ^ 0x7065_726d_7574_6531);
    var i: usize = out.len - 1;
    while (i > 0) : (i -= 1) {
        const j: usize = @intCast(rng.next() % (i + 1));
        std.mem.swap(u8, &out[i], &out[j]);
    }
    return out;
}

fn mixInt(value: usize) u64 {
    var z: u64 = @intCast(value);
    z +%= 0x9e37_79b9_7f4a_7c15;
    z = (z ^ (z >> 30)) *% 0xbf58_476d_1ce4_e5b9;
    z = (z ^ (z >> 27)) *% 0x94d0_49bb_1331_11eb;
    return z ^ (z >> 31);
}

const SplitMix64 = struct {
    state: u64,

    fn init(seed: u64) SplitMix64 {
        return .{ .state = seed };
    }

    fn next(self: *SplitMix64) u64 {
        self.state +%= 0x9e37_79b9_7f4a_7c15;
        var z = self.state;
        z = (z ^ (z >> 30)) *% 0xbf58_476d_1ce4_e5b9;
        z = (z ^ (z >> 27)) *% 0x94d0_49bb_1331_11eb;
        return z ^ (z >> 31);
    }
};

pub const gf = struct {
    const Tables = struct {
        exp: [512]u8,
        log: [256]u8,
    };

    const tables = buildTables();

    pub fn add(a: u8, b: u8) u8 {
        return a ^ b;
    }

    pub fn mul(a: u8, b: u8) u8 {
        if (a == 0 or b == 0) return 0;
        return tables.exp[@as(usize, tables.log[a]) + tables.log[b]];
    }

    pub fn inv(a: u8) u8 {
        std.debug.assert(a != 0);
        return tables.exp[255 - @as(usize, tables.log[a])];
    }

    fn buildTables() Tables {
        var t = Tables{
            .exp = [_]u8{0} ** 512,
            .log = [_]u8{0} ** 256,
        };
        var x: u16 = 1;
        var i: usize = 0;
        while (i < 255) : (i += 1) {
            t.exp[i] = @intCast(x);
            t.log[@intCast(x)] = @intCast(i);
            x <<= 1;
            if ((x & 0x100) != 0) x ^= 0x11d;
        }
        while (i < t.exp.len) : (i += 1) {
            t.exp[i] = t.exp[i - 255];
        }
        return t;
    }
};

test "GF(256) field axioms and inverse round trip" {
    for (1..256) |a_usize| {
        const a: u8 = @intCast(a_usize);
        try std.testing.expectEqual(@as(u8, 1), gf.mul(a, gf.inv(a)));
        try std.testing.expectEqual(a, gf.mul(gf.mul(a, a), gf.inv(a)));
    }

    for (0..64) |i| {
        const a: u8 = @intCast((i * 3) & 0xff);
        const b: u8 = @intCast((i * 5) & 0xff);
        const c: u8 = @intCast((i * 7) & 0xff);
        try std.testing.expectEqual(gf.mul(a, b), gf.mul(b, a));
        try std.testing.expectEqual(
            gf.mul(a, gf.add(b, c)),
            gf.add(gf.mul(a, b), gf.mul(a, c)),
        );
    }
}

test "recover from exactly K systematic symbols" {
    const allocator = std.testing.allocator;
    var raw: [4][8]u8 = undefined;
    for (&raw, 0..) |*symbol, i| {
        for (symbol, 0..) |*b, j| b.* = @intCast(i * 17 + j);
    }

    var slices: [4][]const u8 = undefined;
    for (&raw, 0..) |*symbol, i| slices[i] = symbol;

    var enc = try Encoder.init(allocator, &slices, 8);
    defer enc.deinit();
    var dec = Decoder.init(allocator, slices.len, 8);
    defer dec.deinit();

    for (slices, 0..) |symbol, esi| try dec.addSymbol(esi, symbol);

    const decoded = (try dec.tryDecode()) orelse return error.DecodeFailed;
    defer freeDecoded(allocator, decoded);
    for (slices, decoded) |want, got| {
        try std.testing.expectEqualSlices(u8, want, got);
    }
}

test "recover with 30 percent random erasures using repair symbols" {
    const allocator = std.testing.allocator;
    const k = 32;
    const symbol_len = 64;
    const seed = 0x1c0d_e5f0_ec00_1234;

    var raw: [k][symbol_len]u8 = undefined;
    var fill_rng = SplitMix64.init(0xfeed_fade_1234_5678);
    for (&raw) |*symbol| {
        for (symbol) |*b| b.* = @intCast(fill_rng.next() & 0xff);
    }

    var slices: [k][]const u8 = undefined;
    for (&raw, 0..) |*symbol, i| slices[i] = symbol;

    var enc = try Encoder.initWithSeed(allocator, seed, &slices, symbol_len);
    defer enc.deinit();
    var dec = Decoder.initWithSeed(allocator, seed, k, symbol_len);
    defer dec.deinit();

    var erase_rng = SplitMix64.init(0x7661_6e69_7368_3330);
    var received: usize = 0;
    for (0..k * 2) |esi| {
        if (erase_rng.next() % 10 < 3) continue;
        if (esi < k) {
            try dec.addSymbol(esi, slices[esi]);
        } else {
            const repair = try enc.repairSymbol(esi);
            defer allocator.free(repair);
            try dec.addSymbol(esi, repair);
        }
        received += 1;
    }
    try std.testing.expect(received >= k);

    const decoded = (try dec.tryDecode()) orelse return error.DecodeFailed;
    defer freeDecoded(allocator, decoded);
    for (slices, decoded) |want, got| {
        try std.testing.expectEqualSlices(u8, want, got);
    }
}

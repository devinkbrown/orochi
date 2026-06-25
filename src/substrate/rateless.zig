// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Rateless erasure coding spike.
//!
//! This file implements a small LT-code (Luby transform) over fixed-size byte
//! blocks. An encoder produces an unbounded stream of coded symbols; each
//! symbol is the XOR of a deterministic pseudo-random neighbor set. A decoder
//! collects any slightly-overcomplete subset of symbols and recovers the source
//! blocks with peeling / belief-propagation.
//!
//! The module is deliberately self-contained and std-only so it can be tested
//! in isolation with:
//!
//!     zig test src/substrate/rateless.zig

const std = @import("std");

const Allocator = std.mem.Allocator;

/// Result returned after a symbol is offered to the decoder.
pub const DecodeStatus = enum {
    /// More independent symbols are still needed.
    incomplete,
    /// All source blocks have been recovered.
    complete,
};

/// Errors reported by the rateless encoder/decoder.
pub const RatelessError = error{
    InvalidLayout,
    InvalidSymbol,
    InconsistentSymbols,
};

/// A deterministic SplitMix64 PRNG.
///
/// SplitMix64 is small, reproducible, and has good enough diffusion for symbol
/// scheduling. It is not a cryptographic generator.
pub const SplitMix64 = struct {
    state: u64,

    /// Create a generator with `seed`.
    pub fn init(seed: u64) SplitMix64 {
        return .{ .state = seed };
    }

    /// Return the next 64-bit word.
    pub fn next(self: *SplitMix64) u64 {
        self.state +%= 0x9e3779b97f4a7c15;
        var z = self.state;
        z = (z ^ (z >> 30)) *% 0xbf58476d1ce4e5b9;
        z = (z ^ (z >> 27)) *% 0x94d049bb133111eb;
        return z ^ (z >> 31);
    }

    /// Return a value in `[0, upper)`.
    pub fn bounded(self: *SplitMix64, upper: usize) usize {
        std.debug.assert(upper > 0);
        const limit: u64 = @intCast(upper);
        return @intCast(self.next() % limit);
    }
};

/// A coded LT symbol.
///
/// `index` is enough, together with the shared encoder seed and source layout,
/// to reconstruct the symbol's neighbor set. `bytes` is owned by the caller.
pub const CodedSymbol = struct {
    index: u64,
    bytes: []u8,

    /// Free the owned payload.
    pub fn deinit(self: *CodedSymbol, allocator: Allocator) void {
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

/// Produces an unbounded deterministic stream of LT symbols.
pub const Encoder = struct {
    source: []const u8,
    block_count: usize,
    block_size: usize,
    seed: u64,
    next_index: u64,

    /// Build an encoder over `block_count` fixed-size blocks stored
    /// contiguously in `source`.
    pub fn init(source: []const u8, block_count: usize, block_size: usize, seed: u64) RatelessError!Encoder {
        if (block_count == 0 or block_size == 0) return error.InvalidLayout;
        if (source.len != block_count * block_size) return error.InvalidLayout;
        return .{
            .source = source,
            .block_count = block_count,
            .block_size = block_size,
            .seed = seed,
            .next_index = 0,
        };
    }

    /// Return the next coded symbol in the rateless stream.
    pub fn next(self: *Encoder, allocator: Allocator) (Allocator.Error || RatelessError)!CodedSymbol {
        const symbol = try self.symbolAt(allocator, self.next_index);
        self.next_index += 1;
        return symbol;
    }

    /// Return the coded symbol at a specific stream index.
    pub fn symbolAt(self: *const Encoder, allocator: Allocator, index: u64) (Allocator.Error || RatelessError)!CodedSymbol {
        const neighbors = try makeNeighbors(allocator, self.block_count, self.seed, index);
        defer allocator.free(neighbors);

        const bytes = try allocator.alloc(u8, self.block_size);
        errdefer allocator.free(bytes);
        @memset(bytes, 0);

        for (neighbors) |neighbor| {
            xorInto(bytes, blockAtConst(self.source, self.block_size, neighbor));
        }

        return .{ .index = index, .bytes = bytes };
    }
};

/// Peeling decoder for LT symbols.
///
/// The decoder stores received symbols, reconstructs their deterministic
/// neighbor sets, and repeatedly peels degree-one equations until either all
/// blocks are known or the current graph stalls.
pub const Decoder = struct {
    allocator: Allocator,
    block_count: usize,
    block_size: usize,
    seed: u64,
    received: std.ArrayList(StoredSymbol),
    seen: std.AutoHashMap(u64, void),
    recovered: []u8,
    complete: bool,

    /// Create a decoder for a source layout and encoder seed.
    pub fn init(allocator: Allocator, block_count: usize, block_size: usize, seed: u64) (Allocator.Error || RatelessError)!Decoder {
        if (block_count == 0 or block_size == 0) return error.InvalidLayout;

        const recovered = try allocator.alloc(u8, block_count * block_size);
        @memset(recovered, 0);

        return .{
            .allocator = allocator,
            .block_count = block_count,
            .block_size = block_size,
            .seed = seed,
            .received = .empty,
            .seen = std.AutoHashMap(u64, void).init(allocator),
            .recovered = recovered,
            .complete = false,
        };
    }

    /// Free all symbols and recovered storage owned by this decoder.
    pub fn deinit(self: *Decoder) void {
        for (self.received.items) |*symbol| {
            symbol.deinit(self.allocator);
        }
        self.received.deinit(self.allocator);
        self.seen.deinit();
        self.allocator.free(self.recovered);
        self.* = undefined;
    }

    /// Add a coded symbol. The decoder copies the payload, so the caller keeps
    /// ownership of `symbol`.
    pub fn addSymbol(self: *Decoder, symbol: CodedSymbol) (Allocator.Error || RatelessError)!DecodeStatus {
        if (symbol.bytes.len != self.block_size) return error.InvalidSymbol;
        if (self.complete) return .complete;
        if (self.seen.contains(symbol.index)) return self.attemptDecode();

        const copy = try self.allocator.dupe(u8, symbol.bytes);
        errdefer self.allocator.free(copy);

        try self.seen.put(symbol.index, {});
        errdefer _ = self.seen.remove(symbol.index);

        try self.received.append(self.allocator, .{ .index = symbol.index, .bytes = copy });
        return self.attemptDecode();
    }

    /// True once all source blocks have been recovered.
    pub fn isComplete(self: *const Decoder) bool {
        return self.complete;
    }

    /// Return the recovered block at `index` once decoding is complete.
    pub fn block(self: *const Decoder, index: usize) ?[]const u8 {
        if (!self.complete or index >= self.block_count) return null;
        return blockAtConst(self.recovered, self.block_size, index);
    }

    /// Return all recovered source bytes once decoding is complete.
    pub fn recoveredBytes(self: *const Decoder) ?[]const u8 {
        if (!self.complete) return null;
        return self.recovered;
    }

    fn attemptDecode(self: *Decoder) (Allocator.Error || RatelessError)!DecodeStatus {
        if (self.complete) return .complete;

        var equations: std.ArrayList(Equation) = .empty;
        defer {
            for (equations.items) |*equation| {
                equation.deinit(self.allocator);
            }
            equations.deinit(self.allocator);
        }

        for (self.received.items) |symbol| {
            const neighbors = try makeNeighbors(self.allocator, self.block_count, self.seed, symbol.index);
            errdefer self.allocator.free(neighbors);

            const payload = try self.allocator.dupe(u8, symbol.bytes);
            errdefer self.allocator.free(payload);

            try equations.append(self.allocator, .{
                .neighbors = neighbors,
                .degree = neighbors.len,
                .payload = payload,
                .solved = false,
            });
        }

        const scratch = try self.allocator.alloc(u8, self.block_count * self.block_size);
        defer self.allocator.free(scratch);
        @memset(scratch, 0);

        const known = try self.allocator.alloc(bool, self.block_count);
        defer self.allocator.free(known);
        @memset(known, false);

        var decoded_count: usize = 0;
        var progress = true;
        while (progress) {
            progress = false;

            var chosen: ?usize = null;
            for (equations.items, 0..) |equation, i| {
                if (!equation.solved and equation.degree == 1) {
                    chosen = i;
                    break;
                }
            }

            const equation_index = chosen orelse break;
            var equation = &equations.items[equation_index];
            const source_index = equation.neighbors[0];
            const decoded_block = blockAtMut(scratch, self.block_size, source_index);

            if (known[source_index]) {
                if (!std.mem.eql(u8, decoded_block, equation.payload)) {
                    return error.InconsistentSymbols;
                }
                equation.solved = true;
                progress = true;
                continue;
            }

            @memcpy(decoded_block, equation.payload);
            known[source_index] = true;
            decoded_count += 1;
            equation.solved = true;
            progress = true;

            for (equations.items) |*other| {
                if (other.solved) continue;
                if (removeNeighbor(other, source_index)) {
                    xorInto(other.payload, decoded_block);
                    if (other.degree == 0) {
                        if (!allZero(other.payload)) return error.InconsistentSymbols;
                        other.solved = true;
                    }
                }
            }
        }

        if (decoded_count != self.block_count) return .incomplete;

        @memcpy(self.recovered, scratch);
        self.complete = true;
        return .complete;
    }
};

const StoredSymbol = struct {
    index: u64,
    bytes: []u8,

    fn deinit(self: *StoredSymbol, allocator: Allocator) void {
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

const Equation = struct {
    neighbors: []usize,
    degree: usize,
    payload: []u8,
    solved: bool,

    fn deinit(self: *Equation, allocator: Allocator) void {
        allocator.free(self.neighbors);
        allocator.free(self.payload);
        self.* = undefined;
    }
};

fn blockAtConst(bytes: []const u8, block_size: usize, index: usize) []const u8 {
    const start = index * block_size;
    return bytes[start .. start + block_size];
}

fn blockAtMut(bytes: []u8, block_size: usize, index: usize) []u8 {
    const start = index * block_size;
    return bytes[start .. start + block_size];
}

fn xorInto(dst: []u8, src: []const u8) void {
    std.debug.assert(dst.len == src.len);
    for (dst, src) |*d, s| {
        d.* ^= s;
    }
}

fn allZero(bytes: []const u8) bool {
    for (bytes) |byte| {
        if (byte != 0) return false;
    }
    return true;
}

fn removeNeighbor(equation: *Equation, source_index: usize) bool {
    var i: usize = 0;
    while (i < equation.degree) : (i += 1) {
        if (equation.neighbors[i] == source_index) {
            equation.neighbors[i] = equation.neighbors[equation.degree - 1];
            equation.degree -= 1;
            return true;
        }
    }
    return false;
}

fn makeNeighbors(allocator: Allocator, block_count: usize, seed: u64, symbol_index: u64) Allocator.Error![]usize {
    std.debug.assert(block_count > 0);

    const block_count_u64: u64 = @intCast(block_count);
    const round = symbol_index / block_count_u64;
    const position: usize = @intCast(symbol_index % block_count_u64);

    if (round == 0 or block_count == 1) {
        const neighbors = try allocator.alloc(usize, 1);
        neighbors[0] = position;
        return neighbors;
    }

    if (round == 1) {
        const neighbors = try allocator.alloc(usize, 2);
        const shift = deterministicShift(block_count, seed);
        neighbors[0] = (position + shift) % block_count;
        neighbors[1] = (position + 1 + shift) % block_count;
        return neighbors;
    }

    const degree = robustSolitonLikeDegree(block_count, seed, symbol_index);
    var neighbors = try allocator.alloc(usize, degree);
    errdefer allocator.free(neighbors);

    var rng = SplitMix64.init(mixSeed(seed, symbol_index, 0x82f3_63cd_4bb7_2a35));
    var count: usize = 0;
    while (count < degree) {
        const candidate = rng.bounded(block_count);
        if (!containsPrefix(neighbors, count, candidate)) {
            neighbors[count] = candidate;
            count += 1;
        }
    }

    return neighbors;
}

fn containsPrefix(values: []const usize, len: usize, needle: usize) bool {
    for (values[0..len]) |value| {
        if (value == needle) return true;
    }
    return false;
}

fn deterministicShift(block_count: usize, seed: u64) usize {
    if (block_count == 1) return 0;
    var rng = SplitMix64.init(mixSeed(seed, 0, 0x6d45_421f_3bad_f00d));
    return rng.bounded(block_count);
}

fn robustSolitonLikeDegree(block_count: usize, seed: u64, symbol_index: u64) usize {
    if (block_count <= 1) return 1;

    var rng = SplitMix64.init(mixSeed(seed, symbol_index, 0xa17d_5137_5eed_0001));
    const total = degreeWeightTotal(block_count);
    var ticket = rng.next() % total;

    var degree: usize = 1;
    while (degree <= block_count) : (degree += 1) {
        const weight = degreeWeight(block_count, degree);
        if (ticket < weight) return degree;
        ticket -= weight;
    }

    return block_count;
}

fn degreeWeightTotal(block_count: usize) u64 {
    var total: u64 = 0;
    var degree: usize = 1;
    while (degree <= block_count) : (degree += 1) {
        total += degreeWeight(block_count, degree);
    }
    return total;
}

fn degreeWeight(block_count: usize, degree: usize) u64 {
    const k: u64 = @intCast(block_count);
    if (degree == 1) {
        return @as(u64, @intCast(intSqrtCeil(block_count))) * 12 + 1;
    }

    const d: u64 = @intCast(degree);
    var weight = (k * 24) / (d * (d - 1)) + 1;

    const ripple_limit = intSqrtCeil(block_count) + 1;
    if (degree <= ripple_limit) {
        weight += k / d + 1;
    }

    return weight;
}

fn intSqrtCeil(value: usize) usize {
    var root: usize = 0;
    while (root * root < value) : (root += 1) {}
    return root;
}

fn mixSeed(seed: u64, index: u64, tag: u64) u64 {
    var rng = SplitMix64.init(seed ^ (index *% 0xd1b5_4a32_d192_ed03) ^ tag);
    return rng.next();
}

fn shouldDrop(seed: u64, index: u64) bool {
    var rng = SplitMix64.init(mixSeed(seed, index, 0xd401_7a55_10cc_1e55));
    return rng.next() % 5 == 0;
}

fn makeSource(allocator: Allocator, block_count: usize, block_size: usize, seed: u64) Allocator.Error![]u8 {
    const bytes = try allocator.alloc(u8, block_count * block_size);
    errdefer allocator.free(bytes);

    var rng = SplitMix64.init(seed);
    for (bytes) |*byte| {
        byte.* = @truncate(rng.next());
    }

    return bytes;
}

test "splitmix64 is deterministic" {
    var a = SplitMix64.init(0x1234_5678_9abc_def0);
    var b = SplitMix64.init(0x1234_5678_9abc_def0);

    var i: usize = 0;
    while (i < 128) : (i += 1) {
        try std.testing.expectEqual(a.next(), b.next());
    }
}

test "encoder emits deterministic symbols for the same seed" {
    const allocator = std.testing.allocator;
    const block_count = 12;
    const block_size = 9;
    const seed = 0xa5a5_1234_beef_9876;

    const source = try makeSource(allocator, block_count, block_size, seed);
    defer allocator.free(source);

    var left = try Encoder.init(source, block_count, block_size, seed);
    var right = try Encoder.init(source, block_count, block_size, seed);

    var i: usize = 0;
    while (i < block_count * 3 + 7) : (i += 1) {
        var a = try left.next(allocator);
        defer a.deinit(allocator);
        var b = try right.next(allocator);
        defer b.deinit(allocator);

        try std.testing.expectEqual(a.index, b.index);
        try std.testing.expectEqualSlices(u8, a.bytes, b.bytes);
    }
}

test "decoder reports incomplete before enough symbols and complete after K degree-one symbols" {
    const allocator = std.testing.allocator;
    const block_count = 10;
    const block_size = 11;
    const seed = 0xfeed_9988_7766_5544;

    const source = try makeSource(allocator, block_count, block_size, seed);
    defer allocator.free(source);

    var encoder = try Encoder.init(source, block_count, block_size, seed);
    var decoder = try Decoder.init(allocator, block_count, block_size, seed);
    defer decoder.deinit();

    var status: DecodeStatus = .incomplete;
    var i: usize = 0;
    while (i < block_count - 1) : (i += 1) {
        var symbol = try encoder.next(allocator);
        defer symbol.deinit(allocator);
        status = try decoder.addSymbol(symbol);
        try std.testing.expectEqual(DecodeStatus.incomplete, status);
    }

    var final_symbol = try encoder.next(allocator);
    defer final_symbol.deinit(allocator);
    status = try decoder.addSymbol(final_symbol);

    try std.testing.expectEqual(DecodeStatus.complete, status);
    try std.testing.expectEqualSlices(u8, source, decoder.recoveredBytes().?);
}

test "decoder recovers through deterministic symbol loss with modest overhead" {
    const allocator = std.testing.allocator;
    const Combo = struct {
        block_count: usize,
        block_size: usize,
        seed: u64,
    };
    const combos = [_]Combo{
        .{ .block_count = 4, .block_size = 1, .seed = 0x1111 },
        .{ .block_count = 9, .block_size = 3, .seed = 0x2222_3333 },
        .{ .block_count = 17, .block_size = 13, .seed = 0x3344_5566_7788 },
        .{ .block_count = 32, .block_size = 16, .seed = 0x4455_6677_8899_aabb },
        .{ .block_count = 64, .block_size = 7, .seed = 0x5566_7788_99aa_bbcc },
    };

    for (combos) |combo| {
        const source = try makeSource(allocator, combo.block_count, combo.block_size, combo.seed);
        defer allocator.free(source);

        var encoder = try Encoder.init(source, combo.block_count, combo.block_size, combo.seed);
        var decoder = try Decoder.init(allocator, combo.block_count, combo.block_size, combo.seed);
        defer decoder.deinit();

        var delivered: usize = 0;
        var produced: u64 = 0;
        const max_produced: u64 = @intCast(combo.block_count * 6);

        while (!decoder.isComplete() and produced < max_produced) : (produced += 1) {
            var symbol = try encoder.next(allocator);
            defer symbol.deinit(allocator);

            if (shouldDrop(combo.seed, symbol.index)) continue;

            delivered += 1;
            _ = try decoder.addSymbol(symbol);
        }

        try std.testing.expect(decoder.isComplete());
        try std.testing.expect(delivered < combo.block_count * 2);
        try std.testing.expectEqualSlices(u8, source, decoder.recoveredBytes().?);
    }
}

test "decoder accepts symbols in a random-ish deterministic order" {
    const allocator = std.testing.allocator;
    const block_count = 24;
    const block_size = 5;
    const seed = 0x7777_cccc_1234_9876;

    const source = try makeSource(allocator, block_count, block_size, seed);
    defer allocator.free(source);

    var encoder = try Encoder.init(source, block_count, block_size, seed);
    var symbols: std.ArrayList(CodedSymbol) = .empty;
    defer {
        for (symbols.items) |*symbol| {
            symbol.deinit(allocator);
        }
        symbols.deinit(allocator);
    }

    var i: usize = 0;
    while (i < block_count + 12) : (i += 1) {
        try symbols.append(allocator, try encoder.next(allocator));
    }

    shuffleSymbols(symbols.items, seed ^ 0xabcdef);

    var decoder = try Decoder.init(allocator, block_count, block_size, seed);
    defer decoder.deinit();

    var delivered: usize = 0;
    for (symbols.items) |symbol| {
        delivered += 1;
        if (try decoder.addSymbol(symbol) == .complete) break;
    }

    try std.testing.expect(decoder.isComplete());
    try std.testing.expect(delivered < block_count * 2);
    try std.testing.expectEqualSlices(u8, source, decoder.recoveredBytes().?);
}

fn shuffleSymbols(symbols: []CodedSymbol, seed: u64) void {
    var rng = SplitMix64.init(seed);
    var i = symbols.len;
    while (i > 1) {
        i -= 1;
        const j = rng.bounded(i + 1);
        const tmp = symbols[i];
        symbols[i] = symbols[j];
        symbols[j] = tmp;
    }
}

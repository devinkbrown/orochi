//! Sliding-window XOR FEC scheduler.
//!
//! This module groups equal-size source symbols into fixed generations of `K`
//! symbols and emits `M` deterministic XOR repair symbols per generation. It is
//! deliberately not a full erasure code: repair symbols are binary parity
//! equations over source symbols. A generation is recoverable only when the
//! currently missing source symbols are covered by enough independent received
//! repair equations. Since only `M` repair equations are emitted, more than `M`
//! missing source symbols in one generation can never be recovered by FEC, and
//! some smaller loss patterns may also be unrecoverable when their binary
//! equation columns are dependent.
//!
//! The file is self-contained and std-only so it can be tested in isolation:
//!
//!     zig test src/substrate/fec_window.zig

const std = @import("std");

const Allocator = std.mem.Allocator;

/// Maximum repair equations per generation.
///
/// The schedule stores a source column as a `u64` bitset. This keeps the module
/// compact while covering normal small FEC windows.
pub const max_repair_symbols = 64;

/// FEC layout and sliding-window bounds.
pub const Config = struct {
    /// Source symbols per generation.
    generation_size: usize,
    /// Repair symbols emitted per generation.
    repair_count: usize,
    /// Bytes in every source and repair symbol.
    symbol_size: usize,
    /// Number of generations retained by the decoder.
    window_generations: usize,

    pub fn validate(self: Config) FecError!void {
        if (self.generation_size == 0) return error.InvalidLayout;
        if (self.repair_count == 0 or self.repair_count > max_repair_symbols) return error.InvalidLayout;
        if (self.symbol_size == 0) return error.InvalidLayout;
        if (self.window_generations == 0) return error.InvalidLayout;
    }
};

pub const FecError = error{
    InvalidLayout,
    InvalidSymbol,
    InconsistentSymbols,
    UnknownGeneration,
};

pub const GenerationStatus = enum {
    /// Some symbols are missing and the current repairs are not enough yet.
    incomplete,
    /// Missing symbols exceed the configured parity budget.
    unrecoverable,
    /// The received repair equations can recover all currently missing symbols.
    repairable,
    /// All source symbols in the generation are present.
    complete,
};

/// A source symbol with an owned payload.
pub const SourceSymbol = struct {
    generation: u64,
    position: usize,
    bytes: []u8,

    pub fn deinit(self: *SourceSymbol, allocator: Allocator) void {
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

/// A deterministic XOR repair symbol with an owned payload.
pub const RepairSymbol = struct {
    generation: u64,
    equation: usize,
    bytes: []u8,

    pub fn deinit(self: *RepairSymbol, allocator: Allocator) void {
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

/// Emits source and repair symbols for contiguous fixed-size source data.
pub const Encoder = struct {
    source: []const u8,
    symbol_count: usize,
    config: Config,

    pub fn init(source: []const u8, symbol_count: usize, config: Config) FecError!Encoder {
        try config.validate();
        if (symbol_count == 0) return error.InvalidLayout;
        if (symbol_count % config.generation_size != 0) return error.InvalidLayout;
        if (source.len != symbol_count * config.symbol_size) return error.InvalidLayout;

        return .{
            .source = source,
            .symbol_count = symbol_count,
            .config = config,
        };
    }

    pub fn generationCount(self: Encoder) usize {
        return self.symbol_count / self.config.generation_size;
    }

    pub fn sourceSymbol(self: Encoder, allocator: Allocator, source_index: usize) (Allocator.Error || FecError)!SourceSymbol {
        if (source_index >= self.symbol_count) return error.InvalidSymbol;

        const bytes = try allocator.dupe(u8, sourceAt(self.source, self.config, source_index));
        errdefer allocator.free(bytes);

        return .{
            .generation = sourceGeneration(self.config, source_index),
            .position = sourcePosition(self.config, source_index),
            .bytes = bytes,
        };
    }

    pub fn repairSymbol(self: Encoder, allocator: Allocator, generation: u64, equation: usize) (Allocator.Error || FecError)!RepairSymbol {
        if (generation >= self.generationCount()) return error.InvalidSymbol;
        if (equation >= self.config.repair_count) return error.InvalidSymbol;

        const bytes = try allocator.alloc(u8, self.config.symbol_size);
        errdefer allocator.free(bytes);
        @memset(bytes, 0);

        const base: usize = @intCast(generation * self.config.generation_size);
        var position: usize = 0;
        while (position < self.config.generation_size) : (position += 1) {
            if (participates(equation, position, self.config.repair_count)) {
                xorInto(bytes, sourceAt(self.source, self.config, base + position));
            }
        }

        return .{
            .generation = generation,
            .equation = equation,
            .bytes = bytes,
        };
    }

    pub fn repairSymbols(self: Encoder, allocator: Allocator, generation: u64) (Allocator.Error || FecError)![]RepairSymbol {
        if (generation >= self.generationCount()) return error.InvalidSymbol;

        var repairs = try allocator.alloc(RepairSymbol, self.config.repair_count);
        errdefer allocator.free(repairs);

        var initialized: usize = 0;
        errdefer {
            for (repairs[0..initialized]) |*repair| {
                repair.deinit(allocator);
            }
        }

        while (initialized < repairs.len) : (initialized += 1) {
            repairs[initialized] = try self.repairSymbol(allocator, generation, initialized);
        }

        return repairs;
    }
};

/// Tracks received symbols inside a sliding generation window and recovers
/// missing sources when the received XOR equations have full rank.
pub const Decoder = struct {
    allocator: Allocator,
    config: Config,
    generations: std.AutoHashMap(u64, GenerationState),
    lowest_generation: u64,

    pub fn init(allocator: Allocator, config: Config) FecError!Decoder {
        try config.validate();
        return .{
            .allocator = allocator,
            .config = config,
            .generations = std.AutoHashMap(u64, GenerationState).init(allocator),
            .lowest_generation = 0,
        };
    }

    pub fn deinit(self: *Decoder) void {
        var it = self.generations.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.generations.deinit();
        self.* = undefined;
    }

    pub fn addSource(self: *Decoder, symbol: SourceSymbol) (Allocator.Error || FecError)!GenerationStatus {
        if (symbol.position >= self.config.generation_size) return error.InvalidSymbol;
        if (symbol.bytes.len != self.config.symbol_size) return error.InvalidSymbol;

        const state = try self.ensureGeneration(symbol.generation);
        if (state.sources[symbol.position]) |existing| {
            if (!std.mem.eql(u8, existing, symbol.bytes)) return error.InconsistentSymbols;
            return try self.status(symbol.generation) orelse error.UnknownGeneration;
        }

        state.sources[symbol.position] = try self.allocator.dupe(u8, symbol.bytes);
        state.present_sources += 1;
        return try self.status(symbol.generation) orelse error.UnknownGeneration;
    }

    pub fn addRepair(self: *Decoder, symbol: RepairSymbol) (Allocator.Error || FecError)!GenerationStatus {
        if (symbol.equation >= self.config.repair_count) return error.InvalidSymbol;
        if (symbol.bytes.len != self.config.symbol_size) return error.InvalidSymbol;

        const state = try self.ensureGeneration(symbol.generation);
        if (state.repairs[symbol.equation]) |existing| {
            if (!std.mem.eql(u8, existing, symbol.bytes)) return error.InconsistentSymbols;
            return try self.status(symbol.generation) orelse error.UnknownGeneration;
        }

        state.repairs[symbol.equation] = try self.allocator.dupe(u8, symbol.bytes);
        state.present_repairs += 1;
        return try self.status(symbol.generation) orelse error.UnknownGeneration;
    }

    pub fn status(self: *const Decoder, generation: u64) (Allocator.Error || FecError)!?GenerationStatus {
        var state = self.generations.get(generation) orelse return null;
        if (state.present_sources == self.config.generation_size) return .complete;

        const missing = self.config.generation_size - state.present_sources;
        if (missing > self.config.repair_count) return .unrecoverable;
        if (state.present_repairs < missing) return .incomplete;
        if (try solveGeneration(self.allocator, self.config, &state, false)) return .repairable;
        return .incomplete;
    }

    pub fn canRepair(self: *const Decoder, generation: u64) (Allocator.Error || FecError)!bool {
        return (try self.status(generation)) == .repairable;
    }

    pub fn recover(self: *Decoder, generation: u64) (Allocator.Error || FecError)!bool {
        const state = self.generations.getPtr(generation) orelse return error.UnknownGeneration;
        if (state.present_sources == self.config.generation_size) return true;
        return solveGeneration(self.allocator, self.config, state, true);
    }

    pub fn source(self: *const Decoder, generation: u64, position: usize) ?[]const u8 {
        if (position >= self.config.generation_size) return null;
        const state = self.generations.get(generation) orelse return null;
        return state.sources[position];
    }

    pub fn containsGeneration(self: *const Decoder, generation: u64) bool {
        return self.generations.contains(generation);
    }

    pub fn activeGenerationCount(self: *const Decoder) usize {
        return self.generations.count();
    }

    fn ensureGeneration(self: *Decoder, generation: u64) (Allocator.Error || FecError)!*GenerationState {
        try self.slideTo(generation);

        if (self.generations.getPtr(generation)) |state| return state;

        var state = try GenerationState.init(self.allocator, self.config);
        errdefer state.deinit(self.allocator);

        try self.generations.put(generation, state);
        return self.generations.getPtr(generation).?;
    }

    fn slideTo(self: *Decoder, generation: u64) Allocator.Error!void {
        const window: u64 = @intCast(self.config.window_generations);
        const new_lowest = if (generation >= window) generation - window + 1 else 0;
        if (new_lowest <= self.lowest_generation) return;

        var expired: std.ArrayList(u64) = .empty;
        defer expired.deinit(self.allocator);

        var it = self.generations.iterator();
        while (it.next()) |entry| {
            if (entry.key_ptr.* < new_lowest) {
                try expired.append(self.allocator, entry.key_ptr.*);
            }
        }

        for (expired.items) |old_generation| {
            if (self.generations.fetchRemove(old_generation)) |entry| {
                var state = entry.value;
                state.deinit(self.allocator);
            }
        }

        self.lowest_generation = new_lowest;
    }
};

const GenerationState = struct {
    sources: []?[]u8,
    repairs: []?[]u8,
    present_sources: usize,
    present_repairs: usize,

    fn init(allocator: Allocator, config: Config) Allocator.Error!GenerationState {
        const sources = try allocator.alloc(?[]u8, config.generation_size);
        errdefer allocator.free(sources);
        @memset(sources, null);

        const repairs = try allocator.alloc(?[]u8, config.repair_count);
        errdefer allocator.free(repairs);
        @memset(repairs, null);

        return .{
            .sources = sources,
            .repairs = repairs,
            .present_sources = 0,
            .present_repairs = 0,
        };
    }

    fn deinit(self: *GenerationState, allocator: Allocator) void {
        for (self.sources) |maybe_source| {
            if (maybe_source) |source| allocator.free(source);
        }
        for (self.repairs) |maybe_repair| {
            if (maybe_repair) |repair| allocator.free(repair);
        }
        allocator.free(self.sources);
        allocator.free(self.repairs);
        self.* = undefined;
    }
};

const Equation = struct {
    coeffs: []bool,
    payload: []u8,

    fn deinit(self: *Equation, allocator: Allocator) void {
        allocator.free(self.coeffs);
        allocator.free(self.payload);
        self.* = undefined;
    }
};

fn solveGeneration(allocator: Allocator, config: Config, state: *GenerationState, write: bool) (Allocator.Error || FecError)!bool {
    if (state.present_sources == config.generation_size) return true;

    var missing: std.ArrayList(usize) = .empty;
    defer missing.deinit(allocator);

    var position: usize = 0;
    while (position < config.generation_size) : (position += 1) {
        if (state.sources[position] == null) {
            try missing.append(allocator, position);
        }
    }

    if (missing.items.len == 0) return true;
    if (missing.items.len > config.repair_count) return false;
    if (state.present_repairs < missing.items.len) return false;

    var equations: std.ArrayList(Equation) = .empty;
    defer {
        for (equations.items) |*equation| {
            equation.deinit(allocator);
        }
        equations.deinit(allocator);
    }

    var repair_index: usize = 0;
    while (repair_index < state.repairs.len) : (repair_index += 1) {
        const repair = state.repairs[repair_index] orelse continue;

        const coeffs = try allocator.alloc(bool, missing.items.len);
        errdefer allocator.free(coeffs);
        @memset(coeffs, false);

        const payload = try allocator.dupe(u8, repair);
        errdefer allocator.free(payload);

        var has_unknown = false;
        for (missing.items, 0..) |missing_position, coeff_index| {
            if (participates(repair_index, missing_position, config.repair_count)) {
                coeffs[coeff_index] = true;
                has_unknown = true;
            }
        }

        position = 0;
        while (position < config.generation_size) : (position += 1) {
            if (state.sources[position]) |source| {
                if (participates(repair_index, position, config.repair_count)) {
                    xorInto(payload, source);
                }
            }
        }

        if (!has_unknown) {
            if (!allZero(payload)) return error.InconsistentSymbols;
            allocator.free(coeffs);
            allocator.free(payload);
            continue;
        }

        try equations.append(allocator, .{ .coeffs = coeffs, .payload = payload });
    }

    if (equations.items.len < missing.items.len) return false;

    const pivot_cols = try allocator.alloc(usize, missing.items.len);
    defer allocator.free(pivot_cols);

    const rank = eliminate(config.symbol_size, equations.items, pivot_cols);
    try checkConsistent(equations.items[rank..]);

    if (rank != missing.items.len) return false;
    if (!write) return true;

    for (pivot_cols[0..rank], 0..) |coeff_index, row_index| {
        const missing_position = missing.items[coeff_index];
        std.debug.assert(state.sources[missing_position] == null);
        state.sources[missing_position] = try allocator.dupe(u8, equations.items[row_index].payload);
        state.present_sources += 1;
    }

    return true;
}

fn eliminate(symbol_size: usize, equations: []Equation, pivot_cols: []usize) usize {
    var rank: usize = 0;
    if (equations.len == 0) return 0;

    const width = equations[0].coeffs.len;
    var column: usize = 0;
    while (column < width and rank < equations.len) : (column += 1) {
        var pivot: ?usize = null;
        var row: usize = rank;
        while (row < equations.len) : (row += 1) {
            if (equations[row].coeffs[column]) {
                pivot = row;
                break;
            }
        }

        const pivot_row = pivot orelse continue;
        swapEquations(equations, rank, pivot_row);

        row = 0;
        while (row < equations.len) : (row += 1) {
            if (row != rank and equations[row].coeffs[column]) {
                xorBools(equations[row].coeffs, equations[rank].coeffs);
                xorInto(equations[row].payload, equations[rank].payload[0..symbol_size]);
            }
        }

        pivot_cols[rank] = column;
        rank += 1;
    }

    return rank;
}

fn checkConsistent(rows: []const Equation) FecError!void {
    for (rows) |row| {
        if (!anyBool(row.coeffs) and !allZero(row.payload)) return error.InconsistentSymbols;
    }
}

fn swapEquations(equations: []Equation, a: usize, b: usize) void {
    if (a == b) return;
    const tmp = equations[a];
    equations[a] = equations[b];
    equations[b] = tmp;
}

fn xorBools(dst: []bool, src: []const bool) void {
    std.debug.assert(dst.len == src.len);
    for (dst, src) |*d, s| {
        d.* = d.* != s;
    }
}

fn anyBool(values: []const bool) bool {
    for (values) |value| {
        if (value) return true;
    }
    return false;
}

fn allZero(bytes: []const u8) bool {
    for (bytes) |byte| {
        if (byte != 0) return false;
    }
    return true;
}

fn xorInto(dst: []u8, src: []const u8) void {
    std.debug.assert(dst.len == src.len);
    for (dst, src) |*d, s| {
        d.* ^= s;
    }
}

fn sourceAt(source: []const u8, config: Config, source_index: usize) []const u8 {
    const start = source_index * config.symbol_size;
    return source[start .. start + config.symbol_size];
}

fn sourceGeneration(config: Config, source_index: usize) u64 {
    return @intCast(source_index / config.generation_size);
}

fn sourcePosition(config: Config, source_index: usize) usize {
    return source_index % config.generation_size;
}

fn participates(equation: usize, position: usize, repair_count: usize) bool {
    const shift: u6 = @intCast(equation);
    return ((columnCode(position, repair_count) >> shift) & 1) == 1;
}

fn columnCode(position: usize, repair_count: usize) u64 {
    if (repair_count >= 63) {
        const mixed = mix64(@as(u64, @intCast(position)) +% 1);
        return if (mixed == 0) 1 else mixed;
    }

    const shift: u6 = @intCast(repair_count);
    const span = (@as(u64, 1) << shift) - 1;
    return (@as(u64, @intCast(position)) % span) + 1;
}

fn mix64(value: u64) u64 {
    var z = value +% 0x9e37_79b9_7f4a_7c15;
    z = (z ^ (z >> 30)) *% 0xbf58_476d_1ce4_e5b9;
    z = (z ^ (z >> 27)) *% 0x94d0_49bb_1331_11eb;
    return z ^ (z >> 31);
}

fn makeSource(allocator: Allocator, symbol_count: usize, symbol_size: usize) Allocator.Error![]u8 {
    const bytes = try allocator.alloc(u8, symbol_count * symbol_size);
    errdefer allocator.free(bytes);

    for (bytes, 0..) |*byte, index| {
        byte.* = @truncate((index * 31 + 17) ^ (index >> 1));
    }

    return bytes;
}

fn addAllBut(decoder: *Decoder, encoder: Encoder, allocator: Allocator, generation: u64, skip_positions: []const usize) !void {
    var position: usize = 0;
    while (position < encoder.config.generation_size) : (position += 1) {
        if (contains(skip_positions, position)) continue;

        const index: usize = @intCast(generation * encoder.config.generation_size + position);
        var source = try encoder.sourceSymbol(allocator, index);
        defer source.deinit(allocator);
        _ = try decoder.addSource(source);
    }
}

fn contains(values: []const usize, needle: usize) bool {
    for (values) |value| {
        if (value == needle) return true;
    }
    return false;
}

test "single-loss recovery per independent parity equation" {
    const allocator = std.testing.allocator;
    const config = Config{
        .generation_size = 4,
        .repair_count = 2,
        .symbol_size = 5,
        .window_generations = 4,
    };

    const source = try makeSource(allocator, 4, config.symbol_size);
    defer allocator.free(source);

    const encoder = try Encoder.init(source, 4, config);
    var decoder = try Decoder.init(allocator, config);
    defer decoder.deinit();

    const lost = [_]usize{ 0, 1 };
    try addAllBut(&decoder, encoder, allocator, 0, &lost);

    var repair0 = try encoder.repairSymbol(allocator, 0, 0);
    defer repair0.deinit(allocator);
    try std.testing.expectEqual(GenerationStatus.incomplete, try decoder.addRepair(repair0));

    var repair1 = try encoder.repairSymbol(allocator, 0, 1);
    defer repair1.deinit(allocator);
    try std.testing.expectEqual(GenerationStatus.repairable, try decoder.addRepair(repair1));

    try std.testing.expect(try decoder.canRepair(0));
    try std.testing.expect(try decoder.recover(0));
    try std.testing.expectEqual(GenerationStatus.complete, (try decoder.status(0)).?);

    var position: usize = 0;
    while (position < config.generation_size) : (position += 1) {
        try std.testing.expectEqualSlices(u8, sourceAt(source, config, position), decoder.source(0, position).?);
    }
}

test "generation completion detection does not require repair symbols" {
    const allocator = std.testing.allocator;
    const config = Config{
        .generation_size = 3,
        .repair_count = 1,
        .symbol_size = 7,
        .window_generations = 2,
    };

    const source = try makeSource(allocator, 3, config.symbol_size);
    defer allocator.free(source);

    const encoder = try Encoder.init(source, 3, config);
    var decoder = try Decoder.init(allocator, config);
    defer decoder.deinit();

    var status: GenerationStatus = .incomplete;
    var index: usize = 0;
    while (index < config.generation_size) : (index += 1) {
        var symbol = try encoder.sourceSymbol(allocator, index);
        defer symbol.deinit(allocator);
        status = try decoder.addSource(symbol);
    }

    try std.testing.expectEqual(GenerationStatus.complete, status);
    try std.testing.expectEqual(GenerationStatus.complete, (try decoder.status(0)).?);
}

test "multi-generation sliding retains only the active window" {
    const allocator = std.testing.allocator;
    const config = Config{
        .generation_size = 3,
        .repair_count = 1,
        .symbol_size = 4,
        .window_generations = 2,
    };

    const source = try makeSource(allocator, 9, config.symbol_size);
    defer allocator.free(source);

    const encoder = try Encoder.init(source, 9, config);
    var decoder = try Decoder.init(allocator, config);
    defer decoder.deinit();

    const none = [_]usize{};
    try addAllBut(&decoder, encoder, allocator, 0, &none);

    const lost_one = [_]usize{1};
    try addAllBut(&decoder, encoder, allocator, 1, &lost_one);
    var repair = try encoder.repairSymbol(allocator, 1, 0);
    defer repair.deinit(allocator);
    try std.testing.expectEqual(GenerationStatus.repairable, try decoder.addRepair(repair));
    try std.testing.expect(try decoder.recover(1));

    try addAllBut(&decoder, encoder, allocator, 2, &none);

    try std.testing.expectEqual(@as(usize, 2), decoder.activeGenerationCount());
    try std.testing.expect(!decoder.containsGeneration(0));
    try std.testing.expect(decoder.containsGeneration(1));
    try std.testing.expect(decoder.containsGeneration(2));
    try std.testing.expectEqual(GenerationStatus.complete, (try decoder.status(1)).?);
    try std.testing.expectEqualSlices(u8, sourceAt(source, config, 4), decoder.source(1, 1).?);
}

test "unrecoverable when losses exceed parity budget" {
    const allocator = std.testing.allocator;
    const config = Config{
        .generation_size = 4,
        .repair_count = 1,
        .symbol_size = 6,
        .window_generations = 2,
    };

    const source = try makeSource(allocator, 4, config.symbol_size);
    defer allocator.free(source);

    const encoder = try Encoder.init(source, 4, config);
    var decoder = try Decoder.init(allocator, config);
    defer decoder.deinit();

    const lost = [_]usize{ 0, 2 };
    try addAllBut(&decoder, encoder, allocator, 0, &lost);

    var repair = try encoder.repairSymbol(allocator, 0, 0);
    defer repair.deinit(allocator);
    try std.testing.expectEqual(GenerationStatus.unrecoverable, try decoder.addRepair(repair));
    try std.testing.expect(!try decoder.canRepair(0));
    try std.testing.expect(!try decoder.recover(0));
}

test "repair symbols are deterministic" {
    const allocator = std.testing.allocator;
    const config = Config{
        .generation_size = 5,
        .repair_count = 3,
        .symbol_size = 8,
        .window_generations = 3,
    };

    const source = try makeSource(allocator, 10, config.symbol_size);
    defer allocator.free(source);

    const left = try Encoder.init(source, 10, config);
    const right = try Encoder.init(source, 10, config);

    var generation: u64 = 0;
    while (generation < left.generationCount()) : (generation += 1) {
        var equation: usize = 0;
        while (equation < config.repair_count) : (equation += 1) {
            var a = try left.repairSymbol(allocator, generation, equation);
            defer a.deinit(allocator);
            var b = try right.repairSymbol(allocator, generation, equation);
            defer b.deinit(allocator);

            try std.testing.expectEqual(a.generation, b.generation);
            try std.testing.expectEqual(a.equation, b.equation);
            try std.testing.expectEqualSlices(u8, a.bytes, b.bytes);
        }
    }
}

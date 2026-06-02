//! Delta-state CRDT families for the LADON mesh substrate.
//!
//! This file is self-contained for orchestrator integration: it defines the
//! local dot and causal context helpers used by the OR-Set and LWW register.
const std = @import("std");

/// A unique event produced by one mesh replica.
pub const Dot = struct {
    replica: u64,
    counter: u64,
};

/// Exact dotted causal context.
///
/// This intentionally stores observed dots exactly instead of compressing to a
/// vector clock. Compaction and HLC integration arrive in `clock.zig`; exact
/// coverage keeps this standalone implementation conservative and lawful.
pub const CausalContext = struct {
    dots: std.AutoHashMap(Dot, void),

    pub fn init(allocator: std.mem.Allocator) CausalContext {
        return .{ .dots = std.AutoHashMap(Dot, void).init(allocator) };
    }

    pub fn deinit(self: *CausalContext) void {
        self.dots.deinit();
    }

    pub fn observe(self: *CausalContext, dot: Dot) !void {
        try self.dots.put(dot, {});
    }

    pub fn dominates(self: CausalContext, dot: Dot) bool {
        return self.dots.contains(dot);
    }

    pub fn merge(self: *CausalContext, other: CausalContext) !void {
        var it = other.dots.iterator();
        while (it.next()) |entry| {
            try self.observe(entry.key_ptr.*);
        }
    }

    pub fn nextDot(self: *CausalContext, replica: u64) !Dot {
        var max_counter: u64 = 0;
        var it = self.dots.iterator();
        while (it.next()) |entry| {
            const dot = entry.key_ptr.*;
            if (dot.replica == replica and dot.counter > max_counter) {
                max_counter = dot.counter;
            }
        }

        const dot = Dot{ .replica = replica, .counter = max_counter + 1 };
        try self.observe(dot);
        return dot;
    }

    pub fn clone(self: CausalContext) !CausalContext {
        var out = CausalContext.init(self.dots.allocator);
        errdefer out.deinit();
        try out.merge(self);
        return out;
    }

    pub fn eql(a: CausalContext, b: CausalContext) bool {
        if (a.dots.count() != b.dots.count()) return false;

        var it = a.dots.iterator();
        while (it.next()) |entry| {
            if (!b.dominates(entry.key_ptr.*)) return false;
        }
        return true;
    }
};

/// Add-wins observed-remove set with delta production.
pub fn OrSet(comptime T: type) type {
    return struct {
        const Self = @This();

        const Entry = struct {
            value: T,
            dots: std.ArrayList(Dot),
        };

        allocator: std.mem.Allocator,
        replica_id: u64,
        entries: std.ArrayList(Entry),
        cc: CausalContext,

        pub fn init(allocator: std.mem.Allocator, replica_id: u64) Self {
            return .{
                .allocator = allocator,
                .replica_id = replica_id,
                .entries = .empty,
                .cc = CausalContext.init(allocator),
            };
        }

        pub fn deinit(self: *Self) void {
            for (self.entries.items) |*entry| {
                entry.dots.deinit(self.allocator);
            }
            self.entries.deinit(self.allocator);
            self.cc.deinit();
        }

        /// Add `value` under this replica and return the compact delta.
        pub fn add(self: *Self, value: T) !Self {
            const dot = try self.cc.nextDot(self.replica_id);
            try self.addDot(value, dot);

            var delta = Self.init(self.allocator, self.replica_id);
            errdefer delta.deinit();
            try delta.cc.observe(dot);
            try delta.addDot(value, dot);
            return delta;
        }

        /// Remove currently observed dots for `value` and return the delta.
        pub fn remove(self: *Self, value: T) !Self {
            var delta = Self.init(self.allocator, self.replica_id);
            errdefer delta.deinit();

            const idx = self.findEntryIndex(value) orelse return delta;
            var removed = self.entries.swapRemove(idx);
            defer removed.dots.deinit(self.allocator);

            for (removed.dots.items) |dot| {
                try self.cc.observe(dot);
                try delta.cc.observe(dot);
            }
            return delta;
        }

        pub fn contains(self: Self, value: T) bool {
            const idx = self.findEntryIndex(value) orelse return false;
            return self.entries.items[idx].dots.items.len != 0;
        }

        /// Join this state with a delta produced by another OR-Set.
        pub fn mergeDelta(self: *Self, delta: Self) !void {
            try self.removeDotsDominatedBy(delta);
            try self.applyAddsNotDominated(delta);
            try self.cc.merge(delta.cc);
        }

        /// Join this state with a full OR-Set state.
        pub fn merge(self: *Self, other: Self) !void {
            try self.mergeDelta(other);
        }

        pub fn clone(self: Self) !Self {
            var out = Self.init(self.allocator, self.replica_id);
            errdefer out.deinit();

            for (self.entries.items) |entry| {
                const dst = try out.ensureEntry(entry.value);
                try dst.dots.appendSlice(out.allocator, entry.dots.items);
            }
            try out.cc.merge(self.cc);
            return out;
        }

        pub fn eql(a: Self, b: Self) bool {
            if (!CausalContext.eql(a.cc, b.cc)) return false;
            if (a.entries.items.len != b.entries.items.len) return false;

            for (a.entries.items) |entry_a| {
                const idx_b = b.findEntryIndex(entry_a.value) orelse return false;
                const entry_b = b.entries.items[idx_b];
                if (!dotListsEql(entry_a.dots.items, entry_b.dots.items)) return false;
            }
            return true;
        }

        fn findEntryIndex(self: Self, value: T) ?usize {
            for (self.entries.items, 0..) |entry, idx| {
                if (std.meta.eql(entry.value, value)) return idx;
            }
            return null;
        }

        fn ensureEntry(self: *Self, value: T) !*Entry {
            if (self.findEntryIndex(value)) |idx| {
                return &self.entries.items[idx];
            }

            var dots = std.ArrayList(Dot).empty;
            errdefer dots.deinit(self.allocator);
            try self.entries.append(self.allocator, .{
                .value = value,
                .dots = dots,
            });
            return &self.entries.items[self.entries.items.len - 1];
        }

        fn addDot(self: *Self, value: T, dot: Dot) !void {
            const entry = try self.ensureEntry(value);
            if (!dotListContains(entry.dots.items, dot)) {
                try entry.dots.append(self.allocator, dot);
            }
        }

        fn hasLiveDot(self: Self, dot: Dot) bool {
            for (self.entries.items) |entry| {
                if (dotListContains(entry.dots.items, dot)) return true;
            }
            return false;
        }

        fn removeDotsDominatedBy(self: *Self, delta: Self) !void {
            var idx: usize = 0;
            while (idx < self.entries.items.len) {
                var entry = &self.entries.items[idx];
                var dot_idx: usize = 0;
                while (dot_idx < entry.dots.items.len) {
                    const dot = entry.dots.items[dot_idx];
                    if (delta.cc.dominates(dot) and !delta.hasLiveDot(dot)) {
                        _ = entry.dots.swapRemove(dot_idx);
                    } else {
                        dot_idx += 1;
                    }
                }

                if (entry.dots.items.len == 0) {
                    var removed = self.entries.swapRemove(idx);
                    removed.dots.deinit(self.allocator);
                } else {
                    idx += 1;
                }
            }
        }

        fn applyAddsNotDominated(self: *Self, delta: Self) !void {
            for (delta.entries.items) |entry| {
                for (entry.dots.items) |dot| {
                    if (!self.cc.dominates(dot)) {
                        try self.addDot(entry.value, dot);
                    }
                }
            }
        }

        fn dotListContains(dots: []const Dot, dot: Dot) bool {
            for (dots) |candidate| {
                if (std.meta.eql(candidate, dot)) return true;
            }
            return false;
        }

        fn dotListsEql(a: []const Dot, b: []const Dot) bool {
            if (a.len != b.len) return false;
            for (a) |dot| {
                if (!dotListContains(b, dot)) return false;
            }
            return true;
        }
    };
}

/// Last-writer-wins register ordered by `(timestamp, replica_id)`.
pub fn LwwRegister(comptime T: type) type {
    return struct {
        const Self = @This();

        value: ?T = null,
        timestamp: u64 = 0,
        replica_id: u64 = 0,

        pub fn init() Self {
            return .{};
        }

        /// Set a value and return the delta register for anti-entropy.
        pub fn set(self: *Self, value: T, timestamp: u64, replica_id: u64) Self {
            const delta = Self{
                .value = value,
                .timestamp = timestamp,
                .replica_id = replica_id,
            };
            self.merge(delta);
            return delta;
        }

        pub fn get(self: Self) ?T {
            return self.value;
        }

        pub fn merge(self: *Self, other: Self) void {
            if (other.value == null) return;
            if (self.value == null or wins(other, self.*)) {
                self.* = other;
            }
        }

        pub fn eql(a: Self, b: Self) bool {
            return a.timestamp == b.timestamp and
                a.replica_id == b.replica_id and
                std.meta.eql(a.value, b.value);
        }

        fn wins(candidate: Self, current: Self) bool {
            return candidate.timestamp > current.timestamp or
                (candidate.timestamp == current.timestamp and
                candidate.replica_id > current.replica_id);
        }
    };
}

test "or-set merge is commutative by example" {
    const Set = OrSet(u64);
    const allocator = std.testing.allocator;

    var a = Set.init(allocator, 1);
    defer a.deinit();
    var b = Set.init(allocator, 2);
    defer b.deinit();

    var da = try a.add(10);
    defer da.deinit();
    var db = try b.add(20);
    defer db.deinit();

    var left = try a.clone();
    defer left.deinit();
    try left.merge(b);

    var right = try b.clone();
    defer right.deinit();
    try right.merge(a);

    try std.testing.expect(left.contains(10));
    try std.testing.expect(left.contains(20));
    try std.testing.expect(Set.eql(left, right));
}

test "or-set merge is associative by example" {
    const Set = OrSet(u64);
    const allocator = std.testing.allocator;

    var a = Set.init(allocator, 1);
    defer a.deinit();
    var b = Set.init(allocator, 2);
    defer b.deinit();
    var c = Set.init(allocator, 3);
    defer c.deinit();

    var da = try a.add(1);
    defer da.deinit();
    var db = try b.add(2);
    defer db.deinit();
    var dc = try c.add(3);
    defer dc.deinit();

    var left = try a.clone();
    defer left.deinit();
    try left.merge(b);
    try left.merge(c);

    var bc = try b.clone();
    defer bc.deinit();
    try bc.merge(c);

    var right = try a.clone();
    defer right.deinit();
    try right.merge(bc);

    try std.testing.expect(Set.eql(left, right));
}

test "or-set merge is idempotent by example" {
    const Set = OrSet(u64);
    const allocator = std.testing.allocator;

    var state = Set.init(allocator, 1);
    defer state.deinit();
    var d1 = try state.add(1);
    defer d1.deinit();
    var d2 = try state.add(2);
    defer d2.deinit();

    var expected = try state.clone();
    defer expected.deinit();
    try state.merge(expected);

    try std.testing.expect(Set.eql(state, expected));
}

test "or-set converges for observed remove and concurrent add in different orders" {
    const Set = OrSet(u64);
    const allocator = std.testing.allocator;

    var a = Set.init(allocator, 1);
    defer a.deinit();
    var b = Set.init(allocator, 2);
    defer b.deinit();

    var add_seen = try a.add(42);
    defer add_seen.deinit();
    try b.mergeDelta(add_seen);

    var remove_seen = try b.remove(42);
    defer remove_seen.deinit();

    var add_concurrent = try a.add(42);
    defer add_concurrent.deinit();

    var left = Set.init(allocator, 9);
    defer left.deinit();
    try left.mergeDelta(add_seen);
    try left.mergeDelta(remove_seen);
    try left.mergeDelta(add_concurrent);

    var right = Set.init(allocator, 9);
    defer right.deinit();
    try right.mergeDelta(add_concurrent);
    try right.mergeDelta(remove_seen);
    try right.mergeDelta(add_seen);

    try std.testing.expect(left.contains(42));
    try std.testing.expect(right.contains(42));
    try std.testing.expect(Set.eql(left, right));
}

test "or-set unobserved remove does not erase concurrent add" {
    const Set = OrSet(u64);
    const allocator = std.testing.allocator;

    var a = Set.init(allocator, 1);
    defer a.deinit();
    var b = Set.init(allocator, 2);
    defer b.deinit();

    var remove_empty = try b.remove(7);
    defer remove_empty.deinit();
    var add = try a.add(7);
    defer add.deinit();

    try a.mergeDelta(remove_empty);
    try b.mergeDelta(remove_empty);
    try b.mergeDelta(add);

    try std.testing.expect(a.contains(7));
    try std.testing.expect(b.contains(7));
}

test "lww register uses timestamp then replica tiebreak" {
    const Reg = LwwRegister(u64);

    var a = Reg.init();
    const older = a.set(1, 10, 1);
    const newer = a.set(2, 20, 1);
    try std.testing.expectEqual(@as(?u64, 2), a.get());

    var b = Reg.init();
    b.merge(newer);
    b.merge(older);
    try std.testing.expectEqual(@as(?u64, 2), b.get());

    const tie_low = Reg{ .value = 3, .timestamp = 30, .replica_id = 2 };
    const tie_high = Reg{ .value = 4, .timestamp = 30, .replica_id = 3 };

    var left = Reg.init();
    left.merge(tie_low);
    left.merge(tie_high);

    var right = Reg.init();
    right.merge(tie_high);
    right.merge(tie_low);

    try std.testing.expectEqual(@as(?u64, 4), left.get());
    try std.testing.expect(Reg.eql(left, right));
}

test "lww register merge obeys semilattice laws by example" {
    const Reg = LwwRegister(u64);

    const x = Reg{ .value = 1, .timestamp = 10, .replica_id = 1 };
    const y = Reg{ .value = 2, .timestamp = 10, .replica_id = 2 };
    const z = Reg{ .value = 3, .timestamp = 20, .replica_id = 1 };

    var comm_left = x;
    comm_left.merge(y);
    var comm_right = y;
    comm_right.merge(x);
    try std.testing.expect(Reg.eql(comm_left, comm_right));

    var assoc_left = x;
    assoc_left.merge(y);
    assoc_left.merge(z);

    var yz = y;
    yz.merge(z);
    var assoc_right = x;
    assoc_right.merge(yz);
    try std.testing.expect(Reg.eql(assoc_left, assoc_right));

    var idem = z;
    idem.merge(z);
    try std.testing.expect(Reg.eql(idem, z));
}

// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

const std = @import("std");

/// A state-based positive/negative counter CRDT.
///
/// Each replica owns two grow-only components:
/// - `positives[replica]` records total increments.
/// - `negatives[replica]` records total decrements.
///
/// Merge is an elementwise maximum over both components, which makes it
/// commutative, idempotent, and associative.
pub const PNCounter = struct {
    allocator: std.mem.Allocator,
    positives: std.StringHashMap(u64),
    negatives: std.StringHashMap(u64),

    pub fn init(allocator: std.mem.Allocator) PNCounter {
        return .{
            .allocator = allocator,
            .positives = std.StringHashMap(u64).init(allocator),
            .negatives = std.StringHashMap(u64).init(allocator),
        };
    }

    pub fn deinit(self: *PNCounter) void {
        freeKeys(self.allocator, &self.positives);
        self.positives.deinit();

        freeKeys(self.allocator, &self.negatives);
        self.negatives.deinit();

        self.* = undefined;
    }

    pub fn inc(self: *PNCounter, replica: []const u8, amount: u64) !void {
        try addToComponent(self.allocator, &self.positives, replica, amount);
    }

    pub fn dec(self: *PNCounter, replica: []const u8, amount: u64) !void {
        try addToComponent(self.allocator, &self.negatives, replica, amount);
    }

    pub fn value(self: *const PNCounter) i128 {
        var total: i128 = 0;

        var positive_values = self.positives.valueIterator();
        while (positive_values.next()) |amount| {
            total += @as(i128, amount.*);
        }

        var negative_values = self.negatives.valueIterator();
        while (negative_values.next()) |amount| {
            total -= @as(i128, amount.*);
        }

        return total;
    }

    pub fn merge(self: *PNCounter, other: *const PNCounter) !void {
        try mergeComponent(self.allocator, &self.positives, &other.positives);
        try mergeComponent(self.allocator, &self.negatives, &other.negatives);
    }

    pub fn clone(self: *const PNCounter, allocator: std.mem.Allocator) !PNCounter {
        var copy = PNCounter.init(allocator);
        errdefer copy.deinit();

        try copy.merge(self);
        return copy;
    }
};

pub const Counter = PNCounter;

fn freeKeys(allocator: std.mem.Allocator, map: *std.StringHashMap(u64)) void {
    var entries = map.iterator();
    while (entries.next()) |entry| {
        allocator.free(entry.key_ptr.*);
    }
}

fn addToComponent(
    allocator: std.mem.Allocator,
    component: *std.StringHashMap(u64),
    replica: []const u8,
    amount: u64,
) !void {
    if (amount == 0) return;

    if (component.getPtr(replica)) |existing| {
        if (std.math.maxInt(u64) - existing.* < amount) return error.CounterOverflow;
        existing.* += amount;
        return;
    }

    const owned_replica = try allocator.dupe(u8, replica);
    errdefer allocator.free(owned_replica);
    try component.putNoClobber(owned_replica, amount);
}

fn mergeComponent(
    allocator: std.mem.Allocator,
    into: *std.StringHashMap(u64),
    from: *const std.StringHashMap(u64),
) !void {
    var entries = from.iterator();
    while (entries.next()) |entry| {
        if (into.getPtr(entry.key_ptr.*)) |existing| {
            existing.* = @max(existing.*, entry.value_ptr.*);
            continue;
        }

        const owned_replica = try allocator.dupe(u8, entry.key_ptr.*);
        errdefer allocator.free(owned_replica);
        try into.putNoClobber(owned_replica, entry.value_ptr.*);
    }
}

fn expectValue(counter: *const PNCounter, expected: i128) !void {
    try std.testing.expectEqual(expected, counter.value());
}

fn expectSameState(left: *const PNCounter, right: *const PNCounter) !void {
    try std.testing.expectEqual(left.value(), right.value());
    try expectSameComponent(&left.positives, &right.positives);
    try expectSameComponent(&left.negatives, &right.negatives);
}

fn expectSameComponent(
    left: *const std.StringHashMap(u64),
    right: *const std.StringHashMap(u64),
) !void {
    try std.testing.expectEqual(left.count(), right.count());

    var entries = left.iterator();
    while (entries.next()) |entry| {
        try std.testing.expectEqual(entry.value_ptr.*, right.get(entry.key_ptr.*).?);
    }
}

fn makeReplicaCounter(allocator: std.mem.Allocator, replica: []const u8, inc_by: u64, dec_by: u64) !PNCounter {
    var counter = PNCounter.init(allocator);
    errdefer counter.deinit();

    try counter.inc(replica, inc_by);
    try counter.dec(replica, dec_by);

    return counter;
}

fn mergeInOrder(
    allocator: std.mem.Allocator,
    counters: []const PNCounter,
    order: []const usize,
) !PNCounter {
    var result = PNCounter.init(allocator);
    errdefer result.deinit();

    for (order) |index| {
        try result.merge(&counters[index]);
    }

    return result;
}

test "inc and dec update signed value" {
    var counter = PNCounter.init(std.testing.allocator);
    defer counter.deinit();

    try expectValue(&counter, 0);

    try counter.inc("replica-a", 10);
    try expectValue(&counter, 10);

    try counter.dec("replica-a", 3);
    try expectValue(&counter, 7);

    try counter.dec("replica-b", 11);
    try expectValue(&counter, -4);

    try counter.inc("replica-a", 5);
    try expectValue(&counter, 1);
}

test "merge takes per-replica maxima" {
    var left = PNCounter.init(std.testing.allocator);
    defer left.deinit();

    var right = PNCounter.init(std.testing.allocator);
    defer right.deinit();

    try left.inc("a", 4);
    try left.inc("b", 2);
    try left.dec("a", 7);
    try left.dec("c", 1);

    try right.inc("a", 9);
    try right.inc("b", 1);
    try right.inc("d", 8);
    try right.dec("a", 3);
    try right.dec("c", 5);

    try left.merge(&right);

    try std.testing.expectEqual(@as(u64, 9), left.positives.get("a").?);
    try std.testing.expectEqual(@as(u64, 2), left.positives.get("b").?);
    try std.testing.expectEqual(@as(u64, 8), left.positives.get("d").?);
    try std.testing.expectEqual(@as(u64, 7), left.negatives.get("a").?);
    try std.testing.expectEqual(@as(u64, 5), left.negatives.get("c").?);
    try expectValue(&left, 7);
}

test "merge is commutative" {
    var a = PNCounter.init(std.testing.allocator);
    defer a.deinit();
    try a.inc("a", 5);
    try a.dec("b", 1);

    var b = PNCounter.init(std.testing.allocator);
    defer b.deinit();
    try b.inc("a", 2);
    try b.inc("c", 9);
    try b.dec("b", 4);

    var ab = try a.clone(std.testing.allocator);
    defer ab.deinit();
    try ab.merge(&b);

    var ba = try b.clone(std.testing.allocator);
    defer ba.deinit();
    try ba.merge(&a);

    try expectSameState(&ab, &ba);
    try expectValue(&ab, 10);
}

test "merge is idempotent" {
    var counter = PNCounter.init(std.testing.allocator);
    defer counter.deinit();
    try counter.inc("a", 12);
    try counter.dec("a", 4);
    try counter.inc("b", 6);

    var once = try counter.clone(std.testing.allocator);
    defer once.deinit();
    try once.merge(&counter);

    var twice = try once.clone(std.testing.allocator);
    defer twice.deinit();
    try twice.merge(&counter);

    try expectSameState(&once, &twice);
    try expectValue(&twice, 14);
}

test "merge is associative" {
    var a = PNCounter.init(std.testing.allocator);
    defer a.deinit();
    try a.inc("a", 2);
    try a.dec("a", 1);

    var b = PNCounter.init(std.testing.allocator);
    defer b.deinit();
    try b.inc("a", 5);
    try b.inc("b", 4);

    var c = PNCounter.init(std.testing.allocator);
    defer c.deinit();
    try c.dec("b", 3);
    try c.inc("c", 8);

    var left = try a.clone(std.testing.allocator);
    defer left.deinit();
    var b_then_c = try b.clone(std.testing.allocator);
    defer b_then_c.deinit();
    try b_then_c.merge(&c);
    try left.merge(&b_then_c);

    var right = try a.clone(std.testing.allocator);
    defer right.deinit();
    try right.merge(&b);
    try right.merge(&c);

    try expectSameState(&left, &right);
    try expectValue(&left, 13);
}

test "concurrent increments on different replicas both count" {
    var a = PNCounter.init(std.testing.allocator);
    defer a.deinit();
    try a.inc("replica-a", 7);

    var b = PNCounter.init(std.testing.allocator);
    defer b.deinit();
    try b.inc("replica-b", 11);

    try a.merge(&b);
    try b.merge(&a);

    try expectValue(&a, 18);
    try expectValue(&b, 18);
    try expectSameState(&a, &b);
}

test "random merge orders converge deterministically" {
    const allocator = std.testing.allocator;
    var counters = [_]PNCounter{
        try makeReplicaCounter(allocator, "a", 4, 1),
        try makeReplicaCounter(allocator, "b", 7, 5),
        try makeReplicaCounter(allocator, "c", 2, 0),
        try makeReplicaCounter(allocator, "a", 9, 3),
        try makeReplicaCounter(allocator, "d", 6, 8),
    };
    defer for (&counters) |*counter| counter.deinit();

    const canonical_order = [_]usize{ 0, 1, 2, 3, 4 };
    var canonical = try mergeInOrder(allocator, &counters, &canonical_order);
    defer canonical.deinit();

    var prng = std.Random.DefaultPrng.init(0x6d697a75636869);
    var random = prng.random();

    var order = canonical_order;
    for (0..64) |_| {
        random.shuffle(usize, &order);

        var merged = try mergeInOrder(allocator, &counters, &order);
        defer merged.deinit();

        try expectSameState(&canonical, &merged);
        try expectValue(&merged, 8);
    }
}

test "replica names are owned by the counter" {
    var counter = PNCounter.init(std.testing.allocator);
    defer counter.deinit();

    var replica = std.ArrayList(u8).empty;
    defer replica.deinit(std.testing.allocator);
    try replica.appendSlice(std.testing.allocator, "temporary");

    try counter.inc(replica.items, 3);
    try counter.dec(replica.items, 1);

    @memset(replica.items, 'x');

    try std.testing.expectEqual(@as(u64, 3), counter.positives.get("temporary").?);
    try std.testing.expectEqual(@as(u64, 1), counter.negatives.get("temporary").?);
    try expectValue(&counter, 2);
}

// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deterministic CRDT property tests for the Goryu dotted state types.
const std = @import("std");

const goryu = @import("goryu.zig");

fn expectStateEqual(comptime State: type, a: State, b: State) !void {
    try std.testing.expect(State.eql(a, b));
}

fn randomValue(random: std.Random) u8 {
    return @intCast(random.uintLessThan(u16, 8));
}

fn randomReplicaIndex(random: std.Random, replica_count: usize) usize {
    return random.uintLessThan(usize, replica_count);
}

fn appendOrSetDelta(
    allocator: std.mem.Allocator,
    comptime Set: type,
    deltas: *std.ArrayList(Set),
    delta: Set,
) !void {
    var owned = delta;
    errdefer owned.deinit();
    try deltas.append(allocator, owned);
}

fn deinitOrSetDeltas(comptime Set: type, allocator: std.mem.Allocator, deltas: *std.ArrayList(Set)) void {
    for (deltas.items) |*delta| {
        delta.deinit();
    }
    deltas.deinit(allocator);
}

fn runRandomOrSetWorkload(
    allocator: std.mem.Allocator,
    comptime Set: type,
    random: std.Random,
    replicas: []Set,
    deltas: *std.ArrayList(Set),
    steps: usize,
) !void {
    var step: usize = 0;
    while (step < steps) : (step += 1) {
        const replica_idx = randomReplicaIndex(random, replicas.len);
        const value = randomValue(random);
        const action = random.uintLessThan(u8, 6);

        if (action <= 2) {
            const delta = try replicas[replica_idx].add(value);
            try appendOrSetDelta(allocator, Set, deltas, delta);
        } else if (action <= 4) {
            const delta = try replicas[replica_idx].remove(value);
            try appendOrSetDelta(allocator, Set, deltas, delta);
        } else if (deltas.items.len != 0) {
            const delta_idx = random.uintLessThan(usize, deltas.items.len);
            const target_idx = randomReplicaIndex(random, replicas.len);
            try replicas[target_idx].mergeDelta(deltas.items[delta_idx]);
        }
    }
}

fn expectOrSetLaws(comptime Set: type, a: Set, b: Set, c: Set) !void {
    var ab = try a.clone();
    defer ab.deinit();
    try ab.merge(b);

    var ba = try b.clone();
    defer ba.deinit();
    try ba.merge(a);
    try expectStateEqual(Set, ab, ba);

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
    try expectStateEqual(Set, left, right);

    var idem = try a.clone();
    defer idem.deinit();
    try idem.merge(a);
    try expectStateEqual(Set, idem, a);
}

fn randomContext(allocator: std.mem.Allocator, random: std.Random, dots: usize) !goryu.CausalContext {
    var context = goryu.CausalContext.init(allocator);
    errdefer context.deinit();

    var idx: usize = 0;
    while (idx < dots) : (idx += 1) {
        try context.observe(.{
            .replica = 1 + random.uintLessThan(u64, 4),
            .counter = 1 + random.uintLessThan(u64, 32),
        });
    }
    return context;
}

fn expectCausalContextLaws(
    a: goryu.CausalContext,
    b: goryu.CausalContext,
    c: goryu.CausalContext,
) !void {
    var ab = try a.clone();
    defer ab.deinit();
    try ab.merge(b);

    var ba = try b.clone();
    defer ba.deinit();
    try ba.merge(a);
    try expectStateEqual(goryu.CausalContext, ab, ba);

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
    try expectStateEqual(goryu.CausalContext, left, right);

    var idem = try a.clone();
    defer idem.deinit();
    try idem.merge(a);
    try expectStateEqual(goryu.CausalContext, idem, a);
}

fn randomRegister(comptime Reg: type, random: std.Random, max_sets: usize) Reg {
    var reg = Reg.init();
    const count = random.uintLessThan(usize, max_sets + 1);

    var idx: usize = 0;
    while (idx < count) : (idx += 1) {
        _ = reg.set(
            random.uintLessThan(u16, 1024),
            random.uintLessThan(u64, 64),
            1 + random.uintLessThan(u64, 3),
        );
    }
    return reg;
}

fn expectRegisterLaws(comptime Reg: type, a: Reg, b: Reg, c: Reg) !void {
    var ab = a;
    ab.merge(b);

    var ba = b;
    ba.merge(a);
    try expectStateEqual(Reg, ab, ba);

    var left = a;
    left.merge(b);
    left.merge(c);

    var bc = b;
    bc.merge(c);

    var right = a;
    right.merge(bc);
    try expectStateEqual(Reg, left, right);

    var idem = a;
    idem.merge(a);
    try expectStateEqual(Reg, idem, a);
}

test "causal context randomized merge laws" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x1357_9bdf_2468_ace0);
    const random = prng.random();

    var iter: usize = 0;
    while (iter < 48) : (iter += 1) {
        var a = try randomContext(allocator, random, 1 + random.uintLessThan(usize, 8));
        defer a.deinit();
        var b = try randomContext(allocator, random, 1 + random.uintLessThan(usize, 8));
        defer b.deinit();
        var c = try randomContext(allocator, random, 1 + random.uintLessThan(usize, 8));
        defer c.deinit();

        try expectCausalContextLaws(a, b, c);
    }
}

test "or-set randomized merge laws across replicas" {
    const Set = goryu.OrSet(u8);
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x41f0_d5aa_99c3_1027);
    const random = prng.random();

    var iter: usize = 0;
    while (iter < 24) : (iter += 1) {
        var replicas = [_]Set{
            Set.init(allocator, 1),
            Set.init(allocator, 2),
            Set.init(allocator, 3),
        };
        defer for (&replicas) |*replica| replica.deinit();

        var deltas: std.ArrayList(Set) = .empty;
        defer deinitOrSetDeltas(Set, allocator, &deltas);

        try runRandomOrSetWorkload(allocator, Set, random, replicas[0..], &deltas, 30);
        try expectOrSetLaws(Set, replicas[0], replicas[1], replicas[2]);
    }
}

test "or-set deltas converge in randomized exchange order" {
    const Set = goryu.OrSet(u8);
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x6d61_7475_7265_5f31);
    const random = prng.random();

    var iter: usize = 0;
    while (iter < 20) : (iter += 1) {
        const replica_count = 2 + random.uintLessThan(usize, 2);
        var replicas = [_]Set{
            Set.init(allocator, 1),
            Set.init(allocator, 2),
            Set.init(allocator, 3),
        };
        defer for (&replicas) |*replica| replica.deinit();

        var deltas: std.ArrayList(Set) = .empty;
        defer deinitOrSetDeltas(Set, allocator, &deltas);

        try runRandomOrSetWorkload(
            allocator,
            Set,
            random,
            replicas[0..replica_count],
            &deltas,
            30,
        );

        var order: [30]usize = undefined;
        for (order[0..deltas.items.len], 0..) |*slot, idx| {
            slot.* = idx;
        }

        for (replicas[0..replica_count]) |*replica| {
            random.shuffle(usize, order[0..deltas.items.len]);
            for (order[0..deltas.items.len]) |delta_idx| {
                try replica.mergeDelta(deltas.items[delta_idx]);
            }
        }

        for (replicas[1..replica_count]) |replica| {
            try expectStateEqual(Set, replicas[0], replica);
        }
    }
}

test "or-set remove only cancels observed adds and re-add after remove wins" {
    const Set = goryu.OrSet(u8);
    const allocator = std.testing.allocator;

    var a = Set.init(allocator, 1);
    defer a.deinit();
    var b = Set.init(allocator, 2);
    defer b.deinit();
    var c = Set.init(allocator, 3);
    defer c.deinit();

    var add_observed = try a.add(7);
    defer add_observed.deinit();
    try b.mergeDelta(add_observed);

    var observed_remove = try b.remove(7);
    defer observed_remove.deinit();
    var readd_after_remove = try b.add(7);
    defer readd_after_remove.deinit();

    var unobserved_remove = try c.remove(3);
    defer unobserved_remove.deinit();
    var concurrent_add = try a.add(3);
    defer concurrent_add.deinit();

    var left = Set.init(allocator, 11);
    defer left.deinit();
    try left.mergeDelta(observed_remove);
    try left.mergeDelta(add_observed);
    try left.mergeDelta(readd_after_remove);
    try left.mergeDelta(unobserved_remove);
    try left.mergeDelta(concurrent_add);

    var right = Set.init(allocator, 12);
    defer right.deinit();
    try right.mergeDelta(concurrent_add);
    try right.mergeDelta(readd_after_remove);
    try right.mergeDelta(add_observed);
    try right.mergeDelta(unobserved_remove);
    try right.mergeDelta(observed_remove);

    try std.testing.expect(left.contains(7));
    try std.testing.expect(right.contains(7));
    try std.testing.expect(left.contains(3));
    try std.testing.expect(right.contains(3));
    try expectStateEqual(Set, left, right);
}

test "lww register randomized merge laws" {
    const Reg = goryu.LwwRegister(u16);
    var prng = std.Random.DefaultPrng.init(0x8945_2301_deaf_beef);
    const random = prng.random();

    var iter: usize = 0;
    while (iter < 64) : (iter += 1) {
        const a = randomRegister(Reg, random, 5);
        const b = randomRegister(Reg, random, 5);
        const c = randomRegister(Reg, random, 5);
        try expectRegisterLaws(Reg, a, b, c);
    }
}

test "lww register deltas converge in randomized exchange order" {
    const Reg = goryu.LwwRegister(u16);
    var prng = std.Random.DefaultPrng.init(0xc011_ab1e_7e57_0001);
    const random = prng.random();

    var iter: usize = 0;
    while (iter < 32) : (iter += 1) {
        var replicas = [_]Reg{ Reg.init(), Reg.init(), Reg.init() };
        var deltas: [20]Reg = undefined;

        for (&deltas) |*delta| {
            const replica_idx = randomReplicaIndex(random, replicas.len);
            delta.* = replicas[replica_idx].set(
                random.uintLessThan(u16, 4096),
                random.uintLessThan(u64, 96),
                @as(u64, replica_idx) + 1,
            );
        }

        var order: [20]usize = undefined;
        for (&order, 0..) |*slot, idx| slot.* = idx;

        for (&replicas) |*replica| {
            random.shuffle(usize, order[0..]);
            for (order) |delta_idx| {
                replica.merge(deltas[delta_idx]);
            }
        }

        try expectStateEqual(Reg, replicas[0], replicas[1]);
        try expectStateEqual(Reg, replicas[0], replicas[2]);
    }
}

test "lww register timestamp then replica tiebreak is deterministic" {
    const Reg = goryu.LwwRegister(u16);

    const newer_low_replica = Reg{ .value = 10, .timestamp = 20, .replica_id = 1 };
    const older_high_replica = Reg{ .value = 99, .timestamp = 19, .replica_id = 3 };

    var timestamp_wins = Reg.init();
    timestamp_wins.merge(older_high_replica);
    timestamp_wins.merge(newer_low_replica);
    try std.testing.expectEqual(@as(?u16, 10), timestamp_wins.get());

    const tie_low_replica = Reg{ .value = 21, .timestamp = 30, .replica_id = 1 };
    const tie_high_replica = Reg{ .value = 22, .timestamp = 30, .replica_id = 2 };

    var left = Reg.init();
    left.merge(tie_low_replica);
    left.merge(tie_high_replica);

    var right = Reg.init();
    right.merge(tie_high_replica);
    right.merge(tie_low_replica);

    try std.testing.expectEqual(@as(?u16, 22), left.get());
    try std.testing.expectEqual(@as(?u16, 22), right.get());
    try expectStateEqual(Reg, left, right);
}

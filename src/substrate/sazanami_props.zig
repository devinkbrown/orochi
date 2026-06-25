// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deterministic property tests for the SAZANAMI membership state machine.
const std = @import("std");
const sazanami = @import("sazanami.zig");

const Config = sazanami.Config;
const Incarnation = sazanami.Incarnation;
const Member = sazanami.Member;
const MemberState = sazanami.MemberState;
const Membership = sazanami.Membership;
const NodeId = sazanami.NodeId;
const Reaped = sazanami.Reaped;

const seed: u64 = 0x5a5a_6e61_6d69_1600;
const self_node: NodeId = 0x5155_4945_54;

fn newTable(cfg: Config) Membership {
    return Membership.init(std.testing.allocator, self_node, cfg);
}

fn expectMember(table: *const Membership, id: NodeId) !Member {
    const member = table.get(id);
    try std.testing.expect(member != null);
    return member.?;
}

fn expectState(table: *const Membership, id: NodeId, state: MemberState) !void {
    try std.testing.expectEqual(state, (try expectMember(table, id)).state);
}

fn addWitnessQuorum(
    table: *Membership,
    target: NodeId,
    incarnation: Incarnation,
    witness_base: NodeId,
    now_ms: i64,
    quorum: u8,
) !void {
    var witness_idx: u8 = 0;
    while (witness_idx < quorum) : (witness_idx += 1) {
        _ = try table.applySuspect(target, incarnation, witness_base + witness_idx, now_ms);
    }
}

fn expectProbeInvariants(table: *const Membership, probe: sazanami.Probe) !void {
    if (!probe.active) {
        try std.testing.expectEqual(@as(u8, 0), probe.indirect_len);
        return;
    }

    const target = try expectMember(table, probe.target);
    try std.testing.expect(target.state == .alive or target.state == .suspect);
    try std.testing.expect(probe.indirect_len <= sazanami.max_tracked_witnesses);

    for (probe.indirectSlice(), 0..) |witness, i| {
        try std.testing.expect(witness != probe.target);
        const member = try expectMember(table, witness);
        try std.testing.expectEqual(MemberState.alive, member.state);

        for (probe.indirectSlice()[0..i]) |earlier| {
            try std.testing.expect(witness != earlier);
        }
    }
}

test "property: missed probes transition alive to suspect to dead no earlier than timeout" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0x01);
    const random = prng.random();

    for (0..128) |iteration| {
        const quorum = 1 + random.uintLessThan(u8, 4);
        const timeout = 1 + random.intRangeAtMost(i64, 0, 4_000);
        const start = random.intRangeAtMost(i64, -2_000, 2_000);
        const target: NodeId = 1000 + @as(NodeId, @intCast(iteration));

        var table = newTable(.{
            .suspicion_timeout_ms = timeout,
            .witness_quorum = quorum,
            .indirect_probe_count = random.int(u8),
        });
        defer table.deinit();

        try std.testing.expect(try table.applyAlive(target, 1));
        try expectState(&table, target, .alive);

        try addWitnessQuorum(&table, target, 1, 20_000 + target, start, quorum);
        try expectState(&table, target, .suspect);
        try std.testing.expectEqual(quorum, (try expectMember(&table, target)).witnessCount());

        var reaped: std.ArrayList(Reaped) = .empty;
        defer reaped.deinit(std.testing.allocator);

        _ = try table.tick(start, random.int(u64), &reaped);
        try expectState(&table, target, .suspect);
        try std.testing.expectEqual(@as(usize, 0), reaped.items.len);

        _ = try table.tick(start + timeout - 1, random.int(u64), &reaped);
        try expectState(&table, target, .suspect);
        try std.testing.expectEqual(@as(usize, 0), reaped.items.len);

        _ = try table.tick(start + timeout, random.int(u64), &reaped);
        try expectState(&table, target, .dead);
        try std.testing.expectEqual(@as(usize, 1), reaped.items.len);
        try std.testing.expectEqual(target, reaped.items[0].id);
        try std.testing.expectEqual(@as(Incarnation, 1), reaped.items[0].incarnation);
    }
}

test "property: higher incarnation alive refutes suspicion" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0x02);
    const random = prng.random();

    for (0..192) |iteration| {
        const target: NodeId = 30_000 + @as(NodeId, @intCast(iteration));
        const incarnation = random.intRangeAtMost(Incarnation, 1, std.math.maxInt(Incarnation) - 2);
        const now_ms = random.intRangeAtMost(i64, -50_000, 50_000);

        var table = newTable(.{ .witness_quorum = 2 });
        defer table.deinit();

        try std.testing.expect(try table.applyAlive(target, incarnation));
        try std.testing.expect(try table.applySuspect(target, incarnation, target + 1, now_ms));
        try expectState(&table, target, .suspect);

        try std.testing.expect(!try table.applyAlive(target, incarnation - 1));
        try expectState(&table, target, .suspect);

        try std.testing.expect(try table.applyAlive(target, incarnation + 1));
        const refuted = try expectMember(&table, target);
        try std.testing.expectEqual(MemberState.alive, refuted.state);
        try std.testing.expectEqual(incarnation + 1, refuted.incarnation);
        try std.testing.expectEqual(@as(i64, 0), refuted.suspect_since_ms);
        try std.testing.expectEqual(@as(u8, 0), refuted.witnessCount());
    }
}

test "property: incarnation comparison and terminal merges are monotonic" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0x03);
    const random = prng.random();

    for (0..192) |iteration| {
        const target: NodeId = 60_000 + @as(NodeId, @intCast(iteration));
        const base_inc = random.intRangeAtMost(Incarnation, 8, std.math.maxInt(Incarnation) - 8);
        const stale_inc = base_inc - random.intRangeAtMost(Incarnation, 1, 7);
        const newer_inc = base_inc + random.intRangeAtMost(Incarnation, 1, 7);

        var table = newTable(.{
            .suspicion_timeout_ms = 1,
            .witness_quorum = 2,
        });
        defer table.deinit();

        try std.testing.expect(try table.applyAlive(target, base_inc));
        try std.testing.expect(!try table.applySuspect(target, stale_inc, 1, 0));
        var member = try expectMember(&table, target);
        try std.testing.expectEqual(MemberState.alive, member.state);
        try std.testing.expectEqual(base_inc, member.incarnation);

        try std.testing.expect(try table.applySuspect(target, base_inc, 2, 10));
        try std.testing.expect(!try table.applyAlive(target, stale_inc));
        member = try expectMember(&table, target);
        try std.testing.expectEqual(MemberState.suspect, member.state);
        try std.testing.expectEqual(base_inc, member.incarnation);

        try std.testing.expect(try table.applyDead(target, base_inc, 3, 10));
        _ = try table.tick(11, random.int(u64), null);
        member = try expectMember(&table, target);
        try std.testing.expectEqual(MemberState.dead, member.state);
        try std.testing.expectEqual(base_inc, member.incarnation);

        try std.testing.expect(!try table.applyAlive(target, stale_inc));
        try std.testing.expect(!try table.applySuspect(target, stale_inc, 4, 12));
        try std.testing.expect(!try table.applyDead(target, stale_inc, 5, 12));
        member = try expectMember(&table, target);
        try std.testing.expectEqual(MemberState.dead, member.state);
        try std.testing.expectEqual(base_inc, member.incarnation);

        try std.testing.expect(try table.applyAlive(target, newer_inc));
        member = try expectMember(&table, target);
        try std.testing.expectEqual(MemberState.alive, member.state);
        try std.testing.expectEqual(newer_inc, member.incarnation);

        try std.testing.expect(try table.applyLeft(target, newer_inc));
        try std.testing.expect(!try table.applyAlive(target, newer_inc));
        try std.testing.expect(!try table.applySuspect(target, newer_inc, 6, 13));
        member = try expectMember(&table, target);
        try std.testing.expectEqual(MemberState.left, member.state);
        try std.testing.expectEqual(newer_inc, member.incarnation);
    }
}

test "property: witness tracking respects fixed maximum without overflow" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0x04);
    const random = prng.random();

    for (0..16) |iteration| {
        const target: NodeId = 90_000 + @as(NodeId, @intCast(iteration));
        const incarnation = random.intRangeAtMost(Incarnation, 1, 1_000_000);

        var table = newTable(.{
            .suspicion_timeout_ms = 10_000,
            .witness_quorum = std.math.maxInt(u8),
        });
        defer table.deinit();

        try std.testing.expect(try table.applyAlive(target, incarnation));

        var i: u16 = 0;
        while (i < sazanami.max_tracked_witnesses + 8) : (i += 1) {
            const witness = 1_000_000 + @as(NodeId, @intCast(i));
            _ = try table.applySuspect(target, incarnation, witness, 0);
            const count = (try expectMember(&table, target)).witnessCount();
            try std.testing.expect(count <= sazanami.max_tracked_witnesses);
            try expectState(&table, target, .suspect);
        }

        try std.testing.expectEqual(
            @as(u8, sazanami.max_tracked_witnesses),
            (try expectMember(&table, target)).witnessCount(),
        );

        i = 0;
        while (i < sazanami.max_tracked_witnesses) : (i += 1) {
            const duplicate = 1_000_000 + @as(NodeId, @intCast(random.uintLessThan(u16, sazanami.max_tracked_witnesses)));
            _ = try table.applyDead(target, incarnation, duplicate, @as(i64, @intCast(i)));
            try std.testing.expectEqual(
                @as(u8, sazanami.max_tracked_witnesses),
                (try expectMember(&table, target)).witnessCount(),
            );
        }
    }
}

test "property: malformed and out-of-range probe inputs stay total over public API" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0x05);
    const random = prng.random();

    const interesting_nodes = [_]NodeId{
        0,
        1,
        self_node,
        std.math.maxInt(NodeId),
        std.math.maxInt(NodeId) - 1,
        0x8000_0000_0000_0000,
    };
    const interesting_incarnations = [_]Incarnation{
        0,
        1,
        2,
        std.math.maxInt(Incarnation) - 2,
        std.math.maxInt(Incarnation) - 1,
    };
    const interesting_times = [_]i64{
        -1_000_000,
        -1,
        0,
        1,
        1_000_000,
        std.math.maxInt(i64) - 1_000_000,
    };

    for (0..256) |iteration| {
        var table = newTable(.{
            .protocol_period_ms = if (iteration % 5 == 0) -1 else random.intRangeAtMost(i64, 1, 10_000),
            .suspicion_timeout_ms = if (iteration % 7 == 0) -1 else random.intRangeAtMost(i64, 0, 10_000),
            .indirect_probe_count = random.int(u8),
            .witness_quorum = if (iteration % 11 == 0) 0 else random.int(u8),
        });
        defer table.deinit();

        const node = interesting_nodes[iteration % interesting_nodes.len] ^ random.int(NodeId);
        const witness = interesting_nodes[(iteration + 1) % interesting_nodes.len] ^ random.int(NodeId);
        const incarnation = interesting_incarnations[iteration % interesting_incarnations.len];
        const now_ms = interesting_times[iteration % interesting_times.len] - @as(i64, @intCast(iteration));

        switch (iteration % 4) {
            0 => _ = try table.applyAlive(node, incarnation),
            1 => _ = try table.applySuspect(node, incarnation, witness, now_ms),
            2 => _ = try table.applyDead(node, incarnation, witness, now_ms),
            else => _ = try table.applyLeft(node, incarnation),
        }

        var fill: usize = 0;
        while (fill < 8) : (fill += 1) {
            const id = 10_000 + @as(NodeId, @intCast(fill));
            _ = try table.applyAlive(id, random.intRangeAtMost(Incarnation, 0, 32));
        }

        const probe = try table.tick(now_ms + random.intRangeAtMost(i64, 0, 256), random.int(u64), null);
        try expectProbeInvariants(&table, probe);
    }
}

test {
    std.testing.refAllDecls(@This());
}

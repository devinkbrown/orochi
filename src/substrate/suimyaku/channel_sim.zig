// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deterministic multi-node convergence simulator for the channel CRDT.
//!
//! The simulator drives `channel_crdt.zig` directly: local operations produce
//! channel deltas, network delivery merges those deltas, and the heal phase
//! replays every recorded delta to every replica as anti-entropy repair.
const std = @import("std");

const channel = @import("channel_crdt.zig");

const Allocator = std.mem.Allocator;
const ChannelCrdt = channel.ChannelCrdt;
const KeyMode = channel.KeyMode;
const LimitMode = channel.LimitMode;
const MemberId = channel.MemberId;
const MemberStatus = channel.MemberStatus;
const ReplicaId = channel.ReplicaId;

pub const default_replica_count: usize = 3;
const max_member_pool = 16;

const member_pool = [_]MemberId{
    100, 101, 102, 103,
    104, 105, 106, 107,
    108, 109, 110, 111,
    112, 113, 114, 115,
};

const key_pool = [_][]const u8{
    "alpha",
    "bravo",
    "charlie",
    "delta",
};

pub const NetworkConfig = struct {
    min_delay_ticks: u64 = 1,
    max_delay_ticks: u64 = 8,
    reorder_probability: f64 = 0.35,
    reorder_extra_ticks: u64 = 12,
    drop_probability: f64 = 0.0,
};

const Replica = struct {
    crdt: ChannelCrdt,

    fn init(allocator: Allocator, replica_id: ReplicaId) Replica {
        return .{ .crdt = ChannelCrdt.init(allocator, replica_id) };
    }

    fn deinit(self: *Replica) void {
        self.crdt.deinit();
    }
};

const StoredDelta = struct {
    origin: usize,
    state: ChannelCrdt,

    fn deinit(self: *StoredDelta) void {
        self.state.deinit();
    }
};

const Event = struct {
    due_tick: u64,
    seq: u64,
    from: usize,
    to: usize,
    delta_idx: usize,
};

const Network = struct {
    allocator: Allocator,
    prng: std.Random.DefaultPrng,
    config: NetworkConfig = .{},
    tick: u64 = 0,
    next_seq: u64 = 0,
    groups: std.ArrayList(u8) = .empty,
    pending: std.ArrayList(Event) = .empty,

    fn init(allocator: Allocator, seed: u64, replica_count: usize) !Network {
        var network = Network{
            .allocator = allocator,
            .prng = std.Random.DefaultPrng.init(seed),
        };
        errdefer network.deinit();

        var idx: usize = 0;
        while (idx < replica_count) : (idx += 1) {
            try network.groups.append(allocator, 0);
        }
        return network;
    }

    fn deinit(self: *Network) void {
        self.pending.deinit(self.allocator);
        self.groups.deinit(self.allocator);
    }

    fn schedule(self: *Network, from: usize, to: usize, delta_idx: usize) !void {
        const random = self.prng.random();
        if (random.float(f64) < self.config.drop_probability) return;

        const span = if (self.config.max_delay_ticks > self.config.min_delay_ticks)
            self.config.max_delay_ticks - self.config.min_delay_ticks + 1
        else
            1;

        var delay = self.config.min_delay_ticks + random.uintLessThan(u64, span);
        if (random.float(f64) < self.config.reorder_probability) {
            delay += 1 + random.uintLessThan(u64, @max(@as(u64, 1), self.config.reorder_extra_ticks));
        }

        const seq = self.next_seq;
        self.next_seq += 1;
        try self.pending.append(self.allocator, .{
            .due_tick = self.tick + delay,
            .seq = seq,
            .from = from,
            .to = to,
            .delta_idx = delta_idx,
        });
    }

    fn partitionTwoWay(self: *Network) void {
        const split = @max(@as(usize, 1), self.groups.items.len / 2);
        for (self.groups.items, 0..) |*group, idx| {
            group.* = if (idx < split) 1 else 2;
        }
    }

    fn heal(self: *Network) void {
        @memset(self.groups.items, 0);
    }

    fn popDeliverable(self: *Network) ?Event {
        var best_idx: ?usize = null;
        for (self.pending.items, 0..) |event, idx| {
            if (!self.canDeliver(event.from, event.to)) continue;
            if (best_idx) |best| {
                if (eventBefore(event, self.pending.items[best])) best_idx = idx;
            } else {
                best_idx = idx;
            }
        }

        const idx = best_idx orelse return null;
        const event = self.pending.swapRemove(idx);
        if (event.due_tick > self.tick) self.tick = event.due_tick;
        return event;
    }

    fn canDeliver(self: *const Network, from: usize, to: usize) bool {
        const from_group = self.groups.items[from];
        const to_group = self.groups.items[to];
        return from_group == 0 or to_group == 0 or from_group == to_group;
    }
};

fn eventBefore(a: Event, b: Event) bool {
    if (a.due_tick != b.due_tick) return a.due_tick < b.due_tick;
    return a.seq < b.seq;
}

pub const Sim = struct {
    allocator: Allocator,
    seed: u64,
    prng: std.Random.DefaultPrng,
    replicas: std.ArrayList(Replica) = .empty,
    deltas: std.ArrayList(StoredDelta) = .empty,
    network: Network,
    physical_ms: u64 = 1_000,

    pub fn init(allocator: Allocator, seed: u64, replica_count: usize) !Sim {
        const count = if (replica_count == 0) default_replica_count else replica_count;
        if (count > std.math.maxInt(ReplicaId)) return error.ReplicaCountOutOfRange;

        var sim = Sim{
            .allocator = allocator,
            .seed = seed,
            .prng = std.Random.DefaultPrng.init(seed),
            .network = try Network.init(allocator, deriveSeed(seed, 0xfeed), count),
        };
        errdefer sim.deinit();

        var idx: usize = 0;
        while (idx < count) : (idx += 1) {
            try sim.replicas.append(allocator, Replica.init(allocator, @intCast(idx + 1)));
        }
        return sim;
    }

    pub fn deinit(self: *Sim) void {
        for (self.deltas.items) |*delta| delta.deinit();
        self.deltas.deinit(self.allocator);
        for (self.replicas.items) |*replica| replica.deinit();
        self.replicas.deinit(self.allocator);
        self.network.deinit();
    }

    pub fn setNetworkConfig(self: *Sim, config: NetworkConfig) void {
        self.network.config = config;
    }

    pub fn randomChurn(self: *Sim, steps: usize) !void {
        var step: usize = 0;
        while (step < steps) : (step += 1) {
            const replica_idx = self.randomReplicaIndex();
            try self.applyRandomLocalOp(replica_idx);
            try self.runNetwork(self.prng.random().uintLessThan(usize, 5));
        }
    }

    pub fn partitionTwoWay(self: *Sim) void {
        self.network.partitionTwoWay();
    }

    pub fn healAndExchange(self: *Sim) !void {
        self.network.heal();
        try self.flushNetwork();
        try self.fullDeltaExchange();
    }

    pub fn expectObservableConverged(self: *const Sim) !void {
        if (self.replicas.items.len <= 1) return;

        var first = try observableBytes(self.allocator, &self.replicas.items[0].crdt);
        defer first.deinit(self.allocator);

        for (self.replicas.items[1..], 1..) |*replica, idx| {
            var next = try observableBytes(self.allocator, &replica.crdt);
            defer next.deinit(self.allocator);
            if (!std.mem.eql(u8, first.items, next.items)) {
                std.debug.print("channel sim divergence seed=0x{x} replica={d}\n", .{ self.seed, idx });
                return error.DidNotConverge;
            }
        }
    }

    fn applyRandomLocalOp(self: *Sim, replica_idx: usize) !void {
        const random = self.prng.random();
        const member = member_pool[random.uintLessThan(usize, max_member_pool)];
        const physical = self.nextPhysicalMs();

        switch (random.uintLessThan(u8, 9)) {
            0, 1, 2, 3 => {
                const bits: u4 = @intCast(1 + random.uintLessThan(u8, 15));
                try self.localJoin(replica_idx, member, MemberStatus.init(bits), physical);
            },
            4, 5 => try self.localPart(replica_idx, member),
            6 => try self.localSetMode(replica_idx, .{ .invite_only = random.boolean() }, physical),
            7 => try self.localSetMode(replica_idx, .{
                .limit = if (random.boolean())
                    LimitMode.set(1 + random.uintLessThan(u32, 200))
                else
                    LimitMode.none(),
            }, physical),
            8 => {
                const key = if (random.boolean())
                    try KeyMode.init(key_pool[random.uintLessThan(usize, key_pool.len)])
                else
                    KeyMode.none();
                try self.localSetMode(replica_idx, .{ .key = key }, physical);
            },
            else => unreachable,
        }
    }

    fn localJoin(self: *Sim, replica_idx: usize, member_id: MemberId, status: MemberStatus, physical_ms: u64) !void {
        var delta = try self.replicas.items[replica_idx].crdt.localJoin(member_id, status, physical_ms);
        try self.publishDelta(replica_idx, &delta);
    }

    fn localPart(self: *Sim, replica_idx: usize, member_id: MemberId) !void {
        var delta = try self.replicas.items[replica_idx].crdt.localPart(member_id);
        try self.publishDelta(replica_idx, &delta);
    }

    fn localSetMode(self: *Sim, replica_idx: usize, update: channel.ModeUpdate, physical_ms: u64) !void {
        var delta = try self.replicas.items[replica_idx].crdt.localSetMode(update, physical_ms);
        try self.publishDelta(replica_idx, &delta);
    }

    fn publishDelta(self: *Sim, origin: usize, delta: *ChannelCrdt) !void {
        var moved = false;
        errdefer if (!moved) delta.deinit();

        const delta_idx = self.deltas.items.len;
        try self.deltas.append(self.allocator, .{
            .origin = origin,
            .state = delta.*,
        });
        moved = true;

        for (self.replicas.items, 0..) |_, to| {
            if (to == origin) continue;
            try self.network.schedule(origin, to, delta_idx);
        }
    }

    fn runNetwork(self: *Sim, max_deliveries: usize) !void {
        var delivered: usize = 0;
        while (delivered < max_deliveries) : (delivered += 1) {
            const event = self.network.popDeliverable() orelse return;
            try self.applyEvent(event);
        }
    }

    fn flushNetwork(self: *Sim) !void {
        while (self.network.pending.items.len != 0) {
            const event = self.network.popDeliverable() orelse return error.BlockedDelivery;
            try self.applyEvent(event);
        }
    }

    fn applyEvent(self: *Sim, event: Event) !void {
        if (event.delta_idx >= self.deltas.items.len) return error.InvalidDelta;
        if (event.to >= self.replicas.items.len) return error.InvalidReplica;
        try self.replicas.items[event.to].crdt.merge(&self.deltas.items[event.delta_idx].state);
    }

    fn fullDeltaExchange(self: *Sim) !void {
        var order: std.ArrayList(usize) = .empty;
        defer order.deinit(self.allocator);

        var idx: usize = 0;
        while (idx < self.deltas.items.len) : (idx += 1) {
            try order.append(self.allocator, idx);
        }

        self.prng.random().shuffle(usize, order.items);
        for (order.items) |delta_idx| {
            for (self.replicas.items) |*replica| {
                try replica.crdt.merge(&self.deltas.items[delta_idx].state);
            }
        }
    }

    fn randomReplicaIndex(self: *Sim) usize {
        return self.prng.random().uintLessThan(usize, self.replicas.items.len);
    }

    fn nextPhysicalMs(self: *Sim) u64 {
        self.physical_ms += 1;
        return self.physical_ms;
    }
};

fn observableBytes(allocator: Allocator, crdt: *const ChannelCrdt) !std.ArrayList(u8) {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    for (member_pool) |member_id| {
        if (crdt.memberStatus(member_id)) |status| {
            try out.append(allocator, 1);
            try out.append(allocator, status.bits());
        } else {
            try out.append(allocator, 0);
            try out.append(allocator, 0);
        }
    }

    try appendBoolMode(allocator, &out, crdt.modes.invite_only.get());
    try appendBoolMode(allocator, &out, crdt.modes.moderated.get());
    try appendBoolMode(allocator, &out, crdt.modes.no_external.get());
    try appendBoolMode(allocator, &out, crdt.modes.topic_protected.get());
    try appendBoolMode(allocator, &out, crdt.modes.secret.get());
    try appendLimitMode(allocator, &out, crdt.modes.limit.get());
    try appendKeyMode(allocator, &out, crdt.modes.key.get());
    return out;
}

fn appendBoolMode(allocator: Allocator, out: *std.ArrayList(u8), value: ?bool) !void {
    try out.append(allocator, if (value orelse false) 1 else 0);
}

fn appendLimitMode(allocator: Allocator, out: *std.ArrayList(u8), value: ?LimitMode) !void {
    const limit = value orelse LimitMode.none();
    try out.append(allocator, if (limit.present) 1 else 0);
    appendU32(allocator, out, if (limit.present) limit.value else 0) catch |err| return err;
}

fn appendKeyMode(allocator: Allocator, out: *std.ArrayList(u8), value: ?KeyMode) !void {
    const key = value orelse KeyMode.none();
    if (!key.present) {
        try out.append(allocator, 0);
        try out.append(allocator, 0);
        return;
    }

    try out.append(allocator, 1);
    try out.append(allocator, key.len);
    try out.appendSlice(allocator, key.asSlice());
}

fn appendU32(allocator: Allocator, out: *std.ArrayList(u8), value: u32) !void {
    try out.append(allocator, @intCast(value & 0xff));
    try out.append(allocator, @intCast((value >> 8) & 0xff));
    try out.append(allocator, @intCast((value >> 16) & 0xff));
    try out.append(allocator, @intCast((value >> 24) & 0xff));
}

fn deriveSeed(seed: u64, salt: u64) u64 {
    var z = seed +% salt +% 0x9e37_79b9_7f4a_7c15;
    z = (z ^ (z >> 30)) *% 0xbf58_476d_1ce4_e5b9;
    z = (z ^ (z >> 27)) *% 0x94d0_49bb_1331_11eb;
    return z ^ (z >> 31);
}

fn runRandomChurnCampaign(allocator: Allocator, seed: u64, steps: usize) !void {
    var sim = try Sim.init(allocator, seed, default_replica_count);
    defer sim.deinit();
    sim.setNetworkConfig(.{
        .min_delay_ticks = 1,
        .max_delay_ticks = 10,
        .reorder_probability = 0.65,
        .reorder_extra_ticks = 20,
    });
    try sim.randomChurn(steps);
    try sim.healAndExchange();
    try sim.expectObservableConverged();
}

test "random churn converges under reordered delivery" {
    try runRandomChurnCampaign(std.testing.allocator, 0x4348_5552_4e5f_3031, 128);
}

test "clean two-way partition heals after independent channel ops" {
    const allocator = std.testing.allocator;
    var sim = try Sim.init(allocator, 0x5041_5254_4954_494f, 4);
    defer sim.deinit();

    try sim.localJoin(0, 100, .{ .voice = true }, 10);
    try sim.localJoin(1, 101, .{ .op = true }, 11);
    try sim.healAndExchange();

    sim.partitionTwoWay();
    try sim.localPart(0, 101);
    try sim.localJoin(1, 102, .{ .owner = true }, 20);
    try sim.localSetMode(0, .{ .secret = true }, 21);
    try sim.localSetMode(2, .{ .limit = LimitMode.set(42) }, 22);
    try sim.localJoin(3, 103, .{ .voice = true }, 23);
    try sim.localSetMode(3, .{ .key = try KeyMode.init("partition") }, 24);
    try sim.runNetwork(16);

    try sim.healAndExchange();
    try sim.expectObservableConverged();
    try std.testing.expect(sim.replicas.items[0].crdt.containsMember(100));
    try std.testing.expect(sim.replicas.items[0].crdt.containsMember(102));
    try std.testing.expect(sim.replicas.items[0].crdt.containsMember(103));
    try std.testing.expectEqual(@as(u32, 42), sim.replicas.items[0].crdt.modes.limit.get().?.value);
}

test "concurrent contradictory ops converge with add-wins and LWW tie-break" {
    const allocator = std.testing.allocator;
    var sim = try Sim.init(allocator, 0x434f_4e54_5241_4449, default_replica_count);
    defer sim.deinit();

    try sim.localJoin(0, 104, .{ .voice = true }, 100);
    try sim.healAndExchange();

    sim.partitionTwoWay();
    try sim.localPart(0, 104);
    try sim.localJoin(1, 104, .{ .op = true }, 200);
    try sim.localSetMode(0, .{ .limit = LimitMode.set(10) }, 300);
    try sim.localSetMode(1, .{ .limit = LimitMode.set(20) }, 300);

    try sim.healAndExchange();
    try sim.expectObservableConverged();

    for (sim.replicas.items) |*replica| {
        try std.testing.expect(replica.crdt.containsMember(104));
        try std.testing.expectEqual(@as(u4, 0b0010), replica.crdt.memberStatus(104).?.bits());
        const limit = replica.crdt.modes.limit.get().?;
        try std.testing.expect(limit.present);
        try std.testing.expectEqual(@as(u32, 20), limit.value);
    }
}

test "multi-seed channel simulator loop converges" {
    const allocator = std.testing.allocator;
    var idx: u64 = 0;
    while (idx < 64) : (idx += 1) {
        try runRandomChurnCampaign(allocator, deriveSeed(0x4d55_4c54_495f_5345, idx), 96);
    }
}

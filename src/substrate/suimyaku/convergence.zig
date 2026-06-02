//! Deterministic multi-node convergence harness for the Suimyaku CRDT mesh.
//!
//! The harness deliberately keeps I/O, wall time, and sockets out of the loop:
//! one master seed drives node clocks, node PRNGs, random workload selection,
//! network delay/drop/reorder, partitions, and anti-entropy replay.
const std = @import("std");

const anti_entropy = @import("anti_entropy.zig");
const clock = @import("clock.zig");
const state_mod = @import("state.zig");

const Allocator = std.mem.Allocator;
const Hlc = clock.Hlc;
const NetworkState = state_mod.NetworkState;

const NodeHandle = struct {
    id: u32,
};

const Delivery = struct {
    from: NodeHandle,
    to: NodeHandle,
    payload: u64,
};

const LinkConfig = struct {
    latency_ms: i64 = 1,
    jitter_ms: i64 = 0,
    drop_probability: f64 = 0.0,
    reorder_probability: f64 = 0.0,
    reorder_extra_ms: i64 = 0,
};

const LinkKey = struct {
    from: u32,
    to: u32,
};

const NetworkEvent = struct {
    due_ms: i64,
    seq: u64,
    from: NodeHandle,
    to: NodeHandle,
    payload: u64,
};

fn compareNetworkEvents(_: void, a: NetworkEvent, b: NetworkEvent) std.math.Order {
    const due_order = std.math.order(a.due_ms, b.due_ms);
    if (due_order != .eq) return due_order;
    return std.math.order(a.seq, b.seq);
}

const NetworkQueue = std.PriorityQueue(NetworkEvent, void, compareNetworkEvents);

const Network = struct {
    allocator: Allocator,
    clock_ms: i64 = 0,
    next_seq: u64 = 0,
    prng: std.Random.Pcg,
    events: NetworkQueue,
    partitioned: std.ArrayList(bool) = .empty,
    links: std.AutoHashMap(LinkKey, LinkConfig),
    delivery_log: std.ArrayList(Delivery) = .empty,

    fn init(allocator: Allocator, seed: u64) Network {
        return .{
            .allocator = allocator,
            .prng = std.Random.Pcg.init(seed),
            .events = NetworkQueue.initContext({}),
            .links = std.AutoHashMap(LinkKey, LinkConfig).init(allocator),
        };
    }

    fn deinit(self: *Network) void {
        self.delivery_log.deinit(self.allocator);
        self.links.deinit();
        self.partitioned.deinit(self.allocator);
        self.events.deinit(self.allocator);
        self.* = undefined;
    }

    fn registerNodes(self: *Network, count: usize) !void {
        var i: usize = 0;
        while (i < count) : (i += 1) {
            try self.partitioned.append(self.allocator, false);
        }
    }

    fn setLinkConfig(self: *Network, from: NodeHandle, to: NodeHandle, config: LinkConfig) !void {
        try self.links.put(.{ .from = from.id, .to = to.id }, config);
    }

    fn send(self: *Network, from: NodeHandle, to: NodeHandle, payload: u64) !void {
        const config = self.links.get(.{ .from = from.id, .to = to.id }) orelse LinkConfig{};
        const random = self.prng.random();
        if (random.float(f64) < config.drop_probability) return;

        var delay_ms = config.latency_ms;
        if (config.jitter_ms > 0) {
            delay_ms += random.intRangeAtMost(i64, 0, config.jitter_ms);
        }
        if (config.reorder_probability > 0 and random.float(f64) < config.reorder_probability) {
            const extra = if (config.reorder_extra_ms > 0) config.reorder_extra_ms else config.latency_ms;
            if (extra > 0) delay_ms += random.intRangeAtMost(i64, 1, extra);
        }

        const seq = self.next_seq;
        self.next_seq += 1;
        try self.events.push(self.allocator, .{
            .due_ms = self.clock_ms + delay_ms,
            .seq = seq,
            .from = from,
            .to = to,
            .payload = payload,
        });
    }

    fn partition(self: *Network, set: []const NodeHandle) void {
        @memset(self.partitioned.items, false);
        for (set) |node| self.partitioned.items[node.id] = true;
    }

    fn heal(self: *Network) void {
        @memset(self.partitioned.items, false);
    }

    fn run(self: *Network, max_ticks: usize) !usize {
        var ticks: usize = 0;
        while (ticks < max_ticks) : (ticks += 1) {
            const event = self.events.pop() orelse return ticks;
            if (event.due_ms > self.clock_ms) self.clock_ms = event.due_ms;
            if (self.partitioned.items[event.from.id] == self.partitioned.items[event.to.id]) {
                try self.delivery_log.append(self.allocator, .{
                    .from = event.from,
                    .to = event.to,
                    .payload = event.payload,
                });
            }
        }
        return ticks;
    }

    fn deliveries(self: *const Network) []const Delivery {
        return self.delivery_log.items;
    }
};

const uid_pool = [_][]const u8{
    "001ALPHA",
    "002BRAVO",
    "003CHARLIE",
    "004DELTA",
    "005ECHO",
    "006FOXTROT",
};

const nick_pool = [_][]const u8{
    "alice",
    "bob",
    "carol",
    "dave",
    "erin",
    "frank",
};

const channel_pool = [_][]const u8{
    "#ops",
    "#dev",
    "#mesh",
    "#zig",
};

const mask_pool = [_][]const u8{
    "*!*@a.test",
    "*!*@b.test",
    "*!*@c.test",
    "*!*@d.test",
};

const topic_pool = [_][]const u8{
    "mesh-green",
    "mesh-blue",
    "mesh-red",
    "mesh-gold",
};

const Node = struct {
    handle: NodeHandle,
    state: NetworkState,
    hlc: Hlc = .{},
    prng: std.Random.Pcg,

    fn init(allocator: Allocator, handle: NodeHandle, master_seed: u64) Node {
        const replica_id = @as(u64, handle.id) + 1;
        const node_id = 1000 + replica_id;
        return .{
            .handle = handle,
            .state = NetworkState.init(allocator, replica_id, node_id),
            .prng = std.Random.Pcg.init(deriveSeed(master_seed, replica_id)),
        };
    }

    fn deinit(self: *Node) void {
        self.state.deinit();
        self.* = undefined;
    }
};

const Delta = struct {
    from: u32,
    hlc: Hlc,
    state: NetworkState,

    fn deinit(self: *Delta) void {
        self.state.deinit();
        self.* = undefined;
    }
};

/// Seed-replayable CRDT mesh simulator.
pub const Mesh = struct {
    allocator: Allocator,
    seed: u64,
    network: Network,
    prng: std.Random.Pcg,
    nodes: std.ArrayList(Node) = .empty,
    deltas: std.ArrayList(Delta) = .empty,
    processed_deliveries: usize = 0,
    logical_ms: u64 = 0,

    pub fn init(allocator: Allocator, seed: u64, node_count: usize) !Mesh {
        var mesh = Mesh{
            .allocator = allocator,
            .seed = seed,
            .network = Network.init(allocator, deriveSeed(seed, 0x51d)),
            .prng = std.Random.Pcg.init(deriveSeed(seed, 0xa11ce)),
        };
        errdefer mesh.deinit();

        try mesh.network.registerNodes(node_count);
        var i: usize = 0;
        while (i < node_count) : (i += 1) {
            const handle = NodeHandle{ .id = @intCast(i) };
            try mesh.nodes.append(allocator, Node.init(allocator, handle, seed));
        }

        try mesh.configureLinks();
        return mesh;
    }

    pub fn deinit(self: *Mesh) void {
        for (self.deltas.items) |*delta| delta.deinit();
        self.deltas.deinit(self.allocator);
        for (self.nodes.items) |*node| node.deinit();
        self.nodes.deinit(self.allocator);
        self.network.deinit();
        self.* = undefined;
    }

    pub fn runRandomWorkload(self: *Mesh, steps: usize) !void {
        var step: usize = 0;
        while (step < steps) : (step += 1) {
            const node_idx = self.randomNodeIndex();
            try self.applyRandomOperation(node_idx);
            try self.broadcastSnapshot(node_idx);
            _ = try self.network.run(self.randomSmallTicks());
            try self.drainNetwork();
        }
    }

    pub fn partitionFirstHalf(self: *Mesh) !void {
        var handles: [16]NodeHandle = undefined;
        const count = @min(handles.len, @max(@as(usize, 1), self.nodes.items.len / 2));
        var i: usize = 0;
        while (i < count) : (i += 1) handles[i] = self.nodes.items[i].handle;
        self.network.partition(handles[0..count]);
    }

    pub fn heal(self: *Mesh) void {
        self.network.heal();
    }

    pub fn reconcile(self: *Mesh) !void {
        _ = try self.network.run(100_000);
        try self.drainNetwork();

        try self.replayAllDeltas();
        try self.replayAllDeltas();

        var rounds: usize = 0;
        while (rounds < 16) : (rounds += 1) {
            if (self.allEqual()) return;
            try self.fullStateRepairRound();
        }
    }

    pub fn expectConverged(self: *Mesh) !void {
        if (self.nodes.items.len == 0) return;
        const first = &self.nodes.items[0].state;
        for (self.nodes.items[1..]) |*node| {
            if (!NetworkState.eql(first, &node.state)) {
                std.debug.print("Suimyaku convergence mismatch seed=0x{x}\n", .{self.seed});
                return error.DidNotConverge;
            }
        }
    }

    fn configureLinks(self: *Mesh) !void {
        for (self.nodes.items) |from| {
            for (self.nodes.items) |to| {
                if (from.handle.id == to.handle.id) continue;
                const r = self.prng.random();
                try self.network.setLinkConfig(from.handle, to.handle, .{
                    .latency_ms = r.intRangeAtMost(i64, 1, 8),
                    .jitter_ms = r.intRangeAtMost(i64, 0, 6),
                    .drop_probability = 0.12,
                    .reorder_probability = 0.35,
                    .reorder_extra_ms = 12,
                });
            }
        }
    }

    fn randomNodeIndex(self: *Mesh) usize {
        return self.prng.random().intRangeLessThan(usize, 0, self.nodes.items.len);
    }

    fn randomSmallTicks(self: *Mesh) usize {
        return self.prng.random().intRangeAtMost(usize, 0, 4);
    }

    fn nextHlc(self: *Mesh, node_idx: usize) !Hlc {
        self.logical_ms += 1;
        return self.nodes.items[node_idx].hlc.now(self.logical_ms);
    }

    fn applyRandomOperation(self: *Mesh, node_idx: usize) !void {
        const node = &self.nodes.items[node_idx];
        const r = node.prng.random();
        switch (r.intRangeLessThan(u8, 0, 6)) {
            0 => try self.opNickClaim(node_idx),
            1 => try self.opJoin(node_idx),
            2 => try self.opPart(node_idx),
            3 => try self.opTopic(node_idx),
            4 => try self.opBan(node_idx),
            5 => try self.opPrefixGrant(node_idx),
            else => unreachable,
        }
    }

    fn opNickClaim(self: *Mesh, node_idx: usize) !void {
        const node = &self.nodes.items[node_idx];
        const r = node.prng.random();
        const uid = try state_mod.Uid.init(pick(&uid_pool, r));
        const nick = try state_mod.Nick.init(pick(&nick_pool, r));
        const hlc = try self.nextHlc(node_idx);
        const authority: state_mod.Authority = @intCast(10 + r.intRangeLessThan(u16, 0, 5));
        try node.state.upsertUser(uid, .{
            .nick = nick,
            .realname = try state_mod.ShortText.init("mesh user"),
        }, hlc, authority);
        try node.state.claimNick(nick, uid, authority, hlc);
    }

    fn opJoin(self: *Mesh, node_idx: usize) !void {
        const node = &self.nodes.items[node_idx];
        const r = node.prng.random();
        const uid = try state_mod.Uid.init(pick(&uid_pool, r));
        const chan = try state_mod.ChannelName.init(pick(&channel_pool, r));
        const hlc = try self.nextHlc(node_idx);
        try node.state.createChannel(chan, hlc, 10);
        try node.state.join(chan, uid, 1);
    }

    fn opPart(self: *Mesh, node_idx: usize) !void {
        const node = &self.nodes.items[node_idx];
        const r = node.prng.random();
        const uid = try state_mod.Uid.init(pick(&uid_pool, r));
        const chan = try state_mod.ChannelName.init(pick(&channel_pool, r));
        try node.state.part(chan, uid, 1);
    }

    fn opTopic(self: *Mesh, node_idx: usize) !void {
        const node = &self.nodes.items[node_idx];
        const r = node.prng.random();
        const uid = try state_mod.Uid.init(pick(&uid_pool, r));
        const chan = try state_mod.ChannelName.init(pick(&channel_pool, r));
        const topic = try state_mod.TopicText.init(pick(&topic_pool, r));
        const hlc = try self.nextHlc(node_idx);
        try node.state.createChannel(chan, hlc, 10);
        try node.state.setTopic(chan, topic, uid, hlc);
    }

    fn opBan(self: *Mesh, node_idx: usize) !void {
        const node = &self.nodes.items[node_idx];
        const r = node.prng.random();
        const uid = try state_mod.Uid.init(pick(&uid_pool, r));
        const chan = try state_mod.ChannelName.init(pick(&channel_pool, r));
        const mask = pick(&mask_pool, r);
        if (r.intRangeLessThan(u8, 0, 2) == 0) {
            const hlc = try self.nextHlc(node_idx);
            try node.state.createChannel(chan, hlc, 10);
            try node.state.addBan(chan, .ban, mask, .{
                .setter = uid,
                .reason = try state_mod.ShortText.init("seeded"),
            }, hlc);
        } else {
            try node.state.removeBan(chan, .ban, mask);
        }
    }

    fn opPrefixGrant(self: *Mesh, node_idx: usize) !void {
        const node = &self.nodes.items[node_idx];
        const r = node.prng.random();
        const uid = try state_mod.Uid.init(pick(&uid_pool, r));
        const chan = try state_mod.ChannelName.init(pick(&channel_pool, r));
        const mode: u8 = if (r.intRangeLessThan(u8, 0, 2) == 0) 'o' else 'v';
        const hlc = try self.nextHlc(node_idx);
        try node.state.createChannel(chan, hlc, 10);
        try node.state.join(chan, uid, 1);
        try node.state.setPrefixMode(.{ .channel = chan, .uid = uid, .mode = mode }, true, 10, hlc);
    }

    fn broadcastSnapshot(self: *Mesh, from_idx: usize) !void {
        var snapshot = try cloneNetworkState(&self.nodes.items[from_idx].state);
        var moved = false;
        errdefer if (!moved) snapshot.deinit();

        const payload: u64 = @intCast(self.deltas.items.len);
        try self.deltas.append(self.allocator, .{
            .from = @intCast(from_idx),
            .hlc = self.nodes.items[from_idx].hlc,
            .state = snapshot,
        });
        moved = true;
        for (self.nodes.items, 0..) |node, to_idx| {
            if (to_idx == from_idx) continue;
            try self.network.send(self.nodes.items[from_idx].handle, node.handle, payload);
        }
    }

    fn drainNetwork(self: *Mesh) !void {
        const deliveries = self.network.deliveries();
        while (self.processed_deliveries < deliveries.len) : (self.processed_deliveries += 1) {
            const delivery = deliveries[self.processed_deliveries];
            const payload: usize = @intCast(delivery.payload);
            try self.applyDeltaToNode(payload, delivery.to.id);
        }
    }

    fn replayAllDeltas(self: *Mesh) !void {
        for (self.deltas.items, 0..) |_, payload| {
            for (self.nodes.items, 0..) |_, node_idx| {
                try self.applyDeltaToNode(payload, @intCast(node_idx));
            }
        }
    }

    fn applyDeltaToNode(self: *Mesh, payload: usize, to_id: u32) !void {
        if (payload >= self.deltas.items.len or to_id >= self.nodes.items.len) return error.InvalidDelta;
        const delta = &self.deltas.items[payload];
        const to = &self.nodes.items[to_id];
        _ = try to.hlc.recv(self.logical_ms, delta.hlc);
        try to.state.merge(&delta.state);
    }

    fn fullStateRepairRound(self: *Mesh) !void {
        var i: usize = 0;
        while (i < self.nodes.items.len) : (i += 1) {
            var j: usize = 0;
            while (j < self.nodes.items.len) : (j += 1) {
                if (i == j) continue;
                try self.planPair(i, j);
                try self.nodes.items[i].state.merge(&self.nodes.items[j].state);
            }
        }
    }

    fn planPair(self: *Mesh, local_idx: usize, remote_idx: usize) !void {
        var local = anti_entropy.Lane.init(self.allocator, .memberships);
        defer local.deinit();
        var remote = anti_entropy.Lane.init(self.allocator, .memberships);
        defer remote.deinit();
        try local.putHash("network-state", stateHash(&self.nodes.items[local_idx].state));
        try remote.putHash("network-state", stateHash(&self.nodes.items[remote_idx].state));

        const planner = anti_entropy.Planner.init(self.allocator, .{});
        var plan = try planner.plan(&local, &remote);
        defer plan.deinit();
        _ = plan.strategy;
    }

    fn allEqual(self: *Mesh) bool {
        if (self.nodes.items.len == 0) return true;
        const first = &self.nodes.items[0].state;
        for (self.nodes.items[1..]) |*node| {
            if (!NetworkState.eql(first, &node.state)) return false;
        }
        return true;
    }
};

fn cloneNetworkState(src: *const NetworkState) !NetworkState {
    var out = NetworkState.init(src.allocator, src.replica_id, src.node_id);
    errdefer out.deinit();

    try out.users.appendSlice(out.allocator, src.users.items);
    try out.nick_claims.appendSlice(out.allocator, src.nick_claims.items);
    try out.channels.appendSlice(out.allocator, src.channels.items);
    try out.prefix_modes.appendSlice(out.allocator, src.prefix_modes.items);
    try out.boolean_modes.appendSlice(out.allocator, src.boolean_modes.items);
    try out.param_modes.appendSlice(out.allocator, src.param_modes.items);
    try out.ban_metadata.appendSlice(out.allocator, src.ban_metadata.items);
    try out.topics.appendSlice(out.allocator, src.topics.items);

    var memberships = try src.memberships.clone();
    errdefer memberships.deinit();
    var bans = try src.bans.clone();
    errdefer bans.deinit();

    out.memberships.deinit();
    out.memberships = memberships;
    out.bans.deinit();
    out.bans = bans;
    return out;
}

fn stateHash(ns: *const NetworkState) anti_entropy.Hash {
    var bytes: [128]u8 = undefined;
    const summary = std.fmt.bufPrint(&bytes, "u:{} n:{} c:{} m:{} p:{} b:{} bm:{} t:{}", .{
        ns.users.items.len,
        ns.nick_claims.items.len,
        ns.channels.items.len,
        ns.memberships.entries.items.len,
        ns.prefix_modes.items.len,
        ns.bans.entries.items.len,
        ns.ban_metadata.items.len,
        ns.topics.items.len,
    }) catch "";

    var out: anti_entropy.Hash = undefined;
    std.crypto.hash.sha2.Sha256.hash(summary, &out, .{});
    return out;
}

fn pick(comptime pool: []const []const u8, random: std.Random) []const u8 {
    return pool[random.intRangeLessThan(usize, 0, pool.len)];
}

fn deriveSeed(master_seed: u64, stream: u64) u64 {
    var x = master_seed +% 0x9e37_79b9_7f4a_7c15 +% (stream << 1);
    x = (x ^ (x >> 30)) *% 0xbf58_476d_1ce4_e5b9;
    x = (x ^ (x >> 27)) *% 0x94d0_49bb_1331_11eb;
    return x ^ (x >> 31);
}

fn runConvergenceSeed(seed: u64, partitioned: bool) !void {
    var mesh = try Mesh.init(std.testing.allocator, seed, 4);
    defer mesh.deinit();

    if (partitioned) {
        try mesh.partitionFirstHalf();
        try mesh.runRandomWorkload(80);
        mesh.heal();
        try mesh.runRandomWorkload(40);
    } else {
        try mesh.runRandomWorkload(120);
    }

    try mesh.reconcile();
    try mesh.expectConverged();
}

test "convergence with no partition over random workloads" {
    var i: u64 = 0;
    while (i < 50) : (i += 1) {
        try runConvergenceSeed(0x0160_0000 + i, false);
    }
}

test "convergence after partition and heal over random workloads" {
    var i: u64 = 0;
    while (i < 50) : (i += 1) {
        try runConvergenceSeed(0x0160_1000 + i, true);
    }
}

test "nick collision across partitions converges by rename to UID" {
    var mesh = try Mesh.init(std.testing.allocator, 0x0160_c0111510, 2);
    defer mesh.deinit();

    try mesh.partitionFirstHalf();
    const nick = try state_mod.Nick.init("same");
    const loser_uid = try state_mod.Uid.init("001LOSER");
    const winner_uid = try state_mod.Uid.init("002WINNER");

    const loser_hlc = try mesh.nextHlc(0);
    try mesh.nodes.items[0].state.claimNick(nick, loser_uid, 10, loser_hlc);
    try mesh.broadcastSnapshot(0);

    const winner_hlc = try mesh.nextHlc(1);
    try mesh.nodes.items[1].state.claimNick(nick, winner_uid, 20, winner_hlc);
    try mesh.broadcastSnapshot(1);

    _ = try mesh.network.run(100);
    try mesh.drainNetwork();
    mesh.heal();
    try mesh.reconcile();
    try mesh.expectConverged();

    for (mesh.nodes.items) |*node| {
        const winner = node.state.resolveNick(nick, winner_uid);
        try std.testing.expectEqual(state_mod.NickOutcome.keep_nick, winner.outcome);
        try std.testing.expectEqual(winner_uid, winner.winner_uid.?);

        const loser = node.state.resolveNick(nick, loser_uid);
        try std.testing.expectEqual(state_mod.NickOutcome.rename_to_uid, loser.outcome);
        try std.testing.expectEqual(winner_uid, loser.winner_uid.?);
        try std.testing.expect(std.mem.eql(u8, loser_uid.asSlice(), loser.display.asSlice()));
    }
}

test "redelivering the same delta set twice is idempotent" {
    var mesh = try Mesh.init(std.testing.allocator, 0x0160_1de0, 3);
    defer mesh.deinit();

    try mesh.runRandomWorkload(40);
    try mesh.replayAllDeltas();

    var snapshots = std.ArrayList(NetworkState).empty;
    defer {
        for (snapshots.items) |*snapshot| snapshot.deinit();
        snapshots.deinit(std.testing.allocator);
    }

    for (mesh.nodes.items) |*node| {
        try snapshots.append(std.testing.allocator, try cloneNetworkState(&node.state));
    }

    try mesh.replayAllDeltas();

    for (mesh.nodes.items, snapshots.items) |*node, *snapshot| {
        try std.testing.expect(NetworkState.eql(&node.state, snapshot));
    }
}

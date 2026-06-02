//! Deterministic Ocean simulation harness skeleton.
//!
//! The simulator owns time, randomness, timers, virtual nodes, and a virtual
//! network. It never reads wall time and never touches sockets; replay is driven
//! only by the initial seed and the explicit operations applied to `Sim`.
const std = @import("std");
const reactor_mod = @import("reactor.zig");

/// Opaque virtual node handle.
pub const NodeHandle = struct {
    id: u32,
};

/// Per-link network behavior.
pub const LinkConfig = struct {
    latency_ms: i64 = 1,
    jitter_ms: i64 = 0,
    drop_probability: f64 = 0.0,
    reorder_probability: f64 = 0.0,
    reorder_extra_ms: i64 = 0,
};

/// Delivered virtual packet.
pub const Delivery = struct {
    due_ms: i64,
    seq: u64,
    from: NodeHandle,
    to: NodeHandle,
    payload: u64,
};

/// Processed event trace entry.
pub const EventRecord = struct {
    pub const Kind = enum {
        timer,
        delivered_message,
        blocked_message,
    };

    due_ms: i64,
    seq: u64,
    node: NodeHandle,
    kind: Kind,
    payload: u64,
};

const Node = struct {
    reactor_backend: reactor_mod.SimReactor,
};

const LinkKey = struct {
    from: u32,
    to: u32,
};

const TimerEvent = struct {
    node: NodeHandle,
    token: u64,
};

const MessageEvent = struct {
    from: NodeHandle,
    to: NodeHandle,
    payload: u64,
};

const EventKind = union(enum) {
    timer: TimerEvent,
    message: MessageEvent,
};

const Event = struct {
    due_ms: i64,
    seq: u64,
    kind: EventKind,
};

fn compareEvents(_: void, a: Event, b: Event) std.math.Order {
    const due_order = std.math.order(a.due_ms, b.due_ms);
    if (due_order != .eq) return due_order;
    return std.math.order(a.seq, b.seq);
}

const EventQueue = std.PriorityQueue(Event, void, compareEvents);

/// Seed-replayable simulation driver.
pub const Sim = struct {
    allocator: std.mem.Allocator,
    clock_ms: i64,
    prng: std.Random.Pcg,
    next_seq: u64,
    events: EventQueue,
    nodes: std.ArrayList(Node),
    partitioned: std.ArrayList(bool),
    links: std.AutoHashMap(LinkKey, LinkConfig),
    event_log: std.ArrayList(EventRecord),
    delivery_log: std.ArrayList(Delivery),

    pub fn init(allocator: std.mem.Allocator, seed: u64) Sim {
        return .{
            .allocator = allocator,
            .clock_ms = 0,
            .prng = std.Random.Pcg.init(seed),
            .next_seq = 0,
            .events = EventQueue.initContext({}),
            .nodes = .empty,
            .partitioned = .empty,
            .links = std.AutoHashMap(LinkKey, LinkConfig).init(allocator),
            .event_log = .empty,
            .delivery_log = .empty,
        };
    }

    pub fn deinit(self: *Sim) void {
        self.delivery_log.deinit(self.allocator);
        self.event_log.deinit(self.allocator);
        self.links.deinit();
        self.partitioned.deinit(self.allocator);
        self.nodes.deinit(self.allocator);
        self.events.deinit(self.allocator);
        self.* = undefined;
    }

    /// Current deterministic virtual time in milliseconds.
    pub fn nowMillis(self: *const Sim) i64 {
        return self.clock_ms;
    }

    /// Register one virtual node and return its stable handle.
    pub fn registerNode(self: *Sim) !NodeHandle {
        const id: u32 = @intCast(self.nodes.items.len);
        try self.nodes.append(self.allocator, .{
            .reactor_backend = reactor_mod.SimReactor.init(self.clock_ms),
        });
        try self.partitioned.append(self.allocator, false);
        return .{ .id = id };
    }

    /// Register `count` virtual nodes.
    pub fn registerNodes(self: *Sim, count: usize) !void {
        var i: usize = 0;
        while (i < count) : (i += 1) {
            _ = try self.registerNode();
        }
    }

    /// Reactor clock view for a virtual node.
    pub fn nodeReactor(self: *Sim, node: NodeHandle) !reactor_mod.Reactor {
        try self.validateNode(node);
        return self.nodes.items[node.id].reactor_backend.reactor();
    }

    /// Configure one directed virtual link.
    pub fn setLinkConfig(self: *Sim, from: NodeHandle, to: NodeHandle, config: LinkConfig) !void {
        try self.validateNode(from);
        try self.validateNode(to);
        try validateLinkConfig(config);
        try self.links.put(.{ .from = from.id, .to = to.id }, config);
    }

    /// Schedule a deterministic timer for `node`.
    pub fn scheduleTimer(self: *Sim, node: NodeHandle, delay_ms: i64, token: u64) !void {
        try self.validateNode(node);
        if (delay_ms < 0) return error.InvalidDelay;
        try self.pushEvent(self.clock_ms + delay_ms, .{ .timer = .{
            .node = node,
            .token = token,
        } });
    }

    /// Enqueue a virtual message if the seeded drop decision keeps it.
    pub fn send(self: *Sim, from: NodeHandle, to: NodeHandle, payload: u64) !void {
        try self.validateNode(from);
        try self.validateNode(to);

        const config = self.linkConfig(from, to);
        const random = self.prng.random();
        if (random.float(f64) < config.drop_probability) return;

        var delay_ms = config.latency_ms;
        if (config.jitter_ms > 0) {
            delay_ms += random.intRangeAtMost(i64, 0, config.jitter_ms);
        }
        if (config.reorder_probability > 0 and random.float(f64) < config.reorder_probability) {
            const extra = if (config.reorder_extra_ms > 0) config.reorder_extra_ms else config.latency_ms;
            if (extra > 0) {
                delay_ms += random.intRangeAtMost(i64, 1, extra);
            }
        }

        try self.pushEvent(self.clock_ms + delay_ms, .{ .message = .{
            .from = from,
            .to = to,
            .payload = payload,
        } });
    }

    /// Isolate `set` from all nodes outside `set`.
    pub fn partition(self: *Sim, set: []const NodeHandle) !void {
        for (set) |node| try self.validateNode(node);
        @memset(self.partitioned.items, false);
        for (set) |node| {
            self.partitioned.items[node.id] = true;
        }
    }

    /// Remove all simulated network partitions.
    pub fn heal(self: *Sim) void {
        @memset(self.partitioned.items, false);
    }

    /// Run up to `max_ticks` queued events.
    pub fn run(self: *Sim, max_ticks: usize) !usize {
        var ticks: usize = 0;
        while (ticks < max_ticks) {
            if (!try self.step()) break;
            ticks += 1;
        }
        return ticks;
    }

    /// Advance to the next queued event and process it. Returns false if idle.
    pub fn step(self: *Sim) !bool {
        const event = self.events.pop() orelse return false;
        if (event.due_ms > self.clock_ms) {
            self.clock_ms = event.due_ms;
            self.syncNodeClocks();
        }

        switch (event.kind) {
            .timer => |timer| {
                try self.event_log.append(self.allocator, .{
                    .due_ms = event.due_ms,
                    .seq = event.seq,
                    .node = timer.node,
                    .kind = .timer,
                    .payload = timer.token,
                });
            },
            .message => |message| {
                const blocked = self.linkPartitioned(message.from, message.to);
                try self.event_log.append(self.allocator, .{
                    .due_ms = event.due_ms,
                    .seq = event.seq,
                    .node = message.to,
                    .kind = if (blocked) .blocked_message else .delivered_message,
                    .payload = message.payload,
                });
                if (!blocked) {
                    try self.delivery_log.append(self.allocator, .{
                        .due_ms = event.due_ms,
                        .seq = event.seq,
                        .from = message.from,
                        .to = message.to,
                        .payload = message.payload,
                    });
                }
            },
        }

        return true;
    }

    /// Processed event trace in deterministic order.
    pub fn eventsProcessed(self: *const Sim) []const EventRecord {
        return self.event_log.items;
    }

    /// Delivered virtual messages in deterministic order.
    pub fn deliveries(self: *const Sim) []const Delivery {
        return self.delivery_log.items;
    }

    fn pushEvent(self: *Sim, due_ms: i64, kind: EventKind) !void {
        const seq = self.next_seq;
        self.next_seq += 1;
        try self.events.push(self.allocator, .{
            .due_ms = due_ms,
            .seq = seq,
            .kind = kind,
        });
    }

    fn validateNode(self: *const Sim, node: NodeHandle) !void {
        if (node.id >= self.nodes.items.len) return error.InvalidNode;
    }

    fn linkConfig(self: *const Sim, from: NodeHandle, to: NodeHandle) LinkConfig {
        return self.links.get(.{ .from = from.id, .to = to.id }) orelse .{};
    }

    fn linkPartitioned(self: *const Sim, from: NodeHandle, to: NodeHandle) bool {
        return self.partitioned.items[from.id] != self.partitioned.items[to.id];
    }

    fn syncNodeClocks(self: *Sim) void {
        for (self.nodes.items) |*node| {
            node.reactor_backend.clock_ms = self.clock_ms;
        }
    }
};

fn validateLinkConfig(config: LinkConfig) !void {
    if (config.latency_ms < 0 or config.jitter_ms < 0 or config.reorder_extra_ms < 0) {
        return error.InvalidConfig;
    }
    if (!validProbability(config.drop_probability) or !validProbability(config.reorder_probability)) {
        return error.InvalidConfig;
    }
}

fn validProbability(value: f64) bool {
    return value >= 0.0 and value <= 1.0;
}

fn expectSameDeliveries(a: []const Delivery, b: []const Delivery) !void {
    try std.testing.expectEqual(a.len, b.len);
    for (a, b) |left, right| {
        try std.testing.expectEqual(left.due_ms, right.due_ms);
        try std.testing.expectEqual(left.seq, right.seq);
        try std.testing.expectEqual(left.from.id, right.from.id);
        try std.testing.expectEqual(left.to.id, right.to.id);
        try std.testing.expectEqual(left.payload, right.payload);
    }
}

fn expectSameEvents(a: []const EventRecord, b: []const EventRecord) !void {
    try std.testing.expectEqual(a.len, b.len);
    for (a, b) |left, right| {
        try std.testing.expectEqual(left.due_ms, right.due_ms);
        try std.testing.expectEqual(left.seq, right.seq);
        try std.testing.expectEqual(left.node.id, right.node.id);
        try std.testing.expectEqual(left.kind, right.kind);
        try std.testing.expectEqual(left.payload, right.payload);
    }
}

test "same seed replays event ordering and delivered messages" {
    const allocator = std.testing.allocator;
    var first = Sim.init(allocator, 0x5eed);
    defer first.deinit();
    var second = Sim.init(allocator, 0x5eed);
    defer second.deinit();

    try first.registerNodes(3);
    try second.registerNodes(3);
    const a0 = NodeHandle{ .id = 0 };
    const a1 = NodeHandle{ .id = 1 };
    const a2 = NodeHandle{ .id = 2 };
    const config = LinkConfig{
        .latency_ms = 2,
        .jitter_ms = 6,
        .drop_probability = 0.2,
        .reorder_probability = 0.7,
        .reorder_extra_ms = 8,
    };
    try first.setLinkConfig(a0, a1, config);
    try first.setLinkConfig(a1, a2, config);
    try second.setLinkConfig(a0, a1, config);
    try second.setLinkConfig(a1, a2, config);

    var i: u64 = 0;
    while (i < 100) : (i += 1) {
        try first.send(if (i % 2 == 0) a0 else a1, if (i % 2 == 0) a1 else a2, i);
        try second.send(if (i % 2 == 0) a0 else a1, if (i % 2 == 0) a1 else a2, i);
    }

    try std.testing.expectEqual(try first.run(1000), try second.run(1000));
    try expectSameEvents(first.eventsProcessed(), second.eventsProcessed());
    try expectSameDeliveries(first.deliveries(), second.deliveries());
}

test "drop rate roughly matches configured probability" {
    const allocator = std.testing.allocator;
    var sim = Sim.init(allocator, 0xd0d0);
    defer sim.deinit();

    try sim.registerNodes(2);
    const from = NodeHandle{ .id = 0 };
    const to = NodeHandle{ .id = 1 };
    try sim.setLinkConfig(from, to, .{
        .latency_ms = 1,
        .drop_probability = 0.35,
    });

    const trials: usize = 5000;
    var i: usize = 0;
    while (i < trials) : (i += 1) {
        try sim.send(from, to, @intCast(i));
    }
    _ = try sim.run(trials);

    const delivered = sim.deliveries().len;
    const dropped = trials - delivered;
    const lower = trials * 30 / 100;
    const upper = trials * 40 / 100;
    try std.testing.expect(dropped >= lower);
    try std.testing.expect(dropped <= upper);
}

test "partition prevents delivery and heal restores it" {
    const allocator = std.testing.allocator;
    var sim = Sim.init(allocator, 7);
    defer sim.deinit();

    try sim.registerNodes(2);
    const left = NodeHandle{ .id = 0 };
    const right = NodeHandle{ .id = 1 };
    try sim.setLinkConfig(left, right, .{ .latency_ms = 1 });

    try sim.partition(&.{left});
    try sim.send(left, right, 1);
    _ = try sim.run(10);
    try std.testing.expectEqual(@as(usize, 0), sim.deliveries().len);

    sim.heal();
    try sim.send(left, right, 2);
    _ = try sim.run(10);
    try std.testing.expectEqual(@as(usize, 1), sim.deliveries().len);
    try std.testing.expectEqual(@as(u64, 2), sim.deliveries()[0].payload);
}

test "clock advances monotonically through the queue" {
    const allocator = std.testing.allocator;
    var sim = Sim.init(allocator, 42);
    defer sim.deinit();

    const node = try sim.registerNode();
    const r = try sim.nodeReactor(node);
    try sim.scheduleTimer(node, 10, 10);
    try sim.scheduleTimer(node, 3, 3);
    try sim.scheduleTimer(node, 7, 7);

    var last: i64 = sim.nowMillis();
    while (try sim.step()) {
        const now = sim.nowMillis();
        try std.testing.expect(now >= last);
        try std.testing.expectEqual(now, r.nowMillis());
        last = now;
    }

    const events = sim.eventsProcessed();
    try std.testing.expectEqual(@as(usize, 3), events.len);
    try std.testing.expectEqual(@as(i64, 3), events[0].due_ms);
    try std.testing.expectEqual(@as(i64, 7), events[1].due_ms);
    try std.testing.expectEqual(@as(i64, 10), events[2].due_ms);
}

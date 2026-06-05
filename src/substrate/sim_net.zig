const std = @import("std");

pub const NodeId = u64;
pub const TimeMs = i64;

pub const SimError = error{
    DuplicateNode,
    UnknownNode,
    TimeWentBackwards,
};

pub const Message = struct {
    from: NodeId,
    to: NodeId,
    bytes: []u8,
    sent_at_ms: TimeMs,
    delivered_at_ms: TimeMs,
    seq: u64,
};

pub const ScheduledEvent = struct {
    tag: u32,
    node: ?NodeId = null,
    value: u64 = 0,
};

pub const DeliveryReport = struct {
    from: NodeId,
    to: NodeId,
    sent_at_ms: TimeMs,
    delivered_at_ms: TimeMs,
    len: usize,
    seq: u64,
};

pub const StepResult = union(enum) {
    delivered: DeliveryReport,
    scheduled: ScheduledEvent,
};

const SplitMix64 = struct {
    state: u64,

    fn init(seed: u64) SplitMix64 {
        return .{ .state = seed };
    }

    fn next(self: *SplitMix64) u64 {
        self.state +%= 0x9e3779b97f4a7c15;
        var z = self.state;
        z = (z ^ (z >> 30)) *% 0xbf58476d1ce4e5b9;
        z = (z ^ (z >> 27)) *% 0x94d049bb133111eb;
        return z ^ (z >> 31);
    }

    fn bounded(self: *SplitMix64, n: u64) u64 {
        if (n == 0) return 0;
        return self.next() % n;
    }

    fn chance(self: *SplitMix64, probability: f64) bool {
        if (!(probability > 0.0)) return false;
        if (probability >= 1.0) return true;
        const bits = self.next() >> 11;
        const denom: f64 = @floatFromInt(@as(u64, 1) << 53);
        const unit: f64 = @as(f64, @floatFromInt(bits)) / denom;
        return unit < probability;
    }
};

const Node = struct {
    inbound: std.ArrayList(Message) = .empty,

    fn deinit(self: *Node, allocator: std.mem.Allocator) void {
        for (self.inbound.items) |msg| allocator.free(msg.bytes);
        self.inbound.deinit(allocator);
    }
};

const DeliveryEvent = struct {
    from: NodeId,
    to: NodeId,
    bytes: []u8,
    sent_at_ms: TimeMs,
};

const EventPayload = union(enum) {
    deliver: DeliveryEvent,
    scheduled: ScheduledEvent,

    fn deinit(self: EventPayload, allocator: std.mem.Allocator) void {
        switch (self) {
            .deliver => |delivery| allocator.free(delivery.bytes),
            .scheduled => {},
        }
    }
};

const EventItem = struct {
    at_ms: TimeMs,
    seq: u64,
    payload: EventPayload,
};

const LinkKey = struct {
    from: NodeId,
    to: NodeId,
};

const NetworkModel = struct {
    base_latency_ms: TimeMs = 0,
    jitter_ms: TimeMs = 0,
    loss_probability: f64 = 0.0,
    duplication_probability: f64 = 0.0,
    reordering: bool = false,
    reorder_window_ms: TimeMs = 0,
    per_link_fifo: bool = true,
};

pub const Sim = struct {
    allocator: std.mem.Allocator,
    clock_ms: TimeMs = 0,
    rng: SplitMix64,
    next_seq: u64 = 0,
    next_message_seq: u64 = 0,
    events: std.ArrayList(EventItem) = .empty,
    nodes: std.AutoHashMap(NodeId, Node),
    partitioned: std.AutoHashMap(NodeId, void),
    link_last_delivery: std.AutoHashMap(LinkKey, TimeMs),
    model: NetworkModel = .{},

    pub fn init(allocator: std.mem.Allocator, seed: u64) Sim {
        return .{
            .allocator = allocator,
            .rng = SplitMix64.init(seed),
            .nodes = std.AutoHashMap(NodeId, Node).init(allocator),
            .partitioned = std.AutoHashMap(NodeId, void).init(allocator),
            .link_last_delivery = std.AutoHashMap(LinkKey, TimeMs).init(allocator),
        };
    }

    pub fn deinit(self: *Sim) void {
        for (self.events.items) |event| event.payload.deinit(self.allocator);
        self.events.deinit(self.allocator);

        var node_it = self.nodes.valueIterator();
        while (node_it.next()) |node| node.deinit(self.allocator);
        self.nodes.deinit();

        self.partitioned.deinit();
        self.link_last_delivery.deinit();
    }

    pub fn now(self: *const Sim) TimeMs {
        return self.clock_ms;
    }

    pub fn addNode(self: *Sim, id: NodeId) !void {
        if (self.nodes.contains(id)) return SimError.DuplicateNode;
        try self.nodes.put(id, .{});
    }

    pub fn hasNode(self: *const Sim, id: NodeId) bool {
        return self.nodes.contains(id);
    }

    pub fn setLoss(self: *Sim, probability: f64) void {
        self.model.loss_probability = clampProbability(probability);
    }

    pub fn setDuplication(self: *Sim, probability: f64) void {
        self.model.duplication_probability = clampProbability(probability);
    }

    pub fn setLatency(self: *Sim, base_latency_ms: TimeMs, jitter_ms: TimeMs) void {
        self.model.base_latency_ms = @max(0, base_latency_ms);
        self.model.jitter_ms = @max(0, jitter_ms);
    }

    pub fn setReordering(self: *Sim, enabled: bool, window_ms: TimeMs) void {
        self.model.reordering = enabled;
        self.model.reorder_window_ms = @max(0, window_ms);
    }

    pub fn setPerLinkFifo(self: *Sim, enabled: bool) void {
        self.model.per_link_fifo = enabled;
        if (!enabled) self.link_last_delivery.clearRetainingCapacity();
    }

    pub fn partition(self: *Sim, ids: []const NodeId) !void {
        self.partitioned.clearRetainingCapacity();
        for (ids) |id| {
            if (!self.nodes.contains(id)) return SimError.UnknownNode;
            try self.partitioned.put(id, {});
        }
    }

    pub fn heal(self: *Sim) void {
        self.partitioned.clearRetainingCapacity();
    }

    pub fn send(self: *Sim, from: NodeId, to: NodeId, bytes: []const u8, now_ms: TimeMs) !void {
        if (now_ms < self.clock_ms) return SimError.TimeWentBackwards;
        if (!self.nodes.contains(from) or !self.nodes.contains(to)) return SimError.UnknownNode;
        if (self.isPartitionCut(from, to)) return;
        if (self.rng.chance(self.model.loss_probability)) return;

        try self.enqueueDelivery(from, to, bytes, now_ms);
        if (self.rng.chance(self.model.duplication_probability)) {
            try self.enqueueDelivery(from, to, bytes, now_ms);
        }
    }

    pub fn schedule(self: *Sim, at_ms: TimeMs, event: ScheduledEvent) !void {
        if (at_ms < self.clock_ms) return SimError.TimeWentBackwards;
        try self.enqueue(at_ms, .{ .scheduled = event });
    }

    pub fn step(self: *Sim) !?StepResult {
        if (self.events.items.len == 0) return null;

        const item = self.events.orderedRemove(0);
        std.debug.assert(item.at_ms >= self.clock_ms);
        self.clock_ms = item.at_ms;

        switch (item.payload) {
            .scheduled => |event| return StepResult{ .scheduled = event },
            .deliver => |delivery| {
                if (self.isPartitionCut(delivery.from, delivery.to)) {
                    self.allocator.free(delivery.bytes);
                    return null;
                }

                const node = self.nodes.getPtr(delivery.to) orelse {
                    self.allocator.free(delivery.bytes);
                    return SimError.UnknownNode;
                };
                const msg_seq = self.next_message_seq;
                self.next_message_seq +%= 1;
                try node.inbound.append(self.allocator, .{
                    .from = delivery.from,
                    .to = delivery.to,
                    .bytes = delivery.bytes,
                    .sent_at_ms = delivery.sent_at_ms,
                    .delivered_at_ms = item.at_ms,
                    .seq = msg_seq,
                });
                return StepResult{ .delivered = .{
                    .from = delivery.from,
                    .to = delivery.to,
                    .sent_at_ms = delivery.sent_at_ms,
                    .delivered_at_ms = item.at_ms,
                    .len = delivery.bytes.len,
                    .seq = msg_seq,
                } };
            },
        }
    }

    pub fn run(self: *Sim, until_ms: TimeMs) !void {
        if (until_ms < self.clock_ms) return SimError.TimeWentBackwards;
        while (self.events.items.len > 0 and self.events.items[0].at_ms <= until_ms) {
            _ = try self.step();
        }
        self.clock_ms = until_ms;
    }

    /// Borrowed view of a node's delivered messages. The slice is only valid
    /// until the next `step`/`run`/`send` touching this node, which may grow and
    /// reallocate the backing list — re-fetch after any such call; do not retain.
    pub fn inbound(self: *const Sim, id: NodeId) ![]const Message {
        const node = self.nodes.getPtr(id) orelse return SimError.UnknownNode;
        return node.inbound.items;
    }

    pub fn clearInbound(self: *Sim, id: NodeId) !void {
        const node = self.nodes.getPtr(id) orelse return SimError.UnknownNode;
        for (node.inbound.items) |msg| self.allocator.free(msg.bytes);
        node.inbound.clearRetainingCapacity();
    }

    pub fn pendingEvents(self: *const Sim) usize {
        return self.events.items.len;
    }

    fn enqueueDelivery(self: *Sim, from: NodeId, to: NodeId, bytes: []const u8, now_ms: TimeMs) !void {
        const owned = try self.allocator.dupe(u8, bytes);
        errdefer self.allocator.free(owned);

        const at_ms = try self.deliveryTime(from, to, now_ms);
        try self.enqueue(at_ms, .{ .deliver = .{
            .from = from,
            .to = to,
            .bytes = owned,
            .sent_at_ms = now_ms,
        } });
    }

    fn deliveryTime(self: *Sim, from: NodeId, to: NodeId, now_ms: TimeMs) !TimeMs {
        var latency = self.model.base_latency_ms;
        if (self.model.jitter_ms > 0) {
            latency += @intCast(self.rng.bounded(@as(u64, @intCast(self.model.jitter_ms)) + 1));
        }
        if (self.model.reordering and self.model.reorder_window_ms > 0) {
            latency += @intCast(self.rng.bounded(@as(u64, @intCast(self.model.reorder_window_ms)) + 1));
        }

        var at_ms = now_ms + latency;
        if (self.model.per_link_fifo) {
            const key: LinkKey = .{ .from = from, .to = to };
            const slot = try self.link_last_delivery.getOrPut(key);
            if (!slot.found_existing) slot.value_ptr.* = std.math.minInt(TimeMs);
            if (at_ms <= slot.value_ptr.*) at_ms = slot.value_ptr.* + 1;
            slot.value_ptr.* = at_ms;
        }
        return at_ms;
    }

    fn enqueue(self: *Sim, at_ms: TimeMs, payload: EventPayload) !void {
        const seq = self.next_seq;
        self.next_seq +%= 1;
        const item: EventItem = .{ .at_ms = at_ms, .seq = seq, .payload = payload };
        var index: usize = 0;
        while (index < self.events.items.len) : (index += 1) {
            if (eventLess(item, self.events.items[index])) break;
        }
        try self.events.insert(self.allocator, index, item);
    }

    fn isPartitionCut(self: *const Sim, a: NodeId, b: NodeId) bool {
        if (self.partitioned.count() == 0) return false;
        const a_inside = self.partitioned.contains(a);
        const b_inside = self.partitioned.contains(b);
        return a_inside != b_inside;
    }
};

fn eventLess(a: EventItem, b: EventItem) bool {
    if (a.at_ms != b.at_ms) return a.at_ms < b.at_ms;
    return a.seq < b.seq;
}

fn clampProbability(p: f64) f64 {
    if (!(p > 0.0)) return 0.0;
    if (p > 1.0) return 1.0;
    return p;
}

fn addPair(sim: *Sim, a: NodeId, b: NodeId) !void {
    try sim.addNode(a);
    try sim.addNode(b);
}

test "messages deliver after latency in time order" {
    var sim = Sim.init(std.testing.allocator, 1);
    defer sim.deinit();
    try addPair(&sim, 1, 2);
    sim.setLatency(5, 0);

    try sim.send(1, 2, "a", 0);
    try sim.send(1, 2, "b", 3);

    const first = (try sim.step()).?.delivered;
    const second = (try sim.step()).?.delivered;
    try std.testing.expectEqual(@as(TimeMs, 5), first.delivered_at_ms);
    try std.testing.expectEqual(@as(TimeMs, 8), second.delivered_at_ms);

    const inbox = try sim.inbound(2);
    try std.testing.expectEqual(@as(usize, 2), inbox.len);
    try std.testing.expectEqualSlices(u8, "a", inbox[0].bytes);
    try std.testing.expectEqualSlices(u8, "b", inbox[1].bytes);
}

test "same seed produces identical delivery schedule" {
    var left = Sim.init(std.testing.allocator, 0xabc);
    defer left.deinit();
    var right = Sim.init(std.testing.allocator, 0xabc);
    defer right.deinit();
    try addPair(&left, 1, 2);
    try addPair(&right, 1, 2);
    left.setLatency(10, 40);
    right.setLatency(10, 40);
    left.setReordering(true, 30);
    right.setReordering(true, 30);
    left.setDuplication(0.35);
    right.setDuplication(0.35);

    for (0..20) |i| {
        const byte = [_]u8{@intCast(i)};
        try left.send(1, 2, &byte, @intCast(i));
        try right.send(1, 2, &byte, @intCast(i));
    }

    while (left.pendingEvents() > 0 or right.pendingEvents() > 0) {
        const l = try left.step();
        const r = try right.step();
        try std.testing.expectEqual(l != null, r != null);
        if (l) |lv| {
            const rv = r.?;
            try std.testing.expectEqual(lv.delivered.delivered_at_ms, rv.delivered.delivered_at_ms);
            try std.testing.expectEqual(lv.delivered.sent_at_ms, rv.delivered.sent_at_ms);
            try std.testing.expectEqual(lv.delivered.len, rv.delivered.len);
        }
    }

    const a = try left.inbound(2);
    const b = try right.inbound(2);
    try std.testing.expectEqual(a.len, b.len);
    for (a, b) |am, bm| {
        try std.testing.expectEqual(am.delivered_at_ms, bm.delivered_at_ms);
        try std.testing.expectEqualSlices(u8, am.bytes, bm.bytes);
    }
}

test "drop probability removes messages" {
    var sim = Sim.init(std.testing.allocator, 2);
    defer sim.deinit();
    try addPair(&sim, 1, 2);
    sim.setLoss(1.0);

    try sim.send(1, 2, "lost", 0);
    try sim.run(100);
    try std.testing.expectEqual(@as(usize, 0), (try sim.inbound(2)).len);
}

test "duplication delivers twice" {
    var sim = Sim.init(std.testing.allocator, 3);
    defer sim.deinit();
    try addPair(&sim, 1, 2);
    sim.setLatency(7, 0);
    sim.setDuplication(1.0);

    try sim.send(1, 2, "dup", 0);
    try sim.run(10);

    const inbox = try sim.inbound(2);
    try std.testing.expectEqual(@as(usize, 2), inbox.len);
    try std.testing.expectEqualSlices(u8, "dup", inbox[0].bytes);
    try std.testing.expectEqualSlices(u8, "dup", inbox[1].bytes);
}

test "partitioned nodes do not exchange until healed" {
    var sim = Sim.init(std.testing.allocator, 4);
    defer sim.deinit();
    try addPair(&sim, 1, 2);
    sim.setLatency(10, 0);

    try sim.partition(&.{1});
    try sim.send(1, 2, "blocked", 0);
    try sim.run(50);
    try std.testing.expectEqual(@as(usize, 0), (try sim.inbound(2)).len);

    sim.heal();
    try sim.send(1, 2, "open", 50);
    try sim.run(60);
    const inbox = try sim.inbound(2);
    try std.testing.expectEqual(@as(usize, 1), inbox.len);
    try std.testing.expectEqualSlices(u8, "open", inbox[0].bytes);
}

test "reordering still respects per-link FIFO when configured" {
    var sim = Sim.init(std.testing.allocator, 5);
    defer sim.deinit();
    try addPair(&sim, 1, 2);
    sim.setLatency(0, 25);
    sim.setReordering(true, 25);
    sim.setPerLinkFifo(true);

    for (0..16) |i| {
        const byte = [_]u8{@intCast(i)};
        try sim.send(1, 2, &byte, 0);
    }
    try sim.run(1000);

    const inbox = try sim.inbound(2);
    try std.testing.expectEqual(@as(usize, 16), inbox.len);
    var last: TimeMs = -1;
    for (inbox, 0..) |msg, i| {
        try std.testing.expect(msg.delivered_at_ms > last);
        try std.testing.expectEqual(@as(u8, @intCast(i)), msg.bytes[0]);
        last = msg.delivered_at_ms;
    }
}

test "clock advances monotonically" {
    var sim = Sim.init(std.testing.allocator, 6);
    defer sim.deinit();
    try sim.schedule(30, .{ .tag = 3 });
    try sim.schedule(10, .{ .tag = 1 });
    try sim.schedule(20, .{ .tag = 2 });

    var event = (try sim.step()).?.scheduled;
    try std.testing.expectEqual(@as(u32, 1), event.tag);
    try std.testing.expectEqual(@as(TimeMs, 10), sim.now());

    event = (try sim.step()).?.scheduled;
    try std.testing.expectEqual(@as(u32, 2), event.tag);
    try std.testing.expectEqual(@as(TimeMs, 20), sim.now());

    try sim.run(30);
    try std.testing.expectEqual(@as(TimeMs, 30), sim.now());
    try std.testing.expectError(SimError.TimeWentBackwards, sim.schedule(29, .{ .tag = 9 }));
}

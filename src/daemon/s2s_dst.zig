//! Deterministic S2S simulation harness.
//!
//! `S2sLink` is reactor-independent (bytes in via `feed`, bytes out via
//! `outbound`), and `SimNetReactor` makes the daemon clock follow `sim_net`'s
//! event-driven clock. This harness joins the two: it pumps two links' traffic
//! through a `sim_net.Sim` — with latency, loss, reorder, and partitions — so a
//! full server-to-server handshake + convergence runs entirely in deterministic
//! simulation (Deterministic Ocean), seed-replayable and io_uring-free.
//!
//! This is the seam the live io_uring path mirrors: the same `S2sLink.feed` /
//! `outbound` cycle, with the simulator standing in for the socket. It is the
//! foundation the live Tsumugi handshake wiring (#2) and world projection (#6)
//! build on — both can be exercised here before touching real sockets.
const std = @import("std");

const s2s_link = @import("s2s_link.zig");
const sim_net = @import("../substrate/sim_net.zig");
const reactor_mod = @import("../substrate/reactor.zig");

pub const NodeId = sim_net.NodeId;

/// Two links wired through one simulated network. `a`/`b` live at stable
/// addresses (the driver clock captures their address), so the harness is
/// heap-pinned.
pub const Pair = struct {
    allocator: std.mem.Allocator,
    sim: *sim_net.Sim,
    reactor: reactor_mod.SimNetReactor,
    a: *s2s_link.S2sLink,
    b: *s2s_link.S2sLink,
    id_a: NodeId,
    id_b: NodeId,
    feed_seq: u64 = 0,

    pub fn init(allocator: std.mem.Allocator, seed: u64, id_a: NodeId, id_b: NodeId) !Pair {
        const sim = try allocator.create(sim_net.Sim);
        errdefer allocator.destroy(sim);
        sim.* = sim_net.Sim.init(allocator, seed);
        errdefer sim.deinit();
        try sim.addNode(id_a);
        try sim.addNode(id_b);

        const a = try allocator.create(s2s_link.S2sLink);
        errdefer allocator.destroy(a);
        try a.init(.{
            .allocator = allocator,
            .local_node_id = id_a,
            .remote_node_id = id_b,
            .local_epoch_ms = 1000,
            .server_name = "a.orochi",
        });
        errdefer a.deinit();

        const b = try allocator.create(s2s_link.S2sLink);
        errdefer allocator.destroy(b);
        try b.init(.{
            .allocator = allocator,
            .local_node_id = id_b,
            .remote_node_id = id_a,
            .local_epoch_ms = 1001,
            .server_name = "b.orochi",
        });
        errdefer b.deinit();

        return .{
            .allocator = allocator,
            .sim = sim,
            .reactor = reactor_mod.SimNetReactor.init(sim),
            .a = a,
            .b = b,
            .id_a = id_a,
            .id_b = id_b,
        };
    }

    pub fn deinit(self: *Pair) void {
        self.a.deinit();
        self.allocator.destroy(self.a);
        self.b.deinit();
        self.allocator.destroy(self.b);
        self.sim.deinit();
        self.allocator.destroy(self.sim);
        self.* = undefined;
    }

    fn linkFor(self: *Pair, id: NodeId) *s2s_link.S2sLink {
        return if (id == self.id_a) self.a else self.b;
    }

    fn peerOf(self: *Pair, id: NodeId) NodeId {
        return if (id == self.id_a) self.id_b else self.id_a;
    }

    /// Push a link's pending outbound bytes into the network toward its peer.
    fn flush(self: *Pair, from: NodeId) !void {
        const link = self.linkFor(from);
        const out = link.outbound();
        if (out.len == 0) return;
        try self.sim.send(from, self.peerOf(from), out, self.sim.now());
        link.clearOutbound();
    }

    /// Open the handshake from A and run the network to quiescence (or `max_steps`).
    /// Returns the number of steps consumed. Time is the simulator's clock, read
    /// through the `SimNetReactor` exactly as the daemon would.
    pub fn run(self: *Pair, max_steps: usize) !usize {
        const r = self.reactor.reactor();
        try self.a.start(@intCast(@max(0, r.nowMillis())));
        try self.flush(self.id_a);

        var steps: usize = 0;
        while (steps < max_steps) : (steps += 1) {
            if (self.sim.pendingEvents() == 0) break;
            const result = (try self.reactor.step()) orelse continue; // null = dropped
            switch (result) {
                .delivered => |d| {
                    const now: u64 = @intCast(@max(0, r.nowMillis()));
                    const target = self.linkFor(d.to);
                    const inbox = try self.sim.inbound(d.to);
                    for (inbox) |msg| {
                        self.feed_seq +%= 1;
                        try target.feed(msg.bytes, now, self.feed_seq);
                    }
                    try self.sim.clearInbound(d.to);
                    try self.flush(d.to);
                },
                .scheduled => {},
            }
        }
        return steps;
    }

    pub fn bothEstablished(self: *const Pair) bool {
        return self.a.established() and self.b.established();
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "two peers complete the S2S handshake over a simulated network with latency" {
    var pair = try Pair.init(testing.allocator, 0xD57, 1, 2);
    defer pair.deinit();
    pair.sim.setLatency(20, 5);

    _ = try pair.run(10_000);

    try testing.expect(pair.bothEstablished());
    // Each side learned the other through the registry burst.
    try testing.expect(pair.a.knownServers() >= 2);
    try testing.expect(pair.b.knownServers() >= 2);
    // The daemon-visible clock advanced with the simulated deliveries.
    try testing.expect(pair.reactor.reactor().nowMillis() > 0);
}

test "the simulation is seed-deterministic (identical outcome on replay)" {
    var first = try Pair.init(testing.allocator, 0xBEEF, 1, 2);
    defer first.deinit();
    first.sim.setLatency(15, 40);
    first.sim.setReordering(true, 30);
    const steps1 = try first.run(10_000);

    var second = try Pair.init(testing.allocator, 0xBEEF, 1, 2);
    defer second.deinit();
    second.sim.setLatency(15, 40);
    second.sim.setReordering(true, 30);
    const steps2 = try second.run(10_000);

    try testing.expectEqual(steps1, steps2);
    try testing.expectEqual(first.bothEstablished(), second.bothEstablished());
    try testing.expectEqual(first.a.knownServers(), second.a.knownServers());
    try testing.expectEqual(
        first.reactor.reactor().nowMillis(),
        second.reactor.reactor().nowMillis(),
    );
}

test "a network partition prevents the handshake from completing" {
    var pair = try Pair.init(testing.allocator, 0x9A9, 1, 2);
    defer pair.deinit();
    pair.sim.setLatency(10, 0);
    try pair.sim.partition(&.{1}); // cut node 1 off from node 2

    _ = try pair.run(10_000);

    try testing.expect(!pair.bothEstablished());
}

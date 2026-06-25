// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Small deterministic load balancer for backend pools.
//!
//! The balancer owns N backend records and supports:
//!   * Power-of-two choices (P2C)
//!   * Round-robin
//!   * Least-connections
//!   * Weighted variants of the above
//!
//! Backends marked unhealthy are ignored by every policy.  `pick()` returns a
//! backend index; callers should pass that same index to `onStart` when work is
//! assigned and to `onComplete` when it finishes.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const BackendId = usize;

pub const Policy = enum {
    /// Pick two random healthy backends and choose the lower load.
    p2c,
    /// Rotate through healthy backends in index order.
    round_robin,
    /// Choose the healthy backend with the fewest in-flight requests.
    least_connections,
    /// P2C where load is normalized by backend weight.
    weighted_p2c,
    /// Smooth weighted round-robin across healthy backends.
    weighted_round_robin,
    /// Least-connections where connection count is normalized by weight.
    weighted_least_connections,
};

pub const Backend = struct {
    inflight: u32 = 0,
    ewma_latency: u64 = 0,
    healthy: bool = true,
    weight: u32 = 1,
};

pub const Config = struct {
    policy: Policy,
    seed: u64 = 0x9e37_79b9_7f4a_7c15,
};

pub const LoadBalancer = struct {
    allocator: Allocator,
    policy: Policy,
    rng: Prng,
    backends: std.ArrayList(Backend),
    wrr_credit: std.ArrayList(i64),
    rr_cursor: usize,

    pub fn init(allocator: Allocator, config: Config) LoadBalancer {
        return .{
            .allocator = allocator,
            .policy = config.policy,
            .rng = Prng.init(config.seed),
            .backends = .empty,
            .wrr_credit = .empty,
            .rr_cursor = 0,
        };
    }

    pub fn deinit(self: *LoadBalancer) void {
        self.backends.deinit(self.allocator);
        self.wrr_credit.deinit(self.allocator);
    }

    pub fn addBackend(self: *LoadBalancer, backend_state: Backend) Allocator.Error!BackendId {
        var normalized = backend_state;
        if (normalized.weight == 0) normalized.weight = 1;

        const id = self.backends.items.len;
        try self.backends.append(self.allocator, normalized);
        errdefer _ = self.backends.pop();

        try self.wrr_credit.append(self.allocator, 0);
        return id;
    }

    pub fn backendCount(self: *const LoadBalancer) usize {
        return self.backends.items.len;
    }

    pub fn backend(self: *LoadBalancer, id: BackendId) ?*Backend {
        if (id >= self.backends.items.len) return null;
        return &self.backends.items[id];
    }

    pub fn setHealthy(self: *LoadBalancer, id: BackendId, healthy: bool) void {
        if (id >= self.backends.items.len) return;
        self.backends.items[id].healthy = healthy;
        if (!healthy) self.wrr_credit.items[id] = 0;
    }

    pub fn pick(self: *LoadBalancer) ?BackendId {
        if (self.backends.items.len == 0) return null;

        return switch (self.policy) {
            .p2c => self.pickP2c(false),
            .weighted_p2c => self.pickP2c(true),
            .round_robin => self.pickRoundRobin(),
            .weighted_round_robin => self.pickWeightedRoundRobin(),
            .least_connections => self.pickLeastConnections(false),
            .weighted_least_connections => self.pickLeastConnections(true),
        };
    }

    pub fn onStart(self: *LoadBalancer, id: BackendId) void {
        if (id >= self.backends.items.len) return;
        self.backends.items[id].inflight +|= 1;
    }

    pub fn onComplete(self: *LoadBalancer, id: BackendId, latency: u64) void {
        if (id >= self.backends.items.len) return;

        const backend_state = &self.backends.items[id];
        if (backend_state.inflight > 0) backend_state.inflight -= 1;
        backend_state.ewma_latency = updateEwma(backend_state.ewma_latency, latency);
    }

    fn pickRoundRobin(self: *LoadBalancer) ?BackendId {
        const n = self.backends.items.len;
        if (n == 0) return null;
        if (self.rr_cursor >= n) self.rr_cursor = 0;

        var scanned: usize = 0;
        while (scanned < n) : (scanned += 1) {
            const id = (self.rr_cursor + scanned) % n;
            if (!self.backends.items[id].healthy) continue;
            self.rr_cursor = (id + 1) % n;
            return id;
        }

        return null;
    }

    fn pickLeastConnections(self: *LoadBalancer, weighted: bool) ?BackendId {
        var best: ?BackendId = null;

        for (self.backends.items, 0..) |candidate, id| {
            if (!candidate.healthy) continue;
            if (best == null or lessConnectionLoaded(candidate, self.backends.items[best.?], weighted)) {
                best = id;
            }
        }

        return best;
    }

    fn pickP2c(self: *LoadBalancer, weighted: bool) ?BackendId {
        const healthy = self.healthyCount();
        if (healthy == 0) return null;
        if (healthy == 1) return self.nthHealthy(0);

        const first_ordinal = self.rng.index(healthy);
        var second_ordinal = self.rng.index(healthy - 1);
        if (second_ordinal >= first_ordinal) second_ordinal += 1;

        const a = self.nthHealthy(first_ordinal).?;
        const b = self.nthHealthy(second_ordinal).?;
        const ab = self.backends.items[a];
        const bb = self.backends.items[b];

        if (lessRequestLoaded(bb, ab, weighted)) return b;
        return a;
    }

    fn pickWeightedRoundRobin(self: *LoadBalancer) ?BackendId {
        var total_weight: i64 = 0;
        var best: ?BackendId = null;

        for (self.backends.items, 0..) |backend_state, id| {
            if (!backend_state.healthy) {
                self.wrr_credit.items[id] = 0;
                continue;
            }

            const weight: i64 = @intCast(nonzeroWeight(backend_state));
            self.wrr_credit.items[id] += weight;
            total_weight += weight;

            if (best == null or self.wrr_credit.items[id] > self.wrr_credit.items[best.?]) {
                best = id;
            }
        }

        if (best) |id| {
            self.wrr_credit.items[id] -= total_weight;
            return id;
        }
        return null;
    }

    fn healthyCount(self: *const LoadBalancer) usize {
        var count: usize = 0;
        for (self.backends.items) |backend_state| {
            if (backend_state.healthy) count += 1;
        }
        return count;
    }

    fn nthHealthy(self: *const LoadBalancer, ordinal: usize) ?BackendId {
        var seen: usize = 0;
        for (self.backends.items, 0..) |backend_state, id| {
            if (!backend_state.healthy) continue;
            if (seen == ordinal) return id;
            seen += 1;
        }
        return null;
    }
};

const Prng = struct {
    state: u64,

    fn init(seed: u64) Prng {
        return .{ .state = if (seed == 0) 0xa076_1d64_78bd_642f else seed };
    }

    fn next(self: *Prng) u64 {
        var x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        return x *% 0x2545_f491_4f6c_dd1d;
    }

    fn index(self: *Prng, limit: usize) usize {
        std.debug.assert(limit > 0);
        return @intCast(self.next() % @as(u64, @intCast(limit)));
    }
};

fn updateEwma(old: u64, sample: u64) u64 {
    if (old == 0) return sample;
    const blended = (@as(u128, old) * 7) + sample;
    return @intCast(blended / 8);
}

fn nonzeroWeight(backend: Backend) u32 {
    return if (backend.weight == 0) 1 else backend.weight;
}

fn requestLoad(backend: Backend) u128 {
    const inflight = @as(u128, backend.inflight) + 1;
    return inflight * 1_000_000 + backend.ewma_latency;
}

fn connectionLoad(backend: Backend, weighted: bool) u128 {
    if (weighted) return @as(u128, backend.inflight) + 1;
    return backend.inflight;
}

fn lessRequestLoaded(a: Backend, b: Backend, weighted: bool) bool {
    return lessLoaded(a, b, requestLoad(a), requestLoad(b), weighted);
}

fn lessConnectionLoaded(a: Backend, b: Backend, weighted: bool) bool {
    return lessLoaded(a, b, connectionLoad(a, weighted), connectionLoad(b, weighted), weighted);
}

fn lessLoaded(a: Backend, b: Backend, a_load: u128, b_load: u128, weighted: bool) bool {
    const a_weight = if (weighted) @as(u128, nonzeroWeight(a)) else 1;
    const b_weight = if (weighted) @as(u128, nonzeroWeight(b)) else 1;
    const left = a_load * b_weight;
    const right = b_load * a_weight;

    if (left != right) return left < right;
    if (a.inflight != b.inflight) return a.inflight < b.inflight;
    if (a.ewma_latency != b.ewma_latency) return a.ewma_latency < b.ewma_latency;
    return nonzeroWeight(a) > nonzeroWeight(b);
}

test "round-robin rotates through healthy backends" {
    var lb = LoadBalancer.init(std.testing.allocator, .{
        .policy = .round_robin,
        .seed = 1,
    });
    defer lb.deinit();

    _ = try lb.addBackend(.{});
    _ = try lb.addBackend(.{});
    _ = try lb.addBackend(.{});

    try std.testing.expectEqual(@as(?BackendId, 0), lb.pick());
    try std.testing.expectEqual(@as(?BackendId, 1), lb.pick());
    try std.testing.expectEqual(@as(?BackendId, 2), lb.pick());
    try std.testing.expectEqual(@as(?BackendId, 0), lb.pick());
}

test "least-connections picks the minimum inflight backend" {
    var lb = LoadBalancer.init(std.testing.allocator, .{
        .policy = .least_connections,
        .seed = 2,
    });
    defer lb.deinit();

    _ = try lb.addBackend(.{ .inflight = 8 });
    _ = try lb.addBackend(.{ .inflight = 3 });
    _ = try lb.addBackend(.{ .inflight = 5 });

    try std.testing.expectEqual(@as(?BackendId, 1), lb.pick());
    lb.onStart(1);
    lb.onStart(1);
    lb.onStart(1);
    lb.onStart(1);
    try std.testing.expectEqual(@as(?BackendId, 2), lb.pick());
}

test "unhealthy backends are skipped by every policy" {
    const policies = [_]Policy{
        .p2c,
        .round_robin,
        .least_connections,
        .weighted_p2c,
        .weighted_round_robin,
        .weighted_least_connections,
    };

    for (policies) |policy| {
        var lb = LoadBalancer.init(std.testing.allocator, .{
            .policy = policy,
            .seed = 3,
        });
        defer lb.deinit();

        _ = try lb.addBackend(.{ .healthy = false, .weight = 50 });
        _ = try lb.addBackend(.{ .healthy = true, .weight = 1 });
        _ = try lb.addBackend(.{ .healthy = false, .weight = 50 });

        try std.testing.expectEqual(@as(?BackendId, 1), lb.pick());
    }
}

test "all-unhealthy pool returns null" {
    var lb = LoadBalancer.init(std.testing.allocator, .{
        .policy = .p2c,
        .seed = 4,
    });
    defer lb.deinit();

    _ = try lb.addBackend(.{ .healthy = false });
    _ = try lb.addBackend(.{ .healthy = false });

    try std.testing.expectEqual(@as(?BackendId, null), lb.pick());
}

test "P2C spreads load across the pool" {
    var lb = LoadBalancer.init(std.testing.allocator, .{
        .policy = .p2c,
        .seed = 0x1234_5678,
    });
    defer lb.deinit();

    var i: usize = 0;
    while (i < 8) : (i += 1) {
        _ = try lb.addBackend(.{});
    }

    i = 0;
    while (i < 256) : (i += 1) {
        const picked = lb.pick().?;
        lb.onStart(picked);
    }

    var min_seen: u32 = std.math.maxInt(u32);
    var max_seen: u32 = 0;
    for (lb.backends.items) |backend_state| {
        min_seen = @min(min_seen, backend_state.inflight);
        max_seen = @max(max_seen, backend_state.inflight);
    }

    try std.testing.expect(max_seen - min_seen <= 2);
}

test "P2C avoids the busiest of the two sampled backends" {
    var lb = LoadBalancer.init(std.testing.allocator, .{
        .policy = .p2c,
        .seed = 5,
    });
    defer lb.deinit();

    _ = try lb.addBackend(.{ .inflight = 100 });
    _ = try lb.addBackend(.{ .inflight = 1 });

    try std.testing.expectEqual(@as(?BackendId, 1), lb.pick());
}

test "P2C is deterministic for a given seed" {
    var a = LoadBalancer.init(std.testing.allocator, .{
        .policy = .p2c,
        .seed = 0xfeed_beef,
    });
    defer a.deinit();
    var b = LoadBalancer.init(std.testing.allocator, .{
        .policy = .p2c,
        .seed = 0xfeed_beef,
    });
    defer b.deinit();

    var i: usize = 0;
    while (i < 6) : (i += 1) {
        _ = try a.addBackend(.{ .ewma_latency = @intCast(i * 100) });
        _ = try b.addBackend(.{ .ewma_latency = @intCast(i * 100) });
    }

    i = 0;
    while (i < 64) : (i += 1) {
        const ap = a.pick();
        const bp = b.pick();
        try std.testing.expectEqual(ap, bp);
        if (ap) |id| {
            a.onStart(id);
            b.onStart(id);
        }
    }
}

test "onComplete decrements inflight and updates EWMA latency" {
    var lb = LoadBalancer.init(std.testing.allocator, .{
        .policy = .least_connections,
        .seed = 6,
    });
    defer lb.deinit();

    const id = try lb.addBackend(.{});
    lb.onStart(id);
    lb.onStart(id);
    lb.onComplete(id, 80);
    lb.onComplete(id, 160);

    try std.testing.expectEqual(@as(u32, 0), lb.backends.items[id].inflight);
    try std.testing.expectEqual(@as(u64, 90), lb.backends.items[id].ewma_latency);
}

test "weighted least-connections accounts for backend capacity" {
    var lb = LoadBalancer.init(std.testing.allocator, .{
        .policy = .weighted_least_connections,
        .seed = 7,
    });
    defer lb.deinit();

    _ = try lb.addBackend(.{ .inflight = 1, .weight = 1 });
    _ = try lb.addBackend(.{ .inflight = 4, .weight = 10 });
    _ = try lb.addBackend(.{ .inflight = 2, .weight = 2 });

    try std.testing.expectEqual(@as(?BackendId, 1), lb.pick());
}

test "smooth weighted round-robin follows weights over time" {
    var lb = LoadBalancer.init(std.testing.allocator, .{
        .policy = .weighted_round_robin,
        .seed = 8,
    });
    defer lb.deinit();

    _ = try lb.addBackend(.{ .weight = 3 });
    _ = try lb.addBackend(.{ .weight = 1 });

    var counts = [_]u32{ 0, 0 };
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        counts[lb.pick().?] += 1;
    }

    try std.testing.expectEqual(@as(u32, 6), counts[0]);
    try std.testing.expectEqual(@as(u32, 2), counts[1]);
}

test "weighted P2C prefers lower normalized load" {
    var lb = LoadBalancer.init(std.testing.allocator, .{
        .policy = .weighted_p2c,
        .seed = 9,
    });
    defer lb.deinit();

    _ = try lb.addBackend(.{ .inflight = 2, .weight = 1 });
    _ = try lb.addBackend(.{ .inflight = 8, .weight = 10 });

    try std.testing.expectEqual(@as(?BackendId, 1), lb.pick());
}

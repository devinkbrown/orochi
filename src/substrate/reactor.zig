//! Ringlane reactor seam.
//!
//! DST-first principle (locked decision, planning/00): all time and I/O flow
//! through `Reactor`, so the daemon runs unchanged against either the real
//! io_uring/system backend or the deterministic simulator (Deterministic
//! Ocean). Today the seam covers monotonic time; submit/poll/accept/recv/send
//! land in M1 when Ringlane (io_uring) is implemented.
const std = @import("std");
const platform = @import("platform.zig");
const sim_net = @import("sim_net.zig");

pub const Reactor = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Monotonic time in milliseconds.
        nowMillis: *const fn (ctx: *anyopaque) i64,
    };

    pub fn nowMillis(self: Reactor) i64 {
        return self.vtable.nowMillis(self.ptr);
    }
};

/// Real backend. System clock today; io_uring event loop arrives in M1.
pub const SystemReactor = struct {
    pub fn init() SystemReactor {
        return .{};
    }

    pub fn reactor(self: *SystemReactor) Reactor {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn nowMillis(_: *anyopaque) i64 {
        // M1 will source time from the io_uring ring; for now read the portable
        // monotonic clock (std.time lost its clock helpers in 0.16). Routed
        // through `platform` so non-Linux targets build (CROSS-PLATFORM MANDATE).
        return platform.monotonicMillis();
    }

    const vtable = Reactor.VTable{ .nowMillis = nowMillis };
};

/// Deterministic backend: the clock only moves when the test advances it.
/// Foundation for seed-replayable mesh + crypto simulation.
pub const SimReactor = struct {
    clock_ms: i64 = 0,

    pub fn init(start_ms: i64) SimReactor {
        return .{ .clock_ms = start_ms };
    }

    pub fn advance(self: *SimReactor, delta_ms: i64) void {
        self.clock_ms += delta_ms;
    }

    pub fn reactor(self: *SimReactor) Reactor {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn nowMillis(ctx: *anyopaque) i64 {
        const self: *SimReactor = @ptrCast(@alignCast(ctx));
        return self.clock_ms;
    }

    const vtable = Reactor.VTable{ .nowMillis = nowMillis };
};

/// Deterministic backend bound to a `sim_net.Sim`: the reactor clock IS the
/// network's event-driven clock, so stepping/running the simulated network also
/// advances every daemon timer that reads `nowMillis`. This is the seam through
/// which full S2S deterministic simulation drives the daemon — one clock for the
/// network and the daemon, no manual `advance` to keep them in sync.
pub const SimNetReactor = struct {
    sim: *sim_net.Sim,

    pub fn init(sim: *sim_net.Sim) SimNetReactor {
        return .{ .sim = sim };
    }

    pub fn reactor(self: *SimNetReactor) Reactor {
        return .{ .ptr = self, .vtable = &vtable };
    }

    /// Step one network event (delivery or scheduled timer); time advances to
    /// that event's timestamp, which the reactor clock then reflects.
    pub fn step(self: *SimNetReactor) !?sim_net.StepResult {
        return self.sim.step();
    }

    /// Drain all events up to `until_ms`, leaving the clock at `until_ms`.
    pub fn run(self: *SimNetReactor, until_ms: i64) !void {
        return self.sim.run(until_ms);
    }

    fn nowMillis(ctx: *anyopaque) i64 {
        const self: *SimNetReactor = @ptrCast(@alignCast(ctx));
        return self.sim.now();
    }

    const vtable = Reactor.VTable{ .nowMillis = nowMillis };
};

test "sim reactor clock is deterministic and advances on command" {
    var sim = SimReactor.init(1000);
    const r = sim.reactor();
    try std.testing.expectEqual(@as(i64, 1000), r.nowMillis());
    sim.advance(250);
    try std.testing.expectEqual(@as(i64, 1250), r.nowMillis());
}

test "sim-net reactor clock follows the simulated network clock" {
    var net = sim_net.Sim.init(std.testing.allocator, 0x5eed);
    defer net.deinit();
    try net.addNode(1);
    try net.addNode(2);
    net.setLatency(40, 0);

    var sr = SimNetReactor.init(&net);
    const r = sr.reactor();
    try std.testing.expectEqual(@as(i64, 0), r.nowMillis());

    // A scheduled timer at t=100 moves the clock the daemon would read.
    try net.schedule(100, .{ .tag = 7 });
    const ev = (try sr.step()).?;
    try std.testing.expectEqual(@as(u32, 7), ev.scheduled.tag);
    try std.testing.expectEqual(@as(i64, 100), r.nowMillis());
}

test "sim-net reactor: a delivery advances the daemon-visible clock to its arrival" {
    var net = sim_net.Sim.init(std.testing.allocator, 0xface);
    defer net.deinit();
    try net.addNode(10);
    try net.addNode(20);
    net.setLatency(15, 0);

    var sr = SimNetReactor.init(&net);
    const r = sr.reactor();

    try net.send(10, 20, "s2s-handshake", 0);
    const res = (try sr.step()).?;
    try std.testing.expectEqual(@as(i64, 15), res.delivered.delivered_at_ms);
    // The reactor (what the daemon's nowMs reads) tracks the network clock.
    try std.testing.expectEqual(@as(i64, 15), r.nowMillis());

    // run() to a later horizon leaves both clocks aligned.
    try sr.run(1000);
    try std.testing.expectEqual(@as(i64, 1000), r.nowMillis());
}

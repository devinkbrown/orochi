//! Ringlane reactor seam.
//!
//! DST-first principle (locked decision, planning/00): all time and I/O flow
//! through `Reactor`, so the daemon runs unchanged against either the real
//! io_uring/system backend or the deterministic simulator (Deterministic
//! Ocean). Today the seam covers monotonic time; submit/poll/accept/recv/send
//! land in M1 when Ringlane (io_uring) is implemented.
const std = @import("std");

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
        // M1 will source time from the io_uring ring; for now read the
        // monotonic clock directly (std.time lost its clock helpers in 0.16).
        var ts: std.os.linux.timespec = undefined;
        _ = std.os.linux.clock_gettime(std.os.linux.CLOCK.MONOTONIC, &ts);
        return @as(i64, @intCast(ts.sec)) * 1000 +
            @divTrunc(@as(i64, @intCast(ts.nsec)), 1_000_000);
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

test "sim reactor clock is deterministic and advances on command" {
    var sim = SimReactor.init(1000);
    const r = sim.reactor();
    try std.testing.expectEqual(@as(i64, 1000), r.nowMillis());
    sim.advance(250);
    try std.testing.expectEqual(@as(i64, 1250), r.nowMillis());
}

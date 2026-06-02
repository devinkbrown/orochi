//! Mizuchi entry point (M0 Bootline).
const std = @import("std");
const mizuchi = @import("mizuchi");

pub fn main() !void {
    std.debug.print(
        \\
        \\  Mizuchi {s}  (水蛟)
        \\  Zig-native successor to ophion — LADON + VEIL mesh
        \\
        \\
    , .{mizuchi.version});

    // DST-first: even the real daemon drives time/IO through a Reactor, so the
    // identical logic runs under the deterministic simulator.
    var sys = mizuchi.substrate.SystemReactor.init();
    var d = mizuchi.daemon.Daemon.init(sys.reactor());
    d.boot();
}

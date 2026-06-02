//! Mizuchi entry point (M1: Ringlane TCP server).
const std = @import("std");
const mizuchi = @import("mizuchi");

pub fn main() !void {
    std.debug.print(
        \\
        \\  Mizuchi {s}  (水蛟)
        \\  Zig-native successor to ophion — Suimyaku + Tsumugi mesh
        \\
        \\
    , .{mizuchi.version});

    const allocator = std.heap.page_allocator;

    // 6680 (6667/6697 belong to the local eshmaki server).
    const port: u16 = 6680;

    const Server = mizuchi.daemon.server.Server;
    var srv = Server.init(allocator, .{ .port = port }) catch |err| {
        // io_uring unavailable (old kernel / sandbox): fall back to the DST boot banner.
        std.debug.print("mizuchi: server unavailable ({s}); boot-only.\n", .{@errorName(err)});
        var sys = mizuchi.substrate.SystemReactor.init();
        var d = mizuchi.daemon.Daemon.init(sys.reactor());
        d.boot();
        return;
    };
    defer srv.deinit();

    std.debug.print(
        "mizuchi: listening on 127.0.0.1:{d} (Ringlane io_uring) — PING + registration live\n",
        .{try srv.boundPort()},
    );
    while (true) {
        srv.runOnce() catch |err| {
            std.debug.print("mizuchi: runOnce error: {s}\n", .{@errorName(err)});
            return err;
        };
    }
}

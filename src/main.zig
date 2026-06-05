//! Mizuchi entry point (M1: Ringlane TCP server).
const std = @import("std");
const mizuchi = @import("mizuchi");

/// ${VAR} resolver for the config parser — reads the process environment map
/// (Zig 0.16 delivers the environment via `std.process.Init.environ_map`, which
/// we thread through the resolver `ctx`). Returns an owned dupe of the value.
fn envLookup(ctx: ?*anyopaque, allocator: std.mem.Allocator, name: []const u8) anyerror![]const u8 {
    const map: *std.process.Environ.Map = @ptrCast(@alignCast(ctx orelse return error.EnvironmentVariableNotFound));
    const value = map.get(name) orelse return error.EnvironmentVariableNotFound;
    return allocator.dupe(u8, value);
}

pub fn main(init: std.process.Init) !void {
    std.debug.print(
        \\
        \\  Mizuchi {s}  (水蛟)
        \\  Zig-native successor to ophion — Suimyaku + Tsumugi mesh
        \\
        \\
    , .{mizuchi.version});

    const allocator = init.gpa;

    // Default config (6680; 6667/6697 belong to the local eshmaki server). A
    // config file path may be passed as argv[1]: present values override the
    // defaults; a missing/invalid file keeps defaults (boot never fails on it).
    var srv_cfg = mizuchi.daemon.server.Config{ .port = 6680 };
    var held: ?mizuchi.daemon.config_boot.Loaded = null;
    defer if (held) |*h| h.deinit(allocator);

    var args = try std.process.Args.iterateAllocator(init.minimal.args, allocator);
    defer args.deinit(); // no-op on POSIX, frees the arg buffer on Windows/WASI
    _ = args.skip(); // argv[0]
    if (args.next()) |path| {
        const resolver = mizuchi.daemon.config_format.Resolver{
            .ctx = init.environ_map,
            .env = envLookup,
        };
        if (std.Io.Dir.cwd().readFileAlloc(init.io, path, allocator, .limited(1 << 20))) |text| {
            defer allocator.free(text); // string fields are duped by the parser
            if (mizuchi.daemon.config_boot.loadFromText(allocator, text, srv_cfg, resolver)) |loaded| {
                held = loaded;
                srv_cfg = loaded.config;
                std.debug.print("mizuchi: loaded config from {s}\n", .{path});
            } else |err| {
                std.debug.print("mizuchi: config error in {s} ({s}); using defaults\n", .{ path, @errorName(err) });
            }
        } else |err| {
            std.debug.print("mizuchi: cannot read config {s} ({s}); using defaults\n", .{ path, @errorName(err) });
        }
    }

    const Server = mizuchi.daemon.server.Server;
    var srv = Server.init(allocator, srv_cfg) catch |err| {
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

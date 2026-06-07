//! Mizuchi entry point (M1: Ringlane TCP server).
const std = @import("std");
const builtin = @import("builtin");
const mizuchi = @import("mizuchi");

/// ${VAR} resolver for the config parser — reads the process environment map
/// (Zig 0.16 delivers the environment via `std.process.Init.environ_map`, which
/// we thread through the resolver `ctx`). Returns an owned dupe of the value.
fn envLookup(ctx: ?*anyopaque, allocator: std.mem.Allocator, name: []const u8) anyerror![]const u8 {
    const map: *std.process.Environ.Map = @ptrCast(@alignCast(ctx orelse return error.EnvironmentVariableNotFound));
    const value = map.get(name) orelse return error.EnvironmentVariableNotFound;
    return allocator.dupe(u8, value);
}

/// Services → live-world bridge: a channel registration marks the live channel
/// REGISTERED (+r), materializing it if empty so the reservation persists.
fn svcCreateChannel(ctx: *anyopaque, channel: []const u8) mizuchi.daemon.services.ServiceError!void {
    const srv: *mizuchi.daemon.server.Server = @ptrCast(@alignCast(ctx));
    try srv.markChannelRegistered(channel, true);
}

/// Services → live-world bridge: dropping a registration clears +r so the
/// channel reverts to ephemeral and is reclaimed once empty.
fn svcDropChannel(ctx: *anyopaque, channel: []const u8) mizuchi.daemon.services.ServiceError!void {
    const srv: *mizuchi.daemon.server.Server = @ptrCast(@alignCast(ctx));
    try srv.markChannelRegistered(channel, false);
}

pub fn main(init: std.process.Init) !void {
    std.debug.print(
        \\
        \\  Mizuchi {s}  (水蛟)
        \\  Zig-native mesh IRC daemon — Suimyaku + Tsumugi mesh
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
    if (args.next()) |first| {
        // `mizuchi --supervisor` is the Helix in-process-upgrade successor mode:
        // a fresh image execve'd by an UPGRADE handoff. If the handoff env fds are
        // present we resume from them; otherwise it boots normally. (Full client-fd
        // re-attach is the remaining hardening step — see docs/planning/17.)
        if (std.mem.eql(u8, first, "--supervisor")) {
            if (comptime builtin.os.tag == .linux) {
                if (mizuchi.daemon.helix.live.resumeFromEnv()) |r| {
                    if (r.listen_fd) |lfd| {
                        // Adopt the inherited listening socket so the port stays
                        // bound across the upgrade (no connection-refused window).
                        srv_cfg.inherited_listener_fd = lfd;
                        std.debug.print("mizuchi: Helix resume — adopting listen fd {d}\n", .{lfd});
                    } else {
                        std.debug.print("mizuchi: Helix resume (no listen fd; binding fresh)\n", .{});
                    }
                    // Recover any serialized state capsules from the inherited arena.
                    if (r.arena_fd) |afd| {
                        if (mizuchi.daemon.helix.live.readArena(allocator, afd)) |caps| {
                            defer {
                                for (caps) |*cap| cap.deinit(allocator);
                                allocator.free(caps);
                            }
                            std.debug.print("mizuchi: Helix resume — {d} state capsule(s) recovered\n", .{caps.len});
                        } else |e| {
                            std.debug.print("mizuchi: Helix arena read failed ({s})\n", .{@errorName(e)});
                        }
                    }
                } else {
                    std.debug.print("mizuchi: --supervisor with no Helix handoff env; normal boot\n", .{});
                }
            } else {
                std.debug.print("mizuchi: --supervisor is Linux-only\n", .{});
            }
            // Fall through to a normal boot (config defaults; no config path arg).
        } else
        // `mizuchi acme-issue ...` runs an out-of-band ACME issuance and exits.
        // Linux-only (raw socket syscalls); comptime-gated so non-linux targets
        // never analyze the linux-specific ACME path.
        if (std.mem.eql(u8, first, "acme-issue")) {
            if (comptime builtin.os.tag == .linux) {
                var rest: std.ArrayList([]const u8) = .empty;
                defer rest.deinit(allocator);
                while (args.next()) |a| try rest.append(allocator, a);
                const opts = mizuchi.daemon.acme_cli.parseArgs(rest.items) orelse {
                    mizuchi.daemon.acme_cli.usage();
                    return;
                };
                _ = mizuchi.daemon.acme_cli.runIssue(allocator, init.io, opts) catch |err| {
                    std.debug.print("acme-issue failed: {s}\n", .{@errorName(err)});
                    return;
                };
                return;
            } else {
                std.debug.print("acme-issue is only supported on Linux\n", .{});
                return;
            }
        } else {
            const path = first;
            const resolver = mizuchi.daemon.config_format.Resolver{
            .ctx = init.environ_map,
            .env = envLookup,
        };
        if (std.Io.Dir.cwd().readFileAlloc(init.io, path, allocator, .limited(1 << 20))) |text| {
            defer allocator.free(text); // string fields are duped by the parser
            if (mizuchi.daemon.config_boot.loadFromText(allocator, text, srv_cfg, resolver)) |loaded| {
                held = loaded;
                srv_cfg = loaded.config;
                // Enable live REHASH: the server re-reads this same file/resolver.
                srv_cfg.config_path = path;
                srv_cfg.config_resolver = resolver;
                std.debug.print("mizuchi: loaded config from {s}\n", .{path});
            } else |err| {
                std.debug.print("mizuchi: config error in {s} ({s}); using defaults\n", .{ path, @errorName(err) });
            }
            } else |err| {
                std.debug.print("mizuchi: cannot read config {s} ({s}); using defaults\n", .{ path, @errorName(err) });
            }
        }
    }

    // The platform CSPRNG is always available to the server (session reclaim
    // tokens, etc.); PQ-secured S2S below is the only feature gated on a key.
    srv_cfg.crypto_io = init.io;

    // PQ-secured S2S: if the config supplies node.secret_key, derive this node's
    // Tsumugi identity and enable the secured handshake (TOFU) on S2S links. The
    // identity outlives the server (the server borrows a pointer to it). Without a
    // key, S2S stays plaintext (backward compatible).
    var node_id_holder: ?mizuchi.daemon.node_identity.NodeIdentity = null;
    defer if (node_id_holder) |*n| n.deinit();
    if (held) |h| {
        if (h.parsed.node.secret_key) |sk| {
            if (mizuchi.daemon.node_identity.fromConfig(sk, h.parsed.mesh.realm)) |ident| {
                node_id_holder = ident;
                srv_cfg.node_identity = &node_id_holder.?;
                if (h.parsed.mesh.mesh_pass) |mp| srv_cfg.mesh_pass = mp;
                std.debug.print("mizuchi: PQ-secured S2S enabled (node identity configured)\n", .{});
            } else |err| {
                std.debug.print("mizuchi: node identity error ({s}); S2S stays plaintext\n", .{@errorName(err)});
            }
        }
    }

    // SASL account backend: when `[sasl] account_db` is configured, open the
    // WAL-backed account store and verify SASL PLAIN credentials against it. The
    // store/services/checker live for the server's lifetime (the checker fat
    // pointer is copied into every connection).
    var account_store: ?mizuchi.daemon.services.MizuStore = null;
    defer if (account_store) |*s| s.deinit();
    var account_services: mizuchi.daemon.services.Services = undefined;
    var account_checker: mizuchi.daemon.sasl_bridge.ServicesPlainChecker = undefined;
    if (held) |h| {
        if (h.parsed.sasl.account_db) |db| {
            if (mizuchi.daemon.services.MizuStore.open(allocator, init.io, std.Io.Dir.cwd(), db)) |store| {
                account_store = store;
                account_services = mizuchi.daemon.services.Services.init(&account_store.?, null);
                account_checker = .{ .services = &account_services };
                srv_cfg.sasl_checker = account_checker.checker();
                srv_cfg.account_services = &account_services;
                std.debug.print("mizuchi: SASL account store opened ({s})\n", .{db});
            } else |err| {
                std.debug.print("mizuchi: account store error ({s}); SASL disabled\n", .{@errorName(err)});
            }
        }
    }

    // Hostname cloaking: derive the cloak key from `[cloak] secret` (hashed to
    // 32 bytes), or generate a random per-boot key so a client's real IP is
    // never shown to other users by default.
    var cloak_key_bytes: [mizuchi.proto.cloak.key_len]u8 = undefined;
    if (held) |h| {
        if (h.parsed.cloak.secret) |secret| {
            std.crypto.hash.sha2.Sha256.hash(secret, &cloak_key_bytes, .{});
            srv_cfg.cloak_key = mizuchi.proto.cloak.SecretKey.init(cloak_key_bytes);
        }
    }
    if (srv_cfg.cloak_key == null) {
        init.io.random(&cloak_key_bytes);
        srv_cfg.cloak_key = mizuchi.proto.cloak.SecretKey.init(cloak_key_bytes);
        std.debug.print("mizuchi: cloak key generated (per-boot; set [cloak] secret to persist)\n", .{});
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

    // Drive the SerpentRegistry module init→ready lifecycle now that the server
    // is at its final address (init() returns by value, so `self` is not stable
    // inside it). No-op until a module declares lifecycle fns.
    srv.start();

    // Now that the server (and its live world) exists, attach the services state
    // hook so channel REGISTER/DROP reflects into the world's +r REGISTERED flag.
    if (account_store != null) {
        account_services.state = .{
            .ptr = &srv,
            .create_channel = svcCreateChannel,
            .drop_channel = svcDropChannel,
        };
    }

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

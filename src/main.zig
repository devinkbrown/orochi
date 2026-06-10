//! Orochi entry point (M1: Ringlane TCP server).
const std = @import("std");
const builtin = @import("builtin");
const orochi = @import("orochi");

/// Shared context for the config-string resolver. Both `env:NAME` and
/// `@file:path` indirection run through a single `?*anyopaque` ctx, so it
/// carries everything either lookup needs: the process environment map and an
/// `Io` handle for reading `@file:` payloads off disk.
const ResolverCtx = struct {
    environ_map: *std.process.Environ.Map,
    io: std.Io,
};

/// `env:NAME` resolver for the config parser — reads the process environment map
/// (Zig 0.16 delivers the environment via `std.process.Init.environ_map`, which
/// we thread through the resolver `ctx`). Returns an owned dupe of the value.
fn envLookup(ctx: ?*anyopaque, allocator: std.mem.Allocator, name: []const u8) anyerror![]const u8 {
    const rc: *ResolverCtx = @ptrCast(@alignCast(ctx orelse return error.EnvironmentVariableNotFound));
    const value = rc.environ_map.get(name) orelse return error.EnvironmentVariableNotFound;
    return allocator.dupe(u8, value);
}

/// `@file:path` resolver for the config parser — loads the file's contents
/// (relative to the daemon cwd) as the string value, so secrets and large text
/// blobs (e.g. `[motd] text = "@file:etc/motd.example.txt"`) can live on disk.
fn fileLookup(ctx: ?*anyopaque, allocator: std.mem.Allocator, path: []const u8) anyerror![]const u8 {
    const rc: *ResolverCtx = @ptrCast(@alignCast(ctx orelse return error.FileNotFound));
    return std.Io.Dir.cwd().readFileAlloc(rc.io, path, allocator, .limited(1 << 20));
}

/// Services → live-world bridge: a channel registration marks the live channel
/// REGISTERED (+r), materializing it if empty so the reservation persists.
fn svcCreateChannel(ctx: *anyopaque, channel: []const u8) orochi.daemon.services.ServiceError!void {
    const srv: *orochi.daemon.server.Server = @ptrCast(@alignCast(ctx));
    try srv.markChannelRegistered(channel, true);
}

/// Services → live-world bridge: dropping a registration clears +r so the
/// channel reverts to ephemeral and is reclaimed once empty.
fn svcDropChannel(ctx: *anyopaque, channel: []const u8) orochi.daemon.services.ServiceError!void {
    const srv: *orochi.daemon.server.Server = @ptrCast(@alignCast(ctx));
    try srv.markChannelRegistered(channel, false);
}

pub fn main(init: std.process.Init) !void {
    std.debug.print(
        \\
        \\  Orochi {s}  (大蛇)
        \\  Zig-native mesh IRC daemon — Suimyaku + Tsumugi mesh
        \\
        \\
    , .{orochi.version});

    const allocator = init.gpa;

    // Resolver context for `env:`/`@file:` config indirection. Lives on `main`'s
    // frame for the whole process, so the resolver stored on the live config
    // (used by REHASH) never dangles.
    var resolver_ctx = ResolverCtx{ .environ_map = init.environ_map, .io = init.io };

    // Default config (6680; 6667/6697 belong to the local eshmaki server). A
    // config file path may be passed as argv[1]: present values override the
    // defaults; a missing/invalid file keeps defaults (boot never fails on it).
    var srv_cfg = orochi.daemon.server.Config{ .port = 6680 };
    var held: ?orochi.daemon.config_boot.Loaded = null;
    defer if (held) |*h| h.deinit(allocator);

    var args = try std.process.Args.iterateAllocator(init.minimal.args, allocator);
    defer args.deinit(); // no-op on POSIX, frees the arg buffer on Windows/WASI
    _ = args.skip(); // argv[0]
    if (args.next()) |first| {
        // `orochi --supervisor` is the Helix in-process-upgrade successor mode:
        // a fresh image execve'd by an UPGRADE handoff. If the handoff env fds are
        // present we resume from them; otherwise it boots normally. (Full client-fd
        // re-attach is the remaining hardening step — see docs/planning/17.)
        if (std.mem.eql(u8, first, "--supervisor")) {
            if (comptime builtin.os.tag == .linux) {
                if (orochi.daemon.helix.live.resumeFromEnv()) |r| {
                    if (r.listen_fd) |lfd| {
                        // Adopt the inherited listening socket so the port stays
                        // bound across the upgrade (no connection-refused window).
                        srv_cfg.inherited_listener_fd = lfd;
                        std.debug.print("orochi: Helix resume — adopting listen fd {d}\n", .{lfd});
                    } else {
                        std.debug.print("orochi: Helix resume (no listen fd; binding fresh)\n", .{});
                    }
                    // Hand the inherited state arena to the server, which reads it
                    // after boot and re-attaches the carried-over client connections.
                    if (r.arena_fd) |afd| srv_cfg.resume_arena_fd = afd;
                } else {
                    std.debug.print("orochi: --supervisor with no Helix handoff env; normal boot\n", .{});
                }
            } else {
                std.debug.print("orochi: --supervisor is Linux-only\n", .{});
            }
            // Fall through to a normal boot (config defaults; no config path arg).
        } else
        // `orochi acme-issue ...` runs an out-of-band ACME issuance and exits.
        // Linux-only (raw socket syscalls); comptime-gated so non-linux targets
        // never analyze the linux-specific ACME path.
        if (std.mem.eql(u8, first, "acme-issue")) {
            if (comptime builtin.os.tag == .linux) {
                var rest: std.ArrayList([]const u8) = .empty;
                defer rest.deinit(allocator);
                while (args.next()) |a| try rest.append(allocator, a);
                const opts = orochi.daemon.acme_cli.parseArgs(rest.items) orelse {
                    orochi.daemon.acme_cli.usage();
                    return;
                };
                _ = orochi.daemon.acme_cli.runIssue(allocator, init.io, opts) catch |err| {
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
            const resolver = orochi.daemon.config_format.Resolver{
            .ctx = @ptrCast(&resolver_ctx),
            .env = envLookup,
            .file = fileLookup,
        };
        if (std.Io.Dir.cwd().readFileAlloc(init.io, path, allocator, .limited(1 << 20))) |text| {
            defer allocator.free(text); // string fields are duped by the parser
            if (orochi.daemon.config_boot.loadFromText(allocator, text, srv_cfg, resolver)) |loaded| {
                held = loaded;
                srv_cfg = loaded.config;
                // Carry the requested reactor-shard count onto the live config
                // ([limits].num_shards lifts via the boot projection).
                srv_cfg.num_shards = loaded.num_shards;
                // Enable live REHASH: the server re-reads this same file/resolver.
                srv_cfg.config_path = path;
                srv_cfg.config_resolver = resolver;
                std.debug.print("orochi: loaded config from {s}\n", .{path});
            } else |err| {
                std.debug.print("orochi: config error in {s} ({s}); using defaults\n", .{ path, @errorName(err) });
            }
            } else |err| {
                std.debug.print("orochi: cannot read config {s} ({s}); using defaults\n", .{ path, @errorName(err) });
            }
        }
    }

    // The platform CSPRNG is always available to the server (session reclaim
    // tokens, etc.); PQ-secured S2S below is the only feature gated on a key.
    srv_cfg.crypto_io = init.io;

    // Install the configured network name before building ISUPPORT, so the
    // NETWORK= token and the welcome burst both reflect it. Write-once at boot.
    orochi.proto.protocol_inventory.setNetworkName(srv_cfg.network_name);
    // Advertise config-driven length limits (TOPICLEN) in ISUPPORT. Built once
    // here, before any connection is served; owned for the process lifetime.
    if (orochi.daemon.server.buildIsupportTokens(allocator, srv_cfg)) |tokens| {
        orochi.proto.protocol_inventory.setIsupportOverride(tokens);
    } else |_| {}
    // NICKLEN is enforced in the pre-registration dispatch path, which reads the
    // runtime-limits holder rather than a config handle.
    orochi.proto.protocol_inventory.setRuntimeLimits(.{ .nicklen = srv_cfg.nicklen });

    // PQ-secured S2S: if the config supplies node.secret_key, derive this node's
    // Tsumugi identity and enable the secured handshake (TOFU) on S2S links. The
    // identity outlives the server (the server borrows a pointer to it). Without a
    // key, S2S stays plaintext (backward compatible).
    var node_id_holder: ?orochi.daemon.node_identity.NodeIdentity = null;
    defer if (node_id_holder) |*n| n.deinit();
    if (held) |h| {
        if (h.parsed.node.secret_key) |sk| {
            if (orochi.daemon.node_identity.fromConfig(sk, h.parsed.mesh.realm)) |ident| {
                node_id_holder = ident;
                srv_cfg.node_identity = &node_id_holder.?;
                if (h.parsed.mesh.mesh_pass) |mp| srv_cfg.mesh_pass = mp;
                std.debug.print("orochi: PQ-secured S2S enabled (node identity configured)\n", .{});
            } else |err| {
                std.debug.print("orochi: node identity error ({s}); S2S stays plaintext\n", .{@errorName(err)});
            }
        }
    }

    // SASL account backend: when `[sasl] account_db` is configured, open the
    // WAL-backed account store and verify SASL PLAIN credentials against it. The
    // store/services/checker live for the server's lifetime (the checker fat
    // pointer is copied into every connection).
    var account_store: ?orochi.daemon.services.OroStore = null;
    defer if (account_store) |*s| s.deinit();
    var account_services: orochi.daemon.services.Services = undefined;
    var account_checker: orochi.daemon.sasl_bridge.ServicesPlainChecker = undefined;
    var external_bridge: orochi.daemon.sasl_bridge.ServicesExternalLookup = undefined;
    // SCRAM-SHA-256 credential mirror: provisioned alongside each account so a
    // client can authenticate without sending its password. Must outlive the
    // server (the lookup fat-pointer captures &scram_store).
    var scram_store = orochi.daemon.scram_store.ScramStore.init(allocator);
    defer scram_store.deinit();
    // Account ⇄ TLS certfp bindings for SASL EXTERNAL (CERTADD); outlives server.
    var certfp_binds = orochi.daemon.certfp_bind.CertfpBindStore.init(allocator);
    defer certfp_binds.deinit();
    if (held) |h| {
        if (h.parsed.sasl.account_db) |db| {
            if (orochi.daemon.services.OroStore.open(allocator, init.io, std.Io.Dir.cwd(), db)) |store| {
                account_store = store;
                account_services = orochi.daemon.services.Services.init(&account_store.?, null);
                account_services.attachScramStore(&scram_store);
                account_services.attachCertfpBinds(&certfp_binds);
                // Backfill SCRAM credentials from the durable mirror on a miss,
                // so a SCRAM-SHA-256 login resolves after a restart.
                scram_store.setLoader(account_services.scramLoader());
                account_checker = .{ .services = &account_services };
                external_bridge = .{ .services = &account_services };
                srv_cfg.sasl_checker = account_checker.checker();
                srv_cfg.sasl_scram256 = scram_store.scram256Lookup();
                srv_cfg.sasl_external = external_bridge.lookup();
                srv_cfg.account_services = &account_services;
                std.debug.print("orochi: SASL account store opened ({s}); PLAIN + SCRAM-SHA-256 + EXTERNAL live\n", .{db});
            } else |err| {
                std.debug.print("orochi: account store error ({s}); SASL disabled\n", .{@errorName(err)});
            }
        }
    }

    // Hostname cloaking: derive the cloak key from `[cloak] secret` (hashed to
    // 32 bytes), or generate a random per-boot key so a client's real IP is
    // never shown to other users by default.
    var cloak_key_bytes: [orochi.proto.cloak.key_len]u8 = undefined;
    if (held) |h| {
        if (h.parsed.cloak.secret) |secret| {
            std.crypto.hash.sha2.Sha256.hash(secret, &cloak_key_bytes, .{});
            srv_cfg.cloak_key = orochi.proto.cloak.SecretKey.init(cloak_key_bytes);
        }
    }
    if (srv_cfg.cloak_key == null) {
        init.io.random(&cloak_key_bytes);
        srv_cfg.cloak_key = orochi.proto.cloak.SecretKey.init(cloak_key_bytes);
        std.debug.print("orochi: cloak key generated (per-boot; set [cloak] secret to persist)\n", .{});
    }

    // Implicit-TLS client listener: when `[tls] enabled`, load the configured
    // cert/key (or mint a self-signed bootstrap leaf) and stand up the TLS
    // listener. The chain bytes + signing key live for the server's lifetime
    // (server.Config borrows them). No STARTTLS — this is a separate TLS port.
    var tls_loaded: ?orochi.daemon.tls_certs.Loaded = null;
    defer if (tls_loaded) |*t| t.deinit(allocator);
    if (held) |h| {
        if (h.tls.enabled) {
            if (orochi.daemon.tls_certs.loadOrBootstrap(allocator, init.io, .{
                .enabled = true,
                .cert_path = h.tls.cert_path,
                .key_path = h.tls.key_path,
                .dns_name = h.tls.dns_name,
            })) |loaded| {
                tls_loaded = loaded;
                srv_cfg.tls_port = h.tls.port;
                srv_cfg.tls_cert_chain = tls_loaded.?.cert_chain;
                srv_cfg.tls_signing_key = tls_loaded.?.signing_key;
                srv_cfg.tls_request_client_cert = h.tls.request_client_cert;
                std.debug.print("orochi: TLS listener enabled on port {d}\n", .{h.tls.port});
            } else |err| {
                std.debug.print("orochi: TLS cert error ({s}); TLS disabled\n", .{@errorName(err)});
            }
        }
    }

    // IRCv3 STS: when an operator enables `[sts]` AND a TLS listener is live,
    // build the advertised wire value so each session's `sts` cap is offered.
    // STS without a live TLS port would strand clients, so require both.
    var sts_value_buf: [orochi.proto.sts.MAX_VALUE_LEN]u8 = undefined;
    if (held) |h| {
        if (h.sts.enabled) {
            if (srv_cfg.tls_cert_chain.len != 0) {
                const policy = orochi.proto.sts_policy.Policy{
                    .duration_seconds = h.sts.duration,
                    .port = h.sts.port,
                    .preload = h.sts.preload,
                };
                if (orochi.proto.sts_policy.writeCapValue(policy, .combined, &sts_value_buf)) |value| {
                    srv_cfg.sts_value = value;
                    std.debug.print("orochi: STS advertised ({s})\n", .{value});
                } else |err| {
                    std.debug.print("orochi: STS value error ({s}); STS disabled\n", .{@errorName(err)});
                }
            } else {
                std.debug.print("orochi: [sts] enabled but no TLS listener; STS NOT advertised\n", .{});
            }
        }
    }

    const Server = orochi.daemon.server.Server;
    var srv = Server.init(allocator, srv_cfg) catch |err| {
        // io_uring unavailable (old kernel / sandbox): fall back to the DST boot banner.
        std.debug.print("orochi: server unavailable ({s}); boot-only.\n", .{@errorName(err)});
        var sys = orochi.substrate.SystemReactor.init();
        var d = orochi.daemon.Daemon.init(sys.reactor());
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

    // Helix UPGRADE successor: re-attach the carried-over client connections
    // (inherited socket fds + restored sessions) now that the ring exists.
    if (comptime builtin.os.tag == .linux) srv.adoptInheritedSessions();

    std.debug.print(
        "orochi: listening on 127.0.0.1:{d} (Ringlane io_uring) — PING + registration live\n",
        .{try srv.boundPort()},
    );
    while (true) {
        srv.runOnce() catch |err| {
            std.debug.print("orochi: runOnce error: {s}\n", .{@errorName(err)});
            return err;
        };
    }
}

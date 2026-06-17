//! Boot glue: map a parsed `config_format.Config` onto the runtime
//! `server.Config`, and load it from a settings file at startup.
//!
//! The daemon previously hardcoded its listen port and ignored config entirely;
//! this wires the (most complete) config parser into the boot path. Mapping is
//! conservative — a field is overridden only when the config supplies a
//! meaningful value, otherwise the caller's defaults stand.
const std = @import("std");

const config_format = @import("config_format.zig");
const server = @import("server.zig");
const oper_mod = @import("oper.zig");
const conn_class = @import("conn_class.zig");
const og_mod = @import("operator_groups.zig");
const event_spine = @import("event_spine.zig");
const kagura_frame = @import("../substrate/kagura_frame.zig");
const media_session = @import("../substrate/media_session.zig");

/// Overlay non-empty/non-zero config values onto `base` (which carries defaults).
/// `cfg`'s string fields (e.g. host) are borrowed — keep `cfg` alive as long as
/// the returned Config is used.
pub fn mapToServerConfig(cfg: config_format.Config, base: server.Config) server.Config {
    var out = base;
    if (cfg.network.name.len != 0) out.network_name = cfg.network.name;
    if (cfg.network.server_name) |v| out.server_name = v;
    if (cfg.network.description) |v| {
        if (v.len != 0) out.server_description = v;
    }
    if (cfg.network.icon_url) |v| {
        if (v.len != 0) out.network_icon_url = v;
    }
    if (cfg.motd.text) |t| out.motd_text_raw = t;
    if (cfg.admin.location.len != 0) out.admin_location = cfg.admin.location;
    if (cfg.admin.email.len != 0) out.admin_email = cfg.admin.email;
    out.weather_enabled = cfg.weather.enabled;
    if (cfg.weather.location) |v| out.weather_location = v;
    if (cfg.weather.country) |v| out.weather_country = v;
    if (cfg.weather.units) |v| out.weather_units = v;
    if (cfg.weather.source) |v| out.weather_source = v;
    out.news_enabled = cfg.news.enabled;
    if (cfg.news.source) |v| out.news_source = v;
    out.news_count = cfg.news.count;
    out.geo_enabled = cfg.geo.enabled;
    out.geo_news_insecure_tls = cfg.geo.news_insecure_tls;
    out.geo_cmd_cooldown_ms = cfg.geo.cmd_cooldown_ms;
    if (cfg.geo.default_location) |v| out.geo_default_location = v;
    if (cfg.geo.news_cache_dir) |v| out.geo_news_cache_dir = v;
    if (cfg.oper.grants_path) |v| out.oper_grants_path = v;
    if (cfg.listen.irc != 0) out.port = cfg.listen.irc;
    if (cfg.listen.host.len != 0) out.host = cfg.listen.host;
    if (cfg.listen.s2s != 0) out.s2s_port = cfg.listen.s2s;
    if (cfg.listen.webtransport != 0) out.webtransport_port = cfg.listen.webtransport;
    out.proxy_protocol_enabled = cfg.listen.proxy_protocol;
    if (cfg.listen.trusted_proxies.len != 0) out.trusted_proxies = cfg.listen.trusted_proxies;
    if (cfg.listen.ws != 0) {
        // Secure-WebSocket browser listener intent. The live listener only
        // stands up once main.zig has loaded the TLS certificate (or in the
        // testing-only `ws_plain` mode) — see server.initReactor's gate.
        out.ws_enabled = true;
        out.ws_port = cfg.listen.ws;
        out.ws_allow_plain = cfg.listen.ws_plain;
    }
    if (cfg.listen.media != 0) out.media_port = cfg.listen.media;
    if (cfg.listen.native_media != 0) out.native_media_port = cfg.listen.native_media;
    if (cfg.listen.media_host.len != 0) out.media_host = cfg.listen.media_host;
    out.media_enabled = cfg.media.enabled;
    if (!out.media_enabled) out.disabled_features = &.{"media"};
    out.media_max_upload_bytes = cfg.media.max_upload_bytes;
    out.media_max_frame_bytes = cfg.media.max_frame_bytes;
    out.media_reorder_window_frames = cfg.media.reorder_window_frames;
    out.media_max_participants = cfg.media.max_participants;
    out.native_media_require_mac = cfg.media.native_media_require_mac;
    if (cfg.media.stun_host) |h| out.media_stun_host = h;
    if (cfg.media.stun_port != 0) out.media_stun_port = cfg.media.stun_port;
    if (cfg.stats.dir.len != 0) out.stats_web_dir = cfg.stats.dir;
    if (cfg.stats.interval_ms != 0) out.stats_interval_ms = cfg.stats.interval_ms;
    // [metrics] — live Prometheus /metrics endpoint. Off unless a port is set;
    // the bind defaults to loopback and is only widened by an explicit address.
    if (cfg.metrics.listen != 0) {
        out.metrics_port = cfg.metrics.listen;
        if (parseIp4Host(cfg.metrics.bind)) |addr| out.metrics_bind_addr = addr;
    }
    if (cfg.geoip.database.len != 0) out.geoip_db_path = cfg.geoip.database;
    if (cfg.geoip.asn_database.len != 0) out.geoip_asn_db_path = cfg.geoip.asn_database;
    out.backlog = cfg.limits.backlog;
    out.max_clients = cfg.limits.max_clients;
    out.topiclen = cfg.limits.topiclen;
    out.awaylen = cfg.limits.awaylen;
    out.kicklen = cfg.limits.kicklen;
    out.nicklen = cfg.limits.nicklen;
    out.channellen = cfg.limits.channellen;
    out.maxlist = cfg.limits.maxlist;
    out.chanlimit = cfg.limits.chanlimit;
    out.maxtargets = cfg.limits.maxtargets;
    out.monitorlimit = cfg.limits.monitorlimit;
    out.silencelimit = cfg.limits.silencelimit;
    if (cfg.limits.handshake_timeout_ms != 0) out.registration_timeout_ms = @intCast(cfg.limits.handshake_timeout_ms);
    if (cfg.limits.ping_interval_ms != 0) out.ping_interval_ms = @intCast(cfg.limits.ping_interval_ms);
    if (cfg.limits.ping_timeout_ms != 0) out.ping_timeout_ms = @intCast(cfg.limits.ping_timeout_ms);
    out.max_clones_per_ip = cfg.limits.max_clones_per_ip;
    out.max_clones_per_net = cfg.limits.max_clones_per_net;
    out.reputation_refuse_threshold = cfg.limits.reputation_refuse_threshold;
    if (cfg.limits.reputation_half_life_ms != 0) out.reputation_half_life_ms = @intCast(cfg.limits.reputation_half_life_ms);
    if (cfg.limits.sweep_interval_ms != 0) out.sweep_interval_ms = @intCast(cfg.limits.sweep_interval_ms);
    out.ring_entries = @intCast(cfg.io.ring_entries);
    out.reg_timeout_penalty = cfg.reputation.registration_timeout_penalty;
    out.clone_refuse_penalty = cfg.reputation.clone_refuse_penalty;
    out.session_max_accounts = cfg.sessions.max_accounts;
    out.session_max_per_account = cfg.sessions.max_per_account;
    if (cfg.node.id != 0) out.node_id = cfg.node.id;
    if (cfg.mesh.trust_roots.len != 0) out.mesh_trust_roots = cfg.mesh.trust_roots;
    out.sasl_enabled = cfg.sasl.enabled or !cfg.sasl.enabled_explicit;
    if (cfg.sasl.realm) |realm| out.sasl_realm = realm;
    out.sasl_allow_anonymous = cfg.sasl.allow_anonymous;
    // [mesh].connect — peers this node auto-dials at boot (strings borrow cfg).
    if (cfg.mesh.connect.len != 0) out.mesh_connect = cfg.mesh.connect;
    return out;
}

/// Parse a dotted-quad IPv4 literal into a host-byte-order u32 (e.g. "127.0.0.1"
/// → 0x7f00_0001). Returns null on any malformed input so the caller keeps its
/// secure loopback default rather than binding an unexpected address.
fn parseIp4Host(s: []const u8) ?u32 {
    var octets: [4]u8 = undefined;
    var it = std.mem.splitScalar(u8, s, '.');
    var i: usize = 0;
    while (it.next()) |part| : (i += 1) {
        if (i >= 4) return null;
        octets[i] = std.fmt.parseInt(u8, part, 10) catch return null;
    }
    if (i != 4) return null;
    return (@as(u32, octets[0]) << 24) | (@as(u32, octets[1]) << 16) |
        (@as(u32, octets[2]) << 8) | @as(u32, octets[3]);
}

test "parseIp4Host parses loopback and rejects junk" {
    try std.testing.expectEqual(@as(?u32, 0x7f00_0001), parseIp4Host("127.0.0.1"));
    try std.testing.expectEqual(@as(?u32, 0x0000_0000), parseIp4Host("0.0.0.0"));
    try std.testing.expectEqual(@as(?u32, 0xc0a8_0101), parseIp4Host("192.168.1.1"));
    try std.testing.expectEqual(@as(?u32, null), parseIp4Host("127.0.0"));
    try std.testing.expectEqual(@as(?u32, null), parseIp4Host("not-an-ip"));
    try std.testing.expectEqual(@as(?u32, null), parseIp4Host("256.0.0.1"));
}

/// Neutral STS boot projection consumed by `main.zig` to enable IRCv3 STS per
/// session. This struct deliberately holds no wire/policy values — `main.zig`
/// owns the `proto/sts_policy.zig` build + per-session `enableSts` call; here we
/// only surface the parsed `[sts]` config so the boot path stays decoupled.
pub const StsBootConfig = struct {
    enabled: bool = false,
    duration: u32 = 2_592_000,
    port: u16 = 6697,
    preload: bool = false,
};

/// Project the parsed `[sts]` config onto the neutral boot struct. Unlike
/// `mapToServerConfig`, this copies fields verbatim (no zero-means-default
/// overlay): the parser already carries the secure defaults when `[sts]` is
/// omitted, so `main.zig` reads an authoritative snapshot.
pub fn mapStsBootConfig(cfg: config_format.Config) StsBootConfig {
    return .{
        .enabled = cfg.sts.enabled,
        .duration = cfg.sts.duration,
        .port = cfg.sts.port,
        .preload = cfg.sts.preload,
    };
}

/// Parse `text` and overlay it onto `base`. Returns the mapped Config plus the
/// owned parsed config (caller must `deinit` it AFTER it is done using the
/// returned Config, since string fields are borrowed). On parse failure returns
/// the error and, when available, fills `diag_out`.
/// Neutral projection of the `[tls]` section for the boot layer. `server.Config`
/// has no TLS fields (and is owned by another module), so the parsed TLS intent
/// rides alongside the mapped server config here; `main.zig` consumes it to drive
/// `tls_certs.loadOrBootstrap` and the (separately wired) TLS listener. String
/// fields borrow `parsed` — keep the owning `Loaded` alive while they are used.
pub const TlsBootConfig = struct {
    enabled: bool = false,
    port: u16 = 6697,
    cert_path: ?[]const u8 = null,
    key_path: ?[]const u8 = null,
    dns_name: []const u8 = "localhost",
    request_client_cert: bool = false,
    enable_tls12: bool = false,
    enable_resumption: bool = false,
    early_data_max_size: u32 = 0,
};

/// Project the parsed `[tls]` section onto the neutral boot struct. Borrows
/// `cfg`'s string fields; keep `cfg` alive as long as the result is used.
pub fn mapTlsBootConfig(cfg: config_format.Config) TlsBootConfig {
    return .{
        .enabled = cfg.tls.enabled,
        .port = cfg.tls.port,
        .cert_path = cfg.tls.cert_path,
        .key_path = cfg.tls.key_path,
        .dns_name = cfg.tls.dns_name,
        .request_client_cert = cfg.tls.request_client_cert,
        .enable_tls12 = cfg.tls.enable_tls12,
        .enable_resumption = cfg.tls.enable_resumption,
        .early_data_max_size = cfg.tls.early_data_max_size,
    };
}

/// Neutral boot projection for the in-daemon ACME renewal scheduler. Strings
/// borrow `cfg`; keep the parsed config alive while the scheduler is running.
pub const AcmeBootConfig = struct {
    enabled: bool = false,
    directory_url: []const u8 = config_format.acme_default_directory_url,
    domain: ?[]const u8 = null,
    contact: ?[]const u8 = null,
    renew_before_days: u16 = 30,
    check_interval_ms: u64 = 12 * 60 * 60 * 1000,
};

pub fn mapAcmeBootConfig(cfg: config_format.Config) AcmeBootConfig {
    return .{
        .enabled = cfg.acme.enabled,
        .directory_url = cfg.acme.directory_url,
        .domain = cfg.acme.domain,
        .contact = cfg.acme.contact,
        .renew_before_days = cfg.acme.renew_before_days,
        .check_interval_ms = cfg.acme.check_interval_ms,
    };
}

pub const Loaded = struct {
    config: server.Config,
    parsed: config_format.Config,
    /// Owned oper bindings backing `config.oper_registry` (strings borrow `parsed`).
    oper_bindings: []oper_mod.OperBinding = &.{},
    /// Parsed `[tls]` intent (strings borrow `parsed`); the live listener and
    /// certificate loading are wired by `main.zig`, not here.
    tls: TlsBootConfig = .{},
    /// Parsed `[acme]` renewal intent (strings borrow `parsed`); main owns the
    /// scheduler lifetime because it needs the live server pointer.
    acme: AcmeBootConfig = .{},
    /// Neutral IRCv3 STS boot projection; `main.zig` consumes this to enable STS.
    sts: StsBootConfig = .{},
    /// Number of worker reactor shards to spin up (`ReactorPool` size). 1 = the
    /// single-reactor model. `server.Config` carries no thread-topology field,
    /// so the parsed `[limits].num_shards` rides here for `main.zig` to consume.
    num_shards: u16 = 1,

    pub fn deinit(self: *Loaded, allocator: std.mem.Allocator) void {
        allocator.free(self.oper_bindings);
        if (self.config.class_registry) |*r| r.deinit();
        self.parsed.deinit(allocator);
        self.* = undefined;
    }
};

pub fn loadFromText(
    allocator: std.mem.Allocator,
    text: []const u8,
    base: server.Config,
    resolver: config_format.Resolver,
) !Loaded {
    var parsed = try config_format.parseToml(allocator, text, resolver);
    errdefer parsed.deinit(allocator);

    // Role-based operator groups: build a transient registry from `[[oper_groups]]`
    // (each a named privilege set, optionally inheriting another). An oper's
    // privileges are then resolved from its `class` group; an oper whose class
    // names no group falls back to full privileges (back-compatible default).
    var groups = og_mod.Registry.init();
    defer groups.deinit(allocator);
    for (parsed.oper_groups) |g| {
        var pbuf: [32]oper_mod.Privilege = undefined;
        var pn: usize = 0;
        for (g.privileges) |ps| {
            if (std.meta.stringToEnum(oper_mod.Privilege, ps)) |p| {
                if (pn < pbuf.len) {
                    pbuf[pn] = p;
                    pn += 1;
                }
            }
        }
        groups.add(allocator, g.name, oper_mod.OperPrivileges.initMany(pbuf[0..pn]), if (g.inherits.len > 0) g.inherits else null) catch {};
    }

    // Build the SASL-only operator registry from `[[opers]]` blocks.
    var bindings: std.ArrayList(oper_mod.OperBinding) = .empty;
    errdefer bindings.deinit(allocator);
    for (parsed.opers) |o| {
        if (o.class.len == 0 or groups.get(o.class) == null) {
            std.debug.print("orochi: skipping oper binding for account '{s}': unknown or empty class\n", .{o.account});
            continue;
        }
        const privileges = groups.effectivePrivileges(o.class);
        if (privileges.count() == 0) {
            std.debug.print("orochi: skipping oper binding for account '{s}': class '{s}' has no privileges\n", .{ o.account, o.class });
            continue;
        }
        try bindings.append(allocator, .{
            .account_name = o.account,
            .class_name = o.class,
            .privileges = privileges,
            .title = o.title,
            .presubscribe_bits = event_spine.categoryMaskFromTokens(o.presubscribe).bits,
        });
    }
    const oper_bindings = try bindings.toOwnedSlice(allocator);

    var config = mapToServerConfig(parsed, base);
    if (oper_bindings.len != 0) {
        config.oper_registry = try oper_mod.OperRegistry.init(oper_bindings);
    }
    // Build the connection-class registry from `[class.*]`. A malformed class is
    // skipped with a warning rather than aborting boot; the registry always ends
    // up with at least the built-in `user`/`server` fallbacks. The registry value
    // lives on `config` (a copy reaches the daemon, sharing the heap); `Loaded`
    // owns the allocation and frees it once in `deinit` — mirroring oper_registry.
    {
        var cb = conn_class.Builder.init(allocator);
        errdefer cb.deinit();
        for (parsed.classes) |c| {
            cb.add(.{
                .name = c.name,
                .policy = c.policy,
                .cidr_texts = c.match_texts,
                .tls_only = c.match_tls,
                .account_only = c.match_account,
                .oper_only = c.match_oper,
                .ident_glob = c.ident_glob,
                .host_glob = c.host_glob,
            }) catch |e| std.debug.print("orochi: skipping connection class '{s}': {s}\n", .{ c.name, @errorName(e) });
        }
        config.class_registry = try cb.finish();
    }
    return .{
        .config = config,
        .parsed = parsed,
        .oper_bindings = oper_bindings,
        .tls = mapTlsBootConfig(parsed),
        .acme = mapAcmeBootConfig(parsed),
        .sts = mapStsBootConfig(parsed),
        .num_shards = parsed.limits.num_shards,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "config text overlays the server config" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 42
        \\[listen]
        \\host = "10.0.0.5"
        \\irc = 6700
        \\s2s = 7700
        \\webtransport = 4433
        \\proxy_protocol = true
        \\trusted_proxies = ["127.0.0.1"]
        \\[limits]
        \\max_clients = 2048
        \\[mesh]
        \\trust_roots = ["0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"]
        \\connect = ["ircx.us:6900"]
        \\[media]
        \\enabled = true
        \\max_upload_bytes = 12345
        \\max_frame_bytes = 1200
        \\reorder_window_frames = 32
        \\max_participants = 2
        \\native_media_require_mac = true
        \\[sasl]
        \\enabled = false
        \\realm = "ircxnet"
        \\
    ;
    const base = server.Config{ .port = 6680 };
    var loaded = try loadFromText(allocator, text, base, .{});
    defer loaded.deinit(allocator);

    try testing.expectEqual(@as(u16, 6700), loaded.config.port);
    try testing.expectEqualStrings("10.0.0.5", loaded.config.host);
    try testing.expectEqual(@as(u16, 7700), loaded.config.s2s_port);
    try testing.expectEqual(@as(u16, 4433), loaded.config.webtransport_port);
    try testing.expect(loaded.config.proxy_protocol_enabled);
    try testing.expectEqual(@as(usize, 1), loaded.config.trusted_proxies.len);
    try testing.expectEqualStrings("127.0.0.1", loaded.config.trusted_proxies[0]);
    try testing.expectEqual(@as(u64, 42), loaded.config.node_id);
    try testing.expectEqual(@as(u31, 2048), loaded.config.max_clients);
    try testing.expectEqual(@as(usize, 1), loaded.config.mesh_trust_roots.len);
    try testing.expectEqual(@as(usize, 1), loaded.config.mesh_connect.len);
    try testing.expectEqualStrings("ircx.us:6900", loaded.config.mesh_connect[0]);
    try testing.expect(loaded.config.media_enabled);
    try testing.expectEqual(@as(u64, 12345), loaded.config.media_max_upload_bytes);
    try testing.expectEqual(@as(u64, 1200), loaded.config.media_max_frame_bytes);
    try testing.expectEqual(@as(u32, 32), loaded.config.media_reorder_window_frames);
    try testing.expectEqual(@as(usize, 2), loaded.config.media_max_participants);
    const reassembly_cfg = server.mediaReassemblyConfig(loaded.config);
    try testing.expectEqual(@as(u32, 32), reassembly_cfg.window);
    var rx = media_session.Receiver(media_session.default_max_payload_bytes, kagura_frame.window_cap).init(reassembly_cfg);
    _ = &rx;
    try testing.expect(loaded.config.native_media_require_mac);
    try testing.expect(!loaded.config.sasl_enabled);
    try testing.expectEqualStrings("ircxnet", loaded.config.sasl_realm);
}

test "media listen overlays media port and candidate host" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\media = 7820
        \\media_host = "203.0.113.5"
        \\
    ;
    var loaded = try loadFromText(allocator, text, .{ .port = 6680 }, .{});
    defer loaded.deinit(allocator);
    try testing.expectEqual(@as(u16, 7820), loaded.config.media_port);
    try testing.expectEqualStrings("203.0.113.5", loaded.config.media_host);
}

test "media enabled maps to server gate and disabled feature" {
    const allocator = testing.allocator;

    var disabled = try loadFromText(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[media]
        \\enabled = false
        \\
    , .{ .port = 6680 }, .{});
    defer disabled.deinit(allocator);
    try testing.expect(!disabled.config.media_enabled);
    try testing.expectEqual(@as(usize, 1), disabled.config.disabled_features.len);
    try testing.expectEqualStrings("media", disabled.config.disabled_features[0]);

    var enabled = try loadFromText(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[media]
        \\enabled = true
        \\
    , .{ .port = 6680 }, .{});
    defer enabled.deinit(allocator);
    try testing.expect(enabled.config.media_enabled);
    try testing.expectEqual(@as(usize, 0), enabled.config.disabled_features.len);
}

test "media stun server overlays discovery config" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[media]
        \\stun_host = "198.51.100.9"
        \\stun_port = 3478
        \\
    ;
    var loaded = try loadFromText(allocator, text, .{ .port = 6680 }, .{});
    defer loaded.deinit(allocator);
    try testing.expectEqualStrings("198.51.100.9", loaded.config.media_stun_host);
    try testing.expectEqual(@as(u16, 3478), loaded.config.media_stun_port);
}

test "limits durations overlay timeout knobs" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[limits]
        \\handshake_timeout = "15s"
        \\ping_interval = "90s"
        \\ping_timeout = "45s"
        \\
    ;
    var loaded = try loadFromText(allocator, text, .{ .port = 6680 }, .{});
    defer loaded.deinit(allocator);
    try testing.expectEqual(@as(i64, 15_000), loaded.config.registration_timeout_ms);
    try testing.expectEqual(@as(i64, 90_000), loaded.config.ping_interval_ms);
    try testing.expectEqual(@as(i64, 45_000), loaded.config.ping_timeout_ms);
}

test "limits overlay clone caps" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[limits]
        \\max_clones_per_ip = 4
        \\max_clones_per_net = 32
        \\
    ;
    var loaded = try loadFromText(allocator, text, .{ .port = 6680 }, .{});
    defer loaded.deinit(allocator);
    try testing.expectEqual(@as(u32, 4), loaded.config.max_clones_per_ip);
    try testing.expectEqual(@as(u32, 32), loaded.config.max_clones_per_net);
}

test "limits overlay reputation knobs" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[limits]
        \\reputation_refuse_threshold = 120
        \\reputation_half_life = "90s"
        \\
    ;
    var loaded = try loadFromText(allocator, text, .{ .port = 6680 }, .{});
    defer loaded.deinit(allocator);
    try testing.expectEqual(@as(u32, 120), loaded.config.reputation_refuse_threshold);
    try testing.expectEqual(@as(i64, 90_000), loaded.config.reputation_half_life_ms);
}

test "num_shards lifts onto the boot config and defaults to 1" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[limits]
        \\num_shards = 4
        \\
    ;
    var loaded = try loadFromText(allocator, text, .{ .port = 6680 }, .{});
    defer loaded.deinit(allocator);
    try testing.expectEqual(@as(u16, 4), loaded.num_shards);

    // Omitted -> single reactor.
    var dflt = try loadFromText(allocator, "[node]\nid=1\n[listen]\nirc=6680\n", .{ .port = 6680 }, .{});
    defer dflt.deinit(allocator);
    try testing.expectEqual(@as(u16, 1), dflt.num_shards);
}

test "acme section lifts onto the boot config" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[acme]
        \\enabled = true
        \\directory_url = "https://acme.example/directory"
        \\domain = "irc.example.test"
        \\contact = "mailto:admin@example.test"
        \\renew_before_days = 15
        \\check_interval = "2h"
        \\
    ;
    var loaded = try loadFromText(allocator, text, .{ .port = 6680 }, .{});
    defer loaded.deinit(allocator);

    try testing.expect(loaded.acme.enabled);
    try testing.expectEqualStrings("https://acme.example/directory", loaded.acme.directory_url);
    try testing.expectEqualStrings("irc.example.test", loaded.acme.domain.?);
    try testing.expectEqualStrings("mailto:admin@example.test", loaded.acme.contact.?);
    try testing.expectEqual(@as(u16, 15), loaded.acme.renew_before_days);
    try testing.expectEqual(@as(u64, 2 * 60 * 60 * 1000), loaded.acme.check_interval_ms);
}

test "oper groups project configured privileges and titles" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[[oper_groups]]
        \\name = "observer"
        \\privileges = ["audit_read"]
        \\[[oper_groups]]
        \\name = "admin"
        \\inherits = "observer"
        \\privileges = ["server_rehash"]
        \\[[opers]]
        \\account = "alice"
        \\class = "admin"
        \\title = "Network Guardian"
        \\
    ;
    var loaded = try loadFromText(allocator, text, .{ .port = 6680 }, .{});
    defer loaded.deinit(allocator);

    const registry = loaded.config.oper_registry.?;
    const grant = try registry.elevateAuthenticated(.{ .name = "alice" });
    try testing.expect(grant.privileges.has(.server_rehash));
    try testing.expect(grant.privileges.has(.audit_read));
    try testing.expect(!grant.privileges.has(.server_admin));
    try testing.expectEqualStrings("Network Guardian", grant.title);
}

test "minimal config: unspecified optional fields keep defaults" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 9
        \\[listen]
        \\irc = 6680
        \\
    ;
    const base = server.Config{ .port = 6680 };
    var loaded = try loadFromText(allocator, text, base, .{});
    defer loaded.deinit(allocator);
    try testing.expectEqual(@as(u16, 6680), loaded.config.port);
    try testing.expectEqual(@as(u64, 9), loaded.config.node_id);
    try testing.expectEqual(@as(u16, 0), loaded.config.s2s_port); // unspecified -> default
}

test "tls section projects onto the boot tls config" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[tls]
        \\enabled = true
        \\port = 7001
        \\cert_path = "leaf.pem"
        \\key_path = "leaf.key"
        \\dns_name = "irc.example.test"
        \\
    ;
    var loaded = try loadFromText(allocator, text, .{ .port = 6680 }, .{});
    defer loaded.deinit(allocator);
    try testing.expect(loaded.tls.enabled);
    try testing.expectEqual(@as(u16, 7001), loaded.tls.port);
    try testing.expectEqualStrings("leaf.pem", loaded.tls.cert_path.?);
    try testing.expectEqualStrings("leaf.key", loaded.tls.key_path.?);
    try testing.expectEqualStrings("irc.example.test", loaded.tls.dns_name);
}

test "tls omitted keeps boot defaults" {
    const allocator = testing.allocator;
    const text = "[node]\nid = 1\n[listen]\nirc = 6680\n";
    var loaded = try loadFromText(allocator, text, .{ .port = 6680 }, .{});
    defer loaded.deinit(allocator);
    try testing.expect(!loaded.tls.enabled);
    try testing.expectEqual(@as(u16, 6697), loaded.tls.port);
    try testing.expectEqual(@as(?[]const u8, null), loaded.tls.cert_path);
    try testing.expectEqualStrings("localhost", loaded.tls.dns_name);
}

test "sts boot projection maps the parsed [sts] section" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[sts]
        \\enabled = true
        \\duration = 604800
        \\port = 7000
        \\preload = true
        \\
    ;
    var loaded = try loadFromText(allocator, text, .{ .port = 6680 }, .{});
    defer loaded.deinit(allocator);
    try testing.expect(loaded.sts.enabled);
    try testing.expectEqual(@as(u32, 604800), loaded.sts.duration);
    try testing.expectEqual(@as(u16, 7000), loaded.sts.port);
    try testing.expect(loaded.sts.preload);
}

test "sts boot projection defaults when [sts] omitted" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 9
        \\[listen]
        \\irc = 6680
        \\
    ;
    var loaded = try loadFromText(allocator, text, .{ .port = 6680 }, .{});
    defer loaded.deinit(allocator);
    // STS disabled by default; secure defaults still surface to main.zig.
    try testing.expect(!loaded.sts.enabled);
    try testing.expectEqual(@as(u32, 2_592_000), loaded.sts.duration);
    try testing.expectEqual(@as(u16, 6697), loaded.sts.port);
    try testing.expect(!loaded.sts.preload);
}

test "missing required [node].id is rejected" {
    const allocator = testing.allocator;
    const text = "[listen]\nirc = 6680\n";
    try testing.expectError(error.ParseError, loadFromText(allocator, text, .{ .port = 6680 }, .{}));
}

test "[class.*] parses into the connection-class registry with v4/v6 + TLS match" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[class.user]
        \\sendq = "2M"
        \\max_per_ip = 4
        \\[class.server]
        \\sendq = "16M"
        \\[class.trusted]
        \\sendq = "8M"
        \\flood_exempt = true
        \\match = ["10.0.0.0/8", "::1"]
        \\match_tls = true
        \\
    ;
    var loaded = try loadFromText(allocator, text, .{ .port = 6680 }, .{});
    defer loaded.deinit(allocator);
    const reg = &loaded.config.class_registry.?;
    // Built-in overrides honored; custom class present.
    try testing.expectEqual(@as(u64, 2 << 20), reg.byName("user").?.policy.sendq);
    try testing.expectEqual(@as(u32, 4), reg.byName("user").?.policy.max_per_ip);
    try testing.expectEqual(@as(u64, 16 << 20), reg.byName("server").?.policy.sendq);
    try testing.expect(reg.byName("trusted").?.policy.flood_exempt);
    // Matching: 10.x over TLS -> trusted; without TLS -> user; v6 ::1 TLS -> trusted.
    try testing.expectEqualStrings("trusted", reg.classFor(.{ .ip_text = "10.1.2.3", .is_tls = true }).name);
    try testing.expectEqualStrings("user", reg.classFor(.{ .ip_text = "10.1.2.3", .is_tls = false }).name);
    try testing.expectEqualStrings("trusted", reg.classFor(.{ .ip_text = "::1", .is_tls = true }).name);
    try testing.expectEqualStrings("server", reg.classFor(.{ .is_server_link = true }).name);
}

//! Orochi daemon configuration: a typed `Config` projected from standard TOML.
//!
//! The canonical config format is **TOML v1.0** (parsed by `proto/toml.zig`).
//! `parseToml` reads a TOML document and overlays it onto a defaulted `Config`,
//! preserving the daemon's value conventions:
//!   * `env:NAME` / `@file:path` string indirection, resolved via `Resolver`.
//!   * durations as quoted strings: `"500ms"`, `"30s"`, `"5m"`, `"2h"`.
//!   * operators as a TOML array-of-tables: `[[opers]]` with `account`/`class`.
//! A field is overridden only when the document supplies it; otherwise the
//! defaults stand. Required: `[node].id` and `[listen].irc`.
const std = @import("std");
const toml = @import("../proto/toml.zig");
const shard = @import("shard.zig");

comptime {
    if (@bitSizeOf(usize) != 64) @compileError("config_format requires a 64-bit target");
}

/// Indirection callback: given a name (env var) or path (file), return an owned
/// value. Used to resolve `env:NAME` and `@file:path` string values.
pub const LookupFn = *const fn (?*anyopaque, std.mem.Allocator, []const u8) anyerror![]const u8;

pub const Resolver = struct {
    ctx: ?*anyopaque = null,
    env: ?LookupFn = null,
    file: ?LookupFn = null,
};

pub const Config = struct {
    node: Node = .{},
    network: Network = .{},
    motd: Motd = .{},
    admin: Admin = .{},
    weather: Weather = .{},
    news: News = .{},
    geo: Geo = .{},
    oper: OperSection = .{},
    listen: Listen = .{},
    opers: []Oper = &.{},
    oper_groups: []OperGroup = &.{},
    mesh: Mesh = .{},
    limits: Limits = .{},
    io: Io = .{},
    reputation: Reputation = .{},
    sessions: Sessions = .{},
    media: Media = .{},
    stats: Stats = .{},
    geoip: Geoip = .{},
    sasl: Sasl = .{},
    cloak: Cloak = .{},
    tls: Tls = .{},
    sts: Sts = .{},

    pub const Node = struct {
        id: u64 = 0,
        public_key: ?[]const u8 = null,
        secret_key: ?[]const u8 = null,
    };

    /// Network-wide presentation. `name` is advertised in ISUPPORT `NETWORK=`
    /// and the registration welcome burst.
    pub const Network = struct {
        name: []const u8 = "Orochi",
        /// This server's own name (source prefix + S2S identity). Unique per node.
        server_name: ?[]const u8 = null,
    };

    /// Message of the Day. `text` is served by the MOTD command (split on
    /// newlines into lines). Supports `@file:path` to load from a file; when
    /// empty the daemon's built-in default MOTD is served.
    pub const Motd = struct {
        text: ?[]const u8 = null,
    };

    /// ADMIN command response (RPL_ADMIN*). Operator/network contact details.
    pub const Admin = struct {
        location: []const u8 = "Orochi IRC network",
        email: []const u8 = "admin@orochi.local",
    };

    /// Localized weather for the MOTD `{weather}` placeholder. The daemon reads
    /// `source` (a key=value file written by an external updater: temp_c,
    /// wind_kph, precip_mm, desc, location, country) and renders it in the units
    /// for `units` ("auto" uses `country`/the file's country).
    pub const Weather = struct {
        enabled: bool = false,
        /// Display location override (else the source file's `location`).
        location: ?[]const u8 = null,
        /// ISO country code for unit selection (else the file's `country`).
        country: ?[]const u8 = null,
        /// Unit override: "auto" | "metric" | "imperial" | "uk".
        units: ?[]const u8 = null,
        /// Path to the key=value source file.
        source: ?[]const u8 = null,
    };

    /// Headlines for the MOTD `{news}` placeholder. The daemon reads `source`
    /// (one headline per line) and joins the first `count` into a single line.
    pub const News = struct {
        enabled: bool = false,
        source: ?[]const u8 = null,
        count: u32 = 3,
    };

    /// Live `!weather`/`!news` fantasy bot. When enabled the daemon fetches
    /// wttr.in + the bundled RSS feeds in a background thread.
    pub const Geo = struct {
        enabled: bool = false,
        /// Skip TLS verification for public read-only news feeds.
        news_insecure_tls: bool = true,
        /// Min ms between bot replies per channel (anti-flood). 0 = disabled.
        cmd_cooldown_ms: u32 = 3000,
        /// Fallback `!weather` location when a user has no GeoIP/`location` meta.
        default_location: ?[]const u8 = null,
        /// Directory of updater-written headline files; when set, `!news` reads
        /// these instead of doing in-daemon TLS fetches.
        news_cache_dir: ?[]const u8 = null,
    };

    /// Operator subsystem settings (distinct from the `[[opers]]` bindings).
    pub const OperSection = struct {
        /// Path for persisting runtime GRANT/REVOKE grants across restarts.
        grants_path: ?[]const u8 = null,
    };

    pub const Listen = struct {
        host: []const u8 = "",
        irc: u16 = 0,
        ws: u16 = 0,
        webtransport: u16 = 0,
        s2s: u16 = 0,
        /// UDP port for the media (SFU) transport plane; 0 = ephemeral.
        media: u16 = 0,
        /// UDP port for the native media transport (our OPVOX/OPVIS codec leg);
        /// 0 = ephemeral.
        native_media: u16 = 0,
        /// IP advertised to clients as the server media (ICE) candidate.
        media_host: []const u8 = "",
    };

    /// An operator binding. Orochi grants oper SASL-only: `account` is the SASL
    /// account elevated on login (no password — SASL is the auth), and `class`
    /// names its privilege class. There is no OPER-password credential.
    /// A role-based operator group: a named privilege set (optionally inheriting
    /// another group's privileges). An `[[opers]]` block's `class` names its group.
    pub const OperGroup = struct {
        name: []const u8 = "",
        privileges: []const []const u8 = &.{},
        inherits: []const u8 = "",
    };

    pub const Oper = struct {
        account: []const u8 = "",
        class: []const u8 = "",
        /// Optional custom title shown in WHOIS (e.g. "Network Guardian"). When
        /// empty the generic operator/administrator wording is used.
        title: []const u8 = "",
    };

    pub const Mesh = struct {
        realm: []const u8 = "",
        trust_roots: []const []const u8 = &.{},
        mesh_pass: ?[]const u8 = null,
    };

    pub const Limits = struct {
        backlog: u31 = 128,
        max_clients: u31 = 1024,
        /// Number of worker reactor shards (`ReactorPool` threads). 1 = the
        /// single-reactor model; bounded by `shard.max_shards`.
        num_shards: u16 = 1,
        handshake_timeout_ms: u64 = 30_000,
        ping_interval_ms: u64 = 120_000,
        ping_timeout_ms: u64 = 60_000,
        /// Maximum stored channel topic length in bytes (advertised as TOPICLEN).
        topiclen: u32 = 390,
        /// Maximum away-message length in bytes (advertised as AWAYLEN).
        awaylen: u32 = 256,
        /// Maximum kick-comment length in bytes (advertised as KICKLEN).
        kicklen: u32 = 307,
        /// Maximum nick length in bytes (advertised as NICKLEN; capped at 64).
        nicklen: u32 = 64,
        /// Maximum channel-name length in bytes (advertised as CHANNELLEN).
        channellen: u32 = 64,
        /// Per-channel cap on each list mode +b/+e/+I/+Z (advertised as MAXLIST).
        maxlist: u32 = 100,
        /// Max channels a non-oper may be in (advertised as CHANLIMIT).
        chanlimit: u32 = 50,
        /// Max comma-separated targets per PRIVMSG/NOTICE (advertised MAXTARGETS).
        maxtargets: u32 = 4,
        /// Max MONITOR targets per client (advertised as MONITOR).
        monitorlimit: u32 = 128,
        /// Max SILENCE masks per client (advertised as SILENCE).
        silencelimit: u32 = 32,
        max_clones_per_ip: u32 = 0,
        max_clones_per_net: u32 = 0,
        reputation_refuse_threshold: u32 = 0,
        reputation_half_life_ms: u64 = 60_000,
        /// Period of the io_uring timeout-sweep timer; sets the enforcement
        /// granularity of registration/ping/idle timeouts.
        sweep_interval_ms: u64 = 2_000,
    };

    /// io_uring / per-connection transport tuning.
    pub const Io = struct {
        ring_entries: u32 = 32,
    };

    /// Decaying IP-reputation penalty weights.
    pub const Reputation = struct {
        registration_timeout_penalty: f64 = 50.0,
        clone_refuse_penalty: f64 = 25.0,
    };

    /// Multi-session / bouncer registry sizing.
    pub const Sessions = struct {
        max_accounts: u64 = 65536,
        max_per_account: u32 = 64,
    };

    pub const Media = struct {
        enabled: bool = false,
        max_upload_bytes: u64 = 16 * 1024 * 1024,
        max_frame_bytes: u64 = 64 * 1024,
        /// STUN server (IPv4 literal) queried at boot for the reflexive media
        /// candidate; with stun_port set, overrides listen.media_host on success.
        stun_host: ?[]const u8 = null,
        stun_port: u16 = 0,
    };

    pub const Stats = struct {
        /// Directory to publish web stats into (stats.json + index.html), e.g. an
        /// nginx `root`. Empty = disabled.
        dir: []const u8 = "",
        /// Minimum interval between stats writes, in ms (parsed from a duration).
        interval_ms: i64 = 30_000,
    };

    pub const Geoip = struct {
        /// Path to a MaxMind GeoIP database (.mmdb). Empty = GeoIP disabled.
        database: []const u8 = "",
    };

    pub const Sasl = struct {
        enabled: bool = false,
        realm: ?[]const u8 = null,
        /// Path (relative to the daemon cwd) of the WAL-backed account store. When
        /// set, the daemon opens it and verifies SASL credentials against it.
        account_db: ?[]const u8 = null,
    };

    pub const Cloak = struct {
        /// Secret passphrase for hostname cloaking. Hashed to a 32-byte key at
        /// boot; when set, every client's real IP is HMAC-cloaked. When absent,
        /// the daemon generates a random per-boot key (privacy on by default).
        secret: ?[]const u8 = null,
    };

    /// TLS listener settings. The live listener is wired elsewhere; this section
    /// only describes intent. When `enabled` and no `cert_path`/`key_path` are
    /// given, the daemon bootstraps a self-signed Ed25519 leaf (see
    /// `tls_certs.loadOrBootstrap`) using `dns_name` as the CN/SAN.
    pub const Tls = struct {
        /// Whether to stand up a TLS listener at all.
        enabled: bool = false,
        /// TLS listener port (the conventional IRCS port is 6697).
        port: u16 = 6697,
        /// PEM/DER leaf certificate path. When set together with `key_path`,
        /// the on-disk material is loaded instead of bootstrapping.
        cert_path: ?[]const u8 = null,
        /// PEM/DER private key path; paired with `cert_path`.
        key_path: ?[]const u8 = null,
        /// CN/SAN used for the self-signed bootstrap leaf when no files are set.
        dns_name: []const u8 = "localhost",
        /// Request a client certificate (mutual TLS) so SASL EXTERNAL can match
        /// the presented fingerprint to an account. Off by default.
        request_client_cert: bool = false,
        /// Also accept hardened TLS 1.2 (ECDHE-AEAD) clients on the same listener,
        /// via version-dispatch. Off by default to keep the modern TLS-1.3-only
        /// posture; enabling it widens the accepted protocol surface. The 1.2 leg
        /// always presents a freshly bootstrapped ECDSA-P256 leaf (the 1.2 engine
        /// signs ServerKeyExchange with ecdsa_secp256r1_sha256).
        enable_tls12: bool = false,
    };

    /// IRCv3 STS (Strict Transport Security) advertisement policy. When enabled,
    /// the daemon advertises an `sts=` capability instructing clients to persist
    /// a secure-transport upgrade for `duration` seconds on the secure `port`.
    /// Disabled by default so plaintext deployments are never forced upgrades.
    /// The actual policy build + per-session advertisement lives in `main.zig`
    /// via `proto/sts_policy.zig`; this section only surfaces the parsed config.
    pub const Sts = struct {
        enabled: bool = false,
        /// Persistence lifetime in seconds advertised to secure clients. Default
        /// is 30 days (2592000), the value recommended by the IRCv3 STS spec.
        duration: u32 = 2_592_000,
        /// Secure (TLS) port clients should reconnect to when upgrading. Default
        /// is the conventional IRC-over-TLS port 6697.
        port: u16 = 6697,
        /// When true, advertise `preload`, signaling the policy may be shipped in
        /// client preload lists. Off by default; only opt in deliberately.
        preload: bool = false,
    };

    pub fn initDefaults(allocator: std.mem.Allocator) !Config {
        const host = try allocator.dupe(u8, "127.0.0.1");
        errdefer allocator.free(host);
        const media_host = try allocator.dupe(u8, "127.0.0.1");
        errdefer allocator.free(media_host);
        const stats_dir = try allocator.dupe(u8, "");
        errdefer allocator.free(stats_dir);
        const geoip_db = try allocator.dupe(u8, "");
        errdefer allocator.free(geoip_db);
        return .{
            .network = .{ .name = try allocator.dupe(u8, "Orochi") },
            .admin = .{
                .location = try allocator.dupe(u8, "Orochi IRC network"),
                .email = try allocator.dupe(u8, "admin@orochi.local"),
            },
            .listen = .{ .host = host, .media_host = media_host },
            .mesh = .{ .realm = try allocator.dupe(u8, "local") },
            .tls = .{ .dns_name = try allocator.dupe(u8, "localhost") },
            .stats = .{ .dir = stats_dir },
            .geoip = .{ .database = geoip_db },
        };
    }

    pub fn deinit(self: *Config, allocator: std.mem.Allocator) void {
        if (self.node.public_key) |value| allocator.free(value);
        if (self.node.secret_key) |value| allocator.free(value);
        allocator.free(self.network.name);
        if (self.network.server_name) |v| allocator.free(v);
        if (self.motd.text) |value| allocator.free(value);
        allocator.free(self.admin.location);
        allocator.free(self.admin.email);
        if (self.weather.location) |v| allocator.free(v);
        if (self.weather.country) |v| allocator.free(v);
        if (self.weather.units) |v| allocator.free(v);
        if (self.weather.source) |v| allocator.free(v);
        if (self.news.source) |v| allocator.free(v);
        if (self.geo.default_location) |v| allocator.free(v);
        if (self.geo.news_cache_dir) |v| allocator.free(v);
        if (self.oper.grants_path) |v| allocator.free(v);
        allocator.free(self.listen.host);
        allocator.free(self.listen.media_host);
        for (self.opers) |oper| {
            allocator.free(oper.account);
            allocator.free(oper.class);
            allocator.free(oper.title);
        }
        allocator.free(self.opers);
        for (self.oper_groups) |g| {
            allocator.free(g.name);
            freeStringList(allocator, g.privileges);
            allocator.free(g.inherits);
        }
        allocator.free(self.oper_groups);
        allocator.free(self.mesh.realm);
        freeStringList(allocator, self.mesh.trust_roots);
        if (self.mesh.mesh_pass) |value| allocator.free(value);
        if (self.sasl.realm) |value| allocator.free(value);
        if (self.sasl.account_db) |value| allocator.free(value);
        if (self.media.stun_host) |value| allocator.free(value);
        allocator.free(self.stats.dir);
        allocator.free(self.geoip.database);
        if (self.cloak.secret) |value| allocator.free(value);
        allocator.free(self.tls.dns_name);
        if (self.tls.cert_path) |value| allocator.free(value);
        if (self.tls.key_path) |value| allocator.free(value);
        self.* = .{};
    }
};

pub const TomlError = error{ParseError} || std.mem.Allocator.Error;

/// Parse standard TOML and project it onto a defaulted `Config`.
pub fn parseToml(allocator: std.mem.Allocator, source: []const u8, resolver: Resolver) TomlError!Config {
    var doc = toml.parse(allocator, source) catch return error.ParseError;
    defer doc.deinit(allocator);

    var cfg = try Config.initDefaults(allocator);
    errdefer cfg.deinit(allocator);

    // [node]
    if (doc.getInt("node.id")) |v| {
        if (v < 1) return error.ParseError;
        cfg.node.id = @intCast(v);
    }
    try setOpt(allocator, resolver, doc.getString("node.public_key"), &cfg.node.public_key);
    try setOpt(allocator, resolver, doc.getString("node.secret_key"), &cfg.node.secret_key);

    // [network]
    try setStr(allocator, resolver, doc.getString("network.name"), &cfg.network.name);
    try setOpt(allocator, resolver, doc.getString("network.server_name"), &cfg.network.server_name);

    // [motd] — `text` may use `@file:path` to load from disk.
    try setOpt(allocator, resolver, doc.getString("motd.text"), &cfg.motd.text);

    // [admin]
    try setStr(allocator, resolver, doc.getString("admin.location"), &cfg.admin.location);
    try setStr(allocator, resolver, doc.getString("admin.email"), &cfg.admin.email);

    // [weather]
    if (doc.getBool("weather.enabled")) |b| cfg.weather.enabled = b;
    try setOpt(allocator, resolver, doc.getString("weather.location"), &cfg.weather.location);
    try setOpt(allocator, resolver, doc.getString("weather.country"), &cfg.weather.country);
    try setOpt(allocator, resolver, doc.getString("weather.units"), &cfg.weather.units);
    try setOpt(allocator, resolver, doc.getString("weather.source"), &cfg.weather.source);

    // [news]
    if (doc.getBool("news.enabled")) |b| cfg.news.enabled = b;
    try setOpt(allocator, resolver, doc.getString("news.source"), &cfg.news.source);
    cfg.news.count = @intCast(try uintField(doc, "news.count", cfg.news.count, 1, 20));

    // [geo]
    if (doc.getBool("geo.enabled")) |b| cfg.geo.enabled = b;
    if (doc.getBool("geo.news_insecure_tls")) |b| cfg.geo.news_insecure_tls = b;
    cfg.geo.cmd_cooldown_ms = @intCast(try uintField(doc, "geo.cmd_cooldown_ms", cfg.geo.cmd_cooldown_ms, 0, 600000));
    try setOpt(allocator, resolver, doc.getString("geo.default_location"), &cfg.geo.default_location);
    try setOpt(allocator, resolver, doc.getString("geo.news_cache_dir"), &cfg.geo.news_cache_dir);

    // [oper]
    try setOpt(allocator, resolver, doc.getString("oper.grants_path"), &cfg.oper.grants_path);

    // [listen]
    try setStr(allocator, resolver, doc.getString("listen.host"), &cfg.listen.host);
    cfg.listen.irc = try portField(doc, "listen.irc", cfg.listen.irc);
    cfg.listen.ws = try portField(doc, "listen.ws", cfg.listen.ws);
    cfg.listen.webtransport = try portField(doc, "listen.webtransport", cfg.listen.webtransport);
    cfg.listen.s2s = try portField(doc, "listen.s2s", cfg.listen.s2s);
    cfg.listen.media = try portField(doc, "listen.media", cfg.listen.media);
    cfg.listen.native_media = try portField(doc, "listen.native_media", cfg.listen.native_media);
    try setStr(allocator, resolver, doc.getString("listen.media_host"), &cfg.listen.media_host);

    // [mesh]
    try setStr(allocator, resolver, doc.getString("mesh.realm"), &cfg.mesh.realm);
    try setOpt(allocator, resolver, doc.getString("mesh.mesh_pass"), &cfg.mesh.mesh_pass);
    if (doc.getArray("mesh.trust_roots")) |arr| {
        freeStringList(allocator, cfg.mesh.trust_roots);
        cfg.mesh.trust_roots = try ownStringArray(allocator, resolver, arr);
    }

    // [limits]
    cfg.limits.backlog = @intCast(try uintField(doc, "limits.backlog", cfg.limits.backlog, 1, 32767));
    cfg.limits.max_clients = @intCast(try uintField(doc, "limits.max_clients", cfg.limits.max_clients, 1, 32767));
    cfg.limits.num_shards = @intCast(try uintField(doc, "limits.num_shards", cfg.limits.num_shards, 1, shard.max_shards));
    cfg.limits.max_clones_per_ip = @intCast(try uintField(doc, "limits.max_clones_per_ip", cfg.limits.max_clones_per_ip, 0, 65535));
    cfg.limits.max_clones_per_net = @intCast(try uintField(doc, "limits.max_clones_per_net", cfg.limits.max_clones_per_net, 0, 65535));
    cfg.limits.topiclen = @intCast(try uintField(doc, "limits.topiclen", cfg.limits.topiclen, 1, 8192));
    cfg.limits.awaylen = @intCast(try uintField(doc, "limits.awaylen", cfg.limits.awaylen, 1, 256));
    cfg.limits.kicklen = @intCast(try uintField(doc, "limits.kicklen", cfg.limits.kicklen, 1, 400));
    cfg.limits.nicklen = @intCast(try uintField(doc, "limits.nicklen", cfg.limits.nicklen, 1, 64));
    cfg.limits.channellen = @intCast(try uintField(doc, "limits.channellen", cfg.limits.channellen, 2, 200));
    cfg.limits.maxlist = @intCast(try uintField(doc, "limits.maxlist", cfg.limits.maxlist, 1, 10000));
    cfg.limits.chanlimit = @intCast(try uintField(doc, "limits.chanlimit", cfg.limits.chanlimit, 1, 10000));
    cfg.limits.maxtargets = @intCast(try uintField(doc, "limits.maxtargets", cfg.limits.maxtargets, 1, 64));
    cfg.limits.monitorlimit = @intCast(try uintField(doc, "limits.monitorlimit", cfg.limits.monitorlimit, 1, 100000));
    cfg.limits.silencelimit = @intCast(try uintField(doc, "limits.silencelimit", cfg.limits.silencelimit, 1, 256));
    cfg.limits.reputation_refuse_threshold = @intCast(try uintField(doc, "limits.reputation_refuse_threshold", cfg.limits.reputation_refuse_threshold, 0, 1_000_000));
    if (doc.getString("limits.handshake_timeout")) |s| cfg.limits.handshake_timeout_ms = try durationMs(s);
    if (doc.getString("limits.ping_interval")) |s| cfg.limits.ping_interval_ms = try durationMs(s);
    if (doc.getString("limits.ping_timeout")) |s| cfg.limits.ping_timeout_ms = try durationMs(s);
    if (doc.getString("limits.reputation_half_life")) |s| cfg.limits.reputation_half_life_ms = try durationMs(s);
    if (doc.getString("limits.sweep_interval")) |s| cfg.limits.sweep_interval_ms = try durationMs(s);

    // [io]
    cfg.io.ring_entries = @intCast(try uintField(doc, "io.ring_entries", cfg.io.ring_entries, 8, 4096));

    // [reputation]
    cfg.reputation.registration_timeout_penalty = try floatField(doc, "reputation.registration_timeout_penalty", cfg.reputation.registration_timeout_penalty, 0, 1000);
    cfg.reputation.clone_refuse_penalty = try floatField(doc, "reputation.clone_refuse_penalty", cfg.reputation.clone_refuse_penalty, 0, 1000);

    // [sessions]
    cfg.sessions.max_accounts = try uintField(doc, "sessions.max_accounts", cfg.sessions.max_accounts, 1, std.math.maxInt(u32));
    cfg.sessions.max_per_account = @intCast(try uintField(doc, "sessions.max_per_account", cfg.sessions.max_per_account, 1, 1_000_000));

    // [media]
    if (doc.getBool("media.enabled")) |b| cfg.media.enabled = b;
    cfg.media.max_upload_bytes = try uintField(doc, "media.max_upload_bytes", cfg.media.max_upload_bytes, 0, 1024 * 1024 * 1024);
    cfg.media.max_frame_bytes = try uintField(doc, "media.max_frame_bytes", cfg.media.max_frame_bytes, 0, 16 * 1024 * 1024);
    try setOpt(allocator, resolver, doc.getString("media.stun_host"), &cfg.media.stun_host);

    try setStr(allocator, resolver, doc.getString("stats.dir"), &cfg.stats.dir);
    if (doc.getString("stats.interval")) |s| cfg.stats.interval_ms = @intCast(try durationMs(s));

    try setStr(allocator, resolver, doc.getString("geoip.database"), &cfg.geoip.database);
    cfg.media.stun_port = try portField(doc, "media.stun_port", cfg.media.stun_port);

    // [sasl]
    if (doc.getBool("sasl.enabled")) |b| cfg.sasl.enabled = b;
    try setOpt(allocator, resolver, doc.getString("sasl.realm"), &cfg.sasl.realm);
    try setOpt(allocator, resolver, doc.getString("sasl.account_db"), &cfg.sasl.account_db);

    // [cloak]
    try setOpt(allocator, resolver, doc.getString("cloak.secret"), &cfg.cloak.secret);

    // [tls]
    if (doc.getBool("tls.enabled")) |b| cfg.tls.enabled = b;
    cfg.tls.port = try portField(doc, "tls.port", cfg.tls.port);
    try setOpt(allocator, resolver, doc.getString("tls.cert_path"), &cfg.tls.cert_path);
    try setOpt(allocator, resolver, doc.getString("tls.key_path"), &cfg.tls.key_path);
    try setStr(allocator, resolver, doc.getString("tls.dns_name"), &cfg.tls.dns_name);
    if (doc.getBool("tls.request_client_cert")) |b| cfg.tls.request_client_cert = b;

    // [sts]
    if (doc.getBool("sts.enabled")) |b| cfg.sts.enabled = b;
    cfg.sts.duration = @intCast(try uintField(doc, "sts.duration", cfg.sts.duration, 0, std.math.maxInt(u32)));
    cfg.sts.port = try portField(doc, "sts.port", cfg.sts.port);
    if (doc.getBool("sts.preload")) |b| cfg.sts.preload = b;

    // [[opers]] arrays-of-tables
    if (doc.getArray("opers")) |arr| {
        var list: std.ArrayList(Config.Oper) = .empty;
        errdefer {
            for (list.items) |o| {
                allocator.free(o.account);
                allocator.free(o.class);
            }
            list.deinit(allocator);
        }
        for (arr) |*item| {
            const account_raw = item.getString("account") orelse return error.ParseError;
            const account = try resolveStr(allocator, resolver, account_raw);
            errdefer allocator.free(account);
            const class = if (item.getString("class")) |c|
                try resolveStr(allocator, resolver, c)
            else
                try allocator.dupe(u8, "");
            errdefer allocator.free(class);
            const title = if (item.getString("title")) |t|
                try resolveStr(allocator, resolver, t)
            else
                try allocator.dupe(u8, "");
            try list.append(allocator, .{ .account = account, .class = class, .title = title });
        }
        cfg.opers = try list.toOwnedSlice(allocator);
    }

    // [[oper_groups]] role-based privilege sets
    if (doc.getArray("oper_groups")) |arr| {
        var list: std.ArrayList(Config.OperGroup) = .empty;
        errdefer {
            for (list.items) |g| {
                allocator.free(g.name);
                freeStringList(allocator, g.privileges);
                allocator.free(g.inherits);
            }
            list.deinit(allocator);
        }
        for (arr) |*item| {
            const name = try resolveStr(allocator, resolver, item.getString("name") orelse return error.ParseError);
            errdefer allocator.free(name);
            const privileges: []const []const u8 = if (item.getArray("privileges")) |parr|
                try ownStringArray(allocator, resolver, parr)
            else
                &.{};
            errdefer freeStringList(allocator, privileges);
            const inherits = if (item.getString("inherits")) |s|
                try resolveStr(allocator, resolver, s)
            else
                try allocator.dupe(u8, "");
            try list.append(allocator, .{ .name = name, .privileges = privileges, .inherits = inherits });
        }
        cfg.oper_groups = try list.toOwnedSlice(allocator);
    }

    // Required-field validation.
    if (cfg.node.id == 0) return error.ParseError;
    if (cfg.listen.irc == 0) return error.ParseError;
    for (cfg.opers) |o| if (o.account.len == 0) return error.ParseError;

    return cfg;
}

/// Resolve a raw TOML string into an owned value, honoring `env:NAME` /
/// `@file:path` indirection; a plain string is duped verbatim.
fn resolveStr(allocator: std.mem.Allocator, resolver: Resolver, raw: []const u8) TomlError![]const u8 {
    if (std.mem.startsWith(u8, raw, "env:")) {
        const name = raw["env:".len..];
        if (name.len == 0) return error.ParseError;
        const func = resolver.env orelse return error.ParseError;
        return func(resolver.ctx, allocator, name) catch return error.ParseError;
    }
    if (std.mem.startsWith(u8, raw, "@file:")) {
        const path = raw["@file:".len..];
        if (path.len == 0) return error.ParseError;
        const func = resolver.file orelse return error.ParseError;
        return func(resolver.ctx, allocator, path) catch return error.ParseError;
    }
    return allocator.dupe(u8, raw);
}

/// Overlay an optional string field when the TOML supplies one.
fn setOpt(allocator: std.mem.Allocator, resolver: Resolver, raw: ?[]const u8, slot: *?[]const u8) TomlError!void {
    const value = raw orelse return;
    const owned = try resolveStr(allocator, resolver, value);
    if (slot.*) |old| allocator.free(old);
    slot.* = owned;
}

/// Overlay a non-optional (default-duped) string field when supplied.
fn setStr(allocator: std.mem.Allocator, resolver: Resolver, raw: ?[]const u8, slot: *[]const u8) TomlError!void {
    const value = raw orelse return;
    const owned = try resolveStr(allocator, resolver, value);
    allocator.free(slot.*);
    slot.* = owned;
}

fn ownStringArray(allocator: std.mem.Allocator, resolver: Resolver, arr: []const toml.Value) TomlError![]const []const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (list.items) |s| allocator.free(s);
        list.deinit(allocator);
    }
    for (arr) |*item| {
        const raw = switch (item.*) {
            .string => |s| s,
            else => return error.ParseError,
        };
        try list.append(allocator, try resolveStr(allocator, resolver, raw));
    }
    return list.toOwnedSlice(allocator);
}

fn portField(doc: toml.Document, path: []const u8, current: u16) TomlError!u16 {
    const v = doc.getInt(path) orelse return current;
    if (v < 0 or v > 65535) return error.ParseError;
    return @intCast(v);
}

fn uintField(doc: toml.Document, path: []const u8, current: u64, min: u64, max: u64) TomlError!u64 {
    const v = doc.getInt(path) orelse return current;
    if (v < 0) return error.ParseError;
    const u: u64 = @intCast(v);
    if (u < min or u > max) return error.ParseError;
    return u;
}

fn floatField(doc: toml.Document, path: []const u8, current: f64, min: f64, max: f64) TomlError!f64 {
    const v = doc.getFloat(path) orelse return current;
    if (v < min or v > max) return error.ParseError;
    return v;
}

/// Parse a duration string ("500ms" | "30s" | "5m" | "2h") into milliseconds.
fn durationMs(text: []const u8) TomlError!u64 {
    const units = [_]struct { suffix: []const u8, scale: u64 }{
        .{ .suffix = "ms", .scale = 1 },
        .{ .suffix = "s", .scale = 1000 },
        .{ .suffix = "m", .scale = 60_000 },
        .{ .suffix = "h", .scale = 3_600_000 },
    };
    for (units) |unit| {
        if (std.mem.endsWith(u8, text, unit.suffix)) {
            const digits = text[0 .. text.len - unit.suffix.len];
            const n = std.fmt.parseInt(u64, digits, 10) catch return error.ParseError;
            if (n == 0 or n > std.math.maxInt(u64) / unit.scale) return error.ParseError;
            return n * unit.scale;
        }
    }
    return error.ParseError;
}

fn freeStringList(allocator: std.mem.Allocator, list: []const []const u8) void {
    for (list) |item| allocator.free(item);
    allocator.free(list);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "parseToml: core sections project onto Config" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 42
        \\
        \\[listen]
        \\host = "10.0.0.5"
        \\irc = 6700
        \\s2s = 7700
        \\
        \\[limits]
        \\max_clients = 2048
        \\handshake_timeout = "15s"
        \\ping_interval = "90s"
        \\
    ;
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);
    try testing.expectEqual(@as(u64, 42), cfg.node.id);
    try testing.expectEqualStrings("10.0.0.5", cfg.listen.host);
    try testing.expectEqual(@as(u16, 6700), cfg.listen.irc);
    try testing.expectEqual(@as(u16, 7700), cfg.listen.s2s);
    try testing.expectEqual(@as(u31, 2048), cfg.limits.max_clients);
    try testing.expectEqual(@as(u64, 15_000), cfg.limits.handshake_timeout_ms);
    try testing.expectEqual(@as(u64, 90_000), cfg.limits.ping_interval_ms);
    // Unspecified optional fields keep their defaults.
    try testing.expectEqual(@as(u64, 60_000), cfg.limits.ping_timeout_ms);
    try testing.expectEqualStrings("local", cfg.mesh.realm);
}

test "parseToml: [[opers]] array-of-tables + trust_roots list" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[mesh]
        \\realm = "ircxnet"
        \\trust_roots = ["root-a", "root-b"]
        \\[[opers]]
        \\account = "admin"
        \\class = "netadmin"
        \\[[opers]]
        \\account = "helper"
        \\
    ;
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);
    try testing.expectEqualStrings("ircxnet", cfg.mesh.realm);
    try testing.expectEqual(@as(usize, 2), cfg.mesh.trust_roots.len);
    try testing.expectEqualStrings("root-b", cfg.mesh.trust_roots[1]);
    try testing.expectEqual(@as(usize, 2), cfg.opers.len);
    try testing.expectEqualStrings("admin", cfg.opers[0].account);
    try testing.expectEqualStrings("netadmin", cfg.opers[0].class);
    try testing.expectEqualStrings("helper", cfg.opers[1].account);
    try testing.expectEqualStrings("", cfg.opers[1].class);
}

test "parseToml: env: indirection resolves through the Resolver" {
    const allocator = testing.allocator;
    const Ctx = struct {
        fn env(_: ?*anyopaque, a: std.mem.Allocator, name: []const u8) anyerror![]const u8 {
            try testing.expectEqualStrings("MIZ_SECRET", name);
            return a.dupe(u8, "s3kr3t");
        }
    };
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[cloak]
        \\secret = "env:MIZ_SECRET"
        \\
    ;
    var cfg = try parseToml(allocator, text, .{ .env = Ctx.env });
    defer cfg.deinit(allocator);
    try testing.expectEqualStrings("s3kr3t", cfg.cloak.secret.?);
}

test "parseToml: required fields and ranges are enforced" {
    const allocator = testing.allocator;
    // Missing [node].id.
    try testing.expectError(error.ParseError, parseToml(allocator, "[listen]\nirc = 6680\n", .{}));
    // Missing [listen].irc.
    try testing.expectError(error.ParseError, parseToml(allocator, "[node]\nid = 1\n", .{}));
    // Port out of range.
    try testing.expectError(error.ParseError, parseToml(allocator, "[node]\nid=1\n[listen]\nirc=70000\n", .{}));
    // Bad duration.
    try testing.expectError(error.ParseError, parseToml(allocator, "[node]\nid=1\n[listen]\nirc=1\n[limits]\nping_interval=\"5x\"\n", .{}));
    // Malformed TOML.
    try testing.expectError(error.ParseError, parseToml(allocator, "[node\nid=1\n", .{}));
}

test "parseToml: [io] / [reputation] / sweep_interval lift" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[limits]
        \\sweep_interval = "500ms"
        \\[io]
        \\ring_entries = 256
        \\[reputation]
        \\registration_timeout_penalty = 80.0
        \\clone_refuse_penalty = 10
        \\
    ;
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);
    try testing.expectEqual(@as(u64, 500), cfg.limits.sweep_interval_ms);
    try testing.expectEqual(@as(u32, 256), cfg.io.ring_entries);
    try testing.expectEqual(@as(f64, 80.0), cfg.reputation.registration_timeout_penalty);
    try testing.expectEqual(@as(f64, 10.0), cfg.reputation.clone_refuse_penalty);
    // out-of-range ring_entries rejected
    try testing.expectError(error.ParseError, parseToml(allocator, "[node]\nid=1\n[listen]\nirc=1\n[io]\nring_entries=4\n", .{}));
}

test "parseToml: num_shards lifts and defaults to 1" {
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
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);
    try testing.expectEqual(@as(u16, 4), cfg.limits.num_shards);

    // Omitted -> single-reactor default.
    var dflt = try parseToml(allocator, "[node]\nid=1\n[listen]\nirc=6680\n", .{});
    defer dflt.deinit(allocator);
    try testing.expectEqual(@as(u16, 1), dflt.limits.num_shards);

    // Zero shards is invalid (a reactor pool needs >= 1 worker).
    try testing.expectError(error.ParseError, parseToml(allocator, "[node]\nid=1\n[listen]\nirc=1\n[limits]\nnum_shards=0\n", .{}));
}

test "parseToml: minimal config keeps defaults" {
    const allocator = testing.allocator;
    var cfg = try parseToml(allocator, "[node]\nid = 9\n[listen]\nirc = 6680\n", .{});
    defer cfg.deinit(allocator);
    try testing.expectEqual(@as(u64, 9), cfg.node.id);
    try testing.expectEqual(@as(u16, 6680), cfg.listen.irc);
    try testing.expectEqual(@as(u16, 0), cfg.listen.s2s);
    try testing.expectEqualStrings("127.0.0.1", cfg.listen.host);
}

test "parseToml: [tls] section projects onto Config" {
    // Arrange
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[tls]
        \\enabled = true
        \\port = 7000
        \\cert_path = "/etc/orochi/leaf.pem"
        \\key_path = "/etc/orochi/leaf.key"
        \\dns_name = "irc.example.test"
        \\
    ;

    // Act
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);

    // Assert
    try testing.expect(cfg.tls.enabled);
    try testing.expectEqual(@as(u16, 7000), cfg.tls.port);
    try testing.expectEqualStrings("/etc/orochi/leaf.pem", cfg.tls.cert_path.?);
    try testing.expectEqualStrings("/etc/orochi/leaf.key", cfg.tls.key_path.?);
    try testing.expectEqualStrings("irc.example.test", cfg.tls.dns_name);
}

test "parseToml: [tls] omitted keeps secure defaults" {
    // Arrange
    const allocator = testing.allocator;
    const text = "[node]\nid = 1\n[listen]\nirc = 6680\n";

    // Act
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);

    // Assert
    try testing.expect(!cfg.tls.enabled);
    try testing.expectEqual(@as(u16, 6697), cfg.tls.port);
    try testing.expectEqual(@as(?[]const u8, null), cfg.tls.cert_path);
    try testing.expectEqual(@as(?[]const u8, null), cfg.tls.key_path);
    try testing.expectEqualStrings("localhost", cfg.tls.dns_name);
}

test "parseToml: [sts] section projects onto Config" {
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
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);
    try testing.expect(cfg.sts.enabled);
    try testing.expectEqual(@as(u32, 604800), cfg.sts.duration);
    try testing.expectEqual(@as(u16, 7000), cfg.sts.port);
    try testing.expect(cfg.sts.preload);
}

test "parseToml: [sts] omitted keeps secure defaults" {
    const allocator = testing.allocator;
    var cfg = try parseToml(allocator, "[node]\nid = 1\n[listen]\nirc = 6680\n", .{});
    defer cfg.deinit(allocator);
    // STS off by default; never force-upgrade a plaintext deployment.
    try testing.expect(!cfg.sts.enabled);
    try testing.expectEqual(@as(u32, 2_592_000), cfg.sts.duration);
    try testing.expectEqual(@as(u16, 6697), cfg.sts.port);
    try testing.expect(!cfg.sts.preload);
}

test {
    testing.refAllDecls(@This());
}

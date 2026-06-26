// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

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
const conn_class = @import("conn_class.zig");
const shard = @import("shard.zig");
const kagura_frame = @import("../substrate/kagura_frame.zig");
const media_room = @import("media_room.zig");

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

pub const acme_default_directory_url = "https://acme-v02.api.letsencrypt.org/directory";

pub const Config = struct {
    node: Node = .{},
    network: Network = .{},
    motd: Motd = .{},
    admin: Admin = .{},
    weather: Weather = .{},
    news: News = .{},
    geo: Geo = .{},
    oper: OperSection = .{},
    wasm: Wasm = .{},
    listen: Listen = .{},
    opers: []Oper = &.{},
    oper_groups: []OperGroup = &.{},
    /// `[class.*]` connection classes (owned). Built into a `conn_class.Registry`
    /// by `config_boot`; assignment/enforcement live in the daemon.
    classes: []ClassDef = &.{},
    mesh: Mesh = .{},
    limits: Limits = .{},
    io: Io = .{},
    reputation: Reputation = .{},
    sessions: Sessions = .{},
    media: Media = .{},
    stats: Stats = .{},
    metrics: Metrics = .{},
    geoip: Geoip = .{},
    sasl: Sasl = .{},
    cloak: Cloak = .{},
    tls: Tls = .{},
    acme: Acme = .{},
    sts: Sts = .{},
    dnsbl: Dnsbl = .{},
    mail: Mail = .{},

    /// `[dnsbl]` connect-time DNS blocklist. When enabled with one or more zones,
    /// each non-loopback client IP is checked against the zones off the hot path;
    /// a listed IP is refused (or network-banned) at registration.
    pub const Dnsbl = struct {
        enabled: bool = false,
        /// Blocklist zones, e.g. ["zen.spamhaus.org", "dnsbl.dronebl.org"].
        zones: []const []const u8 = &.{},
        /// false = refuse the connection; true = add a Warden ban for the IP.
        ward: bool = false,
    };

    /// `[mail]` outbound SMTP submission relay. When enabled with a relay host +
    /// sender, the daemon delivers account email-verification and password-reset
    /// codes out-of-band via the relay (off the hot path, on a background thread).
    /// Disabled (default) = no mail: REGISTER records emails as unverified and the
    /// reset flow is unavailable. Never log in the daemon's own MTA; this is a
    /// submission CLIENT to an existing relay.
    pub const Mail = struct {
        enabled: bool = false,
        /// Submission relay hostname (resolved via DNS A record).
        relay_host: ?[]const u8 = null,
        /// Submission port. 587 = STARTTLS (default); 465 = implicit TLS.
        relay_port: u16 = 587,
        /// false = port 465 implicit TLS (TLS from connect); true = STARTTLS on 587.
        starttls: bool = true,
        /// Skip TLS certificate verification of the relay. Default false. Required
        /// (set true) to use AUTH with a NON-loopback relay until trust-anchor
        /// verification is wired — otherwise AUTH to a remote relay is refused, so
        /// submission credentials are never sent over an unverified TLS session.
        insecure_skip_verify: bool = false,
        /// Envelope sender + `From:` address (e.g. "orochi@example.org").
        from: ?[]const u8 = null,
        /// AUTH credentials for the relay (optional; omitted = no AUTH).
        user: ?[]const u8 = null,
        pass: ?[]const u8 = null,
    };

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
        /// Human description of THIS node, shown in VERSION and WHOIS 312 and
        /// gossiped to mesh peers (per-server description). Null = generic tagline.
        description: ?[]const u8 = null,
        /// IRCv3 network icon: a URL to a network logo, advertised as the
        /// `NETWORKICON=<url>` ISUPPORT token when set (Ophion `n_url` parity).
        icon_url: ?[]const u8 = null,
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
    /// `[wasm]` — OroWasm plugin module system.
    pub const Wasm = struct {
        /// Directory scanned at boot (and on REHASH) for `*.wasm` control-plane
        /// plugins; each registers IRC commands consulted AFTER the built-in
        /// registry (so a plugin can never shadow a core command). Unset = off.
        plugin_dir: ?[]const u8 = null,
    };

    pub const OperSection = struct {
        /// Path for persisting runtime GRANT/REVOKE grants across restarts.
        grants_path: ?[]const u8 = null,
        /// Auto-enable the +j override umode on elevation for any operator holding
        /// the `oper_override` privilege, so admins get full channel authority
        /// (KICK/MODE/TOPIC/PROP/…) without a manual `/mode +j`. Default false
        /// keeps override an explicit, audited opt-in.
        auto_override: bool = false,
    };

    pub const Listen = struct {
        host: []const u8 = "",
        irc: u16 = 0,
        /// Secure-WebSocket (wss) port for browser clients; 0 = disabled.
        /// Requires `[tls]` to be enabled (the listener reuses its certificate).
        ws: u16 = 0,
        /// TESTING ONLY: allow the `ws` listener without TLS (plain `ws://`)
        /// when no certificate is configured. Browsers require wss on the
        /// production page, so this defaults OFF.
        ws_plain: bool = false,
        webtransport: u16 = 0,
        /// Accept HAProxy PROXY protocol v1/v2 headers from trusted proxies
        /// before IRC/TLS/WebSocket framing. Requires `trusted_proxies`.
        proxy_protocol: bool = false,
        /// Source IPs allowed to supply PROXY headers.
        trusted_proxies: []const []const u8 = &.{},
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
        /// Event-Spine categories this oper is auto-subscribed to on elevation
        /// (e.g. `["ANNOUNCE", "KILL"]`, or `["ALL"]`). Empty = none — the oper
        /// opts in per-category with `EVENT ADD`.
        presubscribe: []const []const u8 = &.{},
    };

    pub const Mesh = struct {
        realm: []const u8 = "",
        trust_roots: []const []const u8 = &.{},
        mesh_pass: ?[]const u8 = null,
        /// Peers this node dials automatically at boot (and re-dials while the
        /// link is down), each a "host:port" string (IPv6 hosts bracketed,
        /// e.g. "[::1]:6900"). Empty = no auto-connect.
        connect: []const []const u8 = &.{},
        /// When true, refuse plaintext S2S entirely (reject inbound plaintext
        /// peers, never dial plaintext outbound). Only the Tsumugi-secured path
        /// is permitted; if secured S2S is unavailable, all S2S is dropped rather
        /// than falling back to clear. Default false keeps the plaintext fallback.
        require_secured: bool = false,
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
        /// Channel-mode changes a client should combine per MODE command
        /// (advertised as MODES). Set to 1 for one mode/target per line.
        modes_per_line: u32 = 4,
        /// Max MONITOR targets per client (advertised as MONITOR).
        monitorlimit: u32 = 128,
        /// Max SILENCE masks per client (advertised as SILENCE).
        silencelimit: u32 = 32,
        max_clones_per_ip: u32 = 0,
        max_clones_per_net: u32 = 0,
        /// Nick-delay window (ms): how long a released nick is held against reuse
        /// after its owner exits. `0` disables nick delay entirely.
        nick_delay_ms: u64 = 0,
        /// Connection throttle: max new connections one source IP may open within
        /// `throttle_window_ms`. `0` disables the throttle. Loopback / trusted-proxy
        /// sources are exempt (a shared proxy must not throttle distinct clients).
        throttle_connects: u32 = 0,
        throttle_window_ms: u64 = 10_000,
        /// Network raid guard: default join-throttle for channels without an
        /// explicit `+j`. `raid_joins` joins per `raid_window` before new joins are
        /// denied and a one-shot oper raid alert fires. `0` disables the default.
        raid_joins: u16 = 0,
        raid_window_ms: u64 = 10_000,
        /// Network-wide (mesh) concurrent connections per source IP. `0` disables.
        /// Requires a shared `[mesh] pass` so every node salts IPs identically.
        max_clones_per_ip_net: u32 = 0,
        reputation_refuse_threshold: u32 = 0,
        reputation_half_life_ms: u64 = 60_000,
        /// Period of the io_uring timeout-sweep timer; sets the enforcement
        /// granularity of registration/ping/idle timeouts.
        sweep_interval_ms: u64 = 2_000,
    };

    /// One `[class.<name>]` connection class as parsed from TOML (owned strings).
    /// `policy` carries the resource/admission/flood limits; the `match_*` fields
    /// carry the criteria a connection must satisfy to be assigned the class.
    pub const ClassDef = struct {
        name: []const u8 = "",
        policy: conn_class.Policy = .{},
        match_texts: []const []const u8 = &.{},
        match_tls: bool = false,
        match_account: bool = false,
        match_oper: bool = false,
        ident_glob: ?[]const u8 = null,
        host_glob: ?[]const u8 = null,
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
        reorder_window_frames: u32 = kagura_frame.default_reorder_window_frames,
        max_participants: u32 = @intCast(media_room.default_max_participants),
        /// Require HMAC-tagged native OPVOX/OPVIS datagrams. Defaults off until
        /// clients implement the matching Kagura-frame tag contract.
        native_media_require_mac: bool = false,
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

    /// Live Prometheus `/metrics` HTTP endpoint. Off unless `listen` is set.
    pub const Metrics = struct {
        /// TCP port for the `/metrics` listener. 0 (or absent) = disabled.
        listen: u16 = 0,
        /// Bind address for the listener. SECURITY: defaults to loopback
        /// `127.0.0.1` so metrics are never exposed publicly by default. Set to a
        /// private interface (or "0.0.0.0") only deliberately; front it with a
        /// firewall / reverse proxy for remote scraping.
        bind: []const u8 = "127.0.0.1",
    };

    pub const Geoip = struct {
        /// Path to a MaxMind GeoIP database (.mmdb). Empty = GeoIP disabled.
        database: []const u8 = "",
        /// Optional separate ASN database (.mmdb) for the WHOIS AS-number/org
        /// line (city DBs don't carry ASN). Empty = no ASN in WHOIS.
        asn_database: []const u8 = "",
    };

    pub const Sasl = struct {
        enabled: bool = false,
        /// True when `[sasl].enabled` was present. This preserves older configs
        /// where `account_db` alone implied SASL while letting explicit false be
        /// a real off switch.
        enabled_explicit: bool = false,
        allow_anonymous: bool = false,
        realm: ?[]const u8 = null,
        /// Path (relative to the daemon cwd) of the WAL-backed account store. When
        /// set, the daemon opens it and verifies SASL credentials against it.
        account_db: ?[]const u8 = null,
        oauth_issuer: ?[]const u8 = null,
        oauth_audience: ?[]const u8 = null,
        /// Optional claim name mapped to the account. Null means "sub".
        oauth_account_claim: ?[]const u8 = null,
        oauth_hmac_key: ?[]const u8 = null,
        oauth_jwks_file: ?[]const u8 = null,
        oauth_pubkey: ?[]const u8 = null,
    };

    pub const Cloak = struct {
        /// Secret passphrase for hostname cloaking. Hashed to a 32-byte key at
        /// boot; when set, every client's real IP is HMAC-cloaked. When absent,
        /// the daemon generates a random per-boot key (privacy on by default).
        secret: ?[]const u8 = null,
        /// Network-identifying suffix carried by cloaked hosts (IP cloaks end
        /// in `.ip.<suffix>` / `.ip6.<suffix>`; hostname cloaks prefix their
        /// token label with `<suffix>-`). Null = the cloak module's default.
        suffix: ?[]const u8 = null,
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
        /// Enable TLS 1.3 session tickets and PSK resumption on the live TLS
        /// listener. Off by default so existing deployments keep full-handshake
        /// behavior unless they explicitly opt in.
        enable_resumption: bool = false,
        /// Maximum accepted TLS 1.3 0-RTT early application bytes advertised in
        /// issued tickets. Zero disables early data while keeping PSK resumption.
        early_data_max_size: u32 = 0,
    };

    /// In-daemon ACME renewal scheduler. Issuance uses the existing ACME runner
    /// and writes to the configured `[tls]` cert/key paths; this section only
    /// controls cadence and CA/account inputs.
    pub const Acme = struct {
        enabled: bool = false,
        directory_url: []const u8 = acme_default_directory_url,
        domain: ?[]const u8 = null,
        contact: ?[]const u8 = null,
        renew_before_days: u16 = 30,
        check_interval_ms: u64 = 12 * 60 * 60 * 1000,
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
        const metrics_bind = try allocator.dupe(u8, "127.0.0.1");
        errdefer allocator.free(metrics_bind);
        const geoip_db = try allocator.dupe(u8, "");
        errdefer allocator.free(geoip_db);
        const geoip_asn_db = try allocator.dupe(u8, "");
        errdefer allocator.free(geoip_asn_db);
        const acme_directory_url = try allocator.dupe(u8, acme_default_directory_url);
        errdefer allocator.free(acme_directory_url);
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
            .metrics = .{ .bind = metrics_bind },
            .geoip = .{ .database = geoip_db, .asn_database = geoip_asn_db },
            .acme = .{ .directory_url = acme_directory_url },
        };
    }

    pub fn deinit(self: *Config, allocator: std.mem.Allocator) void {
        if (self.node.public_key) |value| allocator.free(value);
        if (self.node.secret_key) |value| allocator.free(value);
        allocator.free(self.network.name);
        if (self.network.server_name) |v| allocator.free(v);
        if (self.network.description) |v| allocator.free(v);
        if (self.network.icon_url) |v| allocator.free(v);
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
        if (self.wasm.plugin_dir) |v| allocator.free(v);
        allocator.free(self.listen.host);
        freeStringList(allocator, self.listen.trusted_proxies);
        allocator.free(self.listen.media_host);
        for (self.opers) |oper| {
            allocator.free(oper.account);
            allocator.free(oper.class);
            allocator.free(oper.title);
            freeStringList(allocator, oper.presubscribe);
        }
        allocator.free(self.opers);
        for (self.oper_groups) |g| {
            allocator.free(g.name);
            freeStringList(allocator, g.privileges);
            allocator.free(g.inherits);
        }
        allocator.free(self.oper_groups);
        for (self.classes) |c| {
            allocator.free(c.name);
            freeStringList(allocator, c.match_texts);
            if (c.ident_glob) |g| allocator.free(g);
            if (c.host_glob) |g| allocator.free(g);
        }
        allocator.free(self.classes);
        allocator.free(self.mesh.realm);
        freeStringList(allocator, self.mesh.trust_roots);
        freeStringList(allocator, self.mesh.connect);
        freeStringList(allocator, self.dnsbl.zones);
        if (self.mail.relay_host) |value| allocator.free(value);
        if (self.mail.from) |value| allocator.free(value);
        if (self.mail.user) |value| allocator.free(value);
        if (self.mail.pass) |value| allocator.free(value);
        if (self.mesh.mesh_pass) |value| allocator.free(value);
        if (self.sasl.realm) |value| allocator.free(value);
        if (self.sasl.account_db) |value| allocator.free(value);
        if (self.sasl.oauth_issuer) |value| allocator.free(value);
        if (self.sasl.oauth_audience) |value| allocator.free(value);
        if (self.sasl.oauth_account_claim) |value| allocator.free(value);
        if (self.sasl.oauth_hmac_key) |value| allocator.free(value);
        if (self.sasl.oauth_jwks_file) |value| allocator.free(value);
        if (self.sasl.oauth_pubkey) |value| allocator.free(value);
        if (self.media.stun_host) |value| allocator.free(value);
        allocator.free(self.stats.dir);
        allocator.free(self.metrics.bind);
        allocator.free(self.geoip.database);
        allocator.free(self.geoip.asn_database);
        if (self.cloak.secret) |value| allocator.free(value);
        if (self.cloak.suffix) |value| allocator.free(value);
        allocator.free(self.tls.dns_name);
        if (self.tls.cert_path) |value| allocator.free(value);
        if (self.tls.key_path) |value| allocator.free(value);
        allocator.free(self.acme.directory_url);
        if (self.acme.domain) |value| allocator.free(value);
        if (self.acme.contact) |value| allocator.free(value);
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
    try setOpt(allocator, resolver, doc.getString("network.description"), &cfg.network.description);
    try setOpt(allocator, resolver, doc.getString("network.icon_url"), &cfg.network.icon_url);

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
    if (doc.getBool("oper.auto_override")) |b| cfg.oper.auto_override = b;
    try setOpt(allocator, resolver, doc.getString("wasm.plugin_dir"), &cfg.wasm.plugin_dir);

    // [listen]
    try setStr(allocator, resolver, doc.getString("listen.host"), &cfg.listen.host);
    cfg.listen.irc = try portField(doc, "listen.irc", cfg.listen.irc);
    cfg.listen.ws = try portField(doc, "listen.ws", cfg.listen.ws);
    if (doc.getBool("listen.ws_plain")) |b| cfg.listen.ws_plain = b;
    cfg.listen.webtransport = try portField(doc, "listen.webtransport", cfg.listen.webtransport);
    if (doc.getBool("listen.proxy_protocol")) |b| cfg.listen.proxy_protocol = b;
    if (doc.getArray("listen.trusted_proxies")) |arr| {
        freeStringList(allocator, cfg.listen.trusted_proxies);
        cfg.listen.trusted_proxies = try ownStringArray(allocator, resolver, arr);
    }
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
    if (doc.getArray("mesh.connect")) |arr| {
        freeStringList(allocator, cfg.mesh.connect);
        cfg.mesh.connect = try ownStringArray(allocator, resolver, arr);
    }
    if (doc.getBool("mesh.require_secured")) |b| cfg.mesh.require_secured = b;

    // [dnsbl]
    if (doc.getBool("dnsbl.enabled")) |b| cfg.dnsbl.enabled = b;
    if (doc.getArray("dnsbl.zones")) |arr| {
        freeStringList(allocator, cfg.dnsbl.zones);
        cfg.dnsbl.zones = try ownStringArray(allocator, resolver, arr);
    }
    if (doc.getString("dnsbl.action")) |a| cfg.dnsbl.ward = std.ascii.eqlIgnoreCase(a, "ward");

    // [mail]
    if (doc.getBool("mail.enabled")) |b| cfg.mail.enabled = b;
    try setOpt(allocator, resolver, doc.getString("mail.relay_host"), &cfg.mail.relay_host);
    cfg.mail.relay_port = @intCast(try uintField(doc, "mail.relay_port", cfg.mail.relay_port, 1, 65535));
    if (doc.getBool("mail.starttls")) |b| cfg.mail.starttls = b;
    if (doc.getBool("mail.insecure_skip_verify")) |b| cfg.mail.insecure_skip_verify = b;
    try setOpt(allocator, resolver, doc.getString("mail.from"), &cfg.mail.from);
    try setOpt(allocator, resolver, doc.getString("mail.user"), &cfg.mail.user);
    try setOpt(allocator, resolver, doc.getString("mail.pass"), &cfg.mail.pass);

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
    cfg.limits.modes_per_line = @intCast(try uintField(doc, "limits.modes_per_line", cfg.limits.modes_per_line, 1, 20));
    cfg.limits.monitorlimit = @intCast(try uintField(doc, "limits.monitorlimit", cfg.limits.monitorlimit, 1, 100000));
    cfg.limits.silencelimit = @intCast(try uintField(doc, "limits.silencelimit", cfg.limits.silencelimit, 1, 256));
    cfg.limits.reputation_refuse_threshold = @intCast(try uintField(doc, "limits.reputation_refuse_threshold", cfg.limits.reputation_refuse_threshold, 0, 1_000_000));
    if (doc.getString("limits.nick_delay")) |s| cfg.limits.nick_delay_ms = try durationMs(s);
    cfg.limits.throttle_connects = @intCast(try uintField(doc, "limits.throttle_connects", cfg.limits.throttle_connects, 0, 1_000_000));
    if (doc.getString("limits.throttle_window")) |s| cfg.limits.throttle_window_ms = try durationMs(s);
    cfg.limits.raid_joins = @intCast(try uintField(doc, "limits.raid_joins", cfg.limits.raid_joins, 0, 65535));
    if (doc.getString("limits.raid_window")) |s| cfg.limits.raid_window_ms = try durationMs(s);
    cfg.limits.max_clones_per_ip_net = @intCast(try uintField(doc, "limits.max_clones_per_ip_net", cfg.limits.max_clones_per_ip_net, 0, 65535));
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
    cfg.media.reorder_window_frames = @intCast(try uintField(doc, "media.reorder_window_frames", cfg.media.reorder_window_frames, 1, kagura_frame.window_cap));
    cfg.media.max_participants = @intCast(try uintField(doc, "media.max_participants", cfg.media.max_participants, 1, media_room.max_participants));
    if (doc.getBool("media.native_media_require_mac")) |b| cfg.media.native_media_require_mac = b;
    try setOpt(allocator, resolver, doc.getString("media.stun_host"), &cfg.media.stun_host);

    try setStr(allocator, resolver, doc.getString("stats.dir"), &cfg.stats.dir);
    if (doc.getString("stats.interval")) |s| cfg.stats.interval_ms = @intCast(try durationMs(s));

    // [metrics] — live Prometheus /metrics endpoint. `listen` = 0/absent off;
    // `bind` defaults to loopback (security: not public by default).
    cfg.metrics.listen = try portField(doc, "metrics.listen", cfg.metrics.listen);
    try setStr(allocator, resolver, doc.getString("metrics.bind"), &cfg.metrics.bind);

    try setStr(allocator, resolver, doc.getString("geoip.database"), &cfg.geoip.database);
    try setStr(allocator, resolver, doc.getString("geoip.asn_database"), &cfg.geoip.asn_database);
    cfg.media.stun_port = try portField(doc, "media.stun_port", cfg.media.stun_port);

    // [sasl]
    if (doc.getBool("sasl.enabled")) |b| {
        cfg.sasl.enabled = b;
        cfg.sasl.enabled_explicit = true;
    }
    try setOpt(allocator, resolver, doc.getString("sasl.realm"), &cfg.sasl.realm);
    try setOpt(allocator, resolver, doc.getString("sasl.account_db"), &cfg.sasl.account_db);
    if (doc.getBool("sasl.allow_anonymous")) |b| cfg.sasl.allow_anonymous = b;
    try setOpt(allocator, resolver, doc.getString("sasl.oauth_issuer"), &cfg.sasl.oauth_issuer);
    try setOpt(allocator, resolver, doc.getString("sasl.oauth_audience"), &cfg.sasl.oauth_audience);
    try setOpt(allocator, resolver, doc.getString("sasl.oauth_account_claim"), &cfg.sasl.oauth_account_claim);
    try setOpt(allocator, resolver, doc.getString("sasl.oauth_hmac_key"), &cfg.sasl.oauth_hmac_key);
    try setOpt(allocator, resolver, doc.getString("sasl.oauth_jwks_file"), &cfg.sasl.oauth_jwks_file);
    try setOpt(allocator, resolver, doc.getString("sasl.oauth_pubkey"), &cfg.sasl.oauth_pubkey);
    const oauth_key_sources: usize =
        @as(usize, @intFromBool(cfg.sasl.oauth_hmac_key != null)) +
        @as(usize, @intFromBool(cfg.sasl.oauth_jwks_file != null)) +
        @as(usize, @intFromBool(cfg.sasl.oauth_pubkey != null));
    if (oauth_key_sources > 1) return error.ParseError;

    // [cloak]
    try setOpt(allocator, resolver, doc.getString("cloak.secret"), &cfg.cloak.secret);
    try setOpt(allocator, resolver, doc.getString("cloak.suffix"), &cfg.cloak.suffix);

    // [tls]
    if (doc.getBool("tls.enabled")) |b| cfg.tls.enabled = b;
    cfg.tls.port = try portField(doc, "tls.port", cfg.tls.port);
    try setOpt(allocator, resolver, doc.getString("tls.cert_path"), &cfg.tls.cert_path);
    try setOpt(allocator, resolver, doc.getString("tls.key_path"), &cfg.tls.key_path);
    try setStr(allocator, resolver, doc.getString("tls.dns_name"), &cfg.tls.dns_name);
    if (doc.getBool("tls.request_client_cert")) |b| cfg.tls.request_client_cert = b;
    if (doc.getBool("tls.enable_tls12")) |b| cfg.tls.enable_tls12 = b;
    if (doc.getBool("tls.enable_resumption")) |b| cfg.tls.enable_resumption = b;
    cfg.tls.early_data_max_size = @intCast(try uintField(doc, "tls.early_data_max_size", cfg.tls.early_data_max_size, 0, std.math.maxInt(u32)));

    // [acme]
    if (doc.getBool("acme.enabled")) |b| cfg.acme.enabled = b;
    try setStr(allocator, resolver, doc.getString("acme.directory_url"), &cfg.acme.directory_url);
    try setOpt(allocator, resolver, doc.getString("acme.domain"), &cfg.acme.domain);
    try setOpt(allocator, resolver, doc.getString("acme.contact"), &cfg.acme.contact);
    cfg.acme.renew_before_days = @intCast(try uintField(doc, "acme.renew_before_days", cfg.acme.renew_before_days, 1, 89));
    if (doc.getString("acme.check_interval")) |s| cfg.acme.check_interval_ms = try durationMs(s);

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
                allocator.free(o.title);
                freeStringList(allocator, o.presubscribe);
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
            errdefer allocator.free(title);
            const presubscribe: []const []const u8 = if (item.getArray("presubscribe")) |parr|
                try ownStringArray(allocator, resolver, parr)
            else
                &.{};
            try list.append(allocator, .{ .account = account, .class = class, .title = title, .presubscribe = presubscribe });
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

    // [class.*] connection classes — a table of named sub-tables. Each becomes a
    // ClassDef (policy + match criteria); config_boot builds the live Registry.
    if (doc.get("class")) |class_val| switch (class_val.*) {
        .table => |tbl| {
            var list: std.ArrayList(Config.ClassDef) = .empty;
            errdefer {
                for (list.items) |c| {
                    allocator.free(c.name);
                    freeStringList(allocator, c.match_texts);
                    if (c.ident_glob) |g| allocator.free(g);
                    if (c.host_glob) |g| allocator.free(g);
                }
                list.deinit(allocator);
            }
            var it = tbl.iterator();
            while (it.next()) |entry| {
                const item = entry.value_ptr;
                if (std.meta.activeTag(item.*) != .table) continue;
                const name = try allocator.dupe(u8, entry.key_ptr.*);
                errdefer allocator.free(name);
                var policy = conn_class.Policy{};
                policy.sendq = try classSize(item, "sendq", policy.sendq);
                policy.recvq = try classSize(item, "recvq", policy.recvq);
                policy.max_clients = try classU32(item, "max_clients", policy.max_clients);
                policy.max_per_ip = try classU32(item, "max_per_ip", policy.max_per_ip);
                policy.max_per_account = try classU32(item, "max_per_account", policy.max_per_account);
                policy.max_per_host = try classU32(item, "max_per_host", policy.max_per_host);
                policy.max_channels = try classU32(item, "max_channels", policy.max_channels);
                policy.ping_interval_ms = try classDur(item, "ping_interval", policy.ping_interval_ms);
                policy.ping_timeout_ms = try classDur(item, "ping_timeout", policy.ping_timeout_ms);
                policy.register_timeout_ms = try classDur(item, "register_timeout", policy.register_timeout_ms);
                policy.flood_lines = try classU32(item, "flood_lines", policy.flood_lines);
                policy.flood_window_ms = try classDur(item, "flood_window", policy.flood_window_ms);
                policy.flood_excess = try classU32(item, "flood_excess", policy.flood_excess);
                policy.flood_targets = try classU32(item, "flood_targets", policy.flood_targets);
                policy.require_tls = item.getBool("require_tls") orelse policy.require_tls;
                policy.require_sasl = item.getBool("require_sasl") orelse policy.require_sasl;
                policy.flood_exempt = item.getBool("flood_exempt") orelse policy.flood_exempt;
                policy.nick_delay_exempt = item.getBool("nick_delay_exempt") orelse policy.nick_delay_exempt;
                policy.max_targets = try classU32(item, "max_targets", policy.max_targets);
                policy.monitor = try classU32(item, "monitor", policy.monitor);
                policy.silence = try classU32(item, "silence", policy.silence);
                const match_texts: []const []const u8 = if (item.getArray("match")) |marr|
                    try ownStringArray(allocator, resolver, marr)
                else
                    &.{};
                errdefer freeStringList(allocator, match_texts);
                const ident_glob: ?[]const u8 = if (item.getString("match_ident")) |g| try resolveStr(allocator, resolver, g) else null;
                errdefer if (ident_glob) |g| allocator.free(g);
                const host_glob: ?[]const u8 = if (item.getString("match_host")) |g| try resolveStr(allocator, resolver, g) else null;
                errdefer if (host_glob) |g| allocator.free(g);
                try list.append(allocator, .{
                    .name = name,
                    .policy = policy,
                    .match_texts = match_texts,
                    .match_tls = item.getBool("match_tls") orelse false,
                    .match_account = item.getBool("match_account") orelse false,
                    .match_oper = item.getBool("match_oper") orelse false,
                    .ident_glob = ident_glob,
                    .host_glob = host_glob,
                });
            }
            cfg.classes = try list.toOwnedSlice(allocator);
        },
        else => {},
    };

    // Required-field validation.
    if (cfg.node.id == 0) return error.ParseError;
    if (cfg.listen.irc == 0) return error.ParseError;
    for (cfg.opers) |o| if (o.account.len == 0) return error.ParseError;

    return cfg;
}

/// Read a class byte-size field: a string ("1M") parsed via `conn_class.parseSize`
/// or a bare integer (bytes). Missing → `current`.
fn classSize(item: *const toml.Value, key: []const u8, current: u64) TomlError!u64 {
    if (item.getString(key)) |s| return conn_class.parseSize(s) catch return error.ParseError;
    if (item.getInt(key)) |n| {
        if (n < 0) return error.ParseError;
        return @intCast(n);
    }
    return current;
}

/// Read a class duration field (ms): a string ("120s") via `parseDurationMs` or a
/// bare integer (ms). Missing → `current`.
fn classDur(item: *const toml.Value, key: []const u8, current: u64) TomlError!u64 {
    if (item.getString(key)) |s| return conn_class.parseDurationMs(s) catch return error.ParseError;
    if (item.getInt(key)) |n| {
        if (n < 0) return error.ParseError;
        return @intCast(n);
    }
    return current;
}

/// Read a class u32 count field. Missing → `current`.
fn classU32(item: *const toml.Value, key: []const u8, current: u32) TomlError!u32 {
    if (item.getInt(key)) |n| {
        if (n < 0 or n > std.math.maxInt(u32)) return error.ParseError;
        return @intCast(n);
    }
    return current;
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
        \\connect = ["ircx.us:6900", "[::1]:7900"]
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
    try testing.expectEqual(@as(usize, 2), cfg.mesh.connect.len);
    try testing.expectEqualStrings("ircx.us:6900", cfg.mesh.connect[0]);
    try testing.expectEqualStrings("[::1]:7900", cfg.mesh.connect[1]);
    try testing.expectEqual(@as(usize, 2), cfg.opers.len);
    try testing.expectEqualStrings("admin", cfg.opers[0].account);
    try testing.expectEqualStrings("netadmin", cfg.opers[0].class);
    try testing.expectEqualStrings("helper", cfg.opers[1].account);
    try testing.expectEqualStrings("", cfg.opers[1].class);
}

test "parseToml: [dnsbl] enabled + zones + action project onto Config" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[dnsbl]
        \\enabled = true
        \\zones = ["zen.spamhaus.org", "dnsbl.dronebl.org"]
        \\action = "ward"
        \\
    ;
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);
    try testing.expect(cfg.dnsbl.enabled);
    try testing.expectEqual(@as(usize, 2), cfg.dnsbl.zones.len);
    try testing.expectEqualStrings("zen.spamhaus.org", cfg.dnsbl.zones[0]);
    try testing.expectEqualStrings("dnsbl.dronebl.org", cfg.dnsbl.zones[1]);
    try testing.expect(cfg.dnsbl.ward); // action = "ward"
}

test "parseToml: [dnsbl] defaults are disabled, no zones, refuse" {
    const allocator = testing.allocator;
    var cfg = try parseToml(allocator, "[node]\nid = 1\n[listen]\nirc = 6680\n", .{});
    defer cfg.deinit(allocator);
    try testing.expect(!cfg.dnsbl.enabled);
    try testing.expectEqual(@as(usize, 0), cfg.dnsbl.zones.len);
    try testing.expect(!cfg.dnsbl.ward);
}

test "parseToml: listen proxy protocol and SASL enabled gate project" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\proxy_protocol = true
        \\trusted_proxies = ["127.0.0.1", "::1"]
        \\[sasl]
        \\enabled = false
        \\realm = "ircxnet"
        \\account_db = "accounts.oro"
        \\allow_anonymous = true
        \\oauth_issuer = "https://issuer.example"
        \\oauth_audience = "orochi"
        \\oauth_account_claim = "preferred_username"
        \\oauth_hmac_key = "test-secret"
        \\
    ;
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);
    try testing.expect(cfg.listen.proxy_protocol);
    try testing.expectEqual(@as(usize, 2), cfg.listen.trusted_proxies.len);
    try testing.expectEqualStrings("127.0.0.1", cfg.listen.trusted_proxies[0]);
    try testing.expect(!cfg.sasl.enabled);
    try testing.expect(cfg.sasl.enabled_explicit);
    try testing.expect(cfg.sasl.allow_anonymous);
    try testing.expectEqualStrings("ircxnet", cfg.sasl.realm.?);
    try testing.expectEqualStrings("accounts.oro", cfg.sasl.account_db.?);
    try testing.expectEqualStrings("https://issuer.example", cfg.sasl.oauth_issuer.?);
    try testing.expectEqualStrings("orochi", cfg.sasl.oauth_audience.?);
    try testing.expectEqualStrings("preferred_username", cfg.sasl.oauth_account_claim.?);
    try testing.expectEqualStrings("test-secret", cfg.sasl.oauth_hmac_key.?);

    var omitted = try parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\
    , .{});
    defer omitted.deinit(allocator);
    try testing.expect(!omitted.sasl.enabled_explicit);
    try testing.expect(!omitted.sasl.allow_anonymous);
    try testing.expect(omitted.sasl.oauth_account_claim == null);
}

test "parseToml: [sasl] rejects multiple OAuth key sources" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[sasl]
        \\oauth_hmac_key = "secret"
        \\oauth_pubkey = "{}"
        \\
    ;
    try testing.expectError(error.ParseError, parseToml(allocator, text, .{}));
}

test "parseToml: [mesh].require_secured projects onto Config and defaults false" {
    const allocator = testing.allocator;
    // Explicit true.
    {
        const text =
            \\[node]
            \\id = 1
            \\[listen]
            \\irc = 6680
            \\[mesh]
            \\realm = "ircxnet"
            \\require_secured = true
            \\
        ;
        var cfg = try parseToml(allocator, text, .{});
        defer cfg.deinit(allocator);
        try testing.expect(cfg.mesh.require_secured);
    }
    // Omitted → backward-compatible default (plaintext fallback allowed).
    {
        const text =
            \\[node]
            \\id = 1
            \\[listen]
            \\irc = 6680
            \\[mesh]
            \\realm = "ircxnet"
            \\
        ;
        var cfg = try parseToml(allocator, text, .{});
        defer cfg.deinit(allocator);
        try testing.expect(!cfg.mesh.require_secured);
    }
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
        \\suffix = "ircxnet"
        \\
    ;
    var cfg = try parseToml(allocator, text, .{ .env = Ctx.env });
    defer cfg.deinit(allocator);
    try testing.expectEqualStrings("s3kr3t", cfg.cloak.secret.?);
    try testing.expectEqualStrings("ircxnet", cfg.cloak.suffix.?);
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
    try testing.expect(!cfg.media.native_media_require_mac);
}

test "parseToml: media sizing keys default, lift, and validate ranges" {
    const allocator = testing.allocator;
    const base =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\
    ;
    var dflt = try parseToml(allocator, base, .{});
    defer dflt.deinit(allocator);
    try testing.expectEqual(kagura_frame.default_reorder_window_frames, dflt.media.reorder_window_frames);
    try testing.expectEqual(@as(u32, @intCast(media_room.default_max_participants)), dflt.media.max_participants);

    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[media]
        \\reorder_window_frames = 32
        \\max_participants = 2
        \\
    ;
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);
    try testing.expectEqual(@as(u32, 32), cfg.media.reorder_window_frames);
    try testing.expectEqual(@as(u32, 2), cfg.media.max_participants);

    try testing.expectError(error.ParseError, parseToml(allocator, base ++ "[media]\nreorder_window_frames = 0\n", .{}));
    try testing.expectError(error.ParseError, parseToml(allocator, base ++ "[media]\nmax_participants = 0\n", .{}));

    const too_wide_window = try std.fmt.allocPrint(allocator, "{s}[media]\nreorder_window_frames = {d}\n", .{ base, kagura_frame.window_cap + 1 });
    defer allocator.free(too_wide_window);
    try testing.expectError(error.ParseError, parseToml(allocator, too_wide_window, .{}));

    const too_many_participants = try std.fmt.allocPrint(allocator, "{s}[media]\nmax_participants = {d}\n", .{ base, media_room.max_participants + 1 });
    defer allocator.free(too_many_participants);
    try testing.expectError(error.ParseError, parseToml(allocator, too_many_participants, .{}));
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
        \\enable_tls12 = true
        \\enable_resumption = true
        \\early_data_max_size = 16384
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
    // These three keys were declared in the schema but never parsed — a TLS 1.2
    // opt-in (and resumption/0-RTT) was silently ignored. Guard the wiring.
    try testing.expect(cfg.tls.enable_tls12);
    try testing.expect(cfg.tls.enable_resumption);
    try testing.expectEqual(@as(u32, 16384), cfg.tls.early_data_max_size);
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

test "parseToml: [acme] section projects onto Config" {
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
        \\renew_before_days = 45
        \\check_interval = "6h"
        \\
    ;
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);

    try testing.expect(cfg.acme.enabled);
    try testing.expectEqualStrings("https://acme.example/directory", cfg.acme.directory_url);
    try testing.expectEqualStrings("irc.example.test", cfg.acme.domain.?);
    try testing.expectEqualStrings("mailto:admin@example.test", cfg.acme.contact.?);
    try testing.expectEqual(@as(u16, 45), cfg.acme.renew_before_days);
    try testing.expectEqual(@as(u64, 6 * 60 * 60 * 1000), cfg.acme.check_interval_ms);
}

test "parseToml: [acme] omitted keeps renewal disabled defaults and validates ranges" {
    const allocator = testing.allocator;
    var cfg = try parseToml(allocator, "[node]\nid = 1\n[listen]\nirc = 6680\n", .{});
    defer cfg.deinit(allocator);

    try testing.expect(!cfg.acme.enabled);
    try testing.expectEqualStrings(acme_default_directory_url, cfg.acme.directory_url);
    try testing.expectEqual(@as(?[]const u8, null), cfg.acme.domain);
    try testing.expectEqual(@as(?[]const u8, null), cfg.acme.contact);
    try testing.expectEqual(@as(u16, 30), cfg.acme.renew_before_days);
    try testing.expectEqual(@as(u64, 12 * 60 * 60 * 1000), cfg.acme.check_interval_ms);

    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[acme]
        \\renew_before_days = 0
        \\
    , .{}));
    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[acme]
        \\renew_before_days = 90
        \\
    , .{}));
    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[acme]
        \\check_interval = "0s"
        \\
    , .{}));
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

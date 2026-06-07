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
const og_mod = @import("operator_groups.zig");

/// Overlay non-empty/non-zero config values onto `base` (which carries defaults).
/// `cfg`'s string fields (e.g. host) are borrowed — keep `cfg` alive as long as
/// the returned Config is used.
pub fn mapToServerConfig(cfg: config_format.Config, base: server.Config) server.Config {
    var out = base;
    if (cfg.listen.irc != 0) out.port = cfg.listen.irc;
    if (cfg.listen.host.len != 0) out.host = cfg.listen.host;
    if (cfg.listen.s2s != 0) out.s2s_port = cfg.listen.s2s;
    if (cfg.listen.media != 0) out.media_port = cfg.listen.media;
    if (cfg.listen.media_host.len != 0) out.media_host = cfg.listen.media_host;
    out.backlog = cfg.limits.backlog;
    out.max_clients = cfg.limits.max_clients;
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
    return out;
}

/// Parse `text` and overlay it onto `base`. Returns the mapped Config plus the
/// owned parsed config (caller must `deinit` it AFTER it is done using the
/// returned Config, since string fields are borrowed). On parse failure returns
/// the error and, when available, fills `diag_out`.
pub const Loaded = struct {
    config: server.Config,
    parsed: config_format.Config,
    /// Owned oper bindings backing `config.oper_registry` (strings borrow `parsed`).
    oper_bindings: []oper_mod.OperBinding = &.{},

    pub fn deinit(self: *Loaded, allocator: std.mem.Allocator) void {
        allocator.free(self.oper_bindings);
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
    const bindings = try allocator.alloc(oper_mod.OperBinding, parsed.opers.len);
    errdefer allocator.free(bindings);
    for (parsed.opers, 0..) |o, i| {
        const privileges = blk: {
            if (o.class.len != 0 and groups.get(o.class) != null) {
                const ep = groups.effectivePrivileges(o.class);
                if (ep.count() > 0) break :blk ep; // empty group => fall back to full
            }
            break :blk oper_mod.OperPrivileges.full;
        };
        bindings[i] = .{
            .account_name = o.account,
            .class_name = if (o.class.len != 0) o.class else "operator",
            .privileges = privileges,
        };
    }

    var config = mapToServerConfig(parsed, base);
    if (bindings.len != 0) {
        config.oper_registry = try oper_mod.OperRegistry.init(bindings);
    }
    return .{ .config = config, .parsed = parsed, .oper_bindings = bindings };
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
        \\[limits]
        \\max_clients = 2048
        \\
    ;
    const base = server.Config{ .port = 6680 };
    var loaded = try loadFromText(allocator, text, base, .{});
    defer loaded.deinit(allocator);

    try testing.expectEqual(@as(u16, 6700), loaded.config.port);
    try testing.expectEqualStrings("10.0.0.5", loaded.config.host);
    try testing.expectEqual(@as(u16, 7700), loaded.config.s2s_port);
    try testing.expectEqual(@as(u64, 42), loaded.config.node_id);
    try testing.expectEqual(@as(u31, 2048), loaded.config.max_clients);
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

test "missing required [node].id is rejected" {
    const allocator = testing.allocator;
    const text = "[listen]\nirc = 6680\n";
    try testing.expectError(error.ParseError, loadFromText(allocator, text, .{ .port = 6680 }, .{}));
}

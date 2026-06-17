//! Connection classes — named per-connection policy bundles, matched to each
//! connection by IP (v4 + v6 CIDR), TLS, account, oper, and ident/host globs.
//!
//! A class is a bundle of resource/admission/flood policy (sendq, recvq, clone
//! and channel caps, ping/registration timeouts, require-TLS/SASL, flood limits)
//! plus a set of match criteria. At registration the daemon builds a
//! `MatchContext` from the connection's facets and asks the `Registry` for the
//! winning class: an S2S link always gets the built-in `server` class; otherwise
//! the first custom class whose criteria ALL match (config order = priority)
//! wins, falling back to the built-in `user` class.
//!
//! Intuitive TOML (arbitrary class names, human sizes/durations):
//!
//!   [class.user]                       # built-in default fallback
//!   sendq = "1M"; recvq = "8K"; max_per_ip = 5; max_channels = 50
//!   [class.server]                     # built-in: every S2S mesh link
//!   sendq = "8M"; recvq = "1M"
//!   [class.trusted]                    # custom, IP + TLS matched
//!   sendq = "16M"; max_per_ip = 0; flood_exempt = true
//!   match = ["10.0.0.0/8", "::1", "2001:db8::/32"]; match_tls = true
//!
//! This module is pure (no daemon coupling): the config layer enumerates the
//! `[class.*]` sections and feeds them to `Builder`; the daemon stores the
//! finished `Registry` and matches each connection. Parsing helpers for the
//! human size/duration literals live here so config + tests share one grammar.
const std = @import("std");
const cidr = @import("../proto/cidr.zig");

pub const max_classes: usize = 64;
pub const max_cidrs_per_class: usize = 64;
pub const max_name_len: usize = 32;
pub const max_glob_len: usize = 128;

pub const Error = error{
    TooManyClasses,
    TooManyCidrs,
    NameTooLong,
    GlobTooLong,
    DuplicateClass,
    InvalidCidr,
    OutOfMemory,
};

pub const ParseError = error{ Invalid, OutOfRange };

/// Per-connection policy. A `0` count/duration means "unlimited" (counts) or
/// "inherit the daemon global" (durations); `recvq` also follows the `0 =
/// inherit` convention. `sendq` always carries a concrete byte cap.
pub const Policy = struct {
    /// Outbound send-queue cap in bytes (the growable SendQ ceiling).
    sendq: u64 = 1 << 20, // 1 MiB
    /// Inbound RecvQ ceiling in bytes: the max length of one unterminated line
    /// before the connection is dropped (lines spill to a heap overflow past the
    /// inline buffer). `0` = inherit the daemon's physical line-buffer default.
    recvq: u64 = 0,
    /// Max live connections in this class (0 = unlimited).
    max_clients: u32 = 0,
    /// Max simultaneous connections from one IP in this class (0 = unlimited).
    /// Skipped for loopback / trusted-proxy sources (a shared proxy IP must not
    /// lump distinct WebSocket clients together).
    max_per_ip: u32 = 0,
    /// Max simultaneous connections authenticated to one account in this class
    /// (0 = unlimited). Account is known at registration, so this is WebSocket-
    /// and proxy-safe regardless of the source IP.
    max_per_account: u32 = 0,
    /// Max simultaneous connections from one resolved host in this class
    /// (0 = unlimited). Skipped for the loopback host for the same reason as
    /// `max_per_ip`.
    max_per_host: u32 = 0,
    /// Max channels a member of this class may join (0 = inherit global).
    max_channels: u32 = 0,
    /// PING keepalive interval / timeout (ms; 0 = inherit global).
    ping_interval_ms: u64 = 0,
    ping_timeout_ms: u64 = 0,
    /// Registration (handshake) timeout (ms; 0 = inherit global).
    register_timeout_ms: u64 = 0,
    /// Line-flood: at most `flood_lines` inbound lines per `flood_window_ms`
    /// (0 lines = no line-flood limit).
    flood_lines: u32 = 0,
    flood_window_ms: u64 = 0,
    /// Admission policy: refuse the connection unless it is TLS / SASL-authed.
    require_tls: bool = false,
    require_sasl: bool = false,
    /// Exempt this class from flood/throttle enforcement entirely.
    flood_exempt: bool = false,
    /// Exempt this class from nick-delay holds: a member may take a held nick
    /// without waiting out its window (like operators do).
    nick_delay_exempt: bool = false,
    /// Per-class overrides of global feature caps (0 = inherit global).
    max_targets: u32 = 0,
    monitor: u32 = 0,
    silence: u32 = 0,
};

/// The facets of a live connection used to choose its class.
pub const MatchContext = struct {
    /// The connection's REAL ip as text (used for CIDR matching). Empty/resolved
    /// hostnames simply never match an IP rule.
    ip_text: []const u8 = "",
    is_tls: bool = false,
    has_account: bool = false,
    is_oper: bool = false,
    ident: []const u8 = "",
    host: []const u8 = "",
    /// S2S mesh links always resolve to the built-in `server` class.
    is_server_link: bool = false,
};

/// One named class: a policy plus its match criteria. A connection matches when
/// EVERY specified criterion holds; the CIDR list is satisfied by ANY member.
pub const Class = struct {
    name: []const u8,
    policy: Policy,
    cidrs: []const cidr.Cidr = &.{},
    tls_only: bool = false,
    account_only: bool = false,
    oper_only: bool = false,
    ident_glob: ?[]const u8 = null,
    host_glob: ?[]const u8 = null,

    /// True when the class declares any match criterion (so it can auto-match).
    /// A criterion-less custom class never wins — only the built-in fallbacks do.
    pub fn hasCriteria(self: *const Class) bool {
        return self.cidrs.len != 0 or self.tls_only or self.account_only or
            self.oper_only or self.ident_glob != null or self.host_glob != null;
    }

    pub fn matches(self: *const Class, ctx: MatchContext) bool {
        if (!self.hasCriteria()) return false;
        if (self.tls_only and !ctx.is_tls) return false;
        if (self.account_only and !ctx.has_account) return false;
        if (self.oper_only and !ctx.is_oper) return false;
        if (self.cidrs.len != 0) {
            var any = false;
            for (self.cidrs) |c| {
                if (c.containsText(ctx.ip_text) catch false) {
                    any = true;
                    break;
                }
            }
            if (!any) return false;
        }
        if (self.ident_glob) |g| {
            if (!globMatch(g, ctx.ident)) return false;
        }
        if (self.host_glob) |g| {
            if (!globMatch(g, ctx.host)) return false;
        }
        return true;
    }
};

/// The finished, immutable class table. Owns every class's name/cidr/glob
/// storage; call `deinit` to release it.
pub const Registry = struct {
    allocator: std.mem.Allocator,
    classes: []Class,
    user_idx: usize,
    server_idx: usize,

    /// Resolve the winning class for a connection (never null).
    pub fn classFor(self: *const Registry, ctx: MatchContext) *const Class {
        if (ctx.is_server_link) return &self.classes[self.server_idx];
        for (self.classes) |*c| {
            if (c.matches(ctx)) return c;
        }
        return &self.classes[self.user_idx];
    }

    pub fn byName(self: *const Registry, name: []const u8) ?*const Class {
        for (self.classes) |*c| {
            if (std.ascii.eqlIgnoreCase(c.name, name)) return c;
        }
        return null;
    }

    pub fn deinit(self: *Registry) void {
        for (self.classes) |*c| {
            self.allocator.free(c.name);
            self.allocator.free(c.cidrs);
            if (c.ident_glob) |g| self.allocator.free(g);
            if (c.host_glob) |g| self.allocator.free(g);
        }
        self.allocator.free(self.classes);
        self.* = undefined;
    }
};

/// Definition fed to the builder by the config layer (borrowed slices; the
/// builder dupes everything it keeps).
pub const Def = struct {
    name: []const u8,
    policy: Policy,
    cidr_texts: []const []const u8 = &.{},
    tls_only: bool = false,
    account_only: bool = false,
    oper_only: bool = false,
    ident_glob: ?[]const u8 = null,
    host_glob: ?[]const u8 = null,
};

/// Builds a `Registry`, guaranteeing the built-in `user` + `server` fallbacks
/// exist (a config may override their policy via a `[class.user]`/`[class.server]`
/// def). Config order is preserved as match priority.
pub const Builder = struct {
    allocator: std.mem.Allocator,
    list: std.ArrayListUnmanaged(Class) = .empty,

    pub fn init(allocator: std.mem.Allocator) Builder {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Builder) void {
        for (self.list.items) |*c| {
            self.allocator.free(c.name);
            self.allocator.free(c.cidrs);
            if (c.ident_glob) |g| self.allocator.free(g);
            if (c.host_glob) |g| self.allocator.free(g);
        }
        self.list.deinit(self.allocator);
    }

    pub fn add(self: *Builder, def: Def) Error!void {
        if (self.list.items.len >= max_classes) return error.TooManyClasses;
        if (def.name.len == 0 or def.name.len > max_name_len) return error.NameTooLong;
        for (self.list.items) |*c| {
            if (std.ascii.eqlIgnoreCase(c.name, def.name)) return error.DuplicateClass;
        }
        if (def.cidr_texts.len > max_cidrs_per_class) return error.TooManyCidrs;

        const name = try self.allocator.dupe(u8, def.name);
        errdefer self.allocator.free(name);

        var cidrs = try self.allocator.alloc(cidr.Cidr, def.cidr_texts.len);
        errdefer self.allocator.free(cidrs);
        for (def.cidr_texts, 0..) |text, i| {
            cidrs[i] = cidr.Cidr.parse(text) catch return error.InvalidCidr;
        }

        const ident_glob = try dupeGlob(self.allocator, def.ident_glob);
        errdefer if (ident_glob) |g| self.allocator.free(g);
        const host_glob = try dupeGlob(self.allocator, def.host_glob);
        errdefer if (host_glob) |g| self.allocator.free(g);

        try self.list.append(self.allocator, .{
            .name = name,
            .policy = def.policy,
            .cidrs = cidrs,
            .tls_only = def.tls_only,
            .account_only = def.account_only,
            .oper_only = def.oper_only,
            .ident_glob = ident_glob,
            .host_glob = host_glob,
        });
    }

    /// Finalize. Appends the built-in `user`/`server` fallbacks if the config did
    /// not define them, and records their indices. The returned Registry owns all
    /// storage; the builder is consumed.
    pub fn finish(self: *Builder) Error!Registry {
        const user_idx = try self.ensureBuiltin("user", .{});
        const server_idx = try self.ensureBuiltin("server", .{ .sendq = 8 << 20 });
        const classes = try self.list.toOwnedSlice(self.allocator);
        return .{
            .allocator = self.allocator,
            .classes = classes,
            .user_idx = user_idx,
            .server_idx = server_idx,
        };
    }

    fn ensureBuiltin(self: *Builder, name: []const u8, default_policy: Policy) Error!usize {
        for (self.list.items, 0..) |*c, i| {
            if (std.ascii.eqlIgnoreCase(c.name, name)) return i;
        }
        const owned = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(owned);
        try self.list.append(self.allocator, .{ .name = owned, .policy = default_policy, .cidrs = &.{} });
        return self.list.items.len - 1;
    }
};

fn dupeGlob(allocator: std.mem.Allocator, glob: ?[]const u8) Error!?[]const u8 {
    const g = glob orelse return null;
    if (g.len > max_glob_len) return error.GlobTooLong;
    return try allocator.dupe(u8, g);
}

// ---------------------------------------------------------------------------
// Human size / duration parsing (shared by the config layer + tests)
// ---------------------------------------------------------------------------

/// Parse a byte size: a bare integer (bytes) or `<n>K|M|G` (binary KiB/MiB/GiB),
/// case-insensitive, optional trailing `B`. e.g. "8192", "8K", "1M", "32m".
pub fn parseSize(text: []const u8) ParseError!u64 {
    return parseScaled(text, &.{
        .{ .suffix = 'k', .mult = 1 << 10 },
        .{ .suffix = 'm', .mult = 1 << 20 },
        .{ .suffix = 'g', .mult = 1 << 30 },
    }, 'b');
}

/// Parse a duration to MILLISECONDS: a bare integer (ms) or `<n>s|m|h|d`.
/// e.g. "30000", "120s", "2m", "1h".
pub fn parseDurationMs(text: []const u8) ParseError!u64 {
    return parseScaled(text, &.{
        .{ .suffix = 's', .mult = 1_000 },
        .{ .suffix = 'm', .mult = 60_000 },
        .{ .suffix = 'h', .mult = 3_600_000 },
        .{ .suffix = 'd', .mult = 86_400_000 },
    }, null);
}

const Unit = struct { suffix: u8, mult: u64 };

fn parseScaled(text_in: []const u8, units: []const Unit, trim: ?u8) ParseError!u64 {
    var text = std.mem.trim(u8, text_in, " \t");
    if (text.len == 0) return error.Invalid;
    // Optional trailing unit byte (e.g. 'B' for sizes) is stripped first.
    if (trim) |t| {
        if (text.len >= 1 and std.ascii.toLower(text[text.len - 1]) == t) text = text[0 .. text.len - 1];
    }
    if (text.len == 0) return error.Invalid;
    var mult: u64 = 1;
    const last = std.ascii.toLower(text[text.len - 1]);
    if (!std.ascii.isDigit(last)) {
        for (units) |u| {
            if (last == u.suffix) {
                mult = u.mult;
                break;
            }
        } else return error.Invalid;
        text = text[0 .. text.len - 1];
    }
    if (text.len == 0) return error.Invalid;
    const n = std.fmt.parseInt(u64, std.mem.trim(u8, text, " \t"), 10) catch return error.Invalid;
    const result = std.math.mul(u64, n, mult) catch return error.OutOfRange;
    return result;
}

/// Minimal IRC-style glob: `*` (any run) and `?` (one char), case-insensitive.
/// Self-contained so the pure module needs no daemon helper.
pub fn globMatch(pattern: []const u8, text: []const u8) bool {
    var p: usize = 0;
    var t: usize = 0;
    var star: ?usize = null;
    var star_t: usize = 0;
    while (t < text.len) {
        if (p < pattern.len and (pattern[p] == '?' or std.ascii.toLower(pattern[p]) == std.ascii.toLower(text[t]))) {
            p += 1;
            t += 1;
        } else if (p < pattern.len and pattern[p] == '*') {
            star = p;
            star_t = t;
            p += 1;
        } else if (star) |s| {
            p = s + 1;
            star_t += 1;
            t = star_t;
        } else return false;
    }
    while (p < pattern.len and pattern[p] == '*') p += 1;
    return p == pattern.len;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "parseSize: bytes, K/M/G, trailing B, case-insensitive" {
    try testing.expectEqual(@as(u64, 8192), try parseSize("8192"));
    try testing.expectEqual(@as(u64, 8 << 10), try parseSize("8K"));
    try testing.expectEqual(@as(u64, 1 << 20), try parseSize("1M"));
    try testing.expectEqual(@as(u64, 32 << 20), try parseSize("32m"));
    try testing.expectEqual(@as(u64, 2 << 30), try parseSize("2G"));
    try testing.expectEqual(@as(u64, 1 << 20), try parseSize("1MB"));
    try testing.expectError(ParseError.Invalid, parseSize("1X"));
    try testing.expectError(ParseError.Invalid, parseSize(""));
}

test "parseDurationMs: ms, s/m/h/d" {
    try testing.expectEqual(@as(u64, 30000), try parseDurationMs("30000"));
    try testing.expectEqual(@as(u64, 120_000), try parseDurationMs("120s"));
    try testing.expectEqual(@as(u64, 120_000), try parseDurationMs("2m"));
    try testing.expectEqual(@as(u64, 3_600_000), try parseDurationMs("1h"));
    try testing.expectError(ParseError.Invalid, parseDurationMs("1y"));
}

test "globMatch: stars and question marks, case-insensitive" {
    try testing.expect(globMatch("*", "anything"));
    try testing.expect(globMatch("ab*", "abcdef"));
    try testing.expect(globMatch("*ef", "abcdef"));
    try testing.expect(globMatch("a?c", "ABC"));
    try testing.expect(globMatch("*.example", "host.example"));
    try testing.expect(!globMatch("a?c", "abbc"));
    try testing.expect(!globMatch("ab", "abc"));
}

test "registry: built-ins synthesized, server link -> server, IP+TLS custom match" {
    var b = Builder.init(testing.allocator);
    // Note: builder is consumed by finish(); no separate deinit on success.
    try b.add(.{
        .name = "trusted",
        .policy = .{ .sendq = 16 << 20, .flood_exempt = true },
        .cidr_texts = &.{ "10.0.0.0/8", "::1" },
        .tls_only = true,
    });
    var reg = try b.finish();
    defer reg.deinit();

    // Built-ins exist.
    try testing.expect(reg.byName("user") != null);
    try testing.expect(reg.byName("server") != null);
    try testing.expectEqual(@as(u64, 8 << 20), reg.byName("server").?.policy.sendq);

    // S2S link -> server class regardless of IP.
    try testing.expectEqualStrings("server", reg.classFor(.{ .is_server_link = true, .ip_text = "10.0.0.5" }).name);

    // 10.x over TLS -> trusted.
    try testing.expectEqualStrings("trusted", reg.classFor(.{ .ip_text = "10.0.0.5", .is_tls = true }).name);
    // 10.x WITHOUT TLS -> falls back to user (tls_only criterion unmet).
    try testing.expectEqualStrings("user", reg.classFor(.{ .ip_text = "10.0.0.5", .is_tls = false }).name);
    // ::1 over TLS -> trusted (v6 CIDR).
    try testing.expectEqualStrings("trusted", reg.classFor(.{ .ip_text = "::1", .is_tls = true }).name);
    // Public IP -> user.
    try testing.expectEqualStrings("user", reg.classFor(.{ .ip_text = "203.0.113.9", .is_tls = true }).name);
}

test "registry: config may override a built-in's policy; duplicate rejected" {
    var b = Builder.init(testing.allocator);
    try b.add(.{ .name = "user", .policy = .{ .sendq = 2 << 20, .max_per_ip = 3 } });
    try testing.expectError(error.DuplicateClass, b.add(.{ .name = "User", .policy = .{} }));
    var reg = try b.finish();
    defer reg.deinit();
    // The overridden user policy is kept (not the synthesized default).
    try testing.expectEqual(@as(u64, 2 << 20), reg.byName("user").?.policy.sendq);
    try testing.expectEqual(@as(u32, 3), reg.byName("user").?.policy.max_per_ip);
}

test "registry: criterion-less custom class never auto-matches" {
    var b = Builder.init(testing.allocator);
    try b.add(.{ .name = "inert", .policy = .{ .sendq = 99 << 20 } }); // no match criteria
    var reg = try b.finish();
    defer reg.deinit();
    try testing.expectEqualStrings("user", reg.classFor(.{ .ip_text = "203.0.113.1" }).name);
}

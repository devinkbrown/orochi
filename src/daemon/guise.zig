//! Guise — Mizuchi's reinvented virtual-host system.
//!
//! Legacy ircds treat a vhost as a single string an operator hangs on a user,
//! or a flat pool of literal offers a user can TAKE one at a time.
//! Guise generalizes that into an identity *wardrobe*:
//!
//!   * Each account holds MULTIPLE named personas and switches between them
//!     instantly with `VHOST USE <name>` — no re-request, no oper round trip.
//!   * Operators publish OFFER *templates* (globs like `*.users.eshmaki.me`),
//!     not just literal hosts; a user self-services any host matching a template
//!     via `VHOST CLAIM <host>` and it becomes a persona immediately.
//!   * Every persona records its PROVENANCE (how it was obtained): operator
//!     grant, self-claim from a template, domain-verified, or auto/cloak — so
//!     the trust origin of an apparent identity is always auditable.
//!
//! This module is pure: it owns the persona + offer storage and the matching
//! logic. The live server applies the active persona to a session (CHGHOST) and
//! gates who may publish offers.

const std = @import("std");

/// How a persona's host was obtained — its trust provenance.
pub const Source = enum {
    granted, // an operator approved a VHOST REQUEST
    claimed, // self-claimed from an operator OFFER template
    verified, // bound to a domain the user proved control of (reserved seam)
    auto, // server-assigned (e.g. cloak-derived default)

    pub fn token(self: Source) []const u8 {
        return switch (self) {
            .granted => "granted",
            .claimed => "claimed",
            .verified => "verified",
            .auto => "auto",
        };
    }
};

/// One named apparent-host a user can wear.
pub const Persona = struct {
    name: []const u8,
    host: []const u8,
    source: Source,
    granted_ms: i64,
};

/// An operator-published vhost template. `template` is a glob (`*`/`?`) that a
/// claimed host must match; `label` is a human description.
pub const Offer = struct {
    template: []const u8,
    label: []const u8,
};

pub const Params = struct {
    max_accounts: usize = 65536,
    max_personas_per_account: usize = 16,
    max_offers: usize = 256,
    max_name: usize = 32,
    max_host: usize = 128,
    max_label: usize = 128,
    max_template: usize = 128,
};

pub const GuiseError = std.mem.Allocator.Error || error{
    NameTooLong,
    HostTooLong,
    LabelTooLong,
    TemplateTooLong,
    EmptyValue,
    TooManyPersonas,
    TooManyOffers,
    TooManyAccounts,
    NotOffered,
    Duplicate,
};

pub const Registry = struct {
    allocator: std.mem.Allocator,
    params: Params,
    /// account (lowercased, owned key) -> owned list of Personas (owned strings).
    accounts: std.StringHashMapUnmanaged(std.ArrayListUnmanaged(Persona)) = .empty,
    offers: std.ArrayListUnmanaged(Offer) = .empty,

    pub fn init(allocator: std.mem.Allocator, params: Params) Registry {
        return .{ .allocator = allocator, .params = params };
    }

    pub fn deinit(self: *Registry) void {
        var it = self.accounts.iterator();
        while (it.next()) |e| {
            for (e.value_ptr.items) |*p| self.freePersona(p);
            e.value_ptr.deinit(self.allocator);
            self.allocator.free(e.key_ptr.*);
        }
        self.accounts.deinit(self.allocator);
        for (self.offers.items) |*o| self.freeOffer(o);
        self.offers.deinit(self.allocator);
        self.* = undefined;
    }

    // ── personas ──────────────────────────────────────────────────────────

    /// Grant a named persona to `account` (replacing one of the same name). The
    /// host's validity is the caller's concern; storage is owned here.
    pub fn grant(self: *Registry, account: []const u8, name: []const u8, host: []const u8, source: Source, now_ms: i64) GuiseError!void {
        if (name.len == 0 or host.len == 0) return error.EmptyValue;
        if (name.len > self.params.max_name) return error.NameTooLong;
        if (host.len > self.params.max_host) return error.HostTooLong;

        const list = try self.accountList(account);
        // Replace a same-named persona in place.
        for (list.items) |*p| {
            if (std.ascii.eqlIgnoreCase(p.name, name)) {
                const new_host = try self.allocator.dupe(u8, host);
                self.allocator.free(@constCast(p.host));
                p.host = new_host;
                p.source = source;
                p.granted_ms = now_ms;
                return;
            }
        }
        if (list.items.len >= self.params.max_personas_per_account) return error.TooManyPersonas;
        const owned_name = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(owned_name);
        const owned_host = try self.allocator.dupe(u8, host);
        errdefer self.allocator.free(owned_host);
        try list.append(self.allocator, .{ .name = owned_name, .host = owned_host, .source = source, .granted_ms = now_ms });
    }

    /// Self-claim `host` if it matches an operator OFFER template. Stored as a
    /// `.claimed` persona named after the host's first label. Returns the offer.
    pub fn claim(self: *Registry, account: []const u8, host: []const u8, now_ms: i64) GuiseError!Offer {
        const offer = self.matchOffer(host) orelse return error.NotOffered;
        const name = firstLabel(host);
        try self.grant(account, name, host, .claimed, now_ms);
        return offer;
    }

    pub fn personas(self: *const Registry, account: []const u8) []const Persona {
        var buf: [Params_account_key_max]u8 = undefined;
        const key = lowerKey(&buf, account) orelse return &.{};
        const list = self.accounts.getPtr(key) orelse return &.{};
        return list.items;
    }

    pub fn find(self: *const Registry, account: []const u8, name: []const u8) ?Persona {
        for (self.personas(account)) |p| {
            if (std.ascii.eqlIgnoreCase(p.name, name)) return p;
        }
        return null;
    }

    pub fn removePersona(self: *Registry, account: []const u8, name: []const u8) bool {
        var buf: [Params_account_key_max]u8 = undefined;
        const key = lowerKey(&buf, account) orelse return false;
        const list = self.accounts.getPtr(key) orelse return false;
        for (list.items, 0..) |*p, i| {
            if (std.ascii.eqlIgnoreCase(p.name, name)) {
                self.freePersona(p);
                _ = list.orderedRemove(i);
                return true;
            }
        }
        return false;
    }

    // ── offers ────────────────────────────────────────────────────────────

    pub fn addOffer(self: *Registry, template: []const u8, label: []const u8) GuiseError!void {
        if (template.len == 0) return error.EmptyValue;
        if (template.len > self.params.max_template) return error.TemplateTooLong;
        if (label.len > self.params.max_label) return error.LabelTooLong;
        for (self.offers.items) |o| {
            if (std.ascii.eqlIgnoreCase(o.template, template)) return error.Duplicate;
        }
        if (self.offers.items.len >= self.params.max_offers) return error.TooManyOffers;
        const t = try self.allocator.dupe(u8, template);
        errdefer self.allocator.free(t);
        const l = try self.allocator.dupe(u8, label);
        try self.offers.append(self.allocator, .{ .template = t, .label = l });
    }

    pub fn removeOffer(self: *Registry, template: []const u8) bool {
        for (self.offers.items, 0..) |*o, i| {
            if (std.ascii.eqlIgnoreCase(o.template, template)) {
                self.freeOffer(o);
                _ = self.offers.orderedRemove(i);
                return true;
            }
        }
        return false;
    }

    pub fn offerList(self: *const Registry) []const Offer {
        return self.offers.items;
    }

    /// First offer whose template glob matches `host`, or null.
    pub fn matchOffer(self: *const Registry, host: []const u8) ?Offer {
        for (self.offers.items) |o| {
            if (globMatch(o.template, host)) return o;
        }
        return null;
    }

    // ── internals ─────────────────────────────────────────────────────────

    fn accountList(self: *Registry, account: []const u8) GuiseError!*std.ArrayListUnmanaged(Persona) {
        var buf: [Params_account_key_max]u8 = undefined;
        const key = lowerKey(&buf, account) orelse return error.NameTooLong;
        if (self.accounts.getPtr(key)) |list| return list;
        if (self.accounts.count() >= self.params.max_accounts) return error.TooManyAccounts;
        const owned_key = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(owned_key);
        try self.accounts.put(self.allocator, owned_key, .empty);
        return self.accounts.getPtr(owned_key).?;
    }

    fn freePersona(self: *Registry, p: *Persona) void {
        self.allocator.free(@constCast(p.name));
        self.allocator.free(@constCast(p.host));
    }

    fn freeOffer(self: *Registry, o: *Offer) void {
        self.allocator.free(@constCast(o.template));
        self.allocator.free(@constCast(o.label));
    }
};

const Params_account_key_max = 128;

fn lowerKey(buf: []u8, account: []const u8) ?[]const u8 {
    if (account.len == 0 or account.len > buf.len) return null;
    return std.ascii.lowerString(buf[0..account.len], account);
}

/// The label before the first '.' of a host (used to auto-name a claimed persona).
fn firstLabel(host: []const u8) []const u8 {
    const dot = std.mem.indexOfScalar(u8, host, '.') orelse return host;
    return if (dot == 0) host else host[0..dot];
}

/// Iterative, case-insensitive `*`/`?` glob (no recursion, backtracking).
pub fn globMatch(pattern: []const u8, text: []const u8) bool {
    var p: usize = 0;
    var t: usize = 0;
    var star: ?usize = null;
    var mark: usize = 0;
    while (t < text.len) {
        if (p < pattern.len and (pattern[p] == '?' or std.ascii.toLower(pattern[p]) == std.ascii.toLower(text[t]))) {
            p += 1;
            t += 1;
        } else if (p < pattern.len and pattern[p] == '*') {
            star = p;
            mark = t;
            p += 1;
        } else if (star) |s| {
            p = s + 1;
            mark += 1;
            t = mark;
        } else return false;
    }
    while (p < pattern.len and pattern[p] == '*') p += 1;
    return p == pattern.len;
}

// ── tests ──────────────────────────────────────────────────────────────────

test "grant stores multiple named personas; find + remove" {
    var reg = Registry.init(std.testing.allocator, .{});
    defer reg.deinit();
    try reg.grant("alice", "work", "alice.staff.example", .granted, 1);
    try reg.grant("alice", "play", "ally.cool.example", .claimed, 2);
    try std.testing.expectEqual(@as(usize, 2), reg.personas("alice").len);
    try std.testing.expectEqualStrings("ally.cool.example", reg.find("alice", "PLAY").?.host);
    try std.testing.expect(reg.removePersona("alice", "work"));
    try std.testing.expectEqual(@as(usize, 1), reg.personas("alice").len);
}

test "grant replaces same-named persona without leaking" {
    var reg = Registry.init(std.testing.allocator, .{});
    defer reg.deinit();
    try reg.grant("bob", "main", "bob.v1.example", .granted, 1);
    try reg.grant("bob", "main", "bob.v2.example", .verified, 2);
    try std.testing.expectEqual(@as(usize, 1), reg.personas("bob").len);
    const p = reg.find("bob", "main").?;
    try std.testing.expectEqualStrings("bob.v2.example", p.host);
    try std.testing.expectEqual(Source.verified, p.source);
}

test "offers: add/list/match glob; claim self-services a matching host" {
    var reg = Registry.init(std.testing.allocator, .{});
    defer reg.deinit();
    try reg.addOffer("*.users.eshmaki.me", "community vhosts");
    try std.testing.expect(reg.matchOffer("alice.users.eshmaki.me") != null);
    try std.testing.expect(reg.matchOffer("alice.staff.other.net") == null);

    const offer = try reg.claim("carol", "carol.users.eshmaki.me", 5);
    try std.testing.expectEqualStrings("community vhosts", offer.label);
    const p = reg.find("carol", "carol").?;
    try std.testing.expectEqual(Source.claimed, p.source);
    try std.testing.expectEqualStrings("carol.users.eshmaki.me", p.host);

    try std.testing.expectError(error.NotOffered, reg.claim("carol", "carol.notoffered.net", 6));
}

test "duplicate offer rejected; removeOffer works" {
    var reg = Registry.init(std.testing.allocator, .{});
    defer reg.deinit();
    try reg.addOffer("*.a.example", "x");
    try std.testing.expectError(error.Duplicate, reg.addOffer("*.A.example", "y"));
    try std.testing.expect(reg.removeOffer("*.a.example"));
    try std.testing.expect(!reg.removeOffer("*.a.example"));
}

test "limits enforced" {
    var reg = Registry.init(std.testing.allocator, .{ .max_personas_per_account = 1, .max_offers = 1, .max_name = 4 });
    defer reg.deinit();
    try reg.grant("u", "main", "h.example", .granted, 0);
    try std.testing.expectError(error.TooManyPersonas, reg.grant("u", "alt", "h2.example", .granted, 0));
    try std.testing.expectError(error.NameTooLong, reg.grant("u", "toolong", "h.example", .granted, 0));
    try reg.addOffer("*.a", "x");
    try std.testing.expectError(error.TooManyOffers, reg.addOffer("*.b", "y"));
}

test "no leak under churn" {
    var reg = Registry.init(std.testing.allocator, .{});
    defer reg.deinit();
    for (0..50) |i| {
        var nb: [16]u8 = undefined;
        var hb: [48]u8 = undefined;
        const name = try std.fmt.bufPrint(&nb, "p{d}", .{i % 8});
        const host = try std.fmt.bufPrint(&hb, "h{d}.example", .{i});
        try reg.grant("churn", name, host, .granted, @intCast(i));
    }
    try std.testing.expect(reg.personas("churn").len <= 8);
}

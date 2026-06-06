//! Warden exemption registry.
//!
//! This module is a pure allow-list store for connection identities. A subject
//! matching any exemption bypasses all ward checks. The store owns every string
//! it accepts, performs no I/O, and keeps address matching compatible with
//! IPv4 CIDR patterns while all facets also support case-insensitive globbing.

const std = @import("std");

/// Which identity facet an exemption pattern is tested against.
pub const ExemptMatch = enum {
    /// IP literal, IPv4 CIDR, or address glob.
    address,
    /// Resolved or cloaked hostname glob.
    host,
    /// Full nick!user@host mask glob.
    mask,
    /// Services account name glob.
    account,
    /// TLS client-certificate fingerprint glob.
    certfp,

    /// Return the stable lowercase token for this match facet.
    pub fn token(self: ExemptMatch) []const u8 {
        return switch (self) {
            .address => "address",
            .host => "host",
            .mask => "mask",
            .account => "account",
            .certfp => "certfp",
        };
    }

    /// Parse a match facet token case-insensitively.
    pub fn parse(raw: []const u8) ?ExemptMatch {
        inline for (@typeInfo(ExemptMatch).@"enum".fields) |field| {
            const facet: ExemptMatch = @enumFromInt(field.value);
            if (std.ascii.eqlIgnoreCase(raw, facet.token())) return facet;
        }
        return null;
    }
};

/// Runtime limits for an exemption registry.
pub const Params = struct {
    /// Maximum stored exemptions.
    max_exemptions: usize = 1024,
    /// Maximum bytes in a match pattern.
    max_pattern: usize = 256,
    /// Maximum bytes in the administrative reason.
    max_reason: usize = 512,
    /// Maximum bytes in the setter identity.
    max_setter: usize = 64,
};

/// Errors returned by exemption registry mutation.
pub const ExemptError = std.mem.Allocator.Error || error{
    EmptyPattern,
    PatternTooLong,
    ReasonTooLong,
    SetterTooLong,
    TooManyExemptions,
};

/// A single ban exemption. String fields are owned by the registry after `add`.
pub const Exemption = struct {
    /// Identity facet to compare against.
    match: ExemptMatch,
    /// Match pattern for the selected facet.
    pattern: []const u8,
    /// Administrative reason for the exemption.
    reason: []const u8 = "",
    /// Operator or service that set the exemption.
    set_by: []const u8 = "",
    /// Creation timestamp in epoch milliseconds.
    created_ms: i64 = 0,
};

/// The identity facets presented by a connecting subject.
pub const Facets = struct {
    /// Remote address text.
    address: []const u8 = "",
    /// Resolved or cloaked hostname.
    host: []const u8 = "",
    /// Full nick!user@host mask.
    mask: []const u8 = "",
    /// Authenticated account name, if any.
    account: ?[]const u8 = null,
    /// TLS client-certificate fingerprint.
    certfp: []const u8 = "",

    fn value(self: Facets, facet: ExemptMatch) []const u8 {
        return switch (facet) {
            .address => self.address,
            .host => self.host,
            .mask => self.mask,
            .account => self.account orelse "",
            .certfp => self.certfp,
        };
    }
};

/// Owned allow-list store for ban exemptions.
pub const ExemptRegistry = struct {
    allocator: std.mem.Allocator,
    params: Params,
    exemptions: std.ArrayListUnmanaged(Exemption) = .empty,

    /// Initialize an empty exemption registry with explicit limits.
    pub fn init(allocator: std.mem.Allocator, params: Params) ExemptRegistry {
        return .{ .allocator = allocator, .params = params };
    }

    /// Free all owned exemption strings and backing storage.
    pub fn deinit(self: *ExemptRegistry) void {
        for (self.exemptions.items) |*exemption| {
            freeExemption(self.allocator, exemption);
        }
        self.exemptions.deinit(self.allocator);
        self.* = undefined;
    }

    /// Add or replace an exemption by the `(match, pattern)` identity.
    pub fn add(self: *ExemptRegistry, exemption: Exemption) ExemptError!void {
        try self.validate(exemption);

        const existing = self.indexOf(exemption.match, exemption.pattern);
        if (existing == null and self.exemptions.items.len >= self.params.max_exemptions) {
            return error.TooManyExemptions;
        }

        var owned = try self.clone(exemption);
        errdefer freeExemption(self.allocator, &owned);

        if (existing) |index| {
            freeExemption(self.allocator, &self.exemptions.items[index]);
            self.exemptions.items[index] = owned;
            return;
        }

        try self.exemptions.append(self.allocator, owned);
    }

    /// Remove an exemption identified by `(match, pattern)`.
    pub fn remove(self: *ExemptRegistry, match: ExemptMatch, pattern: []const u8) bool {
        const index = self.indexOf(match, pattern) orelse return false;
        var exemption = self.exemptions.orderedRemove(index);
        freeExemption(self.allocator, &exemption);
        return true;
    }

    /// Return whether any stored exemption matches the supplied facets.
    pub fn isExempt(self: *const ExemptRegistry, facets: Facets) bool {
        for (self.exemptions.items) |exemption| {
            const facet_value = facets.value(exemption.match);
            if (facet_value.len == 0) continue;
            if (matchValue(exemption.match, exemption.pattern, facet_value)) return true;
        }
        return false;
    }

    /// Copy exemptions, optionally filtered by facet, into `out`.
    pub fn list(self: *const ExemptRegistry, only: ?ExemptMatch, out: []Exemption) []Exemption {
        var count_seen: usize = 0;
        for (self.exemptions.items) |exemption| {
            if (only) |facet| {
                if (exemption.match != facet) continue;
            }
            if (count_seen == out.len) break;
            out[count_seen] = exemption;
            count_seen += 1;
        }
        return out[0..count_seen];
    }

    /// Return the number of stored exemptions.
    pub fn count(self: *const ExemptRegistry) usize {
        return self.exemptions.items.len;
    }

    fn validate(self: *const ExemptRegistry, exemption: Exemption) ExemptError!void {
        if (exemption.pattern.len == 0) return error.EmptyPattern;
        if (exemption.pattern.len > self.params.max_pattern) return error.PatternTooLong;
        if (exemption.reason.len > self.params.max_reason) return error.ReasonTooLong;
        if (exemption.set_by.len > self.params.max_setter) return error.SetterTooLong;
    }

    fn clone(self: *ExemptRegistry, exemption: Exemption) std.mem.Allocator.Error!Exemption {
        const pattern = try self.allocator.dupe(u8, exemption.pattern);
        errdefer self.allocator.free(pattern);
        const reason = try self.allocator.dupe(u8, exemption.reason);
        errdefer self.allocator.free(reason);
        const set_by = try self.allocator.dupe(u8, exemption.set_by);

        return .{
            .match = exemption.match,
            .pattern = pattern,
            .reason = reason,
            .set_by = set_by,
            .created_ms = exemption.created_ms,
        };
    }

    fn indexOf(self: *const ExemptRegistry, match: ExemptMatch, pattern: []const u8) ?usize {
        for (self.exemptions.items, 0..) |exemption, index| {
            if (exemption.match == match and std.mem.eql(u8, exemption.pattern, pattern)) return index;
        }
        return null;
    }
};

fn freeExemption(allocator: std.mem.Allocator, exemption: *Exemption) void {
    allocator.free(exemption.pattern);
    allocator.free(exemption.reason);
    allocator.free(exemption.set_by);
    exemption.* = undefined;
}

fn matchValue(match: ExemptMatch, pattern: []const u8, value: []const u8) bool {
    if (match == .address) {
        if (parseCidr(pattern)) |cidr| {
            if (parseIpv4(value)) |address| return cidr.contains(address);
        }
    }
    return globMatch(pattern, value);
}

fn globMatch(pattern: []const u8, text: []const u8) bool {
    var pattern_index: usize = 0;
    var text_index: usize = 0;
    var star_index: ?usize = null;
    var retry_text_index: usize = 0;

    while (text_index < text.len) {
        if (pattern_index < pattern.len and (pattern[pattern_index] == '?' or std.ascii.toLower(pattern[pattern_index]) == std.ascii.toLower(text[text_index]))) {
            pattern_index += 1;
            text_index += 1;
        } else if (pattern_index < pattern.len and pattern[pattern_index] == '*') {
            star_index = pattern_index;
            retry_text_index = text_index;
            pattern_index += 1;
        } else if (star_index) |star| {
            pattern_index = star + 1;
            retry_text_index += 1;
            text_index = retry_text_index;
        } else {
            return false;
        }
    }

    while (pattern_index < pattern.len and pattern[pattern_index] == '*') {
        pattern_index += 1;
    }
    return pattern_index == pattern.len;
}

const Ipv4Cidr = struct {
    address: u32,
    prefix_bits: u6,

    fn contains(self: Ipv4Cidr, address: u32) bool {
        if (self.prefix_bits == 0) return true;
        const shift: u5 = @intCast(32 - self.prefix_bits);
        const mask: u32 = @as(u32, std.math.maxInt(u32)) << shift;
        return (self.address & mask) == (address & mask);
    }
};

fn parseCidr(bytes: []const u8) ?Ipv4Cidr {
    const slash = std.mem.indexOfScalar(u8, bytes, '/') orelse return null;
    if (std.mem.indexOfScalar(u8, bytes[slash + 1 ..], '/') != null) return null;

    const address = parseIpv4(bytes[0..slash]) orelse return null;
    const prefix = std.fmt.parseInt(u8, bytes[slash + 1 ..], 10) catch return null;
    if (prefix > 32) return null;

    return .{ .address = address, .prefix_bits = @intCast(prefix) };
}

fn parseIpv4(bytes: []const u8) ?u32 {
    var parts: [4]u8 = undefined;
    var count: usize = 0;
    var start: usize = 0;

    while (start <= bytes.len) {
        if (count == parts.len) return null;
        const end = std.mem.indexOfScalarPos(u8, bytes, start, '.') orelse bytes.len;
        if (end == start) return null;

        parts[count] = std.fmt.parseInt(u8, bytes[start..end], 10) catch return null;
        count += 1;

        if (end == bytes.len) break;
        start = end + 1;
    }

    if (count != parts.len) return null;
    return (@as(u32, parts[0]) << 24) | (@as(u32, parts[1]) << 16) | (@as(u32, parts[2]) << 8) | @as(u32, parts[3]);
}

fn mkExemption(match: ExemptMatch, pattern: []const u8) Exemption {
    return .{
        .match = match,
        .pattern = pattern,
        .reason = "trusted identity",
        .set_by = "oper",
        .created_ms = 100,
    };
}

test "exempt match tokens parse round trip case insensitively" {
    // Arrange / Act / Assert.
    inline for (@typeInfo(ExemptMatch).@"enum".fields) |field| {
        const facet: ExemptMatch = @enumFromInt(field.value);
        try std.testing.expectEqual(facet, ExemptMatch.parse(facet.token()).?);
    }
    try std.testing.expectEqual(ExemptMatch.certfp, ExemptMatch.parse("CERTFP").?);
    try std.testing.expect(ExemptMatch.parse("realname") == null);
}

test "add remove and list exemptions by optional facet" {
    // Arrange.
    var registry = ExemptRegistry.init(std.testing.allocator, .{});
    defer registry.deinit();

    // Act.
    try registry.add(mkExemption(.host, "*.trusted.example"));
    try registry.add(mkExemption(.account, "helper-*"));

    var all_out: [4]Exemption = undefined;
    const all = registry.list(null, &all_out);
    var account_out: [4]Exemption = undefined;
    const accounts = registry.list(.account, &account_out);

    // Assert.
    try std.testing.expectEqual(@as(usize, 2), registry.count());
    try std.testing.expectEqual(@as(usize, 2), all.len);
    try std.testing.expectEqual(@as(usize, 1), accounts.len);
    try std.testing.expectEqual(ExemptMatch.account, accounts[0].match);
    try std.testing.expectEqualStrings("helper-*", accounts[0].pattern);
    try std.testing.expect(registry.remove(.host, "*.trusted.example"));
    try std.testing.expect(!registry.remove(.host, "*.trusted.example"));
    try std.testing.expectEqual(@as(usize, 1), registry.count());
}

test "address exemption matches ipv4 cidr and falls back to glob" {
    // Arrange.
    var registry = ExemptRegistry.init(std.testing.allocator, .{});
    defer registry.deinit();
    try registry.add(mkExemption(.address, "192.0.2.0/24"));
    try registry.add(mkExemption(.address, "2001:db8::*"));

    // Act / Assert.
    try std.testing.expect(registry.isExempt(.{ .address = "192.0.2.44" }));
    try std.testing.expect(!registry.isExempt(.{ .address = "192.0.3.44" }));
    try std.testing.expect(registry.isExempt(.{ .address = "2001:db8::1" }));
    try std.testing.expect(!registry.isExempt(.{ .address = "" }));
}

test "host mask account and certfp exemptions match case-insensitive globs" {
    // Arrange.
    var registry = ExemptRegistry.init(std.testing.allocator, .{});
    defer registry.deinit();
    try registry.add(mkExemption(.host, "*.Trusted.Example"));
    try registry.add(mkExemption(.mask, "Helper!*@*.Example"));
    try registry.add(mkExemption(.account, "Staff-*"));
    try registry.add(mkExemption(.certfp, "ABCD??"));

    // Act / Assert.
    try std.testing.expect(registry.isExempt(.{ .host = "node.trusted.example" }));
    try std.testing.expect(registry.isExempt(.{ .mask = "helper!~u@gateway.example" }));
    try std.testing.expect(registry.isExempt(.{ .account = "staff-alice" }));
    try std.testing.expect(registry.isExempt(.{ .certfp = "abcd12" }));
    try std.testing.expect(!registry.isExempt(.{ .host = "node.other.example" }));
    try std.testing.expect(!registry.isExempt(.{ .account = "guest-alice" }));
    try std.testing.expect(!registry.isExempt(.{ .certfp = "abcd123" }));
}

test "absent optional account facet never matches" {
    // Arrange.
    var registry = ExemptRegistry.init(std.testing.allocator, .{});
    defer registry.deinit();
    try registry.add(mkExemption(.account, "*"));

    // Act / Assert.
    try std.testing.expect(!registry.isExempt(.{}));
    try std.testing.expect(!registry.isExempt(.{ .account = null }));
    try std.testing.expect(!registry.isExempt(.{ .account = "" }));
    try std.testing.expect(registry.isExempt(.{ .account = "present" }));
}

test "dedupe replaces exemption contents without changing count" {
    // Arrange.
    var registry = ExemptRegistry.init(std.testing.allocator, .{});
    defer registry.deinit();
    var first = mkExemption(.mask, "*!*@trusted");
    first.reason = "first";
    first.set_by = "alpha";
    var second = mkExemption(.mask, "*!*@trusted");
    second.reason = "second";
    second.set_by = "beta";
    second.created_ms = 200;

    // Act.
    try registry.add(first);
    try registry.add(second);
    var out: [2]Exemption = undefined;
    const listed = registry.list(.mask, &out);

    // Assert.
    try std.testing.expectEqual(@as(usize, 1), registry.count());
    try std.testing.expectEqual(@as(usize, 1), listed.len);
    try std.testing.expectEqualStrings("second", listed[0].reason);
    try std.testing.expectEqualStrings("beta", listed[0].set_by);
    try std.testing.expectEqual(@as(i64, 200), listed[0].created_ms);
}

test "limits reject invalid or excessive exemption records" {
    // Arrange.
    var registry = ExemptRegistry.init(std.testing.allocator, .{
        .max_exemptions = 1,
        .max_pattern = 8,
        .max_reason = 4,
        .max_setter = 5,
    });
    defer registry.deinit();

    // Act / Assert.
    try std.testing.expectError(error.EmptyPattern, registry.add(mkExemption(.host, "")));
    try std.testing.expectError(error.PatternTooLong, registry.add(mkExemption(.host, "too-long-pattern")));

    var long_reason = mkExemption(.host, "a.b");
    long_reason.reason = "later";
    try std.testing.expectError(error.ReasonTooLong, registry.add(long_reason));

    var long_setter = mkExemption(.host, "a.b");
    long_setter.reason = "ok";
    long_setter.set_by = "setter";
    try std.testing.expectError(error.SetterTooLong, registry.add(long_setter));

    var allowed = mkExemption(.host, "a.b");
    allowed.reason = "ok";
    try registry.add(allowed);
    var overflow = mkExemption(.host, "c.d");
    overflow.reason = "ok";
    try std.testing.expectError(error.TooManyExemptions, registry.add(overflow));

    var replacement = mkExemption(.host, "a.b");
    replacement.reason = "swap";
    try registry.add(replacement);
    try std.testing.expectEqual(@as(usize, 1), registry.count());
}

test "list returns only as many exemptions as the caller buffer can hold" {
    // Arrange.
    var registry = ExemptRegistry.init(std.testing.allocator, .{});
    defer registry.deinit();
    try registry.add(mkExemption(.host, "one.example"));
    try registry.add(mkExemption(.host, "two.example"));

    // Act.
    var out: [1]Exemption = undefined;
    const listed = registry.list(.host, &out);

    // Assert.
    try std.testing.expectEqual(@as(usize, 1), listed.len);
    try std.testing.expectEqualStrings("one.example", listed[0].pattern);
}

test "churn add replace remove path releases all owned memory" {
    // Arrange.
    var registry = ExemptRegistry.init(std.testing.allocator, .{ .max_exemptions = 64 });
    defer registry.deinit();

    // Act.
    for (0..32) |index| {
        var pattern_buf: [32]u8 = undefined;
        const pattern = try std.fmt.bufPrint(&pattern_buf, "*!*@trusted-{d}.example", .{index});
        try registry.add(mkExemption(.mask, pattern));
    }
    for (0..16) |index| {
        var pattern_buf: [32]u8 = undefined;
        const pattern = try std.fmt.bufPrint(&pattern_buf, "*!*@trusted-{d}.example", .{index});
        var exemption = mkExemption(.mask, pattern);
        exemption.reason = "replacement";
        try registry.add(exemption);
    }
    for (0..32) |index| {
        var pattern_buf: [32]u8 = undefined;
        const pattern = try std.fmt.bufPrint(&pattern_buf, "*!*@trusted-{d}.example", .{index});
        try std.testing.expect(registry.remove(.mask, pattern));
    }

    // Assert.
    try std.testing.expectEqual(@as(usize, 0), registry.count());
}

//! Bounded CIDR-to-country lookup table with caller-injected data.
//!
//! The table owns only normalized country-code strings. CIDR parsing and IP
//! normalization are delegated to the pure protocol CIDR module, and lookup is
//! a linear longest-prefix scan over the injected ranges.
const std = @import("std");
const cidr_match = @import("../proto/cidr_match.zig");
const numeric = @import("../proto/numeric.zig");

/// Numeric replies related to country lookup presentation.
pub const GeoIpNumeric = enum(u16) {
    /// WHOIS country reply used by callers that expose lookup results.
    RPL_WHOISCOUNTRY = 344,

    /// Return the shared numeric identifier for this reply.
    pub fn known(self: GeoIpNumeric) numeric.Numeric {
        return switch (self) {
            .RPL_WHOISCOUNTRY => .RPL_WHOISCOUNTRY,
        };
    }
};

/// Compile-time limits for a CIDR country table.
pub const Params = struct {
    /// Maximum number of distinct CIDR ranges retained by the table.
    max_entries: usize = 65536,
};

/// Errors returned by table mutation and lookup operations.
pub const GeoIpError = std.mem.Allocator.Error || cidr_match.ParseError || error{
    /// The two-byte country code was empty, oversized, or non-alphabetic.
    InvalidCountryCode,
    /// The table reached `Params.max_entries`.
    TooManyEntries,
};

/// Build a bounded CIDR-to-country lookup table type.
pub fn GeoIpCidr(comptime params: Params) type {
    comptime {
        if (params.max_entries == 0) @compileError("GeoIP CIDR table needs entry storage");
    }

    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        entries: std.ArrayListUnmanaged(Entry) = .empty,

        const Entry = struct {
            cidr: cidr_match.Cidr,
            country_code: []u8,

            fn deinit(self: *Entry, allocator: std.mem.Allocator) void {
                allocator.free(self.country_code);
            }

            fn matches(self: *const Entry, ip: cidr_match.ParsedIp) bool {
                if (self.cidr.is_v6 != ip.is_v6) return false;
                return self.cidr.contains(ip.addr);
            }
        };

        /// Create an empty table bound to `allocator`.
        pub fn init(allocator: std.mem.Allocator) Self {
            return .{ .allocator = allocator };
        }

        /// Release all owned storage and poison the table.
        pub fn deinit(self: *Self) void {
            self.clear();
            self.entries.deinit(self.allocator);
            self.* = undefined;
        }

        /// Remove all ranges while retaining the entry backing allocation.
        pub fn clear(self: *Self) void {
            for (self.entries.items) |*entry| entry.deinit(self.allocator);
            self.entries.clearRetainingCapacity();
        }

        /// Insert or replace one CIDR-to-country mapping.
        ///
        /// `country_code` must be a two-letter ASCII code and is stored as
        /// uppercase. Returns `true` when a new range was inserted, or `false`
        /// when an existing identical range was replaced.
        pub fn add(self: *Self, cidr_text: []const u8, country_code: []const u8) GeoIpError!bool {
            const parsed_cidr = try cidr_match.Cidr.parse(cidr_text);
            var code_buf: [2]u8 = undefined;
            const normalized_code = try normalizeCountryCode(country_code, &code_buf);

            if (self.findEntryIndex(parsed_cidr)) |index| {
                const owned_code = try self.allocator.dupe(u8, normalized_code);
                self.allocator.free(self.entries.items[index].country_code);
                self.entries.items[index].country_code = owned_code;
                return false;
            }

            if (self.entries.items.len >= params.max_entries) return error.TooManyEntries;

            const owned_code = try self.allocator.dupe(u8, normalized_code);
            errdefer self.allocator.free(owned_code);
            try self.entries.append(self.allocator, .{
                .cidr = parsed_cidr,
                .country_code = owned_code,
            });
            return true;
        }

        /// Lookup `ip_text` and return the best country code, if any.
        ///
        /// The returned slice is borrowed from the table and remains valid until
        /// the matching entry is replaced, removed by `clear`, or deinitialized.
        pub fn lookup(self: *const Self, ip_text: []const u8) GeoIpError!?[]const u8 {
            return self.lookupParsed(try cidr_match.parseIp(ip_text));
        }

        /// Lookup a pre-parsed IP address and return the longest-prefix match.
        ///
        /// IPv4 and IPv6 ranges are matched as separate families so an IPv6
        /// default route does not catch IPv4 addresses.
        pub fn lookupParsed(self: *const Self, ip: cidr_match.ParsedIp) ?[]const u8 {
            var best_prefix: ?u8 = null;
            var best_code: ?[]const u8 = null;

            for (self.entries.items) |*entry| {
                if (!entry.matches(ip)) continue;
                if (best_prefix == null or entry.cidr.prefix_bits > best_prefix.?) {
                    best_prefix = entry.cidr.prefix_bits;
                    best_code = entry.country_code;
                }
            }

            return best_code;
        }

        /// Return the number of CIDR ranges currently retained.
        pub fn count(self: *const Self) usize {
            return self.entries.items.len;
        }

        /// Return the maximum number of CIDR ranges this table can retain.
        pub fn capacity(self: *const Self) usize {
            _ = self;
            return params.max_entries;
        }

        fn findEntryIndex(self: *const Self, cidr: cidr_match.Cidr) ?usize {
            for (self.entries.items, 0..) |entry, index| {
                if (sameCidr(entry.cidr, cidr)) return index;
            }
            return null;
        }
    };
}

/// Default CIDR-to-country table limits.
pub const DefaultTable = GeoIpCidr(.{});

fn sameCidr(a: cidr_match.Cidr, b: cidr_match.Cidr) bool {
    return a.addr == b.addr and
        a.prefix_bits == b.prefix_bits and
        a.is_v6 == b.is_v6;
}

fn normalizeCountryCode(input: []const u8, out: *[2]u8) GeoIpError![]const u8 {
    if (input.len != 2) return error.InvalidCountryCode;

    for (input, 0..) |byte, index| {
        if (!isAsciiAlpha(byte)) return error.InvalidCountryCode;
        out[index] = asciiUpper(byte);
    }

    return out[0..];
}

fn isAsciiAlpha(byte: u8) bool {
    return (byte >= 'A' and byte <= 'Z') or (byte >= 'a' and byte <= 'z');
}

fn asciiUpper(byte: u8) u8 {
    if (byte >= 'a' and byte <= 'z') return byte - ('a' - 'A');
    return byte;
}

test "lookup returns the longest IPv4 prefix when ranges overlap" {
    const allocator = std.testing.allocator;

    // Arrange.
    const Table = GeoIpCidr(.{ .max_entries = 8 });
    var table = Table.init(allocator);
    defer table.deinit();
    try std.testing.expect(try table.add("0.0.0.0/0", "ZZ"));
    try std.testing.expect(try table.add("203.0.113.0/24", "US"));
    try std.testing.expect(try table.add("203.0.113.128/25", "CA"));

    // Act.
    const specific = try table.lookup("203.0.113.200");
    const less_specific = try table.lookup("203.0.113.64");
    const fallback = try table.lookup("198.51.100.9");

    // Assert.
    try std.testing.expectEqualStrings("CA", specific.?);
    try std.testing.expectEqualStrings("US", less_specific.?);
    try std.testing.expectEqualStrings("ZZ", fallback.?);
}

test "lookup returns null when no CIDR contains the IP" {
    const allocator = std.testing.allocator;

    // Arrange.
    const Table = GeoIpCidr(.{ .max_entries = 4 });
    var table = Table.init(allocator);
    defer table.deinit();
    try std.testing.expect(try table.add("203.0.113.0/24", "US"));

    // Act.
    const result = try table.lookup("198.51.100.7");

    // Assert.
    try std.testing.expect(result == null);
}

test "overlapping IPv6 ranges prefer the longest prefix" {
    const allocator = std.testing.allocator;

    // Arrange.
    const Table = GeoIpCidr(.{ .max_entries = 8 });
    var table = Table.init(allocator);
    defer table.deinit();
    try std.testing.expect(try table.add("2001:db8::/32", "DE"));
    try std.testing.expect(try table.add("2001:db8:abcd::/48", "FR"));

    // Act.
    const specific = try table.lookup("2001:db8:abcd::42");
    const broader = try table.lookup("2001:db8:ffff::42");

    // Assert.
    try std.testing.expectEqualStrings("FR", specific.?);
    try std.testing.expectEqualStrings("DE", broader.?);
}

test "IPv4 and IPv6 default ranges stay family separated" {
    const allocator = std.testing.allocator;

    // Arrange.
    const Table = GeoIpCidr(.{ .max_entries = 4 });
    var table = Table.init(allocator);
    defer table.deinit();
    try std.testing.expect(try table.add("::/0", "VZ"));

    // Act.
    const ipv4_result = try table.lookup("192.0.2.1");
    const ipv6_result = try table.lookup("2001:db8::1");

    // Assert.
    try std.testing.expect(ipv4_result == null);
    try std.testing.expectEqualStrings("VZ", ipv6_result.?);
}

test "adding an identical CIDR replaces the owned country code" {
    const allocator = std.testing.allocator;

    // Arrange.
    const Table = GeoIpCidr(.{ .max_entries = 2 });
    var table = Table.init(allocator);
    defer table.deinit();
    try std.testing.expect(try table.add("203.0.113.0/24", "us"));

    // Act.
    const inserted = try table.add("203.0.113.0/24", "ca");
    const result = try table.lookup("203.0.113.99");

    // Assert.
    try std.testing.expect(!inserted);
    try std.testing.expectEqual(@as(usize, 1), table.count());
    try std.testing.expectEqualStrings("CA", result.?);
}

test "add rejects invalid data and enforces capacity" {
    const allocator = std.testing.allocator;

    // Arrange.
    const Table = GeoIpCidr(.{ .max_entries = 1 });
    var table = Table.init(allocator);
    defer table.deinit();

    // Act and assert.
    try std.testing.expectError(error.InvalidCountryCode, table.add("203.0.113.0/24", "D"));
    try std.testing.expectError(error.InvalidCountryCode, table.add("203.0.113.0/24", "D1"));
    try std.testing.expectError(error.PrefixOutOfRange, table.add("203.0.113.0/33", "DE"));
    try std.testing.expect(try table.add("203.0.113.0/24", "DE"));
    try std.testing.expectError(error.TooManyEntries, table.add("198.51.100.0/24", "FR"));
}

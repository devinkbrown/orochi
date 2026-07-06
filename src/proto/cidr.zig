// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! CIDR / IP-range matching for D-lines and connection classes.
//!
//! Parses IPv4 and IPv6 networks in CIDR notation (`192.168.0.0/16`,
//! `2001:db8::/32`) as well as bare addresses (implicit `/32` for IPv4 and
//! `/128` for IPv6). Membership is tested by comparing the high `prefix`
//! bits of the candidate address against the network address.
//!
//! This module deliberately parses addresses by hand rather than depending on
//! `std.net`: this Zig std build does not ship a `net` module, and manual
//! parsing keeps the daemon's address handling self-contained and auditable.
//!
//! IPv4 and IPv6 are kept as distinct families: a v4 CIDR never matches a v6
//! address and vice-versa, which avoids surprising matches via IPv4-mapped
//! addresses in access-control contexts.

const std = @import("std");

/// Errors produced while parsing an address or CIDR range.
pub const ParseError = error{
    /// Input was empty.
    Empty,
    /// More than one '/' separator, or text after the prefix.
    BadFormat,
    /// Prefix was not a valid base-10 number.
    BadPrefix,
    /// Prefix exceeded the family maximum (32 for v4, 128 for v6).
    PrefixTooLong,
    /// An IPv4 octet was missing, empty, non-numeric, or > 255.
    BadOctet,
    /// Wrong number of IPv4 octets (must be exactly 4).
    BadOctetCount,
    /// An IPv6 group was malformed or out of range.
    BadGroup,
    /// IPv6 had the wrong number of groups or a bad '::' compression.
    BadGroupCount,
    /// More than one '::' compression marker in an IPv6 address.
    BadCompression,
};

/// Address family discriminant.
pub const Family = enum { v4, v6 };

/// A parsed CIDR network: a base address plus a prefix length, kept in a
/// family-tagged union so v4 and v6 never compare against each other.
pub const Cidr = union(Family) {
    v4: V4,
    v6: V6,

    /// IPv4 network: 32-bit address (big-endian numeric) and 0..=32 prefix.
    pub const V4 = struct {
        addr: u32,
        prefix: u6, // 0..=32 fits in u6

        /// True when `ip` (a 32-bit numeric IPv4 address) falls in this range.
        pub fn contains(self: V4, ip: u32) bool {
            return matchBits(u32, self.addr, ip, self.prefix);
        }
    };

    /// IPv6 network: 128-bit address (big-endian numeric) and 0..=128 prefix.
    pub const V6 = struct {
        addr: u128,
        prefix: u8, // 0..=128

        /// True when `ip` (a 128-bit numeric IPv6 address) falls in this range.
        pub fn contains(self: V6, ip: u128) bool {
            return matchBits(u128, self.addr, ip, self.prefix);
        }
    };

    /// Parse a CIDR string or a bare IP. A bare IPv4 implies `/32`, a bare
    /// IPv6 implies `/128`. Both families are auto-detected: a ':' anywhere
    /// in the address portion selects IPv6.
    pub fn parse(text: []const u8) ParseError!Cidr {
        if (text.len == 0) return ParseError.Empty;

        // Split off the optional prefix.
        var addr_part = text;
        var prefix_part: ?[]const u8 = null;
        if (std.mem.indexOfScalar(u8, text, '/')) |slash| {
            addr_part = text[0..slash];
            const rest = text[slash + 1 ..];
            if (std.mem.indexOfScalar(u8, rest, '/') != null) return ParseError.BadFormat;
            prefix_part = rest;
        }
        if (addr_part.len == 0) return ParseError.Empty;

        const is_v6 = std.mem.indexOfScalar(u8, addr_part, ':') != null;
        if (is_v6) {
            const addr = try parseV6(addr_part);
            const prefix = try parsePrefix(prefix_part, 128);
            return .{ .v6 = .{ .addr = addr, .prefix = @intCast(prefix) } };
        } else {
            const addr = try parseV4(addr_part);
            const prefix = try parsePrefix(prefix_part, 32);
            return .{ .v4 = .{ .addr = addr, .prefix = @intCast(prefix) } };
        }
    }

    /// The family of this network.
    pub fn family(self: Cidr) Family {
        return self;
    }

    /// Test whether a parsed address (same family) is in this network.
    /// Cross-family checks always return false.
    pub fn containsAddr(self: Cidr, addr: Addr) bool {
        return switch (self) {
            .v4 => |net| switch (addr) {
                .v4 => |ip| net.contains(ip),
                .v6 => false,
            },
            .v6 => |net| switch (addr) {
                .v6 => |ip| net.contains(ip),
                .v4 => false,
            },
        };
    }

    /// Convenience: parse `ip_text` as a bare address and test membership.
    pub fn containsText(self: Cidr, ip_text: []const u8) ParseError!bool {
        return self.containsAddr(try parseAddr(ip_text));
    }
};

/// A parsed bare IP address (no prefix), family-tagged.
pub const Addr = union(Family) {
    v4: u32,
    v6: u128,
};

/// Parse a bare IPv4 or IPv6 address (no '/prefix' allowed).
pub fn parseAddr(text: []const u8) ParseError!Addr {
    if (text.len == 0) return ParseError.Empty;
    if (std.mem.indexOfScalar(u8, text, '/') != null) return ParseError.BadFormat;
    if (std.mem.indexOfScalar(u8, text, ':') != null) {
        return .{ .v6 = try parseV6(text) };
    }
    return .{ .v4 = try parseV4(text) };
}

/// Compare the high `prefix` bits of two values of integer type `T`.
/// A prefix of 0 matches everything (no bits compared).
fn matchBits(comptime T: type, net: T, ip: T, prefix: anytype) bool {
    const bits = @typeInfo(T).int.bits;
    if (prefix == 0) return true;
    if (prefix >= bits) return net == ip;
    // Mask = high `prefix` bits set. Built by shifting to avoid overflow.
    const shift: std.math.Log2Int(T) = @intCast(bits - prefix);
    const mask: T = ~@as(T, 0) << shift;
    return (net & mask) == (ip & mask);
}

/// Parse an optional prefix string; absent means the implicit full-length
/// prefix `max` (a bare address). Validates range against `max`.
fn parsePrefix(maybe: ?[]const u8, max: u8) ParseError!u8 {
    const text = maybe orelse return max;
    if (text.len == 0) return ParseError.BadPrefix;
    var value: u16 = 0;
    for (text) |c| {
        if (c < '0' or c > '9') return ParseError.BadPrefix;
        value = value * 10 + (c - '0');
        if (value > 128) return ParseError.PrefixTooLong; // early guard
    }
    if (value > max) return ParseError.PrefixTooLong;
    return @intCast(value);
}

/// Parse dotted-quad IPv4 into a big-endian numeric u32.
fn parseV4(text: []const u8) ParseError!u32 {
    var result: u32 = 0;
    var count: usize = 0;
    var it = std.mem.splitScalar(u8, text, '.');
    while (it.next()) |octet_text| {
        count += 1;
        if (count > 4) return ParseError.BadOctetCount;
        const octet = try parseOctet(octet_text);
        result = (result << 8) | octet;
    }
    if (count != 4) return ParseError.BadOctetCount;
    return result;
}

/// Parse a single decimal octet (0..=255), rejecting empty/overlong input.
fn parseOctet(text: []const u8) ParseError!u32 {
    if (text.len == 0 or text.len > 3) return ParseError.BadOctet;
    var value: u32 = 0;
    for (text) |c| {
        if (c < '0' or c > '9') return ParseError.BadOctet;
        value = value * 10 + (c - '0');
    }
    if (value > 255) return ParseError.BadOctet;
    return value;
}

/// Parse an IPv6 address (with optional '::' compression) into numeric u128.
fn parseV6(text: []const u8) ParseError!u128 {
    // Locate the '::' compression marker, if any.
    const dc = std.mem.indexOf(u8, text, "::");
    if (dc) |idx| {
        // A second '::' is illegal.
        if (std.mem.indexOf(u8, text[idx + 2 ..], "::") != null) return ParseError.BadCompression;
        const head = text[0..idx];
        const tail = text[idx + 2 ..];

        var head_groups: [8]u16 = undefined;
        var tail_groups: [8]u16 = undefined;
        const head_len = try parseV6Groups(head, &head_groups);
        const tail_len = try parseV6Groups(tail, &tail_groups);

        if (head_len + tail_len > 7) return ParseError.BadGroupCount; // '::' must cover >=1 group
        var groups: [8]u16 = @splat(0);
        for (0..head_len) |i| groups[i] = head_groups[i];
        for (0..tail_len) |i| groups[8 - tail_len + i] = tail_groups[i];
        return groupsToU128(&groups);
    }

    var groups: [8]u16 = undefined;
    const len = try parseV6Groups(text, &groups);
    if (len != 8) return ParseError.BadGroupCount;
    return groupsToU128(&groups);
}

/// Parse colon-separated hex groups into `out`, returning the count. Empty
/// input yields zero groups (used by the '::' head/tail halves).
fn parseV6Groups(text: []const u8, out: *[8]u16) ParseError!usize {
    if (text.len == 0) return 0;
    var count: usize = 0;
    var it = std.mem.splitScalar(u8, text, ':');
    while (it.next()) |group_text| {
        if (count >= 8) return ParseError.BadGroupCount;
        out[count] = try parseHexGroup(group_text);
        count += 1;
    }
    return count;
}

/// Parse a single hex group (1..=4 hex digits) into a u16.
fn parseHexGroup(text: []const u8) ParseError!u16 {
    if (text.len == 0 or text.len > 4) return ParseError.BadGroup;
    var value: u32 = 0;
    for (text) |c| {
        const digit: u32 = switch (c) {
            '0'...'9' => c - '0',
            'a'...'f' => c - 'a' + 10,
            'A'...'F' => c - 'A' + 10,
            else => return ParseError.BadGroup,
        };
        value = (value << 4) | digit;
    }
    return @intCast(value);
}

/// Pack 8 big-endian groups into a numeric u128.
fn groupsToU128(groups: *const [8]u16) u128 {
    var result: u128 = 0;
    for (groups) |g| result = (result << 16) | g;
    return result;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "ipv4 in and out of range" {
    const net = try Cidr.parse("192.168.0.0/16");
    try testing.expect(net == .v4);
    try testing.expect(try net.containsText("192.168.1.1"));
    try testing.expect(try net.containsText("192.168.255.255"));
    try testing.expect(!try net.containsText("192.169.0.1"));
    try testing.expect(!try net.containsText("10.0.0.1"));
}

test "ipv4 exact /32" {
    const net = try Cidr.parse("10.0.0.5/32");
    try testing.expect(try net.containsText("10.0.0.5"));
    try testing.expect(!try net.containsText("10.0.0.6"));
}

test "ipv6 in and out of range" {
    const net = try Cidr.parse("2001:db8::/32");
    try testing.expect(net == .v6);
    try testing.expect(try net.containsText("2001:db8::1"));
    try testing.expect(try net.containsText("2001:db8:ffff::abcd"));
    try testing.expect(!try net.containsText("2001:db9::1"));
    try testing.expect(!try net.containsText("2002::1"));
}

test "ipv6 full address /128" {
    const net = try Cidr.parse("2001:db8::1/128");
    try testing.expect(try net.containsText("2001:db8::1"));
    try testing.expect(!try net.containsText("2001:db8::2"));
}

test "bare ipv4 implies /32" {
    const net = try Cidr.parse("203.0.113.7");
    try testing.expect(net == .v4);
    try testing.expectEqual(@as(u6, 32), net.v4.prefix);
    try testing.expect(try net.containsText("203.0.113.7"));
    try testing.expect(!try net.containsText("203.0.113.8"));
}

test "bare ipv6 implies /128" {
    const net = try Cidr.parse("fe80::1");
    try testing.expect(net == .v6);
    try testing.expectEqual(@as(u8, 128), net.v6.prefix);
    try testing.expect(try net.containsText("fe80::1"));
    try testing.expect(!try net.containsText("fe80::2"));
}

test "/0 matches all addresses of same family" {
    const v4all = try Cidr.parse("0.0.0.0/0");
    try testing.expect(try v4all.containsText("0.0.0.0"));
    try testing.expect(try v4all.containsText("255.255.255.255"));
    try testing.expect(try v4all.containsText("8.8.8.8"));

    const v6all = try Cidr.parse("::/0");
    try testing.expect(try v6all.containsText("::"));
    try testing.expect(try v6all.containsText("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"));
}

test "cross-family never matches" {
    const v4 = try Cidr.parse("0.0.0.0/0");
    try testing.expect(!v4.containsAddr(.{ .v6 = 0 }));
    const v6 = try Cidr.parse("::/0");
    try testing.expect(!v6.containsAddr(.{ .v4 = 0 }));
}

test "malformed input is rejected" {
    try testing.expectError(ParseError.Empty, Cidr.parse(""));
    try testing.expectError(ParseError.BadOctetCount, Cidr.parse("192.168.0"));
    try testing.expectError(ParseError.BadOctetCount, Cidr.parse("1.2.3.4.5"));
    try testing.expectError(ParseError.BadOctet, Cidr.parse("256.0.0.1"));
    try testing.expectError(ParseError.BadOctet, Cidr.parse("192.168..1"));
    try testing.expectError(ParseError.BadOctet, Cidr.parse("1.2.3.x"));
    try testing.expectError(ParseError.PrefixTooLong, Cidr.parse("10.0.0.0/33"));
    try testing.expectError(ParseError.PrefixTooLong, Cidr.parse("2001:db8::/129"));
    try testing.expectError(ParseError.BadPrefix, Cidr.parse("10.0.0.0/abc"));
    try testing.expectError(ParseError.BadPrefix, Cidr.parse("10.0.0.0/"));
    try testing.expectError(ParseError.BadFormat, Cidr.parse("10.0.0.0/8/8"));
    try testing.expectError(ParseError.BadGroup, Cidr.parse("2001:zzzz::/32"));
    try testing.expectError(ParseError.BadCompression, Cidr.parse("2001::db8::1"));
    try testing.expectError(ParseError.BadGroupCount, Cidr.parse("1:2:3:4:5:6:7"));
}

test "parseAddr rejects prefixed input" {
    try testing.expectError(ParseError.BadFormat, parseAddr("10.0.0.0/8"));
    const a = try parseAddr("1.2.3.4");
    try testing.expect(a == .v4);
}

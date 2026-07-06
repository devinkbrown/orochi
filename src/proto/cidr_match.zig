// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

const std = @import("std");

const ipv4_mapped_prefix: u128 = @as(u128, 0xffff) << 32;

/// Errors returned while parsing IP addresses and CIDR ranges.
pub const ParseError = error{
    EmptyInput,
    InvalidAddress,
    InvalidCharacter,
    InvalidCompression,
    InvalidOctet,
    InvalidPrefix,
    MissingPrefix,
    PrefixOutOfRange,
    TooFewSegments,
    TooManySegments,
};

/// Parsed IP address in the daemon's normalized 128-bit representation.
pub const ParsedIp = struct {
    /// IPv4 addresses are represented as IPv4-mapped IPv6 values.
    addr: u128,
    /// True when the input was IPv6 syntax.
    is_v6: bool,
};

/// CIDR network with a normalized address and family-local prefix length.
pub const Cidr = struct {
    /// Normalized network address.
    addr: u128,
    /// Prefix length, 0...32 for IPv4 and 0...128 for IPv6.
    prefix_bits: u8,
    /// True when the CIDR was parsed from IPv6 syntax.
    is_v6: bool,

    /// Parses an IPv4 or IPv6 CIDR string.
    pub fn parse(text: []const u8) ParseError!Cidr {
        if (text.len == 0) return error.EmptyInput;

        const slash = std.mem.indexOfScalar(u8, text, '/') orelse return error.MissingPrefix;
        const ip_text = text[0..slash];
        const prefix_text = text[slash + 1 ..];
        if (ip_text.len == 0 or prefix_text.len == 0) return error.InvalidPrefix;
        if (std.mem.indexOfScalar(u8, prefix_text, '/') != null) return error.InvalidPrefix;

        const parsed = try parseIp(ip_text);
        const prefix = try parsePrefix(prefix_text);

        if (parsed.is_v6) {
            if (prefix > 128) return error.PrefixOutOfRange;
            return .{
                .addr = mask128(parsed.addr, prefix),
                .prefix_bits = prefix,
                .is_v6 = true,
            };
        }

        if (prefix > 32) return error.PrefixOutOfRange;
        return .{
            .addr = maskMappedIpv4(parsed.addr, prefix),
            .prefix_bits = prefix,
            .is_v6 = false,
        };
    }

    /// Returns true when a normalized IP address is inside this CIDR.
    pub fn contains(self: Cidr, ip: u128) bool {
        if (self.is_v6) {
            if (self.prefix_bits == 0) return true;
            return mask128(ip, self.prefix_bits) == self.addr;
        }

        if (!isMappedIpv4(ip)) return false;
        if (self.prefix_bits == 0) return true;

        const want = lowIpv4(self.addr);
        const got = lowIpv4(ip);
        const bits: u5 = @intCast(32 - self.prefix_bits);
        const mask = ~@as(u32, 0) << bits;
        return (want & mask) == (got & mask);
    }
};

/// Parses an IPv4 or IPv6 address into a normalized 128-bit representation.
pub fn parseIp(text: []const u8) ParseError!ParsedIp {
    if (text.len == 0) return error.EmptyInput;

    if (std.mem.indexOfScalar(u8, text, ':') != null) {
        return .{ .addr = try parseIpv6(text), .is_v6 = true };
    }

    return .{ .addr = mapIpv4(try parseIpv4Raw(text)), .is_v6 = false };
}

/// Formats a normalized IP address into the supplied buffer.
pub fn ipToString(addr: u128, is_v6: bool, buf: []u8) []const u8 {
    if (!is_v6) {
        const raw = lowIpv4(addr);
        return std.fmt.bufPrint(
            buf,
            "{d}.{d}.{d}.{d}",
            .{
                @as(u8, @truncate(raw >> 24)),
                @as(u8, @truncate(raw >> 16)),
                @as(u8, @truncate(raw >> 8)),
                @as(u8, @truncate(raw)),
            },
        ) catch buf[0..0];
    }

    const groups = groupsFrom128(addr);
    var pos: usize = 0;
    for (groups, 0..) |group, index| {
        if (index != 0) {
            if (pos >= buf.len) return buf[0..0];
            buf[pos] = ':';
            pos += 1;
        }
        const text = std.fmt.bufPrint(buf[pos..], "{x}", .{group}) catch return buf[0..0];
        pos += text.len;
    }
    return buf[0..pos];
}

/// Case-insensitive iterative glob matcher for IRC hostmasks.
pub fn matchHostmask(mask: []const u8, host: []const u8) bool {
    var mask_index: usize = 0;
    var host_index: usize = 0;
    var star_index: ?usize = null;
    var retry_host_index: usize = 0;

    while (host_index < host.len) {
        if (mask_index < mask.len and (mask[mask_index] == '?' or asciiEqual(mask[mask_index], host[host_index]))) {
            mask_index += 1;
            host_index += 1;
        } else if (mask_index < mask.len and mask[mask_index] == '*') {
            star_index = mask_index;
            mask_index += 1;
            retry_host_index = host_index;
        } else if (star_index) |star| {
            mask_index = star + 1;
            retry_host_index += 1;
            host_index = retry_host_index;
        } else {
            return false;
        }
    }

    while (mask_index < mask.len and mask[mask_index] == '*') {
        mask_index += 1;
    }
    return mask_index == mask.len;
}

/// Matches a ban mask as CIDR when it parses as CIDR, otherwise as a hostmask glob.
pub fn matchBan(mask: []const u8, ip: ?u128, host: []const u8) bool {
    if (std.mem.indexOfScalar(u8, mask, '/') != null) {
        if (Cidr.parse(mask)) |cidr| {
            const addr = ip orelse return false;
            return cidr.contains(addr);
        } else |_| {}
    }
    return matchHostmask(mask, host);
}

fn parseIpv6(text: []const u8) ParseError!u128 {
    if (text.len == 0) return error.EmptyInput;

    const compressed_at = std.mem.indexOf(u8, text, "::");
    var left: [8]u16 = undefined;
    var right: [8]u16 = undefined;

    if (compressed_at) |pos| {
        if (std.mem.indexOf(u8, text[pos + 2 ..], "::") != null) return error.InvalidCompression;

        const left_count = try parseIpv6Side(text[0..pos], false, &left);
        const right_count = try parseIpv6Side(text[pos + 2 ..], true, &right);
        const total = left_count + right_count;
        if (total >= 8) return error.InvalidCompression;

        var groups: [8]u16 = @splat(0);
        @memcpy(groups[0..left_count], left[0..left_count]);
        const right_start = 8 - right_count;
        @memcpy(groups[right_start..8], right[0..right_count]);
        return groupsTo128(groups);
    }

    const count = try parseIpv6Side(text, true, &left);
    if (count != 8) return if (count < 8) error.TooFewSegments else error.TooManySegments;
    return groupsTo128(left);
}

fn parseIpv6Side(side: []const u8, allow_ipv4: bool, out: *[8]u16) ParseError!usize {
    if (side.len == 0) return 0;

    var count: usize = 0;
    var start: usize = 0;
    while (start <= side.len) {
        const end = std.mem.indexOfScalarPos(u8, side, start, ':') orelse side.len;
        if (end == start) return error.InvalidAddress;
        const token = side[start..end];

        if (std.mem.indexOfScalar(u8, token, '.') != null) {
            if (!allow_ipv4 or end != side.len) return error.InvalidAddress;
            if (count > 6) return error.TooManySegments;
            const raw = try parseIpv4Raw(token);
            out[count] = @as(u16, @truncate(raw >> 16));
            out[count + 1] = @as(u16, @truncate(raw));
            count += 2;
            return count;
        }

        if (count >= 8) return error.TooManySegments;
        out[count] = try parseHex16(token);
        count += 1;

        if (end == side.len) break;
        start = end + 1;
    }
    return count;
}

fn parseIpv4Raw(text: []const u8) ParseError!u32 {
    if (text.len == 0) return error.EmptyInput;

    var octets: [4]u8 = undefined;
    var count: usize = 0;
    var start: usize = 0;
    while (start <= text.len) {
        const end = std.mem.indexOfScalarPos(u8, text, start, '.') orelse text.len;
        if (end == start) return error.InvalidAddress;
        if (count >= octets.len) return error.TooManySegments;

        var value: u16 = 0;
        for (text[start..end]) |byte| {
            if (byte < '0' or byte > '9') return error.InvalidCharacter;
            value = value * 10 + @as(u16, byte - '0');
            if (value > 255) return error.InvalidOctet;
        }
        octets[count] = @intCast(value);
        count += 1;

        if (end == text.len) break;
        start = end + 1;
    }

    if (count != 4) return if (count < 4) error.TooFewSegments else error.TooManySegments;
    return (@as(u32, octets[0]) << 24) |
        (@as(u32, octets[1]) << 16) |
        (@as(u32, octets[2]) << 8) |
        @as(u32, octets[3]);
}

fn parseHex16(text: []const u8) ParseError!u16 {
    if (text.len == 0 or text.len > 4) return error.InvalidAddress;

    var value: u16 = 0;
    for (text) |byte| {
        const digit = hexValue(byte) orelse return error.InvalidCharacter;
        value = value * 16 + @as(u16, digit);
    }
    return value;
}

fn parsePrefix(text: []const u8) ParseError!u8 {
    if (text.len == 0) return error.InvalidPrefix;

    var value: u16 = 0;
    for (text) |byte| {
        if (byte < '0' or byte > '9') return error.InvalidPrefix;
        value = value * 10 + @as(u16, byte - '0');
        if (value > 128) return error.PrefixOutOfRange;
    }
    return @intCast(value);
}

fn hexValue(byte: u8) ?u8 {
    return switch (byte) {
        '0'...'9' => byte - '0',
        'a'...'f' => byte - 'a' + 10,
        'A'...'F' => byte - 'A' + 10,
        else => null,
    };
}

fn mapIpv4(raw: u32) u128 {
    return ipv4_mapped_prefix | @as(u128, raw);
}

fn maskMappedIpv4(addr: u128, prefix_bits: u8) u128 {
    if (prefix_bits == 0) return ipv4_mapped_prefix;

    const bits: u5 = @intCast(32 - prefix_bits);
    const mask = ~@as(u32, 0) << bits;
    return mapIpv4(lowIpv4(addr) & mask);
}

fn mask128(addr: u128, prefix_bits: u8) u128 {
    if (prefix_bits == 0) return 0;

    const bits: u7 = @intCast(128 - prefix_bits);
    return addr & (~@as(u128, 0) << bits);
}

fn isMappedIpv4(addr: u128) bool {
    return (addr >> 32) == 0xffff;
}

fn lowIpv4(addr: u128) u32 {
    return @as(u32, @truncate(addr));
}

fn groupsTo128(groups: [8]u16) u128 {
    var addr: u128 = 0;
    for (groups) |group| {
        addr = (addr << 16) | @as(u128, group);
    }
    return addr;
}

fn groupsFrom128(addr: u128) [8]u16 {
    var groups: [8]u16 = undefined;
    for (&groups, 0..) |*group, index| {
        const shift: u7 = @intCast(112 - (index * 16));
        group.* = @as(u16, @truncate(addr >> shift));
    }
    return groups;
}

fn asciiEqual(a: u8, b: u8) bool {
    return std.ascii.toLower(a) == std.ascii.toLower(b);
}

test "IPv4 CIDR contains /24 /32 and /0 ranges" {
    // Arrange
    _ = std.testing.allocator;
    const net24 = try Cidr.parse("192.0.2.0/24");
    const net32 = try Cidr.parse("192.0.2.55/32");
    const net0 = try Cidr.parse("192.0.2.0/0");
    const inside = try parseIp("192.0.2.55");
    const outside = try parseIp("198.51.100.7");

    // Act
    const in_24 = net24.contains(inside.addr);
    const out_24 = net24.contains(outside.addr);
    const in_32 = net32.contains(inside.addr);
    const out_32 = net32.contains(outside.addr);
    const in_0 = net0.contains(outside.addr);

    // Assert
    try std.testing.expect(!net24.is_v6);
    try std.testing.expectEqual(@as(u8, 24), net24.prefix_bits);
    try std.testing.expect(in_24);
    try std.testing.expect(!out_24);
    try std.testing.expect(in_32);
    try std.testing.expect(!out_32);
    try std.testing.expect(in_0);
}

test "IPv6 CIDR handles double-colon compression" {
    // Arrange
    _ = std.testing.allocator;
    const cidr = try Cidr.parse("2001:db8::/32");
    const inside = try parseIp("2001:db8::1");
    const inside_long = try parseIp("2001:0db8:0000:0000:0000:0000:0000:abcd");
    const outside = try parseIp("2001:db9::1");

    // Act
    const matches_short = cidr.contains(inside.addr);
    const matches_long = cidr.contains(inside_long.addr);
    const rejects_outside = cidr.contains(outside.addr);

    // Assert
    try std.testing.expect(cidr.is_v6);
    try std.testing.expect(matches_short);
    try std.testing.expect(matches_long);
    try std.testing.expect(!rejects_outside);
}

test "IPv4 mapped text and IPv4 text compare equivalently" {
    // Arrange
    _ = std.testing.allocator;
    const cidr = try Cidr.parse("192.0.2.0/24");
    const dotted = try parseIp("192.0.2.44");
    const mapped = try parseIp("::ffff:192.0.2.44");
    const mapped_cidr = try Cidr.parse("::ffff:192.0.2.0/120");

    // Act
    const same_addr = dotted.addr == mapped.addr;
    const dotted_in_v4 = cidr.contains(dotted.addr);
    const mapped_in_v4 = cidr.contains(mapped.addr);
    const dotted_in_v6 = mapped_cidr.contains(dotted.addr);

    // Assert
    try std.testing.expect(!dotted.is_v6);
    try std.testing.expect(mapped.is_v6);
    try std.testing.expect(same_addr);
    try std.testing.expect(dotted_in_v4);
    try std.testing.expect(mapped_in_v4);
    try std.testing.expect(dotted_in_v6);
}

test "parser rejects malformed IP and CIDR input" {
    // Arrange
    _ = std.testing.allocator;

    // Act and Assert
    try std.testing.expectError(error.InvalidOctet, parseIp("192.0.2.999"));
    try std.testing.expectError(error.TooFewSegments, parseIp("192.0.2"));
    try std.testing.expectError(error.InvalidCompression, parseIp("2001::db8::1"));
    try std.testing.expectError(error.TooFewSegments, parseIp("2001:db8:1"));
    try std.testing.expectError(error.InvalidAddress, parseIp("2001:db8:::1"));
    try std.testing.expectError(error.MissingPrefix, Cidr.parse("192.0.2.0"));
    try std.testing.expectError(error.PrefixOutOfRange, Cidr.parse("192.0.2.0/33"));
    try std.testing.expectError(error.PrefixOutOfRange, Cidr.parse("2001:db8::/129"));
}

test "hostmask glob supports prefix suffix question mark and case folding" {
    // Arrange
    _ = std.testing.allocator;
    const host = "Nick!User@Sub.Example.Test";

    // Act
    const prefix = matchHostmask("nick!*", host);
    const suffix = matchHostmask("*@sub.example.test", host);
    const question = matchHostmask("N?ck!Us?r@Sub.Example.Test", host);
    const miss = matchHostmask("N?ck!root@Sub.Example.Test", host);

    // Assert
    try std.testing.expect(prefix);
    try std.testing.expect(suffix);
    try std.testing.expect(question);
    try std.testing.expect(!miss);
}

test "matchBan dispatches CIDR masks before glob hostmasks" {
    // Arrange
    _ = std.testing.allocator;
    const ip = (try parseIp("203.0.113.9")).addr;
    const host = "alice!user@gateway.example.test";

    // Act
    const cidr_hit = matchBan("203.0.113.0/24", ip, host);
    const cidr_miss = matchBan("198.51.100.0/24", ip, host);
    const cidr_without_ip = matchBan("203.0.113.0/24", null, host);
    const glob_hit = matchBan("*@gateway.example.test", null, host);

    // Assert
    try std.testing.expect(cidr_hit);
    try std.testing.expect(!cidr_miss);
    try std.testing.expect(!cidr_without_ip);
    try std.testing.expect(glob_hit);
}

test "ipToString output parses back to the same normalized address" {
    // Arrange
    _ = std.testing.allocator;
    var ipv4_buf: [16]u8 = undefined;
    var ipv6_buf: [40]u8 = undefined;
    const ipv4 = try parseIp("198.51.100.42");
    const ipv6 = try parseIp("2001:db8::abcd");

    // Act
    const ipv4_text = ipToString(ipv4.addr, ipv4.is_v6, &ipv4_buf);
    const ipv6_text = ipToString(ipv6.addr, ipv6.is_v6, &ipv6_buf);
    const ipv4_again = try parseIp(ipv4_text);
    const ipv6_again = try parseIp(ipv6_text);

    // Assert
    try std.testing.expectEqualStrings("198.51.100.42", ipv4_text);
    try std.testing.expectEqual(ipv4.addr, ipv4_again.addr);
    try std.testing.expectEqual(ipv6.addr, ipv6_again.addr);
    try std.testing.expect(ipv6_again.is_v6);
}

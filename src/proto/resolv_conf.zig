// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure parser for resolv.conf-style configuration text.
//!
//! This module performs NO I/O: the caller supplies the file contents as a
//! `[]const u8`. It extracts nameserver addresses, the search/domain list, and
//! the subset of `options` that a stub resolver actually consumes (ndots,
//! timeout, attempts, rotate).
//!
//! Malformed lines are tolerated: anything that does not parse cleanly is
//! skipped rather than reported as an error, mirroring libc stub behaviour.

const std = @import("std");
const Address = @import("dns.zig").Address;

/// Maximum nameservers honoured by a typical stub resolver.
pub const max_nameservers: usize = 4;
/// Maximum search-domain entries retained.
pub const max_search: usize = 6;
/// Longest domain text we will store for a search entry.
pub const max_domain_len: usize = 253;

/// Default `options` values matching libc when unspecified.
pub const default_ndots: u8 = 1;
pub const default_timeout: u8 = 5;
pub const default_attempts: u8 = 2;

/// A single search-domain string stored inline (no heap).
pub const SearchEntry = struct {
    buf: [max_domain_len]u8 = undefined,
    len: usize = 0,

    pub fn slice(self: *const SearchEntry) []const u8 {
        return self.buf[0..self.len];
    }
};

/// Fully parsed resolver configuration. Fixed capacity, no allocation.
pub const ResolvConf = struct {
    nameservers: [max_nameservers]Address = undefined,
    nameserver_count: usize = 0,

    search: [max_search]SearchEntry = [_]SearchEntry{.{}} ** max_search,
    search_count: usize = 0,

    ndots: u8 = default_ndots,
    timeout: u8 = default_timeout,
    attempts: u8 = default_attempts,
    rotate: bool = false,

    pub fn nameserverSlice(self: *const ResolvConf) []const Address {
        return self.nameservers[0..self.nameserver_count];
    }

    pub fn searchSlice(self: *const ResolvConf) []const SearchEntry {
        return self.search[0..self.search_count];
    }
};

/// Parse resolv.conf text into a fixed-capacity `ResolvConf`.
///
/// Never fails: unknown directives, malformed addresses, and over-capacity
/// entries are silently ignored. Comments (`#`/`;`) and blank lines are skipped.
pub fn parse(text: []const u8) ResolvConf {
    var cfg = ResolvConf{};

    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw_line| {
        const line = stripComment(raw_line);
        var tokens = std.mem.tokenizeAny(u8, line, " \t\r");
        const directive = tokens.next() orelse continue;

        if (std.mem.eql(u8, directive, "nameserver")) {
            handleNameserver(&cfg, &tokens);
        } else if (std.mem.eql(u8, directive, "search")) {
            handleSearch(&cfg, &tokens);
        } else if (std.mem.eql(u8, directive, "domain")) {
            handleDomain(&cfg, &tokens);
        } else if (std.mem.eql(u8, directive, "options")) {
            handleOptions(&cfg, &tokens);
        }
        // Unknown directives (sortlist, etc.) are ignored.
    }

    return cfg;
}

/// Drop everything from the first `#` or `;` comment marker onward.
fn stripComment(line: []const u8) []const u8 {
    for (line, 0..) |c, i| {
        if (c == '#' or c == ';') return line[0..i];
    }
    return line;
}

fn handleNameserver(cfg: *ResolvConf, tokens: *std.mem.TokenIterator(u8, .any)) void {
    const text = tokens.next() orelse return;
    if (cfg.nameserver_count >= max_nameservers) return;
    const addr = parseIp(text) orelse return;
    cfg.nameservers[cfg.nameserver_count] = addr;
    cfg.nameserver_count += 1;
}

/// `search` replaces the entire list with its arguments.
fn handleSearch(cfg: *ResolvConf, tokens: *std.mem.TokenIterator(u8, .any)) void {
    cfg.search_count = 0;
    while (tokens.next()) |domain| {
        appendSearch(cfg, domain);
    }
}

/// `domain` sets a single search entry, replacing any prior list.
fn handleDomain(cfg: *ResolvConf, tokens: *std.mem.TokenIterator(u8, .any)) void {
    const name = tokens.next() orelse return;
    cfg.search_count = 0;
    appendSearch(cfg, name);
}

fn appendSearch(cfg: *ResolvConf, domain: []const u8) void {
    if (cfg.search_count >= max_search) return;
    if (domain.len == 0 or domain.len > max_domain_len) return;
    var entry = SearchEntry{};
    @memcpy(entry.buf[0..domain.len], domain);
    entry.len = domain.len;
    cfg.search[cfg.search_count] = entry;
    cfg.search_count += 1;
}

fn handleOptions(cfg: *ResolvConf, tokens: *std.mem.TokenIterator(u8, .any)) void {
    while (tokens.next()) |opt| {
        if (std.mem.eql(u8, opt, "rotate")) {
            cfg.rotate = true;
        } else if (parseOptionValue(opt, "ndots:")) |v| {
            cfg.ndots = v;
        } else if (parseOptionValue(opt, "timeout:")) |v| {
            cfg.timeout = v;
        } else if (parseOptionValue(opt, "attempts:")) |v| {
            cfg.attempts = v;
        }
        // Unknown options ignored.
    }
}

/// Parse `prefix:N` into a u8, returning null on mismatch or overflow.
fn parseOptionValue(opt: []const u8, prefix: []const u8) ?u8 {
    if (!std.mem.startsWith(u8, opt, prefix)) return null;
    const digits = opt[prefix.len..];
    if (digits.len == 0) return null;
    return std.fmt.parseInt(u8, digits, 10) catch null;
}

// ---------------------------------------------------------------------------
// IP text parsing (local, pure — no std.net dependency).
// ---------------------------------------------------------------------------

/// Parse dotted-quad IPv4 or colon-delimited IPv6 text. Returns null on any
/// malformed input.
pub fn parseIp(text: []const u8) ?Address {
    if (std.mem.indexOfScalar(u8, text, ':') != null) {
        if (parseIpv6(text)) |bytes| return Address{ .ipv6 = bytes };
        return null;
    }
    if (parseIpv4(text)) |bytes| return Address{ .ipv4 = bytes };
    return null;
}

fn parseIpv4(text: []const u8) ?[4]u8 {
    var out: [4]u8 = undefined;
    var parts = std.mem.splitScalar(u8, text, '.');
    var idx: usize = 0;
    while (parts.next()) |part| {
        if (idx >= 4) return null; // too many octets
        if (part.len == 0 or part.len > 3) return null;
        out[idx] = std.fmt.parseInt(u8, part, 10) catch return null;
        idx += 1;
    }
    if (idx != 4) return null;
    return out;
}

/// Minimal RFC 4291 IPv6 text parser supporting `::` compression. Does not
/// accept embedded IPv4 (e.g. `::ffff:1.2.3.4`); such forms return null.
fn parseIpv6(text: []const u8) ?[16]u8 {
    if (text.len == 0) return null;

    // Split on "::" into head and tail halves at most once.
    const dbl = std.mem.indexOf(u8, text, "::");
    var head: [16]u8 = [_]u8{0} ** 16;
    var head_groups: usize = 0;
    var tail: [16]u8 = [_]u8{0} ** 16;
    var tail_groups: usize = 0;

    if (dbl) |pos| {
        // Reject a second "::".
        if (std.mem.indexOf(u8, text[pos + 2 ..], "::") != null) return null;
        const head_text = text[0..pos];
        const tail_text = text[pos + 2 ..];
        head_groups = parseHexGroups(head_text, &head) orelse return null;
        tail_groups = parseHexGroups(tail_text, &tail) orelse return null;
        if (head_groups + tail_groups > 7) return null; // must leave room for compression
    } else {
        head_groups = parseHexGroups(text, &head) orelse return null;
        if (head_groups != 8) return null;
    }

    var out: [16]u8 = [_]u8{0} ** 16;
    @memcpy(out[0 .. head_groups * 2], head[0 .. head_groups * 2]);
    const tail_off = 16 - tail_groups * 2;
    @memcpy(out[tail_off..16], tail[0 .. tail_groups * 2]);
    return out;
}

/// Parse a colon-separated list of 1-4 hex digit groups into `dest` (big
/// endian, 2 bytes per group). Returns the group count, or null on error.
/// An empty input yields zero groups (valid for the edges of `::`).
fn parseHexGroups(text: []const u8, dest: *[16]u8) ?usize {
    if (text.len == 0) return 0;
    var groups = std.mem.splitScalar(u8, text, ':');
    var count: usize = 0;
    while (groups.next()) |grp| {
        if (count >= 8) return null;
        if (grp.len == 0 or grp.len > 4) return null;
        const value = std.fmt.parseInt(u16, grp, 16) catch return null;
        dest[count * 2] = @intCast(value >> 8);
        dest[count * 2 + 1] = @intCast(value & 0xff);
        count += 1;
    }
    return count;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "parse collects multiple IPv4 nameservers in order" {
    // Arrange
    const text =
        \\nameserver 8.8.8.8
        \\nameserver 1.1.1.1
        \\nameserver 192.168.0.1
    ;

    // Act
    const cfg = parse(text);

    // Assert
    try testing.expectEqual(@as(usize, 3), cfg.nameserver_count);
    try testing.expectEqual(Address{ .ipv4 = .{ 8, 8, 8, 8 } }, cfg.nameservers[0]);
    try testing.expectEqual(Address{ .ipv4 = .{ 1, 1, 1, 1 } }, cfg.nameservers[1]);
    try testing.expectEqual(Address{ .ipv4 = .{ 192, 168, 0, 1 } }, cfg.nameservers[2]);
}

test "parse caps nameservers at max_nameservers" {
    // Arrange
    const text =
        \\nameserver 1.0.0.1
        \\nameserver 1.0.0.2
        \\nameserver 1.0.0.3
        \\nameserver 1.0.0.4
        \\nameserver 1.0.0.5
    ;

    // Act
    const cfg = parse(text);

    // Assert
    try testing.expectEqual(max_nameservers, cfg.nameserver_count);
    try testing.expectEqual(Address{ .ipv4 = .{ 1, 0, 0, 4 } }, cfg.nameservers[3]);
}

test "parse handles an IPv6 nameserver with compression" {
    // Arrange
    const text = "nameserver 2001:4860:4860::8888\n";

    // Act
    const cfg = parse(text);

    // Assert
    try testing.expectEqual(@as(usize, 1), cfg.nameserver_count);
    const expected = [16]u8{
        0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x88,
    };
    try testing.expectEqual(Address{ .ipv6 = expected }, cfg.nameservers[0]);
}

test "parse reads full IPv6 loopback ::1" {
    // Arrange
    const text = "nameserver ::1\n";

    // Act
    const cfg = parse(text);

    // Assert
    var expected = [_]u8{0} ** 16;
    expected[15] = 1;
    try testing.expectEqual(Address{ .ipv6 = expected }, cfg.nameservers[0]);
}

test "parse builds the search list and exposes slices" {
    // Arrange
    const text = "search example.com sub.example.com corp.net\n";

    // Act
    const cfg = parse(text);

    // Assert
    const entries = cfg.searchSlice();
    try testing.expectEqual(@as(usize, 3), entries.len);
    try testing.expectEqualStrings("example.com", entries[0].slice());
    try testing.expectEqualStrings("sub.example.com", entries[1].slice());
    try testing.expectEqualStrings("corp.net", entries[2].slice());
}

test "domain directive replaces the search list with one entry" {
    // Arrange
    const text =
        \\search a.com b.com
        \\domain only.example
    ;

    // Act
    const cfg = parse(text);

    // Assert
    try testing.expectEqual(@as(usize, 1), cfg.search_count);
    try testing.expectEqualStrings("only.example", cfg.search[0].slice());
}

test "options parse ndots timeout attempts and rotate" {
    // Arrange
    const text = "options ndots:3 timeout:10 attempts:4 rotate\n";

    // Act
    const cfg = parse(text);

    // Assert
    try testing.expectEqual(@as(u8, 3), cfg.ndots);
    try testing.expectEqual(@as(u8, 10), cfg.timeout);
    try testing.expectEqual(@as(u8, 4), cfg.attempts);
    try testing.expect(cfg.rotate);
}

test "options use defaults when unspecified" {
    // Arrange
    const text = "nameserver 9.9.9.9\n";

    // Act
    const cfg = parse(text);

    // Assert
    try testing.expectEqual(default_ndots, cfg.ndots);
    try testing.expectEqual(default_timeout, cfg.timeout);
    try testing.expectEqual(default_attempts, cfg.attempts);
    try testing.expect(!cfg.rotate);
}

test "parse tolerates comments blank lines and garbage" {
    // Arrange
    const text =
        \\# leading comment
        \\
        \\nameserver 8.8.4.4 ; trailing comment
        \\nameserver not-an-ip
        \\nameserver 999.1.1.1
        \\garbage directive here
        \\
        \\options ndots:notanumber timeout:7
    ;

    // Act
    const cfg = parse(text);

    // Assert: only the one valid nameserver survives.
    try testing.expectEqual(@as(usize, 1), cfg.nameserver_count);
    try testing.expectEqual(Address{ .ipv4 = .{ 8, 8, 4, 4 } }, cfg.nameservers[0]);
    // ndots stayed default (bad value), timeout took effect.
    try testing.expectEqual(default_ndots, cfg.ndots);
    try testing.expectEqual(@as(u8, 7), cfg.timeout);
}

test "parseIp rejects malformed IPv4 octet counts and ranges" {
    // Arrange / Act / Assert
    try testing.expect(parseIp("1.2.3") == null);
    try testing.expect(parseIp("1.2.3.4.5") == null);
    try testing.expect(parseIp("256.1.1.1") == null);
    try testing.expect(parseIp("1..2.3") == null);
    try testing.expectEqual(Address{ .ipv4 = .{ 0, 0, 0, 0 } }, parseIp("0.0.0.0").?);
}

test "parseIp rejects malformed IPv6 double compression" {
    // Arrange / Act / Assert
    try testing.expect(parseIp("2001::4860::1") == null);
    try testing.expect(parseIp("gggg::1") == null);
    try testing.expect(parseIp("12345::1") == null);
}

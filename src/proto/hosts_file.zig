// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure parser and lookup table for hosts-file-style text (no I/O).
//!
//! Callers pass the file contents as a byte slice; the parser builds in-memory
//! forward/reverse lookup tables. Each line: `<ip> <canonical> [aliases...]`
//! with `#` introducing a comment. Malformed lines are silently skipped so one
//! garbage line never poisons the table. Forward lookup maps a name (ASCII
//! case-insensitive) to its first address; reverse lookup maps an address back
//! to the first canonical name that claimed it.
const std = @import("std");

const Address = @import("dns.zig").Address;

/// Maximum decimal value for an IPv4 octet.
const max_octet: u16 = 255;
/// Number of 16-bit groups in an IPv6 address.
const ipv6_groups: usize = 8;

/// Hosts table with forward (name -> address) and reverse (address -> name)
/// lookup. All owned keys are duped from the input and released in `deinit`.
pub const HostsTable = struct {
    allocator: std.mem.Allocator,
    /// name (lowercased, owned) -> first address seen for that name.
    forward: std.StringHashMapUnmanaged(Address),
    /// address-key (16 bytes + family tag) -> canonical name (lowercased, owned).
    reverse: std.AutoHashMapUnmanaged(AddressKey, []const u8),

    /// Canonical, hashable representation of an `Address`.
    const AddressKey = struct {
        is_v6: bool,
        bytes: [16]u8,
    };

    /// Empty table bound to `allocator`. No allocations happen until `parse`.
    pub fn init(allocator: std.mem.Allocator) HostsTable {
        return .{
            .allocator = allocator,
            .forward = .empty,
            .reverse = .empty,
        };
    }

    /// Release every owned key and the backing maps.
    pub fn deinit(self: *HostsTable) void {
        var fwd_it = self.forward.iterator();
        while (fwd_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.forward.deinit(self.allocator);

        var rev_it = self.reverse.iterator();
        while (rev_it.next()) |entry| {
            self.allocator.free(entry.value_ptr.*);
        }
        self.reverse.deinit(self.allocator);
    }

    /// Forward lookup (ASCII case-insensitive): first address for `name`, or null.
    pub fn lookup(self: *const HostsTable, name: []const u8) ?Address {
        var buf: [max_name_len]u8 = undefined;
        const key = lowerName(&buf, name) orelse return null;
        return self.forward.get(key);
    }

    /// Reverse lookup: canonical name for `address` (owned, valid until deinit).
    pub fn reverseLookup(self: *const HostsTable, address: Address) ?[]const u8 {
        return self.reverse.get(addressKey(address));
    }

    /// Number of distinct names in the forward table.
    pub fn nameCount(self: *const HostsTable) usize {
        return self.forward.count();
    }

    /// Parse `text` and populate the table. Duplicate names/addresses keep the
    /// earlier binding ("first match wins"). Only `error.OutOfMemory` escapes;
    /// malformed lines are skipped.
    pub fn parse(self: *HostsTable, text: []const u8) std.mem.Allocator.Error!void {
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |raw_line| {
            try self.parseLine(raw_line);
        }
    }

    /// Parse a single line. Returns without inserting on any malformation.
    fn parseLine(self: *HostsTable, raw_line: []const u8) std.mem.Allocator.Error!void {
        const line = stripComment(raw_line);
        var fields = std.mem.tokenizeAny(u8, line, " \t\r");

        const ip_text = fields.next() orelse return;
        const canonical = fields.next() orelse return;

        const address = parseAddress(ip_text) orelse return;

        // Canonical name owns the reverse mapping; aliases are forward-only.
        try self.insertName(canonical, address, true);
        while (fields.next()) |alias| {
            try self.insertName(alias, address, false);
        }
    }

    /// Insert a forward name->address binding; if `is_canonical`, also record
    /// the reverse mapping. Names too long to normalize are skipped.
    fn insertName(
        self: *HostsTable,
        name: []const u8,
        address: Address,
        is_canonical: bool,
    ) std.mem.Allocator.Error!void {
        var buf: [max_name_len]u8 = undefined;
        const lowered = lowerName(&buf, name) orelse return;

        if (!self.forward.contains(lowered)) {
            const owned = try self.allocator.dupe(u8, lowered);
            const fwd = self.forward.getOrPut(self.allocator, owned) catch |err| {
                self.allocator.free(owned);
                return err;
            };
            if (fwd.found_existing) {
                self.allocator.free(owned);
            } else {
                fwd.value_ptr.* = address;
            }
        }

        if (!is_canonical) return;

        const key = addressKey(address);
        if (!self.reverse.contains(key)) {
            const owned = try self.allocator.dupe(u8, lowered);
            const rev = self.reverse.getOrPut(self.allocator, key) catch |err| {
                self.allocator.free(owned);
                return err;
            };
            if (rev.found_existing) {
                self.allocator.free(owned);
            } else {
                rev.value_ptr.* = owned;
            }
        }
    }
};

/// Maximum name length we will normalize; longer names are rejected (skipped).
const max_name_len: usize = 255;

/// Strip a trailing `# comment` from a line, returning the part before it.
fn stripComment(line: []const u8) []const u8 {
    if (std.mem.indexOfScalar(u8, line, '#')) |idx| {
        return line[0..idx];
    }
    return line;
}

/// ASCII-lowercase `name` into `buf`; null when empty or too long.
fn lowerName(buf: []u8, name: []const u8) ?[]const u8 {
    if (name.len == 0 or name.len > buf.len) return null;
    for (name, 0..) |c, i| {
        buf[i] = std.ascii.toLower(c);
    }
    return buf[0..name.len];
}

/// Build the hashable key for an address via an exhaustive switch.
fn addressKey(address: Address) HostsTable.AddressKey {
    var key = HostsTable.AddressKey{ .is_v6 = false, .bytes = [_]u8{0} ** 16 };
    switch (address) {
        .ipv4 => |octets| {
            key.is_v6 = false;
            @memcpy(key.bytes[0..4], &octets);
        },
        .ipv6 => |octets| {
            key.is_v6 = true;
            @memcpy(key.bytes[0..16], &octets);
        },
    }
    return key;
}

/// Parse a textual address; a `:` selects IPv6, else IPv4. Null on malformation.
fn parseAddress(text: []const u8) ?Address {
    if (text.len == 0) return null;
    if (std.mem.indexOfScalar(u8, text, ':') != null) {
        const octets = parseIpv6(text) orelse return null;
        return Address{ .ipv6 = octets };
    }
    const octets = parseIpv4(text) orelse return null;
    return Address{ .ipv4 = octets };
}

/// Parse dotted-quad IPv4 (exactly four octets in 0..=255).
fn parseIpv4(text: []const u8) ?[4]u8 {
    var out: [4]u8 = undefined;
    var parts = std.mem.splitScalar(u8, text, '.');
    var count: usize = 0;
    while (parts.next()) |part| {
        if (count >= 4) return null;
        if (part.len == 0 or part.len > 3) return null;
        const value = std.fmt.parseInt(u16, part, 10) catch return null;
        if (value > max_octet) return null;
        out[count] = @intCast(value);
        count += 1;
    }
    if (count != 4) return null;
    return out;
}

/// Parse an IPv6 address with a single optional `::` zero-run. Embedded IPv4
/// tails are not handled and yield null (treated as malformed -> skip).
fn parseIpv6(text: []const u8) ?[16]u8 {
    if (text.len < 2) return null;

    const double_colon = std.mem.indexOf(u8, text, "::");
    if (double_colon) |idx| {
        if (std.mem.indexOfPos(u8, text, idx + 2, "::") != null) return null; // one `::` only
        const head = text[0..idx];
        const tail = text[idx + 2 ..];

        var head_groups: [ipv6_groups]u16 = undefined;
        var tail_groups: [ipv6_groups]u16 = undefined;
        const head_len = parseGroups(head, &head_groups) orelse return null;
        const tail_len = parseGroups(tail, &tail_groups) orelse return null;
        if (head_len + tail_len > ipv6_groups) return null;

        var groups = [_]u16{0} ** ipv6_groups;
        for (0..head_len) |i| groups[i] = head_groups[i];
        const tail_start = ipv6_groups - tail_len;
        for (0..tail_len) |i| groups[tail_start + i] = tail_groups[i];
        return groupsToBytes(groups);
    }

    var groups: [ipv6_groups]u16 = undefined;
    const len = parseGroups(text, &groups) orelse return null;
    if (len != ipv6_groups) return null;
    return groupsToBytes(groups);
}

/// Parse colon-separated hex groups into `out`, returning the count (0 if
/// empty). Null on any malformed group.
fn parseGroups(text: []const u8, out: *[ipv6_groups]u16) ?usize {
    if (text.len == 0) return 0;
    var parts = std.mem.splitScalar(u8, text, ':');
    var count: usize = 0;
    while (parts.next()) |part| {
        if (count >= ipv6_groups) return null;
        if (part.len == 0 or part.len > 4) return null;
        const value = std.fmt.parseInt(u16, part, 16) catch return null;
        out[count] = value;
        count += 1;
    }
    return count;
}

/// Expand groups into 16 big-endian bytes.
fn groupsToBytes(groups: [ipv6_groups]u16) [16]u8 {
    var bytes: [16]u8 = undefined;
    for (groups, 0..) |group, i| {
        bytes[i * 2] = @intCast(group >> 8);
        bytes[i * 2 + 1] = @intCast(group & 0xff);
    }
    return bytes;
}

// --- Tests ---

test "forward lookup resolves canonical name to its address" {
    // Arrange
    var table = HostsTable.init(std.testing.allocator);
    defer table.deinit();
    try table.parse("127.0.0.1 localhost\n");

    // Act
    const result = table.lookup("localhost");

    // Assert
    try std.testing.expect(result != null);
    try std.testing.expectEqual(Address{ .ipv4 = .{ 127, 0, 0, 1 } }, result.?);
}

test "reverse lookup returns the canonical name for an address" {
    // Arrange
    var table = HostsTable.init(std.testing.allocator);
    defer table.deinit();
    try table.parse("10.0.0.5 host.example alias1 alias2\n");

    // Act
    const name = table.reverseLookup(Address{ .ipv4 = .{ 10, 0, 0, 5 } });

    // Assert
    try std.testing.expect(name != null);
    try std.testing.expectEqualStrings("host.example", name.?);
}

test "aliases resolve forward but do not own the reverse mapping" {
    // Arrange
    var table = HostsTable.init(std.testing.allocator);
    defer table.deinit();
    try table.parse("192.168.1.1 router gateway gw\n");
    const expected = Address{ .ipv4 = .{ 192, 168, 1, 1 } };

    // Act
    const router = table.lookup("router");
    const gateway = table.lookup("gateway");
    const gw = table.lookup("gw");
    const reverse = table.reverseLookup(expected);

    // Assert
    try std.testing.expectEqual(expected, router.?);
    try std.testing.expectEqual(expected, gateway.?);
    try std.testing.expectEqual(expected, gw.?);
    try std.testing.expectEqualStrings("router", reverse.?);
}

test "name matching is ASCII case-insensitive" {
    // Arrange
    var table = HostsTable.init(std.testing.allocator);
    defer table.deinit();
    try table.parse("127.0.1.1 MixedCase.Host\n");
    const expected = Address{ .ipv4 = .{ 127, 0, 1, 1 } };

    // Act
    const lower = table.lookup("mixedcase.host");
    const upper = table.lookup("MIXEDCASE.HOST");
    const reverse = table.reverseLookup(expected);

    // Assert
    try std.testing.expectEqual(expected, lower.?);
    try std.testing.expectEqual(expected, upper.?);
    // Stored canonical name is normalized to lowercase.
    try std.testing.expectEqualStrings("mixedcase.host", reverse.?);
}

test "IPv6 entry parses with zero-run compression in both directions" {
    // Arrange
    var table = HostsTable.init(std.testing.allocator);
    defer table.deinit();
    try table.parse("::1 ip6-localhost ip6-loopback\n");
    var expected_bytes = [_]u8{0} ** 16;
    expected_bytes[15] = 1;
    const expected = Address{ .ipv6 = expected_bytes };

    // Act
    const forward = table.lookup("ip6-localhost");
    const alias = table.lookup("ip6-loopback");
    const reverse = table.reverseLookup(expected);

    // Assert
    try std.testing.expectEqual(expected, forward.?);
    try std.testing.expectEqual(expected, alias.?);
    try std.testing.expectEqualStrings("ip6-localhost", reverse.?);
}

test "full uncompressed IPv6 address parses correctly" {
    // Arrange
    var table = HostsTable.init(std.testing.allocator);
    defer table.deinit();
    try table.parse("2001:0db8:0000:0000:0000:0000:0000:0001 ipv6.host\n");

    // Act
    const result = table.lookup("ipv6.host");

    // Assert
    try std.testing.expect(result != null);
    const expected_bytes = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    try std.testing.expectEqual(Address{ .ipv6 = expected_bytes }, result.?);
}

test "comments and inline comments are ignored" {
    // Arrange
    var table = HostsTable.init(std.testing.allocator);
    defer table.deinit();
    const text =
        \\# this is a full-line comment
        \\127.0.0.1 localhost # trailing comment with garbage 999.999.999.999
        \\
        \\   # indented comment
    ;
    try table.parse(text);

    // Act
    const result = table.lookup("localhost");

    // Assert
    try std.testing.expectEqual(Address{ .ipv4 = .{ 127, 0, 0, 1 } }, result.?);
    try std.testing.expectEqual(@as(usize, 1), table.nameCount());
}

test "malformed lines are skipped without poisoning valid entries" {
    // Arrange
    var table = HostsTable.init(std.testing.allocator);
    defer table.deinit();
    const text =
        \\999.1.1.1 badoctet
        \\1.2.3 tooshort
        \\1.2.3.4.5 toolong
        \\not-an-ip alsobad
        \\10.0.0.1
        \\10.0.0.2 valid.host
        \\garbage line with no leading ip but words
    ;
    try table.parse(text);

    // Act
    const valid = table.lookup("valid.host");
    const bad_octet = table.lookup("badoctet");
    const too_short = table.lookup("tooshort");

    // Assert
    try std.testing.expectEqual(Address{ .ipv4 = .{ 10, 0, 0, 2 } }, valid.?);
    try std.testing.expect(bad_octet == null);
    try std.testing.expect(too_short == null);
}

test "missing name returns null for both lookups" {
    // Arrange
    var table = HostsTable.init(std.testing.allocator);
    defer table.deinit();
    try table.parse("127.0.0.1 localhost\n");

    // Act
    const forward_miss = table.lookup("nonexistent.host");
    const reverse_miss = table.reverseLookup(Address{ .ipv4 = .{ 8, 8, 8, 8 } });
    const empty_miss = table.lookup("");

    // Assert
    try std.testing.expect(forward_miss == null);
    try std.testing.expect(reverse_miss == null);
    try std.testing.expect(empty_miss == null);
}

test "first binding wins for duplicate names and addresses" {
    // Arrange
    var table = HostsTable.init(std.testing.allocator);
    defer table.deinit();
    const text =
        \\10.0.0.1 dup.host
        \\10.0.0.2 dup.host
        \\10.0.0.1 second.name
    ;
    try table.parse(text);

    // Act
    const name_addr = table.lookup("dup.host");
    const reverse = table.reverseLookup(Address{ .ipv4 = .{ 10, 0, 0, 1 } });

    // Assert
    // Forward keeps the first address seen for the name.
    try std.testing.expectEqual(Address{ .ipv4 = .{ 10, 0, 0, 1 } }, name_addr.?);
    // Reverse keeps the first canonical name to claim the address.
    try std.testing.expectEqualStrings("dup.host", reverse.?);
}

test "empty input produces an empty table" {
    // Arrange
    var table = HostsTable.init(std.testing.allocator);
    defer table.deinit();

    // Act
    try table.parse("");

    // Assert
    try std.testing.expectEqual(@as(usize, 0), table.nameCount());
}

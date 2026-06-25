// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! GagSet — the persistent set of gagged IP addresses for IRCX +z GAG.
//!
//! GAG is set on a client (`MODE <nick> +z`), but it binds to that client's IP
//! address: every nick connecting from a gagged IP is silenced, and the gag
//! survives reconnection (it lives here, on the server, not on the transient
//! connection). This module owns the IP set; the daemon resolves a target nick
//! to its IP, records it here, and consults it when silencing senders and when
//! a client registers. Pure: owns its strings, performs no I/O.

const std = @import("std");

pub const Params = struct {
    max_entries: usize = 4096,
    max_ip: usize = 64,
};

pub const GagError = std.mem.Allocator.Error || error{
    EmptyIp,
    IpTooLong,
    TooManyEntries,
};

/// An owning set of gagged IP addresses (exact, case-insensitive match).
pub const GagSet = struct {
    allocator: std.mem.Allocator,
    params: Params,
    ips: std.ArrayListUnmanaged([]u8) = .empty,

    pub fn init(allocator: std.mem.Allocator, params: Params) GagSet {
        return .{ .allocator = allocator, .params = params };
    }

    pub fn deinit(self: *GagSet) void {
        for (self.ips.items) |ip| self.allocator.free(ip);
        self.ips.deinit(self.allocator);
        self.* = undefined;
    }

    /// Record `ip` as gagged. Idempotent: a duplicate IP is a no-op success.
    pub fn add(self: *GagSet, ip: []const u8) GagError!void {
        if (ip.len == 0) return error.EmptyIp;
        if (ip.len > self.params.max_ip) return error.IpTooLong;
        if (self.indexOf(ip) != null) return;
        if (self.ips.items.len >= self.params.max_entries) return error.TooManyEntries;
        const owned = try self.allocator.dupe(u8, ip);
        errdefer self.allocator.free(owned);
        try self.ips.append(self.allocator, owned);
    }

    /// Remove `ip` from the set. Returns true when it was present.
    pub fn remove(self: *GagSet, ip: []const u8) bool {
        const idx = self.indexOf(ip) orelse return false;
        const owned = self.ips.orderedRemove(idx);
        self.allocator.free(owned);
        return true;
    }

    /// Whether `ip` is currently gagged.
    pub fn contains(self: *const GagSet, ip: []const u8) bool {
        return self.indexOf(ip) != null;
    }

    pub fn count(self: *const GagSet) usize {
        return self.ips.items.len;
    }

    fn indexOf(self: *const GagSet, ip: []const u8) ?usize {
        for (self.ips.items, 0..) |stored, i| {
            if (std.ascii.eqlIgnoreCase(stored, ip)) return i;
        }
        return null;
    }
};

const testing = std.testing;

test "add records an ip; contains matches case-insensitively" {
    var set = GagSet.init(testing.allocator, .{});
    defer set.deinit();
    try set.add("192.0.2.10");
    try testing.expect(set.contains("192.0.2.10"));
    try testing.expect(set.contains("192.0.2.10"));
    try testing.expect(!set.contains("192.0.2.11"));
}

test "add is idempotent" {
    var set = GagSet.init(testing.allocator, .{});
    defer set.deinit();
    try set.add("2001:db8::1");
    try set.add("2001:DB8::1");
    try testing.expectEqual(@as(usize, 1), set.count());
}

test "remove clears only the named ip" {
    var set = GagSet.init(testing.allocator, .{});
    defer set.deinit();
    try set.add("10.0.0.1");
    try set.add("10.0.0.2");
    try testing.expect(set.remove("10.0.0.1"));
    try testing.expect(!set.remove("10.0.0.1"));
    try testing.expect(!set.contains("10.0.0.1"));
    try testing.expect(set.contains("10.0.0.2"));
}

test "validation: empty, too long, and capacity" {
    var set = GagSet.init(testing.allocator, .{ .max_entries = 1, .max_ip = 8 });
    defer set.deinit();
    try testing.expectError(error.EmptyIp, set.add(""));
    try testing.expectError(error.IpTooLong, set.add("toolong-address"));
    try set.add("1.2.3.4");
    try testing.expectError(error.TooManyEntries, set.add("5.6.7.8"));
}

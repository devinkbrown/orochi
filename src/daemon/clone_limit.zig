// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure per-host connection-clone limiter.
//!
//! Tracks the number of concurrently live connections keyed by exact address,
//! and (optionally) by an aggregated network prefix: /24 for IPv4 and /64 for
//! IPv6. Unlike a rate limiter, this counts *concurrent* connections rather
//! than connection events over time. It reads no clock, touches no sockets,
//! and performs no filesystem I/O; the only external resource is an allocator.
//!
//! Use `register` on accept and `release` on disconnect. `register` increments
//! the relevant counters only when both the per-IP and per-net limits would be
//! respected; on rejection it returns an error and leaves all state untouched.

const std = @import("std");
const Address = @import("../proto/dns.zig").Address;

/// IPv4 host bytes that are aggregated away to form the /24 prefix key.
const ipv4_net_host_bytes: usize = 1;
/// IPv6 host bytes that are aggregated away to form the /64 prefix key.
const ipv6_net_host_bytes: usize = 8;

/// Errors returned when a registration would exceed a configured limit.
pub const RegisterError = error{
    TooManyPerIp,
    TooManyPerNet,
};

/// Fixed-width hashable key for an exact address or a network prefix.
///
/// `len` selects the significant prefix of `bytes`. For a /24 prefix the first
/// three IPv4 octets are kept; for a /64 prefix the first eight IPv6 bytes are
/// kept. `family` keeps IPv4 and IPv6 keys disjoint even when byte prefixes
/// would otherwise collide.
const Key = struct {
    family: Family,
    len: u8,
    bytes: [16]u8,

    const Family = enum(u8) { ipv4, ipv6 };

    fn exact(addr: Address) Key {
        return switch (addr) {
            .ipv4 => |b| build(.ipv4, b[0..], b.len),
            .ipv6 => |b| build(.ipv6, b[0..], b.len),
        };
    }

    fn net(addr: Address) Key {
        return switch (addr) {
            .ipv4 => |b| build(.ipv4, b[0..], b.len - ipv4_net_host_bytes),
            .ipv6 => |b| build(.ipv6, b[0..], b.len - ipv6_net_host_bytes),
        };
    }

    fn build(family: Family, src: []const u8, len: usize) Key {
        var key = Key{ .family = family, .len = @intCast(len), .bytes = @as([16]u8, @splat(0)) };
        @memcpy(key.bytes[0..len], src[0..len]);
        return key;
    }
};

/// Limiter configuration. Each limit caps the number of concurrent
/// connections; a value of zero disables that dimension entirely.
pub const Config = struct {
    /// Maximum concurrent connections from a single exact address.
    max_per_ip: u32,
    /// Maximum concurrent connections aggregated across a /24 or /64 prefix.
    /// Set to zero to skip per-network accounting.
    max_per_net: u32,
};

/// Concurrent-connection clone limiter over exact addresses and net prefixes.
pub const CloneLimiter = struct {
    allocator: std.mem.Allocator,
    config: Config,
    per_ip: std.AutoHashMapUnmanaged(Key, u32) = .empty,
    per_net: std.AutoHashMapUnmanaged(Key, u32) = .empty,

    /// Initialize an empty limiter bound to `allocator`.
    pub fn init(allocator: std.mem.Allocator, config: Config) CloneLimiter {
        return .{ .allocator = allocator, .config = config };
    }

    /// Release all tracked counters.
    pub fn deinit(self: *CloneLimiter) void {
        self.per_ip.deinit(self.allocator);
        self.per_net.deinit(self.allocator);
        self.* = undefined;
    }

    /// Whether per-network accounting is active for this limiter.
    fn netEnabled(self: *const CloneLimiter) bool {
        return self.config.max_per_net != 0;
    }

    /// Register one new connection from `addr`.
    ///
    /// Increments the per-IP counter, and (when enabled) the per-net counter,
    /// only if neither would exceed its configured maximum. On rejection no
    /// counter is modified. Returns `error.NoSpaceLeft` if the allocator
    /// cannot grow a map; in that case no counter is modified either.
    pub fn register(self: *CloneLimiter, addr: Address) (RegisterError || error{NoSpaceLeft})!void {
        const ip_key = Key.exact(addr);
        const ip_count = self.per_ip.get(ip_key) orelse 0;
        if (self.config.max_per_ip != 0 and ip_count >= self.config.max_per_ip) {
            return error.TooManyPerIp;
        }

        if (!self.netEnabled()) {
            self.per_ip.ensureUnusedCapacity(self.allocator, 1) catch return error.NoSpaceLeft;
            self.per_ip.putAssumeCapacity(ip_key, ip_count + 1);
            return;
        }

        const net_key = Key.net(addr);
        const net_count = self.per_net.get(net_key) orelse 0;
        if (net_count >= self.config.max_per_net) {
            return error.TooManyPerNet;
        }

        // Reserve capacity on both maps before mutating either, so a failed
        // allocation cannot leave the counters half-incremented.
        self.per_ip.ensureUnusedCapacity(self.allocator, 1) catch return error.NoSpaceLeft;
        self.per_net.ensureUnusedCapacity(self.allocator, 1) catch return error.NoSpaceLeft;

        self.per_ip.putAssumeCapacity(ip_key, ip_count + 1);
        self.per_net.putAssumeCapacity(net_key, net_count + 1);
    }

    /// Release one connection from `addr`.
    ///
    /// Counters never drop below zero, and entries that reach zero are removed.
    /// Releasing an address that is not currently tracked is a no-op.
    pub fn release(self: *CloneLimiter, addr: Address) void {
        decrement(&self.per_ip, Key.exact(addr));
        if (self.netEnabled()) {
            decrement(&self.per_net, Key.net(addr));
        }
    }

    /// Current concurrent connection count for the exact address.
    pub fn countForIp(self: *const CloneLimiter, addr: Address) u32 {
        return self.per_ip.get(Key.exact(addr)) orelse 0;
    }

    /// Current concurrent connection count for the address's /24 or /64 prefix.
    /// Always zero when per-network accounting is disabled.
    pub fn countForNet(self: *const CloneLimiter, addr: Address) u32 {
        if (!self.netEnabled()) return 0;
        return self.per_net.get(Key.net(addr)) orelse 0;
    }

    fn decrement(map: *std.AutoHashMapUnmanaged(Key, u32), key: Key) void {
        const entry = map.getPtr(key) orelse return;
        if (entry.* <= 1) {
            _ = map.remove(key);
            return;
        }
        entry.* -= 1;
    }
};

// -- Test fixtures -----------------------------------------------------------

fn v4(a: u8, b: u8, c: u8, d: u8) Address {
    return .{ .ipv4 = .{ a, b, c, d } };
}

fn v6(prefix: [8]u8, host: [8]u8) Address {
    var bytes: [16]u8 = undefined;
    @memcpy(bytes[0..8], &prefix);
    @memcpy(bytes[8..16], &host);
    return .{ .ipv6 = bytes };
}

// -- Tests -------------------------------------------------------------------

test "register succeeds while under the per-ip limit" {
    // Arrange
    var limiter = CloneLimiter.init(std.testing.allocator, .{ .max_per_ip = 3, .max_per_net = 0 });
    defer limiter.deinit();
    const addr = v4(192, 0, 2, 10);

    // Act
    try limiter.register(addr);
    try limiter.register(addr);

    // Assert
    try std.testing.expectEqual(@as(u32, 2), limiter.countForIp(addr));
}

test "register at the per-ip limit returns error and does not increment" {
    // Arrange
    var limiter = CloneLimiter.init(std.testing.allocator, .{ .max_per_ip = 2, .max_per_net = 0 });
    defer limiter.deinit();
    const addr = v4(198, 51, 100, 7);
    try limiter.register(addr);
    try limiter.register(addr);

    // Act
    const result = limiter.register(addr);

    // Assert
    try std.testing.expectError(error.TooManyPerIp, result);
    try std.testing.expectEqual(@as(u32, 2), limiter.countForIp(addr));
}

test "release decrements and frees the entry when it reaches zero" {
    // Arrange
    var limiter = CloneLimiter.init(std.testing.allocator, .{ .max_per_ip = 4, .max_per_net = 0 });
    defer limiter.deinit();
    const addr = v4(203, 0, 113, 4);
    try limiter.register(addr);
    try limiter.register(addr);

    // Act
    limiter.release(addr);
    try std.testing.expectEqual(@as(u32, 1), limiter.countForIp(addr));
    limiter.release(addr);

    // Assert
    try std.testing.expectEqual(@as(u32, 0), limiter.countForIp(addr));
    try std.testing.expectEqual(@as(usize, 0), limiter.per_ip.count());
}

test "per-/24 aggregation across distinct ips trips TooManyPerNet" {
    // Arrange
    var limiter = CloneLimiter.init(std.testing.allocator, .{ .max_per_ip = 5, .max_per_net = 2 });
    defer limiter.deinit();

    // Act: three distinct hosts inside 192.0.2.0/24.
    try limiter.register(v4(192, 0, 2, 1));
    try limiter.register(v4(192, 0, 2, 2));
    const result = limiter.register(v4(192, 0, 2, 3));

    // Assert
    try std.testing.expectError(error.TooManyPerNet, result);
    try std.testing.expectEqual(@as(u32, 2), limiter.countForNet(v4(192, 0, 2, 99)));
    // The rejected host must not have been recorded.
    try std.testing.expectEqual(@as(u32, 0), limiter.countForIp(v4(192, 0, 2, 3)));
}

test "different /24 networks are accounted separately" {
    // Arrange
    var limiter = CloneLimiter.init(std.testing.allocator, .{ .max_per_ip = 5, .max_per_net = 1 });
    defer limiter.deinit();

    // Act
    try limiter.register(v4(192, 0, 2, 1));
    try limiter.register(v4(192, 0, 3, 1));

    // Assert
    try std.testing.expectEqual(@as(u32, 1), limiter.countForNet(v4(192, 0, 2, 5)));
    try std.testing.expectEqual(@as(u32, 1), limiter.countForNet(v4(192, 0, 3, 5)));
}

test "per-/64 aggregation across distinct ipv6 hosts trips TooManyPerNet" {
    // Arrange
    var limiter = CloneLimiter.init(std.testing.allocator, .{ .max_per_ip = 5, .max_per_net = 2 });
    defer limiter.deinit();
    const prefix = [8]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0 };

    // Act: distinct host suffixes share the same /64.
    try limiter.register(v6(prefix, .{ 0, 0, 0, 0, 0, 0, 0, 1 }));
    try limiter.register(v6(prefix, .{ 0, 0, 0, 0, 0, 0, 0, 2 }));
    const result = limiter.register(v6(prefix, .{ 0, 0, 0, 0, 0, 0, 0, 3 }));

    // Assert
    try std.testing.expectError(error.TooManyPerNet, result);
    try std.testing.expectEqual(
        @as(u32, 2),
        limiter.countForNet(v6(prefix, .{ 9, 9, 9, 9, 9, 9, 9, 9 })),
    );
}

test "ipv6 hosts in different /64 prefixes do not aggregate together" {
    // Arrange
    var limiter = CloneLimiter.init(std.testing.allocator, .{ .max_per_ip = 5, .max_per_net = 1 });
    defer limiter.deinit();
    const prefix_a = [8]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0 };
    const prefix_b = [8]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1 };
    const host = [8]u8{ 0, 0, 0, 0, 0, 0, 0, 1 };

    // Act
    try limiter.register(v6(prefix_a, host));
    try limiter.register(v6(prefix_b, host));

    // Assert
    try std.testing.expectEqual(@as(u32, 1), limiter.countForNet(v6(prefix_a, host)));
    try std.testing.expectEqual(@as(u32, 1), limiter.countForNet(v6(prefix_b, host)));
}

test "release of an unknown address is a no-op" {
    // Arrange
    var limiter = CloneLimiter.init(std.testing.allocator, .{ .max_per_ip = 2, .max_per_net = 2 });
    defer limiter.deinit();

    // Act
    limiter.release(v4(10, 0, 0, 1));
    limiter.release(v6(@as([8]u8, @splat(0)), @as([8]u8, @splat(0))));

    // Assert
    try std.testing.expectEqual(@as(u32, 0), limiter.countForIp(v4(10, 0, 0, 1)));
    try std.testing.expectEqual(@as(usize, 0), limiter.per_ip.count());
    try std.testing.expectEqual(@as(usize, 0), limiter.per_net.count());
}

test "per-ip rejection does not consume per-net capacity" {
    // Arrange
    var limiter = CloneLimiter.init(std.testing.allocator, .{ .max_per_ip = 1, .max_per_net = 4 });
    defer limiter.deinit();
    const addr = v4(192, 0, 2, 50);
    try limiter.register(addr);

    // Act: the second register on the same IP should fail on the per-ip check
    // before the per-net counter is ever touched.
    const result = limiter.register(addr);

    // Assert
    try std.testing.expectError(error.TooManyPerIp, result);
    try std.testing.expectEqual(@as(u32, 1), limiter.countForNet(addr));
}

test "release decrements both per-ip and per-net dimensions" {
    // Arrange
    var limiter = CloneLimiter.init(std.testing.allocator, .{ .max_per_ip = 4, .max_per_net = 4 });
    defer limiter.deinit();
    try limiter.register(v4(192, 0, 2, 1));
    try limiter.register(v4(192, 0, 2, 2));

    // Act
    limiter.release(v4(192, 0, 2, 1));

    // Assert
    try std.testing.expectEqual(@as(u32, 0), limiter.countForIp(v4(192, 0, 2, 1)));
    try std.testing.expectEqual(@as(u32, 1), limiter.countForIp(v4(192, 0, 2, 2)));
    try std.testing.expectEqual(@as(u32, 1), limiter.countForNet(v4(192, 0, 2, 9)));
}

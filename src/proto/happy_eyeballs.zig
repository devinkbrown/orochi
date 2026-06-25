// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

const std = @import("std");

const Allocator = std.mem.Allocator;

pub const Family = enum {
    ipv6,
    ipv4,
};

pub const Address = struct {
    family: Family,
    bytes: [16]u8,
    port: u16,

    pub fn ipv4(octets: [4]u8, port: u16) Address {
        var bytes = [_]u8{0} ** 16;
        bytes[10] = 0xff;
        bytes[11] = 0xff;
        @memcpy(bytes[12..16], octets[0..]);
        return .{
            .family = .ipv4,
            .bytes = bytes,
            .port = port,
        };
    }

    pub fn ipv6(bytes: [16]u8, port: u16) Address {
        return .{
            .family = .ipv6,
            .bytes = bytes,
            .port = port,
        };
    }

    pub fn eql(self: Address, other: Address) bool {
        return self.family == other.family and
            self.port == other.port and
            std.mem.eql(u8, self.bytes[0..], other.bytes[0..]);
    }
};

pub const Config = struct {
    allocator: Allocator,
    connection_attempt_delay_ms: u64 = 250,
};

const AttemptState = enum {
    queued,
    in_flight,
    failed,
    succeeded,
    canceled,
};

const Attempt = struct {
    addr: Address,
    state: AttemptState = .queued,
};

pub const HappyEyeballs = struct {
    allocator: Allocator,
    attempts: []Attempt,
    delay_ms: u64,
    next_index: usize = 0,
    active_count: usize = 0,
    have_last_start: bool = false,
    last_start_ms: u64 = 0,
    winner_index: ?usize = null,

    pub fn init(addresses: []const Address, cfg: Config) !HappyEyeballs {
        var ipv6_addrs: std.ArrayList(Address) = .empty;
        defer ipv6_addrs.deinit(cfg.allocator);

        var ipv4_addrs: std.ArrayList(Address) = .empty;
        defer ipv4_addrs.deinit(cfg.allocator);

        for (addresses) |addr| {
            switch (addr.family) {
                .ipv6 => try ipv6_addrs.append(cfg.allocator, addr),
                .ipv4 => try ipv4_addrs.append(cfg.allocator, addr),
            }
        }

        var attempts: std.ArrayList(Attempt) = .empty;
        errdefer attempts.deinit(cfg.allocator);

        var v6_index: usize = 0;
        var v4_index: usize = 0;
        while (v6_index < ipv6_addrs.items.len or v4_index < ipv4_addrs.items.len) {
            if (v6_index < ipv6_addrs.items.len) {
                try attempts.append(cfg.allocator, .{ .addr = ipv6_addrs.items[v6_index] });
                v6_index += 1;
            }
            if (v4_index < ipv4_addrs.items.len) {
                try attempts.append(cfg.allocator, .{ .addr = ipv4_addrs.items[v4_index] });
                v4_index += 1;
            }
        }

        return .{
            .allocator = cfg.allocator,
            .attempts = try attempts.toOwnedSlice(cfg.allocator),
            .delay_ms = cfg.connection_attempt_delay_ms,
        };
    }

    pub fn deinit(self: *HappyEyeballs) void {
        self.allocator.free(self.attempts);
        self.* = undefined;
    }

    pub fn nextAttempt(self: *HappyEyeballs, now_ms: u64) ?Address {
        if (self.done() or self.next_index >= self.attempts.len) return null;
        if (!self.canStart(now_ms)) return null;

        const index = self.next_index;
        self.next_index += 1;
        self.attempts[index].state = .in_flight;
        self.active_count += 1;
        self.have_last_start = true;
        self.last_start_ms = now_ms;
        return self.attempts[index].addr;
    }

    pub fn onConnected(self: *HappyEyeballs, addr: Address) bool {
        if (self.winner_index != null) return false;
        const index = self.findActive(addr) orelse return false;

        self.attempts[index].state = .succeeded;
        self.winner_index = index;
        self.cancelOthers(index);
        return true;
    }

    pub fn onFailed(self: *HappyEyeballs, addr: Address, now_ms: u64) bool {
        _ = now_ms;
        if (self.winner_index != null) return false;
        const index = self.findActive(addr) orelse return false;

        self.attempts[index].state = .failed;
        self.active_count -= 1;
        return true;
    }

    pub fn done(self: *const HappyEyeballs) bool {
        if (self.winner_index != null) return true;
        return self.next_index >= self.attempts.len and self.active_count == 0;
    }

    pub fn winner(self: *const HappyEyeballs) ?Address {
        const index = self.winner_index orelse return null;
        return self.attempts[index].addr;
    }

    fn canStart(self: *const HappyEyeballs, now_ms: u64) bool {
        if (!self.have_last_start) return true;
        if (self.active_count == 0) return true;
        if (self.delay_ms == 0) return true;
        if (now_ms < self.last_start_ms) return false;
        return now_ms - self.last_start_ms >= self.delay_ms;
    }

    fn findActive(self: *const HappyEyeballs, addr: Address) ?usize {
        for (self.attempts, 0..) |attempt, index| {
            if (attempt.state == .in_flight and attempt.addr.eql(addr)) return index;
        }
        return null;
    }

    fn cancelOthers(self: *HappyEyeballs, winner_index: usize) void {
        for (self.attempts, 0..) |*attempt, index| {
            if (index == winner_index) continue;
            switch (attempt.state) {
                .queued, .in_flight => attempt.state = .canceled,
                .failed, .succeeded, .canceled => {},
            }
        }
        self.active_count = 0;
    }
};

pub fn init(addresses: []const Address, cfg: Config) !HappyEyeballs {
    return HappyEyeballs.init(addresses, cfg);
}

fn v6(last: u8) Address {
    var bytes = [_]u8{0} ** 16;
    bytes[15] = last;
    return Address.ipv6(bytes, 443);
}

fn v4(last: u8) Address {
    return Address.ipv4(.{ 192, 0, 2, last }, 443);
}

fn expectAddr(actual: ?Address, expected: Address) !void {
    try std.testing.expect(actual != null);
    try std.testing.expect(actual.?.eql(expected));
}

test "v6/v4 interleaving order keeps family-local order and starts with v6" {
    const addrs = [_]Address{
        v4(1),
        v4(2),
        v6(1),
        v6(2),
        v4(3),
    };

    var he = try init(addrs[0..], .{
        .allocator = std.testing.allocator,
        .connection_attempt_delay_ms = 0,
    });
    defer he.deinit();

    try expectAddr(he.nextAttempt(10), v6(1));
    try expectAddr(he.nextAttempt(10), v4(1));
    try expectAddr(he.nextAttempt(10), v6(2));
    try expectAddr(he.nextAttempt(10), v4(2));
    try expectAddr(he.nextAttempt(10), v4(3));
    try std.testing.expect(he.nextAttempt(10) == null);
}

test "staggered start respects connection attempt delay" {
    const addrs = [_]Address{
        v6(1),
        v4(1),
        v6(2),
    };

    var he = try init(addrs[0..], .{
        .allocator = std.testing.allocator,
        .connection_attempt_delay_ms = 100,
    });
    defer he.deinit();

    try expectAddr(he.nextAttempt(1000), v6(1));
    try std.testing.expect(he.nextAttempt(1099) == null);
    try expectAddr(he.nextAttempt(1100), v4(1));
    try std.testing.expect(he.nextAttempt(1199) == null);
    try expectAddr(he.nextAttempt(1200), v6(2));
    try std.testing.expect(he.nextAttempt(1300) == null);
}

test "first success wins and cancels queued and in-flight attempts" {
    const addrs = [_]Address{
        v6(1),
        v4(1),
        v6(2),
    };

    var he = try init(addrs[0..], .{
        .allocator = std.testing.allocator,
        .connection_attempt_delay_ms = 50,
    });
    defer he.deinit();

    try expectAddr(he.nextAttempt(0), v6(1));
    try expectAddr(he.nextAttempt(50), v4(1));

    try std.testing.expect(he.onConnected(v4(1)));
    try std.testing.expect(he.done());
    try expectAddr(he.winner(), v4(1));
    try std.testing.expect(he.nextAttempt(100) == null);
    try std.testing.expect(!he.onConnected(v6(1)));
    try std.testing.expect(!he.onFailed(v6(1), 100));
}

test "all fail terminates without winner" {
    const addrs = [_]Address{
        v6(1),
        v4(1),
        v6(2),
    };

    var he = try init(addrs[0..], .{
        .allocator = std.testing.allocator,
        .connection_attempt_delay_ms = 0,
    });
    defer he.deinit();

    try expectAddr(he.nextAttempt(0), v6(1));
    try expectAddr(he.nextAttempt(0), v4(1));
    try expectAddr(he.nextAttempt(0), v6(2));
    try std.testing.expect(!he.done());

    try std.testing.expect(he.onFailed(v4(1), 5));
    try std.testing.expect(he.onFailed(v6(1), 6));
    try std.testing.expect(!he.done());
    try std.testing.expect(he.onFailed(v6(2), 7));
    try std.testing.expect(he.done());
    try std.testing.expect(he.winner() == null);
    try std.testing.expect(he.nextAttempt(8) == null);
}

test "failing first family falls through to next family immediately" {
    const addrs = [_]Address{
        v6(1),
        v4(1),
    };

    var he = try init(addrs[0..], .{
        .allocator = std.testing.allocator,
        .connection_attempt_delay_ms = 250,
    });
    defer he.deinit();

    try expectAddr(he.nextAttempt(0), v6(1));
    try std.testing.expect(he.nextAttempt(20) == null);
    try std.testing.expect(he.onFailed(v6(1), 20));
    try expectAddr(he.nextAttempt(20), v4(1));
}

test "schedule is deterministic across identical inputs" {
    const addrs = [_]Address{
        v4(10),
        v6(10),
        v4(11),
        v6(11),
        v4(12),
    };

    var first = try init(addrs[0..], .{
        .allocator = std.testing.allocator,
        .connection_attempt_delay_ms = 0,
    });
    defer first.deinit();

    var second = try init(addrs[0..], .{
        .allocator = std.testing.allocator,
        .connection_attempt_delay_ms = 0,
    });
    defer second.deinit();

    while (true) {
        const a = first.nextAttempt(0);
        const b = second.nextAttempt(0);
        if (a == null or b == null) {
            try std.testing.expect(a == null and b == null);
            break;
        }
        try std.testing.expect(a.?.eql(b.?));
    }
}

test "empty address list is immediately done" {
    const addrs = [_]Address{};

    var he = try init(addrs[0..], .{
        .allocator = std.testing.allocator,
    });
    defer he.deinit();

    try std.testing.expect(he.done());
    try std.testing.expect(he.nextAttempt(0) == null);
    try std.testing.expect(he.winner() == null);
}

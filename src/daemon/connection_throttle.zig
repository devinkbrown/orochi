const std = @import("std");

pub const ConnectionThrottle = struct {
    pub const default_window_ms: i64 = 60000;
    pub const max_ips: usize = 65536;
    pub const max_ip_len: usize = 128;
    pub const max_events_per_ip: usize = 4096;

    pub const Error = error{
        EmptyIp,
        IpTooLong,
        InvalidWindow,
        TooManyIps,
        TooManyEvents,
    } || std.mem.Allocator.Error;

    allocator: std.mem.Allocator,
    window_ms: i64,
    ips: std.StringHashMap(IpState),

    pub fn init(allocator: std.mem.Allocator) ConnectionThrottle {
        return .{
            .allocator = allocator,
            .window_ms = default_window_ms,
            .ips = std.StringHashMap(IpState).init(allocator),
        };
    }

    pub fn initWithWindow(allocator: std.mem.Allocator, window_ms: i64) Error!ConnectionThrottle {
        if (window_ms <= 0) return error.InvalidWindow;
        return .{
            .allocator = allocator,
            .window_ms = window_ms,
            .ips = std.StringHashMap(IpState).init(allocator),
        };
    }

    pub fn deinit(self: *ConnectionThrottle) void {
        var it = self.ips.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.ips.deinit();
        self.* = undefined;
    }

    pub fn record(self: *ConnectionThrottle, ip: []const u8, now_ms: i64) Error!u32 {
        try validateIp(ip);

        if (self.ips.getPtr(ip)) |state| {
            state.prune(now_ms, self.window_ms);
            try state.append(self.allocator, now_ms);
            return @intCast(state.events.items.len);
        }

        try self.ensureRoom(now_ms);

        const owned_ip = try self.allocator.dupe(u8, ip);
        errdefer self.allocator.free(owned_ip);

        var state = IpState{};
        errdefer state.deinit(self.allocator);
        try state.append(self.allocator, now_ms);

        try self.ips.put(owned_ip, state);
        return 1;
    }

    pub fn tripped(self: *ConnectionThrottle, ip: []const u8, now_ms: i64, threshold: u32) bool {
        if (threshold == 0) return true;
        if (!validIp(ip)) return true;
        const state = self.ips.getPtr(ip) orelse return false;
        state.prune(now_ms, self.window_ms);
        return state.events.items.len >= threshold;
    }

    pub fn countOf(self: *ConnectionThrottle, ip: []const u8, now_ms: i64) u32 {
        if (!validIp(ip)) return 0;
        const state = self.ips.getPtr(ip) orelse return 0;
        state.prune(now_ms, self.window_ms);
        return @intCast(state.events.items.len);
    }

    pub fn prune(self: *ConnectionThrottle, now_ms: i64) void {
        while (self.removeOneEmpty(now_ms)) {}
    }

    pub fn trackedIps(self: *const ConnectionThrottle) usize {
        return self.ips.count();
    }

    fn ensureRoom(self: *ConnectionThrottle, now_ms: i64) Error!void {
        if (self.ips.count() < max_ips) return;
        self.prune(now_ms);
        if (self.ips.count() >= max_ips) return error.TooManyIps;
    }

    fn removeOneEmpty(self: *ConnectionThrottle, now_ms: i64) bool {
        var it = self.ips.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.prune(now_ms, self.window_ms);
            if (entry.value_ptr.events.items.len != 0) continue;

            const removed = self.ips.fetchRemove(entry.key_ptr.*).?;
            self.allocator.free(removed.key);
            var state = removed.value;
            state.deinit(self.allocator);
            return true;
        }
        return false;
    }

    fn validateIp(ip: []const u8) Error!void {
        if (ip.len == 0) return error.EmptyIp;
        if (ip.len > max_ip_len) return error.IpTooLong;
    }

    fn validIp(ip: []const u8) bool {
        return ip.len > 0 and ip.len <= max_ip_len;
    }
};

const IpState = struct {
    events: std.ArrayList(i64) = .empty,

    fn deinit(self: *IpState, allocator: std.mem.Allocator) void {
        self.events.deinit(allocator);
        self.* = undefined;
    }

    fn append(self: *IpState, allocator: std.mem.Allocator, now_ms: i64) ConnectionThrottle.Error!void {
        if (self.events.items.len >= ConnectionThrottle.max_events_per_ip) return error.TooManyEvents;
        try self.events.append(allocator, now_ms);
    }

    fn prune(self: *IpState, now_ms: i64, window_ms: i64) void {
        var write: usize = 0;
        for (self.events.items) |seen_ms| {
            if (insideWindow(seen_ms, now_ms, window_ms)) {
                self.events.items[write] = seen_ms;
                write += 1;
            }
        }
        self.events.shrinkRetainingCapacity(write);
    }
};

fn insideWindow(seen_ms: i64, now_ms: i64, window_ms: i64) bool {
    if (now_ms <= seen_ms) return true;
    return now_ms - seen_ms < window_ms;
}

test "record counts events inside the default window" {
    var throttle = ConnectionThrottle.init(std.testing.allocator);
    defer throttle.deinit();

    try std.testing.expectEqual(@as(u32, 1), try throttle.record("192.0.2.1", 0));
    try std.testing.expectEqual(@as(u32, 2), try throttle.record("192.0.2.1", 1000));
    try std.testing.expectEqual(@as(u32, 2), throttle.countOf("192.0.2.1", 1000));
}

test "old events are pruned from the sliding window" {
    var throttle = try ConnectionThrottle.initWithWindow(std.testing.allocator, 1000);
    defer throttle.deinit();

    try std.testing.expectEqual(@as(u32, 1), try throttle.record("198.51.100.2", 0));
    try std.testing.expectEqual(@as(u32, 2), try throttle.record("198.51.100.2", 500));
    try std.testing.expectEqual(@as(u32, 2), throttle.countOf("198.51.100.2", 999));
    try std.testing.expectEqual(@as(u32, 1), throttle.countOf("198.51.100.2", 1000));
}

test "tripped compares the pruned count to threshold" {
    var throttle = try ConnectionThrottle.initWithWindow(std.testing.allocator, 1000);
    defer throttle.deinit();

    _ = try throttle.record("203.0.113.4", 0);
    _ = try throttle.record("203.0.113.4", 100);
    _ = try throttle.record("203.0.113.4", 200);
    try std.testing.expect(throttle.tripped("203.0.113.4", 200, 3));
    try std.testing.expect(!throttle.tripped("203.0.113.4", 1000, 3));
}

test "prune removes empty ip states" {
    var throttle = try ConnectionThrottle.initWithWindow(std.testing.allocator, 10);
    defer throttle.deinit();

    _ = try throttle.record("2001:db8::1", 0);
    try std.testing.expectEqual(@as(usize, 1), throttle.trackedIps());
    throttle.prune(10);
    try std.testing.expectEqual(@as(usize, 0), throttle.trackedIps());
}

//! Deterministic per-IP connection clone and reconnect throttle detection.
//!
//! Callers provide a stable IP string and monotonic-ish time in milliseconds.
//! This module reads no clock and performs no I/O. State is bounded by
//! `max_tracked_ips`, `max_ip_len`, and `max_connects_per_window`.
const std = @import("std");

pub const Decision = enum {
    allow,
    clone_limited,
    connect_throttled,
};

pub const Params = struct {
    max_concurrent_per_ip: usize,
    max_connects_per_window: usize,
    window_ms: u64,
    max_tracked_ips: usize = 4096,
    max_ip_len: usize = 128,
};

pub const CloneDetectError = error{
    EmptyIp,
    IpTooLong,
    TooManyTrackedIps,
    InvalidParams,
} || std.mem.Allocator.Error;

pub const CloneDetector = struct {
    allocator: std.mem.Allocator,
    params: Params,
    ips: std.StringHashMap(IpState),

    pub fn init(allocator: std.mem.Allocator, params: Params) CloneDetector {
        std.debug.assert(validParams(params));
        return .{
            .allocator = allocator,
            .params = params,
            .ips = std.StringHashMap(IpState).init(allocator),
        };
    }

    pub fn initChecked(allocator: std.mem.Allocator, params: Params) CloneDetectError!CloneDetector {
        if (!validParams(params)) return error.InvalidParams;
        return init(allocator, params);
    }

    pub fn deinit(self: *CloneDetector) void {
        var it = self.ips.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.ips.deinit();
        self.* = undefined;
    }

    /// Classify and, when allowed, record a new active connection for `ip`.
    pub fn classifyConnect(self: *CloneDetector, now_ms: i64, ip: []const u8) CloneDetectError!Decision {
        try self.validateIp(ip);

        if (self.ips.getPtr(ip)) |state| {
            state.prune(now_ms, self.params.window_ms);
            return self.classifyExisting(now_ms, state);
        }

        try self.ensureRoomForNewIp(now_ms);

        const owned_ip = try self.allocator.dupe(u8, ip);
        errdefer self.allocator.free(owned_ip);

        var state: IpState = .{};
        errdefer state.deinit(self.allocator);

        const decision = try self.classifyExisting(now_ms, &state);
        if (decision == .allow) {
            try self.ips.put(owned_ip, state);
        }
        return decision;
    }

    /// Release one active connection for `ip`. Returns false when none exists.
    pub fn disconnect(self: *CloneDetector, ip: []const u8) bool {
        const state = self.ips.getPtr(ip) orelse return false;
        if (state.active == 0) return false;
        state.active -= 1;
        return true;
    }

    pub fn prune(self: *CloneDetector, now_ms: i64) void {
        while (self.removeOneExpiredEmptyIp(now_ms)) {}
    }

    pub fn activeCount(self: *const CloneDetector, ip: []const u8) usize {
        const state = self.ips.getPtr(ip) orelse return 0;
        return state.active;
    }

    pub fn recentCount(self: *const CloneDetector, ip: []const u8) usize {
        const state = self.ips.getPtr(ip) orelse return 0;
        return state.recent.items.len;
    }

    pub fn trackedIps(self: *const CloneDetector) usize {
        return self.ips.count();
    }

    fn classifyExisting(self: *CloneDetector, now_ms: i64, state: *IpState) CloneDetectError!Decision {
        if (state.active >= self.params.max_concurrent_per_ip) {
            return .clone_limited;
        }
        if (state.recent.items.len >= self.params.max_connects_per_window) {
            return .connect_throttled;
        }

        try state.recent.append(self.allocator, now_ms);
        state.active += 1;
        return .allow;
    }

    fn ensureRoomForNewIp(self: *CloneDetector, now_ms: i64) CloneDetectError!void {
        if (self.ips.count() < self.params.max_tracked_ips) return;
        self.prune(now_ms);
        if (self.ips.count() >= self.params.max_tracked_ips) return error.TooManyTrackedIps;
    }

    fn removeOneExpiredEmptyIp(self: *CloneDetector, now_ms: i64) bool {
        var it = self.ips.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.prune(now_ms, self.params.window_ms);
            if (!entry.value_ptr.empty()) continue;

            const key = entry.key_ptr.*;
            const removed = self.ips.fetchRemove(key).?;
            self.allocator.free(removed.key);
            var state = removed.value;
            state.deinit(self.allocator);
            return true;
        }
        return false;
    }

    fn validateIp(self: *const CloneDetector, ip: []const u8) CloneDetectError!void {
        if (ip.len == 0) return error.EmptyIp;
        if (ip.len > self.params.max_ip_len) return error.IpTooLong;
    }
};

const IpState = struct {
    active: usize = 0,
    recent: std.ArrayList(i64) = .empty,

    fn deinit(self: *IpState, allocator: std.mem.Allocator) void {
        self.recent.deinit(allocator);
        self.* = undefined;
    }

    fn prune(self: *IpState, now_ms: i64, window_ms: u64) void {
        var write: usize = 0;
        for (self.recent.items) |connected_at| {
            if (insideWindow(connected_at, now_ms, window_ms)) {
                self.recent.items[write] = connected_at;
                write += 1;
            }
        }
        self.recent.shrinkRetainingCapacity(write);
    }

    fn empty(self: *const IpState) bool {
        return self.active == 0 and self.recent.items.len == 0;
    }
};

fn validParams(params: Params) bool {
    return params.max_concurrent_per_ip > 0 and
        params.max_connects_per_window > 0 and
        params.window_ms > 0 and
        params.max_tracked_ips > 0 and
        params.max_ip_len > 0;
}

fn insideWindow(connected_at: i64, now_ms: i64, window_ms: u64) bool {
    const delta = @as(i128, now_ms) - @as(i128, connected_at);
    if (delta < 0) return true;
    return @as(u128, @intCast(delta)) < @as(u128, window_ms);
}

test "clone limit triggers at N concurrent" {
    var detector = CloneDetector.init(std.testing.allocator, .{
        .max_concurrent_per_ip = 2,
        .max_connects_per_window = 8,
        .window_ms = 1000,
    });
    defer detector.deinit();

    try std.testing.expectEqual(Decision.allow, try detector.classifyConnect(0, "192.0.2.10"));
    try std.testing.expectEqual(Decision.allow, try detector.classifyConnect(1, "192.0.2.10"));
    try std.testing.expectEqual(Decision.clone_limited, try detector.classifyConnect(2, "192.0.2.10"));
    try std.testing.expectEqual(@as(usize, 2), detector.activeCount("192.0.2.10"));
}

test "throttle triggers on rapid reconnects" {
    var detector = CloneDetector.init(std.testing.allocator, .{
        .max_concurrent_per_ip = 1,
        .max_connects_per_window = 2,
        .window_ms = 1000,
    });
    defer detector.deinit();

    try std.testing.expectEqual(Decision.allow, try detector.classifyConnect(0, "198.51.100.7"));
    try std.testing.expect(detector.disconnect("198.51.100.7"));
    try std.testing.expectEqual(Decision.allow, try detector.classifyConnect(10, "198.51.100.7"));
    try std.testing.expect(detector.disconnect("198.51.100.7"));
    try std.testing.expectEqual(Decision.connect_throttled, try detector.classifyConnect(20, "198.51.100.7"));
    try std.testing.expectEqual(Decision.allow, try detector.classifyConnect(1000, "198.51.100.7"));
}

test "releases on disconnect" {
    var detector = CloneDetector.init(std.testing.allocator, .{
        .max_concurrent_per_ip = 1,
        .max_connects_per_window = 4,
        .window_ms = 1000,
    });
    defer detector.deinit();

    try std.testing.expectEqual(Decision.allow, try detector.classifyConnect(0, "203.0.113.4"));
    try std.testing.expectEqual(Decision.clone_limited, try detector.classifyConnect(1, "203.0.113.4"));
    try std.testing.expect(detector.disconnect("203.0.113.4"));
    try std.testing.expectEqual(Decision.allow, try detector.classifyConnect(2, "203.0.113.4"));
    try std.testing.expectEqual(@as(usize, 1), detector.activeCount("203.0.113.4"));
}

test "state is bounded and prunes empty expired IPs" {
    var detector = CloneDetector.init(std.testing.allocator, .{
        .max_concurrent_per_ip = 2,
        .max_connects_per_window = 2,
        .window_ms = 100,
        .max_tracked_ips = 2,
    });
    defer detector.deinit();

    try std.testing.expectEqual(Decision.allow, try detector.classifyConnect(0, "10.0.0.1"));
    try std.testing.expectEqual(Decision.allow, try detector.classifyConnect(0, "10.0.0.2"));
    try std.testing.expectError(error.TooManyTrackedIps, detector.classifyConnect(1, "10.0.0.3"));

    try std.testing.expect(detector.disconnect("10.0.0.1"));
    detector.prune(100);
    try std.testing.expectEqual(@as(usize, 1), detector.trackedIps());
    try std.testing.expectEqual(Decision.allow, try detector.classifyConnect(100, "10.0.0.3"));
    try std.testing.expect(detector.trackedIps() <= 2);
}

test "no leak across denied connects and deinit" {
    var detector = try CloneDetector.initChecked(std.testing.allocator, .{
        .max_concurrent_per_ip = 1,
        .max_connects_per_window = 1,
        .window_ms = 50,
        .max_tracked_ips = 4,
        .max_ip_len = 16,
    });
    defer detector.deinit();

    try std.testing.expectError(error.EmptyIp, detector.classifyConnect(0, ""));
    try std.testing.expectError(error.IpTooLong, detector.classifyConnect(0, "12345678901234567"));

    try std.testing.expectEqual(Decision.allow, try detector.classifyConnect(0, "192.0.2.1"));
    try std.testing.expectEqual(Decision.clone_limited, try detector.classifyConnect(1, "192.0.2.1"));
    try std.testing.expect(detector.disconnect("192.0.2.1"));
    try std.testing.expectEqual(Decision.connect_throttled, try detector.classifyConnect(2, "192.0.2.1"));

    detector.prune(50);
    try std.testing.expectEqual(@as(usize, 0), detector.trackedIps());
}

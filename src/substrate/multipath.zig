// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

const std = @import("std");

pub const PathId = u64;

pub const Mode = enum {
    min_rtt,
    round_robin,
    redundant,
};

pub const Path = struct {
    id: PathId,
    rtt_us: u64,
    cwnd: u64,
    inflight: u64,
    loss: f64,

    pub fn availableBudget(self: Path) u64 {
        if (self.cwnd <= self.inflight) return 0;
        return self.cwnd - self.inflight;
    }

    pub fn canSend(self: Path, packet_bytes: u64) bool {
        return packet_bytes > 0 and self.availableBudget() >= packet_bytes;
    }
};

pub const PathUpdate = struct {
    rtt_us: ?u64 = null,
    cwnd: ?u64 = null,
    inflight: ?u64 = null,
    loss: ?f64 = null,
};

pub const Error = error{
    DuplicatePath,
    ZeroPacket,
};

pub const Scheduler = struct {
    mode: Mode,
    paths: std.ArrayList(Path) = .empty,
    rr_cursor: usize = 0,

    const Self = @This();

    pub fn init(mode: Mode) Self {
        return .{ .mode = mode };
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        self.paths.deinit(allocator);
        self.* = undefined;
    }

    pub fn setMode(self: *Self, mode: Mode) void {
        self.mode = mode;
    }

    pub fn pathCount(self: *const Self) usize {
        return self.paths.items.len;
    }

    pub fn addPath(self: *Self, allocator: std.mem.Allocator, new_path: Path) !void {
        if (self.findIndex(new_path.id) != null) return Error.DuplicatePath;
        try self.paths.append(allocator, new_path);
    }

    pub fn removePath(self: *Self, id: PathId) bool {
        const index = self.findIndex(id) orelse return false;
        _ = self.paths.orderedRemove(index);

        if (self.paths.items.len == 0) {
            self.rr_cursor = 0;
        } else {
            if (self.rr_cursor > index) self.rr_cursor -= 1;
            self.rr_cursor %= self.paths.items.len;
        }

        return true;
    }

    pub fn updatePath(self: *Self, id: PathId, update: PathUpdate) bool {
        const index = self.findIndex(id) orelse return false;
        var entry = &self.paths.items[index];

        if (update.rtt_us) |value| entry.rtt_us = value;
        if (update.cwnd) |value| entry.cwnd = value;
        if (update.inflight) |value| entry.inflight = value;
        if (update.loss) |value| entry.loss = value;

        return true;
    }

    pub fn getPath(self: *const Self, id: PathId) ?Path {
        const index = self.findIndex(id) orelse return null;
        return self.paths.items[index];
    }

    pub fn aggregateAvailableBudget(self: *const Self) u64 {
        var total: u64 = 0;
        for (self.paths.items) |entry| {
            total = saturatingAdd(total, entry.availableBudget());
        }
        return total;
    }

    /// Select path ids for one packet and reserve `packet_bytes` as inflight.
    /// Redundant mode returns every path with enough available cwnd.
    pub fn schedule(
        self: *Self,
        allocator: std.mem.Allocator,
        packet_bytes: u64,
    ) ![]PathId {
        if (packet_bytes == 0) return Error.ZeroPacket;

        return switch (self.mode) {
            .min_rtt => self.scheduleMinRtt(allocator, packet_bytes),
            .round_robin => self.scheduleRoundRobin(allocator, packet_bytes),
            .redundant => self.scheduleRedundant(allocator, packet_bytes),
        };
    }

    fn scheduleMinRtt(
        self: *Self,
        allocator: std.mem.Allocator,
        packet_bytes: u64,
    ) ![]PathId {
        var selected: std.ArrayList(PathId) = .empty;
        errdefer selected.deinit(allocator);

        if (self.bestMinRttIndex(packet_bytes)) |index| {
            try selected.append(allocator, self.paths.items[index].id);
            self.paths.items[index].inflight += packet_bytes;
        }

        return selected.toOwnedSlice(allocator);
    }

    fn scheduleRoundRobin(
        self: *Self,
        allocator: std.mem.Allocator,
        packet_bytes: u64,
    ) ![]PathId {
        var selected: std.ArrayList(PathId) = .empty;
        errdefer selected.deinit(allocator);

        const len = self.paths.items.len;
        if (len == 0) return selected.toOwnedSlice(allocator);

        const start = self.rr_cursor % len;
        var offset: usize = 0;
        while (offset < len) : (offset += 1) {
            const index = (start + offset) % len;
            if (!self.paths.items[index].canSend(packet_bytes)) continue;

            try selected.append(allocator, self.paths.items[index].id);
            self.paths.items[index].inflight += packet_bytes;
            self.rr_cursor = (index + 1) % len;
            break;
        }

        return selected.toOwnedSlice(allocator);
    }

    fn scheduleRedundant(
        self: *Self,
        allocator: std.mem.Allocator,
        packet_bytes: u64,
    ) ![]PathId {
        var selected: std.ArrayList(PathId) = .empty;
        errdefer selected.deinit(allocator);
        try selected.ensureTotalCapacity(allocator, self.paths.items.len);

        for (self.paths.items) |entry| {
            if (entry.canSend(packet_bytes)) selected.appendAssumeCapacity(entry.id);
        }

        for (selected.items) |id| {
            const index = self.findIndex(id).?;
            self.paths.items[index].inflight += packet_bytes;
        }

        return selected.toOwnedSlice(allocator);
    }

    fn bestMinRttIndex(self: *const Self, packet_bytes: u64) ?usize {
        var best_index: ?usize = null;

        for (self.paths.items, 0..) |entry, index| {
            if (!entry.canSend(packet_bytes)) continue;

            if (best_index) |current| {
                const best = self.paths.items[current];
                if (entry.rtt_us < best.rtt_us) best_index = index;
            } else {
                best_index = index;
            }
        }

        return best_index;
    }

    fn findIndex(self: *const Self, id: PathId) ?usize {
        for (self.paths.items, 0..) |entry, index| {
            if (entry.id == id) return index;
        }

        return null;
    }
};

pub fn makePath(id: PathId, rtt_us: u64, cwnd: u64, inflight: u64, loss: f64) Path {
    return .{
        .id = id,
        .rtt_us = rtt_us,
        .cwnd = cwnd,
        .inflight = inflight,
        .loss = loss,
    };
}

fn saturatingAdd(a: u64, b: u64) u64 {
    const max = std.math.maxInt(u64);
    if (max - a < b) return max;
    return a + b;
}

fn expectIds(actual: []const PathId, expected: []const PathId) !void {
    try std.testing.expectEqual(expected.len, actual.len);
    for (expected, 0..) |id, index| {
        try std.testing.expectEqual(id, actual[index]);
    }
}

test "min-RTT picks fastest path with room then spills to next" {
    const allocator = std.testing.allocator;
    var scheduler = Scheduler.init(.min_rtt);
    defer scheduler.deinit(allocator);

    try scheduler.addPath(allocator, makePath(1, 50_000, 1_000, 0, 0.0));
    try scheduler.addPath(allocator, makePath(2, 10_000, 1_000, 0, 0.0));
    try scheduler.addPath(allocator, makePath(3, 25_000, 1_000, 0, 0.0));

    const first = try scheduler.schedule(allocator, 600);
    defer allocator.free(first);
    try expectIds(first, &.{2});

    const second = try scheduler.schedule(allocator, 600);
    defer allocator.free(second);
    try expectIds(second, &.{3});

    const third = try scheduler.schedule(allocator, 600);
    defer allocator.free(third);
    try expectIds(third, &.{1});

    try std.testing.expectEqual(@as(u64, 600), scheduler.getPath(1).?.inflight);
    try std.testing.expectEqual(@as(u64, 600), scheduler.getPath(2).?.inflight);
    try std.testing.expectEqual(@as(u64, 600), scheduler.getPath(3).?.inflight);
}

test "round-robin rotates over available paths" {
    const allocator = std.testing.allocator;
    var scheduler = Scheduler.init(.round_robin);
    defer scheduler.deinit(allocator);

    try scheduler.addPath(allocator, makePath(10, 40_000, 1_000, 0, 0.0));
    try scheduler.addPath(allocator, makePath(20, 10_000, 1_000, 0, 0.0));
    try scheduler.addPath(allocator, makePath(30, 20_000, 1_000, 0, 0.0));

    const first = try scheduler.schedule(allocator, 100);
    defer allocator.free(first);
    try expectIds(first, &.{10});

    const second = try scheduler.schedule(allocator, 100);
    defer allocator.free(second);
    try expectIds(second, &.{20});

    const third = try scheduler.schedule(allocator, 100);
    defer allocator.free(third);
    try expectIds(third, &.{30});

    const fourth = try scheduler.schedule(allocator, 100);
    defer allocator.free(fourth);
    try expectIds(fourth, &.{10});
}

test "path with no cwnd is skipped" {
    const allocator = std.testing.allocator;
    var scheduler = Scheduler.init(.round_robin);
    defer scheduler.deinit(allocator);

    try scheduler.addPath(allocator, makePath(1, 10_000, 500, 500, 0.0));
    try scheduler.addPath(allocator, makePath(2, 20_000, 500, 0, 0.0));

    const first = try scheduler.schedule(allocator, 100);
    defer allocator.free(first);
    try expectIds(first, &.{2});

    try std.testing.expectEqual(@as(u64, 500), scheduler.getPath(1).?.inflight);
    try std.testing.expectEqual(@as(u64, 100), scheduler.getPath(2).?.inflight);
}

test "redundant mode duplicates to all paths with room" {
    const allocator = std.testing.allocator;
    var scheduler = Scheduler.init(.redundant);
    defer scheduler.deinit(allocator);

    try scheduler.addPath(allocator, makePath(1, 30_000, 1_000, 0, 0.0));
    try scheduler.addPath(allocator, makePath(2, 20_000, 1_000, 0, 0.0));
    try scheduler.addPath(allocator, makePath(3, 10_000, 1_000, 0, 0.0));

    const selected = try scheduler.schedule(allocator, 200);
    defer allocator.free(selected);
    try expectIds(selected, &.{ 1, 2, 3 });

    try std.testing.expectEqual(@as(u64, 200), scheduler.getPath(1).?.inflight);
    try std.testing.expectEqual(@as(u64, 200), scheduler.getPath(2).?.inflight);
    try std.testing.expectEqual(@as(u64, 200), scheduler.getPath(3).?.inflight);
}

test "aggregate budget reflects add update schedule and remove" {
    const allocator = std.testing.allocator;
    var scheduler = Scheduler.init(.min_rtt);
    defer scheduler.deinit(allocator);

    try scheduler.addPath(allocator, makePath(1, 10_000, 1_000, 100, 0.0));
    try scheduler.addPath(allocator, makePath(2, 20_000, 500, 600, 0.0));

    try std.testing.expectEqual(@as(u64, 900), scheduler.aggregateAvailableBudget());

    try std.testing.expect(scheduler.updatePath(2, .{ .cwnd = 1_000, .inflight = 200 }));
    try std.testing.expectEqual(@as(u64, 1_700), scheduler.aggregateAvailableBudget());

    const selected = try scheduler.schedule(allocator, 250);
    defer allocator.free(selected);
    try expectIds(selected, &.{1});
    try std.testing.expectEqual(@as(u64, 1_450), scheduler.aggregateAvailableBudget());

    try std.testing.expect(scheduler.removePath(1));
    try std.testing.expectEqual(@as(usize, 1), scheduler.pathCount());
    try std.testing.expectEqual(@as(u64, 800), scheduler.aggregateAvailableBudget());
}

test "duplicate add fails and missing path mutations are deterministic no-ops" {
    const allocator = std.testing.allocator;
    var scheduler = Scheduler.init(.min_rtt);
    defer scheduler.deinit(allocator);

    try scheduler.addPath(allocator, makePath(9, 10_000, 1_000, 0, 0.0));
    try std.testing.expectError(Error.DuplicatePath, scheduler.addPath(allocator, makePath(9, 1, 1, 0, 0.0)));

    try std.testing.expect(!scheduler.updatePath(42, .{ .rtt_us = 1 }));
    try std.testing.expect(!scheduler.removePath(42));
    try std.testing.expectEqual(@as(usize, 1), scheduler.pathCount());
    try std.testing.expectEqual(@as(u64, 1_000), scheduler.aggregateAvailableBudget());
}

test "min-RTT tie keeps insertion order and zero packet is rejected" {
    const allocator = std.testing.allocator;
    var scheduler = Scheduler.init(.min_rtt);
    defer scheduler.deinit(allocator);

    try scheduler.addPath(allocator, makePath(7, 10_000, 1_000, 0, 0.0));
    try scheduler.addPath(allocator, makePath(8, 10_000, 1_000, 0, 0.0));

    const selected = try scheduler.schedule(allocator, 100);
    defer allocator.free(selected);
    try expectIds(selected, &.{7});

    try std.testing.expectError(Error.ZeroPacket, scheduler.schedule(allocator, 0));
}

test "round-robin skips exhausted paths without moving cursor on no selection" {
    const allocator = std.testing.allocator;
    var scheduler = Scheduler.init(.round_robin);
    defer scheduler.deinit(allocator);

    try scheduler.addPath(allocator, makePath(1, 10_000, 100, 0, 0.0));
    try scheduler.addPath(allocator, makePath(2, 10_000, 100, 100, 0.0));

    const first = try scheduler.schedule(allocator, 100);
    defer allocator.free(first);
    try expectIds(first, &.{1});

    const none = try scheduler.schedule(allocator, 1);
    defer allocator.free(none);
    try expectIds(none, &.{});

    try std.testing.expect(scheduler.updatePath(2, .{ .inflight = 0 }));
    const second = try scheduler.schedule(allocator, 1);
    defer allocator.free(second);
    try expectIds(second, &.{2});
}

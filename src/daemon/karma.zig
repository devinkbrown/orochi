//! Per-account karma with per-giver direction deduplication.
const std = @import("std");

const GiverSet = std.StringHashMap(void);

const Target = struct {
    score: i64 = 0,
    up_givers: GiverSet,
    down_givers: GiverSet,

    fn init(allocator: std.mem.Allocator) Target {
        return .{
            .up_givers = GiverSet.init(allocator),
            .down_givers = GiverSet.init(allocator),
        };
    }

    fn deinit(self: *Target, allocator: std.mem.Allocator) void {
        freeKeys(&self.up_givers, allocator);
        freeKeys(&self.down_givers, allocator);
        self.up_givers.deinit();
        self.down_givers.deinit();
        self.* = undefined;
    }
};

pub const Karma = struct {
    allocator: std.mem.Allocator,
    targets: std.StringHashMap(Target),

    pub const Error = std.mem.Allocator.Error || error{Overflow};

    pub fn init(allocator: std.mem.Allocator) Karma {
        return .{
            .allocator = allocator,
            .targets = std.StringHashMap(Target).init(allocator),
        };
    }

    pub fn deinit(self: *Karma) void {
        var it = self.targets.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.targets.deinit();
        self.* = undefined;
    }

    /// Applies one vote per giver per direction and returns the target score.
    pub fn give(self: *Karma, target: []const u8, giver: []const u8, up: bool) Error!i64 {
        const entry = try self.ensureTarget(target);
        const set = if (up) &entry.value_ptr.up_givers else &entry.value_ptr.down_givers;
        if (set.contains(giver)) return entry.value_ptr.score;

        const next = if (up)
            std.math.add(i64, entry.value_ptr.score, 1) catch return error.Overflow
        else
            std.math.sub(i64, entry.value_ptr.score, 1) catch return error.Overflow;

        const owned_giver = try self.allocator.dupe(u8, giver);
        errdefer self.allocator.free(owned_giver);
        try set.putNoClobber(owned_giver, {});
        entry.value_ptr.score = next;
        return next;
    }

    pub fn score(self: *const Karma, target: []const u8) i64 {
        const current = self.targets.get(target) orelse return 0;
        return current.score;
    }

    fn ensureTarget(self: *Karma, target: []const u8) std.mem.Allocator.Error!std.StringHashMap(Target).Entry {
        if (self.targets.getEntry(target)) |entry| return entry;

        const owned = try self.allocator.dupe(u8, target);
        errdefer self.allocator.free(owned);

        var value = Target.init(self.allocator);
        errdefer value.deinit(self.allocator);
        try self.targets.putNoClobber(owned, value);
        return self.targets.getEntry(target).?;
    }
};

fn freeKeys(map: *GiverSet, allocator: std.mem.Allocator) void {
    var it = map.iterator();
    while (it.next()) |entry| {
        allocator.free(entry.key_ptr.*);
    }
}

const testing = std.testing;

test "up votes increase score once per giver" {
    var karma = Karma.init(testing.allocator);
    defer karma.deinit();

    try testing.expectEqual(@as(i64, 1), try karma.give("alice", "bob", true));
    try testing.expectEqual(@as(i64, 1), try karma.give("alice", "bob", true));
    try testing.expectEqual(@as(i64, 1), karma.score("alice"));
}

test "down votes decrease score once per giver" {
    var karma = Karma.init(testing.allocator);
    defer karma.deinit();

    try testing.expectEqual(@as(i64, -1), try karma.give("alice", "bob", false));
    try testing.expectEqual(@as(i64, -1), try karma.give("alice", "bob", false));
    try testing.expectEqual(@as(i64, -1), karma.score("alice"));
}

test "deduplication is per target and direction" {
    var karma = Karma.init(testing.allocator);
    defer karma.deinit();

    _ = try karma.give("alice", "bob", true);
    _ = try karma.give("alice", "bob", false);
    _ = try karma.give("carol", "bob", true);
    try testing.expectEqual(@as(i64, 0), karma.score("alice"));
    try testing.expectEqual(@as(i64, 1), karma.score("carol"));
}

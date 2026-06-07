//! Clean-room channel operator restoration scoring for Mizuchi.
//!
//! The daemon feeds observations when trusted channel state shows an identity
//! holding operator status. This module keeps a bounded, time-decayed model per
//! channel and returns the strongest restoration candidates when a registered
//! channel has too few operators.

const std = @import("std");

pub const Error = std.mem.Allocator.Error || error{
    EmptyChannel,
    EmptyIdentity,
};

pub const Config = struct {
    half_life_ms: i64 = 7 * 24 * 60 * 60 * 1000,
    max_identities_per_channel: usize = 64,
    min_ops: usize = 1,

    fn normalized(self: Config) Config {
        return .{
            .half_life_ms = @max(self.half_life_ms, 1),
            .max_identities_per_channel = @max(self.max_identities_per_channel, 1),
            .min_ops = self.min_ops,
        };
    }
};

pub const Candidate = struct {
    identity: []const u8,
    score: f64,
};

const Score = struct {
    value: f64,
    updated_ms: i64,
};

const Channel = struct {
    registered: bool = false,
    scores: std.StringHashMapUnmanaged(Score) = .empty,

    fn deinit(self: *Channel, allocator: std.mem.Allocator) void {
        var it = self.scores.iterator();
        while (it.next()) |entry| allocator.free(entry.key_ptr.*);
        self.scores.deinit(allocator);
        self.* = undefined;
    }
};

pub const ChanFix = struct {
    config: Config,
    channels: std.StringHashMapUnmanaged(Channel) = .empty,

    pub fn init(config: Config) ChanFix {
        return .{ .config = config.normalized() };
    }

    pub fn deinit(self: *ChanFix, allocator: std.mem.Allocator) void {
        var it = self.channels.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(allocator);
        }
        self.channels.deinit(allocator);
        self.* = undefined;
    }

    pub fn setRegistered(
        self: *ChanFix,
        allocator: std.mem.Allocator,
        channel_name: []const u8,
        registered: bool,
    ) Error!void {
        if (channel_name.len == 0) return error.EmptyChannel;
        const channel = try self.channelFor(allocator, channel_name);
        channel.registered = registered;
    }

    pub fn recordOpSeen(
        self: *ChanFix,
        allocator: std.mem.Allocator,
        channel_name: []const u8,
        identity: []const u8,
        now_ms: i64,
    ) Error!void {
        if (channel_name.len == 0) return error.EmptyChannel;
        if (identity.len == 0) return error.EmptyIdentity;

        const channel = try self.channelFor(allocator, channel_name);
        if (channel.scores.getPtr(identity)) |score| {
            decayOne(score, now_ms, self.config.half_life_ms);
            score.value += 1.0;
            return;
        }

        if (channel.scores.count() >= self.config.max_identities_per_channel) {
            decayChannel(channel, now_ms, self.config.half_life_ms);
            evictLowest(channel, allocator);
        }

        const owned_identity = try allocator.dupe(u8, identity);
        errdefer allocator.free(owned_identity);
        try channel.scores.put(allocator, owned_identity, .{
            .value = 1.0,
            .updated_ms = now_ms,
        });
    }

    pub fn topCandidates(
        self: *ChanFix,
        allocator: std.mem.Allocator,
        channel_name: []const u8,
        n: usize,
        now_ms: i64,
    ) Error![]Candidate {
        if (channel_name.len == 0) return error.EmptyChannel;
        const channel = self.channels.getPtr(channel_name) orelse
            return allocator.alloc(Candidate, 0);

        decayChannel(channel, now_ms, self.config.half_life_ms);

        var all: std.ArrayListUnmanaged(Candidate) = .empty;
        defer all.deinit(allocator);

        var it = channel.scores.iterator();
        while (it.next()) |entry| {
            try all.append(allocator, .{
                .identity = entry.key_ptr.*,
                .score = entry.value_ptr.value,
            });
        }

        std.mem.sort(Candidate, all.items, {}, candidateBefore);

        const take = @min(n, all.items.len);
        const out = try allocator.alloc(Candidate, take);
        @memcpy(out, all.items[0..take]);
        return out;
    }

    pub fn shouldFix(
        self: *const ChanFix,
        channel_name: []const u8,
        current_op_count: usize,
    ) bool {
        const channel = self.channels.getPtr(channel_name) orelse return false;
        return channel.registered and current_op_count < self.config.min_ops;
    }

    pub fn scoreOf(
        self: *ChanFix,
        channel_name: []const u8,
        identity: []const u8,
        now_ms: i64,
    ) f64 {
        const channel = self.channels.getPtr(channel_name) orelse return 0.0;
        const score = channel.scores.getPtr(identity) orelse return 0.0;
        decayOne(score, now_ms, self.config.half_life_ms);
        return score.value;
    }

    pub fn identityCount(self: *const ChanFix, channel_name: []const u8) usize {
        const channel = self.channels.getPtr(channel_name) orelse return 0;
        return channel.scores.count();
    }

    fn channelFor(
        self: *ChanFix,
        allocator: std.mem.Allocator,
        channel_name: []const u8,
    ) std.mem.Allocator.Error!*Channel {
        if (self.channels.getPtr(channel_name)) |channel| return channel;

        const owned_name = try allocator.dupe(u8, channel_name);
        errdefer allocator.free(owned_name);
        try self.channels.put(allocator, owned_name, .{});
        return self.channels.getPtr(owned_name).?;
    }
};

fn decayChannel(channel: *Channel, now_ms: i64, half_life_ms: i64) void {
    var it = channel.scores.iterator();
    while (it.next()) |entry| decayOne(entry.value_ptr, now_ms, half_life_ms);
}

fn decayOne(score: *Score, now_ms: i64, half_life_ms: i64) void {
    if (now_ms <= score.updated_ms) return;
    const age_ms = now_ms - score.updated_ms;
    const age = @as(f64, @floatFromInt(age_ms));
    const half_life = @as(f64, @floatFromInt(half_life_ms));
    score.value *= std.math.pow(f64, 0.5, age / half_life);
    score.updated_ms = now_ms;
}

fn evictLowest(channel: *Channel, allocator: std.mem.Allocator) void {
    var lowest: ?[]const u8 = null;
    var lowest_score: f64 = 0.0;

    var it = channel.scores.iterator();
    while (it.next()) |entry| {
        const identity = entry.key_ptr.*;
        const value = entry.value_ptr.value;
        if (lowest == null or lowerThan(value, identity, lowest_score, lowest.?)) {
            lowest = identity;
            lowest_score = value;
        }
    }

    if (lowest) |identity| {
        if (channel.scores.fetchRemove(identity)) |removed| {
            allocator.free(removed.key);
        }
    }
}

fn lowerThan(score: f64, identity: []const u8, best_score: f64, best_identity: []const u8) bool {
    if (score != best_score) return score < best_score;
    return std.mem.lessThan(u8, best_identity, identity);
}

fn candidateBefore(_: void, lhs: Candidate, rhs: Candidate) bool {
    if (lhs.score != rhs.score) return lhs.score > rhs.score;
    return std.mem.lessThan(u8, lhs.identity, rhs.identity);
}

const testing = std.testing;

test "more op-time produces a higher score" {
    var model = ChanFix.init(.{});
    defer model.deinit(testing.allocator);

    try model.recordOpSeen(testing.allocator, "#build", "alice@home", 1_000);
    try model.recordOpSeen(testing.allocator, "#build", "alice@home", 2_000);
    try model.recordOpSeen(testing.allocator, "#build", "bob@host", 2_000);

    const alice = model.scoreOf("#build", "alice@home", 2_000);
    const bob = model.scoreOf("#build", "bob@host", 2_000);
    try testing.expect(alice > bob);
}

test "decay lowers stale scores" {
    var model = ChanFix.init(.{ .half_life_ms = 1_000 });
    defer model.deinit(testing.allocator);

    try model.recordOpSeen(testing.allocator, "#ops", "carol", 0);
    const fresh = model.scoreOf("#ops", "carol", 0);
    const stale = model.scoreOf("#ops", "carol", 1_000);

    try testing.expect(stale < fresh);
    try testing.expectApproxEqAbs(@as(f64, 0.5), stale, 0.000_001);
}

test "topCandidates returns highest scores in deterministic order" {
    var model = ChanFix.init(.{ .half_life_ms = 10_000 });
    defer model.deinit(testing.allocator);

    try model.recordOpSeen(testing.allocator, "#team", "bravo", 0);
    try model.recordOpSeen(testing.allocator, "#team", "alpha", 0);
    try model.recordOpSeen(testing.allocator, "#team", "delta", 0);
    try model.recordOpSeen(testing.allocator, "#team", "delta", 100);

    const top = try model.topCandidates(testing.allocator, "#team", 3, 100);
    defer testing.allocator.free(top);

    try testing.expectEqual(@as(usize, 3), top.len);
    try testing.expectEqualStrings("delta", top[0].identity);
    try testing.expectEqualStrings("alpha", top[1].identity);
    try testing.expectEqualStrings("bravo", top[2].identity);
}

test "shouldFix requires registration and too few current operators" {
    var model = ChanFix.init(.{ .min_ops = 2 });
    defer model.deinit(testing.allocator);

    try testing.expect(!model.shouldFix("#main", 0));

    try model.setRegistered(testing.allocator, "#main", true);
    try testing.expect(model.shouldFix("#main", 0));
    try testing.expect(model.shouldFix("#main", 1));
    try testing.expect(!model.shouldFix("#main", 2));

    try model.setRegistered(testing.allocator, "#main", false);
    try testing.expect(!model.shouldFix("#main", 0));
}

test "per-channel identity storage evicts the lowest score" {
    var model = ChanFix.init(.{
        .half_life_ms = 60_000,
        .max_identities_per_channel = 2,
    });
    defer model.deinit(testing.allocator);

    try model.recordOpSeen(testing.allocator, "#small", "keeper", 0);
    try model.recordOpSeen(testing.allocator, "#small", "keeper", 1);
    try model.recordOpSeen(testing.allocator, "#small", "drop", 1);
    try model.recordOpSeen(testing.allocator, "#small", "newcomer", 2);

    try testing.expectEqual(@as(usize, 2), model.identityCount("#small"));
    try testing.expect(model.scoreOf("#small", "keeper", 2) > 0.0);
    try testing.expect(model.scoreOf("#small", "newcomer", 2) > 0.0);
    try testing.expectEqual(@as(f64, 0.0), model.scoreOf("#small", "drop", 2));
}

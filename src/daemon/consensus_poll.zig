const std = @import("std");

pub const Choice = enum {
    yes,
    no,
    abstain,
};

pub const Counts = struct {
    yes: u64 = 0,
    no: u64 = 0,
    abstain: u64 = 0,
};

pub const Error = std.mem.Allocator.Error || error{
    AlreadyCast,
};

const PollState = struct {
    counts: Counts = .{},
    voters: std.StringHashMap(Choice),

    fn init(allocator: std.mem.Allocator) PollState {
        return .{ .voters = std.StringHashMap(Choice).init(allocator) };
    }

    fn deinit(self: *PollState, allocator: std.mem.Allocator) void {
        var it = self.voters.keyIterator();
        while (it.next()) |voter| allocator.free(voter.*);
        self.voters.deinit();
        self.* = undefined;
    }
};

pub const ConsensusPoll = struct {
    allocator: std.mem.Allocator,
    polls: std.StringHashMap(PollState),

    pub fn init(allocator: std.mem.Allocator) ConsensusPoll {
        return .{
            .allocator = allocator,
            .polls = std.StringHashMap(PollState).init(allocator),
        };
    }

    pub fn deinit(self: *ConsensusPoll) void {
        var it = self.polls.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.polls.deinit();
        self.* = undefined;
    }

    pub fn cast(self: *ConsensusPoll, key: []const u8, voter: []const u8, choice: Choice) Error!void {
        const poll = try self.ensurePoll(key);
        if (poll.voters.contains(voter)) return error.AlreadyCast;

        const owned_voter = try self.allocator.dupe(u8, voter);
        errdefer self.allocator.free(owned_voter);
        try poll.voters.putNoClobber(owned_voter, choice);
        switch (choice) {
            .yes => poll.counts.yes += 1,
            .no => poll.counts.no += 1,
            .abstain => poll.counts.abstain += 1,
        }
    }

    pub fn result(self: *const ConsensusPoll, key: []const u8) Counts {
        const poll = self.polls.getPtr(key) orelse return .{};
        return poll.counts;
    }

    fn ensurePoll(self: *ConsensusPoll, key: []const u8) Error!*PollState {
        if (self.polls.getPtr(key)) |poll| return poll;

        const owned_key = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(owned_key);
        try self.polls.putNoClobber(owned_key, PollState.init(self.allocator));
        return self.polls.getPtr(key).?;
    }
};

const testing = std.testing;

test "cast counts each choice" {
    var polls = ConsensusPoll.init(testing.allocator);
    defer polls.deinit();

    try polls.cast("release", "alice", .yes);
    try polls.cast("release", "bob", .no);
    try polls.cast("release", "carol", .abstain);

    const counts = polls.result("release");
    try testing.expectEqual(@as(u64, 1), counts.yes);
    try testing.expectEqual(@as(u64, 1), counts.no);
    try testing.expectEqual(@as(u64, 1), counts.abstain);
}

test "one voter may cast once per key" {
    var polls = ConsensusPoll.init(testing.allocator);
    defer polls.deinit();

    try polls.cast("topic-a", "alice", .yes);
    try testing.expectError(error.AlreadyCast, polls.cast("topic-a", "alice", .no));
    try polls.cast("topic-b", "alice", .no);

    try testing.expectEqual(@as(u64, 1), polls.result("topic-a").yes);
    try testing.expectEqual(@as(u64, 1), polls.result("topic-b").no);
}

test "missing keys return zero counts" {
    var polls = ConsensusPoll.init(testing.allocator);
    defer polls.deinit();

    const counts = polls.result("unknown");
    try testing.expectEqual(@as(u64, 0), counts.yes);
    try testing.expectEqual(@as(u64, 0), counts.no);
    try testing.expectEqual(@as(u64, 0), counts.abstain);
}

test "separate keys do not share counts" {
    var polls = ConsensusPoll.init(testing.allocator);
    defer polls.deinit();

    try polls.cast("one", "alice", .yes);
    try polls.cast("two", "bob", .abstain);

    try testing.expectEqual(@as(u64, 1), polls.result("one").yes);
    try testing.expectEqual(@as(u64, 0), polls.result("one").abstain);
    try testing.expectEqual(@as(u64, 0), polls.result("two").yes);
    try testing.expectEqual(@as(u64, 1), polls.result("two").abstain);
}

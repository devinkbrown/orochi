const std = @import("std");

pub const max_targets: usize = 4096;
pub const max_channel_len: usize = 128;
pub const max_msgid_len: usize = 128;
pub const max_voter_len: usize = 128;
pub const max_votes_per_target: usize = 1024;

pub const Error = std.mem.Allocator.Error || error{
    ChannelTooLong,
    MessageIdTooLong,
    VoterTooLong,
    EmptyChannel,
    EmptyVoter,
    TooManyTargets,
    TooManyVotes,
};

const TargetKey = struct {
    channel: []u8,
    msgid: []u8,
};

const VoteSet = struct {
    voters: std.ArrayListUnmanaged([]u8) = .empty,

    fn deinit(self: *VoteSet, allocator: std.mem.Allocator) void {
        for (self.voters.items) |voter| allocator.free(voter);
        self.voters.deinit(allocator);
    }

    fn find(self: *const VoteSet, voter: []const u8) ?usize {
        for (self.voters.items, 0..) |known, i| {
            if (std.mem.eql(u8, known, voter)) return i;
        }
        return null;
    }
};

const Target = struct {
    key: TargetKey,
    votes: VoteSet,

    fn deinit(self: *Target, allocator: std.mem.Allocator) void {
        allocator.free(self.key.channel);
        allocator.free(self.key.msgid);
        self.votes.deinit(allocator);
    }
};

pub const PinVote = struct {
    allocator: std.mem.Allocator,
    targets: std.ArrayListUnmanaged(Target) = .empty,

    pub fn init(allocator: std.mem.Allocator) PinVote {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *PinVote) void {
        for (self.targets.items) |*target| target.deinit(self.allocator);
        self.targets.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn vote(self: *PinVote, channel: []const u8, msgid: []const u8, voter: []const u8) Error!u32 {
        try validateInput(channel, msgid, voter);
        const target = try self.ensureTarget(channel, msgid);
        if (target.votes.find(voter) != null) return @intCast(target.votes.voters.items.len);
        if (target.votes.voters.items.len >= max_votes_per_target) return error.TooManyVotes;

        const owned_voter = try self.allocator.dupe(u8, voter);
        errdefer self.allocator.free(owned_voter);
        try target.votes.voters.append(self.allocator, owned_voter);
        return @intCast(target.votes.voters.items.len);
    }

    pub fn tally(self: *const PinVote, channel: []const u8, msgid: []const u8) u32 {
        const idx = self.findTarget(channel, msgid) orelse return 0;
        return @intCast(self.targets.items[idx].votes.voters.items.len);
    }

    pub fn clear(self: *PinVote, channel: []const u8, msgid: []const u8) bool {
        const idx = self.findTarget(channel, msgid) orelse return false;
        var removed = self.targets.orderedRemove(idx);
        removed.deinit(self.allocator);
        return true;
    }

    fn ensureTarget(self: *PinVote, channel: []const u8, msgid: []const u8) Error!*Target {
        if (self.findTarget(channel, msgid)) |idx| return &self.targets.items[idx];
        if (self.targets.items.len >= max_targets) return error.TooManyTargets;

        const owned_channel = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(owned_channel);
        const owned_msgid = try self.allocator.dupe(u8, msgid);
        errdefer self.allocator.free(owned_msgid);

        try self.targets.append(self.allocator, .{
            .key = .{ .channel = owned_channel, .msgid = owned_msgid },
            .votes = .{},
        });
        return &self.targets.items[self.targets.items.len - 1];
    }

    fn findTarget(self: *const PinVote, channel: []const u8, msgid: []const u8) ?usize {
        for (self.targets.items, 0..) |target, i| {
            if (std.mem.eql(u8, target.key.channel, channel) and std.mem.eql(u8, target.key.msgid, msgid)) return i;
        }
        return null;
    }
};

fn validateInput(channel: []const u8, msgid: []const u8, voter: []const u8) Error!void {
    if (channel.len == 0) return error.EmptyChannel;
    if (channel.len > max_channel_len) return error.ChannelTooLong;
    if (msgid.len > max_msgid_len) return error.MessageIdTooLong;
    if (voter.len == 0) return error.EmptyVoter;
    if (voter.len > max_voter_len) return error.VoterTooLong;
}

const testing = std.testing;

test "vote counts distinct voters for one target" {
    var votes = PinVote.init(testing.allocator);
    defer votes.deinit();

    try testing.expectEqual(@as(u32, 1), try votes.vote("#chat", "m1", "alice"));
    try testing.expectEqual(@as(u32, 2), try votes.vote("#chat", "m1", "bob"));
    try testing.expectEqual(@as(u32, 2), try votes.vote("#chat", "m1", "alice"));
    try testing.expectEqual(@as(u32, 2), votes.tally("#chat", "m1"));
}

test "same message id in different channels is isolated" {
    var votes = PinVote.init(testing.allocator);
    defer votes.deinit();

    _ = try votes.vote("#a", "same", "one");
    _ = try votes.vote("#b", "same", "one");
    _ = try votes.vote("#b", "same", "two");
    try testing.expectEqual(@as(u32, 1), votes.tally("#a", "same"));
    try testing.expectEqual(@as(u32, 2), votes.tally("#b", "same"));
}

test "clear removes one target" {
    var votes = PinVote.init(testing.allocator);
    defer votes.deinit();

    _ = try votes.vote("#chat", "m2", "alice");
    _ = try votes.vote("#chat", "m3", "alice");
    try testing.expect(votes.clear("#chat", "m2"));
    try testing.expect(!votes.clear("#chat", "m2"));
    try testing.expectEqual(@as(u32, 0), votes.tally("#chat", "m2"));
    try testing.expectEqual(@as(u32, 1), votes.tally("#chat", "m3"));
}

test "input caps are enforced" {
    var votes = PinVote.init(testing.allocator);
    defer votes.deinit();

    try testing.expectError(error.EmptyChannel, votes.vote("", "m", "a"));
    try testing.expectError(error.EmptyVoter, votes.vote("#c", "m", ""));
    try testing.expectError(error.ChannelTooLong, votes.vote("#" ** (max_channel_len + 1), "m", "a"));
    try testing.expectError(error.MessageIdTooLong, votes.vote("#c", "m" ** (max_msgid_len + 1), "a"));
    try testing.expectError(error.VoterTooLong, votes.vote("#c", "m", "v" ** (max_voter_len + 1)));
}

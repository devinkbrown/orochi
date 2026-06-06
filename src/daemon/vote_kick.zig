//! Bounded vote tracking for channel target removal decisions.
const std = @import("std");

pub const VoteKick = struct {
    pub const max_pairs: usize = 4096;
    pub const max_voters_per_pair: usize = 1024;
    pub const max_channel_len: usize = 128;
    pub const max_target_len: usize = 128;
    pub const max_voter_len: usize = 128;

    pub const Error = std.mem.Allocator.Error || error{
        ChannelTooLong,
        TargetTooLong,
        VoterTooLong,
        TooManyPairs,
        TooManyVoters,
    };

    allocator: std.mem.Allocator,
    channels: std.StringHashMap(ChannelVotes),
    pair_count: usize = 0,

    pub fn init(allocator: std.mem.Allocator) VoteKick {
        return .{
            .allocator = allocator,
            .channels = std.StringHashMap(ChannelVotes).init(allocator),
        };
    }

    pub fn deinit(self: *VoteKick) void {
        var it = self.channels.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.channels.deinit();
        self.* = undefined;
    }

    pub fn vote(self: *VoteKick, channel: []const u8, target: []const u8, voter: []const u8) Error!u32 {
        try validate(channel, target, voter);

        if (self.channels.getPtr(channel)) |channel_votes| {
            if (channel_votes.targets.getPtr(target)) |set| {
                return try set.add(self.allocator, voter);
            }
            if (self.pair_count >= max_pairs) return error.TooManyPairs;
            const count = try channel_votes.addTarget(self.allocator, target, voter);
            self.pair_count += 1;
            return count;
        }

        if (self.pair_count >= max_pairs) return error.TooManyPairs;

        const owned_channel = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(owned_channel);

        var channel_votes = ChannelVotes.init(self.allocator);
        errdefer channel_votes.deinit(self.allocator);

        const count = try channel_votes.addTarget(self.allocator, target, voter);
        try self.channels.putNoClobber(owned_channel, channel_votes);
        self.pair_count += 1;
        return count;
    }

    pub fn tally(self: *const VoteKick, channel: []const u8, target: []const u8) u32 {
        const channel_votes = self.channels.getPtr(channel) orelse return 0;
        const set = channel_votes.targets.getPtr(target) orelse return 0;
        return @intCast(set.voters.items.len);
    }

    pub fn clear(self: *VoteKick, channel: []const u8, target: []const u8) bool {
        const channel_entry = self.channels.getEntry(channel) orelse return false;
        const removed = channel_entry.value_ptr.targets.fetchRemove(target) orelse return false;

        self.allocator.free(removed.key);
        var set = removed.value;
        set.deinit(self.allocator);
        self.pair_count -= 1;

        if (channel_entry.value_ptr.targets.count() == 0) {
            const owned_channel = channel_entry.key_ptr.*;
            channel_entry.value_ptr.deinit(self.allocator);
            self.channels.removeByPtr(channel_entry.key_ptr);
            self.allocator.free(owned_channel);
        }

        return true;
    }

    pub fn pairs(self: *const VoteKick) usize {
        return self.pair_count;
    }
};

const ChannelVotes = struct {
    targets: std.StringHashMap(VoterSet),

    fn init(allocator: std.mem.Allocator) ChannelVotes {
        return .{ .targets = std.StringHashMap(VoterSet).init(allocator) };
    }

    fn deinit(self: *ChannelVotes, allocator: std.mem.Allocator) void {
        var it = self.targets.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(allocator);
        }
        self.targets.deinit();
        self.* = undefined;
    }

    fn addTarget(self: *ChannelVotes, allocator: std.mem.Allocator, target: []const u8, voter: []const u8) VoteKick.Error!u32 {
        const owned_target = try allocator.dupe(u8, target);
        errdefer allocator.free(owned_target);

        var set: VoterSet = .{};
        errdefer set.deinit(allocator);

        const count = try set.add(allocator, voter);
        try self.targets.putNoClobber(owned_target, set);
        return count;
    }
};

const VoterSet = struct {
    voters: std.ArrayListUnmanaged([]u8) = .empty,

    fn deinit(self: *VoterSet, allocator: std.mem.Allocator) void {
        for (self.voters.items) |voter| allocator.free(voter);
        self.voters.deinit(allocator);
        self.* = undefined;
    }

    fn add(self: *VoterSet, allocator: std.mem.Allocator, voter: []const u8) VoteKick.Error!u32 {
        if (self.contains(voter)) return @intCast(self.voters.items.len);
        if (self.voters.items.len >= VoteKick.max_voters_per_pair) return error.TooManyVoters;

        const owned_voter = try allocator.dupe(u8, voter);
        errdefer allocator.free(owned_voter);

        try self.voters.append(allocator, owned_voter);
        return @intCast(self.voters.items.len);
    }

    fn contains(self: *const VoterSet, voter: []const u8) bool {
        for (self.voters.items) |known| {
            if (std.mem.eql(u8, known, voter)) return true;
        }
        return false;
    }
};

fn validate(channel: []const u8, target: []const u8, voter: []const u8) VoteKick.Error!void {
    if (channel.len > VoteKick.max_channel_len) return error.ChannelTooLong;
    if (target.len > VoteKick.max_target_len) return error.TargetTooLong;
    if (voter.len > VoteKick.max_voter_len) return error.VoterTooLong;
}

const testing = std.testing;

test "distinct voters are counted once" {
    var votes = VoteKick.init(testing.allocator);
    defer votes.deinit();

    try testing.expectEqual(@as(u32, 1), try votes.vote("#chat", "mallory", "alice"));
    try testing.expectEqual(@as(u32, 2), try votes.vote("#chat", "mallory", "bob"));
    try testing.expectEqual(@as(u32, 2), try votes.vote("#chat", "mallory", "alice"));
    try testing.expectEqual(@as(u32, 2), votes.tally("#chat", "mallory"));
}

test "channels and targets are independent" {
    var votes = VoteKick.init(testing.allocator);
    defer votes.deinit();

    _ = try votes.vote("#a", "mallory", "alice");
    _ = try votes.vote("#a", "trent", "alice");
    _ = try votes.vote("#b", "mallory", "alice");

    try testing.expectEqual(@as(u32, 1), votes.tally("#a", "mallory"));
    try testing.expectEqual(@as(u32, 1), votes.tally("#a", "trent"));
    try testing.expectEqual(@as(u32, 1), votes.tally("#b", "mallory"));
    try testing.expectEqual(@as(usize, 3), votes.pairs());
}

test "clear removes one pair and prunes empty channels" {
    var votes = VoteKick.init(testing.allocator);
    defer votes.deinit();

    _ = try votes.vote("#chat", "mallory", "alice");

    try testing.expect(votes.clear("#chat", "mallory"));
    try testing.expect(!votes.clear("#chat", "mallory"));
    try testing.expectEqual(@as(u32, 0), votes.tally("#chat", "mallory"));
    try testing.expectEqual(@as(usize, 0), votes.pairs());
}

test "voter length cap is enforced" {
    var votes = VoteKick.init(testing.allocator);
    defer votes.deinit();

    const voter = "v" ** (VoteKick.max_voter_len + 1);
    try testing.expectError(error.VoterTooLong, votes.vote("#chat", "mallory", voter));
    try testing.expectEqual(@as(usize, 0), votes.pairs());
}

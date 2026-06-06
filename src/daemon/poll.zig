//! Per-channel in-call polls with bounded options and voter state. Poll data is
//! copied on entry and can be tallied without exposing mutable internals.
const std = @import("std");

pub const max_channels: usize = 4096;
pub const max_polls_per_channel: usize = 32;
pub const max_voters_per_poll: usize = 4096;
pub const max_channel_bytes: usize = 128;
pub const max_id_bytes: usize = 64;
pub const max_question_bytes: usize = 512;
pub const max_option_bytes: usize = 128;
pub const max_options: usize = 8;

pub const Error = std.mem.Allocator.Error || error{ TooManyChannels, TooManyPolls, TooManyVoters, InvalidPoll };

const PollRecord = struct {
    id: []u8,
    question: []u8,
    options: std.ArrayListUnmanaged([]u8) = .empty,
    counts: std.ArrayListUnmanaged(u32) = .empty,
    votes: std.StringHashMap(usize),

    fn init(allocator: std.mem.Allocator, id: []const u8, question: []const u8, options: []const []const u8) Error!PollRecord {
        var rec = PollRecord{
            .id = try allocator.dupe(u8, id),
            .question = undefined,
            .votes = std.StringHashMap(usize).init(allocator),
        };
        errdefer rec.deinit(allocator);

        rec.question = try allocator.dupe(u8, question);
        try rec.options.ensureTotalCapacity(allocator, options.len);
        try rec.counts.ensureTotalCapacity(allocator, options.len);
        for (options) |option| {
            const owned = try allocator.dupe(u8, option);
            rec.options.appendAssumeCapacity(owned);
            rec.counts.appendAssumeCapacity(0);
        }
        return rec;
    }

    fn deinit(self: *PollRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.question);
        for (self.options.items) |option| allocator.free(option);
        self.options.deinit(allocator);
        self.counts.deinit(allocator);
        var it = self.votes.keyIterator();
        while (it.next()) |key| allocator.free(key.*);
        self.votes.deinit();
    }

    fn vote(self: *PollRecord, allocator: std.mem.Allocator, voter: []const u8, option_idx: usize) Error!void {
        if (!validName(voter, max_id_bytes) or option_idx >= self.counts.items.len) return error.InvalidPoll;
        if (self.votes.getPtr(voter)) |old| {
            self.counts.items[old.*] -= 1;
            old.* = option_idx;
            self.counts.items[option_idx] += 1;
            return;
        }
        if (self.votes.count() >= max_voters_per_poll) return error.TooManyVoters;
        const owned = try allocator.dupe(u8, voter);
        errdefer allocator.free(owned);
        try self.votes.putNoClobber(owned, option_idx);
        self.counts.items[option_idx] += 1;
    }
};

const ChannelPolls = struct {
    polls: std.ArrayListUnmanaged(PollRecord) = .empty,

    fn deinit(self: *ChannelPolls, allocator: std.mem.Allocator) void {
        for (self.polls.items) |*poll| poll.deinit(allocator);
        self.polls.deinit(allocator);
    }

    fn find(self: *ChannelPolls, id: []const u8) ?usize {
        for (self.polls.items, 0..) |*poll, i| {
            if (std.mem.eql(u8, poll.id, id)) return i;
        }
        return null;
    }

    fn findConst(self: *const ChannelPolls, id: []const u8) ?usize {
        for (self.polls.items, 0..) |*poll, i| {
            if (std.mem.eql(u8, poll.id, id)) return i;
        }
        return null;
    }
};

pub const Poll = struct {
    allocator: std.mem.Allocator,
    channels: std.StringHashMap(ChannelPolls),

    pub fn init(allocator: std.mem.Allocator) Poll {
        return .{ .allocator = allocator, .channels = std.StringHashMap(ChannelPolls).init(allocator) };
    }

    pub fn deinit(self: *Poll) void {
        var it = self.channels.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.channels.deinit();
        self.* = undefined;
    }

    pub fn create(self: *Poll, channel: []const u8, id: []const u8, question: []const u8, options: []const []const u8) Error!void {
        if (!validName(channel, max_channel_bytes)) return error.InvalidPoll;
        if (!validName(id, max_id_bytes)) return error.InvalidPoll;
        if (question.len == 0 or question.len > max_question_bytes) return error.InvalidPoll;
        if (options.len == 0 or options.len > max_options) return error.InvalidPoll;
        for (options) |option| {
            if (option.len == 0 or option.len > max_option_bytes or std.mem.indexOfScalar(u8, option, 0) != null) return error.InvalidPoll;
        }

        const list = try self.ensureChannel(channel);
        if (list.find(id) != null) return error.InvalidPoll;
        if (list.polls.items.len >= max_polls_per_channel) return error.TooManyPolls;
        const rec = try PollRecord.init(self.allocator, id, question, options);
        errdefer {
            var tmp = rec;
            tmp.deinit(self.allocator);
        }
        try list.polls.append(self.allocator, rec);
    }

    pub fn vote(self: *Poll, channel: []const u8, id: []const u8, voter: []const u8, optionIdx: usize) Error!void {
        const list = self.channels.getPtr(channel) orelse return error.InvalidPoll;
        const idx = list.find(id) orelse return error.InvalidPoll;
        try list.polls.items[idx].vote(self.allocator, voter, optionIdx);
    }

    pub fn tally(self: *const Poll, channel: []const u8, id: []const u8) ?[]const u32 {
        const list = self.channels.getPtr(channel) orelse return null;
        const idx = list.findConst(id) orelse return null;
        return list.polls.items[idx].counts.items;
    }

    pub fn close(self: *Poll, channel: []const u8, id: []const u8) bool {
        const entry = self.channels.getEntry(channel) orelse return false;
        const idx = entry.value_ptr.find(id) orelse return false;
        var rec = entry.value_ptr.polls.orderedRemove(idx);
        rec.deinit(self.allocator);
        if (entry.value_ptr.polls.items.len == 0) {
            const key = entry.key_ptr.*;
            entry.value_ptr.deinit(self.allocator);
            self.channels.removeByPtr(entry.key_ptr);
            self.allocator.free(key);
        }
        return true;
    }

    fn ensureChannel(self: *Poll, channel: []const u8) Error!*ChannelPolls {
        if (self.channels.getPtr(channel)) |list| return list;
        if (self.channels.count() >= max_channels) return error.TooManyChannels;
        const owned = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(owned);
        try self.channels.putNoClobber(owned, .{});
        return self.channels.getPtr(channel).?;
    }
};

fn validName(value: []const u8, cap: usize) bool {
    return value.len > 0 and value.len <= cap and std.mem.indexOfScalar(u8, value, 0) == null;
}

const testing = std.testing;

test "create and tally empty poll" {
    var polls = Poll.init(testing.allocator);
    defer polls.deinit();

    const options = [_][]const u8{ "yes", "no" };
    try polls.create("#meet", "p1", "Ship it?", &options);

    const counts = polls.tally("#meet", "p1").?;
    try testing.expectEqual(@as(usize, 2), counts.len);
    try testing.expectEqual(@as(u32, 0), counts[0]);
    try testing.expectEqual(@as(u32, 0), counts[1]);
}

test "vote is one per voter and changeable" {
    var polls = Poll.init(testing.allocator);
    defer polls.deinit();

    const options = [_][]const u8{ "red", "blue", "green" };
    try polls.create("#meet", "colors", "Pick one", &options);
    try polls.vote("#meet", "colors", "alice", 0);
    try polls.vote("#meet", "colors", "bob", 1);
    try polls.vote("#meet", "colors", "alice", 2);

    const counts = polls.tally("#meet", "colors").?;
    try testing.expectEqual(@as(u32, 0), counts[0]);
    try testing.expectEqual(@as(u32, 1), counts[1]);
    try testing.expectEqual(@as(u32, 1), counts[2]);
}

test "close removes a poll" {
    var polls = Poll.init(testing.allocator);
    defer polls.deinit();

    const options = [_][]const u8{ "up", "down" };
    try polls.create("#meet", "p1", "Direction?", &options);
    try testing.expect(polls.close("#meet", "p1"));
    try testing.expect(polls.tally("#meet", "p1") == null);
    try testing.expect(!polls.close("#meet", "p1"));
}

test "option cap is enforced" {
    var polls = Poll.init(testing.allocator);
    defer polls.deinit();

    const options = [_][]const u8{ "a", "b", "c", "d", "e", "f", "g", "h", "i" };
    try testing.expectError(error.InvalidPoll, polls.create("#meet", "p1", "Too many", &options));
}

// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

const std = @import("std");

pub const Tally = struct {
    @"for": u64,
    against: u64,
};

pub const Error = std.mem.Allocator.Error || error{
    IdExhausted,
    UnknownChannel,
    UnknownProposal,
    AlreadyVoted,
};

const ProposalRecord = struct {
    id: u64,
    text: []u8,
    by: []u8,
    votes: std.StringHashMap(bool),
    for_count: u64 = 0,
    against_count: u64 = 0,

    fn init(allocator: std.mem.Allocator, id: u64, text: []const u8, by: []const u8) std.mem.Allocator.Error!ProposalRecord {
        const owned_text = try allocator.dupe(u8, text);
        errdefer allocator.free(owned_text);
        const owned_by = try allocator.dupe(u8, by);
        errdefer allocator.free(owned_by);

        return .{
            .id = id,
            .text = owned_text,
            .by = owned_by,
            .votes = std.StringHashMap(bool).init(allocator),
        };
    }

    fn deinit(self: *ProposalRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.text);
        allocator.free(self.by);
        var it = self.votes.keyIterator();
        while (it.next()) |voter| allocator.free(voter.*);
        self.votes.deinit();
        self.* = undefined;
    }
};

const ChannelProposals = struct {
    next_id: u64 = 1,
    items: std.AutoHashMap(u64, ProposalRecord),

    fn init(allocator: std.mem.Allocator) ChannelProposals {
        return .{ .items = std.AutoHashMap(u64, ProposalRecord).init(allocator) };
    }

    fn deinit(self: *ChannelProposals, allocator: std.mem.Allocator) void {
        var it = self.items.valueIterator();
        while (it.next()) |item| item.deinit(allocator);
        self.items.deinit();
        self.* = undefined;
    }
};

pub const Proposal = struct {
    allocator: std.mem.Allocator,
    channels: std.StringHashMap(ChannelProposals),

    pub fn init(allocator: std.mem.Allocator) Proposal {
        return .{
            .allocator = allocator,
            .channels = std.StringHashMap(ChannelProposals).init(allocator),
        };
    }

    pub fn deinit(self: *Proposal) void {
        var it = self.channels.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.channels.deinit();
        self.* = undefined;
    }

    pub fn open(self: *Proposal, channel: []const u8, text: []const u8, by: []const u8) Error!u64 {
        const proposals = try self.ensureChannel(channel);
        if (proposals.next_id == std.math.maxInt(u64)) return error.IdExhausted;

        const id = proposals.next_id;
        proposals.next_id += 1;

        var record = try ProposalRecord.init(self.allocator, id, text, by);
        errdefer record.deinit(self.allocator);
        try proposals.items.putNoClobber(id, record);
        return id;
    }

    pub fn vote(self: *Proposal, channel: []const u8, id: u64, voter: []const u8, yes: bool) Error!void {
        const proposals = self.channels.getPtr(channel) orelse return error.UnknownChannel;
        const record = proposals.items.getPtr(id) orelse return error.UnknownProposal;
        if (record.votes.contains(voter)) return error.AlreadyVoted;

        const owned_voter = try self.allocator.dupe(u8, voter);
        errdefer self.allocator.free(owned_voter);
        try record.votes.putNoClobber(owned_voter, yes);
        if (yes) {
            record.for_count += 1;
        } else {
            record.against_count += 1;
        }
    }

    pub fn tally(self: *const Proposal, channel: []const u8, id: u64) ?Tally {
        const proposals = self.channels.getPtr(channel) orelse return null;
        const record = proposals.items.get(id) orelse return null;
        return .{ .@"for" = record.for_count, .against = record.against_count };
    }

    pub fn close(self: *Proposal, channel: []const u8, id: u64) bool {
        const proposals = self.channels.getPtr(channel) orelse return false;
        if (proposals.items.fetchRemove(id)) |removed| {
            var record = removed.value;
            record.deinit(self.allocator);
            return true;
        }
        return false;
    }

    fn ensureChannel(self: *Proposal, channel: []const u8) std.mem.Allocator.Error!*ChannelProposals {
        if (self.channels.getPtr(channel)) |proposals| return proposals;

        const owned_channel = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(owned_channel);
        try self.channels.putNoClobber(owned_channel, ChannelProposals.init(self.allocator));
        return self.channels.getPtr(channel).?;
    }
};

const testing = std.testing;

test "open assigns per-channel 64-bit ids" {
    var proposals = Proposal.init(testing.allocator);
    defer proposals.deinit();

    try testing.expectEqual(@as(u64, 1), try proposals.open("#ops", "rotate topic", "alice"));
    try testing.expectEqual(@as(u64, 2), try proposals.open("#ops", "publish notes", "bob"));
    try testing.expectEqual(@as(u64, 1), try proposals.open("#dev", "ship build", "carol"));
}

test "vote accepts one ballot per voter" {
    var proposals = Proposal.init(testing.allocator);
    defer proposals.deinit();

    const id = try proposals.open("#ops", "add quiet hours", "alice");
    try proposals.vote("#ops", id, "bob", true);
    try proposals.vote("#ops", id, "carol", false);
    try testing.expectError(error.AlreadyVoted, proposals.vote("#ops", id, "bob", false));

    const counts = proposals.tally("#ops", id).?;
    try testing.expectEqual(@as(u64, 1), counts.@"for");
    try testing.expectEqual(@as(u64, 1), counts.against);
}

test "close removes a proposal" {
    var proposals = Proposal.init(testing.allocator);
    defer proposals.deinit();

    const id = try proposals.open("#ops", "archive stale ban list", "alice");
    try testing.expect(proposals.tally("#ops", id) != null);
    try testing.expect(proposals.close("#ops", id));
    try testing.expect(!proposals.close("#ops", id));
    try testing.expect(proposals.tally("#ops", id) == null);
}

test "unknown channel and proposal are reported" {
    var proposals = Proposal.init(testing.allocator);
    defer proposals.deinit();

    const id = try proposals.open("#ops", "document policy", "alice");
    try testing.expectError(error.UnknownChannel, proposals.vote("#none", id, "bob", true));
    try testing.expectError(error.UnknownProposal, proposals.vote("#ops", id + 1, "bob", true));
}

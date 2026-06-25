// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

const std = @import("std");

/// Threshold policy used to decide whether a proposal has enough votes.
pub const Policy = enum(u2) {
    majority,
    two_thirds,
    all,
};

/// Compile-time limits for a quorum vote tracker.
pub const Params = struct {
    /// Maximum number of node ids allowed in one voting membership.
    max_members: usize = 1024,
    /// Maximum node id length in bytes.
    max_node_id_bytes: usize = 128,
};

/// Errors returned by quorum membership and voting operations.
pub const QuorumError = std.mem.Allocator.Error || error{
    EmptyNodeId,
    NodeIdTooLong,
    TooManyMembers,
    UnknownNode,
};

/// Snapshot of the current proposal vote totals.
pub const Tally = struct {
    votes: usize = 0,
    members: usize = 0,
    missing: usize = 0,
};

/// Returns the number of votes required by `policy` for `total` eligible nodes.
pub fn threshold(total: usize, policy: Policy) usize {
    if (total == 0) return 0;
    return switch (policy) {
        .majority => (total / 2) + 1,
        .two_thirds => (2 * (total / 3)) + (total % 3),
        .all => total,
    };
}

/// Returns a bounded quorum tracker type for one mesh proposal.
pub fn Quorum(comptime params: Params) type {
    comptime {
        if (params.max_members == 0) @compileError("quorum needs member storage");
        if (params.max_node_id_bytes == 0) @compileError("quorum node ids need storage");
    }

    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        members: std.StringHashMap(void),
        votes: std.StringHashMap(void),

        /// Initializes an empty quorum tracker.
        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .allocator = allocator,
                .members = std.StringHashMap(void).init(allocator),
                .votes = std.StringHashMap(void).init(allocator),
            };
        }

        /// Frees all owned node ids and invalidates the tracker.
        pub fn deinit(self: *Self) void {
            self.clear();
            self.members.deinit();
            self.votes.deinit();
            self.* = undefined;
        }

        /// Removes all members and votes while retaining map capacity.
        pub fn clear(self: *Self) void {
            var vote_it = self.votes.keyIterator();
            while (vote_it.next()) |node_id| self.allocator.free(node_id.*);
            self.votes.clearRetainingCapacity();

            var member_it = self.members.keyIterator();
            while (member_it.next()) |node_id| self.allocator.free(node_id.*);
            self.members.clearRetainingCapacity();
        }

        /// Adds a voting member and returns whether the member was new.
        pub fn addMember(self: *Self, node_id: []const u8) QuorumError!bool {
            try validateNodeId(node_id);
            if (self.members.contains(node_id)) return false;
            if (self.members.count() >= params.max_members) return error.TooManyMembers;

            const owned_node_id = try self.allocator.dupe(u8, node_id);
            errdefer self.allocator.free(owned_node_id);
            try self.members.putNoClobber(owned_node_id, {});
            return true;
        }

        /// Removes a member and any vote cast by that member.
        pub fn removeMember(self: *Self, node_id: []const u8) bool {
            const removed_member = self.members.fetchRemove(node_id) orelse return false;
            self.allocator.free(removed_member.key);

            if (self.votes.fetchRemove(node_id)) |removed_vote| {
                self.allocator.free(removed_vote.key);
            }
            return true;
        }

        /// Records a member vote and returns whether it changed the tally.
        pub fn vote(self: *Self, node_id: []const u8) QuorumError!bool {
            try validateNodeId(node_id);
            if (!self.members.contains(node_id)) return error.UnknownNode;
            if (self.votes.contains(node_id)) return false;

            const owned_node_id = try self.allocator.dupe(u8, node_id);
            errdefer self.allocator.free(owned_node_id);
            try self.votes.putNoClobber(owned_node_id, {});
            return true;
        }

        /// Returns the number of current votes, members, and missing votes.
        pub fn tally(self: *const Self) Tally {
            const members = self.members.count();
            const votes = self.votes.count();
            return .{
                .votes = votes,
                .members = members,
                .missing = members - votes,
            };
        }

        /// Returns whether current votes satisfy `policy` for `total` nodes.
        pub fn hasQuorum(self: *const Self, total: usize, policy: Policy) bool {
            if (total == 0) return false;
            return self.votes.count() >= threshold(total, policy);
        }

        /// Returns whether current votes satisfy `policy` for current membership.
        pub fn hasMemberQuorum(self: *const Self, policy: Policy) bool {
            return self.hasQuorum(self.members.count(), policy);
        }

        /// Returns the number of current voting members.
        pub fn memberCount(self: *const Self) usize {
            return self.members.count();
        }

        /// Returns whether `node_id` is part of the voting membership.
        pub fn containsMember(self: *const Self, node_id: []const u8) bool {
            return self.members.contains(node_id);
        }

        /// Returns whether `node_id` has already cast a vote.
        pub fn containsVote(self: *const Self, node_id: []const u8) bool {
            return self.votes.contains(node_id);
        }

        fn validateNodeId(node_id: []const u8) QuorumError!void {
            if (node_id.len == 0) return error.EmptyNodeId;
            if (node_id.len > params.max_node_id_bytes) return error.NodeIdTooLong;
        }
    };
}

/// Default quorum tracker for ordinary mesh proposal decisions.
pub const DefaultQuorum = Quorum(.{});

const testing = std.testing;

test "majority quorum is reached once more than half of members vote" {
    // Arrange
    var quorum = DefaultQuorum.init(testing.allocator);
    defer quorum.deinit();
    try testing.expect(try quorum.addMember("node-a"));
    try testing.expect(try quorum.addMember("node-b"));
    try testing.expect(try quorum.addMember("node-c"));

    // Act
    try testing.expect(try quorum.vote("node-a"));
    const before_majority = quorum.hasQuorum(3, .majority);
    try testing.expect(try quorum.vote("node-b"));
    const after_majority = quorum.hasQuorum(3, .majority);
    const tally = quorum.tally();

    // Assert
    try testing.expect(!before_majority);
    try testing.expect(after_majority);
    try testing.expectEqual(@as(usize, 2), tally.votes);
    try testing.expectEqual(@as(usize, 3), tally.members);
    try testing.expectEqual(@as(usize, 1), tally.missing);
}

test "majority quorum is not reached below threshold" {
    // Arrange
    var quorum = DefaultQuorum.init(testing.allocator);
    defer quorum.deinit();
    try testing.expect(try quorum.addMember("node-a"));
    try testing.expect(try quorum.addMember("node-b"));
    try testing.expect(try quorum.addMember("node-c"));
    try testing.expect(try quorum.addMember("node-d"));
    try testing.expect(try quorum.addMember("node-e"));

    // Act
    try testing.expect(try quorum.vote("node-a"));
    try testing.expect(try quorum.vote("node-b"));

    // Assert
    try testing.expect(!quorum.hasQuorum(5, .majority));
    try testing.expect(!quorum.hasMemberQuorum(.majority));
    try testing.expectEqual(@as(usize, 3), threshold(5, .majority));
}

test "two thirds quorum rounds up for partial thirds" {
    // Arrange
    var quorum = DefaultQuorum.init(testing.allocator);
    defer quorum.deinit();
    try testing.expect(try quorum.addMember("node-a"));
    try testing.expect(try quorum.addMember("node-b"));
    try testing.expect(try quorum.addMember("node-c"));
    try testing.expect(try quorum.addMember("node-d"));

    // Act
    try testing.expect(try quorum.vote("node-a"));
    try testing.expect(try quorum.vote("node-b"));
    const before_two_thirds = quorum.hasQuorum(4, .two_thirds);
    try testing.expect(try quorum.vote("node-c"));
    const after_two_thirds = quorum.hasQuorum(4, .two_thirds);

    // Assert
    try testing.expectEqual(@as(usize, 3), threshold(4, .two_thirds));
    try testing.expect(!before_two_thirds);
    try testing.expect(after_two_thirds);
}

test "duplicate votes are deduped without changing tally" {
    // Arrange
    var quorum = DefaultQuorum.init(testing.allocator);
    defer quorum.deinit();
    try testing.expect(try quorum.addMember("node-a"));
    try testing.expect(try quorum.addMember("node-b"));

    // Act
    const first = try quorum.vote("node-a");
    const duplicate = try quorum.vote("node-a");
    const tally = quorum.tally();

    // Assert
    try testing.expect(first);
    try testing.expect(!duplicate);
    try testing.expect(quorum.containsVote("node-a"));
    try testing.expectEqual(@as(usize, 1), tally.votes);
    try testing.expectEqual(@as(usize, 1), tally.missing);
}

test "dynamic membership changes quorum and removes departed votes" {
    // Arrange
    var quorum = DefaultQuorum.init(testing.allocator);
    defer quorum.deinit();
    try testing.expect(try quorum.addMember("node-a"));
    try testing.expect(try quorum.addMember("node-b"));
    try testing.expect(try quorum.addMember("node-c"));
    try testing.expect(try quorum.addMember("node-d"));
    try testing.expect(try quorum.vote("node-a"));
    try testing.expect(try quorum.vote("node-b"));

    // Act
    const before_remove = quorum.hasMemberQuorum(.majority);
    try testing.expect(quorum.removeMember("node-d"));
    const after_remove = quorum.hasMemberQuorum(.majority);
    try testing.expect(quorum.removeMember("node-b"));
    const tally = quorum.tally();

    // Assert
    try testing.expect(!before_remove);
    try testing.expect(after_remove);
    try testing.expect(!quorum.containsMember("node-b"));
    try testing.expect(!quorum.containsVote("node-b"));
    try testing.expectEqual(@as(usize, 1), tally.votes);
    try testing.expectEqual(@as(usize, 2), tally.members);
    try testing.expectEqual(@as(usize, 1), tally.missing);
}

test "unknown and invalid node ids are rejected" {
    // Arrange
    var quorum = Quorum(.{ .max_members = 1, .max_node_id_bytes = 4 }).init(testing.allocator);
    defer quorum.deinit();

    // Act / Assert
    try testing.expectError(error.EmptyNodeId, quorum.addMember(""));
    try testing.expectError(error.NodeIdTooLong, quorum.addMember("node-a"));
    try testing.expect(try quorum.addMember("n-a"));
    try testing.expect(!(try quorum.addMember("n-a")));
    try testing.expectError(error.TooManyMembers, quorum.addMember("n-b"));
    try testing.expectError(error.UnknownNode, quorum.vote("n-b"));
}

test "all quorum requires every current member vote" {
    // Arrange
    var quorum = DefaultQuorum.init(testing.allocator);
    defer quorum.deinit();
    try testing.expect(try quorum.addMember("node-a"));
    try testing.expect(try quorum.addMember("node-b"));

    // Act
    try testing.expect(try quorum.vote("node-a"));
    const before_all = quorum.hasMemberQuorum(.all);
    try testing.expect(try quorum.vote("node-b"));
    const after_all = quorum.hasMemberQuorum(.all);

    // Assert
    try testing.expect(!before_all);
    try testing.expect(after_all);
    try testing.expect(!quorum.hasQuorum(0, .all));
}

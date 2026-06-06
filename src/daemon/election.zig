const std = @import("std");

pub const Error = std.mem.Allocator.Error || error{
    DuplicateCandidate,
    UnknownCandidate,
    AlreadyVoted,
};

pub const Result = struct {
    candidate: []const u8,
    votes: u64,
};

const Candidate = struct {
    votes: u64 = 0,
};

pub const Election = struct {
    allocator: std.mem.Allocator,
    candidates: std.StringHashMap(Candidate),
    votes: std.StringHashMap([]const u8),

    pub fn init(allocator: std.mem.Allocator) Election {
        return .{
            .allocator = allocator,
            .candidates = std.StringHashMap(Candidate).init(allocator),
            .votes = std.StringHashMap([]const u8).init(allocator),
        };
    }

    pub fn deinit(self: *Election) void {
        var vit = self.votes.keyIterator();
        while (vit.next()) |account| self.allocator.free(account.*);
        self.votes.deinit();

        var cit = self.candidates.keyIterator();
        while (cit.next()) |name| self.allocator.free(name.*);
        self.candidates.deinit();
        self.* = undefined;
    }

    pub fn addCandidate(self: *Election, name: []const u8) Error!void {
        if (self.candidates.contains(name)) return error.DuplicateCandidate;

        const owned_name = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(owned_name);
        try self.candidates.putNoClobber(owned_name, .{});
    }

    pub fn vote(self: *Election, account: []const u8, candidate: []const u8) Error!void {
        const candidate_entry = self.candidates.getEntry(candidate) orelse return error.UnknownCandidate;
        if (self.votes.contains(account)) return error.AlreadyVoted;

        const owned_account = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(owned_account);
        try self.votes.putNoClobber(owned_account, candidate_entry.key_ptr.*);
        candidate_entry.value_ptr.votes += 1;
    }

    pub fn leader(self: *const Election) ?[]const u8 {
        var best_name: ?[]const u8 = null;
        var best_votes: u64 = 0;

        var it = self.candidates.iterator();
        while (it.next()) |entry| {
            if (best_name == null or entry.value_ptr.votes > best_votes) {
                best_name = entry.key_ptr.*;
                best_votes = entry.value_ptr.votes;
            }
        }
        return best_name;
    }

    pub fn tally(self: *const Election, out: []Result) usize {
        var written: usize = 0;
        var it = self.candidates.iterator();
        while (it.next()) |entry| {
            if (written == out.len) break;
            out[written] = .{
                .candidate = entry.key_ptr.*,
                .votes = entry.value_ptr.votes,
            };
            written += 1;
        }
        return written;
    }
};

const testing = std.testing;

test "candidates are unique" {
    var election = Election.init(testing.allocator);
    defer election.deinit();

    try election.addCandidate("alice");
    try election.addCandidate("bob");
    try testing.expectError(error.DuplicateCandidate, election.addCandidate("alice"));
}

test "vote tallies one account once" {
    var election = Election.init(testing.allocator);
    defer election.deinit();

    try election.addCandidate("alice");
    try election.addCandidate("bob");
    try election.vote("acct1", "alice");
    try election.vote("acct2", "alice");
    try election.vote("acct3", "bob");
    try testing.expectError(error.AlreadyVoted, election.vote("acct1", "bob"));
    try testing.expectEqualStrings("alice", election.leader().?);
}

test "unknown candidates are rejected" {
    var election = Election.init(testing.allocator);
    defer election.deinit();

    try testing.expectError(error.UnknownCandidate, election.vote("acct1", "nobody"));
    try testing.expect(election.leader() == null);
}

test "tally writes bounded output" {
    var election = Election.init(testing.allocator);
    defer election.deinit();

    try election.addCandidate("alice");
    try election.addCandidate("bob");
    try election.addCandidate("carol");
    try election.vote("acct1", "bob");

    var out: [2]Result = undefined;
    const n = election.tally(&out);
    try testing.expectEqual(@as(usize, 2), n);
    for (out[0..n]) |row| {
        if (std.mem.eql(u8, row.candidate, "bob")) {
            try testing.expectEqual(@as(u64, 1), row.votes);
            return;
        }
    }
    return error.TestExpectedEqual;
}

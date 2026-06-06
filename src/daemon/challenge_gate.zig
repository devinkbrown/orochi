const std = @import("std");

pub const ChallengeGate = struct {
    pub const max_pending: usize = 65536;
    pub const max_account_len: usize = 128;
    pub const max_token_len: usize = 256;

    pub const Error = error{
        EmptyAccount,
        AccountTooLong,
        EmptyToken,
        TokenTooLong,
        TooManyPending,
    } || std.mem.Allocator.Error;

    allocator: std.mem.Allocator,
    tokens: std.StringHashMap([]u8),

    pub fn init(allocator: std.mem.Allocator) ChallengeGate {
        return .{
            .allocator = allocator,
            .tokens = std.StringHashMap([]u8).init(allocator),
        };
    }

    pub fn deinit(self: *ChallengeGate) void {
        var it = self.tokens.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.tokens.deinit();
        self.* = undefined;
    }

    pub fn issue(self: *ChallengeGate, account: []const u8, token: []const u8) Error!void {
        try validateAccount(account);
        try validateToken(token);

        if (self.tokens.getPtr(account)) |stored| {
            const owned_token = try self.allocator.dupe(u8, token);
            self.allocator.free(stored.*);
            stored.* = owned_token;
            return;
        }

        if (self.tokens.count() >= max_pending) return error.TooManyPending;

        const owned_account = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(owned_account);
        const owned_token = try self.allocator.dupe(u8, token);
        errdefer self.allocator.free(owned_token);

        try self.tokens.put(owned_account, owned_token);
    }

    pub fn verify(self: *ChallengeGate, account: []const u8, token: []const u8) bool {
        if (!validAccount(account) or !validToken(token)) return false;
        const stored = self.tokens.get(account) orelse return false;
        if (!std.mem.eql(u8, stored, token)) return false;

        const removed = self.tokens.fetchRemove(account).?;
        self.allocator.free(removed.key);
        self.allocator.free(removed.value);
        return true;
    }

    pub fn pending(self: *const ChallengeGate, account: []const u8) bool {
        if (!validAccount(account)) return false;
        return self.tokens.contains(account);
    }

    pub fn pendingCount(self: *const ChallengeGate) usize {
        return self.tokens.count();
    }

    fn validateAccount(account: []const u8) Error!void {
        if (account.len == 0) return error.EmptyAccount;
        if (account.len > max_account_len) return error.AccountTooLong;
    }

    fn validateToken(token: []const u8) Error!void {
        if (token.len == 0) return error.EmptyToken;
        if (token.len > max_token_len) return error.TokenTooLong;
    }

    fn validAccount(account: []const u8) bool {
        return account.len > 0 and account.len <= max_account_len;
    }

    fn validToken(token: []const u8) bool {
        return token.len > 0 and token.len <= max_token_len;
    }
};

test "issue records a pending token" {
    var gate = ChallengeGate.init(std.testing.allocator);
    defer gate.deinit();

    try gate.issue("alice", "token-1");
    try std.testing.expect(gate.pending("alice"));
    try std.testing.expectEqual(@as(usize, 1), gate.pendingCount());
}

test "verify consumes only a matching token" {
    var gate = ChallengeGate.init(std.testing.allocator);
    defer gate.deinit();

    try gate.issue("bob", "expected");
    try std.testing.expect(!gate.verify("bob", "wrong"));
    try std.testing.expect(gate.pending("bob"));
    try std.testing.expect(gate.verify("bob", "expected"));
    try std.testing.expect(!gate.pending("bob"));
    try std.testing.expect(!gate.verify("bob", "expected"));
}

test "issuing again replaces the old token" {
    var gate = ChallengeGate.init(std.testing.allocator);
    defer gate.deinit();

    try gate.issue("carol", "first");
    try gate.issue("carol", "second");
    try std.testing.expect(!gate.verify("carol", "first"));
    try std.testing.expect(gate.verify("carol", "second"));
    try std.testing.expectEqual(@as(usize, 0), gate.pendingCount());
}

test "invalid account and token inputs are rejected" {
    var gate = ChallengeGate.init(std.testing.allocator);
    defer gate.deinit();

    try std.testing.expectError(error.EmptyAccount, gate.issue("", "token"));
    try std.testing.expectError(error.EmptyToken, gate.issue("delta", ""));
    try std.testing.expect(!gate.pending(""));
    try std.testing.expect(!gate.verify("delta", ""));
}

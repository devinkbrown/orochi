// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Network-level new-user onboarding pack.
//!
//! This module stores a single, ordered set of welcome lines (editable by
//! operators) plus a per-account record of which accounts have already been
//! sent the pack. Its purpose is one-time onboarding: a brand-new account
//! receives the pack exactly once on first login, never again on subsequent
//! logins or reconnects.
//!
//! This is deliberately distinct from per-channel on-join welcome messaging:
//!   * The pack is network-scoped, not keyed by channel.
//!   * The pack is an ordered sequence of lines, not a single message.
//!   * Delivery is tracked per account and is one-time, not per join/connect.
//!
//! The module owns every string it stores and frees them on `deinit`. Message
//! delivery (the actual NOTICE/PRIVMSG send) and any persistence stay with the
//! caller; this module only tracks content and delivery state.

const std = @import("std");

/// Runtime bounds for the onboarding pack and its delivery ledger.
pub const Params = struct {
    /// Maximum number of lines the pack may hold.
    max_lines: usize = 64,
    /// Maximum byte length of any single welcome line.
    max_line_bytes: usize = 400,
    /// Maximum number of distinct accounts tracked as "delivered".
    max_accounts: usize = 1 << 20,
    /// Maximum byte length of an account name.
    max_account_bytes: usize = 128,
};

/// Errors returned while editing the pack or recording delivery.
pub const Error = std.mem.Allocator.Error || error{
    /// More lines were supplied than `Params.max_lines` permits.
    TooManyLines,
    /// A supplied line exceeded `Params.max_line_bytes`.
    LineTooLong,
    /// A supplied line was empty.
    EmptyLine,
    /// The account name was empty.
    InvalidAccount,
    /// The account name exceeded `Params.max_account_bytes`.
    AccountTooLong,
    /// The delivery ledger is full (`Params.max_accounts`).
    TooManyAccounts,
};

/// Stores the onboarding pack content and the per-account delivery ledger.
///
/// All stored strings are owned by the pack. Call `deinit` to release them.
pub const WelcomePack = struct {
    allocator: std.mem.Allocator,
    params: Params,
    /// Ordered, owned welcome lines.
    pack_lines: std.ArrayList([]u8) = .empty,
    /// Set of accounts that have already received the pack. Keys are owned.
    delivered: std.StringHashMapUnmanaged(void) = .empty,

    /// Create an empty pack with default bounds.
    pub fn init(allocator: std.mem.Allocator) WelcomePack {
        return initParams(allocator, .{});
    }

    /// Create an empty pack with caller-supplied bounds.
    pub fn initParams(allocator: std.mem.Allocator, params: Params) WelcomePack {
        return .{ .allocator = allocator, .params = params };
    }

    /// Release every owned line and delivery key, then reset to empty.
    pub fn deinit(self: *WelcomePack) void {
        self.freeLines();
        self.pack_lines.deinit(self.allocator);

        var it = self.delivered.keyIterator();
        while (it.next()) |key| {
            self.allocator.free(key.*);
        }
        self.delivered.deinit(self.allocator);

        self.* = WelcomePack.initParams(self.allocator, self.params);
    }

    /// Replace the entire ordered pack with `new_lines`.
    ///
    /// On success the pack owns independent copies of every line. On any error
    /// the previous pack content is left untouched and no copies leak. Passing
    /// an empty slice clears the pack.
    pub fn setLines(self: *WelcomePack, new_lines: []const []const u8) Error!void {
        if (new_lines.len > self.params.max_lines) return error.TooManyLines;
        for (new_lines) |line| {
            if (line.len == 0) return error.EmptyLine;
            if (line.len > self.params.max_line_bytes) return error.LineTooLong;
        }

        // Build the replacement in a scratch list so a mid-way allocation
        // failure cannot corrupt or partially replace the live pack.
        var staged: std.ArrayList([]u8) = .empty;
        errdefer {
            for (staged.items) |line| self.allocator.free(line);
            staged.deinit(self.allocator);
        }
        try staged.ensureTotalCapacity(self.allocator, new_lines.len);
        for (new_lines) |line| {
            const copy = try self.allocator.dupe(u8, line);
            staged.appendAssumeCapacity(copy);
        }

        self.freeLines();
        self.pack_lines.deinit(self.allocator);
        self.pack_lines = staged;
    }

    /// Return the current ordered pack lines.
    ///
    /// The returned slice and its strings are owned by the pack and remain
    /// valid until the next mutating call (`setLines`/`deinit`). Callers must
    /// not free them.
    pub fn lines(self: *const WelcomePack) []const []const u8 {
        return @ptrCast(self.pack_lines.items);
    }

    /// Number of lines currently in the pack.
    pub fn lineCount(self: *const WelcomePack) usize {
        return self.pack_lines.items.len;
    }

    /// Record that `account` has received the onboarding pack.
    ///
    /// Idempotent: marking an already-delivered account succeeds without
    /// storing a duplicate. The first successful mark for an account copies the
    /// account name into pack-owned storage.
    pub fn markDelivered(self: *WelcomePack, account: []const u8) Error!void {
        try validateAccount(account, self.params);
        if (self.delivered.contains(account)) return;
        if (self.delivered.count() >= self.params.max_accounts) {
            return error.TooManyAccounts;
        }

        const key = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(key);
        try self.delivered.put(self.allocator, key, {});
    }

    /// Report whether `account` has already received the pack.
    pub fn wasDelivered(self: *const WelcomePack, account: []const u8) bool {
        return self.delivered.contains(account);
    }

    /// Number of accounts recorded as having received the pack.
    pub fn deliveredCount(self: *const WelcomePack) usize {
        return self.delivered.count();
    }

    /// Convenience: if `account` has not yet received the pack and the pack is
    /// non-empty, mark it delivered and return the lines to send. Returns null
    /// when the account was already served or the pack is empty, so the caller
    /// sends nothing.
    ///
    /// This makes "exactly once per account" a single atomic step for the
    /// common first-login path. The returned slice is pack-owned (see `lines`).
    pub fn deliverOnce(self: *WelcomePack, account: []const u8) Error!?[]const []const u8 {
        try validateAccount(account, self.params);
        if (self.pack_lines.items.len == 0) return null;
        if (self.delivered.contains(account)) return null;
        try self.markDelivered(account);
        return self.lines();
    }

    /// Forget that `account` received the pack, e.g. when an account is
    /// deleted. Returns true if a record was removed.
    pub fn forget(self: *WelcomePack, account: []const u8) bool {
        if (self.delivered.fetchRemove(account)) |kv| {
            self.allocator.free(kv.key);
            return true;
        }
        return false;
    }

    fn freeLines(self: *WelcomePack) void {
        for (self.pack_lines.items) |line| self.allocator.free(line);
        self.pack_lines.clearRetainingCapacity();
    }

    fn validateAccount(account: []const u8, params: Params) Error!void {
        if (account.len == 0) return error.InvalidAccount;
        if (account.len > params.max_account_bytes) return error.AccountTooLong;
    }
};

test "pack starts empty" {
    var pack = WelcomePack.init(std.testing.allocator);
    defer pack.deinit();

    try std.testing.expectEqual(@as(usize, 0), pack.lineCount());
    try std.testing.expectEqual(@as(usize, 0), pack.deliveredCount());
    try std.testing.expectEqual(@as(usize, 0), pack.lines().len);
}

test "setLines stores ordered owned copies" {
    var pack = WelcomePack.init(std.testing.allocator);
    defer pack.deinit();

    try pack.setLines(&.{ "Welcome aboard.", "Read the rules.", "Have fun." });

    const got = pack.lines();
    try std.testing.expectEqual(@as(usize, 3), got.len);
    try std.testing.expectEqualStrings("Welcome aboard.", got[0]);
    try std.testing.expectEqualStrings("Read the rules.", got[1]);
    try std.testing.expectEqualStrings("Have fun.", got[2]);
}

test "setLines copies are independent of caller buffer" {
    var pack = WelcomePack.init(std.testing.allocator);
    defer pack.deinit();

    var buf = [_]u8{ 'h', 'i' };
    try pack.setLines(&.{&buf});
    buf[0] = 'X';

    try std.testing.expectEqualStrings("hi", pack.lines()[0]);
}

test "setLines replaces previous content without leaking" {
    var pack = WelcomePack.init(std.testing.allocator);
    defer pack.deinit();

    try pack.setLines(&.{ "old one", "old two", "old three" });
    try pack.setLines(&.{"only new"});

    try std.testing.expectEqual(@as(usize, 1), pack.lineCount());
    try std.testing.expectEqualStrings("only new", pack.lines()[0]);
}

test "setLines with empty slice clears the pack" {
    var pack = WelcomePack.init(std.testing.allocator);
    defer pack.deinit();

    try pack.setLines(&.{"something"});
    try pack.setLines(&.{});
    try std.testing.expectEqual(@as(usize, 0), pack.lineCount());
}

test "setLines rejects too many lines and keeps old content" {
    var pack = WelcomePack.initParams(std.testing.allocator, .{ .max_lines = 2 });
    defer pack.deinit();

    try pack.setLines(&.{"keep me"});
    try std.testing.expectError(
        error.TooManyLines,
        pack.setLines(&.{ "a", "b", "c" }),
    );
    // Previous content survives a rejected replacement.
    try std.testing.expectEqual(@as(usize, 1), pack.lineCount());
    try std.testing.expectEqualStrings("keep me", pack.lines()[0]);
}

test "setLines rejects overlong and empty lines" {
    var pack = WelcomePack.initParams(std.testing.allocator, .{ .max_line_bytes = 8 });
    defer pack.deinit();

    try std.testing.expectError(error.LineTooLong, pack.setLines(&.{"123456789"}));
    try std.testing.expectError(error.EmptyLine, pack.setLines(&.{""}));
    try std.testing.expectEqual(@as(usize, 0), pack.lineCount());
}

test "markDelivered then wasDelivered is once-only" {
    var pack = WelcomePack.init(std.testing.allocator);
    defer pack.deinit();

    try std.testing.expect(!pack.wasDelivered("alice"));
    try pack.markDelivered("alice");
    try std.testing.expect(pack.wasDelivered("alice"));

    // Idempotent re-mark: no error, no duplicate.
    try pack.markDelivered("alice");
    try std.testing.expectEqual(@as(usize, 1), pack.deliveredCount());

    try std.testing.expect(!pack.wasDelivered("bob"));
}

test "markDelivered rejects invalid accounts" {
    var pack = WelcomePack.initParams(std.testing.allocator, .{ .max_account_bytes = 4 });
    defer pack.deinit();

    try std.testing.expectError(error.InvalidAccount, pack.markDelivered(""));
    try std.testing.expectError(error.AccountTooLong, pack.markDelivered("toolong"));
}

test "markDelivered enforces account ledger bound" {
    var pack = WelcomePack.initParams(std.testing.allocator, .{ .max_accounts = 2 });
    defer pack.deinit();

    try pack.markDelivered("a");
    try pack.markDelivered("b");
    try std.testing.expectError(error.TooManyAccounts, pack.markDelivered("c"));
    // Re-marking an existing account still works at the bound.
    try pack.markDelivered("a");
}

test "deliverOnce sends pack exactly once per account" {
    var pack = WelcomePack.init(std.testing.allocator);
    defer pack.deinit();

    try pack.setLines(&.{ "line 1", "line 2" });

    const first = try pack.deliverOnce("carol");
    try std.testing.expect(first != null);
    try std.testing.expectEqual(@as(usize, 2), first.?.len);
    try std.testing.expectEqualStrings("line 1", first.?[0]);

    // Second attempt for the same account delivers nothing.
    const second = try pack.deliverOnce("carol");
    try std.testing.expect(second == null);

    // A different new account still gets it.
    const other = try pack.deliverOnce("dave");
    try std.testing.expect(other != null);
}

test "deliverOnce returns null for empty pack and does not mark" {
    var pack = WelcomePack.init(std.testing.allocator);
    defer pack.deinit();

    const result = try pack.deliverOnce("erin");
    try std.testing.expect(result == null);
    // Account must not be consumed when nothing was sent.
    try std.testing.expect(!pack.wasDelivered("erin"));
    try std.testing.expectEqual(@as(usize, 0), pack.deliveredCount());
}

test "forget removes a delivery record" {
    var pack = WelcomePack.init(std.testing.allocator);
    defer pack.deinit();

    try pack.setLines(&.{"hi"});
    try pack.markDelivered("frank");
    try std.testing.expect(pack.forget("frank"));
    try std.testing.expect(!pack.forget("frank"));
    try std.testing.expect(!pack.wasDelivered("frank"));

    // After forgetting, the pack can be delivered again.
    const again = try pack.deliverOnce("frank");
    try std.testing.expect(again != null);
}

test "deinit frees lines and delivery keys without leaks" {
    var pack = WelcomePack.init(std.testing.allocator);
    try pack.setLines(&.{ "alpha", "beta", "gamma" });
    try pack.markDelivered("one");
    try pack.markDelivered("two");
    pack.deinit();
    // std.testing.allocator asserts no leaks at test teardown.
}

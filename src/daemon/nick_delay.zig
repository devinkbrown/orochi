// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Nick-delay registry: holds a recently released nick for a configured window
//! so it cannot be grabbed by a hijacker the instant its owner drops (the
//! classic "nick camping" race, and services-bypass during netsplits/quits).
//!
//! A nick is held when its owner exits (disconnect / QUIT). During the hold:
//!   - the owning account (when the releaser was authenticated) may reclaim it,
//!   - server operators bypass the hold entirely,
//!   - a connection-class flagged `nick_delay_exempt` bypasses it,
//!   - everyone else is refused until the hold expires.
//!
//! Pure: it reads no clock and touches no sockets — the caller supplies `now`
//! (monotonic ms). Nick keys are folded to ASCII lowercase, matching the
//! daemon's RFC1459-ish case-insensitive nick comparison.

const std = @import("std");

pub const NickDelay = struct {
    allocator: std.mem.Allocator,
    held: std.StringHashMapUnmanaged(Entry) = .empty,

    pub const Entry = struct {
        /// Monotonic-ms deadline; the hold lapses once `now >= expires_ms`.
        expires_ms: i64,
        /// Owning account (owned copy), or null when the releasing user was
        /// anonymous. Only this account may reclaim the nick during the hold.
        owner: ?[]u8,
    };

    /// A live hold, returned by `check`. `owner` is null for an anonymous holder.
    pub const Held = struct { owner: ?[]const u8 };

    /// Longest nick handled (the daemon NICKLEN ceiling). Anything longer is
    /// never a valid nick, so it is never held.
    pub const max_nick = 64;

    pub fn init(allocator: std.mem.Allocator) NickDelay {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *NickDelay) void {
        var it = self.held.iterator();
        while (it.next()) |e| {
            self.allocator.free(e.key_ptr.*);
            if (e.value_ptr.owner) |o| self.allocator.free(o);
        }
        self.held.deinit(self.allocator);
        self.* = undefined;
    }

    /// Fold `nick` to ASCII lowercase into `buf`; null if empty or too long.
    fn fold(buf: []u8, nick: []const u8) ?[]const u8 {
        if (nick.len == 0 or nick.len > buf.len) return null;
        for (nick, 0..) |c, i| buf[i] = std.ascii.toLower(c);
        return buf[0..nick.len];
    }

    /// Hold `nick` until `expires_ms`, recording `owner` (account) when any.
    /// Replaces any prior hold for the same (case-insensitive) nick.
    pub fn hold(self: *NickDelay, nick: []const u8, expires_ms: i64, owner: ?[]const u8) !void {
        var kb: [max_nick]u8 = undefined;
        const key = fold(&kb, nick) orelse return;

        const owner_copy: ?[]u8 = if (owner) |o| try self.allocator.dupe(u8, o) else null;
        errdefer if (owner_copy) |o| self.allocator.free(o);

        if (self.held.getPtr(key)) |e| {
            if (e.owner) |old| self.allocator.free(old);
            e.* = .{ .expires_ms = expires_ms, .owner = owner_copy };
            return;
        }
        const key_copy = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(key_copy);
        try self.held.put(self.allocator, key_copy, .{ .expires_ms = expires_ms, .owner = owner_copy });
    }

    /// The live hold for `nick` at `now`, or null when it is not held. An expired
    /// entry is evicted in passing. The returned `owner` slice is valid until the
    /// next mutation of this registry.
    pub fn check(self: *NickDelay, nick: []const u8, now: i64) ?Held {
        var kb: [max_nick]u8 = undefined;
        const key = fold(&kb, nick) orelse return null;
        const e = self.held.getPtr(key) orelse return null;
        if (now >= e.expires_ms) {
            self.releaseKey(key);
            return null;
        }
        return .{ .owner = e.owner };
    }

    /// Explicitly drop any hold for `nick` (a legitimate reclaim / re-register).
    pub fn release(self: *NickDelay, nick: []const u8) void {
        var kb: [max_nick]u8 = undefined;
        const key = fold(&kb, nick) orelse return;
        self.releaseKey(key);
    }

    fn releaseKey(self: *NickDelay, key: []const u8) void {
        if (self.held.fetchRemove(key)) |kv| {
            self.allocator.free(kv.key);
            if (kv.value.owner) |o| self.allocator.free(o);
        }
    }

    /// Evict entries expired at `now` (up to a bounded batch; the remainder is
    /// reclaimed on the next call). Returns the number removed. Called from the
    /// periodic timeout sweep so churned nicks do not accumulate.
    pub fn sweep(self: *NickDelay, now: i64) usize {
        var batch: [64][]const u8 = undefined;
        var n: usize = 0;
        var it = self.held.iterator();
        while (it.next()) |e| {
            if (now >= e.value_ptr.expires_ms) {
                batch[n] = e.key_ptr.*;
                n += 1;
                if (n == batch.len) break;
            }
        }
        for (batch[0..n]) |k| self.releaseKey(k);
        return n;
    }

    /// Number of nicks currently held (includes not-yet-swept expired entries).
    pub fn count(self: *const NickDelay) usize {
        return self.held.count();
    }
};

// -- Tests -------------------------------------------------------------------

test "held nick is reported within the window and evicted after it lapses" {
    var nd = NickDelay.init(std.testing.allocator);
    defer nd.deinit();

    try nd.hold("Alice", 1000, null);
    // Case-insensitive: "alice" matches the held "Alice".
    try std.testing.expect(nd.check("alice", 500) != null);
    // At/after the deadline the hold lapses and is evicted in passing.
    try std.testing.expect(nd.check("alice", 1000) == null);
    try std.testing.expectEqual(@as(usize, 0), nd.count());
}

test "owner account is recorded and returned for reclaim checks" {
    var nd = NickDelay.init(std.testing.allocator);
    defer nd.deinit();

    try nd.hold("Bob", 2000, "bob-acct");
    const h = nd.check("bob", 100) orelse return error.TestUnexpectedResult;
    try std.testing.expect(h.owner != null);
    try std.testing.expectEqualStrings("bob-acct", h.owner.?);
}

test "explicit release drops the hold immediately" {
    var nd = NickDelay.init(std.testing.allocator);
    defer nd.deinit();

    try nd.hold("Carol", 5000, "carol");
    nd.release("CAROL");
    try std.testing.expect(nd.check("carol", 0) == null);
    try std.testing.expectEqual(@as(usize, 0), nd.count());
}

test "hold replaces a prior entry and frees the old owner" {
    var nd = NickDelay.init(std.testing.allocator);
    defer nd.deinit();

    try nd.hold("Dave", 1000, "old-acct");
    try nd.hold("dave", 9000, "new-acct"); // same nick, new deadline + owner
    try std.testing.expectEqual(@as(usize, 1), nd.count());
    const h = nd.check("Dave", 8000) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("new-acct", h.owner.?);
}

test "sweep evicts only the expired entries" {
    var nd = NickDelay.init(std.testing.allocator);
    defer nd.deinit();

    try nd.hold("aaa", 100, null);
    try nd.hold("bbb", 100, null);
    try nd.hold("ccc", 9000, null);
    const removed = nd.sweep(500);
    try std.testing.expectEqual(@as(usize, 2), removed);
    try std.testing.expectEqual(@as(usize, 1), nd.count());
    try std.testing.expect(nd.check("ccc", 500) != null);
}

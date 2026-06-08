//! S2S session migration — the capsule a node ships to a peer to hand off a live
//! client session, plus the receiving node's holding area.
//!
//! Unlike a hot UPGRADE (same machine, the socket fd is inherited), an S2S
//! migration crosses processes/machines: the fd CANNOT move, so the client
//! reconnects to the target node and RECLAIMS its session by token. This module
//! is the data layer for that:
//!
//!   * `Capsule` — token + account + a `session_snapshot` blob (nick/account/
//!     hosts/away/oper/channels). The `fd` inside the snapshot is meaningless
//!     across machines and ignored on reclaim.
//!   * `PendingMigrations` — the target node's holding area: token -> (account,
//!     snapshot), inserted when the capsule arrives and consumed when the client
//!     reconnects with that token. Pairs with `sessions.SessionStore` (which
//!     tracks the reclaimable detached session) — this holds the state to restore.
//!
//! Transport-agnostic: the capsule rides whatever carries it (S2S relay frame,
//! conduit, ...). Wiring it onto the live S2S link + the reclaim path are later
//! slices.
const std = @import("std");

pub const Token = [16]u8;
pub const Error = error{ Truncated, TooLong };

/// A migrated session in flight: who it is + its serialized state.
pub const Capsule = struct {
    token: Token,
    account: []const u8,
    /// A `session_snapshot.encode` blob (borrowed on decode).
    snapshot: []const u8,
};

/// Wire: [16 token][u16 account_len][account][u32 snap_len][snapshot]
pub fn encode(allocator: std.mem.Allocator, cap: Capsule) (Error || std.mem.Allocator.Error)![]u8 {
    if (cap.account.len > std.math.maxInt(u16)) return error.TooLong;
    if (cap.snapshot.len > std.math.maxInt(u32)) return error.TooLong;
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, &cap.token);
    var alen: [2]u8 = undefined;
    std.mem.writeInt(u16, &alen, @intCast(cap.account.len), .little);
    try out.appendSlice(allocator, &alen);
    try out.appendSlice(allocator, cap.account);
    var slen: [4]u8 = undefined;
    std.mem.writeInt(u32, &slen, @intCast(cap.snapshot.len), .little);
    try out.appendSlice(allocator, &slen);
    try out.appendSlice(allocator, cap.snapshot);
    return out.toOwnedSlice(allocator);
}

/// Decode a capsule, returning views that borrow `bytes`.
pub fn decode(bytes: []const u8) Error!Capsule {
    if (bytes.len < 16 + 2) return error.Truncated;
    var token: Token = undefined;
    @memcpy(&token, bytes[0..16]);
    var pos: usize = 16;
    const alen = std.mem.readInt(u16, bytes[pos..][0..2], .little);
    pos += 2;
    if (pos + alen + 4 > bytes.len) return error.Truncated;
    const account = bytes[pos .. pos + alen];
    pos += alen;
    const slen = std.mem.readInt(u32, bytes[pos..][0..4], .little);
    pos += 4;
    if (pos + slen > bytes.len) return error.Truncated;
    const snapshot = bytes[pos .. pos + slen];
    return .{ .token = token, .account = account, .snapshot = snapshot };
}

/// Target-node holding area: migrated sessions awaiting the client's reconnect.
pub const PendingMigrations = struct {
    allocator: std.mem.Allocator,
    map: std.AutoHashMapUnmanaged(Token, Entry) = .empty,

    pub const Entry = struct {
        account: []u8,
        snapshot: []u8,
    };

    pub fn init(allocator: std.mem.Allocator) PendingMigrations {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *PendingMigrations) void {
        var it = self.map.valueIterator();
        while (it.next()) |e| {
            self.allocator.free(e.account);
            self.allocator.free(e.snapshot);
        }
        self.map.deinit(self.allocator);
    }

    /// Store a freshly-arrived capsule (copies the account + snapshot). Replaces
    /// any existing entry for the same token (freeing the old).
    pub fn put(self: *PendingMigrations, cap: Capsule) std.mem.Allocator.Error!void {
        const account = try self.allocator.dupe(u8, cap.account);
        errdefer self.allocator.free(account);
        const snapshot = try self.allocator.dupe(u8, cap.snapshot);
        errdefer self.allocator.free(snapshot);
        const gop = try self.map.getOrPut(self.allocator, cap.token);
        if (gop.found_existing) {
            self.allocator.free(gop.value_ptr.account);
            self.allocator.free(gop.value_ptr.snapshot);
        }
        gop.value_ptr.* = .{ .account = account, .snapshot = snapshot };
    }

    /// Whether a migrated session is waiting for `token`.
    pub fn has(self: *const PendingMigrations, token: Token) bool {
        return self.map.contains(token);
    }

    /// Remove and return the migrated session for `token` (caller owns the slices;
    /// release with `freeEntry`). Null if none — the client reclaims on reconnect.
    pub fn take(self: *PendingMigrations, token: Token) ?Entry {
        const e = self.map.fetchRemove(token) orelse return null;
        return e.value;
    }

    pub fn freeEntry(self: *PendingMigrations, e: Entry) void {
        self.allocator.free(e.account);
        self.allocator.free(e.snapshot);
    }

    pub fn count(self: *const PendingMigrations) usize {
        return self.map.count();
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "migration capsule encode/decode round-trips" {
    const allocator = testing.allocator;
    const token: Token = .{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    const cap = Capsule{ .token = token, .account = "alice", .snapshot = "snap-bytes-here" };
    const bytes = try encode(allocator, cap);
    defer allocator.free(bytes);

    const got = try decode(bytes);
    try testing.expectEqualSlices(u8, &token, &got.token);
    try testing.expectEqualStrings("alice", got.account);
    try testing.expectEqualStrings("snap-bytes-here", got.snapshot);
}

test "decode rejects truncated input" {
    try testing.expectError(error.Truncated, decode(&[_]u8{ 1, 2, 3 }));
    // valid token + account-len claiming more than present
    var buf: [20]u8 = .{0} ** 20;
    buf[16] = 50; // account_len = 50, but no bytes follow
    try testing.expectError(error.Truncated, decode(&buf));
}

test "PendingMigrations stores, finds, and consumes by token" {
    const allocator = testing.allocator;
    var pm = PendingMigrations.init(allocator);
    defer pm.deinit();

    const t1: Token = .{0} ** 15 ++ .{1};
    const t2: Token = .{0} ** 15 ++ .{2};
    try pm.put(.{ .token = t1, .account = "alice", .snapshot = "A" });
    try pm.put(.{ .token = t2, .account = "bob", .snapshot = "BB" });
    try testing.expectEqual(@as(usize, 2), pm.count());
    try testing.expect(pm.has(t1));

    const e = pm.take(t1) orelse return error.TestUnexpectedResult;
    defer pm.freeEntry(e);
    try testing.expectEqualStrings("alice", e.account);
    try testing.expectEqualStrings("A", e.snapshot);
    try testing.expect(!pm.has(t1)); // consumed
    try testing.expect(pm.take(t1) == null);
    try testing.expectEqual(@as(usize, 1), pm.count()); // bob remains
}

test "put replaces an existing token without leaking" {
    const allocator = testing.allocator;
    var pm = PendingMigrations.init(allocator);
    defer pm.deinit();
    const t: Token = .{9} ** 16;
    try pm.put(.{ .token = t, .account = "old", .snapshot = "x" });
    try pm.put(.{ .token = t, .account = "new", .snapshot = "yy" });
    try testing.expectEqual(@as(usize, 1), pm.count());
    const e = pm.take(t).?;
    defer pm.freeEntry(e);
    try testing.expectEqualStrings("new", e.account);
}

// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Reserved nickname registry for the Orochi IRC daemon.
//!
//! Maps a reserved nickname to the account that owns it. Nickname comparison
//! is case-insensitive (folded to lowercase ASCII), so `Spirit`, `spirit`, and
//! `SPIRIT` all refer to the same reservation.

const std = @import("std");

/// Maximum length (in bytes) for a single nickname or account name. Used to
/// bound the temporary fold buffer on the stack instead of heap-allocating.
const max_name_len: usize = 64;

/// Registry mapping case-insensitive nicknames to their owning account.
///
/// Keys are heap-owned lowercased nickname copies; values are heap-owned copies
/// of the original (case-preserving) account string. Both are freed on `deinit`.
pub const ReservedNick = struct {
    allocator: std.mem.Allocator,
    /// lowercased nick -> owned account name
    map: std.StringHashMap([]u8),

    /// Initialize an empty registry backed by `allocator`.
    pub fn init(allocator: std.mem.Allocator) ReservedNick {
        return .{
            .allocator = allocator,
            .map = std.StringHashMap([]u8).init(allocator),
        };
    }

    /// Free every owned key and value, then the backing map.
    pub fn deinit(self: *ReservedNick) void {
        var it = self.map.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.map.deinit();
    }

    /// Fold an ASCII nickname to lowercase into `buf`, returning the slice.
    /// Returns `error.NameTooLong` if `name` exceeds `max_name_len`.
    fn foldInto(name: []const u8, buf: []u8) error{NameTooLong}![]u8 {
        if (name.len > buf.len) return error.NameTooLong;
        for (name, 0..) |c, i| {
            buf[i] = std.ascii.toLower(c);
        }
        return buf[0..name.len];
    }

    /// Reserve `nick` for `account`.
    ///
    /// Returns `true` if the nick was newly reserved, or if it was already
    /// reserved by the SAME account (re-affirmation is idempotent).
    /// Returns `false` if it is already reserved by a DIFFERENT account.
    pub fn reserve(self: *ReservedNick, nick: []const u8, account: []const u8) !bool {
        var fold_buf: [max_name_len]u8 = undefined;
        const folded = try foldInto(nick, &fold_buf);

        if (self.map.get(folded)) |existing| {
            // Already reserved: only the current owner re-affirms successfully.
            return std.mem.eql(u8, existing, account);
        }

        // New reservation: own copies of both key and value.
        const key = try self.allocator.dupe(u8, folded);
        errdefer self.allocator.free(key);

        const value = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(value);

        try self.map.put(key, value);
        return true;
    }

    /// Release `nick` if and only if `account` is its current owner.
    ///
    /// Returns `true` if the reservation was removed; `false` if the nick was
    /// not reserved or is owned by a different account.
    pub fn release(self: *ReservedNick, nick: []const u8, account: []const u8) bool {
        var fold_buf: [max_name_len]u8 = undefined;
        const folded = foldInto(nick, &fold_buf) catch return false;

        const entry = self.map.getEntry(folded) orelse return false;
        if (!std.mem.eql(u8, entry.value_ptr.*, account)) return false;

        const owned_key = entry.key_ptr.*;
        const owned_value = entry.value_ptr.*;
        _ = self.map.remove(folded);
        self.allocator.free(owned_key);
        self.allocator.free(owned_value);
        return true;
    }

    /// Return the owning account for `nick`, or `null` if not reserved.
    /// The returned slice is owned by the registry and valid until the
    /// reservation is released or the registry is deinitialized.
    pub fn ownerOf(self: *const ReservedNick, nick: []const u8) ?[]const u8 {
        var fold_buf: [max_name_len]u8 = undefined;
        const folded = foldInto(nick, &fold_buf) catch return null;
        return self.map.get(folded);
    }

    /// Return whether `nick` is currently reserved.
    pub fn isReserved(self: *const ReservedNick, nick: []const u8) bool {
        return self.ownerOf(nick) != null;
    }
};

test "reserve records owner and reports reservation" {
    var registry = ReservedNick.init(std.testing.allocator);
    defer registry.deinit();

    try std.testing.expect(try registry.reserve("Spirit", "acct-1"));
    try std.testing.expect(registry.isReserved("Spirit"));
    try std.testing.expectEqualStrings("acct-1", registry.ownerOf("Spirit").?);

    // Re-affirmation by the same account is idempotent and returns true.
    try std.testing.expect(try registry.reserve("Spirit", "acct-1"));
    try std.testing.expect(registry.isReserved("Spirit"));
}

test "conflict: a different account cannot reserve a taken nick" {
    var registry = ReservedNick.init(std.testing.allocator);
    defer registry.deinit();

    try std.testing.expect(try registry.reserve("Drake", "owner"));
    try std.testing.expect(!try registry.reserve("Drake", "intruder"));

    // Owner is unchanged after the failed conflicting reservation.
    try std.testing.expectEqualStrings("owner", registry.ownerOf("Drake").?);
}

test "release only succeeds for the owning account" {
    var registry = ReservedNick.init(std.testing.allocator);
    defer registry.deinit();

    try std.testing.expect(try registry.reserve("Tide", "captain"));

    // Non-owner cannot release.
    try std.testing.expect(!registry.release("Tide", "stowaway"));
    try std.testing.expect(registry.isReserved("Tide"));

    // Owner releases successfully.
    try std.testing.expect(registry.release("Tide", "captain"));
    try std.testing.expect(!registry.isReserved("Tide"));
    try std.testing.expect(registry.ownerOf("Tide") == null);

    // Releasing an unreserved nick returns false.
    try std.testing.expect(!registry.release("Tide", "captain"));
}

test "nick comparison is case-insensitive" {
    var registry = ReservedNick.init(std.testing.allocator);
    defer registry.deinit();

    try std.testing.expect(try registry.reserve("MoonGazer", "luna"));

    // All casings refer to the same reservation.
    try std.testing.expect(registry.isReserved("moongazer"));
    try std.testing.expect(registry.isReserved("MOONGAZER"));
    try std.testing.expect(registry.isReserved("mOoNgAzEr"));
    try std.testing.expectEqualStrings("luna", registry.ownerOf("MOONGAZER").?);

    // A conflicting reservation under different casing is rejected.
    try std.testing.expect(!try registry.reserve("moongazer", "imposter"));

    // The owner can release using a different casing than registration.
    try std.testing.expect(registry.release("MOONGAZER", "luna"));
    try std.testing.expect(!registry.isReserved("MoonGazer"));
}

test "independent reservations coexist without leaking" {
    var registry = ReservedNick.init(std.testing.allocator);
    defer registry.deinit();

    try std.testing.expect(try registry.reserve("Alpha", "a"));
    try std.testing.expect(try registry.reserve("Beta", "b"));
    try std.testing.expect(try registry.reserve("Gamma", "c"));

    try std.testing.expectEqualStrings("a", registry.ownerOf("alpha").?);
    try std.testing.expectEqualStrings("b", registry.ownerOf("beta").?);
    try std.testing.expectEqualStrings("c", registry.ownerOf("gamma").?);

    try std.testing.expect(registry.release("Beta", "b"));
    try std.testing.expect(!registry.isReserved("Beta"));
    try std.testing.expect(registry.isReserved("Alpha"));
    try std.testing.expect(registry.isReserved("Gamma"));
}

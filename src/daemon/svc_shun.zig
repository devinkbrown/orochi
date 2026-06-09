//! Network SHUN list.
//!
//! A SHUN silences a user network-wide: an operator adds a `nick!user@host`
//! glob mask and any message matching that mask is dropped, while the client
//! stays connected. This module owns only the in-memory store and matching
//! logic; the dispatch layer is responsible for translating SHUN/UNSHUN
//! commands and the actual message drop. The store is intentionally free of
//! daemon globals so it can be unit-tested in isolation, importing only `std`.
//!
//! Entries carry a glob mask, a human-readable reason, the setter's name, the
//! creation time, and an optional absolute expiry (both in epoch milliseconds).
//! Lookups skip entries whose expiry has passed; `sweep` permanently removes
//! them. The store owns every string it holds: `add` duplicates the caller's
//! slices and `remove`/`sweep`/`deinit` free them, so there are no leaks and
//! no aliasing of caller-owned memory.
//!
//! Glob semantics (ASCII, case-insensitive):
//!   * `*` matches zero or more arbitrary characters
//!   * `?` matches exactly one arbitrary character
//!   * every other byte matches itself, folded to lowercase
//!
//! The matcher is strictly iterative with a single backtrack anchor, giving
//! O(len(pattern) * len(text)) worst-case behavior with no recursion, so
//! adversarial masks such as `a*a*a*...` cannot blow the stack or hang.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// ASCII-only lowercase fold. Non-uppercase bytes pass through unchanged.
fn fold(c: u8) u8 {
    return if (c >= 'A' and c <= 'Z') c + 32 else c;
}

/// Case-insensitive (ASCII) glob match of `pattern` against `text`.
///
/// Supports `*` (zero or more) and `?` (exactly one). Iterative with a single
/// backtrack anchor; no recursion, no allocation.
pub fn matchGlob(pattern: []const u8, text: []const u8) bool {
    var p: usize = 0; // cursor into pattern
    var t: usize = 0; // cursor into text
    var star: ?usize = null; // pattern index just after the last '*'
    var star_t: usize = 0; // text index where that '*' began matching

    while (t < text.len) {
        if (p < pattern.len and (pattern[p] == '?' or fold(pattern[p]) == fold(text[t]))) {
            p += 1;
            t += 1;
        } else if (p < pattern.len and pattern[p] == '*') {
            star = p;
            star_t = t;
            p += 1;
        } else if (star) |s| {
            p = s + 1;
            star_t += 1;
            t = star_t;
        } else {
            return false;
        }
    }

    while (p < pattern.len and pattern[p] == '*') p += 1;
    return p == pattern.len;
}

/// A single network SHUN entry. All slices are owned by the parent `ShunList`.
pub const Entry = struct {
    /// Glob mask of the form `nick!user@host` (case-insensitive).
    mask: []const u8,
    /// Operator-supplied reason shown in listings.
    reason: []const u8,
    /// Name of the operator who set the SHUN.
    setter: []const u8,
    /// Creation time, epoch milliseconds.
    added_at: i64,
    /// Absolute expiry, epoch milliseconds. `null` means permanent.
    expires_at: ?i64,

    /// True if `now_ms` is at or past this entry's expiry.
    pub fn isExpired(self: Entry, now_ms: i64) bool {
        return if (self.expires_at) |exp| now_ms >= exp else false;
    }
};

/// In-memory network SHUN store. Not internally synchronized; the caller holds
/// whatever lock the daemon uses around it.
pub const ShunList = struct {
    allocator: Allocator,
    entries: std.ArrayList(Entry) = .empty,

    /// Upper bound on stored entries; `add` fails rather than growing without
    /// limit so a hostile or buggy oper script cannot exhaust memory.
    pub const max_entries: usize = 4096;

    pub const Error = error{ MaskTooLong, TooManyShuns } || Allocator.Error;

    /// Longest accepted mask. `nick!user@host` components are short in practice;
    /// this guards against pathological input.
    pub const max_mask_len: usize = 256;

    pub fn init(allocator: Allocator) ShunList {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *ShunList) void {
        for (self.entries.items) |entry| self.freeEntry(entry);
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    fn freeEntry(self: *ShunList, entry: Entry) void {
        self.allocator.free(entry.mask);
        self.allocator.free(entry.reason);
        self.allocator.free(entry.setter);
    }

    /// Number of entries currently stored (including any not yet swept).
    pub fn count(self: *const ShunList) usize {
        return self.entries.items.len;
    }

    /// Read-only view of the backing slice for listing.
    pub fn items(self: *const ShunList) []const Entry {
        return self.entries.items;
    }

    /// Add (or replace) a SHUN for `mask`.
    ///
    /// If an entry with the same mask already exists (case-insensitive), it is
    /// updated in place: this lets an oper refresh the reason or expiry without
    /// a separate remove. All strings are duplicated; the caller retains
    /// ownership of its inputs. `expires_at` is absolute epoch ms, or `null`
    /// for a permanent SHUN.
    pub fn add(
        self: *ShunList,
        mask: []const u8,
        reason: []const u8,
        setter: []const u8,
        added_at: i64,
        expires_at: ?i64,
    ) Error!void {
        if (mask.len == 0 or mask.len > max_mask_len) return Error.MaskTooLong;

        // Replace an existing entry with the same mask in place.
        if (self.findIndexByMask(mask)) |idx| {
            const new_reason = try self.allocator.dupe(u8, reason);
            errdefer self.allocator.free(new_reason);
            const new_setter = try self.allocator.dupe(u8, setter);

            const old = self.entries.items[idx];
            self.allocator.free(old.reason);
            self.allocator.free(old.setter);
            self.entries.items[idx] = .{
                .mask = old.mask, // mask string unchanged, keep it
                .reason = new_reason,
                .setter = new_setter,
                .added_at = added_at,
                .expires_at = expires_at,
            };
            return;
        }

        if (self.entries.items.len >= max_entries) return Error.TooManyShuns;

        const owned_mask = try self.allocator.dupe(u8, mask);
        errdefer self.allocator.free(owned_mask);
        const owned_reason = try self.allocator.dupe(u8, reason);
        errdefer self.allocator.free(owned_reason);
        const owned_setter = try self.allocator.dupe(u8, setter);
        errdefer self.allocator.free(owned_setter);

        try self.entries.append(self.allocator, .{
            .mask = owned_mask,
            .reason = owned_reason,
            .setter = owned_setter,
            .added_at = added_at,
            .expires_at = expires_at,
        });
    }

    /// Remove the SHUN whose mask matches `mask` exactly (case-insensitive).
    /// Returns true if an entry was removed.
    pub fn remove(self: *ShunList, mask: []const u8) bool {
        const idx = self.findIndexByMask(mask) orelse return false;
        const entry = self.entries.orderedRemove(idx);
        self.freeEntry(entry);
        return true;
    }

    /// Locate the index of an entry whose stored mask equals `mask`
    /// case-insensitively. Used for add-replace and remove.
    fn findIndexByMask(self: *const ShunList, mask: []const u8) ?usize {
        for (self.entries.items, 0..) |entry, idx| {
            if (eqlIgnoreCase(entry.mask, mask)) return idx;
        }
        return null;
    }

    /// Return the first non-expired entry whose mask matches the given
    /// `nick!user@host` `hostmask`, or `null` if the target is not shunned.
    /// Expired entries are skipped but left in place; call `sweep` to reclaim.
    pub fn isShunned(self: *const ShunList, hostmask: []const u8, now_ms: i64) ?Entry {
        for (self.entries.items) |entry| {
            if (entry.isExpired(now_ms)) continue;
            if (matchGlob(entry.mask, hostmask)) return entry;
        }
        return null;
    }

    /// Remove every entry that has expired as of `now_ms`. Returns the number
    /// removed. Iterates back-to-front so in-place removal stays O(n).
    pub fn sweep(self: *ShunList, now_ms: i64) usize {
        var removed: usize = 0;
        var i: usize = self.entries.items.len;
        while (i > 0) {
            i -= 1;
            if (self.entries.items[i].isExpired(now_ms)) {
                const entry = self.entries.orderedRemove(i);
                self.freeEntry(entry);
                removed += 1;
            }
        }
        return removed;
    }
};

/// ASCII case-insensitive slice equality.
fn eqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (fold(ca) != fold(cb)) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "matchGlob basic literal, star and question" {
    try testing.expect(matchGlob("abc", "abc"));
    try testing.expect(!matchGlob("abc", "abd"));
    try testing.expect(matchGlob("a*c", "axyzc"));
    try testing.expect(matchGlob("a?c", "abc"));
    try testing.expect(!matchGlob("a?c", "ac"));
    try testing.expect(matchGlob("*", "anything"));
    try testing.expect(matchGlob("*", ""));
    try testing.expect(matchGlob("", ""));
    try testing.expect(!matchGlob("", "x"));
}

test "matchGlob is case-insensitive" {
    try testing.expect(matchGlob("Nick!User@Host", "nick!user@host"));
    try testing.expect(matchGlob("*!*@HOST.EXAMPLE", "bob!b@host.example"));
}

test "matchGlob no catastrophic backtracking" {
    // Adversarial pattern must terminate quickly and correctly.
    const pat = "a*a*a*a*a*a*a*a*b";
    try testing.expect(!matchGlob(pat, "a" ** 64));
    try testing.expect(matchGlob(pat, "a" ** 64 ++ "b"));
}

test "add then isShunned matches hostmask" {
    var list = ShunList.init(testing.allocator);
    defer list.deinit();

    try list.add("bad!*@*", "spamming", "oper1", 1000, null);
    try testing.expectEqual(@as(usize, 1), list.count());

    const hit = list.isShunned("bad!user@host.example", 2000);
    try testing.expect(hit != null);
    try testing.expectEqualStrings("spamming", hit.?.reason);
    try testing.expectEqualStrings("oper1", hit.?.setter);

    try testing.expect(list.isShunned("good!user@host.example", 2000) == null);
}

test "isShunned skips expired entries" {
    var list = ShunList.init(testing.allocator);
    defer list.deinit();

    // Expires at 5000ms.
    try list.add("*!*@evil.net", "temp shun", "oper", 1000, 5000);

    // Before expiry: matches.
    try testing.expect(list.isShunned("x!y@evil.net", 4999) != null);
    // At/after expiry: skipped.
    try testing.expect(list.isShunned("x!y@evil.net", 5000) == null);
    try testing.expect(list.isShunned("x!y@evil.net", 9999) == null);

    // Still present until swept.
    try testing.expectEqual(@as(usize, 1), list.count());
}

test "permanent entry never expires" {
    var list = ShunList.init(testing.allocator);
    defer list.deinit();

    try list.add("perm!*@*", "forever", "oper", 0, null);
    try testing.expect(list.isShunned("perm!u@h", std.math.maxInt(i64)) != null);
}

test "remove deletes matching entry and frees strings" {
    var list = ShunList.init(testing.allocator);
    defer list.deinit();

    try list.add("a!*@*", "r1", "o1", 1, null);
    try list.add("b!*@*", "r2", "o2", 1, null);
    try testing.expectEqual(@as(usize, 2), list.count());

    try testing.expect(list.remove("A!*@*")); // case-insensitive
    try testing.expectEqual(@as(usize, 1), list.count());
    try testing.expect(list.isShunned("a!u@h", 100) == null);
    try testing.expect(list.isShunned("b!u@h", 100) != null);

    try testing.expect(!list.remove("missing!*@*"));
}

test "add replaces existing mask in place without leaking" {
    var list = ShunList.init(testing.allocator);
    defer list.deinit();

    try list.add("dup!*@*", "first", "oper1", 1000, 2000);
    try list.add("DUP!*@*", "second", "oper2", 3000, null); // same mask, new data
    try testing.expectEqual(@as(usize, 1), list.count());

    const hit = list.isShunned("dup!u@h", std.math.maxInt(i64)).?;
    try testing.expectEqualStrings("second", hit.reason);
    try testing.expectEqualStrings("oper2", hit.setter);
    try testing.expectEqual(@as(i64, 3000), hit.added_at);
    try testing.expect(hit.expires_at == null);
}

test "sweep removes only expired entries and frees them" {
    var list = ShunList.init(testing.allocator);
    defer list.deinit();

    try list.add("p!*@*", "perm", "o", 0, null);
    try list.add("e1!*@*", "exp1", "o", 0, 1000);
    try list.add("e2!*@*", "exp2", "o", 0, 2000);
    try list.add("future!*@*", "later", "o", 0, 9000);
    try testing.expectEqual(@as(usize, 4), list.count());

    const removed = list.sweep(2500);
    try testing.expectEqual(@as(usize, 2), removed); // e1 and e2
    try testing.expectEqual(@as(usize, 2), list.count());

    try testing.expect(list.isShunned("p!u@h", 2500) != null);
    try testing.expect(list.isShunned("future!u@h", 2500) != null);
    try testing.expect(list.isShunned("e1!u@h", 2500) == null);
}

test "sweep on empty and all-permanent lists removes nothing" {
    var list = ShunList.init(testing.allocator);
    defer list.deinit();

    try testing.expectEqual(@as(usize, 0), list.sweep(1000));

    try list.add("a!*@*", "r", "o", 0, null);
    try list.add("b!*@*", "r", "o", 0, null);
    try testing.expectEqual(@as(usize, 0), list.sweep(std.math.maxInt(i64)));
    try testing.expectEqual(@as(usize, 2), list.count());
}

test "add rejects empty and oversized masks" {
    var list = ShunList.init(testing.allocator);
    defer list.deinit();

    try testing.expectError(error.MaskTooLong, list.add("", "r", "o", 0, null));

    const big = "a" ** (ShunList.max_mask_len + 1);
    try testing.expectError(error.MaskTooLong, list.add(big, "r", "o", 0, null));
}

test "add enforces max_entries cap" {
    var list = ShunList.init(testing.allocator);
    defer list.deinit();

    var buf: [32]u8 = undefined;
    var i: usize = 0;
    while (i < ShunList.max_entries) : (i += 1) {
        const mask = try std.fmt.bufPrint(&buf, "n{d}!*@*", .{i});
        try list.add(mask, "r", "o", 0, null);
    }
    try testing.expectEqual(ShunList.max_entries, list.count());
    try testing.expectError(error.TooManyShuns, list.add("overflow!*@*", "r", "o", 0, null));
}

test "Entry.isExpired boundary" {
    const e_perm = Entry{ .mask = "x", .reason = "", .setter = "", .added_at = 0, .expires_at = null };
    try testing.expect(!e_perm.isExpired(std.math.maxInt(i64)));

    const e_temp = Entry{ .mask = "x", .reason = "", .setter = "", .added_at = 0, .expires_at = 100 };
    try testing.expect(!e_temp.isExpired(99));
    try testing.expect(e_temp.isExpired(100)); // expiry is inclusive
    try testing.expect(e_temp.isExpired(101));
}

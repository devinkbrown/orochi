//! JUPE / forbid store.
//!
//! An oper forbids a nick or channel name pattern (glob) from being used. Each
//! entry carries a reason, the setter's name, and an optional absolute expiry.
//! The store owns every string it holds and frees them on removal, sweep, and
//! deinit. Matching is a pure case-insensitive glob, mirroring IRC name folding.
//!
//! This module is a pure policy store: it has no knowledge of clients, sockets,
//! or numerics. Command handlers query `isJuped` before accepting a NICK or a
//! channel JOIN and translate the result into the appropriate refusal.

const std = @import("std");

/// Which namespace an entry forbids. Nick and channel patterns never collide,
/// so the two are stored and queried independently.
pub const Kind = enum {
    nick,
    channel,
};

/// A single forbid entry. String fields are owned by the `JupeStore` that
/// returns them; borrow them only for the lifetime of the store.
pub const Entry = struct {
    kind: Kind,
    /// Case-insensitive glob: `*` matches any run, `?` matches one byte.
    pattern: []const u8,
    reason: []const u8,
    setter: []const u8,
    created_ms: i64,
    /// Absolute expiry in epoch milliseconds; 0 means permanent.
    expires_ms: i64 = 0,

    /// Whether this entry has expired at `now_ms`. Permanent entries (expiry 0)
    /// never expire.
    pub fn isExpired(self: Entry, now_ms: i64) bool {
        return self.expires_ms != 0 and self.expires_ms <= now_ms;
    }
};

/// Storage and validation limits for a `JupeStore`.
pub const Params = struct {
    max_entries: usize = 1024,
    max_pattern: usize = 256,
    max_reason: usize = 512,
    max_setter: usize = 64,
};

/// Errors returned while validating or storing entries.
pub const JupeError = error{
    EmptyPattern,
    PatternTooLong,
    ReasonTooLong,
    SetterTooLong,
    TooManyEntries,
};

/// Owning registry for nick and channel forbids.
pub const JupeStore = struct {
    allocator: std.mem.Allocator,
    params: Params,
    entries: std.ArrayListUnmanaged(Entry) = .empty,

    /// Initialize an empty store with the supplied allocator and limits.
    pub fn init(allocator: std.mem.Allocator, params: Params) JupeStore {
        return .{ .allocator = allocator, .params = params };
    }

    /// Free all owned strings and backing storage.
    pub fn deinit(self: *JupeStore) void {
        for (self.entries.items) |*entry| freeEntry(self.allocator, entry);
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    /// Add a forbid, duplicating its strings. An existing entry with the same
    /// kind and exact pattern is replaced in place (its prior strings freed).
    /// `expires_ms` of 0 means permanent.
    pub fn add(
        self: *JupeStore,
        kind: Kind,
        pattern: []const u8,
        reason: []const u8,
        setter: []const u8,
        created_ms: i64,
        expires_ms: i64,
    ) (JupeError || std.mem.Allocator.Error)!void {
        try self.validate(pattern, reason, setter);

        var owned = try self.clone(kind, pattern, reason, setter, created_ms, expires_ms);
        errdefer freeEntry(self.allocator, &owned);

        if (self.indexOf(kind, pattern)) |idx| {
            freeEntry(self.allocator, &self.entries.items[idx]);
            self.entries.items[idx] = owned;
            return;
        }

        if (self.entries.items.len >= self.params.max_entries) return error.TooManyEntries;
        try self.entries.append(self.allocator, owned);
    }

    /// Remove a forbid by exact kind and pattern. Returns true when an entry was
    /// present and freed.
    pub fn remove(self: *JupeStore, kind: Kind, pattern: []const u8) bool {
        const idx = self.indexOf(kind, pattern) orelse return false;
        var removed = self.entries.orderedRemove(idx);
        freeEntry(self.allocator, &removed);
        return true;
    }

    /// Copy every entry of `kind` into `out` and return the filled prefix.
    /// Returned entries borrow owned strings from the store. Expired entries are
    /// included; call `sweep` first to exclude them.
    pub fn list(self: *const JupeStore, kind: Kind, out: []Entry) []Entry {
        var n: usize = 0;
        for (self.entries.items) |entry| {
            if (entry.kind != kind) continue;
            if (n >= out.len) break;
            out[n] = entry;
            n += 1;
        }
        return out[0..n];
    }

    /// Return the first active entry whose pattern matches `name` in `kind`, or
    /// null. Expired entries are skipped but not removed; matching is a pure
    /// case-insensitive glob.
    pub fn isJuped(self: *const JupeStore, kind: Kind, name: []const u8, now_ms: i64) ?Entry {
        for (self.entries.items) |entry| {
            if (entry.kind != kind) continue;
            if (entry.isExpired(now_ms)) continue;
            if (globMatch(entry.pattern, name)) return entry;
        }
        return null;
    }

    /// Remove every entry whose expiry is at or before `now_ms`, freeing its
    /// strings. Returns the number of entries removed.
    pub fn sweep(self: *JupeStore, now_ms: i64) usize {
        var removed: usize = 0;
        var i: usize = 0;
        while (i < self.entries.items.len) {
            if (self.entries.items[i].isExpired(now_ms)) {
                var gone = self.entries.orderedRemove(i);
                freeEntry(self.allocator, &gone);
                removed += 1;
            } else {
                i += 1;
            }
        }
        return removed;
    }

    /// Total number of stored entries across both namespaces.
    pub fn count(self: *const JupeStore) usize {
        return self.entries.items.len;
    }

    fn validate(
        self: *const JupeStore,
        pattern: []const u8,
        reason: []const u8,
        setter: []const u8,
    ) JupeError!void {
        if (pattern.len == 0) return error.EmptyPattern;
        if (pattern.len > self.params.max_pattern) return error.PatternTooLong;
        if (reason.len > self.params.max_reason) return error.ReasonTooLong;
        if (setter.len > self.params.max_setter) return error.SetterTooLong;
    }

    fn clone(
        self: *JupeStore,
        kind: Kind,
        pattern: []const u8,
        reason: []const u8,
        setter: []const u8,
        created_ms: i64,
        expires_ms: i64,
    ) std.mem.Allocator.Error!Entry {
        const owned_pattern = try self.allocator.dupe(u8, pattern);
        errdefer self.allocator.free(owned_pattern);
        const owned_reason = try self.allocator.dupe(u8, reason);
        errdefer self.allocator.free(owned_reason);
        const owned_setter = try self.allocator.dupe(u8, setter);
        return .{
            .kind = kind,
            .pattern = owned_pattern,
            .reason = owned_reason,
            .setter = owned_setter,
            .created_ms = created_ms,
            .expires_ms = expires_ms,
        };
    }

    fn indexOf(self: *const JupeStore, kind: Kind, pattern: []const u8) ?usize {
        for (self.entries.items, 0..) |entry, idx| {
            if (entry.kind != kind) continue;
            if (std.mem.eql(u8, entry.pattern, pattern)) return idx;
        }
        return null;
    }
};

fn freeEntry(allocator: std.mem.Allocator, entry: *Entry) void {
    allocator.free(entry.pattern);
    allocator.free(entry.reason);
    allocator.free(entry.setter);
    entry.* = undefined;
}

/// Case-insensitive glob: `*` matches any run (including empty), `?` matches a
/// single byte. Backtracking is iterative, so adversarial patterns cannot blow
/// the stack.
fn globMatch(pattern: []const u8, text: []const u8) bool {
    var p: usize = 0;
    var t: usize = 0;
    var star: ?usize = null;
    var mark: usize = 0;

    while (t < text.len) {
        if (p < pattern.len and (pattern[p] == '?' or eqlFold(pattern[p], text[t]))) {
            p += 1;
            t += 1;
        } else if (p < pattern.len and pattern[p] == '*') {
            star = p;
            mark = t;
            p += 1;
        } else if (star) |s| {
            p = s + 1;
            mark += 1;
            t = mark;
        } else {
            return false;
        }
    }

    while (p < pattern.len and pattern[p] == '*') p += 1;
    return p == pattern.len;
}

fn eqlFold(a: u8, b: u8) bool {
    return std.ascii.toLower(a) == std.ascii.toLower(b);
}

const testing = std.testing;

test "add stores owned copies and count tracks both namespaces" {
    // Arrange.
    var store = JupeStore.init(testing.allocator, .{});
    defer store.deinit();

    // Act: mutate caller buffers after add to prove the store owns its copies.
    var pat = [_]u8{ 'E', 'v', 'i', 'l', '*' };
    try store.add(.nick, &pat, "impersonation", "oper", 100, 0);
    pat[0] = 'X';
    try store.add(.channel, "#warez*", "piracy", "admin", 100, 0);

    // Assert.
    try testing.expectEqual(@as(usize, 2), store.count());
    const hit = store.isJuped(.nick, "Evilbob", 200).?;
    try testing.expectEqualStrings("Evil*", hit.pattern);
    try testing.expectEqualStrings("impersonation", hit.reason);
    try testing.expectEqualStrings("oper", hit.setter);
}

test "isJuped is a case-insensitive glob honoring star and question" {
    // Arrange.
    var store = JupeStore.init(testing.allocator, .{});
    defer store.deinit();
    try store.add(.nick, "Serv?ce*", "reserved", "oper", 0, 0);

    // Act + Assert.
    try testing.expect(store.isJuped(.nick, "service-bot", 0) != null);
    try testing.expect(store.isJuped(.nick, "SERVICE", 0) != null);
    try testing.expect(store.isJuped(.nick, "ServXce", 0) != null);
    // `?` requires exactly one byte where the literal would sit.
    try testing.expect(store.isJuped(.nick, "Serve", 0) == null);
}

test "namespaces are independent" {
    // Arrange.
    var store = JupeStore.init(testing.allocator, .{});
    defer store.deinit();
    try store.add(.nick, "#admin", "n", "o", 0, 0);

    // Act + Assert: a nick pattern must not forbid a same-text channel.
    try testing.expect(store.isJuped(.channel, "#admin", 0) == null);
    try testing.expect(store.isJuped(.nick, "#admin", 0) != null);
}

test "add with same kind and pattern replaces in place without leaking" {
    // Arrange.
    var store = JupeStore.init(testing.allocator, .{});
    defer store.deinit();

    // Act.
    try store.add(.channel, "#dup", "first", "alice", 100, 0);
    try store.add(.channel, "#dup", "second", "bob", 200, 0);

    // Assert: one entry, updated reason and setter.
    try testing.expectEqual(@as(usize, 1), store.count());
    const hit = store.isJuped(.channel, "#dup", 300).?;
    try testing.expectEqualStrings("second", hit.reason);
    try testing.expectEqualStrings("bob", hit.setter);
}

test "remove frees by exact kind and pattern only" {
    // Arrange.
    var store = JupeStore.init(testing.allocator, .{});
    defer store.deinit();
    try store.add(.nick, "ghost*", "r", "o", 0, 0);

    // Act + Assert.
    try testing.expect(!store.remove(.channel, "ghost*")); // wrong kind
    try testing.expect(!store.remove(.nick, "ghost")); // wrong pattern
    try testing.expect(store.remove(.nick, "ghost*"));
    try testing.expectEqual(@as(usize, 0), store.count());
}

test "expired entries are skipped by isJuped and dropped by sweep" {
    // Arrange.
    var store = JupeStore.init(testing.allocator, .{});
    defer store.deinit();
    try store.add(.nick, "temp*", "r", "o", 0, 1000); // expires at t=1000
    try store.add(.nick, "perm*", "r", "o", 0, 0); // permanent

    // Act + Assert: before expiry both match.
    try testing.expect(store.isJuped(.nick, "tempbot", 500) != null);
    // After expiry the temp entry is skipped but still stored.
    try testing.expect(store.isJuped(.nick, "tempbot", 1000) == null);
    try testing.expectEqual(@as(usize, 2), store.count());

    // Sweep removes only the expired one.
    try testing.expectEqual(@as(usize, 1), store.sweep(1000));
    try testing.expectEqual(@as(usize, 1), store.count());
    try testing.expect(store.isJuped(.nick, "permanent", 9999) != null);
}

test "list returns only the requested namespace" {
    // Arrange.
    var store = JupeStore.init(testing.allocator, .{});
    defer store.deinit();
    try store.add(.nick, "a*", "r", "o", 0, 0);
    try store.add(.channel, "#b*", "r", "o", 0, 0);
    try store.add(.nick, "c*", "r", "o", 0, 0);

    // Act.
    var out: [8]Entry = undefined;
    const nicks = store.list(.nick, &out);
    const chans = store.list(.channel, &out);

    // Assert.
    try testing.expectEqual(@as(usize, 2), nicks.len);
    try testing.expectEqual(@as(usize, 1), chans.len);
    try testing.expectEqualStrings("#b*", chans[0].pattern);
}

test "validation rejects bad input and enforces capacity" {
    // Arrange.
    var store = JupeStore.init(testing.allocator, .{ .max_entries = 1, .max_pattern = 4 });
    defer store.deinit();

    // Act + Assert.
    try testing.expectError(error.EmptyPattern, store.add(.nick, "", "r", "o", 0, 0));
    try testing.expectError(error.PatternTooLong, store.add(.nick, "toolong", "r", "o", 0, 0));
    try store.add(.nick, "ok*", "r", "o", 0, 0);
    try testing.expectError(error.TooManyEntries, store.add(.channel, "#x*", "r", "o", 0, 0));
}

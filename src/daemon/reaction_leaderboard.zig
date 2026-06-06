//! ReactionLeaderboard — per-channel tally of reactions contributed by each
//! account, used by the Mizuchi daemon to surface "most reactive" members.
//!
//! Storage model: a single flat hash map keyed by a composite byte string
//! "<channel>\x00<account>" that maps to a u64 contribution counter. Every key
//! string stored in the map is owned (heap-duplicated) by this structure and
//! freed on removal / deinit. Counts are 64-bit.

const std = @import("std");

/// Byte separating the channel segment from the account segment inside a
/// composite map key. NUL can never appear inside an IRC channel or account
/// name, so it is an unambiguous delimiter.
const key_separator: u8 = 0;

/// A single leaderboard row handed back to callers via `top`.
pub const Entry = struct {
    /// Account name slice. Borrowed from internal storage; valid only until the
    /// next mutating call (`bump`, `clearChannel`, `deinit`).
    account: []const u8,
    /// Number of reactions this account has contributed in the channel.
    count: u64,
};

pub const ReactionLeaderboard = struct {
    allocator: std.mem.Allocator,
    /// Composite-key -> count. Keys are owned, heap-allocated byte strings.
    tallies: std.StringHashMapUnmanaged(u64),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .tallies = .{},
        };
    }

    /// Release every owned key and the backing map. Safe to call once.
    pub fn deinit(self: *Self) void {
        var it = self.tallies.iterator();
        while (it.next()) |kv| {
            self.allocator.free(kv.key_ptr.*);
        }
        self.tallies.deinit(self.allocator);
        self.* = undefined;
    }

    /// Build the owned composite key "<channel>\x00<account>".
    fn makeKey(self: *Self, channel: []const u8, account: []const u8) ![]u8 {
        const buf = try self.allocator.alloc(u8, channel.len + 1 + account.len);
        @memcpy(buf[0..channel.len], channel);
        buf[channel.len] = key_separator;
        @memcpy(buf[channel.len + 1 ..], account);
        return buf;
    }

    /// Increment the reaction count for `account` in `channel` and return the
    /// new total. The first reaction creates the entry.
    pub fn bump(self: *Self, channel: []const u8, account: []const u8) !u64 {
        const probe = try self.makeKey(channel, account);
        if (self.tallies.getEntry(probe)) |existing| {
            // Key already owned by the map; discard the probe.
            self.allocator.free(probe);
            existing.value_ptr.* += 1;
            return existing.value_ptr.*;
        }
        // New entry: the map takes ownership of `probe`.
        errdefer self.allocator.free(probe);
        try self.tallies.put(self.allocator, probe, 1);
        return 1;
    }

    /// Fill `out` with up to `n` highest-count entries for `channel`, sorted by
    /// count descending (ties broken by account name ascending for stability).
    /// Returns the number of entries written.
    pub fn top(self: *Self, channel: []const u8, n: usize, out: []Entry) usize {
        if (n == 0 or out.len == 0) return 0;

        const limit = @min(n, out.len);
        var written: usize = 0;

        var it = self.tallies.iterator();
        while (it.next()) |kv| {
            const account = accountOf(kv.key_ptr.*, channel) orelse continue;
            const candidate = Entry{ .account = account, .count = kv.value_ptr.* };

            // Insertion sort into the bounded output window.
            var pos: usize = written;
            while (pos > 0 and lessThan(out[pos - 1], candidate)) : (pos -= 1) {}
            // `pos` is the slot where candidate belongs. Only act if it fits.
            if (pos >= limit) continue;

            const end = if (written < limit) written else limit - 1;
            var i: usize = end;
            while (i > pos) : (i -= 1) {
                out[i] = out[i - 1];
            }
            out[pos] = candidate;
            if (written < limit) written += 1;
        }

        return written;
    }

    /// Remove every entry belonging to `channel`. Returns the count removed.
    pub fn clearChannel(self: *Self, channel: []const u8) usize {
        var doomed: std.ArrayListUnmanaged([]const u8) = .empty;
        defer doomed.deinit(self.allocator);

        var it = self.tallies.iterator();
        while (it.next()) |kv| {
            if (accountOf(kv.key_ptr.*, channel) != null) {
                // Collecting first avoids mutating the map mid-iteration.
                doomed.append(self.allocator, kv.key_ptr.*) catch {
                    // On OOM during collection, fall back to safe per-key path.
                    return self.clearChannelSlow(channel);
                };
            }
        }

        for (doomed.items) |key| {
            _ = self.tallies.remove(key);
            self.allocator.free(key);
        }
        return doomed.items.len;
    }

    /// Allocation-free fallback for `clearChannel` used if collection OOMs.
    fn clearChannelSlow(self: *Self, channel: []const u8) usize {
        var removed: usize = 0;
        var progressed = true;
        while (progressed) {
            progressed = false;
            var it = self.tallies.iterator();
            while (it.next()) |kv| {
                if (accountOf(kv.key_ptr.*, channel) != null) {
                    const key = kv.key_ptr.*;
                    _ = self.tallies.remove(key);
                    self.allocator.free(key);
                    removed += 1;
                    progressed = true;
                    break;
                }
            }
        }
        return removed;
    }
};

/// If `key` belongs to `channel`, return the account segment; else null.
fn accountOf(key: []const u8, channel: []const u8) ?[]const u8 {
    if (key.len < channel.len + 1) return null;
    if (!std.mem.eql(u8, key[0..channel.len], channel)) return null;
    if (key[channel.len] != key_separator) return null;
    return key[channel.len + 1 ..];
}

/// Ordering predicate: returns true when `a` ranks below `b` (i.e. `b` should
/// appear earlier). Higher count wins; ties favour lexicographically smaller
/// account names for deterministic output.
fn lessThan(a: Entry, b: Entry) bool {
    if (a.count != b.count) return a.count < b.count;
    return std.mem.order(u8, a.account, b.account) == .gt;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "bump increments and returns running total" {
    var lb = ReactionLeaderboard.init(std.testing.allocator);
    defer lb.deinit();

    try std.testing.expectEqual(@as(u64, 1), try lb.bump("#hydra", "kappa"));
    try std.testing.expectEqual(@as(u64, 2), try lb.bump("#hydra", "kappa"));
    try std.testing.expectEqual(@as(u64, 1), try lb.bump("#hydra", "nessie"));
    try std.testing.expectEqual(@as(u64, 3), try lb.bump("#hydra", "kappa"));
}

test "top returns entries in descending count order" {
    var lb = ReactionLeaderboard.init(std.testing.allocator);
    defer lb.deinit();

    _ = try lb.bump("#hydra", "low"); // 1
    var i: usize = 0;
    while (i < 5) : (i += 1) _ = try lb.bump("#hydra", "high"); // 5
    i = 0;
    while (i < 3) : (i += 1) _ = try lb.bump("#hydra", "mid"); // 3

    var out: [8]Entry = undefined;
    const got = lb.top("#hydra", 8, out[0..]);
    try std.testing.expectEqual(@as(usize, 3), got);

    try std.testing.expectEqualStrings("high", out[0].account);
    try std.testing.expectEqual(@as(u64, 5), out[0].count);
    try std.testing.expectEqualStrings("mid", out[1].account);
    try std.testing.expectEqual(@as(u64, 3), out[1].count);
    try std.testing.expectEqualStrings("low", out[2].account);
    try std.testing.expectEqual(@as(u64, 1), out[2].count);
}

test "top honours the n limit" {
    var lb = ReactionLeaderboard.init(std.testing.allocator);
    defer lb.deinit();

    _ = try lb.bump("#tide", "a");
    _ = try lb.bump("#tide", "a");
    _ = try lb.bump("#tide", "a");
    _ = try lb.bump("#tide", "b");
    _ = try lb.bump("#tide", "b");
    _ = try lb.bump("#tide", "c");

    var out: [2]Entry = undefined;
    const got = lb.top("#tide", 2, out[0..]);
    try std.testing.expectEqual(@as(usize, 2), got);
    try std.testing.expectEqualStrings("a", out[0].account);
    try std.testing.expectEqualStrings("b", out[1].account);
}

test "channels are scoped independently" {
    var lb = ReactionLeaderboard.init(std.testing.allocator);
    defer lb.deinit();

    _ = try lb.bump("#alpha", "shared");
    _ = try lb.bump("#alpha", "shared");
    _ = try lb.bump("#beta", "shared");

    var out: [4]Entry = undefined;

    const a = lb.top("#alpha", 4, out[0..]);
    try std.testing.expectEqual(@as(usize, 1), a);
    try std.testing.expectEqual(@as(u64, 2), out[0].count);

    const b = lb.top("#beta", 4, out[0..]);
    try std.testing.expectEqual(@as(usize, 1), b);
    try std.testing.expectEqual(@as(u64, 1), out[0].count);
}

test "clearChannel removes only the targeted channel" {
    var lb = ReactionLeaderboard.init(std.testing.allocator);
    defer lb.deinit();

    _ = try lb.bump("#keep", "x");
    _ = try lb.bump("#drop", "y");
    _ = try lb.bump("#drop", "z");
    _ = try lb.bump("#drop", "y");

    const removed = lb.clearChannel("#drop");
    try std.testing.expectEqual(@as(usize, 2), removed);

    var out: [4]Entry = undefined;
    try std.testing.expectEqual(@as(usize, 0), lb.top("#drop", 4, out[0..]));
    try std.testing.expectEqual(@as(usize, 1), lb.top("#keep", 4, out[0..]));
    try std.testing.expectEqualStrings("x", out[0].account);

    // A prefix that is not separator-aligned must not match.
    _ = try lb.bump("#keepsake", "w");
    try std.testing.expectEqual(@as(usize, 0), lb.clearChannel("#kee"));
    try std.testing.expectEqual(@as(usize, 1), lb.top("#keepsake", 4, out[0..]));
}

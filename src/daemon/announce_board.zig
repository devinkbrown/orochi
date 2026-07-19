// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Onyx Server structured announcement subsystem.
//!
//! `AnnounceBoard` is a retained, prioritized, expiring announcement store
//! intended for bot/oper accounts. It replaces the legacy "announcement flag"
//! with a real board: scoped (global or per-channel) entries with categories,
//! priorities, expiry, per-account dismissal tracking, and explicit revocation.
//!
//! Clean-room Onyx Server-native implementation. Imports only `std`.

const std = @import("std");
const toml = @import("../proto/toml.zig");

/// Historical default limits (kept as named constants for tests / call sites).
pub const default_max_announcements: usize = 512;
pub const default_max_category_len: usize = 32;
pub const default_max_title_len: usize = 120;
pub const default_max_body_len: usize = 1000;

/// Runtime-tunable announcement-board limits. Defaults preserve the historical
/// hardcoded behaviour; the orchestrator overlays the `[bouncer]` TOML section
/// via `Config.applyToml` before constructing an `AnnounceBoard`.
pub const Config = struct {
    /// Retained announcement-board cap (FIFO eviction).
    max_announcements: usize = default_max_announcements,
    /// Max announcement category tag length (bytes).
    max_category_len: usize = default_max_category_len,
    /// Max announcement headline length (bytes).
    max_title_len: usize = default_max_title_len,
    /// Max announcement body length (bytes).
    max_body_len: usize = default_max_body_len,

    /// Overlay `[bouncer]` keys from a parsed TOML document onto `cfg`. Missing
    /// keys leave the current value untouched. Pure: no I/O, never fails.
    pub fn applyToml(cfg: *Config, doc: *const toml.Document) void {
        if (doc.getUint("bouncer.announce_max_entries")) |v| {
            if (v >= 1) cfg.max_announcements = @intCast(v);
        }
        if (doc.getUint("bouncer.announce_category_max_len")) |v| {
            if (v >= 1) cfg.max_category_len = @intCast(v);
        }
        if (doc.getUint("bouncer.announce_title_max_len")) |v| {
            if (v >= 1) cfg.max_title_len = @intCast(v);
        }
        if (doc.getUint("bouncer.announce_body_max_len")) |v| {
            if (v >= 1) cfg.max_body_len = @intCast(v);
        }
    }
};

pub const Error = error{
    AnnouncementInvalid,
} || std.mem.Allocator.Error;

/// Relative urgency of an announcement. Ordered low -> urgent.
pub const Priority = enum(u2) {
    low,
    normal,
    high,
    urgent,
};

/// A single retained announcement. All string slices are owned by the board
/// and freed in `deinit` / on eviction / on revoke.
pub const Announcement = struct {
    id: u64,
    /// "*" for a global announcement, otherwise a channel name.
    scope: []u8,
    /// Short classification tag (<= default_max_category_len).
    category: []u8,
    /// Headline (<= default_max_title_len).
    title: []u8,
    /// Full text (<= default_max_body_len).
    body: []u8,
    /// Publishing account/identity.
    by: []u8,
    priority: Priority,
    /// Publication timestamp (epoch milliseconds).
    at_ms: i64,
    /// Expiry timestamp (epoch milliseconds); 0 = never expires.
    expires_ms: i64,

    fn isExpired(self: *const Announcement, now_ms: i64) bool {
        return self.expires_ms != 0 and now_ms >= self.expires_ms;
    }
};

pub const AnnounceBoard = struct {
    allocator: std.mem.Allocator,
    items: std.ArrayListUnmanaged(Announcement),
    /// Per-account set of dismissed announcement ids.
    /// Key: owned account string. Value: set of dismissed ids.
    dismissals: std.StringHashMapUnmanaged(IdSet),
    next_id: u64,
    cfg: Config = .{},

    const IdSet = std.AutoHashMapUnmanaged(u64, void);

    pub fn init(allocator: std.mem.Allocator) AnnounceBoard {
        return initWithConfig(allocator, .{});
    }

    pub fn initWithConfig(allocator: std.mem.Allocator, cfg: Config) AnnounceBoard {
        return .{
            .allocator = allocator,
            .items = .empty,
            .dismissals = .empty,
            .next_id = 1,
            .cfg = cfg,
        };
    }

    pub fn deinit(self: *AnnounceBoard) void {
        for (self.items.items) |*a| self.freeAnnouncement(a);
        self.items.deinit(self.allocator);

        var it = self.dismissals.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.dismissals.deinit(self.allocator);

        self.* = undefined;
    }

    fn freeAnnouncement(self: *AnnounceBoard, a: *Announcement) void {
        self.allocator.free(a.scope);
        self.allocator.free(a.category);
        self.allocator.free(a.title);
        self.allocator.free(a.body);
        self.allocator.free(a.by);
    }

    /// Publish a new announcement. Returns the freshly assigned id.
    ///
    /// Validation: every text field must be non-empty and within its length
    /// bound, otherwise `error.AnnouncementInvalid` is returned and nothing is
    /// stored. When the board is at `default_max_announcements`, the oldest entry
    /// (FIFO) is evicted to make room.
    pub fn publish(
        self: *AnnounceBoard,
        scope: []const u8,
        category: []const u8,
        title: []const u8,
        body: []const u8,
        by: []const u8,
        priority: Priority,
        now_ms: i64,
        expires_ms: i64,
    ) Error!u64 {
        if (!validField(scope, scope.len)) return error.AnnouncementInvalid;
        if (!validField(category, self.cfg.max_category_len)) return error.AnnouncementInvalid;
        if (!validField(title, self.cfg.max_title_len)) return error.AnnouncementInvalid;
        if (!validField(body, self.cfg.max_body_len)) return error.AnnouncementInvalid;
        if (!validField(by, by.len)) return error.AnnouncementInvalid;

        // FIFO eviction when at capacity. Index 0 is the oldest insertion.
        if (self.items.items.len >= self.cfg.max_announcements) {
            var oldest = self.items.orderedRemove(0);
            self.freeAnnouncement(&oldest);
        }

        const owned_scope = try self.allocator.dupe(u8, scope);
        errdefer self.allocator.free(owned_scope);
        const owned_category = try self.allocator.dupe(u8, category);
        errdefer self.allocator.free(owned_category);
        const owned_title = try self.allocator.dupe(u8, title);
        errdefer self.allocator.free(owned_title);
        const owned_body = try self.allocator.dupe(u8, body);
        errdefer self.allocator.free(owned_body);
        const owned_by = try self.allocator.dupe(u8, by);
        errdefer self.allocator.free(owned_by);

        const id = self.next_id;

        try self.items.append(self.allocator, .{
            .id = id,
            .scope = owned_scope,
            .category = owned_category,
            .title = owned_title,
            .body = owned_body,
            .by = owned_by,
            .priority = priority,
            .at_ms = now_ms,
            .expires_ms = expires_ms,
        });

        self.next_id += 1;
        return id;
    }

    /// Fill `out` with pointers to non-expired announcements matching `scope`
    /// exactly OR carrying the global scope "*", newest-first. Returns the
    /// number of entries written (capped at `out.len`).
    pub fn active(
        self: *const AnnounceBoard,
        scope: []const u8,
        now_ms: i64,
        out: []*const Announcement,
    ) usize {
        if (out.len == 0) return 0;
        var count: usize = 0;

        // Iterate newest-first: later insertions live at higher indices.
        var i: usize = self.items.items.len;
        while (i > 0) {
            i -= 1;
            const a = &self.items.items[i];
            if (a.isExpired(now_ms)) continue;
            if (!scopeMatches(a.scope, scope)) continue;

            out[count] = a;
            count += 1;
            if (count == out.len) break;
        }

        return count;
    }

    /// Remove every expired announcement. Returns the number freed.
    pub fn expireSweep(self: *AnnounceBoard, now_ms: i64) usize {
        var freed: usize = 0;
        var i: usize = 0;
        while (i < self.items.items.len) {
            const a = &self.items.items[i];
            if (a.isExpired(now_ms)) {
                var removed = self.items.orderedRemove(i);
                self.freeAnnouncement(&removed);
                freed += 1;
                // Do not advance i: the next element shifted into this slot.
            } else {
                i += 1;
            }
        }
        return freed;
    }

    /// Record that `account` has dismissed announcement `id`. Idempotent.
    pub fn dismiss(self: *AnnounceBoard, account: []const u8, id: u64) Error!void {
        const gop = try self.dismissals.getOrPut(self.allocator, account);
        if (!gop.found_existing) {
            const owned_key = self.allocator.dupe(u8, account) catch |err| {
                self.dismissals.removeByPtr(gop.key_ptr);
                return err;
            };
            gop.key_ptr.* = owned_key;
            gop.value_ptr.* = .empty;
        }
        try gop.value_ptr.put(self.allocator, id, {});
    }

    /// Whether `account` has dismissed announcement `id`.
    pub fn isDismissed(self: *const AnnounceBoard, account: []const u8, id: u64) bool {
        const set = self.dismissals.get(account) orelse return false;
        return set.contains(id);
    }

    /// Remove a specific announcement by id. Returns true if one was removed.
    pub fn revoke(self: *AnnounceBoard, id: u64) bool {
        for (self.items.items, 0..) |a, idx| {
            if (a.id == id) {
                var removed = self.items.orderedRemove(idx);
                self.freeAnnouncement(&removed);
                return true;
            }
        }
        return false;
    }

    /// Current number of stored announcements (including not-yet-swept expired).
    pub fn len(self: *const AnnounceBoard) usize {
        return self.items.items.len;
    }
};

const global_scope = "*";

fn validField(s: []const u8, max_len: usize) bool {
    return s.len != 0 and s.len <= max_len;
}

fn scopeMatches(announcement_scope: []const u8, query_scope: []const u8) bool {
    if (std.mem.eql(u8, announcement_scope, global_scope)) return true;
    return std.mem.eql(u8, announcement_scope, query_scope);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "publish and active filter by scope and global" {
    var board = AnnounceBoard.init(std.testing.allocator);
    defer board.deinit();

    const now: i64 = 1_000;

    _ = try board.publish("*", "news", "Global notice", "everyone sees this", "bot", .normal, now, 0);
    _ = try board.publish("#onyx", "ops", "Channel notice", "channel only", "oper", .high, now, 0);
    _ = try board.publish("#other", "ops", "Other channel", "not for us", "oper", .low, now, 0);

    var buf: [16]*const Announcement = undefined;

    // #onyx sees its own + the global one.
    const n_chan = board.active("#onyx", now, &buf);
    try std.testing.expectEqual(@as(usize, 2), n_chan);
    // Newest-first: #onyx was published after the global one.
    try std.testing.expectEqualStrings("Channel notice", buf[0].title);
    try std.testing.expectEqualStrings("Global notice", buf[1].title);

    // A scope with no specific announcements still sees the global one.
    const n_unknown = board.active("#nowhere", now, &buf);
    try std.testing.expectEqual(@as(usize, 1), n_unknown);
    try std.testing.expectEqualStrings("Global notice", buf[0].title);

    // Querying global scope returns only global entries.
    const n_global = board.active("*", now, &buf);
    try std.testing.expectEqual(@as(usize, 1), n_global);
    try std.testing.expectEqualStrings("Global notice", buf[0].title);
}

test "expiry: active skips expired and expireSweep frees them" {
    var board = AnnounceBoard.init(std.testing.allocator);
    defer board.deinit();

    const now: i64 = 1_000;

    _ = try board.publish("*", "news", "Permanent", "never expires", "bot", .normal, now, 0);
    const short_id = try board.publish("*", "news", "Temporary", "expires soon", "bot", .normal, now, now + 100);

    var buf: [16]*const Announcement = undefined;

    // Before expiry, both are active.
    try std.testing.expectEqual(@as(usize, 2), board.active("*", now, &buf));

    // After expiry time, active() skips the expired one without removing it.
    const later: i64 = now + 200;
    const n_after = board.active("*", later, &buf);
    try std.testing.expectEqual(@as(usize, 1), n_after);
    try std.testing.expectEqualStrings("Permanent", buf[0].title);
    try std.testing.expectEqual(@as(usize, 2), board.len());

    // Sweep removes exactly the expired entry.
    const freed = board.expireSweep(later);
    try std.testing.expectEqual(@as(usize, 1), freed);
    try std.testing.expectEqual(@as(usize, 1), board.len());

    // The permanent one survives, the expired id is gone.
    try std.testing.expect(!board.revoke(short_id));
    try std.testing.expectEqual(@as(usize, 1), board.active("*", later, &buf));

    // Sweeping again frees nothing.
    try std.testing.expectEqual(@as(usize, 0), board.expireSweep(later));
}

test "dismiss and isDismissed track per-account state" {
    var board = AnnounceBoard.init(std.testing.allocator);
    defer board.deinit();

    const now: i64 = 1_000;
    const id_a = try board.publish("*", "news", "Alpha", "first", "bot", .normal, now, 0);
    const id_b = try board.publish("*", "news", "Beta", "second", "bot", .normal, now, 0);

    try std.testing.expect(!board.isDismissed("alice", id_a));

    try board.dismiss("alice", id_a);
    try std.testing.expect(board.isDismissed("alice", id_a));
    // Other id and other account are unaffected.
    try std.testing.expect(!board.isDismissed("alice", id_b));
    try std.testing.expect(!board.isDismissed("bob", id_a));

    // Dismissal is idempotent.
    try board.dismiss("alice", id_a);
    try std.testing.expect(board.isDismissed("alice", id_a));

    // A second account can dismiss the same id independently.
    try board.dismiss("bob", id_a);
    try board.dismiss("alice", id_b);
    try std.testing.expect(board.isDismissed("bob", id_a));
    try std.testing.expect(board.isDismissed("alice", id_b));
}

test "cap eviction drops oldest FIFO when full" {
    var board = AnnounceBoard.init(std.testing.allocator);
    defer board.deinit();

    const now: i64 = 1_000;

    // Fill to capacity.
    var first_id: u64 = 0;
    var i: usize = 0;
    while (i < default_max_announcements) : (i += 1) {
        const id = try board.publish("*", "c", "t", "b", "bot", .normal, now, 0);
        if (i == 0) first_id = id;
    }
    try std.testing.expectEqual(default_max_announcements, board.len());

    // One more publish evicts the oldest (first_id) but stays at the cap.
    const overflow_id = try board.publish("*", "c", "newest", "b", "bot", .urgent, now, 0);
    try std.testing.expectEqual(default_max_announcements, board.len());

    // The evicted oldest is gone; the new one is present.
    try std.testing.expect(!board.revoke(first_id));

    var buf: [1]*const Announcement = undefined;
    const n = board.active("*", now, &buf);
    try std.testing.expectEqual(@as(usize, 1), n);
    // Newest-first: the urgent overflow entry leads.
    try std.testing.expectEqual(overflow_id, buf[0].id);
    try std.testing.expectEqualStrings("newest", buf[0].title);
}

test "publish rejects invalid fields" {
    var board = AnnounceBoard.init(std.testing.allocator);
    defer board.deinit();

    const now: i64 = 1_000;
    const big_category = &@as([(default_max_category_len + 1)]u8, @splat('x'));
    const big_title = &@as([(default_max_title_len + 1)]u8, @splat('y'));
    const big_body = &@as([(default_max_body_len + 1)]u8, @splat('z'));

    try std.testing.expectError(error.AnnouncementInvalid, board.publish("", "c", "t", "b", "bot", .normal, now, 0));
    try std.testing.expectError(error.AnnouncementInvalid, board.publish("*", "", "t", "b", "bot", .normal, now, 0));
    try std.testing.expectError(error.AnnouncementInvalid, board.publish("*", big_category, "t", "b", "bot", .normal, now, 0));
    try std.testing.expectError(error.AnnouncementInvalid, board.publish("*", "c", big_title, "b", "bot", .normal, now, 0));
    try std.testing.expectError(error.AnnouncementInvalid, board.publish("*", "c", "t", big_body, "bot", .normal, now, 0));
    try std.testing.expectError(error.AnnouncementInvalid, board.publish("*", "c", "t", "b", "", .normal, now, 0));

    // Nothing was stored.
    try std.testing.expectEqual(@as(usize, 0), board.len());
}

test "Config defaults preserve historical limits" {
    const cfg = Config{};
    try std.testing.expectEqual(default_max_announcements, cfg.max_announcements);
    try std.testing.expectEqual(default_max_category_len, cfg.max_category_len);
    try std.testing.expectEqual(default_max_title_len, cfg.max_title_len);
    try std.testing.expectEqual(default_max_body_len, cfg.max_body_len);
}

test "Config.applyToml overlays [bouncer] announce keys" {
    var doc = try toml.parse(
        std.testing.allocator,
        "[bouncer]\nannounce_max_entries = 32\nannounce_category_max_len = 8\nannounce_title_max_len = 16\nannounce_body_max_len = 128\n",
    );
    defer doc.deinit(std.testing.allocator);

    var cfg = Config{};
    cfg.applyToml(&doc);
    try std.testing.expectEqual(@as(usize, 32), cfg.max_announcements);
    try std.testing.expectEqual(@as(usize, 8), cfg.max_category_len);
    try std.testing.expectEqual(@as(usize, 16), cfg.max_title_len);
    try std.testing.expectEqual(@as(usize, 128), cfg.max_body_len);
}

test "initWithConfig enforces a smaller board cap" {
    var board = AnnounceBoard.initWithConfig(std.testing.allocator, .{ .max_announcements = 2 });
    defer board.deinit();

    const now: i64 = 1_000;
    _ = try board.publish("*", "c", "t", "b", "bot", .normal, now, 0);
    _ = try board.publish("*", "c", "t", "b", "bot", .normal, now, 0);
    _ = try board.publish("*", "c", "newest", "b", "bot", .normal, now, 0); // evicts oldest
    try std.testing.expectEqual(@as(usize, 2), board.len());
}

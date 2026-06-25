// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bot account registry and announcement gating for the Orochi IRC daemon.
//!
//! Tracks which accounts are recognized bots, whether they are permitted to
//! publish announcements, the scope of those announcements, and enforces a
//! sliding one-hour rate window per account.
//!
//! Pure Zig 0.16. Imports only `std`.

const std = @import("std");

/// Reach of an announcement an account is permitted to publish.
pub const Scope = enum {
    /// No announcement reach at all.
    none,
    /// May only announce to channels the bot itself owns/operates.
    own_channels,
    /// May announce to every channel / network-wide.
    global,
};

/// Per-account metadata describing announcement entitlements.
pub const BotInfo = struct {
    /// Whether the account has passed verification.
    verified: bool = false,
    /// Whether the account is permitted to announce at all.
    may_announce: bool = false,
    /// The widest reach the account may target.
    announce_scope: Scope = .none,
    /// Maximum announcements permitted within the sliding one-hour window.
    per_hour: u16 = 0,
};

/// Length of the rate-limiter sliding window, in milliseconds (one hour).
const WINDOW_MS: u64 = 60 * 60 * 1000;

/// A bounded ring of recent announcement timestamps (milliseconds).
///
/// Capacity matches the account's `per_hour` cap: once full, the oldest
/// in-window entry must have expired before another announcement is allowed.
const TimeRing = struct {
    /// Backing storage of timestamps in milliseconds. Capacity == per_hour.
    stamps: []u64,
    /// Index of the oldest stored timestamp.
    head: usize = 0,
    /// Number of live entries currently stored.
    len: usize = 0,

    fn init(allocator: std.mem.Allocator, capacity: usize) !TimeRing {
        const stamps = try allocator.alloc(u64, capacity);
        return .{ .stamps = stamps, .head = 0, .len = 0 };
    }

    fn deinit(self: *TimeRing, allocator: std.mem.Allocator) void {
        allocator.free(self.stamps);
        self.* = undefined;
    }

    /// Drop all timestamps older than the window relative to `now_ms`.
    fn evict(self: *TimeRing, now_ms: u64) void {
        const cutoff = if (now_ms >= WINDOW_MS) now_ms - WINDOW_MS else 0;
        while (self.len > 0) {
            const oldest = self.stamps[self.head];
            // Strictly older than the window start falls out of the window.
            if (oldest >= cutoff) break;
            self.head = (self.head + 1) % self.stamps.len;
            self.len -= 1;
        }
    }

    /// Append a timestamp. Caller must ensure there is room (len < capacity).
    fn push(self: *TimeRing, now_ms: u64) void {
        const tail = (self.head + self.len) % self.stamps.len;
        self.stamps[tail] = now_ms;
        self.len += 1;
    }
};

/// State stored per registered account: its info plus rate-limit ring.
const Entry = struct {
    info: BotInfo,
    ring: TimeRing,
};

/// Registry of bot accounts and their announcement permissions/rate.
pub const BotRegistry = struct {
    allocator: std.mem.Allocator,
    /// Maps owned account-key strings to their entry state.
    map: std.StringHashMapUnmanaged(Entry) = .{},

    pub fn init(allocator: std.mem.Allocator) BotRegistry {
        return .{ .allocator = allocator, .map = .{} };
    }

    pub fn deinit(self: *BotRegistry) void {
        var it = self.map.iterator();
        while (it.next()) |kv| {
            self.allocator.free(kv.key_ptr.*);
            kv.value_ptr.ring.deinit(self.allocator);
        }
        self.map.deinit(self.allocator);
        self.* = undefined;
    }

    /// Register (or overwrite) an account. The account key is duplicated and
    /// owned by the registry. Overwriting resets the rate-limit window.
    pub fn register(self: *BotRegistry, account: []const u8, bot_info: BotInfo) !void {
        // The ring capacity must be able to hold up to `per_hour` entries.
        var ring = try TimeRing.init(self.allocator, bot_info.per_hour);
        errdefer ring.deinit(self.allocator);

        if (self.map.getPtr(account)) |existing| {
            // Overwrite in place; reuse the existing owned key.
            existing.ring.deinit(self.allocator);
            existing.* = .{ .info = bot_info, .ring = ring };
            return;
        }

        const key = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(key);
        try self.map.put(self.allocator, key, .{ .info = bot_info, .ring = ring });
    }

    /// Remove an account. Returns true if it was present.
    pub fn unregister(self: *BotRegistry, account: []const u8) bool {
        if (self.map.fetchRemove(account)) |kv| {
            self.allocator.free(kv.key);
            var entry = kv.value;
            entry.ring.deinit(self.allocator);
            return true;
        }
        return false;
    }

    /// Whether the account is a registered bot.
    pub fn isBot(self: *const BotRegistry, account: []const u8) bool {
        return self.map.contains(account);
    }

    /// Fetch a copy of the account's info, if registered.
    pub fn info(self: *const BotRegistry, account: []const u8) ?BotInfo {
        if (self.map.getPtr(account)) |entry| return entry.info;
        return null;
    }

    /// Whether the account may publish an announcement of the requested reach.
    ///
    /// Requires the account to be registered, verified, permitted to announce,
    /// and have a scope that covers the request. A `global` request requires
    /// `announce_scope == .global`.
    pub fn mayAnnounce(self: *const BotRegistry, account: []const u8, global: bool) bool {
        const entry = self.map.getPtr(account) orelse return false;
        const i = entry.info;
        if (!i.verified or !i.may_announce) return false;
        return switch (i.announce_scope) {
            .none => false,
            .own_channels => !global,
            .global => true,
        };
    }

    /// Record an announcement against the sliding window rate limiter.
    ///
    /// Returns false (without recording) if the account is at or over its
    /// `per_hour` cap within the trailing one-hour window. Otherwise records
    /// the timestamp and returns true. Returns false for unknown accounts and
    /// for accounts whose `per_hour` is zero.
    pub fn recordAnnounce(self: *BotRegistry, account: []const u8, now_ms: u64) !bool {
        const entry = self.map.getPtr(account) orelse return false;
        if (entry.info.per_hour == 0) return false;

        entry.ring.evict(now_ms);
        if (entry.ring.len >= entry.info.per_hour) return false;

        entry.ring.push(now_ms);
        return true;
    }
};

test "register / isBot / info" {
    const allocator = std.testing.allocator;
    var reg = BotRegistry.init(allocator);
    defer reg.deinit();

    try std.testing.expect(!reg.isBot("newsbot"));
    try std.testing.expect(reg.info("newsbot") == null);

    try reg.register("newsbot", .{
        .verified = true,
        .may_announce = true,
        .announce_scope = .own_channels,
        .per_hour = 5,
    });

    try std.testing.expect(reg.isBot("newsbot"));
    const got = reg.info("newsbot").?;
    try std.testing.expectEqual(true, got.verified);
    try std.testing.expectEqual(@as(u16, 5), got.per_hour);
    try std.testing.expectEqual(Scope.own_channels, got.announce_scope);

    // Overwrite with new info (dup-overwrite ok).
    try reg.register("newsbot", .{
        .verified = false,
        .may_announce = false,
        .announce_scope = .none,
        .per_hour = 0,
    });
    const got2 = reg.info("newsbot").?;
    try std.testing.expectEqual(false, got2.verified);
    try std.testing.expectEqual(@as(u16, 0), got2.per_hour);
    try std.testing.expectEqual(@as(u32, 1), reg.map.count());
}

test "mayAnnounce scope and verification gating" {
    const allocator = std.testing.allocator;
    var reg = BotRegistry.init(allocator);
    defer reg.deinit();

    // Unknown account: always false.
    try std.testing.expect(!reg.mayAnnounce("ghost", false));
    try std.testing.expect(!reg.mayAnnounce("ghost", true));

    // Scope none: never allowed.
    try reg.register("a", .{ .verified = true, .may_announce = true, .announce_scope = .none, .per_hour = 1 });
    try std.testing.expect(!reg.mayAnnounce("a", false));
    try std.testing.expect(!reg.mayAnnounce("a", true));

    // own_channels: local yes, global no.
    try reg.register("b", .{ .verified = true, .may_announce = true, .announce_scope = .own_channels, .per_hour = 1 });
    try std.testing.expect(reg.mayAnnounce("b", false));
    try std.testing.expect(!reg.mayAnnounce("b", true));

    // global: both yes.
    try reg.register("c", .{ .verified = true, .may_announce = true, .announce_scope = .global, .per_hour = 1 });
    try std.testing.expect(reg.mayAnnounce("c", false));
    try std.testing.expect(reg.mayAnnounce("c", true));

    // Not verified: blocked even with global scope.
    try reg.register("d", .{ .verified = false, .may_announce = true, .announce_scope = .global, .per_hour = 1 });
    try std.testing.expect(!reg.mayAnnounce("d", false));
    try std.testing.expect(!reg.mayAnnounce("d", true));

    // may_announce false: blocked.
    try reg.register("e", .{ .verified = true, .may_announce = false, .announce_scope = .global, .per_hour = 1 });
    try std.testing.expect(!reg.mayAnnounce("e", false));
    try std.testing.expect(!reg.mayAnnounce("e", true));
}

test "rate limiter trips at per_hour and recovers after window" {
    const allocator = std.testing.allocator;
    var reg = BotRegistry.init(allocator);
    defer reg.deinit();

    try reg.register("rl", .{
        .verified = true,
        .may_announce = true,
        .announce_scope = .global,
        .per_hour = 3,
    });

    const base: u64 = 10 * WINDOW_MS; // well past zero to exercise eviction math

    // First three within the same window succeed.
    try std.testing.expect(try reg.recordAnnounce("rl", base));
    try std.testing.expect(try reg.recordAnnounce("rl", base + 1000));
    try std.testing.expect(try reg.recordAnnounce("rl", base + 2000));

    // Fourth within the window is over the cap.
    try std.testing.expect(!try reg.recordAnnounce("rl", base + 3000));

    // Still over the cap just before the first entry expires.
    try std.testing.expect(!try reg.recordAnnounce("rl", base + WINDOW_MS - 1));

    // Once the first entry ages out, a slot frees up and we recover.
    try std.testing.expect(try reg.recordAnnounce("rl", base + WINDOW_MS + 1));

    // But the second/third are still in-window, so we are capped again.
    try std.testing.expect(!try reg.recordAnnounce("rl", base + WINDOW_MS + 2));

    // per_hour == 0 means no announcements ever recorded.
    try reg.register("zero", .{
        .verified = true,
        .may_announce = true,
        .announce_scope = .global,
        .per_hour = 0,
    });
    try std.testing.expect(!try reg.recordAnnounce("zero", base));

    // Unknown account records nothing.
    try std.testing.expect(!try reg.recordAnnounce("nobody", base));
}

test "unregister" {
    const allocator = std.testing.allocator;
    var reg = BotRegistry.init(allocator);
    defer reg.deinit();

    try reg.register("temp", .{
        .verified = true,
        .may_announce = true,
        .announce_scope = .global,
        .per_hour = 2,
    });
    try std.testing.expect(reg.isBot("temp"));

    try std.testing.expect(reg.unregister("temp"));
    try std.testing.expect(!reg.isBot("temp"));
    try std.testing.expect(reg.info("temp") == null);

    // Removing again reports false.
    try std.testing.expect(!reg.unregister("temp"));

    // Removing a never-registered account reports false.
    try std.testing.expect(!reg.unregister("never"));
}

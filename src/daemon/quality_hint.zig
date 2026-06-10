//! QualityHint — per-(channel, participant) media bitrate hints for the Orochi
//! IRC daemon.
//!
//! Each entry records a suggested media bitrate, expressed in kilobits per
//! second, for a single participant within a single channel. Hints are stored
//! in a flat hash map keyed by a composite "channel\x00participant" string.
//!
//! Storage discipline:
//!   - The bitrate value is stored inline (a plain u32); there is no per-entry
//!     value allocation.
//!   - Only the composite keys are heap-owned. They are duplicated on insert
//!     and freed on removal / teardown.
//!
//! This module imports only `std` and is self-contained.

const std = @import("std");

/// Separator byte joining the channel and participant segments of a key.
/// NUL is illegal inside both channel names and participant identifiers, so it
/// is an unambiguous delimiter and a safe prefix boundary for channel scans.
const KEY_SEP: u8 = 0;

/// Bitrate returned when no hint has been recorded for a participant.
const DEFAULT_KBPS: u32 = 0;

pub const QualityHint = struct {
    allocator: std.mem.Allocator,
    map: std.StringHashMap(u32),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .map = std.StringHashMap(u32).init(allocator),
        };
    }

    /// Release every owned key and the backing map. Safe to call once.
    pub fn deinit(self: *Self) void {
        var it = self.map.keyIterator();
        while (it.next()) |key_ptr| {
            self.allocator.free(key_ptr.*);
        }
        self.map.deinit();
        self.* = undefined;
    }

    /// Build the composite "channel\x00participant" key into a freshly
    /// allocated, caller-owned buffer.
    fn composeKey(self: *Self, channel: []const u8, pid: []const u8) ![]u8 {
        const total = channel.len + 1 + pid.len;
        const buf = try self.allocator.alloc(u8, total);
        @memcpy(buf[0..channel.len], channel);
        buf[channel.len] = KEY_SEP;
        @memcpy(buf[channel.len + 1 ..], pid);
        return buf;
    }

    /// Record (or overwrite) the bitrate hint for a participant in a channel.
    /// On overwrite the existing key is retained and only the value updated, so
    /// no extra allocation occurs.
    pub fn set(self: *Self, channel: []const u8, pid: []const u8, kbps: u32) !void {
        const key = try self.composeKey(channel, pid);
        const gop = self.map.getOrPut(key) catch |err| {
            self.allocator.free(key);
            return err;
        };
        if (gop.found_existing) {
            // Existing entry already owns an equal key; drop the duplicate.
            self.allocator.free(key);
        }
        gop.value_ptr.* = kbps;
    }

    /// Return the recorded bitrate hint, or `DEFAULT_KBPS` when unset.
    pub fn get(self: *Self, channel: []const u8, pid: []const u8) u32 {
        const key = self.composeKey(channel, pid) catch return DEFAULT_KBPS;
        defer self.allocator.free(key);
        return self.map.get(key) orelse DEFAULT_KBPS;
    }

    /// Remove a single participant's hint. Returns true if an entry existed.
    pub fn clearParticipant(self: *Self, channel: []const u8, pid: []const u8) bool {
        const key = self.composeKey(channel, pid) catch return false;
        defer self.allocator.free(key);
        if (self.map.fetchRemove(key)) |kv| {
            self.allocator.free(kv.key);
            return true;
        }
        return false;
    }

    /// Remove every hint belonging to a channel (all keys beginning with
    /// "channel\x00"). Returns the number of entries removed.
    pub fn clearChannel(self: *Self, channel: []const u8) usize {
        // Build the "channel\x00" prefix once for matching.
        const prefix = self.allocator.alloc(u8, channel.len + 1) catch return 0;
        defer self.allocator.free(prefix);
        @memcpy(prefix[0..channel.len], channel);
        prefix[channel.len] = KEY_SEP;

        // Collect matching keys first; mutating the map mid-iteration is unsafe.
        var doomed: std.ArrayList([]const u8) = .empty;
        defer doomed.deinit(self.allocator);

        var it = self.map.keyIterator();
        while (it.next()) |key_ptr| {
            const key = key_ptr.*;
            if (key.len >= prefix.len and std.mem.eql(u8, key[0..prefix.len], prefix)) {
                doomed.append(self.allocator, key) catch return 0;
            }
        }

        var removed: usize = 0;
        for (doomed.items) |key| {
            if (self.map.fetchRemove(key)) |kv| {
                self.allocator.free(kv.key);
                removed += 1;
            }
        }
        return removed;
    }
};

test "set/get/default" {
    const allocator = std.testing.allocator;
    var qh = QualityHint.init(allocator);
    defer qh.deinit();

    // Unset participants fall back to the default.
    try std.testing.expectEqual(@as(u32, 0), qh.get("#river", "drift-01"));

    try qh.set("#river", "drift-01", 256);
    try std.testing.expectEqual(@as(u32, 256), qh.get("#river", "drift-01"));

    // Overwrite updates value without leaking a key.
    try qh.set("#river", "drift-01", 512);
    try std.testing.expectEqual(@as(u32, 512), qh.get("#river", "drift-01"));

    // Distinct participant remains independent.
    try qh.set("#river", "drift-02", 96);
    try std.testing.expectEqual(@as(u32, 512), qh.get("#river", "drift-01"));
    try std.testing.expectEqual(@as(u32, 96), qh.get("#river", "drift-02"));
}

test "clearParticipant" {
    const allocator = std.testing.allocator;
    var qh = QualityHint.init(allocator);
    defer qh.deinit();

    try qh.set("#delta", "node-a", 128);
    try qh.set("#delta", "node-b", 384);

    // Removing a present entry reports true and resets to default.
    try std.testing.expect(qh.clearParticipant("#delta", "node-a"));
    try std.testing.expectEqual(@as(u32, 0), qh.get("#delta", "node-a"));

    // A second removal of the same key reports false.
    try std.testing.expect(!qh.clearParticipant("#delta", "node-a"));

    // Removing an unknown participant reports false; siblings untouched.
    try std.testing.expect(!qh.clearParticipant("#delta", "ghost"));
    try std.testing.expectEqual(@as(u32, 384), qh.get("#delta", "node-b"));
}

test "clearChannel scoping" {
    const allocator = std.testing.allocator;
    var qh = QualityHint.init(allocator);
    defer qh.deinit();

    try qh.set("#tide", "p1", 64);
    try qh.set("#tide", "p2", 128);
    try qh.set("#tide", "p3", 256);
    // A channel whose name is a prefix-confusable of "#tide" must NOT match,
    // because the NUL separator anchors the prefix boundary.
    try qh.set("#tidewater", "p1", 999);

    const removed = qh.clearChannel("#tide");
    try std.testing.expectEqual(@as(usize, 3), removed);

    // All "#tide" hints are gone.
    try std.testing.expectEqual(@as(u32, 0), qh.get("#tide", "p1"));
    try std.testing.expectEqual(@as(u32, 0), qh.get("#tide", "p2"));
    try std.testing.expectEqual(@as(u32, 0), qh.get("#tide", "p3"));

    // The look-alike channel is untouched.
    try std.testing.expectEqual(@as(u32, 999), qh.get("#tidewater", "p1"));

    // Clearing an empty/absent channel removes nothing.
    try std.testing.expectEqual(@as(usize, 0), qh.clearChannel("#tide"));
    try std.testing.expectEqual(@as(usize, 0), qh.clearChannel("#nope"));
}

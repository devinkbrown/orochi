//! Time-windowed string deduplication with owned keys.
const std = @import("std");

pub const DedupWindow = struct {
    allocator: std.mem.Allocator,
    keys: std.StringHashMap(u64),

    pub fn init(allocator: std.mem.Allocator) DedupWindow {
        return .{
            .allocator = allocator,
            .keys = std.StringHashMap(u64).init(allocator),
        };
    }

    pub fn deinit(self: *DedupWindow) void {
        var it = self.keys.iterator();
        while (it.next()) |entry| self.allocator.free(entry.key_ptr.*);
        self.keys.deinit();
        self.* = undefined;
    }

    pub fn seen(self: *DedupWindow, key: []const u8, now: u64, window_ms: u64) bool {
        if (self.keys.getEntry(key)) |entry| {
            const was_recent = insideWindow(entry.value_ptr.*, now, window_ms);
            entry.value_ptr.* = now;
            return was_recent;
        }

        const owned_key = self.allocator.dupe(u8, key) catch return false;
        self.keys.putNoClobber(owned_key, now) catch {
            self.allocator.free(owned_key);
            return false;
        };
        return false;
    }

    pub fn prune(self: *DedupWindow, now: u64, window_ms: u64) void {
        while (self.removeOneOld(now, window_ms)) {}
    }

    pub fn count(self: *const DedupWindow) usize {
        return self.keys.count();
    }

    fn removeOneOld(self: *DedupWindow, now: u64, window_ms: u64) bool {
        var it = self.keys.iterator();
        while (it.next()) |entry| {
            if (insideWindow(entry.value_ptr.*, now, window_ms)) continue;
            const removed = self.keys.fetchRemove(entry.key_ptr.*).?;
            self.allocator.free(removed.key);
            return true;
        }
        return false;
    }
};

fn insideWindow(previous: u64, now: u64, window_ms: u64) bool {
    if (previous > now) return true;
    return now - previous <= window_ms;
}

const testing = std.testing;

test "seen returns false first and true within the window" {
    var window = DedupWindow.init(testing.allocator);
    defer window.deinit();

    try testing.expect(!window.seen("m1", 100, 50));
    try testing.expect(window.seen("m1", 125, 50));
    try testing.expectEqual(@as(usize, 1), window.count());
}

test "seen returns false after expiry and records the new timestamp" {
    var window = DedupWindow.init(testing.allocator);
    defer window.deinit();

    try testing.expect(!window.seen("m1", 100, 50));
    try testing.expect(!window.seen("m1", 151, 50));
    try testing.expect(window.seen("m1", 200, 50));
}

test "different keys are tracked independently" {
    var window = DedupWindow.init(testing.allocator);
    defer window.deinit();

    try testing.expect(!window.seen("a", 10, 10));
    try testing.expect(!window.seen("b", 10, 10));
    try testing.expect(window.seen("a", 15, 10));
    try testing.expect(window.seen("b", 20, 10));
}

test "prune removes keys outside the supplied window" {
    var window = DedupWindow.init(testing.allocator);
    defer window.deinit();

    _ = window.seen("old", 10, 100);
    _ = window.seen("fresh", 80, 100);
    window.prune(110, 30);

    try testing.expectEqual(@as(usize, 1), window.count());
    try testing.expect(window.seen("fresh", 110, 30));
    try testing.expect(!window.seen("old", 112, 30));
}

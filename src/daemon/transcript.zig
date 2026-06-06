//! Per-channel live transcript — a bounded ring of speaker-tagged captions for a
//! media call. Captions are pushed by participants (client-side speech-to-text),
//! fanned out live by the server, and retained briefly so a late joiner can pull
//! the recent context (`MEDIA TRANSCRIPT`). The ring is cleared when the call
//! ends. Owned strings; FIFO eviction past the per-channel cap.
const std = @import("std");

pub const max_text_bytes: usize = 400;
pub const max_speaker_bytes: usize = 64;
pub const max_per_channel: usize = 128;
pub const max_channels: usize = 4096;

pub const Error = std.mem.Allocator.Error || error{ TooManyChannels, CaptionInvalid };

pub const Caption = struct {
    speaker: []u8,
    text: []u8,
    at_ms: i64,

    fn deinit(self: *Caption, allocator: std.mem.Allocator) void {
        allocator.free(self.speaker);
        allocator.free(self.text);
    }
};

const Ring = struct {
    items: std.ArrayListUnmanaged(Caption) = .empty,

    fn deinit(self: *Ring, allocator: std.mem.Allocator) void {
        for (self.items.items) |*c| c.deinit(allocator);
        self.items.deinit(allocator);
    }
};

pub const TranscriptLog = struct {
    allocator: std.mem.Allocator,
    channels: std.StringHashMap(Ring),

    pub fn init(allocator: std.mem.Allocator) TranscriptLog {
        return .{ .allocator = allocator, .channels = std.StringHashMap(Ring).init(allocator) };
    }

    pub fn deinit(self: *TranscriptLog) void {
        var it = self.channels.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.channels.deinit();
        self.* = undefined;
    }

    /// Append a caption to `channel`'s transcript (FIFO-evicting the oldest past
    /// the cap). `speaker`/`text` are copied. Returns the new depth.
    pub fn push(self: *TranscriptLog, channel: []const u8, speaker: []const u8, text: []const u8, at_ms: i64) Error!usize {
        if (speaker.len == 0 or speaker.len > max_speaker_bytes) return error.CaptionInvalid;
        if (text.len == 0 or text.len > max_text_bytes) return error.CaptionInvalid;
        const ring = try self.ensure(channel);

        const speaker_owned = try self.allocator.dupe(u8, speaker);
        errdefer self.allocator.free(speaker_owned);
        const text_owned = try self.allocator.dupe(u8, text);
        errdefer self.allocator.free(text_owned);
        try ring.items.append(self.allocator, .{ .speaker = speaker_owned, .text = text_owned, .at_ms = at_ms });
        if (ring.items.items.len > max_per_channel) {
            var evicted = ring.items.orderedRemove(0);
            evicted.deinit(self.allocator);
        }
        return ring.items.items.len;
    }

    /// Borrowed recent captions for `channel`, oldest-first (empty if none).
    pub fn recent(self: *const TranscriptLog, channel: []const u8) []const Caption {
        const ring = self.channels.getPtr(channel) orelse return &.{};
        return ring.items.items;
    }

    /// Drop a channel's transcript (e.g. when its call ends). Returns the count.
    pub fn clearChannel(self: *TranscriptLog, channel: []const u8) usize {
        const entry = self.channels.getEntry(channel) orelse return 0;
        const n = entry.value_ptr.items.items.len;
        entry.value_ptr.deinit(self.allocator);
        const key = entry.key_ptr.*;
        self.channels.removeByPtr(entry.key_ptr);
        self.allocator.free(key);
        return n;
    }

    fn ensure(self: *TranscriptLog, channel: []const u8) Error!*Ring {
        if (self.channels.getPtr(channel)) |ring| return ring;
        if (self.channels.count() >= max_channels) return error.TooManyChannels;
        const owned = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(owned);
        try self.channels.putNoClobber(owned, .{});
        return self.channels.getPtr(channel).?;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "push/recent/clear round-trip" {
    var t = TranscriptLog.init(testing.allocator);
    defer t.deinit();
    try testing.expectEqual(@as(usize, 0), t.recent("#c").len);
    try testing.expectEqual(@as(usize, 1), try t.push("#c", "alice", "hello", 1));
    try testing.expectEqual(@as(usize, 2), try t.push("#c", "bob", "hi", 2));
    const r = t.recent("#c");
    try testing.expectEqualStrings("alice", r[0].speaker);
    try testing.expectEqualStrings("hi", r[1].text);
    try testing.expectEqual(@as(usize, 2), t.clearChannel("#c"));
    try testing.expectEqual(@as(usize, 0), t.recent("#c").len);
}

test "ring evicts oldest past the per-channel cap" {
    var t = TranscriptLog.init(testing.allocator);
    defer t.deinit();
    var i: usize = 0;
    while (i < max_per_channel + 10) : (i += 1) _ = try t.push("#c", "s", "m", @intCast(i));
    try testing.expectEqual(max_per_channel, t.recent("#c").len);
    // The 10 oldest were evicted, so the front timestamp advanced to 10.
    try testing.expectEqual(@as(i64, 10), t.recent("#c")[0].at_ms);
}

test "rejects empty/oversize captions" {
    var t = TranscriptLog.init(testing.allocator);
    defer t.deinit();
    try testing.expectError(error.CaptionInvalid, t.push("#c", "alice", "", 0));
    try testing.expectError(error.CaptionInvalid, t.push("#c", "", "hi", 0));
}

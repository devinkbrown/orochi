//! Per-channel live transcript — a bounded ring of speaker-tagged captions for a
//! media call. Captions are pushed by participants (client-side speech-to-text),
//! fanned out live by the server, and retained briefly so a late joiner can pull
//! the recent context (`MEDIA TRANSCRIPT`). The ring is cleared when the call
//! ends. Owned strings; FIFO eviction past the per-channel cap.
const std = @import("std");
const toml = @import("../proto/toml.zig");

pub const max_text_bytes: usize = 400;
pub const max_speaker_bytes: usize = 64;
pub const max_per_channel: usize = 128;
pub const max_channels: usize = 4096;

/// Runtime-tunable caption-ring limits. Defaults equal the historical bare
/// constants above; `applyToml` overlays the `[media.captions]` section.
pub const Config = struct {
    max_text_bytes: usize = max_text_bytes,
    max_speaker_bytes: usize = max_speaker_bytes,
    max_per_channel: usize = max_per_channel,
    max_channels: usize = max_channels,
};

/// Overlay `[media.captions]` keys from a parsed TOML document onto `cfg`.
/// Absent keys leave the existing (default) value untouched.
pub fn applyToml(cfg: *Config, doc: *const toml.Document) void {
    if (doc.getUint("media.captions.max_text_bytes")) |v| cfg.max_text_bytes = @intCast(v);
    if (doc.getUint("media.captions.max_speaker_bytes")) |v| cfg.max_speaker_bytes = @intCast(v);
    if (doc.getUint("media.captions.ring_depth_per_channel")) |v| cfg.max_per_channel = @intCast(v);
    if (doc.getUint("media.captions.max_channels")) |v| cfg.max_channels = @intCast(v);
}

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
    config: Config,

    pub fn init(allocator: std.mem.Allocator) TranscriptLog {
        return initConfig(allocator, .{});
    }

    pub fn initConfig(allocator: std.mem.Allocator, config: Config) TranscriptLog {
        return .{ .allocator = allocator, .channels = std.StringHashMap(Ring).init(allocator), .config = config };
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
        if (speaker.len == 0 or speaker.len > self.config.max_speaker_bytes) return error.CaptionInvalid;
        if (text.len == 0 or text.len > self.config.max_text_bytes) return error.CaptionInvalid;
        const ring = try self.ensure(channel);

        const speaker_owned = try self.allocator.dupe(u8, speaker);
        errdefer self.allocator.free(speaker_owned);
        const text_owned = try self.allocator.dupe(u8, text);
        errdefer self.allocator.free(text_owned);
        try ring.items.append(self.allocator, .{ .speaker = speaker_owned, .text = text_owned, .at_ms = at_ms });
        if (ring.items.items.len > self.config.max_per_channel) {
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
        if (self.channels.count() >= self.config.max_channels) return error.TooManyChannels;
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

test "applyToml defaults match historical constants" {
    var doc = try toml.parse(testing.allocator, "");
    defer doc.deinit(testing.allocator);
    var cfg: Config = .{};
    applyToml(&cfg, &doc);
    try testing.expectEqual(max_text_bytes, cfg.max_text_bytes);
    try testing.expectEqual(max_speaker_bytes, cfg.max_speaker_bytes);
    try testing.expectEqual(max_per_channel, cfg.max_per_channel);
    try testing.expectEqual(max_channels, cfg.max_channels);
}

test "applyToml overlays media.captions keys" {
    const src =
        \\[media.captions]
        \\max_text_bytes = 1000
        \\max_speaker_bytes = 80
        \\ring_depth_per_channel = 8
        \\max_channels = 99
    ;
    var doc = try toml.parse(testing.allocator, src);
    defer doc.deinit(testing.allocator);
    var cfg: Config = .{};
    applyToml(&cfg, &doc);
    try testing.expectEqual(@as(usize, 1000), cfg.max_text_bytes);
    try testing.expectEqual(@as(usize, 80), cfg.max_speaker_bytes);
    try testing.expectEqual(@as(usize, 8), cfg.max_per_channel);
    try testing.expectEqual(@as(usize, 99), cfg.max_channels);
}

test "config-driven ring depth evicts at the overlaid cap" {
    var t = TranscriptLog.initConfig(testing.allocator, .{ .max_per_channel = 3 });
    defer t.deinit();
    var i: usize = 0;
    while (i < 10) : (i += 1) _ = try t.push("#c", "s", "m", @intCast(i));
    try testing.expectEqual(@as(usize, 3), t.recent("#c").len);
    try testing.expectEqual(@as(i64, 7), t.recent("#c")[0].at_ms);
}

const std = @import("std");
const toml = @import("../proto/toml.zig");

pub const max_channels = 4096;
pub const max_sessions_per_channel = 1024;
pub const max_key_bytes = 128;

/// Runtime-tunable recording-index bounds. Defaults equal the bare constants
/// above; `applyToml` overlays the `[media.recording]` section.
pub const Config = struct {
    max_channels: usize = max_channels,
    max_sessions_per_channel: usize = max_sessions_per_channel,
    max_key_bytes: usize = max_key_bytes,
};

/// Overlay `[media.recording]` keys from a parsed TOML document onto `cfg`.
/// Shares the section with `recording_consent`; only index-owned keys are read.
pub fn applyToml(cfg: *Config, doc: *const toml.Document) void {
    if (doc.getUint("media.recording.max_channels")) |v| cfg.max_channels = @intCast(v);
    if (doc.getUint("media.recording.max_sessions_per_channel")) |v| cfg.max_sessions_per_channel = @intCast(v);
    if (doc.getUint("media.recording.max_key_bytes")) |v| cfg.max_key_bytes = @intCast(v);
}

pub const RecordingIndex = struct {
    const Self = @This();
    const SessionList = std.ArrayList(Session);

    pub const Session = struct {
        id: []const u8,
        by: []const u8,
        started_ms: i64,
        stopped_ms: i64 = 0,
    };

    allocator: std.mem.Allocator,
    by_channel: std.StringHashMap(SessionList),
    config: Config,

    pub fn init(allocator: std.mem.Allocator) Self {
        return initConfig(allocator, .{});
    }

    pub fn initConfig(allocator: std.mem.Allocator, config: Config) Self {
        return .{
            .allocator = allocator,
            .by_channel = std.StringHashMap(SessionList).init(allocator),
            .config = config,
        };
    }

    pub fn deinit(self: *Self) void {
        var it = self.by_channel.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            freeSessions(self.allocator, entry.value_ptr);
        }
        self.by_channel.deinit();
        self.* = undefined;
    }

    pub fn start(self: *Self, channel: []const u8, id: []const u8, by: []const u8, now: i64) !void {
        try self.checkKey(channel);
        try self.checkKey(id);
        try self.checkKey(by);

        // `owned_id`/`owned_by` are freed by these errdefers on every error path
        // until ownership transfers into the SessionList (which then owns them and
        // frees them in `freeSessions`). Do NOT add a second guard for these — a
        // redundant guard double-frees on the capacity-exceeded paths below.
        const owned_id = try self.allocator.dupe(u8, id);
        errdefer self.allocator.free(owned_id);
        const owned_by = try self.allocator.dupe(u8, by);
        errdefer self.allocator.free(owned_by);

        const session: Session = .{
            .id = owned_id,
            .by = owned_by,
            .started_ms = now,
        };

        if (self.by_channel.getPtr(channel)) |sessions| {
            if (sessions.items.len >= self.config.max_sessions_per_channel) return error.TooManySessions;
            try sessions.append(self.allocator, session);
            return;
        }

        if (self.by_channel.count() >= self.config.max_channels) return error.TooManyChannels;

        const owned_channel = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(owned_channel);
        var sessions: SessionList = .empty;
        var list_owned = false;
        errdefer if (!list_owned) sessions.deinit(self.allocator);

        try sessions.append(self.allocator, session);
        try self.by_channel.put(owned_channel, sessions);
        list_owned = true;
    }

    pub fn stop(self: *Self, channel: []const u8, id: []const u8, now: i64) bool {
        const sessions = self.by_channel.getPtr(channel) orelse return false;
        for (sessions.items) |*session| {
            if (session.stopped_ms == 0 and std.mem.eql(u8, session.id, id)) {
                session.stopped_ms = now;
                return true;
            }
        }
        return false;
    }

    pub fn list(self: *const Self, channel: []const u8) []const Session {
        if (self.by_channel.get(channel)) |sessions| return sessions.items;
        return &.{};
    }

    fn freeSessions(allocator: std.mem.Allocator, sessions: *SessionList) void {
        for (sessions.items) |session| {
            allocator.free(session.id);
            allocator.free(session.by);
        }
        sessions.deinit(allocator);
    }

    fn checkKey(self: *const Self, value: []const u8) !void {
        if (value.len == 0) return error.EmptyKey;
        if (value.len > self.config.max_key_bytes) return error.KeyTooLong;
    }
};

test "start records sessions by channel" {
    var index = RecordingIndex.init(std.testing.allocator);
    defer index.deinit();

    try index.start("#alpha", "rec-1", "maki", 100);
    try index.start("#alpha", "rec-2", "sora", 200);
    try index.start("#beta", "rec-3", "ren", 300);

    const alpha = index.list("#alpha");
    try std.testing.expectEqual(@as(usize, 2), alpha.len);
    try std.testing.expectEqualStrings("rec-1", alpha[0].id);
    try std.testing.expectEqualStrings("sora", alpha[1].by);
    try std.testing.expectEqual(@as(i64, 300), index.list("#beta")[0].started_ms);
}

test "stop marks only the first active matching session" {
    var index = RecordingIndex.init(std.testing.allocator);
    defer index.deinit();

    try index.start("#alpha", "rec-1", "maki", 100);
    try index.start("#alpha", "rec-1", "maki", 150);

    try std.testing.expect(index.stop("#alpha", "rec-1", 250));
    const sessions = index.list("#alpha");
    try std.testing.expectEqual(@as(i64, 250), sessions[0].stopped_ms);
    try std.testing.expectEqual(@as(i64, 0), sessions[1].stopped_ms);
}

test "missing channels and duplicate stops are stable" {
    var index = RecordingIndex.init(std.testing.allocator);
    defer index.deinit();

    try index.start("#alpha", "rec-1", "maki", 100);

    try std.testing.expectEqual(@as(usize, 0), index.list("#none").len);
    try std.testing.expect(!index.stop("#none", "rec-1", 200));
    try std.testing.expect(index.stop("#alpha", "rec-1", 200));
    try std.testing.expect(!index.stop("#alpha", "rec-1", 300));
}

test "empty and oversized keys are rejected" {
    var index = RecordingIndex.init(std.testing.allocator);
    defer index.deinit();

    try std.testing.expectError(error.EmptyKey, index.start("", "rec-1", "maki", 100));

    var long: [129]u8 = undefined;
    @memset(&long, 'x');
    try std.testing.expectError(error.KeyTooLong, index.start("#alpha", &long, "maki", 100));
}

test "applyToml defaults match historical constants" {
    var doc = try toml.parse(std.testing.allocator, "");
    defer doc.deinit(std.testing.allocator);
    var cfg: Config = .{};
    applyToml(&cfg, &doc);
    try std.testing.expectEqual(@as(usize, max_channels), cfg.max_channels);
    try std.testing.expectEqual(@as(usize, max_sessions_per_channel), cfg.max_sessions_per_channel);
    try std.testing.expectEqual(@as(usize, max_key_bytes), cfg.max_key_bytes);
}

test "applyToml overlays media.recording keys and drives the per-channel cap" {
    const src =
        \\[media.recording]
        \\max_channels = 3
        \\max_sessions_per_channel = 2
        \\max_key_bytes = 8
    ;
    var doc = try toml.parse(std.testing.allocator, src);
    defer doc.deinit(std.testing.allocator);
    var cfg: Config = .{};
    applyToml(&cfg, &doc);
    try std.testing.expectEqual(@as(usize, 2), cfg.max_sessions_per_channel);

    var index = RecordingIndex.initConfig(std.testing.allocator, cfg);
    defer index.deinit();
    try index.start("#a", "r1", "m", 1);
    try index.start("#a", "r2", "m", 2);
    try std.testing.expectError(error.TooManySessions, index.start("#a", "r3", "m", 3));
    try std.testing.expectError(error.KeyTooLong, index.start("#a", "012345678", "m", 4));
}

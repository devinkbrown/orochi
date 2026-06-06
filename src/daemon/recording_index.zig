const std = @import("std");

pub const RecordingIndex = struct {
    const Self = @This();
    const SessionList = std.ArrayList(Session);

    const max_channels = 4096;
    const max_sessions_per_channel = 1024;
    const max_key_bytes = 128;

    pub const Session = struct {
        id: []const u8,
        by: []const u8,
        started_ms: i64,
        stopped_ms: i64 = 0,
    };

    allocator: std.mem.Allocator,
    by_channel: std.StringHashMap(SessionList),

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .by_channel = std.StringHashMap(SessionList).init(allocator),
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
        try checkKey(channel);
        try checkKey(id);
        try checkKey(by);

        const owned_id = try self.allocator.dupe(u8, id);
        errdefer self.allocator.free(owned_id);
        const owned_by = try self.allocator.dupe(u8, by);
        errdefer self.allocator.free(owned_by);
        var session_owned = false;
        errdefer if (!session_owned) {
            self.allocator.free(owned_id);
            self.allocator.free(owned_by);
        };

        const session: Session = .{
            .id = owned_id,
            .by = owned_by,
            .started_ms = now,
        };

        if (self.by_channel.getPtr(channel)) |sessions| {
            if (sessions.items.len >= max_sessions_per_channel) return error.TooManySessions;
            try sessions.append(self.allocator, session);
            session_owned = true;
            return;
        }

        if (self.by_channel.count() >= max_channels) return error.TooManyChannels;

        const owned_channel = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(owned_channel);
        var sessions: SessionList = .empty;
        var list_owned = false;
        errdefer if (!list_owned) sessions.deinit(self.allocator);

        try sessions.append(self.allocator, session);
        try self.by_channel.put(owned_channel, sessions);
        list_owned = true;
        session_owned = true;
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

    fn checkKey(value: []const u8) !void {
        if (value.len == 0) return error.EmptyKey;
        if (value.len > max_key_bytes) return error.KeyTooLong;
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

//! Per-channel media rooms — the daemon-side manager that maps an IRC channel
//! to a Suimyaku media Session (the SFU participant model). This is the control
//! plane only: it tracks who is in a call and what they publish (voice/video/
//! screen) plus mute/speaking state. The media bytes themselves flow over the
//! transport substrate, not through here.
//!
//! Rooms are created on first join and pruned when empty. Each room is heap-
//! allocated (the Session value is large) and keyed by an owned channel name.
const std = @import("std");
const media = @import("../substrate/suimyaku/media.zig");

pub const max_participants: usize = 64;
pub const Room = media.Session(max_participants);
pub const MediaKind = media.MediaKind;
pub const Participant = media.Participant;

pub const Error = std.mem.Allocator.Error || media.SessionError;

/// Parse a media-kind token (case-insensitive). "audio" is an alias for voice.
pub fn parseKind(name: []const u8) ?MediaKind {
    if (std.ascii.eqlIgnoreCase(name, "voice") or std.ascii.eqlIgnoreCase(name, "audio")) return .voice;
    if (std.ascii.eqlIgnoreCase(name, "video")) return .video;
    if (std.ascii.eqlIgnoreCase(name, "screen")) return .screen;
    return null;
}

pub fn kindName(kind: MediaKind) []const u8 {
    return switch (kind) {
        .voice => "voice",
        .video => "video",
        .screen => "screen",
    };
}

pub const MediaRooms = struct {
    allocator: std.mem.Allocator,
    rooms: std.StringHashMap(*Room),

    pub fn init(allocator: std.mem.Allocator) MediaRooms {
        return .{ .allocator = allocator, .rooms = std.StringHashMap(*Room).init(allocator) };
    }

    pub fn deinit(self: *MediaRooms) void {
        var it = self.rooms.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.rooms.deinit();
        self.* = undefined;
    }

    /// The room for `channel`, or null when no call is active there.
    pub fn room(self: *MediaRooms, channel: []const u8) ?*Room {
        return self.rooms.get(channel);
    }

    /// Participant `pid` joins `channel`'s call publishing `kind` (creating the
    /// room on first join).
    pub fn join(self: *MediaRooms, channel: []const u8, pid: []const u8, kind: MediaKind) Error!void {
        const id = try media.ParticipantId.init(pid);
        const r = try self.ensure(channel);
        try r.join(id, kind);
    }

    /// Participant `pid` leaves `channel` entirely (all kinds). Returns true if
    /// they were present; prunes the room when it empties.
    pub fn leaveAll(self: *MediaRooms, channel: []const u8, pid: []const u8) bool {
        const entry = self.rooms.getEntry(channel) orelse return false;
        const id = media.ParticipantId.init(pid) catch return false;
        entry.value_ptr.*.leaveAll(id) catch return false;
        if (entry.value_ptr.*.count() == 0) self.dropRoom(entry);
        return true;
    }

    pub fn setMuted(self: *MediaRooms, channel: []const u8, pid: []const u8, kind: MediaKind, muted: bool) bool {
        const r = self.rooms.get(channel) orelse return false;
        const id = media.ParticipantId.init(pid) catch return false;
        r.setMuted(id, kind, muted) catch return false;
        return true;
    }

    pub fn setSpeaking(self: *MediaRooms, channel: []const u8, pid: []const u8, kind: MediaKind, speaking: bool) bool {
        const r = self.rooms.get(channel) orelse return false;
        const id = media.ParticipantId.init(pid) catch return false;
        r.setSpeaking(id, kind, speaking) catch return false;
        return true;
    }

    /// Borrowed participant slice for `channel` (empty if no room).
    pub fn roster(self: *MediaRooms, channel: []const u8) []const Participant {
        const r = self.rooms.get(channel) orelse return &.{};
        return r.participants[0..r.len];
    }

    fn ensure(self: *MediaRooms, channel: []const u8) Error!*Room {
        if (self.rooms.get(channel)) |r| return r;
        const r = try self.allocator.create(Room);
        errdefer self.allocator.destroy(r);
        r.* = Room.init();
        const owned = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(owned);
        try self.rooms.putNoClobber(owned, r);
        return r;
    }

    fn dropRoom(self: *MediaRooms, entry: std.StringHashMap(*Room).Entry) void {
        const key = entry.key_ptr.*;
        const r = entry.value_ptr.*;
        self.rooms.removeByPtr(entry.key_ptr);
        self.allocator.free(key);
        self.allocator.destroy(r);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "join/roster/leave lifecycle prunes empty rooms" {
    var m = MediaRooms.init(testing.allocator);
    defer m.deinit();
    try testing.expect(m.room("#c") == null);
    try m.join("#c", "alice", .voice);
    try m.join("#c", "bob", .voice);
    try testing.expectEqual(@as(usize, 2), m.roster("#c").len);
    try testing.expect(m.leaveAll("#c", "alice"));
    try testing.expectEqual(@as(usize, 1), m.roster("#c").len);
    try testing.expect(m.leaveAll("#c", "bob"));
    try testing.expect(m.room("#c") == null); // pruned
}

test "mute and speaking state track per kind" {
    var m = MediaRooms.init(testing.allocator);
    defer m.deinit();
    try m.join("#c", "alice", .voice);
    try testing.expect(m.setSpeaking("#c", "alice", .voice, true));
    const p = m.room("#c").?.participant(media.ParticipantId.init("alice") catch unreachable).?;
    try testing.expect(p.speaking.contains(.voice));
    try testing.expect(m.setMuted("#c", "alice", .voice, true));
    // muting clears speaking
    const p2 = m.room("#c").?.participant(media.ParticipantId.init("alice") catch unreachable).?;
    try testing.expect(p2.muted.contains(.voice));
    try testing.expect(!p2.speaking.contains(.voice));
}

test "parseKind accepts aliases and rejects junk" {
    try testing.expectEqual(MediaKind.voice, parseKind("AUDIO").?);
    try testing.expectEqual(MediaKind.voice, parseKind("voice").?);
    try testing.expectEqual(MediaKind.video, parseKind("Video").?);
    try testing.expectEqual(MediaKind.screen, parseKind("screen").?);
    try testing.expect(parseKind("hologram") == null);
}

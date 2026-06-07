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
const toml = @import("../proto/toml.zig");

pub const max_participants: usize = 64;
pub const Room = media.Session(max_participants);
pub const MediaKind = media.MediaKind;
pub const Participant = media.Participant;

/// Runtime-tunable media-room bounds.
///
/// `max_participants` is intentionally NOT here: it parameterizes the comptime
/// `Session(N)` roster type (`[N]Participant` inline storage) and cannot be made
/// runtime without reworking the substrate Session into heap storage. It stays a
/// comptime constant; `[media.sfu] max_participants_per_room` is DEFERRED.
///
/// Only the runtime breakout-label cap is config-driven here. Defaults equal the
/// bare constants; `applyToml` overlays the `[media.sfu]` section.
pub const Config = struct {
    max_breakout_bytes: usize = max_breakout_bytes,
};

/// Overlay `[media.sfu]` keys from a parsed TOML document onto `cfg`.
/// `max_participants_per_room` is deferred (comptime) and ignored here.
pub fn applyToml(cfg: *Config, doc: *const toml.Document) void {
    if (doc.getUint("media.sfu.max_breakout_label_bytes")) |v| cfg.max_breakout_bytes = @intCast(v);
}

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

pub const default_breakout = "main";
pub const max_breakout_bytes: usize = 32;

/// 2D position in a call's spatial-audio plane (arbitrary integer units; clients
/// scale/normalize). Default is the origin (centered / non-spatial).
pub const Position = struct { x: i32 = 0, y: i32 = 0 };

pub const MediaRooms = struct {
    allocator: std.mem.Allocator,
    config: Config,
    rooms: std.StringHashMap(*Room),
    /// Optional breakout (sub-room) label per participant, keyed by the composite
    /// "channel\x00participant". Absent = the default "main" breakout. Kept in a
    /// flat map so the substrate Session participant model stays untouched.
    breakouts: std.StringHashMap([]u8),
    /// Optional spatial-audio position per participant (same composite key).
    /// Absent = origin. Value is inline (no per-entry allocation).
    positions: std.StringHashMap(Position),
    /// Raised-hand set (same composite key). Presence of the key = hand raised.
    hands: std.StringHashMap(void),

    pub fn init(allocator: std.mem.Allocator) MediaRooms {
        return initConfig(allocator, .{});
    }

    pub fn initConfig(allocator: std.mem.Allocator, config: Config) MediaRooms {
        return .{
            .allocator = allocator,
            .config = config,
            .rooms = std.StringHashMap(*Room).init(allocator),
            .breakouts = std.StringHashMap([]u8).init(allocator),
            .positions = std.StringHashMap(Position).init(allocator),
            .hands = std.StringHashMap(void).init(allocator),
        };
    }

    pub fn deinit(self: *MediaRooms) void {
        var it = self.rooms.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.rooms.deinit();
        var bit = self.breakouts.iterator();
        while (bit.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.breakouts.deinit();
        var pit = self.positions.keyIterator();
        while (pit.next()) |key| self.allocator.free(key.*);
        self.positions.deinit();
        var hit = self.hands.keyIterator();
        while (hit.next()) |key| self.allocator.free(key.*);
        self.hands.deinit();
        self.* = undefined;
    }

    /// Build the "channel\x00participant" composite key into `buf`.
    fn breakoutKey(buf: []u8, channel: []const u8, pid: []const u8) ?[]const u8 {
        if (channel.len + 1 + pid.len > buf.len) return null;
        @memcpy(buf[0..channel.len], channel);
        buf[channel.len] = 0;
        @memcpy(buf[channel.len + 1 ..][0..pid.len], pid);
        return buf[0 .. channel.len + 1 + pid.len];
    }

    /// Assign `pid` in `channel` to breakout `name` (truncated to the cap).
    pub fn setBreakout(self: *MediaRooms, channel: []const u8, pid: []const u8, name: []const u8) Error!void {
        var kb: [256]u8 = undefined;
        const k = breakoutKey(&kb, channel, pid) orelse return;
        const trimmed = name[0..@min(name.len, self.config.max_breakout_bytes)];
        const gop = try self.breakouts.getOrPut(k);
        if (!gop.found_existing) {
            gop.key_ptr.* = self.allocator.dupe(u8, k) catch |e| {
                _ = self.breakouts.remove(k);
                return e;
            };
        } else {
            self.allocator.free(gop.value_ptr.*);
        }
        gop.value_ptr.* = try self.allocator.dupe(u8, trimmed);
    }

    /// The breakout `pid` is in within `channel` (default "main").
    pub fn breakoutOf(self: *const MediaRooms, channel: []const u8, pid: []const u8) []const u8 {
        var kb: [256]u8 = undefined;
        const k = breakoutKey(&kb, channel, pid) orelse return default_breakout;
        return self.breakouts.get(k) orelse default_breakout;
    }

    fn clearBreakout(self: *MediaRooms, channel: []const u8, pid: []const u8) void {
        var kb: [256]u8 = undefined;
        const k = breakoutKey(&kb, channel, pid) orelse return;
        if (self.breakouts.fetchRemove(k)) |kv| {
            self.allocator.free(kv.key);
            self.allocator.free(kv.value);
        }
    }

    /// Set `pid`'s spatial-audio position within `channel`.
    pub fn setPosition(self: *MediaRooms, channel: []const u8, pid: []const u8, pos: Position) Error!void {
        var kb: [256]u8 = undefined;
        const k = breakoutKey(&kb, channel, pid) orelse return;
        const gop = try self.positions.getOrPut(k);
        if (!gop.found_existing) {
            gop.key_ptr.* = self.allocator.dupe(u8, k) catch |e| {
                _ = self.positions.remove(k);
                return e;
            };
        }
        gop.value_ptr.* = pos;
    }

    /// `pid`'s position within `channel` (origin if unset).
    pub fn positionOf(self: *const MediaRooms, channel: []const u8, pid: []const u8) Position {
        var kb: [256]u8 = undefined;
        const k = breakoutKey(&kb, channel, pid) orelse return .{};
        return self.positions.get(k) orelse .{};
    }

    fn clearPosition(self: *MediaRooms, channel: []const u8, pid: []const u8) void {
        var kb: [256]u8 = undefined;
        const k = breakoutKey(&kb, channel, pid) orelse return;
        if (self.positions.fetchRemove(k)) |kv| self.allocator.free(kv.key);
    }

    /// Raise or lower `pid`'s hand in `channel`.
    pub fn setHand(self: *MediaRooms, channel: []const u8, pid: []const u8, raised: bool) Error!void {
        var kb: [256]u8 = undefined;
        const k = breakoutKey(&kb, channel, pid) orelse return;
        if (raised) {
            const gop = try self.hands.getOrPut(k);
            if (!gop.found_existing) {
                gop.key_ptr.* = self.allocator.dupe(u8, k) catch |e| {
                    _ = self.hands.remove(k);
                    return e;
                };
            }
        } else self.clearHand(channel, pid);
    }

    /// Whether `pid`'s hand is raised in `channel`.
    pub fn handRaised(self: *const MediaRooms, channel: []const u8, pid: []const u8) bool {
        var kb: [256]u8 = undefined;
        const k = breakoutKey(&kb, channel, pid) orelse return false;
        return self.hands.contains(k);
    }

    fn clearHand(self: *MediaRooms, channel: []const u8, pid: []const u8) void {
        var kb: [256]u8 = undefined;
        const k = breakoutKey(&kb, channel, pid) orelse return;
        if (self.hands.fetchRemove(k)) |kv| self.allocator.free(kv.key);
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
        self.clearBreakout(channel, pid);
        self.clearPosition(channel, pid);
        self.clearHand(channel, pid);
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

    /// Whether `pid` is currently in `channel`'s call.
    pub fn isParticipant(self: *MediaRooms, channel: []const u8, pid: []const u8) bool {
        const r = self.rooms.get(channel) orelse return false;
        const id = media.ParticipantId.init(pid) catch return false;
        return r.participant(id) != null;
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

test "breakout assignment defaults to main and clears on leave" {
    var m = MediaRooms.init(testing.allocator);
    defer m.deinit();
    try m.join("#c", "alice", .voice);
    try testing.expectEqualStrings("main", m.breakoutOf("#c", "alice"));
    try m.setBreakout("#c", "alice", "design");
    try testing.expectEqualStrings("design", m.breakoutOf("#c", "alice"));
    try m.setBreakout("#c", "alice", "ops"); // reassign frees the old value
    try testing.expectEqualStrings("ops", m.breakoutOf("#c", "alice"));
    try testing.expect(m.leaveAll("#c", "alice"));
    try testing.expectEqualStrings("main", m.breakoutOf("#c", "alice")); // cleared
}

test "spatial position defaults to origin and clears on leave" {
    var m = MediaRooms.init(testing.allocator);
    defer m.deinit();
    try m.join("#c", "alice", .voice);
    try testing.expectEqual(Position{ .x = 0, .y = 0 }, m.positionOf("#c", "alice"));
    try m.setPosition("#c", "alice", .{ .x = -120, .y = 80 });
    try testing.expectEqual(Position{ .x = -120, .y = 80 }, m.positionOf("#c", "alice"));
    try m.setPosition("#c", "alice", .{ .x = 5, .y = 5 }); // overwrite in place
    try testing.expectEqual(Position{ .x = 5, .y = 5 }, m.positionOf("#c", "alice"));
    try testing.expect(m.leaveAll("#c", "alice"));
    try testing.expectEqual(Position{ .x = 0, .y = 0 }, m.positionOf("#c", "alice")); // cleared
}

test "raise-hand toggles and clears on leave" {
    var m = MediaRooms.init(testing.allocator);
    defer m.deinit();
    try m.join("#c", "alice", .voice);
    try testing.expect(!m.handRaised("#c", "alice"));
    try m.setHand("#c", "alice", true);
    try testing.expect(m.handRaised("#c", "alice"));
    try m.setHand("#c", "alice", true); // idempotent
    try testing.expect(m.handRaised("#c", "alice"));
    try m.setHand("#c", "alice", false);
    try testing.expect(!m.handRaised("#c", "alice"));
    try m.setHand("#c", "alice", true);
    try testing.expect(m.leaveAll("#c", "alice"));
    try testing.expect(!m.handRaised("#c", "alice")); // cleared on leave
}

test "parseKind accepts aliases and rejects junk" {
    try testing.expectEqual(MediaKind.voice, parseKind("AUDIO").?);
    try testing.expectEqual(MediaKind.voice, parseKind("voice").?);
    try testing.expectEqual(MediaKind.video, parseKind("Video").?);
    try testing.expectEqual(MediaKind.screen, parseKind("screen").?);
    try testing.expect(parseKind("hologram") == null);
}

test "applyToml defaults match historical constants" {
    var doc = try toml.parse(testing.allocator, "");
    defer doc.deinit(testing.allocator);
    var cfg: Config = .{};
    applyToml(&cfg, &doc);
    try testing.expectEqual(max_breakout_bytes, cfg.max_breakout_bytes);
}

test "applyToml overlays media.sfu breakout label cap" {
    const src =
        \\[media.sfu]
        \\max_breakout_label_bytes = 4
        \\max_participants_per_room = 8
    ;
    var doc = try toml.parse(testing.allocator, src);
    defer doc.deinit(testing.allocator);
    var cfg: Config = .{};
    applyToml(&cfg, &doc);
    try testing.expectEqual(@as(usize, 4), cfg.max_breakout_bytes);

    var m = MediaRooms.initConfig(testing.allocator, cfg);
    defer m.deinit();
    try m.join("#c", "alice", .voice);
    try m.setBreakout("#c", "alice", "engineering"); // truncated to 4 bytes
    try testing.expectEqualStrings("engi", m.breakoutOf("#c", "alice"));
}

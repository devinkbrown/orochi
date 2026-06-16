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
const sdp = @import("../proto/sdp.zig");

pub const default_max_participants: usize = 64;
pub const max_participants: usize = 256;
pub const Room = media.Session(max_participants);
pub const MediaKind = media.MediaKind;
pub const Participant = media.Participant;

/// Runtime-tunable media-room bounds. `max_participants` is still the inline
/// `Session(N)` ceiling; `Config.max_participants` is a runtime cap below it.
pub const Config = struct {
    max_participants: usize = default_max_participants,
    max_breakout_bytes: usize = max_breakout_bytes,
};

/// Overlay media room keys from a parsed TOML document onto `cfg`.
pub fn applyToml(cfg: *Config, doc: *const toml.Document) void {
    if (doc.getUint("media.max_participants")) |v| cfg.max_participants = @intCast(v);
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

/// Max distinct codecs a negotiated call profile retains.
pub const max_profile_codecs: usize = 4;

/// The codec/FEC set agreed for a channel's call, established by `MEDIA OFFER`
/// and used as the baseline a later `MEDIA ANSWER` negotiates against. Stored
/// fully inline (all scalar fields) so no per-call heap allocation is needed.
pub const CallProfile = struct {
    codecs: [max_profile_codecs]sdp.Codec = undefined,
    codec_count: u8 = 0,
    fec: sdp.Fec = .{ .scheme = .none, .redundancy = 0 },

    /// Borrowed view of the negotiated codecs.
    pub fn slice(self: *const CallProfile) []const sdp.Codec {
        return self.codecs[0..self.codec_count];
    }
};

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
    /// Negotiated codec/FEC profile per channel (the call's agreed media set),
    /// keyed by an owned channel name. Established by `MEDIA OFFER`; consulted by
    /// `MEDIA ANSWER`. Cleared when the call ends.
    profiles: std.StringHashMap(CallProfile),

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
            .profiles = std.StringHashMap(CallProfile).init(allocator),
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
        var fit = self.profiles.keyIterator();
        while (fit.next()) |key| self.allocator.free(key.*);
        self.profiles.deinit();
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
        const owned_value = try self.allocator.dupe(u8, trimmed);
        var value_stored = false;
        errdefer if (!value_stored) self.allocator.free(owned_value);
        const gop = try self.breakouts.getOrPut(k);
        if (!gop.found_existing) {
            gop.key_ptr.* = self.allocator.dupe(u8, k) catch |e| {
                _ = self.breakouts.remove(k);
                return e;
            };
        } else {
            self.allocator.free(gop.value_ptr.*);
        }
        gop.value_ptr.* = owned_value;
        value_stored = true;
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

    /// Record the call's negotiated codec/FEC set for `channel` (overwrites any
    /// prior profile). `codecs` is copied inline (truncated to the cap).
    pub fn setProfile(self: *MediaRooms, channel: []const u8, codecs: []const sdp.Codec, fec: sdp.Fec) Error!void {
        var prof = CallProfile{ .fec = fec };
        const n = @min(codecs.len, max_profile_codecs);
        @memcpy(prof.codecs[0..n], codecs[0..n]);
        prof.codec_count = @intCast(n);
        const gop = try self.profiles.getOrPut(channel);
        if (!gop.found_existing) {
            gop.key_ptr.* = self.allocator.dupe(u8, channel) catch |e| {
                _ = self.profiles.remove(channel);
                return e;
            };
        }
        gop.value_ptr.* = prof;
    }

    /// The negotiated profile for `channel`, or null when none has been set.
    pub fn profileOf(self: *const MediaRooms, channel: []const u8) ?CallProfile {
        return self.profiles.get(channel);
    }

    fn clearProfile(self: *MediaRooms, channel: []const u8) void {
        if (self.profiles.fetchRemove(channel)) |kv| self.allocator.free(kv.key);
    }

    /// Participant `pid` joins `channel`'s call publishing `kind` (creating the
    /// room on first join).
    pub fn join(self: *MediaRooms, channel: []const u8, pid: []const u8, kind: MediaKind) Error!void {
        const id = try media.ParticipantId.init(pid);
        const r = try self.ensure(channel);
        if (r.participant(id) == null and r.count() >= @min(self.config.max_participants, max_participants))
            return error.ParticipantCapacityExceeded;
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
        self.clearProfile(key);
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

test "call profile persists then clears when the call ends" {
    var m = MediaRooms.init(testing.allocator);
    defer m.deinit();
    try testing.expect(m.profileOf("#c") == null);
    try m.join("#c", "alice", .voice);
    const codecs = [_]sdp.Codec{.{ .tag = .opvox, .clock_rate = 48000, .params = 0 }};
    try m.setProfile("#c", &codecs, .{ .scheme = .rs_block, .redundancy = 1 });
    const prof = m.profileOf("#c").?;
    try testing.expectEqual(@as(usize, 1), prof.slice().len);
    try testing.expectEqual(sdp.CodecTag.opvox, prof.slice()[0].tag);
    try testing.expectEqual(sdp.FecScheme.rs_block, prof.fec.scheme);
    // reassigning overwrites in place (no leak)
    const codecs2 = [_]sdp.Codec{ .{ .tag = .opvox, .clock_rate = 48000, .params = 0 }, .{ .tag = .opvis, .clock_rate = 90000, .params = 0 } };
    try m.setProfile("#c", &codecs2, .{ .scheme = .none, .redundancy = 0 });
    try testing.expectEqual(@as(usize, 2), m.profileOf("#c").?.slice().len);
    try testing.expect(m.leaveAll("#c", "alice"));
    try testing.expect(m.profileOf("#c") == null); // cleared with the room
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
    try testing.expectEqual(default_max_participants, cfg.max_participants);
    try testing.expectEqual(max_breakout_bytes, cfg.max_breakout_bytes);
}

test "applyToml overlays media participant and sfu breakout caps" {
    const src =
        \\[media]
        \\max_participants = 8
        \\[media.sfu]
        \\max_breakout_label_bytes = 4
    ;
    var doc = try toml.parse(testing.allocator, src);
    defer doc.deinit(testing.allocator);
    var cfg: Config = .{};
    applyToml(&cfg, &doc);
    try testing.expectEqual(@as(usize, 8), cfg.max_participants);
    try testing.expectEqual(@as(usize, 4), cfg.max_breakout_bytes);

    var m = MediaRooms.initConfig(testing.allocator, cfg);
    defer m.deinit();
    try m.join("#c", "alice", .voice);
    try m.setBreakout("#c", "alice", "engineering"); // truncated to 4 bytes
    try testing.expectEqualStrings("engi", m.breakoutOf("#c", "alice"));
}

test "join refuses new participants at runtime cap" {
    var m = MediaRooms.initConfig(testing.allocator, .{ .max_participants = 2 });
    defer m.deinit();
    try m.join("#c", "alice", .voice);
    try m.join("#c", "bob", .voice);
    try testing.expectError(error.ParticipantCapacityExceeded, m.join("#c", "carol", .voice));
    try m.join("#c", "alice", .video);
    try testing.expectEqual(@as(usize, 2), m.roster("#c").len);
}

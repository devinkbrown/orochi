//! Flat recording-consent store keyed by a channel and participant pair. Values
//! are explicit booleans so callers can distinguish "unset" operationally by
//! clearing a channel while reads stay simple.
const std = @import("std");
const toml = @import("../proto/toml.zig");

pub const max_entries: usize = 262144;
pub const max_channel_bytes: usize = 128;
pub const max_participant_bytes: usize = 64;

/// Runtime-tunable consent-store bounds. Defaults equal the bare constants
/// above; `applyToml` overlays the `[media.recording]` section (shared with the
/// recording index).
///
/// Note: the per-pair lookup buffer is sized at COMPTIME to the historical
/// `max_channel_bytes`/`max_participant_bytes` (the upper bound). Config may
/// only TIGHTEN the accepted key length below that ceiling — a configured value
/// above the comptime ceiling is clamped to it so the stack buffer never
/// overflows.
pub const Config = struct {
    max_entries: usize = max_entries,
    max_channel_bytes: usize = max_channel_bytes,
    max_participant_bytes: usize = max_participant_bytes,
};

/// Overlay `[media.recording]` keys from a parsed TOML document onto `cfg`.
/// Byte-length keys are clamped to the comptime buffer ceiling.
pub fn applyToml(cfg: *Config, doc: *const toml.Document) void {
    if (doc.getUint("media.recording.max_consent_entries")) |v| cfg.max_entries = @intCast(v);
    if (doc.getUint("media.recording.max_channel_bytes")) |v| cfg.max_channel_bytes = @min(@as(usize, @intCast(v)), max_channel_bytes);
    if (doc.getUint("media.recording.max_participant_bytes")) |v| cfg.max_participant_bytes = @min(@as(usize, @intCast(v)), max_participant_bytes);
}

pub const Error = std.mem.Allocator.Error || error{ TooManyEntries, InvalidKey };

pub const RecordingConsent = struct {
    allocator: std.mem.Allocator,
    entries: std.StringHashMap(bool),
    config: Config,

    pub fn init(allocator: std.mem.Allocator) RecordingConsent {
        return initConfig(allocator, .{});
    }

    pub fn initConfig(allocator: std.mem.Allocator, config: Config) RecordingConsent {
        return .{ .allocator = allocator, .entries = std.StringHashMap(bool).init(allocator), .config = config };
    }

    pub fn deinit(self: *RecordingConsent) void {
        var it = self.entries.keyIterator();
        while (it.next()) |key| self.allocator.free(key.*);
        self.entries.deinit();
        self.* = undefined;
    }

    pub fn setConsent(self: *RecordingConsent, channel: []const u8, pid: []const u8, value: bool) Error!void {
        try validatePair(self, channel, pid);
        var stack: [max_channel_bytes + 1 + max_participant_bytes]u8 = undefined;
        const lookup = pairKey(&stack, channel, pid);
        if (self.entries.getPtr(lookup)) |existing| {
            existing.* = value;
            return;
        }
        if (self.entries.count() >= self.config.max_entries) return error.TooManyEntries;
        const owned = try self.allocator.dupe(u8, lookup);
        errdefer self.allocator.free(owned);
        try self.entries.putNoClobber(owned, value);
    }

    pub fn consented(self: *const RecordingConsent, channel: []const u8, pid: []const u8) bool {
        validatePair(self, channel, pid) catch return false;
        var stack: [max_channel_bytes + 1 + max_participant_bytes]u8 = undefined;
        const lookup = pairKey(&stack, channel, pid);
        return self.entries.get(lookup) orelse false;
    }

    pub fn clearChannel(self: *RecordingConsent, channel: []const u8) usize {
        if (!validPart(channel, self.config.max_channel_bytes)) return 0;
        var removed: usize = 0;
        while (self.findChannelKey(channel)) |key| {
            if (self.entries.fetchRemove(key)) |kv| {
                self.allocator.free(kv.key);
                removed += 1;
            }
        }
        return removed;
    }

    fn findChannelKey(self: *const RecordingConsent, channel: []const u8) ?[]const u8 {
        var it = self.entries.keyIterator();
        while (it.next()) |key| {
            if (hasChannel(key.*, channel)) return key.*;
        }
        return null;
    }
};

fn validatePair(self: *const RecordingConsent, channel: []const u8, pid: []const u8) Error!void {
    if (!validPart(channel, self.config.max_channel_bytes) or !validPart(pid, self.config.max_participant_bytes)) return error.InvalidKey;
}

fn validPart(value: []const u8, cap: usize) bool {
    return value.len > 0 and value.len <= cap and std.mem.indexOfScalar(u8, value, 0) == null;
}

fn pairKey(buf: []u8, channel: []const u8, pid: []const u8) []const u8 {
    @memcpy(buf[0..channel.len], channel);
    buf[channel.len] = 0;
    @memcpy(buf[channel.len + 1 ..][0..pid.len], pid);
    return buf[0 .. channel.len + 1 + pid.len];
}

fn hasChannel(key: []const u8, channel: []const u8) bool {
    return key.len > channel.len and key[channel.len] == 0 and std.mem.eql(u8, key[0..channel.len], channel);
}

const testing = std.testing;

test "set and read consent" {
    var consent = RecordingConsent.init(testing.allocator);
    defer consent.deinit();

    try testing.expect(!consent.consented("#call", "alice"));
    try consent.setConsent("#call", "alice", true);
    try testing.expect(consent.consented("#call", "alice"));
    try testing.expect(!consent.consented("#call", "bob"));
}

test "consent can be changed" {
    var consent = RecordingConsent.init(testing.allocator);
    defer consent.deinit();

    try consent.setConsent("#call", "alice", true);
    try consent.setConsent("#call", "alice", false);
    try testing.expect(!consent.consented("#call", "alice"));
}

test "clearChannel removes only one channel" {
    var consent = RecordingConsent.init(testing.allocator);
    defer consent.deinit();

    try consent.setConsent("#a", "alice", true);
    try consent.setConsent("#a", "bob", true);
    try consent.setConsent("#b", "alice", true);

    try testing.expectEqual(@as(usize, 2), consent.clearChannel("#a"));
    try testing.expect(!consent.consented("#a", "alice"));
    try testing.expect(consent.consented("#b", "alice"));
}

test "invalid keys are rejected" {
    var consent = RecordingConsent.init(testing.allocator);
    defer consent.deinit();

    try testing.expectError(error.InvalidKey, consent.setConsent("", "alice", true));
    try testing.expect(!consent.consented("#call", ""));
}

test "applyToml defaults match historical constants" {
    var doc = try toml.parse(testing.allocator, "");
    defer doc.deinit(testing.allocator);
    var cfg: Config = .{};
    applyToml(&cfg, &doc);
    try testing.expectEqual(max_entries, cfg.max_entries);
    try testing.expectEqual(max_channel_bytes, cfg.max_channel_bytes);
    try testing.expectEqual(max_participant_bytes, cfg.max_participant_bytes);
}

test "applyToml overlays media.recording keys and clamps byte caps to ceiling" {
    const src =
        \\[media.recording]
        \\max_consent_entries = 10
        \\max_channel_bytes = 8
        \\max_participant_bytes = 999999
    ;
    var doc = try toml.parse(testing.allocator, src);
    defer doc.deinit(testing.allocator);
    var cfg: Config = .{};
    applyToml(&cfg, &doc);
    try testing.expectEqual(@as(usize, 10), cfg.max_entries);
    try testing.expectEqual(@as(usize, 8), cfg.max_channel_bytes);
    // Above-ceiling participant cap clamps to the comptime buffer bound.
    try testing.expectEqual(max_participant_bytes, cfg.max_participant_bytes);

    var consent = RecordingConsent.initConfig(testing.allocator, cfg);
    defer consent.deinit();
    // 8-byte channel ok, 9-byte rejected under the tightened cap.
    try consent.setConsent("#chan123", "alice", true);
    try testing.expect(consent.consented("#chan123", "alice"));
    try testing.expectError(error.InvalidKey, consent.setConsent("#chan1234", "alice", true));
}

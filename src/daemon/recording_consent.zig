//! Flat recording-consent store keyed by a channel and participant pair. Values
//! are explicit booleans so callers can distinguish "unset" operationally by
//! clearing a channel while reads stay simple.
const std = @import("std");

pub const max_entries: usize = 262144;
pub const max_channel_bytes: usize = 128;
pub const max_participant_bytes: usize = 64;

pub const Error = std.mem.Allocator.Error || error{ TooManyEntries, InvalidKey };

pub const RecordingConsent = struct {
    allocator: std.mem.Allocator,
    entries: std.StringHashMap(bool),

    pub fn init(allocator: std.mem.Allocator) RecordingConsent {
        return .{ .allocator = allocator, .entries = std.StringHashMap(bool).init(allocator) };
    }

    pub fn deinit(self: *RecordingConsent) void {
        var it = self.entries.keyIterator();
        while (it.next()) |key| self.allocator.free(key.*);
        self.entries.deinit();
        self.* = undefined;
    }

    pub fn setConsent(self: *RecordingConsent, channel: []const u8, pid: []const u8, value: bool) Error!void {
        try validatePair(channel, pid);
        var stack: [max_channel_bytes + 1 + max_participant_bytes]u8 = undefined;
        const lookup = pairKey(&stack, channel, pid);
        if (self.entries.getPtr(lookup)) |existing| {
            existing.* = value;
            return;
        }
        if (self.entries.count() >= max_entries) return error.TooManyEntries;
        const owned = try self.allocator.dupe(u8, lookup);
        errdefer self.allocator.free(owned);
        try self.entries.putNoClobber(owned, value);
    }

    pub fn consented(self: *const RecordingConsent, channel: []const u8, pid: []const u8) bool {
        validatePair(channel, pid) catch return false;
        var stack: [max_channel_bytes + 1 + max_participant_bytes]u8 = undefined;
        const lookup = pairKey(&stack, channel, pid);
        return self.entries.get(lookup) orelse false;
    }

    pub fn clearChannel(self: *RecordingConsent, channel: []const u8) usize {
        if (!validPart(channel, max_channel_bytes)) return 0;
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

fn validatePair(channel: []const u8, pid: []const u8) Error!void {
    if (!validPart(channel, max_channel_bytes) or !validPart(pid, max_participant_bytes)) return error.InvalidKey;
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

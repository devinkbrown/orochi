// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Typed value helpers for RTP MID and RID header extension element data.
//!
//! RFC 8285 framing lives outside this module. The functions here validate and
//! copy only the extension element payload bytes: MID (RFC 9143/RFC 8843), RID,
//! and repaired-rid (RFC 8852) string values.
const std = @import("std");

pub const Error = error{ TooLong, Invalid, BufferTooSmall };

pub const max_mid_len: usize = 16;
pub const max_rid_len: usize = 16;

fn isMidTokenChar(c: u8) bool {
    return switch (c) {
        0x21,
        0x23...0x27,
        0x2a...0x2b,
        0x2d...0x2e,
        '0'...'9',
        'A'...'Z',
        0x5e...0x7e,
        => true,
        else => false,
    };
}

fn isRidChar(c: u8) bool {
    return switch (c) {
        '0'...'9', 'A'...'Z', 'a'...'z', '-', '_' => true,
        else => false,
    };
}

pub fn validateMid(s: []const u8) Error!void {
    if (s.len == 0) return error.Invalid;
    if (s.len > max_mid_len) return error.TooLong;
    for (s) |c| {
        if (!isMidTokenChar(c)) return error.Invalid;
    }
}

pub fn validateRid(s: []const u8) Error!void {
    if (s.len == 0) return error.Invalid;
    if (s.len > max_rid_len) return error.TooLong;
    for (s) |c| {
        if (!isRidChar(c)) return error.Invalid;
    }
}

pub fn writeMid(s: []const u8, out: []u8) Error![]const u8 {
    try validateMid(s);
    if (out.len < s.len) return error.BufferTooSmall;
    @memcpy(out[0..s.len], s);
    return out[0..s.len];
}

pub fn writeRid(s: []const u8, out: []u8) Error![]const u8 {
    try validateRid(s);
    if (out.len < s.len) return error.BufferTooSmall;
    @memcpy(out[0..s.len], s);
    return out[0..s.len];
}

pub const Demux = struct {
    pub const capacity: usize = 32;

    const max_key_len: usize = @max(max_mid_len, max_rid_len);

    const Entry = struct {
        used: bool = false,
        len: usize = 0,
        key: [max_key_len]u8 = @splat(0),
        token: u32 = 0,

        fn matches(self: Entry, key: []const u8) bool {
            return self.used and self.len == key.len and std.mem.eql(u8, self.key[0..self.len], key);
        }
    };

    entries: [capacity]Entry = @splat(.{}),

    pub fn put(self: *Demux, key: []const u8, token: u32) !void {
        try validateMid(key);

        for (&self.entries) |*entry| {
            if (entry.matches(key)) {
                entry.token = token;
                return;
            }
        }

        for (&self.entries) |*entry| {
            if (!entry.used) {
                @memcpy(entry.key[0..key.len], key);
                entry.len = key.len;
                entry.token = token;
                entry.used = true;
                return;
            }
        }

        return error.Full;
    }

    pub fn get(self: *const Demux, key: []const u8) ?u32 {
        validateMid(key) catch return null;
        for (&self.entries) |*entry| {
            if (entry.matches(key)) return entry.token;
        }
        return null;
    }
};

const testing = std.testing;

test "validateMid accepts token values" {
    try validateMid("0");
    try validateMid("audio");
    try validateMid("video-1");
    try validateMid("data_2");
    try validateMid("a.b_c");
    try validateMid("A9!#$%&'*+-.^_~");
}

test "validateMid rejects empty too-long and bad characters" {
    try testing.expectError(error.Invalid, validateMid(""));
    try testing.expectError(error.TooLong, validateMid("1234567890abcdefg"));
    try testing.expectError(error.Invalid, validateMid("has space"));
    try testing.expectError(error.Invalid, validateMid("has/slash"));
    try testing.expectError(error.Invalid, validateMid("has\"quote"));
}

test "validateRid accepts identifier values" {
    try validateRid("0");
    try validateRid("audio");
    try validateRid("video-1");
    try validateRid("repair_2");
    try validateRid("AZaz09-_");
}

test "validateRid rejects empty too-long and bad characters" {
    try testing.expectError(error.Invalid, validateRid(""));
    try testing.expectError(error.TooLong, validateRid("1234567890abcdefg"));
    try testing.expectError(error.Invalid, validateRid("a.b"));
    try testing.expectError(error.Invalid, validateRid("has/slash"));
    try testing.expectError(error.Invalid, validateRid("has space"));
}

test "writeMid and writeRid copy validated payload bytes" {
    var mid_buf: [max_mid_len]u8 = undefined;
    const mid = try writeMid("audio-1", &mid_buf);
    try testing.expectEqualSlices(u8, "audio-1", mid);

    var rid_buf: [max_rid_len]u8 = undefined;
    const rid = try writeRid("hi_720p", &rid_buf);
    try testing.expectEqualSlices(u8, "hi_720p", rid);
}

test "writeMid and writeRid reject too-long and small output buffers" {
    var buf: [4]u8 = undefined;
    try testing.expectError(error.TooLong, writeMid("1234567890abcdefg", &buf));
    try testing.expectError(error.TooLong, writeRid("1234567890abcdefg", &buf));
    try testing.expectError(error.BufferTooSmall, writeMid("audio", &buf));
    try testing.expectError(error.BufferTooSmall, writeRid("video", &buf));
}

test "Demux put get round-trips MID and RID keys" {
    var demux = Demux{};

    try demux.put("audio", 11);
    try demux.put("video-1", 22);
    try demux.put("hi_720p", 33);
    try demux.put("a.b_c", 44);

    try testing.expectEqual(@as(?u32, 11), demux.get("audio"));
    try testing.expectEqual(@as(?u32, 22), demux.get("video-1"));
    try testing.expectEqual(@as(?u32, 33), demux.get("hi_720p"));
    try testing.expectEqual(@as(?u32, 44), demux.get("a.b_c"));
    try testing.expectEqual(@as(?u32, null), demux.get("unknown"));
}

test "Demux updates existing keys and rejects invalid keys" {
    var demux = Demux{};

    try demux.put("audio", 1);
    try demux.put("audio", 2);

    try testing.expectEqual(@as(?u32, 2), demux.get("audio"));
    try testing.expectError(error.Invalid, demux.put("", 3));
    try testing.expectError(error.TooLong, demux.put("1234567890abcdefg", 4));
    try testing.expectEqual(@as(?u32, null), demux.get("bad key"));
}

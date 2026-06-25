// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! IRCv3 outbound message-tag composer.
//!
//! Send paths pass already-rendered IRC lines plus a negotiated `CapSet`.
//! This module prefixes only the tags that recipient may receive, writes into
//! caller-owned buffers, and never allocates on the hot path.
const std = @import("std");
const irc_line = @import("irc_line.zig");
const cap = @import("cap.zig");

pub const MSGID_LEN: usize = 22;
pub const SERVER_TIME_LEN: usize = 24;

const MAX_UNIX_MILLIS: i64 = 253_402_300_799_999; // 9999-12-31T23:59:59.999Z
const BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

pub const ComposeError = error{
    OutputTooSmall,
    InvalidLine,
    InvalidTime,
    InvalidTagValue,
};

/// Deterministic entropy inputs for IRCv3 `msgid`.
///
/// The encoded id is a fixed-width base62 representation of `rng || counter`,
/// so every call emits exactly `MSGID_LEN` bytes and sequential counters do not
/// collide for a fixed random prefix.
pub const MsgIdSource = struct {
    counter: u64,
    rng: u64,
};

/// Candidate outbound tags. Each field is still gated by recipient caps.
pub const OutboundTags = struct {
    server_time_millis: ?i64 = null,
    account: ?[]const u8 = null,
    msgid: ?MsgIdSource = null,
    draft_label: ?[]const u8 = null,
    label: ?[]const u8 = null,
    batch: ?[]const u8 = null,
    bot: bool = false,
};

/// Compile-time switches for specialized send paths.
pub const ComposeConfig = struct {
    server_time: bool = true,
    account: bool = true,
    msgid: bool = true,
    draft_label: bool = true,
    label: bool = true,
    batch: bool = true,
    bot: bool = true,
};

pub const default_config = ComposeConfig{};

/// Prefix a cap-gated tag set onto an already-rendered outbound IRC line.
///
/// If no requested tag is negotiated, the line is copied unchanged into `out`.
/// The returned slice always points into `out`.
pub fn composeOutbound(
    comptime config: ComposeConfig,
    caps: cap.CapSet,
    tags: OutboundTags,
    line: []const u8,
    out: []u8,
) ComposeError![]const u8 {
    try validateLine(line);

    var writer = TagWriter{ .buf = out };

    if (config.server_time and tags.server_time_millis != null and caps.contains(.server_time)) {
        var time_buf: [SERVER_TIME_LEN]u8 = undefined;
        const time = try writeServerTime(tags.server_time_millis.?, &time_buf);
        try writer.writeValue("time", time);
    }
    if (config.account and tags.account != null and caps.contains(.account_tag)) {
        try writer.writeEscapedValue("account", tags.account.?);
    }
    if (config.msgid and tags.msgid != null and caps.contains(.msgid)) {
        var msgid_buf: [MSGID_LEN]u8 = undefined;
        const msgid = try writeMsgId(tags.msgid.?, &msgid_buf);
        try writer.writeValue("msgid", msgid);
    }
    if (config.draft_label and tags.draft_label != null and caps.contains(.labeled_response)) {
        try writer.writeEscapedValue("+draft/label", tags.draft_label.?);
    }
    if (config.label and tags.label != null and caps.contains(.labeled_response)) {
        try writer.writeEscapedValue("label", tags.label.?);
    }
    if (config.batch and tags.batch != null and caps.contains(.batch)) {
        try writer.writeEscapedValue("batch", tags.batch.?);
    }
    if (config.bot and tags.bot and caps.contains(.bot)) {
        try writer.writeBare("bot");
    }

    if (writer.count != 0) {
        try writer.finishTags();
    }
    try writer.append(line);
    return out[0..writer.len];
}

/// Write an IRCv3 server-time value as `YYYY-MM-DDTHH:mm:ss.sssZ`.
pub fn writeServerTime(unix_millis: i64, out: []u8) ComposeError![]const u8 {
    if (unix_millis < 0 or unix_millis > MAX_UNIX_MILLIS) return error.InvalidTime;
    if (out.len < SERVER_TIME_LEN) return error.OutputTooSmall;

    const seconds = @as(u64, @intCast(@divTrunc(unix_millis, 1000)));
    const millis = @as(u16, @intCast(@mod(unix_millis, 1000)));
    const epoch_seconds = std.time.epoch.EpochSeconds{ .secs = seconds };
    const year_day = epoch_seconds.getEpochDay().calculateYearDay();
    if (year_day.year > 9999) return error.InvalidTime;

    const month_day = year_day.calculateMonthDay();
    const day_seconds = epoch_seconds.getDaySeconds();

    writeFixed(out[0..4], year_day.year, 4);
    out[4] = '-';
    writeFixed(out[5..7], month_day.month.numeric(), 2);
    out[7] = '-';
    writeFixed(out[8..10], @as(u8, month_day.day_index) + 1, 2);
    out[10] = 'T';
    writeFixed(out[11..13], day_seconds.getHoursIntoDay(), 2);
    out[13] = ':';
    writeFixed(out[14..16], day_seconds.getMinutesIntoHour(), 2);
    out[16] = ':';
    writeFixed(out[17..19], day_seconds.getSecondsIntoMinute(), 2);
    out[19] = '.';
    writeFixed(out[20..23], millis, 3);
    out[23] = 'Z';
    return out[0..SERVER_TIME_LEN];
}

/// Write a fixed-width base62 IRCv3 `msgid`.
pub fn writeMsgId(source: MsgIdSource, out: []u8) ComposeError![]const u8 {
    if (out.len < MSGID_LEN) return error.OutputTooSmall;

    var value = (@as(u128, source.rng) << 64) | @as(u128, source.counter);
    var index: usize = MSGID_LEN;
    while (index != 0) {
        index -= 1;
        out[index] = BASE62[@as(usize, @intCast(value % 62))];
        value /= 62;
    }
    return out[0..MSGID_LEN];
}

fn validateLine(line: []const u8) ComposeError!void {
    if (line.len == 0 or line.len > irc_line.MAX_LINE_BODY) return error.InvalidLine;
    if (line[0] == '@') return error.InvalidLine;
    for (line) |ch| {
        switch (ch) {
            0, '\r', '\n' => return error.InvalidLine,
            else => {},
        }
    }
}

fn writeFixed(out: []u8, value: anytype, comptime width: usize) void {
    var remaining = @as(u64, @intCast(value));
    var index: usize = width;
    while (index != 0) {
        index -= 1;
        out[index] = @as(u8, @intCast('0' + remaining % 10));
        remaining /= 10;
    }
}

const TagWriter = struct {
    buf: []u8,
    len: usize = 0,
    count: usize = 0,

    fn writeBare(self: *TagWriter, key: []const u8) ComposeError!void {
        try self.beginTag(key);
        self.count += 1;
    }

    fn writeValue(self: *TagWriter, key: []const u8, value: []const u8) ComposeError!void {
        try self.beginTag(key);
        try self.appendByte('=');
        try self.append(value);
        self.count += 1;
    }

    fn writeEscapedValue(self: *TagWriter, key: []const u8, value: []const u8) ComposeError!void {
        try self.beginTag(key);
        try self.appendByte('=');
        try self.appendEscaped(value);
        self.count += 1;
    }

    fn beginTag(self: *TagWriter, key: []const u8) ComposeError!void {
        if (self.count == 0) {
            try self.appendByte('@');
        } else {
            try self.appendByte(';');
        }
        try self.append(key);
    }

    fn finishTags(self: *TagWriter) ComposeError!void {
        try self.appendByte(' ');
    }

    fn appendEscaped(self: *TagWriter, value: []const u8) ComposeError!void {
        for (value) |ch| {
            switch (ch) {
                0 => return error.InvalidTagValue,
                ';' => try self.append("\\:"),
                ' ' => try self.append("\\s"),
                '\r' => try self.append("\\r"),
                '\n' => try self.append("\\n"),
                '\\' => try self.append("\\\\"),
                else => try self.appendByte(ch),
            }
        }
    }

    fn append(self: *TagWriter, bytes: []const u8) ComposeError!void {
        if (self.buf.len - self.len < bytes.len) return error.OutputTooSmall;
        @memcpy(self.buf[self.len .. self.len + bytes.len], bytes);
        self.len += bytes.len;
    }

    fn appendByte(self: *TagWriter, byte: u8) ComposeError!void {
        if (self.len == self.buf.len) return error.OutputTooSmall;
        self.buf[self.len] = byte;
        self.len += 1;
    }
};

fn capsWith(comptime ids: []const cap.CapId) cap.CapSet {
    var set = cap.CapSet.empty();
    for (ids) |id| {
        set.add(id);
    }
    return set;
}

test "server-time is emitted only when negotiated" {
    var out: [128]u8 = undefined;
    const tags = OutboundTags{ .server_time_millis = 1_685_732_096_123 };

    const without = try composeOutbound(default_config, cap.CapSet.empty(), tags, ":s PRIVMSG #c :hi", &out);
    try std.testing.expectEqualStrings(":s PRIVMSG #c :hi", without);

    const with = try composeOutbound(default_config, capsWith(&.{.server_time}), tags, ":s PRIVMSG #c :hi", &out);
    try std.testing.expectEqualStrings("@time=2023-06-02T18:54:56.123Z :s PRIVMSG #c :hi", with);
}

test "msgid is fixed-width base62" {
    var msgid_buf: [MSGID_LEN]u8 = undefined;
    const msgid = try writeMsgId(.{
        .counter = 0x0123_4567_89ab_cdef,
        .rng = 0xfedc_ba98_7654_3210,
    }, &msgid_buf);

    try std.testing.expectEqual(@as(usize, MSGID_LEN), msgid.len);
    for (msgid) |ch| {
        try std.testing.expect(std.mem.indexOfScalar(u8, BASE62, ch) != null);
    }

    var out: [128]u8 = undefined;
    const line = try composeOutbound(
        default_config,
        capsWith(&.{.msgid}),
        .{ .msgid = .{ .counter = 1, .rng = 2 } },
        "PING :abc",
        &out,
    );
    try std.testing.expect(std.mem.startsWith(u8, line, "@msgid="));
    try std.testing.expectEqual(@as(usize, 1 + "msgid=".len + MSGID_LEN + 1 + "PING :abc".len), line.len);
}

test "label echo is gated and escaped" {
    var out: [128]u8 = undefined;
    const tags = OutboundTags{ .draft_label = "client label" };

    const without = try composeOutbound(default_config, cap.CapSet.empty(), tags, "NOTICE nick :ok", &out);
    try std.testing.expectEqualStrings("NOTICE nick :ok", without);

    const with = try composeOutbound(default_config, capsWith(&.{.labeled_response}), tags, "NOTICE nick :ok", &out);
    try std.testing.expectEqualStrings("@+draft/label=client\\slabel NOTICE nick :ok", with);
}

test "escapes semicolon space CR LF and backslash" {
    var out: [160]u8 = undefined;
    const line = try composeOutbound(
        default_config,
        capsWith(&.{.account_tag}),
        .{ .account = "a;b c\rd\ne\\f" },
        "PRIVMSG #c :hello",
        &out,
    );
    try std.testing.expectEqualStrings("@account=a\\:b\\sc\\rd\\ne\\\\f PRIVMSG #c :hello", line);
}

test "multiple tags have deterministic ordering" {
    var out: [256]u8 = undefined;
    const line = try composeOutbound(
        default_config,
        capsWith(&.{ .server_time, .account_tag, .msgid, .labeled_response, .batch, .bot }),
        .{
            .server_time_millis = 0,
            .account = "acct",
            .msgid = .{ .counter = 7, .rng = 11 },
            .draft_label = "lbl",
            .batch = "batch1",
            .bot = true,
        },
        ":s PRIVMSG #c :hi",
        &out,
    );
    try std.testing.expectEqualStrings(
        "@time=1970-01-01T00:00:00.000Z;account=acct;msgid=00000000003tlV7OC5p74x;+draft/label=lbl;batch=batch1;bot :s PRIVMSG #c :hi",
        line,
    );
}

test "rejects attacker-controlled invalid bytes and small outputs" {
    var out: [64]u8 = undefined;
    try std.testing.expectError(
        error.InvalidLine,
        composeOutbound(default_config, cap.CapSet.empty(), .{}, "PING bad\nline", &out),
    );
    try std.testing.expectError(
        error.InvalidLine,
        composeOutbound(default_config, cap.CapSet.empty(), .{}, "@time=x PING", &out),
    );
    try std.testing.expectError(
        error.InvalidTagValue,
        composeOutbound(default_config, capsWith(&.{.account_tag}), .{ .account = "bad\x00acct" }, "PING :x", &out),
    );

    var tiny: [4]u8 = undefined;
    try std.testing.expectError(
        error.OutputTooSmall,
        composeOutbound(default_config, capsWith(&.{.server_time}), .{ .server_time_millis = 0 }, "PING :x", &tiny),
    );
}

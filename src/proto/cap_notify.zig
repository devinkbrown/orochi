//! IRCv3 CAP NEW / CAP DEL dynamic capability notifications.
//!
//! This module is intentionally self-contained: callers provide capability
//! names, recipient selection, and a sink that accepts completed wire lines.
const std = @import("std");

pub const MAX_IRC_LINE: usize = 512;
pub const LINE_ENDING = "\r\n";

pub const NotifyError = error{
    InvalidCapability,
    InvalidTarget,
    LineTooLong,
    OutputTooSmall,
    TooManyLines,
    TooManyRecipients,
    OutOfMemory,
};

pub const Kind = enum {
    new,
    del,

    fn text(self: Kind) []const u8 {
        return switch (self) {
            .new => "NEW",
            .del => "DEL",
        };
    }
};

pub const CapToken = struct {
    name: []const u8,
    value: ?[]const u8 = null,
};

/// Caller-owned fixed storage sink for completed CAP notification lines.
pub const LineSink = struct {
    lines: [][]const u8,
    storage: []u8,
    count: usize = 0,
    used: usize = 0,

    pub fn appendLine(self: *LineSink, line: []const u8) NotifyError!void {
        if (line.len > MAX_IRC_LINE) return error.LineTooLong;
        if (self.count >= self.lines.len) return error.TooManyLines;
        if (self.used + line.len > self.storage.len) return error.OutputTooSmall;

        const start = self.used;
        const end = start + line.len;
        @memcpy(self.storage[start..end], line);
        self.used = end;
        self.lines[self.count] = self.storage[start..end];
        self.count += 1;
    }

    pub fn slice(self: *const LineSink) []const []const u8 {
        return self.lines[0..self.count];
    }
};

pub fn emitNew(
    sink: anytype,
    server_name: []const u8,
    nick: []const u8,
    caps: []const CapToken,
) NotifyError!void {
    try emit(.new, sink, server_name, nick, caps);
}

pub fn emitDel(
    sink: anytype,
    server_name: []const u8,
    nick: []const u8,
    caps: []const CapToken,
) NotifyError!void {
    try emit(.del, sink, server_name, nick, caps);
}

pub fn emit(
    kind: Kind,
    sink: anytype,
    server_name: []const u8,
    nick: []const u8,
    caps: []const CapToken,
) NotifyError!void {
    if (caps.len == 0) return;
    try validateTarget(server_name);
    try validateTarget(nick);

    const cap_room = capBodyRoom(kind, server_name, nick);
    if (cap_room == 0) return error.LineTooLong;

    var body: [MAX_IRC_LINE]u8 = undefined;
    var body_len: usize = 0;

    for (caps) |cap_token| {
        try validateCap(kind, cap_token);
        const token_len = renderedTokenLen(kind, cap_token);
        if (token_len > cap_room) return error.LineTooLong;

        const sep_len: usize = if (body_len == 0) 0 else 1;
        if (body_len != 0 and body_len + sep_len + token_len > cap_room) {
            try emitOne(kind, sink, server_name, nick, body[0..body_len]);
            body_len = 0;
        }

        if (body_len != 0) {
            body[body_len] = ' ';
            body_len += 1;
        }
        const written = writeToken(kind, cap_token, body[body_len..]);
        body_len += written.len;
    }

    if (body_len != 0) {
        try emitOne(kind, sink, server_name, nick, body[0..body_len]);
    }
}

/// Return true when the caller-supplied negotiated-capability predicate says
/// this session should receive cap-notify output.
pub fn shouldNotify(
    comptime Session: type,
    session: *const Session,
    ctx: anytype,
    comptime negotiatedCapNotify: fn (@TypeOf(ctx), *const Session) bool,
) bool {
    return negotiatedCapNotify(ctx, session);
}

/// Copy pointers to sessions that negotiated cap-notify into caller storage.
pub fn filterRecipients(
    comptime Session: type,
    sessions: []const Session,
    out: []*const Session,
    ctx: anytype,
    comptime negotiatedCapNotify: fn (@TypeOf(ctx), *const Session) bool,
) NotifyError![]const *const Session {
    var count: usize = 0;
    for (sessions) |*session| {
        if (!negotiatedCapNotify(ctx, session)) continue;
        if (count >= out.len) return error.TooManyRecipients;
        out[count] = session;
        count += 1;
    }
    return out[0..count];
}

fn emitOne(
    kind: Kind,
    sink: anytype,
    server_name: []const u8,
    nick: []const u8,
    cap_body: []const u8,
) NotifyError!void {
    var line: [MAX_IRC_LINE]u8 = undefined;
    var len: usize = 0;

    line[len] = ':';
    len += 1;
    @memcpy(line[len .. len + server_name.len], server_name);
    len += server_name.len;
    @memcpy(line[len .. len + " CAP ".len], " CAP ");
    len += " CAP ".len;
    @memcpy(line[len .. len + nick.len], nick);
    len += nick.len;
    line[len] = ' ';
    len += 1;
    const verb = kind.text();
    @memcpy(line[len .. len + verb.len], verb);
    len += verb.len;
    @memcpy(line[len .. len + " :".len], " :");
    len += " :".len;
    @memcpy(line[len .. len + cap_body.len], cap_body);
    len += cap_body.len;
    @memcpy(line[len .. len + LINE_ENDING.len], LINE_ENDING);
    len += LINE_ENDING.len;

    if (len > MAX_IRC_LINE) return error.LineTooLong;
    try sink.appendLine(line[0..len]);
}

fn capBodyRoom(kind: Kind, server_name: []const u8, nick: []const u8) usize {
    const fixed_len =
        1 + server_name.len +
        " CAP ".len + nick.len +
        1 + kind.text().len +
        " :".len + LINE_ENDING.len;
    if (fixed_len >= MAX_IRC_LINE) return 0;
    return MAX_IRC_LINE - fixed_len;
}

fn renderedTokenLen(kind: Kind, cap_token: CapToken) usize {
    return switch (kind) {
        .new => cap_token.name.len + if (cap_token.value) |value| 1 + value.len else 0,
        .del => cap_token.name.len,
    };
}

fn writeToken(kind: Kind, cap_token: CapToken, out: []u8) []const u8 {
    @memcpy(out[0..cap_token.name.len], cap_token.name);
    var len = cap_token.name.len;
    if (kind == .new) {
        if (cap_token.value) |value| {
            out[len] = '=';
            len += 1;
            @memcpy(out[len .. len + value.len], value);
            len += value.len;
        }
    }
    return out[0..len];
}

fn validateTarget(bytes: []const u8) NotifyError!void {
    if (bytes.len == 0) return error.InvalidTarget;
    for (bytes) |ch| {
        switch (ch) {
            0, '\r', '\n', ' ' => return error.InvalidTarget,
            else => {},
        }
    }
}

fn validateCap(kind: Kind, cap_token: CapToken) NotifyError!void {
    if (!validCapAtom(cap_token.name) or std.mem.indexOfScalar(u8, cap_token.name, '=') != null) {
        return error.InvalidCapability;
    }
    switch (kind) {
        .new => if (cap_token.value) |value| {
            if (!validCapValue(value)) return error.InvalidCapability;
        },
        .del => if (cap_token.value != null) return error.InvalidCapability,
    }
}

fn validCapAtom(bytes: []const u8) bool {
    if (bytes.len == 0) return false;
    for (bytes) |ch| {
        switch (ch) {
            0...32, 127 => return false,
            else => {},
        }
    }
    return true;
}

fn validCapValue(bytes: []const u8) bool {
    for (bytes) |ch| {
        switch (ch) {
            0...32, 127 => return false,
            else => {},
        }
    }
    return true;
}

const AllocLineSink = struct {
    allocator: std.mem.Allocator,
    lines: std.ArrayList([]u8) = .empty,

    fn appendLine(self: *AllocLineSink, line: []const u8) NotifyError!void {
        if (line.len > MAX_IRC_LINE) return error.LineTooLong;
        const owned = self.allocator.dupe(u8, line) catch return error.OutOfMemory;
        errdefer self.allocator.free(owned);
        self.lines.append(self.allocator, owned) catch return error.OutOfMemory;
    }

    fn deinit(self: *AllocLineSink) void {
        for (self.lines.items) |line| self.allocator.free(line);
        self.lines.deinit(self.allocator);
    }
};

test "NEW notification includes CAP 302 values exactly" {
    var sink = AllocLineSink{ .allocator = std.testing.allocator };
    defer sink.deinit();

    try emitNew(&sink, "irc.example.test", "kain", &.{
        .{ .name = "sts", .value = "duration=604800" },
        .{ .name = "sasl", .value = "PLAIN,EXTERNAL" },
        .{ .name = "echo-message" },
    });

    try std.testing.expectEqual(@as(usize, 1), sink.lines.items.len);
    try std.testing.expectEqualStrings(
        ":irc.example.test CAP kain NEW :sts=duration=604800 sasl=PLAIN,EXTERNAL echo-message\r\n",
        sink.lines.items[0],
    );
}

test "DEL notification omits values exactly" {
    var line_slots: [2][]const u8 = undefined;
    var storage: [256]u8 = undefined;
    var sink = LineSink{ .lines = &line_slots, .storage = &storage };

    try emitDel(&sink, "orochi.test", "akari", &.{
        .{ .name = "away-notify" },
        .{ .name = "chghost" },
    });

    const lines = sink.slice();
    try std.testing.expectEqual(@as(usize, 1), lines.len);
    try std.testing.expectEqualStrings(
        ":orochi.test CAP akari DEL :away-notify chghost\r\n",
        lines[0],
    );
}

test "splits NEW notification at the 512 byte wire cap" {
    const allocator = std.testing.allocator;
    const long_name = try allocator.alloc(u8, 496);
    defer allocator.free(long_name);
    @memset(long_name, 'a');

    var sink = AllocLineSink{ .allocator = allocator };
    defer sink.deinit();

    try emitNew(&sink, "s", "n", &.{
        .{ .name = long_name },
        .{ .name = "b" },
    });

    try std.testing.expectEqual(@as(usize, 2), sink.lines.items.len);
    try std.testing.expectEqual(@as(usize, MAX_IRC_LINE), sink.lines.items[0].len);

    var expected: std.ArrayList(u8) = .empty;
    defer expected.deinit(allocator);
    try expected.appendSlice(allocator, ":s CAP n NEW :");
    try expected.appendSlice(allocator, long_name);
    try expected.appendSlice(allocator, "\r\n");

    try std.testing.expectEqualStrings(expected.items, sink.lines.items[0]);
    try std.testing.expectEqualStrings(":s CAP n NEW :b\r\n", sink.lines.items[1]);
}

test "recipient filter keeps only sessions that negotiated cap-notify" {
    const Session = struct {
        nick: []const u8,
        cap_notify: bool,

        fn wants(_: void, session: *const @This()) bool {
            return session.cap_notify;
        }
    };

    const sessions = [_]Session{
        .{ .nick = "a", .cap_notify = true },
        .{ .nick = "b", .cap_notify = false },
        .{ .nick = "c", .cap_notify = true },
    };
    var out: [2]*const Session = undefined;

    const selected = try filterRecipients(Session, sessions[0..], &out, {}, Session.wants);
    try std.testing.expectEqual(@as(usize, 2), selected.len);
    try std.testing.expectEqualStrings("a", selected[0].nick);
    try std.testing.expectEqualStrings("c", selected[1].nick);
    try std.testing.expect(shouldNotify(Session, &sessions[0], {}, Session.wants));
    try std.testing.expect(!shouldNotify(Session, &sessions[1], {}, Session.wants));
}

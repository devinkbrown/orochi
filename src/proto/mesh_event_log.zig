// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure fixed-size log for recent mesh events plus an oper-facing renderer.
//!
//! This module owns no daemon state, allocates no memory, performs no I/O, and
//! imports only the Zig standard library. Callers push plain `MeshEvent` values;
//! the log copies subject/detail bytes into inline buffers so transient caller
//! slices remain safe.

const std = @import("std");

pub const MeshEventKind = enum {
    peer_up,
    peer_down,
    link_handshake,
    split,
    heal,
    oper_grant_in,
    oper_grant_out,
    oper_grant_revoke,
    route_change,
    resync,
};

pub const MeshEvent = struct {
    kind: MeshEventKind,
    ts_unix: i64 = 0,
    subject: []const u8 = "",
    detail: []const u8 = "",
};

pub fn kindWord(k: MeshEventKind) []const u8 {
    return switch (k) {
        .peer_up => "peer-up",
        .peer_down => "peer-down",
        .link_handshake => "link-handshake",
        .split => "split",
        .heal => "heal",
        .oper_grant_in => "oper-grant-in",
        .oper_grant_out => "oper-grant-out",
        .oper_grant_revoke => "oper-grant-revoke",
        .route_change => "route-change",
        .resync => "resync",
    };
}

pub fn MeshEventLog(comptime capacity: usize) type {
    return struct {
        const Self = @This();

        pub const subject_cap: usize = 64;
        pub const detail_cap: usize = 64;

        const StoredEvent = struct {
            kind: MeshEventKind,
            ts_unix: i64,
            subject_buf: [subject_cap]u8,
            subject_len: usize,
            detail_buf: [detail_cap]u8,
            detail_len: usize,

            fn init(ev: MeshEvent) StoredEvent {
                var stored: StoredEvent = .{
                    .kind = ev.kind,
                    .ts_unix = ev.ts_unix,
                    .subject_buf = undefined,
                    .subject_len = 0,
                    .detail_buf = undefined,
                    .detail_len = 0,
                };
                stored.subject_len = copyTruncated(stored.subject_buf[0..], ev.subject);
                stored.detail_len = copyTruncated(stored.detail_buf[0..], ev.detail);
                return stored;
            }

            fn public(self: *const StoredEvent) MeshEvent {
                return .{
                    .kind = self.kind,
                    .ts_unix = self.ts_unix,
                    .subject = self.subject_buf[0..self.subject_len],
                    .detail = self.detail_buf[0..self.detail_len],
                };
            }
        };

        items: [capacity]StoredEvent = undefined,
        start: usize = 0,
        count: usize = 0,

        pub const Iterator = struct {
            log: *const Self,
            index: usize = 0,

            pub fn next(self: *Iterator) ?MeshEvent {
                const ev = self.log.get(self.index) orelse return null;
                self.index += 1;
                return ev;
            }
        };

        pub fn push(self: *Self, ev: MeshEvent) void {
            if (capacity == 0) return;

            const slot = if (self.count < capacity) slot: {
                const index = (self.start + self.count) % capacity;
                self.count += 1;
                break :slot index;
            } else slot: {
                const index = self.start;
                self.start = (self.start + 1) % capacity;
                break :slot index;
            };

            self.items[slot] = StoredEvent.init(ev);
        }

        pub fn len(self: *const Self) usize {
            return self.count;
        }

        pub fn clear(self: *Self) void {
            self.start = 0;
            self.count = 0;
        }

        pub fn get(self: *const Self, index: usize) ?MeshEvent {
            if (capacity == 0) return null;
            if (index >= self.count) return null;
            return self.items[(self.start + index) % capacity].public();
        }

        pub fn iterator(self: *const Self) Iterator {
            return .{ .log = self };
        }
    };
}

pub fn render(log: anytype, writer: anytype) !void {
    try writer.print("MESH LOG ({d} events)\n", .{log.len()});

    var it = log.iterator();
    while (it.next()) |ev| {
        try writer.print("{d} {s} ", .{ ev.ts_unix, kindWord(ev.kind) });
        try writeClean(writer, ev.subject);
        if (visibleLen(ev.detail) != 0) {
            try writer.writeAll(" :");
            try writeClean(writer, ev.detail);
        }
        try writer.writeByte('\n');
    }

    try writer.writeAll("end of mesh log\n");
}

fn copyTruncated(dst: []u8, src: []const u8) usize {
    const n = @min(dst.len, src.len);
    @memcpy(dst[0..n], src[0..n]);
    return n;
}

fn visibleLen(s: []const u8) usize {
    var n: usize = 0;
    for (s) |c| {
        if (c != '\r' and c != '\n') n += 1;
    }
    return n;
}

fn writeClean(writer: anytype, s: []const u8) !void {
    for (s) |c| {
        if (c != '\r' and c != '\n') try writer.writeByte(c);
    }
}

fn renderToBuf(log: anytype, buf: []u8) ![]const u8 {
    var w = std.Io.Writer.fixed(buf);
    try render(log, &w);
    return w.buffered();
}

test "push below capacity stores copied events oldest to newest" {
    // Arrange
    const Log = MeshEventLog(4);
    var log = Log{};
    var subject = [_]u8{ 'n', 'o', 'd', 'e', '1' };
    var detail = [_]u8{ 'u', 'p' };

    // Act
    log.push(.{ .kind = .peer_up, .ts_unix = 10, .subject = subject[0..], .detail = detail[0..] });
    subject[0] = 'X';
    detail[0] = 'Y';
    log.push(.{ .kind = .heal, .ts_unix = 11, .subject = "mesh", .detail = "" });

    // Assert
    try std.testing.expectEqual(@as(usize, 2), log.len());
    const first = log.get(0).?;
    const second = log.get(1).?;
    try std.testing.expectEqual(MeshEventKind.peer_up, first.kind);
    try std.testing.expectEqual(@as(i64, 10), first.ts_unix);
    try std.testing.expectEqualStrings("node1", first.subject);
    try std.testing.expectEqualStrings("up", first.detail);
    try std.testing.expectEqual(MeshEventKind.heal, second.kind);
    try std.testing.expectEqualStrings("mesh", second.subject);
    try std.testing.expectEqualStrings("", second.detail);
}

test "overflow wraps and drops oldest entries" {
    // Arrange
    const Log = MeshEventLog(3);
    var log = Log{};

    // Act
    log.push(.{ .kind = .peer_up, .ts_unix = 1, .subject = "one" });
    log.push(.{ .kind = .peer_down, .ts_unix = 2, .subject = "two" });
    log.push(.{ .kind = .split, .ts_unix = 3, .subject = "three" });
    log.push(.{ .kind = .heal, .ts_unix = 4, .subject = "four" });
    log.push(.{ .kind = .resync, .ts_unix = 5, .subject = "five" });

    // Assert
    try std.testing.expectEqual(@as(usize, 3), log.len());
    try std.testing.expectEqualStrings("three", log.get(0).?.subject);
    try std.testing.expectEqualStrings("four", log.get(1).?.subject);
    try std.testing.expectEqualStrings("five", log.get(2).?.subject);
    try std.testing.expectEqual(@as(?MeshEvent, null), log.get(3));
}

test "oversized subject and detail are truncated to inline caps" {
    // Arrange
    const Log = MeshEventLog(2);
    var log = Log{};
    const long_subject =
        "subject-abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789-extra";
    const long_detail =
        "detail-abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789-extra";

    // Act
    log.push(.{ .kind = .route_change, .subject = long_subject, .detail = long_detail });

    // Assert
    const ev = log.get(0).?;
    try std.testing.expectEqual(@as(usize, Log.subject_cap), ev.subject.len);
    try std.testing.expectEqual(@as(usize, Log.detail_cap), ev.detail.len);
    try std.testing.expectEqualStrings(long_subject[0..Log.subject_cap], ev.subject);
    try std.testing.expectEqualStrings(long_detail[0..Log.detail_cap], ev.detail);
}

test "render output is ordered oldest to newest with detail only when present" {
    // Arrange
    const Log = MeshEventLog(3);
    var log = Log{};
    log.push(.{ .kind = .peer_up, .ts_unix = 100, .subject = "alpha", .detail = "connected" });
    log.push(.{ .kind = .split, .ts_unix = 101, .subject = "beta" });
    log.push(.{ .kind = .heal, .ts_unix = 102, .subject = "gamma", .detail = "rejoined" });

    // Act
    var buf: [512]u8 = undefined;
    const out = try renderToBuf(&log, &buf);

    // Assert
    try std.testing.expectEqualStrings(
        "MESH LOG (3 events)\n" ++
            "100 peer-up alpha :connected\n" ++
            "101 split beta\n" ++
            "102 heal gamma :rejoined\n" ++
            "end of mesh log\n",
        out,
    );
}

test "kindWord covers every mesh event kind" {
    // Arrange
    const cases = [_]struct { kind: MeshEventKind, word: []const u8 }{
        .{ .kind = .peer_up, .word = "peer-up" },
        .{ .kind = .peer_down, .word = "peer-down" },
        .{ .kind = .link_handshake, .word = "link-handshake" },
        .{ .kind = .split, .word = "split" },
        .{ .kind = .heal, .word = "heal" },
        .{ .kind = .oper_grant_in, .word = "oper-grant-in" },
        .{ .kind = .oper_grant_revoke, .word = "oper-grant-revoke" },
        .{ .kind = .route_change, .word = "route-change" },
        .{ .kind = .resync, .word = "resync" },
    };

    // Act / Assert
    inline for (cases) |case| {
        try std.testing.expectEqualStrings(case.word, kindWord(case.kind));
    }
}

test "empty log renders header and footer with zero events" {
    // Arrange
    const Log = MeshEventLog(4);
    var log = Log{};

    // Act
    var buf: [128]u8 = undefined;
    const out = try renderToBuf(&log, &buf);

    // Assert
    try std.testing.expectEqualStrings("MESH LOG (0 events)\nend of mesh log\n", out);
}

test "clear resets length and iteration" {
    // Arrange
    const Log = MeshEventLog(2);
    var log = Log{};
    log.push(.{ .kind = .peer_up, .subject = "alpha" });
    log.push(.{ .kind = .peer_down, .subject = "beta" });

    // Act
    log.clear();

    // Assert
    try std.testing.expectEqual(@as(usize, 0), log.len());
    var it = log.iterator();
    try std.testing.expect(it.next() == null);
}

test "zero capacity log remains empty and renderable" {
    // Arrange
    const Log = MeshEventLog(0);
    var log = Log{};

    // Act
    log.push(.{ .kind = .peer_up, .subject = "ignored" });
    var buf: [128]u8 = undefined;
    const out = try renderToBuf(&log, &buf);

    // Assert
    try std.testing.expectEqual(@as(usize, 0), log.len());
    try std.testing.expectEqualStrings("MESH LOG (0 events)\nend of mesh log\n", out);
}

test "render strips CR and LF from fields without adding stray carriage returns" {
    // Arrange
    const Log = MeshEventLog(2);
    var log = Log{};
    log.push(.{
        .kind = .link_handshake,
        .ts_unix = 7,
        .subject = "node\r\nA",
        .detail = "phase\r\none",
    });

    // Act
    var buf: [256]u8 = undefined;
    const out = try renderToBuf(&log, &buf);

    // Assert
    try std.testing.expectEqualStrings(
        "MESH LOG (1 events)\n" ++
            "7 link-handshake nodeA :phaseone\n" ++
            "end of mesh log\n",
        out,
    );
    try std.testing.expect(std.mem.indexOfScalar(u8, out, '\r') == null);
}

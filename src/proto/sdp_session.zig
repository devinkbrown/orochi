// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Textual SDP parser and builder for WebRTC offer/answer metadata.
//!
//! This module handles the RFC 4566 / RFC 8866 text layer. It is intentionally
//! separate from `sdp.zig`, which is Onyx Server's compact binary SDP-lite format.
const std = @import("std");

pub const Error = error{
    InvalidLine,
    InvalidMedia,
    InvalidMediaKind,
    InvalidPort,
    MissingMedia,
};

pub const MediaKind = enum {
    audio,
    video,
    application,
};

pub const Direction = enum {
    sendrecv,
    sendonly,
    recvonly,
    inactive,
};

pub const Media = struct {
    kind: MediaKind,
    port: u16,
    payload_types: []const u8,
    mid: []const u8 = "",
    ufrag: []const u8 = "",
    pwd: []const u8 = "",
    fingerprint: []const u8 = "",
    setup: []const u8 = "",
    direction: Direction = .sendrecv,
    rtcp_mux: bool = false,
    rtpmap: []const []const u8 = &.{},
    rtcp_fb: []const []const u8 = &.{},
    candidates: []const []const u8 = &.{},

    fn deinitOwned(self: *Media, allocator: std.mem.Allocator) void {
        allocator.free(self.rtpmap);
        allocator.free(self.rtcp_fb);
        allocator.free(self.candidates);
        self.rtpmap = &.{};
        self.rtcp_fb = &.{};
        self.candidates = &.{};
    }
};

pub const Session = struct {
    version: []const u8 = "0",
    origin: []const u8 = "- 0 0 IN IP4 127.0.0.1",
    name: []const u8 = "-",
    timing: []const u8 = "0 0",
    ufrag: []const u8 = "",
    pwd: []const u8 = "",
    fingerprint: []const u8 = "",
    media: []Media,
    _owned_text: ?[]u8 = null,
    _owns_allocations: bool = false,

    pub fn deinit(self: *Session, allocator: std.mem.Allocator) void {
        if (!self._owns_allocations) return;

        for (self.media) |*media| {
            media.deinitOwned(allocator);
        }
        allocator.free(self.media);
        if (self._owned_text) |owned_text| allocator.free(owned_text);

        self.media = &.{};
        self._owned_text = null;
        self._owns_allocations = false;
    }
};

pub fn parse(allocator: std.mem.Allocator, text: []const u8) !Session {
    var owned_text = try allocator.dupe(u8, text);
    errdefer allocator.free(owned_text);

    var media_list: std.ArrayList(Media) = .empty;
    errdefer {
        for (media_list.items) |*media| media.deinitOwned(allocator);
        media_list.deinit(allocator);
    }

    var rtpmap_list: std.ArrayList([]const u8) = .empty;
    var rtcp_fb_list: std.ArrayList([]const u8) = .empty;
    var candidate_list: std.ArrayList([]const u8) = .empty;
    errdefer {
        rtpmap_list.deinit(allocator);
        rtcp_fb_list.deinit(allocator);
        candidate_list.deinit(allocator);
    }

    var session = Session{
        .media = &.{},
        ._owned_text = owned_text,
        ._owns_allocations = true,
    };
    var current_media: ?Media = null;

    var lines = std.mem.tokenizeAny(u8, owned_text, "\r\n");
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t");
        if (line.len == 0) continue;

        if (std.mem.startsWith(u8, line, "m=")) {
            try finishMedia(allocator, &current_media, &rtpmap_list, &rtcp_fb_list, &candidate_list, &media_list);
            current_media = try parseMediaLine(line);
            continue;
        }

        if (std.mem.startsWith(u8, line, "a=")) {
            try parseAttribute(allocator, line[2..], &session, &current_media, &rtpmap_list, &rtcp_fb_list, &candidate_list);
            continue;
        }

        if (current_media == null) {
            parseSessionLine(line, &session);
        }
    }

    try finishMedia(allocator, &current_media, &rtpmap_list, &rtcp_fb_list, &candidate_list, &media_list);
    if (media_list.items.len == 0) return error.MissingMedia;

    session.media = try media_list.toOwnedSlice(allocator);
    session._owned_text = owned_text;
    applySessionDefaults(&session);
    owned_text = &.{};

    return session;
}

pub fn build(allocator: std.mem.Allocator, session: Session) ![]u8 {
    if (session.media.len == 0) return error.MissingMedia;

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    try out.print(allocator, "v={s}\r\n", .{orDefault(session.version, "0")});
    try out.print(allocator, "o={s}\r\n", .{orDefault(session.origin, "- 0 0 IN IP4 127.0.0.1")});
    try out.print(allocator, "s={s}\r\n", .{orDefault(session.name, "-")});
    try out.print(allocator, "t={s}\r\n", .{orDefault(session.timing, "0 0")});

    if (session.ufrag.len != 0) try out.print(allocator, "a=ice-ufrag:{s}\r\n", .{session.ufrag});
    if (session.pwd.len != 0) try out.print(allocator, "a=ice-pwd:{s}\r\n", .{session.pwd});
    if (session.fingerprint.len != 0) try out.print(allocator, "a=fingerprint:{s}\r\n", .{session.fingerprint});

    for (session.media) |media| {
        if (media.payload_types.len == 0) return error.InvalidMedia;

        try out.print(
            allocator,
            "m={s} {d} UDP/TLS/RTP/SAVPF {s}\r\n",
            .{ mediaKindName(media.kind), media.port, media.payload_types },
        );
        if (media.mid.len != 0) try out.print(allocator, "a=mid:{s}\r\n", .{media.mid});
        if (media.ufrag.len != 0 and !std.mem.eql(u8, media.ufrag, session.ufrag)) {
            try out.print(allocator, "a=ice-ufrag:{s}\r\n", .{media.ufrag});
        }
        if (media.pwd.len != 0 and !std.mem.eql(u8, media.pwd, session.pwd)) {
            try out.print(allocator, "a=ice-pwd:{s}\r\n", .{media.pwd});
        }
        if (media.fingerprint.len != 0 and !std.mem.eql(u8, media.fingerprint, session.fingerprint)) {
            try out.print(allocator, "a=fingerprint:{s}\r\n", .{media.fingerprint});
        }
        if (media.setup.len != 0) try out.print(allocator, "a=setup:{s}\r\n", .{media.setup});
        for (media.rtpmap) |rtpmap| try out.print(allocator, "a=rtpmap:{s}\r\n", .{rtpmap});
        for (media.rtcp_fb) |rtcp_fb| try out.print(allocator, "a=rtcp-fb:{s}\r\n", .{rtcp_fb});
        if (media.rtcp_mux) try out.appendSlice(allocator, "a=rtcp-mux\r\n");
        try out.print(allocator, "a={s}\r\n", .{directionName(media.direction)});
        for (media.candidates) |candidate| try out.print(allocator, "a=candidate:{s}\r\n", .{candidate});
    }

    return out.toOwnedSlice(allocator);
}

fn parseSessionLine(line: []const u8, session: *Session) void {
    if (std.mem.startsWith(u8, line, "v=")) {
        session.version = std.mem.trim(u8, line[2..], " \t");
    } else if (std.mem.startsWith(u8, line, "o=")) {
        session.origin = std.mem.trim(u8, line[2..], " \t");
    } else if (std.mem.startsWith(u8, line, "s=")) {
        session.name = std.mem.trim(u8, line[2..], " \t");
    } else if (std.mem.startsWith(u8, line, "t=")) {
        session.timing = std.mem.trim(u8, line[2..], " \t");
    }
}

fn parseAttribute(
    allocator: std.mem.Allocator,
    attr: []const u8,
    session: *Session,
    current_media: *?Media,
    rtpmap_list: *std.ArrayList([]const u8),
    rtcp_fb_list: *std.ArrayList([]const u8),
    candidate_list: *std.ArrayList([]const u8),
) !void {
    if (valueAfter(attr, "ice-ufrag:")) |value| {
        if (current_media.*) |*media| {
            media.ufrag = value;
        } else {
            session.ufrag = value;
        }
    } else if (valueAfter(attr, "ice-pwd:")) |value| {
        if (current_media.*) |*media| {
            media.pwd = value;
        } else {
            session.pwd = value;
        }
    } else if (valueAfter(attr, "fingerprint:")) |value| {
        if (current_media.*) |*media| {
            media.fingerprint = value;
        } else {
            session.fingerprint = value;
        }
    } else if (valueAfter(attr, "setup:")) |value| {
        if (current_media.*) |*media| media.setup = value;
    } else if (valueAfter(attr, "mid:")) |value| {
        if (current_media.*) |*media| media.mid = value;
    } else if (valueAfter(attr, "rtpmap:")) |value| {
        if (current_media.* != null) try rtpmap_list.append(allocator, value);
    } else if (valueAfter(attr, "rtcp-fb:")) |value| {
        if (current_media.* != null) try rtcp_fb_list.append(allocator, value);
    } else if (valueAfter(attr, "candidate:")) |value| {
        if (current_media.* != null) try candidate_list.append(allocator, value);
    } else if (std.mem.eql(u8, attr, "rtcp-mux")) {
        if (current_media.*) |*media| media.rtcp_mux = true;
    } else if (parseDirection(attr)) |direction| {
        if (current_media.*) |*media| media.direction = direction;
    }
}

fn finishMedia(
    allocator: std.mem.Allocator,
    current_media: *?Media,
    rtpmap_list: *std.ArrayList([]const u8),
    rtcp_fb_list: *std.ArrayList([]const u8),
    candidate_list: *std.ArrayList([]const u8),
    media_list: *std.ArrayList(Media),
) !void {
    var media = current_media.* orelse return;

    const rtpmap = try rtpmap_list.toOwnedSlice(allocator);
    errdefer allocator.free(rtpmap);
    const rtcp_fb = try rtcp_fb_list.toOwnedSlice(allocator);
    errdefer allocator.free(rtcp_fb);
    const candidates = try candidate_list.toOwnedSlice(allocator);
    errdefer allocator.free(candidates);

    media.rtpmap = rtpmap;
    media.rtcp_fb = rtcp_fb;
    media.candidates = candidates;
    try media_list.append(allocator, media);

    current_media.* = null;
}

fn parseMediaLine(line: []const u8) !Media {
    var rest = std.mem.trim(u8, line[2..], " \t");
    const kind_text = nextField(&rest) orelse return error.InvalidMedia;
    const port_text = nextField(&rest) orelse return error.InvalidMedia;
    const proto_text = nextField(&rest) orelse return error.InvalidMedia;
    const payload_types = std.mem.trim(u8, rest, " \t");

    if (!std.mem.eql(u8, proto_text, "UDP/TLS/RTP/SAVPF")) return error.InvalidMedia;
    if (payload_types.len == 0) return error.InvalidMedia;

    return .{
        .kind = try parseMediaKind(kind_text),
        .port = std.fmt.parseInt(u16, port_text, 10) catch return error.InvalidPort,
        .payload_types = payload_types,
    };
}

fn nextField(rest: *[]const u8) ?[]const u8 {
    rest.* = std.mem.trimStart(u8, rest.*, " \t");
    if (rest.*.len == 0) return null;

    const end = std.mem.indexOfAny(u8, rest.*, " \t") orelse rest.*.len;
    const field = rest.*[0..end];
    rest.* = rest.*[end..];
    return field;
}

fn parseMediaKind(text: []const u8) Error!MediaKind {
    if (std.mem.eql(u8, text, "audio")) return .audio;
    if (std.mem.eql(u8, text, "video")) return .video;
    if (std.mem.eql(u8, text, "application")) return .application;
    return error.InvalidMediaKind;
}

fn mediaKindName(kind: MediaKind) []const u8 {
    return switch (kind) {
        .audio => "audio",
        .video => "video",
        .application => "application",
    };
}

fn parseDirection(attr: []const u8) ?Direction {
    if (std.mem.eql(u8, attr, "sendrecv")) return .sendrecv;
    if (std.mem.eql(u8, attr, "sendonly")) return .sendonly;
    if (std.mem.eql(u8, attr, "recvonly")) return .recvonly;
    if (std.mem.eql(u8, attr, "inactive")) return .inactive;
    return null;
}

fn directionName(direction: Direction) []const u8 {
    return switch (direction) {
        .sendrecv => "sendrecv",
        .sendonly => "sendonly",
        .recvonly => "recvonly",
        .inactive => "inactive",
    };
}

fn valueAfter(attr: []const u8, prefix: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, attr, prefix)) return null;
    return std.mem.trim(u8, attr[prefix.len..], " \t");
}

fn orDefault(value: []const u8, default_value: []const u8) []const u8 {
    return if (value.len == 0) default_value else value;
}

fn applySessionDefaults(session: *Session) void {
    for (session.media) |media| {
        if (session.ufrag.len == 0 and media.ufrag.len != 0) session.ufrag = media.ufrag;
        if (session.pwd.len == 0 and media.pwd.len != 0) session.pwd = media.pwd;
        if (session.fingerprint.len == 0 and media.fingerprint.len != 0) session.fingerprint = media.fingerprint;
    }

    for (session.media) |*media| {
        if (media.ufrag.len == 0) media.ufrag = session.ufrag;
        if (media.pwd.len == 0) media.pwd = session.pwd;
        if (media.fingerprint.len == 0) media.fingerprint = session.fingerprint;
    }
}

test "parse realistic minimal WebRTC audio offer" {
    const text =
        "v=0\r\n" ++
        "o=- 4611733050198790857 2 IN IP4 127.0.0.1\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "a=unknown-session:ignored\r\n" ++
        "m=audio 9 UDP/TLS/RTP/SAVPF 111 0 8\r\n" ++
        "a=ice-ufrag:abcD\r\n" ++
        "a=ice-pwd:0123456789abcdefghijklmn\r\n" ++
        "a=fingerprint:sha-256 12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF\r\n" ++
        "a=setup:actpass\r\n" ++
        "a=mid:0\r\n" ++
        "a=rtpmap:111 opus/48000/2\r\n" ++
        "a=rtcp-fb:111 transport-cc\r\n" ++
        "a=rtcp-mux\r\n" ++
        "a=sendrecv\r\n" ++
        "a=candidate:842163049 1 udp 1677729535 192.0.2.1 54400 typ srflx raddr 10.0.0.1 rport 54400\r\n" ++
        "a=unknown-media:ignored\r\n";

    var session = try parse(std.testing.allocator, text);
    defer session.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("0", session.version);
    try std.testing.expectEqualStrings("- 4611733050198790857 2 IN IP4 127.0.0.1", session.origin);
    try std.testing.expectEqual(@as(usize, 1), session.media.len);
    try std.testing.expectEqualStrings("abcD", session.ufrag);
    try std.testing.expectEqualStrings("0123456789abcdefghijklmn", session.pwd);
    try std.testing.expect(std.mem.startsWith(u8, session.fingerprint, "sha-256 "));

    const audio = session.media[0];
    try std.testing.expectEqual(.audio, audio.kind);
    try std.testing.expectEqual(@as(u16, 9), audio.port);
    try std.testing.expectEqualStrings("111 0 8", audio.payload_types);
    try std.testing.expectEqualStrings("0", audio.mid);
    try std.testing.expectEqualStrings("abcD", audio.ufrag);
    try std.testing.expectEqualStrings("0123456789abcdefghijklmn", audio.pwd);
    try std.testing.expectEqualStrings("actpass", audio.setup);
    try std.testing.expectEqual(.sendrecv, audio.direction);
    try std.testing.expect(audio.rtcp_mux);
    try std.testing.expectEqual(@as(usize, 1), audio.rtpmap.len);
    try std.testing.expectEqualStrings("111 opus/48000/2", audio.rtpmap[0]);
    try std.testing.expectEqual(@as(usize, 1), audio.rtcp_fb.len);
    try std.testing.expectEqualStrings("111 transport-cc", audio.rtcp_fb[0]);
    try std.testing.expectEqual(@as(usize, 1), audio.candidates.len);
}

test "build and parse round trip key fields" {
    const rtpmaps = [_][]const u8{
        "111 opus/48000/2",
        "0 PCMU/8000",
    };
    const rtcp_fb = [_][]const u8{
        "111 transport-cc",
    };
    const candidates = [_][]const u8{
        "1 1 udp 2130706431 203.0.113.1 50000 typ host",
    };
    var media = [_]Media{
        .{
            .kind = .audio,
            .port = 9,
            .payload_types = "111 0",
            .mid = "audio0",
            .setup = "actpass",
            .direction = .sendonly,
            .rtcp_mux = true,
            .rtpmap = rtpmaps[0..],
            .rtcp_fb = rtcp_fb[0..],
            .candidates = candidates[0..],
        },
    };
    const session = Session{
        .origin = "- 1 1 IN IP4 127.0.0.1",
        .ufrag = "ufrag1",
        .pwd = "passwordpasswordpassword",
        .fingerprint = "sha-256 AA:BB:CC",
        .media = media[0..],
    };

    const text = try build(std.testing.allocator, session);
    defer std.testing.allocator.free(text);

    var parsed = try parse(std.testing.allocator, text);
    defer parsed.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("ufrag1", parsed.ufrag);
    try std.testing.expectEqualStrings("passwordpasswordpassword", parsed.pwd);
    try std.testing.expectEqualStrings("sha-256 AA:BB:CC", parsed.fingerprint);
    try std.testing.expectEqual(@as(usize, 1), parsed.media.len);

    const parsed_media = parsed.media[0];
    try std.testing.expectEqual(.audio, parsed_media.kind);
    try std.testing.expectEqual(@as(u16, 9), parsed_media.port);
    try std.testing.expectEqualStrings("111 0", parsed_media.payload_types);
    try std.testing.expectEqualStrings("audio0", parsed_media.mid);
    try std.testing.expectEqualStrings("ufrag1", parsed_media.ufrag);
    try std.testing.expectEqualStrings("passwordpasswordpassword", parsed_media.pwd);
    try std.testing.expectEqualStrings("sha-256 AA:BB:CC", parsed_media.fingerprint);
    try std.testing.expectEqualStrings("actpass", parsed_media.setup);
    try std.testing.expectEqual(.sendonly, parsed_media.direction);
    try std.testing.expect(parsed_media.rtcp_mux);
    try std.testing.expectEqualStrings("111 opus/48000/2", parsed_media.rtpmap[0]);
    try std.testing.expectEqualStrings("111 transport-cc", parsed_media.rtcp_fb[0]);
    try std.testing.expectEqualStrings("1 1 udp 2130706431 203.0.113.1 50000 typ host", parsed_media.candidates[0]);
}

test "parse LF line endings and ignore unknown attributes" {
    const text =
        "v=0\n" ++
        "o=- 2 2 IN IP4 127.0.0.1\n" ++
        "s=-\n" ++
        "t=0 0\n" ++
        "a=ice-ufrag:sessionUfrag\n" ++
        "a=ice-pwd:sessionPassword\n" ++
        "m=video 9 UDP/TLS/RTP/SAVPF 96\n" ++
        "a=mid:video0\n" ++
        "a=rtpmap:96 VP8/90000\n" ++
        "a=unknown:ignored\n" ++
        "a=recvonly\n";

    var session = try parse(std.testing.allocator, text);
    defer session.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("sessionUfrag", session.ufrag);
    try std.testing.expectEqualStrings("sessionPassword", session.pwd);
    try std.testing.expectEqual(@as(usize, 1), session.media.len);
    try std.testing.expectEqual(.video, session.media[0].kind);
    try std.testing.expectEqualStrings("96", session.media[0].payload_types);
    try std.testing.expectEqualStrings("video0", session.media[0].mid);
    try std.testing.expectEqualStrings("sessionUfrag", session.media[0].ufrag);
    try std.testing.expectEqual(.recvonly, session.media[0].direction);
    try std.testing.expectEqual(@as(usize, 1), session.media[0].rtpmap.len);
    try std.testing.expectEqual(@as(usize, 0), session.media[0].rtcp_fb.len);
}

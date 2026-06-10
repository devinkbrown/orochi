//! MIC relay compatibility model for comic-prefixed chat text.
//!
//! The daemon still owns negotiation and delivery. This module only models the
//! per-message compatibility rule: a MIC comic prefix is opaque bytes that may
//! be preserved for MIC peers and hidden from plain IRC/IRCX peers.
//!
//! Sentinel convention: within this model, a comic prefix is present only when
//! the message starts with `comic_prefix_open` and contains the first following
//! `comic_prefix_close`. The prefix slice includes both sentinels and every byte
//! between them. The payload between the sentinels is intentionally not parsed;
//! malformed or non-leading sentinels are treated as ordinary message text.

const std = @import("std");

/// Internal marker that opens an opaque MIC comic prefix.
pub const comic_prefix_open = "\x1eMIC{";

/// Internal marker that closes an opaque MIC comic prefix.
pub const comic_prefix_close = "}\x1e";

/// Numeric emitted when channel MIC policy refuses a join.
pub const join_refusal_numeric: u16 = 900;

/// Client protocol family relevant to MIC compatibility handling.
pub const ProtocolClass = enum {
    irc,
    ircx,
    mic,
};

/// Channel admission policy for MIC-aware and non-MIC clients.
pub const ChannelMicPolicy = enum {
    any,
    mic_only,
    irc_ircx_only,
};

/// Borrowed split view of a message after applying the MIC sentinel convention.
pub const ComicSplit = struct {
    /// Opaque prefix bytes, including sentinels, or empty when absent.
    prefix: []const u8,
    /// Message text after the prefix, or the whole text when no valid prefix exists.
    body: []const u8,

    pub fn hasPrefix(self: ComicSplit) bool {
        return self.prefix.len != 0;
    }
};

/// Structured join refusal surfaced by the pure model for later daemon wiring.
pub const JoinRefusal = struct {
    numeric: u16 = join_refusal_numeric,
    text: []const u8,
};

/// Admission decision with the refusal numeric already selected.
pub const JoinDecision = union(enum) {
    allowed,
    refused: JoinRefusal,
};

/// Split a message into opaque MIC comic prefix and normal body.
pub fn splitComicPrefix(text: []const u8) ComicSplit {
    if (!std.mem.startsWith(u8, text, comic_prefix_open)) {
        return .{ .prefix = "", .body = text };
    }

    const rest = text[comic_prefix_open.len..];
    const close_at = std.mem.indexOf(u8, rest, comic_prefix_close) orelse {
        return .{ .prefix = "", .body = text };
    };
    const prefix_end = comic_prefix_open.len + close_at + comic_prefix_close.len;
    return .{ .prefix = text[0..prefix_end], .body = text[prefix_end..] };
}

/// Render one stored message for a recipient class and channel format mode.
pub fn renderFor(class: ProtocolClass, noformat: bool, text: []const u8) []const u8 {
    const split = splitComicPrefix(text);
    return switch (class) {
        .mic => if (noformat) split.body else text,
        .irc, .ircx => split.body,
    };
}

/// Return whether a client class may join a channel with the given MIC policy.
pub fn joinAllowed(policy: ChannelMicPolicy, class: ProtocolClass) bool {
    return switch (policy) {
        .any => true,
        .mic_only => switch (class) {
            .mic => true,
            .irc, .ircx => false,
        },
        .irc_ircx_only => switch (class) {
            .irc, .ircx => true,
            .mic => false,
        },
    };
}

/// Return a structured admission result, including numeric 900 on refusal.
pub fn decideJoin(policy: ChannelMicPolicy, class: ProtocolClass) JoinDecision {
    if (joinAllowed(policy, class)) return .allowed;
    return .{ .refused = .{ .text = refusalText(policy, class) } };
}

/// Return the refusal numeric when a join would be denied.
pub fn joinRefusalNumeric(policy: ChannelMicPolicy, class: ProtocolClass) ?u16 {
    return switch (decideJoin(policy, class)) {
        .allowed => null,
        .refused => |refusal| refusal.numeric,
    };
}

/// Append an IRC numeric line for a denied MIC-policy join.
pub fn emitJoinRefusal(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(u8),
    server_name: []const u8,
    nick: []const u8,
    channel: []const u8,
    policy: ChannelMicPolicy,
    class: ProtocolClass,
) !bool {
    const decision = decideJoin(policy, class);
    const refusal = switch (decision) {
        .allowed => return false,
        .refused => |value| value,
    };

    var code_buf: [3]u8 = undefined;
    const code = try std.fmt.bufPrint(&code_buf, "{d}", .{refusal.numeric});

    try out.appendSlice(allocator, ":");
    try out.appendSlice(allocator, server_name);
    try out.appendSlice(allocator, " ");
    try out.appendSlice(allocator, code);
    try out.appendSlice(allocator, " ");
    try out.appendSlice(allocator, nick);
    try out.appendSlice(allocator, " ");
    try out.appendSlice(allocator, channel);
    try out.appendSlice(allocator, " :");
    try out.appendSlice(allocator, refusal.text);
    try out.appendSlice(allocator, "\r\n");
    return true;
}

fn refusalText(policy: ChannelMicPolicy, class: ProtocolClass) []const u8 {
    return switch (policy) {
        .any => switch (class) {
            .irc, .ircx, .mic => "Join allowed",
        },
        .mic_only => switch (class) {
            .irc, .ircx => "Cannot join MIC only channel with IRC client",
            .mic => "Join allowed",
        },
        .irc_ircx_only => switch (class) {
            .irc, .ircx => "Join allowed",
            .mic => "Cannot join IRC/IRCX only channel with MIC client",
        },
    };
}

test "mic rendering keeps opaque comic prefix" {
    const text = comic_prefix_open ++ "\x00\x7fpose=9" ++ comic_prefix_close ++ "hello";

    const split = splitComicPrefix(text);
    try std.testing.expect(split.hasPrefix());
    try std.testing.expectEqualStrings(comic_prefix_open ++ "\x00\x7fpose=9" ++ comic_prefix_close, split.prefix);
    try std.testing.expectEqualStrings("hello", split.body);
    try std.testing.expectEqualStrings(text, renderFor(.mic, false, text));
}

test "irc rendering strips opaque comic prefix" {
    const text = comic_prefix_open ++ "opaque comic bytes" ++ comic_prefix_close ++ "plain body";

    try std.testing.expectEqualStrings("plain body", renderFor(.irc, false, text));
    try std.testing.expectEqualStrings("plain body", renderFor(.ircx, false, text));
}

test "noformat strips comic prefix even for mic" {
    const text = comic_prefix_open ++ "gesture wheel data" ++ comic_prefix_close ++ "body only";

    try std.testing.expectEqualStrings("body only", renderFor(.mic, true, text));
}

test "mic only refuses irc with numeric 900" {
    try std.testing.expect(!joinAllowed(.mic_only, .irc));
    try std.testing.expectEqual(@as(?u16, join_refusal_numeric), joinRefusalNumeric(.mic_only, .irc));

    var out = std.ArrayListUnmanaged(u8).empty;
    defer out.deinit(std.testing.allocator);

    try std.testing.expect(try emitJoinRefusal(
        std.testing.allocator,
        &out,
        "orochi.test",
        "plain",
        "#comic",
        .mic_only,
        .irc,
    ));
    try std.testing.expectEqualStrings(
        ":orochi.test 900 plain #comic :Cannot join MIC only channel with IRC client\r\n",
        out.items,
    );
}

// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deterministic local membership burst construction for fresh UNDERTOW links.
//!
//! This module is a pure transform: callers provide a stable snapshot of this
//! node's current local channel memberships, and the returned events borrow
//! names from that snapshot.

const std = @import("std");

/// One local membership fact to advertise.
pub const LocalMember = struct {
    channel: []const u8,
    nick: []const u8,
    status: u4,
};

/// A membership event ready to hand to the per-link sender (present=true =>
/// join/status).
pub const BurstEvent = struct {
    channel: []const u8,
    nick: []const u8,
    status: u4,
    origin_node: u64,
    hlc: u64,
    present: bool = true,
};

pub const Options = struct {
    origin_node: u64,
    /// Monotonic base; `build` assigns `hlc_base + i` to event `i`.
    hlc_base: u64,
    /// Upper bound on emitted events.
    max_events: usize = 4096,
};

/// Produce a deterministic (stable channel-then-nick ordering), de-duplicated
/// (one event per (channel,nick), keeping the highest status), bounded list.
/// Caller owns the returned slice (allocator.free); event string fields borrow
/// from `members` (do not free separately).
pub fn build(allocator: std.mem.Allocator, members: []const LocalMember, opts: Options) ![]BurstEvent {
    if (members.len == 0 or opts.max_events == 0) {
        return allocator.alloc(BurstEvent, 0);
    }

    const sorted = try allocator.alloc(LocalMember, members.len);
    defer allocator.free(sorted);
    @memcpy(sorted, members);
    std.mem.sort(LocalMember, sorted, {}, lessMember);

    const capacity = @min(members.len, opts.max_events);
    var events = try allocator.alloc(BurstEvent, capacity);
    errdefer allocator.free(events);

    var in_idx: usize = 0;
    var out_len: usize = 0;
    while (in_idx < sorted.len and out_len < opts.max_events) {
        const first = sorted[in_idx];
        var status = first.status;
        in_idx += 1;

        while (in_idx < sorted.len and sameIdentity(first, sorted[in_idx])) : (in_idx += 1) {
            status = @max(status, sorted[in_idx].status);
        }

        events[out_len] = .{
            .channel = first.channel,
            .nick = first.nick,
            .status = status,
            .origin_node = opts.origin_node,
            .hlc = opts.hlc_base + out_len,
        };
        out_len += 1;
    }

    return allocator.realloc(events, out_len);
}

fn sameIdentity(a: LocalMember, b: LocalMember) bool {
    return std.mem.eql(u8, a.channel, b.channel) and std.mem.eql(u8, a.nick, b.nick);
}

fn lessMember(_: void, a: LocalMember, b: LocalMember) bool {
    const channel_cmp = std.mem.order(u8, a.channel, b.channel);
    if (channel_cmp != .eq) return channel_cmp == .lt;
    return std.mem.order(u8, a.nick, b.nick) == .lt;
}

test "dedup keeps higher status" {
    const members = [_]LocalMember{
        .{ .channel = "#z", .nick = "alice", .status = 1 },
        .{ .channel = "#z", .nick = "alice", .status = 8 },
        .{ .channel = "#z", .nick = "alice", .status = 4 },
    };

    const events = try build(std.testing.allocator, &members, .{
        .origin_node = 7,
        .hlc_base = 100,
    });
    defer std.testing.allocator.free(events);

    try std.testing.expectEqual(@as(usize, 1), events.len);
    try std.testing.expectEqualStrings("#z", events[0].channel);
    try std.testing.expectEqualStrings("alice", events[0].nick);
    try std.testing.expectEqual(@as(u4, 8), events[0].status);
    try std.testing.expectEqual(@as(u64, 7), events[0].origin_node);
    try std.testing.expectEqual(@as(u64, 100), events[0].hlc);
    try std.testing.expect(events[0].present);
}

test "ordering is stable" {
    const members = [_]LocalMember{
        .{ .channel = "#b", .nick = "zoe", .status = 0 },
        .{ .channel = "#a", .nick = "mallory", .status = 0 },
        .{ .channel = "#a", .nick = "alice", .status = 0 },
        .{ .channel = "#b", .nick = "bob", .status = 0 },
    };

    const events = try build(std.testing.allocator, &members, .{
        .origin_node = 9,
        .hlc_base = 50,
    });
    defer std.testing.allocator.free(events);

    try std.testing.expectEqual(@as(usize, 4), events.len);
    try std.testing.expectEqualStrings("#a", events[0].channel);
    try std.testing.expectEqualStrings("alice", events[0].nick);
    try std.testing.expectEqualStrings("#a", events[1].channel);
    try std.testing.expectEqualStrings("mallory", events[1].nick);
    try std.testing.expectEqualStrings("#b", events[2].channel);
    try std.testing.expectEqualStrings("bob", events[2].nick);
    try std.testing.expectEqualStrings("#b", events[3].channel);
    try std.testing.expectEqualStrings("zoe", events[3].nick);
    try std.testing.expectEqual(@as(u64, 50), events[0].hlc);
    try std.testing.expectEqual(@as(u64, 53), events[3].hlc);
}

test "max_events truncates" {
    const members = [_]LocalMember{
        .{ .channel = "#a", .nick = "a", .status = 0 },
        .{ .channel = "#a", .nick = "b", .status = 0 },
        .{ .channel = "#a", .nick = "c", .status = 0 },
    };

    const events = try build(std.testing.allocator, &members, .{
        .origin_node = 1,
        .hlc_base = 10,
        .max_events = 2,
    });
    defer std.testing.allocator.free(events);

    try std.testing.expectEqual(@as(usize, 2), events.len);
    try std.testing.expectEqualStrings("a", events[0].nick);
    try std.testing.expectEqualStrings("b", events[1].nick);
    try std.testing.expectEqual(@as(u64, 10), events[0].hlc);
    try std.testing.expectEqual(@as(u64, 11), events[1].hlc);
}

test "empty input returns empty slice" {
    const events = try build(std.testing.allocator, &.{}, .{
        .origin_node = 1,
        .hlc_base = 1,
    });
    defer std.testing.allocator.free(events);

    try std.testing.expectEqual(@as(usize, 0), events.len);
}

//! IRCX +x AUDITORIUM channel visibility predicates.
//!
//! These helpers are pure policy checks only. Callers that know member
//! identity should always include the viewer's own nick in NAMES/WHO output;
//! `visibleTo` answers whether another member is visible by rank.
const std = @import("std");

pub const flag_letter: u8 = 'x';

pub const Rank = enum {
    regular,
    voice,
    op,
};

/// Return whether `member_rank` is visible to `viewer_rank` in an auditorium
/// channel, excluding the viewer's own member record.
pub fn visibleTo(viewer_rank: Rank, member_rank: Rank) bool {
    if (member_rank == .op) return true;
    if (viewer_rank == .op or viewer_rank == .voice) return true;
    return false;
}

/// Return whether a member with `member_rank` should receive auditorium
/// join/part relays.
pub fn shouldRelayJoinPart(member_rank: Rank) bool {
    return member_rank == .op or member_rank == .voice;
}

test "regular member hidden from regular member" {
    const allocator = std.testing.allocator;
    const pair = try allocator.alloc(Rank, 2);
    defer allocator.free(pair);

    pair[0] = .regular;
    pair[1] = .regular;

    try std.testing.expect(!visibleTo(pair[0], pair[1]));
}

test "op visible to all" {
    inline for (.{ Rank.regular, Rank.voice, Rank.op }) |viewer_rank| {
        try std.testing.expect(visibleTo(viewer_rank, .op));
    }
}

test "join and part relay only to voiced or op members" {
    try std.testing.expect(!shouldRelayJoinPart(.regular));
    try std.testing.expect(shouldRelayJoinPart(.voice));
    try std.testing.expect(shouldRelayJoinPart(.op));
}

test "auditorium mode flag is x" {
    try std.testing.expectEqual(@as(u8, 'x'), flag_letter);
}

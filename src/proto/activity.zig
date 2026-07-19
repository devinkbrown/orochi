// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Real-time activity schemas: typing, reactions, and presence.
//!
//! Clean-room server-side data model for the Event-Spine "activity stream"
//! (planning/13): typed representations the daemon stores, converges (Concord
//! CRDT for reactions), and pushes to `ACTIVITY SUBSCRIBE`rs. The IRCv3 tag
//! *relay* already lives in `message_tags_relay`; this is the typed layer
//! underneath — parsing tag values into states, and one tagged union the
//! activity subscription carries.
//!
//! Wire conventions (IRCv3 drafts):
//!   * typing:    `@+typing=active|paused|done` on TAGMSG.
//!   * reactions: `@+draft/react=<reaction>;+draft/reply=<msgid>` on TAGMSG.
//!   * presence:  availability + activity, carried in the Event-Spine payload.
const std = @import("std");

pub const Error = error{
    UnknownTypingState,
    UnknownAvailability,
    EmptyReaction,
    ReactionTooLong,
    MissingReplyTarget,
};

/// Longest accepted reaction token (an emoji or short `:shortcode:`). Bounds the
/// store and prevents a hostile client from pinning unbounded reaction strings.
pub const max_reaction_len = 64;

// ---------------------------------------------------------------------------
// Typing  (IRCv3 draft/typing)
// ---------------------------------------------------------------------------

pub const TypingState = enum {
    active,
    paused,
    done,

    pub fn token(self: TypingState) []const u8 {
        return @tagName(self);
    }

    /// Parse a `+typing` tag value. Unknown values are an error (callers may map
    /// that to `.done` to fail safe, but the schema does not guess).
    pub fn parse(value: []const u8) Error!TypingState {
        if (std.mem.eql(u8, value, "active")) return .active;
        if (std.mem.eql(u8, value, "paused")) return .paused;
        if (std.mem.eql(u8, value, "done")) return .done;
        return error.UnknownTypingState;
    }
};

// ---------------------------------------------------------------------------
// Reactions  (IRCv3 draft/react + draft/reply)
// ---------------------------------------------------------------------------

pub const ReactionOp = enum { add, remove };

/// A reaction event against a prior message. `reaction` and `target_msgid`
/// borrow their inputs. The convergent store keys on `(target_msgid, reactor,
/// reaction)`; `op` drives add/remove in the CRDT.
pub const Reaction = struct {
    target_msgid: []const u8,
    reaction: []const u8,
    op: ReactionOp = .add,

    /// Build a reaction from a TAGMSG's `+draft/react` value plus its
    /// `+draft/reply` target. A bare TAGMSG react is always an `add`; removal is
    /// a separate convergent op the store applies.
    pub fn fromTags(react_value: []const u8, reply_target: ?[]const u8) Error!Reaction {
        return fromTagsWithOp(react_value, reply_target, .add);
    }

    pub fn fromTagsWithOp(react_value: []const u8, reply_target: ?[]const u8, op: ReactionOp) Error!Reaction {
        if (react_value.len == 0) return error.EmptyReaction;
        if (react_value.len > max_reaction_len) return error.ReactionTooLong;
        const target = reply_target orelse return error.MissingReplyTarget;
        if (target.len == 0) return error.MissingReplyTarget;
        return .{ .target_msgid = target, .reaction = react_value, .op = op };
    }
};

// ---------------------------------------------------------------------------
// Presence  (status + activity)
// ---------------------------------------------------------------------------

/// Coarse availability, ordered least→most "do not disturb". Maps onto AWAY:
/// `.active` is here/available, the rest are degrees of unavailable.
pub const Availability = enum {
    active, // present and available
    away, // stepped away
    extended_away, // away for a long time (xa)
    dnd, // do not disturb

    pub fn token(self: Availability) []const u8 {
        return switch (self) {
            .active => "active",
            .away => "away",
            .extended_away => "xa",
            .dnd => "dnd",
        };
    }

    pub fn parse(value: []const u8) Error!Availability {
        if (std.mem.eql(u8, value, "active")) return .active;
        if (std.mem.eql(u8, value, "away")) return .away;
        if (std.mem.eql(u8, value, "xa")) return .extended_away;
        if (std.mem.eql(u8, value, "dnd")) return .dnd;
        return error.UnknownAvailability;
    }
};

/// What the user is actively doing right now (orthogonal to availability).
pub const Activity = enum { idle, typing, speaking };

pub const Presence = struct {
    availability: Availability = .active,
    activity: Activity = .idle,
};

// ---------------------------------------------------------------------------
// Event-Spine activity event
// ---------------------------------------------------------------------------

/// One activity event delivered to an `ACTIVITY SUBSCRIBE`r. The `who`/`channel`
/// strings borrow the caller's storage.
pub const ActivityEvent = struct {
    who: []const u8,
    channel: []const u8,
    payload: Payload,

    pub const Kind = enum { typing, reaction, presence };

    pub const Payload = union(Kind) {
        typing: TypingState,
        reaction: Reaction,
        presence: Presence,
    };

    pub fn kind(self: ActivityEvent) Kind {
        return self.payload;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "typing state round-trips through its tag token" {
    for ([_]TypingState{ .active, .paused, .done }) |s| {
        try testing.expectEqual(s, try TypingState.parse(s.token()));
    }
    try testing.expectError(error.UnknownTypingState, TypingState.parse("typing"));
}

test "reaction from tags requires a reply target and a non-empty reaction" {
    const r = try Reaction.fromTags("🔥", "msg-7");
    try testing.expectEqualStrings("msg-7", r.target_msgid);
    try testing.expectEqualStrings("🔥", r.reaction);
    try testing.expectEqual(ReactionOp.add, r.op);

    const removed = try Reaction.fromTagsWithOp("🔥", "msg-7", .remove);
    try testing.expectEqualStrings("msg-7", removed.target_msgid);
    try testing.expectEqualStrings("🔥", removed.reaction);
    try testing.expectEqual(ReactionOp.remove, removed.op);

    try testing.expectError(error.EmptyReaction, Reaction.fromTags("", "msg-7"));
    try testing.expectError(error.MissingReplyTarget, Reaction.fromTags("👍", null));
    try testing.expectError(error.MissingReplyTarget, Reaction.fromTags("👍", ""));
}

test "an over-long reaction is rejected" {
    const big = &@as([(max_reaction_len + 1)]u8, @splat('x'));
    try testing.expectError(error.ReactionTooLong, Reaction.fromTags(big, "m1"));
}

test "availability tokens map xa correctly and reject unknowns" {
    try testing.expectEqualStrings("xa", Availability.extended_away.token());
    try testing.expectEqual(Availability.extended_away, try Availability.parse("xa"));
    try testing.expectEqual(Availability.dnd, try Availability.parse("dnd"));
    try testing.expectError(error.UnknownAvailability, Availability.parse("invisible"));
}

test "activity event reports its kind from the payload union" {
    const ev = ActivityEvent{
        .who = "alice",
        .channel = "#chat",
        .payload = .{ .typing = .active },
    };
    try testing.expectEqual(ActivityEvent.Kind.typing, ev.kind());

    const re = ActivityEvent{
        .who = "bob",
        .channel = "#chat",
        .payload = .{ .reaction = try Reaction.fromTags("👍", "m1") },
    };
    try testing.expectEqual(ActivityEvent.Kind.reaction, re.kind());
}

test "default presence is active and idle" {
    const p = Presence{};
    try testing.expectEqual(Availability.active, p.availability);
    try testing.expectEqual(Activity.idle, p.activity);
}

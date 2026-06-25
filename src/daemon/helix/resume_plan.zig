// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure, allocation-free resume planner for the Helix upgrade flow.
//!
//! After a Helix in-process upgrade, the successor process receives:
//!   - an array of decoded `ConnCapsule` records (the per-connection state), and
//!   - an array of file descriptors recovered out-of-band via SCM_RIGHTS.
//!
//! Each capsule references its fd by `fd_index` (an index into the fds array,
//! NOT the fd number). Before the server rebuilds any connection state, this
//! planner validates that mapping and produces an ordered list of resume
//! actions pairing each capsule with its concrete fd.
//!
//! Corruption caught here (before any rebuild) includes:
//!   - `fd_index` pointing past the end of the recovered fds array, and
//!   - two capsules claiming the same `fd_index` (a recipe for fd aliasing).
//!
//! The planner is pure and std-only: it never allocates. Callers supply the
//! output buffer. Duplicate detection uses a fixed-size stack bitset, so the
//! number of recoverable fds is bounded; see `max_fds`.

const std = @import("std");
const conn_capsule = @import("conn_capsule.zig");

/// Upper bound on the number of fds the duplicate-detection bitset can track.
/// Sized generously for a single upgrade hand-off; raise if needed.
pub const max_fds: usize = 1 << 20;

/// Errors produced by the planner.
pub const Error = error{
    /// A capsule's `fd_index` was >= the number of recovered fds.
    FdIndexOutOfRange,
    /// Two capsules referenced the same `fd_index`.
    DuplicateFdIndex,
    /// The output buffer was too small to hold one action per capsule, or the
    /// fd count exceeded `max_fds` (the duplicate-tracking limit).
    TooMany,
};

/// One validated resume action: a concrete fd paired with its capsule.
pub const ResumeAction = struct {
    fd: i32,
    capsule: conn_capsule.ConnCapsule,
};

/// Number of u64 words needed to back a bitset covering `max_fds` bits.
const bitset_words = (max_fds + 63) / 64;

/// Build an ordered, validated list of resume actions.
///
/// For each capsule, validates that `capsule.fd_index < fds.len`
/// (`FdIndexOutOfRange` otherwise) and that no two capsules share an
/// `fd_index` (`DuplicateFdIndex` otherwise). On success, pairs
/// `fds[capsule.fd_index]` with the capsule into `out`, preserving input order,
/// and returns the filled prefix of `out`.
///
/// Returns `TooMany` if `capsules.len > out.len`, or if `fds.len > max_fds`
/// (the duplicate-tracking bitset cannot cover that many indices).
pub fn plan(
    capsules: []const conn_capsule.ConnCapsule,
    fds: []const i32,
    out: []ResumeAction,
) Error![]ResumeAction {
    if (capsules.len > out.len) return error.TooMany;
    if (fds.len > max_fds) return error.TooMany;

    var seen = [_]u64{0} ** bitset_words;

    for (capsules, 0..) |capsule, i| {
        const idx = capsule.fd_index;
        if (idx >= fds.len) return error.FdIndexOutOfRange;

        if (bitTest(&seen, idx)) return error.DuplicateFdIndex;
        bitSet(&seen, idx);

        out[i] = .{ .fd = fds[idx], .capsule = capsule };
    }

    return out[0..capsules.len];
}

/// Fast pre-check that `plan` would succeed, without producing actions.
///
/// Performs the same range and duplicate validation against `fd_count` (the
/// number of recovered fds) as `plan` does. Does not require an output buffer,
/// so it never returns `TooMany` for output sizing; it only returns `TooMany`
/// when `fd_count` exceeds `max_fds`.
pub fn validate(
    capsules: []const conn_capsule.ConnCapsule,
    fd_count: usize,
) Error!void {
    if (fd_count > max_fds) return error.TooMany;

    var seen = [_]u64{0} ** bitset_words;

    for (capsules) |capsule| {
        const idx = capsule.fd_index;
        if (idx >= fd_count) return error.FdIndexOutOfRange;

        if (bitTest(&seen, idx)) return error.DuplicateFdIndex;
        bitSet(&seen, idx);
    }
}

// --- bitset helpers ---------------------------------------------------------

fn bitTest(seen: []const u64, idx: usize) bool {
    return (seen[idx / 64] & (@as(u64, 1) << @intCast(idx % 64))) != 0;
}

fn bitSet(seen: []u64, idx: usize) void {
    seen[idx / 64] |= (@as(u64, 1) << @intCast(idx % 64));
}

// --- tests ------------------------------------------------------------------

const ConnCapsule = conn_capsule.ConnCapsule;

fn makeCapsule(nick: []const u8, fd_index: u32) ConnCapsule {
    return .{
        .fd_index = fd_index,
        .caps = 0,
        .flags = .{},
        .nick = nick,
        .user = "u",
        .realname = "r",
        .host = "h",
        .account = null,
    };
}

test "plan pairs each fd with the right capsule in order" {
    const capsules = [_]ConnCapsule{
        makeCapsule("alice", 0),
        makeCapsule("bob", 1),
        makeCapsule("carol", 2),
    };
    const fds = [_]i32{ 10, 11, 12 };

    var out: [3]ResumeAction = undefined;
    const actions = try plan(&capsules, &fds, &out);

    try std.testing.expectEqual(@as(usize, 3), actions.len);

    try std.testing.expectEqualStrings("alice", actions[0].capsule.nick);
    try std.testing.expectEqual(@as(i32, 10), actions[0].fd);

    try std.testing.expectEqualStrings("bob", actions[1].capsule.nick);
    try std.testing.expectEqual(@as(i32, 11), actions[1].fd);

    try std.testing.expectEqualStrings("carol", actions[2].capsule.nick);
    try std.testing.expectEqual(@as(i32, 12), actions[2].fd);
}

test "plan honors fd_index ordering, not array position" {
    // Capsules in one order, but their fd_index values point elsewhere.
    const capsules = [_]ConnCapsule{
        makeCapsule("alice", 2),
        makeCapsule("bob", 0),
        makeCapsule("carol", 1),
    };
    const fds = [_]i32{ 10, 11, 12 };

    var out: [3]ResumeAction = undefined;
    const actions = try plan(&capsules, &fds, &out);

    try std.testing.expectEqual(@as(i32, 12), actions[0].fd); // alice -> fds[2]
    try std.testing.expectEqual(@as(i32, 10), actions[1].fd); // bob   -> fds[0]
    try std.testing.expectEqual(@as(i32, 11), actions[2].fd); // carol -> fds[1]
}

test "plan returns DuplicateFdIndex when two capsules share an index" {
    const capsules = [_]ConnCapsule{
        makeCapsule("alice", 0),
        makeCapsule("bob", 1),
        makeCapsule("carol", 1), // duplicate
    };
    const fds = [_]i32{ 10, 11, 12 };

    var out: [3]ResumeAction = undefined;
    try std.testing.expectError(error.DuplicateFdIndex, plan(&capsules, &fds, &out));
}

test "plan returns FdIndexOutOfRange when an index is past the fds array" {
    const capsules = [_]ConnCapsule{
        makeCapsule("alice", 0),
        makeCapsule("bob", 3), // fds only has indices 0..2
    };
    const fds = [_]i32{ 10, 11, 12 };

    var out: [2]ResumeAction = undefined;
    try std.testing.expectError(error.FdIndexOutOfRange, plan(&capsules, &fds, &out));
}

test "plan returns TooMany when the output buffer is too small" {
    const capsules = [_]ConnCapsule{
        makeCapsule("alice", 0),
        makeCapsule("bob", 1),
        makeCapsule("carol", 2),
    };
    const fds = [_]i32{ 10, 11, 12 };

    var out: [2]ResumeAction = undefined; // one short
    try std.testing.expectError(error.TooMany, plan(&capsules, &fds, &out));
}

test "validate agrees with plan on the good case" {
    const capsules = [_]ConnCapsule{
        makeCapsule("alice", 0),
        makeCapsule("bob", 1),
        makeCapsule("carol", 2),
    };
    const fds = [_]i32{ 10, 11, 12 };

    try validate(&capsules, fds.len);

    var out: [3]ResumeAction = undefined;
    _ = try plan(&capsules, &fds, &out);
}

test "validate agrees with plan on DuplicateFdIndex" {
    const capsules = [_]ConnCapsule{
        makeCapsule("alice", 0),
        makeCapsule("bob", 0), // duplicate
    };
    const fds = [_]i32{ 10, 11 };

    try std.testing.expectError(error.DuplicateFdIndex, validate(&capsules, fds.len));

    var out: [2]ResumeAction = undefined;
    try std.testing.expectError(error.DuplicateFdIndex, plan(&capsules, &fds, &out));
}

test "validate agrees with plan on FdIndexOutOfRange" {
    const capsules = [_]ConnCapsule{
        makeCapsule("alice", 0),
        makeCapsule("bob", 5), // out of range
    };
    const fds = [_]i32{ 10, 11 };

    try std.testing.expectError(error.FdIndexOutOfRange, validate(&capsules, fds.len));

    var out: [2]ResumeAction = undefined;
    try std.testing.expectError(error.FdIndexOutOfRange, plan(&capsules, &fds, &out));
}

test "empty capsules plan to an empty action slice" {
    const capsules = [_]ConnCapsule{};
    const fds = [_]i32{ 10, 11, 12 };

    var out: [4]ResumeAction = undefined;
    const actions = try plan(&capsules, &fds, &out);
    try std.testing.expectEqual(@as(usize, 0), actions.len);

    try validate(&capsules, fds.len);
}

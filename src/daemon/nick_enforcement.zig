// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fallback guest-nick generation for the Orochi IRC daemon.
//!
//! When the registration sweep (or a RECOVER) force-renames an unauthenticated
//! connection off a registered nick, it needs a collision-resistant fallback
//! nickname. That is the one piece of nick-enforcement mechanism that lives
//! here. The *policy* — whether and when to enforce, per the owner account's
//! SECURE/ENFORCE settings — lives in `svc_enforce.zig`, and the claim
//! bookkeeping is the connection's own `nick_claimed_at_ms`. This module owns no
//! sockets, timers, or clock access.

const std = @import("std");

/// Format a fallback guest nick like "Guest12345" into `buf`.
///
/// Returns the written slice, or `error.NoSpaceLeft` if `buf` is too small.
/// `seed` is supplied by the caller (e.g. a connection id or counter); this
/// helper performs no randomness and reads no clock.
pub fn guestNick(buf: []u8, seed: u64) error{NoSpaceLeft}![]const u8 {
    return std.fmt.bufPrint(buf, "Guest{d}", .{seed});
}

test "guestNick: formats a Guest nick from the seed" {
    var buf: [64]u8 = undefined;
    const nick = try guestNick(&buf, 12_345);
    try std.testing.expectEqualStrings("Guest12345", nick);
}

test "guestNick: reports NoSpaceLeft when the buffer is too small" {
    // "Guest9" needs 6 bytes; give it 3.
    var buf: [3]u8 = undefined;
    try std.testing.expectError(error.NoSpaceLeft, guestNick(&buf, 9));
}

// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared wire ceiling for a portable reusable-session snapshot.
//!
//! The same canonical snapshot must fit both the current signed
//! SESSION_REPLICA transport and the rolling-old SESSION_MIGRATE adapter. The
//! latter nests the snapshot inside a migration-relay capsule, repeats the
//! signed relay token, then adds the legacy session capsule before S2S framing.
//! Reserve a conservative 4 KiB for those bounded wrappers so accepting a
//! snapshot at one layer cannot make it permanently unsendable at another.

const std = @import("std");
const s2s_frame = @import("s2s_frame.zig");

pub const legacy_envelope_reserve: usize = 4 * 1024;

/// Largest canonical snapshot shared by every portable-session wire path.
pub const max_snapshot_len: usize = s2s_frame.default_max_frame_size -
    s2s_frame.header_len - legacy_envelope_reserve;

comptime {
    std.debug.assert(max_snapshot_len + legacy_envelope_reserve +
        s2s_frame.header_len == s2s_frame.default_max_frame_size);
}

test "portable snapshot ceiling reserves the rolling-old envelope" {
    try std.testing.expect(max_snapshot_len < s2s_frame.default_max_frame_size);
    try std.testing.expectEqual(
        s2s_frame.default_max_frame_size,
        max_snapshot_len + legacy_envelope_reserve + s2s_frame.header_len,
    );
}

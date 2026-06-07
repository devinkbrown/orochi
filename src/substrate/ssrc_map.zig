//! Allocation-free bidirectional identity map for the Kakehashi SFU media bridge.
//!
//! Translates between the native media stream identity (`stream_id: u32` carried
//! by opcodec frames) and the WebRTC RTP `ssrc: u32`, while tracking the
//! participant that owns each binding. Pure, std-only, fixed capacity — no
//! allocation, no hidden state.

const std = @import("std");

pub const Error = error{
    Full,
    NotFound,
};

pub const Entry = struct {
    stream_id: u32,
    ssrc: u32,
    participant: u64,
};

/// A fixed-capacity bidirectional `stream_id <-> ssrc` map.
///
/// Both `stream_id` and `ssrc` are unique keys: binding a `stream_id` or `ssrc`
/// that is already present replaces the prior binding rather than adding a
/// duplicate.
pub fn SsrcMap(comptime capacity: usize) type {
    return struct {
        const Self = @This();

        entries: [capacity]Entry = undefined,
        len: usize = 0,

        /// Bind `stream_id` and `ssrc` to `participant`.
        ///
        /// If either id is already mapped, the existing binding is replaced
        /// (any conflicting binding on the *other* key is removed first so the
        /// map never holds duplicate keys). Returns `Error.Full` only when a
        /// brand-new entry would exceed `capacity`.
        pub fn bind(self: *Self, stream_id: u32, ssrc: u32, participant: u64) Error!void {
            const new_entry = Entry{
                .stream_id = stream_id,
                .ssrc = ssrc,
                .participant = participant,
            };

            // Reuse an existing slot keyed by stream_id if present.
            if (self.indexOfStream(stream_id)) |i| {
                // Drop any *other* entry that already owns this ssrc.
                if (self.indexOfSsrc(ssrc)) |j| {
                    if (j != i) self.removeAt(j);
                }
                // removeAt above may have shifted our slot; re-locate.
                const slot = self.indexOfStream(stream_id).?;
                self.entries[slot] = new_entry;
                return;
            }

            // No stream_id match — reuse a slot keyed by ssrc if present.
            if (self.indexOfSsrc(ssrc)) |i| {
                self.entries[i] = new_entry;
                return;
            }

            // Genuinely new binding.
            if (self.len == capacity) return Error.Full;
            self.entries[self.len] = new_entry;
            self.len += 1;
        }

        pub fn ssrcForStream(self: *const Self, stream_id: u32) ?u32 {
            const i = self.indexOfStream(stream_id) orelse return null;
            return self.entries[i].ssrc;
        }

        pub fn streamForSsrc(self: *const Self, ssrc: u32) ?u32 {
            const i = self.indexOfSsrc(ssrc) orelse return null;
            return self.entries[i].stream_id;
        }

        pub fn participantForSsrc(self: *const Self, ssrc: u32) ?u64 {
            const i = self.indexOfSsrc(ssrc) orelse return null;
            return self.entries[i].participant;
        }

        pub fn participantForStream(self: *const Self, stream_id: u32) ?u64 {
            const i = self.indexOfStream(stream_id) orelse return null;
            return self.entries[i].participant;
        }

        /// Remove the binding owning `stream_id`. Returns true if one existed.
        pub fn unbindStream(self: *Self, stream_id: u32) bool {
            const i = self.indexOfStream(stream_id) orelse return false;
            self.removeAt(i);
            return true;
        }

        /// Remove the binding owning `ssrc`. Returns true if one existed.
        pub fn unbindSsrc(self: *Self, ssrc: u32) bool {
            const i = self.indexOfSsrc(ssrc) orelse return false;
            self.removeAt(i);
            return true;
        }

        pub fn count(self: *const Self) usize {
            return self.len;
        }

        fn indexOfStream(self: *const Self, stream_id: u32) ?usize {
            var i: usize = 0;
            while (i < self.len) : (i += 1) {
                if (self.entries[i].stream_id == stream_id) return i;
            }
            return null;
        }

        fn indexOfSsrc(self: *const Self, ssrc: u32) ?usize {
            var i: usize = 0;
            while (i < self.len) : (i += 1) {
                if (self.entries[i].ssrc == ssrc) return i;
            }
            return null;
        }

        /// Swap-remove: move the last live entry into the freed slot.
        fn removeAt(self: *Self, index: usize) void {
            std.debug.assert(index < self.len);
            const last = self.len - 1;
            if (index != last) {
                self.entries[index] = self.entries[last];
            }
            self.len = last;
        }
    };
}

/// Default sizing for the Kakehashi bridge.
pub const Map = SsrcMap(256);

test "bind and resolve both directions plus participant lookups" {
    var map = SsrcMap(8){};

    try map.bind(10, 1000, 7);
    try map.bind(11, 1001, 7);
    try map.bind(12, 2002, 9);

    try std.testing.expectEqual(@as(usize, 3), map.count());

    try std.testing.expectEqual(@as(?u32, 1000), map.ssrcForStream(10));
    try std.testing.expectEqual(@as(?u32, 2002), map.ssrcForStream(12));

    try std.testing.expectEqual(@as(?u32, 11), map.streamForSsrc(1001));
    try std.testing.expectEqual(@as(?u32, 12), map.streamForSsrc(2002));

    try std.testing.expectEqual(@as(?u64, 7), map.participantForSsrc(1000));
    try std.testing.expectEqual(@as(?u64, 9), map.participantForSsrc(2002));
    try std.testing.expectEqual(@as(?u64, 7), map.participantForStream(11));
    try std.testing.expectEqual(@as(?u64, 9), map.participantForStream(12));
}

test "rebind existing stream_id updates ssrc and participant" {
    var map = SsrcMap(8){};

    try map.bind(10, 1000, 7);
    try std.testing.expectEqual(@as(usize, 1), map.count());

    // Rebind same stream_id to a new ssrc/participant.
    try map.bind(10, 5000, 42);
    try std.testing.expectEqual(@as(usize, 1), map.count());

    try std.testing.expectEqual(@as(?u32, 5000), map.ssrcForStream(10));
    try std.testing.expectEqual(@as(?u64, 42), map.participantForStream(10));

    // The stale ssrc must no longer resolve.
    try std.testing.expectEqual(@as(?u32, null), map.streamForSsrc(1000));
    try std.testing.expectEqual(@as(?u32, 10), map.streamForSsrc(5000));
}

test "rebind reusing an existing ssrc replaces in place" {
    var map = SsrcMap(8){};

    try map.bind(10, 1000, 7);
    // Same ssrc, different stream_id -> reuse the ssrc slot.
    try map.bind(20, 1000, 8);
    try std.testing.expectEqual(@as(usize, 1), map.count());

    try std.testing.expectEqual(@as(?u32, 20), map.streamForSsrc(1000));
    try std.testing.expectEqual(@as(?u32, null), map.ssrcForStream(10));
    try std.testing.expectEqual(@as(?u32, 1000), map.ssrcForStream(20));
    try std.testing.expectEqual(@as(?u64, 8), map.participantForSsrc(1000));
}

test "rebind that collides on both keys collapses to one entry" {
    var map = SsrcMap(8){};

    try map.bind(10, 1000, 1);
    try map.bind(20, 2000, 2);
    try std.testing.expectEqual(@as(usize, 2), map.count());

    // stream_id 10 (existing) now claims ssrc 2000 (owned by entry 20).
    try map.bind(10, 2000, 3);
    try std.testing.expectEqual(@as(usize, 1), map.count());

    try std.testing.expectEqual(@as(?u32, 2000), map.ssrcForStream(10));
    try std.testing.expectEqual(@as(?u32, 10), map.streamForSsrc(2000));
    try std.testing.expectEqual(@as(?u64, 3), map.participantForStream(10));
    // The old stream_id 20 binding is gone.
    try std.testing.expectEqual(@as(?u32, null), map.ssrcForStream(20));
}

test "Full when exceeding capacity" {
    var map = SsrcMap(2){};

    try map.bind(1, 100, 1);
    try map.bind(2, 200, 2);
    try std.testing.expectEqual(@as(usize, 2), map.count());

    try std.testing.expectError(Error.Full, map.bind(3, 300, 3));
    try std.testing.expectEqual(@as(usize, 2), map.count());

    // Rebinding an existing key at capacity must still succeed.
    try map.bind(1, 101, 9);
    try std.testing.expectEqual(@as(?u32, 101), map.ssrcForStream(1));
}

test "unbind removes both directions" {
    var map = SsrcMap(8){};

    try map.bind(10, 1000, 7);
    try map.bind(11, 1001, 7);

    try std.testing.expect(map.unbindStream(10));
    try std.testing.expectEqual(@as(usize, 1), map.count());
    try std.testing.expectEqual(@as(?u32, null), map.ssrcForStream(10));
    try std.testing.expectEqual(@as(?u32, null), map.streamForSsrc(1000));

    try std.testing.expect(map.unbindSsrc(1001));
    try std.testing.expectEqual(@as(usize, 0), map.count());
    try std.testing.expectEqual(@as(?u32, null), map.streamForSsrc(1001));
    try std.testing.expectEqual(@as(?u32, null), map.ssrcForStream(11));
}

test "unbind unknown ids returns false" {
    var map = SsrcMap(8){};
    try map.bind(10, 1000, 7);

    try std.testing.expect(!map.unbindStream(999));
    try std.testing.expect(!map.unbindSsrc(999));
    try std.testing.expectEqual(@as(usize, 1), map.count());
}

test "lookups for unknown ids return null" {
    var map = SsrcMap(8){};
    try map.bind(10, 1000, 7);

    try std.testing.expectEqual(@as(?u32, null), map.ssrcForStream(99));
    try std.testing.expectEqual(@as(?u32, null), map.streamForSsrc(99));
    try std.testing.expectEqual(@as(?u64, null), map.participantForSsrc(99));
    try std.testing.expectEqual(@as(?u64, null), map.participantForStream(99));
}

test "default Map alias is usable" {
    var map = Map{};
    try map.bind(1, 2, 3);
    try std.testing.expectEqual(@as(?u32, 2), map.ssrcForStream(1));
    try std.testing.expectEqual(@as(usize, 1), map.count());
}

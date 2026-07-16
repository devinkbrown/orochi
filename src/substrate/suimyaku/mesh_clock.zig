// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The cross-mesh Hybrid Logical Clock (HLC).
//!
//! Every mesh CRDT value — a nick claim, a channel PROP, a channel-mode state,
//! a topic — is tie-broken across replicas by an `hlc: u64` under Last-Writer-
//! Wins. For that ordering to be correct the physical component MUST be a
//! WALL-CLOCK reading (Unix epoch ms): both nodes track real time, so their
//! stamps are directly comparable and the genuinely-more-recent write wins.
//!
//! The historical bug this type fixes: the hlc was packed from a MONOTONIC
//! clock (per-process time-since-boot). Two hosts with different uptimes then
//! produced non-comparable stamps, so `candidateWins` / `applyMembership` LWW
//! resolved contests by whichever node had the larger uptime, not by recency —
//! e.g. a live client reconnecting after a USR2 could LOSE its own nick to the
//! stale ghost a longer-uptime peer still held. (Same clock-source class of bug
//! already fixed for oper-grant expiry and the zombie-member GC.)
//!
//! Layout: `(physical_ms << 16) | (seq & 0xffff)`. The low 16 bits are a
//! per-node sequence that orders writes inside a single millisecond and, on a
//! same-node re-assert, keeps the stamp strictly increasing. The physical
//! component is monotonic-guarded here — it never regresses even if the wall
//! clock steps backward (an NTP correction), so a node's own later write always
//! out-ranks its earlier one. Cross-node ties on the physical+seq value fall
//! through to the node-id tiebreak in `nick_collision` / `state`.
//!
//! NOTE ON LAYOUT: this deliberately matches the packing already on the S2S
//! wire (`(physical << 16) | seq`, physical in the HIGH bits) so a rolling
//! upgrade stays compatible — a deployed peer decodes nothing here, it only
//! compares the opaque u64. This is intentionally NOT `clock.Hlc`, which packs
//! the opposite way (`wall_ms` low, `logical` high) for the UID-keyed claim
//! CRDT; adopting it would flip the on-wire representation. Only the clock
//! SOURCE changes here (monotonic → wall), never the layout.
const std = @import("std");

/// Bits reserved for the per-node sequence in the low end of the packed hlc.
pub const seq_bits: u6 = 16;
const seq_mask: u64 = (1 << seq_bits) - 1;

/// Maximum wall-clock lead accepted when an authenticated peer's HLC is folded
/// into the local causal high-water mark. Keep this aligned with the default
/// SESSION_REPLICA lifetime policy: a peer may be slightly ahead because of
/// normal clock skew, but it may not pin this node's clock arbitrarily far into
/// the future.
pub const default_max_future_skew_ms: u64 = 5 * 60 * 1000;

pub const ObserveError = error{
    /// The observed physical component is beyond `now_ms + max_future_skew_ms`.
    FutureSkew,
    /// No strictly greater packed HLC exists, so accepting the observation would
    /// make the next locally-authored event repeat the remote stamp.
    ClockExhausted,
};

/// Per-node HLC generator. One instance lives on the server; `stamp` is called
/// for every outbound mesh event. Not thread-safe on its own — callers stamp
/// under the same serialization (world write lock) that guards the mesh state.
pub const MeshClock = struct {
    /// Highest physical (wall-clock ms) component ever emitted. The guard that
    /// makes the clock never run backward across a wall-clock step-back.
    last_physical: u64 = 0,
    /// Highest complete packed stamp emitted. `seq` is supplied by callers and
    /// eventually wraps its 16-bit wire lane; retaining the full high-water mark
    /// prevents that wrap (or a process-local counter reset after adoption) from
    /// making a later event compare older than an earlier one.
    last_stamp: u64 = 0,

    /// Produce the next hlc for an outbound mesh write. `wall_ms` is the current
    /// wall-clock reading (`Reactor.wallMillis`, or `platform.realtimeMillis`
    /// off-reactor); `seq` is the node's rolling message sequence (only its low
    /// `seq_bits` are used). The returned value is >= every value this clock has
    /// returned before whenever `seq` advanced, so a node's writes stay ordered.
    pub fn stamp(self: *MeshClock, wall_ms: u64, seq: u64) u64 {
        // Never regress: hold at the high-water mark if the wall clock jumped
        // back. Advancing normally, `physical` simply tracks `wall_ms`.
        if (wall_ms > self.last_physical) self.last_physical = wall_ms;
        var candidate = (self.last_physical << seq_bits) | (seq & seq_mask);
        if (candidate <= self.last_stamp) {
            candidate = self.last_stamp +| 1;
            self.last_physical = physicalOf(candidate);
        }
        self.last_stamp = candidate;
        return candidate;
    }

    /// Causally observe one authenticated packed HLC without allowing a remote
    /// peer to poison this process's restart-persistent high-water mark.
    ///
    /// On success, the next call to `stamp` is guaranteed to return a value
    /// strictly greater than `remote_stamp`. `maxInt(u64)` is rejected explicitly
    /// because there is no representable successor. The future bound uses
    /// saturating addition so an extreme caller-supplied `now_ms` cannot wrap the
    /// admission window back toward zero.
    pub fn observeChecked(
        self: *MeshClock,
        remote_stamp: u64,
        now_ms: u64,
        max_future_skew_ms: u64,
    ) ObserveError!void {
        if (self.last_stamp == std.math.maxInt(u64) or remote_stamp == std.math.maxInt(u64))
            return error.ClockExhausted;

        const latest_physical = std.math.add(u64, now_ms, max_future_skew_ms) catch std.math.maxInt(u64);
        if (physicalOf(remote_stamp) > latest_physical) return error.FutureSkew;

        if (remote_stamp > self.last_stamp) self.last_stamp = remote_stamp;
        self.last_physical = @max(self.last_physical, physicalOf(self.last_stamp));
    }

    /// The physical (wall-clock ms) component of a packed hlc — for diagnostics
    /// (MESH GRANTS-style introspection, tests), never for LWW (compare the full
    /// u64 so the seq tiebreak is honored).
    pub fn physicalOf(hlc: u64) u64 {
        return hlc >> seq_bits;
    }
};

const testing = std.testing;

test "stamp packs physical high, seq low" {
    var c: MeshClock = .{};
    const h = c.stamp(1_700_000_000_000, 7);
    try testing.expectEqual(@as(u64, 1_700_000_000_000), MeshClock.physicalOf(h));
    try testing.expectEqual(@as(u64, 7), h & seq_mask);
}

test "stamp never regresses across a wall-clock step-back" {
    var c: MeshClock = .{};
    const a = c.stamp(1_700_000_000_000, 1);
    // Wall clock steps BACK (NTP correction) — the hlc must not go backward.
    const b = c.stamp(1_699_999_999_000, 2);
    try testing.expect(b > a);
    // Physical is held at the high-water mark, not the regressed reading.
    try testing.expectEqual(MeshClock.physicalOf(a), MeshClock.physicalOf(b));
}

test "later wall time always out-ranks earlier" {
    var c: MeshClock = .{};
    const a = c.stamp(1_700_000_000_000, 500);
    const b = c.stamp(1_700_000_000_050, 1); // 50ms later, tiny seq
    try testing.expect(b > a); // recency wins even though seq is far smaller
}

// The core cross-node property: recency (wall clock), NOT uptime (monotonic),
// decides a contest. Two nodes with very different uptimes but synced wall
// clocks each stamp a claim; the later wall-clock claim must produce the higher
// hlc regardless of which node has been up longer.
test "recency decides across nodes, not uptime" {
    // Node A: huge uptime — a monotonic clock would read ~30 days of ms.
    var node_a: MeshClock = .{};
    // Node B: just booted — a monotonic clock would read seconds.
    var node_b: MeshClock = .{};

    const wall_now: u64 = 1_700_000_000_000;
    // A made its claim a full second in the PAST.
    const a_claim = node_a.stamp(wall_now - 1000, 4242);
    // B makes its claim NOW (the genuinely more recent write).
    const b_claim = node_b.stamp(wall_now, 1);

    // Recency wins: B's newer claim out-ranks A's older one, even though under
    // the old monotonic scheme A's multi-day uptime would have dominated.
    try testing.expect(b_claim > a_claim);
}

test "same millisecond orders by seq" {
    var c: MeshClock = .{};
    const a = c.stamp(1_700_000_000_000, 10);
    const b = c.stamp(1_700_000_000_000, 11);
    try testing.expect(b > a);
    try testing.expectEqual(MeshClock.physicalOf(a), MeshClock.physicalOf(b));
}

test "more than one full sequence lane in one millisecond never repeats or regresses" {
    var c: MeshClock = .{};
    var previous: u64 = 0;
    var seq: u64 = 0;
    while (seq < (@as(u64, 1) << seq_bits) + 1024) : (seq += 1) {
        const current = c.stamp(1_700_000_000_000, seq);
        try testing.expect(current > previous);
        previous = current;
    }
    try testing.expect(MeshClock.physicalOf(previous) > 1_700_000_000_000);
}

test "counter reset at the physical high-water mark still advances" {
    var c: MeshClock = .{};
    const before = c.stamp(1_700_000_000_000, 40_000);
    const after = c.stamp(1_700_000_000_000, 1);
    try testing.expect(after > before);
}

test "checked observation makes the next local stamp causally newer" {
    const now_ms: u64 = 1_700_000_000_000;
    const remote_physical = now_ms + default_max_future_skew_ms;
    const remote = (remote_physical << seq_bits) | seq_mask;
    var clock: MeshClock = .{};

    try clock.observeChecked(remote, now_ms, default_max_future_skew_ms);
    const local = clock.stamp(now_ms, 1);
    try testing.expect(local > remote);
    try testing.expect(MeshClock.physicalOf(local) > remote_physical);
}

test "checked observation rejects future and maximum poison without mutation" {
    const now_ms: u64 = 1_700_000_000_000;
    var clock: MeshClock = .{};
    const baseline = clock.stamp(now_ms, 7);

    const too_future = ((now_ms + default_max_future_skew_ms + 1) << seq_bits) | 1;
    try testing.expectError(
        error.FutureSkew,
        clock.observeChecked(too_future, now_ms, default_max_future_skew_ms),
    );
    try testing.expectEqual(baseline, clock.last_stamp);

    try testing.expectError(
        error.ClockExhausted,
        clock.observeChecked(std.math.maxInt(u64), std.math.maxInt(u64), std.math.maxInt(u64)),
    );
    try testing.expectEqual(baseline, clock.last_stamp);
}

test "checked observation reports an already exhausted local clock" {
    var clock = MeshClock{
        .last_physical = MeshClock.physicalOf(std.math.maxInt(u64)),
        .last_stamp = std.math.maxInt(u64),
    };
    try testing.expectError(error.ClockExhausted, clock.observeChecked(1, 1, 1));
}

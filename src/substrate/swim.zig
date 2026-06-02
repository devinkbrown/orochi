//! Witnessed SWIM membership state machine (LADON mesh, planning/04).
//!
//! Pure, deterministic failure detection. There is NO real networking and NO
//! real clock here: the protocol period is driven by `tick(now_ms, rng_seed)`,
//! and the probe target / witness selection is derived from the seed, so the
//! whole thing replays identically under Deterministic Ocean (planning/00).
//!
//! This models the *decisions* of SWIM (Das/Gupta/Motivala) -- which probes to
//! emit, when a node ages out of suspicion -- as returned values. The caller
//! (the LADON peer actor, M-later) is responsible for turning a `Probe` into
//! real PING / PING_REQ frames and feeding observed events back in via the
//! `applyAlive` / `applySuspect` / `applyDead` / `applyLeft` methods.
//!
//! Two SWIM correctness mechanisms are implemented:
//!
//!   1. **Incarnation numbers.** Suspicion and death carry the incarnation the
//!      reporter believes the target is at. A target can *refute* a suspicion
//!      by bumping its own incarnation; a higher incarnation always wins, so a
//!      live node is never permanently buried by a stale rumor.
//!
//!   2. **Witnessed extension** (planning/04, "Witnessed SWIM"). Suspicion and
//!      dead reports carry the witness that observed them. A node only
//!      transitions SUSPECT -> DEAD once a configurable *witness quorum* of
//!      distinct witnesses agree (or the suspicion timer expires for a target
//!      that already met quorum). A single flaky / Byzantine node can no longer
//!      force a healthy peer to DEAD on its own.
const std = @import("std");

/// Local belief about a member's liveness.
pub const MemberState = enum {
    /// Reachable and recently confirmed.
    alive,
    /// Possibly failed; awaiting refutation, quorum, or timeout.
    suspect,
    /// Confirmed failed (quorum + timeout). Tombstoned, gossiped as dead.
    dead,
    /// Gracefully departed (explicit LEAVE). Distinct from dead so a clean
    /// shutdown is not mistaken for a fault.
    left,
};

/// Tuning for the protocol. All durations are milliseconds.
pub const Config = struct {
    /// Length of one protocol period. `tick` is expected once per period.
    protocol_period_ms: i64 = 1_000,
    /// How long a node may sit in SUSPECT before it is eligible for DEAD.
    suspicion_timeout_ms: i64 = 3_000,
    /// Number of indirect-probe witnesses (the `k` in SWIM PING_REQ fanout).
    indirect_probe_count: u8 = 3,
    /// Distinct witnesses required before SUSPECT -> DEAD. A value of 1 is
    /// classic SWIM; >1 is the Witnessed extension. Must be >= 1.
    witness_quorum: u8 = 2,

    /// Returns a config with invalid fields snapped into a sane range, so a
    /// misconfiguration degrades gracefully instead of panicking on probe.
    pub fn sanitized(self: Config) Config {
        var c = self;
        if (c.protocol_period_ms < 1) c.protocol_period_ms = 1;
        if (c.suspicion_timeout_ms < 0) c.suspicion_timeout_ms = 0;
        if (c.witness_quorum < 1) c.witness_quorum = 1;
        return c;
    }
};

/// Stable identifier for a mesh node (planning/04: low 64 bits of NodeId).
pub const NodeId = u64;

/// Monotonic per-node version. A node bumps its own incarnation to refute a
/// suspicion about itself; higher always wins ties.
pub const Incarnation = u64;

/// Maximum distinct witnesses tracked per suspected node. Quorum cannot exceed
/// this; extra witnesses past the cap are ignored (quorum is already met by
/// then, so the surplus carries no decision value).
pub const max_tracked_witnesses = 16;

/// One member's slot in the table.
pub const Member = struct {
    id: NodeId,
    state: MemberState,
    incarnation: Incarnation,
    /// Wall-ish time (caller's `now_ms`) the node first entered SUSPECT in the
    /// current suspicion episode. Only meaningful while `state == .suspect`.
    suspect_since_ms: i64 = 0,
    /// Distinct witnesses for the current suspicion episode. Reset whenever the
    /// node leaves SUSPECT (refuted, dead, or left).
    witnesses: WitnessSet = .{},

    /// Number of distinct witnesses currently backing this suspicion.
    pub fn witnessCount(self: *const Member) u8 {
        return self.witnesses.len;
    }
};

/// Fixed-capacity set of witness NodeIds. No allocation; dedupes on insert.
const WitnessSet = struct {
    ids: [max_tracked_witnesses]NodeId = undefined,
    len: u8 = 0,

    fn clear(self: *WitnessSet) void {
        self.len = 0;
    }

    fn contains(self: *const WitnessSet, id: NodeId) bool {
        var i: u8 = 0;
        while (i < self.len) : (i += 1) {
            if (self.ids[i] == id) return true;
        }
        return false;
    }

    /// Adds `id` if absent and there is room. Returns true if the set changed.
    fn add(self: *WitnessSet, id: NodeId) bool {
        if (self.contains(id)) return false;
        if (self.len >= max_tracked_witnesses) return false;
        self.ids[self.len] = id;
        self.len += 1;
        return true;
    }
};

/// What `tick` decided the caller should do this protocol period. The caller
/// translates these into real LADON frames; nothing here performs I/O.
pub const Probe = struct {
    /// Whether a direct PING should be sent at all (false when the mesh has no
    /// other reachable members to probe).
    active: bool = false,
    /// Direct PING target for this period.
    target: NodeId = 0,
    /// Witnesses to fan PING_REQ out to if the direct PING is not answered.
    indirect: [max_tracked_witnesses]NodeId = undefined,
    indirect_len: u8 = 0,

    pub fn indirectSlice(self: *const Probe) []const NodeId {
        return self.indirect[0..self.indirect_len];
    }
};

/// A member that `tick` aged out of SUSPECT into DEAD this period. Returned so
/// the caller can gossip the resulting dead delta.
pub const Reaped = struct {
    id: NodeId,
    incarnation: Incarnation,
};

/// Witnessed-SWIM membership table.
pub const Membership = struct {
    allocator: std.mem.Allocator,
    cfg: Config,
    /// This node's own id and incarnation, so it can refute suspicion of self.
    self_id: NodeId,
    self_incarnation: Incarnation = 0,
    members: std.AutoHashMap(NodeId, Member),

    pub fn init(allocator: std.mem.Allocator, self_id: NodeId, cfg: Config) Membership {
        return .{
            .allocator = allocator,
            .cfg = cfg.sanitized(),
            .self_id = self_id,
            .members = std.AutoHashMap(NodeId, Member).init(allocator),
        };
    }

    pub fn deinit(self: *Membership) void {
        self.members.deinit();
    }

    /// Current local belief about `id`, or null if unknown.
    pub fn get(self: *const Membership, id: NodeId) ?Member {
        return self.members.get(id);
    }

    /// Number of members tracked (excludes self).
    pub fn count(self: *const Membership) u32 {
        return self.members.count();
    }

    // -- Event application ---------------------------------------------------
    //
    // Each `apply*` returns whether local state changed, so the caller can
    // decide whether a delta is worth gossiping. Self-reports are special-cased
    // to drive incarnation refutation.

    /// Learned that `node` is alive at `incarnation`. Higher incarnation always
    /// wins; an equal incarnation can still rescue a node out of SUSPECT.
    pub fn applyAlive(self: *Membership, node: NodeId, incarnation: Incarnation) !bool {
        if (node == self.self_id) {
            // Someone reports us alive at >= our incarnation: adopt the max so
            // our future refutations stay strictly higher than rumor.
            if (incarnation > self.self_incarnation) {
                self.self_incarnation = incarnation;
                return true;
            }
            return false;
        }

        const gop = try self.members.getOrPut(node);
        if (!gop.found_existing) {
            gop.value_ptr.* = .{
                .id = node,
                .state = .alive,
                .incarnation = incarnation,
            };
            return true;
        }

        const m = gop.value_ptr;
        // A node that gracefully left stays left; a fresh higher incarnation
        // means it rejoined, which we honor.
        if (m.state == .left and incarnation <= m.incarnation) return false;
        if (m.state == .dead and incarnation <= m.incarnation) return false;

        if (incarnation > m.incarnation) {
            m.incarnation = incarnation;
            return self.toAlive(m);
        }
        if (incarnation == m.incarnation and m.state == .suspect) {
            // Same incarnation but a fresh ALIVE observation clears suspicion.
            return self.toAlive(m);
        }
        return false;
    }

    /// Learned that `witness` suspects `node` at `incarnation`.
    pub fn applySuspect(
        self: *Membership,
        node: NodeId,
        incarnation: Incarnation,
        witness: NodeId,
        now_ms: i64,
    ) !bool {
        if (node == self.self_id) {
            // Suspicion of ourselves: refute by bumping our incarnation above
            // the rumor. This is the SWIM self-refutation path.
            if (incarnation >= self.self_incarnation) {
                self.self_incarnation = incarnation + 1;
                return true;
            }
            return false;
        }

        const gop = try self.members.getOrPut(node);
        if (!gop.found_existing) {
            gop.value_ptr.* = .{
                .id = node,
                .state = .suspect,
                .incarnation = incarnation,
                .suspect_since_ms = now_ms,
            };
            _ = gop.value_ptr.witnesses.add(witness);
            return true;
        }

        const m = gop.value_ptr;
        // Stale suspicion (older incarnation) cannot resurrect or override.
        if (incarnation < m.incarnation) return false;
        if (m.state == .left or m.state == .dead) return false;

        if (incarnation > m.incarnation) {
            // Newer episode: reset suspicion bookkeeping.
            m.incarnation = incarnation;
            m.state = .suspect;
            m.suspect_since_ms = now_ms;
            m.witnesses.clear();
            _ = m.witnesses.add(witness);
            return true;
        }

        // Same incarnation.
        if (m.state == .alive) {
            m.state = .suspect;
            m.suspect_since_ms = now_ms;
            m.witnesses.clear();
            _ = m.witnesses.add(witness);
            return true;
        }
        // Already suspect at this incarnation: record a (possibly new) witness.
        return m.witnesses.add(witness);
    }

    /// Learned a DEAD report for `node` at `incarnation` from `witness`.
    /// Under the Witnessed extension this does NOT immediately bury the node:
    /// it counts as a witness toward quorum. Only at/above quorum does the node
    /// actually transition to DEAD.
    pub fn applyDead(
        self: *Membership,
        node: NodeId,
        incarnation: Incarnation,
        witness: NodeId,
        now_ms: i64,
    ) !bool {
        if (node == self.self_id) {
            // We are obviously not dead. Refute hard.
            if (incarnation >= self.self_incarnation) {
                self.self_incarnation = incarnation + 1;
                return true;
            }
            return false;
        }

        const gop = try self.members.getOrPut(node);
        if (!gop.found_existing) {
            gop.value_ptr.* = .{
                .id = node,
                .state = .suspect,
                .incarnation = incarnation,
                .suspect_since_ms = now_ms,
            };
            _ = gop.value_ptr.witnesses.add(witness);
            return self.maybeBury(gop.value_ptr, now_ms);
        }

        const m = gop.value_ptr;
        if (incarnation < m.incarnation) return false;
        if (m.state == .left or m.state == .dead) return false;

        if (incarnation > m.incarnation) {
            m.incarnation = incarnation;
            m.state = .suspect;
            m.suspect_since_ms = now_ms;
            m.witnesses.clear();
            _ = m.witnesses.add(witness);
            return self.maybeBury(m, now_ms) or true;
        }

        // Same incarnation: ensure suspect and add the witness.
        var changed = false;
        if (m.state == .alive) {
            m.state = .suspect;
            m.suspect_since_ms = now_ms;
            m.witnesses.clear();
            changed = true;
        }
        if (m.witnesses.add(witness)) changed = true;
        if (self.maybeBury(m, now_ms)) changed = true;
        return changed;
    }

    /// Learned that `node` gracefully left at `incarnation`. A leave tombstone
    /// always wins over alive/suspect at the same or older incarnation.
    pub fn applyLeft(self: *Membership, node: NodeId, incarnation: Incarnation) !bool {
        if (node == self.self_id) return false;

        const gop = try self.members.getOrPut(node);
        if (!gop.found_existing) {
            gop.value_ptr.* = .{
                .id = node,
                .state = .left,
                .incarnation = incarnation,
            };
            return true;
        }

        const m = gop.value_ptr;
        if (m.state == .left) {
            if (incarnation > m.incarnation) {
                m.incarnation = incarnation;
                return true;
            }
            return false;
        }
        if (incarnation < m.incarnation) return false;
        m.state = .left;
        m.incarnation = incarnation;
        m.witnesses.clear();
        return true;
    }

    // -- Protocol period -----------------------------------------------------

    /// Drive one protocol period.
    ///
    /// Two responsibilities, both pure:
    ///   1. Age every SUSPECT member: any that has met witness quorum AND been
    ///      suspect longer than `suspicion_timeout_ms` is buried (-> DEAD).
    ///   2. Pick a probe target + indirect witnesses deterministically from
    ///      `rng_seed` (mixed with `now_ms` so successive periods rotate).
    ///
    /// `reaped`, if non-null, is filled with members that died this period
    /// (caller may pass null to ignore). Returns the `Probe` decision.
    pub fn tick(
        self: *Membership,
        now_ms: i64,
        rng_seed: u64,
        reaped: ?*std.ArrayList(Reaped),
    ) !Probe {
        try self.reapSuspects(now_ms, reaped);
        return self.selectProbe(now_ms, rng_seed);
    }

    /// Age suspects to dead where quorum + timeout are both satisfied.
    fn reapSuspects(
        self: *Membership,
        now_ms: i64,
        reaped: ?*std.ArrayList(Reaped),
    ) !void {
        var it = self.members.iterator();
        while (it.next()) |entry| {
            const m = entry.value_ptr;
            if (m.state != .suspect) continue;
            if (!self.quorumMet(m)) continue;
            if (now_ms - m.suspect_since_ms < self.cfg.suspicion_timeout_ms) continue;
            m.state = .dead;
            m.witnesses.clear();
            if (reaped) |list| {
                try list.append(self.allocator, .{ .id = m.id, .incarnation = m.incarnation });
            }
        }
    }

    /// Deterministic probe selection. Targets cycle through alive+suspect
    /// members (dead/left are never probed). Indirect witnesses are distinct
    /// alive members other than the target.
    fn selectProbe(self: *Membership, now_ms: i64, rng_seed: u64) Probe {
        // Mix the period into the seed so consecutive ticks rotate targets, yet
        // a given (seed, now_ms) pair is fully reproducible.
        const mixed = rng_seed ^ (@as(u64, @bitCast(now_ms)) *% 0x9E3779B97F4A7C15);
        var prng = std.Random.Pcg.init(mixed);
        const rnd = prng.random();

        var probe = Probe{};

        const target = self.pickProbeTarget(rnd) orelse return probe;
        probe.active = true;
        probe.target = target;

        // Gather up to `indirect_probe_count` distinct alive witnesses != target.
        const want: u8 = self.cfg.indirect_probe_count;
        const cap: u8 = if (want > max_tracked_witnesses) max_tracked_witnesses else want;
        var it = self.members.iterator();
        while (it.next()) |entry| {
            if (probe.indirect_len >= cap) break;
            const m = entry.value_ptr;
            if (m.id == target) continue;
            if (m.state != .alive) continue;
            probe.indirect[probe.indirect_len] = m.id;
            probe.indirect_len += 1;
        }
        return probe;
    }

    /// Pick one probeable member uniformly. Returns null if none exist.
    fn pickProbeTarget(self: *Membership, rnd: std.Random) ?NodeId {
        const n = self.probeableCount();
        if (n == 0) return null;
        const choice = rnd.uintLessThan(u32, n);
        var idx: u32 = 0;
        var it = self.members.iterator();
        while (it.next()) |entry| {
            const m = entry.value_ptr;
            if (!isProbeable(m.state)) continue;
            if (idx == choice) return m.id;
            idx += 1;
        }
        return null;
    }

    fn probeableCount(self: *const Membership) u32 {
        var n: u32 = 0;
        var it = self.members.iterator();
        while (it.next()) |entry| {
            if (isProbeable(entry.value_ptr.state)) n += 1;
        }
        return n;
    }

    // -- Internal helpers ----------------------------------------------------

    fn isProbeable(state: MemberState) bool {
        return state == .alive or state == .suspect;
    }

    fn quorumMet(self: *const Membership, m: *const Member) bool {
        return m.witnesses.len >= self.cfg.witness_quorum;
    }

    /// Transition a member to ALIVE, clearing suspicion bookkeeping. Returns
    /// whether the state actually changed.
    fn toAlive(self: *Membership, m: *Member) bool {
        _ = self;
        const changed = m.state != .alive;
        m.state = .alive;
        m.suspect_since_ms = 0;
        m.witnesses.clear();
        return changed;
    }

    /// If quorum is already met at apply time AND the suspicion timeout is zero
    /// (immediate-bury config), transition straight to DEAD. With a non-zero
    /// timeout the death is deferred to `tick`/`reapSuspects`. Returns whether
    /// state changed.
    fn maybeBury(self: *Membership, m: *Member, now_ms: i64) bool {
        _ = now_ms;
        if (m.state != .suspect) return false;
        if (!self.quorumMet(m)) return false;
        if (self.cfg.suspicion_timeout_ms != 0) return false;
        m.state = .dead;
        m.witnesses.clear();
        return true;
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;
const self_node: NodeId = 1;

fn newTable(cfg: Config) Membership {
    return Membership.init(testing.allocator, self_node, cfg);
}

test "alive -> suspect -> dead progression under timeout with quorum" {
    var t = newTable(.{
        .suspicion_timeout_ms = 3_000,
        .witness_quorum = 2,
    });
    defer t.deinit();

    const target: NodeId = 42;
    try testing.expect(try t.applyAlive(target, 1));
    try testing.expectEqual(MemberState.alive, t.get(target).?.state);

    // Two distinct witnesses suspect it -> quorum met, but still SUSPECT until
    // the timeout elapses.
    try testing.expect(try t.applySuspect(target, 1, 7, 0));
    try testing.expect(try t.applySuspect(target, 1, 8, 0));
    try testing.expectEqual(MemberState.suspect, t.get(target).?.state);
    try testing.expectEqual(@as(u8, 2), t.get(target).?.witnessCount());

    // Tick before timeout: no death.
    _ = try t.tick(1_000, 0xABCD, null);
    try testing.expectEqual(MemberState.suspect, t.get(target).?.state);

    // Tick after timeout: reaped to DEAD.
    var reaped: std.ArrayList(Reaped) = .empty;
    defer reaped.deinit(testing.allocator);
    _ = try t.tick(4_000, 0xABCD, &reaped);
    try testing.expectEqual(MemberState.dead, t.get(target).?.state);
    try testing.expectEqual(@as(usize, 1), reaped.items.len);
    try testing.expectEqual(target, reaped.items[0].id);
}

test "incarnation refutation resets suspect back to alive" {
    var t = newTable(.{ .witness_quorum = 1 });
    defer t.deinit();

    const target: NodeId = 99;
    try testing.expect(try t.applyAlive(target, 5));
    try testing.expect(try t.applySuspect(target, 5, 2, 0));
    try testing.expectEqual(MemberState.suspect, t.get(target).?.state);

    // Stale alive (lower incarnation) does not rescue.
    try testing.expect(!try t.applyAlive(target, 4));
    try testing.expectEqual(MemberState.suspect, t.get(target).?.state);

    // Higher incarnation refutes: back to alive, witnesses cleared.
    try testing.expect(try t.applyAlive(target, 6));
    try testing.expectEqual(MemberState.alive, t.get(target).?.state);
    try testing.expectEqual(@as(Incarnation, 6), t.get(target).?.incarnation);
    try testing.expectEqual(@as(u8, 0), t.get(target).?.witnessCount());
}

test "self-suspicion bumps own incarnation to refute" {
    var t = newTable(.{});
    defer t.deinit();
    t.self_incarnation = 10;

    // Suspicion of self at our incarnation -> we jump strictly above it.
    try testing.expect(try t.applySuspect(self_node, 10, 55, 0));
    try testing.expectEqual(@as(Incarnation, 11), t.self_incarnation);

    // A dead report about self refutes even harder, and self is never tabled.
    try testing.expect(try t.applyDead(self_node, 11, 55, 0));
    try testing.expectEqual(@as(Incarnation, 12), t.self_incarnation);
    try testing.expectEqual(@as(u32, 0), t.count());
}

test "witness quorum gating: below quorum stays suspect; at quorum -> dead" {
    var t = newTable(.{
        .suspicion_timeout_ms = 1_000,
        .witness_quorum = 3,
    });
    defer t.deinit();

    const target: NodeId = 77;
    try testing.expect(try t.applyAlive(target, 1));

    // One witness: below quorum. Even after the timeout, no death.
    try testing.expect(try t.applySuspect(target, 1, 100, 0));
    _ = try t.tick(5_000, 1, null);
    try testing.expectEqual(MemberState.suspect, t.get(target).?.state);

    // Second distinct witness: still below quorum (3).
    try testing.expect(try t.applySuspect(target, 1, 101, 0));
    _ = try t.tick(10_000, 1, null);
    try testing.expectEqual(MemberState.suspect, t.get(target).?.state);

    // Duplicate witness does not advance quorum.
    try testing.expect(!try t.applySuspect(target, 1, 101, 0));
    try testing.expectEqual(@as(u8, 2), t.get(target).?.witnessCount());

    // Third distinct witness: quorum met. Now a post-timeout tick buries it.
    try testing.expect(try t.applySuspect(target, 1, 102, 0));
    _ = try t.tick(15_000, 1, null);
    try testing.expectEqual(MemberState.dead, t.get(target).?.state);
}

test "dead reports count toward quorum without immediate burial" {
    var t = newTable(.{
        .suspicion_timeout_ms = 2_000,
        .witness_quorum = 2,
    });
    defer t.deinit();

    const target: NodeId = 5;
    try testing.expect(try t.applyAlive(target, 1));

    // Two DEAD reports = quorum, but timeout not elapsed -> still suspect.
    try testing.expect(try t.applyDead(target, 1, 200, 0));
    try testing.expectEqual(MemberState.suspect, t.get(target).?.state);
    try testing.expect(try t.applyDead(target, 1, 201, 0));
    try testing.expectEqual(MemberState.suspect, t.get(target).?.state);
    try testing.expectEqual(@as(u8, 2), t.get(target).?.witnessCount());

    // After timeout, tick buries it.
    _ = try t.tick(3_000, 9, null);
    try testing.expectEqual(MemberState.dead, t.get(target).?.state);
}

test "immediate burial when suspicion timeout is zero and quorum met" {
    var t = newTable(.{
        .suspicion_timeout_ms = 0,
        .witness_quorum = 2,
    });
    defer t.deinit();

    const target: NodeId = 3;
    try testing.expect(try t.applyAlive(target, 1));
    try testing.expect(try t.applyDead(target, 1, 10, 0)); // 1st witness, stays suspect
    try testing.expectEqual(MemberState.suspect, t.get(target).?.state);
    try testing.expect(try t.applyDead(target, 1, 11, 0)); // 2nd -> quorum -> dead now
    try testing.expectEqual(MemberState.dead, t.get(target).?.state);
}

test "graceful leave tombstone wins and is distinct from dead" {
    var t = newTable(.{ .witness_quorum = 1 });
    defer t.deinit();

    const target: NodeId = 8;
    try testing.expect(try t.applyAlive(target, 1));
    try testing.expect(try t.applySuspect(target, 1, 20, 0));
    try testing.expect(try t.applyLeft(target, 1));
    try testing.expectEqual(MemberState.left, t.get(target).?.state);

    // A stale suspicion cannot drag a left node back.
    try testing.expect(!try t.applySuspect(target, 1, 21, 0));
    try testing.expectEqual(MemberState.left, t.get(target).?.state);

    // Re-join requires a strictly higher incarnation.
    try testing.expect(!try t.applyAlive(target, 1));
    try testing.expectEqual(MemberState.left, t.get(target).?.state);
    try testing.expect(try t.applyAlive(target, 2));
    try testing.expectEqual(MemberState.alive, t.get(target).?.state);
}

test "deterministic probe target selection for a fixed seed" {
    var t = newTable(.{ .indirect_probe_count = 2 });
    defer t.deinit();

    // Populate a stable membership.
    var i: NodeId = 10;
    while (i < 20) : (i += 1) {
        try testing.expect(try t.applyAlive(i, 1));
    }

    const seed: u64 = 0xDEADBEEFCAFEF00D;
    const now: i64 = 7_000;

    const p1 = try t.tick(now, seed, null);
    const p2 = try t.tick(now, seed, null);
    try testing.expect(p1.active);
    // Same (seed, now) -> identical decision, every time.
    try testing.expectEqual(p1.target, p2.target);
    try testing.expectEqual(p1.indirect_len, p2.indirect_len);
    try testing.expectEqualSlices(NodeId, p1.indirectSlice(), p2.indirectSlice());

    // Indirect witnesses exclude the target and respect the configured count.
    try testing.expect(p1.indirect_len <= 2);
    for (p1.indirectSlice()) |w| {
        try testing.expect(w != p1.target);
    }
}

test "no probe emitted when there are no probeable members" {
    var t = newTable(.{});
    defer t.deinit();

    // Empty mesh.
    const p0 = try t.tick(1_000, 1, null);
    try testing.expect(!p0.active);

    // Only dead/left members -> still nothing to probe.
    try testing.expect(try t.applyLeft(50, 1));
    try testing.expect(try t.applyAlive(51, 1));
    try testing.expect(try t.applyDead(51, 1, 1, 0));
    try testing.expect(try t.applyDead(51, 1, 2, 0)); // quorum default 2
    _ = try t.tick(99_000, 1, null); // bury 51 (default timeout 3000)
    try testing.expectEqual(MemberState.dead, t.get(51).?.state);

    const p1 = try t.tick(100_000, 1, null);
    try testing.expect(!p1.active);
}

test "config sanitization clamps invalid values" {
    const c = (Config{
        .protocol_period_ms = -5,
        .suspicion_timeout_ms = -1,
        .witness_quorum = 0,
    }).sanitized();
    try testing.expectEqual(@as(i64, 1), c.protocol_period_ms);
    try testing.expectEqual(@as(i64, 0), c.suspicion_timeout_ms);
    try testing.expectEqual(@as(u8, 1), c.witness_quorum);
}

test "unknown-node suspect/dead reports create suspect entries" {
    var t = newTable(.{ .witness_quorum = 2, .suspicion_timeout_ms = 1_000 });
    defer t.deinit();

    // First contact is a suspicion: node appears as suspect.
    try testing.expect(try t.applySuspect(300, 4, 1, 0));
    try testing.expectEqual(MemberState.suspect, t.get(300).?.state);
    try testing.expectEqual(@as(Incarnation, 4), t.get(300).?.incarnation);
}

test "no memory leaks across full lifecycle" {
    // Exercises getOrPut growth, the reaped ArrayList, and deinit. Run under
    // std.testing.allocator so any leak fails the test.
    var t = newTable(.{ .witness_quorum = 1, .suspicion_timeout_ms = 500 });
    defer t.deinit();

    var reaped: std.ArrayList(Reaped) = .empty;
    defer reaped.deinit(testing.allocator);

    var id: NodeId = 1000;
    while (id < 1050) : (id += 1) {
        try testing.expect(try t.applyAlive(id, 1));
        try testing.expect(try t.applySuspect(id, 1, id + 1, 0));
    }
    _ = try t.tick(10_000, 0x1234, &reaped);
    try testing.expectEqual(@as(usize, 50), reaped.items.len);

    var seed: u64 = 0;
    while (seed < 25) : (seed += 1) {
        _ = try t.tick(@as(i64, @intCast(seed)) * 1_000, seed, null);
    }
}

test {
    std.testing.refAllDecls(@This());
}

//! Datagram Packetization Layer Path MTU Discovery (DPLPMTUD, RFC 8899).
//!
//! This module is transport-agnostic: it never opens sockets and never reads a
//! clock. Callers ask for the next probe size, transmit a datagram of that size,
//! then feed the result back through `onProbeAcked`, `onProbeLost`, or
//! `onPtbReceived`.

const std = @import("std");
const toml = @import("../proto/toml.zig");

/// DPLPMTUD search state.
pub const State = enum {
    /// Operating at the base MTU. More upward probes may still be available.
    Base,
    /// Searching for a larger supported packet size.
    Searching,
    /// No larger packet size inside the configured range remains untested.
    SearchComplete,
    /// The path appears unable to support the configured base MTU.
    Error,
};

/// Configuration for the packetization-layer PMTUD controller.
pub const Config = struct {
    /// Conservative floor. For IPv6/QUIC-like transports this is commonly 1200.
    base_mtu: usize = 1200,
    /// Upper bound the caller is willing to probe.
    max_mtu: usize = 1500,
    /// Smallest useful increase over the current MTU.
    min_probe_delta: usize = 1,
    /// Number of consecutive losses at the current effective MTU before the
    /// controller treats the path as blackholed and falls back.
    blackhole_loss_threshold: u8 = 3,
};

/// Overlay `[transport.pmtud]` keys onto `cfg`. Absent keys are left at their
/// current values, so the default config is behavior-preserving.
pub fn applyToml(cfg: *Config, doc: *const toml.Document) void {
    const p = "transport.pmtud.";
    if (doc.getUint(p ++ "base_mtu")) |v| cfg.base_mtu = @intCast(v);
    if (doc.getUint(p ++ "max_mtu")) |v| cfg.max_mtu = @intCast(v);
    if (doc.getUint(p ++ "min_probe_delta")) |v| cfg.min_probe_delta = @intCast(v);
    if (doc.getUint(p ++ "blackhole_loss_threshold")) |v| cfg.blackhole_loss_threshold = @intCast(v);
}

pub const InitError = error{
    InvalidBaseMtu,
    InvalidCeiling,
    InvalidProbeDelta,
    InvalidBlackholeThreshold,
};

/// Deterministic DPLPMTUD controller.
pub const Pmtud = struct {
    base_mtu: usize,
    ceiling_mtu: usize,
    current_mtu: usize,
    min_probe_delta: usize,
    blackhole_loss_threshold: u8,
    consecutive_current_losses: u8 = 0,
    pending_probe: ?usize = null,
    current_state: State = .Base,

    pub fn init(config: Config) InitError!Pmtud {
        if (config.base_mtu == 0) return error.InvalidBaseMtu;
        if (config.max_mtu < config.base_mtu) return error.InvalidCeiling;
        if (config.min_probe_delta == 0) return error.InvalidProbeDelta;
        if (config.blackhole_loss_threshold == 0) return error.InvalidBlackholeThreshold;

        var p = Pmtud{
            .base_mtu = config.base_mtu,
            .ceiling_mtu = config.max_mtu,
            .current_mtu = config.base_mtu,
            .min_probe_delta = config.min_probe_delta,
            .blackhole_loss_threshold = config.blackhole_loss_threshold,
        };
        p.refreshState();
        return p;
    }

    /// Current effective MTU the caller may use for ordinary datagrams.
    pub fn currentMtu(self: Pmtud) usize {
        return self.current_mtu;
    }

    /// Current upper bound for probing. Exposed for diagnostics and tests.
    pub fn ceilingMtu(self: Pmtud) usize {
        return self.ceiling_mtu;
    }

    pub fn state(self: Pmtud) State {
        return self.current_state;
    }

    /// Return the next probe size, or null when no probe should be sent.
    ///
    /// The same pending probe is returned until the caller reports an ACK, loss,
    /// or PTB. This keeps the state machine deterministic even if `probeSize`
    /// is queried more than once before a result arrives.
    pub fn probeSize(self: *Pmtud) ?usize {
        if (self.current_state == .Error) return null;
        self.refreshState();
        if (self.current_state == .SearchComplete or self.current_state == .Error) return null;
        if (self.pending_probe) |probe| return probe;

        const probe = self.nextProbe() orelse {
            self.refreshState();
            return null;
        };
        self.pending_probe = probe;
        self.current_state = .Searching;
        return probe;
    }

    /// Report that a probe of `size` was acknowledged by the peer.
    pub fn onProbeAcked(self: *Pmtud, size: usize) void {
        if (self.current_state == .Error) return;
        self.clearPending(size);

        if (size >= self.current_mtu) {
            self.consecutive_current_losses = 0;
        }

        if (size > self.current_mtu and size <= self.ceiling_mtu) {
            self.current_mtu = size;
        } else if (size > self.ceiling_mtu) {
            self.current_mtu = self.ceiling_mtu;
        }

        self.refreshState();
    }

    /// Report that a probe or ordinary datagram of `size` was lost.
    pub fn onProbeLost(self: *Pmtud, size: usize) void {
        if (self.current_state == .Error) return;
        self.clearPending(size);

        if (size > self.current_mtu) {
            self.consecutive_current_losses = 0;
            self.ceiling_mtu = @min(self.ceiling_mtu, size - 1);
            self.refreshState();
            return;
        }

        if (size == self.current_mtu) {
            self.recordCurrentMtuLoss();
        }

        self.refreshState();
    }

    /// Report an ICMP Packet Too Big signal carrying the path MTU in bytes.
    pub fn onPtbReceived(self: *Pmtud, size: usize) void {
        self.pending_probe = null;
        self.consecutive_current_losses = 0;

        if (size < self.base_mtu) {
            self.ceiling_mtu = size;
            self.current_state = .Error;
            return;
        }

        self.ceiling_mtu = @min(self.ceiling_mtu, size);
        if (self.current_mtu > self.ceiling_mtu) {
            self.current_mtu = self.ceiling_mtu;
        }

        self.refreshState();
    }

    fn clearPending(self: *Pmtud, size: usize) void {
        if (self.pending_probe != null and self.pending_probe.? == size) {
            self.pending_probe = null;
        }
    }

    fn nextProbe(self: Pmtud) ?usize {
        if (self.ceiling_mtu < self.base_mtu) return null;
        if (self.current_mtu >= self.ceiling_mtu) return null;

        const span = self.ceiling_mtu - self.current_mtu;
        if (span < self.min_probe_delta) return null;

        var delta = ceilDiv(span, 2);
        if (delta < self.min_probe_delta) delta = self.min_probe_delta;

        const probe = saturatingAdd(self.current_mtu, delta);
        return @min(probe, self.ceiling_mtu);
    }

    fn recordCurrentMtuLoss(self: *Pmtud) void {
        if (self.consecutive_current_losses < std.math.maxInt(u8)) {
            self.consecutive_current_losses += 1;
        }

        if (self.consecutive_current_losses < self.blackhole_loss_threshold) return;

        self.pending_probe = null;
        self.consecutive_current_losses = 0;

        if (self.current_mtu <= self.base_mtu) {
            self.current_state = .Error;
            return;
        }

        self.ceiling_mtu = @min(self.ceiling_mtu, self.current_mtu - 1);
        self.current_mtu = self.base_mtu;
    }

    fn refreshState(self: *Pmtud) void {
        if (self.current_state == .Error) return;
        if (self.ceiling_mtu < self.base_mtu) {
            self.current_state = .Error;
            return;
        }
        if (self.current_mtu > self.ceiling_mtu) {
            self.current_mtu = self.ceiling_mtu;
        }

        if (self.current_mtu >= self.ceiling_mtu or
            self.ceiling_mtu - self.current_mtu < self.min_probe_delta)
        {
            self.pending_probe = null;
            self.current_state = .SearchComplete;
        } else if (self.current_mtu == self.base_mtu and self.pending_probe == null) {
            self.current_state = .Base;
        } else {
            self.current_state = .Searching;
        }
    }
};

pub const Dplpmtud = Pmtud;

fn ceilDiv(n: usize, d: usize) usize {
    return n / d + @intFromBool(n % d != 0);
}

fn saturatingAdd(a: usize, b: usize) usize {
    const result, const overflow = @addWithOverflow(a, b);
    return if (overflow == 0) result else std.math.maxInt(usize);
}

test "initial state starts at base and proposes upward binary probe" {
    var p = try Pmtud.init(.{ .base_mtu = 1200, .max_mtu = 1500 });

    try std.testing.expectEqual(State.Base, p.state());
    try std.testing.expectEqual(@as(usize, 1200), p.currentMtu());
    try std.testing.expectEqual(@as(usize, 1500), p.ceilingMtu());

    const first = p.probeSize();
    try std.testing.expectEqual(@as(?usize, 1350), first);
    try std.testing.expectEqual(State.Searching, p.state());
    try std.testing.expectEqual(first, p.probeSize());
    try std.testing.expectEqual(@as(usize, 1200), p.currentMtu());
}

test "acked probes raise the effective MTU and continue upward" {
    var p = try Pmtud.init(.{ .base_mtu = 1200, .max_mtu = 1500 });

    const first = p.probeSize().?;
    p.onProbeAcked(first);
    try std.testing.expectEqual(@as(usize, 1350), p.currentMtu());

    const second = p.probeSize().?;
    try std.testing.expectEqual(@as(usize, 1425), second);
    p.onProbeAcked(second);
    try std.testing.expectEqual(@as(usize, 1425), p.currentMtu());
    try std.testing.expectEqual(State.Searching, p.state());
}

test "searches upward until the ceiling is verified" {
    var p = try Pmtud.init(.{ .base_mtu = 1200, .max_mtu = 1232 });

    var last_probe: usize = 0;
    var iterations: usize = 0;
    while (p.probeSize()) |probe| {
        try std.testing.expect(probe > p.currentMtu());
        try std.testing.expect(probe > last_probe);
        last_probe = probe;
        p.onProbeAcked(probe);
        iterations += 1;
        try std.testing.expect(iterations < 32);
    }

    try std.testing.expectEqual(@as(usize, 1232), p.currentMtu());
    try std.testing.expectEqual(State.SearchComplete, p.state());
    try std.testing.expectEqual(@as(?usize, null), p.probeSize());
}

test "lost probes bound the search and converge to the largest acked size" {
    const path_mtu: usize = 1376;
    var p = try Pmtud.init(.{ .base_mtu = 1200, .max_mtu = 1500 });

    var iterations: usize = 0;
    while (p.probeSize()) |probe| {
        if (probe <= path_mtu) {
            p.onProbeAcked(probe);
            try std.testing.expect(p.currentMtu() <= path_mtu);
        } else {
            p.onProbeLost(probe);
            try std.testing.expect(p.ceilingMtu() < probe);
        }
        iterations += 1;
        try std.testing.expect(iterations < 64);
    }

    try std.testing.expectEqual(path_mtu, p.currentMtu());
    try std.testing.expectEqual(path_mtu, p.ceilingMtu());
    try std.testing.expectEqual(State.SearchComplete, p.state());
}

test "PTB lowers the ceiling and prevents larger probes" {
    var p = try Pmtud.init(.{ .base_mtu = 1200, .max_mtu = 1500 });

    const first = p.probeSize().?;
    p.onProbeAcked(first);
    try std.testing.expectEqual(@as(usize, 1350), p.currentMtu());

    p.onPtbReceived(1400);
    try std.testing.expectEqual(@as(usize, 1350), p.currentMtu());
    try std.testing.expectEqual(@as(usize, 1400), p.ceilingMtu());

    while (p.probeSize()) |probe| {
        try std.testing.expect(probe <= 1400);
        p.onProbeLost(probe);
    }
    try std.testing.expect(p.currentMtu() <= 1400);
}

test "PTB below current MTU lowers the effective MTU" {
    var p = try Pmtud.init(.{ .base_mtu = 1200, .max_mtu = 1500 });

    const first = p.probeSize().?;
    p.onProbeAcked(first);
    try std.testing.expectEqual(@as(usize, 1350), p.currentMtu());

    p.onPtbReceived(1280);
    try std.testing.expectEqual(@as(usize, 1280), p.currentMtu());
    try std.testing.expectEqual(@as(usize, 1280), p.ceilingMtu());
    try std.testing.expectEqual(State.SearchComplete, p.state());
    try std.testing.expectEqual(@as(?usize, null), p.probeSize());
}

test "PTB below base enters error state" {
    var p = try Pmtud.init(.{ .base_mtu = 1200, .max_mtu = 1500 });

    p.onPtbReceived(1199);
    try std.testing.expectEqual(State.Error, p.state());
    try std.testing.expectEqual(@as(?usize, null), p.probeSize());
}

test "blackhole detection drops the current MTU back to base" {
    var p = try Pmtud.init(.{
        .base_mtu = 1200,
        .max_mtu = 1500,
        .blackhole_loss_threshold = 3,
    });

    const first = p.probeSize().?;
    p.onProbeAcked(first);
    const second = p.probeSize().?;
    p.onProbeAcked(second);
    try std.testing.expectEqual(@as(usize, 1425), p.currentMtu());

    p.onProbeLost(p.currentMtu());
    try std.testing.expectEqual(@as(usize, 1425), p.currentMtu());
    p.onProbeLost(p.currentMtu());
    try std.testing.expectEqual(@as(usize, 1425), p.currentMtu());
    p.onProbeLost(p.currentMtu());

    try std.testing.expectEqual(@as(usize, 1200), p.currentMtu());
    try std.testing.expectEqual(@as(usize, 1424), p.ceilingMtu());
    try std.testing.expectEqual(State.Base, p.state());
    try std.testing.expect(p.probeSize().? < 1425);
}

test "repeated loss at base enters error state" {
    var p = try Pmtud.init(.{
        .base_mtu = 1200,
        .max_mtu = 1500,
        .blackhole_loss_threshold = 2,
    });

    p.onProbeLost(1200);
    try std.testing.expectEqual(State.Base, p.state());
    p.onProbeLost(1200);

    try std.testing.expectEqual(State.Error, p.state());
    try std.testing.expectEqual(@as(?usize, null), p.probeSize());
}

test "deterministic event replay produces the same probe sequence" {
    var a = try Pmtud.init(.{ .base_mtu = 1200, .max_mtu = 1500 });
    var b = try Pmtud.init(.{ .base_mtu = 1200, .max_mtu = 1500 });
    const path_mtu: usize = 1364;

    var probes_a: [16]usize = undefined;
    var probes_b: [16]usize = undefined;
    const len_a = driveSearch(&a, path_mtu, &probes_a);
    const len_b = driveSearch(&b, path_mtu, &probes_b);

    try std.testing.expectEqual(len_a, len_b);
    try std.testing.expectEqualSlices(usize, probes_a[0..len_a], probes_b[0..len_b]);
    try std.testing.expectEqual(a.currentMtu(), b.currentMtu());
    try std.testing.expectEqual(State.SearchComplete, a.state());
    try std.testing.expectEqual(@as(usize, 1364), a.currentMtu());
}

test "invalid configurations are rejected" {
    try std.testing.expectError(error.InvalidBaseMtu, Pmtud.init(.{ .base_mtu = 0 }));
    try std.testing.expectError(error.InvalidCeiling, Pmtud.init(.{
        .base_mtu = 1200,
        .max_mtu = 1199,
    }));
    try std.testing.expectError(error.InvalidProbeDelta, Pmtud.init(.{
        .base_mtu = 1200,
        .max_mtu = 1500,
        .min_probe_delta = 0,
    }));
    try std.testing.expectError(error.InvalidBlackholeThreshold, Pmtud.init(.{
        .base_mtu = 1200,
        .max_mtu = 1500,
        .blackhole_loss_threshold = 0,
    }));
}

test "applyToml overlays pmtud keys and preserves defaults when absent" {
    const src =
        \\[transport.pmtud]
        \\base_mtu = 1280
        \\max_mtu = 9000
        \\min_probe_delta = 4
        \\blackhole_loss_threshold = 5
    ;
    var doc = try toml.parse(std.testing.allocator, src);
    defer doc.deinit(std.testing.allocator);

    var cfg = Config{};
    applyToml(&cfg, &doc);

    try std.testing.expectEqual(@as(usize, 1280), cfg.base_mtu);
    try std.testing.expectEqual(@as(usize, 9000), cfg.max_mtu);
    try std.testing.expectEqual(@as(usize, 4), cfg.min_probe_delta);
    try std.testing.expectEqual(@as(u8, 5), cfg.blackhole_loss_threshold);

    var def_doc = try toml.parse(std.testing.allocator, "x = 1\n");
    defer def_doc.deinit(std.testing.allocator);
    var def_cfg = Config{};
    applyToml(&def_cfg, &def_doc);
    try std.testing.expectEqual((Config{}).base_mtu, def_cfg.base_mtu);
    try std.testing.expectEqual((Config{}).max_mtu, def_cfg.max_mtu);
    try std.testing.expectEqual((Config{}).blackhole_loss_threshold, def_cfg.blackhole_loss_threshold);
}

fn driveSearch(p: *Pmtud, path_mtu: usize, out: []usize) usize {
    var count: usize = 0;
    while (p.probeSize()) |probe| {
        out[count] = probe;
        count += 1;
        if (probe <= path_mtu) {
            p.onProbeAcked(probe);
        } else {
            p.onProbeLost(probe);
        }
    }
    return count;
}

// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Transport stack: composes the parallel-authored transport primitives into one
//! congestion-controlled, paced, loss-recovering datagram sender behind the
//! adaptive transport seam.
//!
//!   send  -> cwnd gate (in-flight vs cc.cwnd) -> optional rate cap -> pacer ->
//!            transport.startSend -> loss.onSent + pacer.onSent + qlog
//!   recv  -> transport.supplyReceiveBuffer + pollReceiveCompletions
//!   onAck -> loss.onAck (RTT/in-flight) -> cc.onAck -> repace -> qlog
//!   tick  -> loss.detectLost -> cc.onLoss (+ qlog) -> caller retransmits
//!
//! The congestion controller is pluggable behind a tiny vtable so l4s (scalable
//! marking) and bbr (bw+rtt model) interchange; their differing method shapes
//! are bridged by adapters. ACK generation is the peer/application's job — the
//! stack only consumes ACKs. Deterministic (no clocks/RNG of its own), so it
//! drops into the DST harness.
const std = @import("std");

const adaptive_transport = @import("adaptive_transport.zig");
const l4s = @import("l4s.zig");
const bbr = @import("bbr.zig");
const pacing = @import("pacing.zig");
const flow = @import("flow.zig");
const loss_recovery = @import("loss_recovery.zig");
const qlog = @import("qlog.zig");
const toml = @import("../proto/toml.zig");

pub const PacketNumber = loss_recovery.PacketNumber;
pub const SackRange = loss_recovery.SackRange;

/// Pluggable congestion controller. l4s and bbr have different method shapes
/// (l4s wants CE marking + total; bbr wants now + app-limited and has no loss
/// hook); the vtable carries the superset and each adapter drops what it ignores.
pub const CongestionControl = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        on_ack: *const fn (ptr: *anyopaque, now_us: u64, acked_bytes: u64, total_acked: u64, rtt_us: u64, ce_marked: bool, app_limited: bool) void,
        on_loss: *const fn (ptr: *anyopaque, now_us: u64) void,
        cwnd: *const fn (ptr: *anyopaque) u64,
        pacing_rate: *const fn (ptr: *anyopaque, rtt_us: u64) u64,
    };

    pub fn onAck(self: CongestionControl, now_us: u64, acked: u64, total: u64, rtt_us: u64, ce: bool, app_limited: bool) void {
        self.vtable.on_ack(self.ptr, now_us, acked, total, rtt_us, ce, app_limited);
    }
    pub fn onLoss(self: CongestionControl, now_us: u64) void {
        self.vtable.on_loss(self.ptr, now_us);
    }
    pub fn cwnd(self: CongestionControl) u64 {
        return self.vtable.cwnd(self.ptr);
    }
    pub fn pacingRate(self: CongestionControl, rtt_us: u64) u64 {
        return self.vtable.pacing_rate(self.ptr, rtt_us);
    }
};

/// Wrap an `l4s.Controller` as a CongestionControl.
pub fn l4sController(c: *l4s.Controller) CongestionControl {
    const Adapter = struct {
        fn onAck(ptr: *anyopaque, now_us: u64, acked: u64, total: u64, rtt_us: u64, ce: bool, app_limited: bool) void {
            _ = now_us;
            _ = app_limited;
            const self: *l4s.Controller = @ptrCast(@alignCast(ptr));
            self.onAck(acked, ce, total, rtt_us);
        }
        fn onLoss(ptr: *anyopaque, now_us: u64) void {
            _ = now_us;
            const self: *l4s.Controller = @ptrCast(@alignCast(ptr));
            self.onLoss();
        }
        fn cwnd(ptr: *anyopaque) u64 {
            const self: *l4s.Controller = @ptrCast(@alignCast(ptr));
            return self.cwnd();
        }
        fn pacingRate(ptr: *anyopaque, rtt_us: u64) u64 {
            const self: *l4s.Controller = @ptrCast(@alignCast(ptr));
            return self.pacingRate(rtt_us);
        }
        const vtable = CongestionControl.VTable{ .on_ack = onAck, .on_loss = onLoss, .cwnd = cwnd, .pacing_rate = pacingRate };
    };
    return .{ .ptr = c, .vtable = &Adapter.vtable };
}

/// Wrap a `bbr.Bbr` as a CongestionControl. BBR has no loss hook; its window is
/// authoritative, so on_loss is a model no-op and recovery comes from retransmit
/// + the bandwidth/rtt-driven cwnd.
pub fn bbrController(c: *bbr.Bbr) CongestionControl {
    const Adapter = struct {
        fn onAck(ptr: *anyopaque, now_us: u64, acked: u64, total: u64, rtt_us: u64, ce: bool, app_limited: bool) void {
            _ = total;
            _ = ce;
            const self: *bbr.Bbr = @ptrCast(@alignCast(ptr));
            self.onAck(now_us, acked, rtt_us, app_limited);
        }
        fn onLoss(ptr: *anyopaque, now_us: u64) void {
            _ = ptr;
            _ = now_us;
        }
        fn cwnd(ptr: *anyopaque) u64 {
            const self: *bbr.Bbr = @ptrCast(@alignCast(ptr));
            return self.cwnd();
        }
        fn pacingRate(ptr: *anyopaque, rtt_us: u64) u64 {
            _ = rtt_us;
            const self: *bbr.Bbr = @ptrCast(@alignCast(ptr));
            return self.pacingRate();
        }
        const vtable = CongestionControl.VTable{ .on_ack = onAck, .on_loss = onLoss, .cwnd = cwnd, .pacing_rate = pacingRate };
    };
    return .{ .ptr = c, .vtable = &Adapter.vtable };
}

pub const Config = struct {
    mss: u64 = 1460,
    /// Optional admission rate ceiling (bytes/sec); 0 disables it.
    rate_cap_bps: u64 = 0,
    rate_cap_burst: u64 = 0,
    start_us: u64 = 0,
    /// RTT (microseconds) assumed when seeding the initial pacer rate before the
    /// first ACK arrives.
    seed_rtt_us: u64 = 10_000,
    /// RTT (microseconds) used for cc/pacing when no SRTT sample exists yet.
    fallback_rtt_us: u64 = 10_000,
    /// Pacer burst budget expressed as a multiple of MSS.
    pacer_burst_mss_multiple: u64 = 2,
};

/// Overlay `[transport]` (stack-level) keys onto `cfg`. Absent keys are left at
/// their current values, so the default config is behavior-preserving.
///
/// NOTE: `transport.qlog_capacity` is intentionally NOT applied here — the qlog
/// ring capacity is a comptime type parameter (`qlog.Recorder(N)`), so it is
/// resolved at the orchestrator's `Recorder` type alias, not at runtime.
pub fn applyToml(cfg: *Config, doc: *const toml.Document) void {
    if (doc.getUint("transport.mss_bytes")) |v| cfg.mss = v;
    if (doc.getUint("transport.rate_cap_bps")) |v| cfg.rate_cap_bps = v;
    if (doc.getUint("transport.rate_cap_burst_bytes")) |v| cfg.rate_cap_burst = v;
    if (doc.getUint("transport.seed_rtt_us")) |v| cfg.seed_rtt_us = v;
    if (doc.getUint("transport.fallback_rtt_us")) |v| cfg.fallback_rtt_us = v;
    if (doc.getUint("transport.pacer_burst_mss_multiple")) |v| cfg.pacer_burst_mss_multiple = v;
}

pub const SendResult = union(enum) {
    sent: struct { pn: PacketNumber, bytes: usize },
    blocked_cwnd,
    blocked_rate,
    blocked_pacer,
    nothing_sent,
};

pub const Recorder = qlog.Recorder(1024);

pub const TransportStack = struct {
    allocator: std.mem.Allocator,
    transport: adaptive_transport.Transport,
    cc: CongestionControl,
    pacer: pacing.Pacer,
    rate_cap: ?flow.TokenBucket,
    loss: loss_recovery.LossRecovery,
    recorder: *Recorder,
    cfg: Config,
    next_pn: PacketNumber = 0,
    now_us: u64,

    pub fn init(
        allocator: std.mem.Allocator,
        transport: adaptive_transport.Transport,
        cc: CongestionControl,
        recorder: *Recorder,
        cfg: Config,
    ) TransportStack {
        const seed_rate = @max(cc.pacingRate(cfg.seed_rtt_us), 1);
        return .{
            .allocator = allocator,
            .transport = transport,
            .cc = cc,
            .pacer = pacing.Pacer.init(seed_rate, @max(cfg.pacer_burst_mss_multiple * cfg.mss, 1), cfg.start_us),
            .rate_cap = if (cfg.rate_cap_bps > 0) flow.TokenBucket.init(cfg.rate_cap_burst, cfg.rate_cap_bps, cfg.start_us) else null,
            .loss = loss_recovery.LossRecovery.init(allocator),
            .recorder = recorder,
            .cfg = cfg,
            .now_us = cfg.start_us,
        };
    }

    pub fn deinit(self: *TransportStack) void {
        self.loss.deinit();
    }

    pub fn setTime(self: *TransportStack, now_us: u64) void {
        self.now_us = now_us;
    }

    pub fn inFlightBytes(self: *const TransportStack) u64 {
        return self.loss.inFlightBytes();
    }

    pub fn cwnd(self: TransportStack) u64 {
        return self.cc.cwnd();
    }

    /// Attempt to send one datagram. Gated independently by the congestion
    /// window (in-flight + len <= cwnd), the optional rate cap, and the pacer.
    pub fn send(self: *TransportStack, payload: []const u8) !SendResult {
        if (self.loss.inFlightBytes() + payload.len > self.cc.cwnd()) return .blocked_cwnd;
        if (self.rate_cap) |*b| {
            if (!b.take(self.now_us, payload.len)) return .blocked_rate;
        }
        if (!self.pacer.canSend(self.now_us, payload.len)) return .blocked_pacer;

        const pn = self.next_pn;
        _ = try self.transport.startSend(payload);

        var comps: [8]adaptive_transport.SendCompletion = undefined;
        const n = try self.transport.pollSendCompletions(&comps);
        var accepted: usize = 0;
        for (comps[0..n]) |c| accepted += c.bytes; // sent or dropped: both left the host
        if (accepted == 0) return .nothing_sent;

        self.next_pn += 1;
        try self.loss.onSent(pn, self.now_us, accepted);
        self.pacer.onSent(self.now_us, accepted);
        self.recorder.record(qlog.Event.init(self.now_us, .transport, "packet_sent"));
        return .{ .sent = .{ .pn = pn, .bytes = accepted } };
    }

    /// Pull one received datagram (or null). The caller owns `buffer`.
    pub fn recv(self: *TransportStack, buffer: []u8) !?[]u8 {
        try self.transport.supplyReceiveBuffer(buffer);
        var comps: [4]adaptive_transport.ReceiveCompletion = undefined;
        const n = try self.transport.pollReceiveCompletions(&comps);
        if (n == 0) return null;
        return comps[0].bytes();
    }

    /// Apply an ACK (the peer/app supplies the acked pns / SACK ranges).
    pub fn onAck(
        self: *TransportStack,
        acked_pns: []const PacketNumber,
        sack_ranges: []const SackRange,
        ack_delay_us: u64,
        ce_marked: bool,
        app_limited: bool,
    ) !void {
        const before = self.loss.inFlightBytes();
        try self.loss.onAck(acked_pns, sack_ranges, self.now_us, ack_delay_us);
        const acked_bytes = before - self.loss.inFlightBytes();
        const rtt = self.loss.smoothedRtt() orelse self.cfg.fallback_rtt_us;

        self.cc.onAck(self.now_us, acked_bytes, acked_bytes, rtt, ce_marked, app_limited);
        self.pacer.pacing_rate = @max(self.cc.pacingRate(rtt), 1);
        self.recorder.record(qlog.Event.init(self.now_us, .recovery, "metrics_updated"));
    }

    /// Advance time-based loss detection. Returns lost packet numbers (borrowed
    /// from the loss detector) for the caller to retransmit; on any loss the
    /// congestion controller is notified.
    pub fn tick(self: *TransportStack, now_us: u64) ![]const PacketNumber {
        self.now_us = now_us;
        const lost = try self.loss.detectLost(now_us);
        if (lost.len > 0) {
            self.cc.onLoss(now_us);
            self.recorder.record(qlog.Event.init(now_us, .recovery, "packets_lost"));
        }
        return lost;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "l4s and bbr adapters drive the underlying controller" {
    var l = l4s.Controller.init(.{});
    const cc_l = l4sController(&l);
    const c0 = cc_l.cwnd();
    cc_l.onAck(1000, 1460, 1460, 10_000, false, false); // unmarked acks grow cwnd
    cc_l.onAck(2000, 1460, 1460, 10_000, false, false);
    try testing.expect(cc_l.cwnd() >= c0);
    cc_l.onLoss(3000);
    try testing.expect(cc_l.cwnd() < 16 * 1024 * 1024);

    var b = bbr.Bbr.init(.{});
    const cc_b = bbrController(&b);
    try testing.expect(cc_b.cwnd() > 0);
    cc_b.onAck(1000, 1460, 1460, 10_000, false, false);
    cc_b.onLoss(2000); // no-op for bbr, must not crash
    try testing.expect(cc_b.pacingRate(10_000) > 0);
}

fn pumpOnce(a: *LB, b: *LB) !void {
    try a.flush();
    try b.flush();
}

const LB = adaptive_transport.LoopbackTransport;

test "two stacks: paced cwnd-limited delivery with ack-driven cwnd growth" {
    const allocator = testing.allocator;
    var pairs = try adaptive_transport.LoopbackTransport.pair(allocator, .{});
    defer pairs.deinit();

    var cc_a = l4s.Controller.init(.{ .initial_cwnd = 6000 });
    var rec_a = Recorder.init();
    var a = TransportStack.init(allocator, (&pairs.a).transport(), l4sController(&cc_a), &rec_a, .{ .start_us = 0 });
    defer a.deinit();

    var rec_b = Recorder.init();
    var cc_b = l4s.Controller.init(.{});
    var b = TransportStack.init(allocator, (&pairs.b).transport(), l4sController(&cc_b), &rec_b, .{ .start_us = 0 });
    defer b.deinit();

    const cwnd0 = a.cwnd();
    var delivered: usize = 0;
    var t: u64 = 0;
    var round: usize = 0;
    while (round < 200) : (round += 1) {
        t += 5_000;
        a.setTime(t);
        b.setTime(t);
        const payload = "datagram-payload-of-some-bytes!!"; // 32 bytes
        const r = try a.send(payload);
        switch (r) {
            .sent => |s| {
                try pumpOnce(&pairs.a, &pairs.b);
                var buf: [256]u8 = undefined;
                if (try b.recv(&buf)) |got| {
                    if (got.len == payload.len) delivered += 1;
                }
                // B acks the packet to A (one RTT later, modeled same tick).
                try a.onAck(&.{s.pn}, &.{}, 0, false, false);
            },
            else => {}, // blocked_pacer/cwnd — advance time and retry next round
        }
    }

    try testing.expect(delivered > 0); // data crossed the seam
    try testing.expect(a.inFlightBytes() == 0); // everything acked
    try testing.expect(a.cwnd() >= cwnd0); // unmarked acks did not shrink cwnd
    try testing.expect(rec_a.count() > 0); // qlog recorded events
}

test "a gap (later pns acked) is detected as loss and drives cc.onLoss" {
    const allocator = testing.allocator;
    var pairs = try adaptive_transport.LoopbackTransport.pair(allocator, .{});
    defer pairs.deinit();

    var cc_a = l4s.Controller.init(.{ .initial_cwnd = 1_000_000 });
    var rec_a = Recorder.init();
    var a = TransportStack.init(allocator, (&pairs.a).transport(), l4sController(&cc_a), &rec_a, .{ .start_us = 0 });
    defer a.deinit();

    // Send 4 packets (pacer-spaced); capture their pns.
    var pns: [4]PacketNumber = undefined;
    var t: u64 = 0;
    var sent: usize = 0;
    while (sent < 4) {
        t += 100_000;
        a.setTime(t);
        switch (try a.send("payload-bytes-here-1234567890ab")) {
            .sent => |s| {
                pns[sent] = s.pn;
                sent += 1;
            },
            else => {},
        }
    }

    // ACK the three LATER packets but not pns[0]: that leaves pns[0] behind a
    // run of acked packets, which RACK / packet-threshold detects as lost.
    t += 50_000;
    a.setTime(t);
    try a.onAck(&.{ pns[1], pns[2], pns[3] }, &.{}, 0, false, false);

    var fired = false;
    var i: usize = 0;
    while (i < 10 and !fired) : (i += 1) {
        t += 100_000;
        const lost = try a.tick(t);
        for (lost) |pn| {
            if (pn == pns[0]) fired = true;
        }
    }
    try testing.expect(fired); // pns[0] reported lost; cc.onLoss invoked
}

test "applyToml overlays stack-level keys and preserves defaults when absent" {
    const src =
        \\[transport]
        \\mss_bytes = 1500
        \\rate_cap_bps = 1000000
        \\rate_cap_burst_bytes = 65536
        \\seed_rtt_us = 20000
        \\fallback_rtt_us = 30000
        \\pacer_burst_mss_multiple = 4
    ;
    var doc = try toml.parse(testing.allocator, src);
    defer doc.deinit(testing.allocator);

    var cfg = Config{};
    applyToml(&cfg, &doc);

    try testing.expectEqual(@as(u64, 1500), cfg.mss);
    try testing.expectEqual(@as(u64, 1_000_000), cfg.rate_cap_bps);
    try testing.expectEqual(@as(u64, 65_536), cfg.rate_cap_burst);
    try testing.expectEqual(@as(u64, 20_000), cfg.seed_rtt_us);
    try testing.expectEqual(@as(u64, 30_000), cfg.fallback_rtt_us);
    try testing.expectEqual(@as(u64, 4), cfg.pacer_burst_mss_multiple);

    var def_doc = try toml.parse(testing.allocator, "x = 1\n");
    defer def_doc.deinit(testing.allocator);
    var def_cfg = Config{};
    applyToml(&def_cfg, &def_doc);
    try testing.expectEqual((Config{}).mss, def_cfg.mss);
    try testing.expectEqual((Config{}).seed_rtt_us, def_cfg.seed_rtt_us);
    try testing.expectEqual((Config{}).pacer_burst_mss_multiple, def_cfg.pacer_burst_mss_multiple);
}

// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

const std = @import("std");
const toml = @import("../proto/toml.zig");

const DEFAULT_C: f64 = 0.4;
const DEFAULT_BETA: f64 = 0.7;
const USEC_PER_SEC: f64 = 1_000_000.0;

/// Overlay `[transport.congestion.cubic]` keys onto `cfg`. Absent keys are left
/// at their current values. `max_cwnd_packets` / `initial_ssthresh_packets` of
/// `0` mean "unbounded" (maxInt(u64)), matching the struct defaults.
pub fn applyToml(cfg: *Cubic.Config, doc: *const toml.Document) void {
    const p = "transport.congestion.cubic.";
    if (doc.getFloat(p ++ "c")) |v| cfg.c = v;
    if (doc.getFloat(p ++ "beta")) |v| cfg.beta = v;
    if (doc.getUint(p ++ "initial_cwnd_packets")) |v| cfg.initial_cwnd = v;
    if (doc.getUint(p ++ "min_cwnd_packets")) |v| cfg.min_cwnd = v;
    if (doc.getUint(p ++ "max_cwnd_packets")) |v| {
        cfg.max_cwnd = if (v == 0) std.math.maxInt(u64) else v;
    }
    if (doc.getUint(p ++ "initial_ssthresh_packets")) |v| {
        cfg.initial_ssthresh = if (v == 0) std.math.maxInt(u64) else v;
    }
}

pub const Cubic = struct {
    const Self = @This();

    pub const Config = struct {
        initial_cwnd: u64 = 10,
        min_cwnd: u64 = 2,
        max_cwnd: u64 = std.math.maxInt(u64),
        initial_ssthresh: u64 = std.math.maxInt(u64),
        c: f64 = DEFAULT_C,
        beta: f64 = DEFAULT_BETA,
    };

    cwnd_packets: f64,
    ssthresh_packets: f64,
    min_cwnd_packets: f64,
    max_cwnd_packets: f64,
    w_max_packets: f64,
    tcp_epoch_base_packets: f64,
    c: f64,
    beta: f64,
    k_seconds: f64,
    epoch_start_us: ?u64,
    last_loss_us: ?u64,
    have_w_max: bool,

    pub fn init(config: Config) Self {
        const min_cwnd = if (config.min_cwnd == 0) 1 else config.min_cwnd;
        const max_cwnd = if (config.max_cwnd < min_cwnd) min_cwnd else config.max_cwnd;
        const initial = clampU64(config.initial_cwnd, min_cwnd, max_cwnd);
        const ssthresh_value = if (config.initial_ssthresh < min_cwnd)
            min_cwnd
        else
            config.initial_ssthresh;

        const initial_f = asF64(initial);

        return .{
            .cwnd_packets = initial_f,
            .ssthresh_packets = asF64(ssthresh_value),
            .min_cwnd_packets = asF64(min_cwnd),
            .max_cwnd_packets = asF64(max_cwnd),
            .w_max_packets = initial_f,
            .tcp_epoch_base_packets = initial_f,
            .c = validPositive(config.c, DEFAULT_C),
            .beta = validBeta(config.beta),
            .k_seconds = 0.0,
            .epoch_start_us = null,
            .last_loss_us = null,
            .have_w_max = false,
        };
    }

    pub fn cwnd(self: *const Self) u64 {
        return floorWindow(self.cwnd_packets, 1);
    }

    pub fn ssthresh(self: *const Self) u64 {
        return floorWindow(self.ssthresh_packets, 1);
    }

    pub fn onAck(self: *Self, now_us: u64, acked: u64, rtt_us: u64) void {
        if (acked == 0) return;

        const acked_f = asF64(acked);
        if (self.cwnd_packets < self.ssthresh_packets) {
            self.cwnd_packets = self.clampWindow(self.cwnd_packets + acked_f);
            if (self.cwnd_packets >= self.ssthresh_packets) {
                self.epoch_start_us = null;
            }
            return;
        }

        if (self.epoch_start_us == null) {
            self.startEpoch(now_us);
        }

        const target = self.targetWindow(now_us, rtt_us);
        if (target <= self.cwnd_packets) return;

        const per_ack = (target - self.cwnd_packets) / self.cwnd_packets;
        const delta = @min(target - self.cwnd_packets, per_ack * acked_f);
        self.cwnd_packets = self.clampWindow(self.cwnd_packets + delta);
    }

    pub fn onLoss(self: *Self, now_us: u64) void {
        const old_cwnd = self.cwnd_packets;
        self.w_max_packets = old_cwnd;
        self.have_w_max = true;
        self.cwnd_packets = self.clampWindow(old_cwnd * self.beta);
        self.ssthresh_packets = self.cwnd_packets;
        self.epoch_start_us = null;
        self.k_seconds = 0.0;
        self.last_loss_us = now_us;
    }

    fn startEpoch(self: *Self, now_us: u64) void {
        self.epoch_start_us = now_us;
        self.tcp_epoch_base_packets = self.cwnd_packets;

        if (!self.have_w_max or self.cwnd_packets >= self.w_max_packets) {
            self.w_max_packets = self.cwnd_packets;
            self.k_seconds = 0.0;
            return;
        }

        self.k_seconds = cubeRoot((self.w_max_packets - self.cwnd_packets) / self.c);
    }

    fn targetWindow(self: *const Self, now_us: u64, rtt_us: u64) f64 {
        const elapsed = self.elapsedSeconds(now_us);
        const cubic = self.cubicWindow(elapsed);
        const friendly = self.tcpFriendlyWindow(elapsed, rtt_us);
        return self.clampWindow(@max(cubic, friendly));
    }

    fn cubicWindow(self: *const Self, elapsed_seconds: f64) f64 {
        const offset = elapsed_seconds - self.k_seconds;
        return self.w_max_packets + self.c * offset * offset * offset;
    }

    fn tcpFriendlyWindow(self: *const Self, elapsed_seconds: f64, rtt_us: u64) f64 {
        const rtt_seconds = @max(asF64(if (rtt_us == 0) 1 else rtt_us) / USEC_PER_SEC, 0.000001);
        const alpha = 3.0 * (1.0 - self.beta) / (1.0 + self.beta);
        return self.tcp_epoch_base_packets + alpha * (elapsed_seconds / rtt_seconds);
    }

    fn elapsedSeconds(self: *const Self, now_us: u64) f64 {
        const start = self.epoch_start_us orelse now_us;
        if (now_us <= start) return 0.0;
        return asF64(now_us - start) / USEC_PER_SEC;
    }

    fn clampWindow(self: *const Self, value: f64) f64 {
        return @min(@max(value, self.min_cwnd_packets), self.max_cwnd_packets);
    }
};

fn asF64(value: u64) f64 {
    return @as(f64, @floatFromInt(value));
}

fn clampU64(value: u64, min_value: u64, max_value: u64) u64 {
    return @min(@max(value, min_value), max_value);
}

fn validPositive(value: f64, fallback: f64) f64 {
    if (value > 0.0) return value;
    return fallback;
}

fn validBeta(value: f64) f64 {
    if (value > 0.0 and value < 1.0) return value;
    return DEFAULT_BETA;
}

fn floorWindow(value: f64, min_value: u64) u64 {
    const floored = @floor(value);
    if (floored <= asF64(min_value)) return min_value;
    if (floored >= asF64(std.math.maxInt(u64))) return std.math.maxInt(u64);
    return @as(u64, @intFromFloat(floored));
}

fn cubeRoot(value: f64) f64 {
    if (value <= 0.0) return 0.0;

    var low: f64 = 0.0;
    var high: f64 = if (value >= 1.0) value else 1.0;
    while (high * high * high < value) {
        high *= 2.0;
    }

    for (0..96) |_| {
        const mid = (low + high) / 2.0;
        if (mid * mid * mid < value) {
            low = mid;
        } else {
            high = mid;
        }
    }

    return (low + high) / 2.0;
}

fn expectApprox(actual: f64, expected: f64, tolerance: f64) !void {
    try std.testing.expect(@abs(actual - expected) <= tolerance);
}

test "slow-start then cubic growth" {
    var cc = Cubic.init(.{
        .initial_cwnd = 4,
        .initial_ssthresh = 8,
    });

    cc.onAck(0, 2, 100_000);
    try std.testing.expectEqual(@as(u64, 6), cc.cwnd());

    cc.onAck(10_000, 2, 100_000);
    try std.testing.expectEqual(@as(u64, 8), cc.cwnd());
    try std.testing.expect(cc.epoch_start_us == null);

    cc.onAck(1_010_000, 8, 100_000);
    try std.testing.expectEqual(@as(u64, 8), cc.cwnd());
    try std.testing.expect(cc.epoch_start_us != null);

    cc.onAck(2_010_000, 8, 100_000);
    try std.testing.expect(cc.cwnd() > 8);
    try std.testing.expect(cc.epoch_start_us != null);
}

test "loss sets W_max and reduces by beta" {
    var cc = Cubic.init(.{
        .initial_cwnd = 100,
        .initial_ssthresh = 100,
    });

    cc.onLoss(42);

    try expectApprox(cc.w_max_packets, 100.0, 0.000001);
    try expectApprox(cc.cwnd_packets, 70.0, 0.000001);
    try expectApprox(cc.ssthresh_packets, 70.0, 0.000001);
    try std.testing.expectEqual(@as(u64, 70), cc.cwnd());
    try std.testing.expectEqual(@as(u64, 70), cc.ssthresh());
    try std.testing.expect(cc.have_w_max);
    try std.testing.expectEqual(@as(?u64, 42), cc.last_loss_us);
}

test "concave-then-convex growth around W_max" {
    var cc = Cubic.init(.{
        .initial_cwnd = 100,
        .initial_ssthresh = 100,
    });
    cc.onLoss(0);
    cc.startEpoch(0);

    const w1 = cc.targetWindow(1_000_000, 100_000_000);
    const w2 = cc.targetWindow(2_000_000, 100_000_000);
    const w3 = cc.targetWindow(3_000_000, 100_000_000);
    const w5 = cc.targetWindow(5_000_000, 100_000_000);
    const w6 = cc.targetWindow(6_000_000, 100_000_000);
    const w7 = cc.targetWindow(7_000_000, 100_000_000);

    try std.testing.expect(w1 > cc.cwnd_packets);
    try std.testing.expect(w3 < cc.w_max_packets);
    try std.testing.expect(w5 > cc.w_max_packets);
    try std.testing.expect((w2 - w1) > (w3 - w2));
    try std.testing.expect((w7 - w6) > (w6 - w5));
}

test "TCP-friendly floor" {
    var cc = Cubic.init(.{
        .initial_cwnd = 100,
        .initial_ssthresh = 100,
    });
    cc.onLoss(0);
    cc.startEpoch(0);

    const now = 1_000_000;
    const rtt = 10_000;
    const cubic = cc.cubicWindow(1.0);
    const friendly = cc.tcpFriendlyWindow(1.0, rtt);
    const target = cc.targetWindow(now, rtt);

    try std.testing.expect(friendly > cubic);
    try expectApprox(target, friendly, 0.000001);

    cc.onAck(now, cc.cwnd(), rtt);
    try std.testing.expect(cc.cwnd_packets > cubic);
}

test "deterministic" {
    const Step = struct {
        now_us: u64,
        acked: u64,
        rtt_us: u64,
        loss: bool = false,
    };

    const steps = [_]Step{
        .{ .now_us = 0, .acked = 5, .rtt_us = 50_000 },
        .{ .now_us = 100_000, .acked = 5, .rtt_us = 50_000 },
        .{ .now_us = 350_000, .acked = 10, .rtt_us = 55_000 },
        .{ .now_us = 400_000, .acked = 0, .rtt_us = 55_000, .loss = true },
        .{ .now_us = 900_000, .acked = 7, .rtt_us = 60_000 },
        .{ .now_us = 1_800_000, .acked = 9, .rtt_us = 45_000 },
        .{ .now_us = 2_700_000, .acked = 12, .rtt_us = 45_000 },
    };

    var a = Cubic.init(.{
        .initial_cwnd = 10,
        .initial_ssthresh = 20,
    });
    var b = Cubic.init(.{
        .initial_cwnd = 10,
        .initial_ssthresh = 20,
    });

    for (steps) |step| {
        if (step.loss) {
            a.onLoss(step.now_us);
            b.onLoss(step.now_us);
        } else {
            a.onAck(step.now_us, step.acked, step.rtt_us);
            b.onAck(step.now_us, step.acked, step.rtt_us);
        }
    }

    try expectApprox(a.cwnd_packets, b.cwnd_packets, 0.0);
    try expectApprox(a.ssthresh_packets, b.ssthresh_packets, 0.0);
    try expectApprox(a.w_max_packets, b.w_max_packets, 0.0);
    try std.testing.expectEqual(a.cwnd(), b.cwnd());
    try std.testing.expectEqual(a.ssthresh(), b.ssthresh());
}

test "applyToml overlays cubic keys; 0 means unbounded for max/ssthresh" {
    const src =
        \\[transport.congestion.cubic]
        \\c = 0.5
        \\beta = 0.8
        \\initial_cwnd_packets = 20
        \\min_cwnd_packets = 4
        \\max_cwnd_packets = 0
        \\initial_ssthresh_packets = 64
    ;
    var doc = try toml.parse(std.testing.allocator, src);
    defer doc.deinit(std.testing.allocator);

    var cfg = Cubic.Config{};
    applyToml(&cfg, &doc);

    try expectApprox(cfg.c, 0.5, 1e-9);
    try expectApprox(cfg.beta, 0.8, 1e-9);
    try std.testing.expectEqual(@as(u64, 20), cfg.initial_cwnd);
    try std.testing.expectEqual(@as(u64, 4), cfg.min_cwnd);
    try std.testing.expectEqual(std.math.maxInt(u64), cfg.max_cwnd); // 0 -> unbounded
    try std.testing.expectEqual(@as(u64, 64), cfg.initial_ssthresh);

    var def_doc = try toml.parse(std.testing.allocator, "x = 1\n");
    defer def_doc.deinit(std.testing.allocator);
    var def_cfg = Cubic.Config{};
    applyToml(&def_cfg, &def_doc);
    try expectApprox(def_cfg.c, DEFAULT_C, 1e-9);
    try expectApprox(def_cfg.beta, DEFAULT_BETA, 1e-9);
    try std.testing.expectEqual(std.math.maxInt(u64), def_cfg.max_cwnd);
}

//! Deterministic L4S scalable congestion control.
//!
//! The controller keeps `cwnd` in bytes and tracks the DCTCP alpha value as a
//! Q16 fixed-point EWMA. CE-marked ACKs reduce the window by `alpha / 2` by
//! default; actual loss uses the configured classic multiplicative backoff.

const std = @import("std");
const toml = @import("../proto/toml.zig");

/// Q16 fixed-point scale used for ECN marking fractions.
pub const fraction_one: u32 = 1 << 16;

/// Configuration for a DCTCP / TCP-Prague-lite congestion controller.
pub const Config = struct {
    /// Initial congestion window in bytes.
    initial_cwnd: u64 = 12_000,
    /// Lower congestion-window clamp in bytes.
    min_cwnd: u64 = 2_400,
    /// Upper congestion-window clamp in bytes.
    max_cwnd: u64 = 16 * 1024 * 1024,
    /// Byte quantum used for additive increase. Usually one MSS.
    additive_increase_bytes: u64 = 1_200,
    /// EWMA gain numerator. Default gain is 1/16.
    alpha_gain_num: u32 = 1,
    /// EWMA gain denominator. Default gain is 1/16.
    alpha_gain_den: u32 = 16,
    /// Marking backoff numerator. Default reduction is `cwnd * alpha / 2`.
    marking_reduction_num: u32 = 1,
    /// Marking backoff denominator. Default reduction is `cwnd * alpha / 2`.
    marking_reduction_den: u32 = 2,
    /// Loss backoff numerator. Default is classic halving.
    loss_backoff_num: u32 = 1,
    /// Loss backoff denominator. Default is classic halving.
    loss_backoff_den: u32 = 2,
};

/// Overlay `[transport.congestion.l4s]` keys onto `cfg`. Absent keys are left at
/// their current values, so the default config is behavior-preserving.
pub fn applyToml(cfg: *Config, doc: *const toml.Document) void {
    const p = "transport.congestion.l4s.";
    if (doc.getUint(p ++ "initial_cwnd_bytes")) |v| cfg.initial_cwnd = v;
    if (doc.getUint(p ++ "min_cwnd_bytes")) |v| cfg.min_cwnd = v;
    if (doc.getUint(p ++ "max_cwnd_bytes")) |v| cfg.max_cwnd = v;
    if (doc.getUint(p ++ "additive_increase_bytes")) |v| cfg.additive_increase_bytes = v;
    if (doc.getUint(p ++ "alpha_gain_num")) |v| cfg.alpha_gain_num = @intCast(v);
    if (doc.getUint(p ++ "alpha_gain_den")) |v| cfg.alpha_gain_den = @intCast(v);
    if (doc.getUint(p ++ "marking_reduction_num")) |v| cfg.marking_reduction_num = @intCast(v);
    if (doc.getUint(p ++ "marking_reduction_den")) |v| cfg.marking_reduction_den = @intCast(v);
    if (doc.getUint(p ++ "loss_backoff_num")) |v| cfg.loss_backoff_num = @intCast(v);
    if (doc.getUint(p ++ "loss_backoff_den")) |v| cfg.loss_backoff_den = @intCast(v);
}

/// A deterministic scalable congestion controller.
pub const Controller = struct {
    cfg: Config,
    cwnd_bytes: u64,
    alpha_q16: u32,
    ai_remainder: u128,
    last_rtt_us: u64,

    /// Construct a controller from `cfg`, normalizing invalid ratios.
    pub fn init(cfg: Config) Controller {
        const normalized = normalizeConfig(cfg);
        return .{
            .cfg = normalized,
            .cwnd_bytes = clamp(normalized.initial_cwnd, normalized.min_cwnd, normalized.max_cwnd),
            .alpha_q16 = 0,
            .ai_remainder = 0,
            .last_rtt_us = 0,
        };
    }

    /// Process newly acknowledged bytes.
    ///
    /// `ce_marked` says whether this ACK event covered CE-marked bytes.
    /// `total_acked` is the denominator for the marking sample. When it is
    /// zero, `bytes_acked` is used so a marked ACK samples as 100%.
    pub fn onAck(self: *Controller, bytes_acked: u64, ce_marked: bool, total_acked: u64, rtt_us: u64) void {
        if (rtt_us != 0) self.last_rtt_us = rtt_us;
        if (bytes_acked == 0) return;

        const sample = markingSample(bytes_acked, ce_marked, total_acked);
        self.updateAlpha(sample);

        if (ce_marked) {
            self.applyMarkingReduction();
        } else {
            self.applyAdditiveIncrease(bytes_acked);
        }

        self.clampWindow();
    }

    /// Apply classic loss response. This is intentionally stronger than normal
    /// L4S ECN response.
    pub fn onLoss(self: *Controller) void {
        const kept = mulDivFloor(self.cwnd_bytes, self.cfg.loss_backoff_num, self.cfg.loss_backoff_den);
        self.cwnd_bytes = if (kept == 0) self.cfg.min_cwnd else kept;
        self.ai_remainder = 0;
        self.clampWindow();
    }

    /// Current congestion window in bytes.
    pub fn cwnd(self: *const Controller) u64 {
        return self.cwnd_bytes;
    }

    /// Pacing rate in bytes per second for `rtt_us`.
    ///
    /// A zero RTT is treated as one microsecond to keep the result finite and
    /// deterministic.
    pub fn pacingRate(self: *const Controller, rtt_us: u64) u64 {
        const effective_rtt = if (rtt_us == 0) 1 else rtt_us;
        return saturatingMulDiv(self.cwnd_bytes, 1_000_000, effective_rtt);
    }

    /// Current EWMA ECN-CE marking fraction as Q16.
    pub fn markingFraction(self: *const Controller) u32 {
        return self.alpha_q16;
    }

    fn updateAlpha(self: *Controller, sample_q16: u32) void {
        const gain_num = self.cfg.alpha_gain_num;
        const gain_den = self.cfg.alpha_gain_den;
        if (sample_q16 >= self.alpha_q16) {
            const delta = sample_q16 - self.alpha_q16;
            self.alpha_q16 += @intCast((@as(u64, delta) * gain_num) / gain_den);
        } else {
            const delta = self.alpha_q16 - sample_q16;
            self.alpha_q16 -= @intCast((@as(u64, delta) * gain_num) / gain_den);
        }
    }

    fn applyAdditiveIncrease(self: *Controller, bytes_acked: u64) void {
        const numerator = @as(u128, self.cfg.additive_increase_bytes) * bytes_acked + self.ai_remainder;
        const denom = @max(self.cwnd_bytes, @as(u64, 1));
        const increment: u64 = @intCast(numerator / denom);
        self.ai_remainder = numerator % denom;
        self.cwnd_bytes = saturatingAdd(self.cwnd_bytes, increment);
    }

    fn applyMarkingReduction(self: *Controller) void {
        const reduction_num = @as(u128, self.alpha_q16) * self.cfg.marking_reduction_num;
        const reduction_den = @as(u128, fraction_one) * self.cfg.marking_reduction_den;
        var reduction: u64 = @intCast((@as(u128, self.cwnd_bytes) * reduction_num) / reduction_den);
        if (reduction == 0 and self.alpha_q16 != 0 and self.cwnd_bytes > self.cfg.min_cwnd) {
            reduction = 1;
        }

        self.cwnd_bytes = if (reduction >= self.cwnd_bytes) 0 else self.cwnd_bytes - reduction;
        self.ai_remainder = 0;
    }

    fn clampWindow(self: *Controller) void {
        self.cwnd_bytes = clamp(self.cwnd_bytes, self.cfg.min_cwnd, self.cfg.max_cwnd);
        if (self.cwnd_bytes == self.cfg.max_cwnd) self.ai_remainder = 0;
    }
};

fn normalizeConfig(cfg: Config) Config {
    var out = cfg;

    if (out.min_cwnd == 0) out.min_cwnd = 1;
    if (out.max_cwnd < out.min_cwnd) out.max_cwnd = out.min_cwnd;
    if (out.initial_cwnd == 0) out.initial_cwnd = out.min_cwnd;
    if (out.additive_increase_bytes == 0) out.additive_increase_bytes = 1;

    normalizeRatio(&out.alpha_gain_num, &out.alpha_gain_den);
    normalizeRatio(&out.marking_reduction_num, &out.marking_reduction_den);
    normalizeRatio(&out.loss_backoff_num, &out.loss_backoff_den);

    return out;
}

fn normalizeRatio(num: *u32, den: *u32) void {
    if (num.* == 0) num.* = 1;
    if (den.* == 0) den.* = 1;
    if (num.* > den.*) den.* = num.*;
}

fn markingSample(bytes_acked: u64, ce_marked: bool, total_acked: u64) u32 {
    if (!ce_marked) return 0;
    const denom = if (total_acked == 0) bytes_acked else @max(total_acked, bytes_acked);
    const scaled = (@as(u128, bytes_acked) * fraction_one) / denom;
    return @intCast(@min(scaled, fraction_one));
}

fn clamp(value: u64, min_value: u64, max_value: u64) u64 {
    return @min(@max(value, min_value), max_value);
}

fn saturatingAdd(a: u64, b: u64) u64 {
    const sum = @as(u128, a) + b;
    return @intCast(@min(sum, std.math.maxInt(u64)));
}

fn mulDivFloor(value: u64, num: u32, den: u32) u64 {
    return @intCast((@as(u128, value) * num) / den);
}

fn saturatingMulDiv(value: u64, num: u64, den: u64) u64 {
    const result = (@as(u128, value) * num) / den;
    return @intCast(@min(result, std.math.maxInt(u64)));
}

fn q16FromPermille(permille: u32) u32 {
    return @intCast((@as(u64, fraction_one) * permille) / 1_000);
}

fn simulateRound(cc: *Controller, marking_permille: u32, rtt_us: u64) void {
    const before = cc.cwnd();
    const marked = (@as(u128, before) * marking_permille) / 1_000;
    const marked_bytes: u64 = @intCast(@min(marked, before));
    const clean_bytes = before - marked_bytes;

    if (clean_bytes != 0) cc.onAck(clean_bytes, false, before, rtt_us);
    if (marked_bytes != 0) cc.onAck(marked_bytes, true, before, rtt_us);
}

test "cwnd grows under zero marks" {
    var cc = Controller.init(.{
        .initial_cwnd = 12_000,
        .min_cwnd = 2_400,
        .max_cwnd = 120_000,
        .additive_increase_bytes = 1_200,
    });

    const start = cc.cwnd();
    for (0..20) |_| {
        const before = cc.cwnd();
        cc.onAck(before, false, before, 10_000);
    }

    try std.testing.expect(cc.cwnd() > start);
    try std.testing.expectEqual(@as(u32, 0), cc.markingFraction());
    try std.testing.expect(cc.cwnd() >= start + 20 * 1_100);
}

test "constant marking reduces proportionally and reaches lower steady cwnd with more marking" {
    var low = Controller.init(.{
        .initial_cwnd = 80_000,
        .min_cwnd = 2_400,
        .max_cwnd = 500_000,
        .additive_increase_bytes = 1_200,
        .alpha_gain_num = 1,
        .alpha_gain_den = 4,
    });
    var high = Controller.init(.{
        .initial_cwnd = 80_000,
        .min_cwnd = 2_400,
        .max_cwnd = 500_000,
        .additive_increase_bytes = 1_200,
        .alpha_gain_num = 1,
        .alpha_gain_den = 4,
    });

    for (0..180) |_| {
        simulateRound(&low, 100, 10_000);
        simulateRound(&high, 300, 10_000);
    }

    const low_before = low.cwnd();
    const high_before = high.cwnd();

    for (0..20) |_| {
        simulateRound(&low, 100, 10_000);
        simulateRound(&high, 300, 10_000);
    }

    const low_delta = absDiff(low.cwnd(), low_before);
    const high_delta = absDiff(high.cwnd(), high_before);

    try std.testing.expect(low.markingFraction() > q16FromPermille(45));
    try std.testing.expect(high.markingFraction() > low.markingFraction());
    try std.testing.expect(high.cwnd() < low.cwnd());
    try std.testing.expect(low_delta < low.cwnd() / 4);
    try std.testing.expect(high_delta < high.cwnd() / 4);
}

test "marked ack reduction is gentle and scalable rather than fixed halving" {
    var cc = Controller.init(.{
        .initial_cwnd = 100_000,
        .min_cwnd = 2_400,
        .max_cwnd = 500_000,
        .alpha_gain_num = 1,
        .alpha_gain_den = 1,
    });

    cc.onAck(25_000, true, 100_000, 10_000);
    const after_twenty_five_percent_marks = cc.cwnd();

    try std.testing.expect(cc.markingFraction() >= q16FromPermille(249));
    try std.testing.expect(after_twenty_five_percent_marks > 80_000);
    try std.testing.expect(after_twenty_five_percent_marks < 95_000);
}

test "loss causes larger multiplicative backoff than marking" {
    var marked = Controller.init(.{
        .initial_cwnd = 120_000,
        .min_cwnd = 2_400,
        .max_cwnd = 500_000,
        .alpha_gain_num = 1,
        .alpha_gain_den = 1,
    });
    var lost = Controller.init(.{
        .initial_cwnd = 120_000,
        .min_cwnd = 2_400,
        .max_cwnd = 500_000,
        .alpha_gain_num = 1,
        .alpha_gain_den = 1,
    });

    marked.onAck(30_000, true, 120_000, 10_000);
    lost.onLoss();

    try std.testing.expect(marked.cwnd() > lost.cwnd());
    try std.testing.expectEqual(@as(u64, 60_000), lost.cwnd());
}

test "min and max clamps hold" {
    var low = Controller.init(.{
        .initial_cwnd = 3_000,
        .min_cwnd = 2_400,
        .max_cwnd = 30_000,
        .alpha_gain_num = 1,
        .alpha_gain_den = 1,
    });

    for (0..20) |_| low.onLoss();
    try std.testing.expectEqual(@as(u64, 2_400), low.cwnd());

    var high = Controller.init(.{
        .initial_cwnd = 28_000,
        .min_cwnd = 2_400,
        .max_cwnd = 30_000,
        .additive_increase_bytes = 10_000,
    });

    for (0..10) |_| high.onAck(high.cwnd(), false, high.cwnd(), 10_000);
    try std.testing.expectEqual(@as(u64, 30_000), high.cwnd());
}

test "pacing rate is cwnd divided by rtt" {
    var cc = Controller.init(.{
        .initial_cwnd = 64_000,
        .min_cwnd = 2_400,
        .max_cwnd = 128_000,
    });

    try std.testing.expectEqual(@as(u64, 6_400_000), cc.pacingRate(10_000));
    try std.testing.expectEqual(@as(u64, 64_000_000_000), cc.pacingRate(1));
    try std.testing.expectEqual(cc.pacingRate(1), cc.pacingRate(0));
}

test "deterministic given identical inputs" {
    var a = Controller.init(.{
        .initial_cwnd = 50_000,
        .min_cwnd = 2_400,
        .max_cwnd = 250_000,
        .alpha_gain_num = 3,
        .alpha_gain_den = 16,
    });
    var b = Controller.init(.{
        .initial_cwnd = 50_000,
        .min_cwnd = 2_400,
        .max_cwnd = 250_000,
        .alpha_gain_num = 3,
        .alpha_gain_den = 16,
    });

    const marks = [_]u32{ 0, 80, 0, 180, 40, 0, 300, 0, 120, 0, 0, 220 };
    for (marks) |marking| {
        simulateRound(&a, marking, 12_500);
        simulateRound(&b, marking, 12_500);
        if (marking == 0) {
            a.onAck(1_200, false, 1_200, 12_500);
            b.onAck(1_200, false, 1_200, 12_500);
        }
    }
    a.onLoss();
    b.onLoss();

    try std.testing.expectEqual(a.cwnd(), b.cwnd());
    try std.testing.expectEqual(a.markingFraction(), b.markingFraction());
    try std.testing.expectEqual(a.pacingRate(12_500), b.pacingRate(12_500));
}

fn absDiff(a: u64, b: u64) u64 {
    return if (a > b) a - b else b - a;
}

test "applyToml overlays l4s keys and preserves defaults when absent" {
    const src =
        \\[transport.congestion.l4s]
        \\initial_cwnd_bytes = 24000
        \\min_cwnd_bytes = 3600
        \\max_cwnd_bytes = 8388608
        \\additive_increase_bytes = 1460
        \\alpha_gain_num = 1
        \\alpha_gain_den = 8
        \\marking_reduction_num = 1
        \\marking_reduction_den = 4
        \\loss_backoff_num = 2
        \\loss_backoff_den = 3
    ;
    var doc = try toml.parse(std.testing.allocator, src);
    defer doc.deinit(std.testing.allocator);

    var cfg = Config{};
    applyToml(&cfg, &doc);

    try std.testing.expectEqual(@as(u64, 24_000), cfg.initial_cwnd);
    try std.testing.expectEqual(@as(u64, 3_600), cfg.min_cwnd);
    try std.testing.expectEqual(@as(u64, 8_388_608), cfg.max_cwnd);
    try std.testing.expectEqual(@as(u64, 1_460), cfg.additive_increase_bytes);
    try std.testing.expectEqual(@as(u32, 1), cfg.alpha_gain_num);
    try std.testing.expectEqual(@as(u32, 8), cfg.alpha_gain_den);
    try std.testing.expectEqual(@as(u32, 1), cfg.marking_reduction_num);
    try std.testing.expectEqual(@as(u32, 4), cfg.marking_reduction_den);
    try std.testing.expectEqual(@as(u32, 2), cfg.loss_backoff_num);
    try std.testing.expectEqual(@as(u32, 3), cfg.loss_backoff_den);

    var def_doc = try toml.parse(std.testing.allocator, "x = 1\n");
    defer def_doc.deinit(std.testing.allocator);
    var def_cfg = Config{};
    applyToml(&def_cfg, &def_doc);
    try std.testing.expectEqual((Config{}).initial_cwnd, def_cfg.initial_cwnd);
    try std.testing.expectEqual((Config{}).max_cwnd, def_cfg.max_cwnd);
}

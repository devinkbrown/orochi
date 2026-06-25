// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Allocation-free aggregate media statistics for the SFU MEDIA STATS surface.
//!
//! The caller owns time: all timestamps are monotonic milliseconds supplied to
//! `init` and `onRelay`.  The bitrate estimate is integer-only and updates when
//! a relay call crosses a roughly one-second window boundary.

const std = @import("std");

const window_ms: i64 = 1000;

pub const Stats = struct {
    rx_packets: u64,
    rx_bytes: u64,
    tx_packets: u64,
    tx_bytes: u64,
    bitrate_bps_ema: u64,
    loss_fraction_q8: u8,
    participants: u32,
};

pub const Aggregator = struct {
    rx_packets: u64,
    rx_bytes: u64,
    tx_packets: u64,
    tx_bytes: u64,
    bitrate_bps_ema: u64,
    loss_fraction_q8: u8,
    participants: u32,

    window_start_ms: i64,
    window_bytes: u64,
    ema_initialized: bool,

    pub fn init(now_ms: i64) Aggregator {
        return .{
            .rx_packets = 0,
            .rx_bytes = 0,
            .tx_packets = 0,
            .tx_bytes = 0,
            .bitrate_bps_ema = 0,
            .loss_fraction_q8 = 0,
            .participants = 0,
            .window_start_ms = now_ms,
            .window_bytes = 0,
            .ema_initialized = false,
        };
    }

    /// Record one inbound media frame relayed to `fanout` outbound peers.
    pub fn onRelay(self: *Aggregator, in_bytes: usize, fanout: usize, now_ms: i64) void {
        self.advanceWindow(now_ms);

        const rx_bytes_delta: u64 = @intCast(in_bytes);
        const fanout_u64: u64 = @intCast(fanout);
        const tx_bytes_delta = rx_bytes_delta *| fanout_u64;

        self.rx_packets +|= 1;
        self.rx_bytes +|= rx_bytes_delta;
        self.tx_packets +|= fanout_u64;
        self.tx_bytes +|= tx_bytes_delta;
        self.window_bytes +|= rx_bytes_delta +| tx_bytes_delta;
    }

    /// Update loss as q8 fixed point: 0 means no loss, 255 approximates 100%.
    pub fn onLoss(self: *Aggregator, lost: u32, expected: u32) void {
        if (expected == 0) {
            self.loss_fraction_q8 = 0;
            return;
        }

        const q8 = (@as(u64, lost) * 256) / @as(u64, expected);
        self.loss_fraction_q8 = if (q8 > std.math.maxInt(u8)) std.math.maxInt(u8) else @intCast(q8);
    }

    pub fn setParticipants(self: *Aggregator, n: u32) void {
        self.participants = n;
    }

    pub fn snapshot(self: *const Aggregator) Stats {
        return .{
            .rx_packets = self.rx_packets,
            .rx_bytes = self.rx_bytes,
            .tx_packets = self.tx_packets,
            .tx_bytes = self.tx_bytes,
            .bitrate_bps_ema = self.bitrate_bps_ema,
            .loss_fraction_q8 = self.loss_fraction_q8,
            .participants = self.participants,
        };
    }

    fn advanceWindow(self: *Aggregator, now_ms: i64) void {
        if (now_ms - self.window_start_ms < window_ms) return;

        self.updateEma(self.window_bytes *| 8);
        self.window_bytes = 0;
        self.window_start_ms = now_ms;
    }

    fn updateEma(self: *Aggregator, bitrate_bps: u64) void {
        if (!self.ema_initialized) {
            self.bitrate_bps_ema = bitrate_bps;
            self.ema_initialized = true;
            return;
        }

        self.bitrate_bps_ema = ((self.bitrate_bps_ema * 7) + bitrate_bps) / 8;
    }
};

test "zero-traffic snapshot is all zeros" {
    const stats = Aggregator.init(1234).snapshot();

    try std.testing.expectEqual(@as(u64, 0), stats.rx_packets);
    try std.testing.expectEqual(@as(u64, 0), stats.rx_bytes);
    try std.testing.expectEqual(@as(u64, 0), stats.tx_packets);
    try std.testing.expectEqual(@as(u64, 0), stats.tx_bytes);
    try std.testing.expectEqual(@as(u64, 0), stats.bitrate_bps_ema);
    try std.testing.expectEqual(@as(u8, 0), stats.loss_fraction_q8);
    try std.testing.expectEqual(@as(u32, 0), stats.participants);
}

test "onRelay accumulates rx and fanout-scaled tx counters" {
    var agg = Aggregator.init(0);

    agg.onRelay(1200, 3, 10);
    agg.onRelay(800, 2, 20);

    const stats = agg.snapshot();
    try std.testing.expectEqual(@as(u64, 2), stats.rx_packets);
    try std.testing.expectEqual(@as(u64, 2000), stats.rx_bytes);
    try std.testing.expectEqual(@as(u64, 5), stats.tx_packets);
    try std.testing.expectEqual(@as(u64, 5200), stats.tx_bytes);
}

test "steady traffic updates EMA near the offered aggregate bitrate" {
    var agg = Aggregator.init(0);

    var now_ms: i64 = 0;
    while (now_ms < 1000) : (now_ms += 100) {
        agg.onRelay(100, 1, now_ms);
    }
    agg.onRelay(0, 0, 1000);

    const stats = agg.snapshot();
    try std.testing.expectEqual(@as(u64, 16_000), stats.bitrate_bps_ema);
}

test "subsequent windows use 7/8 old plus 1/8 new EMA" {
    var agg = Aggregator.init(0);

    var now_ms: i64 = 0;
    while (now_ms < 1000) : (now_ms += 100) {
        agg.onRelay(100, 1, now_ms);
    }
    agg.onRelay(0, 0, 1000);

    now_ms = 1000;
    while (now_ms < 2000) : (now_ms += 100) {
        agg.onRelay(200, 1, now_ms);
    }
    agg.onRelay(0, 0, 2000);

    const stats = agg.snapshot();
    try std.testing.expectEqual(@as(u64, 18_000), stats.bitrate_bps_ema);
}

test "onLoss computes q8 loss fraction" {
    var agg = Aggregator.init(0);

    agg.onLoss(1, 4);
    try std.testing.expectEqual(@as(u8, 64), agg.snapshot().loss_fraction_q8);

    agg.onLoss(0, 0);
    try std.testing.expectEqual(@as(u8, 0), agg.snapshot().loss_fraction_q8);
}

test "setParticipants is reflected in snapshot" {
    var agg = Aggregator.init(0);

    agg.setParticipants(42);

    try std.testing.expectEqual(@as(u32, 42), agg.snapshot().participants);
}

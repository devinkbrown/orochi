//! Receiver-side RTP-style packet-loss statistics.
//!
//! This module computes RTCP receiver-report metrics from 16-bit sequence
//! numbers: expected packets, received packets, cumulative loss, and interval
//! fraction lost. It does not track or expose the missing packet list.

const std = @import("std");

const seq_mod: u32 = 1 << 16;
const seq_half: u32 = 1 << 15;

pub const Monitor = struct {
    base_seq: u32,
    max_seq: u32,
    cycles: u32,
    received: u64,
    expected_prior: u64,
    received_prior: u64,
    has_base: bool,

    pub fn init() Monitor {
        return .{
            .base_seq = 0,
            .max_seq = 0,
            .cycles = 0,
            .received = 0,
            .expected_prior = 0,
            .received_prior = 0,
            .has_base = false,
        };
    }

    pub fn onReceived(self: *Monitor, seq: u16) void {
        const seq_u32: u32 = seq;

        if (!self.has_base) {
            self.base_seq = seq_u32;
            self.max_seq = seq_u32;
            self.cycles = 0;
            self.received = 1;
            self.has_base = true;
            return;
        }

        if (seq_u32 < self.max_seq and self.max_seq - seq_u32 > seq_half) {
            self.cycles += 1;
            self.max_seq = seq_u32;
        } else if (seq_u32 > self.max_seq and seq_u32 - self.max_seq < seq_half) {
            self.max_seq = seq_u32;
        }

        self.received += 1;
    }

    pub fn extendedHighestSeq(self: *const Monitor) u32 {
        return (self.cycles << 16) | (self.max_seq & (seq_mod - 1));
    }

    pub fn expected(self: *const Monitor) u64 {
        if (!self.has_base) return 0;
        return @as(u64, self.extendedHighestSeq() - self.base_seq) + 1;
    }

    pub fn cumulativeLost(self: *const Monitor) i64 {
        return @as(i64, @intCast(self.expected())) - @as(i64, @intCast(self.received));
    }

    pub fn fractionLostQ8(self: *Monitor) u8 {
        const expected_now = self.expected();
        const received_now = self.received;
        const expected_interval = expected_now - self.expected_prior;
        const received_interval = received_now - self.received_prior;

        self.expected_prior = expected_now;
        self.received_prior = received_now;

        if (expected_interval == 0 or received_interval >= expected_interval) {
            return 0;
        }

        const lost_interval = expected_interval - received_interval;
        const fraction = (lost_interval << 8) / expected_interval;
        return @intCast(@min(fraction, 255));
    }
};

test "in-order receipt has no loss" {
    var monitor = Monitor.init();

    monitor.onReceived(10);
    monitor.onReceived(11);
    monitor.onReceived(12);
    monitor.onReceived(13);

    try std.testing.expectEqual(@as(u64, 4), monitor.expected());
    try std.testing.expectEqual(@as(u64, 4), monitor.received);
    try std.testing.expectEqual(@as(i64, 0), monitor.cumulativeLost());
    try std.testing.expectEqual(@as(u8, 0), monitor.fractionLostQ8());
}

test "dropped sequence numbers contribute to cumulative and interval loss" {
    var monitor = Monitor.init();

    monitor.onReceived(100);
    monitor.onReceived(101);
    monitor.onReceived(104);

    try std.testing.expectEqual(@as(u64, 5), monitor.expected());
    try std.testing.expectEqual(@as(u64, 3), monitor.received);
    try std.testing.expectEqual(@as(i64, 2), monitor.cumulativeLost());
    try std.testing.expectEqual(@as(u8, 102), monitor.fractionLostQ8());
}

test "sixteen-bit wrap increments cycles and keeps counts sane" {
    var monitor = Monitor.init();

    monitor.onReceived(65534);
    monitor.onReceived(65535);
    monitor.onReceived(0);
    monitor.onReceived(1);

    try std.testing.expectEqual(@as(u32, 1), monitor.cycles);
    try std.testing.expectEqual(@as(u32, 1), monitor.max_seq);
    try std.testing.expectEqual(@as(u32, 65537), monitor.extendedHighestSeq());
    try std.testing.expectEqual(@as(u64, 4), monitor.expected());
    try std.testing.expectEqual(@as(u64, 4), monitor.received);
    try std.testing.expectEqual(@as(i64, 0), monitor.cumulativeLost());
}

test "fraction lost is measured over each interval" {
    var monitor = Monitor.init();

    monitor.onReceived(200);
    monitor.onReceived(201);
    monitor.onReceived(204);

    try std.testing.expectEqual(@as(u8, 102), monitor.fractionLostQ8());
    try std.testing.expectEqual(@as(u8, 0), monitor.fractionLostQ8());

    monitor.onReceived(205);
    monitor.onReceived(208);

    try std.testing.expectEqual(@as(i64, 4), monitor.cumulativeLost());
    try std.testing.expectEqual(@as(u8, 128), monitor.fractionLostQ8());
}

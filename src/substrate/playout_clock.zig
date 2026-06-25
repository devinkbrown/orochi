// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

const std = @import("std");

const us_per_second: i128 = 1_000_000;

pub const Clock = struct {
    clock_rate_hz: u32,
    base_media: u32,
    base_wall_us: i64,
    has_base: bool,

    pub fn init(clock_rate_hz: u32) Clock {
        std.debug.assert(clock_rate_hz != 0);
        return .{
            .clock_rate_hz = clock_rate_hz,
            .base_media = 0,
            .base_wall_us = 0,
            .has_base = false,
        };
    }

    pub fn anchor(self: *Clock, media_ts: u32, wall_us: i64) void {
        self.base_media = media_ts;
        self.base_wall_us = wall_us;
        self.has_base = true;
    }

    pub fn toWallUs(self: *const Clock, media_ts: u32) i64 {
        const base_media = if (self.has_base) self.base_media else 0;
        const base_wall_us = if (self.has_base) self.base_wall_us else 0;
        const ticks = media_ts -% base_media;
        return base_wall_us + ticksToUs(ticks, self.clock_rate_hz);
    }

    pub fn mediaForWallUs(self: *const Clock, wall_us: i64) u32 {
        const base_media = if (self.has_base) self.base_media else 0;
        const base_wall_us = if (self.has_base) self.base_wall_us else 0;
        const delta_us = wall_us - base_wall_us;
        const ticks = usToTicks(delta_us, self.clock_rate_hz);

        if (ticks >= 0) {
            const tick_mod: u32 = @truncate(@as(u128, @intCast(ticks)));
            return base_media +% tick_mod;
        } else {
            const tick_mod: u32 = @truncate(@as(u128, @intCast(-ticks)));
            return base_media -% tick_mod;
        }
    }

    pub fn driftUs(self: *const Clock, media_ts: u32, observed_wall_us: i64) i64 {
        return observed_wall_us - self.toWallUs(media_ts);
    }
};

fn ticksToUs(ticks: u32, clock_rate_hz: u32) i64 {
    std.debug.assert(clock_rate_hz != 0);
    const product = @as(i128, ticks) * us_per_second;
    return @intCast(@divTrunc(product, @as(i128, clock_rate_hz)));
}

fn usToTicks(delta_us: i64, clock_rate_hz: u32) i128 {
    std.debug.assert(clock_rate_hz != 0);
    const product = @as(i128, delta_us) * @as(i128, clock_rate_hz);
    return @divTrunc(product, us_per_second);
}

fn expectWithinOneTick(base_media: u32, expected: u32, actual: u32) !void {
    const expected_delta = expected -% base_media;
    const actual_delta = actual -% base_media;

    if (expected_delta >= actual_delta) {
        try std.testing.expect(expected_delta - actual_delta <= 1);
    } else {
        try std.testing.expect(actual_delta - expected_delta <= 1);
    }
}

test "anchor then one second maps to wall clock" {
    var clock = Clock.init(48_000);
    clock.anchor(12_345, 9_000_000);

    try std.testing.expectEqual(@as(i64, 10_000_000), clock.toWallUs(12_345 + 48_000));
}

test "mediaForWallUs inverts toWallUs within one tick" {
    var clock = Clock.init(90_000);
    clock.anchor(0x1234_5678, -250_000);

    const media_ts = clock.base_media +% 12_345;
    const wall_us = clock.toWallUs(media_ts);
    const roundtrip = clock.mediaForWallUs(wall_us);

    try expectWithinOneTick(clock.base_media, media_ts, roundtrip);
}

test "drift is zero on schedule and signed for late or early observations" {
    var clock = Clock.init(48_000);
    clock.anchor(1_000, 2_000_000);

    const media_ts = clock.base_media +% 24_000;
    const expected_wall_us = clock.toWallUs(media_ts);

    try std.testing.expectEqual(@as(i64, 0), clock.driftUs(media_ts, expected_wall_us));
    try std.testing.expect(clock.driftUs(media_ts, expected_wall_us + 2_500) > 0);
    try std.testing.expect(clock.driftUs(media_ts, expected_wall_us - 1_500) < 0);
}

test "wraparound across 2^32 maps correctly" {
    var clock = Clock.init(90_000);
    clock.anchor(0xffff_fff0, 50_000);

    const media_ts = clock.base_media +% 90_000;
    try std.testing.expect(media_ts < clock.base_media);
    try std.testing.expectEqual(@as(i64, 1_050_000), clock.toWallUs(media_ts));
    try std.testing.expectEqual(media_ts, clock.mediaForWallUs(1_050_000));
}

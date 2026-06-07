const std = @import("std");

const min_rto_us: i64 = 200_000;
const max_rto_us: i64 = 60_000_000;

pub const Estimator = struct {
    srtt_us: i64,
    rttvar_us: i64,
    rto_us: i64,
    min_rtt_us: i64,
    has_sample: bool,

    pub fn init() Estimator {
        return .{
            .srtt_us = 0,
            .rttvar_us = 0,
            .rto_us = min_rto_us,
            .min_rtt_us = 0,
            .has_sample = false,
        };
    }

    pub fn onSample(self: *Estimator, rtt_us: i64) void {
        if (!self.has_sample) {
            self.srtt_us = rtt_us;
            self.rttvar_us = @divTrunc(rtt_us, 2);
            self.min_rtt_us = rtt_us;
            self.has_sample = true;
        } else {
            const diff = absI64(self.srtt_us - rtt_us);

            self.rttvar_us = @divTrunc(3 * self.rttvar_us + diff, 4);
            self.srtt_us = @divTrunc(7 * self.srtt_us + rtt_us, 8);

            if (rtt_us < self.min_rtt_us) {
                self.min_rtt_us = rtt_us;
            }
        }

        self.rto_us = clampRto(self.srtt_us + 4 * self.rttvar_us);
    }

    pub fn measure(self: *Estimator, send_us: i64, recv_us: i64) void {
        self.onSample(recv_us - send_us);
    }

    pub fn srtt(self: Estimator) i64 {
        return self.srtt_us;
    }

    pub fn rto(self: Estimator) i64 {
        return self.rto_us;
    }

    pub fn minRtt(self: Estimator) i64 {
        return self.min_rtt_us;
    }
};

fn absI64(value: i64) i64 {
    return if (value < 0) -value else value;
}

fn clampRto(rto_us: i64) i64 {
    return std.math.clamp(rto_us, min_rto_us, max_rto_us);
}

test "first sample sets srtt and sane rto" {
    var estimator = Estimator.init();

    estimator.onSample(100_000);

    try std.testing.expect(estimator.has_sample);
    try std.testing.expectEqual(@as(i64, 100_000), estimator.srtt());
    try std.testing.expectEqual(@as(i64, 50_000), estimator.rttvar_us);
    try std.testing.expectEqual(@as(i64, 300_000), estimator.rto());
    try std.testing.expectEqual(@as(i64, 100_000), estimator.minRtt());
}

test "stable samples converge srtt and shrink rttvar" {
    var estimator = Estimator.init();

    for (0..32) |_| {
        estimator.onSample(100_000);
    }

    try std.testing.expect(estimator.srtt() >= 99_000 and estimator.srtt() <= 101_000);
    try std.testing.expect(estimator.rttvar_us < 1_000);
    try std.testing.expect(estimator.rto() >= min_rto_us);
    try std.testing.expect(estimator.rto() <= 205_000);
}

test "latency spike raises rto then decays as samples stabilize" {
    var estimator = Estimator.init();

    for (0..20) |_| {
        estimator.onSample(100_000);
    }
    const stable_rto = estimator.rto();

    estimator.onSample(800_000);
    const spike_rto = estimator.rto();

    for (0..40) |_| {
        estimator.onSample(100_000);
    }
    const recovered_rto = estimator.rto();

    try std.testing.expect(spike_rto > stable_rto);
    try std.testing.expect(recovered_rto < spike_rto);
    try std.testing.expect(recovered_rto <= 220_000);
}

test "min rtt tracks the lowest sample and measure uses timestamps" {
    var estimator = Estimator.init();

    estimator.measure(1_000_000, 1_090_000);
    estimator.onSample(120_000);
    estimator.measure(2_000_000, 2_045_000);
    estimator.onSample(60_000);

    try std.testing.expectEqual(@as(i64, 45_000), estimator.minRtt());
}

test "rto clamps to bounds" {
    var low = Estimator.init();
    low.onSample(1);
    try std.testing.expectEqual(@as(i64, min_rto_us), low.rto());

    var high = Estimator.init();
    high.onSample(100_000_000);
    try std.testing.expectEqual(@as(i64, max_rto_us), high.rto());
}

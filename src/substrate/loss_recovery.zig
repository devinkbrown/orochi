const std = @import("std");

pub const PacketNumber = u64;

pub const SackRange = struct {
    start: PacketNumber,
    end: PacketNumber,

    pub fn contains(self: SackRange, pn: PacketNumber) bool {
        const lo = @min(self.start, self.end);
        const hi = @max(self.start, self.end);
        return pn >= lo and pn <= hi;
    }
};

const Packet = struct {
    pn: PacketNumber,
    bytes: u64,
    sent_us: u64,
    in_flight: bool = true,
    acked: bool = false,
    lost: bool = false,
};

const initial_rto_us: u64 = 1_000_000;
const min_rto_us: u64 = 1_000_000;
const clock_granularity_us: u64 = 1_000;
const rack_min_reorder_window_us: u64 = 1_000;
const initial_tlp_delay_us: u64 = 200_000;
const min_tlp_delay_us: u64 = 10_000;
const default_packet_threshold: u64 = 3;

pub const LossRecovery = struct {
    allocator: std.mem.Allocator,
    sent: std.ArrayList(Packet) = .empty,
    lost_scratch: std.ArrayList(PacketNumber) = .empty,
    bytes_in_flight: u64 = 0,
    srtt_us: ?u64 = null,
    rttvar_us: ?u64 = null,
    min_rtt_us: ?u64 = null,
    largest_acked: ?PacketNumber = null,
    latest_acked_sent_us: ?u64 = null,
    packet_threshold: u64 = default_packet_threshold,
    consecutive_rto_timeouts: u5 = 0,

    pub fn init(allocator: std.mem.Allocator) LossRecovery {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *LossRecovery) void {
        self.sent.deinit(self.allocator);
        self.lost_scratch.deinit(self.allocator);
    }

    pub fn onSent(self: *LossRecovery, pn: PacketNumber, now_us: u64, bytes: u64) !void {
        for (self.sent.items) |packet| {
            if (packet.pn == pn) return error.DuplicatePacketNumber;
        }

        try self.sent.append(self.allocator, .{
            .pn = pn,
            .bytes = bytes,
            .sent_us = now_us,
        });
        self.bytes_in_flight = saturatingAdd(self.bytes_in_flight, bytes);
    }

    pub fn onAck(
        self: *LossRecovery,
        acked_pns: []const PacketNumber,
        sack_ranges: []const SackRange,
        now_us: u64,
        ack_delay_us: u64,
    ) !void {
        var best_rtt_sample: ?u64 = null;
        var best_sent_us: ?u64 = null;
        var newly_acked = false;

        for (self.sent.items) |*packet| {
            if (!isAcked(packet.pn, acked_pns, sack_ranges)) continue;

            if (packet.in_flight) {
                packet.in_flight = false;
                self.bytes_in_flight -|= packet.bytes;
                newly_acked = true;
            }

            if (!packet.acked) {
                packet.acked = true;
                packet.lost = false;
            }

            self.largest_acked = maxOptional(self.largest_acked, packet.pn);
            self.latest_acked_sent_us = maxOptional(self.latest_acked_sent_us, packet.sent_us);

            const raw_sample = elapsed(packet.sent_us, now_us);
            self.min_rtt_us = minOptional(self.min_rtt_us, raw_sample);
            if (best_sent_us == null or packet.sent_us > best_sent_us.?) {
                best_sent_us = packet.sent_us;
                best_rtt_sample = adjustedRtt(raw_sample, ack_delay_us);
            }
        }

        if (best_rtt_sample) |sample| self.updateRtt(sample);
        if (newly_acked) self.consecutive_rto_timeouts = 0;
    }

    pub fn detectLost(self: *LossRecovery, now_us: u64) ![]const PacketNumber {
        self.lost_scratch.clearRetainingCapacity();

        for (self.sent.items) |*packet| {
            if (!packet.in_flight or packet.lost or packet.acked) continue;

            if (self.packetThresholdLost(packet.*) or self.rackLost(packet.*, now_us)) {
                packet.in_flight = false;
                packet.lost = true;
                self.bytes_in_flight -|= packet.bytes;
                try self.lost_scratch.append(self.allocator, packet.pn);
            }
        }

        return self.lost_scratch.items;
    }

    pub fn rto(self: LossRecovery) u64 {
        const base = if (self.srtt_us) |srtt| blk: {
            const variation = @max(clock_granularity_us, saturatingMul(self.rttvar_us orelse 0, 4));
            break :blk @max(min_rto_us, saturatingAdd(srtt, variation));
        } else initial_rto_us;

        return saturatingShiftLeft(base, self.consecutive_rto_timeouts);
    }

    pub fn onRtoTimeout(self: *LossRecovery) void {
        if (self.consecutive_rto_timeouts < std.math.maxInt(u5)) {
            self.consecutive_rto_timeouts += 1;
        }
    }

    pub fn tlpTimeout(self: LossRecovery) ?u64 {
        const tail_sent = self.latestInflightSentTime() orelse return null;
        const probe_delay = if (self.srtt_us) |srtt|
            @max(min_tlp_delay_us, saturatingMul(srtt, 2))
        else
            initial_tlp_delay_us;
        return saturatingAdd(tail_sent, @min(probe_delay, self.rto()));
    }

    pub fn smoothedRtt(self: LossRecovery) ?u64 {
        return self.srtt_us;
    }

    pub fn rttVar(self: LossRecovery) ?u64 {
        return self.rttvar_us;
    }

    pub fn inFlightBytes(self: LossRecovery) u64 {
        return self.bytes_in_flight;
    }

    pub fn inFlightCount(self: LossRecovery) usize {
        var count: usize = 0;
        for (self.sent.items) |packet| {
            if (packet.in_flight) count += 1;
        }
        return count;
    }

    pub fn trackedCount(self: LossRecovery) usize {
        return self.sent.items.len;
    }

    fn updateRtt(self: *LossRecovery, sample_us: u64) void {
        const sample = @max(sample_us, 1);

        if (self.srtt_us == null) {
            self.srtt_us = sample;
            self.rttvar_us = @max(sample / 2, 1);
            return;
        }

        const srtt = self.srtt_us.?;
        const rttvar = self.rttvar_us orelse 1;
        const deviation = if (srtt > sample) srtt - sample else sample - srtt;

        self.rttvar_us = @intCast((@as(u128, rttvar) * 3 + deviation) / 4);
        self.srtt_us = @intCast((@as(u128, srtt) * 7 + sample) / 8);
    }

    fn packetThresholdLost(self: LossRecovery, packet: Packet) bool {
        const largest = self.largest_acked orelse return false;
        if (largest < self.packet_threshold) return false;
        return packet.pn <= largest - self.packet_threshold;
    }

    fn rackLost(self: LossRecovery, packet: Packet, now_us: u64) bool {
        const latest_sent = self.latest_acked_sent_us orelse return false;
        _ = self.largest_acked orelse return false;
        if (packet.sent_us >= latest_sent) return false;

        return elapsed(packet.sent_us, now_us) >= self.rackReorderWindow();
    }

    fn rackReorderWindow(self: LossRecovery) u64 {
        const min_rtt = self.min_rtt_us orelse return rack_min_reorder_window_us;
        return @max(rack_min_reorder_window_us, min_rtt / 4);
    }

    fn latestInflightSentTime(self: LossRecovery) ?u64 {
        var latest: ?u64 = null;
        for (self.sent.items) |packet| {
            if (!packet.in_flight) continue;
            latest = maxOptional(latest, packet.sent_us);
        }
        return latest;
    }
};

fn isAcked(pn: PacketNumber, acked_pns: []const PacketNumber, sack_ranges: []const SackRange) bool {
    for (acked_pns) |acked| {
        if (acked == pn) return true;
    }
    for (sack_ranges) |range| {
        if (range.contains(pn)) return true;
    }
    return false;
}

fn adjustedRtt(raw_sample_us: u64, ack_delay_us: u64) u64 {
    if (raw_sample_us == 0) return 1;
    const removable_delay = @min(ack_delay_us, raw_sample_us - 1);
    return raw_sample_us - removable_delay;
}

fn elapsed(start_us: u64, now_us: u64) u64 {
    if (now_us <= start_us) return 0;
    return now_us - start_us;
}

fn maxOptional(current: ?u64, candidate: u64) ?u64 {
    if (current) |value| return @max(value, candidate);
    return candidate;
}

fn minOptional(current: ?u64, candidate: u64) ?u64 {
    if (current) |value| return @min(value, candidate);
    return candidate;
}

fn saturatingAdd(a: u64, b: u64) u64 {
    const value, const overflow = @addWithOverflow(a, b);
    return if (overflow == 1) std.math.maxInt(u64) else value;
}

fn saturatingMul(a: u64, b: u64) u64 {
    const value, const overflow = @mulWithOverflow(a, b);
    return if (overflow == 1) std.math.maxInt(u64) else value;
}

fn saturatingShiftLeft(value: u64, amount: u5) u64 {
    var result = value;
    var i: u5 = 0;
    while (i < amount) : (i += 1) {
        result = saturatingMul(result, 2);
    }
    return result;
}

test "in-order acks clear in-flight and update srtt and rttvar" {
    var recovery = LossRecovery.init(std.testing.allocator);
    defer recovery.deinit();

    try recovery.onSent(1, 1_000, 1200);
    try recovery.onSent(2, 2_000, 900);

    try recovery.onAck(&.{ 1, 2 }, &.{}, 102_000, 1_000);

    try std.testing.expectEqual(@as(u64, 0), recovery.inFlightBytes());
    try std.testing.expectEqual(@as(usize, 0), recovery.inFlightCount());
    try std.testing.expectEqual(@as(?u64, 99_000), recovery.smoothedRtt());
    try std.testing.expectEqual(@as(?u64, 49_500), recovery.rttVar());
    try std.testing.expect(recovery.rto() >= min_rto_us);
}

test "sack ranges clear in-flight packets inclusively" {
    var recovery = LossRecovery.init(std.testing.allocator);
    defer recovery.deinit();

    try recovery.onSent(7, 0, 100);
    try recovery.onSent(8, 10, 100);
    try recovery.onSent(9, 20, 100);

    try recovery.onAck(&.{}, &.{.{ .start = 7, .end = 9 }}, 100_020, 0);

    try std.testing.expectEqual(@as(u64, 0), recovery.inFlightBytes());
    try std.testing.expectEqual(@as(usize, 0), recovery.inFlightCount());
    try std.testing.expectEqual(@as(?u64, 100_000), recovery.smoothedRtt());
}

test "a gap with later acks triggers rack loss detection after reorder window" {
    var recovery = LossRecovery.init(std.testing.allocator);
    defer recovery.deinit();

    try recovery.onSent(1, 0, 100);
    try recovery.onSent(2, 1_000, 100);
    try recovery.onSent(3, 2_000, 100);

    try recovery.onAck(&.{3}, &.{}, 102_000, 0);

    const early = try recovery.detectLost(10_000);
    try std.testing.expectEqual(@as(usize, 0), early.len);

    const late = try recovery.detectLost(30_000);
    try std.testing.expectEqualSlices(PacketNumber, &.{ 1, 2 }, late);
    try std.testing.expectEqual(@as(u64, 0), recovery.inFlightBytes());
}

test "packet threshold marks packets too far behind largest acked" {
    var recovery = LossRecovery.init(std.testing.allocator);
    defer recovery.deinit();

    try recovery.onSent(1, 0, 100);
    try recovery.onSent(2, 0, 100);
    try recovery.onSent(3, 0, 100);
    try recovery.onSent(4, 0, 100);

    try recovery.onAck(&.{4}, &.{}, 100_000, 0);

    const lost = try recovery.detectLost(100_000);
    try std.testing.expectEqualSlices(PacketNumber, &.{1}, lost);
    try std.testing.expectEqual(@as(u64, 200), recovery.inFlightBytes());
}

test "rto backoff doubles on consecutive timeouts and resets on ack" {
    var recovery = LossRecovery.init(std.testing.allocator);
    defer recovery.deinit();

    try recovery.onSent(1, 0, 100);
    try recovery.onAck(&.{1}, &.{}, 100_000, 0);

    const base = recovery.rto();
    recovery.onRtoTimeout();
    try std.testing.expectEqual(base * 2, recovery.rto());
    recovery.onRtoTimeout();
    try std.testing.expectEqual(base * 4, recovery.rto());

    try recovery.onSent(2, 200_000, 100);
    try recovery.onAck(&.{2}, &.{}, 300_000, 0);
    try std.testing.expectEqual(base, recovery.rto());
}

test "tlp is scheduled when tail remains outstanding" {
    var recovery = LossRecovery.init(std.testing.allocator);
    defer recovery.deinit();

    try recovery.onSent(1, 0, 100);
    try recovery.onSent(2, 10_000, 100);

    try std.testing.expectEqual(@as(?u64, 210_000), recovery.tlpTimeout());

    try recovery.onAck(&.{1}, &.{}, 100_000, 0);
    try std.testing.expect(recovery.tlpTimeout() != null);
    try std.testing.expectEqual(@as(?u64, 210_000), recovery.tlpTimeout());

    try recovery.onAck(&.{2}, &.{}, 110_000, 0);
    try std.testing.expectEqual(@as(?u64, null), recovery.tlpTimeout());
}

test "deterministic for identical supplied timestamps" {
    var a = LossRecovery.init(std.testing.allocator);
    defer a.deinit();
    var b = LossRecovery.init(std.testing.allocator);
    defer b.deinit();

    try a.onSent(1, 1_000, 100);
    try b.onSent(1, 1_000, 100);
    try a.onSent(2, 2_000, 100);
    try b.onSent(2, 2_000, 100);
    try a.onSent(3, 3_000, 100);
    try b.onSent(3, 3_000, 100);

    try a.onAck(&.{3}, &.{}, 103_000, 500);
    try b.onAck(&.{3}, &.{}, 103_000, 500);

    const lost_a = try a.detectLost(40_000);
    const lost_b = try b.detectLost(40_000);

    try std.testing.expectEqualSlices(PacketNumber, lost_a, lost_b);
    try std.testing.expectEqual(a.rto(), b.rto());
    try std.testing.expectEqual(a.tlpTimeout(), b.tlpTimeout());
    try std.testing.expectEqual(a.inFlightBytes(), b.inFlightBytes());
}

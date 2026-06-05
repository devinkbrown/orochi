//! Adaptive jitter buffer for RTP-like media packets.
//!
//! The buffer is deterministic: callers provide every timestamp and clock
//! value, and this module never reads time itself. Payloads passed to `push`
//! are copied into allocator-owned storage. A popped `Frame` transfers that
//! storage to the caller, who must free it with `Frame.deinit`.
const std = @import("std");

const us_per_second: u64 = 1_000_000;
const seq_modulus: i64 = 1 << 16;
const ts_modulus: i128 = 1 << 32;

pub const Config = struct {
    /// RTP timestamp units per second.
    clock_rate_hz: u32 = 48_000,
    /// Lower bound for adaptive playout delay.
    min_delay_us: u64 = 20_000,
    /// Initial playout delay and adaptive floor.
    initial_delay_us: u64 = 60_000,
    /// Upper bound for adaptive playout delay.
    max_delay_us: u64 = 250_000,
};

pub const Stats = struct {
    late: u64 = 0,
    lost: u64 = 0,
    buffered: usize = 0,
};

pub const Frame = struct {
    seq: u16,
    ts: u32,
    arrival_us: u64,
    payload: []u8,

    pub fn deinit(self: Frame, allocator: std.mem.Allocator) void {
        allocator.free(self.payload);
    }
};

const StoredFrame = struct {
    ext_seq: i64,
    ext_ts: i128,
    frame: Frame,
};

pub const JitterBuffer = struct {
    allocator: std.mem.Allocator,
    config: Config,
    frames: std.ArrayList(StoredFrame) = .empty,
    stats_data: Stats = .{},
    target_delay_us: u64,
    jitter_us: u64 = 0,
    base_arrival_us: ?u64 = null,
    base_ext_ts: ?i128 = null,
    max_ext_seq: ?i64 = null,
    last_ext_ts: ?i128 = null,
    prev_transit_us: ?i128 = null,
    next_pop_seq: ?i64 = null,

    pub fn init(allocator: std.mem.Allocator, config: Config) JitterBuffer {
        std.debug.assert(config.clock_rate_hz > 0);
        std.debug.assert(config.max_delay_us >= config.min_delay_us);
        std.debug.assert(config.max_delay_us >= config.initial_delay_us);

        return .{
            .allocator = allocator,
            .config = config,
            .target_delay_us = @max(config.initial_delay_us, config.min_delay_us),
        };
    }

    pub fn deinit(self: *JitterBuffer) void {
        for (self.frames.items) |stored| {
            stored.frame.deinit(self.allocator);
        }
        self.frames.deinit(self.allocator);
        self.* = undefined;
    }

    /// Push a packet into the buffer.
    ///
    /// Returns `true` when the payload was accepted and copied. Returns `false`
    /// when the packet was duplicate or too late to ever play.
    pub fn push(
        self: *JitterBuffer,
        seq: u16,
        ts: u32,
        now_us: u64,
        payload: []const u8,
    ) std.mem.Allocator.Error!bool {
        const ext_seq = self.extendSeq(seq);
        const ext_ts = self.extendTimestamp(ts);

        for (self.frames.items) |stored| {
            if (stored.ext_seq == ext_seq) return false;
        }

        if (self.next_pop_seq) |next| {
            if (ext_seq < next) {
                self.stats_data.late += 1;
                return false;
            }
        }

        if (self.base_arrival_us == null) {
            self.base_arrival_us = now_us;
            self.base_ext_ts = ext_ts;
        }

        if (self.playoutTimeUs(ext_ts) <= @as(i128, now_us)) {
            self.stats_data.late += 1;
            return false;
        }

        self.updateJitter(ext_ts, now_us);

        const copied = try self.allocator.dupe(u8, payload);
        errdefer self.allocator.free(copied);

        const stored = StoredFrame{
            .ext_seq = ext_seq,
            .ext_ts = ext_ts,
            .frame = .{
                .seq = seq,
                .ts = ts,
                .arrival_us = now_us,
                .payload = copied,
            },
        };

        try self.insertSorted(stored);
        self.max_ext_seq = maxOptionalI64(self.max_ext_seq, ext_seq);
        self.last_ext_ts = ext_ts;
        self.stats_data.buffered = self.frames.items.len;
        return true;
    }

    /// Pop the earliest timestamped frame whose adaptive playout time has
    /// elapsed. The returned payload is owned by the caller.
    pub fn pop(self: *JitterBuffer, now_us: u64) ?Frame {
        if (self.frames.items.len == 0) return null;
        const head = self.frames.items[0];
        if (self.playoutTimeUs(head.ext_ts) > @as(i128, now_us)) return null;

        const stored = self.frames.orderedRemove(0);
        self.recordLossBefore(stored.ext_seq);
        self.stats_data.buffered = self.frames.items.len;
        return stored.frame;
    }

    pub fn stats(self: JitterBuffer) Stats {
        return .{
            .late = self.stats_data.late,
            .lost = self.stats_data.lost,
            .buffered = self.frames.items.len,
        };
    }

    pub fn targetDelayUs(self: JitterBuffer) u64 {
        return self.target_delay_us;
    }

    pub fn estimatedJitterUs(self: JitterBuffer) u64 {
        return self.jitter_us;
    }

    fn insertSorted(self: *JitterBuffer, stored: StoredFrame) std.mem.Allocator.Error!void {
        var index: usize = 0;
        while (index < self.frames.items.len) : (index += 1) {
            const item = self.frames.items[index];
            if (stored.ext_ts < item.ext_ts or
                (stored.ext_ts == item.ext_ts and stored.ext_seq < item.ext_seq))
            {
                break;
            }
        }

        try self.frames.insert(self.allocator, index, stored);
    }

    fn recordLossBefore(self: *JitterBuffer, ext_seq: i64) void {
        if (self.next_pop_seq) |next| {
            if (ext_seq > next) {
                self.stats_data.lost += @intCast(ext_seq - next);
            }
        }
        self.next_pop_seq = ext_seq + 1;
    }

    fn updateJitter(self: *JitterBuffer, ext_ts: i128, now_us: u64) void {
        const base_ts = self.base_ext_ts orelse ext_ts;
        const media_us = timestampDeltaUs(ext_ts - base_ts, self.config.clock_rate_hz);
        const transit = @as(i128, now_us) - media_us;

        if (self.prev_transit_us) |prev| {
            const d = absI128(transit - prev);
            self.jitter_us = @intCast((@as(u128, self.jitter_us) * 15 + d + 8) / 16);
            self.updateTargetDelay();
        }

        self.prev_transit_us = transit;
    }

    fn updateTargetDelay(self: *JitterBuffer) void {
        const adaptive = saturatingAdd(self.config.min_delay_us, saturatingMul(self.jitter_us, 4));
        self.target_delay_us = clampU64(
            @max(self.config.initial_delay_us, adaptive),
            self.config.min_delay_us,
            self.config.max_delay_us,
        );
    }

    fn playoutTimeUs(self: JitterBuffer, ext_ts: i128) i128 {
        const base_arrival = self.base_arrival_us orelse 0;
        const base_ts = self.base_ext_ts orelse ext_ts;
        return @as(i128, base_arrival) +
            @as(i128, self.target_delay_us) +
            timestampDeltaUs(ext_ts - base_ts, self.config.clock_rate_hz);
    }

    fn extendSeq(self: JitterBuffer, seq: u16) i64 {
        const reference = self.max_ext_seq orelse @as(i64, seq);
        return unwrap16(seq, reference);
    }

    fn extendTimestamp(self: JitterBuffer, ts: u32) i128 {
        const reference = self.last_ext_ts orelse self.base_ext_ts orelse @as(i128, ts);
        return unwrap32(ts, reference);
    }
};

fn timestampDeltaUs(delta_ts: i128, clock_rate_hz: u32) i128 {
    return @divTrunc(delta_ts * @as(i128, us_per_second), @as(i128, clock_rate_hz));
}

fn unwrap16(value: u16, reference: i64) i64 {
    const low = @mod(reference, seq_modulus);
    var candidate = reference + (@as(i64, value) - low);
    if (candidate - reference > seq_modulus / 2) candidate -= seq_modulus;
    if (reference - candidate > seq_modulus / 2) candidate += seq_modulus;
    return candidate;
}

fn unwrap32(value: u32, reference: i128) i128 {
    const low = @mod(reference, ts_modulus);
    var candidate = reference + (@as(i128, value) - low);
    if (candidate - reference > ts_modulus / 2) candidate -= ts_modulus;
    if (reference - candidate > ts_modulus / 2) candidate += ts_modulus;
    return candidate;
}

fn absI128(value: i128) u128 {
    return if (value < 0) @intCast(-value) else @intCast(value);
}

fn maxOptionalI64(current: ?i64, value: i64) ?i64 {
    if (current) |existing| return @max(existing, value);
    return value;
}

fn saturatingAdd(a: u64, b: u64) u64 {
    return a +| b;
}

fn saturatingMul(a: u64, b: u64) u64 {
    return a *| b;
}

fn clampU64(value: u64, min_value: u64, max_value: u64) u64 {
    return @min(@max(value, min_value), max_value);
}

const testing = std.testing;

fn defaultTestConfig() Config {
    return .{
        .clock_rate_hz = 48_000,
        .min_delay_us = 50_000,
        .initial_delay_us = 50_000,
        .max_delay_us = 250_000,
    };
}

fn expectFrame(frame: Frame, seq: u16, ts: u32, payload: []const u8) !void {
    defer frame.deinit(testing.allocator);
    try testing.expectEqual(seq, frame.seq);
    try testing.expectEqual(ts, frame.ts);
    try testing.expectEqualSlices(u8, payload, frame.payload);
}

test "in-order playout after target delay" {
    var jb = JitterBuffer.init(testing.allocator, defaultTestConfig());
    defer jb.deinit();

    try testing.expect(try jb.push(1, 0, 0, "a"));
    try testing.expect(try jb.push(2, 960, 20_000, "b"));
    try testing.expectEqual(@as(usize, 2), jb.stats().buffered);

    try testing.expectEqual(@as(?Frame, null), jb.pop(49_999));
    try expectFrame(jb.pop(50_000).?, 1, 0, "a");
    try testing.expectEqual(@as(?Frame, null), jb.pop(69_999));
    try expectFrame(jb.pop(70_000).?, 2, 960, "b");
    try testing.expectEqual(@as(usize, 0), jb.stats().buffered);
}

test "reorders within the window" {
    var jb = JitterBuffer.init(testing.allocator, defaultTestConfig());
    defer jb.deinit();

    try testing.expect(try jb.push(10, 0, 0, "zero"));
    try testing.expect(try jb.push(12, 1_920, 15_000, "two"));
    try testing.expect(try jb.push(11, 960, 25_000, "one"));

    try expectFrame(jb.pop(200_000).?, 10, 0, "zero");
    try expectFrame(jb.pop(200_000).?, 11, 960, "one");
    try expectFrame(jb.pop(200_000).?, 12, 1_920, "two");
    try testing.expectEqual(@as(u64, 0), jb.stats().lost);
}

test "late frame dropped and counted" {
    var jb = JitterBuffer.init(testing.allocator, defaultTestConfig());
    defer jb.deinit();

    try testing.expect(try jb.push(100, 0, 0, "first"));
    try expectFrame(jb.pop(50_000).?, 100, 0, "first");
    try testing.expect(!(try jb.push(101, 960, 80_000, "late")));
    try testing.expect(try jb.push(102, 1_920, 80_000, "third"));

    const stats_after_late = jb.stats();
    try testing.expectEqual(@as(u64, 1), stats_after_late.late);
    try testing.expectEqual(@as(u64, 0), stats_after_late.lost);

    try expectFrame(jb.pop(100_000).?, 102, 1_920, "third");
    try testing.expectEqual(@as(u64, 1), jb.stats().lost);
}

test "adapts delay up under high jitter" {
    var jb = JitterBuffer.init(testing.allocator, .{
        .clock_rate_hz = 48_000,
        .min_delay_us = 80_000,
        .initial_delay_us = 80_000,
        .max_delay_us = 250_000,
    });
    defer jb.deinit();

    try testing.expect(try jb.push(1, 0, 0, "a"));
    try testing.expect(try jb.push(2, 960, 80_000, "b"));
    try testing.expect(try jb.push(3, 1_920, 130_000, "c"));

    try testing.expect(jb.estimatedJitterUs() > 0);
    try testing.expect(jb.targetDelayUs() > 80_000);
    try testing.expect(jb.targetDelayUs() <= 250_000);
}

test "sequence and timestamp wrap" {
    var jb = JitterBuffer.init(testing.allocator, defaultTestConfig());
    defer jb.deinit();

    const ts0: u32 = 0xffff_ff00;
    const ts1: u32 = ts0 +% 960;
    const ts2: u32 = ts1 +% 960;

    try testing.expect(try jb.push(0xfffe, ts0, 0, "a"));
    try testing.expect(try jb.push(0xffff, ts1, 20_000, "b"));
    try testing.expect(try jb.push(0x0000, ts2, 40_000, "c"));

    try expectFrame(jb.pop(50_000).?, 0xfffe, ts0, "a");
    try expectFrame(jb.pop(70_000).?, 0xffff, ts1, "b");
    try expectFrame(jb.pop(90_000).?, 0x0000, ts2, "c");
    try testing.expectEqual(@as(u64, 0), jb.stats().lost);
}

test "deterministic results for identical inputs" {
    var a = JitterBuffer.init(testing.allocator, defaultTestConfig());
    defer a.deinit();
    var b = JitterBuffer.init(testing.allocator, defaultTestConfig());
    defer b.deinit();

    const seqs = [_]u16{ 7, 9, 8, 10 };
    const tss = [_]u32{ 0, 1_920, 960, 2_880 };
    const arrivals = [_]u64{ 0, 15_000, 25_000, 45_000 };
    const payloads = [_][]const u8{ "a", "c", "b", "d" };

    for (seqs, tss, arrivals, payloads) |seq, ts, now, payload| {
        try testing.expectEqual(try a.push(seq, ts, now, payload), try b.push(seq, ts, now, payload));
    }

    try testing.expectEqual(a.targetDelayUs(), b.targetDelayUs());
    try testing.expectEqual(a.estimatedJitterUs(), b.estimatedJitterUs());
    try testing.expectEqual(a.stats(), b.stats());

    while (a.pop(200_000)) |fa| {
        const fb = b.pop(200_000).?;
        defer fb.deinit(testing.allocator);
        try expectFrame(fa, fb.seq, fb.ts, fb.payload);
    }
    try testing.expectEqual(@as(?Frame, null), b.pop(200_000));
    try testing.expectEqual(a.stats(), b.stats());
}

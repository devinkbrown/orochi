//! RTP-like media transport profile helpers for Orochi media bands.
//!
//! This module deliberately does not own sockets or scheduling. It provides the
//! byte-level packet header, RFC 3550-style jitter/loss accounting, and a small
//! RTCP-like SR/RR report format suitable for embedding inside Orochi media
//! frames.
const std = @import("std");

pub const header_len: usize = 12;
pub const rtcp_sender_report_len: usize = 28;
pub const rtcp_receiver_report_len: usize = 32;
pub const rtp_version: u2 = 2;

const endian = .big;

pub const WireError = error{
    BufferTooSmall,
    Truncated,
    InvalidVersion,
    InvalidRtcpType,
    InvalidRtcpLength,
    InvalidReportCount,
    ValueOutOfRange,
};

pub const Header = struct {
    version: u2 = rtp_version,
    marker: bool = false,
    payload_type: u7,
    sequence: u16,
    timestamp: u32,
    ssrc: u32,
};

pub const Packet = struct {
    header: Header,
    payload: []const u8,
};

pub const DecodedHeader = struct {
    header: Header,
    len: usize = header_len,
};

pub const DecodedPacket = struct {
    packet: Packet,
    len: usize,
};

pub fn encodedPacketLen(payload_len: usize) WireError!usize {
    if (payload_len > std.math.maxInt(usize) - header_len) return error.ValueOutOfRange;
    return header_len + payload_len;
}

pub fn encodeHeader(header: Header, out: []u8) WireError![]const u8 {
    if (out.len < header_len) return error.BufferTooSmall;

    out[0] = @as(u8, header.version) << 6;
    out[1] = (@as(u8, if (header.marker) 0x80 else 0x00)) | @as(u8, header.payload_type);
    std.mem.writeInt(u16, out[2..4], header.sequence, endian);
    std.mem.writeInt(u32, out[4..8], header.timestamp, endian);
    std.mem.writeInt(u32, out[8..12], header.ssrc, endian);

    return out[0..header_len];
}

pub fn decodeHeader(input: []const u8) WireError!DecodedHeader {
    if (input.len < header_len) return error.Truncated;

    const version: u2 = @intCast(input[0] >> 6);
    if (version != rtp_version) return error.InvalidVersion;

    return .{
        .header = .{
            .version = version,
            .marker = (input[1] & 0x80) != 0,
            .payload_type = @intCast(input[1] & 0x7f),
            .sequence = std.mem.readInt(u16, input[2..4], endian),
            .timestamp = std.mem.readInt(u32, input[4..8], endian),
            .ssrc = std.mem.readInt(u32, input[8..12], endian),
        },
    };
}

pub fn encodePacket(packet: Packet, out: []u8) WireError![]const u8 {
    const total = try encodedPacketLen(packet.payload.len);
    if (out.len < total) return error.BufferTooSmall;

    _ = try encodeHeader(packet.header, out[0..header_len]);
    @memcpy(out[header_len..total], packet.payload);
    return out[0..total];
}

pub fn decodePacket(input: []const u8) WireError!DecodedPacket {
    const decoded = try decodeHeader(input);
    return .{
        .packet = .{
            .header = decoded.header,
            .payload = input[header_len..],
        },
        .len = input.len,
    };
}

pub const JitterEstimator = struct {
    initialized: bool = false,
    previous_transit: i64 = 0,
    jitter: f64 = 0.0,

    /// Updates interarrival jitter. `arrival_timestamp_units` must use the same
    /// media clock as the RTP timestamp.
    pub fn update(self: *JitterEstimator, timestamp: u32, arrival_timestamp_units: i64) f64 {
        const transit = arrival_timestamp_units - @as(i64, timestamp);
        if (!self.initialized) {
            self.initialized = true;
            self.previous_transit = transit;
            return self.jitter;
        }

        const delta = transit - self.previous_transit;
        self.previous_transit = transit;
        const abs_delta = if (delta < 0) -delta else delta;
        const d: f64 = @floatFromInt(abs_delta);
        self.jitter += (d - self.jitter) / 16.0;
        return self.jitter;
    }

    pub fn reset(self: *JitterEstimator) void {
        self.* = .{};
    }

    pub fn estimate(self: JitterEstimator) f64 {
        return self.jitter;
    }

    pub fn estimateRounded(self: JitterEstimator) u32 {
        if (self.jitter <= 0.0) return 0;
        if (self.jitter >= @as(f64, @floatFromInt(std.math.maxInt(u32)))) return std.math.maxInt(u32);
        return @intFromFloat(self.jitter + 0.5);
    }
};

pub const ReceiverStats = struct {
    expected: u32,
    received: u32,
    cumulative_lost: i32,
    fraction_lost: u8,
    highest_seq_with_cycles: u32,
};

pub const ReceiverStatsTracker = struct {
    initialized: bool = false,
    base_seq: u16 = 0,
    max_seq: u16 = 0,
    cycles: u32 = 0,
    received: u32 = 0,
    expected_prior: u32 = 0,
    received_prior: u32 = 0,

    pub fn observe(self: *ReceiverStatsTracker, sequence: u16) void {
        if (!self.initialized) {
            self.initialized = true;
            self.base_seq = sequence;
            self.max_seq = sequence;
            self.received = 1;
            return;
        }

        if (sequence < self.max_seq) {
            const backward = @as(u32, self.max_seq) - @as(u32, sequence);
            if (backward > 0x8000) {
                self.cycles = std.math.add(u32, self.cycles, 1 << 16) catch std.math.maxInt(u32);
                self.max_seq = sequence;
            }
        } else if (sequence > self.max_seq) {
            const forward = @as(u32, sequence) - @as(u32, self.max_seq);
            if (forward < 0x8000) self.max_seq = sequence;
        }

        self.received = std.math.add(u32, self.received, 1) catch std.math.maxInt(u32);
    }

    pub fn highestSeqWithCycles(self: ReceiverStatsTracker) u32 {
        if (!self.initialized) return 0;
        return self.cycles + @as(u32, self.max_seq);
    }

    pub fn expected(self: ReceiverStatsTracker) u32 {
        if (!self.initialized) return 0;
        return self.highestSeqWithCycles() - @as(u32, self.base_seq) + 1;
    }

    pub fn cumulativeLost(self: ReceiverStatsTracker) i32 {
        return @as(i32, @intCast(self.expected())) - @as(i32, @intCast(self.received));
    }

    pub fn fractionLost(self: ReceiverStatsTracker) u8 {
        const expected_now = self.expected();
        const expected_interval = expected_now - self.expected_prior;
        const received_interval = self.received - self.received_prior;
        if (expected_interval == 0 or received_interval >= expected_interval) return 0;

        const lost_interval = expected_interval - received_interval;
        return @intCast((lost_interval << 8) / expected_interval);
    }

    pub fn snapshot(self: ReceiverStatsTracker) ReceiverStats {
        return .{
            .expected = self.expected(),
            .received = self.received,
            .cumulative_lost = self.cumulativeLost(),
            .fraction_lost = self.fractionLost(),
            .highest_seq_with_cycles = self.highestSeqWithCycles(),
        };
    }

    pub fn markReported(self: *ReceiverStatsTracker) void {
        self.expected_prior = self.expected();
        self.received_prior = self.received;
    }

    pub fn makeReportBlock(
        self: *ReceiverStatsTracker,
        source_ssrc: u32,
        jitter: u32,
        lsr: u32,
        dlsr: u32,
    ) ReportBlock {
        const stats = self.snapshot();
        self.markReported();
        return .{
            .ssrc = source_ssrc,
            .fraction_lost = stats.fraction_lost,
            .cumulative_lost = stats.cumulative_lost,
            .highest_seq_with_cycles = stats.highest_seq_with_cycles,
            .jitter = jitter,
            .lsr = lsr,
            .dlsr = dlsr,
        };
    }

    pub fn reset(self: *ReceiverStatsTracker) void {
        self.* = .{};
    }
};

pub const SenderReport = struct {
    ssrc: u32,
    ntp_timestamp: u64,
    rtp_timestamp: u32,
    packet_count: u32,
    octet_count: u32,
};

pub const ReportBlock = struct {
    ssrc: u32,
    fraction_lost: u8,
    cumulative_lost: i32,
    highest_seq_with_cycles: u32,
    jitter: u32,
    lsr: u32 = 0,
    dlsr: u32 = 0,
};

pub const ReceiverReport = struct {
    reporter_ssrc: u32,
    report: ReportBlock,
};

pub const DecodedSenderReport = struct {
    report: SenderReport,
    len: usize = rtcp_sender_report_len,
};

pub const DecodedReceiverReport = struct {
    report: ReceiverReport,
    len: usize = rtcp_receiver_report_len,
};

pub fn buildSenderReport(report: SenderReport, out: []u8) WireError![]const u8 {
    if (out.len < rtcp_sender_report_len) return error.BufferTooSmall;

    writeRtcpHeader(out[0..4], 0, 200, rtcp_sender_report_len);
    std.mem.writeInt(u32, out[4..8], report.ssrc, endian);
    std.mem.writeInt(u64, out[8..16], report.ntp_timestamp, endian);
    std.mem.writeInt(u32, out[16..20], report.rtp_timestamp, endian);
    std.mem.writeInt(u32, out[20..24], report.packet_count, endian);
    std.mem.writeInt(u32, out[24..28], report.octet_count, endian);
    return out[0..rtcp_sender_report_len];
}

pub fn parseSenderReport(input: []const u8) WireError!DecodedSenderReport {
    try expectRtcpHeader(input, 0, 200, rtcp_sender_report_len);
    return .{
        .report = .{
            .ssrc = std.mem.readInt(u32, input[4..8], endian),
            .ntp_timestamp = std.mem.readInt(u64, input[8..16], endian),
            .rtp_timestamp = std.mem.readInt(u32, input[16..20], endian),
            .packet_count = std.mem.readInt(u32, input[20..24], endian),
            .octet_count = std.mem.readInt(u32, input[24..28], endian),
        },
    };
}

pub fn buildReceiverReport(report: ReceiverReport, out: []u8) WireError![]const u8 {
    if (out.len < rtcp_receiver_report_len) return error.BufferTooSmall;

    writeRtcpHeader(out[0..4], 1, 201, rtcp_receiver_report_len);
    std.mem.writeInt(u32, out[4..8], report.reporter_ssrc, endian);
    writeReportBlock(report.report, out[8..32]) catch |err| return err;
    return out[0..rtcp_receiver_report_len];
}

pub fn parseReceiverReport(input: []const u8) WireError!DecodedReceiverReport {
    try expectRtcpHeader(input, 1, 201, rtcp_receiver_report_len);
    return .{
        .report = .{
            .reporter_ssrc = std.mem.readInt(u32, input[4..8], endian),
            .report = readReportBlock(input[8..32]),
        },
    };
}

fn writeRtcpHeader(out: []u8, count: u5, packet_type: u8, total_len: usize) void {
    std.debug.assert(out.len >= 4);
    std.debug.assert(total_len % 4 == 0);
    out[0] = (@as(u8, rtp_version) << 6) | @as(u8, count);
    out[1] = packet_type;
    std.mem.writeInt(u16, out[2..4], @intCast((total_len / 4) - 1), endian);
}

fn expectRtcpHeader(input: []const u8, count: u5, packet_type: u8, total_len: usize) WireError!void {
    if (input.len < 4) return error.Truncated;

    const version: u2 = @intCast(input[0] >> 6);
    if (version != rtp_version) return error.InvalidVersion;
    if ((input[0] & 0x20) != 0) return error.InvalidRtcpLength;
    if ((input[0] & 0x1f) != @as(u8, count)) return error.InvalidReportCount;
    if (input[1] != packet_type) return error.InvalidRtcpType;

    const words_minus_one = std.mem.readInt(u16, input[2..4], endian);
    const actual_total = (@as(usize, words_minus_one) + 1) * 4;
    if (actual_total != total_len) return error.InvalidRtcpLength;
    if (input.len < actual_total) return error.Truncated;
}

fn writeReportBlock(block: ReportBlock, out: []u8) WireError!void {
    std.debug.assert(out.len >= 24);
    std.mem.writeInt(u32, out[0..4], block.ssrc, endian);
    out[4] = block.fraction_lost;
    writeI24(block.cumulative_lost, out[5..8]) catch |err| return err;
    std.mem.writeInt(u32, out[8..12], block.highest_seq_with_cycles, endian);
    std.mem.writeInt(u32, out[12..16], block.jitter, endian);
    std.mem.writeInt(u32, out[16..20], block.lsr, endian);
    std.mem.writeInt(u32, out[20..24], block.dlsr, endian);
}

fn readReportBlock(input: []const u8) ReportBlock {
    std.debug.assert(input.len >= 24);
    return .{
        .ssrc = std.mem.readInt(u32, input[0..4], endian),
        .fraction_lost = input[4],
        .cumulative_lost = readI24(input[5..8]),
        .highest_seq_with_cycles = std.mem.readInt(u32, input[8..12], endian),
        .jitter = std.mem.readInt(u32, input[12..16], endian),
        .lsr = std.mem.readInt(u32, input[16..20], endian),
        .dlsr = std.mem.readInt(u32, input[20..24], endian),
    };
}

fn writeI24(value: i32, out: []u8) WireError!void {
    if (value < -0x800000 or value > 0x7fffff) return error.ValueOutOfRange;

    const raw: u32 = if (value < 0)
        @intCast(0x1000000 + value)
    else
        @intCast(value);
    out[0] = @intCast((raw >> 16) & 0xff);
    out[1] = @intCast((raw >> 8) & 0xff);
    out[2] = @intCast(raw & 0xff);
}

fn readI24(input: []const u8) i32 {
    const raw = (@as(u32, input[0]) << 16) | (@as(u32, input[1]) << 8) | @as(u32, input[2]);
    if ((raw & 0x800000) != 0) return @as(i32, @intCast(raw)) - 0x1000000;
    return @intCast(raw);
}

const testing = std.testing;

test "header round-trip" {
    const header = Header{
        .marker = true,
        .payload_type = 111,
        .sequence = 0xabcd,
        .timestamp = 0x10203040,
        .ssrc = 0xaabbccdd,
    };

    var buf: [header_len]u8 = undefined;
    const encoded = try encodeHeader(header, &buf);
    try testing.expectEqual(@as(usize, header_len), encoded.len);
    try testing.expectEqual(@as(u8, 0x80), encoded[0]);
    try testing.expectEqual(@as(u8, 0xef), encoded[1]);

    const decoded = try decodeHeader(encoded);
    try testing.expectEqual(header.version, decoded.header.version);
    try testing.expectEqual(header.marker, decoded.header.marker);
    try testing.expectEqual(header.payload_type, decoded.header.payload_type);
    try testing.expectEqual(header.sequence, decoded.header.sequence);
    try testing.expectEqual(header.timestamp, decoded.header.timestamp);
    try testing.expectEqual(header.ssrc, decoded.header.ssrc);
}

test "packet framing round-trip preserves payload slice" {
    const payload = "orochi-media";
    const packet = Packet{
        .header = .{
            .marker = false,
            .payload_type = 96,
            .sequence = 42,
            .timestamp = 9000,
            .ssrc = 0x01020304,
        },
        .payload = payload,
    };

    var buf: [header_len + payload.len]u8 = undefined;
    const encoded = try encodePacket(packet, &buf);
    const decoded = try decodePacket(encoded);

    try testing.expectEqual(packet.header.sequence, decoded.packet.header.sequence);
    try testing.expectEqual(packet.header.timestamp, decoded.packet.header.timestamp);
    try testing.expectEqual(packet.header.ssrc, decoded.packet.header.ssrc);
    try testing.expectEqualSlices(u8, payload, decoded.packet.payload);
    try testing.expectEqual(encoded.len, decoded.len);
}

test "sequence-number cycle handling in expected math" {
    var tracker = ReceiverStatsTracker{};
    tracker.observe(65534);
    tracker.observe(65535);
    tracker.observe(0);
    tracker.observe(1);

    const stats = tracker.snapshot();
    try testing.expectEqual(@as(u32, 65537), stats.highest_seq_with_cycles);
    try testing.expectEqual(@as(u32, 4), stats.expected);
    try testing.expectEqual(@as(u32, 4), stats.received);
    try testing.expectEqual(@as(i32, 0), stats.cumulative_lost);
    try testing.expectEqual(@as(u8, 0), stats.fraction_lost);
}

test "jitter estimate follows RFC 3550 recurrence" {
    var jitter = JitterEstimator{};

    _ = jitter.update(0, 0);
    _ = jitter.update(160, 170);
    _ = jitter.update(320, 350);
    const estimate = jitter.update(480, 520);

    try testing.expectApproxEqAbs(@as(f64, 2.34619140625), estimate, 0.0000000001);
    try testing.expectApproxEqAbs(estimate, jitter.estimate(), 0.0);
}

test "fraction-lost and cumulative-loss under drops" {
    var tracker = ReceiverStatsTracker{};
    tracker.observe(10);
    tracker.observe(11);
    tracker.observe(13);
    tracker.observe(14);

    const stats = tracker.snapshot();
    try testing.expectEqual(@as(u32, 5), stats.expected);
    try testing.expectEqual(@as(u32, 4), stats.received);
    try testing.expectEqual(@as(i32, 1), stats.cumulative_lost);
    try testing.expectEqual(@as(u8, 51), stats.fraction_lost);

    tracker.markReported();
    tracker.observe(15);
    const next = tracker.snapshot();
    try testing.expectEqual(@as(u8, 0), next.fraction_lost);
    try testing.expectEqual(@as(i32, 1), next.cumulative_lost);
}

test "sender report round-trip" {
    const report = SenderReport{
        .ssrc = 0x11223344,
        .ntp_timestamp = 0x0102030405060708,
        .rtp_timestamp = 0x99aabbcc,
        .packet_count = 1234,
        .octet_count = 5678,
    };

    var buf: [rtcp_sender_report_len]u8 = undefined;
    const encoded = try buildSenderReport(report, &buf);
    try testing.expectEqual(@as(u8, 0x80), encoded[0]);
    try testing.expectEqual(@as(u8, 200), encoded[1]);
    try testing.expectEqual(@as(u16, 6), std.mem.readInt(u16, encoded[2..4], endian));

    const decoded = try parseSenderReport(encoded);
    try testing.expectEqual(report.ssrc, decoded.report.ssrc);
    try testing.expectEqual(report.ntp_timestamp, decoded.report.ntp_timestamp);
    try testing.expectEqual(report.rtp_timestamp, decoded.report.rtp_timestamp);
    try testing.expectEqual(report.packet_count, decoded.report.packet_count);
    try testing.expectEqual(report.octet_count, decoded.report.octet_count);
}

test "receiver report round-trip" {
    const report = ReceiverReport{
        .reporter_ssrc = 0xfeedbeef,
        .report = .{
            .ssrc = 0x01020304,
            .fraction_lost = 64,
            .cumulative_lost = -3,
            .highest_seq_with_cycles = 0x0001fffe,
            .jitter = 77,
            .lsr = 0x10203040,
            .dlsr = 0x50607080,
        },
    };

    var buf: [rtcp_receiver_report_len]u8 = undefined;
    const encoded = try buildReceiverReport(report, &buf);
    try testing.expectEqual(@as(u8, 0x81), encoded[0]);
    try testing.expectEqual(@as(u8, 201), encoded[1]);
    try testing.expectEqual(@as(u16, 7), std.mem.readInt(u16, encoded[2..4], endian));

    const decoded = try parseReceiverReport(encoded);
    try testing.expectEqual(report.reporter_ssrc, decoded.report.reporter_ssrc);
    try testing.expectEqual(report.report.ssrc, decoded.report.report.ssrc);
    try testing.expectEqual(report.report.fraction_lost, decoded.report.report.fraction_lost);
    try testing.expectEqual(report.report.cumulative_lost, decoded.report.report.cumulative_lost);
    try testing.expectEqual(report.report.highest_seq_with_cycles, decoded.report.report.highest_seq_with_cycles);
    try testing.expectEqual(report.report.jitter, decoded.report.report.jitter);
    try testing.expectEqual(report.report.lsr, decoded.report.report.lsr);
    try testing.expectEqual(report.report.dlsr, decoded.report.report.dlsr);
}

test "stats tracker builds receiver report block" {
    var tracker = ReceiverStatsTracker{};
    tracker.observe(100);
    tracker.observe(101);
    tracker.observe(103);

    const block = tracker.makeReportBlock(0xa0b0c0d0, 19, 1, 2);
    try testing.expectEqual(@as(u32, 0xa0b0c0d0), block.ssrc);
    try testing.expectEqual(@as(u8, 64), block.fraction_lost);
    try testing.expectEqual(@as(i32, 1), block.cumulative_lost);
    try testing.expectEqual(@as(u32, 103), block.highest_seq_with_cycles);
    try testing.expectEqual(@as(u32, 19), block.jitter);

    tracker.observe(104);
    try testing.expectEqual(@as(u8, 0), tracker.snapshot().fraction_lost);
}

test "truncation and validation errors are deterministic" {
    var header_buf: [header_len - 1]u8 = undefined;
    try testing.expectError(error.Truncated, decodeHeader(&header_buf));

    var packet_buf: [header_len]u8 = undefined;
    const bad_header = Header{ .payload_type = 1, .sequence = 1, .timestamp = 1, .ssrc = 1 };
    _ = try encodeHeader(bad_header, &packet_buf);
    packet_buf[0] = 0x40;
    try testing.expectError(error.InvalidVersion, decodeHeader(&packet_buf));

    var sr_buf: [rtcp_sender_report_len]u8 = undefined;
    const sr = SenderReport{ .ssrc = 1, .ntp_timestamp = 2, .rtp_timestamp = 3, .packet_count = 4, .octet_count = 5 };
    _ = try buildSenderReport(sr, &sr_buf);
    try testing.expectError(error.Truncated, parseSenderReport(sr_buf[0 .. rtcp_sender_report_len - 1]));

    sr_buf[1] = 201;
    try testing.expectError(error.InvalidRtcpType, parseSenderReport(&sr_buf));

    var small_out: [rtcp_receiver_report_len - 1]u8 = undefined;
    const rr = ReceiverReport{
        .reporter_ssrc = 1,
        .report = .{
            .ssrc = 2,
            .fraction_lost = 0,
            .cumulative_lost = 0x800000,
            .highest_seq_with_cycles = 3,
            .jitter = 4,
        },
    };
    try testing.expectError(error.BufferTooSmall, buildReceiverReport(rr, &small_out));

    var full_out: [rtcp_receiver_report_len]u8 = undefined;
    try testing.expectError(error.ValueOutOfRange, buildReceiverReport(rr, &full_out));
}

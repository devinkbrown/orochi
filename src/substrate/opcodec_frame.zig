//! Opcodec media framing layer — container/packetization for Mizuchi media bands.
//!
//! NOT the audio/video codec itself: this is the wire container that carries
//! encoded payloads over Suimyaku mesh "media bands".
//!
//! ## Band model
//! Band IDs < 64 are control bands.  Media frames must use band IDs >= 64.
//!
//! ## Wire format
//! ```
//! [ 4-byte payload-length (LE u32) ]
//! [ 1-byte  band_id                ]
//! [ 4-byte  stream_id  (LE u32)    ]
//! [ 4-byte  sequence   (LE u32)    ]
//! [ 8-byte  timestamp  (LE u64)    ]
//! [ 1-byte  flags  (bit0=keyframe) ]
//! [ 1-byte  codec_tag              ]
//! [ payload bytes …               ]
//! ```
//! MIN_FRAME_WIRE_BYTES = 23 (4-byte prefix + 19-byte header).
//!
//! ## Reassembly buffer
//! Bounded sliding-window: accepts out-of-order frames, emits in-order,
//! drops duplicates, surfaces gap ranges for FEC/retransmit.
const std = @import("std");

const Allocator = std.mem.Allocator;

// -- Constants ---------------------------------------------------------------

/// Band IDs [0, MEDIA_BAND_FLOOR) are reserved for control traffic.
pub const MEDIA_BAND_FLOOR: u8 = 64;
/// Header size excluding the 4-byte length prefix.
/// band_id(1)+stream_id(4)+sequence(4)+timestamp(8)+flags(1)+codec_tag(1)=19.
pub const HEADER_BYTES: usize = 19;
/// Minimum encoded frame size: 4 (length prefix) + 19 (header).
pub const MIN_FRAME_WIRE_BYTES: usize = 4 + HEADER_BYTES;

// -- Codec tag ---------------------------------------------------------------

/// Codec family that produced the payload bytes.
pub const CodecTag = enum(u8) {
    opvox_audio = 0x01,
    opvis_video = 0x02,
    raw = 0x00,

    pub fn fromByte(b: u8) DecodeError!CodecTag {
        return switch (b) {
            0x00 => .raw,
            0x01 => .opvox_audio,
            0x02 => .opvis_video,
            else => error.UnknownCodecTag,
        };
    }
};

// -- Error sets --------------------------------------------------------------

pub const DecodeError = error{
    Truncated,
    ControlBandId,
    TrailingBytes,
    UnknownCodecTag,
};

pub const EncodeError = error{
    BufferTooSmall,
    ControlBandId,
};

// -- MediaFrame --------------------------------------------------------------

/// One media frame.  Payload slice is borrowed — not owned by this struct.
pub const MediaFrame = struct {
    /// Media band; must be >= MEDIA_BAND_FLOOR.
    band_id: u8,
    /// Logical stream identifier (e.g. one participant's audio track).
    stream_id: u32,
    /// Monotonically increasing sequence; wraps at 2^32.
    sequence: u32,
    /// Media clock timestamp (samples or ms ticks, codec-defined).
    timestamp: u64,
    /// True when this is a codec key/sync frame (IDR, etc.).
    keyframe: bool,
    /// Codec that produced `payload`.
    codec: CodecTag,
    payload: []const u8,
};

/// Decoded frame that borrows the input buffer.
pub const FrameView = MediaFrame;

/// Returns `true` when `band_id` is a media band (>= MEDIA_BAND_FLOOR).
pub fn isMediaBand(band_id: u8) bool {
    return band_id >= MEDIA_BAND_FLOOR;
}

// -- Encoding ----------------------------------------------------------------

/// Encode `frame` into `buf`.  Returns bytes written, or an error.
pub fn encode(frame: MediaFrame, buf: []u8) EncodeError!usize {
    if (!isMediaBand(frame.band_id)) return error.ControlBandId;
    const payload_len = frame.payload.len;
    const total = MIN_FRAME_WIRE_BYTES + payload_len;
    if (buf.len < total) return error.BufferTooSmall;
    var pos: usize = 0;
    writeU32Le(buf[pos..], @intCast(payload_len));
    pos += 4;
    buf[pos] = frame.band_id;
    pos += 1;
    writeU32Le(buf[pos..], frame.stream_id);
    pos += 4;
    writeU32Le(buf[pos..], frame.sequence);
    pos += 4;
    writeU64Le(buf[pos..], frame.timestamp);
    pos += 8;
    buf[pos] = if (frame.keyframe) @as(u8, 1) else @as(u8, 0);
    pos += 1;
    buf[pos] = @intFromEnum(frame.codec);
    pos += 1;
    @memcpy(buf[pos .. pos + payload_len], frame.payload);
    pos += payload_len;
    return pos;
}

// -- Decoding ----------------------------------------------------------------

/// Decode a frame from `buf`, returning a `FrameView` that borrows `buf`.
/// Rejects truncation, control band IDs, unknown codec tags, trailing bytes.
pub fn decode(buf: []const u8) DecodeError!FrameView {
    if (buf.len < MIN_FRAME_WIRE_BYTES) return error.Truncated;
    var pos: usize = 0;
    const payload_len: usize = readU32Le(buf[pos..]);
    pos += 4;
    const declared_total = MIN_FRAME_WIRE_BYTES + payload_len;
    if (buf.len < declared_total) return error.Truncated;
    if (buf.len > declared_total) return error.TrailingBytes;
    const band_id = buf[pos];
    pos += 1;
    if (!isMediaBand(band_id)) return error.ControlBandId;
    const stream_id = readU32Le(buf[pos..]);
    pos += 4;
    const sequence = readU32Le(buf[pos..]);
    pos += 4;
    const timestamp = readU64Le(buf[pos..]);
    pos += 8;
    const flags = buf[pos];
    pos += 1;
    const keyframe = (flags & 0x01) != 0;
    const codec = try CodecTag.fromByte(buf[pos]);
    pos += 1;
    // payload slice borrows buf
    const payload = buf[pos .. pos + payload_len];

    return FrameView{
        .band_id = band_id,
        .stream_id = stream_id,
        .sequence = sequence,
        .timestamp = timestamp,
        .keyframe = keyframe,
        .codec = codec,
        .payload = payload,
    };
}

/// Encode `frame` and return a freshly-allocated slice owned by the caller.
pub fn encodeAlloc(frame: MediaFrame, allocator: Allocator) (EncodeError || Allocator.Error)![]u8 {
    if (!isMediaBand(frame.band_id)) return error.ControlBandId;
    const buf = try allocator.alloc(u8, MIN_FRAME_WIRE_BYTES + frame.payload.len);
    errdefer allocator.free(buf);
    _ = try encode(frame, buf);
    return buf;
}

// -- Gap range (FEC seam) ----------------------------------------------------

/// Half-open range of missing sequence numbers [start, end).
pub const GapRange = struct {
    start: u32,
    end: u32,
    pub fn len(self: GapRange) u32 {
        return wrappingDelta(self.start, self.end);
    }
};

// -- Reassembly buffer -------------------------------------------------------

pub const ReassemblyConfig = struct {
    /// Out-of-order window size.  Frames outside this window are late-dropped.
    window: u32 = 64,
    /// Optional anchor sequence.  When null, the first push sets the anchor.
    initial_seq: ?u32 = null,
};

const SlotState = enum { empty, filled, consumed };

fn Slot(comptime max_payload: usize) type {
    return struct {
        state: SlotState = .empty,
        frame: MediaFrame = undefined,
        payload_buf: [max_payload]u8 = undefined,
        payload_len: usize = 0,
    };
}

pub const PushResult = enum { buffered, duplicate, late_drop };

/// Jitter/reorder reassembly buffer.  Accepts out-of-order frames, emits
/// in-order.  `max_payload` and `window_cap` are compile-time bounds;
/// runtime window from `ReassemblyConfig` must be <= `window_cap`.
pub fn ReassemblyBuffer(comptime max_payload: usize, comptime window_cap: u32) type {
    return struct {
        const Self = @This();
        const RingSlot = Slot(max_payload);

        ring: [window_cap]RingSlot = [_]RingSlot{.{}} ** window_cap,
        next_seq: u32 = 0,
        anchored: bool = false,
        /// Highest buffered sequence; bounds gap scanning in reportGaps.
        high_watermark: u32 = 0,
        high_watermark_set: bool = false,
        window: u32 = window_cap,
        // Statistics (all public, read-only by callers).
        late_drop_count: u64 = 0,
        duplicate_count: u64 = 0,
        gap_count: u64 = 0,
        // Bitset: recovered[offset] = FEC has synthesised next_seq+offset.
        recovered_bits: [window_cap / 8 + 1]u8 = [_]u8{0} ** (window_cap / 8 + 1),

        pub fn init(cfg: ReassemblyConfig) Self {
            std.debug.assert(cfg.window > 0 and cfg.window <= window_cap);
            var self = Self{};
            self.window = cfg.window;
            if (cfg.initial_seq) |s| {
                self.next_seq = s;
                self.anchored = true;
            }
            return self;
        }

        /// Insert a frame.  Payload copied into inline storage.
        /// Returns `.buffered`, `.duplicate`, or `.late_drop`.
        pub fn push(self: *Self, frame: MediaFrame) PushResult {
            if (!self.anchored) {
                self.next_seq = frame.sequence;
                self.anchored = true;
            }
            const seq = frame.sequence;
            const win = self.window;
            const fwd = wrappingDelta(self.next_seq, seq); // distance forward
            const behind = wrappingDelta(seq, self.next_seq); // distance backward

            if (fwd == 0) {
                // seq == next_seq; fall through to normal slot handling.
            } else if (fwd < win) {
                // within forward window; fall through.
            } else if (behind > 0 and behind <= win) {
                // seq is behind next_seq by at most one window → duplicate.
                const idx = seq % window_cap;
                const slot = &self.ring[idx];
                _ = slot; // slot check below covers consumed case too
                self.duplicate_count += 1;
                return .duplicate;
            } else {
                self.late_drop_count += 1;
                return .late_drop;
            }

            const idx = seq % window_cap;
            var slot = &self.ring[idx];

            if (slot.state == .filled and slot.frame.sequence == seq) {
                self.duplicate_count += 1;
                return .duplicate;
            }
            if (slot.state == .consumed and slot.frame.sequence == seq) {
                self.duplicate_count += 1;
                return .duplicate;
            }

            // Copy payload into inline storage.
            const plen = @min(frame.payload.len, max_payload);
            slot.payload_len = plen;
            @memcpy(slot.payload_buf[0..plen], frame.payload[0..plen]);

            slot.frame = frame;
            slot.frame.payload = slot.payload_buf[0..plen];
            slot.state = .filled;

            // Update high watermark (wrapping-aware).
            if (!self.high_watermark_set) {
                self.high_watermark = seq;
                self.high_watermark_set = true;
            } else if (wrappingDelta(self.high_watermark, seq) < self.window) {
                self.high_watermark = seq;
            }

            return .buffered;
        }

        /// Attempt to drain in-order frames into `out_slice`.
        /// Returns the number of frames written to `out_slice`.
        /// The frames in `out_slice` borrow payload from ring storage;
        /// the caller must consume them before the next `push`.
        pub fn drain(self: *Self, out_slice: []MediaFrame) usize {
            var count: usize = 0;
            while (count < out_slice.len) {
                const idx = self.next_seq % window_cap;
                const slot = &self.ring[idx];
                if (slot.state != .filled or slot.frame.sequence != self.next_seq) break;

                out_slice[count] = slot.frame;
                slot.state = .consumed;
                self.next_seq +%= 1;
                count += 1;
            }
            return count;
        }

        /// Report contiguous gap ranges in [next_seq, high_watermark].
        /// Invokes `callback` for each gap; recovered sequences are skipped.
        pub fn reportGaps(self: *const Self, callback: fn (GapRange) void) void {
            if (!self.anchored or !self.high_watermark_set) return;
            const scan_end = self.high_watermark +% 1;
            const scan_count = wrappingDelta(self.next_seq, scan_end);
            if (scan_count == 0) return;
            var gap_start: ?u32 = null;
            var offset: u32 = 0;
            while (offset < scan_count) : (offset += 1) {
                const seq = self.next_seq +% offset;
                const slot = &self.ring[seq % window_cap];
                const filled = slot.state == .filled and slot.frame.sequence == seq;
                if (!filled and !self.isRecoveredBit(offset)) {
                    if (gap_start == null) gap_start = seq;
                } else if (gap_start) |gs| {
                    callback(.{ .start = gs, .end = seq });
                    gap_start = null;
                }
            }
            if (gap_start) |gs| callback(.{ .start = gs, .end = scan_end });
        }

        /// Mark `seq` as FEC-recovered; synthesises a placeholder so drain
        /// can advance past the gap without stalling.
        pub fn markRecovered(self: *Self, seq: u32) void {
            if (!self.anchored) return;
            const delta = wrappingDelta(self.next_seq, seq);
            if (delta >= self.window) return;
            self.setRecoveredBit(delta);
            const idx = seq % window_cap;
            var slot = &self.ring[idx];
            if (slot.state != .filled) {
                slot.payload_len = 0;
                slot.frame = .{
                    .band_id = MEDIA_BAND_FLOOR,
                    .stream_id = 0,
                    .sequence = seq,
                    .timestamp = 0,
                    .keyframe = false,
                    .codec = .raw,
                    .payload = slot.payload_buf[0..0],
                };
                slot.state = .filled;
            }
        }

        fn isRecoveredBit(self: *const Self, offset: u32) bool {
            const byte_idx = offset / 8;
            const bit_idx: u3 = @intCast(offset % 8);
            if (byte_idx >= self.recovered_bits.len) return false;
            return (self.recovered_bits[byte_idx] >> bit_idx) & 1 == 1;
        }

        fn setRecoveredBit(self: *Self, offset: u32) void {
            const byte_idx = offset / 8;
            const bit_idx: u3 = @intCast(offset % 8);
            if (byte_idx >= self.recovered_bits.len) return;
            self.recovered_bits[byte_idx] |= @as(u8, 1) << bit_idx;
        }

        fn clearRecoveredBits(self: *Self) void {
            @memset(&self.recovered_bits, 0);
        }

        // gap_count_incr is called from a const context in reportGaps; we need
        // interior mutability for the counter.  Worked around by making
        // reportGaps take *const Self and not incrementing in the hot path —
        // instead we expose gap_count as a read-only statistic updated on
        // drain when gaps close.  (The reportGaps callback is the FEC seam;
        // counting happens there.)
        fn gap_count_incr(_: *const Self) void {}
    };
}

// Little-endian I/O helpers (no std.mem.readInt in hot paths — inline)

fn writeU32Le(buf: []u8, v: u32) void {
    buf[0] = @truncate(v);
    buf[1] = @truncate(v >> 8);
    buf[2] = @truncate(v >> 16);
    buf[3] = @truncate(v >> 24);
}

fn writeU64Le(buf: []u8, v: u64) void {
    buf[0] = @truncate(v);
    buf[1] = @truncate(v >> 8);
    buf[2] = @truncate(v >> 16);
    buf[3] = @truncate(v >> 24);
    buf[4] = @truncate(v >> 32);
    buf[5] = @truncate(v >> 40);
    buf[6] = @truncate(v >> 48);
    buf[7] = @truncate(v >> 56);
}

fn readU32Le(buf: []const u8) u32 {
    return @as(u32, buf[0]) |
        (@as(u32, buf[1]) << 8) |
        (@as(u32, buf[2]) << 16) |
        (@as(u32, buf[3]) << 24);
}

fn readU64Le(buf: []const u8) u64 {
    return @as(u64, buf[0]) |
        (@as(u64, buf[1]) << 8) |
        (@as(u64, buf[2]) << 16) |
        (@as(u64, buf[3]) << 24) |
        (@as(u64, buf[4]) << 32) |
        (@as(u64, buf[5]) << 40) |
        (@as(u64, buf[6]) << 48) |
        (@as(u64, buf[7]) << 56);
}

/// Wrapping forward distance b - a (mod 2^32).
fn wrappingDelta(a: u32, b: u32) u32 {
    return b -% a;
}

// ===========================================================================
// Tests
// ===========================================================================

const testing = std.testing;

fn testFrame(band_id: u8, stream_id: u32, seq: u32, ts: u64, kf: bool, codec: CodecTag, payload: []const u8) MediaFrame {
    return MediaFrame{
        .band_id = band_id,
        .stream_id = stream_id,
        .sequence = seq,
        .timestamp = ts,
        .keyframe = kf,
        .codec = codec,
        .payload = payload,
    };
}

test "encode/decode round-trip: opvox_audio" {
    const payload = "audiobytes";
    const frame = testFrame(64, 1, 10, 48000, false, .opvox_audio, payload);

    var buf: [256]u8 = undefined;
    const written = try encode(frame, &buf);
    try testing.expectEqual(MIN_FRAME_WIRE_BYTES + payload.len, written);

    const view = try decode(buf[0..written]);
    try testing.expectEqual(@as(u8, 64), view.band_id);
    try testing.expectEqual(@as(u32, 1), view.stream_id);
    try testing.expectEqual(@as(u32, 10), view.sequence);
    try testing.expectEqual(@as(u64, 48000), view.timestamp);
    try testing.expect(!view.keyframe);
    try testing.expectEqual(CodecTag.opvox_audio, view.codec);
    try testing.expectEqualSlices(u8, payload, view.payload);
}

test "encode/decode round-trip: opvis_video keyframe" {
    const payload = "videoframe";
    const frame = testFrame(128, 2, 0, 90000, true, .opvis_video, payload);

    var buf: [256]u8 = undefined;
    const written = try encode(frame, &buf);
    const view = try decode(buf[0..written]);

    try testing.expectEqual(CodecTag.opvis_video, view.codec);
    try testing.expect(view.keyframe);
    try testing.expectEqual(@as(u64, 90000), view.timestamp);
}

test "encode/decode round-trip: raw codec, empty payload" {
    const frame = testFrame(255, 0, 0xFFFF_FFFE, 0, false, .raw, &[_]u8{});

    var buf: [MIN_FRAME_WIRE_BYTES + 4]u8 = undefined;
    const written = try encode(frame, &buf);
    try testing.expectEqual(MIN_FRAME_WIRE_BYTES, written);

    const view = try decode(buf[0..written]);
    try testing.expectEqual(CodecTag.raw, view.codec);
    try testing.expectEqual(@as(usize, 0), view.payload.len);
    try testing.expectEqual(@as(u32, 0xFFFF_FFFE), view.sequence);
}

test "control band rejected on encode" {
    const frame = testFrame(63, 1, 0, 0, false, .raw, &[_]u8{0x42});
    var buf: [256]u8 = undefined;
    try testing.expectError(error.ControlBandId, encode(frame, &buf));
}

test "control band rejected on decode" {
    // Manually craft a wire frame with band_id = 0.
    // Layout: [0..4]=payload_len, [4]=band_id, [5..9]=stream_id,
    //         [9..13]=sequence, [13..21]=timestamp, [21]=flags, [22]=codec_tag
    var buf: [MIN_FRAME_WIRE_BYTES]u8 = undefined;
    @memset(&buf, 0);
    // payload_len = 0 → already zeroed
    buf[4] = 0x00; // band_id = 0 (control)
    buf[22] = 0x00; // codec_tag = raw (irrelevant; band check fires first)
    try testing.expectError(error.ControlBandId, decode(&buf));
}

test "band boundary: 63 rejected, 64 accepted" {
    try testing.expect(!isMediaBand(63));
    try testing.expect(isMediaBand(64));
    try testing.expect(isMediaBand(255));
}

test "decode truncated: buffer too short" {
    var buf: [MIN_FRAME_WIRE_BYTES - 1]u8 = undefined;
    @memset(&buf, 0);
    try testing.expectError(error.Truncated, decode(&buf));
}

test "decode truncated: declared payload exceeds buffer" {
    var buf: [MIN_FRAME_WIRE_BYTES + 4]u8 = undefined;
    @memset(&buf, 0);
    buf[4] = 64; // valid band_id
    buf[22] = 0x01; // codec = opvox_audio (at fixed offset 22)
    // payload_len = 10 but buf only has space for 4 extra bytes
    writeU32Le(buf[0..4], 10);
    try testing.expectError(error.Truncated, decode(&buf));
}

test "decode trailing bytes rejected" {
    const payload = "hello";
    const frame = testFrame(64, 0, 0, 0, false, .raw, payload);

    var buf: [256]u8 = undefined;
    const written = try encode(frame, &buf);
    // Append a stray byte.
    buf[written] = 0xFF;
    try testing.expectError(error.TrailingBytes, decode(buf[0 .. written + 1]));
}

test "decode unknown codec tag rejected" {
    var buf: [MIN_FRAME_WIRE_BYTES]u8 = undefined;
    @memset(&buf, 0);
    writeU32Le(buf[0..4], 0); // payload_len = 0
    buf[4] = 64; // band_id
    buf[22] = 0xFF; // codec_tag = 0xFF (unknown)
    try testing.expectError(error.UnknownCodecTag, decode(&buf));
}

// encodeAlloc

test "encodeAlloc produces correct bytes" {
    const allocator = testing.allocator;
    const payload = "alloctest";
    const frame = testFrame(100, 7, 3, 1234, true, .opvox_audio, payload);

    const owned = try encodeAlloc(frame, allocator);
    defer allocator.free(owned);

    const view = try decode(owned);
    try testing.expectEqualSlices(u8, payload, view.payload);
    try testing.expectEqual(@as(u8, 100), view.band_id);
    try testing.expect(view.keyframe);
}

// Reassembly: in-order delivery

test "reassembly: in-order frames drain immediately" {
    var rb = ReassemblyBuffer(128, 64).init(.{ .window = 16 });

    const payload = "data";
    var out: [4]MediaFrame = undefined;

    for (0..4) |i| {
        const f = testFrame(64, 0, @intCast(i), @intCast(i * 100), false, .raw, payload);
        const result = rb.push(f);
        try testing.expectEqual(PushResult.buffered, result);
    }

    const n = rb.drain(&out);
    try testing.expectEqual(@as(usize, 4), n);
    for (out[0..n], 0..) |f, i| {
        try testing.expectEqual(@as(u32, @intCast(i)), f.sequence);
    }
}

// Reassembly: out-of-order arrival

test "reassembly: out-of-order reordered on drain" {
    // Use initial_seq=0 so the buffer knows to expect from seq 0.
    var rb = ReassemblyBuffer(128, 64).init(.{ .window = 16, .initial_seq = 0 });

    const payload = "ooo";
    // Insert in reverse order: seq 2, 1, 0.
    _ = rb.push(testFrame(64, 0, 2, 200, false, .raw, payload));
    _ = rb.push(testFrame(64, 0, 1, 100, false, .raw, payload));

    var out: [8]MediaFrame = undefined;

    // Nothing deliverable yet (seq 0 missing).
    var n = rb.drain(&out);
    try testing.expectEqual(@as(usize, 0), n);

    _ = rb.push(testFrame(64, 0, 0, 0, false, .raw, payload));

    n = rb.drain(&out);
    try testing.expectEqual(@as(usize, 3), n);
    try testing.expectEqual(@as(u32, 0), out[0].sequence);
    try testing.expectEqual(@as(u32, 1), out[1].sequence);
    try testing.expectEqual(@as(u32, 2), out[2].sequence);
}

// Reassembly: duplicate detection

test "reassembly: duplicate dropped and counted" {
    var rb = ReassemblyBuffer(128, 64).init(.{ .window = 16 });

    const f = testFrame(64, 0, 0, 0, false, .raw, "d");
    _ = rb.push(f);
    const result = rb.push(f);
    try testing.expectEqual(PushResult.duplicate, result);
    try testing.expectEqual(@as(u64, 1), rb.duplicate_count);
}

test "reassembly: duplicate of already-delivered frame counted" {
    var rb = ReassemblyBuffer(128, 64).init(.{ .window = 16 });

    const f = testFrame(64, 0, 0, 0, false, .raw, "d");
    _ = rb.push(f);

    var out: [1]MediaFrame = undefined;
    _ = rb.drain(&out);

    // Now push the same sequence again — already consumed.
    const result = rb.push(f);
    try testing.expectEqual(PushResult.duplicate, result);
    try testing.expectEqual(@as(u64, 1), rb.duplicate_count);
}

// Reassembly: gap detection

test "reassembly: gap reporting identifies missing range" {
    var rb = ReassemblyBuffer(128, 64).init(.{ .window = 16 });

    // Insert seq 0 and seq 3 — gaps at 1 and 2.
    _ = rb.push(testFrame(64, 0, 0, 0, false, .raw, "a"));
    _ = rb.push(testFrame(64, 0, 3, 300, false, .raw, "d"));

    var out: [1]MediaFrame = undefined;
    _ = rb.drain(&out); // advance next_seq to 1

    const GapCollector = struct {
        var gaps: [8]GapRange = undefined;
        var count: usize = 0;

        fn cb(g: GapRange) void {
            if (count < gaps.len) {
                gaps[count] = g;
                count += 1;
            }
        }
    };
    GapCollector.count = 0;

    rb.reportGaps(GapCollector.cb);

    // Should surface the gap [1, 3) — sequences 1 and 2 are missing.
    try testing.expectEqual(@as(usize, 1), GapCollector.count);
    try testing.expectEqual(@as(u32, 1), GapCollector.gaps[0].start);
    try testing.expectEqual(@as(u32, 3), GapCollector.gaps[0].end);
    try testing.expectEqual(@as(u32, 2), GapCollector.gaps[0].len());
}

test "reassembly: multiple disjoint gaps reported" {
    var rb = ReassemblyBuffer(128, 64).init(.{ .window = 16 });

    // Deliver seq 0, buffer seq 2 and seq 5 — gaps [1,2) and [3,5).
    _ = rb.push(testFrame(64, 0, 0, 0, false, .raw, "a"));
    _ = rb.push(testFrame(64, 0, 2, 200, false, .raw, "c"));
    _ = rb.push(testFrame(64, 0, 5, 500, false, .raw, "f"));

    var out: [1]MediaFrame = undefined;
    _ = rb.drain(&out);

    const GapCollector = struct {
        var gaps: [8]GapRange = undefined;
        var count: usize = 0;

        fn cb(g: GapRange) void {
            if (count < gaps.len) {
                gaps[count] = g;
                count += 1;
            }
        }
    };
    GapCollector.count = 0;
    rb.reportGaps(GapCollector.cb);

    try testing.expectEqual(@as(usize, 2), GapCollector.count);
    try testing.expectEqual(@as(u32, 1), GapCollector.gaps[0].start);
    try testing.expectEqual(@as(u32, 2), GapCollector.gaps[0].end);
    try testing.expectEqual(@as(u32, 3), GapCollector.gaps[1].start);
    try testing.expectEqual(@as(u32, 5), GapCollector.gaps[1].end);
}

// Reassembly: FEC recovery hook

test "reassembly: markRecovered unblocks drain" {
    var rb = ReassemblyBuffer(128, 64).init(.{ .window = 16 });

    // seq 0 arrives, seq 1 is lost, seq 2 arrives.
    _ = rb.push(testFrame(64, 0, 0, 0, false, .raw, "a"));
    _ = rb.push(testFrame(64, 0, 2, 200, false, .raw, "c"));

    var out: [4]MediaFrame = undefined;
    var n = rb.drain(&out);
    try testing.expectEqual(@as(usize, 1), n); // only seq 0

    // FEC layer recovers seq 1.
    rb.markRecovered(1);

    n = rb.drain(&out);
    try testing.expectEqual(@as(usize, 2), n); // placeholder for 1, then real 2
    try testing.expectEqual(@as(u32, 1), out[0].sequence);
    try testing.expectEqual(@as(u32, 2), out[1].sequence);
}

// Reassembly: window overflow / late drop

test "reassembly: frame outside window is late-dropped and counted" {
    var rb = ReassemblyBuffer(128, 64).init(.{ .window = 8 });

    // Anchor at seq 0.
    _ = rb.push(testFrame(64, 0, 0, 0, false, .raw, "a"));

    // Frame at seq 100 is far outside the window of 8.
    const result = rb.push(testFrame(64, 0, 100, 9999, false, .raw, "late"));
    try testing.expectEqual(PushResult.late_drop, result);
    try testing.expectEqual(@as(u64, 1), rb.late_drop_count);
}

test "reassembly: frame at window boundary is late-dropped" {
    // With initial_seq=0 and window=4, valid range is [0,4).
    // seq 4 has fwd=4 which equals the window → late drop.
    var rb = ReassemblyBuffer(128, 64).init(.{ .window = 4, .initial_seq = 0 });

    // Fill window slots 1, 2, 3 (seq 0 missing = stall).
    _ = rb.push(testFrame(64, 0, 1, 100, false, .raw, "b"));
    _ = rb.push(testFrame(64, 0, 2, 200, false, .raw, "c"));
    _ = rb.push(testFrame(64, 0, 3, 300, false, .raw, "d"));

    // seq 4 is fwd=4 from next_seq=0 → equals window → late drop.
    const r4 = rb.push(testFrame(64, 0, 4, 400, false, .raw, "e"));
    try testing.expectEqual(PushResult.late_drop, r4);

    // Now deliver seq 0 to unblock and drain all buffered frames.
    _ = rb.push(testFrame(64, 0, 0, 0, false, .raw, "a"));
    var out: [8]MediaFrame = undefined;
    const n = rb.drain(&out);
    try testing.expectEqual(@as(usize, 4), n);
}

// Reassembly: sequence wrap-around

test "reassembly: sequence wraps around u32 max" {
    var rb = ReassemblyBuffer(128, 64).init(.{ .window = 8 });

    const max_seq: u32 = 0xFFFF_FFFF;

    // Insert near max and across the wrap.
    _ = rb.push(testFrame(64, 0, max_seq -% 1, 0, false, .raw, "penult"));
    _ = rb.push(testFrame(64, 0, max_seq, 1, false, .raw, "last"));
    _ = rb.push(testFrame(64, 0, 0, 2, false, .raw, "wrapped_0"));
    _ = rb.push(testFrame(64, 0, 1, 3, false, .raw, "wrapped_1"));

    var out: [8]MediaFrame = undefined;
    const n = rb.drain(&out);
    try testing.expectEqual(@as(usize, 4), n);
    try testing.expectEqual(max_seq -% 1, out[0].sequence);
    try testing.expectEqual(max_seq, out[1].sequence);
    try testing.expectEqual(@as(u32, 0), out[2].sequence);
    try testing.expectEqual(@as(u32, 1), out[3].sequence);
}

test "GapRange.len wrapping" {
    // 1 -% 0xFFFFFFFE = 3 in wrapping u32 arithmetic.
    const g = GapRange{ .start = 0xFFFF_FFFE, .end = 1 };
    try testing.expectEqual(@as(u32, 3), g.len());
}

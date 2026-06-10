//! RFC 6464 / RFC 6465 audio-level header-extension value codec for Orochi.
//!
//! This module is a pure, allocation-free codec for the *typed value* layer of
//! the RTP audio-level header extension. It encodes and decodes only the
//! element payload bytes; the generic RFC 8285 framing (one-byte / two-byte
//! header-extension blocks) lives in `rtp_ext.zig` and is not duplicated here.
//!
//! Two semantics share the same per-source byte layout:
//!   - RFC 6464 (client-to-mixer): the element data is a single byte:
//!       bit 7  (0x80)  V     voice-activity flag
//!       bits 0-6       level the negation of the audio level in dBov, where
//!                            0 == loudest and 127 == silence.
//!   - RFC 6465 (mixer-to-client): the element data is a sequence of such
//!     bytes, one per contributing source (paired positionally with the CSRC
//!     list carried elsewhere in the packet).
//!
//! Like the rest of the proto layer, this module owns no sockets, allocators,
//! or scheduling; it operates entirely on caller-provided buffers.
const std = @import("std");

/// Errors surfaced by the mixer (multi-byte) codepaths. The single-byte
/// client codec is total and never fails.
pub const Error = error{ Truncated, BufferTooSmall };

/// High bit of an audio-level byte carries the voice-activity flag (RFC 6464).
pub const voice_mask: u8 = 0x80;
/// Low 7 bits carry the level (negated dBov).
pub const level_mask: u8 = 0x7f;

/// dBov value reported when the source is effectively silent.
pub const silence_dbov: u7 = 127;
/// dBov value reported for the loudest possible source.
pub const loudest_dbov: u7 = 0;

/// A decoded audio level.
///
/// `dbov` is the 7-bit on-the-wire level: 0 is loudest, 127 is silence. It is
/// the negation of the audio level expressed in dBov, matching RFC 6464.
pub const Level = struct {
    voice: bool,
    dbov: u7,
};

/// Encode a single client-to-mixer (RFC 6464) audio-level byte.
pub fn encodeClient(level: Level) u8 {
    const v: u8 = if (level.voice) voice_mask else 0;
    return v | @as(u8, level.dbov);
}

/// Decode a single client-to-mixer (RFC 6464) audio-level byte.
pub fn decodeClient(byte: u8) Level {
    return .{
        .voice = (byte & voice_mask) != 0,
        .dbov = @intCast(byte & level_mask),
    };
}

/// Encode a mixer-to-client (RFC 6465) sequence: one byte per level, in order.
///
/// Returns a slice of `out` covering exactly the encoded bytes. `out` must hold
/// at least `levels.len` bytes or `Error.BufferTooSmall` is returned.
pub fn encodeMixer(levels: []const Level, out: []u8) Error![]const u8 {
    if (out.len < levels.len) return Error.BufferTooSmall;
    for (levels, 0..) |level, i| {
        out[i] = encodeClient(level);
    }
    return out[0..levels.len];
}

/// Decode a mixer-to-client (RFC 6465) sequence into `out`.
///
/// One `Level` is produced per input byte. Returns `Error.BufferTooSmall` when
/// `out` cannot hold every decoded level. (`Truncated` is reserved for callers
/// that slice partial element payloads before handing them here.)
pub fn decodeMixer(bytes: []const u8, out: []Level) Error![]Level {
    if (out.len < bytes.len) return Error.BufferTooSmall;
    for (bytes, 0..) |byte, i| {
        out[i] = decodeClient(byte);
    }
    return out[0..bytes.len];
}

/// Streaming decoder over a mixer-to-client byte sequence. Borrows its input
/// and performs no allocation; an alternative to `decodeMixer` when the caller
/// would rather not provide an output buffer.
pub const MixerIterator = struct {
    bytes: []const u8,
    index: usize = 0,

    pub fn init(bytes: []const u8) MixerIterator {
        return .{ .bytes = bytes };
    }

    /// Returns the next decoded level, or null at the end of the sequence.
    pub fn next(self: *MixerIterator) ?Level {
        if (self.index >= self.bytes.len) return null;
        const byte = self.bytes[self.index];
        self.index += 1;
        return decodeClient(byte);
    }
};

/// True when the level reports silence (dBov == 127).
pub fn isSilent(level: Level) bool {
    return level.dbov == silence_dbov;
}

/// Clamp/convert a raw audio level in dBov into a `Level`.
///
/// RFC 6464 levels are negative dBov values (0 dBov is the loudest, more
/// negative is quieter). On the wire the value is the *negation*, clamped to
/// the 0..127 range: 0 == loudest, 127 == silence. Positive inputs (above
/// 0 dBov) saturate to loudest; inputs below -127 dBov saturate to silence.
pub fn levelFromDbov(dbov_raw: i16, voice: bool) Level {
    const negated: i16 = -dbov_raw;
    const clamped: i16 = std.math.clamp(negated, @as(i16, loudest_dbov), @as(i16, silence_dbov));
    return .{ .voice = voice, .dbov = @intCast(clamped) };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "client encode/decode round-trips voice flag and dbov range" {
    const cases = [_]Level{
        .{ .voice = false, .dbov = 0 },
        .{ .voice = true, .dbov = 0 },
        .{ .voice = false, .dbov = 1 },
        .{ .voice = true, .dbov = 64 },
        .{ .voice = false, .dbov = 126 },
        .{ .voice = true, .dbov = 127 },
        .{ .voice = false, .dbov = 127 },
    };
    for (cases) |c| {
        const byte = encodeClient(c);
        const back = decodeClient(byte);
        try std.testing.expectEqual(c.voice, back.voice);
        try std.testing.expectEqual(c.dbov, back.dbov);
    }
}

test "V bit is high bit and level occupies low 7 bits (exact bytes)" {
    // voice=true, dbov=3 -> 0x80 | 0x03 == 0x83
    try std.testing.expectEqual(@as(u8, 0x83), encodeClient(.{ .voice = true, .dbov = 3 }));
    // voice=false, dbov=3 -> 0x03
    try std.testing.expectEqual(@as(u8, 0x03), encodeClient(.{ .voice = false, .dbov = 3 }));
    // voice=true, dbov=0 -> 0x80
    try std.testing.expectEqual(@as(u8, 0x80), encodeClient(.{ .voice = true, .dbov = 0 }));
    // voice=false, dbov=127 -> 0x7f
    try std.testing.expectEqual(@as(u8, 0x7f), encodeClient(.{ .voice = false, .dbov = 127 }));
    // voice=true, dbov=127 -> 0xff
    try std.testing.expectEqual(@as(u8, 0xff), encodeClient(.{ .voice = true, .dbov = 127 }));

    // Decode the masks back out.
    const d = decodeClient(0x83);
    try std.testing.expect(d.voice);
    try std.testing.expectEqual(@as(u7, 3), d.dbov);
}

test "mixer encode of 3 levels round-trips via decodeMixer" {
    const levels = [_]Level{
        .{ .voice = true, .dbov = 0 },
        .{ .voice = false, .dbov = 42 },
        .{ .voice = true, .dbov = 127 },
    };
    var enc_buf: [3]u8 = undefined;
    const enc = try encodeMixer(&levels, &enc_buf);
    try std.testing.expectEqual(@as(usize, 3), enc.len);
    try std.testing.expectEqual(@as(u8, 0x80), enc[0]);
    try std.testing.expectEqual(@as(u8, 0x2a), enc[1]);
    try std.testing.expectEqual(@as(u8, 0xff), enc[2]);

    var dec_buf: [3]Level = undefined;
    const dec = try decodeMixer(enc, &dec_buf);
    try std.testing.expectEqual(@as(usize, 3), dec.len);
    for (levels, dec) |want, got| {
        try std.testing.expectEqual(want.voice, got.voice);
        try std.testing.expectEqual(want.dbov, got.dbov);
    }
}

test "mixer encode BufferTooSmall when out is too small" {
    const levels = [_]Level{
        .{ .voice = true, .dbov = 1 },
        .{ .voice = false, .dbov = 2 },
    };
    var small: [1]u8 = undefined;
    try std.testing.expectError(Error.BufferTooSmall, encodeMixer(&levels, &small));
}

test "mixer decode BufferTooSmall when out is too small" {
    const bytes = [_]u8{ 0x80, 0x01, 0x02 };
    var small: [2]Level = undefined;
    try std.testing.expectError(Error.BufferTooSmall, decodeMixer(&bytes, &small));
}

test "MixerIterator yields each decoded level then null" {
    const bytes = [_]u8{ 0x80, 0x2a, 0xff };
    var it = MixerIterator.init(&bytes);

    const a = it.next().?;
    try std.testing.expect(a.voice);
    try std.testing.expectEqual(@as(u7, 0), a.dbov);

    const b = it.next().?;
    try std.testing.expect(!b.voice);
    try std.testing.expectEqual(@as(u7, 42), b.dbov);

    const c = it.next().?;
    try std.testing.expect(c.voice);
    try std.testing.expectEqual(@as(u7, 127), c.dbov);

    try std.testing.expect(it.next() == null);
    try std.testing.expect(it.next() == null);
}

test "isSilent only at dbov 127" {
    try std.testing.expect(isSilent(.{ .voice = false, .dbov = 127 }));
    try std.testing.expect(isSilent(.{ .voice = true, .dbov = 127 }));
    try std.testing.expect(!isSilent(.{ .voice = false, .dbov = 126 }));
    try std.testing.expect(!isSilent(.{ .voice = false, .dbov = 0 }));
}

test "levelFromDbov clamps and negates raw dBov" {
    // -30 dBov -> wire level 30.
    try std.testing.expectEqual(@as(u7, 30), levelFromDbov(-30, false).dbov);
    // 0 dBov (loudest) -> 0.
    try std.testing.expectEqual(@as(u7, 0), levelFromDbov(0, true).dbov);
    // Positive (above 0 dBov) saturates to loudest (0).
    try std.testing.expectEqual(@as(u7, 0), levelFromDbov(5, false).dbov);
    // Below -127 dBov saturates to silence (127).
    try std.testing.expectEqual(@as(u7, 127), levelFromDbov(-200, false).dbov);
    // Exactly -127 dBov -> 127.
    try std.testing.expectEqual(@as(u7, 127), levelFromDbov(-127, false).dbov);
    // Voice flag is carried through unchanged.
    try std.testing.expect(levelFromDbov(-10, true).voice);
}

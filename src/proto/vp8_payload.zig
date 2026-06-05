//! VP8 RTP payload descriptor – RFC 7741.
//!
//! Covers parse and build of the VP8 payload descriptor that sits between the
//! RTP header and the VP8 bitstream. Also exposes keyframe detection from the
//! VP8 frame header when the RTP packet begins a new partition (S=1, PID=0).
//!
//! All functions are allocation-free. Callers supply complete slices; the
//! module never touches the heap.
const std = @import("std");

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

pub const ParseError = error{
    /// Input slice is empty.
    Truncated,
    /// Required extension byte or optional field is missing.
    ExtensionTruncated,
    /// A reserved bit that must be zero was set.
    ReservedBitSet,
    /// PictureID extension byte indicates a 15-bit ID but only 1 byte remains.
    PictureIdTruncated,
    /// The VP8 payload (after the descriptor) is too short to read the frame header.
    PayloadTruncated,
};

pub const BuildError = error{
    /// Output buffer is too small for the encoded descriptor.
    OutputTooSmall,
    /// PictureID value exceeds the 15-bit range (0–32767).
    PictureIdOutOfRange,
};

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Optional fields carried by the X extension byte.
pub const Extension = struct {
    /// 15-bit PictureID when present; null when absent.
    picture_id: ?u15 = null,
    /// TL0PICIDX when present (requires L bit in X byte).
    tl0picidx: ?u8 = null,
    /// TID (2 bits, 0–3), Y bit, KEYIDX (5 bits) when present (K bit).
    tid: ?u2 = null,
    y_bit: bool = false,
    keyidx: ?u5 = null,
};

/// Parsed VP8 RTP payload descriptor.
pub const Descriptor = struct {
    /// Start-of-VP8-partition flag.
    start_of_partition: bool,
    /// Partition index (PID), 0–7.
    partition_id: u3,
    /// Optional extension fields; null when X bit was clear.
    extension: ?Extension,
    /// Number of bytes consumed from the input to parse the descriptor.
    consumed: usize,
};

/// Fields used to build a VP8 RTP payload descriptor.
pub const BuildFields = struct {
    start_of_partition: bool = false,
    partition_id: u3 = 0,
    /// When non-null the X bit is set and the extension byte is emitted.
    extension: ?Extension = null,
};

// ---------------------------------------------------------------------------
// Parse
// ---------------------------------------------------------------------------

/// Parse a VP8 RTP payload descriptor from `buf`.
///
/// Returns `Descriptor` with the number of bytes consumed so the caller can
/// slice `buf[d.consumed..]` to reach the VP8 bitstream.
pub fn parse(buf: []const u8) ParseError!Descriptor {
    if (buf.len == 0) return error.Truncated;

    const b0 = buf[0];

    // RFC 7741 §4.2 – mandatory first byte layout:
    //   X  R  N  S  R  PID[2:0]
    // Bit 7 = X (extension present)
    // Bit 6 = R (must be 0)
    // Bit 5 = N (non-reference frame; informational, not validated here)
    // Bit 4 = S (start of VP8 partition)
    // Bit 3 = R (must be 0)
    // Bits 2:0 = partition index

    // Reserved bits 6 and 3 must be zero.
    if ((b0 & 0x40) != 0) return error.ReservedBitSet;
    if ((b0 & 0x08) != 0) return error.ReservedBitSet;

    const x_bit = (b0 & 0x80) != 0;
    const s_bit = (b0 & 0x10) != 0;
    const pid: u3 = @truncate(b0 & 0x07);

    var pos: usize = 1;

    if (!x_bit) {
        return Descriptor{
            .start_of_partition = s_bit,
            .partition_id = pid,
            .extension = null,
            .consumed = pos,
        };
    }

    // --- Extension byte ---
    if (pos >= buf.len) return error.ExtensionTruncated;
    const xb = buf[pos];
    pos += 1;

    // Extension byte layout: I  L  T  K  RRRR
    // Bit 7 = I (PictureID present)
    // Bit 6 = L (TL0PICIDX present)
    // Bit 5 = T (TID/Y/KEYIDX present)
    // Bit 4 = K (also TID/Y/KEYIDX; RFC uses T and K together)
    // Bits 3:0 = reserved (must be 0)
    if ((xb & 0x0F) != 0) return error.ReservedBitSet;

    const i_bit = (xb & 0x80) != 0;
    const l_bit = (xb & 0x40) != 0;
    const t_bit = (xb & 0x20) != 0;
    const k_bit = (xb & 0x10) != 0;

    var ext = Extension{};

    // --- PictureID ---
    if (i_bit) {
        if (pos >= buf.len) return error.ExtensionTruncated;
        const pid_b0 = buf[pos];
        pos += 1;
        if ((pid_b0 & 0x80) != 0) {
            // 15-bit PictureID: M=1 + 7 high bits in first byte, 8 low bits in next.
            if (pos >= buf.len) return error.PictureIdTruncated;
            const pid_b1 = buf[pos];
            pos += 1;
            const high: u15 = @intCast(@as(u15, pid_b0 & 0x7F) << 8);
            const low: u15 = @intCast(pid_b1);
            ext.picture_id = high | low;
        } else {
            // 7-bit PictureID.
            ext.picture_id = @intCast(pid_b0 & 0x7F);
        }
    }

    // --- TL0PICIDX ---
    if (l_bit) {
        if (pos >= buf.len) return error.ExtensionTruncated;
        ext.tl0picidx = buf[pos];
        pos += 1;
    }

    // --- TID / Y / KEYIDX ---
    if (t_bit or k_bit) {
        if (pos >= buf.len) return error.ExtensionTruncated;
        const tk = buf[pos];
        pos += 1;
        // Byte layout: TID[7:6]  Y[5]  KEYIDX[4:0]
        ext.tid = @truncate((tk >> 6) & 0x03);
        ext.y_bit = (tk & 0x20) != 0;
        ext.keyidx = @truncate(tk & 0x1F);
    }

    return Descriptor{
        .start_of_partition = s_bit,
        .partition_id = pid,
        .extension = ext,
        .consumed = pos,
    };
}

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------

/// Encode a VP8 RTP payload descriptor into `out`.
///
/// Returns the slice of `out` that was written.
pub fn build(fields: BuildFields, out: []u8) BuildError![]u8 {
    // Conservative upper-bound: 1 (mandatory) + 1 (X) + 3 (PicID) + 1 (TL0) + 1 (TID) = 7
    var pos: usize = 0;

    // --- Mandatory byte ---
    // X R N S R PID[2:0] — R bits stay 0, N stays 0 (caller can OR it later if needed).
    const x_bit: u8 = if (fields.extension != null) 0x80 else 0x00;
    const s_bit: u8 = if (fields.start_of_partition) 0x10 else 0x00;
    const pid_bits: u8 = @as(u8, fields.partition_id) & 0x07;
    if (pos >= out.len) return error.OutputTooSmall;
    out[pos] = x_bit | s_bit | pid_bits;
    pos += 1;

    const ext = fields.extension orelse return out[0..pos];

    // --- Extension byte ---
    const i_bit: u8 = if (ext.picture_id != null) 0x80 else 0x00;
    const l_bit: u8 = if (ext.tl0picidx != null) 0x40 else 0x00;
    const tk_present = ext.tid != null or ext.keyidx != null;
    const t_bit: u8 = if (tk_present) 0x20 else 0x00;
    const k_bit: u8 = if (tk_present) 0x10 else 0x00;
    if (pos >= out.len) return error.OutputTooSmall;
    out[pos] = i_bit | l_bit | t_bit | k_bit;
    pos += 1;

    // --- PictureID ---
    if (ext.picture_id) |pid_val| {
        if (pid_val > 0x7FFF) return error.PictureIdOutOfRange;
        if (pid_val > 0x7F) {
            // 15-bit encoding: M=1 + high 7 bits, then low 8 bits.
            if (pos + 1 >= out.len) return error.OutputTooSmall;
            out[pos] = 0x80 | @as(u8, @intCast((pid_val >> 8) & 0x7F));
            pos += 1;
            out[pos] = @as(u8, @intCast(pid_val & 0xFF));
            pos += 1;
        } else {
            // 7-bit encoding: M=0 + 7-bit value.
            if (pos >= out.len) return error.OutputTooSmall;
            out[pos] = @as(u8, @intCast(pid_val & 0x7F));
            pos += 1;
        }
    }

    // --- TL0PICIDX ---
    if (ext.tl0picidx) |tl0| {
        if (pos >= out.len) return error.OutputTooSmall;
        out[pos] = tl0;
        pos += 1;
    }

    // --- TID / Y / KEYIDX ---
    if (tk_present) {
        if (pos >= out.len) return error.OutputTooSmall;
        const tid_val: u8 = @as(u8, ext.tid orelse 0) << 6;
        const y_val: u8 = if (ext.y_bit) 0x20 else 0x00;
        const kidx_val: u8 = @as(u8, ext.keyidx orelse 0) & 0x1F;
        out[pos] = tid_val | y_val | kidx_val;
        pos += 1;
    }

    return out[0..pos];
}

// ---------------------------------------------------------------------------
// Keyframe detection
// ---------------------------------------------------------------------------

/// Returns `true` when `rtp_payload` carries the start of a VP8 keyframe.
///
/// A keyframe is present when:
///   - The descriptor has S=1 and PID=0 (start of a new partition 0), AND
///   - The P bit in the first VP8 frame-tag byte is 0 (0 = keyframe per VP8
///     spec §9.1).
///
/// `rtp_payload` must be the full payload after the RTP header, including the
/// VP8 payload descriptor.
pub fn isKeyframe(rtp_payload: []const u8) ParseError!bool {
    const desc = try parse(rtp_payload);

    // Only check partition 0, start-of-partition packets.
    if (!desc.start_of_partition or desc.partition_id != 0) {
        return false;
    }

    // At least one byte of VP8 bitstream must follow the descriptor.
    if (desc.consumed >= rtp_payload.len) return error.PayloadTruncated;

    // VP8 uncompressed data chunk (frame tag) first 3 bytes (§9.1):
    //   bits 0:   key_frame  (0 = keyframe, 1 = interframe)
    //   bits 2:1  version
    //   bit  3    show_frame
    //   bits 18:4 first_part_size
    // The P bit referred to in VP8 RTP literature is bit 0 of the first frame
    // tag byte: 0 means keyframe.
    const frame_tag = rtp_payload[desc.consumed];
    return (frame_tag & 0x01) == 0;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "minimal descriptor – no extension, no S bit" {
    // Byte: X=0 R=0 N=0 S=0 R=0 PID=0  →  0x00
    const buf = [_]u8{0x00};
    const d = try parse(&buf);
    try std.testing.expect(!d.start_of_partition);
    try std.testing.expectEqual(@as(u3, 0), d.partition_id);
    try std.testing.expect(d.extension == null);
    try std.testing.expectEqual(@as(usize, 1), d.consumed);
}

test "minimal descriptor – S=1, PID=3" {
    // Byte: X=0 R=0 N=0 S=1 R=0 PID=3  →  0x13
    const buf = [_]u8{0x13};
    const d = try parse(&buf);
    try std.testing.expect(d.start_of_partition);
    try std.testing.expectEqual(@as(u3, 3), d.partition_id);
    try std.testing.expect(d.extension == null);
    try std.testing.expectEqual(@as(usize, 1), d.consumed);
}

test "minimal descriptor round-trip" {
    const fields = BuildFields{
        .start_of_partition = true,
        .partition_id = 5,
        .extension = null,
    };
    var out: [16]u8 = undefined;
    const encoded = try build(fields, &out);
    try std.testing.expectEqual(@as(usize, 1), encoded.len);

    const d = try parse(encoded);
    try std.testing.expect(d.start_of_partition);
    try std.testing.expectEqual(@as(u3, 5), d.partition_id);
    try std.testing.expect(d.extension == null);
}

test "extended descriptor – 7-bit PictureID round-trip" {
    const fields = BuildFields{
        .start_of_partition = true,
        .partition_id = 0,
        .extension = .{
            .picture_id = 42,
        },
    };
    var out: [16]u8 = undefined;
    const encoded = try build(fields, &out);
    // Expected: mandatory(1) + X byte(1) + PicID 7-bit(1) = 3 bytes
    try std.testing.expectEqual(@as(usize, 3), encoded.len);

    const d = try parse(encoded);
    try std.testing.expect(d.start_of_partition);
    try std.testing.expectEqual(@as(u3, 0), d.partition_id);
    const ext = d.extension orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(?u15, 42), ext.picture_id);
    try std.testing.expectEqual(@as(?u8, null), ext.tl0picidx);
    try std.testing.expectEqual(@as(?u2, null), ext.tid);
}

test "extended descriptor – 15-bit PictureID round-trip" {
    const fields = BuildFields{
        .start_of_partition = false,
        .partition_id = 2,
        .extension = .{
            .picture_id = 0x1234,
        },
    };
    var out: [16]u8 = undefined;
    const encoded = try build(fields, &out);
    // mandatory(1) + X byte(1) + PicID 15-bit(2) = 4 bytes
    try std.testing.expectEqual(@as(usize, 4), encoded.len);

    const d = try parse(encoded);
    try std.testing.expect(!d.start_of_partition);
    try std.testing.expectEqual(@as(u3, 2), d.partition_id);
    const ext = d.extension orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(?u15, 0x1234), ext.picture_id);
}

test "extended descriptor – PictureID boundary values" {
    // Maximum 7-bit value (127)
    {
        const fields = BuildFields{
            .extension = .{ .picture_id = 127 },
        };
        var out: [16]u8 = undefined;
        const encoded = try build(fields, &out);
        const d = try parse(encoded);
        const ext = d.extension orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(@as(?u15, 127), ext.picture_id);
    }
    // Minimum 15-bit value that forces the two-byte form (128)
    {
        const fields = BuildFields{
            .extension = .{ .picture_id = 128 },
        };
        var out: [16]u8 = undefined;
        const encoded = try build(fields, &out);
        const d = try parse(encoded);
        const ext = d.extension orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(@as(?u15, 128), ext.picture_id);
    }
    // Maximum 15-bit value (32767)
    {
        const fields = BuildFields{
            .extension = .{ .picture_id = 32767 },
        };
        var out: [16]u8 = undefined;
        const encoded = try build(fields, &out);
        const d = try parse(encoded);
        const ext = d.extension orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(@as(?u15, 32767), ext.picture_id);
    }
}

test "extended descriptor – TL0PICIDX + TID/Y/KEYIDX round-trip" {
    const fields = BuildFields{
        .start_of_partition = true,
        .partition_id = 0,
        .extension = .{
            .picture_id = 100,
            .tl0picidx = 0xAB,
            .tid = 2,
            .y_bit = true,
            .keyidx = 0x1F,
        },
    };
    var out: [16]u8 = undefined;
    const encoded = try build(fields, &out);
    // mandatory(1) + X(1) + PicID 7-bit(1) + TL0(1) + TID/Y/KEYIDX(1) = 5 bytes
    try std.testing.expectEqual(@as(usize, 5), encoded.len);

    const d = try parse(encoded);
    try std.testing.expect(d.start_of_partition);
    try std.testing.expectEqual(@as(u3, 0), d.partition_id);
    const ext = d.extension orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(?u15, 100), ext.picture_id);
    try std.testing.expectEqual(@as(?u8, 0xAB), ext.tl0picidx);
    try std.testing.expectEqual(@as(?u2, 2), ext.tid);
    try std.testing.expect(ext.y_bit);
    try std.testing.expectEqual(@as(?u5, 0x1F), ext.keyidx);
}

test "extended descriptor – TID only, no PictureID or TL0PICIDX" {
    const fields = BuildFields{
        .extension = .{
            .tid = 1,
            .y_bit = false,
            .keyidx = 7,
        },
    };
    var out: [16]u8 = undefined;
    const encoded = try build(fields, &out);
    // mandatory(1) + X(1) + TID/Y/KEYIDX(1) = 3 bytes
    try std.testing.expectEqual(@as(usize, 3), encoded.len);

    const d = try parse(encoded);
    const ext = d.extension orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(?u15, null), ext.picture_id);
    try std.testing.expectEqual(@as(?u8, null), ext.tl0picidx);
    try std.testing.expectEqual(@as(?u2, 1), ext.tid);
    try std.testing.expect(!ext.y_bit);
    try std.testing.expectEqual(@as(?u5, 7), ext.keyidx);
}

test "S bit and PID field" {
    // S=1, PID=7, no extension: 0x17
    const buf = [_]u8{0x17};
    const d = try parse(&buf);
    try std.testing.expect(d.start_of_partition);
    try std.testing.expectEqual(@as(u3, 7), d.partition_id);

    // S=0, PID=6, no extension: 0x06
    const buf2 = [_]u8{0x06};
    const d2 = try parse(&buf2);
    try std.testing.expect(!d2.start_of_partition);
    try std.testing.expectEqual(@as(u3, 6), d2.partition_id);
}

test "keyframe detection – keyframe (P=0)" {
    // Descriptor: mandatory only, S=1, PID=0 → 0x10
    // VP8 frame tag byte: P=0 (keyframe) → 0x00 (version=0, show=0, keyframe)
    const buf = [_]u8{ 0x10, 0x00, 0x00, 0x00 };
    const kf = try isKeyframe(&buf);
    try std.testing.expect(kf);
}

test "keyframe detection – interframe (P=1)" {
    // Descriptor: S=1, PID=0 → 0x10
    // VP8 frame tag: P=1 (interframe) → 0x01
    const buf = [_]u8{ 0x10, 0x01, 0x00, 0x00 };
    const kf = try isKeyframe(&buf);
    try std.testing.expect(!kf);
}

test "keyframe detection – non-zero PID, not a key check point" {
    // Even if the frame tag says P=0, we return false for PID != 0.
    const buf = [_]u8{ 0x11, 0x00 }; // S=1, PID=1
    const kf = try isKeyframe(&buf);
    try std.testing.expect(!kf);
}

test "keyframe detection – S=0, returns false regardless" {
    const buf = [_]u8{ 0x00, 0x00 }; // S=0, PID=0
    const kf = try isKeyframe(&buf);
    try std.testing.expect(!kf);
}

test "keyframe detection – with extended descriptor" {
    // S=1, PID=0, X=1, I=1, 7-bit PicID=1 → [0x90, 0x80, 0x01], then keyframe tag 0x00
    var out: [16]u8 = undefined;
    const encoded = try build(.{
        .start_of_partition = true,
        .partition_id = 0,
        .extension = .{ .picture_id = 1 },
    }, &out);

    var payload: [16]u8 = undefined;
    @memcpy(payload[0..encoded.len], encoded);
    payload[encoded.len] = 0x00; // keyframe tag
    const kf = try isKeyframe(payload[0 .. encoded.len + 1]);
    try std.testing.expect(kf);
}

test "truncation – empty input" {
    const result = parse(&[_]u8{});
    try std.testing.expectError(error.Truncated, result);
}

test "truncation – X set but no extension byte" {
    // 0x80 = X=1, no further bytes
    const result = parse(&[_]u8{0x80});
    try std.testing.expectError(error.ExtensionTruncated, result);
}

test "truncation – I set but no PictureID byte" {
    // mandatory=0x80 (X=1), ext byte=0x80 (I=1, nothing else), then nothing
    const result = parse(&[_]u8{ 0x80, 0x80 });
    try std.testing.expectError(error.ExtensionTruncated, result);
}

test "truncation – 15-bit PictureID missing second byte" {
    // mandatory=0x80, ext=0x80 (I=1), PicID first byte with M=1 → need second byte
    const result = parse(&[_]u8{ 0x80, 0x80, 0xFF });
    try std.testing.expectError(error.PictureIdTruncated, result);
}

test "truncation – L set but no TL0PICIDX byte" {
    // mandatory=0x80, ext=0x40 (L=1 only), nothing more
    const result = parse(&[_]u8{ 0x80, 0x40 });
    try std.testing.expectError(error.ExtensionTruncated, result);
}

test "truncation – T/K set but no TID byte" {
    // mandatory=0x80, ext=0x20 (T=1 only), nothing more
    const result = parse(&[_]u8{ 0x80, 0x20 });
    try std.testing.expectError(error.ExtensionTruncated, result);
}

test "keyframe detection – payload truncated after descriptor" {
    // S=1, PID=0, no extension, but no VP8 payload byte follows
    const result = isKeyframe(&[_]u8{0x10});
    try std.testing.expectError(error.PayloadTruncated, result);
}

test "reserved bit in mandatory byte – bit 6" {
    const result = parse(&[_]u8{0x40});
    try std.testing.expectError(error.ReservedBitSet, result);
}

test "reserved bit in mandatory byte – bit 3" {
    const result = parse(&[_]u8{0x08});
    try std.testing.expectError(error.ReservedBitSet, result);
}

test "reserved bits in extension byte" {
    // mandatory=0x80 (X=1), ext byte with reserved low nibble set
    const result = parse(&[_]u8{ 0x80, 0x0F });
    try std.testing.expectError(error.ReservedBitSet, result);
}

test "build – output buffer too small" {
    var out: [0]u8 = undefined;
    const result = build(.{}, &out);
    try std.testing.expectError(error.OutputTooSmall, result);
}

test "deterministic – same input gives same output" {
    const fields = BuildFields{
        .start_of_partition = true,
        .partition_id = 1,
        .extension = .{
            .picture_id = 500,
            .tl0picidx = 12,
            .tid = 3,
            .y_bit = false,
            .keyidx = 10,
        },
    };
    var out1: [16]u8 = undefined;
    var out2: [16]u8 = undefined;
    const e1 = try build(fields, &out1);
    const e2 = try build(fields, &out2);
    try std.testing.expectEqualSlices(u8, e1, e2);

    const d1 = try parse(e1);
    const d2 = try parse(e2);
    try std.testing.expectEqual(d1.consumed, d2.consumed);
    try std.testing.expectEqual(d1.start_of_partition, d2.start_of_partition);
    try std.testing.expectEqual(d1.partition_id, d2.partition_id);
    const x1 = d1.extension.?;
    const x2 = d2.extension.?;
    try std.testing.expectEqual(x1.picture_id, x2.picture_id);
    try std.testing.expectEqual(x1.tl0picidx, x2.tl0picidx);
    try std.testing.expectEqual(x1.tid, x2.tid);
    try std.testing.expectEqual(x1.y_bit, x2.y_bit);
    try std.testing.expectEqual(x1.keyidx, x2.keyidx);
}

test "full round-trip – all fields present" {
    const fields = BuildFields{
        .start_of_partition = true,
        .partition_id = 0,
        .extension = .{
            .picture_id = 0x7FFF, // max 15-bit
            .tl0picidx = 0xFF,
            .tid = 3,
            .y_bit = true,
            .keyidx = 0x1F,
        },
    };
    var out: [16]u8 = undefined;
    const encoded = try build(fields, &out);
    // mandatory(1) + X(1) + PicID 15-bit(2) + TL0(1) + TID/Y/KEYIDX(1) = 6 bytes
    try std.testing.expectEqual(@as(usize, 6), encoded.len);

    const d = try parse(encoded);
    try std.testing.expect(d.start_of_partition);
    try std.testing.expectEqual(@as(u3, 0), d.partition_id);
    const ext = d.extension orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(?u15, 0x7FFF), ext.picture_id);
    try std.testing.expectEqual(@as(?u8, 0xFF), ext.tl0picidx);
    try std.testing.expectEqual(@as(?u2, 3), ext.tid);
    try std.testing.expect(ext.y_bit);
    try std.testing.expectEqual(@as(?u5, 0x1F), ext.keyidx);
}

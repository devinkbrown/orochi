//! RTP RED (RFC 2198) framing + ULPFEC (RFC 5109) XOR-based FEC.
//!
//! RED:
//!   Encodes a primary payload plus zero or more redundant (older) payloads
//!   into a single RTP payload block.  Block header layout per RFC 2198 §4:
//!
//!     Primary block header (1 byte, F=0):
//!       [0] = PT (7 bits)   F bit = 0 (last header)
//!
//!     Redundant block header (4 bytes, F=1):
//!       [0]   = F(1) | PT(7)
//!       [1:2] = timestamp offset (14 bits, big-endian)
//!       [2:3] = lower 6 bits of [1:2] + upper 2 bits of block length
//!       [3]   = lower 8 bits of block length
//!       (block length = 10-bit field in bits [22:32] of the 4-byte header)
//!
//! ULPFEC (RFC 5109):
//!   FEC packet payload = FEC Header (10 bytes) + FEC Level Header (4 bytes)
//!   + XOR of all protected media packet payloads (after the first 2 RTP
//!   header bytes are XOR-folded into the FEC header fields).
//!
//!   FEC Header (10 bytes):
//!     [0:1]  E(1)|L(1)|P(1)|X(1)|CC(4) | M(1)|PT recovery(7)
//!     [2:3]  SN base (sequence number of first protected packet)
//!     [4:7]  TS recovery
//!     [8:9]  length recovery
//!
//!   FEC Level Header (4 bytes following FEC Header):
//!     [0:1]  protection length (bytes of media payload covered)
//!     [2:3]  mask (16-bit bitmask, bit 15 = offset 0 = SN base)
//!
//! Only Level 0 (single level, mask ≤ 16 packets) is implemented here.

const std = @import("std");
const mem = std.mem;
const testing = std.testing;

// ---------------------------------------------------------------------------
// RED  (RFC 2198)
// ---------------------------------------------------------------------------

/// One block carried inside a RED packet (primary or redundant).
pub const RedBlock = struct {
    /// RTP payload type of this block.
    pt: u7,
    /// Timestamp offset relative to the outer RTP timestamp (0 for primary).
    timestamp_offset: u14,
    /// Raw payload bytes of this block.
    payload: []const u8,
};

/// Encode a slice of RedBlocks into `out`.
///
/// `blocks[len-1]` is the **primary** (most recent) block; earlier entries are
/// redundant (oldest first).  The caller must ensure `out` is large enough;
/// use `redEncodeSize` to pre-compute the required size.
///
/// Returns the number of bytes written.
pub fn redEncodeSize(blocks: []const RedBlock) usize {
    if (blocks.len == 0) return 0;
    var size: usize = 0;
    // Redundant block headers: 4 bytes each (F=1)
    size += (blocks.len - 1) * 4;
    // Primary block header: 1 byte (F=0)
    size += 1;
    // All payloads
    for (blocks) |b| size += b.payload.len;
    return size;
}

pub fn redEncode(blocks: []const RedBlock, out: []u8) !usize {
    if (blocks.len == 0) return 0;
    const required = redEncodeSize(blocks);
    if (out.len < required) return error.BufferTooSmall;

    var pos: usize = 0;
    const primary_idx = blocks.len - 1;

    // Write redundant block headers (F=1) for all but the last
    for (0..primary_idx) |i| {
        const b = blocks[i];
        // byte 0: F=1 | PT (7 bits)
        out[pos] = 0x80 | @as(u8, b.pt);
        pos += 1;
        // bytes 1-3: timestamp_offset (14 bits) + block_length (10 bits)
        //   bits [0:13]  = timestamp offset
        //   bits [14:23] = block length (10 bits)
        // packed into 24 bits big-endian across 3 bytes
        const bl: u10 = @intCast(b.payload.len);
        const word: u24 = (@as(u24, b.timestamp_offset) << 10) | @as(u24, bl);
        out[pos] = @intCast((word >> 16) & 0xFF);
        out[pos + 1] = @intCast((word >> 8) & 0xFF);
        out[pos + 2] = @intCast(word & 0xFF);
        pos += 3;
    }

    // Primary block header (F=0): just the PT
    out[pos] = @as(u8, blocks[primary_idx].pt); // F bit = 0
    pos += 1;

    // All payloads in order
    for (blocks) |b| {
        @memcpy(out[pos .. pos + b.payload.len], b.payload);
        pos += b.payload.len;
    }

    return pos;
}

/// Decode a RED payload.  Appends decoded RedBlocks to `list`; `payload_buf`
/// is used as backing storage for payload slices (must outlive the list).
/// The returned slices alias `raw[...]` — no copy is made.
pub fn redDecode(
    allocator: mem.Allocator,
    raw: []const u8,
    list: *std.ArrayListUnmanaged(RedBlock),
) !void {
    if (raw.len == 0) return error.TruncatedInput;

    // First pass: parse headers to learn payload offsets
    const max_blocks = 32;
    var headers: [max_blocks]struct {
        pt: u7,
        ts_offset: u14,
        block_len: usize,
        is_primary: bool,
    } = undefined;
    var hdr_count: usize = 0;
    var pos: usize = 0;

    // Parse all headers
    while (pos < raw.len) {
        if (hdr_count >= max_blocks) return error.TooManyBlocks;
        const b0 = raw[pos];
        const f_bit = (b0 & 0x80) != 0;
        if (!f_bit) {
            // Primary header: 1 byte
            headers[hdr_count] = .{
                .pt = @intCast(b0 & 0x7F),
                .ts_offset = 0,
                .block_len = 0, // will fill in below
                .is_primary = true,
            };
            hdr_count += 1;
            pos += 1;
            break;
        } else {
            // Redundant header: 4 bytes
            if (pos + 4 > raw.len) return error.TruncatedInput;
            const word: u24 = (@as(u24, raw[pos + 1]) << 16) |
                (@as(u24, raw[pos + 2]) << 8) |
                @as(u24, raw[pos + 3]);
            const ts_off: u14 = @intCast((word >> 10) & 0x3FFF);
            const bl: usize = @intCast(word & 0x3FF);
            headers[hdr_count] = .{
                .pt = @intCast(b0 & 0x7F),
                .ts_offset = ts_off,
                .block_len = bl,
                .is_primary = false,
            };
            hdr_count += 1;
            pos += 4;
        }
    }

    // `pos` now points to start of payload section
    const payload_start = pos;

    // Compute sizes: redundant blocks have explicit lengths; primary takes
    // whatever is left.
    var redundant_total: usize = 0;
    for (0..hdr_count) |i| {
        if (!headers[i].is_primary) redundant_total += headers[i].block_len;
    }
    if (payload_start + redundant_total > raw.len) return error.TruncatedInput;
    const primary_len = raw.len - payload_start - redundant_total;

    // Set primary block length
    for (0..hdr_count) |i| {
        if (headers[i].is_primary) headers[i].block_len = primary_len;
    }

    // Second pass: extract payloads
    var ppos = payload_start;
    for (0..hdr_count) |i| {
        const h = headers[i];
        if (ppos + h.block_len > raw.len) return error.TruncatedInput;
        try list.append(allocator, .{
            .pt = h.pt,
            .timestamp_offset = h.ts_offset,
            .payload = raw[ppos .. ppos + h.block_len],
        });
        ppos += h.block_len;
    }
}

// ---------------------------------------------------------------------------
// ULPFEC  (RFC 5109)
// ---------------------------------------------------------------------------

pub const FEC_HEADER_SIZE: usize = 10;
pub const FEC_LEVEL_HEADER_SIZE: usize = 4;
pub const FEC_OVERHEAD: usize = FEC_HEADER_SIZE + FEC_LEVEL_HEADER_SIZE;

/// Parsed FEC header fields.
pub const FecHeader = struct {
    /// E bit (extension – reserved, must be 0).
    e: bool,
    /// L bit (long mask – if set mask is 48 bits; we only support 16-bit mask).
    l: bool,
    /// P/X/CC fields from the XOR of protected packet headers.
    p: bool,
    x: bool,
    cc: u4,
    /// M bit recovery.
    m: bool,
    /// PT recovery (XOR of protected packet PTs).
    pt_recovery: u7,
    /// SN base – sequence number of the first protected packet.
    sn_base: u16,
    /// TS recovery.
    ts_recovery: u32,
    /// Length recovery.
    length_recovery: u16,
    /// Protection length from level header.
    protection_length: u16,
    /// 16-bit mask.  Bit 15 corresponds to SN base + 0.
    mask: u16,
};

pub fn parseFecHeader(data: []const u8) !FecHeader {
    if (data.len < FEC_OVERHEAD) return error.TruncatedInput;
    const e = (data[0] & 0x80) != 0;
    const l = (data[0] & 0x40) != 0;
    const p = (data[0] & 0x20) != 0;
    const x = (data[0] & 0x10) != 0;
    const cc: u4 = @intCast(data[0] & 0x0F);
    const m = (data[1] & 0x80) != 0;
    const pt_recovery: u7 = @intCast(data[1] & 0x7F);
    const sn_base: u16 = (@as(u16, data[2]) << 8) | data[3];
    const ts_recovery: u32 = (@as(u32, data[4]) << 24) |
        (@as(u32, data[5]) << 16) |
        (@as(u32, data[6]) << 8) |
        data[7];
    const length_recovery: u16 = (@as(u16, data[8]) << 8) | data[9];
    const protection_length: u16 = (@as(u16, data[10]) << 8) | data[11];
    const mask: u16 = (@as(u16, data[12]) << 8) | data[13];
    return FecHeader{
        .e = e,
        .l = l,
        .p = p,
        .x = x,
        .cc = cc,
        .m = m,
        .pt_recovery = pt_recovery,
        .sn_base = sn_base,
        .ts_recovery = ts_recovery,
        .length_recovery = length_recovery,
        .protection_length = protection_length,
        .mask = mask,
    };
}

/// One protected media packet for FEC input.
pub const MediaPacket = struct {
    /// Full RTP sequence number.
    seq: u16,
    /// RTP payload type.
    pt: u7,
    /// RTP marker bit.
    marker: bool,
    /// RTP timestamp.
    timestamp: u32,
    /// RTP payload (not including fixed 12-byte RTP header).
    payload: []const u8,
};

/// Build a ULPFEC packet over `packets` into `out`.
/// `out` must be at least `fecPacketSize(packets)` bytes.
/// Returns bytes written.
pub fn fecPacketSize(packets: []const MediaPacket) usize {
    var max_len: usize = 0;
    for (packets) |p| {
        if (p.payload.len > max_len) max_len = p.payload.len;
    }
    return FEC_OVERHEAD + max_len;
}

pub fn buildFecPacket(
    packets: []const MediaPacket,
    out: []u8,
) !usize {
    if (packets.len == 0) return error.NoPackets;
    if (packets.len > 16) return error.TooManyPackets;

    const max_payload_len = blk: {
        var m: usize = 0;
        for (packets) |p| if (p.payload.len > m) {
            m = p.payload.len;
        };
        break :blk m;
    };

    const total = FEC_OVERHEAD + max_payload_len;
    if (out.len < total) return error.BufferTooSmall;

    // Zero the output buffer (XOR identity).
    @memset(out[0..total], 0);

    const sn_base = packets[0].seq;

    // Build the 16-bit mask
    var mask: u16 = 0;
    for (packets) |p| {
        const offset = p.seq -% sn_base;
        if (offset >= 16) return error.SeqRangeExceeded;
        mask |= @as(u16, 0x8000) >> @intCast(offset);
    }

    // XOR recovery fields across all packets.
    // P/X/CC are XOR-of-zeros (all media packets use standard fixed header),
    // so they stay 0 and are written as constants below.
    var pt_recovery: u7 = 0;
    var m_recovery: bool = false;
    var ts_recovery: u32 = 0;
    var length_recovery: u16 = 0;

    for (packets) |p| {
        pt_recovery ^= p.pt;
        m_recovery = m_recovery != p.marker;
        ts_recovery ^= p.timestamp;
        length_recovery ^= @intCast(p.payload.len & 0xFFFF);
        // XOR payload bytes (pad shorter payloads with 0)
        for (0..max_payload_len) |i| {
            const byte: u8 = if (i < p.payload.len) p.payload[i] else 0;
            out[FEC_OVERHEAD + i] ^= byte;
        }
    }

    // FEC Header (10 bytes)
    // byte 0: E(0)|L(0)|P(0)|X(0)|CC(0)
    out[0] = 0;
    // byte 1: M|PT_recovery
    out[1] = (@as(u8, if (m_recovery) 1 else 0) << 7) | @as(u8, pt_recovery);
    // bytes 2-3: SN base
    out[2] = @intCast((sn_base >> 8) & 0xFF);
    out[3] = @intCast(sn_base & 0xFF);
    // bytes 4-7: TS recovery
    out[4] = @intCast((ts_recovery >> 24) & 0xFF);
    out[5] = @intCast((ts_recovery >> 16) & 0xFF);
    out[6] = @intCast((ts_recovery >> 8) & 0xFF);
    out[7] = @intCast(ts_recovery & 0xFF);
    // bytes 8-9: length recovery
    out[8] = @intCast((length_recovery >> 8) & 0xFF);
    out[9] = @intCast(length_recovery & 0xFF);

    // FEC Level Header (4 bytes)
    const prot_len: u16 = @intCast(max_payload_len);
    out[10] = @intCast((prot_len >> 8) & 0xFF);
    out[11] = @intCast(prot_len & 0xFF);
    out[12] = @intCast((mask >> 8) & 0xFF);
    out[13] = @intCast(mask & 0xFF);

    return total;
}

/// Attempt to recover a single missing media packet.
///
/// `fec_data`    – the FEC packet payload (starting at FEC Header).
/// `received`    – all other (surviving) protected packets.
/// `missing_seq` – the RTP sequence number of the lost packet.
/// `allocator`   – used to allocate the recovered payload.
///
/// Returns a newly-allocated `MediaPacket` (caller owns `.payload`), or
/// `null` if recovery is impossible (e.g., more than one packet is missing
/// from this FEC group, or `missing_seq` is not protected by this packet).
pub fn recoverPacket(
    fec_data: []const u8,
    received: []const MediaPacket,
    missing_seq: u16,
    allocator: mem.Allocator,
) !?MediaPacket {
    const hdr = try parseFecHeader(fec_data);

    // Verify missing_seq is in the mask
    const missing_offset = missing_seq -% hdr.sn_base;
    if (missing_offset >= 16) return null;
    const missing_bit = @as(u16, 0x8000) >> @intCast(missing_offset);
    if ((hdr.mask & missing_bit) == 0) return null;

    // Count how many protected seq numbers are NOT in `received`
    var missing_count: usize = 0;
    for (0..16) |bit| {
        const b = @as(u16, 0x8000) >> @intCast(bit);
        if ((hdr.mask & b) == 0) continue;
        const seq: u16 = hdr.sn_base +% @as(u16, @intCast(bit));
        var found = false;
        for (received) |p| {
            if (p.seq == seq) {
                found = true;
                break;
            }
        }
        if (!found) missing_count += 1;
    }

    if (missing_count != 1) return null; // can't recover multiple losses

    // XOR-fold received packets out of the FEC repair data to get the missing
    // packet's fields.
    const prot_len = hdr.protection_length;
    var recovered_payload = try allocator.alloc(u8, prot_len);
    errdefer allocator.free(recovered_payload);

    // Start with the FEC repair payload bytes
    const fec_repair = fec_data[FEC_OVERHEAD .. FEC_OVERHEAD + prot_len];
    if (fec_data.len < FEC_OVERHEAD + prot_len) {
        allocator.free(recovered_payload);
        return error.TruncatedInput;
    }
    @memcpy(recovered_payload[0..prot_len], fec_repair);

    // XOR out all received packets
    for (received) |p| {
        const b2: u16 = p.seq -% hdr.sn_base;
        if (b2 >= 16) continue;
        if ((hdr.mask & (@as(u16, 0x8000) >> @intCast(b2))) == 0) continue;
        for (0..prot_len) |i| {
            const byte: u8 = if (i < p.payload.len) p.payload[i] else 0;
            recovered_payload[i] ^= byte;
        }
    }

    // Recover scalar header fields by XOR-ing out all received packets
    var pt_r: u7 = hdr.pt_recovery;
    var m_r: bool = hdr.m;
    var ts_r: u32 = hdr.ts_recovery;
    var len_r: u16 = hdr.length_recovery;

    for (received) |p| {
        const b2: u16 = p.seq -% hdr.sn_base;
        if (b2 >= 16) continue;
        if ((hdr.mask & (@as(u16, 0x8000) >> @intCast(b2))) == 0) continue;
        pt_r ^= p.pt;
        m_r = m_r != p.marker;
        ts_r ^= p.timestamp;
        len_r ^= @intCast(p.payload.len & 0xFFFF);
    }

    // Trim recovered_payload to actual length
    const actual_len: usize = @intCast(len_r);
    if (actual_len > prot_len) {
        allocator.free(recovered_payload);
        return error.RecoveredLengthExceedsProtection;
    }
    // Resize (shrink – won't fail)
    recovered_payload = try allocator.realloc(recovered_payload, actual_len);

    return MediaPacket{
        .seq = missing_seq,
        .pt = pt_r,
        .marker = m_r,
        .timestamp = ts_r,
        .payload = recovered_payload,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "RED encode/decode round-trip: primary only" {
    const alloc = testing.allocator;

    const blocks = [_]RedBlock{
        .{ .pt = 96, .timestamp_offset = 0, .payload = "hello" },
    };

    var buf: [256]u8 = undefined;
    const written = try redEncode(&blocks, &buf);

    var list: std.ArrayListUnmanaged(RedBlock) = .empty;
    defer list.deinit(alloc);
    try redDecode(alloc, buf[0..written], &list);

    try testing.expectEqual(@as(usize, 1), list.items.len);
    try testing.expectEqual(@as(u7, 96), list.items[0].pt);
    try testing.expectEqualSlices(u8, "hello", list.items[0].payload);
}

test "RED encode/decode round-trip: primary + 1 redundant" {
    const alloc = testing.allocator;

    const redundant_payload = [_]u8{ 0xAA, 0xBB, 0xCC };
    const primary_payload = [_]u8{ 0x01, 0x02, 0x03, 0x04 };

    const blocks = [_]RedBlock{
        .{ .pt = 111, .timestamp_offset = 160, .payload = &redundant_payload },
        .{ .pt = 96, .timestamp_offset = 0, .payload = &primary_payload },
    };

    var buf: [256]u8 = undefined;
    const written = try redEncode(&blocks, &buf);

    var list: std.ArrayListUnmanaged(RedBlock) = .empty;
    defer list.deinit(alloc);
    try redDecode(alloc, buf[0..written], &list);

    try testing.expectEqual(@as(usize, 2), list.items.len);
    // First decoded = first block (redundant)
    try testing.expectEqual(@as(u7, 111), list.items[0].pt);
    try testing.expectEqual(@as(u14, 160), list.items[0].timestamp_offset);
    try testing.expectEqualSlices(u8, &redundant_payload, list.items[0].payload);
    // Second decoded = primary
    try testing.expectEqual(@as(u7, 96), list.items[1].pt);
    try testing.expectEqual(@as(u14, 0), list.items[1].timestamp_offset);
    try testing.expectEqualSlices(u8, &primary_payload, list.items[1].payload);
}

test "RED encode/decode round-trip: primary + 2 redundant blocks" {
    const alloc = testing.allocator;

    const r0 = [_]u8{ 0x10, 0x20 };
    const r1 = [_]u8{ 0x30, 0x40, 0x50 };
    const prim = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };

    const blocks = [_]RedBlock{
        .{ .pt = 100, .timestamp_offset = 320, .payload = &r0 },
        .{ .pt = 100, .timestamp_offset = 160, .payload = &r1 },
        .{ .pt = 96, .timestamp_offset = 0, .payload = &prim },
    };

    var buf: [512]u8 = undefined;
    const written = try redEncode(&blocks, &buf);

    var list: std.ArrayListUnmanaged(RedBlock) = .empty;
    defer list.deinit(alloc);
    try redDecode(alloc, buf[0..written], &list);

    try testing.expectEqual(@as(usize, 3), list.items.len);
    try testing.expectEqual(@as(u14, 320), list.items[0].timestamp_offset);
    try testing.expectEqualSlices(u8, &r0, list.items[0].payload);
    try testing.expectEqual(@as(u14, 160), list.items[1].timestamp_offset);
    try testing.expectEqualSlices(u8, &r1, list.items[1].payload);
    try testing.expectEqualSlices(u8, &prim, list.items[2].payload);
}

test "RED decode truncated input returns error" {
    const alloc = testing.allocator;
    var list: std.ArrayListUnmanaged(RedBlock) = .empty;
    defer list.deinit(alloc);
    // Only 2 bytes: redundant header needs 4 bytes → TruncatedInput
    const bad = [_]u8{ 0x80 | 96, 0x00 };
    try testing.expectError(error.TruncatedInput, redDecode(alloc, &bad, &list));
}

test "RED encode buffer too small returns error" {
    const blocks = [_]RedBlock{
        .{ .pt = 96, .timestamp_offset = 0, .payload = "data" },
    };
    var tiny: [2]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, redEncode(&blocks, &tiny));
}

test "ULPFEC: build packet and parse header" {
    const p0_payload = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const p1_payload = [_]u8{ 0x10, 0x20, 0x30, 0x40 };
    const p2_payload = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };

    const packets = [_]MediaPacket{
        .{ .seq = 1000, .pt = 96, .marker = false, .timestamp = 0x1000, .payload = &p0_payload },
        .{ .seq = 1001, .pt = 96, .marker = false, .timestamp = 0x1080, .payload = &p1_payload },
        .{ .seq = 1002, .pt = 96, .marker = true, .timestamp = 0x1100, .payload = &p2_payload },
    };

    var fec_buf: [256]u8 = undefined;
    const written = try buildFecPacket(&packets, &fec_buf);
    try testing.expect(written >= FEC_OVERHEAD + 4);

    const hdr = try parseFecHeader(fec_buf[0..written]);
    try testing.expectEqual(@as(u16, 1000), hdr.sn_base);
    // Mask: bits 15, 14, 13 set for offsets 0, 1, 2
    try testing.expectEqual(@as(u16, 0xE000), hdr.mask);
    // PT recovery: 96 ^ 96 ^ 96 = 96
    try testing.expectEqual(@as(u7, 96), hdr.pt_recovery);
}

test "ULPFEC: XOR over N packets recovers a single dropped packet" {
    const alloc = testing.allocator;

    const p0_payload = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    const p1_payload = [_]u8{ 0xCA, 0xFE, 0xBA, 0xBE };
    const p2_payload = [_]u8{ 0x01, 0x23, 0x45, 0x67 };

    const all_packets = [_]MediaPacket{
        .{ .seq = 200, .pt = 97, .marker = false, .timestamp = 0x2000, .payload = &p0_payload },
        .{ .seq = 201, .pt = 97, .marker = false, .timestamp = 0x2100, .payload = &p1_payload },
        .{ .seq = 202, .pt = 97, .marker = true, .timestamp = 0x2200, .payload = &p2_payload },
    };

    var fec_buf: [256]u8 = undefined;
    const fec_len = try buildFecPacket(&all_packets, &fec_buf);

    // Simulate dropping packet seq=201
    const received = [_]MediaPacket{
        all_packets[0],
        all_packets[2],
    };

    const recovered = try recoverPacket(fec_buf[0..fec_len], &received, 201, alloc);
    defer if (recovered) |r| alloc.free(r.payload);

    try testing.expect(recovered != null);
    const r = recovered.?;
    try testing.expectEqual(@as(u16, 201), r.seq);
    try testing.expectEqual(@as(u7, 97), r.pt);
    try testing.expectEqual(false, r.marker);
    try testing.expectEqual(@as(u32, 0x2100), r.timestamp);
    try testing.expectEqualSlices(u8, &p1_payload, r.payload);
}

test "ULPFEC: recover first packet in group" {
    const alloc = testing.allocator;

    const a = [_]u8{ 0x11, 0x22 };
    const b = [_]u8{ 0x33, 0x44 };

    const all_packets = [_]MediaPacket{
        .{ .seq = 50, .pt = 98, .marker = false, .timestamp = 5000, .payload = &a },
        .{ .seq = 51, .pt = 98, .marker = false, .timestamp = 5160, .payload = &b },
    };

    var fec_buf: [256]u8 = undefined;
    const fec_len = try buildFecPacket(&all_packets, &fec_buf);

    // Drop seq=50
    const received = [_]MediaPacket{all_packets[1]};

    const recovered = try recoverPacket(fec_buf[0..fec_len], &received, 50, alloc);
    defer if (recovered) |r| alloc.free(r.payload);

    try testing.expect(recovered != null);
    const r = recovered.?;
    try testing.expectEqual(@as(u16, 50), r.seq);
    try testing.expectEqualSlices(u8, &a, r.payload);
    try testing.expectEqual(@as(u32, 5000), r.timestamp);
}

test "ULPFEC: cannot recover 2 losses from one FEC packet" {
    const alloc = testing.allocator;

    const a = [_]u8{0xAA};
    const b = [_]u8{0xBB};
    const c = [_]u8{0xCC};

    const all_packets = [_]MediaPacket{
        .{ .seq = 10, .pt = 99, .marker = false, .timestamp = 1000, .payload = &a },
        .{ .seq = 11, .pt = 99, .marker = false, .timestamp = 1160, .payload = &b },
        .{ .seq = 12, .pt = 99, .marker = false, .timestamp = 1320, .payload = &c },
    };

    var fec_buf: [256]u8 = undefined;
    const fec_len = try buildFecPacket(&all_packets, &fec_buf);

    // Only one packet received; two are missing → cannot recover
    const received = [_]MediaPacket{all_packets[2]};

    const result = try recoverPacket(fec_buf[0..fec_len], &received, 10, alloc);
    try testing.expect(result == null);
}

test "ULPFEC: missing_seq not protected returns null" {
    const alloc = testing.allocator;

    const a = [_]u8{0x01};
    const b = [_]u8{0x02};

    const all_packets = [_]MediaPacket{
        .{ .seq = 300, .pt = 96, .marker = false, .timestamp = 3000, .payload = &a },
        .{ .seq = 301, .pt = 96, .marker = false, .timestamp = 3160, .payload = &b },
    };

    var fec_buf: [256]u8 = undefined;
    const fec_len = try buildFecPacket(&all_packets, &fec_buf);

    const received = [_]MediaPacket{all_packets[1]};
    // seq=500 is not protected by this FEC packet
    const result = try recoverPacket(fec_buf[0..fec_len], &received, 500, alloc);
    try testing.expect(result == null);
}

test "ULPFEC: mask and level header parse correctness" {
    const a = [_]u8{ 0x01, 0x02, 0x03 };
    const b = [_]u8{ 0x04, 0x05, 0x06 };

    const packets = [_]MediaPacket{
        .{ .seq = 700, .pt = 96, .marker = false, .timestamp = 7000, .payload = &a },
        .{ .seq = 702, .pt = 96, .marker = false, .timestamp = 7320, .payload = &b },
        // seq 701 intentionally skipped — offset 1 should NOT be in mask
    };

    var fec_buf: [256]u8 = undefined;
    const written = try buildFecPacket(&packets, &fec_buf);
    const hdr = try parseFecHeader(fec_buf[0..written]);

    // Bit 15 = offset 0 (seq 700), bit 13 = offset 2 (seq 702)
    try testing.expectEqual(@as(u16, 700), hdr.sn_base);
    try testing.expectEqual(@as(u16, 0xA000), hdr.mask);
    try testing.expectEqual(@as(u16, 3), hdr.protection_length);
}

test "FEC parseFecHeader truncation" {
    const short = [_]u8{ 0x00, 0x00, 0x00 };
    try testing.expectError(error.TruncatedInput, parseFecHeader(&short));
}

test "buildFecPacket with no packets returns error" {
    var buf: [256]u8 = undefined;
    try testing.expectError(error.NoPackets, buildFecPacket(&[_]MediaPacket{}, &buf));
}

test "buildFecPacket too many packets returns error" {
    const pl = [_]u8{0x00};
    var packets: [17]MediaPacket = undefined;
    for (0..17) |i| {
        packets[i] = .{ .seq = @intCast(i), .pt = 96, .marker = false, .timestamp = 0, .payload = &pl };
    }
    var buf: [512]u8 = undefined;
    try testing.expectError(error.TooManyPackets, buildFecPacket(&packets, &buf));
}

test "ULPFEC: recover packet with variable-length payloads" {
    const alloc = testing.allocator;

    const short_payload = [_]u8{ 0xAA, 0xBB };
    const long_payload = [_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55 };

    const all_packets = [_]MediaPacket{
        .{ .seq = 400, .pt = 96, .marker = false, .timestamp = 4000, .payload = &short_payload },
        .{ .seq = 401, .pt = 96, .marker = false, .timestamp = 4160, .payload = &long_payload },
    };

    var fec_buf: [256]u8 = undefined;
    const fec_len = try buildFecPacket(&all_packets, &fec_buf);

    // Drop the shorter packet
    const received = [_]MediaPacket{all_packets[1]};
    const recovered = try recoverPacket(fec_buf[0..fec_len], &received, 400, alloc);
    defer if (recovered) |r| alloc.free(r.payload);

    try testing.expect(recovered != null);
    const r = recovered.?;
    try testing.expectEqual(@as(u16, 400), r.seq);
    try testing.expectEqualSlices(u8, &short_payload, r.payload);
}

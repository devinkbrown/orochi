const std = @import("std");

/// RFC 2198 RED codec errors.
pub const Error = error{ Truncated, TooManyBlocks, BufferTooSmall, BadFormat };

/// A single RED block. For redundant blocks `timestamp_offset` is the
/// (positive) magnitude of the negative offset from the primary RTP
/// timestamp; the primary block always has `timestamp_offset == 0`.
pub const Block = struct {
    pt: u7,
    timestamp_offset: u14,
    data: []const u8,
};

/// Maximum number of blocks (redundant + primary) handled in one packet.
pub const max_blocks: usize = 8;

const redundant_header_len: usize = 4;
const primary_header_len: usize = 1;
const max_block_len: usize = 1023; // 10-bit length field
const f_bit: u8 = 0x80;

/// Encodes redundant blocks followed by a primary block into RFC 2198 RED
/// payload format. Writes redundant headers (F=1) in order, the primary
/// header (F=0), then all block data (redundant first, primary last).
/// Returns the slice of `out` that was written.
pub fn encode(
    redundant: []const Block,
    primary_pt: u7,
    primary_data: []const u8,
    out: []u8,
) Error![]const u8 {
    if (redundant.len + 1 > max_blocks) return Error.TooManyBlocks;

    // Compute required size and validate redundant block lengths.
    var header_bytes: usize = primary_header_len;
    var data_bytes: usize = primary_data.len;
    for (redundant) |blk| {
        if (blk.data.len > max_block_len) return Error.BadFormat;
        header_bytes += redundant_header_len;
        data_bytes += blk.data.len;
    }
    const total = header_bytes + data_bytes;
    if (out.len < total) return Error.BufferTooSmall;

    var pos: usize = 0;

    // Redundant headers (F=1, 4 bytes each).
    for (redundant) |blk| {
        // byte 0: F(1) | PT(7)
        out[pos] = f_bit | @as(u8, blk.pt);
        // bytes 1..3: timestamp offset (14 bits) | block length (10 bits)
        // Layout big-endian across 3 bytes: TTTTTTTT TTTTTTLL LLLLLLLL
        const ts: u32 = @as(u32, blk.timestamp_offset);
        const len: u32 = @as(u32, @intCast(blk.data.len));
        const packed_bits: u32 = (ts << 10) | len; // 24 bits used
        out[pos + 1] = @intCast((packed_bits >> 16) & 0xff);
        out[pos + 2] = @intCast((packed_bits >> 8) & 0xff);
        out[pos + 3] = @intCast(packed_bits & 0xff);
        pos += redundant_header_len;
    }

    // Primary header (F=0, 1 byte).
    out[pos] = @as(u8, primary_pt) & 0x7f;
    pos += primary_header_len;

    // Data: redundant blocks in order, then primary.
    for (redundant) |blk| {
        @memcpy(out[pos .. pos + blk.data.len], blk.data);
        pos += blk.data.len;
    }
    @memcpy(out[pos .. pos + primary_data.len], primary_data);
    pos += primary_data.len;

    return out[0..pos];
}

/// Result of decoding a RED payload.
const DecodeResult = struct {
    blocks: []Block,
    primary_index: usize,
};

/// Decodes an RFC 2198 RED payload. Parses the header list (a 1-byte header
/// with F=0 terminates the list and marks the primary), then slices out each
/// block's data from `payload`. All slices borrow `payload`. Blocks are
/// written into `blocks_out` (redundant first, primary last). The returned
/// `primary_index` is the index of the primary block (always the last one).
pub fn decode(payload: []const u8, blocks_out: []Block) Error!DecodeResult {
    // Phase 1: parse headers, collecting redundant block (pt, ts, len) and
    // detecting the primary header.
    var header_pos: usize = 0;
    var count: usize = 0;
    var primary_pt: u7 = 0;

    while (true) {
        if (header_pos >= payload.len) return Error.Truncated;
        const b0 = payload[header_pos];
        const is_redundant = (b0 & f_bit) != 0;

        if (!is_redundant) {
            // Primary header: 1 byte, runs to end of packet.
            primary_pt = @intCast(b0 & 0x7f);
            header_pos += primary_header_len;
            break;
        }

        // Redundant header: needs 4 bytes.
        if (header_pos + redundant_header_len > payload.len) return Error.Truncated;
        if (count >= blocks_out.len) return Error.TooManyBlocks;

        const pt: u7 = @intCast(b0 & 0x7f);
        const packed_bits: u32 =
            (@as(u32, payload[header_pos + 1]) << 16) |
            (@as(u32, payload[header_pos + 2]) << 8) |
            @as(u32, payload[header_pos + 3]);
        const ts: u14 = @intCast((packed_bits >> 10) & 0x3fff);
        const len: usize = @intCast(packed_bits & 0x3ff);

        // Stash the declared length in `data.len`; phase 2 recomputes the
        // real offsets. Anchor at byte 0 — only `.len` is read back. Guard
        // against a length that cannot possibly fit so the slice is in-bounds.
        if (len > payload.len) return Error.Truncated;
        blocks_out[count] = .{
            .pt = pt,
            .timestamp_offset = ts,
            .data = payload[0..len],
        };
        count += 1;
        header_pos += redundant_header_len;
    }

    // Reserve a slot for the primary block.
    if (count >= blocks_out.len) return Error.TooManyBlocks;

    // Phase 2: assign data slices. Redundant blocks consume their declared
    // length (currently held in `data.len`) starting at header_pos; the
    // primary consumes the remainder.
    var data_pos: usize = header_pos;
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const len = blocks_out[i].data.len;
        if (data_pos + len > payload.len) return Error.Truncated;
        blocks_out[i].data = payload[data_pos .. data_pos + len];
        data_pos += len;
    }

    // Primary block: remaining bytes.
    blocks_out[count] = .{
        .pt = primary_pt,
        .timestamp_offset = 0,
        .data = payload[data_pos..payload.len],
    };
    const primary_index = count;
    count += 1;

    return .{ .blocks = blocks_out[0..count], .primary_index = primary_index };
}

test "encode then decode round-trips 2 redundant + primary" {
    const r0_data = "alpha";
    const r1_data = "bravo!!";
    const prim_data = "primary-payload";

    const redundant = [_]Block{
        .{ .pt = 96, .timestamp_offset = 320, .data = r0_data },
        .{ .pt = 97, .timestamp_offset = 640, .data = r1_data },
    };

    var buf: [128]u8 = undefined;
    const encoded = try encode(&redundant, 100, prim_data, &buf);

    var blocks: [max_blocks]Block = undefined;
    const result = try decode(encoded, &blocks);

    try std.testing.expectEqual(@as(usize, 3), result.blocks.len);
    try std.testing.expectEqual(@as(usize, 2), result.primary_index);

    // Redundant block 0
    try std.testing.expectEqual(@as(u7, 96), result.blocks[0].pt);
    try std.testing.expectEqual(@as(u14, 320), result.blocks[0].timestamp_offset);
    try std.testing.expectEqualStrings(r0_data, result.blocks[0].data);

    // Redundant block 1
    try std.testing.expectEqual(@as(u7, 97), result.blocks[1].pt);
    try std.testing.expectEqual(@as(u14, 640), result.blocks[1].timestamp_offset);
    try std.testing.expectEqualStrings(r1_data, result.blocks[1].data);

    // Primary block
    try std.testing.expectEqual(@as(u7, 100), result.blocks[2].pt);
    try std.testing.expectEqual(@as(u14, 0), result.blocks[2].timestamp_offset);
    try std.testing.expectEqualStrings(prim_data, result.blocks[2].data);
}

test "primary-only payload decodes to 1 block" {
    const prim_data = "just-the-primary";

    var buf: [64]u8 = undefined;
    const encoded = try encode(&[_]Block{}, 8, prim_data, &buf);

    var blocks: [max_blocks]Block = undefined;
    const result = try decode(encoded, &blocks);

    try std.testing.expectEqual(@as(usize, 1), result.blocks.len);
    try std.testing.expectEqual(@as(usize, 0), result.primary_index);
    try std.testing.expectEqual(@as(u7, 8), result.blocks[0].pt);
    try std.testing.expectEqual(@as(u14, 0), result.blocks[0].timestamp_offset);
    try std.testing.expectEqualStrings(prim_data, result.blocks[0].data);
}

test "Truncated when header claims more length than present" {
    // Hand-craft: one redundant header claiming len=10, but only 3 data
    // bytes plus a primary header follow.
    // Redundant header (4 bytes): F=1|PT=96, ts=0, len=10
    const len: u32 = 10;
    const packed_bits: u32 = (0 << 10) | len;
    var payload = [_]u8{
        f_bit | 96,
        @intCast((packed_bits >> 16) & 0xff),
        @intCast((packed_bits >> 8) & 0xff),
        @intCast(packed_bits & 0xff),
        8, // primary header F=0, PT=8
        'a', 'b', 'c', // only 3 bytes of redundant data (need 10)
    };

    var blocks: [max_blocks]Block = undefined;
    try std.testing.expectError(Error.Truncated, decode(&payload, &blocks));
}

test "BadFormat when redundant block exceeds 1023 bytes" {
    var big: [1024]u8 = undefined;
    @memset(&big, 'x');

    const redundant = [_]Block{
        .{ .pt = 96, .timestamp_offset = 0, .data = &big },
    };

    var buf: [2048]u8 = undefined;
    try std.testing.expectError(Error.BadFormat, encode(&redundant, 100, "p", &buf));
}

test "BufferTooSmall when out buffer cannot hold output" {
    const redundant = [_]Block{
        .{ .pt = 96, .timestamp_offset = 100, .data = "hello" },
    };
    var tiny: [4]u8 = undefined;
    try std.testing.expectError(Error.BufferTooSmall, encode(&redundant, 100, "primary", &tiny));
}

test "TooManyBlocks when blocks_out too small on decode" {
    const redundant = [_]Block{
        .{ .pt = 96, .timestamp_offset = 1, .data = "a" },
        .{ .pt = 97, .timestamp_offset = 2, .data = "b" },
    };
    var buf: [64]u8 = undefined;
    const encoded = try encode(&redundant, 100, "p", &buf);

    var blocks: [1]Block = undefined; // too small for 2 redundant + primary
    try std.testing.expectError(Error.TooManyBlocks, decode(encoded, &blocks));
}

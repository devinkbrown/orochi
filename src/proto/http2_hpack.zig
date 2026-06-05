//! HPACK header compression for HTTP/2 (RFC 7541).
//!
//! Implements:
//!   - Prefix integers (RFC 7541 §5.1)
//!   - String literals with Huffman coding (RFC 7541 §5.2 + Appendix B)
//!   - 61-entry static table (RFC 7541 Appendix A)
//!   - Dynamic table with bounded size and eviction
//!   - Full header list encode/decode
//!   - Decompression-bomb guard (configurable output cap)

const std = @import("std");
const mem = std.mem;
const testing = std.testing;

// ---------------------------------------------------------------------------
// Prefix-integer codec (RFC 7541 §5.1)
// ---------------------------------------------------------------------------

/// Encode `value` with an N-bit prefix into `buf`.
/// High bits of `buf[0]` above the N-bit field are set from `prefix_bits`.
/// Returns bytes written.
pub fn encodeInt(buf: []u8, n: u3, prefix_bits: u8, value: u64) error{NoSpaceLeft}!usize {
    const max_first: u64 = (@as(u64, 1) << n) - 1;
    if (buf.len == 0) return error.NoSpaceLeft;
    if (value < max_first) {
        buf[0] = (prefix_bits & ~(@as(u8, @intCast(max_first)))) | @as(u8, @intCast(value));
        return 1;
    }
    buf[0] = prefix_bits | @as(u8, @intCast(max_first));
    var rem: u64 = value - max_first;
    var i: usize = 1;
    while (rem >= 128) {
        if (i >= buf.len) return error.NoSpaceLeft;
        buf[i] = @as(u8, @intCast((rem & 0x7f) | 0x80));
        rem >>= 7;
        i += 1;
    }
    if (i >= buf.len) return error.NoSpaceLeft;
    buf[i] = @as(u8, @intCast(rem));
    return i + 1;
}

/// Decode a prefix integer from `data`.
/// `first_byte` is `data[0]` (already read by the caller for dispatch).
/// Returns `{value, bytes_consumed}` where consumed includes the first byte.
pub fn decodeInt(
    data: []const u8,
    n: u3,
    first_byte: u8,
) error{ Overflow, Truncated }!struct { value: u64, consumed: usize } {
    const mask: u8 = (@as(u8, 1) << n) - 1;
    const max_first: u64 = mask;
    var value: u64 = first_byte & mask;
    if (value < max_first) return .{ .value = value, .consumed = 1 };
    var shift: u6 = 0;
    var i: usize = 1;
    while (true) {
        if (i >= data.len) return error.Truncated;
        const b = data[i];
        i += 1;
        const contrib = @as(u64, b & 0x7f);
        if (shift >= 57) return error.Overflow;
        value += contrib << shift;
        shift += 7;
        if ((b & 0x80) == 0) break;
    }
    return .{ .value = value, .consumed = i };
}

// ---------------------------------------------------------------------------
// Huffman codec (RFC 7541 Appendix B — 257 entries: symbols 0-255 + EOS)
// ---------------------------------------------------------------------------

// Each row: {code, bit_length} for symbol index (0-255) + EOS (256).
// Source: RFC 7541 Appendix B, verified against hpack.js reference implementation.
const HUF_TABLE: [257][2]u32 = .{
    .{ 0x1ff8, 13 }, .{ 0x7fffd8, 23 }, .{ 0xfffffe2, 28 }, .{ 0xfffffe3, 28 }, // 0
    .{ 0xfffffe4, 28 }, .{ 0xfffffe5, 28 }, .{ 0xfffffe6, 28 }, .{ 0xfffffe7, 28 }, // 4
    .{ 0xfffffe8, 28 }, .{ 0xffffea, 24 }, .{ 0x3ffffffc, 30 }, .{ 0xfffffe9, 28 }, // 8
    .{ 0xfffffea, 28 }, .{ 0x3ffffffd, 30 }, .{ 0xfffffeb, 28 }, .{ 0xfffffec, 28 }, // 12
    .{ 0xfffffed, 28 }, .{ 0xfffffee, 28 }, .{ 0xfffffef, 28 }, .{ 0xffffff0, 28 }, // 16
    .{ 0xffffff1, 28 }, .{ 0xffffff2, 28 }, .{ 0x3ffffffe, 30 }, .{ 0xffffff3, 28 }, // 20
    .{ 0xffffff4, 28 }, .{ 0xffffff5, 28 }, .{ 0xffffff6, 28 }, .{ 0xffffff7, 28 }, // 24
    .{ 0xffffff8, 28 }, .{ 0xffffff9, 28 }, .{ 0xffffffa, 28 }, .{ 0xffffffb, 28 }, // 28
    .{ 0x14, 6 }, .{ 0x3f8, 10 }, .{ 0x3f9, 10 }, .{ 0xffa, 12 }, // 32 SP!"#
    .{ 0x1ff9, 13 }, .{ 0x15, 6 }, .{ 0xf8, 8 }, .{ 0x7fa, 11 }, // 36 $%&'
    .{ 0x3fa, 10 }, .{ 0x3fb, 10 }, .{ 0xf9, 8 }, .{ 0x7fb, 11 }, // 40 ()*+
    .{ 0xfa, 8 }, .{ 0x16, 6 }, .{ 0x17, 6 }, .{ 0x18, 6 }, // 44 ,-./
    .{ 0x0, 5 }, .{ 0x1, 5 }, .{ 0x2, 5 }, .{ 0x19, 6 }, // 48 0123
    .{ 0x1a, 6 }, .{ 0x1b, 6 }, .{ 0x1c, 6 }, .{ 0x1d, 6 }, // 52 4567
    .{ 0x1e, 6 }, .{ 0x1f, 6 }, .{ 0x5c, 7 }, .{ 0xfb, 8 }, // 56 89:;
    .{ 0x7ffc, 15 }, .{ 0x20, 6 }, .{ 0xffb, 12 }, .{ 0x3fc, 10 }, // 60 <=>?
    .{ 0x1ffa, 13 }, .{ 0x21, 6 }, .{ 0x5d, 7 }, .{ 0x5e, 7 }, // 64 @ABC
    .{ 0x5f, 7 }, .{ 0x60, 7 }, .{ 0x61, 7 }, .{ 0x62, 7 }, // 68 DEFG
    .{ 0x63, 7 }, .{ 0x64, 7 }, .{ 0x65, 7 }, .{ 0x66, 7 }, // 72 HIJK
    .{ 0x67, 7 }, .{ 0x68, 7 }, .{ 0x69, 7 }, .{ 0x6a, 7 }, // 76 LMNO
    .{ 0x6b, 7 }, .{ 0x6c, 7 }, .{ 0x6d, 7 }, .{ 0x6e, 7 }, // 80 PQRS
    .{ 0x6f, 7 }, .{ 0x70, 7 }, .{ 0x71, 7 }, .{ 0x72, 7 }, // 84 TUVW
    .{ 0xfc, 8 }, .{ 0x73, 7 }, .{ 0xfd, 8 }, .{ 0x1ffb, 13 }, // 88 XYZ[
    .{ 0x7fff0, 19 }, .{ 0x1ffc, 13 }, .{ 0x3ffc, 14 }, .{ 0x22, 6 }, // 92 \]^_
    .{ 0x7ffd, 15 }, .{ 0x3, 5 }, .{ 0x23, 6 }, .{ 0x4, 5 }, // 96 `abc
    .{ 0x24, 6 }, .{ 0x5, 5 }, .{ 0x25, 6 }, .{ 0x26, 6 }, // 100 defg
    .{ 0x27, 6 }, .{ 0x6, 5 }, .{ 0x74, 7 }, .{ 0x75, 7 }, // 104 hijk
    .{ 0x28, 6 }, .{ 0x29, 6 }, .{ 0x2a, 6 }, .{ 0x7, 5 }, // 108 lmno
    .{ 0x2b, 6 }, .{ 0x76, 7 }, .{ 0x2c, 6 }, .{ 0x8, 5 }, // 112 pqrs
    .{ 0x9, 5 }, .{ 0x2d, 6 }, .{ 0x77, 7 }, .{ 0x78, 7 }, // 116 tuvw
    .{ 0x79, 7 }, .{ 0x7a, 7 }, .{ 0x7b, 7 }, .{ 0x7ffe, 15 }, // 120 xyz{
    .{ 0x7fc, 11 }, .{ 0x3ffd, 14 }, .{ 0x1ffd, 13 }, .{ 0xffffffc, 28 }, // 124 |}~DEL
    .{ 0xfffe6, 20 }, .{ 0x3fffd2, 22 }, .{ 0xfffe7, 20 }, .{ 0xfffe8, 20 }, // 128
    .{ 0x3fffd3, 22 }, .{ 0x3fffd4, 22 }, .{ 0x3fffd5, 22 }, .{ 0x7fffd9, 23 }, // 132
    .{ 0x3fffd6, 22 }, .{ 0x7fffda, 23 }, .{ 0x7fffdb, 23 }, .{ 0x7fffdc, 23 }, // 136
    .{ 0x7fffdd, 23 }, .{ 0x7fffde, 23 }, .{ 0xffffeb, 24 }, .{ 0x7fffdf, 23 }, // 140
    .{ 0xffffec, 24 }, .{ 0xffffed, 24 }, .{ 0x3fffd7, 22 }, .{ 0x7fffe0, 23 }, // 144
    .{ 0xffffee, 24 }, .{ 0x7fffe1, 23 }, .{ 0x7fffe2, 23 }, .{ 0x7fffe3, 23 }, // 148
    .{ 0x7fffe4, 23 }, .{ 0x1fffdc, 21 }, .{ 0x3fffd8, 22 }, .{ 0x7fffe5, 23 }, // 152
    .{ 0x3fffd9, 22 }, .{ 0x7fffe6, 23 }, .{ 0x7fffe7, 23 }, .{ 0xffffef, 24 }, // 156
    .{ 0x3fffda, 22 }, .{ 0x1fffdd, 21 }, .{ 0xfffe9, 20 }, .{ 0x3fffdb, 22 }, // 160
    .{ 0x3fffdc, 22 }, .{ 0x7fffe8, 23 }, .{ 0x7fffe9, 23 }, .{ 0x1fffde, 21 }, // 164
    .{ 0x7fffea, 23 }, .{ 0x3fffdd, 22 }, .{ 0x3fffde, 22 }, .{ 0xfffff0, 24 }, // 168
    .{ 0x1fffdf, 21 }, .{ 0x3fffdf, 22 }, .{ 0x7fffeb, 23 }, .{ 0x7fffec, 23 }, // 172
    .{ 0x1fffe0, 21 }, .{ 0x1fffe1, 21 }, .{ 0x3fffe0, 22 }, .{ 0x1fffe2, 21 }, // 176
    .{ 0x7fffed, 23 }, .{ 0x3fffe1, 22 }, .{ 0x7fffee, 23 }, .{ 0x7fffef, 23 }, // 180
    .{ 0xfffea, 20 }, .{ 0x3fffe2, 22 }, .{ 0x3fffe3, 22 }, .{ 0x3fffe4, 22 }, // 184
    .{ 0x7ffff0, 23 }, .{ 0x3fffe5, 22 }, .{ 0x3fffe6, 22 }, .{ 0x7ffff1, 23 }, // 188
    .{ 0x3ffffe0, 26 }, .{ 0x3ffffe1, 26 }, .{ 0xfffeb, 20 }, .{ 0x7fff1, 19 }, // 192
    .{ 0x3fffe7, 22 }, .{ 0x7ffff2, 23 }, .{ 0x3fffe8, 22 }, .{ 0x1ffffec, 25 }, // 196
    .{ 0x3ffffe2, 26 }, .{ 0x3ffffe3, 26 }, .{ 0x3ffffe4, 26 }, .{ 0x7ffffde, 27 }, // 200
    .{ 0x7ffffdf, 27 }, .{ 0x3ffffe5, 26 }, .{ 0xfffff1, 24 }, .{ 0x1ffffed, 25 }, // 204
    .{ 0x7fff2, 19 }, .{ 0x1fffe3, 21 }, .{ 0x3ffffe6, 26 }, .{ 0x7ffffe0, 27 }, // 208
    .{ 0x7ffffe1, 27 }, .{ 0x3ffffe7, 26 }, .{ 0x7ffffe2, 27 }, .{ 0xfffff2, 24 }, // 212
    .{ 0x1fffe4, 21 }, .{ 0x1fffe5, 21 }, .{ 0x3ffffe8, 26 }, .{ 0x3ffffe9, 26 }, // 216
    .{ 0xffffffd, 28 }, .{ 0x7ffffe3, 27 }, .{ 0x7ffffe4, 27 }, .{ 0x7ffffe5, 27 }, // 220
    .{ 0xfffec, 20 }, .{ 0xfffff3, 24 }, .{ 0xfffed, 20 }, .{ 0x1fffe6, 21 }, // 224
    .{ 0x3fffe9, 22 }, .{ 0x1fffe7, 21 }, .{ 0x1fffe8, 21 }, .{ 0x7ffff3, 23 }, // 228
    .{ 0x3fffea, 22 }, .{ 0x3fffeb, 22 }, .{ 0x1ffffee, 25 }, .{ 0x1ffffef, 25 }, // 232
    .{ 0xfffff4, 24 }, .{ 0xfffff5, 24 }, .{ 0x3ffffea, 26 }, .{ 0x7ffff4, 23 }, // 236
    .{ 0x3ffffeb, 26 }, .{ 0x7ffffe6, 27 }, .{ 0x3ffffec, 26 }, .{ 0x3ffffed, 26 }, // 240
    .{ 0x7ffffe7, 27 }, .{ 0x7ffffe8, 27 }, .{ 0x7ffffe9, 27 }, .{ 0x7ffffea, 27 }, // 244
    .{ 0x7ffffeb, 27 }, .{ 0xffffffe, 28 }, .{ 0x7ffffec, 27 }, .{ 0x7ffffed, 27 }, // 248
    .{ 0x7ffffee, 27 }, .{ 0x7ffffef, 27 }, .{ 0x7fffff0, 27 }, .{ 0x3ffffee, 26 }, // 252
    .{ 0x3fffffff, 30 }, // 256 EOS
};

/// Huffman-encode `src` into `out`. Returns bytes written.
pub fn huffmanEncode(out: []u8, src: []const u8) error{NoSpaceLeft}!usize {
    @memset(out, 0);
    var bit_pos: usize = 0;
    for (src) |byte| {
        const entry = HUF_TABLE[byte];
        const code = entry[0];
        const bits: usize = entry[1];
        var b: usize = bits;
        while (b > 0) {
            b -= 1;
            const bit: u1 = @intCast((code >> @intCast(b)) & 1);
            const byte_idx = bit_pos / 8;
            const bit_shift: u3 = @intCast(7 - (bit_pos % 8));
            if (byte_idx >= out.len) return error.NoSpaceLeft;
            if (bit == 1) out[byte_idx] |= @as(u8, 1) << bit_shift;
            bit_pos += 1;
        }
    }
    // Pad final partial byte with 1-bits (EOS prefix)
    while (bit_pos % 8 != 0) {
        const byte_idx = bit_pos / 8;
        const bit_shift: u3 = @intCast(7 - (bit_pos % 8));
        if (byte_idx >= out.len) return error.NoSpaceLeft;
        out[byte_idx] |= @as(u8, 1) << bit_shift;
        bit_pos += 1;
    }
    return bit_pos / 8;
}

/// Compute the Huffman-encoded byte length without writing.
pub fn huffmanEncodedLen(src: []const u8) usize {
    var bits: usize = 0;
    for (src) |b| bits += HUF_TABLE[b][1];
    return (bits + 7) / 8;
}

/// Huffman-decode `src` into `out`. Returns bytes written.
pub fn huffmanDecode(out: []u8, src: []const u8) error{ NoSpaceLeft, InvalidCode, EarlyEOS }!usize {
    var out_len: usize = 0;
    var bit_buf: u64 = 0;
    var bits_avail: u8 = 0; // max 64, u6 would overflow at 56+8
    var src_idx: usize = 0;

    while (true) {
        // Refill bit buffer (keep bits_avail <= 64)
        while (bits_avail <= 56 and src_idx < src.len) {
            bit_buf = (bit_buf << 8) | src[src_idx];
            bits_avail += 8;
            src_idx += 1;
        }
        if (bits_avail == 0) break;

        var matched = false;
        for (0..256) |sym| {
            const bits: u8 = @intCast(HUF_TABLE[sym][1]);
            if (bits > bits_avail) continue;
            const code = HUF_TABLE[sym][0];
            const shift: u6 = @intCast(bits_avail - bits);
            const candidate: u32 = @intCast((bit_buf >> shift) & ((@as(u64, 1) << @intCast(bits)) - 1));
            if (candidate == code) {
                if (out_len >= out.len) return error.NoSpaceLeft;
                out[out_len] = @intCast(sym);
                out_len += 1;
                bits_avail -= bits;
                if (bits_avail == 0) {
                    bit_buf = 0;
                } else {
                    bit_buf &= (@as(u64, 1) << @intCast(bits_avail)) - 1;
                }
                matched = true;
                break;
            }
        }
        if (!matched) {
            // Remaining bits must be padding: < 8 bits, all ones
            if (bits_avail >= 8) return error.InvalidCode;
            const padding_mask = (@as(u64, 1) << @as(u6, @intCast(bits_avail))) - 1;
            if ((bit_buf & padding_mask) != padding_mask) return error.InvalidCode;
            break;
        }
    }
    return out_len;
}

// ---------------------------------------------------------------------------
// Static table (RFC 7541 Appendix A, 61 entries)
// ---------------------------------------------------------------------------

pub const HeaderField = struct {
    name: []const u8,
    value: []const u8,
};

const STATIC_TABLE: [61]HeaderField = .{
    .{ .name = ":authority", .value = "" },
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":method", .value = "POST" },
    .{ .name = ":path", .value = "/" },
    .{ .name = ":path", .value = "/index.html" },
    .{ .name = ":scheme", .value = "http" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":status", .value = "200" },
    .{ .name = ":status", .value = "204" },
    .{ .name = ":status", .value = "206" },
    .{ .name = ":status", .value = "304" },
    .{ .name = ":status", .value = "400" },
    .{ .name = ":status", .value = "404" },
    .{ .name = ":status", .value = "500" },
    .{ .name = "accept-charset", .value = "" },
    .{ .name = "accept-encoding", .value = "gzip, deflate" },
    .{ .name = "accept-language", .value = "" },
    .{ .name = "accept-ranges", .value = "" },
    .{ .name = "accept", .value = "" },
    .{ .name = "access-control-allow-origin", .value = "" },
    .{ .name = "age", .value = "" },
    .{ .name = "allow", .value = "" },
    .{ .name = "authorization", .value = "" },
    .{ .name = "cache-control", .value = "" },
    .{ .name = "content-disposition", .value = "" },
    .{ .name = "content-encoding", .value = "" },
    .{ .name = "content-language", .value = "" },
    .{ .name = "content-length", .value = "" },
    .{ .name = "content-location", .value = "" },
    .{ .name = "content-range", .value = "" },
    .{ .name = "content-type", .value = "" },
    .{ .name = "cookie", .value = "" },
    .{ .name = "date", .value = "" },
    .{ .name = "etag", .value = "" },
    .{ .name = "expect", .value = "" },
    .{ .name = "expires", .value = "" },
    .{ .name = "from", .value = "" },
    .{ .name = "host", .value = "" },
    .{ .name = "if-match", .value = "" },
    .{ .name = "if-modified-since", .value = "" },
    .{ .name = "if-none-match", .value = "" },
    .{ .name = "if-range", .value = "" },
    .{ .name = "if-unmodified-since", .value = "" },
    .{ .name = "last-modified", .value = "" },
    .{ .name = "link", .value = "" },
    .{ .name = "location", .value = "" },
    .{ .name = "max-forwards", .value = "" },
    .{ .name = "proxy-authenticate", .value = "" },
    .{ .name = "proxy-authorization", .value = "" },
    .{ .name = "range", .value = "" },
    .{ .name = "referer", .value = "" },
    .{ .name = "refresh", .value = "" },
    .{ .name = "retry-after", .value = "" },
    .{ .name = "server", .value = "" },
    .{ .name = "set-cookie", .value = "" },
    .{ .name = "strict-transport-security", .value = "" },
    .{ .name = "transfer-encoding", .value = "" },
    .{ .name = "user-agent", .value = "" },
    .{ .name = "vary", .value = "" },
    .{ .name = "via", .value = "" },
    .{ .name = "www-authenticate", .value = "" },
};

// ---------------------------------------------------------------------------
// Dynamic table
// ---------------------------------------------------------------------------

pub const DynamicTable = struct {
    entries: std.ArrayListUnmanaged(OwnedHeader),
    current_size: usize,
    max_size: usize,
    protocol_max: usize,

    const Self = @This();

    pub const OwnedHeader = struct {
        name: []u8,
        value: []u8,

        fn entrySize(self: OwnedHeader) usize {
            return self.name.len + self.value.len + 32;
        }

        fn deinit(self: OwnedHeader, alloc: mem.Allocator) void {
            alloc.free(self.name);
            alloc.free(self.value);
        }
    };

    pub fn init(max_size: usize) Self {
        return .{
            .entries = std.ArrayListUnmanaged(OwnedHeader).empty,
            .current_size = 0,
            .max_size = max_size,
            .protocol_max = max_size,
        };
    }

    pub fn deinit(self: *Self, alloc: mem.Allocator) void {
        for (self.entries.items) |e| e.deinit(alloc);
        self.entries.deinit(alloc);
    }

    /// Add a header. Evicts oldest entries to make room.
    pub fn add(self: *Self, alloc: mem.Allocator, name: []const u8, value: []const u8) !void {
        const entry_size = name.len + value.len + 32;
        if (entry_size > self.max_size) {
            self.evictAll(alloc);
            return;
        }
        while (self.current_size + entry_size > self.max_size) {
            self.evictOldest(alloc);
        }
        const owned_name = try alloc.dupe(u8, name);
        errdefer alloc.free(owned_name);
        const owned_value = try alloc.dupe(u8, value);
        errdefer alloc.free(owned_value);
        try self.entries.insert(alloc, 0, .{ .name = owned_name, .value = owned_value });
        self.current_size += entry_size;
    }

    /// Apply a dynamic table size update instruction.
    pub fn updateMaxSize(self: *Self, alloc: mem.Allocator, new_max: usize) void {
        self.max_size = @min(new_max, self.protocol_max);
        while (self.current_size > self.max_size) {
            self.evictOldest(alloc);
        }
    }

    fn evictOldest(self: *Self, alloc: mem.Allocator) void {
        if (self.entries.items.len == 0) return;
        const last = self.entries.pop().?;
        self.current_size -= last.entrySize();
        last.deinit(alloc);
    }

    fn evictAll(self: *Self, alloc: mem.Allocator) void {
        for (self.entries.items) |e| e.deinit(alloc);
        self.entries.clearRetainingCapacity();
        self.current_size = 0;
    }

    /// Look up by 1-based index (static 1..61, dynamic 62+).
    pub fn get(self: *const Self, index: u64) ?HeaderField {
        if (index == 0) return null;
        if (index <= 61) return STATIC_TABLE[index - 1];
        const dyn_idx = index - 62;
        if (dyn_idx >= self.entries.items.len) return null;
        const e = self.entries.items[dyn_idx];
        return HeaderField{ .name = e.name, .value = e.value };
    }

    /// Find the 1-based index for a name+value pair.
    /// Returns {index, full=true} for an exact match, {index, full=false} for name-only.
    pub fn findIndex(
        self: *const Self,
        name: []const u8,
        value: []const u8,
    ) ?struct { index: u64, full: bool } {
        var name_only: ?u64 = null;
        for (STATIC_TABLE, 0..) |hf, i| {
            if (mem.eql(u8, hf.name, name)) {
                if (mem.eql(u8, hf.value, value)) return .{ .index = i + 1, .full = true };
                if (name_only == null) name_only = i + 1;
            }
        }
        for (self.entries.items, 0..) |e, i| {
            if (mem.eql(u8, e.name, name)) {
                if (mem.eql(u8, e.value, value)) return .{ .index = i + 62, .full = true };
                if (name_only == null) name_only = i + 62;
            }
        }
        if (name_only) |idx| return .{ .index = idx, .full = false };
        return null;
    }
};

// ---------------------------------------------------------------------------
// HPACK encoder
// ---------------------------------------------------------------------------

pub const IndexingMode = enum {
    incremental, // §6.2.1 — adds to dynamic table
    without_indexing, // §6.2.2
    never_indexed, // §6.2.3
};

pub const EncodeOpts = struct {
    use_huffman: bool = true,
    indexing: IndexingMode = .incremental,
};

fn encodeString(buf: []u8, s: []const u8, use_huffman: bool) error{NoSpaceLeft}!usize {
    if (use_huffman) {
        const hlen = huffmanEncodedLen(s);
        var tmp: [10]u8 = undefined;
        const lbytes = try encodeInt(&tmp, 7, 0x80, hlen);
        if (lbytes + hlen > buf.len) return error.NoSpaceLeft;
        @memcpy(buf[0..lbytes], tmp[0..lbytes]);
        const written = try huffmanEncode(buf[lbytes..][0..hlen], s);
        return lbytes + written;
    } else {
        var tmp: [10]u8 = undefined;
        const lbytes = try encodeInt(&tmp, 7, 0x00, s.len);
        if (lbytes + s.len > buf.len) return error.NoSpaceLeft;
        @memcpy(buf[0..lbytes], tmp[0..lbytes]);
        @memcpy(buf[lbytes..][0..s.len], s);
        return lbytes + s.len;
    }
}

/// Encode a header list into `buf`. Returns bytes written.
pub fn encode(
    buf: []u8,
    alloc: mem.Allocator,
    table: *DynamicTable,
    headers: []const HeaderField,
    opts: EncodeOpts,
) !usize {
    var pos: usize = 0;
    for (headers) |hf| {
        // Indexed representation when we have a full match
        if (table.findIndex(hf.name, hf.value)) |found| {
            if (found.full) {
                var tmp: [10]u8 = undefined;
                const n = try encodeInt(&tmp, 7, 0x80, found.index);
                if (pos + n > buf.len) return error.NoSpaceLeft;
                @memcpy(buf[pos..][0..n], tmp[0..n]);
                pos += n;
                continue;
            }
        }
        switch (opts.indexing) {
            .incremental => {
                // 6-bit prefix, flag 0x40
                if (table.findIndex(hf.name, hf.value)) |found| {
                    var tmp: [10]u8 = undefined;
                    const n = try encodeInt(&tmp, 6, 0x40, found.index);
                    if (pos + n > buf.len) return error.NoSpaceLeft;
                    @memcpy(buf[pos..][0..n], tmp[0..n]);
                    pos += n;
                } else {
                    if (pos >= buf.len) return error.NoSpaceLeft;
                    buf[pos] = 0x40;
                    pos += 1;
                    const nn = try encodeString(buf[pos..], hf.name, opts.use_huffman);
                    pos += nn;
                }
                const vn = try encodeString(buf[pos..], hf.value, opts.use_huffman);
                pos += vn;
                try table.add(alloc, hf.name, hf.value);
            },
            .without_indexing => {
                if (pos >= buf.len) return error.NoSpaceLeft;
                buf[pos] = 0x00;
                pos += 1;
                const nn = try encodeString(buf[pos..], hf.name, opts.use_huffman);
                pos += nn;
                const vn = try encodeString(buf[pos..], hf.value, opts.use_huffman);
                pos += vn;
            },
            .never_indexed => {
                if (pos >= buf.len) return error.NoSpaceLeft;
                buf[pos] = 0x10;
                pos += 1;
                const nn = try encodeString(buf[pos..], hf.name, opts.use_huffman);
                pos += nn;
                const vn = try encodeString(buf[pos..], hf.value, opts.use_huffman);
                pos += vn;
            },
        }
    }
    return pos;
}

// ---------------------------------------------------------------------------
// HPACK decoder
// ---------------------------------------------------------------------------

pub const DecodeError = error{
    Truncated,
    InvalidIndex,
    InvalidHuffman,
    DecompressionBomb,
    InvalidTableSizeUpdate,
    Overflow,
    NoSpaceLeft,
    OutOfMemory,
};

fn decodeString(
    data: []const u8,
    pos: *usize,
    out: *std.ArrayListUnmanaged(u8),
    alloc: mem.Allocator,
    bomb_limit: usize,
) DecodeError!void {
    if (pos.* >= data.len) return error.Truncated;
    const first = data[pos.*];
    const is_huffman = (first & 0x80) != 0;
    const lr = decodeInt(data[pos.*..], 7, first) catch |e| switch (e) {
        error.Overflow => return error.Overflow,
        error.Truncated => return error.Truncated,
    };
    pos.* += lr.consumed;
    const slen: usize = @intCast(lr.value);
    if (pos.* + slen > data.len) return error.Truncated;
    const raw = data[pos.*..][0..slen];
    pos.* += slen;

    if (is_huffman) {
        const max_decoded = @min(slen * 8, bomb_limit + 1);
        const tmp = try alloc.alloc(u8, max_decoded);
        defer alloc.free(tmp);
        const n = huffmanDecode(tmp, raw) catch |e| switch (e) {
            error.NoSpaceLeft => return error.DecompressionBomb,
            error.InvalidCode, error.EarlyEOS => return error.InvalidHuffman,
        };
        if (out.items.len + n > bomb_limit) return error.DecompressionBomb;
        try out.appendSlice(alloc, tmp[0..n]);
    } else {
        if (out.items.len + slen > bomb_limit) return error.DecompressionBomb;
        try out.appendSlice(alloc, raw);
    }
}

pub const DecodedHeader = struct {
    name: []u8,
    value: []u8,

    pub fn deinit(self: DecodedHeader, alloc: mem.Allocator) void {
        alloc.free(self.name);
        alloc.free(self.value);
    }
};

// Decode a literal header field (§6.2.x). `name_idx` is 0 for new name, else table index.
// `add_to_table` controls incremental indexing. `total_bytes` is updated in place.
fn decodeLiteral(
    data: []const u8,
    pos: *usize,
    alloc: mem.Allocator,
    table: *DynamicTable,
    name_idx: u64,
    add_to_table: bool,
    bomb_limit: usize,
    total_bytes: *usize,
) DecodeError!DecodedHeader {
    var name_buf = std.ArrayListUnmanaged(u8).empty;
    defer name_buf.deinit(alloc);
    var value_buf = std.ArrayListUnmanaged(u8).empty;
    defer value_buf.deinit(alloc);
    if (name_idx != 0) {
        const hf = table.get(name_idx) orelse return error.InvalidIndex;
        try name_buf.appendSlice(alloc, hf.name);
    } else {
        try decodeString(data, pos, &name_buf, alloc, bomb_limit);
    }
    try decodeString(data, pos, &value_buf, alloc, bomb_limit);
    total_bytes.* += name_buf.items.len + value_buf.items.len;
    if (total_bytes.* > bomb_limit) return error.DecompressionBomb;
    if (add_to_table) try table.add(alloc, name_buf.items, value_buf.items);
    return .{
        .name = try name_buf.toOwnedSlice(alloc),
        .value = try value_buf.toOwnedSlice(alloc),
    };
}

/// Decode a complete HPACK block. Caller frees each DecodedHeader and the slice.
pub fn decode(
    data: []const u8,
    alloc: mem.Allocator,
    table: *DynamicTable,
    bomb_limit: usize,
) DecodeError![]DecodedHeader {
    var headers = std.ArrayListUnmanaged(DecodedHeader).empty;
    errdefer {
        for (headers.items) |h| h.deinit(alloc);
        headers.deinit(alloc);
    }
    var total_bytes: usize = 0;
    var pos: usize = 0;

    while (pos < data.len) {
        const b = data[pos];
        if ((b & 0x80) != 0) {
            // §6.1 Indexed header field
            const r = decodeInt(data[pos..], 7, b) catch |e| switch (e) {
                error.Overflow => return error.Overflow,
                error.Truncated => return error.Truncated,
            };
            pos += r.consumed;
            if (r.value == 0) return error.InvalidIndex;
            const hf = table.get(r.value) orelse return error.InvalidIndex;
            total_bytes += hf.name.len + hf.value.len;
            if (total_bytes > bomb_limit) return error.DecompressionBomb;
            try headers.append(alloc, .{
                .name = try alloc.dupe(u8, hf.name),
                .value = try alloc.dupe(u8, hf.value),
            });
        } else if ((b & 0x40) != 0) {
            // §6.2.1 Literal with incremental indexing
            const r = decodeInt(data[pos..], 6, b) catch |e| switch (e) {
                error.Overflow => return error.Overflow,
                error.Truncated => return error.Truncated,
            };
            pos += r.consumed;
            const dh = try decodeLiteral(data, &pos, alloc, table, r.value, true, bomb_limit, &total_bytes);
            try headers.append(alloc, dh);
        } else if ((b & 0x20) != 0) {
            // §6.3 Dynamic table size update
            const r = decodeInt(data[pos..], 5, b) catch |e| switch (e) {
                error.Overflow => return error.Overflow,
                error.Truncated => return error.Truncated,
            };
            pos += r.consumed;
            if (r.value > table.protocol_max) return error.InvalidTableSizeUpdate;
            table.updateMaxSize(alloc, @intCast(r.value));
        } else {
            // §6.2.2 Literal without indexing (0x0X) or §6.2.3 never indexed (0x1X)
            const n_bits: u3 = 4;
            const r = decodeInt(data[pos..], n_bits, b) catch |e| switch (e) {
                error.Overflow => return error.Overflow,
                error.Truncated => return error.Truncated,
            };
            pos += r.consumed;
            const dh = try decodeLiteral(data, &pos, alloc, table, r.value, false, bomb_limit, &total_bytes);
            try headers.append(alloc, dh);
        }
    }
    return headers.toOwnedSlice(alloc);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "prefix int round-trip small" {
    var buf: [16]u8 = undefined;
    const n = try encodeInt(&buf, 5, 0, 10);
    try testing.expectEqual(@as(usize, 1), n);
    const r = try decodeInt(buf[0..n], 5, buf[0]);
    try testing.expectEqual(@as(u64, 10), r.value);
    try testing.expectEqual(n, r.consumed);
}

test "prefix int round-trip at boundary" {
    var buf: [16]u8 = undefined;
    const n = try encodeInt(&buf, 5, 0, 31);
    try testing.expect(n > 1);
    const r = try decodeInt(buf[0..n], 5, buf[0]);
    try testing.expectEqual(@as(u64, 31), r.value);
}

test "prefix int RFC 7541 C.1.1 value 1337 N=5" {
    // RFC §C.1.1: N=5, value=1337 → 0x1f 0x9a 0x0a
    var buf: [16]u8 = undefined;
    const n = try encodeInt(&buf, 5, 0, 1337);
    try testing.expectEqual(@as(usize, 3), n);
    try testing.expectEqual(@as(u8, 0x1f), buf[0]);
    try testing.expectEqual(@as(u8, 0x9a), buf[1]);
    try testing.expectEqual(@as(u8, 0x0a), buf[2]);
    const r = try decodeInt(buf[0..n], 5, buf[0]);
    try testing.expectEqual(@as(u64, 1337), r.value);
}

test "prefix int large value round-trip" {
    var buf: [16]u8 = undefined;
    const value: u64 = 1_000_000_000;
    const n = try encodeInt(&buf, 3, 0, value);
    const r = try decodeInt(buf[0..n], 3, buf[0]);
    try testing.expectEqual(value, r.value);
}

test "huffman encode/decode round-trip ASCII" {
    const alloc = testing.allocator;
    const src = "www.example.com";
    const hlen = huffmanEncodedLen(src);
    const enc_buf = try alloc.alloc(u8, hlen);
    defer alloc.free(enc_buf);
    const enc_n = try huffmanEncode(enc_buf, src);
    try testing.expectEqual(hlen, enc_n);
    const dec_buf = try alloc.alloc(u8, src.len);
    defer alloc.free(dec_buf);
    const dec_n = try huffmanDecode(dec_buf, enc_buf[0..enc_n]);
    try testing.expectEqual(src.len, dec_n);
    try testing.expectEqualSlices(u8, src, dec_buf[0..dec_n]);
}

test "huffman RFC C.4: no-cache encodes to 6 bytes" {
    // RFC §C.4.1: "no-cache" Huffman-encoded is 0xa8eb10649cbf (6 bytes)
    const alloc = testing.allocator;
    const src = "no-cache";
    const hlen = huffmanEncodedLen(src);
    const enc_buf = try alloc.alloc(u8, hlen);
    defer alloc.free(enc_buf);
    const n = try huffmanEncode(enc_buf, src);
    try testing.expectEqual(@as(usize, 6), n);
    // Verify round-trip
    const dec_buf = try alloc.alloc(u8, 32);
    defer alloc.free(dec_buf);
    const dn = try huffmanDecode(dec_buf, enc_buf[0..n]);
    try testing.expectEqualSlices(u8, src, dec_buf[0..dn]);
}

test "huffman encode/decode full byte range 0-127" {
    const alloc = testing.allocator;
    var src: [128]u8 = undefined;
    for (0..128) |i| src[i] = @intCast(i);
    const hlen = huffmanEncodedLen(&src);
    const enc_buf = try alloc.alloc(u8, hlen);
    defer alloc.free(enc_buf);
    _ = try huffmanEncode(enc_buf, &src);
    const dec_buf = try alloc.alloc(u8, 256);
    defer alloc.free(dec_buf);
    const dn = try huffmanDecode(dec_buf, enc_buf);
    try testing.expectEqualSlices(u8, &src, dec_buf[0..dn]);
}

test "static table lookup" {
    var table = DynamicTable.init(4096);
    const hf1 = table.get(1).?;
    try testing.expectEqualStrings(":authority", hf1.name);
    const hf2 = table.get(2).?;
    try testing.expectEqualStrings("GET", hf2.value);
    const hf61 = table.get(61).?;
    try testing.expectEqualStrings("www-authenticate", hf61.name);
    try testing.expect(table.get(0) == null);
    try testing.expect(table.get(62) == null);
}

test "dynamic table add and lookup" {
    const alloc = testing.allocator;
    var table = DynamicTable.init(4096);
    defer table.deinit(alloc);
    try table.add(alloc, "custom-key", "custom-value");
    const hf = table.get(62).?;
    try testing.expectEqualStrings("custom-key", hf.name);
    // Adding another entry pushes the previous to index 63
    try table.add(alloc, "second-key", "second-value");
    const hf2 = table.get(62).?;
    try testing.expectEqualStrings("second-key", hf2.name);
    const hf3 = table.get(63).?;
    try testing.expectEqualStrings("custom-key", hf3.name);
}

test "dynamic table eviction on size update" {
    const alloc = testing.allocator;
    var table = DynamicTable.init(4096);
    defer table.deinit(alloc);
    try table.add(alloc, "key1", "val1"); // 4+4+32 = 40
    try table.add(alloc, "key2", "val2"); // 40 → total 80
    try testing.expectEqual(@as(usize, 80), table.current_size);
    // Shrink to 50 — evicts key1 (oldest)
    table.updateMaxSize(alloc, 50);
    try testing.expect(table.current_size <= 50);
    try testing.expectEqual(@as(usize, 1), table.entries.items.len);
    try testing.expectEqualStrings("key2", table.entries.items[0].name);
}

test "dynamic table evict all when entry exceeds max" {
    const alloc = testing.allocator;
    var table = DynamicTable.init(50);
    defer table.deinit(alloc);
    try table.add(alloc, "a", "b"); // 34 bytes
    // Entry alone exceeds max_size → evict everything, do not add
    try table.add(alloc, "this-name-is-very-long-exceeding-limit", "value");
    try testing.expectEqual(@as(usize, 0), table.entries.items.len);
}

test "malformed index 0 rejected" {
    const alloc = testing.allocator;
    var table = DynamicTable.init(4096);
    defer table.deinit(alloc);
    const data = [_]u8{0x80}; // indexed representation, index=0
    const result = decode(&data, alloc, &table, 65536);
    try testing.expectError(error.InvalidIndex, result);
}

test "out-of-range dynamic index rejected" {
    const alloc = testing.allocator;
    var table = DynamicTable.init(4096);
    defer table.deinit(alloc);
    var buf: [4]u8 = undefined;
    const n = try encodeInt(&buf, 7, 0x80, 62);
    const result = decode(buf[0..n], alloc, &table, 65536);
    try testing.expectError(error.InvalidIndex, result);
}

test "decompression bomb guard" {
    const alloc = testing.allocator;
    var table = DynamicTable.init(4096);
    defer table.deinit(alloc);
    // Build a literal-without-indexing block: name="x", value=200 bytes of 'a'
    var buf: [300]u8 = undefined;
    var pos: usize = 0;
    buf[pos] = 0x00;
    pos += 1; // literal without indexing, name index = 0
    buf[pos] = 0x01;
    pos += 1; // raw name len = 1
    buf[pos] = 'x';
    pos += 1;
    // value length = 200 (raw, 7-bit prefix)
    const vlen_bytes = try encodeInt(buf[pos..], 7, 0x00, 200);
    pos += vlen_bytes;
    @memset(buf[pos..][0..200], 'a');
    pos += 200;
    // bomb_limit = 10 — should trigger the guard
    const result = decode(buf[0..pos], alloc, &table, 10);
    try testing.expectError(error.DecompressionBomb, result);
}

test "encode/decode round-trip incremental indexing no huffman" {
    const alloc = testing.allocator;
    var enc_table = DynamicTable.init(4096);
    defer enc_table.deinit(alloc);
    var dec_table = DynamicTable.init(4096);
    defer dec_table.deinit(alloc);

    const headers = [_]HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/index.html" },
        .{ .name = "x-custom", .value = "hello" },
    };
    var buf: [1024]u8 = undefined;
    const n = try encode(&buf, alloc, &enc_table, &headers, .{ .use_huffman = false });
    const decoded = try decode(buf[0..n], alloc, &dec_table, 65536);
    defer {
        for (decoded) |h| h.deinit(alloc);
        alloc.free(decoded);
    }
    try testing.expectEqual(@as(usize, 3), decoded.len);
    try testing.expectEqualStrings(":method", decoded[0].name);
    try testing.expectEqualStrings("GET", decoded[0].value);
    try testing.expectEqualStrings(":path", decoded[1].name);
    try testing.expectEqualStrings("/index.html", decoded[1].value);
    try testing.expectEqualStrings("x-custom", decoded[2].name);
    try testing.expectEqualStrings("hello", decoded[2].value);
}

test "encode/decode round-trip with huffman" {
    const alloc = testing.allocator;
    var enc_table = DynamicTable.init(4096);
    defer enc_table.deinit(alloc);
    var dec_table = DynamicTable.init(4096);
    defer dec_table.deinit(alloc);

    const headers = [_]HeaderField{
        .{ .name = "content-type", .value = "application/json" },
        .{ .name = "authorization", .value = "Bearer token123" },
    };
    var buf: [512]u8 = undefined;
    const n = try encode(&buf, alloc, &enc_table, &headers, .{ .use_huffman = true });
    const decoded = try decode(buf[0..n], alloc, &dec_table, 65536);
    defer {
        for (decoded) |h| h.deinit(alloc);
        alloc.free(decoded);
    }
    try testing.expectEqual(@as(usize, 2), decoded.len);
    try testing.expectEqualStrings("content-type", decoded[0].name);
    try testing.expectEqualStrings("application/json", decoded[0].value);
    try testing.expectEqualStrings("authorization", decoded[1].name);
    try testing.expectEqualStrings("Bearer token123", decoded[1].value);
}

test "never-indexed does not pollute dynamic table" {
    const alloc = testing.allocator;
    var enc_table = DynamicTable.init(4096);
    defer enc_table.deinit(alloc);
    var dec_table = DynamicTable.init(4096);
    defer dec_table.deinit(alloc);

    const headers = [_]HeaderField{.{ .name = "password", .value = "s3cr3t" }};
    var buf: [128]u8 = undefined;
    const n = try encode(&buf, alloc, &enc_table, &headers, .{
        .use_huffman = false,
        .indexing = .never_indexed,
    });
    try testing.expectEqual(@as(usize, 0), enc_table.entries.items.len);
    const decoded = try decode(buf[0..n], alloc, &dec_table, 65536);
    defer {
        for (decoded) |h| h.deinit(alloc);
        alloc.free(decoded);
    }
    try testing.expectEqual(@as(usize, 1), decoded.len);
    try testing.expectEqualStrings("password", decoded[0].name);
    try testing.expectEqualStrings("s3cr3t", decoded[0].value);
    try testing.expectEqual(@as(usize, 0), dec_table.entries.items.len);
}

test "dynamic table size update instruction in stream" {
    const alloc = testing.allocator;
    var table = DynamicTable.init(4096);
    defer table.deinit(alloc);
    try table.add(alloc, "k1", "v1"); // 2+2+32=36
    try table.add(alloc, "k2", "v2"); // total 72
    try testing.expectEqual(@as(usize, 72), table.current_size);
    // Encode a size update to 40 and decode it
    var buf: [32]u8 = undefined;
    var pos: usize = 0;
    const su = try encodeInt(buf[pos..], 5, 0x20, 40);
    pos += su;
    const decoded = try decode(buf[0..pos], alloc, &table, 65536);
    defer {
        for (decoded) |h| h.deinit(alloc);
        alloc.free(decoded);
    }
    try testing.expect(table.current_size <= 40);
    try testing.expectEqual(@as(usize, 1), table.entries.items.len);
}

test "findIndex name-only and full match" {
    const alloc = testing.allocator;
    var table = DynamicTable.init(4096);
    defer table.deinit(alloc);
    // :method GET → full match at index 2
    const fm = table.findIndex(":method", "GET").?;
    try testing.expectEqual(@as(u64, 2), fm.index);
    try testing.expect(fm.full);
    // :method DELETE → name-only match
    const nm = table.findIndex(":method", "DELETE").?;
    try testing.expect(!nm.full);
    // Unknown → null
    try testing.expect(table.findIndex("x-nope", "v") == null);
}

test "RFC C.6 response sequence with evictions on 256-byte table" {
    // Verifies encode+decode across three responses that exercise eviction.
    const alloc = testing.allocator;
    var enc_table = DynamicTable.init(256);
    defer enc_table.deinit(alloc);
    var dec_table = DynamicTable.init(256);
    defer dec_table.deinit(alloc);

    const r1 = [_]HeaderField{
        .{ .name = ":status", .value = "302" },
        .{ .name = "cache-control", .value = "private" },
        .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
        .{ .name = "location", .value = "https://www.example.com" },
    };
    var buf: [2048]u8 = undefined;
    const n1 = try encode(&buf, alloc, &enc_table, &r1, .{ .use_huffman = true });
    const d1 = try decode(buf[0..n1], alloc, &dec_table, 65536);
    defer {
        for (d1) |h| h.deinit(alloc);
        alloc.free(d1);
    }
    try testing.expectEqual(@as(usize, 4), d1.len);
    try testing.expectEqualStrings("302", d1[0].value);

    const r2 = [_]HeaderField{
        .{ .name = ":status", .value = "307" },
        .{ .name = "cache-control", .value = "private" },
        .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
        .{ .name = "location", .value = "https://www.example.com" },
    };
    const n2 = try encode(buf[0..], alloc, &enc_table, &r2, .{ .use_huffman = true });
    const d2 = try decode(buf[0..n2], alloc, &dec_table, 65536);
    defer {
        for (d2) |h| h.deinit(alloc);
        alloc.free(d2);
    }
    try testing.expectEqual(@as(usize, 4), d2.len);
    try testing.expectEqualStrings("307", d2[0].value);

    const r3 = [_]HeaderField{
        .{ .name = ":status", .value = "200" },
        .{ .name = "cache-control", .value = "private" },
        .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:22 GMT" },
        .{ .name = "content-encoding", .value = "gzip" },
        .{ .name = "set-cookie", .value = "foo=ASDJKHQKBZXOQWEOPIUAXQ; max-age=3600" },
    };
    const n3 = try encode(buf[0..], alloc, &enc_table, &r3, .{ .use_huffman = true });
    const d3 = try decode(buf[0..n3], alloc, &dec_table, 65536);
    defer {
        for (d3) |h| h.deinit(alloc);
        alloc.free(d3);
    }
    try testing.expectEqual(@as(usize, 5), d3.len);
    try testing.expectEqualStrings("200", d3[0].value);
    // Both sides must remain in sync after evictions
    try testing.expectEqual(enc_table.current_size, dec_table.current_size);
}

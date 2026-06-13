//! QPACK header compression for HTTP/3 (RFC 9204).
//!
//! Self-contained, std-only implementation using only the STATIC TABLE
//! (no dynamic table).  Required Insert Count and Base are always zero,
//! making the encoded field section fully decodable without encoder-stream
//! coordination.
//!
//! Supported representations (RFC 9204 §4):
//!   - Indexed Field Line — static table (prefix 1xxxxxxx, T=1)
//!   - Literal Field Line With Name Reference — static table name
//!     (prefix 0100xxxx, N=0, T=1)
//!   - Literal Field Line With Literal Name
//!     (prefix 001xxxxx)
//!
//! Integer and string encoding follows RFC 7541 §§5.1–5.2 (reused by
//! QPACK).  Huffman encoding is NOT applied (Huffman bit always 0).

const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayListUnmanaged;

// ---------------------------------------------------------------------------
// Prefix-integer encode / decode  (RFC 7541 §5.1)
// ---------------------------------------------------------------------------

pub const IntError = error{
    Overflow,
    Truncated,
};

/// Encode `value` into `buf` using an N-bit prefix stored in the high bits of
/// `prefix_bits` (the N low bits of the first byte).  Returns the number of
/// bytes written.  `buf` must be at least 11 bytes (worst case for 1-bit
/// prefix and a 64-bit value).
pub fn encodeInt(buf: []u8, n_bits: u4, prefix_bits: u8, value: u64) usize {
    const max_prefix: u64 = (@as(u64, 1) << n_bits) - 1;
    const mask: u8 = @intCast(max_prefix);
    const high: u8 = prefix_bits & ~mask; // caller-supplied high bits

    if (value < max_prefix) {
        buf[0] = high | @as(u8, @intCast(value));
        return 1;
    }
    buf[0] = high | mask;
    var rem: u64 = value - max_prefix;
    var i: usize = 1;
    while (rem >= 128) {
        buf[i] = @as(u8, @intCast(rem & 0x7f)) | 0x80;
        rem >>= 7;
        i += 1;
    }
    buf[i] = @as(u8, @intCast(rem));
    return i + 1;
}

/// Decode a prefix integer from `data`.  `n_bits` is the number of low bits
/// in `data[0]` that carry the integer.  Returns `{value, bytes_consumed}`.
pub fn decodeInt(data: []const u8, n_bits: u4) IntError!struct { value: u64, consumed: usize } {
    if (data.len == 0) return IntError.Truncated;
    const max_prefix: u64 = (@as(u64, 1) << n_bits) - 1;
    const first: u64 = data[0] & @as(u8, @intCast(max_prefix));
    if (first < max_prefix) return .{ .value = first, .consumed = 1 };

    // Multi-byte continuation
    var value: u64 = max_prefix;
    var shift: u6 = 0;
    var i: usize = 1;
    while (true) {
        if (i >= data.len) return IntError.Truncated;
        const b = data[i];
        i += 1;
        const bits: u64 = b & 0x7f;
        // Overflow guard: shift must not exceed 63
        if (shift > 56) return IntError.Overflow;
        value +|= bits << shift;
        shift += 7;
        if (b & 0x80 == 0) break;
    }
    return .{ .value = value, .consumed = i };
}

// ---------------------------------------------------------------------------
// String literals  (RFC 7541 §5.2) — Huffman bit always 0
// ---------------------------------------------------------------------------

pub const StringError = error{
    Truncated,
    HuffmanNotSupported,
    IntError,
} || IntError;

/// Encode a string literal into `out`.  Huffman bit = 0.
/// Returns number of bytes written.
pub fn encodeString(out: []u8, s: []const u8) error{NoSpaceLeft}!usize {
    var tmp: [11]u8 = undefined;
    const len_bytes = encodeInt(&tmp, 7, 0x00, s.len);
    if (len_bytes > out.len) return error.NoSpaceLeft;
    if (s.len > out.len - len_bytes) return error.NoSpaceLeft;
    @memcpy(out[0..len_bytes], tmp[0..len_bytes]);
    @memcpy(out[len_bytes..][0..s.len], s);
    return len_bytes + s.len;
}

/// Decode a string literal from `data`.  Returns `{slice_into_data, bytes_consumed}`.
/// The returned slice points into `data` (no allocation).
pub fn decodeString(data: []const u8) StringError!struct { str: []const u8, consumed: usize } {
    if (data.len == 0) return StringError.Truncated;
    const huffman_bit = (data[0] & 0x80) != 0;
    if (huffman_bit) return StringError.HuffmanNotSupported;

    const r = try decodeInt(data, 7);
    const start = r.consumed;
    const end = start + @as(usize, r.value);
    if (end > data.len) return StringError.Truncated;
    return .{ .str = data[start..end], .consumed = end };
}

// ---------------------------------------------------------------------------
// QPACK static table (RFC 9204 Appendix A, 99 entries, 1-indexed)
// ---------------------------------------------------------------------------

pub const StaticEntry = struct {
    name: []const u8,
    value: []const u8,
};

// Entry 0 is a sentinel; real entries are at indices 1–99.
pub const STATIC_TABLE = [_]StaticEntry{
    .{ .name = "", .value = "" }, // sentinel index 0
    .{ .name = ":authority", .value = "" },
    .{ .name = ":path", .value = "/" },
    .{ .name = "age", .value = "0" },
    .{ .name = "content-disposition", .value = "" },
    .{ .name = "content-length", .value = "0" },
    .{ .name = "cookie", .value = "" },
    .{ .name = "date", .value = "" },
    .{ .name = "etag", .value = "" },
    .{ .name = "if-modified-since", .value = "" },
    .{ .name = "if-none-match", .value = "" }, // 10
    .{ .name = "last-modified", .value = "" },
    .{ .name = "link", .value = "" },
    .{ .name = "location", .value = "" },
    .{ .name = "referer", .value = "" },
    .{ .name = "set-cookie", .value = "" },
    .{ .name = ":method", .value = "CONNECT" },
    .{ .name = ":method", .value = "DELETE" },
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":method", .value = "HEAD" },
    .{ .name = ":method", .value = "OPTIONS" }, // 20
    .{ .name = ":method", .value = "POST" },
    .{ .name = ":method", .value = "PUT" },
    .{ .name = ":scheme", .value = "http" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":status", .value = "103" },
    .{ .name = ":status", .value = "200" },
    .{ .name = ":status", .value = "304" },
    .{ .name = ":status", .value = "404" },
    .{ .name = ":status", .value = "503" },
    .{ .name = "accept", .value = "*/*" }, // 30
    .{ .name = "accept", .value = "application/dns-message" },
    .{ .name = "accept-encoding", .value = "gzip, deflate, br" },
    .{ .name = "accept-ranges", .value = "bytes" },
    .{ .name = "access-control-allow-headers", .value = "cache-control" },
    .{ .name = "access-control-allow-headers", .value = "content-type" },
    .{ .name = "access-control-allow-origin", .value = "*" },
    .{ .name = "cache-control", .value = "max-age=0" },
    .{ .name = "cache-control", .value = "max-age=2592000" },
    .{ .name = "cache-control", .value = "max-age=604800" },
    .{ .name = "cache-control", .value = "no-cache" }, // 40
    .{ .name = "cache-control", .value = "no-store" },
    .{ .name = "cache-control", .value = "public, max-age=31536000" },
    .{ .name = "content-encoding", .value = "br" },
    .{ .name = "content-encoding", .value = "gzip" },
    .{ .name = "content-type", .value = "application/dns-message" },
    .{ .name = "content-type", .value = "application/javascript" },
    .{ .name = "content-type", .value = "application/json" },
    .{ .name = "content-type", .value = "application/x-www-form-urlencoded" },
    .{ .name = "content-type", .value = "image/gif" },
    .{ .name = "content-type", .value = "image/jpeg" }, // 50
    .{ .name = "content-type", .value = "image/png" },
    .{ .name = "content-type", .value = "text/css" },
    .{ .name = "content-type", .value = "text/html; charset=utf-8" },
    .{ .name = "content-type", .value = "text/plain" },
    .{ .name = "content-type", .value = "text/plain;charset=utf-8" },
    .{ .name = "range", .value = "bytes=0-" },
    .{ .name = "strict-transport-security", .value = "max-age=31536000" },
    .{ .name = "strict-transport-security", .value = "max-age=31536000; includesubdomains" },
    .{ .name = "strict-transport-security", .value = "max-age=31536000; includesubdomains; preload" },
    .{ .name = "vary", .value = "accept-encoding" }, // 60
    .{ .name = "vary", .value = "origin" },
    .{ .name = "x-content-type-options", .value = "nosniff" },
    .{ .name = "x-xss-protection", .value = "1; mode=block" },
    .{ .name = ":status", .value = "100" },
    .{ .name = ":status", .value = "204" },
    .{ .name = ":status", .value = "206" },
    .{ .name = ":status", .value = "302" },
    .{ .name = ":status", .value = "400" },
    .{ .name = ":status", .value = "403" },
    .{ .name = ":status", .value = "421" }, // 70
    .{ .name = ":status", .value = "425" },
    .{ .name = ":status", .value = "500" },
    .{ .name = "accept-language", .value = "" },
    .{ .name = "access-control-allow-credentials", .value = "FALSE" },
    .{ .name = "access-control-allow-credentials", .value = "TRUE" },
    .{ .name = "access-control-allow-headers", .value = "*" },
    .{ .name = "access-control-allow-methods", .value = "get" },
    .{ .name = "access-control-allow-methods", .value = "get, post, options" },
    .{ .name = "access-control-allow-methods", .value = "options" },
    .{ .name = "access-control-allow-origin", .value = "\"\"" }, // 80 (empty string per RFC)
    .{ .name = "access-control-expose-headers", .value = "content-length" },
    .{ .name = "access-control-request-headers", .value = "content-type" },
    .{ .name = "access-control-request-method", .value = "get" },
    .{ .name = "access-control-request-method", .value = "post" },
    .{ .name = "alt-svc", .value = "clear" },
    .{ .name = "authorization", .value = "" },
    .{ .name = "content-security-policy", .value = "script-src 'none'; object-src 'none'; base-uri 'none'" },
    .{ .name = "early-data", .value = "1" },
    .{ .name = "expect-ct", .value = "" },
    .{ .name = "forwarded", .value = "" }, // 90
    .{ .name = "if-range", .value = "" },
    .{ .name = "origin", .value = "" },
    .{ .name = "purpose", .value = "prefetch" },
    .{ .name = "server", .value = "" },
    .{ .name = "timing-allow-origin", .value = "*" },
    .{ .name = "upgrade-insecure-requests", .value = "1" },
    .{ .name = "user-agent", .value = "" },
    .{ .name = "x-forwarded-for", .value = "" },
    .{ .name = "x-frame-options", .value = "deny" },
    .{ .name = "x-frame-options", .value = "sameorigin" }, // 99
};

pub const STATIC_TABLE_SIZE: usize = STATIC_TABLE.len - 1; // 99 real entries

/// Look up an exact name+value match in the static table. Returns 1-based index or 0.
pub fn staticLookupExact(name: []const u8, value: []const u8) u7 {
    for (STATIC_TABLE[1..], 1..) |entry, idx| {
        if (std.mem.eql(u8, entry.name, name) and std.mem.eql(u8, entry.value, value))
            return @intCast(idx);
    }
    return 0;
}

/// Look up name-only match (first occurrence). Returns 1-based index or 0.
pub fn staticLookupName(name: []const u8) u7 {
    for (STATIC_TABLE[1..], 1..) |entry, idx| {
        if (std.mem.eql(u8, entry.name, name))
            return @intCast(idx);
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Field header: a name/value pair (owned or borrowed)
// ---------------------------------------------------------------------------

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

// ---------------------------------------------------------------------------
// Encode a field section (RFC 9204 §4)
// ---------------------------------------------------------------------------

pub const EncodeError = error{
    OutOfMemory,
    NoSpaceLeft,
};

/// Encode a slice of headers into QPACK-encoded field section bytes.
/// Required Insert Count = 0, Base = 0, static-table only.
/// Caller owns returned slice (allocated from `allocator`).
pub fn encodeFieldSection(allocator: Allocator, headers: []const Header) EncodeError![]u8 {
    var buf = ArrayList(u8).empty;
    errdefer buf.deinit(allocator);

    // Required Insert Count = 0, S=0, Base delta = 0
    // Section prefix: two integers, each 0.
    // RIC: prefix=8, value=0 → 1 byte 0x00
    // Base: S bit (bit 7) = 0, value=0 → 1 byte 0x00
    try buf.append(allocator, 0x00); // RIC = 0
    try buf.append(allocator, 0x00); // S=0, base delta=0

    var tmp: [256]u8 = undefined;

    for (headers) |h| {
        const exact = staticLookupExact(h.name, h.value);
        if (exact != 0) {
            // Indexed Field Line, T=1 (static), 6-bit index
            // Format: 1 T 6*index  → 0b11xxxxxx  (T=1 means 0xC0 | idx)
            const n = encodeInt(&tmp, 6, 0xC0, exact);
            try buf.appendSlice(allocator, tmp[0..n]);
            continue;
        }

        const name_idx = staticLookupName(h.name);
        if (name_idx != 0) {
            // Literal Field Line With Name Reference (static), N=0
            // Format: 0 1 0 0 T 4*index  → 0b0100xxxx  (T=1: 0x50 | idx)
            const n = encodeInt(&tmp, 4, 0x50, name_idx);
            try buf.appendSlice(allocator, tmp[0..n]);
            // value string
            const vs = try encodeString(tmp[n..], h.value);
            try buf.appendSlice(allocator, tmp[n .. n + vs]);
            continue;
        }

        // Literal Field Line With Literal Name (never-indexed bit N=0)
        // Format: 0 0 1 N H 3*name-length  → 0b001 0 0 xxx = 0x20
        {
            const n = encodeInt(&tmp, 3, 0x20, h.name.len);
            try buf.appendSlice(allocator, tmp[0..n]);
            try buf.appendSlice(allocator, h.name);
            const vs = try encodeString(tmp[0..], h.value);
            try buf.appendSlice(allocator, tmp[0..vs]);
        }
    }

    return buf.toOwnedSlice(allocator);
}

// ---------------------------------------------------------------------------
// Decode a field section
// ---------------------------------------------------------------------------

pub const DecodeError = error{
    OutOfMemory,
    Truncated,
    InvalidRepresentation,
    StaticIndexOutOfRange,
    HuffmanNotSupported,
    IntegerOverflow,
};

/// Decode a QPACK-encoded field section.  Returns an owned slice of Headers.
/// All name/value slices point into `data` — no extra allocation for strings.
/// Caller must free the returned slice with `allocator.free(result)`.
pub fn decodeFieldSection(allocator: Allocator, data: []const u8) DecodeError![]Header {
    if (data.len < 2) return DecodeError.Truncated;

    // Skip section prefix (RIC + Base); we only handle RIC=0, Base=0.
    // RIC is an 8-bit prefix integer.
    const ric_r = decodeInt(data[0..], 8) catch return DecodeError.Truncated;
    _ = ric_r.value; // we don't validate, just skip
    if (ric_r.consumed > data.len) return DecodeError.Truncated;

    // Base is a 7-bit prefix integer (S bit is bit 7 of that byte).
    const base_data = data[ric_r.consumed..];
    if (base_data.len == 0) return DecodeError.Truncated;
    const base_r = decodeInt(base_data, 7) catch return DecodeError.Truncated;
    _ = base_r.value;
    const payload_start = ric_r.consumed + base_r.consumed;

    var headers = ArrayList(Header).empty;
    errdefer headers.deinit(allocator);

    var pos: usize = payload_start;
    while (pos < data.len) {
        const b = data[pos];

        if (b & 0x80 != 0) {
            // Indexed Field Line (bit pattern 1xxxxxxx)
            // T bit = bit 6: 1 = static, 0 = dynamic (we reject dynamic)
            if (b & 0x40 == 0) return DecodeError.InvalidRepresentation; // dynamic
            const r = decodeInt(data[pos..], 6) catch return DecodeError.Truncated;
            pos += r.consumed;
            const idx = r.value;
            if (idx == 0 or idx > STATIC_TABLE_SIZE) return DecodeError.StaticIndexOutOfRange;
            try headers.append(allocator, .{
                .name = STATIC_TABLE[idx].name,
                .value = STATIC_TABLE[idx].value,
            });
        } else if (b & 0x40 != 0) {
            // Literal With Name Reference (bit pattern 01xxxxxx)
            // Next bit (0x20) = N (never-indexed); bit 0x10 = T (static/dynamic)
            if (b & 0x10 == 0) return DecodeError.InvalidRepresentation; // dynamic name ref
            const r = decodeInt(data[pos..], 4) catch return DecodeError.Truncated;
            pos += r.consumed;
            const idx = r.value;
            if (idx == 0 or idx > STATIC_TABLE_SIZE) return DecodeError.StaticIndexOutOfRange;
            const name = STATIC_TABLE[idx].name;
            const vs = decodeString(data[pos..]) catch return DecodeError.Truncated;
            pos += vs.consumed;
            try headers.append(allocator, .{ .name = name, .value = vs.str });
        } else if (b & 0x20 != 0) {
            // Literal With Literal Name (bit pattern 001xxxxx)
            // Bits: 0 0 1 N H 3*name-length
            if (b & 0x08 != 0) return DecodeError.HuffmanNotSupported; // H bit in name
            const nr = decodeInt(data[pos..], 3) catch return DecodeError.Truncated;
            pos += nr.consumed;
            const nlen: usize = @intCast(nr.value);
            if (pos + nlen > data.len) return DecodeError.Truncated;
            const name = data[pos .. pos + nlen];
            pos += nlen;
            const vs = decodeString(data[pos..]) catch return DecodeError.Truncated;
            pos += vs.consumed;
            try headers.append(allocator, .{ .name = name, .value = vs.str });
        } else {
            return DecodeError.InvalidRepresentation;
        }
    }

    return headers.toOwnedSlice(allocator);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "prefix integer: single-byte values" {
    var buf: [16]u8 = undefined;

    // 5-bit prefix, value 0
    const n0 = encodeInt(&buf, 5, 0x00, 0);
    try testing.expectEqual(@as(usize, 1), n0);
    const r0 = try decodeInt(buf[0..n0], 5);
    try testing.expectEqual(@as(u64, 0), r0.value);
    try testing.expectEqual(n0, r0.consumed);

    // 5-bit prefix, max single-byte value = 30
    const n30 = encodeInt(&buf, 5, 0x00, 30);
    try testing.expectEqual(@as(usize, 1), n30);
    const r30 = try decodeInt(buf[0..n30], 5);
    try testing.expectEqual(@as(u64, 30), r30.value);

    // 5-bit prefix, value 31 triggers continuation
    const n31 = encodeInt(&buf, 5, 0x00, 31);
    try testing.expect(n31 >= 2);
    const r31 = try decodeInt(buf[0..n31], 5);
    try testing.expectEqual(@as(u64, 31), r31.value);
}

test "prefix integer: multi-byte continuation" {
    var buf: [16]u8 = undefined;

    // 5-bit prefix, value 1337 (from RFC 7541 example)
    const n = encodeInt(&buf, 5, 0x00, 1337);
    const r = try decodeInt(buf[0..n], 5);
    try testing.expectEqual(@as(u64, 1337), r.value);
    try testing.expectEqual(n, r.consumed);

    // 1-bit prefix, large value
    const big: u64 = 100_000;
    const nb = encodeInt(&buf, 1, 0x00, big);
    const rb = try decodeInt(buf[0..nb], 1);
    try testing.expectEqual(big, rb.value);
}

test "prefix integer: boundary values for each prefix width" {
    var buf: [16]u8 = undefined;
    const widths = [_]u4{ 1, 2, 3, 4, 5, 6, 7, 8 };
    for (widths) |w| {
        const max: u64 = (@as(u64, 1) << w) - 1;
        // value just below boundary (single byte)
        if (max > 0) {
            const n = encodeInt(&buf, w, 0x00, max - 1);
            try testing.expectEqual(@as(usize, 1), n);
            const r = try decodeInt(buf[0..n], w);
            try testing.expectEqual(max - 1, r.value);
        }
        // value at boundary (triggers continuation)
        const n2 = encodeInt(&buf, w, 0x00, max);
        const r2 = try decodeInt(buf[0..n2], w);
        try testing.expectEqual(max, r2.value);
        // value above boundary
        const n3 = encodeInt(&buf, w, 0x00, max + 1);
        const r3 = try decodeInt(buf[0..n3], w);
        try testing.expectEqual(max + 1, r3.value);
    }
}

test "prefix integer: truncation error" {
    var buf: [16]u8 = undefined;
    const n = encodeInt(&buf, 5, 0x00, 1337);
    try testing.expect(n >= 2); // must be multi-byte
    // Feed only first byte of a multi-byte encoding
    const result = decodeInt(buf[0..1], 5);
    try testing.expectError(IntError.Truncated, result);
}

test "prefix integer: high bits preserved" {
    var buf: [4]u8 = undefined;
    // 6-bit prefix with 0xC0 high bits (Indexed Field Line pattern)
    const n = encodeInt(&buf, 6, 0xC0, 18);
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expectEqual(@as(u8, 0xC0 | 18), buf[0]);
    const r = try decodeInt(buf[0..n], 6);
    try testing.expectEqual(@as(u64, 18), r.value);
}

test "string literal: round-trip" {
    var buf: [64]u8 = undefined;
    const s = "hello";
    const n = try encodeString(&buf, s);
    const r = try decodeString(buf[0..n]);
    try testing.expectEqualStrings(s, r.str);
    try testing.expectEqual(n, r.consumed);
}

test "string literal: empty string" {
    var buf: [4]u8 = undefined;
    const n = try encodeString(&buf, "");
    const r = try decodeString(buf[0..n]);
    try testing.expectEqualStrings("", r.str);
}

test "string literal: long string" {
    var buf: [512]u8 = undefined;
    const s = "x" ** 200;
    const n = try encodeString(&buf, s);
    const r = try decodeString(buf[0..n]);
    try testing.expectEqualStrings(s, r.str);
}

test "string literal: truncation" {
    var buf: [8]u8 = undefined;
    const s = "hello";
    const n = try encodeString(&buf, s);
    // Truncate to just the length prefix
    const result = decodeString(buf[0..1]);
    try testing.expectError(StringError.Truncated, result);
    _ = n;
}

test "static table: lookup exact" {
    try testing.expectEqual(@as(u7, 18), staticLookupExact(":method", "GET"));
    try testing.expectEqual(@as(u7, 26), staticLookupExact(":status", "200"));
    try testing.expectEqual(@as(u7, 0), staticLookupExact(":method", "PATCH")); // not in table
}

test "static table: lookup name only" {
    const idx = staticLookupName(":authority");
    try testing.expectEqual(@as(u7, 1), idx);
    const idx2 = staticLookupName("x-custom-header");
    try testing.expectEqual(@as(u7, 0), idx2);
}

test "encode/decode: indexed field from static table" {
    const alloc = testing.allocator;
    const hdrs = [_]Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":status", .value = "200" },
    };
    const encoded = try encodeFieldSection(alloc, &hdrs);
    defer alloc.free(encoded);

    const decoded = try decodeFieldSection(alloc, encoded);
    defer alloc.free(decoded);

    try testing.expectEqual(@as(usize, 2), decoded.len);
    try testing.expectEqualStrings(":method", decoded[0].name);
    try testing.expectEqualStrings("GET", decoded[0].value);
    try testing.expectEqualStrings(":status", decoded[1].name);
    try testing.expectEqualStrings("200", decoded[1].value);
}

test "encode/decode: literal with name reference" {
    const alloc = testing.allocator;
    // :authority is in static table (index 1) but empty value is the stored value.
    // Use a custom value to trigger name-ref + literal value path.
    const hdrs = [_]Header{
        .{ .name = ":authority", .value = "example.com" },
    };
    const encoded = try encodeFieldSection(alloc, &hdrs);
    defer alloc.free(encoded);

    const decoded = try decodeFieldSection(alloc, encoded);
    defer alloc.free(decoded);

    try testing.expectEqual(@as(usize, 1), decoded.len);
    try testing.expectEqualStrings(":authority", decoded[0].name);
    try testing.expectEqualStrings("example.com", decoded[0].value);
}

test "encode/decode: literal with literal name" {
    const alloc = testing.allocator;
    const hdrs = [_]Header{
        .{ .name = "x-custom", .value = "my-value" },
    };
    const encoded = try encodeFieldSection(alloc, &hdrs);
    defer alloc.free(encoded);

    const decoded = try decodeFieldSection(alloc, encoded);
    defer alloc.free(decoded);

    try testing.expectEqual(@as(usize, 1), decoded.len);
    try testing.expectEqualStrings("x-custom", decoded[0].name);
    try testing.expectEqualStrings("my-value", decoded[0].value);
}

test "encode/decode: realistic HTTP/3 request header set" {
    const alloc = testing.allocator;
    const hdrs = [_]Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/api/v1/data" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "api.example.com" },
        .{ .name = "accept", .value = "application/json" },
        .{ .name = "x-request-id", .value = "abc-123" },
    };
    const encoded = try encodeFieldSection(alloc, &hdrs);
    defer alloc.free(encoded);

    const decoded = try decodeFieldSection(alloc, encoded);
    defer alloc.free(decoded);

    try testing.expectEqual(hdrs.len, decoded.len);
    for (hdrs, decoded) |expected, got| {
        try testing.expectEqualStrings(expected.name, got.name);
        try testing.expectEqualStrings(expected.value, got.value);
    }
}

test "encode/decode: deterministic encoding" {
    const alloc = testing.allocator;
    const hdrs = [_]Header{
        .{ .name = ":method", .value = "POST" },
        .{ .name = "content-type", .value = "application/json" },
    };
    const enc1 = try encodeFieldSection(alloc, &hdrs);
    defer alloc.free(enc1);
    const enc2 = try encodeFieldSection(alloc, &hdrs);
    defer alloc.free(enc2);

    try testing.expectEqualSlices(u8, enc1, enc2);
}

test "decode: truncated payload" {
    const alloc = testing.allocator;
    // A minimal valid encoded section is at least 2 bytes (prefix).
    // Provide just 1 byte to trigger truncation.
    const data = [_]u8{0x00};
    const result = decodeFieldSection(alloc, &data);
    try testing.expectError(DecodeError.Truncated, result);
}

test "decode: invalid dynamic table reference rejected" {
    const alloc = testing.allocator;
    // 0x80 = Indexed, T=0 (dynamic) — should be rejected
    const data = [_]u8{ 0x00, 0x00, 0x80 };
    const result = decodeFieldSection(alloc, &data);
    try testing.expectError(DecodeError.InvalidRepresentation, result);
}

test "decode: static index out of range" {
    const alloc = testing.allocator;
    // Indexed static with index 0 (sentinel) → out of range
    // 0xC0 = 1 1 xxxxxx, T=1, 6-bit index = 0
    const data = [_]u8{ 0x00, 0x00, 0xC0 };
    const result = decodeFieldSection(alloc, &data);
    try testing.expectError(DecodeError.StaticIndexOutOfRange, result);
}

test "encode/decode: empty header list" {
    const alloc = testing.allocator;
    const hdrs = [_]Header{};
    const encoded = try encodeFieldSection(alloc, &hdrs);
    defer alloc.free(encoded);

    const decoded = try decodeFieldSection(alloc, encoded);
    defer alloc.free(decoded);

    try testing.expectEqual(@as(usize, 0), decoded.len);
}

test "encode/decode: :path with non-default value uses name-ref" {
    const alloc = testing.allocator;
    // :path index 2 stores "/" — custom path triggers name-ref + literal value
    const hdrs = [_]Header{
        .{ .name = ":path", .value = "/index.html" },
    };
    const encoded = try encodeFieldSection(alloc, &hdrs);
    defer alloc.free(encoded);

    const decoded = try decodeFieldSection(alloc, encoded);
    defer alloc.free(decoded);

    try testing.expectEqualStrings(":path", decoded[0].name);
    try testing.expectEqualStrings("/index.html", decoded[0].value);
}

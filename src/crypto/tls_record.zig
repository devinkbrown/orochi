// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! TLS 1.3 record-layer framing (RFC 8446 section 5).
//!
//! This module is pure caller-buffered code: it builds and parses
//! TLSCiphertext records, derives per-record AEAD nonces, forms TLS 1.3
//! additional data from the wire header, and encodes/decodes
//! TLSInnerPlaintext.content || type || zero-padding.
const std = @import("std");
const aead = record_aead;
const tls = record_tls;

const record_tls = struct {
    pub const max_plaintext_len = 16 * 1024;
    pub const max_ciphertext_len = @This().max_plaintext_len + 256;
    pub const record_header_len = 5;
    pub const tls12_wire_version: u16 = 0x0303;

    pub const ContentType = enum(u8) {
        change_cipher_spec = 20,
        alert = 21,
        handshake = 22,
        application_data = 23,

        pub fn fromWire(v: u8) ?@This() {
            return switch (v) {
                20 => .change_cipher_spec,
                21 => .alert,
                22 => .handshake,
                23 => .application_data,
                else => null,
            };
        }
    };
};

// Mirrors src/crypto/aead.zig's typed AEAD surface for this standalone
// direct-file test target. The underlying std.crypto AEADs are the same ones
// used by aead.zig.
const record_aead = struct {
    pub const Error = error{
        AuthFailed,
        BufferLengthMismatch,
        NonceCounterExhausted,
    };

    pub const AeadAlg = enum {
        chacha20_poly1305,
        aes256_gcm,

        fn Impl(comptime alg: AeadAlg) type {
            return switch (alg) {
                .chacha20_poly1305 => std.crypto.aead.chacha_poly.ChaCha20Poly1305,
                .aes256_gcm => std.crypto.aead.aes_gcm.Aes256Gcm,
            };
        }
    };

    pub const Nonce96 = [12]u8;

    pub fn Aead(comptime alg: AeadAlg) type {
        const Impl = alg.Impl();
        return struct {
            const Self = @This();

            pub const Key = [Impl.key_length]u8;
            pub const Nonce = [Impl.nonce_length]u8;
            pub const Tag = [Impl.tag_length]u8;
            pub const key_length = Impl.key_length;
            pub const nonce_length = Impl.nonce_length;
            pub const tag_length = Impl.tag_length;

            key: Key,

            pub fn init(key: Key) Self {
                return .{ .key = key };
            }

            pub fn deinit(self: *Self) void {
                std.crypto.secureZero(u8, &self.key);
            }

            pub fn seal(
                self: *const Self,
                nonce: Nonce,
                aad: []const u8,
                plaintext: []const u8,
                out: []u8,
            ) record_aead.Error!Tag {
                if (out.len != plaintext.len) return record_aead.Error.BufferLengthMismatch;
                var tag: Tag = undefined;
                Impl.encrypt(out, &tag, plaintext, aad, nonce, self.key);
                return tag;
            }

            pub fn open(
                self: *const Self,
                nonce: Nonce,
                aad: []const u8,
                ciphertext: []const u8,
                tag: Tag,
                out: []u8,
            ) record_aead.Error!void {
                if (out.len != ciphertext.len) return record_aead.Error.BufferLengthMismatch;
                Impl.decrypt(out, ciphertext, tag, aad, nonce, self.key) catch return record_aead.Error.AuthFailed;
            }
        };
    }
};

pub const ContentType = tls.ContentType;
pub const Nonce96 = aead.Nonce96;

pub const record_header_len = tls.record_header_len;
pub const max_plaintext_len = tls.max_plaintext_len;
pub const max_ciphertext_len = tls.max_ciphertext_len;
pub const legacy_record_version = tls.tls12_wire_version;
pub const outer_content_type = ContentType.application_data;

/// RFC 8449: the largest application-data content one record may carry given a
/// peer's advertised `record_size_limit` (a TLSInnerPlaintext bound). Since
/// TLSInnerPlaintext = content + 1 content-type byte + padding(0), content must
/// be <= limit - 1, and is never allowed above the protocol max (2^14). The
/// default limit (2^14+1) yields exactly `max_plaintext_len` — no restriction.
pub fn recordContentLimit(peer_record_size_limit: usize) usize {
    const inner = if (peer_record_size_limit > 1) peer_record_size_limit - 1 else 1;
    return @min(max_plaintext_len, inner);
}

/// RFC 8449 for TLS 1.2 and earlier: the peer's advertised `record_size_limit`
/// bounds `TLSPlaintext.fragment` directly. Unlike TLS 1.3 there is no inner
/// content-type byte or padding in the plaintext, so no `- 1` adjustment
/// applies — the fragment content limit is the advertised value itself, capped
/// at the protocol max (2^14). The explicit nonce and AEAD tag are record
/// protection overhead outside the fragment and are not counted. The default
/// limit (2^14+1) yields exactly `max_plaintext_len` — no restriction.
pub fn recordContentLimit12(peer_record_size_limit: usize) usize {
    // `@max(1, …)` keeps the invariant local: a 0 limit (unreachable from the
    // wire — parse enforces ≥64 — but settable directly, e.g. in tests) would
    // otherwise make the caller's fragmentation loop emit zero-length records
    // forever. Real limits are ≥64 so this is a no-op for them.
    return @max(1, @min(max_plaintext_len, peer_record_size_limit));
}

/// RFC 8449 record_size_limit bounds: the smallest legal advertised value is 64;
/// the largest is 2^14+1 (TLSInnerPlaintext including the content-type byte).
pub const record_size_limit_min: u16 = 64;
pub const record_size_limit_max: u16 = max_plaintext_len + 1;

pub const Error = aead.Error || error{
    BadRecordHeader,
    InvalidContentType,
    InvalidInnerPlaintext,
    OutputTooSmall,
    PlaintextTooLong,
    RecordOverflow,
};

pub const TLSCiphertext = struct {
    content_type: ContentType,
    legacy_record_version: u16,
    encrypted_record: []const u8,

    pub fn headerBytes(self: TLSCiphertext) [record_header_len]u8 {
        return makeAdditionalData(@intCast(self.encrypted_record.len));
    }
};

pub const OpenedPlaintext = struct {
    content_type: ContentType,
    content: []u8,
    padding_len: usize,
};

/// TLS 1.3 per-record nonce: static write_iv XOR (0x00000000 || seq_be64).
pub fn deriveNonce(write_iv: Nonce96, seq: u64) Nonce96 {
    var nonce = write_iv;
    var seq_bytes: Nonce96 = [_]u8{0} ** @sizeOf(Nonce96);
    std.mem.writeInt(u64, seq_bytes[4..12], seq, .big);
    for (&nonce, seq_bytes) |*dst, rhs| {
        dst.* ^= rhs;
    }
    return nonce;
}

/// TLS 1.3 AEAD additional_data is the serialized TLSCiphertext header.
pub fn makeAdditionalData(encrypted_record_len: u16) [record_header_len]u8 {
    var aad: [record_header_len]u8 = undefined;
    aad[0] = @intFromEnum(outer_content_type);
    std.mem.writeInt(u16, aad[1..3], legacy_record_version, .big);
    std.mem.writeInt(u16, aad[3..5], encrypted_record_len, .big);
    return aad;
}

/// Parse one complete TLS 1.3 TLSCiphertext record.
pub fn parseCiphertext(record: []const u8) Error!TLSCiphertext {
    if (record.len < record_header_len) return error.BadRecordHeader;
    const length = std.mem.readInt(u16, record[3..5], .big);
    if (length > max_ciphertext_len) return error.RecordOverflow;
    if (record.len != record_header_len + @as(usize, length)) return error.BadRecordHeader;

    const ct = ContentType.fromWire(record[0]) orelse return error.BadRecordHeader;
    if (ct != outer_content_type) return error.InvalidContentType;
    const version = std.mem.readInt(u16, record[1..3], .big);
    if (version != legacy_record_version) return error.BadRecordHeader;

    return .{
        .content_type = ct,
        .legacy_record_version = version,
        .encrypted_record = record[record_header_len..],
    };
}

pub fn encodeInnerPlaintext(
    content_type: ContentType,
    plaintext: []const u8,
    padding_len: usize,
    out: []u8,
) Error![]u8 {
    if (!isInnerContentType(content_type)) return error.InvalidContentType;
    if (plaintext.len > max_plaintext_len) return error.PlaintextTooLong;
    const inner_len = plaintext.len + 1 + padding_len;
    if (inner_len > max_ciphertext_len) return error.RecordOverflow;
    if (out.len < inner_len) return error.OutputTooSmall;

    @memcpy(out[0..plaintext.len], plaintext);
    out[plaintext.len] = @intFromEnum(content_type);
    @memset(out[plaintext.len + 1 .. inner_len], 0);
    return out[0..inner_len];
}

/// Strip TLS 1.3 zero padding with a full-length scan.
pub fn decodeInnerPlaintext(inner: []u8) Error!OpenedPlaintext {
    if (inner.len == 0) return error.InvalidInnerPlaintext;

    var found: u8 = 0;
    var type_index: usize = 0;
    var type_byte: u8 = 0;

    var i = inner.len;
    while (i != 0) {
        i -= 1;
        const b = inner[i];
        const select = ctNonZero(b) & (found ^ 1);
        type_index = ctSelectUsize(select, i, type_index);
        type_byte = ctSelectU8(select, b, type_byte);
        found |= ctNonZero(b);
    }

    if (found == 0) return error.InvalidInnerPlaintext;
    if (type_index > max_plaintext_len) return error.PlaintextTooLong;
    const content_type = ContentType.fromWire(type_byte) orelse return error.InvalidContentType;
    if (!isInnerContentType(content_type)) return error.InvalidContentType;

    return .{
        .content_type = content_type,
        .content = inner[0..type_index],
        .padding_len = inner.len - type_index - 1,
    };
}

pub fn sealRecord(
    comptime alg: aead.AeadAlg,
    cipher: *const aead.Aead(alg),
    write_iv: Nonce96,
    seq: u64,
    content_type: ContentType,
    plaintext: []const u8,
    padding_len: usize,
    inner_scratch: []u8,
    record_out: []u8,
) Error![]u8 {
    const A = aead.Aead(alg);
    const inner = try encodeInnerPlaintext(content_type, plaintext, padding_len, inner_scratch);
    const encrypted_len = inner.len + A.tag_length;
    if (encrypted_len > max_ciphertext_len) return error.RecordOverflow;
    if (record_out.len < record_header_len + encrypted_len) return error.OutputTooSmall;

    const aad = makeAdditionalData(@intCast(encrypted_len));
    @memcpy(record_out[0..record_header_len], &aad);

    const ciphertext = record_out[record_header_len..][0..inner.len];
    const nonce = deriveNonce(write_iv, seq);
    const tag = try cipher.seal(nonce, &aad, inner, ciphertext);
    @memcpy(record_out[record_header_len + inner.len ..][0..A.tag_length], &tag);

    return record_out[0 .. record_header_len + encrypted_len];
}

pub fn openRecord(
    comptime alg: aead.AeadAlg,
    cipher: *const aead.Aead(alg),
    write_iv: Nonce96,
    seq: u64,
    record: []const u8,
    plaintext_out: []u8,
) Error!OpenedPlaintext {
    const A = aead.Aead(alg);
    const parsed = try parseCiphertext(record);
    if (parsed.encrypted_record.len < A.tag_length) return error.BadRecordHeader;
    const ciphertext_len = parsed.encrypted_record.len - A.tag_length;
    if (plaintext_out.len < ciphertext_len) return error.OutputTooSmall;

    const aad = parsed.headerBytes();
    const nonce = deriveNonce(write_iv, seq);
    const ciphertext = parsed.encrypted_record[0..ciphertext_len];
    var tag: A.Tag = undefined;
    @memcpy(tag[0..], parsed.encrypted_record[ciphertext_len..][0..A.tag_length]);

    try cipher.open(nonce, &aad, ciphertext, tag, plaintext_out[0..ciphertext_len]);
    return decodeInnerPlaintext(plaintext_out[0..ciphertext_len]);
}

fn isInnerContentType(content_type: ContentType) bool {
    return switch (content_type) {
        .alert, .handshake, .application_data => true,
        .change_cipher_spec => false,
    };
}

fn ctNonZero(x: u8) u8 {
    const ux: u16 = x;
    return @intCast(((ux | (0 -% ux)) >> 8) & 1);
}

fn ctSelectU8(select: u8, a: u8, b: u8) u8 {
    const mask: u8 = 0 -% select;
    return (a & mask) | (b & ~mask);
}

fn ctSelectUsize(select: u8, a: usize, b: usize) usize {
    const mask: usize = 0 -% @as(usize, select);
    return (a & mask) | (b & ~mask);
}

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "seal/open round-trip" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const A = aead.Aead(.chacha20_poly1305);
    var cipher = A.init([_]u8{0x42} ** A.key_length);
    defer cipher.deinit();

    const iv = hex("000102030405060708090a0b");
    const plaintext = "orochi tls record payload";
    const padding_len = 5;
    const inner_len = plaintext.len + 1 + padding_len;

    const inner = try allocator.alloc(u8, inner_len);
    defer allocator.free(inner);
    const record_buf = try allocator.alloc(u8, record_header_len + inner_len + A.tag_length);
    defer allocator.free(record_buf);
    const opened_buf = try allocator.alloc(u8, inner_len);
    defer allocator.free(opened_buf);

    const record = try sealRecord(
        .chacha20_poly1305,
        &cipher,
        iv,
        7,
        .application_data,
        plaintext,
        padding_len,
        inner,
        record_buf,
    );
    const opened = try openRecord(.chacha20_poly1305, &cipher, iv, 7, record, opened_buf);
    try testing.expectEqual(ContentType.application_data, opened.content_type);
    try testing.expectEqualSlices(u8, plaintext, opened.content);
    try testing.expectEqual(@as(usize, padding_len), opened.padding_len);
}

test "nonce derivation xors write_iv with sequence number" {
    const iv = hex("000102030405060708090a0b");
    const nonce = deriveNonce(iv, 0x0102030405060708);
    try std.testing.expectEqualSlices(u8, &hex("00010203050705030d0f0d03"), &nonce);
}

test "tamper detection rejects modified ciphertext and tag" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const A = aead.Aead(.chacha20_poly1305);
    var cipher = A.init([_]u8{0xA5} ** A.key_length);
    defer cipher.deinit();

    const iv = hex("101112131415161718191a1b");
    const plaintext = "authenticated record";
    const inner_len = plaintext.len + 1;
    const inner = try allocator.alloc(u8, inner_len);
    defer allocator.free(inner);
    const record_buf = try allocator.alloc(u8, record_header_len + inner_len + A.tag_length);
    defer allocator.free(record_buf);
    const opened_buf = try allocator.alloc(u8, inner_len);
    defer allocator.free(opened_buf);

    const record = try sealRecord(
        .chacha20_poly1305,
        &cipher,
        iv,
        1,
        .application_data,
        plaintext,
        0,
        inner,
        record_buf,
    );

    record_buf[record_header_len] ^= 0x01;
    try testing.expectError(error.AuthFailed, openRecord(.chacha20_poly1305, &cipher, iv, 1, record, opened_buf));
    record_buf[record_header_len] ^= 0x01;

    record_buf[record.len - 1] ^= 0x80;
    try testing.expectError(error.AuthFailed, openRecord(.chacha20_poly1305, &cipher, iv, 1, record, opened_buf));
}

test "padding strip returns content before type byte" {
    const testing = std.testing;
    const allocator = testing.allocator;
    var inner = try allocator.alloc(u8, 9);
    defer allocator.free(inner);
    @memcpy(inner[0..4], "ping");
    inner[4] = @intFromEnum(ContentType.handshake);
    @memset(inner[5..], 0);

    const opened = try decodeInnerPlaintext(inner);
    try testing.expectEqual(ContentType.handshake, opened.content_type);
    try testing.expectEqualSlices(u8, "ping", opened.content);
    try testing.expectEqual(@as(usize, 4), opened.padding_len);
}

test {
    std.testing.refAllDecls(@This());
}

//! RSA private-key DER codec for daemon TLS certificate loading.
//!
//! Operators commonly receive RSA leaves with either a traditional PKCS#1
//! `RSAPrivateKey` (`-----BEGIN RSA PRIVATE KEY-----`) or a PKCS#8
//! `PrivateKeyInfo` (`-----BEGIN PRIVATE KEY-----`) wrapper around that same
//! structure. This module accepts both forms, validates DER bounds with the
//! shared X.509 `DerReader`, and returns an `rsa_sign.PrivateKey` whose integer
//! slices point into one owned allocation.

const std = @import("std");

const rsa_sign = @import("../crypto/rsa_sign.zig");
const x509 = @import("../crypto/x509.zig");

comptime {
    if (@bitSizeOf(usize) != 64) @compileError("rsa_pkcs requires a 64-bit target");
}

/// PKCS#1/PKCS#8 RSA private-key parse failures.
pub const ParseError = x509.Error || std.mem.Allocator.Error || error{
    /// The structure is DER, but not a supported key version.
    UnsupportedVersion,
    /// The PKCS#8 AlgorithmIdentifier is not rsaEncryption.
    UnsupportedAlgorithm,
    /// The decoded key is missing required two-prime RSA components.
    InvalidKey,
};

/// DER encode failures for the small test/operator helper encoders below.
pub const EncodeError = error{NoSpaceLeft};

/// ASN.1 object identifier for rsaEncryption (1.2.840.113549.1.1.1).
const oid_rsa_encryption = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };

/// Owned RSA private key material.
///
/// `key` is the shape consumed by `crypto/rsa_sign.zig`; every slice inside it
/// aliases `storage`. Keep this value alive for as long as the TLS engine may
/// sign with the key, then call `deinit` to zero and free the backing bytes.
pub const OwnedPrivateKey = struct {
    key: rsa_sign.PrivateKey,
    storage: []u8,

    pub fn deinit(self: *OwnedPrivateKey, allocator: std.mem.Allocator) void {
        std.crypto.secureZero(u8, self.storage);
        allocator.free(self.storage);
        self.* = undefined;
    }
};

/// Parse a DER `RSAPrivateKey` (PKCS#1) or `PrivateKeyInfo` (PKCS#8 RSA).
pub fn parse(allocator: std.mem.Allocator, der: []const u8) ParseError!OwnedPrivateKey {
    var top = x509.DerReader.init(der);
    const seq = try top.readExpected(x509.Tag.sequence);
    try top.expectEmpty();

    var body = try top.child(seq);
    const version = try body.readExpected(x509.Tag.integer);
    if (!std.mem.eql(u8, version.value, &.{0x00})) return error.UnsupportedVersion;

    const next = try body.peekTag();
    return switch (next) {
        x509.Tag.sequence => parsePkcs8Body(allocator, body),
        x509.Tag.integer => parsePkcs1Body(allocator, body),
        else => error.InvalidKey,
    };
}

/// Encode a PKCS#1 `RSAPrivateKey` DER value from a private key.
///
/// This is intentionally small and strict; it exists primarily for tests and
/// local operator tooling that needs to round-trip the same format the loader
/// accepts.
pub fn encodePkcs1(out: []u8, key: rsa_sign.PrivateKey) EncodeError![]const u8 {
    const p = key.p orelse return error.NoSpaceLeft;
    const q = key.q orelse return error.NoSpaceLeft;
    const dp = key.dp orelse return error.NoSpaceLeft;
    const dq = key.dq orelse return error.NoSpaceLeft;
    const qinv = key.qinv orelse return error.NoSpaceLeft;

    var body_buf: [4096]u8 = undefined;
    var body = Writer.init(&body_buf);
    try body.integer(&.{0x00});
    try body.positiveInteger(key.n);
    try body.positiveInteger(key.e);
    try body.positiveInteger(key.d);
    try body.positiveInteger(p);
    try body.positiveInteger(q);
    try body.positiveInteger(dp);
    try body.positiveInteger(dq);
    try body.positiveInteger(qinv);

    var w = Writer.init(out);
    try w.tlv(x509.Tag.sequence, body.bytes());
    return w.bytes();
}

/// Encode a PKCS#8 `PrivateKeyInfo` wrapping a PKCS#1 RSA private key.
pub fn encodePkcs8(out: []u8, key: rsa_sign.PrivateKey) EncodeError![]const u8 {
    var pkcs1_buf: [4096]u8 = undefined;
    const pkcs1 = try encodePkcs1(&pkcs1_buf, key);

    var alg_body_buf: [64]u8 = undefined;
    var alg_body = Writer.init(&alg_body_buf);
    try alg_body.tlv(x509.Tag.oid, &oid_rsa_encryption);
    try alg_body.tlv(x509.Tag.null_value, &.{});

    var alg_buf: [80]u8 = undefined;
    var alg = Writer.init(&alg_buf);
    try alg.tlv(x509.Tag.sequence, alg_body.bytes());

    var body_buf: [4096]u8 = undefined;
    var body = Writer.init(&body_buf);
    try body.integer(&.{0x00});
    try body.write(alg.bytes());
    try body.tlv(x509.Tag.octet_string, pkcs1);

    var w = Writer.init(out);
    try w.tlv(x509.Tag.sequence, body.bytes());
    return w.bytes();
}

fn parsePkcs8Body(allocator: std.mem.Allocator, body_start: x509.DerReader) ParseError!OwnedPrivateKey {
    var body = body_start;
    const algorithm = try body.readExpected(x509.Tag.sequence);
    try parseAlgorithm(body, algorithm);

    const private_key = try body.readExpected(x509.Tag.octet_string);
    try body.expectEmpty();
    return parse(allocator, private_key.value);
}

fn parsePkcs1Body(allocator: std.mem.Allocator, body_start: x509.DerReader) ParseError!OwnedPrivateKey {
    var body = body_start;
    const n = try keyInteger(try body.readExpected(x509.Tag.integer));
    const e = try keyInteger(try body.readExpected(x509.Tag.integer));
    const d = try keyInteger(try body.readExpected(x509.Tag.integer));
    const p = try keyInteger(try body.readExpected(x509.Tag.integer));
    const q = try keyInteger(try body.readExpected(x509.Tag.integer));
    const dp = try keyInteger(try body.readExpected(x509.Tag.integer));
    const dq = try keyInteger(try body.readExpected(x509.Tag.integer));
    const qinv = try keyInteger(try body.readExpected(x509.Tag.integer));
    try body.expectEmpty();

    const total = n.len + e.len + d.len + p.len + q.len + dp.len + dq.len + qinv.len;
    if (total == 0) return error.InvalidKey;
    const storage = try allocator.alloc(u8, total);
    errdefer {
        std.crypto.secureZero(u8, storage);
        allocator.free(storage);
    }

    var cursor: usize = 0;
    const n_owned = copyPart(storage, &cursor, n);
    const e_owned = copyPart(storage, &cursor, e);
    const d_owned = copyPart(storage, &cursor, d);
    const p_owned = copyPart(storage, &cursor, p);
    const q_owned = copyPart(storage, &cursor, q);
    const dp_owned = copyPart(storage, &cursor, dp);
    const dq_owned = copyPart(storage, &cursor, dq);
    const qinv_owned = copyPart(storage, &cursor, qinv);

    return .{
        .key = .{
            .n = n_owned,
            .e = e_owned,
            .d = d_owned,
            .p = p_owned,
            .q = q_owned,
            .dp = dp_owned,
            .dq = dq_owned,
            .qinv = qinv_owned,
        },
        .storage = storage,
    };
}

fn parseAlgorithm(parent: x509.DerReader, seq: x509.Tlv) ParseError!void {
    var body = try parent.child(seq);
    const oid = try body.readExpected(x509.Tag.oid);
    if (!std.mem.eql(u8, oid.value, &oid_rsa_encryption)) return error.UnsupportedAlgorithm;
    if (body.hasRemaining()) {
        const params = try body.readExpected(x509.Tag.null_value);
        if (params.value.len != 0) return error.InvalidKey;
    }
    try body.expectEmpty();
}

fn keyInteger(tlv: x509.Tlv) ParseError![]const u8 {
    const value = try positiveIntegerValue(tlv.value);
    if (isZero(value)) return error.InvalidKey;
    return value;
}

fn positiveIntegerValue(value: []const u8) ParseError![]const u8 {
    if (value.len == 0) return error.InvalidInteger;
    if (value[0] == 0x00) {
        if (value.len == 1) return value;
        if ((value[1] & 0x80) == 0) return error.InvalidInteger;
        return value[1..];
    }
    if ((value[0] & 0x80) != 0) return error.InvalidInteger;
    return value;
}

fn isZero(bytes: []const u8) bool {
    for (bytes) |b| if (b != 0) return false;
    return true;
}

fn copyPart(storage: []u8, cursor: *usize, value: []const u8) []const u8 {
    const start = cursor.*;
    @memcpy(storage[start..][0..value.len], value);
    cursor.* += value.len;
    return storage[start..cursor.*];
}

const Writer = struct {
    out: []u8,
    pos: usize = 0,

    fn init(out: []u8) Writer {
        return .{ .out = out };
    }

    fn bytes(self: *const Writer) []const u8 {
        return self.out[0..self.pos];
    }

    fn write(self: *Writer, bytes_in: []const u8) EncodeError!void {
        if (self.out.len - self.pos < bytes_in.len) return error.NoSpaceLeft;
        @memcpy(self.out[self.pos..][0..bytes_in.len], bytes_in);
        self.pos += bytes_in.len;
    }

    fn byte(self: *Writer, b: u8) EncodeError!void {
        if (self.pos >= self.out.len) return error.NoSpaceLeft;
        self.out[self.pos] = b;
        self.pos += 1;
    }

    fn tlv(self: *Writer, tag: u8, value: []const u8) EncodeError!void {
        try self.byte(tag);
        try self.length(value.len);
        try self.write(value);
    }

    fn integer(self: *Writer, value: []const u8) EncodeError!void {
        try self.tlv(x509.Tag.integer, value);
    }

    fn positiveInteger(self: *Writer, value: []const u8) EncodeError!void {
        if (value.len == 0) return error.NoSpaceLeft;
        if ((value[0] & 0x80) == 0) {
            try self.integer(value);
            return;
        }
        var buf: [1024]u8 = undefined;
        if (value.len + 1 > buf.len) return error.NoSpaceLeft;
        buf[0] = 0x00;
        @memcpy(buf[1..][0..value.len], value);
        try self.integer(buf[0 .. value.len + 1]);
    }

    fn length(self: *Writer, len: usize) EncodeError!void {
        if (len < 128) {
            try self.byte(@intCast(len));
            return;
        }

        var tmp: [@sizeOf(usize)]u8 = undefined;
        var n = len;
        var count: usize = 0;
        while (n != 0) : (n >>= 8) {
            tmp[tmp.len - 1 - count] = @intCast(n & 0xff);
            count += 1;
        }
        try self.byte(0x80 | @as(u8, @intCast(count)));
        try self.write(tmp[tmp.len - count ..]);
    }
};

fn hexToBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    comptime {
        if (hex.len % 2 != 0) @compileError("hex string length must be even");
    }
    var out: [hex.len / 2]u8 = undefined;
    var i: usize = 0;
    while (i < out.len) : (i += 1) {
        out[i] = (hexNibble(hex[i * 2]) << 4) | hexNibble(hex[i * 2 + 1]);
    }
    return out;
}

fn hexNibble(c: u8) u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => @compileError("invalid hex digit"),
    };
}

const test_rsa_n = hexToBytes("a0bd1304a87f0a69b8ef18eaa1da15522c221b1e9b1efaee23bea1faa7eaaefe1e09eba390ec9334aea9457530d40c6a6b89c039865e98dd9d7491ea57288debf370f796fe05904a589027272fc9bd803fcf9d228c5552da7ff4f2a25c1606b3a4794f4ffa5bd94ab2150026dbcd31c4f4a5755d449a7aaf41861ff069fa455563cb22de14114aff8085fc3d3c07bc929d761f6449c1a13975738c9876319599f88bd3676230802d76b7292ad0759dad8fc70ee18fded69e32216a7f52833f1138caa7f90307c236500c3aa1a6cd082097fc3e28609b8d33514f16d6687bed504aee82775a41e4b125eba9ca544dc375c29c19d20f10900301eea8e68be3b3d7");
const test_rsa_e = hexToBytes("010001");
const test_rsa_d = hexToBytes("12036e6cb0b76002de1b49770e01632f4ccbdbaf2fe2266be6ac97f97fb4f0bc80c04adc8f42bbf284fa6a52ca50913da1e4939abec0be2fe3d3eb0050993662716b410bf656c84754aa7f00c8bdba93735340805d2ab8b8cceb35ffd50310e833eff65ff7a630714b08c876125eea0b710153e84a6667865978fefe51da1ec7d7cfc1afb96c4223b187b49cb6305be1a2eccbb8d07ed016bc257908bec7daf322658bda2dc4abd3671ffa6919da8b86ecbefa2658c3c01bacee5c9cff02f1cbac3f05feb2d68c61ef9a5427f73edb1949f776350bd63475c3cb78c5605b094d5043756e894bf538e811903212b6990a75153e261a36630657f8b91dfdadf45d");
const test_rsa_p = hexToBytes("e03b0d999233d320ae90bb8fa28ba36ad8c0bedeea9bc1218f65f1aac329e0c921a6aaf62a56719c6bd01c33ff119a657005eb500c33aa52e6d2fb6a55723f6fc2076fb8d30df12801dca523515992cad6ad628d180947e846fa3a3a3046c84c25266faf9079f44022bd4b5600d98a8ee4cbda9fddf01e9efb5d7eb62f7edb5d");
const test_rsa_q = hexToBytes("b7832256daec3eb9c325d1cdd4b3e2036723d02daa96e029518640c40d87bde9df147bd8488031df85caa449ec42735cbfd1125f843027352d396e7e9024b76335a98148a553d31872f32275582897d1e8f2b1460f1a3bd0375fe8a884f2372e716d51a4b71043c9730d74a7263476362d502496c19f6a45a615517b4a7f4cc3");
const test_rsa_dp = hexToBytes("1a1be62e7e8e9843d2efb95735370b3532bde6bbb017a8ba4ea731279007fd4b8e2688fb96dc6fe825c99aaf174126782f3e113345e87229ab04e00f769991f762615949ed114f86380948153fb0ad5dfef73b65706a0c3c689f544e5836b5b5e01184a9ada9f59dce2dba6aee386660d31545849de40abcba4a1da9fb07cb65");
const test_rsa_dq = hexToBytes("90779aabf7b2adfabda763507fd790e10eec41b201aebf0fa80f61a335e79bd9a675d0bd46ee2cd503d5b09a457556ae388f95c03e274e666d90ddeca2fb54a7b49219a620092a90ffc56a66289de44f2aed0c23d435d9caa41d4be286aecc4432a555f5aeec0e016422bea7ebcab71915791724db8eed31a17afce76b9165d3");
const test_rsa_qinv = hexToBytes("c4cae178938b60717e4d0484c144c548b275f87dd2723cfe1b6a5ba68305b154d1c86c894716bd9d5b4f974f51ad98942fa26005188896931a73206b778b946f96c6443f67bbb1861ce8a2e9d438befdb6cb1b7f413edc5b155b436660320f3cd26b0f65a9f586f957257b81e7c410856150abf4bb8f691beabecf7e428a2f8c");

fn testPrivateKey() rsa_sign.PrivateKey {
    return .{
        .n = &test_rsa_n,
        .e = &test_rsa_e,
        .d = &test_rsa_d,
        .p = &test_rsa_p,
        .q = &test_rsa_q,
        .dp = &test_rsa_dp,
        .dq = &test_rsa_dq,
        .qinv = &test_rsa_qinv,
    };
}

fn expectKeyEqual(expected: rsa_sign.PrivateKey, actual: rsa_sign.PrivateKey) !void {
    try std.testing.expectEqualSlices(u8, expected.n, actual.n);
    try std.testing.expectEqualSlices(u8, expected.e, actual.e);
    try std.testing.expectEqualSlices(u8, expected.d, actual.d);
    try std.testing.expectEqualSlices(u8, expected.p.?, actual.p.?);
    try std.testing.expectEqualSlices(u8, expected.q.?, actual.q.?);
    try std.testing.expectEqualSlices(u8, expected.dp.?, actual.dp.?);
    try std.testing.expectEqualSlices(u8, expected.dq.?, actual.dq.?);
    try std.testing.expectEqualSlices(u8, expected.qinv.?, actual.qinv.?);
}

test "parse accepts PKCS#1 RSAPrivateKey DER" {
    const allocator = std.testing.allocator;
    const expected = testPrivateKey();
    var der_buf: [4096]u8 = undefined;
    const der = try encodePkcs1(&der_buf, expected);

    var parsed = try parse(allocator, der);
    defer parsed.deinit(allocator);

    try expectKeyEqual(expected, parsed.key);
}

test "parse accepts PKCS#8 PrivateKeyInfo wrapping RSA" {
    const allocator = std.testing.allocator;
    const expected = testPrivateKey();
    var der_buf: [4096]u8 = undefined;
    const der = try encodePkcs8(&der_buf, expected);

    var parsed = try parse(allocator, der);
    defer parsed.deinit(allocator);

    try expectKeyEqual(expected, parsed.key);
}

test "parse rejects malformed RSA private keys" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.Truncated, parse(allocator, &.{0x30}));
    // SEQUENCE ends immediately after the version INTEGER: the required key
    // fields are absent, so the next TLV read is genuinely truncated.
    try std.testing.expectError(error.Truncated, parse(allocator, &.{ 0x30, 0x03, 0x02, 0x01, 0x00 }));

    var der_buf: [4096]u8 = undefined;
    const der = try encodePkcs1(&der_buf, testPrivateKey());
    var tampered: [4096]u8 = undefined;
    @memcpy(tampered[0..der.len], der);
    // Bump the version INTEGER value from 0 to 1. The SEQUENCE may use a
    // long-form length (`30 82 LL LL` for a 2048-bit key), so derive the body
    // offset from the length byte rather than assuming a fixed header size; the
    // version TLV (`02 01 vv`) then sits at body_start, value at body_start + 2.
    const len_byte = tampered[1];
    const header_len: usize = if (len_byte < 0x80) 2 else 2 + (len_byte & 0x7f);
    tampered[header_len + 2] = 0x01;
    try std.testing.expectError(error.UnsupportedVersion, parse(allocator, tampered[0..der.len]));
}

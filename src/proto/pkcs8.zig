//! Generic PKCS#8 PrivateKeyInfo / OneAsymmetricKey outer wrapper.
//!
//! This module is algorithm-agnostic: it only parses and emits the DER wrapper
//! around key material. Returned slices borrow from the caller-provided DER.

const std = @import("std");

comptime {
    if (@bitSizeOf(usize) != 64) @compileError("pkcs8.zig requires 64-bit usize");
}

pub const max_der_len: usize = 1024 * 1024;

pub const Error = error{
    EmptyInput,
    Oversize,
    Truncated,
    TrailingData,
    UnsupportedTag,
    InvalidTag,
    InvalidLength,
    NonCanonicalLength,
    IndefiniteLength,
    InvalidInteger,
    InvalidVersion,
    InvalidOid,
    NoSpaceLeft,
};

pub const PrivateKeyInfo = struct {
    version: u8,
    algorithm_oid_content: []const u8,
    /// Raw AlgorithmIdentifier parameters TLV, or an empty slice when absent.
    algorithm_params: []const u8,
    /// Contents of the outer privateKey OCTET STRING.
    private_key: []const u8,
};

const Tag = struct {
    const integer = 0x02;
    const octet_string = 0x04;
    const oid = 0x06;
    const sequence = 0x30;
    const attributes_0 = 0xa0;
    const public_key_1 = 0xa1;
};

const Tlv = struct {
    tag: u8,
    value: []const u8,
    raw: []const u8,
};

const DerReader = struct {
    input: []const u8,
    offset: usize = 0,

    fn init(input: []const u8) DerReader {
        return .{ .input = input };
    }

    fn hasRemaining(self: DerReader) bool {
        return self.offset < self.input.len;
    }

    fn readTlv(self: *DerReader) Error!Tlv {
        if (self.input.len > max_der_len) return error.Oversize;
        if (self.offset >= self.input.len) return error.Truncated;

        const start = self.offset;
        if (self.input.len - start < 2) return error.Truncated;
        const tag = self.input[start];
        if ((tag & 0x1f) == 0x1f) return error.UnsupportedTag;

        var pos = start + 2;
        var len: usize = 0;
        const first_len = self.input[start + 1];
        if ((first_len & 0x80) == 0) {
            len = first_len;
        } else {
            const len_octets = first_len & 0x7f;
            if (len_octets == 0) return error.IndefiniteLength;
            if (len_octets > @sizeOf(usize)) return error.InvalidLength;
            if (self.input.len - pos < len_octets) return error.Truncated;
            if (len_octets > 1 and self.input[pos] == 0) return error.NonCanonicalLength;

            var i: usize = 0;
            while (i < len_octets) : (i += 1) {
                if (len > (std.math.maxInt(usize) >> 8)) return error.InvalidLength;
                len = (len << 8) | self.input[pos + i];
            }
            if (len < 128) return error.NonCanonicalLength;
            pos += len_octets;
        }

        if (len > max_der_len) return error.Oversize;
        if (self.input.len - pos < len) return error.Truncated;
        const end = pos + len;
        self.offset = end;
        return .{
            .tag = tag,
            .value = self.input[pos..end],
            .raw = self.input[start..end],
        };
    }

    fn readExpected(self: *DerReader, expected_tag: u8) Error!Tlv {
        const tlv = try self.readTlv();
        if (tlv.tag != expected_tag) return error.InvalidTag;
        return tlv;
    }

    fn expectEmpty(self: DerReader) Error!void {
        if (self.hasRemaining()) return error.TrailingData;
    }
};

/// Parse DER PKCS#8 PrivateKeyInfo or RFC 5958 OneAsymmetricKey.
pub fn parse(der: []const u8) Error!PrivateKeyInfo {
    if (der.len == 0) return error.EmptyInput;
    if (der.len > max_der_len) return error.Oversize;

    var reader = DerReader.init(der);
    const outer = try reader.readExpected(Tag.sequence);
    try reader.expectEmpty();

    var body = DerReader.init(outer.value);
    const version_tlv = try body.readExpected(Tag.integer);
    const version = try parseVersion(version_tlv.value);

    const algorithm = try body.readExpected(Tag.sequence);
    var alg_body = DerReader.init(algorithm.value);
    const oid = try alg_body.readExpected(Tag.oid);
    try validateOidContent(oid.value);
    const params = if (alg_body.hasRemaining()) (try alg_body.readTlv()).raw else "";
    try alg_body.expectEmpty();

    const private_key = try body.readExpected(Tag.octet_string);
    while (body.hasRemaining()) {
        const extra = try body.readTlv();
        switch (extra.tag) {
            Tag.attributes_0, Tag.public_key_1 => {},
            else => return error.InvalidTag,
        }
    }

    return .{
        .version = version,
        .algorithm_oid_content = oid.value,
        .algorithm_params = params,
        .private_key = private_key.value,
    };
}

/// Return the exact DER byte count produced by `wrap`.
pub fn wrappedLen(alg_oid_content: []const u8, alg_params: []const u8, private_key: []const u8) Error!usize {
    try validateOidContent(alg_oid_content);
    if (alg_params.len != 0) try validateSingleTlv(alg_params);

    const alg_oid_len = try tlvLen(alg_oid_content.len);
    const alg_body_len = try checkedAdd(alg_oid_len, alg_params.len);
    const alg_len = try tlvLen(alg_body_len);
    const private_key_len = try tlvLen(private_key.len);
    const inner_len = try checkedAdd(try checkedAdd(3, alg_len), private_key_len);
    return tlvLen(inner_len);
}

/// Build DER PKCS#8 PrivateKeyInfo with version 0 into caller storage.
pub fn wrap(out: []u8, alg_oid_content: []const u8, alg_params: []const u8, private_key: []const u8) Error![]const u8 {
    const total = try wrappedLen(alg_oid_content, alg_params, private_key);
    if (total > out.len) return error.NoSpaceLeft;

    var idx: usize = 0;
    const alg_body_len = (try tlvLen(alg_oid_content.len)) + alg_params.len;
    const inner_len = 3 + (try tlvLen(alg_body_len)) + (try tlvLen(private_key.len));

    try writeHeader(out, &idx, Tag.sequence, inner_len);
    try writeTlv(out, &idx, Tag.integer, &[_]u8{0});
    try writeHeader(out, &idx, Tag.sequence, alg_body_len);
    try writeTlv(out, &idx, Tag.oid, alg_oid_content);
    try writeBytes(out, &idx, alg_params);
    try writeTlv(out, &idx, Tag.octet_string, private_key);

    return out[0..idx];
}

fn parseVersion(bytes: []const u8) Error!u8 {
    if (bytes.len == 0) return error.InvalidInteger;
    if ((bytes[0] & 0x80) != 0) return error.InvalidInteger;
    if (bytes.len > 1 and bytes[0] == 0 and (bytes[1] & 0x80) == 0) return error.InvalidInteger;
    if (bytes.len > 1) return error.InvalidVersion;
    switch (bytes[0]) {
        0, 1 => return bytes[0],
        else => return error.InvalidVersion,
    }
}

fn validateOidContent(bytes: []const u8) Error!void {
    if (bytes.len == 0) return error.InvalidOid;

    var offset: usize = 0;
    while (offset < bytes.len) {
        var value: u64 = 0;
        var group_len: usize = 0;
        while (true) {
            if (offset >= bytes.len) return error.InvalidOid;
            const b = bytes[offset];
            if (group_len == 0 and b == 0x80) return error.InvalidOid;
            if (value > (std.math.maxInt(u64) >> 7)) return error.InvalidOid;
            value = (value << 7) | @as(u64, b & 0x7f);
            offset += 1;
            group_len += 1;
            if ((b & 0x80) == 0) break;
        }
    }
}

fn validateSingleTlv(bytes: []const u8) Error!void {
    var reader = DerReader.init(bytes);
    _ = try reader.readTlv();
    try reader.expectEmpty();
}

fn lenLen(len: usize) Error!usize {
    if (len > max_der_len) return error.Oversize;
    if (len < 128) return 1;
    var n = len;
    var count: usize = 0;
    while (n != 0) : (n >>= 8) count += 1;
    return 1 + count;
}

fn tlvLen(value_len: usize) Error!usize {
    const header_len = try checkedAdd(1, try lenLen(value_len));
    return checkedAdd(header_len, value_len);
}

fn checkedAdd(a: usize, b: usize) Error!usize {
    if (a > max_der_len or b > max_der_len) return error.Oversize;
    if (a > max_der_len - b) return error.Oversize;
    return a + b;
}

fn writeHeader(out: []u8, idx: *usize, tag: u8, value_len: usize) Error!void {
    if (idx.* >= out.len) return error.NoSpaceLeft;
    out[idx.*] = tag;
    idx.* += 1;

    if (value_len < 128) {
        if (idx.* >= out.len) return error.NoSpaceLeft;
        out[idx.*] = @as(u8, @intCast(value_len));
        idx.* += 1;
        return;
    }

    const len_octets = (try lenLen(value_len)) - 1;
    if (out.len - idx.* < 1 + len_octets) return error.NoSpaceLeft;
    out[idx.*] = 0x80 | @as(u8, @intCast(len_octets));
    idx.* += 1;

    var shift: u6 = @as(u6, @intCast((len_octets - 1) * 8));
    while (true) {
        out[idx.*] = @as(u8, @intCast((value_len >> shift) & 0xff));
        idx.* += 1;
        if (shift == 0) break;
        shift -= 8;
    }
}

fn writeBytes(out: []u8, idx: *usize, bytes: []const u8) Error!void {
    if (bytes.len > out.len - idx.*) return error.NoSpaceLeft;
    @memcpy(out[idx.* .. idx.* + bytes.len], bytes);
    idx.* += bytes.len;
}

fn writeTlv(out: []u8, idx: *usize, tag: u8, value: []const u8) Error!void {
    try writeHeader(out, idx, tag, value.len);
    try writeBytes(out, idx, value);
}

const oid_ed25519 = [_]u8{ 0x2b, 0x65, 0x70 };
const oid_rsa_encryption = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
const oid_ec_public_key = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
const oid_prime256v1_param = [_]u8{ 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };

test "parse returns fields from known Ed25519 PrivateKeyInfo DER" {
    // Arrange
    const der = [_]u8{
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
        0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };

    // Act
    const parsed = try parse(&der);

    // Assert
    try std.testing.expectEqual(@as(u8, 0), parsed.version);
    try std.testing.expectEqualSlices(u8, &oid_ed25519, parsed.algorithm_oid_content);
    try std.testing.expectEqual(@as(usize, 0), parsed.algorithm_params.len);
    try std.testing.expectEqualSlices(u8, der[14..], parsed.private_key);
}

test "wrap reproduces known Ed25519 PrivateKeyInfo DER" {
    // Arrange
    const private_key = [_]u8{
        0x04, 0x20, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
        0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    };
    const expected = [_]u8{
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
        0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    var out: [expected.len]u8 = undefined;

    // Act
    const der = try wrap(&out, &oid_ed25519, "", &private_key);

    // Assert
    try std.testing.expectEqualSlices(u8, &expected, der);
}

test "wrap then parse round-trips RSA with NULL parameters" {
    // Arrange
    const params = [_]u8{ 0x05, 0x00 };
    const private_key = [_]u8{ 0x30, 0x0a, 0x02, 0x01, 0x00, 0x02, 0x01, 0x03, 0x02, 0x01, 0x07, 0x02 };
    var out: [128]u8 = undefined;

    // Act
    const der = try wrap(&out, &oid_rsa_encryption, &params, &private_key);
    const parsed = try parse(der);

    // Assert
    try std.testing.expectEqual(@as(u8, 0), parsed.version);
    try std.testing.expectEqualSlices(u8, &oid_rsa_encryption, parsed.algorithm_oid_content);
    try std.testing.expectEqualSlices(u8, &params, parsed.algorithm_params);
    try std.testing.expectEqualSlices(u8, &private_key, parsed.private_key);
}

test "wrap then parse round-trips EC with named-curve parameters" {
    // Arrange
    const private_key = [_]u8{ 0x30, 0x06, 0x02, 0x01, 0x01, 0x04, 0x01, 0x42 };
    var out: [128]u8 = undefined;

    // Act
    const der = try wrap(&out, &oid_ec_public_key, &oid_prime256v1_param, &private_key);
    const parsed = try parse(der);

    // Assert
    try std.testing.expectEqualSlices(u8, &oid_ec_public_key, parsed.algorithm_oid_content);
    try std.testing.expectEqualSlices(u8, &oid_prime256v1_param, parsed.algorithm_params);
    try std.testing.expectEqualSlices(u8, &private_key, parsed.private_key);
}

test "parse accepts RFC 5958 version one with public key trailer" {
    // Arrange
    const der = [_]u8{
        0x30, 0x12, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06,
        0x03, 0x2b, 0x65, 0x70, 0x04, 0x02, 0xaa, 0xbb,
        0xa1, 0x02, 0x03, 0x00,
    };

    // Act
    const parsed = try parse(&der);

    // Assert
    try std.testing.expectEqual(@as(u8, 1), parsed.version);
    try std.testing.expectEqualSlices(u8, &oid_ed25519, parsed.algorithm_oid_content);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xaa, 0xbb }, parsed.private_key);
}

test "parse reports truncation for shortened wrapper" {
    // Arrange
    const der = [_]u8{ 0x30, 0x0b, 0x02, 0x01, 0x00, 0x30, 0x03, 0x06, 0x01, 0x2a, 0x04, 0x01, 0xff };

    // Act + Assert
    try std.testing.expectError(error.Truncated, parse(der[0 .. der.len - 1]));
}

test "parse reports oversize input before reading DER" {
    // Arrange
    var huge: [max_der_len + 1]u8 = undefined;

    // Act + Assert
    try std.testing.expectError(error.Oversize, parse(&huge));
}

test "wrap reports NoSpaceLeft for undersized caller buffer" {
    // Arrange
    const private_key = [_]u8{ 0x04, 0x20, 0xaa };
    var out: [8]u8 = undefined;

    // Act + Assert
    try std.testing.expectError(error.NoSpaceLeft, wrap(&out, &oid_ed25519, "", &private_key));
}

test "parse rejects non-canonical and malformed wrapper fields" {
    // Arrange
    const non_canonical_len = [_]u8{ 0x30, 0x81, 0x03, 0x02, 0x01, 0x00 };
    const bad_version = [_]u8{ 0x30, 0x0b, 0x02, 0x01, 0x02, 0x30, 0x03, 0x06, 0x01, 0x2a, 0x04, 0x01, 0xff };
    const trailing_alg_data = [_]u8{ 0x30, 0x0e, 0x02, 0x01, 0x00, 0x30, 0x06, 0x06, 0x01, 0x2a, 0x05, 0x00, 0x00, 0x04, 0x01, 0xff };

    // Act + Assert
    try std.testing.expectError(error.NonCanonicalLength, parse(&non_canonical_len));
    try std.testing.expectError(error.InvalidVersion, parse(&bad_version));
    try std.testing.expectError(error.TrailingData, parse(&trailing_alg_data));
}

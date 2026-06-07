//! PKCS#10 CertificationRequest DER builder for ACME finalize flows.
//!
//! The caller signs the returned CertificationRequestInfo bytes and then calls
//! `assemble` with the DER-encoded signature AlgorithmIdentifier.
const std = @import("std");
const der_oid = @import("der_oid.zig");
const asn1_bitstring = @import("asn1_bitstring.zig");

comptime {
    if (@bitSizeOf(usize) != 64) @compileError("csr requires a 64-bit target");
}

pub const Params = struct {
    common_name: []const u8,
    dns_names: []const []const u8,
    spki_der: []const u8,
};

pub const Error = error{
    NoSpaceLeft,
    LengthTooLarge,
    InvalidCommonName,
    CommonNameTooLong,
    InvalidDnsName,
    DnsNameTooLong,
    InvalidSubjectPublicKeyInfo,
    InvalidCertificationRequestInfo,
    InvalidSignatureAlgorithm,
    InvalidSignature,
    InvalidDer,
};

const tag_integer: u8 = 0x02;
const tag_bit_string: u8 = 0x03;
const tag_octet_string: u8 = 0x04;
const tag_oid: u8 = 0x06;
const tag_utf8_string: u8 = 0x0c;
const tag_sequence: u8 = 0x30;
const tag_set: u8 = 0x31;
const tag_context_0_constructed: u8 = 0xa0;
const tag_dns_name: u8 = 0x82;

const max_common_name_len = 255;
const max_dns_name_len = 253;

const oid_extension_request = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e };
const oid_subject_alt_name = [_]u8{ 0x55, 0x1d, 0x11 };

/// Build CertificationRequestInfo:
/// SEQUENCE { version, subject Name, SubjectPublicKeyInfo, attributes [0] }.
pub fn certificationRequestInfo(out: []u8, params: Params) ![]const u8 {
    try validateParams(params);

    const body_len = try sumLens(&.{
        try tlvLen(1),
        try nameLen(params.common_name),
        params.spki_der.len,
        try attributesLen(params.dns_names),
    });

    var writer = DerWriter.init(out);
    try writer.header(tag_sequence, body_len);
    try writer.tlv(tag_integer, &.{0});
    try writeName(&writer, params.common_name);
    try writer.write(params.spki_der);
    try writeAttributes(&writer, params.dns_names);
    return writer.bytes();
}

/// Assemble the signed CertificationRequest:
/// SEQUENCE { CertificationRequestInfo, signatureAlgorithm, signature }.
pub fn assemble(out: []u8, cri_der: []const u8, sig_alg_der: []const u8, signature: []const u8) ![]const u8 {
    try validateDerSequence(cri_der, error.InvalidCertificationRequestInfo);
    try validateDerSequence(sig_alg_der, error.InvalidSignatureAlgorithm);
    if (signature.len == 0) return error.InvalidSignature;

    const bit_string_len = try asn1_bitstring.encodedLen(signature.len);
    const body_len = try sumLens(&.{ cri_der.len, sig_alg_der.len, bit_string_len });

    var writer = DerWriter.init(out);
    try writer.header(tag_sequence, body_len);
    try writer.write(cri_der);
    try writer.write(sig_alg_der);
    const bit_string = try asn1_bitstring.encodeBytes(writer.remaining(), signature);
    writer.advance(bit_string.len);
    return writer.bytes();
}

fn validateParams(params: Params) Error!void {
    if (params.common_name.len == 0) return error.InvalidCommonName;
    if (params.common_name.len > max_common_name_len) return error.CommonNameTooLong;
    for (params.common_name) |b| {
        if (b < 0x20 or b == 0x7f) return error.InvalidCommonName;
    }

    if (params.dns_names.len == 0) return error.InvalidDnsName;
    for (params.dns_names) |name| {
        if (name.len == 0) return error.InvalidDnsName;
        if (name.len > max_dns_name_len) return error.DnsNameTooLong;
        for (name) |b| {
            if (b <= 0x20 or b >= 0x7f) return error.InvalidDnsName;
        }
    }

    try validateDerSequence(params.spki_der, error.InvalidSubjectPublicKeyInfo);
}

fn nameLen(common_name: []const u8) Error!usize {
    const attr_value_len = try sumLens(&.{ try tlvLen(der_oid.common_name.len), try tlvLen(common_name.len) });
    return tlvLen(try tlvLen(try tlvLen(attr_value_len)));
}

fn attributesLen(dns_names: []const []const u8) Error!usize {
    const general_names = try generalNamesLen(dns_names);
    const extension_body = try sumLens(&.{ try tlvLen(oid_subject_alt_name.len), try tlvLen(general_names) });
    const extensions = try tlvLen(try tlvLen(extension_body));
    const attr_body = try sumLens(&.{ try tlvLen(oid_extension_request.len), try tlvLen(extensions) });
    return tlvLen(try tlvLen(attr_body));
}

fn generalNamesLen(dns_names: []const []const u8) Error!usize {
    var content_len: usize = 0;
    for (dns_names) |name| {
        content_len = try addLen(content_len, try tlvLen(name.len));
    }
    return tlvLen(content_len);
}

fn writeName(writer: *DerWriter, common_name: []const u8) Error!void {
    const attr_value_len = try sumLens(&.{ try tlvLen(der_oid.common_name.len), try tlvLen(common_name.len) });
    try writer.header(tag_sequence, try tlvLen(try tlvLen(attr_value_len)));
    try writer.header(tag_set, try tlvLen(attr_value_len));
    try writer.header(tag_sequence, attr_value_len);
    try writer.tlv(tag_oid, &der_oid.common_name);
    try writer.tlv(tag_utf8_string, common_name);
}

fn writeAttributes(writer: *DerWriter, dns_names: []const []const u8) Error!void {
    const general_names = try generalNamesLen(dns_names);
    const extension_body = try sumLens(&.{ try tlvLen(oid_subject_alt_name.len), try tlvLen(general_names) });
    const extensions = try tlvLen(try tlvLen(extension_body));
    const attr_body = try sumLens(&.{ try tlvLen(oid_extension_request.len), try tlvLen(extensions) });

    try writer.header(tag_context_0_constructed, try tlvLen(attr_body));
    try writer.header(tag_sequence, attr_body);
    try writer.tlv(tag_oid, &oid_extension_request);
    try writer.header(tag_set, extensions);
    try writer.header(tag_sequence, try tlvLen(extension_body));
    try writer.header(tag_sequence, extension_body);
    try writer.tlv(tag_oid, &oid_subject_alt_name);
    try writer.header(tag_octet_string, general_names);
    try writeGeneralNames(writer, dns_names);
}

fn writeGeneralNames(writer: *DerWriter, dns_names: []const []const u8) Error!void {
    var content_len: usize = 0;
    for (dns_names) |name| {
        content_len = try addLen(content_len, try tlvLen(name.len));
    }
    try writer.header(tag_sequence, content_len);
    for (dns_names) |name| {
        try writer.tlv(tag_dns_name, name);
    }
}

fn validateDerSequence(input: []const u8, err: Error) Error!void {
    var cursor: usize = 0;
    const tlv = readTlv(input, &cursor) catch return err;
    if (tlv.tag != tag_sequence or cursor != input.len) return err;
}

fn sumLens(parts: []const usize) Error!usize {
    var total: usize = 0;
    for (parts) |part| {
        total = try addLen(total, part);
    }
    return total;
}

fn addLen(a: usize, b: usize) Error!usize {
    return std.math.add(usize, a, b) catch error.LengthTooLarge;
}

fn tlvLen(value_len: usize) Error!usize {
    return addLen(try addLen(1, lengthFieldLen(value_len)), value_len);
}

fn lengthFieldLen(len: usize) usize {
    if (len < 0x80) return 1;

    var octets: usize = 0;
    var n = len;
    while (n != 0) : (n >>= 8) {
        octets += 1;
    }
    return 1 + octets;
}

const DerWriter = struct {
    buf: []u8,
    pos: usize = 0,

    fn init(buf: []u8) DerWriter {
        return .{ .buf = buf };
    }

    fn bytes(self: *const DerWriter) []const u8 {
        return self.buf[0..self.pos];
    }

    fn remaining(self: *DerWriter) []u8 {
        return self.buf[self.pos..];
    }

    fn advance(self: *DerWriter, len: usize) void {
        self.pos += len;
    }

    fn write(self: *DerWriter, input: []const u8) Error!void {
        if (input.len > self.buf.len - self.pos) return error.NoSpaceLeft;
        @memcpy(self.buf[self.pos .. self.pos + input.len], input);
        self.pos += input.len;
    }

    fn tlv(self: *DerWriter, tag: u8, value: []const u8) Error!void {
        try self.header(tag, value.len);
        try self.write(value);
    }

    fn header(self: *DerWriter, tag: u8, len: usize) Error!void {
        if (self.buf.len - self.pos < 1) return error.NoSpaceLeft;
        self.buf[self.pos] = tag;
        self.pos += 1;
        try self.length(len);
    }

    fn length(self: *DerWriter, len: usize) Error!void {
        if (len < 0x80) {
            if (self.buf.len - self.pos < 1) return error.NoSpaceLeft;
            self.buf[self.pos] = @intCast(len);
            self.pos += 1;
            return;
        }

        var tmp: [@sizeOf(usize)]u8 = undefined;
        var n = len;
        var count: usize = 0;
        while (n != 0) : (n >>= 8) {
            tmp[tmp.len - 1 - count] = @intCast(n & 0xff);
            count += 1;
        }
        if (self.buf.len - self.pos < 1 + count) return error.NoSpaceLeft;
        self.buf[self.pos] = 0x80 | @as(u8, @intCast(count));
        self.pos += 1;
        try self.write(tmp[tmp.len - count ..]);
    }
};

const Tlv = struct {
    tag: u8,
    value: []const u8,
    full: []const u8,
};

fn readTlv(input: []const u8, cursor: *usize) Error!Tlv {
    const start = cursor.*;
    if (input.len - cursor.* < 2) return error.InvalidDer;
    const tag = input[cursor.*];
    cursor.* += 1;

    const len = try readLength(input, cursor);
    if (len > input.len - cursor.*) return error.InvalidDer;
    cursor.* += len;
    return .{ .tag = tag, .value = input[cursor.* - len .. cursor.*], .full = input[start..cursor.*] };
}

fn readLength(input: []const u8, cursor: *usize) Error!usize {
    if (cursor.* >= input.len) return error.InvalidDer;
    const first = input[cursor.*];
    cursor.* += 1;
    if (first & 0x80 == 0) return first;

    const count = first & 0x7f;
    if (count == 0 or count > @sizeOf(usize)) return error.InvalidDer;
    if (count > input.len - cursor.*) return error.InvalidDer;
    if (input[cursor.*] == 0) return error.InvalidDer;

    var len: usize = 0;
    for (0..count) |_| {
        len = (len << 8) | input[cursor.*];
        cursor.* += 1;
    }
    if (len < 0x80) return error.InvalidDer;
    return len;
}

const testing = std.testing;

const Fixture = struct {
    common_name: []const u8,
    dns_names: []const []const u8,
    spki_der_hex: []const u8,
    sig_alg_der_hex: []const u8,
    signature_hex: []const u8,
};

const fixture_json =
    \\{
    \\  "common_name": "example.test",
    \\  "dns_names": ["example.test", "www.example.test"],
    \\  "spki_der_hex": "302a300506032b6570032100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    \\  "sig_alg_der_hex": "300506032b6570",
    \\  "signature_hex": "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
    \\}
;

fn decodeHex(out: []u8, hex: []const u8) ![]const u8 {
    if (hex.len % 2 != 0) return error.InvalidHex;
    const byte_len = hex.len / 2;
    if (out.len < byte_len) return error.NoSpaceLeft;
    return std.fmt.hexToBytes(out[0..byte_len], hex);
}

test "certificationRequestInfo encodes fixture subject spki and extensionRequest SANs" {
    // Arrange
    var parsed = try std.json.parseFromSlice(Fixture, testing.allocator, fixture_json, .{});
    defer parsed.deinit();
    var spki_buf: [64]u8 = undefined;
    const spki = try decodeHex(&spki_buf, parsed.value.spki_der_hex);
    const params = Params{
        .common_name = parsed.value.common_name,
        .dns_names = parsed.value.dns_names,
        .spki_der = spki,
    };
    var out: [512]u8 = undefined;

    // Act
    const cri = try certificationRequestInfo(&out, params);

    // Assert
    var cursor: usize = 0;
    const outer = try readTlv(cri, &cursor);
    try testing.expectEqual(tag_sequence, outer.tag);
    try testing.expectEqual(cri.len, cursor);

    cursor = 0;
    const version = try readTlv(outer.value, &cursor);
    const subject = try readTlv(outer.value, &cursor);
    const spki_tlv = try readTlv(outer.value, &cursor);
    const attrs = try readTlv(outer.value, &cursor);
    try testing.expectEqual(outer.value.len, cursor);
    try testing.expectEqualSlices(u8, &.{0}, version.value);
    try testing.expectEqualSlices(u8, spki, spki_tlv.full);
    try testing.expectEqual(tag_context_0_constructed, attrs.tag);

    var subject_cursor: usize = 0;
    const rdn = try readTlv(subject.value, &subject_cursor);
    var rdn_cursor: usize = 0;
    const attr = try readTlv(rdn.value, &rdn_cursor);
    var attr_cursor: usize = 0;
    const cn_oid = try readTlv(attr.value, &attr_cursor);
    const cn_value = try readTlv(attr.value, &attr_cursor);
    try testing.expect(der_oid.eql(&der_oid.common_name, cn_oid.value));
    try testing.expectEqualSlices(u8, parsed.value.common_name, cn_value.value);

    var attrs_cursor: usize = 0;
    const ext_req = try readTlv(attrs.value, &attrs_cursor);
    var ext_req_cursor: usize = 0;
    const ext_req_oid = try readTlv(ext_req.value, &ext_req_cursor);
    const ext_req_values = try readTlv(ext_req.value, &ext_req_cursor);
    try testing.expect(der_oid.eql(&oid_extension_request, ext_req_oid.value));
    try testing.expectEqual(tag_set, ext_req_values.tag);

    var values_cursor: usize = 0;
    const extensions = try readTlv(ext_req_values.value, &values_cursor);
    var extensions_cursor: usize = 0;
    const san_extension = try readTlv(extensions.value, &extensions_cursor);
    var san_cursor: usize = 0;
    const san_oid = try readTlv(san_extension.value, &san_cursor);
    const san_value = try readTlv(san_extension.value, &san_cursor);
    try testing.expect(der_oid.eql(&oid_subject_alt_name, san_oid.value));

    var general_names_cursor: usize = 0;
    const general_names = try readTlv(san_value.value, &general_names_cursor);
    var names_cursor: usize = 0;
    for (parsed.value.dns_names) |expected_name| {
        const name = try readTlv(general_names.value, &names_cursor);
        try testing.expectEqual(tag_dns_name, name.tag);
        try testing.expectEqualSlices(u8, expected_name, name.value);
    }
    try testing.expectEqual(general_names.value.len, names_cursor);
}

test "assemble wraps fixture request algorithm and signature as DER BIT STRING" {
    // Arrange
    var parsed = try std.json.parseFromSlice(Fixture, testing.allocator, fixture_json, .{});
    defer parsed.deinit();
    var spki_buf: [64]u8 = undefined;
    var alg_buf: [16]u8 = undefined;
    var sig_buf: [128]u8 = undefined;
    const spki = try decodeHex(&spki_buf, parsed.value.spki_der_hex);
    const sig_alg = try decodeHex(&alg_buf, parsed.value.sig_alg_der_hex);
    const signature = try decodeHex(&sig_buf, parsed.value.signature_hex);
    var cri_buf: [512]u8 = undefined;
    const cri = try certificationRequestInfo(&cri_buf, .{
        .common_name = parsed.value.common_name,
        .dns_names = parsed.value.dns_names,
        .spki_der = spki,
    });
    var out: [768]u8 = undefined;

    // Act
    const csr_der = try assemble(&out, cri, sig_alg, signature);

    // Assert
    var cursor: usize = 0;
    const csr = try readTlv(csr_der, &cursor);
    try testing.expectEqual(csr_der.len, cursor);
    cursor = 0;
    const got_cri = try readTlv(csr.value, &cursor);
    const got_alg = try readTlv(csr.value, &cursor);
    const got_sig = try readTlv(csr.value, &cursor);
    try testing.expectEqual(csr.value.len, cursor);
    try testing.expectEqualSlices(u8, cri, got_cri.full);
    try testing.expectEqualSlices(u8, sig_alg, got_alg.full);
    try testing.expectEqual(tag_bit_string, got_sig.tag);
    try testing.expectEqual(@as(u8, 0), got_sig.value[0]);
    try testing.expectEqualSlices(u8, signature, got_sig.value[1..]);
}

test "builder reports missing JSON fields and invalid params" {
    // Arrange
    const missing_field_json =
        \\{"common_name":"example.test","dns_names":["example.test"]}
    ;
    var out: [256]u8 = undefined;
    const bad_spki = [_]u8{ 0x04, 0x00 };

    // Act / Assert
    try testing.expectError(error.MissingField, std.json.parseFromSlice(Fixture, testing.allocator, missing_field_json, .{}));
    try testing.expectError(error.InvalidDnsName, certificationRequestInfo(&out, .{
        .common_name = "example.test",
        .dns_names = &.{""},
        .spki_der = &bad_spki,
    }));
    try testing.expectError(error.InvalidSubjectPublicKeyInfo, certificationRequestInfo(&out, .{
        .common_name = "example.test",
        .dns_names = &.{"example.test"},
        .spki_der = &bad_spki,
    }));
}

test "builder returns NoSpaceLeft for truncated caller buffers" {
    // Arrange
    var parsed = try std.json.parseFromSlice(Fixture, testing.allocator, fixture_json, .{});
    defer parsed.deinit();
    var spki_buf: [64]u8 = undefined;
    const spki = try decodeHex(&spki_buf, parsed.value.spki_der_hex);
    var small: [32]u8 = undefined;

    // Act
    const result = certificationRequestInfo(&small, .{
        .common_name = parsed.value.common_name,
        .dns_names = parsed.value.dns_names,
        .spki_der = spki,
    });

    // Assert
    try testing.expectError(error.NoSpaceLeft, result);
}

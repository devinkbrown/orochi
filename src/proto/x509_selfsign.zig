const std = @import("std");

const Ed25519 = std.crypto.sign.Ed25519;

pub const Error = error{
    NoSpaceLeft,
    UnsupportedArchitecture,
    InvalidCommonName,
    CommonNameTooLong,
    InvalidSerial,
    SerialTooLarge,
    InvalidValidity,
    InvalidTime,
    InvalidDnsName,
};

pub const Params = struct {
    common_name: []const u8,
    not_before: i64,
    not_after: i64,
    serial: []const u8,
    key_pair: Ed25519.KeyPair,
    /// SubjectAltName dNSName entries. Standards TLS clients (RFC 6125) ignore
    /// the CN and match the hostname against the SAN, so a server cert MUST
    /// carry at least one. Empty keeps the legacy (extension-less) output.
    dns_names: []const []const u8 = &.{},
    /// Emit a critical BasicConstraints `cA:TRUE` so the cert can serve as its
    /// own trust anchor (self-signed root). Off by default.
    is_ca: bool = false,
};

const tag_integer: u8 = 0x02;
const tag_bit_string: u8 = 0x03;
const tag_oid: u8 = 0x06;
const tag_utf8_string: u8 = 0x0c;
const tag_sequence: u8 = 0x30;
const tag_set: u8 = 0x31;
const tag_utc_time: u8 = 0x17;
const tag_generalized_time: u8 = 0x18;
const tag_context_0_constructed: u8 = 0xa0;

const max_common_name_len = 64;
const max_serial_len = 20;
const max_dns_name_len = 253;
const oid_ed25519 = [_]u8{ 0x2b, 0x65, 0x70 };
const oid_common_name = [_]u8{ 0x55, 0x04, 0x03 };
const oid_subject_alt_name = [_]u8{ 0x55, 0x1d, 0x11 }; // 2.5.29.17
const oid_basic_constraints = [_]u8{ 0x55, 0x1d, 0x13 }; // 2.5.29.19
const tag_boolean: u8 = 0x01;
const tag_octet_string: u8 = 0x04;
const tag_context_3_constructed: u8 = 0xa3;
const tag_san_dns_name: u8 = 0x82; // GeneralName [2] dNSName (context, primitive)

pub fn buildSelfSigned(out: []u8, params: Params) ![]const u8 {
    if (@bitSizeOf(usize) != 64) return error.UnsupportedArchitecture;
    try validateParams(params);

    var tbs_buf: [1024]u8 = undefined;
    const tbs = try buildTbs(&tbs_buf, params);
    const sig = try Ed25519.KeyPair.sign(params.key_pair, tbs, null);
    const sig_bytes = sig.toBytes();

    var cert_body_buf: [1280]u8 = undefined;
    var cert_body = DerWriter.init(&cert_body_buf);
    try cert_body.write(tbs);
    try writeAlgorithmIdentifier(&cert_body);
    try writeSignatureBitString(&cert_body, &sig_bytes);

    var cert = DerWriter.init(out);
    try cert.tlv(tag_sequence, cert_body.bytes());
    return cert.bytes();
}

fn validateParams(params: Params) Error!void {
    if (params.common_name.len == 0) return error.InvalidCommonName;
    if (params.common_name.len > max_common_name_len) return error.CommonNameTooLong;
    for (params.common_name) |b| {
        if (b < 0x20 or b == 0x7f) return error.InvalidCommonName;
    }
    if (params.serial.len == 0) return error.InvalidSerial;
    if (params.not_after < params.not_before) return error.InvalidValidity;
    for (params.dns_names) |name| {
        if (name.len == 0 or name.len > max_dns_name_len) return error.InvalidDnsName;
        for (name) |b| if (b <= 0x20 or b >= 0x7f) return error.InvalidDnsName;
    }
}

fn buildTbs(out: []u8, params: Params) ![]const u8 {
    var body_buf: [960]u8 = undefined;
    var body = DerWriter.init(&body_buf);
    try writeVersion(&body);
    try writeSerial(&body, params.serial);
    try writeAlgorithmIdentifier(&body);
    try writeName(&body, params.common_name);
    try writeValidity(&body, params.not_before, params.not_after);
    try writeName(&body, params.common_name);
    try writeSubjectPublicKeyInfo(&body, params.key_pair.public_key.toBytes());
    if (params.dns_names.len != 0 or params.is_ca) try writeExtensions(&body, params);

    var tbs = DerWriter.init(out);
    try tbs.tlv(tag_sequence, body.bytes());
    return tbs.bytes();
}

/// `[3] EXPLICIT SEQUENCE OF Extension` carrying SubjectAltName (dNSNames) and,
/// optionally, a critical BasicConstraints cA:TRUE.
fn writeExtensions(w: *DerWriter, params: Params) !void {
    var seq_buf: [768]u8 = undefined;
    var seq = DerWriter.init(&seq_buf);

    if (params.is_ca) {
        // BasicConstraints ::= SEQUENCE { cA BOOLEAN } -> octet-string -> ext.
        var bc_buf: [8]u8 = undefined;
        var bc = DerWriter.init(&bc_buf);
        try bc.tlv(tag_boolean, &.{0xff});
        var bc_seq_buf: [12]u8 = undefined;
        var bc_seq = DerWriter.init(&bc_seq_buf);
        try bc_seq.tlv(tag_sequence, bc.bytes());
        try writeExtension(&seq, &oid_basic_constraints, true, bc_seq.bytes());
    }

    if (params.dns_names.len != 0) {
        var names_buf: [600]u8 = undefined;
        var names = DerWriter.init(&names_buf);
        for (params.dns_names) |name| try names.tlv(tag_san_dns_name, name);
        var san_buf: [620]u8 = undefined;
        var san = DerWriter.init(&san_buf);
        try san.tlv(tag_sequence, names.bytes());
        try writeExtension(&seq, &oid_subject_alt_name, false, san.bytes());
    }

    var explicit_buf: [768]u8 = undefined;
    var explicit = DerWriter.init(&explicit_buf);
    try explicit.tlv(tag_sequence, seq.bytes());
    try w.tlv(tag_context_3_constructed, explicit.bytes());
}

/// One `Extension ::= SEQUENCE { extnID OID, critical BOOLEAN OPTIONAL,
/// extnValue OCTET STRING }`. `der` is the already-encoded extension value.
fn writeExtension(w: *DerWriter, oid: []const u8, critical: bool, der: []const u8) !void {
    var ext_buf: [700]u8 = undefined;
    var ext = DerWriter.init(&ext_buf);
    try ext.tlv(tag_oid, oid);
    if (critical) try ext.tlv(tag_boolean, &.{0xff});
    try ext.tlv(tag_octet_string, der);
    try w.tlv(tag_sequence, ext.bytes());
}

fn writeVersion(w: *DerWriter) !void {
    var inner_buf: [3]u8 = undefined;
    var inner = DerWriter.init(&inner_buf);
    try inner.tlv(tag_integer, &.{0x02});
    try w.tlv(tag_context_0_constructed, inner.bytes());
}

fn writeSerial(w: *DerWriter, serial: []const u8) !void {
    var start: usize = 0;
    while (start < serial.len and serial[start] == 0) : (start += 1) {}
    if (start == serial.len) return error.InvalidSerial;
    const trimmed = serial[start..];
    if (trimmed.len > max_serial_len) return error.SerialTooLarge;

    var buf: [max_serial_len + 1]u8 = undefined;
    var len = trimmed.len;
    if ((trimmed[0] & 0x80) != 0) {
        buf[0] = 0;
        @memcpy(buf[1 .. 1 + trimmed.len], trimmed);
        len += 1;
    } else {
        @memcpy(buf[0..trimmed.len], trimmed);
    }
    try w.tlv(tag_integer, buf[0..len]);
}

fn writeAlgorithmIdentifier(w: *DerWriter) !void {
    var body_buf: [8]u8 = undefined;
    var body = DerWriter.init(&body_buf);
    try body.tlv(tag_oid, &oid_ed25519);
    try w.tlv(tag_sequence, body.bytes());
}

fn writeName(w: *DerWriter, common_name: []const u8) !void {
    var attr_body_buf: [80]u8 = undefined;
    var attr_body = DerWriter.init(&attr_body_buf);
    try attr_body.tlv(tag_oid, &oid_common_name);
    try attr_body.tlv(tag_utf8_string, common_name);

    var attr_buf: [96]u8 = undefined;
    var attr = DerWriter.init(&attr_buf);
    try attr.tlv(tag_sequence, attr_body.bytes());

    var rdn_buf: [112]u8 = undefined;
    var rdn = DerWriter.init(&rdn_buf);
    try rdn.tlv(tag_set, attr.bytes());

    try w.tlv(tag_sequence, rdn.bytes());
}

fn writeValidity(w: *DerWriter, not_before: i64, not_after: i64) !void {
    var before_buf: [15]u8 = undefined;
    var after_buf: [15]u8 = undefined;
    const before = try formatAsn1Time(&before_buf, not_before);
    const after = try formatAsn1Time(&after_buf, not_after);

    var body_buf: [36]u8 = undefined;
    var body = DerWriter.init(&body_buf);
    try body.tlv(before.tag, before_buf[0..before.len]);
    try body.tlv(after.tag, after_buf[0..after.len]);
    try w.tlv(tag_sequence, body.bytes());
}

fn writeSubjectPublicKeyInfo(w: *DerWriter, public_key: [Ed25519.PublicKey.encoded_length]u8) !void {
    var body_buf: [48]u8 = undefined;
    var body = DerWriter.init(&body_buf);
    try writeAlgorithmIdentifier(&body);

    var bit_string: [1 + Ed25519.PublicKey.encoded_length]u8 = undefined;
    bit_string[0] = 0;
    @memcpy(bit_string[1..], &public_key);
    try body.tlv(tag_bit_string, &bit_string);
    try w.tlv(tag_sequence, body.bytes());
}

fn writeSignatureBitString(w: *DerWriter, signature: *const [Ed25519.Signature.encoded_length]u8) !void {
    var bit_string: [1 + Ed25519.Signature.encoded_length]u8 = undefined;
    bit_string[0] = 0;
    @memcpy(bit_string[1..], signature);
    try w.tlv(tag_bit_string, &bit_string);
}

const Asn1Time = struct {
    tag: u8,
    len: usize,
};

fn formatAsn1Time(out: *[15]u8, unix_seconds: i64) Error!Asn1Time {
    const seconds_per_day: i64 = 86_400;
    const days = @divFloor(unix_seconds, seconds_per_day);
    const sod_i64 = @mod(unix_seconds, seconds_per_day);
    const date = civilFromDays(days);
    if (date.year < 1 or date.year > 9999) return error.InvalidTime;

    const hour = @divTrunc(sod_i64, 3600);
    const minute = @divTrunc(sod_i64 - hour * 3600, 60);
    const second = sod_i64 - hour * 3600 - minute * 60;

    if (date.year >= 1950 and date.year <= 2049) {
        write2(out[0..2], @intCast(@mod(date.year, 100)));
        write2(out[2..4], @intCast(date.month));
        write2(out[4..6], @intCast(date.day));
        write2(out[6..8], @intCast(hour));
        write2(out[8..10], @intCast(minute));
        write2(out[10..12], @intCast(second));
        out[12] = 'Z';
        return .{ .tag = tag_utc_time, .len = 13 };
    }

    write4(out[0..4], @intCast(date.year));
    write2(out[4..6], @intCast(date.month));
    write2(out[6..8], @intCast(date.day));
    write2(out[8..10], @intCast(hour));
    write2(out[10..12], @intCast(minute));
    write2(out[12..14], @intCast(second));
    out[14] = 'Z';
    return .{ .tag = tag_generalized_time, .len = 15 };
}

const Date = struct {
    year: i64,
    month: i64,
    day: i64,
};

fn civilFromDays(days_since_epoch: i64) Date {
    const z = days_since_epoch + 719_468;
    const era = @divFloor(z, 146_097);
    const doe = z - era * 146_097;
    const yoe = @divTrunc(doe - @divTrunc(doe, 1460) + @divTrunc(doe, 36_524) - @divTrunc(doe, 146_096), 365);
    var year = yoe + era * 400;
    const doy = doe - (365 * yoe + @divTrunc(yoe, 4) - @divTrunc(yoe, 100));
    const mp = @divTrunc(5 * doy + 2, 153);
    const day = doy - @divTrunc(153 * mp + 2, 5) + 1;
    const month = mp + if (mp < 10) @as(i64, 3) else -9;
    if (month <= 2) year += 1;
    return .{ .year = year, .month = month, .day = day };
}

fn write2(out: []u8, value: u8) void {
    out[0] = '0' + value / 10;
    out[1] = '0' + value % 10;
}

fn write4(out: []u8, value: u16) void {
    out[0] = '0' + @as(u8, @intCast(value / 1000));
    out[1] = '0' + @as(u8, @intCast(value / 100 % 10));
    out[2] = '0' + @as(u8, @intCast(value / 10 % 10));
    out[3] = '0' + @as(u8, @intCast(value % 10));
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

    fn write(self: *DerWriter, bytes_in: []const u8) !void {
        if (self.buf.len - self.pos < bytes_in.len) return error.NoSpaceLeft;
        @memcpy(self.buf[self.pos .. self.pos + bytes_in.len], bytes_in);
        self.pos += bytes_in.len;
    }

    fn tlv(self: *DerWriter, tag: u8, value: []const u8) !void {
        if (self.buf.len - self.pos < 1) return error.NoSpaceLeft;
        self.buf[self.pos] = tag;
        self.pos += 1;
        try self.length(value.len);
        try self.write(value);
    }

    fn length(self: *DerWriter, len: usize) !void {
        if (len < 128) {
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

const testing = std.testing;

const Tlv = struct {
    tag: u8,
    value: []const u8,
    full: []const u8,
};

fn readTlv(input: []const u8, cursor: *usize) !Tlv {
    const start = cursor.*;
    if (input.len - cursor.* < 2) return error.Truncated;
    const tag = input[cursor.*];
    cursor.* += 1;
    const len_byte = input[cursor.*];
    cursor.* += 1;
    var len: usize = 0;
    if ((len_byte & 0x80) == 0) {
        len = len_byte;
    } else {
        const count = len_byte & 0x7f;
        if (count == 0 or count > @sizeOf(usize)) return error.BadLength;
        if (input.len - cursor.* < count) return error.Truncated;
        for (0..count) |_| {
            len = (len << 8) | input[cursor.*];
            cursor.* += 1;
        }
    }
    if (input.len - cursor.* < len) return error.Truncated;
    const value = input[cursor.* .. cursor.* + len];
    cursor.* += len;
    return .{ .tag = tag, .value = value, .full = input[start..cursor.*] };
}

fn testParams() !Params {
    return .{
        .common_name = "example.test",
        .not_before = 1_704_067_200,
        .not_after = 1_735_689_599,
        .serial = &.{ 0x7f, 0x01 },
        .key_pair = try Ed25519.KeyPair.generateDeterministic([_]u8{0x42} ** Ed25519.KeyPair.seed_length),
    };
}

test "buildSelfSigned returns a self-signed DER certificate with matching issuer subject and signature" {
    // Arrange
    const params = try testParams();
    var out: [512]u8 = undefined;

    // Act
    const der = try buildSelfSigned(&out, params);

    // Assert
    var cert_cursor: usize = 0;
    const cert = try readTlv(der, &cert_cursor);
    try testing.expectEqual(tag_sequence, cert.tag);
    try testing.expectEqual(der.len, cert_cursor);

    var body_cursor: usize = 0;
    const tbs = try readTlv(cert.value, &body_cursor);
    const sig_alg = try readTlv(cert.value, &body_cursor);
    const sig_bits = try readTlv(cert.value, &body_cursor);
    try testing.expectEqual(cert.value.len, body_cursor);
    try testing.expectEqual(tag_sequence, tbs.tag);
    try testing.expectEqualSlices(u8, &.{ 0x06, 0x03, 0x2b, 0x65, 0x70 }, sig_alg.value);
    try testing.expectEqual(tag_bit_string, sig_bits.tag);
    try testing.expectEqual(@as(u8, 0), sig_bits.value[0]);

    var tbs_cursor: usize = 0;
    _ = try readTlv(tbs.value, &tbs_cursor);
    _ = try readTlv(tbs.value, &tbs_cursor);
    _ = try readTlv(tbs.value, &tbs_cursor);
    const issuer = try readTlv(tbs.value, &tbs_cursor);
    _ = try readTlv(tbs.value, &tbs_cursor);
    const subject = try readTlv(tbs.value, &tbs_cursor);
    try testing.expectEqualSlices(u8, issuer.full, subject.full);

    const signature = Ed25519.Signature.fromBytes(sig_bits.value[1..][0..Ed25519.Signature.encoded_length].*);
    try signature.verify(tbs.full, params.key_pair.public_key);
}

test "buildSelfSigned encodes UTCTime and GeneralizedTime boundaries" {
    // Arrange
    var params = try testParams();
    params.not_before = -631_152_000;
    params.not_after = 2_524_608_000;
    var out: [512]u8 = undefined;

    // Act
    const der = try buildSelfSigned(&out, params);

    // Assert
    var cursor: usize = 0;
    const cert = try readTlv(der, &cursor);
    cursor = 0;
    const tbs = try readTlv(cert.value, &cursor);
    cursor = 0;
    _ = try readTlv(tbs.value, &cursor);
    _ = try readTlv(tbs.value, &cursor);
    _ = try readTlv(tbs.value, &cursor);
    _ = try readTlv(tbs.value, &cursor);
    const validity = try readTlv(tbs.value, &cursor);
    cursor = 0;
    const before = try readTlv(validity.value, &cursor);
    const after = try readTlv(validity.value, &cursor);
    try testing.expectEqual(tag_utc_time, before.tag);
    try testing.expectEqualSlices(u8, "500101000000Z", before.value);
    try testing.expectEqual(tag_generalized_time, after.tag);
    try testing.expectEqualSlices(u8, "20500101000000Z", after.value);
}

test "buildSelfSigned reports truncation and oversized inputs with typed errors" {
    // Arrange
    var params = try testParams();
    var out: [512]u8 = undefined;
    const full = try buildSelfSigned(&out, params);
    var small: [1]u8 = undefined;

    // Act and assert
    try testing.expectError(error.NoSpaceLeft, buildSelfSigned(&small, params));
    var cursor: usize = 0;
    try testing.expectError(error.Truncated, readTlv(full[0 .. full.len - 1], &cursor));

    params.serial = &([_]u8{0x01} ** 21);
    try testing.expectError(error.SerialTooLarge, buildSelfSigned(&out, params));

    params.serial = &.{0};
    try testing.expectError(error.InvalidSerial, buildSelfSigned(&out, params));

    params.serial = &.{1};
    params.common_name = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklm";
    try testing.expectError(error.CommonNameTooLong, buildSelfSigned(&out, params));
}

test "buildSelfSigned emits SAN dnsNames + CA basic-constraints parseable by x509" {
    const x509 = @import("../crypto/x509.zig");
    var params = try testParams();
    params.dns_names = &.{ "irc.example.test", "example.test" };
    params.is_ca = true;
    var out: [1024]u8 = undefined;
    const der = try buildSelfSigned(&out, params);

    const cert = try x509.parse(der);
    try testing.expect(cert.basic_constraints_ca);
    try testing.expectEqual(@as(usize, 2), cert.san_dns_count);
    try testing.expectEqualStrings("irc.example.test", cert.san_dns[0]);
    try testing.expectEqualStrings("example.test", cert.san_dns[1]);

    // The TBS signature must still verify after adding the v3 extensions block.
    var cursor: usize = 0;
    const outer = try readTlv(der, &cursor);
    var body_cursor: usize = 0;
    const tbs = try readTlv(outer.value, &body_cursor);
    _ = try readTlv(outer.value, &body_cursor);
    const sig_bits = try readTlv(outer.value, &body_cursor);
    const signature = Ed25519.Signature.fromBytes(sig_bits.value[1..][0..Ed25519.Signature.encoded_length].*);
    try signature.verify(tbs.full, params.key_pair.public_key);
}

test "buildSelfSigned rejects malformed SAN dnsNames" {
    var params = try testParams();
    params.dns_names = &.{"bad host"}; // space is not a legal dNSName byte
    var out: [1024]u8 = undefined;
    try testing.expectError(error.InvalidDnsName, buildSelfSigned(&out, params));
}

test "buildSelfSigned has stable DER known-answer prefix for deterministic inputs" {
    // Arrange
    const params = try testParams();
    var out: [512]u8 = undefined;

    // Act
    const der = try buildSelfSigned(&out, params);

    // Assert
    const expected_prefix = [_]u8{
        0x30, 0x81, 0xdb, 0x30, 0x81, 0x8e, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02,
        0x02, 0x7f, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x30, 0x17,
    };
    try testing.expect(der.len > expected_prefix.len);
    try testing.expectEqualSlices(u8, &expected_prefix, der[0..expected_prefix.len]);
}

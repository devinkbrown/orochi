// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Minimal fail-closed X.509/DER reader for TLS and certfp.
//!
//! This is not a chain validator. It extracts only the certificate fields the
//! TLS and certfp layers need, keeps parsed data as slices into caller-owned
//! DER bytes, and refuses non-canonical or truncated DER.
const std = @import("std");
const hash = @import("hash.zig");

pub const MaxDerLen = 1024 * 1024;
pub const MaxDepth = 16;
// CDN/shared certs routinely carry many SAN dNSName entries (wildcards for
// dozens of subdomains), so the default bound is generous enough to parse
// real-world leaf certificates from public hosts.
pub const DefaultMaxDnsNames = 192;
pub const DefaultMaxIpAddresses = 16;

pub const Error = error{
    EmptyInput,
    Oversize,
    OverDepth,
    Truncated,
    TrailingData,
    UnsupportedTag,
    InvalidTag,
    InvalidLength,
    NonCanonicalLength,
    IndefiniteLength,
    InvalidInteger,
    InvalidBitString,
    InvalidOid,
    InvalidBoolean,
    InvalidTime,
    InvalidCertificate,
    MissingField,
    TooManySan,
    InvalidName,
    InvalidIpAddress,
    PemBeginMissing,
    PemEndMissing,
    PemInvalidBase64,
    OutputTooSmall,
    /// SubjectPublicKeyInfo uses an algorithm Orochi's verifier does not support.
    UnsupportedKey,
    /// SubjectPublicKeyInfo is structurally malformed for its key family.
    InvalidKey,
};

pub const Sha256Digest = hash.Sha256.Digest;

pub const Tag = struct {
    pub const boolean = 0x01;
    pub const integer = 0x02;
    pub const bit_string = 0x03;
    pub const octet_string = 0x04;
    pub const null_value = 0x05;
    pub const oid = 0x06;
    pub const sequence = 0x30;
    pub const utc_time = 0x17;
    pub const generalized_time = 0x18;
    pub const context_0_constructed = 0xA0;
    pub const context_1_constructed = 0xA1;
    pub const context_3_constructed = 0xA3;
    pub const san_dns_name = 0x82;
    pub const san_ip_address = 0x87;
};

/// Maximum dNSName subtrees per direction (permitted/excluded) retained from a
/// NameConstraints extension. Real CAs use a handful; excess subtrees are
/// rejected rather than silently dropped.
pub const MaxNameConstraints = 24;

const Oid = struct {
    const subject_alt_name = [_]u8{ 0x55, 0x1D, 0x11 };
    const basic_constraints = [_]u8{ 0x55, 0x1D, 0x13 };
    const name_constraints = [_]u8{ 0x55, 0x1D, 0x1E };
    const key_usage = [_]u8{ 0x55, 0x1D, 0x0F };
    const extended_key_usage = [_]u8{ 0x55, 0x1D, 0x25 };
    // id-kp-serverAuth (1.3.6.1.5.5.7.3.1) and anyExtendedKeyUsage (2.5.29.37.0).
    const eku_server_auth = [_]u8{ 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01 };
    const eku_any = [_]u8{ 0x55, 0x1D, 0x25, 0x00 };
    // authorityInfoAccess (1.3.6.1.5.5.7.1.1); id-ad-ocsp (1.3.6.1.5.5.7.48.1).
    const authority_info_access = [_]u8{ 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01 };
    const id_ad_ocsp = [_]u8{ 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01 };
    // id-pe-tlsfeature (1.3.6.1.5.5.7.1.24) — OCSP must-staple carrier.
    const tls_feature = [_]u8{ 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x18 };
};

pub const TimeKind = enum { utc, generalized };

pub const Time = struct {
    kind: TimeKind,
    bytes: []const u8,
    epoch_seconds: i64,
};

pub const IpAddress = struct {
    bytes: [16]u8,
    len: u8,

    pub fn slice(self: *const IpAddress) []const u8 {
        return self.bytes[0..self.len];
    }
};

pub const Tlv = struct {
    tag: u8,
    header_len: usize,
    value: []const u8,
    raw: []const u8,
};

/// Cursor over DER TLV elements with strict length and bounds checks.
pub const DerReader = struct {
    input: []const u8,
    offset: usize = 0,
    depth: usize = 0,

    pub fn init(input: []const u8) DerReader {
        return .{ .input = input };
    }

    pub fn hasRemaining(self: DerReader) bool {
        return self.offset < self.input.len;
    }

    pub fn remaining(self: DerReader) []const u8 {
        return self.input[self.offset..];
    }

    pub fn peekTag(self: DerReader) Error!u8 {
        if (!self.hasRemaining()) return error.Truncated;
        return self.input[self.offset];
    }

    pub fn readTlv(self: *DerReader) Error!Tlv {
        if (self.input.len > MaxDerLen) return error.Oversize;
        if (self.offset >= self.input.len) return error.Truncated;
        const start = self.offset;
        if (self.input.len - start < 2) return error.Truncated;

        const tag = self.input[start];
        if ((tag & 0x1F) == 0x1F) return error.UnsupportedTag;

        var pos = start + 2;
        var len: usize = 0;
        const first_len = self.input[start + 1];
        if ((first_len & 0x80) == 0) {
            len = first_len;
        } else {
            const len_octets = first_len & 0x7F;
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

        if (len > MaxDerLen) return error.Oversize;
        if (self.input.len - pos < len) return error.Truncated;
        const end = pos + len;
        self.offset = end;
        return .{
            .tag = tag,
            .header_len = pos - start,
            .value = self.input[pos..end],
            .raw = self.input[start..end],
        };
    }

    pub fn readExpected(self: *DerReader, expected_tag: u8) Error!Tlv {
        const tlv = try self.readTlv();
        if (tlv.tag != expected_tag) return error.InvalidTag;
        return tlv;
    }

    pub fn child(self: DerReader, tlv: Tlv) Error!DerReader {
        if (self.depth >= MaxDepth) return error.OverDepth;
        return .{ .input = tlv.value, .depth = self.depth + 1 };
    }

    pub fn expectEmpty(self: DerReader) Error!void {
        if (self.hasRemaining()) return error.TrailingData;
    }
};

/// Parsed certificate with comptime-bounded SAN storage.
pub fn ParsedCertificate(comptime max_dns_names: usize, comptime max_ip_addresses: usize) type {
    return struct {
        const Self = @This();

        der: []const u8,
        tbs_der: []const u8,
        /// DER INTEGER contents for TBSCertificate.serialNumber, including any
        /// leading sign-padding byte required by DER for a positive serial.
        serial_der: []const u8,
        spki_der: []const u8,
        spki_value: []const u8,
        /// The subject `Name` TLV (full tag+len+value). When this cert is a CA,
        /// this is the `issuer_name_der` an OCSP CertID hashes (RFC 6960).
        subject_der: []const u8,
        /// The raw subjectPublicKey BIT STRING value WITHOUT the leading
        /// unused-bits octet — the `issuer_key_bytes` an OCSP CertID hashes.
        subject_public_key: []const u8,
        /// The id-ad-ocsp responder URI from authorityInfoAccess (empty if absent):
        /// where to fetch an OCSP response to staple.
        aia_ocsp_url: []const u8,
        /// True when the cert carries the TLS Feature (id-pe-tlsfeature) extension
        /// listing status_request(5) — OCSP must-staple.
        must_staple: bool,
        not_before: Time,
        not_after: Time,
        signature_algorithm_oid: []const u8,
        san_dns: [max_dns_names][]const u8,
        san_dns_count: usize,
        san_ips: [max_ip_addresses]IpAddress,
        san_ip_count: usize,
        basic_constraints_ca: bool,
        /// basicConstraints pathLenConstraint (RFC 5280 §4.2.1.10): the maximum
        /// number of non-self-issued intermediate CAs that may follow this cert
        /// toward the leaf. `null` when absent (CA with no path limit, or a
        /// non-CA cert). Only meaningful when `basic_constraints_ca` is true.
        basic_constraints_path_len: ?u32,
        /// KeyUsage extension (2.5.29.15). `key_usage_present` is false when the
        /// extension is absent; the bit fields are only meaningful when present.
        key_usage_present: bool,
        key_usage_digital_signature: bool,
        key_usage_cert_sign: bool,
        /// ExtendedKeyUsage extension (2.5.29.37). `eku_present` is false when
        /// absent. `eku_server_auth` is true when id-kp-serverAuth or
        /// anyExtendedKeyUsage is listed.
        eku_present: bool,
        eku_server_auth: bool,
        /// NameConstraints extension (2.5.29.30) dNSName subtrees. Only meaningful
        /// when `name_constraints_present`. When `nc_permitted_dns_count > 0`, a
        /// constrained dNSName must match one permitted subtree; it must match no
        /// excluded subtree. Other GeneralName types are not enforced here.
        name_constraints_present: bool,
        nc_permitted_dns: [MaxNameConstraints][]const u8,
        nc_permitted_dns_count: usize,
        nc_excluded_dns: [MaxNameConstraints][]const u8,
        nc_excluded_dns_count: usize,

        pub fn parse(der: []const u8) Error!Self {
            var cert = Self{
                .der = der,
                .tbs_der = &.{},
                .serial_der = &.{},
                .spki_der = &.{},
                .spki_value = &.{},
                .subject_der = &.{},
                .subject_public_key = &.{},
                .aia_ocsp_url = &.{},
                .must_staple = false,
                .not_before = emptyTime(),
                .not_after = emptyTime(),
                .signature_algorithm_oid = &.{},
                .san_dns = undefined,
                .san_dns_count = 0,
                .san_ips = undefined,
                .san_ip_count = 0,
                .basic_constraints_ca = false,
                .basic_constraints_path_len = null,
                .key_usage_present = false,
                .key_usage_digital_signature = false,
                .key_usage_cert_sign = false,
                .eku_present = false,
                .eku_server_auth = false,
                .name_constraints_present = false,
                .nc_permitted_dns = undefined,
                .nc_permitted_dns_count = 0,
                .nc_excluded_dns = undefined,
                .nc_excluded_dns_count = 0,
            };
            try parseInto(Self, &cert, der);
            return cert;
        }

        pub fn certSha256(self: Self) Sha256Digest {
            return hash.Sha256.hash(self.der);
        }

        pub fn spkiSha256(self: Self) Sha256Digest {
            return hash.Sha256.hash(self.spki_der);
        }

        pub fn certSha256Hex(self: Self, out: []u8) Error![]const u8 {
            return writeHex(&self.certSha256(), out);
        }

        pub fn spkiSha256Hex(self: Self, out: []u8) Error![]const u8 {
            return writeHex(&self.spkiSha256(), out);
        }
    };
}

pub const Certificate = ParsedCertificate(DefaultMaxDnsNames, DefaultMaxIpAddresses);

pub fn parse(der: []const u8) Error!Certificate {
    return Certificate.parse(der);
}

// ---------------------------------------------------------------------------
// SubjectPublicKeyInfo extraction.
//
// Recovers the raw public-key material an issuer needs to verify a child
// certificate's signature. Slices alias the caller-owned SPKI bytes; no
// allocation, no copying. Only the key families Orochi's X.509 verifier
// dispatches on are recognized — anything else is `UnsupportedKey`, so callers
// fail closed rather than treating an unknown key as trusted.
// ---------------------------------------------------------------------------

/// Algorithm OIDs found in a SubjectPublicKeyInfo AlgorithmIdentifier.
const SpkiOid = struct {
    /// rsaEncryption (1.2.840.113549.1.1.1).
    const rsa_encryption = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };
    /// id-ecPublicKey (1.2.840.10045.2.1).
    const ec_public_key = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
    /// prime256v1 / secp256r1 (1.2.840.10045.3.1.7).
    const prime256v1 = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
    /// id-Ed25519 (1.3.101.112).
    const ed25519 = [_]u8{ 0x2B, 0x65, 0x70 };
};

/// Length of an Ed25519 raw public key.
pub const ed25519_public_key_len = 32;
/// Length of an uncompressed SEC1 P-256 point (0x04 || X32 || Y32).
pub const ec_p256_sec1_len = 65;

/// RSA public key recovered from an SPKI: big-endian modulus and exponent with
/// any DER sign-padding (leading 0x00) byte stripped to the unsigned magnitude.
pub const RsaPublicKey = struct {
    modulus: []const u8,
    exponent: []const u8,
};

/// A parsed SubjectPublicKeyInfo, tagged by key family.
pub const SubjectPublicKey = union(enum) {
    rsa: RsaPublicKey,
    /// Uncompressed SEC1 P-256 point (`0x04 || X32 || Y32`), 65 bytes.
    ecdsa_p256: []const u8,
    /// Raw 32-byte Ed25519 public key.
    ed25519: []const u8,
};

/// Parse a SubjectPublicKeyInfo (`spki_der`, the full `SEQUENCE`) into the raw
/// public-key material. Recognizes RSA, ECDSA P-256, and Ed25519; any other
/// algorithm is `error.UnsupportedKey`.
pub fn extractPublicKey(spki_der: []const u8) Error!SubjectPublicKey {
    var top = DerReader.init(spki_der);
    const seq = try top.readExpected(Tag.sequence);
    try top.expectEmpty();

    var spki = try top.child(seq);
    const alg_seq = try spki.readExpected(Tag.sequence);
    const key_bits = try spki.readExpected(Tag.bit_string);
    try spki.expectEmpty();

    const alg = try parseSpkiAlgorithm(spki, alg_seq);
    const key_bytes = try parseBitString(key_bits);

    if (std.mem.eql(u8, alg.oid, &SpkiOid.rsa_encryption)) {
        var r = DerReader.init(key_bytes);
        const rsa_seq = try r.readExpected(Tag.sequence);
        try r.expectEmpty();
        var body = try r.child(rsa_seq);
        const modulus = try unsignedInteger(try body.readExpected(Tag.integer));
        const exponent = try unsignedInteger(try body.readExpected(Tag.integer));
        try body.expectEmpty();
        return .{ .rsa = .{ .modulus = modulus, .exponent = exponent } };
    }
    if (std.mem.eql(u8, alg.oid, &SpkiOid.ec_public_key)) {
        const params = alg.params orelse return error.UnsupportedKey;
        if (!std.mem.eql(u8, params, &SpkiOid.prime256v1)) return error.UnsupportedKey;
        if (key_bytes.len != ec_p256_sec1_len or key_bytes[0] != 0x04) return error.InvalidKey;
        return .{ .ecdsa_p256 = key_bytes };
    }
    if (std.mem.eql(u8, alg.oid, &SpkiOid.ed25519)) {
        if (key_bytes.len != ed25519_public_key_len) return error.InvalidKey;
        return .{ .ed25519 = key_bytes };
    }
    return error.UnsupportedKey;
}

const SpkiAlgorithm = struct {
    oid: []const u8,
    params: ?[]const u8,
};

fn parseSpkiAlgorithm(parent: DerReader, seq_tlv: Tlv) Error!SpkiAlgorithm {
    var r = try parent.child(seq_tlv);
    const oid = try r.readExpected(Tag.oid);
    try validateOid(oid.value);
    var params: ?[]const u8 = null;
    if (r.hasRemaining()) {
        const p = try r.readTlv();
        if (p.tag == Tag.oid) params = p.value;
    }
    try r.expectEmpty();
    return .{ .oid = oid.value, .params = params };
}

/// DER INTEGER content as an unsigned big-endian magnitude: rejects negatives
/// and strips the single leading 0x00 sign byte DER requires when the magnitude
/// MSB is set.
fn unsignedInteger(tlv: Tlv) Error![]const u8 {
    if (tlv.tag != Tag.integer or tlv.value.len == 0) return error.InvalidInteger;
    try validateDerInteger(tlv.value);
    if ((tlv.value[0] & 0x80) != 0) return error.InvalidInteger; // negative
    var v = tlv.value;
    if (v.len > 1 and v[0] == 0) v = v[1..];
    if (v.len == 0) return error.InvalidInteger;
    return v;
}

/// Decode a single CERTIFICATE PEM block into caller-provided DER storage.
pub fn pemToDer(pem: []const u8, out: []u8) Error![]const u8 {
    const begin = "-----BEGIN CERTIFICATE-----";
    const end = "-----END CERTIFICATE-----";
    const begin_pos = std.mem.indexOf(u8, pem, begin) orelse return error.PemBeginMissing;
    const data_start = begin_pos + begin.len;
    const rel_end = std.mem.indexOf(u8, pem[data_start..], end) orelse return error.PemEndMissing;
    const b64 = pem[data_start .. data_start + rel_end];
    if (b64.len > MaxDerLen * 2) return error.Oversize;

    const decoder = std.base64.standard.decoderWithIgnore(" \t\r\n");
    if (decoder.calcSizeUpperBound(b64.len) > out.len) return error.OutputTooSmall;
    const written = decoder.decode(out, b64) catch |err| switch (err) {
        error.NoSpaceLeft => return error.OutputTooSmall,
        error.InvalidCharacter, error.InvalidPadding => return error.PemInvalidBase64,
    };
    if (written == 0) return error.EmptyInput;
    if (written > MaxDerLen) return error.Oversize;
    return out[0..written];
}

/// Write lowercase hexadecimal bytes into `out`.
pub fn writeHex(bytes: []const u8, out: []u8) Error![]const u8 {
    if (out.len < bytes.len * 2) return error.OutputTooSmall;
    const digits = "0123456789abcdef";
    for (bytes, 0..) |byte, i| {
        out[i * 2] = digits[byte >> 4];
        out[i * 2 + 1] = digits[byte & 0x0F];
    }
    return out[0 .. bytes.len * 2];
}

fn parseInto(comptime CertType: type, cert: *CertType, der: []const u8) Error!void {
    if (der.len == 0) return error.EmptyInput;
    if (der.len > MaxDerLen) return error.Oversize;

    var top = DerReader.init(der);
    const cert_seq = try top.readExpected(Tag.sequence);
    try top.expectEmpty();

    var body = try top.child(cert_seq);
    const tbs = try body.readExpected(Tag.sequence);
    cert.tbs_der = tbs.raw;

    const sig_alg = try body.readExpected(Tag.sequence);
    cert.signature_algorithm_oid = try parseAlgorithmOid(body, sig_alg);

    const signature = try body.readExpected(Tag.bit_string);
    _ = try parseBitString(signature);
    try body.expectEmpty();

    try parseTbs(CertType, cert, body, tbs);
    if (cert.tbs_der.len == 0 or cert.spki_der.len == 0 or
        cert.signature_algorithm_oid.len == 0)
    {
        return error.MissingField;
    }
}

fn parseTbs(comptime CertType: type, cert: *CertType, parent: DerReader, tbs: Tlv) Error!void {
    var tbs_reader = try parent.child(tbs);

    if (tbs_reader.hasRemaining() and try tbs_reader.peekTag() == Tag.context_0_constructed) {
        try parseVersion(tbs_reader, try tbs_reader.readTlv());
    }

    const serial = try tbs_reader.readExpected(Tag.integer);
    try validatePositiveInteger(serial.value);
    cert.serial_der = serial.value;

    _ = try tbs_reader.readExpected(Tag.sequence); // TBSCertificate.signature
    _ = try tbs_reader.readExpected(Tag.sequence); // issuer

    const validity = try tbs_reader.readExpected(Tag.sequence);
    var validity_reader = try tbs_reader.child(validity);
    cert.not_before = try parseTime(try validity_reader.readTlv());
    cert.not_after = try parseTime(try validity_reader.readTlv());
    try validity_reader.expectEmpty();

    const subject = try tbs_reader.readExpected(Tag.sequence); // subject
    cert.subject_der = subject.raw;

    const spki = try tbs_reader.readExpected(Tag.sequence);
    cert.spki_der = spki.raw;
    cert.spki_value = spki.value;
    // Capture the raw subjectPublicKey bit-string value (minus the unused-bits
    // octet) for the OCSP CertID issuerKeyHash.
    {
        var spki_reader = try tbs_reader.child(spki);
        _ = try spki_reader.readExpected(Tag.sequence); // AlgorithmIdentifier
        const bits = try spki_reader.readExpected(Tag.bit_string);
        if (bits.value.len >= 1) cert.subject_public_key = bits.value[1..];
    }
    try validateSpki(tbs_reader, spki);

    var saw_extensions = false;
    while (tbs_reader.hasRemaining()) {
        const tag = try tbs_reader.peekTag();
        switch (tag) {
            0x81, 0x82 => {
                _ = try tbs_reader.readTlv(); // issuerUniqueID / subjectUniqueID
            },
            Tag.context_3_constructed => {
                if (saw_extensions) return error.InvalidCertificate;
                saw_extensions = true;
                try parseExtensions(CertType, cert, tbs_reader, try tbs_reader.readTlv());
            },
            else => return error.InvalidTag,
        }
    }
}

fn parseVersion(parent: DerReader, version_tlv: Tlv) Error!void {
    var explicit = try parent.child(version_tlv);
    const version = try explicit.readExpected(Tag.integer);
    try explicit.expectEmpty();
    try validateDerInteger(version.value);
    if (version.value.len != 1 or version.value[0] > 2) return error.InvalidCertificate;
}

fn validateSpki(parent: DerReader, spki_tlv: Tlv) Error!void {
    var spki = try parent.child(spki_tlv);
    const alg = try spki.readExpected(Tag.sequence);
    _ = try parseAlgorithmOid(spki, alg);
    const key = try spki.readExpected(Tag.bit_string);
    _ = try parseBitString(key);
    try spki.expectEmpty();
}

fn parseAlgorithmOid(parent: DerReader, seq_tlv: Tlv) Error![]const u8 {
    var alg = try parent.child(seq_tlv);
    const oid = try alg.readExpected(Tag.oid);
    try validateOid(oid.value);
    if (alg.hasRemaining()) {
        _ = try alg.readTlv(); // optional parameters
    }
    try alg.expectEmpty();
    return oid.value;
}

fn parseExtensions(comptime CertType: type, cert: *CertType, parent: DerReader, ext_tlv: Tlv) Error!void {
    var explicit = try parent.child(ext_tlv);
    const seq_tlv = try explicit.readExpected(Tag.sequence);
    try explicit.expectEmpty();

    var extensions = try explicit.child(seq_tlv);
    while (extensions.hasRemaining()) {
        const one_tlv = try extensions.readExpected(Tag.sequence);
        var one = try extensions.child(one_tlv);
        const oid_tlv = try one.readExpected(Tag.oid);
        try validateOid(oid_tlv.value);

        if (one.hasRemaining() and try one.peekTag() == Tag.boolean) {
            _ = try parseBoolean(try one.readTlv());
        }

        const value = try one.readExpected(Tag.octet_string);
        try one.expectEmpty();

        if (std.mem.eql(u8, oid_tlv.value, &Oid.subject_alt_name)) {
            try parseSubjectAltName(CertType, cert, one, value.value);
        } else if (std.mem.eql(u8, oid_tlv.value, &Oid.basic_constraints)) {
            const bc = try parseBasicConstraints(one, value.value);
            cert.basic_constraints_ca = bc.ca;
            cert.basic_constraints_path_len = bc.path_len;
        } else if (std.mem.eql(u8, oid_tlv.value, &Oid.key_usage)) {
            try parseKeyUsage(CertType, cert, one, value.value);
        } else if (std.mem.eql(u8, oid_tlv.value, &Oid.extended_key_usage)) {
            try parseExtendedKeyUsage(CertType, cert, one, value.value);
        } else if (std.mem.eql(u8, oid_tlv.value, &Oid.name_constraints)) {
            try parseNameConstraints(CertType, cert, one, value.value);
        } else if (std.mem.eql(u8, oid_tlv.value, &Oid.authority_info_access)) {
            try parseAuthorityInfoAccess(CertType, cert, one, value.value);
        } else if (std.mem.eql(u8, oid_tlv.value, &Oid.tls_feature)) {
            try parseTlsFeature(CertType, cert, one, value.value);
        }
    }
}

/// authorityInfoAccess (RFC 5280 §4.2.2.1): capture the id-ad-ocsp responder URI
/// (GeneralName uniformResourceIdentifier, context-primitive tag [6] = 0x86).
fn parseAuthorityInfoAccess(comptime CertType: type, cert: *CertType, parent: DerReader, value: []const u8) Error!void {
    var inner = try nestedBytes(parent, value);
    const seq_tlv = try inner.readExpected(Tag.sequence); // SEQUENCE OF AccessDescription
    try inner.expectEmpty();
    var seq = try inner.child(seq_tlv);
    while (seq.hasRemaining()) {
        const ad_tlv = try seq.readExpected(Tag.sequence); // AccessDescription
        var ad = try seq.child(ad_tlv);
        const method = try ad.readExpected(Tag.oid);
        if (std.mem.eql(u8, method.value, &Oid.id_ad_ocsp) and ad.hasRemaining()) {
            const loc = try ad.readTlv();
            if (loc.tag == 0x86 and cert.aia_ocsp_url.len == 0) cert.aia_ocsp_url = loc.value;
        }
    }
}

/// id-pe-tlsfeature (RFC 7633): `Features ::= SEQUENCE OF INTEGER`. Set
/// `must_staple` when status_request(5) is present.
fn parseTlsFeature(comptime CertType: type, cert: *CertType, parent: DerReader, value: []const u8) Error!void {
    var inner = try nestedBytes(parent, value);
    const seq_tlv = try inner.readExpected(Tag.sequence);
    try inner.expectEmpty();
    var seq = try inner.child(seq_tlv);
    while (seq.hasRemaining()) {
        const feat = try seq.readExpected(Tag.integer);
        if (feat.value.len == 1 and feat.value[0] == 5) cert.must_staple = true;
    }
}

/// NameConstraints (RFC 5280 §4.2.1.10): SEQUENCE { permittedSubtrees [0],
/// excludedSubtrees [1] }, each GeneralSubtrees = SEQUENCE OF GeneralSubtree.
/// Only dNSName bases are retained; minimum/maximum and other name types are
/// ignored (we do not enforce base distances).
fn parseNameConstraints(comptime CertType: type, cert: *CertType, parent: DerReader, value: []const u8) Error!void {
    var inner = try nestedBytes(parent, value);
    const seq_tlv = try inner.readExpected(Tag.sequence);
    try inner.expectEmpty();
    cert.name_constraints_present = true;

    var nc = try inner.child(seq_tlv);
    while (nc.hasRemaining()) {
        const tag = try nc.peekTag();
        const tlv = try nc.readTlv();
        if (tag == Tag.context_0_constructed) {
            try collectDnsSubtrees(CertType, nc, tlv, &cert.nc_permitted_dns, &cert.nc_permitted_dns_count);
        } else if (tag == Tag.context_1_constructed) {
            try collectDnsSubtrees(CertType, nc, tlv, &cert.nc_excluded_dns, &cert.nc_excluded_dns_count);
        }
    }
}

fn collectDnsSubtrees(
    comptime CertType: type,
    parent: DerReader,
    subtrees_tlv: Tlv,
    out: *[MaxNameConstraints][]const u8,
    count: *usize,
) Error!void {
    _ = CertType;
    var subs = try parent.child(subtrees_tlv);
    while (subs.hasRemaining()) {
        const gs_tlv = try subs.readExpected(Tag.sequence);
        var gs = try subs.child(gs_tlv);
        const base = try gs.readTlv(); // GeneralName (minimum/maximum ignored)
        if (base.tag == Tag.san_dns_name) {
            if (count.* >= out.len) return error.TooManySan;
            out[count.*] = base.value;
            count.* += 1;
        }
    }
}

/// KeyUsage is a DER BIT STRING; bit 0 (MSB of the first content byte) is
/// digitalSignature and bit 5 is keyCertSign (RFC 5280 §4.2.1.3).
fn parseKeyUsage(comptime CertType: type, cert: *CertType, parent: DerReader, value: []const u8) Error!void {
    var inner = try nestedBytes(parent, value);
    const bits = try inner.readExpected(Tag.bit_string);
    try inner.expectEmpty();
    if (bits.value.len < 1) return error.InvalidBitString;
    const unused = bits.value[0];
    if (unused > 7) return error.InvalidBitString;
    cert.key_usage_present = true;
    if (bits.value.len >= 2) {
        cert.key_usage_digital_signature = (bits.value[1] & 0x80) != 0;
        cert.key_usage_cert_sign = (bits.value[1] & 0x04) != 0;
    }
}

/// ExtendedKeyUsage is a SEQUENCE OF KeyPurposeId (OID). serverAuth or
/// anyExtendedKeyUsage marks the cert usable for TLS server authentication.
fn parseExtendedKeyUsage(comptime CertType: type, cert: *CertType, parent: DerReader, value: []const u8) Error!void {
    var inner = try nestedBytes(parent, value);
    const seq_tlv = try inner.readExpected(Tag.sequence);
    try inner.expectEmpty();
    cert.eku_present = true;
    var seq = try inner.child(seq_tlv);
    while (seq.hasRemaining()) {
        const oid_tlv = try seq.readExpected(Tag.oid);
        try validateOid(oid_tlv.value);
        if (std.mem.eql(u8, oid_tlv.value, &Oid.eku_server_auth) or
            std.mem.eql(u8, oid_tlv.value, &Oid.eku_any))
        {
            cert.eku_server_auth = true;
        }
    }
}

fn parseSubjectAltName(comptime CertType: type, cert: *CertType, parent: DerReader, value: []const u8) Error!void {
    var inner = try nestedBytes(parent, value);
    const names_tlv = try inner.readExpected(Tag.sequence);
    try inner.expectEmpty();

    var names = try inner.child(names_tlv);
    while (names.hasRemaining()) {
        const name = try names.readTlv();
        switch (name.tag) {
            Tag.san_dns_name => {
                try validateDnsName(name.value);
                if (cert.san_dns_count >= cert.san_dns.len) return error.TooManySan;
                cert.san_dns[cert.san_dns_count] = name.value;
                cert.san_dns_count += 1;
            },
            Tag.san_ip_address => {
                if (name.value.len != 4 and name.value.len != 16) return error.InvalidIpAddress;
                if (cert.san_ip_count >= cert.san_ips.len) return error.TooManySan;
                var ip = IpAddress{ .bytes = [_]u8{0} ** 16, .len = @intCast(name.value.len) };
                @memcpy(ip.bytes[0..name.value.len], name.value);
                cert.san_ips[cert.san_ip_count] = ip;
                cert.san_ip_count += 1;
            },
            else => {},
        }
    }
}

const BasicConstraints = struct { ca: bool, path_len: ?u32 };

fn parseBasicConstraints(parent: DerReader, value: []const u8) Error!BasicConstraints {
    var inner = try nestedBytes(parent, value);
    const seq_tlv = try inner.readExpected(Tag.sequence);
    try inner.expectEmpty();

    var seq = try inner.child(seq_tlv);
    var ca = false;
    if (seq.hasRemaining() and try seq.peekTag() == Tag.boolean) {
        ca = try parseBoolean(try seq.readTlv());
    }
    var path_len: ?u32 = null;
    if (seq.hasRemaining() and try seq.peekTag() == Tag.integer) {
        const pl = try seq.readTlv();
        try validatePositiveInteger(pl.value);
        path_len = derIntegerToU32(pl.value);
    }
    try seq.expectEmpty();
    return .{ .ca = ca, .path_len = path_len };
}

/// Decode a validated non-negative DER INTEGER body (big-endian, optional
/// leading sign byte) into a u32. An absurdly large value (>4 bytes) is clamped
/// to maxInt — a path length that big is effectively no constraint.
fn derIntegerToU32(bytes: []const u8) u32 {
    var v = bytes;
    while (v.len > 0 and v[0] == 0x00) v = v[1..];
    if (v.len == 0) return 0;
    if (v.len > 4) return std.math.maxInt(u32);
    var acc: u32 = 0;
    for (v) |b| acc = (acc << 8) | b;
    return acc;
}

test "derIntegerToU32 decodes small path-length integers" {
    try std.testing.expectEqual(@as(u32, 0), derIntegerToU32(&.{0x00}));
    try std.testing.expectEqual(@as(u32, 0), derIntegerToU32(&.{}));
    try std.testing.expectEqual(@as(u32, 5), derIntegerToU32(&.{0x05}));
    try std.testing.expectEqual(@as(u32, 200), derIntegerToU32(&.{ 0x00, 0xC8 })); // sign byte stripped
    try std.testing.expectEqual(@as(u32, 0x0102), derIntegerToU32(&.{ 0x01, 0x02 }));
    try std.testing.expectEqual(std.math.maxInt(u32), derIntegerToU32(&.{ 0x01, 0x02, 0x03, 0x04, 0x05 }));
}

fn nestedBytes(parent: DerReader, value: []const u8) Error!DerReader {
    if (parent.depth >= MaxDepth) return error.OverDepth;
    return .{ .input = value, .depth = parent.depth + 1 };
}

fn parseBoolean(tlv: Tlv) Error!bool {
    if (tlv.tag != Tag.boolean or tlv.value.len != 1) return error.InvalidBoolean;
    return switch (tlv.value[0]) {
        0x00 => false,
        0xFF => true,
        else => error.InvalidBoolean,
    };
}

fn validatePositiveInteger(value: []const u8) Error!void {
    try validateDerInteger(value);
    if ((value[0] & 0x80) != 0) return error.InvalidInteger;
}

fn validateDerInteger(value: []const u8) Error!void {
    if (value.len == 0) return error.InvalidInteger;
    if (value.len > 1) {
        if (value[0] == 0x00 and (value[1] & 0x80) == 0) return error.InvalidInteger;
        if (value[0] == 0xFF and (value[1] & 0x80) != 0) return error.InvalidInteger;
    }
}

fn parseBitString(tlv: Tlv) Error![]const u8 {
    if (tlv.tag != Tag.bit_string or tlv.value.len == 0) return error.InvalidBitString;
    const unused_bits = tlv.value[0];
    if (unused_bits > 7) return error.InvalidBitString;
    if (tlv.value.len == 1 and unused_bits != 0) return error.InvalidBitString;
    return tlv.value[1..];
}

fn validateOid(value: []const u8) Error!void {
    if (value.len == 0) return error.InvalidOid;
    var at_arc_start = true;
    var ended_arc = false;
    for (value) |byte| {
        if (at_arc_start and byte == 0x80) return error.InvalidOid;
        ended_arc = (byte & 0x80) == 0;
        at_arc_start = ended_arc;
    }
    if (!ended_arc) return error.InvalidOid;
}

fn validateDnsName(name: []const u8) Error!void {
    if (name.len == 0 or name.len > 253) return error.InvalidName;
    var label_len: usize = 0;
    for (name) |c| {
        if (c == 0 or c > 0x7F or c <= ' ' or c == 0x7F) return error.InvalidName;
        if (c == '.') {
            if (label_len == 0) return error.InvalidName;
            label_len = 0;
        } else {
            label_len += 1;
            if (label_len > 63) return error.InvalidName;
        }
    }
    if (label_len == 0) return error.InvalidName;
}

fn parseTime(tlv: Tlv) Error!Time {
    return switch (tlv.tag) {
        Tag.utc_time => parseUtcTime(tlv.value),
        Tag.generalized_time => parseGeneralizedTime(tlv.value),
        else => error.InvalidTime,
    };
}

fn parseUtcTime(bytes: []const u8) Error!Time {
    if (bytes.len != 13 or bytes[12] != 'Z') return error.InvalidTime;
    const yy = try twoDigits(bytes[0..2], 0, 99);
    const year: i32 = if (yy >= 50) 1900 + @as(i32, yy) else 2000 + @as(i32, yy);
    const month = try twoDigits(bytes[2..4], 1, 12);
    const day = try twoDigits(bytes[4..6], 1, 31);
    const hour = try twoDigits(bytes[6..8], 0, 23);
    const minute = try twoDigits(bytes[8..10], 0, 59);
    const second = try twoDigits(bytes[10..12], 0, 59);
    return .{
        .kind = .utc,
        .bytes = bytes,
        .epoch_seconds = try epochSeconds(year, month, day, hour, minute, second),
    };
}

fn parseGeneralizedTime(bytes: []const u8) Error!Time {
    if (bytes.len != 15 or bytes[14] != 'Z') return error.InvalidTime;
    const year_u16 = try fourDigits(bytes[0..4]);
    const month = try twoDigits(bytes[4..6], 1, 12);
    const day = try twoDigits(bytes[6..8], 1, 31);
    const hour = try twoDigits(bytes[8..10], 0, 23);
    const minute = try twoDigits(bytes[10..12], 0, 59);
    const second = try twoDigits(bytes[12..14], 0, 59);
    return .{
        .kind = .generalized,
        .bytes = bytes,
        .epoch_seconds = try epochSeconds(@intCast(year_u16), month, day, hour, minute, second),
    };
}

fn twoDigits(bytes: []const u8, min: u8, max: u8) Error!u8 {
    if (bytes.len != 2) return error.InvalidTime;
    if (!std.ascii.isDigit(bytes[0]) or !std.ascii.isDigit(bytes[1])) return error.InvalidTime;
    const value = (bytes[0] - '0') * 10 + (bytes[1] - '0');
    if (value < min or value > max) return error.InvalidTime;
    return value;
}

fn fourDigits(bytes: []const u8) Error!u16 {
    if (bytes.len != 4) return error.InvalidTime;
    var value: u16 = 0;
    for (bytes) |byte| {
        if (!std.ascii.isDigit(byte)) return error.InvalidTime;
        value = value * 10 + @as(u16, byte - '0');
    }
    return value;
}

fn epochSeconds(year: i32, month: u8, day: u8, hour: u8, minute: u8, second: u8) Error!i64 {
    const max_day = daysInMonth(year, month);
    if (day > max_day) return error.InvalidTime;

    var days: i64 = 0;
    if (year >= 1970) {
        var y: i32 = 1970;
        while (y < year) : (y += 1) {
            days += daysInYear(y);
        }
    } else {
        var y: i32 = year;
        while (y < 1970) : (y += 1) {
            days -= daysInYear(y);
        }
    }

    var m: u8 = 1;
    while (m < month) : (m += 1) {
        days += daysInMonth(year, m);
    }
    days += @as(i64, day) - 1;
    return days * 86_400 + @as(i64, hour) * 3_600 + @as(i64, minute) * 60 + second;
}

fn daysInYear(year: i32) i64 {
    return if (isLeapYear(year)) 366 else 365;
}

fn daysInMonth(year: i32, month: u8) u8 {
    return switch (month) {
        1, 3, 5, 7, 8, 10, 12 => 31,
        4, 6, 9, 11 => 30,
        2 => if (isLeapYear(year)) 29 else 28,
        else => 0,
    };
}

fn isLeapYear(year: i32) bool {
    return @mod(year, 4) == 0 and (@mod(year, 100) != 0 or @mod(year, 400) == 0);
}

fn emptyTime() Time {
    return .{ .kind = .utc, .bytes = &.{}, .epoch_seconds = 0 };
}

const TestPem =
    \\-----BEGIN CERTIFICATE-----
    \\MIIBTjCCAQCgAwIBAgIUJDiKIghmTbbnchKxfF7JSGOq2GMwBQYDK2VwMBcxFTAT
    \\BgNVBAMMDG1penVjaGkudGVzdDAeFw0yNjA2MDIwNzQzMTNaFw0yNzA2MDIwNzQz
    \\MTNaMBcxFTATBgNVBAMMDG1penVjaGkudGVzdDAqMAUGAytlcAMhAFKLR+w7sDBj
    \\GGqbwTEB1UK8m3dRhczE6hE5oFndyhmNo14wXDAdBgNVHREEFjAUggxtaXp1Y2hp
    \\LnRlc3SHBH8AAAEwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0O
    \\BBYEFM5XZQQHVbUTvF3XM2VYeRv9h3SCMAUGAytlcANBACgR6nP3aanandt+lYUf
    \\lPQ6FtadqQb/sXCs8RR2CW5KGu5dOfvFjedfNm9mhzhvT6QjHTj3UjTEQ3obrANN
    \\Lw0=
    \\-----END CERTIFICATE-----
;

const TestDerBase64Compact =
    "MIIBTjCCAQCgAwIBAgIUJDiKIghmTbbnchKxfF7JSGOq2GMwBQYDK2VwMBcxFTAT" ++
    "BgNVBAMMDG1penVjaGkudGVzdDAeFw0yNjA2MDIwNzQzMTNaFw0yNzA2MDIwNzQz" ++
    "MTNaMBcxFTATBgNVBAMMDG1penVjaGkudGVzdDAqMAUGAytlcAMhAFKLR+w7sDBj" ++
    "GGqbwTEB1UK8m3dRhczE6hE5oFndyhmNo14wXDAdBgNVHREEFjAUggxtaXp1Y2hp" ++
    "LnRlc3SHBH8AAAEwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0O" ++
    "BBYEFM5XZQQHVbUTvF3XM2VYeRv9h3SCMAUGAytlcANBACgR6nP3aanandt+lYUf" ++
    "lPQ6FtadqQb/sXCs8RR2CW5KGu5dOfvFjedfNm9mhzhvT6QjHTj3UjTEQ3obrANN" ++
    "Lw0=";

test "parse embedded certificate and compute certfp" {
    var der_buf: [512]u8 = undefined;
    const der = try pemToDer(TestPem, &der_buf);
    const cert = try parse(der);

    try std.testing.expect(cert.tbs_der.len > 0);
    try std.testing.expect(cert.spki_der.len > 0);
    try std.testing.expect(cert.spki_value.len > 0);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x2B, 0x65, 0x70 }, cert.signature_algorithm_oid);
    try std.testing.expectEqual(@as(usize, 1), cert.san_dns_count);
    // Structural SAN check (the embedded fixture's dNSName ends in ".test").
    try std.testing.expect(cert.san_dns[0].len > 0);
    try std.testing.expect(std.mem.endsWith(u8, cert.san_dns[0], ".test"));
    try std.testing.expectEqual(@as(usize, 1), cert.san_ip_count);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 127, 0, 0, 1 }, cert.san_ips[0].slice());
    try std.testing.expect(!cert.basic_constraints_ca);
    // The fixture carries a KeyUsage extension (digitalSignature only) and no
    // ExtendedKeyUsage extension.
    try std.testing.expect(cert.key_usage_present);
    try std.testing.expect(cert.key_usage_digital_signature);
    try std.testing.expect(!cert.key_usage_cert_sign);
    try std.testing.expect(!cert.eku_present);
    try std.testing.expect(!cert.eku_server_auth);

    var cert_hex: [64]u8 = undefined;
    var spki_hex: [64]u8 = undefined;
    try std.testing.expectEqualSlices(
        u8,
        "231a5709f3e42db6130a35b75d56b45dedee32690a9e6f71bf6ad87e6707ba7a",
        try cert.certSha256Hex(&cert_hex),
    );
    try std.testing.expectEqualSlices(
        u8,
        "4d9627b687eb99707c4e16eb91705ab468c12055662837088931f27bd38b721e",
        try cert.spkiSha256Hex(&spki_hex),
    );

    var encoded: [512]u8 = undefined;
    const out = std.base64.standard.Encoder.encode(&encoded, der);
    try std.testing.expectEqualSlices(u8, TestDerBase64Compact, out);
}

test "DER reader rejects malformed TLVs" {
    var truncated = DerReader.init(&[_]u8{0x30});
    var indefinite = DerReader.init(&[_]u8{ 0x30, 0x80 });
    var non_canonical = DerReader.init(&[_]u8{ 0x04, 0x81, 0x7F });
    var unsupported = DerReader.init(&[_]u8{ 0x1F, 0x01, 0x00 });

    try std.testing.expectError(error.Truncated, truncated.readTlv());
    try std.testing.expectError(error.IndefiniteLength, indefinite.readTlv());
    try std.testing.expectError(error.NonCanonicalLength, non_canonical.readTlv());
    try std.testing.expectError(error.UnsupportedTag, unsupported.readTlv());
}

test "malformed certificates and PEM are rejected" {
    var der_buf: [512]u8 = undefined;
    const der = try pemToDer(TestPem, &der_buf);
    try std.testing.expectError(error.Truncated, parse(der[0 .. der.len - 1]));
    try std.testing.expectError(error.PemBeginMissing, pemToDer("not a cert", &der_buf));
    try std.testing.expectError(
        error.PemInvalidBase64,
        pemToDer("-----BEGIN CERTIFICATE-----\n@@@@\n-----END CERTIFICATE-----\n", &der_buf),
    );
}

test "extractPublicKey recovers the Ed25519 key from the embedded SPKI" {
    var der_buf: [512]u8 = undefined;
    const der = try pemToDer(TestPem, &der_buf);
    const cert = try parse(der);

    const key = try extractPublicKey(cert.spki_der);
    switch (key) {
        .ed25519 => |raw| {
            try std.testing.expectEqual(@as(usize, ed25519_public_key_len), raw.len);
            // The embedded fixture's SPKI key bits are the 32 bytes after the
            // BIT STRING's leading unused-bits octet.
            try std.testing.expectEqualSlices(u8, cert.spki_value[cert.spki_value.len - 32 ..], raw);
        },
        else => return error.InvalidCertificate,
    }
}

test "extractPublicKey rejects a truncated SPKI" {
    var der_buf: [512]u8 = undefined;
    const der = try pemToDer(TestPem, &der_buf);
    const cert = try parse(der);
    try std.testing.expectError(error.Truncated, extractPublicKey(cert.spki_der[0 .. cert.spki_der.len - 1]));
}

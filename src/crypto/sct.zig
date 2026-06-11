//! RFC 6962 Certificate Transparency — Signed Certificate Timestamp (SCT)
//! parsing and signed-data reconstruction.
//!
//! This module decodes the `SignedCertificateTimestampList` carried by the
//! X.509 SCT extension (OID 1.3.6.1.4.1.11129.2.4.2) and each contained
//! `SignedCertificateTimestamp` (SCT), and reconstructs the byte string a CT
//! log signs over (`CertificateTimestamp`) so a caller can later verify an
//! SCT's signature against a known log's public key.
//!
//! Scope and boundaries:
//!   * Input is the *unwrapped* extension value. The X.509 extension stores its
//!     value as a DER OCTET STRING whose contents are themselves a DER OCTET
//!     STRING wrapping the TLS-encoded list. The caller is responsible for
//!     peeling both OCTET STRING wrappers (the daemon's `x509.zig` DER reader
//!     does this); `parseList` receives the raw TLS bytes:
//!
//!         struct {
//!             SerializedSCT sct_list<1..2^16-1>;
//!         } SignedCertificateTimestampList;
//!
//!     i.e. a 2-byte big-endian total length followed by a sequence of
//!     `serialized_sct` items, each itself prefixed with a 2-byte length.
//!
//!   * Each `SignedCertificateTimestamp` (RFC 6962 §3.2) is:
//!
//!         struct {
//!             Version sct_version;            // u8, v1 = 0
//!             LogID id;                       // opaque[32]
//!             uint64 timestamp;               // ms since the epoch
//!             CtExtensions extensions;        // opaque<0..2^16-1>
//!             digitally-signed struct { ... } signature;
//!         } SignedCertificateTimestamp;
//!
//!     where the trailing `digitally-signed` value (RFC 5246 §4.7) is a
//!     `SignatureAndHashAlgorithm` (2 bytes: hash, signature) followed by an
//!     opaque signature `<0..2^16-1>`.
//!
//! Pure logic: no I/O, no clock, no RNG, no allocation. Callers own every
//! buffer. Parsed structs alias the input slice; every length is bounds-checked
//! and a truncated or malformed block yields a typed error rather than reading
//! past the slice.
//!
//! OUT OF SCOPE for this module (by design):
//!   * Actual signature verification (ECDSA P-256 / Ed25519). The daemon's
//!     `ecdsa_p256.zig` / `sign.zig` modules perform the cryptographic check;
//!     this module only reconstructs the signed bytes via `buildSignedData`.
//!   * Shipping or matching a CT log list / public keys. A future log-list
//!     module would map a parsed `log_id` to a verification key.
//!   * DER decoding of the X.509 extension envelope (handled by `x509.zig`).
const std = @import("std");

/// Width of a length prefix used throughout the SCT wire format.
const len_prefix_len: usize = 2;

/// Width of the fixed `LogID` field (RFC 6962 §3.2: SHA-256 of the log key).
pub const log_id_len: usize = 32;

/// Width of the `timestamp` field in bytes (a big-endian `uint64`).
const timestamp_len: usize = 8;

/// Width of a `SignatureAndHashAlgorithm` (RFC 5246 §7.4.1.4.1).
const sig_alg_len: usize = 2;

/// Maximum number of SCTs `parseList` will surface from a single list.
///
/// A bounded fixed array keeps the hot path allocation-free. CT lists are
/// small in practice (a handful of logs); lists longer than this are rejected
/// with `error.TooManySct` so the cap never silently truncates.
pub const max_scts: usize = 8;

/// SCT structure version (RFC 6962 §3.2). Only `v1` is defined.
pub const Version = enum(u8) {
    v1 = 0,
    _,
};

/// `SignatureType` discriminant for the signed `CertificateTimestamp`
/// (RFC 6962 §3.2). `certificate_timestamp` is the only value used when a log
/// signs an SCT; `tree_hash` appears in Signed Tree Heads, outside this module.
pub const SignatureType = enum(u8) {
    certificate_timestamp = 0,
    tree_hash = 1,
};

/// `LogEntryType` (RFC 6962 §3.1): the kind of entry the log certified.
pub const LogEntryType = enum(u16) {
    /// A full X.509 certificate. `signed_entry` is its DER, length-prefixed.
    x509_entry = 0,
    /// A precertificate. `signed_entry` is the issuer key hash (32 bytes)
    /// followed by the length-prefixed TBSCertificate.
    precert_entry = 1,
};

/// Errors produced while parsing an SCT list or building signed data.
pub const Error = error{
    /// A length prefix or fixed field ran past the end of the input.
    Truncated,
    /// A declared length did not match the bytes actually present, or the
    /// outer list length disagreed with its trailing bytes.
    LengthMismatch,
    /// An individual `serialized_sct` declared zero length (RFC 6962 requires
    /// `<1..2^16-1>`), or the list framing was otherwise inconsistent.
    InvalidLength,
    /// More SCTs were present than `max_scts` allows.
    TooManySct,
    /// A build target buffer ran out of room. Matches `std`'s spelling.
    NoSpaceLeft,
};

/// A single parsed `SignedCertificateTimestamp`. All slice fields alias the
/// input passed to `parseList`; copy them out if the input is transient.
pub const Sct = struct {
    /// SCT structure version (`v1` in practice).
    version: Version,
    /// SHA-256 hash of the issuing log's public key (DER SubjectPublicKeyInfo).
    log_id: [log_id_len]u8,
    /// Milliseconds since the Unix epoch at which the log issued the SCT.
    timestamp: u64,
    /// `CtExtensions` opaque blob (almost always empty); aliases the input.
    extensions: []const u8,
    /// `SignatureAndHashAlgorithm.hash` (RFC 5246 §7.4.1.4.1 HashAlgorithm).
    sig_hash_alg: u8,
    /// `SignatureAndHashAlgorithm.signature` (RFC 5246 SignatureAlgorithm).
    sig_signature_alg: u8,
    /// Raw signature bytes (the opaque body of the `digitally-signed` struct);
    /// aliases the input.
    signature: []const u8,

    /// Convenience accessor for the combined 16-bit
    /// `SignatureAndHashAlgorithm` code (hash in the high byte). This matches
    /// the TLS 1.3 `SignatureScheme` numbering only for schemes whose legacy
    /// hash/sig pair coincides with the modern code; treat it as informational.
    pub fn sigAlgCode(self: *const Sct) u16 {
        return (@as(u16, self.sig_hash_alg) << 8) | @as(u16, self.sig_signature_alg);
    }
};

/// A bounded, parsed `SignedCertificateTimestampList`. Holds up to `max_scts`
/// SCTs whose slices alias the input passed to `parseList`.
pub const SctList = struct {
    items: [max_scts]Sct = undefined,
    len: usize = 0,

    /// The populated prefix of `items` as a slice.
    pub fn slice(self: *const SctList) []const Sct {
        return self.items[0..self.len];
    }
};

/// Read a big-endian `u16` from the first two bytes of `b` (caller guarantees
/// `b.len >= 2`).
fn readU16(b: []const u8) u16 {
    return std.mem.readInt(u16, b[0..2], .big);
}

/// Write a big-endian `u16` into the first two bytes of `out` (caller
/// guarantees `out.len >= 2`).
fn writeU16(out: []u8, value: u16) void {
    std.mem.writeInt(u16, out[0..2], value, .big);
}

/// A length-prefixed-vector reader that refuses to read past `buf`. Used to
/// walk the SCT wire format field by field without aliasing past the input.
const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    fn init(buf: []const u8) Reader {
        return .{ .buf = buf };
    }

    fn remaining(self: *const Reader) usize {
        return self.buf.len - self.pos;
    }

    /// Take exactly `n` bytes, advancing the cursor. Fails closed if short.
    fn take(self: *Reader, n: usize) Error![]const u8 {
        if (self.remaining() < n) return error.Truncated;
        const out = self.buf[self.pos..][0..n];
        self.pos += n;
        return out;
    }

    /// Read a single big-endian `u8`.
    fn readU8(self: *Reader) Error!u8 {
        const b = try self.take(1);
        return b[0];
    }

    /// Read a big-endian `u16`.
    fn readU16(self: *Reader) Error!u16 {
        const b = try self.take(len_prefix_len);
        return std.mem.readInt(u16, b[0..2], .big);
    }

    /// Read a big-endian `u64`.
    fn readU64(self: *Reader) Error!u64 {
        const b = try self.take(timestamp_len);
        return std.mem.readInt(u64, b[0..8], .big);
    }

    /// Read a `u16`-length-prefixed opaque vector and return its body (aliasing
    /// the input). The declared length is validated against the remaining bytes.
    fn readVarU16(self: *Reader) Error![]const u8 {
        const n = try self.readU16();
        return self.take(n);
    }
};

/// Parse a `SignedCertificateTimestampList` into a bounded `SctList`.
///
/// `bytes` must be the TLS-encoded list (both X.509 OCTET STRING wrappers
/// already stripped): a 2-byte total length followed by that many bytes of
/// `serialized_sct` items, each 2-byte-length-prefixed. The total length must
/// exactly account for the trailing bytes; trailing slack is rejected.
///
/// On success the returned `SctList` aliases `bytes`. Fails closed with a typed
/// error on any framing inconsistency, and with `error.TooManySct` if the list
/// holds more than `max_scts` SCTs.
pub fn parseList(bytes: []const u8) Error!SctList {
    if (bytes.len < len_prefix_len) return error.Truncated;
    const declared = readU16(bytes[0..len_prefix_len]);
    const body = bytes[len_prefix_len..];
    if (body.len != declared) return error.LengthMismatch;

    var list: SctList = .{};
    var r = Reader.init(body);
    while (r.remaining() != 0) {
        const item = try r.readVarU16();
        // RFC 6962 declares serialized_sct as <1..2^16-1>; a zero-length item
        // is malformed framing.
        if (item.len == 0) return error.InvalidLength;
        if (list.len >= max_scts) return error.TooManySct;
        list.items[list.len] = try parseSct(item);
        list.len += 1;
    }
    return list;
}

/// Parse a single `serialized_sct` body (one `SignedCertificateTimestamp`).
///
/// `bytes` is exactly the SCT body (the per-item 2-byte length prefix already
/// stripped by `parseList`). Every field is bounds-checked; any trailing byte
/// after the signature is a framing error.
pub fn parseSct(bytes: []const u8) Error!Sct {
    var r = Reader.init(bytes);

    const version: Version = @enumFromInt(try r.readU8());

    const id_bytes = try r.take(log_id_len);
    var log_id: [log_id_len]u8 = undefined;
    @memcpy(&log_id, id_bytes);

    const timestamp = try r.readU64();
    const extensions = try r.readVarU16();

    const sig_alg = try r.take(sig_alg_len);
    const sig_hash_alg = sig_alg[0];
    const sig_signature_alg = sig_alg[1];
    const signature = try r.readVarU16();

    // A well-formed SCT consumes its body exactly; surplus bytes are malformed.
    if (r.remaining() != 0) return error.LengthMismatch;

    return .{
        .version = version,
        .log_id = log_id,
        .timestamp = timestamp,
        .extensions = extensions,
        .sig_hash_alg = sig_hash_alg,
        .sig_signature_alg = sig_signature_alg,
        .signature = signature,
    };
}

/// Inputs to `buildSignedData`: the parsed SCT plus the certified entry.
///
/// The caller supplies `signed_entry` already in the form the log signs:
///   * For `x509_entry`: the leaf certificate's DER (`ASN.1Cert`), which is
///     emitted length-prefixed with a 24-bit length.
///   * For `precert_entry`: the 32-byte issuer-key hash concatenated with the
///     TBSCertificate, emitted as `PreCert { opaque[32]; opaque<1..2^24-1> }`.
///     Construct this blob with `buildPrecertEntry` before calling.
///
/// `extensions` mirrors the SCT's `CtExtensions` (usually empty); pass
/// `sct.extensions`.
pub const SignedDataInput = struct {
    version: Version = .v1,
    timestamp: u64,
    entry_type: LogEntryType,
    /// The `signed_entry` bytes exactly as the log hashes them (see above).
    signed_entry: []const u8,
    /// `CtExtensions` opaque body (typically empty).
    extensions: []const u8 = &.{},
};

/// Width of the 24-bit length prefix used by the precert TBSCertificate vector.
const u24_prefix_len: usize = 3;

/// Reconstruct the byte string a CT log signs for a certificate/precert entry:
/// the `CertificateTimestamp` structure of RFC 6962 §3.2.
///
///     digitally-signed struct {
///         Version sct_version;            // u8
///         SignatureType signature_type;   // u8 = certificate_timestamp(0)
///         uint64 timestamp;
///         LogEntryType entry_type;        // u16
///         select(entry_type) {
///             case x509_entry:   ASN.1Cert;   // opaque<1..2^24-1>
///             case precert_entry: PreCert;     // already in signed_entry
///         } signed_entry;
///         CtExtensions extensions;        // opaque<0..2^16-1>
///     } CertificateTimestamp;
///
/// `signed_entry` is written verbatim for `precert_entry` (the caller framed
/// the `PreCert`), and wrapped in a 24-bit length prefix for `x509_entry`
/// (the `ASN.1Cert` opaque<1..2^24-1>).
///
/// Writes into `out` and returns the written prefix; fails with
/// `error.NoSpaceLeft` if `out` is too small. The resulting bytes are exactly
/// what `ecdsa_p256`/`sign` would later verify against a log's public key.
pub fn buildSignedData(out: []u8, input: SignedDataInput) Error![]const u8 {
    const entry_overhead: usize = switch (input.entry_type) {
        .x509_entry => u24_prefix_len,
        .precert_entry => 0,
    };
    if (input.extensions.len > 0xffff) return error.InvalidLength;
    if (input.signed_entry.len > 0xff_ffff) return error.InvalidLength;

    const total =
        1 + // version
        1 + // signature_type
        timestamp_len +
        sig_alg_len + // entry_type (u16)
        entry_overhead +
        input.signed_entry.len +
        len_prefix_len + // extensions length
        input.extensions.len;
    if (out.len < total) return error.NoSpaceLeft;

    var off: usize = 0;

    out[off] = @intFromEnum(input.version);
    off += 1;
    out[off] = @intFromEnum(SignatureType.certificate_timestamp);
    off += 1;

    std.mem.writeInt(u64, out[off..][0..timestamp_len], input.timestamp, .big);
    off += timestamp_len;

    writeU16(out[off..], @intFromEnum(input.entry_type));
    off += sig_alg_len;

    switch (input.entry_type) {
        .x509_entry => {
            // ASN.1Cert is opaque<1..2^24-1>: a 24-bit length then the DER.
            writeU24(out[off..], @intCast(input.signed_entry.len));
            off += u24_prefix_len;
        },
        .precert_entry => {}, // signed_entry already carries its own framing.
    }
    @memcpy(out[off..][0..input.signed_entry.len], input.signed_entry);
    off += input.signed_entry.len;

    writeU16(out[off..], @intCast(input.extensions.len));
    off += len_prefix_len;
    @memcpy(out[off..][0..input.extensions.len], input.extensions);
    off += input.extensions.len;

    return out[0..off];
}

/// Frame a `PreCert { opaque issuer_key_hash[32]; TBSCertificate tbs; }` blob
/// (RFC 6962 §3.2) into `out` so it can be passed as `signed_entry` for a
/// `precert_entry`. `tbs` is the TBSCertificate DER, emitted as opaque<1..2^24-1>.
pub fn buildPrecertEntry(out: []u8, issuer_key_hash: [log_id_len]u8, tbs: []const u8) Error![]const u8 {
    if (tbs.len > 0xff_ffff) return error.InvalidLength;
    const total = log_id_len + u24_prefix_len + tbs.len;
    if (out.len < total) return error.NoSpaceLeft;

    @memcpy(out[0..log_id_len], &issuer_key_hash);
    writeU24(out[log_id_len..], @intCast(tbs.len));
    @memcpy(out[log_id_len + u24_prefix_len ..][0..tbs.len], tbs);
    return out[0..total];
}

/// Write a big-endian 24-bit length into the first three bytes of `out`
/// (caller guarantees `out.len >= 3` and `value <= 0xff_ffff`).
fn writeU24(out: []u8, value: u24) void {
    out[0] = @intCast((value >> 16) & 0xff);
    out[1] = @intCast((value >> 8) & 0xff);
    out[2] = @intCast(value & 0xff);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

/// TLS HashAlgorithm.sha256 / SignatureAlgorithm.ecdsa (RFC 5246 §7.4.1.4.1),
/// i.e. the legacy pair that combines to the 0x0403 ecdsa_secp256r1_sha256
/// SignatureScheme code.
const hash_sha256: u8 = 4;
const sig_ecdsa: u8 = 3;

/// Hand-build a `serialized_sct` body for one v1 SCT.
fn buildOneSctBody(
    out: []u8,
    log_id: [log_id_len]u8,
    timestamp: u64,
    extensions: []const u8,
    signature: []const u8,
) []const u8 {
    var off: usize = 0;
    out[off] = @intFromEnum(Version.v1);
    off += 1;
    @memcpy(out[off..][0..log_id_len], &log_id);
    off += log_id_len;
    std.mem.writeInt(u64, out[off..][0..8], timestamp, .big);
    off += 8;
    writeU16(out[off..], @intCast(extensions.len));
    off += 2;
    @memcpy(out[off..][0..extensions.len], extensions);
    off += extensions.len;
    out[off] = hash_sha256;
    off += 1;
    out[off] = sig_ecdsa;
    off += 1;
    writeU16(out[off..], @intCast(signature.len));
    off += 2;
    @memcpy(out[off..][0..signature.len], signature);
    off += signature.len;
    return out[0..off];
}

/// Wrap one or more `serialized_sct` bodies into a full
/// `SignedCertificateTimestampList` (outer u16 length + per-item u16 lengths).
fn buildList(out: []u8, bodies: []const []const u8) []const u8 {
    var inner_off: usize = len_prefix_len;
    for (bodies) |b| {
        writeU16(out[inner_off..], @intCast(b.len));
        inner_off += len_prefix_len;
        @memcpy(out[inner_off..][0..b.len], b);
        inner_off += b.len;
    }
    writeU16(out[0..], @intCast(inner_off - len_prefix_len));
    return out[0..inner_off];
}

test "parseList decodes a single v1 SCT with every field intact" {
    // Arrange
    var log_id: [log_id_len]u8 = undefined;
    for (&log_id, 0..) |*b, i| b.* = @intCast(i + 1);
    const timestamp: u64 = 0x0000_0193_4d2e_a1f0;
    const signature = [_]u8{ 0x30, 0x06, 0x02, 0x01, 0x2a, 0x02, 0x01, 0x07 };

    var body_buf: [256]u8 = undefined;
    const body = buildOneSctBody(&body_buf, log_id, timestamp, &.{}, &signature);
    var list_buf: [512]u8 = undefined;
    const list_bytes = buildList(&list_buf, &.{body});

    // Act
    const parsed = try parseList(list_bytes);

    // Assert
    try testing.expectEqual(@as(usize, 1), parsed.len);
    const sct = parsed.slice()[0];
    try testing.expectEqual(Version.v1, sct.version);
    try testing.expectEqualSlices(u8, &log_id, &sct.log_id);
    try testing.expectEqual(timestamp, sct.timestamp);
    try testing.expectEqual(@as(usize, 0), sct.extensions.len);
    try testing.expectEqual(hash_sha256, sct.sig_hash_alg);
    try testing.expectEqual(sig_ecdsa, sct.sig_signature_alg);
    try testing.expectEqual(@as(u16, 0x0403), sct.sigAlgCode());
    try testing.expectEqualSlices(u8, &signature, sct.signature);
}

test "parseList preserves non-empty CtExtensions" {
    // Arrange
    const log_id = [_]u8{0xAB} ** log_id_len;
    const extensions = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    const signature = [_]u8{ 0x01, 0x02 };

    var body_buf: [256]u8 = undefined;
    const body = buildOneSctBody(&body_buf, log_id, 42, &extensions, &signature);
    var list_buf: [512]u8 = undefined;
    const list_bytes = buildList(&list_buf, &.{body});

    // Act
    const parsed = try parseList(list_bytes);

    // Assert
    try testing.expectEqual(@as(usize, 1), parsed.len);
    try testing.expectEqualSlices(u8, &extensions, parsed.slice()[0].extensions);
}

test "parseList decodes two SCTs in wire order" {
    // Arrange
    const log_id_a = [_]u8{0x11} ** log_id_len;
    const log_id_b = [_]u8{0x22} ** log_id_len;
    const sig_a = [_]u8{0xaa};
    const sig_b = [_]u8{ 0xbb, 0xbb };

    var ba: [128]u8 = undefined;
    var bb: [128]u8 = undefined;
    const body_a = buildOneSctBody(&ba, log_id_a, 1, &.{}, &sig_a);
    const body_b = buildOneSctBody(&bb, log_id_b, 2, &.{}, &sig_b);
    var list_buf: [512]u8 = undefined;
    const list_bytes = buildList(&list_buf, &.{ body_a, body_b });

    // Act
    const parsed = try parseList(list_bytes);

    // Assert
    try testing.expectEqual(@as(usize, 2), parsed.len);
    try testing.expectEqualSlices(u8, &log_id_a, &parsed.slice()[0].log_id);
    try testing.expectEqual(@as(u64, 1), parsed.slice()[0].timestamp);
    try testing.expectEqualSlices(u8, &log_id_b, &parsed.slice()[1].log_id);
    try testing.expectEqualSlices(u8, &sig_b, parsed.slice()[1].signature);
}

test "parseList accepts an empty list" {
    // Arrange: outer length 0, no items.
    const list_bytes = [_]u8{ 0x00, 0x00 };

    // Act
    const parsed = try parseList(&list_bytes);

    // Assert
    try testing.expectEqual(@as(usize, 0), parsed.len);
    try testing.expectEqual(@as(usize, 0), parsed.slice().len);
}

test "parseList rejects input with no full outer length prefix" {
    // Arrange
    const list_bytes = [_]u8{0x00};

    // Act / Assert
    try testing.expectError(error.Truncated, parseList(&list_bytes));
}

test "parseList rejects an outer length that exceeds the body" {
    // Arrange: declares 8 body bytes but carries only 4.
    const list_bytes = [_]u8{ 0x00, 0x08, 0x00, 0x01, 0x00, 0x02 };

    // Act / Assert
    try testing.expectError(error.LengthMismatch, parseList(&list_bytes));
}

test "parseList rejects trailing bytes after the declared body" {
    // Arrange: declares 4 body bytes but carries 5.
    const list_bytes = [_]u8{ 0x00, 0x04, 0x00, 0x01, 0xff, 0xff, 0x00 };

    // Act / Assert
    try testing.expectError(error.LengthMismatch, parseList(&list_bytes));
}

test "parseList rejects a zero-length serialized_sct item" {
    // Arrange: outer length 2, one item declaring length 0.
    const list_bytes = [_]u8{ 0x00, 0x02, 0x00, 0x00 };

    // Act / Assert
    try testing.expectError(error.InvalidLength, parseList(&list_bytes));
}

test "parseList rejects a serialized_sct that overruns the list body" {
    // Arrange: item declares 16 bytes but only 2 follow.
    const list_bytes = [_]u8{ 0x00, 0x04, 0x00, 0x10, 0xaa, 0xbb };

    // Act / Assert
    try testing.expectError(error.Truncated, parseList(&list_bytes));
}

test "parseSct rejects a truncated SCT (LogID cut short)" {
    // Arrange: version + 4 LogID bytes, then nothing.
    const body = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04 };

    // Act / Assert
    try testing.expectError(error.Truncated, parseSct(&body));
}

test "parseSct rejects surplus bytes after the signature" {
    // Arrange: a valid SCT body with one extra trailing byte appended.
    const log_id = [_]u8{0x07} ** log_id_len;
    const signature = [_]u8{ 0x09, 0x0a };
    var body_buf: [256]u8 = undefined;
    const body = buildOneSctBody(&body_buf, log_id, 99, &.{}, &signature);

    var overlong: [256]u8 = undefined;
    @memcpy(overlong[0..body.len], body);
    overlong[body.len] = 0xff;

    // Act / Assert
    try testing.expectError(error.LengthMismatch, parseSct(overlong[0 .. body.len + 1]));
}

test "parseSct rejects a signature length that overruns the body" {
    // Arrange: hand-build an SCT whose signature length prefix lies.
    var body: [1 + log_id_len + 8 + 2 + 2 + 2]u8 = undefined;
    var off: usize = 0;
    body[off] = @intFromEnum(Version.v1);
    off += 1;
    @memset(body[off..][0..log_id_len], 0x00);
    off += log_id_len;
    @memset(body[off..][0..8], 0x00);
    off += 8;
    writeU16(body[off..], 0); // empty extensions
    off += 2;
    body[off] = hash_sha256;
    body[off + 1] = sig_ecdsa;
    off += 2;
    writeU16(body[off..], 0x00ff); // claims 255 signature bytes
    off += 2;

    // Act / Assert
    try testing.expectError(error.Truncated, parseSct(body[0..off]));
}

test "parseList surfaces version even for an unknown version byte" {
    // Arrange: an SCT whose version byte is 9 (not v1).
    const log_id = [_]u8{0x01} ** log_id_len;
    const signature = [_]u8{0x00};
    var body_buf: [256]u8 = undefined;
    const body = buildOneSctBody(&body_buf, log_id, 0, &.{}, &signature);
    var mutable: [256]u8 = undefined;
    @memcpy(mutable[0..body.len], body);
    mutable[0] = 9; // corrupt the version

    var list_buf: [512]u8 = undefined;
    const list_bytes = buildList(&list_buf, &.{mutable[0..body.len]});

    // Act
    const parsed = try parseList(list_bytes);

    // Assert: non-exhaustive enum preserves the wire value; v1 is the only
    // named member, so an unknown byte is not equal to v1.
    try testing.expectEqual(@as(usize, 1), parsed.len);
    try testing.expect(parsed.slice()[0].version != .v1);
    try testing.expectEqual(@as(u8, 9), @intFromEnum(parsed.slice()[0].version));
}

test "parseList rejects more than max_scts entries" {
    // Arrange: build max_scts + 1 minimal SCTs.
    const log_id = [_]u8{0x00} ** log_id_len;
    const signature = [_]u8{0x00};
    var bodies_storage: [max_scts + 1][128]u8 = undefined;
    var bodies: [max_scts + 1][]const u8 = undefined;
    for (0..max_scts + 1) |i| {
        bodies[i] = buildOneSctBody(&bodies_storage[i], log_id, @intCast(i), &.{}, &signature);
    }
    var list_buf: [2048]u8 = undefined;
    const list_bytes = buildList(&list_buf, &bodies);

    // Act / Assert
    try testing.expectError(error.TooManySct, parseList(list_bytes));
}

test "buildSignedData frames an x509 entry as CertificateTimestamp" {
    // Arrange
    const cert_der = [_]u8{ 0x30, 0x03, 0x02, 0x01, 0x05 };
    var out: [128]u8 = undefined;

    // Act
    const signed = try buildSignedData(&out, .{
        .timestamp = 0x0102_0304_0506_0708,
        .entry_type = .x509_entry,
        .signed_entry = &cert_der,
        .extensions = &.{},
    });

    // Assert: layout is version|sigtype|ts|entry_type|certlen24|cert|extlen16.
    const expected = [_]u8{
        0x00, // version v1
        0x00, // signature_type certificate_timestamp
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // timestamp
        0x00, 0x00, // entry_type x509_entry
        0x00, 0x00, 0x05, // 24-bit cert length
        0x30, 0x03, 0x02, 0x01, 0x05, // cert DER
        0x00, 0x00, // extensions length 0
    };
    try testing.expectEqualSlices(u8, &expected, signed);
}

test "buildSignedData includes non-empty extensions" {
    // Arrange
    const cert_der = [_]u8{0x42};
    const extensions = [_]u8{ 0xaa, 0xbb };
    var out: [64]u8 = undefined;

    // Act
    const signed = try buildSignedData(&out, .{
        .timestamp = 0,
        .entry_type = .x509_entry,
        .signed_entry = &cert_der,
        .extensions = &extensions,
    });

    // Assert: last four bytes are extlen(0x0002) || extensions.
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x02, 0xaa, 0xbb }, signed[signed.len - 4 ..]);
}

test "buildSignedData writes a precert entry verbatim" {
    // Arrange: precert signed_entry is issuer_key_hash[32] || tbs<1..2^24-1>.
    const issuer_key_hash = [_]u8{0x33} ** log_id_len;
    const tbs = [_]u8{ 0x30, 0x01, 0x00 };
    var entry_buf: [64]u8 = undefined;
    const entry = try buildPrecertEntry(&entry_buf, issuer_key_hash, &tbs);

    var out: [128]u8 = undefined;

    // Act
    const signed = try buildSignedData(&out, .{
        .timestamp = 7,
        .entry_type = .precert_entry,
        .signed_entry = entry,
        .extensions = &.{},
    });

    // Assert: entry_type is precert(0x0001) and the entry follows un-prefixed.
    try testing.expectEqual(@as(u16, 0x0001), readU16(signed[10..12]));
    try testing.expectEqualSlices(u8, entry, signed[12 .. 12 + entry.len]);
    // entry itself: 32-byte hash, then 24-bit tbs length, then tbs.
    try testing.expectEqualSlices(u8, &issuer_key_hash, entry[0..log_id_len]);
    try testing.expectEqual(@as(u24, tbs.len), std.mem.readInt(u24, entry[log_id_len..][0..3], .big));
    try testing.expectEqualSlices(u8, &tbs, entry[log_id_len + 3 ..]);
}

test "buildSignedData reports NoSpaceLeft when out is too small" {
    // Arrange
    const cert_der = [_]u8{ 0x01, 0x02, 0x03 };
    var tiny: [8]u8 = undefined;

    // Act / Assert
    try testing.expectError(error.NoSpaceLeft, buildSignedData(&tiny, .{
        .timestamp = 0,
        .entry_type = .x509_entry,
        .signed_entry = &cert_der,
        .extensions = &.{},
    }));
}

test "buildSignedData output round-trips the parsed SCT timestamp" {
    // Arrange: parse an SCT, then rebuild signed data using its timestamp.
    const log_id = [_]u8{0x5a} ** log_id_len;
    const ts: u64 = 0x0000_018f_aa00_1234;
    const signature = [_]u8{ 0x30, 0x02, 0x05, 0x00 };
    var body_buf: [256]u8 = undefined;
    const body = buildOneSctBody(&body_buf, log_id, ts, &.{}, &signature);
    var list_buf: [512]u8 = undefined;
    const list_bytes = buildList(&list_buf, &.{body});
    const parsed = try parseList(list_bytes);
    const sct = parsed.slice()[0];

    const cert_der = [_]u8{0x99};
    var out: [64]u8 = undefined;

    // Act
    const signed = try buildSignedData(&out, .{
        .version = sct.version,
        .timestamp = sct.timestamp,
        .entry_type = .x509_entry,
        .signed_entry = &cert_der,
        .extensions = sct.extensions,
    });

    // Assert: the timestamp field (bytes 2..10) equals the parsed timestamp.
    try testing.expectEqual(ts, std.mem.readInt(u64, signed[2..10], .big));
}

test "buildPrecertEntry reports NoSpaceLeft when out is too small" {
    // Arrange
    const issuer_key_hash = [_]u8{0x00} ** log_id_len;
    const tbs = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    var tiny: [16]u8 = undefined; // needs 32 + 3 + 4

    // Act / Assert
    try testing.expectError(error.NoSpaceLeft, buildPrecertEntry(&tiny, issuer_key_hash, &tbs));
}

test {
    std.testing.refAllDecls(@This());
}

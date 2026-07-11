// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! WebAuthn (FIDO2) assertion verification — server-side verify of a
//! navigator.credentials.get() response for passkey login.
//!
//! Supports ES256 (P-256 / ECDSA-SHA256) and EdDSA (Ed25519) credential
//! public keys encoded as COSE_Key maps.  Includes a minimal CBOR decoder
//! sufficient to parse the COSE_Key structure; no external dependencies.

const std = @import("std");
const crypto = std.crypto;
const Sha256 = crypto.hash.sha2.Sha256;
const Ed25519 = crypto.sign.Ed25519;
const EcdsaP256Sha256 = crypto.sign.ecdsa.EcdsaP256Sha256;
const mem = std.mem;

// -- Public error sets -------------------------------------------------------

pub const CborError = error{
    Overflow,
    InvalidEncoding,
    UnexpectedType,
    MapKeyNotFound,
};

pub const AuthDataError = error{
    TooShort,
    RpIdHashMismatch,
    UserPresenceRequired,
    UserVerificationRequired,
    CounterRegression,
    InvalidCredentialData,
};

pub const CoseError = error{
    UnsupportedAlgorithm,
    MissingField,
    InvalidKeyType,
    InvalidCurve,
    InvalidKeyLength,
};

pub const AssertionError = AuthDataError || CoseError || CborError ||
    crypto.errors.SignatureVerificationError ||
    crypto.errors.EncodingError ||
    crypto.errors.NonCanonicalError ||
    crypto.errors.IdentityElementError ||
    crypto.errors.WeakPublicKeyError;

// -- COSE algorithm identifiers (RFC 8152) -----------------------------------

pub const COSE_ALG_ES256: i64 = -7; // ECDSA w/ SHA-256, P-256
pub const COSE_ALG_EDDSA: i64 = -8; // EdDSA (Ed25519)

const COSE_KTY_EC2: i64 = 2;
const COSE_KTY_OKP: i64 = 1;
const COSE_CURVE_P256: i64 = 1;
const COSE_CURVE_ED25519: i64 = 6;

// -- Minimal CBOR decoder (major-type subset needed for COSE_Key) ------------

/// A lightweight CBOR value that covers the types present in a COSE_Key map.
const CborVal = union(enum) {
    uint: u64,
    nint: i64, // negative integer: encoded as -1 - n
    bstr: []const u8,
    map_start: u64, // number of key/value pairs (definite-length only)
};

const CborCursor = struct {
    data: []const u8,
    pos: usize,

    fn init(data: []const u8) CborCursor {
        return .{ .data = data, .pos = 0 };
    }

    fn remaining(self: CborCursor) []const u8 {
        return self.data[self.pos..];
    }

    fn readByte(self: *CborCursor) CborError!u8 {
        if (self.pos >= self.data.len) return error.InvalidEncoding;
        const b = self.data[self.pos];
        self.pos += 1;
        return b;
    }

    /// Decode the additional-info argument (1/2/4/8 bytes or inline 0-23).
    fn readArgument(self: *CborCursor, add_info: u8) CborError!u64 {
        return switch (add_info) {
            0...23 => add_info,
            24 => @as(u64, try self.readByte()),
            25 => blk: {
                if (self.pos + 2 > self.data.len) return error.InvalidEncoding;
                const v = mem.readInt(u16, self.data[self.pos..][0..2], .big);
                self.pos += 2;
                break :blk v;
            },
            26 => blk: {
                if (self.pos + 4 > self.data.len) return error.InvalidEncoding;
                const v = mem.readInt(u32, self.data[self.pos..][0..4], .big);
                self.pos += 4;
                break :blk v;
            },
            27 => blk: {
                if (self.pos + 8 > self.data.len) return error.InvalidEncoding;
                const v = mem.readInt(u64, self.data[self.pos..][0..8], .big);
                self.pos += 8;
                break :blk v;
            },
            else => error.InvalidEncoding,
        };
    }

    /// Peek at the next CBOR item without advancing position.
    fn peek(self: *CborCursor) CborError!CborVal {
        const saved = self.pos;
        const result = try self.next();
        self.pos = saved;
        return result;
    }

    /// Advance past the next CBOR item (used to skip values).
    fn skip(self: *CborCursor) CborError!void {
        return self.skipDepth(0);
    }

    fn skipDepth(self: *CborCursor, depth: u32) CborError!void {
        if (depth >= 32) return error.InvalidEncoding; // bound recursion
        const ib = try self.readByte();
        const major = ib >> 5;
        const add = ib & 0x1f;
        const arg = try self.readArgument(add);
        switch (major) {
            0, 1 => {}, // uint / nint — no extra bytes
            2, 3 => { // bstr / tstr — arg bytes follow
                const len: usize = std.math.cast(usize, arg) orelse return error.Overflow;
                if (len > self.data.len - self.pos) return error.InvalidEncoding;
                self.pos += len;
            },
            4 => { // array — skip arg items
                var i: u64 = 0;
                while (i < arg) : (i += 1) try self.skipDepth(depth + 1);
            },
            5 => { // map — skip arg key/value pairs (two items each). Iterate the
                // pair count directly (never `2 * arg`, which overflows for a
                // hostile `arg` up to u64 max); each inner skip reads ≥1 byte, so
                // a bogus `arg` runs out of input and returns InvalidEncoding.
                var i: u64 = 0;
                while (i < arg) : (i += 1) {
                    try self.skipDepth(depth + 1); // key
                    try self.skipDepth(depth + 1); // value
                }
            },
            6 => try self.skipDepth(depth + 1), // tag — skip the tagged item
            else => return error.InvalidEncoding,
        }
    }

    /// Decode the next CBOR item.  Only the types needed for COSE_Key are
    /// decoded to a CborVal; other types return InvalidEncoding.
    fn next(self: *CborCursor) CborError!CborVal {
        const ib = try self.readByte();
        const major = ib >> 5;
        const add = ib & 0x1f;
        const arg = try self.readArgument(add);
        switch (major) {
            0 => return CborVal{ .uint = arg },
            1 => {
                // negative integer: value is -1 - arg
                const n = std.math.cast(i64, arg) orelse return error.Overflow;
                return CborVal{ .nint = -1 - n };
            },
            2 => {
                const len: usize = std.math.cast(usize, arg) orelse return error.Overflow;
                // Bounds-check without addition to avoid usize overflow.
                if (len > self.data.len - self.pos) return error.InvalidEncoding;
                const slice = self.data[self.pos .. self.pos + len];
                self.pos += len;
                return CborVal{ .bstr = slice };
            },
            5 => return CborVal{ .map_start = arg },
            else => return error.UnexpectedType,
        }
    }

    /// Read the next value as an integer (uint or nint).
    fn nextInt(self: *CborCursor) CborError!i64 {
        const v = try self.next();
        return switch (v) {
            .uint => |u| std.math.cast(i64, u) orelse error.Overflow,
            .nint => |n| n,
            else => error.UnexpectedType,
        };
    }

    /// Read the next value as a byte string.
    fn nextBytes(self: *CborCursor) CborError![]const u8 {
        const v = try self.next();
        return switch (v) {
            .bstr => |b| b,
            else => error.UnexpectedType,
        };
    }

    /// Read the next item as a CBOR text string (major type 3), returning the
    /// bytes (borrowing `data`). Used for the string keys of the top-level
    /// attestationObject map and the `attStmt` map. `next()` deliberately does
    /// not decode text strings, so this is a dedicated reader.
    fn nextTextString(self: *CborCursor) CborError![]const u8 {
        const ib = try self.readByte();
        if (ib >> 5 != 3) return error.UnexpectedType;
        const arg = try self.readArgument(ib & 0x1f);
        const len: usize = std.math.cast(usize, arg) orelse return error.Overflow;
        if (len > self.data.len - self.pos) return error.InvalidEncoding;
        const slice = self.data[self.pos .. self.pos + len];
        self.pos += len;
        return slice;
    }

    /// Read the next item as a CBOR array header (major type 4), returning the
    /// element count. The elements themselves are consumed by the caller.
    fn nextArrayLen(self: *CborCursor) CborError!u64 {
        const ib = try self.readByte();
        if (ib >> 5 != 4) return error.UnexpectedType;
        return self.readArgument(ib & 0x1f);
    }
};

/// Look up a COSE map key (integer) in a CBOR map and return the value bytes.
/// The cursor must be positioned at the start of the CBOR map header byte.
fn coseMapGetBytes(data: []const u8, key: i64) CborError![]const u8 {
    var cur = CborCursor.init(data);
    const v = try cur.next();
    const pairs = switch (v) {
        .map_start => |n| n,
        else => return error.UnexpectedType,
    };
    var i: u64 = 0;
    while (i < pairs) : (i += 1) {
        const k = try cur.nextInt();
        if (k == key) {
            return cur.nextBytes();
        }
        try cur.skip(); // skip value
    }
    return error.MapKeyNotFound;
}

/// Look up a COSE map key (integer) and return the integer value.
fn coseMapGetInt(data: []const u8, key: i64) CborError!i64 {
    var cur = CborCursor.init(data);
    const v = try cur.next();
    const pairs = switch (v) {
        .map_start => |n| n,
        else => return error.UnexpectedType,
    };
    var i: u64 = 0;
    while (i < pairs) : (i += 1) {
        const k = try cur.nextInt();
        if (k == key) {
            return cur.nextInt();
        }
        try cur.skip(); // skip value
    }
    return error.MapKeyNotFound;
}

// -- COSE_Key parsing --------------------------------------------------------

/// A parsed public key, ready for signature verification.
pub const CosePublicKey = union(enum) {
    es256: EcdsaP256Sha256.PublicKey,
    eddsa: Ed25519.PublicKey,
};

/// Parse a COSE_Key CBOR map and return a CosePublicKey.
///
/// Supports:
///   - kty=2 (EC2), alg=-7 (ES256), crv=1 (P-256): uncompressed x+y
///   - kty=1 (OKP), alg=-8 (EdDSA), crv=6 (Ed25519): x coordinate only
pub fn parseCoseKey(cbor: []const u8) (CoseError || CborError)!CosePublicKey {
    const kty = coseMapGetInt(cbor, 1) catch return error.MissingField;
    const alg = coseMapGetInt(cbor, 3) catch return error.MissingField;

    if (kty == COSE_KTY_EC2 and alg == COSE_ALG_ES256) {
        const crv = coseMapGetInt(cbor, -1) catch return error.MissingField;
        if (crv != COSE_CURVE_P256) return error.InvalidCurve;
        const x = coseMapGetBytes(cbor, -2) catch return error.MissingField;
        const y = coseMapGetBytes(cbor, -3) catch return error.MissingField;
        if (x.len != 32 or y.len != 32) return error.InvalidKeyLength;
        // Build uncompressed SEC-1 point: 0x04 || x || y
        var sec1: [65]u8 = undefined;
        sec1[0] = 0x04;
        @memcpy(sec1[1..33], x);
        @memcpy(sec1[33..65], y);
        const pk = EcdsaP256Sha256.PublicKey.fromSec1(&sec1) catch return error.InvalidKeyLength;
        return CosePublicKey{ .es256 = pk };
    } else if (kty == COSE_KTY_OKP and alg == COSE_ALG_EDDSA) {
        const crv = coseMapGetInt(cbor, -1) catch return error.MissingField;
        if (crv != COSE_CURVE_ED25519) return error.InvalidCurve;
        const x = coseMapGetBytes(cbor, -2) catch return error.MissingField;
        if (x.len != 32) return error.InvalidKeyLength;
        const pk = Ed25519.PublicKey.fromBytes(x[0..32].*) catch return error.InvalidKeyLength;
        return CosePublicKey{ .eddsa = pk };
    }

    return error.UnsupportedAlgorithm;
}

// -- authenticatorData parsing -----------------------------------------------

/// Flags byte bit positions (WebAuthn spec §6.1)
const FLAG_UP: u8 = 1 << 0; // User Presence
const FLAG_UV: u8 = 1 << 2; // User Verification
const FLAG_AT: u8 = 1 << 6; // Attested Credential Data present
const FLAG_ED: u8 = 1 << 7; // Extension Data present

pub const AuthData = struct {
    rp_id_hash: [32]u8,
    flags: u8,
    sign_count: u32,
    /// Raw remainder of authData after the first 37 bytes (may be empty).
    attested_credential_data: []const u8,
};

/// Parse the fixed header of an authenticatorData buffer.
/// Caller supplies the raw authData bytes (not base64-encoded).
pub fn parseAuthData(auth_data: []const u8) AuthDataError!AuthData {
    if (auth_data.len < 37) return error.TooShort;
    const rp_id_hash = auth_data[0..32].*;
    const flags = auth_data[32];
    const sign_count = mem.readInt(u32, auth_data[33..37], .big);
    return AuthData{
        .rp_id_hash = rp_id_hash,
        .flags = flags,
        .sign_count = sign_count,
        .attested_credential_data = auth_data[37..],
    };
}

/// Whether an authenticatorData buffer carries attested credential data (AT
/// flag, set only on a registration/`navigator.credentials.create` response).
pub fn hasAttestedCredentialData(auth_data: []const u8) bool {
    if (auth_data.len < 37) return false;
    return (auth_data[32] & FLAG_AT) != 0;
}

/// Whether parsed authData asserts User Presence (UP).
pub fn userPresent(ad: AuthData) bool {
    return ad.flags & FLAG_UP != 0;
}

/// Whether parsed authData asserts User Verification (UV).
pub fn userVerified(ad: AuthData) bool {
    return ad.flags & FLAG_UV != 0;
}

/// Attested credential data extracted from a registration authenticatorData.
/// `credential_id` and `cose_public_key` borrow `auth_data` (no copy); the
/// COSE key is bounded to its exact CBOR extent so any trailing extension map
/// (ED flag) is excluded.
pub const AttestedCredential = struct {
    aaguid: [16]u8,
    credential_id: []const u8,
    cose_public_key: []const u8,
};

/// Parse the attestedCredentialData region of a registration authenticatorData.
///
/// Layout after the 37-byte header (WebAuthn §6.5.1):
///   aaguid (16) | credentialIdLength (2, big-endian) | credentialId (L) |
///   credentialPublicKey (COSE_Key CBOR map) [| extensions (CBOR map)]
///
/// Fail-closed: every length is bounds-checked before use, and the COSE key
/// extent is derived by a bounded CBOR skip (rejecting a malformed map) rather
/// than by trusting the remainder length. Returns `InvalidCredentialData` when
/// the AT flag is unset or any field would overrun the buffer.
pub fn parseAttestedCredentialData(auth_data: []const u8) (AuthDataError || CborError)!AttestedCredential {
    const ad = try parseAuthData(auth_data);
    if (ad.flags & FLAG_AT == 0) return error.InvalidCredentialData;
    const rest = ad.attested_credential_data;
    if (rest.len < 18) return error.InvalidCredentialData; // aaguid(16) + idLen(2)
    var aaguid: [16]u8 = undefined;
    @memcpy(&aaguid, rest[0..16]);
    const id_len: usize = mem.readInt(u16, rest[16..18], .big);
    const id_start: usize = 18;
    const id_end = id_start + id_len;
    if (id_end > rest.len) return error.InvalidCredentialData;
    const credential_id = rest[id_start..id_end];

    // Bound the COSE public key to its exact CBOR extent so trailing extension
    // data (when the ED flag is set) is not folded into the stored key.
    const key_region = rest[id_end..];
    var cur = CborCursor.init(key_region);
    // The first item must be a map (the COSE_Key); skip validates + measures it.
    const head = cur.peek() catch return error.InvalidCredentialData;
    switch (head) {
        .map_start => {},
        else => return error.InvalidCredentialData,
    }
    cur.skip() catch return error.InvalidCredentialData;
    const cose_public_key = key_region[0..cur.pos];
    return .{ .aaguid = aaguid, .credential_id = credential_id, .cose_public_key = cose_public_key };
}

// -- Registration attestation ------------------------------------------------

const x509 = @import("x509.zig");

/// Errors specific to attestation-statement verification (registration). Folds
/// in the CBOR / authData / COSE / signature error sets so a caller can map one
/// union to a FAIL code.
pub const AttestationError = error{
    /// The attestation `fmt` is not one this build verifies (none/packed/fido-u2f).
    UnsupportedFormat,
    /// The attStmt map is structurally wrong (missing/oversized/garbled).
    MalformedAttestation,
    /// `fmt` is "none" but the policy requires a real attestation statement.
    AttestationRequired,
    /// A required attStmt field (alg/sig/x5c) is absent.
    MissingAttestationField,
    /// The attStmt `alg` does not match the key used to sign (credential key for
    /// self-attestation, or the leaf cert key for basic/AttCA).
    AttestationAlgMismatch,
    /// The x5c leaf certificate uses a key family we cannot verify against.
    UnsupportedAttestationKey,
} || CborError || AuthDataError || CoseError ||
    crypto.errors.SignatureVerificationError ||
    crypto.errors.EncodingError ||
    crypto.errors.NonCanonicalError ||
    crypto.errors.IdentityElementError ||
    crypto.errors.WeakPublicKeyError;

/// Supported attestation statement formats (WebAuthn §8).
pub const AttestationFormat = enum { none, @"packed", fido_u2f };

fn attestationFormat(fmt: []const u8) ?AttestationFormat {
    if (mem.eql(u8, fmt, "none")) return .none;
    if (mem.eql(u8, fmt, "packed")) return .@"packed";
    if (mem.eql(u8, fmt, "fido-u2f")) return .fido_u2f;
    return null;
}

/// The three top-level members of an attestationObject (WebAuthn §6.5). All
/// slices borrow the source CBOR; `att_stmt` is the exact CBOR extent of the
/// attStmt map (header included) so it can be re-walked.
pub const AttestationObject = struct {
    fmt: []const u8,
    att_stmt: []const u8,
    auth_data: []const u8,
};

/// Parse the CBOR `attestationObject` = {"fmt": tstr, "attStmt": map,
/// "authData": bstr}. Member order is not fixed by CBOR, so each key is matched
/// by name. Fail-closed: a missing member is `MapKeyNotFound`; any structural
/// defect is a `CborError`. Never panics on hostile bytes.
pub fn parseAttestationObject(cbor: []const u8) CborError!AttestationObject {
    var cur = CborCursor.init(cbor);
    const head = try cur.next();
    const pairs = switch (head) {
        .map_start => |n| n,
        else => return error.UnexpectedType,
    };
    var fmt: ?[]const u8 = null;
    var att_stmt: ?[]const u8 = null;
    var auth_data: ?[]const u8 = null;
    var i: u64 = 0;
    while (i < pairs) : (i += 1) {
        const key = try cur.nextTextString();
        if (mem.eql(u8, key, "fmt")) {
            fmt = try cur.nextTextString();
        } else if (mem.eql(u8, key, "authData")) {
            auth_data = try cur.nextBytes();
        } else if (mem.eql(u8, key, "attStmt")) {
            const start = cur.pos;
            try cur.skip(); // validate + measure the attStmt map extent
            att_stmt = cbor[start..cur.pos];
        } else {
            try cur.skip(); // ignore unknown members
        }
    }
    return .{
        .fmt = fmt orelse return error.MapKeyNotFound,
        .att_stmt = att_stmt orelse return error.MapKeyNotFound,
        .auth_data = auth_data orelse return error.MapKeyNotFound,
    };
}

/// The decoded fields of a `packed`/`fido-u2f` attStmt map. `pair_count` lets
/// the `none` branch assert an empty map.
const AttStmt = struct {
    alg: ?i64 = null,
    sig: ?[]const u8 = null,
    /// The first (leaf) certificate of the x5c array, if present.
    x5c_leaf: ?[]const u8 = null,
    x5c_present: bool = false,
    pair_count: u64 = 0,
};

fn parseAttStmt(att_stmt: []const u8) CborError!AttStmt {
    var cur = CborCursor.init(att_stmt);
    const head = try cur.next();
    const pairs = switch (head) {
        .map_start => |n| n,
        else => return error.UnexpectedType,
    };
    var out = AttStmt{ .pair_count = pairs };
    var i: u64 = 0;
    while (i < pairs) : (i += 1) {
        const key = try cur.nextTextString();
        if (mem.eql(u8, key, "alg")) {
            out.alg = try cur.nextInt();
        } else if (mem.eql(u8, key, "sig")) {
            out.sig = try cur.nextBytes();
        } else if (mem.eql(u8, key, "x5c")) {
            out.x5c_present = true;
            const n = try cur.nextArrayLen();
            if (n != 0) {
                out.x5c_leaf = try cur.nextBytes(); // leaf attestation cert
                var j: u64 = 1;
                while (j < n) : (j += 1) try cur.skip(); // skip chain remainder
            }
        } else {
            try cur.skip();
        }
    }
    return out;
}

/// Verify an ECDSA-P256 or Ed25519 signature over (`msg1` || `msg2`) with a
/// COSE credential public key, requiring `alg` to name that key family.
fn verifyCoseSig(
    cose_key: CosePublicKey,
    alg: i64,
    signature: []const u8,
    msg1: []const u8,
    msg2: []const u8,
) AttestationError!void {
    switch (cose_key) {
        .es256 => |pk| {
            if (alg != COSE_ALG_ES256) return error.AttestationAlgMismatch;
            const sig = EcdsaP256Sha256.Signature.fromDer(signature) catch
                return error.InvalidEncoding;
            var vrf = sig.verifier(pk) catch |e| return e;
            vrf.update(msg1);
            vrf.update(msg2);
            try vrf.verify();
        },
        .eddsa => |pk| {
            if (alg != COSE_ALG_EDDSA) return error.AttestationAlgMismatch;
            if (signature.len != Ed25519.Signature.encoded_length) return error.InvalidEncoding;
            const sig = Ed25519.Signature.fromBytes(signature[0..Ed25519.Signature.encoded_length].*);
            var vrf = sig.verifier(pk) catch |e| return e;
            vrf.update(msg1);
            vrf.update(msg2);
            try vrf.verify();
        },
    }
}

/// Extract the P-256 / Ed25519 public key from an x5c leaf certificate. RSA and
/// every other family fail closed as `UnsupportedAttestationKey` (this build
/// verifies ECDSA-P256 and Ed25519 attestation certs only).
fn leafCertKey(leaf_der: []const u8) AttestationError!CosePublicKey {
    const cert = x509.parse(leaf_der) catch return error.MalformedAttestation;
    const spk = x509.extractPublicKey(cert.spki_der) catch return error.UnsupportedAttestationKey;
    return switch (spk) {
        .ecdsa_p256 => |sec1| .{ .es256 = EcdsaP256Sha256.PublicKey.fromSec1(sec1) catch
            return error.UnsupportedAttestationKey },
        .ed25519 => |raw| blk: {
            if (raw.len != 32) return error.UnsupportedAttestationKey;
            break :blk .{ .eddsa = Ed25519.PublicKey.fromBytes(raw[0..32].*) catch
                return error.UnsupportedAttestationKey };
        },
        .rsa => error.UnsupportedAttestationKey,
    };
}

/// Verify a `packed` attStmt (WebAuthn §8.2). Self-attestation (no x5c) checks
/// the signature over (authData || clientDataHash) with the credential key and
/// requires alg == the credential key's algorithm. Basic/AttCA (x5c present)
/// verifies the same signed data against the leaf attestation certificate's key.
///
/// NOTE: basic attestation additionally requires anchoring the x5c chain to a
/// trusted attestation root and matching the AAGUID — this build does NOT run a
/// chain-to-root check (no bundled FIDO metadata trust store). The attestation
/// signature is cryptographically verified against the presented leaf, which is
/// tamper-evident, but the leaf is not proven to be a genuine authenticator
/// root. Callers wanting hard attestation guarantees must add a trust store.
fn verifyPacked(
    att_stmt: []const u8,
    auth_data: []const u8,
    client_data_hash: [32]u8,
    cose_key: CosePublicKey,
) AttestationError!void {
    const st = try parseAttStmt(att_stmt);
    const alg = st.alg orelse return error.MissingAttestationField;
    const sig = st.sig orelse return error.MissingAttestationField;
    if (st.x5c_present) {
        const leaf = st.x5c_leaf orelse return error.MalformedAttestation;
        const leaf_key = try leafCertKey(leaf);
        try verifyCoseSig(leaf_key, alg, sig, auth_data, &client_data_hash);
    } else {
        try verifyCoseSig(cose_key, alg, sig, auth_data, &client_data_hash);
    }
}

/// Verify a `fido-u2f` attStmt (WebAuthn §8.6). verificationData =
/// 0x00 || rpIdHash || clientDataHash || credentialId || (0x04||x||y); the
/// signature is ECDSA-SHA256 over it with the x5c leaf cert (which MUST be
/// P-256). The credential key MUST be EC2 P-256 (U2F predates other curves).
fn verifyFidoU2f(
    att_stmt: []const u8,
    rp_id_hash: [32]u8,
    client_data_hash: [32]u8,
    cred: AttestedCredential,
) AttestationError!void {
    const st = try parseAttStmt(att_stmt);
    const sig = st.sig orelse return error.MissingAttestationField;
    const leaf = st.x5c_leaf orelse return error.MissingAttestationField;

    // U2F authenticators have no AAGUID: a conformant fido-u2f authData carries
    // an all-zero AAGUID (WebAuthn §8.6). Reject a non-zero one fail-closed.
    for (cred.aaguid) |b| {
        if (b != 0) return error.MalformedAttestation;
    }

    const cose_key = try parseCoseKey(cred.cose_public_key);
    const pub_u2f: [65]u8 = switch (cose_key) {
        .es256 => |pk| pk.toUncompressedSec1(),
        else => return error.AttestationAlgMismatch,
    };

    const leaf_key = try leafCertKey(leaf);
    const leaf_pk = switch (leaf_key) {
        .es256 => |pk| pk, // U2F attestation certs are P-256
        else => return error.UnsupportedAttestationKey,
    };
    const s = EcdsaP256Sha256.Signature.fromDer(sig) catch return error.InvalidEncoding;
    var vrf = s.verifier(leaf_pk) catch |e| return e;
    const zero = [_]u8{0x00};
    vrf.update(&zero);
    vrf.update(&rp_id_hash);
    vrf.update(&client_data_hash);
    vrf.update(cred.credential_id);
    vrf.update(&pub_u2f);
    try vrf.verify();
}

/// Options controlling registration attestation verification.
pub const AttestationOptions = struct {
    /// Relying-party id; the authData rpIdHash must equal SHA-256(rp_id).
    rp_id: []const u8,
    /// SHA-256(clientDataJSON) — bound into the attestation signature.
    client_data_hash: [32]u8,
    /// Require the UV flag in authData (opt-in).
    require_uv: bool,
    /// Reject `fmt == "none"` (require a real, verified attestation statement).
    require_attestation: bool,
};

/// The result of a successful attestation verification. Slices borrow the
/// attestationObject CBOR passed to `verifyAttestation`.
pub const VerifiedAttestation = struct {
    format: AttestationFormat,
    /// false only for `none` (unattested / trust-on-first-use).
    attested: bool,
    /// The attested credential (aaguid, credentialId, COSE key) from authData.
    credential: AttestedCredential,
    /// The registration authenticator signature counter (seeds the store).
    sign_count: u32,
};

/// Verify a registration `attestationObject` (navigator.credentials.create).
///
/// Binds rpIdHash, UP (always) and UV (when `require_uv`), then verifies the
/// attestation statement for its format:
///   - `none`      → accepted as unattested (TOFU) unless `require_attestation`;
///                   the attStmt MUST be an empty map.
///   - `packed`    → self-attestation (credential key) or basic (x5c leaf key).
///   - `fido-u2f`  → U2F verificationData signed by the x5c leaf (P-256).
///
/// Fail-closed on a present-but-invalid attestation. Never panics on hostile
/// CBOR/attestation bytes.
pub fn verifyAttestation(
    attestation_object: []const u8,
    opts: AttestationOptions,
) AttestationError!VerifiedAttestation {
    const obj = try parseAttestationObject(attestation_object);
    const ad = try parseAuthData(obj.auth_data);

    // rpIdHash == SHA-256(rp_id)
    var expected_hash: [32]u8 = undefined;
    Sha256.hash(opts.rp_id, &expected_hash, .{});
    if (!mem.eql(u8, &ad.rp_id_hash, &expected_hash)) return error.RpIdHashMismatch;

    // Presence is always required; verification is opt-in.
    if (ad.flags & FLAG_UP == 0) return error.UserPresenceRequired;
    if (opts.require_uv and (ad.flags & FLAG_UV == 0)) return error.UserVerificationRequired;
    if (ad.flags & FLAG_AT == 0) return error.InvalidCredentialData;

    const cred = try parseAttestedCredentialData(obj.auth_data);
    // Ensure the COSE key is one we can store + verify later.
    const cose_key = try parseCoseKey(cred.cose_public_key);

    const fmt = attestationFormat(obj.fmt) orelse return error.UnsupportedFormat;
    var attested = false;
    switch (fmt) {
        .none => {
            if (opts.require_attestation) return error.AttestationRequired;
            // A `none` attStmt MUST be an empty map (WebAuthn §8.7); a stuffed
            // map is malformed.
            const st = try parseAttStmt(obj.att_stmt);
            if (st.pair_count != 0) return error.MalformedAttestation;
        },
        .@"packed" => {
            try verifyPacked(obj.att_stmt, obj.auth_data, opts.client_data_hash, cose_key);
            attested = true;
        },
        .fido_u2f => {
            try verifyFidoU2f(obj.att_stmt, ad.rp_id_hash, opts.client_data_hash, cred);
            attested = true;
        },
    }

    return .{
        .format = fmt,
        .attested = attested,
        .credential = cred,
        .sign_count = ad.sign_count,
    };
}

// -- Assertion options / state -----------------------------------------------

/// Options controlling the assertion check.
pub const AssertionOptions = struct {
    /// The relying-party identifier (e.g. "example.com").
    rp_id: []const u8,
    /// The expected COSE public key (parsed with parseCoseKey).
    credential_public_key: CosePublicKey,
    /// The last known signature counter for this credential.
    /// Pass 0 if unknown (first authentication).
    stored_sign_count: u32,
    /// Whether to require the UV flag in addition to UP.
    require_uv: bool,
};

// -- Core assertion verification ---------------------------------------------

/// Verify a WebAuthn assertion (navigator.credentials.get response).
///
/// - auth_data:        raw authenticatorData bytes
/// - client_data_json: raw clientDataJSON bytes (UTF-8)
/// - signature:        DER-encoded signature (ES256) or 64-byte raw (EdDSA)
/// - opts:             see AssertionOptions
///
/// Returns the new signature counter on success (caller should persist it).
///
/// Errors on any validation failure.
pub fn verifyAssertion(
    auth_data: []const u8,
    client_data_json: []const u8,
    signature: []const u8,
    opts: AssertionOptions,
) AssertionError!u32 {
    // 1. Parse authenticatorData
    const ad = try parseAuthData(auth_data);

    // 2. Verify rpIdHash == SHA-256(rpId)
    var expected_hash: [32]u8 = undefined;
    Sha256.hash(opts.rp_id, &expected_hash, .{});
    if (!mem.eql(u8, &ad.rp_id_hash, &expected_hash)) {
        return error.RpIdHashMismatch;
    }

    // 3. Require UP flag
    if (ad.flags & FLAG_UP == 0) {
        return error.UserPresenceRequired;
    }

    // 4. Optionally require UV flag (opt-in; UV is a superset of presence).
    if (opts.require_uv and (ad.flags & FLAG_UV == 0)) {
        return error.UserVerificationRequired;
    }

    // 5. Verify signature counter (monotonic, unless both are 0)
    if (ad.sign_count != 0 or opts.stored_sign_count != 0) {
        if (ad.sign_count <= opts.stored_sign_count) {
            return error.CounterRegression;
        }
    }

    // 6. Compute the signed message: authData || SHA-256(clientDataJSON)
    var cdj_hash: [32]u8 = undefined;
    Sha256.hash(client_data_json, &cdj_hash, .{});

    // 7. Verify signature (heap-free: two-part update on the verifier)
    switch (opts.credential_public_key) {
        .es256 => |pk| {
            // DER-encoded ECDSA; hash is applied over (authData || SHA-256(clientDataJSON))
            const sig = EcdsaP256Sha256.Signature.fromDer(signature) catch
                return error.InvalidEncoding;
            var vrf = sig.verifier(pk) catch |e| return e;
            vrf.update(auth_data);
            vrf.update(&cdj_hash);
            try vrf.verify();
        },
        .eddsa => |pk| {
            // 64 raw bytes (R || S, little-endian)
            if (signature.len != Ed25519.Signature.encoded_length) return error.InvalidEncoding;
            const sig = Ed25519.Signature.fromBytes(signature[0..Ed25519.Signature.encoded_length].*);
            var vrf = sig.verifier(pk) catch |e| return e;
            vrf.update(auth_data);
            vrf.update(&cdj_hash);
            try vrf.verify();
        },
    }

    return ad.sign_count;
}

// -- Tests -------------------------------------------------------------------

const testing = std.testing;

// Helper: build a minimal authenticatorData for tests
// Layout: rpIdHash (32) | flags (1) | signCount (4 big-endian) [| credData...]
fn makeAuthData(rp_id_hash: [32]u8, flags: u8, sign_count: u32) [37]u8 {
    var buf: [37]u8 = undefined;
    buf[0..32].* = rp_id_hash;
    buf[32] = flags;
    mem.writeInt(u32, buf[33..37], sign_count, .big);
    return buf;
}

// Helper: SHA-256 of a string
fn sha256Str(s: []const u8) [32]u8 {
    var h: [32]u8 = undefined;
    Sha256.hash(s, &h, .{});
    return h;
}

// Helper: build a minimal COSE_Key CBOR map for EC2 / ES256
// Map: {1: 2, 3: -7, -1: 1, -2: x(32), -3: y(32)}  — 5 pairs
fn buildCoseEs256(x: [32]u8, y: [32]u8, out: *[77]u8) void {
    var i: usize = 0;
    // map(5)
    out[i] = 0xa5;
    i += 1;
    // 1: 2
    out[i] = 0x01;
    i += 1; // key 1 (uint)
    out[i] = 0x02;
    i += 1; // value 2
    // 3: -7  (nint: major=1, value=6 → -7)
    out[i] = 0x03;
    i += 1; // key 3
    out[i] = 0x26;
    i += 1; // -7 = 0x20 | 6
    // -1: 1  (key -1 = nint 0 = 0x20, value 1 = 0x01)
    out[i] = 0x20;
    i += 1; // -1
    out[i] = 0x01;
    i += 1; // crv P-256
    // -2: x (bstr 32)
    out[i] = 0x21;
    i += 1; // -2
    out[i] = 0x58;
    i += 1;
    out[i] = 0x20;
    i += 1; // bstr(32)
    @memcpy(out[i .. i + 32], &x);
    i += 32;
    // -3: y (bstr 32)
    out[i] = 0x22;
    i += 1; // -3
    out[i] = 0x58;
    i += 1;
    out[i] = 0x20;
    i += 1; // bstr(32)
    @memcpy(out[i .. i + 32], &y);
    i += 32;
    std.debug.assert(i == 77);
}

// Helper: build a minimal COSE_Key CBOR map for OKP / EdDSA
// Map: {1: 1, 3: -8, -1: 6, -2: x(32)}  — 4 pairs
fn buildCoseEdDSA(x: [32]u8, out: *[42]u8) void {
    var i: usize = 0;
    out[i] = 0xa4;
    i += 1; // map(4)
    out[i] = 0x01;
    i += 1;
    out[i] = 0x01;
    i += 1; // 1: 1 (OKP)
    out[i] = 0x03;
    i += 1;
    out[i] = 0x27;
    i += 1; // 3: -8 (EdDSA) = 0x20 | 7
    out[i] = 0x20;
    i += 1;
    out[i] = 0x06;
    i += 1; // -1: 6 (Ed25519 curve)
    out[i] = 0x21;
    i += 1; // -2
    out[i] = 0x58;
    i += 1;
    out[i] = 0x20;
    i += 1; // bstr(32)
    @memcpy(out[i .. i + 32], &x);
    i += 32;
    std.debug.assert(i == 42);
}

test "parseCoseKey: EC2 P-256 roundtrip" {
    // Generate a throw-away P-256 key pair
    const kp = EcdsaP256Sha256.KeyPair.generate(testing.io);
    const sec1 = kp.public_key.toUncompressedSec1(); // 0x04 || x || y
    const x = sec1[1..33].*;
    const y = sec1[33..65].*;

    var cbor: [77]u8 = undefined;
    buildCoseEs256(x, y, &cbor);

    const key = try parseCoseKey(&cbor);
    switch (key) {
        .es256 => |pk| {
            const got = pk.toUncompressedSec1();
            try testing.expectEqualSlices(u8, &sec1, &got);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "parseCoseKey: OKP Ed25519 roundtrip" {
    const kp = Ed25519.KeyPair.generate(testing.io);
    const pk_bytes = kp.public_key.toBytes();

    var cbor: [42]u8 = undefined;
    buildCoseEdDSA(pk_bytes, &cbor);

    const key = try parseCoseKey(&cbor);
    switch (key) {
        .eddsa => |pk| {
            try testing.expectEqualSlices(u8, &pk_bytes, &pk.toBytes());
        },
        else => return error.TestUnexpectedResult,
    }
}

test "verifyAssertion: valid ES256 assertion" {
    const rp_id = "example.com";
    const rp_id_hash = sha256Str(rp_id);
    const auth_data = makeAuthData(rp_id_hash, FLAG_UP | FLAG_UV, 1);
    const client_data_json = "{\"type\":\"webauthn.get\",\"challenge\":\"abc\"}";

    // Build the signed message: authData || SHA-256(clientDataJSON)
    var cdj_hash: [32]u8 = undefined;
    Sha256.hash(client_data_json, &cdj_hash, .{});

    // Generate key pair and sign
    const kp = EcdsaP256Sha256.KeyPair.generate(testing.io);
    var signer = try kp.signer(null);
    signer.update(&auth_data);
    signer.update(&cdj_hash);
    const sig = try signer.finalize();

    // DER-encode signature
    var der_buf: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
    const der = sig.toDer(&der_buf);

    // Build COSE_Key
    const sec1 = kp.public_key.toUncompressedSec1();
    var cose_buf: [77]u8 = undefined;
    buildCoseEs256(sec1[1..33].*, sec1[33..65].*, &cose_buf);
    const cpk = try parseCoseKey(&cose_buf);

    const new_count = try verifyAssertion(&auth_data, client_data_json, der, .{
        .rp_id = rp_id,
        .credential_public_key = cpk,
        .stored_sign_count = 0,
        .require_uv = true,
    });
    try testing.expectEqual(@as(u32, 1), new_count);
}

test "verifyAssertion: valid EdDSA assertion" {
    const rp_id = "example.com";
    const rp_id_hash = sha256Str(rp_id);
    const auth_data = makeAuthData(rp_id_hash, FLAG_UP, 5);
    const client_data_json = "{\"type\":\"webauthn.get\",\"challenge\":\"xyz\"}";

    var cdj_hash: [32]u8 = undefined;
    Sha256.hash(client_data_json, &cdj_hash, .{});

    const kp = Ed25519.KeyPair.generate(testing.io);
    var signer_st = try kp.signer(null, testing.io);
    signer_st.update(&auth_data);
    signer_st.update(&cdj_hash);
    const sig = signer_st.finalize();
    const sig_bytes = sig.toBytes();

    var cose_buf: [42]u8 = undefined;
    buildCoseEdDSA(kp.public_key.toBytes(), &cose_buf);
    const cpk = try parseCoseKey(&cose_buf);

    const new_count = try verifyAssertion(&auth_data, client_data_json, &sig_bytes, .{
        .rp_id = rp_id,
        .credential_public_key = cpk,
        .stored_sign_count = 4,
        .require_uv = false,
    });
    try testing.expectEqual(@as(u32, 5), new_count);
}

test "verifyAssertion: wrong rpIdHash rejected" {
    const rp_id = "example.com";
    const wrong_hash = sha256Str("evil.com");
    const auth_data = makeAuthData(wrong_hash, FLAG_UP, 1);
    const client_data_json = "{}";

    const kp = EcdsaP256Sha256.KeyPair.generate(testing.io);
    const sec1 = kp.public_key.toUncompressedSec1();
    var cose_buf: [77]u8 = undefined;
    buildCoseEs256(sec1[1..33].*, sec1[33..65].*, &cose_buf);
    const cpk = try parseCoseKey(&cose_buf);

    const result = verifyAssertion(&auth_data, client_data_json, &@as([64]u8, @splat(0)), .{
        .rp_id = rp_id,
        .credential_public_key = cpk,
        .stored_sign_count = 0,
        .require_uv = false,
    });
    try testing.expectError(error.RpIdHashMismatch, result);
}

test "verifyAssertion: UP flag absent rejected" {
    const rp_id = "example.com";
    const rp_id_hash = sha256Str(rp_id);
    // flags = 0: no UP
    const auth_data = makeAuthData(rp_id_hash, 0, 1);
    const client_data_json = "{}";

    const kp = EcdsaP256Sha256.KeyPair.generate(testing.io);
    const sec1 = kp.public_key.toUncompressedSec1();
    var cose_buf: [77]u8 = undefined;
    buildCoseEs256(sec1[1..33].*, sec1[33..65].*, &cose_buf);
    const cpk = try parseCoseKey(&cose_buf);

    const result = verifyAssertion(&auth_data, client_data_json, &@as([64]u8, @splat(0)), .{
        .rp_id = rp_id,
        .credential_public_key = cpk,
        .stored_sign_count = 0,
        .require_uv = false,
    });
    try testing.expectError(error.UserPresenceRequired, result);
}

test "verifyAssertion: counter regression rejected" {
    const rp_id = "example.com";
    const rp_id_hash = sha256Str(rp_id);
    // sign_count = 3, stored = 5  → regression
    const auth_data = makeAuthData(rp_id_hash, FLAG_UP, 3);
    const client_data_json = "{}";

    const kp = EcdsaP256Sha256.KeyPair.generate(testing.io);
    const sec1 = kp.public_key.toUncompressedSec1();
    var cose_buf: [77]u8 = undefined;
    buildCoseEs256(sec1[1..33].*, sec1[33..65].*, &cose_buf);
    const cpk = try parseCoseKey(&cose_buf);

    const result = verifyAssertion(&auth_data, client_data_json, &@as([64]u8, @splat(0)), .{
        .rp_id = rp_id,
        .credential_public_key = cpk,
        .stored_sign_count = 5,
        .require_uv = false,
    });
    try testing.expectError(error.CounterRegression, result);
}

test "verifyAssertion: tampered authData signature rejected (ES256)" {
    const rp_id = "example.com";
    const rp_id_hash = sha256Str(rp_id);
    var auth_data = makeAuthData(rp_id_hash, FLAG_UP, 1);
    const client_data_json = "{\"type\":\"webauthn.get\"}";

    var cdj_hash: [32]u8 = undefined;
    Sha256.hash(client_data_json, &cdj_hash, .{});

    const kp = EcdsaP256Sha256.KeyPair.generate(testing.io);
    var signer = try kp.signer(null);
    signer.update(&auth_data);
    signer.update(&cdj_hash);
    const sig = try signer.finalize();

    var der_buf: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
    const der = sig.toDer(&der_buf);

    // Tamper: flip a byte in auth_data after signing
    auth_data[36] ^= 0xff;

    const sec1 = kp.public_key.toUncompressedSec1();
    var cose_buf: [77]u8 = undefined;
    buildCoseEs256(sec1[1..33].*, sec1[33..65].*, &cose_buf);
    const cpk = try parseCoseKey(&cose_buf);

    const result = verifyAssertion(&auth_data, client_data_json, der, .{
        .rp_id = rp_id,
        .credential_public_key = cpk,
        .stored_sign_count = 0,
        .require_uv = false,
    });
    try testing.expectError(error.SignatureVerificationFailed, result);
}

test "verifyAssertion: tampered signature rejected (EdDSA)" {
    const rp_id = "example.com";
    const rp_id_hash = sha256Str(rp_id);
    const auth_data = makeAuthData(rp_id_hash, FLAG_UP, 2);
    const client_data_json = "{\"type\":\"webauthn.get\"}";

    var cdj_hash: [32]u8 = undefined;
    Sha256.hash(client_data_json, &cdj_hash, .{});

    const kp = Ed25519.KeyPair.generate(testing.io);
    var signer_st = try kp.signer(null, testing.io);
    signer_st.update(&auth_data);
    signer_st.update(&cdj_hash);
    const sig = signer_st.finalize();
    var sig_bytes = sig.toBytes();

    // Tamper: flip a byte in the signature
    sig_bytes[10] ^= 0x01;

    var cose_buf: [42]u8 = undefined;
    buildCoseEdDSA(kp.public_key.toBytes(), &cose_buf);
    const cpk = try parseCoseKey(&cose_buf);

    const result = verifyAssertion(&auth_data, client_data_json, &sig_bytes, .{
        .rp_id = rp_id,
        .credential_public_key = cpk,
        .stored_sign_count = 1,
        .require_uv = false,
    });
    // Ed25519 tamper can produce NonCanonical, InvalidEncoding, or SignatureVerificationFailed
    const is_expected = (result == error.SignatureVerificationFailed or
        result == error.NonCanonical or
        result == error.InvalidEncoding);
    try testing.expect(is_expected);
}

test "verifyAssertion: counter equal to stored rejected" {
    const rp_id = "example.com";
    const rp_id_hash = sha256Str(rp_id);
    // sign_count == stored_sign_count (replay)
    const auth_data = makeAuthData(rp_id_hash, FLAG_UP, 7);
    const client_data_json = "{}";

    const kp = EcdsaP256Sha256.KeyPair.generate(testing.io);
    const sec1 = kp.public_key.toUncompressedSec1();
    var cose_buf: [77]u8 = undefined;
    buildCoseEs256(sec1[1..33].*, sec1[33..65].*, &cose_buf);
    const cpk = try parseCoseKey(&cose_buf);

    const result = verifyAssertion(&auth_data, client_data_json, &@as([64]u8, @splat(0)), .{
        .rp_id = rp_id,
        .credential_public_key = cpk,
        .stored_sign_count = 7,
        .require_uv = false,
    });
    try testing.expectError(error.CounterRegression, result);
}

test "verifyAssertion: both counters zero allowed (stateless authenticator)" {
    const rp_id = "example.com";
    const rp_id_hash = sha256Str(rp_id);
    // Both 0 → skip counter check
    const auth_data = makeAuthData(rp_id_hash, FLAG_UP, 0);
    const client_data_json = "{\"challenge\":\"zero\"}";

    var cdj_hash: [32]u8 = undefined;
    Sha256.hash(client_data_json, &cdj_hash, .{});

    const kp = EcdsaP256Sha256.KeyPair.generate(testing.io);
    var signer = try kp.signer(null);
    signer.update(&auth_data);
    signer.update(&cdj_hash);
    const sig = try signer.finalize();
    var der_buf: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
    const der = sig.toDer(&der_buf);

    const sec1 = kp.public_key.toUncompressedSec1();
    var cose_buf: [77]u8 = undefined;
    buildCoseEs256(sec1[1..33].*, sec1[33..65].*, &cose_buf);
    const cpk = try parseCoseKey(&cose_buf);

    const new_count = try verifyAssertion(&auth_data, client_data_json, der, .{
        .rp_id = rp_id,
        .credential_public_key = cpk,
        .stored_sign_count = 0,
        .require_uv = false,
    });
    try testing.expectEqual(@as(u32, 0), new_count);
}

// Build a registration authenticatorData with attested credential data:
//   rpIdHash(32) | flags | signCount(4) | aaguid(16) | credIdLen(2) | credId | COSE(77)
// `out` must be exactly 37 + 16 + 2 + credId.len + 77 bytes.
fn buildRegAuthDataEs256(
    rp_id_hash: [32]u8,
    sign_count: u32,
    aaguid: [16]u8,
    cred_id: []const u8,
    cose77: [77]u8,
    out: []u8,
) usize {
    var i: usize = 0;
    @memcpy(out[0..32], &rp_id_hash);
    i = 32;
    out[i] = FLAG_UP | FLAG_AT; // present + attested credential data
    i += 1;
    mem.writeInt(u32, out[i..][0..4], sign_count, .big);
    i += 4;
    @memcpy(out[i..][0..16], &aaguid);
    i += 16;
    mem.writeInt(u16, out[i..][0..2], @intCast(cred_id.len), .big);
    i += 2;
    @memcpy(out[i..][0..cred_id.len], cred_id);
    i += cred_id.len;
    @memcpy(out[i..][0..77], &cose77);
    i += 77;
    return i;
}

test "parseAttestedCredentialData: extracts credId + exact COSE key (ES256)" {
    const kp = EcdsaP256Sha256.KeyPair.generate(testing.io);
    const sec1 = kp.public_key.toUncompressedSec1();
    var cose: [77]u8 = undefined;
    buildCoseEs256(sec1[1..33].*, sec1[33..65].*, &cose);

    const rp_id_hash = sha256Str("example.com");
    const aaguid: [16]u8 = @splat(0xAB);
    const cred_id = "credential-0001"; // 15 bytes
    var buf: [37 + 16 + 2 + 15 + 77]u8 = undefined;
    const n = buildRegAuthDataEs256(rp_id_hash, 7, aaguid, cred_id, cose, &buf);
    try testing.expectEqual(buf.len, n);

    try testing.expect(hasAttestedCredentialData(buf[0..n]));
    const att = try parseAttestedCredentialData(buf[0..n]);
    try testing.expectEqualSlices(u8, &aaguid, &att.aaguid);
    try testing.expectEqualSlices(u8, cred_id, att.credential_id);
    // The bounded COSE key must be byte-exact and re-parse to the same key.
    try testing.expectEqualSlices(u8, &cose, att.cose_public_key);
    const cpk = try parseCoseKey(att.cose_public_key);
    switch (cpk) {
        .es256 => |pk| try testing.expectEqualSlices(u8, &sec1, &pk.toUncompressedSec1()),
        else => return error.TestUnexpectedResult,
    }
}

test "parseAttestedCredentialData: trailing extension bytes are excluded from the COSE key" {
    const kp = EcdsaP256Sha256.KeyPair.generate(testing.io);
    const sec1 = kp.public_key.toUncompressedSec1();
    var cose: [77]u8 = undefined;
    buildCoseEs256(sec1[1..33].*, sec1[33..65].*, &cose);

    const rp_id_hash = sha256Str("example.com");
    const aaguid: [16]u8 = @splat(0);
    const cred_id = "id";
    var buf: [37 + 16 + 2 + 2 + 77 + 3]u8 = undefined;
    const base = buildRegAuthDataEs256(rp_id_hash, 1, aaguid, cred_id, cose, buf[0 .. buf.len - 3]);
    // Append a 3-byte CBOR extension map {} placeholder-ish tail (a1 00 00).
    buf[base] = 0xa1;
    buf[base + 1] = 0x00;
    buf[base + 2] = 0x00;

    const att = try parseAttestedCredentialData(&buf);
    // COSE key must stop at its own CBOR extent, not swallow the tail.
    try testing.expectEqual(@as(usize, 77), att.cose_public_key.len);
    try testing.expectEqualSlices(u8, &cose, att.cose_public_key);
}

test "parseAttestedCredentialData: AT flag absent rejected" {
    const rp_id_hash = sha256Str("example.com");
    const auth_data = makeAuthData(rp_id_hash, FLAG_UP, 3); // no AT flag
    try testing.expect(!hasAttestedCredentialData(&auth_data));
    try testing.expectError(error.InvalidCredentialData, parseAttestedCredentialData(&auth_data));
}

test "parseAttestedCredentialData: credIdLength overrun rejected" {
    var buf: [37 + 18]u8 = undefined;
    const rp_id_hash = sha256Str("example.com");
    @memcpy(buf[0..32], &rp_id_hash);
    buf[32] = FLAG_UP | FLAG_AT;
    mem.writeInt(u32, buf[33..37], 1, .big);
    @memset(buf[37..53], 0); // aaguid
    mem.writeInt(u16, buf[53..55], 9999, .big); // credIdLen far past end
    try testing.expectError(error.InvalidCredentialData, parseAttestedCredentialData(&buf));
}

test "parseAttestedCredentialData: COSE map with a huge pair count fails closed (no overflow/panic)" {
    // A COSE map header claiming 2^63 pairs (major 5, add-info 27 = 8-byte len)
    // must NOT compute `2 * arg` and overflow — it must run out of input and
    // return InvalidEncoding cleanly. Attacker-reachable via a registration
    // authData, so this must be an error, never a panic (safe builds) or UB wrap.
    const rp_id_hash = sha256Str("example.com");
    const aaguid: [16]u8 = @splat(0);
    var buf: [37 + 16 + 2 + 1 + 9]u8 = undefined;
    @memcpy(buf[0..32], &rp_id_hash);
    buf[32] = FLAG_UP | FLAG_AT;
    mem.writeInt(u32, buf[33..37], 1, .big);
    @memcpy(buf[37..53], &aaguid);
    mem.writeInt(u16, buf[53..55], 1, .big);
    buf[55] = 'x'; // credId
    buf[56] = 0xbb; // map(*) with a 64-bit count
    mem.writeInt(u64, buf[57..65], 0x8000_0000_0000_0000, .big);
    try testing.expectError(error.InvalidCredentialData, parseAttestedCredentialData(&buf));
}

test "parseAttestedCredentialData: malformed COSE map rejected" {
    const kp = EcdsaP256Sha256.KeyPair.generate(testing.io);
    _ = kp;
    const rp_id_hash = sha256Str("example.com");
    const aaguid: [16]u8 = @splat(0);
    // credId "x", then a truncated CBOR map header (0xa5 claims 5 pairs, no body).
    var buf: [37 + 16 + 2 + 1 + 1]u8 = undefined;
    @memcpy(buf[0..32], &rp_id_hash);
    buf[32] = FLAG_UP | FLAG_AT;
    mem.writeInt(u32, buf[33..37], 1, .big);
    @memcpy(buf[37..53], &aaguid);
    mem.writeInt(u16, buf[53..55], 1, .big);
    buf[55] = 'x';
    buf[56] = 0xa5; // map(5) with no entries following
    try testing.expectError(error.InvalidCredentialData, parseAttestedCredentialData(&buf));
}

// -- Attestation verification tests ------------------------------------------
//
// These build GENUINE attestation objects: real ECDSA-P256 / Ed25519 keys sign
// real (authData || clientDataHash) data, and basic/u2f attestations embed real
// self-signed P-256 leaf certificates (via x509_selfsign). The underlying
// primitives (ECDSA, SHA-256, DER) are KAT-verified elsewhere in the tree
// (wycheproof); these vectors exercise the attestation *verification path*
// (CBOR walk, format dispatch, signed-data construction) the way the existing
// verifyAssertion tests exercise the assertion path. No published third-party
// binary "packed" vector is embedded — none with a recoverable trust context
// exists for a self/basic statement — so genuine constructions are used and
// their provenance is stated here.

/// Minimal CBOR writer for building test attestation objects.
const CborW = struct {
    buf: []u8,
    len: usize = 0,

    fn init(buf: []u8) CborW {
        return .{ .buf = buf };
    }
    fn byte(self: *CborW, b: u8) void {
        self.buf[self.len] = b;
        self.len += 1;
    }
    fn head(self: *CborW, major: u8, arg: u64) void {
        const m: u8 = major << 5;
        if (arg < 24) {
            self.byte(m | @as(u8, @intCast(arg)));
        } else if (arg < 0x100) {
            self.byte(m | 24);
            self.byte(@intCast(arg));
        } else if (arg < 0x10000) {
            self.byte(m | 25);
            self.byte(@intCast(arg >> 8));
            self.byte(@intCast(arg & 0xff));
        } else {
            self.byte(m | 26);
            self.byte(@intCast(arg >> 24));
            self.byte(@intCast((arg >> 16) & 0xff));
            self.byte(@intCast((arg >> 8) & 0xff));
            self.byte(@intCast(arg & 0xff));
        }
    }
    fn nint(self: *CborW, v: i64) void {
        self.head(1, @intCast(-1 - v));
    }
    fn bstr(self: *CborW, b: []const u8) void {
        self.head(2, b.len);
        @memcpy(self.buf[self.len..][0..b.len], b);
        self.len += b.len;
    }
    fn tstr(self: *CborW, t: []const u8) void {
        self.head(3, t.len);
        @memcpy(self.buf[self.len..][0..t.len], t);
        self.len += t.len;
    }
    fn arr(self: *CborW, n: u64) void {
        self.head(4, n);
    }
    fn map(self: *CborW, n: u64) void {
        self.head(5, n);
    }
    fn slice(self: *CborW) []const u8 {
        return self.buf[0..self.len];
    }
};

// Build registration authData with the ES256 credential key `cred_kp` and the
// given flags, returning the bytes in `out` and the credential cose bytes.
fn regAuthDataEs256(
    rp_id_hash: [32]u8,
    flags: u8,
    sign_count: u32,
    aaguid: [16]u8,
    cred_id: []const u8,
    cose77: [77]u8,
    out: []u8,
) usize {
    var i: usize = 0;
    @memcpy(out[0..32], &rp_id_hash);
    i = 32;
    out[i] = flags;
    i += 1;
    mem.writeInt(u32, out[i..][0..4], sign_count, .big);
    i += 4;
    @memcpy(out[i..][0..16], &aaguid);
    i += 16;
    mem.writeInt(u16, out[i..][0..2], @intCast(cred_id.len), .big);
    i += 2;
    @memcpy(out[i..][0..cred_id.len], cred_id);
    i += cred_id.len;
    @memcpy(out[i..][0..77], &cose77);
    i += 77;
    return i;
}

// Mirror the daemon's legacy (no-attestation) REGISTER-FINISH binding sequence
// against synthesized authData. The legacy branch checks: parseAuthData ->
// rpIdHash == SHA-256(rp_id) -> UP present -> (require_uv) UV -> attested-cred.
// This pins the User-Present guard the branch enforces (WebAuthn §7.1): a
// registration authData with UP=0 MUST be rejected; UP=1 passes the same gate.
test "WEBAUTHN legacy registration binding rejects UP=0 authData, accepts UP=1" {
    const rp_id = "example.com";
    const rp_id_hash = sha256Str(rp_id);
    const kp = EcdsaP256Sha256.KeyPair.generate(testing.io);
    const sec1 = kp.public_key.toUncompressedSec1();
    var cose: [77]u8 = undefined;
    buildCoseEs256(sec1[1..33].*, sec1[33..65].*, &cose);
    const aaguid: [16]u8 = @splat(0);
    const cred_id = "legacy-cred-01";

    // UP=0 (attested-credential data present, but no user-presence): the fixed
    // legacy branch rejects this via `webauthn.userPresent`.
    var no_up_buf: [37 + 16 + 2 + 14 + 77]u8 = undefined;
    const no_up_len = regAuthDataEs256(rp_id_hash, FLAG_AT, 1, aaguid, cred_id, cose, &no_up_buf);
    const no_up = no_up_buf[0..no_up_len];
    const ad_no_up = try parseAuthData(no_up);
    try testing.expect(mem.eql(u8, &ad_no_up.rp_id_hash, &rp_id_hash)); // rpIdHash gate passes
    try testing.expect(!userPresent(ad_no_up)); // ...but the UP gate rejects it
    try testing.expect(hasAttestedCredentialData(no_up)); // AT present, so pre-fix this was accepted

    // UP=1: same input with the presence flag set clears every legacy gate.
    var up_buf: [37 + 16 + 2 + 14 + 77]u8 = undefined;
    const up_len = regAuthDataEs256(rp_id_hash, FLAG_UP | FLAG_AT, 1, aaguid, cred_id, cose, &up_buf);
    const up = up_buf[0..up_len];
    const ad_up = try parseAuthData(up);
    try testing.expect(mem.eql(u8, &ad_up.rp_id_hash, &rp_id_hash));
    try testing.expect(userPresent(ad_up));
    try testing.expect(hasAttestedCredentialData(up));
    const att = try parseAttestedCredentialData(up);
    try testing.expectEqualSlices(u8, cred_id, att.credential_id);
}

test "verifyAttestation: fmt=none accepted as TOFU, rejected when attestation required" {
    const rp_id = "example.com";
    const rp_id_hash = sha256Str(rp_id);
    const kp = EcdsaP256Sha256.KeyPair.generate(testing.io);
    const sec1 = kp.public_key.toUncompressedSec1();
    var cose: [77]u8 = undefined;
    buildCoseEs256(sec1[1..33].*, sec1[33..65].*, &cose);
    const aaguid: [16]u8 = @splat(0);
    const cred_id = "cred-none";
    var ad_buf: [37 + 16 + 2 + 9 + 77]u8 = undefined;
    const ad_len = regAuthDataEs256(rp_id_hash, FLAG_UP | FLAG_AT, 4, aaguid, cred_id, cose, &ad_buf);
    const auth_data = ad_buf[0..ad_len];

    var cdh: [32]u8 = undefined;
    Sha256.hash("{\"type\":\"webauthn.create\"}", &cdh, .{});

    var ao: [1024]u8 = undefined;
    var w = CborW.init(&ao);
    w.map(3);
    w.tstr("fmt");
    w.tstr("none");
    w.tstr("attStmt");
    w.map(0);
    w.tstr("authData");
    w.bstr(auth_data);
    const att_obj = w.slice();

    // TOFU: accepted when attestation is not required.
    const v = try verifyAttestation(att_obj, .{
        .rp_id = rp_id,
        .client_data_hash = cdh,
        .require_uv = false,
        .require_attestation = false,
    });
    try testing.expectEqual(AttestationFormat.none, v.format);
    try testing.expect(!v.attested);
    try testing.expectEqualSlices(u8, cred_id, v.credential.credential_id);

    // Rejected when attestation is required.
    try testing.expectError(error.AttestationRequired, verifyAttestation(att_obj, .{
        .rp_id = rp_id,
        .client_data_hash = cdh,
        .require_uv = false,
        .require_attestation = true,
    }));
}

test "verifyAttestation: fmt=none with a stuffed attStmt is malformed" {
    const rp_id = "example.com";
    const rp_id_hash = sha256Str(rp_id);
    const kp = EcdsaP256Sha256.KeyPair.generate(testing.io);
    const sec1 = kp.public_key.toUncompressedSec1();
    var cose: [77]u8 = undefined;
    buildCoseEs256(sec1[1..33].*, sec1[33..65].*, &cose);
    const aaguid: [16]u8 = @splat(0);
    var ad_buf: [37 + 16 + 2 + 2 + 77]u8 = undefined;
    const ad_len = regAuthDataEs256(rp_id_hash, FLAG_UP | FLAG_AT, 1, aaguid, "id", cose, &ad_buf);
    const auth_data = ad_buf[0..ad_len];
    var cdh: [32]u8 = undefined;
    Sha256.hash("{}", &cdh, .{});

    var ao: [1024]u8 = undefined;
    var w = CborW.init(&ao);
    w.map(3);
    w.tstr("fmt");
    w.tstr("none");
    w.tstr("attStmt");
    w.map(1); // non-empty: illegal for `none`
    w.tstr("x");
    w.head(0, 1);
    w.tstr("authData");
    w.bstr(auth_data);

    try testing.expectError(error.MalformedAttestation, verifyAttestation(w.slice(), .{
        .rp_id = rp_id,
        .client_data_hash = cdh,
        .require_uv = false,
        .require_attestation = false,
    }));
}

test "verifyAttestation: packed self-attestation (ES256) verifies; tamper rejected" {
    const rp_id = "example.com";
    const rp_id_hash = sha256Str(rp_id);
    const kp = EcdsaP256Sha256.KeyPair.generate(testing.io);
    const sec1 = kp.public_key.toUncompressedSec1();
    var cose: [77]u8 = undefined;
    buildCoseEs256(sec1[1..33].*, sec1[33..65].*, &cose);
    const aaguid: [16]u8 = @splat(0);
    const cred_id = "cred-packed-self";
    var ad_buf: [37 + 16 + 2 + 16 + 77]u8 = undefined;
    const ad_len = regAuthDataEs256(rp_id_hash, FLAG_UP | FLAG_UV | FLAG_AT, 9, aaguid, cred_id, cose, &ad_buf);
    const auth_data = ad_buf[0..ad_len];

    var cdh: [32]u8 = undefined;
    Sha256.hash("{\"type\":\"webauthn.create\",\"challenge\":\"c\"}", &cdh, .{});

    var signer = try kp.signer(null);
    signer.update(auth_data);
    signer.update(&cdh);
    const sig = try signer.finalize();
    var der_buf: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
    const der = sig.toDer(&der_buf);

    var ao: [2048]u8 = undefined;
    var w = CborW.init(&ao);
    w.map(3);
    w.tstr("fmt");
    w.tstr("packed");
    w.tstr("attStmt");
    w.map(2);
    w.tstr("alg");
    w.nint(-7);
    w.tstr("sig");
    w.bstr(der);
    w.tstr("authData");
    w.bstr(auth_data);
    const att_obj = w.slice();

    const v = try verifyAttestation(att_obj, .{
        .rp_id = rp_id,
        .client_data_hash = cdh,
        .require_uv = true,
        .require_attestation = true,
    });
    try testing.expectEqual(AttestationFormat.@"packed", v.format);
    try testing.expect(v.attested);
    try testing.expectEqual(@as(u32, 9), v.sign_count);
    try testing.expectEqualSlices(u8, cred_id, v.credential.credential_id);

    // Tamper the DER signature's last byte → verification fails.
    var der_bad_buf: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
    @memcpy(der_bad_buf[0..der.len], der);
    der_bad_buf[der.len - 1] ^= 0xff;
    var ao2: [2048]u8 = undefined;
    var w2 = CborW.init(&ao2);
    w2.map(3);
    w2.tstr("fmt");
    w2.tstr("packed");
    w2.tstr("attStmt");
    w2.map(2);
    w2.tstr("alg");
    w2.nint(-7);
    w2.tstr("sig");
    w2.bstr(der_bad_buf[0..der.len]);
    w2.tstr("authData");
    w2.bstr(auth_data);
    try testing.expectError(error.SignatureVerificationFailed, verifyAttestation(w2.slice(), .{
        .rp_id = rp_id,
        .client_data_hash = cdh,
        .require_uv = false,
        .require_attestation = true,
    }));
}

test "verifyAttestation: packed self-attestation with wrong alg is rejected" {
    const rp_id = "example.com";
    const rp_id_hash = sha256Str(rp_id);
    const kp = EcdsaP256Sha256.KeyPair.generate(testing.io);
    const sec1 = kp.public_key.toUncompressedSec1();
    var cose: [77]u8 = undefined;
    buildCoseEs256(sec1[1..33].*, sec1[33..65].*, &cose);
    const aaguid: [16]u8 = @splat(0);
    var ad_buf: [37 + 16 + 2 + 2 + 77]u8 = undefined;
    const ad_len = regAuthDataEs256(rp_id_hash, FLAG_UP | FLAG_AT, 1, aaguid, "id", cose, &ad_buf);
    const auth_data = ad_buf[0..ad_len];
    var cdh: [32]u8 = undefined;
    Sha256.hash("{}", &cdh, .{});
    var signer = try kp.signer(null);
    signer.update(auth_data);
    signer.update(&cdh);
    const sig = try signer.finalize();
    var der_buf: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
    const der = sig.toDer(&der_buf);

    var ao: [2048]u8 = undefined;
    var w = CborW.init(&ao);
    w.map(3);
    w.tstr("fmt");
    w.tstr("packed");
    w.tstr("attStmt");
    w.map(2);
    w.tstr("alg");
    w.nint(-8); // EdDSA alg for an ES256 credential key → mismatch
    w.tstr("sig");
    w.bstr(der);
    w.tstr("authData");
    w.bstr(auth_data);
    try testing.expectError(error.AttestationAlgMismatch, verifyAttestation(w.slice(), .{
        .rp_id = rp_id,
        .client_data_hash = cdh,
        .require_uv = false,
        .require_attestation = true,
    }));
}

test "verifyAttestation: packed basic attestation (x5c ES256 leaf) verifies" {
    const x509_selfsign = @import("../proto/x509_selfsign.zig");
    const rp_id = "example.com";
    const rp_id_hash = sha256Str(rp_id);

    // Credential key is distinct from the attestation key.
    const cred_kp = EcdsaP256Sha256.KeyPair.generate(testing.io);
    const csec1 = cred_kp.public_key.toUncompressedSec1();
    var cose: [77]u8 = undefined;
    buildCoseEs256(csec1[1..33].*, csec1[33..65].*, &cose);
    const aaguid: [16]u8 = @splat(0x11);
    const cred_id = "cred-basic";
    var ad_buf: [37 + 16 + 2 + 10 + 77]u8 = undefined;
    const ad_len = regAuthDataEs256(rp_id_hash, FLAG_UP | FLAG_AT, 3, aaguid, cred_id, cose, &ad_buf);
    const auth_data = ad_buf[0..ad_len];
    var cdh: [32]u8 = undefined;
    Sha256.hash("{\"type\":\"webauthn.create\"}", &cdh, .{});

    // Genuine self-signed P-256 attestation certificate + key.
    const att_kp = EcdsaP256Sha256.KeyPair.generate(testing.io);
    var cert_buf: [2048]u8 = undefined;
    const cert_der = try x509_selfsign.buildSelfSignedEcdsaP256(&cert_buf, .{
        .common_name = "Orochi Test Attestation",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{0x01},
        .key_pair = att_kp,
    });

    var signer = try att_kp.signer(null);
    signer.update(auth_data);
    signer.update(&cdh);
    const sig = try signer.finalize();
    var der_buf: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
    const der = sig.toDer(&der_buf);

    var ao: [4096]u8 = undefined;
    var w = CborW.init(&ao);
    w.map(3);
    w.tstr("fmt");
    w.tstr("packed");
    w.tstr("attStmt");
    w.map(3);
    w.tstr("alg");
    w.nint(-7);
    w.tstr("sig");
    w.bstr(der);
    w.tstr("x5c");
    w.arr(1);
    w.bstr(cert_der);
    w.tstr("authData");
    w.bstr(auth_data);

    const v = try verifyAttestation(w.slice(), .{
        .rp_id = rp_id,
        .client_data_hash = cdh,
        .require_uv = false,
        .require_attestation = true,
    });
    try testing.expect(v.attested);
    try testing.expectEqualSlices(u8, cred_id, v.credential.credential_id);

    // A signature made by the WRONG key (the credential key, not the cert key)
    // must fail against the leaf cert.
    var bad_signer = try cred_kp.signer(null);
    bad_signer.update(auth_data);
    bad_signer.update(&cdh);
    const bad_sig = try bad_signer.finalize();
    var bad_der_buf: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
    const bad_der = bad_sig.toDer(&bad_der_buf);
    var ao2: [4096]u8 = undefined;
    var w2 = CborW.init(&ao2);
    w2.map(3);
    w2.tstr("fmt");
    w2.tstr("packed");
    w2.tstr("attStmt");
    w2.map(3);
    w2.tstr("alg");
    w2.nint(-7);
    w2.tstr("sig");
    w2.bstr(bad_der);
    w2.tstr("x5c");
    w2.arr(1);
    w2.bstr(cert_der);
    w2.tstr("authData");
    w2.bstr(auth_data);
    try testing.expectError(error.SignatureVerificationFailed, verifyAttestation(w2.slice(), .{
        .rp_id = rp_id,
        .client_data_hash = cdh,
        .require_uv = false,
        .require_attestation = true,
    }));
}

test "verifyAttestation: fido-u2f (x5c P-256 leaf) verifies" {
    const x509_selfsign = @import("../proto/x509_selfsign.zig");
    const rp_id = "example.com";
    const rp_id_hash = sha256Str(rp_id);

    const cred_kp = EcdsaP256Sha256.KeyPair.generate(testing.io);
    const csec1 = cred_kp.public_key.toUncompressedSec1();
    var cose: [77]u8 = undefined;
    buildCoseEs256(csec1[1..33].*, csec1[33..65].*, &cose);
    const aaguid: [16]u8 = @splat(0);
    const cred_id = "u2f-cred-id-01";
    var ad_buf: [37 + 16 + 2 + 14 + 77]u8 = undefined;
    const ad_len = regAuthDataEs256(rp_id_hash, FLAG_UP | FLAG_AT, 0, aaguid, cred_id, cose, &ad_buf);
    const auth_data = ad_buf[0..ad_len];
    var cdh: [32]u8 = undefined;
    Sha256.hash("{\"type\":\"webauthn.create\"}", &cdh, .{});

    const att_kp = EcdsaP256Sha256.KeyPair.generate(testing.io);
    var cert_buf: [2048]u8 = undefined;
    const cert_der = try x509_selfsign.buildSelfSignedEcdsaP256(&cert_buf, .{
        .common_name = "Orochi Test U2F",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{0x02},
        .key_pair = att_kp,
    });

    // verificationData = 0x00 || rpIdHash || clientDataHash || credId || (0x04||x||y)
    var signer = try att_kp.signer(null);
    signer.update(&[_]u8{0x00});
    signer.update(&rp_id_hash);
    signer.update(&cdh);
    signer.update(cred_id);
    signer.update(&csec1); // 0x04 || x || y
    const sig = try signer.finalize();
    var der_buf: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
    const der = sig.toDer(&der_buf);

    var ao: [4096]u8 = undefined;
    var w = CborW.init(&ao);
    w.map(3);
    w.tstr("fmt");
    w.tstr("fido-u2f");
    w.tstr("attStmt");
    w.map(2);
    w.tstr("sig");
    w.bstr(der);
    w.tstr("x5c");
    w.arr(1);
    w.bstr(cert_der);
    w.tstr("authData");
    w.bstr(auth_data);

    const v = try verifyAttestation(w.slice(), .{
        .rp_id = rp_id,
        .client_data_hash = cdh,
        .require_uv = false,
        .require_attestation = true,
    });
    try testing.expectEqual(AttestationFormat.fido_u2f, v.format);
    try testing.expect(v.attested);
    try testing.expectEqualSlices(u8, cred_id, v.credential.credential_id);
}

test "verifyAttestation: fido-u2f with a non-zero AAGUID is rejected" {
    const x509_selfsign = @import("../proto/x509_selfsign.zig");
    const rp_id = "example.com";
    const rp_id_hash = sha256Str(rp_id);

    const cred_kp = EcdsaP256Sha256.KeyPair.generate(testing.io);
    const csec1 = cred_kp.public_key.toUncompressedSec1();
    var cose: [77]u8 = undefined;
    buildCoseEs256(csec1[1..33].*, csec1[33..65].*, &cose);
    const aaguid: [16]u8 = @splat(0x01); // illegal for U2F
    const cred_id = "u2f-bad-aaguid";
    var ad_buf: [37 + 16 + 2 + 14 + 77]u8 = undefined;
    const ad_len = regAuthDataEs256(rp_id_hash, FLAG_UP | FLAG_AT, 0, aaguid, cred_id, cose, &ad_buf);
    const auth_data = ad_buf[0..ad_len];
    var cdh: [32]u8 = undefined;
    Sha256.hash("{\"type\":\"webauthn.create\"}", &cdh, .{});

    const att_kp = EcdsaP256Sha256.KeyPair.generate(testing.io);
    var cert_buf: [2048]u8 = undefined;
    const cert_der = try x509_selfsign.buildSelfSignedEcdsaP256(&cert_buf, .{
        .common_name = "Orochi Test U2F",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{0x03},
        .key_pair = att_kp,
    });
    var signer = try att_kp.signer(null);
    signer.update(&[_]u8{0x00});
    signer.update(&rp_id_hash);
    signer.update(&cdh);
    signer.update(cred_id);
    signer.update(&csec1);
    const sig = try signer.finalize();
    var der_buf: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
    const der = sig.toDer(&der_buf);

    var ao: [4096]u8 = undefined;
    var w = CborW.init(&ao);
    w.map(3);
    w.tstr("fmt");
    w.tstr("fido-u2f");
    w.tstr("attStmt");
    w.map(2);
    w.tstr("sig");
    w.bstr(der);
    w.tstr("x5c");
    w.arr(1);
    w.bstr(cert_der);
    w.tstr("authData");
    w.bstr(auth_data);
    try testing.expectError(error.MalformedAttestation, verifyAttestation(w.slice(), .{
        .rp_id = rp_id,
        .client_data_hash = cdh,
        .require_uv = false,
        .require_attestation = true,
    }));
}

test "verifyAttestation: require_uv rejects UV-absent, accepts UV-present (registration)" {
    const rp_id = "example.com";
    const rp_id_hash = sha256Str(rp_id);
    const kp = EcdsaP256Sha256.KeyPair.generate(testing.io);
    const sec1 = kp.public_key.toUncompressedSec1();
    var cose: [77]u8 = undefined;
    buildCoseEs256(sec1[1..33].*, sec1[33..65].*, &cose);
    const aaguid: [16]u8 = @splat(0);

    // UP-only authData (no UV).
    var ad_up: [37 + 16 + 2 + 2 + 77]u8 = undefined;
    const up_len = regAuthDataEs256(rp_id_hash, FLAG_UP | FLAG_AT, 1, aaguid, "id", cose, &ad_up);
    var cdh: [32]u8 = undefined;
    Sha256.hash("{}", &cdh, .{});
    var ao: [1024]u8 = undefined;
    var w = CborW.init(&ao);
    w.map(3);
    w.tstr("fmt");
    w.tstr("none");
    w.tstr("attStmt");
    w.map(0);
    w.tstr("authData");
    w.bstr(ad_up[0..up_len]);
    try testing.expectError(error.UserVerificationRequired, verifyAttestation(w.slice(), .{
        .rp_id = rp_id,
        .client_data_hash = cdh,
        .require_uv = true,
        .require_attestation = false,
    }));

    // UV-present authData is accepted.
    var ad_uv: [37 + 16 + 2 + 2 + 77]u8 = undefined;
    const uv_len = regAuthDataEs256(rp_id_hash, FLAG_UP | FLAG_UV | FLAG_AT, 1, aaguid, "id", cose, &ad_uv);
    var ao2: [1024]u8 = undefined;
    var w2 = CborW.init(&ao2);
    w2.map(3);
    w2.tstr("fmt");
    w2.tstr("none");
    w2.tstr("attStmt");
    w2.map(0);
    w2.tstr("authData");
    w2.bstr(ad_uv[0..uv_len]);
    const v = try verifyAttestation(w2.slice(), .{
        .rp_id = rp_id,
        .client_data_hash = cdh,
        .require_uv = true,
        .require_attestation = false,
    });
    try testing.expect(!v.attested);
}

test "verifyAttestation: malformed / truncated attestationObject fails closed (no panic)" {
    const opts = AttestationOptions{
        .rp_id = "example.com",
        .client_data_hash = @splat(0),
        .require_uv = false,
        .require_attestation = false,
    };
    try testing.expectError(error.InvalidEncoding, verifyAttestation("", opts));
    try testing.expectError(error.InvalidEncoding, verifyAttestation(&[_]u8{0xa3}, opts)); // map(3), no body
    // A map whose first key claims a 2^63-byte text string must not overflow.
    var buf: [10]u8 = undefined;
    buf[0] = 0xa3; // map(3)
    buf[1] = 0x7b; // text string, 8-byte length follows
    mem.writeInt(u64, buf[2..10], 0x7fff_ffff_ffff_ffff, .big);
    try testing.expectError(error.InvalidEncoding, verifyAttestation(&buf, opts));
}

test "verifyAttestation: rpIdHash mismatch rejected" {
    const rp_id = "example.com";
    const wrong_hash = sha256Str("evil.com");
    const kp = EcdsaP256Sha256.KeyPair.generate(testing.io);
    const sec1 = kp.public_key.toUncompressedSec1();
    var cose: [77]u8 = undefined;
    buildCoseEs256(sec1[1..33].*, sec1[33..65].*, &cose);
    const aaguid: [16]u8 = @splat(0);
    var ad_buf: [37 + 16 + 2 + 2 + 77]u8 = undefined;
    const ad_len = regAuthDataEs256(wrong_hash, FLAG_UP | FLAG_AT, 1, aaguid, "id", cose, &ad_buf);
    var cdh: [32]u8 = undefined;
    Sha256.hash("{}", &cdh, .{});
    var ao: [1024]u8 = undefined;
    var w = CborW.init(&ao);
    w.map(3);
    w.tstr("fmt");
    w.tstr("none");
    w.tstr("attStmt");
    w.map(0);
    w.tstr("authData");
    w.bstr(ad_buf[0..ad_len]);
    try testing.expectError(error.RpIdHashMismatch, verifyAttestation(w.slice(), .{
        .rp_id = rp_id,
        .client_data_hash = cdh,
        .require_uv = false,
        .require_attestation = false,
    }));
}

test "verifyAssertion: require_uv rejects a UV-absent assertion with UserVerificationRequired" {
    const rp_id = "example.com";
    const rp_id_hash = sha256Str(rp_id);
    const auth_data = makeAuthData(rp_id_hash, FLAG_UP, 1); // UP but no UV
    const client_data_json = "{\"type\":\"webauthn.get\"}";
    var cdj_hash: [32]u8 = undefined;
    Sha256.hash(client_data_json, &cdj_hash, .{});

    const kp = EcdsaP256Sha256.KeyPair.generate(testing.io);
    var signer = try kp.signer(null);
    signer.update(&auth_data);
    signer.update(&cdj_hash);
    const sig = try signer.finalize();
    var der_buf: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
    const der = sig.toDer(&der_buf);

    const sec1 = kp.public_key.toUncompressedSec1();
    var cose_buf: [77]u8 = undefined;
    buildCoseEs256(sec1[1..33].*, sec1[33..65].*, &cose_buf);
    const cpk = try parseCoseKey(&cose_buf);

    try testing.expectError(error.UserVerificationRequired, verifyAssertion(&auth_data, client_data_json, der, .{
        .rp_id = rp_id,
        .credential_public_key = cpk,
        .stored_sign_count = 0,
        .require_uv = true,
    }));
}

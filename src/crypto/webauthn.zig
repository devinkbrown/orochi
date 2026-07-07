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

    // 4. Optionally require UV flag
    if (opts.require_uv and (ad.flags & FLAG_UV == 0)) {
        return error.UserPresenceRequired; // reuse error; UV is a superset of presence
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

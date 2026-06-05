//! Self-contained JWT (RFC 7519) signing and verification helpers.
//!
//! Supports compact JWS tokens with HS256 and EdDSA/Ed25519 only. The verifier
//! requires the caller's expected algorithm and rejects header mismatches to
//! avoid algorithm-confusion bugs.
const std = @import("std");

const Allocator = std.mem.Allocator;
const Ed25519 = std.crypto.sign.Ed25519;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub const Algorithm = enum {
    HS256,
    EdDSA,

    fn jsonName(self: Algorithm) []const u8 {
        return switch (self) {
            .HS256 => "HS256",
            .EdDSA => "EdDSA",
        };
    }
};

pub const Hs256Key = []const u8;
pub const Ed25519SecretKey = [Ed25519.SecretKey.encoded_length]u8;
pub const Ed25519PublicKey = [Ed25519.PublicKey.encoded_length]u8;

pub const SigningKey = union(Algorithm) {
    HS256: Hs256Key,
    EdDSA: Ed25519SecretKey,
};

pub const VerificationKey = union(Algorithm) {
    HS256: Hs256Key,
    EdDSA: Ed25519PublicKey,
};

pub const JwtError = error{
    AlgorithmMismatch,
    AlgorithmNoneRejected,
    InvalidAlgorithm,
    InvalidClaims,
    InvalidKey,
    InvalidToken,
    InvalidJson,
    InvalidSignature,
    TokenExpired,
    TokenNotYetValid,
    TokenIssuedInFuture,
};

pub const Error = JwtError || Allocator.Error || std.base64.Error ||
    Ed25519.Signature.VerifyError || std.crypto.errors.KeyMismatchError;

const header_hs256 = "{\"typ\":\"JWT\",\"alg\":\"HS256\"}";
const header_eddsa = "{\"typ\":\"JWT\",\"alg\":\"EdDSA\"}";

/// Sign `claims_json` and return an allocated compact JWT.
pub fn sign(allocator: Allocator, claims_json: []const u8, alg: Algorithm, key: SigningKey) Error![]u8 {
    try ensureJsonObject(allocator, claims_json);
    if (signingKeyAlg(key) != alg) return error.InvalidKey;

    const header_json = switch (alg) {
        .HS256 => header_hs256,
        .EdDSA => header_eddsa,
    };

    const encoded_header = try base64UrlEncodeAlloc(allocator, header_json);
    defer allocator.free(encoded_header);
    const encoded_claims = try base64UrlEncodeAlloc(allocator, claims_json);
    defer allocator.free(encoded_claims);

    const signing_input = try std.fmt.allocPrint(
        allocator,
        "{s}.{s}",
        .{ encoded_header, encoded_claims },
    );
    defer allocator.free(signing_input);

    const signature = try signInput(allocator, signing_input, alg, key);
    defer allocator.free(signature);

    const encoded_sig = try base64UrlEncodeAlloc(allocator, signature);
    defer allocator.free(encoded_sig);

    return std.fmt.allocPrint(allocator, "{s}.{s}", .{ signing_input, encoded_sig });
}

/// Verify `token` at the caller-provided Unix timestamp and return allocated claims JSON.
///
/// `leeway_seconds` is applied to `exp`, `nbf`, and future `iat` checks.
pub fn verifyAt(
    allocator: Allocator,
    token: []const u8,
    alg: Algorithm,
    key: VerificationKey,
    now_seconds: i64,
    leeway_seconds: i64,
) Error![]u8 {
    if (verificationKeyAlg(key) != alg) return error.InvalidKey;
    const leeway = @max(leeway_seconds, 0);

    const parts = try splitToken(token);
    const signing_input = token[0..parts.payload_end];

    const header_json = try base64UrlDecodeAlloc(allocator, parts.header);
    defer allocator.free(header_json);
    const payload_json = try base64UrlDecodeAlloc(allocator, parts.payload);
    errdefer allocator.free(payload_json);

    try verifyHeaderAlg(allocator, header_json, alg);

    const signature = try base64UrlDecodeAlloc(allocator, parts.signature);
    defer allocator.free(signature);
    try verifySignature(signing_input, signature, alg, key);
    try verifyClaimsTime(allocator, payload_json, now_seconds, leeway);

    return payload_json;
}

/// Convenience verifier that uses `std.time.timestamp()`.
pub fn verify(
    allocator: Allocator,
    token: []const u8,
    alg: Algorithm,
    key: VerificationKey,
    leeway_seconds: i64,
) Error![]u8 {
    return verifyAt(allocator, token, alg, key, std.time.timestamp(), leeway_seconds);
}

pub fn base64UrlEncodeAlloc(allocator: Allocator, bytes: []const u8) Allocator.Error![]u8 {
    const len = std.base64.url_safe_no_pad.Encoder.calcSize(bytes.len);
    const out = try allocator.alloc(u8, len);
    _ = std.base64.url_safe_no_pad.Encoder.encode(out, bytes);
    return out;
}

pub fn base64UrlDecodeAlloc(allocator: Allocator, text: []const u8) (Allocator.Error || std.base64.Error)![]u8 {
    const len = try std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(text);
    const out = try allocator.alloc(u8, len);
    errdefer allocator.free(out);
    try std.base64.url_safe_no_pad.Decoder.decode(out, text);
    return out;
}

fn signInput(allocator: Allocator, input: []const u8, alg: Algorithm, key: SigningKey) Error![]u8 {
    switch (alg) {
        .HS256 => {
            const raw_key = switch (key) {
                .HS256 => |k| k,
                else => return error.InvalidKey,
            };
            const out = try allocator.alloc(u8, HmacSha256.mac_length);
            var mac: [HmacSha256.mac_length]u8 = undefined;
            HmacSha256.create(&mac, input, raw_key);
            @memcpy(out, &mac);
            return out;
        },
        .EdDSA => {
            const raw_key = switch (key) {
                .EdDSA => |k| k,
                else => return error.InvalidKey,
            };
            const secret = try Ed25519.SecretKey.fromBytes(raw_key);
            const kp = try Ed25519.KeyPair.fromSecretKey(secret);
            const sig = try kp.sign(input, null);
            const bytes = sig.toBytes();
            const out = try allocator.alloc(u8, bytes.len);
            @memcpy(out, &bytes);
            return out;
        },
    }
}

fn signingKeyAlg(key: SigningKey) Algorithm {
    return switch (key) {
        .HS256 => .HS256,
        .EdDSA => .EdDSA,
    };
}

fn verificationKeyAlg(key: VerificationKey) Algorithm {
    return switch (key) {
        .HS256 => .HS256,
        .EdDSA => .EdDSA,
    };
}

fn verifySignature(input: []const u8, signature: []const u8, alg: Algorithm, key: VerificationKey) Error!void {
    switch (alg) {
        .HS256 => {
            const raw_key = switch (key) {
                .HS256 => |k| k,
                else => return error.InvalidKey,
            };
            if (signature.len != HmacSha256.mac_length) return error.InvalidSignature;
            var expected: [HmacSha256.mac_length]u8 = undefined;
            HmacSha256.create(&expected, input, raw_key);
            if (!std.crypto.timing_safe.eql([HmacSha256.mac_length]u8, expected, signature[0..HmacSha256.mac_length].*)) {
                return error.InvalidSignature;
            }
        },
        .EdDSA => {
            const raw_key = switch (key) {
                .EdDSA => |k| k,
                else => return error.InvalidKey,
            };
            if (signature.len != Ed25519.Signature.encoded_length) return error.InvalidSignature;
            const public_key = try Ed25519.PublicKey.fromBytes(raw_key);
            const sig = Ed25519.Signature.fromBytes(signature[0..Ed25519.Signature.encoded_length].*);
            sig.verify(input, public_key) catch |err| switch (err) {
                error.SignatureVerificationFailed => return error.InvalidSignature,
                else => return err,
            };
        },
    }
}

fn verifyHeaderAlg(allocator: Allocator, header_json: []const u8, expected: Algorithm) Error!void {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, header_json, .{}) catch return error.InvalidJson;
    defer parsed.deinit();

    if (parsed.value != .object) return error.InvalidJson;
    const alg_value = parsed.value.object.get("alg") orelse return error.InvalidAlgorithm;
    if (alg_value != .string) return error.InvalidAlgorithm;
    const actual = alg_value.string;
    if (std.mem.eql(u8, actual, "none")) return error.AlgorithmNoneRejected;
    if (!std.mem.eql(u8, actual, expected.jsonName())) return error.AlgorithmMismatch;
}

fn ensureJsonObject(allocator: Allocator, json: []const u8) Error!void {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, json, .{}) catch return error.InvalidJson;
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidClaims;
}

fn verifyClaimsTime(allocator: Allocator, claims_json: []const u8, now: i64, leeway: i64) Error!void {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, claims_json, .{}) catch return error.InvalidJson;
    defer parsed.deinit();

    if (parsed.value != .object) return error.InvalidClaims;
    const obj = parsed.value.object;

    if (obj.get("exp")) |v| {
        const exp = try intDate(v);
        if (now > exp +| leeway) return error.TokenExpired;
    }
    if (obj.get("nbf")) |v| {
        const nbf = try intDate(v);
        if (now +| leeway < nbf) return error.TokenNotYetValid;
    }
    if (obj.get("iat")) |v| {
        const iat = try intDate(v);
        if (now +| leeway < iat) return error.TokenIssuedInFuture;
    }
}

fn intDate(value: std.json.Value) Error!i64 {
    return switch (value) {
        .integer => |n| n,
        .number_string => |s| std.fmt.parseInt(i64, s, 10) catch return error.InvalidClaims,
        else => error.InvalidClaims,
    };
}

const TokenParts = struct {
    header: []const u8,
    payload: []const u8,
    signature: []const u8,
    payload_end: usize,
};

fn splitToken(token: []const u8) Error!TokenParts {
    const first = std.mem.indexOfScalar(u8, token, '.') orelse return error.InvalidToken;
    const second_rel = std.mem.indexOfScalar(u8, token[first + 1 ..], '.') orelse return error.InvalidToken;
    const second = first + 1 + second_rel;
    if (std.mem.indexOfScalar(u8, token[second + 1 ..], '.') != null) return error.InvalidToken;
    if (first == 0 or second == first + 1 or second == token.len - 1) return error.InvalidToken;

    return .{
        .header = token[0..first],
        .payload = token[first + 1 .. second],
        .signature = token[second + 1 ..],
        .payload_end = second,
    };
}

fn expectVerifyError(expected: anyerror, token: []const u8, alg: Algorithm, key: VerificationKey, now: i64, leeway: i64) !void {
    const actual = verifyAt(std.testing.allocator, token, alg, key, now, leeway);
    if (actual) |claims| {
        std.testing.allocator.free(claims);
        return error.ExpectedVerifyFailure;
    } else |err| {
        try std.testing.expectEqual(expected, err);
    }
}

fn tamperLastChar(allocator: Allocator, text: []const u8) ![]u8 {
    const out = try allocator.dupe(u8, text);
    out[out.len - 1] = if (out[out.len - 1] == 'A') 'B' else 'A';
    return out;
}

fn replacePayload(allocator: Allocator, token: []const u8, new_payload_json: []const u8) ![]u8 {
    const parts = try splitToken(token);
    const encoded_payload = try base64UrlEncodeAlloc(allocator, new_payload_json);
    defer allocator.free(encoded_payload);
    return std.fmt.allocPrint(
        allocator,
        "{s}.{s}.{s}",
        .{ parts.header, encoded_payload, parts.signature },
    );
}

fn tokenWithHeader(allocator: Allocator, header_json: []const u8, claims_json: []const u8) ![]u8 {
    const encoded_header = try base64UrlEncodeAlloc(allocator, header_json);
    defer allocator.free(encoded_header);
    const encoded_claims = try base64UrlEncodeAlloc(allocator, claims_json);
    defer allocator.free(encoded_claims);
    return std.fmt.allocPrint(allocator, "{s}.{s}.x", .{ encoded_header, encoded_claims });
}

fn testEdKeyPair() !Ed25519.KeyPair {
    return Ed25519.KeyPair.generateDeterministic([_]u8{
        0,  1,  2,  3,  4,  5,  6,  7,
        8,  9,  10, 11, 12, 13, 14, 15,
        16, 17, 18, 19, 20, 21, 22, 23,
        24, 25, 26, 27, 28, 29, 30, 31,
    });
}

test "base64url no padding correctness" {
    const allocator = std.testing.allocator;

    const encoded = try base64UrlEncodeAlloc(allocator, "\xfb\xff\xee?");
    defer allocator.free(encoded);
    try std.testing.expectEqualStrings("-__uPw", encoded);
    try std.testing.expect(std.mem.indexOfScalar(u8, encoded, '=') == null);

    const decoded = try base64UrlDecodeAlloc(allocator, encoded);
    defer allocator.free(decoded);
    try std.testing.expectEqualSlices(u8, "\xfb\xff\xee?", decoded);
}

test "HS256 sign verify round trip" {
    const allocator = std.testing.allocator;
    const claims = "{\"sub\":\"alice\",\"iat\":1000,\"nbf\":990,\"exp\":1100}";

    const token = try sign(allocator, claims, .HS256, .{ .HS256 = "secret" });
    defer allocator.free(token);
    const got = try verifyAt(allocator, token, .HS256, .{ .HS256 = "secret" }, 1000, 0);
    defer allocator.free(got);

    try std.testing.expectEqualSlices(u8, claims, got);
}

test "EdDSA sign verify round trip" {
    const allocator = std.testing.allocator;
    const kp = try testEdKeyPair();
    const claims = "{\"sub\":\"alice\",\"iat\":1000,\"nbf\":990,\"exp\":1100}";

    const token = try sign(allocator, claims, .EdDSA, .{ .EdDSA = kp.secret_key.toBytes() });
    defer allocator.free(token);
    const got = try verifyAt(allocator, token, .EdDSA, .{ .EdDSA = kp.public_key.toBytes() }, 1000, 0);
    defer allocator.free(got);

    try std.testing.expectEqualSlices(u8, claims, got);
}

test "tampered payload is rejected" {
    const allocator = std.testing.allocator;
    const token = try sign(allocator, "{\"sub\":\"alice\",\"exp\":1100}", .HS256, .{ .HS256 = "secret" });
    defer allocator.free(token);
    const tampered = try replacePayload(allocator, token, "{\"sub\":\"mallory\",\"exp\":1100}");
    defer allocator.free(tampered);

    try expectVerifyError(error.InvalidSignature, tampered, .HS256, .{ .HS256 = "secret" }, 1000, 0);
}

test "tampered signature is rejected" {
    const allocator = std.testing.allocator;
    const token = try sign(allocator, "{\"sub\":\"alice\",\"exp\":1100}", .HS256, .{ .HS256 = "secret" });
    defer allocator.free(token);
    const tampered = try tamperLastChar(allocator, token);
    defer allocator.free(tampered);

    try expectVerifyError(error.InvalidSignature, tampered, .HS256, .{ .HS256 = "secret" }, 1000, 0);
}

test "algorithm confusion is rejected before signature trust" {
    const allocator = std.testing.allocator;
    const kp = try testEdKeyPair();
    const token = try sign(allocator, "{\"sub\":\"alice\",\"exp\":1100}", .HS256, .{ .HS256 = "secret" });
    defer allocator.free(token);

    try expectVerifyError(error.AlgorithmMismatch, token, .EdDSA, .{ .EdDSA = kp.public_key.toBytes() }, 1000, 0);
}

test "alg none is rejected" {
    const allocator = std.testing.allocator;
    const token = try tokenWithHeader(allocator, "{\"typ\":\"JWT\",\"alg\":\"none\"}", "{\"sub\":\"alice\"}");
    defer allocator.free(token);

    try expectVerifyError(error.AlgorithmNoneRejected, token, .HS256, .{ .HS256 = "secret" }, 1000, 0);
}

test "expired token is rejected" {
    const allocator = std.testing.allocator;
    const token = try sign(allocator, "{\"sub\":\"alice\",\"exp\":999}", .HS256, .{ .HS256 = "secret" });
    defer allocator.free(token);

    try expectVerifyError(error.TokenExpired, token, .HS256, .{ .HS256 = "secret" }, 1000, 0);
}

test "nbf in future is rejected" {
    const allocator = std.testing.allocator;
    const token = try sign(allocator, "{\"sub\":\"alice\",\"nbf\":1001}", .HS256, .{ .HS256 = "secret" });
    defer allocator.free(token);

    try expectVerifyError(error.TokenNotYetValid, token, .HS256, .{ .HS256 = "secret" }, 1000, 0);
}

test "iat in future is rejected" {
    const allocator = std.testing.allocator;
    const token = try sign(allocator, "{\"sub\":\"alice\",\"iat\":1001}", .HS256, .{ .HS256 = "secret" });
    defer allocator.free(token);

    try expectVerifyError(error.TokenIssuedInFuture, token, .HS256, .{ .HS256 = "secret" }, 1000, 0);
}

test "clock skew leeway is applied to exp nbf and iat" {
    const allocator = std.testing.allocator;
    const token = try sign(
        allocator,
        "{\"sub\":\"alice\",\"exp\":995,\"nbf\":1005,\"iat\":1005}",
        .HS256,
        .{ .HS256 = "secret" },
    );
    defer allocator.free(token);

    const got = try verifyAt(allocator, token, .HS256, .{ .HS256 = "secret" }, 1000, 5);
    defer allocator.free(got);
    try std.testing.expectEqualStrings("{\"sub\":\"alice\",\"exp\":995,\"nbf\":1005,\"iat\":1005}", got);
}

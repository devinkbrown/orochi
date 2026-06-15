//! Minimal signed-JWT verifier for SASL OAUTHBEARER.
//!
//! This module is daemon glue: it validates compact JWS tokens with locally
//! configured keys and exposes the result as a mechrouter callback. No network
//! introspection, discovery, or pseudo-service identity is involved.
const std = @import("std");

const mechrouter = @import("../proto/sasl_mechrouter.zig");
const jwt = @import("../crypto/jwt.zig");
const rsa_verify = @import("../crypto/rsa_verify.zig");
const ecdsa_p256 = @import("../crypto/ecdsa_p256.zig");
const x509 = @import("../crypto/x509.zig");
const platform = @import("../substrate/platform.zig");

const HmacSha256 = std.crypto.auth.hmac.Hmac(std.crypto.hash.sha2.Sha256);

pub const VerifyError = error{
    InvalidToken,
    InvalidJson,
    InvalidAlgorithm,
    InvalidSignature,
    InvalidClaims,
    TokenExpired,
    IssuerMismatch,
    AudienceMismatch,
    AuthzidMismatch,
    UnsupportedKey,
    NoSpaceLeft,
};

pub const Key = union(enum) {
    hs256: []const u8,
    rs256: rsa_verify.PublicKey,
    es256: ecdsa_p256.PublicKey,

    fn alg(self: Key) []const u8 {
        return switch (self) {
            .hs256 => "HS256",
            .rs256 => "RS256",
            .es256 => "ES256",
        };
    }
};

pub const OwnedKey = struct {
    allocator: std.mem.Allocator,
    key: Key,
    owned_a: ?[]u8 = null,
    owned_b: ?[]u8 = null,

    pub fn fromJwks(allocator: std.mem.Allocator, json: []const u8) !OwnedKey {
        var parsed = std.json.parseFromSlice(std.json.Value, allocator, json, .{}) catch return error.InvalidJson;
        defer parsed.deinit();

        if (parsed.value != .object) return error.InvalidJson;
        if (parsed.value.object.get("keys")) |keys_value| {
            if (keys_value != .array) return error.InvalidJson;
            for (keys_value.array.items) |item| {
                if (fromJwkValue(allocator, item)) |owned| return owned else |_| {}
            }
            return error.UnsupportedKey;
        }
        return fromJwkValue(allocator, parsed.value);
    }

    pub fn fromPubkey(allocator: std.mem.Allocator, text: []const u8) !OwnedKey {
        const trimmed = std.mem.trim(u8, text, " \t\r\n");
        if (trimmed.len == 0) return error.InvalidJson;
        if (trimmed[0] == '{') return fromJwks(allocator, trimmed);

        const der = decodeBase64AnyAlloc(allocator, trimmed) catch return error.InvalidJson;
        defer allocator.free(der);
        const extracted = x509.extractPublicKey(der) catch return error.UnsupportedKey;
        return switch (extracted) {
            .rsa => |rsa| blk: {
                const n = try allocator.dupe(u8, rsa.modulus);
                errdefer allocator.free(n);
                const e = try allocator.dupe(u8, rsa.exponent);
                break :blk .{
                    .allocator = allocator,
                    .key = .{ .rs256 = .{ .n = n, .e = e } },
                    .owned_a = n,
                    .owned_b = e,
                };
            },
            .ecdsa_p256 => |sec1| .{
                .allocator = allocator,
                .key = .{ .es256 = try ecdsa_p256.parsePublicKeySec1(sec1) },
            },
            .ed25519 => error.UnsupportedKey,
        };
    }

    pub fn deinit(self: *OwnedKey) void {
        if (self.owned_a) |bytes| self.allocator.free(bytes);
        if (self.owned_b) |bytes| self.allocator.free(bytes);
        self.* = undefined;
    }
};

pub const Verifier = struct {
    key: Key,
    issuer: ?[]const u8 = null,
    audience: ?[]const u8 = null,
    account_claim: []const u8 = "sub",
    nowFn: ?*const fn () i64 = null,

    pub fn lookup(self: *Verifier) mechrouter.OAuthBearerLookup {
        return .{ .ptr = self, .verifyFn = verifyThunk };
    }

    fn verifyThunk(ptr: *anyopaque, token: []const u8, authzid: ?[]const u8, account_out: []u8) ?[]const u8 {
        const self: *Verifier = @ptrCast(@alignCast(ptr));
        return self.verify(token, authzid, account_out) catch null;
    }

    pub fn verify(self: *const Verifier, token: []const u8, authzid: ?[]const u8, account_out: []u8) VerifyError![]const u8 {
        var backing: [20 * 1024]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&backing);
        const allocator = fba.allocator();
        const parts = try splitToken(token);
        const header_json = jwt.base64UrlDecodeAlloc(allocator, parts.header) catch return error.InvalidToken;
        const payload_json = jwt.base64UrlDecodeAlloc(allocator, parts.payload) catch return error.InvalidToken;
        const signature = jwt.base64UrlDecodeAlloc(allocator, parts.signature) catch return error.InvalidToken;

        if (!try headerAlgorithmMatches(allocator, header_json, self.key.alg())) return error.InvalidAlgorithm;
        try verifySignature(self.key, token[0..parts.payload_end], signature);
        return try self.claimAccount(allocator, payload_json, authzid, account_out);
    }

    fn claimAccount(
        self: *const Verifier,
        allocator: std.mem.Allocator,
        payload_json: []const u8,
        authzid: ?[]const u8,
        account_out: []u8,
    ) VerifyError![]const u8 {
        var parsed = std.json.parseFromSlice(std.json.Value, allocator, payload_json, .{}) catch return error.InvalidJson;
        defer parsed.deinit();
        if (parsed.value != .object) return error.InvalidClaims;
        const obj = parsed.value.object;

        const exp_value = obj.get("exp") orelse return error.InvalidClaims;
        const exp = try intDate(exp_value);
        const now = if (self.nowFn) |func| func() else @divTrunc(platform.realtimeMillis(), 1000);
        if (now > exp) return error.TokenExpired;

        if (self.issuer) |issuer| {
            const iss = obj.get("iss") orelse return error.IssuerMismatch;
            if (iss != .string or !std.mem.eql(u8, iss.string, issuer)) return error.IssuerMismatch;
        }
        if (self.audience) |audience| {
            const aud = obj.get("aud") orelse return error.AudienceMismatch;
            if (!audienceMatches(aud, audience)) return error.AudienceMismatch;
        }

        const claim = obj.get(self.account_claim) orelse return error.InvalidClaims;
        if (claim != .string or claim.string.len == 0 or claim.string.len > account_out.len) return error.InvalidClaims;
        if (authzid) |zid| {
            if (!std.mem.eql(u8, zid, claim.string)) return error.AuthzidMismatch;
        }
        @memcpy(account_out[0..claim.string.len], claim.string);
        return account_out[0..claim.string.len];
    }
};

const TokenParts = struct {
    header: []const u8,
    payload: []const u8,
    signature: []const u8,
    payload_end: usize,
};

fn splitToken(token: []const u8) VerifyError!TokenParts {
    const first = std.mem.indexOfScalar(u8, token, '.') orelse return error.InvalidToken;
    const second_rel = std.mem.indexOfScalar(u8, token[first + 1 ..], '.') orelse return error.InvalidToken;
    const second = first + 1 + second_rel;
    if (first == 0 or second == first + 1 or second == token.len - 1) return error.InvalidToken;
    if (std.mem.indexOfScalar(u8, token[second + 1 ..], '.') != null) return error.InvalidToken;
    return .{
        .header = token[0..first],
        .payload = token[first + 1 .. second],
        .signature = token[second + 1 ..],
        .payload_end = second,
    };
}

fn headerAlgorithmMatches(allocator: std.mem.Allocator, header_json: []const u8, expected: []const u8) VerifyError!bool {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, header_json, .{}) catch return error.InvalidJson;
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidJson;
    const alg = parsed.value.object.get("alg") orelse return error.InvalidAlgorithm;
    if (alg != .string or std.mem.eql(u8, alg.string, "none")) return error.InvalidAlgorithm;
    return std.mem.eql(u8, alg.string, expected);
}

fn verifySignature(key: Key, signed_input: []const u8, signature: []const u8) VerifyError!void {
    switch (key) {
        .hs256 => |secret| {
            if (signature.len != HmacSha256.mac_length) return error.InvalidSignature;
            var expected: [HmacSha256.mac_length]u8 = undefined;
            HmacSha256.create(&expected, signed_input, secret);
            var got: [HmacSha256.mac_length]u8 = undefined;
            @memcpy(&got, signature);
            if (!std.crypto.timing_safe.eql([HmacSha256.mac_length]u8, expected, got)) return error.InvalidSignature;
        },
        .rs256 => |public_key| {
            var digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(signed_input, &digest, .{});
            if (!rsa_verify.verifyPkcs1v15(public_key, .sha256, &digest, signature)) return error.InvalidSignature;
        },
        .es256 => |public_key| {
            if (signature.len != ecdsa_p256.raw_signature_length) return error.InvalidSignature;
            const sig = ecdsa_p256.Signature.fromBytes(signature[0..ecdsa_p256.raw_signature_length].*);
            if (!ecdsa_p256.verify(sig, signed_input, public_key)) return error.InvalidSignature;
        },
    }
}

fn intDate(value: std.json.Value) VerifyError!i64 {
    return switch (value) {
        .integer => |n| n,
        .number_string => |s| std.fmt.parseInt(i64, s, 10) catch return error.InvalidClaims,
        else => error.InvalidClaims,
    };
}

fn audienceMatches(value: std.json.Value, audience: []const u8) bool {
    return switch (value) {
        .string => |s| std.mem.eql(u8, s, audience),
        .array => |arr| blk: {
            for (arr.items) |item| {
                if (item == .string and std.mem.eql(u8, item.string, audience)) break :blk true;
            }
            break :blk false;
        },
        else => false,
    };
}

fn fromJwkValue(allocator: std.mem.Allocator, value: std.json.Value) !OwnedKey {
    if (value != .object) return error.InvalidJson;
    const obj = value.object;
    const kty = obj.get("kty") orelse return error.UnsupportedKey;
    if (kty != .string) return error.UnsupportedKey;

    if (std.mem.eql(u8, kty.string, "RSA")) {
        const n_text = jsonString(obj, "n") orelse return error.UnsupportedKey;
        const e_text = jsonString(obj, "e") orelse return error.UnsupportedKey;
        const n = jwt.base64UrlDecodeAlloc(allocator, n_text) catch return error.UnsupportedKey;
        errdefer allocator.free(n);
        const e = jwt.base64UrlDecodeAlloc(allocator, e_text) catch return error.UnsupportedKey;
        return .{
            .allocator = allocator,
            .key = .{ .rs256 = .{ .n = n, .e = e } },
            .owned_a = n,
            .owned_b = e,
        };
    }
    if (std.mem.eql(u8, kty.string, "EC")) {
        const crv = jsonString(obj, "crv") orelse return error.UnsupportedKey;
        if (!std.mem.eql(u8, crv, "P-256")) return error.UnsupportedKey;
        const x_text = jsonString(obj, "x") orelse return error.UnsupportedKey;
        const y_text = jsonString(obj, "y") orelse return error.UnsupportedKey;
        const x = jwt.base64UrlDecodeAlloc(allocator, x_text) catch return error.UnsupportedKey;
        defer allocator.free(x);
        const y = jwt.base64UrlDecodeAlloc(allocator, y_text) catch return error.UnsupportedKey;
        defer allocator.free(y);
        if (x.len != 32 or y.len != 32) return error.UnsupportedKey;
        var sec1: [ecdsa_p256.sec1_uncompressed_length]u8 = undefined;
        sec1[0] = 0x04;
        @memcpy(sec1[1..33], x);
        @memcpy(sec1[33..65], y);
        return .{
            .allocator = allocator,
            .key = .{ .es256 = try ecdsa_p256.parsePublicKeySec1(&sec1) },
        };
    }
    return error.UnsupportedKey;
}

fn jsonString(obj: std.json.ObjectMap, name: []const u8) ?[]const u8 {
    const value = obj.get(name) orelse return null;
    if (value != .string) return null;
    return value.string;
}

fn decodeBase64AnyAlloc(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    if (jwt.base64UrlDecodeAlloc(allocator, text)) |bytes| return bytes else |_| {}
    const decoder = std.base64.standard.decoderWithIgnore(" \t\r\n");
    const out = try allocator.alloc(u8, decoder.calcSizeUpperBound(text.len));
    errdefer allocator.free(out);
    const written = try decoder.decode(out, text);
    return out[0..written];
}

fn fixedNow() i64 {
    return 1_000;
}

test "HS256 OAuth verifier accepts issuer audience and subject" {
    const allocator = std.testing.allocator;
    const claims = "{\"iss\":\"issuer-a\",\"aud\":\"orochi\",\"sub\":\"alice\",\"exp\":1100}";
    const token = try jwt.sign(allocator, claims, .HS256, .{ .HS256 = "secret" });
    defer allocator.free(token);

    var verifier = Verifier{
        .key = .{ .hs256 = "secret" },
        .issuer = "issuer-a",
        .audience = "orochi",
        .account_claim = "sub",
        .nowFn = fixedNow,
    };
    var out: [64]u8 = undefined;
    const account = try verifier.verify(token, null, &out);
    try std.testing.expectEqualStrings("alice", account);

    var wrong = Verifier{
        .key = .{ .hs256 = "wrong" },
        .issuer = "issuer-a",
        .audience = "orochi",
        .account_claim = "sub",
        .nowFn = fixedNow,
    };
    try std.testing.expectError(error.InvalidSignature, wrong.verify(token, null, &out));
}

test "OAuth verifier rejects expired and mismatched audience tokens" {
    const allocator = std.testing.allocator;
    const expired = try jwt.sign(allocator, "{\"iss\":\"issuer-a\",\"aud\":\"orochi\",\"sub\":\"alice\",\"exp\":999}", .HS256, .{ .HS256 = "secret" });
    defer allocator.free(expired);
    const wrong_aud = try jwt.sign(allocator, "{\"iss\":\"issuer-a\",\"aud\":\"other\",\"sub\":\"alice\",\"exp\":1100}", .HS256, .{ .HS256 = "secret" });
    defer allocator.free(wrong_aud);

    var verifier = Verifier{
        .key = .{ .hs256 = "secret" },
        .issuer = "issuer-a",
        .audience = "orochi",
        .account_claim = "sub",
        .nowFn = fixedNow,
    };
    var out: [64]u8 = undefined;
    try std.testing.expectError(error.TokenExpired, verifier.verify(expired, null, &out));
    try std.testing.expectError(error.AudienceMismatch, verifier.verify(wrong_aud, null, &out));
}

test "JWKS EC key parses and verifies ES256 token" {
    const allocator = std.testing.allocator;
    const kp = ecdsa_p256.KeyPair.generate(std.testing.io);
    const pub_sec1 = kp.public_key.toUncompressedSec1();
    const x = try jwt.base64UrlEncodeAlloc(allocator, pub_sec1[1..33]);
    defer allocator.free(x);
    const y = try jwt.base64UrlEncodeAlloc(allocator, pub_sec1[33..65]);
    defer allocator.free(y);
    const jwks = try std.fmt.allocPrint(allocator, "{{\"keys\":[{{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"{s}\",\"y\":\"{s}\"}}]}}", .{ x, y });
    defer allocator.free(jwks);
    var owned = try OwnedKey.fromJwks(allocator, jwks);
    defer owned.deinit();

    const header = try jwt.base64UrlEncodeAlloc(allocator, "{\"alg\":\"ES256\",\"typ\":\"JWT\"}");
    defer allocator.free(header);
    const payload = try jwt.base64UrlEncodeAlloc(allocator, "{\"iss\":\"issuer-a\",\"aud\":[\"other\",\"orochi\"],\"sub\":\"alice\",\"exp\":1100}");
    defer allocator.free(payload);
    const signing_input = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ header, payload });
    defer allocator.free(signing_input);
    const sig = try ecdsa_p256.sign(signing_input, kp);
    const sig_bytes = sig.toBytes();
    const sig_b64 = try jwt.base64UrlEncodeAlloc(allocator, &sig_bytes);
    defer allocator.free(sig_b64);
    const token = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ signing_input, sig_b64 });
    defer allocator.free(token);

    var verifier = Verifier{
        .key = owned.key,
        .issuer = "issuer-a",
        .audience = "orochi",
        .account_claim = "sub",
        .nowFn = fixedNow,
    };
    var out: [64]u8 = undefined;
    try std.testing.expectEqualStrings("alice", try verifier.verify(token, null, &out));
}

test {
    std.testing.refAllDecls(@This());
}

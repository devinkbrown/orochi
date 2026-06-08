//! HMAC-signed migration token for Helix S2S session migration.
//!
//! The token is intentionally compact and canonical: all integer fields are
//! little-endian and the authenticated bytes are exactly the serialized claims.
//! Verification returns slices into the caller-provided token blob; callers must
//! keep that blob alive while using the returned `Claims`.

const std = @import("std");
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub const max_account_len = 64;
pub const nonce_len = 16;
pub const tag_len = 32;
pub const fixed_claim_len = 2 + 8 + 8 + 8 + 8 + nonce_len;
pub const max_canonical_len = fixed_claim_len + max_account_len;

pub const Claims = struct {
    account: []const u8,
    source_node: u64,
    dest_node: u64,
    issued_ms: i64,
    expires_ms: i64,
    nonce: [nonce_len]u8,
};

pub const EncodeError = error{AccountTooLong} || std.mem.Allocator.Error;
pub const VerifyError = error{ BadTag, Expired, Truncated };

pub fn encodeClaims(allocator: std.mem.Allocator, claims: Claims) EncodeError![]u8 {
    if (claims.account.len > max_account_len) return error.AccountTooLong;

    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(allocator);

    try bytes.ensureTotalCapacity(allocator, canonicalLen(claims.account.len));
    appendU16(&bytes, @intCast(claims.account.len));
    try bytes.appendSlice(allocator, claims.account);
    appendU64(&bytes, claims.source_node);
    appendU64(&bytes, claims.dest_node);
    appendI64(&bytes, claims.issued_ms);
    appendI64(&bytes, claims.expires_ms);
    try bytes.appendSlice(allocator, &claims.nonce);

    return bytes.toOwnedSlice(allocator);
}

pub fn sign(key: []const u8, claims: Claims) [tag_len]u8 {
    std.debug.assert(claims.account.len <= max_account_len);

    var canonical: [max_canonical_len]u8 = undefined;
    const msg = writeCanonical(&canonical, claims);

    var tag: [tag_len]u8 = undefined;
    HmacSha256.create(&tag, msg, key);
    return tag;
}

pub fn verify(key: []const u8, token_blob: []const u8, now_ms: i64) VerifyError!Claims {
    const parsed = try parseCanonicalPrefix(token_blob);
    const canonical = token_blob[0..parsed.canonical_len];
    const supplied_tag = token_blob[parsed.canonical_len..][0..tag_len];

    var expected_tag: [tag_len]u8 = undefined;
    HmacSha256.create(&expected_tag, canonical, key);
    if (!std.crypto.timing_safe.eql([tag_len]u8, expected_tag, supplied_tag.*)) {
        return error.BadTag;
    }

    if (now_ms > parsed.claims.expires_ms) return error.Expired;
    return parsed.claims;
}

fn canonicalLen(account_len: usize) usize {
    return fixed_claim_len + account_len;
}

fn writeCanonical(buffer: *[max_canonical_len]u8, claims: Claims) []const u8 {
    var offset: usize = 0;
    std.mem.writeInt(u16, buffer[offset..][0..2], @intCast(claims.account.len), .little);
    offset += 2;
    @memcpy(buffer[offset..][0..claims.account.len], claims.account);
    offset += claims.account.len;
    std.mem.writeInt(u64, buffer[offset..][0..8], claims.source_node, .little);
    offset += 8;
    std.mem.writeInt(u64, buffer[offset..][0..8], claims.dest_node, .little);
    offset += 8;
    std.mem.writeInt(i64, buffer[offset..][0..8], claims.issued_ms, .little);
    offset += 8;
    std.mem.writeInt(i64, buffer[offset..][0..8], claims.expires_ms, .little);
    offset += 8;
    @memcpy(buffer[offset..][0..nonce_len], &claims.nonce);
    offset += nonce_len;
    return buffer[0..offset];
}

fn appendU16(bytes: *std.ArrayList(u8), value: u16) void {
    const start = bytes.items.len;
    bytes.items.len += 2;
    std.mem.writeInt(u16, bytes.items[start..][0..2], value, .little);
}

fn appendU64(bytes: *std.ArrayList(u8), value: u64) void {
    const start = bytes.items.len;
    bytes.items.len += 8;
    std.mem.writeInt(u64, bytes.items[start..][0..8], value, .little);
}

fn appendI64(bytes: *std.ArrayList(u8), value: i64) void {
    const start = bytes.items.len;
    bytes.items.len += 8;
    std.mem.writeInt(i64, bytes.items[start..][0..8], value, .little);
}

const Parsed = struct {
    claims: Claims,
    canonical_len: usize,
};

fn parseCanonicalPrefix(token_blob: []const u8) VerifyError!Parsed {
    if (token_blob.len < 2) return error.Truncated;

    const account_len = std.mem.readInt(u16, token_blob[0..2], .little);
    if (account_len > max_account_len) return error.Truncated;

    const claim_len = canonicalLen(account_len);
    if (token_blob.len < claim_len + tag_len) return error.Truncated;

    var offset: usize = 2;
    const account = token_blob[offset..][0..account_len];
    offset += account_len;
    const source_node = std.mem.readInt(u64, token_blob[offset..][0..8], .little);
    offset += 8;
    const dest_node = std.mem.readInt(u64, token_blob[offset..][0..8], .little);
    offset += 8;
    const issued_ms = std.mem.readInt(i64, token_blob[offset..][0..8], .little);
    offset += 8;
    const expires_ms = std.mem.readInt(i64, token_blob[offset..][0..8], .little);
    offset += 8;
    const nonce = token_blob[offset..][0..nonce_len].*;
    offset += nonce_len;

    return .{
        .claims = .{
            .account = account,
            .source_node = source_node,
            .dest_node = dest_node,
            .issued_ms = issued_ms,
            .expires_ms = expires_ms,
            .nonce = nonce,
        },
        .canonical_len = offset,
    };
}

fn makeClaims() Claims {
    return .{
        .account = "alice",
        .source_node = 0x1020_3040_5060_7080,
        .dest_node = 0x8877_6655_4433_2211,
        .issued_ms = 1_700_000_000_000,
        .expires_ms = 1_700_000_060_000,
        .nonce = .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    };
}

test "sign and verify roundtrip" {
    const allocator = std.testing.allocator;
    const key = "migration-key";
    const claims = makeClaims();

    const canonical = try encodeClaims(allocator, claims);
    defer allocator.free(canonical);

    var token: std.ArrayList(u8) = .empty;
    defer token.deinit(allocator);
    try token.appendSlice(allocator, canonical);
    try token.appendSlice(allocator, &sign(key, claims));

    const decoded = try verify(key, token.items, claims.issued_ms);
    try std.testing.expectEqualStrings(claims.account, decoded.account);
    try std.testing.expectEqual(claims.source_node, decoded.source_node);
    try std.testing.expectEqual(claims.dest_node, decoded.dest_node);
    try std.testing.expectEqual(claims.issued_ms, decoded.issued_ms);
    try std.testing.expectEqual(claims.expires_ms, decoded.expires_ms);
    try std.testing.expectEqualSlices(u8, &claims.nonce, &decoded.nonce);
}

test "tampered byte is rejected with BadTag" {
    const allocator = std.testing.allocator;
    const key = "migration-key";
    const claims = makeClaims();

    const canonical = try encodeClaims(allocator, claims);
    defer allocator.free(canonical);

    var token: std.ArrayList(u8) = .empty;
    defer token.deinit(allocator);
    try token.appendSlice(allocator, canonical);
    try token.appendSlice(allocator, &sign(key, claims));

    token.items[3] ^= 0xff;
    try std.testing.expectError(error.BadTag, verify(key, token.items, claims.issued_ms));
}

test "expired token is rejected after tag validation" {
    const allocator = std.testing.allocator;
    const key = "migration-key";
    const claims = makeClaims();

    const canonical = try encodeClaims(allocator, claims);
    defer allocator.free(canonical);

    var token: std.ArrayList(u8) = .empty;
    defer token.deinit(allocator);
    try token.appendSlice(allocator, canonical);
    try token.appendSlice(allocator, &sign(key, claims));

    try std.testing.expectError(error.Expired, verify(key, token.items, claims.expires_ms + 1));
}

test "truncated tokens are rejected" {
    const allocator = std.testing.allocator;
    const key = "migration-key";
    const claims = makeClaims();

    const canonical = try encodeClaims(allocator, claims);
    defer allocator.free(canonical);

    var token: std.ArrayList(u8) = .empty;
    defer token.deinit(allocator);
    try token.appendSlice(allocator, canonical);
    try token.appendSlice(allocator, &sign(key, claims));

    try std.testing.expectError(error.Truncated, verify(key, token.items[0..0], claims.issued_ms));
    try std.testing.expectError(error.Truncated, verify(key, token.items[0..1], claims.issued_ms));
    try std.testing.expectError(error.Truncated, verify(key, token.items[0 .. token.items.len - 1], claims.issued_ms));
}

test "canonical encoding uses little endian fields" {
    const allocator = std.testing.allocator;
    const claims: Claims = .{
        .account = "xy",
        .source_node = 0x0102_0304_0506_0708,
        .dest_node = 0x1112_1314_1516_1718,
        .issued_ms = -2,
        .expires_ms = 0x0102_0304_0506_0708,
        .nonce = .{ 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 },
    };

    const canonical = try encodeClaims(allocator, claims);
    defer allocator.free(canonical);

    try std.testing.expectEqual(@as(usize, canonicalLen(2)), canonical.len);
    try std.testing.expectEqualSlices(u8, &.{ 2, 0 }, canonical[0..2]);
    try std.testing.expectEqualStrings("xy", canonical[2..4]);
    try std.testing.expectEqualSlices(u8, &.{ 8, 7, 6, 5, 4, 3, 2, 1 }, canonical[4..12]);
    try std.testing.expectEqualSlices(u8, &.{ 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, canonical[20..28]);
}

test "account length above limit is rejected by encoder" {
    const allocator = std.testing.allocator;
    const long_account = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    var claims = makeClaims();
    claims.account = long_account;

    try std.testing.expectError(error.AccountTooLong, encodeClaims(allocator, claims));
}

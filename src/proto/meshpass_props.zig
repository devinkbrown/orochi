// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Property and fuzz tests for MeshPass admission tokens.
//!
//! MeshPass tokens are Ed25519-signed capability envelopes. These tests keep
//! the generated cases deterministic and bounded while stressing the security
//! boundary: trusted roots verify, untrusted or tampered material fails closed,
//! arbitrary decoder input produces values or typed errors, and canonical
//! encode/decode preserves every public field.
const std = @import("std");
const meshpass = @import("meshpass.zig");

const Ed25519 = std.crypto.sign.Ed25519;

const seed: u64 = 0x6d_65_73_68_70_61_73_73;
const decoder_fuzz_iterations = 256;
const round_trip_iterations = 128;

const Range = struct {
    start: usize,
    end: usize,
};

const TokenRanges = struct {
    signed: Range,
    signature: Range,
};

fn expectDecodeError(err: meshpass.DecodeError) void {
    switch (err) {
        error.Truncated,
        error.VarintTooLong,
        error.VarintOverflow,
        error.NonCanonicalVarint,
        error.LengthTooLarge,
        error.InvalidBool,
        error.InvalidSchema,
        error.InvalidFieldBitmap,
        error.InvalidPublicKeyLen,
        error.InvalidSignatureLen,
        error.InvalidRealm,
        error.InvalidTime,
        error.TrailingBytes,
        error.ValueTooLarge,
        => {},
    }
}

fn fixedKey(byte: u8) !Ed25519.KeyPair {
    return Ed25519.KeyPair.generateDeterministic([_]u8{byte} ** 32);
}

fn randomKey(random: std.Random) !Ed25519.KeyPair {
    var key_seed: [Ed25519.KeyPair.seed_length]u8 = undefined;
    random.bytes(&key_seed);
    return Ed25519.KeyPair.generateDeterministic(key_seed);
}

fn baseFields(node_pubkey: meshpass.PublicKeyBytes, realm: []const u8) meshpass.Fields {
    return .{
        .node_pubkey = node_pubkey,
        .realm = realm,
        .roles = meshpass.roles(&.{ .operator, .relay, .media }),
        .issued_ms = 1_000,
        .expiry_ms = 10_000,
        .allowed_frame_families = meshpass.frameFamilies(&.{ .control, .sync, .irc_app, .tsumugi }),
        .max_fanout = 16,
        .media_rights = meshpass.mediaRights(&.{ .voice, .video, .data }),
        .revocation_epoch = 7,
    };
}

fn randomFields(
    random: std.Random,
    node_pubkey: meshpass.PublicKeyBytes,
    realm_storage: *[meshpass.max_realm_len]u8,
    iteration: usize,
) meshpass.Fields {
    const realm_len = switch (iteration % 11) {
        0 => 1,
        1 => meshpass.default_realm.len,
        2 => 127,
        3 => 128,
        4 => meshpass.max_realm_len,
        else => random.intRangeAtMost(usize, 1, meshpass.max_realm_len),
    };
    random.bytes(realm_storage[0..realm_len]);
    if (iteration % 11 == 1) {
        @memcpy(realm_storage[0..meshpass.default_realm.len], meshpass.default_realm);
    }

    const issued = random.intRangeAtMost(u64, 0, 1_000_000_000);
    const lifetime = random.intRangeAtMost(u64, 0, 5_000_000);
    return .{
        .node_pubkey = node_pubkey,
        .realm = realm_storage[0..realm_len],
        .roles = random.int(u64),
        .issued_ms = issued,
        .expiry_ms = issued + lifetime,
        .allowed_frame_families = random.int(u32),
        .max_fanout = random.int(u32),
        .media_rights = random.int(u32),
        .revocation_epoch = random.int(u64),
    };
}

fn expectFieldsEqual(expected: meshpass.Fields, actual: meshpass.Fields) !void {
    try std.testing.expectEqualSlices(u8, &expected.node_pubkey, &actual.node_pubkey);
    try std.testing.expectEqualSlices(u8, expected.realm, actual.realm);
    try std.testing.expectEqual(expected.roles, actual.roles);
    try std.testing.expectEqual(expected.issued_ms, actual.issued_ms);
    try std.testing.expectEqual(expected.expiry_ms, actual.expiry_ms);
    try std.testing.expectEqual(expected.allowed_frame_families, actual.allowed_frame_families);
    try std.testing.expectEqual(expected.max_fanout, actual.max_fanout);
    try std.testing.expectEqual(expected.media_rights, actual.media_rights);
    try std.testing.expectEqual(expected.revocation_epoch, actual.revocation_epoch);
}

fn expectTokenEqual(expected: meshpass.Token, actual: meshpass.Token) !void {
    try expectFieldsEqual(expected.fields, actual.fields);
    try std.testing.expectEqualSlices(u8, &expected.signature, &actual.signature);
}

fn readVarint(input: []const u8, pos: *usize) !u64 {
    var value: u64 = 0;
    var shift: u6 = 0;

    var i: usize = 0;
    while (i < 10) : (i += 1) {
        try std.testing.expect(pos.* < input.len);
        const byte = input[pos.*];
        pos.* += 1;

        const payload = byte & 0x7f;
        value |= @as(u64, payload) << shift;
        if ((byte & 0x80) == 0) return value;
        shift += 7;
    }

    return error.TestVarintTooLong;
}

fn readBytesRange(input: []const u8, pos: *usize) !Range {
    const len64 = try readVarint(input, pos);
    try std.testing.expect(len64 <= std.math.maxInt(usize));
    const len: usize = @intCast(len64);
    try std.testing.expect(pos.* + len <= input.len);
    const start = pos.*;
    pos.* += len;
    return .{ .start = start, .end = pos.* };
}

fn tokenRanges(encoded: []const u8) !TokenRanges {
    var pos: usize = 0;
    _ = try readVarint(encoded, &pos);
    _ = try readVarint(encoded, &pos);
    const signed = try readBytesRange(encoded, &pos);
    const signature = try readBytesRange(encoded, &pos);
    try std.testing.expectEqual(encoded.len, pos);
    try std.testing.expectEqual(meshpass.signature_len, signature.end - signature.start);
    return .{ .signed = signed, .signature = signature };
}

fn appendByte(out: []u8, pos: *usize, byte: u8) !void {
    try std.testing.expect(pos.* < out.len);
    out[pos.*] = byte;
    pos.* += 1;
}

fn appendVarint(out: []u8, pos: *usize, value: u64) !void {
    var n = value;
    while (n >= 0x80) {
        try appendByte(out, pos, @as(u8, @intCast(n & 0x7f)) | 0x80);
        n >>= 7;
    }
    try appendByte(out, pos, @intCast(n));
}

fn appendBytes(out: []u8, pos: *usize, bytes: []const u8) !void {
    try appendVarint(out, pos, bytes.len);
    try std.testing.expect(pos.* + bytes.len <= out.len);
    @memcpy(out[pos.* .. pos.* + bytes.len], bytes);
    pos.* += bytes.len;
}

fn appendSignedFieldsUnchecked(
    out: []u8,
    node_pubkey: meshpass.PublicKeyBytes,
    realm: []const u8,
) !usize {
    var pos: usize = 0;
    try appendVarint(out, &pos, 0x04_01);
    try appendVarint(out, &pos, (1 << 9) - 1);
    try appendBytes(out, &pos, &node_pubkey);
    try appendBytes(out, &pos, realm);
    try appendVarint(out, &pos, meshpass.roles(&.{.relay}));
    try appendVarint(out, &pos, 1_000);
    try appendVarint(out, &pos, 10_000);
    try appendVarint(out, &pos, meshpass.frameFamilies(&.{.sync}));
    try appendVarint(out, &pos, 4);
    try appendVarint(out, &pos, meshpass.mediaRights(&.{.voice}));
    try appendVarint(out, &pos, 0);
    return pos;
}

fn fillAdversarial(random: std.Random, buf: []u8, iteration: usize) void {
    random.bytes(buf);
    const pattern = [_]u8{
        0x00, 0x01, 0x02, 0x7f, 0x80, 0x81, 0xff,
        '\r', '\n', ' ',  ',',  ':',  0xc2, 0xa9,
        0xe2, 0x82, 0xac, 0xf0, 0x9f, 0x92, 0xa9,
    };
    for (pattern, 0..) |byte, i| {
        if (buf.len == 0) break;
        buf[(iteration * 37 + i * 19) % buf.len] = byte;
    }
}

fn expectDecodeOkOrTypedError(input: []const u8) !void {
    const decoded = meshpass.decode(input) catch |err| {
        expectDecodeError(err);
        return;
    };

    try std.testing.expect(decoded.fields.realm.len > 0);
    try std.testing.expect(decoded.fields.realm.len <= meshpass.max_realm_len);
    try std.testing.expect(decoded.fields.issued_ms <= decoded.fields.expiry_ms);

    var encoded: [meshpass.max_token_len]u8 = undefined;
    const written = try meshpass.encode(&encoded, decoded);
    try std.testing.expect(written <= meshpass.max_token_len);

    const reparsed = try meshpass.decode(encoded[0..written]);
    try expectTokenEqual(decoded, reparsed);
}

test "trusted roots verify while untrusted roots and realm mismatches are rejected" {
    const issuer = try fixedKey(0x11);
    const untrusted = try fixedKey(0x12);
    const node = try fixedKey(0x21);

    const fields = baseFields(node.public_key.toBytes(), meshpass.default_realm);
    const token = try meshpass.issue(issuer, fields);

    const trusted_root = meshpass.TrustRoot{
        .public_key = issuer.public_key.toBytes(),
        .realm = meshpass.default_realm,
        .min_revocation_epoch = fields.revocation_epoch,
    };
    try meshpass.verify(token, trusted_root, 2_000);

    try std.testing.expectError(error.BadSig, meshpass.verify(token, untrusted.public_key.toBytes(), 2_000));

    const wrong_realm_root = meshpass.TrustRoot{
        .public_key = issuer.public_key.toBytes(),
        .realm = "suimyaku-other",
    };
    try std.testing.expectError(error.WrongRealm, meshpass.verify(token, wrong_realm_root, 2_000));
}

test "every single-bit flip in signed body or signature fails closed" {
    const issuer = try fixedKey(0x31);
    const node = try fixedKey(0x32);

    var max_realm: [meshpass.max_realm_len]u8 = undefined;
    @memset(&max_realm, 'r');
    const fields = baseFields(node.public_key.toBytes(), &max_realm);
    const token = try meshpass.issue(issuer, fields);
    const root = meshpass.TrustRoot{
        .public_key = issuer.public_key.toBytes(),
        .realm = &max_realm,
    };
    try meshpass.verify(token, root, 2_000);

    var encoded: [meshpass.max_token_len]u8 = undefined;
    const encoded_len = try meshpass.encode(&encoded, token);
    const ranges = try tokenRanges(encoded[0..encoded_len]);

    var bit_index: usize = 0;
    while (bit_index < (ranges.signed.end - ranges.signed.start) * 8) : (bit_index += 1) {
        var tampered = encoded;
        const byte_index = ranges.signed.start + bit_index / 8;
        tampered[byte_index] ^= @as(u8, 1) << @intCast(bit_index % 8);

        const decoded = meshpass.decode(tampered[0..encoded_len]) catch |err| {
            expectDecodeError(err);
            continue;
        };
        try std.testing.expectError(error.BadSig, meshpass.verify(decoded, root, 2_000));
    }

    bit_index = 0;
    while (bit_index < meshpass.signature_len * 8) : (bit_index += 1) {
        var tampered = encoded;
        const byte_index = ranges.signature.start + bit_index / 8;
        tampered[byte_index] ^= @as(u8, 1) << @intCast(bit_index % 8);

        const decoded = meshpass.decode(tampered[0..encoded_len]) catch |err| {
            expectDecodeError(err);
            continue;
        };
        try std.testing.expectError(error.BadSig, meshpass.verify(decoded, root, 2_000));
    }
}

test "expired and invalid validity windows fail closed" {
    const issuer = try fixedKey(0x41);
    const node = try fixedKey(0x42);

    const fields = baseFields(node.public_key.toBytes(), meshpass.default_realm);
    const token = try meshpass.issue(issuer, fields);
    try std.testing.expectError(error.Expired, meshpass.verify(token, issuer.public_key.toBytes(), fields.expiry_ms + 1));

    var invalid = fields;
    invalid.issued_ms = fields.expiry_ms + 1;
    try std.testing.expectError(error.InvalidTime, meshpass.issue(issuer, invalid));

    var invalid_signed: [meshpass.max_signed_len]u8 = undefined;
    try std.testing.expectError(error.InvalidTime, meshpass.encodeSignedFields(&invalid_signed, invalid));

    var unchecked: [meshpass.max_signed_len]u8 = undefined;
    var pos: usize = 0;
    try appendVarint(&unchecked, &pos, 0x04_01);
    try appendVarint(&unchecked, &pos, (1 << 9) - 1);
    try appendBytes(&unchecked, &pos, &invalid.node_pubkey);
    try appendBytes(&unchecked, &pos, invalid.realm);
    try appendVarint(&unchecked, &pos, invalid.roles);
    try appendVarint(&unchecked, &pos, invalid.issued_ms);
    try appendVarint(&unchecked, &pos, invalid.expiry_ms);
    try appendVarint(&unchecked, &pos, invalid.allowed_frame_families);
    try appendVarint(&unchecked, &pos, invalid.max_fanout);
    try appendVarint(&unchecked, &pos, invalid.media_rights);
    try appendVarint(&unchecked, &pos, invalid.revocation_epoch);
    try std.testing.expectError(error.InvalidTime, meshpass.decodeSignedFields(unchecked[0..pos]));
}

test "decoder accepts arbitrary bytes only as values or typed errors" {
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();

    var input: [meshpass.max_token_len + 64]u8 = undefined;
    var i: usize = 0;
    while (i < decoder_fuzz_iterations) : (i += 1) {
        const len = switch (i % 17) {
            0 => 0,
            1 => 1,
            2 => meshpass.max_token_len - 1,
            3 => meshpass.max_token_len,
            4 => meshpass.max_token_len + 1,
            else => random.intRangeAtMost(usize, 0, input.len),
        };
        fillAdversarial(random, input[0..len], i);
        try expectDecodeOkOrTypedError(input[0..len]);
    }
}

test "oversize realm and token inputs fail closed" {
    const issuer = try fixedKey(0x51);
    const node = try fixedKey(0x52);

    var oversize_realm: [meshpass.max_realm_len + 1]u8 = undefined;
    @memset(&oversize_realm, 'x');
    var signed: [meshpass.max_signed_len]u8 = undefined;
    const signed_len = try appendSignedFieldsUnchecked(&signed, node.public_key.toBytes(), &oversize_realm);
    try std.testing.expectError(error.InvalidRealm, meshpass.decodeSignedFields(signed[0..signed_len]));

    var fields = baseFields(node.public_key.toBytes(), meshpass.default_realm);
    fields.realm = meshpass.default_realm;
    const token = try meshpass.issue(issuer, fields);

    var encoded: [meshpass.max_token_len + 1]u8 = undefined;
    const encoded_len = try meshpass.encode(&encoded, token);
    try std.testing.expect(encoded_len < meshpass.max_token_len + 1);
    @memset(encoded[encoded_len..], 0xa5);
    try std.testing.expectError(error.TrailingBytes, meshpass.decode(encoded[0 .. meshpass.max_token_len + 1]));

    var too_long_fields = fields;
    too_long_fields.realm = &oversize_realm;
    try std.testing.expectError(error.InvalidRealm, meshpass.encode(&encoded, .{
        .fields = too_long_fields,
        .signature = token.signature,
    }));
}

test "encode decode round-trip preserves all fields and signatures" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0xa5a5_5a5a_1337_7331);
    const random = prng.random();

    var encoded: [meshpass.max_token_len]u8 = undefined;
    var canonical: [meshpass.max_token_len]u8 = undefined;

    var i: usize = 0;
    while (i < round_trip_iterations) : (i += 1) {
        const issuer = try randomKey(random);
        const node = try randomKey(random);

        var realm_storage: [meshpass.max_realm_len]u8 = undefined;
        const fields = randomFields(random, node.public_key.toBytes(), &realm_storage, i);
        const token = try meshpass.issue(issuer, fields);

        const encoded_len = try meshpass.encode(&encoded, token);
        try std.testing.expect(encoded_len <= meshpass.max_token_len);

        const decoded = try meshpass.decode(encoded[0..encoded_len]);
        try expectTokenEqual(token, decoded);
        const root = meshpass.TrustRoot{
            .public_key = issuer.public_key.toBytes(),
            .realm = decoded.fields.realm,
            .min_revocation_epoch = decoded.fields.revocation_epoch,
        };
        try meshpass.verify(decoded, root, decoded.fields.issued_ms);

        const canonical_len = try meshpass.encode(&canonical, decoded);
        try std.testing.expectEqual(encoded_len, canonical_len);
        try std.testing.expectEqualSlices(u8, encoded[0..encoded_len], canonical[0..canonical_len]);
    }
}

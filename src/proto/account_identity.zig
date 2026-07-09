// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Portable account identity assertions.
//!
//! A sovereign account key is an Ed25519 public key plus a self-signature over
//! the account binding. The daemon does not mint user keys; it verifies that the
//! presented key controls its own account assertion, then stores the bounded
//! public metadata as user PROP facts that ride ENTITY_PROP replication.
const std = @import("std");

const Ed25519 = std.crypto.sign.Ed25519;

pub const prop_prefix = "identity.key.";
pub const max_label_len: usize = 32;
pub const public_key_len: usize = Ed25519.PublicKey.encoded_length;
pub const signature_len: usize = Ed25519.Signature.encoded_length;
pub const public_key_hex_len: usize = public_key_len * 2;
pub const signature_hex_len: usize = signature_len * 2;
pub const max_value_len: usize = public_key_hex_len + 1 + signature_hex_len;
pub const max_account_len: usize = 64;
pub const max_transcript_len: usize = transcript_domain.len + 1 + max_account_len + 1 + max_label_len + 1 + public_key_len;

const transcript_domain = "OROCHI-ACCOUNT-IDENTITY-v1";

pub const Claim = struct {
    public_key: [public_key_len]u8,
    signature: [signature_len]u8,
};

pub fn validLabel(raw: []const u8) bool {
    if (raw.len == 0 or raw.len > max_label_len) return false;
    for (raw) |byte| switch (byte) {
        'a'...'z', 'A'...'Z', '0'...'9', '_', '-', '.' => {},
        else => return false,
    };
    return true;
}

fn decodeHex(comptime len: usize, raw: []const u8) ?[len / 2]u8 {
    if (raw.len != len) return null;
    var out: [len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, raw) catch return null;
    return out;
}

pub fn parsePublicKeyHex(raw: []const u8) ?[public_key_len]u8 {
    return decodeHex(public_key_hex_len, raw);
}

pub fn parseSignatureHex(raw: []const u8) ?[signature_len]u8 {
    return decodeHex(signature_hex_len, raw);
}

pub fn transcript(account: []const u8, label: []const u8, public_key: [public_key_len]u8, out: []u8) ?[]const u8 {
    if (account.len == 0 or account.len > max_account_len or !validLabel(label)) return null;
    const need = transcript_domain.len + 1 + account.len + 1 + label.len + 1 + public_key.len;
    if (need > out.len) return null;
    var off: usize = 0;
    @memcpy(out[off..][0..transcript_domain.len], transcript_domain);
    off += transcript_domain.len;
    out[off] = 0;
    off += 1;
    @memcpy(out[off..][0..account.len], account);
    off += account.len;
    out[off] = 0;
    off += 1;
    @memcpy(out[off..][0..label.len], label);
    off += label.len;
    out[off] = 0;
    off += 1;
    @memcpy(out[off..][0..public_key.len], &public_key);
    off += public_key.len;
    return out[0..off];
}

pub fn verifyClaim(account: []const u8, label: []const u8, public_key_hex: []const u8, signature_hex: []const u8) bool {
    const public_key = parsePublicKeyHex(public_key_hex) orelse return false;
    const signature = parseSignatureHex(signature_hex) orelse return false;
    const pk = Ed25519.PublicKey.fromBytes(public_key) catch return false;
    const sig = Ed25519.Signature.fromBytes(signature);
    var transcript_buf: [max_transcript_len]u8 = undefined;
    const msg = transcript(account, label, public_key, &transcript_buf) orelse return false;
    sig.verifyStrict(msg, pk) catch return false;
    return true;
}

pub fn propKey(label: []const u8, out: []u8) ?[]const u8 {
    if (!validLabel(label)) return null;
    if (prop_prefix.len + label.len > out.len) return null;
    @memcpy(out[0..prop_prefix.len], prop_prefix);
    @memcpy(out[prop_prefix.len..][0..label.len], label);
    return out[0 .. prop_prefix.len + label.len];
}

pub fn isPropKey(key: []const u8) bool {
    return std.mem.startsWith(u8, key, prop_prefix) and validLabel(key[prop_prefix.len..]);
}

pub fn claimValue(public_key_hex: []const u8, signature_hex: []const u8, out: []u8) ?[]const u8 {
    const public_key = parsePublicKeyHex(public_key_hex) orelse return null;
    const signature = parseSignatureHex(signature_hex) orelse return null;
    if (max_value_len > out.len) return null;
    const public_hex = std.fmt.bytesToHex(public_key, .lower);
    const sig_hex = std.fmt.bytesToHex(signature, .lower);
    @memcpy(out[0..public_key_hex_len], &public_hex);
    out[public_key_hex_len] = ':';
    @memcpy(out[public_key_hex_len + 1 ..][0..signature_hex_len], &sig_hex);
    return out[0..max_value_len];
}

pub fn parseClaimValue(value: []const u8) ?Claim {
    if (value.len != max_value_len or value[public_key_hex_len] != ':') return null;
    return .{
        .public_key = parsePublicKeyHex(value[0..public_key_hex_len]) orelse return null,
        .signature = parseSignatureHex(value[public_key_hex_len + 1 ..]) orelse return null,
    };
}

test "account identity claim validates self-signed account binding" {
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x41)));
    const public_hex = std.fmt.bytesToHex(kp.public_key.toBytes(), .lower);
    var transcript_buf: [max_transcript_len]u8 = undefined;
    const msg = transcript("alice", "primary", kp.public_key.toBytes(), &transcript_buf).?;
    const sig = try kp.sign(msg, null);
    const sig_hex = std.fmt.bytesToHex(sig.toBytes(), .lower);

    try std.testing.expect(verifyClaim("alice", "primary", &public_hex, &sig_hex));
    try std.testing.expect(!verifyClaim("alice", "laptop", &public_hex, &sig_hex));
    try std.testing.expect(!verifyClaim("bob", "primary", &public_hex, &sig_hex));
}

test "account identity props are bounded and normalized" {
    var key_buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("identity.key.primary", propKey("primary", &key_buf).?);
    try std.testing.expect(propKey("bad label", &key_buf) == null);
    try std.testing.expect(isPropKey("identity.key.primary"));
    try std.testing.expect(!isPropKey("identity.key.bad label"));

    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x42)));
    const public_hex = std.fmt.bytesToHex(kp.public_key.toBytes(), .upper);
    var transcript_buf: [max_transcript_len]u8 = undefined;
    const msg = transcript("alice", "primary", kp.public_key.toBytes(), &transcript_buf).?;
    const sig = try kp.sign(msg, null);
    const sig_hex = std.fmt.bytesToHex(sig.toBytes(), .upper);
    var value_buf: [max_value_len]u8 = undefined;
    const value = claimValue(&public_hex, &sig_hex, &value_buf).?;
    try std.testing.expectEqual(@as(usize, max_value_len), value.len);
    try std.testing.expect(parseClaimValue(value) != null);
}

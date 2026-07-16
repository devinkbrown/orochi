// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Versioned transport envelope for SESSION_REPLICA v2 S2S frames.
//!
//! The daemon's Helix `session_replica` module owns the self-certifying signed
//! OFFER/ACK objects and their semantic verification. This protocol module adds
//! a small rolling-upgrade-safe transport header, binds each payload to the S2S
//! frame kind, and enforces a bound that still fits inside the default S2S frame
//! after the direct-peer signed envelope is added.
//!
//! Wire format:
//!   magic[4] = "SRTF"
//!   version u8 = 2
//!   kind u8 = OFFER(1) | ACK(2) | REVOKE(3)
//!   signed_payload_len u32 (big endian)
//!   signed_payload bytes
//!
//! OFFER and REVOKE both carry the Helix `SRO2` signed object, but the operation
//! byte must respectively be upsert(1) or remove(2). ACK carries `SRA2`. This
//! redundant kind binding prevents a valid object being reclassified merely by
//! changing the outer S2S frame tag. Cryptographic verification remains the
//! daemon callback's responsibility.

const std = @import("std");
const s2s_frame = @import("s2s_frame.zig");

pub const magic = [_]u8{ 'S', 'R', 'T', 'F' };
pub const version: u8 = 2;
pub const header_len: usize = magic.len + 1 + 1 + 4;

/// `[Ed25519 public key:32][signature:64]` added by `signed_frame` on the S2S
/// direct-peer authentication layer. Kept explicit here to make the frame-size
/// proof visible at the protocol boundary without importing daemon/substrate
/// implementation code into `proto`.
pub const outer_signed_envelope_len: usize = 32 + 64;

/// Largest Helix signed object that can be encoded, wrapped in the S2S signed
/// envelope, and still fit the default length-delimited frame exactly.
pub const max_signed_payload_len: usize = s2s_frame.default_max_frame_size -
    s2s_frame.header_len - outer_signed_envelope_len - header_len;

const offer_magic = [_]u8{ 'S', 'R', 'O', '2' };
const ack_magic = [_]u8{ 'S', 'R', 'A', '2' };
const offer_fixed_len: usize = 4 + 1 + 16 + 24 + 8 + 8 + 2 + 2 + 4;
const ack_transcript_len: usize = 4 + 1 + 16 + 24 + 24 + 8 + 8 + 8;
const inner_signature_len: usize = 32 + 64;
const ack_signed_len: usize = ack_transcript_len + inner_signature_len;
const account_len_offset: usize = 4 + 1 + 16 + 24 + 8 + 8;
const max_account_len: usize = 128;
const max_nick_len: usize = 64;
const max_snapshot_len: usize = 1024 * 1024;

pub const Kind = enum(u8) {
    offer = 1,
    ack = 2,
    revoke = 3,

    pub fn fromByte(value: u8) ?Kind {
        return switch (value) {
            1 => .offer,
            2 => .ack,
            3 => .revoke,
            else => null,
        };
    }
};

pub const Frame = struct {
    kind: Kind,
    /// Borrowed from the encoded transport frame.
    signed_payload: []const u8,
};

pub const EncodeError = error{
    BufferTooSmall,
    InvalidPayload,
    PayloadTooLarge,
};

pub const DecodeError = error{
    BadMagic,
    InvalidKind,
    InvalidPayload,
    PayloadTooLarge,
    TrailingBytes,
    Truncated,
    UnsupportedVersion,
    WrongKind,
};

pub fn encodedLen(signed_payload_len: usize) EncodeError!usize {
    if (signed_payload_len > max_signed_payload_len) return error.PayloadTooLarge;
    return header_len + signed_payload_len;
}

pub fn encode(kind: Kind, signed_payload: []const u8, out: []u8) EncodeError![]const u8 {
    try validatePayload(kind, signed_payload);
    const total = try encodedLen(signed_payload.len);
    if (out.len < total) return error.BufferTooSmall;

    @memcpy(out[0..magic.len], &magic);
    out[magic.len] = version;
    out[magic.len + 1] = @intFromEnum(kind);
    std.mem.writeInt(u32, out[magic.len + 2 ..][0..4], @intCast(signed_payload.len), .big);
    @memcpy(out[header_len..total], signed_payload);
    return out[0..total];
}

/// Strictly decode one transport frame. `expected_kind` is derived from the
/// outer S2S frame tag and prevents cross-tag replay. Returned bytes borrow
/// `bytes` and still require Helix signature + semantic verification.
pub fn decode(expected_kind: Kind, bytes: []const u8) DecodeError!Frame {
    if (bytes.len < header_len) return error.Truncated;
    if (!std.mem.eql(u8, bytes[0..magic.len], &magic)) return error.BadMagic;
    if (bytes[magic.len] != version) return error.UnsupportedVersion;
    const kind = Kind.fromByte(bytes[magic.len + 1]) orelse return error.InvalidKind;
    if (kind != expected_kind) return error.WrongKind;

    const payload_len: usize = @intCast(std.mem.readInt(u32, bytes[magic.len + 2 ..][0..4], .big));
    if (payload_len > max_signed_payload_len) return error.PayloadTooLarge;
    if (payload_len > bytes.len - header_len) return error.Truncated;
    const total = header_len + payload_len;
    if (bytes.len != total) return error.TrailingBytes;
    const signed_payload = bytes[header_len..total];
    validatePayload(kind, signed_payload) catch |err| return switch (err) {
        error.PayloadTooLarge => error.PayloadTooLarge,
        else => error.InvalidPayload,
    };
    return .{ .kind = kind, .signed_payload = signed_payload };
}

fn validatePayload(kind: Kind, payload: []const u8) EncodeError!void {
    if (payload.len > max_signed_payload_len) return error.PayloadTooLarge;
    switch (kind) {
        .offer => try validateOffer(payload, 1),
        .revoke => try validateOffer(payload, 2),
        .ack => {
            if (payload.len != ack_signed_len) return error.InvalidPayload;
            if (!std.mem.eql(u8, payload[0..ack_magic.len], &ack_magic)) return error.InvalidPayload;
        },
    }
}

fn validateOffer(payload: []const u8, expected_operation: u8) EncodeError!void {
    if (payload.len < offer_fixed_len + inner_signature_len) return error.InvalidPayload;
    if (!std.mem.eql(u8, payload[0..offer_magic.len], &offer_magic)) return error.InvalidPayload;
    if (payload[offer_magic.len] != expected_operation) return error.InvalidPayload;

    const account_len: usize = std.mem.readInt(u16, payload[account_len_offset..][0..2], .big);
    const nick_len: usize = std.mem.readInt(u16, payload[account_len_offset + 2 ..][0..2], .big);
    const snapshot_len: usize = @intCast(std.mem.readInt(u32, payload[account_len_offset + 4 ..][0..4], .big));
    if (account_len > max_account_len or nick_len > max_nick_len or snapshot_len > max_snapshot_len) return error.InvalidPayload;

    const variable_len = account_len + nick_len + snapshot_len;
    if (payload.len != offer_fixed_len + variable_len + inner_signature_len) return error.InvalidPayload;
    if (expected_operation == 1) {
        if (account_len == 0 or nick_len == 0 or snapshot_len == 0) return error.InvalidPayload;
    } else if (variable_len != 0) return error.InvalidPayload;
}

const testing = std.testing;

fn fakeOffer(allocator: std.mem.Allocator, kind: Kind) ![]u8 {
    const is_offer = kind == .offer;
    const account = if (is_offer) "a" else "";
    const nick = if (is_offer) "n" else "";
    const snapshot = if (is_offer) "s" else "";
    const total = offer_fixed_len + account.len + nick.len + snapshot.len + inner_signature_len;
    const out = try allocator.alloc(u8, total);
    @memset(out, 0);
    @memcpy(out[0..offer_magic.len], &offer_magic);
    out[offer_magic.len] = if (is_offer) 1 else 2;
    std.mem.writeInt(u16, out[account_len_offset..][0..2], @intCast(account.len), .big);
    std.mem.writeInt(u16, out[account_len_offset + 2 ..][0..2], @intCast(nick.len), .big);
    std.mem.writeInt(u32, out[account_len_offset + 4 ..][0..4], @intCast(snapshot.len), .big);
    var pos: usize = offer_fixed_len;
    @memcpy(out[pos .. pos + account.len], account);
    pos += account.len;
    @memcpy(out[pos .. pos + nick.len], nick);
    pos += nick.len;
    @memcpy(out[pos .. pos + snapshot.len], snapshot);
    return out;
}

fn fakeAck() [ack_signed_len]u8 {
    var out: [ack_signed_len]u8 = @splat(0);
    @memcpy(out[0..ack_magic.len], &ack_magic);
    out[ack_magic.len] = 1;
    return out;
}

test "session replica transport OFFER ACK and REVOKE round-trip" {
    const offer = try fakeOffer(testing.allocator, .offer);
    defer testing.allocator.free(offer);
    const revoke = try fakeOffer(testing.allocator, .revoke);
    defer testing.allocator.free(revoke);
    const ack = fakeAck();

    const cases = [_]struct { kind: Kind, payload: []const u8 }{
        .{ .kind = .offer, .payload = offer },
        .{ .kind = .ack, .payload = &ack },
        .{ .kind = .revoke, .payload = revoke },
    };
    for (cases) |case| {
        const out = try testing.allocator.alloc(u8, header_len + case.payload.len);
        defer testing.allocator.free(out);
        const wire = try encode(case.kind, case.payload, out);
        const decoded = try decode(case.kind, wire);
        try testing.expectEqual(case.kind, decoded.kind);
        try testing.expectEqualSlices(u8, case.payload, decoded.signed_payload);
    }
}

test "session replica transport binds inner object to outer kind" {
    const offer = try fakeOffer(testing.allocator, .offer);
    defer testing.allocator.free(offer);
    const revoke = try fakeOffer(testing.allocator, .revoke);
    defer testing.allocator.free(revoke);
    const ack = fakeAck();
    var out: [header_len + ack_signed_len]u8 = undefined;

    try testing.expectError(error.InvalidPayload, encode(.revoke, offer, &out));
    try testing.expectError(error.InvalidPayload, encode(.offer, revoke, &out));
    try testing.expectError(error.InvalidPayload, encode(.offer, &ack, &out));
    const ack_wire = try encode(.ack, &ack, &out);
    try testing.expectError(error.WrongKind, decode(.offer, ack_wire));
}

test "session replica transport rejects every truncation and trailing bytes" {
    const ack = fakeAck();
    var out: [header_len + ack_signed_len + 1]u8 = undefined;
    const wire = try encode(.ack, &ack, out[0 .. out.len - 1]);
    for (0..wire.len) |end| try testing.expectError(error.Truncated, decode(.ack, wire[0..end]));
    out[wire.len] = 0xff;
    try testing.expectError(error.TrailingBytes, decode(.ack, &out));
}

test "session replica transport rejects malformed headers lengths and payloads" {
    const ack = fakeAck();
    var out: [header_len + ack_signed_len]u8 = undefined;
    _ = try encode(.ack, &ack, &out);

    var changed = out;
    changed[0] = 'X';
    try testing.expectError(error.BadMagic, decode(.ack, &changed));
    changed = out;
    changed[magic.len] = version + 1;
    try testing.expectError(error.UnsupportedVersion, decode(.ack, &changed));
    changed = out;
    changed[magic.len + 1] = 0xff;
    try testing.expectError(error.InvalidKind, decode(.ack, &changed));
    changed = out;
    std.mem.writeInt(u32, changed[magic.len + 2 ..][0..4], ack_signed_len + 1, .big);
    try testing.expectError(error.Truncated, decode(.ack, &changed));
    changed = out;
    changed[header_len] = 'X';
    try testing.expectError(error.InvalidPayload, decode(.ack, &changed));
}

test "session replica transport enforces frame-size bound before allocation or parse" {
    const oversized = try testing.allocator.alloc(u8, max_signed_payload_len + 1);
    defer testing.allocator.free(oversized);
    @memset(oversized, 0);
    var one: [1]u8 = undefined;
    try testing.expectError(error.PayloadTooLarge, encode(.offer, oversized, &one));

    var header: [header_len]u8 = @splat(0);
    @memcpy(header[0..magic.len], &magic);
    header[magic.len] = version;
    header[magic.len + 1] = @intFromEnum(Kind.offer);
    std.mem.writeInt(u32, header[magic.len + 2 ..][0..4], @intCast(max_signed_payload_len + 1), .big);
    try testing.expectError(error.PayloadTooLarge, decode(.offer, &header));
}

test "session replica transport OFFER declared fields are strict and bounded" {
    const offer = try fakeOffer(testing.allocator, .offer);
    defer testing.allocator.free(offer);
    var changed = try testing.allocator.dupe(u8, offer);
    defer testing.allocator.free(changed);
    std.mem.writeInt(u16, changed[account_len_offset..][0..2], max_account_len + 1, .big);
    var out: [512]u8 = undefined;
    try testing.expectError(error.InvalidPayload, encode(.offer, changed, &out));

    @memcpy(changed, offer);
    std.mem.writeInt(u32, changed[account_len_offset + 4 ..][0..4], 99, .big);
    try testing.expectError(error.InvalidPayload, encode(.offer, changed, &out));
}

// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Stable identity for one physical client attached to a reusable session.
//!
//! An attachment id is not a credential. It is minted independently of the
//! reusable bearer token and remains stable while runtime client ids, file
//! descriptors, nodes, and Helix incarnations change. Wire routing uses
//! domain-separated one-way ids derived from both the token and attachment id,
//! so neither derived id exposes the bearer token or collapses sibling clients.

const std = @import("std");

pub const byte_len: usize = 16;
pub const hex_len: usize = byte_len * 2;
pub const SessionToken = [byte_len]u8;
pub const PresenceId = [byte_len]u8;
pub const RouteId = [byte_len]u8;

const presence_id_domain = "orochi-session-presence-id-v1\x00";
const route_id_domain = "orochi-session-route-id-v1\x00";
const max_mint_attempts: usize = 4;

pub const ParseError = error{
    InvalidLength,
    InvalidHex,
    ZeroAttachmentId,
};

pub const MintError = error{ZeroEntropy};

pub const DeriveError = error{
    NullSessionToken,
    ZeroAttachmentId,
    InvalidDerivedId,
};

/// Exactly 128 bits of stable, non-secret physical-attachment identity.
///
/// Current-state decoders must construct values through `fromBytes` or
/// `parseHex`; direct aggregate construction is reserved for trusted constants
/// and tests because the all-zero value is not a valid current attachment id.
pub const AttachmentId = struct {
    raw: [byte_len]u8,

    /// Mint a non-zero id from `std.Io`'s CSPRNG. Four consecutive all-zero
    /// blocks indicate a broken/injected source and fail rather than publishing
    /// the reserved value or looping forever.
    pub fn mint(io: std.Io) MintError!AttachmentId {
        for (0..max_mint_attempts) |_| {
            var raw: [byte_len]u8 = undefined;
            io.random(&raw);
            if (!isZeroBytes(raw)) return .{ .raw = raw };
        }
        return error.ZeroEntropy;
    }

    /// Validate bytes decoded from current state.
    pub fn fromBytes(raw: [byte_len]u8) ParseError!AttachmentId {
        if (isZeroBytes(raw)) return error.ZeroAttachmentId;
        return .{ .raw = raw };
    }

    /// Parse exactly 32 hexadecimal characters. Hex digits are case-insensitive;
    /// whitespace, prefixes, separators, short forms, and the all-zero id are
    /// rejected so current state has one unambiguous textual representation.
    pub fn parseHex(text: []const u8) ParseError!AttachmentId {
        if (text.len != hex_len) return error.InvalidLength;
        var raw: [byte_len]u8 = undefined;
        const decoded = std.fmt.hexToBytes(&raw, text) catch return error.InvalidHex;
        std.debug.assert(decoded.len == byte_len);
        return fromBytes(raw);
    }

    /// Render the canonical lowercase 32-hex representation.
    pub fn toHex(self: AttachmentId) [hex_len]u8 {
        return std.fmt.bytesToHex(self.raw, .lower);
    }

    pub fn isZero(self: AttachmentId) bool {
        return isZeroBytes(self.raw);
    }

    /// Constant-time equality avoids creating a timing distinction when this id
    /// is checked beside credential-bearing session state.
    pub fn eql(self: AttachmentId, other: AttachmentId) bool {
        return std.crypto.timing_safe.eql([byte_len]u8, self.raw, other.raw);
    }
};

/// Derive the opaque identity carried by membership/presence state.
pub fn presenceId(token: SessionToken, attachment_id: AttachmentId) DeriveError!PresenceId {
    return deriveId(presence_id_domain, token, attachment_id);
}

/// Derive the opaque identity carried by directed/message routing state.
pub fn routeId(token: SessionToken, attachment_id: AttachmentId) DeriveError!RouteId {
    return deriveId(route_id_domain, token, attachment_id);
}

fn deriveId(
    comptime domain: []const u8,
    token: SessionToken,
    attachment_id: AttachmentId,
) DeriveError![byte_len]u8 {
    if (isZeroBytes(token)) return error.NullSessionToken;
    if (attachment_id.isZero()) return error.ZeroAttachmentId;

    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update(domain);
    hasher.update(&token);
    hasher.update(&attachment_id.raw);
    var digest: [std.crypto.hash.Blake3.digest_length]u8 = undefined;
    hasher.final(&digest);
    const id: [byte_len]u8 = digest[0..byte_len].*;
    if (isZeroBytes(id)) return error.InvalidDerivedId;
    return id;
}

fn isZeroBytes(bytes: [byte_len]u8) bool {
    return std.mem.allEqual(u8, &bytes, 0);
}

test "attachment id has exact stable widths" {
    try std.testing.expectEqual(@as(usize, byte_len), @sizeOf(AttachmentId));
    try std.testing.expectEqual(@as(usize, byte_len), @sizeOf(PresenceId));
    try std.testing.expectEqual(@as(usize, byte_len), @sizeOf(RouteId));
    try std.testing.expectEqual(@as(usize, hex_len), @sizeOf([hex_len]u8));
}

test "attachment id parses case-insensitively and renders canonical lowercase" {
    const canonical = "0123456789abcdeffedcba9876543210";
    const upper = "0123456789ABCDEFFEDCBA9876543210";
    const mixed = "0123456789aBcDeFfEdCbA9876543210";

    const from_lower = try AttachmentId.parseHex(canonical);
    const from_upper = try AttachmentId.parseHex(upper);
    const from_mixed = try AttachmentId.parseHex(mixed);
    try std.testing.expect(from_lower.eql(from_upper));
    try std.testing.expect(from_lower.eql(from_mixed));
    try std.testing.expectEqualStrings(canonical, &from_upper.toHex());
}

test "attachment id rejects malformed and zero text" {
    try std.testing.expectError(error.InvalidLength, AttachmentId.parseHex(""));
    try std.testing.expectError(error.InvalidLength, AttachmentId.parseHex("0123456789abcdeffedcba987654321"));
    try std.testing.expectError(error.InvalidLength, AttachmentId.parseHex("0123456789abcdeffedcba98765432100"));
    try std.testing.expectError(error.InvalidLength, AttachmentId.parseHex(" 0123456789abcdeffedcba9876543210"));
    try std.testing.expectError(error.InvalidHex, AttachmentId.parseHex("g123456789abcdeffedcba9876543210"));
    try std.testing.expectError(error.InvalidHex, AttachmentId.parseHex("01234567-9abcdeffedcba9876543210"));
    try std.testing.expectError(error.ZeroAttachmentId, AttachmentId.parseHex("00000000000000000000000000000000"));
    try std.testing.expectError(error.ZeroAttachmentId, AttachmentId.fromBytes(@splat(0)));
}

test "attachment id accepts non-zero boundary values" {
    const low = try AttachmentId.parseHex("00000000000000000000000000000001");
    const high = try AttachmentId.parseHex("ffffffffffffffffffffffffffffffff");
    try std.testing.expect(!low.isZero());
    try std.testing.expect(!high.isZero());
    try std.testing.expect(!low.eql(high));
    try std.testing.expectEqualStrings("00000000000000000000000000000001", &low.toHex());
    try std.testing.expectEqualStrings("ffffffffffffffffffffffffffffffff", &high.toHex());
}

test "attachment id mint retries zero and fails a permanently zero source" {
    const ScriptedRandom = struct {
        calls: usize = 0,
        always_zero: bool = false,

        fn random(userdata: ?*anyopaque, out: []u8) void {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            self.calls += 1;
            if (self.always_zero or self.calls == 1) {
                @memset(out, 0);
            } else {
                @memset(out, 0xa5);
            }
        }
    };

    var vtable = std.testing.io.vtable.*;
    vtable.random = ScriptedRandom.random;
    var scripted = ScriptedRandom{};
    const scripted_io = std.Io{ .userdata = &scripted, .vtable = &vtable };
    const minted = try AttachmentId.mint(scripted_io);
    try std.testing.expectEqual(@as(usize, 2), scripted.calls);
    try std.testing.expectEqual(@as([byte_len]u8, @splat(0xa5)), minted.raw);

    var zero_source = ScriptedRandom{ .always_zero = true };
    const zero_io = std.Io{ .userdata = &zero_source, .vtable = &vtable };
    try std.testing.expectError(error.ZeroEntropy, AttachmentId.mint(zero_io));
    try std.testing.expectEqual(max_mint_attempts, zero_source.calls);
}

test "presence and route derivation are deterministic and domain separated" {
    const token: SessionToken = .{
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };
    const attachment = try AttachmentId.parseHex("fedcba98765432100123456789abcdef");
    const presence_a = try presenceId(token, attachment);
    const presence_b = try presenceId(token, attachment);
    const route_a = try routeId(token, attachment);
    const route_b = try routeId(token, attachment);

    try std.testing.expectEqual(presence_a, presence_b);
    try std.testing.expectEqual(route_a, route_b);
    try std.testing.expect(!std.crypto.timing_safe.eql([byte_len]u8, presence_a, route_a));
    try std.testing.expect(!std.crypto.timing_safe.eql([byte_len]u8, token, presence_a));
    try std.testing.expect(!std.crypto.timing_safe.eql([byte_len]u8, token, route_a));

    // Fixed vectors pin the domain, token/attachment ordering, hash, and
    // 128-bit truncation.
    try std.testing.expectEqualStrings(
        "80a5882324b7c821c0746a6c1ee9277b",
        &std.fmt.bytesToHex(presence_a, .lower),
    );
    try std.testing.expectEqualStrings(
        "5b822bd872fc48fbf86f62db678f59ca",
        &std.fmt.bytesToHex(route_a, .lower),
    );
}

test "derived identities do not collapse sibling attachments or tokens" {
    const token_a: SessionToken = @splat(0x11);
    var token_b: SessionToken = token_a;
    token_b[byte_len - 1] = 0x12;
    var seen_presence: [256]PresenceId = undefined;
    var seen_routes: [256]RouteId = undefined;

    for (1..257) |n| {
        var raw: [byte_len]u8 = @splat(0);
        std.mem.writeInt(u64, raw[byte_len - 8 ..][0..8], n, .big);
        const attachment = try AttachmentId.fromBytes(raw);
        const presence = try presenceId(token_a, attachment);
        const route = try routeId(token_a, attachment);
        for (seen_presence[0 .. n - 1]) |prior|
            try std.testing.expect(!std.mem.eql(u8, &prior, &presence));
        for (seen_routes[0 .. n - 1]) |prior|
            try std.testing.expect(!std.mem.eql(u8, &prior, &route));
        try std.testing.expect(!std.mem.eql(u8, &presence, &(try presenceId(token_b, attachment))));
        try std.testing.expect(!std.mem.eql(u8, &route, &(try routeId(token_b, attachment))));
        seen_presence[n - 1] = presence;
        seen_routes[n - 1] = route;
    }
}

test "derivation rejects reserved token and attachment ids" {
    const valid_token: SessionToken = @splat(0x44);
    const valid_attachment = try AttachmentId.fromBytes(@splat(0x55));
    const zero_attachment = AttachmentId{ .raw = @splat(0) };
    try std.testing.expectError(error.NullSessionToken, presenceId(@splat(0), valid_attachment));
    try std.testing.expectError(error.NullSessionToken, routeId(@splat(0), valid_attachment));
    try std.testing.expectError(error.ZeroAttachmentId, presenceId(valid_token, zero_attachment));
    try std.testing.expectError(error.ZeroAttachmentId, routeId(valid_token, zero_attachment));
}

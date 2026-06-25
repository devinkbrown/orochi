// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! TLS 1.3 pre_shared_key extension codec (RFC 8446 section 4.2.11).
//!
//! This module handles only the extension_data payload for ClientHello and
//! ServerHello forms. It is pure slice encode/decode logic: no I/O, clock,
//! randomness, or allocation. Returned slices alias the caller's input.

const std = @import("std");
const mem = std.mem;

comptime {
    if (@bitSizeOf(usize) != 64) {
        @compileError("tls_psk.zig requires a 64-bit target");
    }
}

pub const max_identity_len: usize = std.math.maxInt(u16);
pub const max_identity_list_len: usize = std.math.maxInt(u16);
pub const max_binder_len: usize = std.math.maxInt(u8);
pub const max_binder_list_len: usize = std.math.maxInt(u16);
pub const server_psk_len: usize = 2;

pub const Error = error{
    BufferTooShort,
    TrailingBytes,
    NoSpaceLeft,
    IdentityTooLarge,
    IdentityListTooLarge,
    BinderTooLarge,
    BinderListTooLarge,
};

pub const PskIdentity = struct {
    identity: []const u8,
    obfuscated_ticket_age: u32,

    pub fn wireLen(self: PskIdentity) Error!usize {
        if (self.identity.len > max_identity_len) return error.IdentityTooLarge;
        return 2 + self.identity.len + 4;
    }
};

pub const IdentityIterator = struct {
    body: []const u8,
    pos: usize = 0,

    pub fn init(body: []const u8) IdentityIterator {
        return .{ .body = body };
    }

    pub fn next(self: *IdentityIterator) Error!?PskIdentity {
        if (self.pos == self.body.len) return null;
        if (self.body.len - self.pos < 2) return error.BufferTooShort;

        const identity_len = mem.readInt(u16, self.body[self.pos..][0..2], .big);
        self.pos += 2;
        if (self.body.len - self.pos < @as(usize, identity_len) + 4) return error.BufferTooShort;

        const identity = self.body[self.pos .. self.pos + identity_len];
        self.pos += identity_len;
        const age = mem.readInt(u32, self.body[self.pos..][0..4], .big);
        self.pos += 4;

        return .{
            .identity = identity,
            .obfuscated_ticket_age = age,
        };
    }

    pub fn remaining(self: IdentityIterator) usize {
        return self.body.len - self.pos;
    }
};

pub const BinderIterator = struct {
    body: []const u8,
    pos: usize = 0,

    pub fn init(body: []const u8) BinderIterator {
        return .{ .body = body };
    }

    pub fn next(self: *BinderIterator) Error!?[]const u8 {
        if (self.pos == self.body.len) return null;
        if (self.body.len - self.pos < 1) return error.BufferTooShort;

        const binder_len = self.body[self.pos];
        self.pos += 1;
        if (self.body.len - self.pos < binder_len) return error.BufferTooShort;

        const binder = self.body[self.pos .. self.pos + binder_len];
        self.pos += binder_len;
        return binder;
    }

    pub fn remaining(self: BinderIterator) usize {
        return self.body.len - self.pos;
    }
};

pub const ClientPsk = struct {
    identities: IdentityIterator,
    binders: BinderIterator,
};

/// Parse a ClientHello pre_shared_key extension_data payload.
pub fn parseClientPsk(block: []const u8) Error!ClientPsk {
    const binders_at = try binderListOffset(block);
    const identities_body = block[2..binders_at];

    var off = binders_at;
    const binders_len = try readU16(block, &off);
    if (block.len - off < binders_len) return error.BufferTooShort;
    const binders_body = block[off .. off + binders_len];
    off += binders_len;
    if (off != block.len) return error.TrailingBytes;

    try validateIdentities(identities_body);
    try validateBinders(binders_body);

    return .{
        .identities = IdentityIterator.init(identities_body),
        .binders = BinderIterator.init(binders_body),
    };
}

/// Build a ClientHello pre_shared_key extension_data payload into `out`.
pub fn buildClientPsk(
    out: []u8,
    identities: []const PskIdentity,
    binders: []const []const u8,
) Error![]const u8 {
    const identities_len = try identityListLen(identities);
    const binders_len = try binderListLen(binders);
    const total = 2 + identities_len + 2 + binders_len;
    if (out.len < total) return error.NoSpaceLeft;

    var off: usize = 0;
    mem.writeInt(u16, out[off..][0..2], @intCast(identities_len), .big);
    off += 2;
    for (identities) |identity| {
        mem.writeInt(u16, out[off..][0..2], @intCast(identity.identity.len), .big);
        off += 2;
        @memcpy(out[off .. off + identity.identity.len], identity.identity);
        off += identity.identity.len;
        mem.writeInt(u32, out[off..][0..4], identity.obfuscated_ticket_age, .big);
        off += 4;
    }

    mem.writeInt(u16, out[off..][0..2], @intCast(binders_len), .big);
    off += 2;
    for (binders) |binder| {
        out[off] = @intCast(binder.len);
        off += 1;
        @memcpy(out[off .. off + binder.len], binder);
        off += binder.len;
    }

    return out[0..off];
}

/// Parse a ServerHello pre_shared_key extension_data payload.
pub fn parseServerPsk(block: []const u8) Error!u16 {
    if (block.len < server_psk_len) return error.BufferTooShort;
    if (block.len != server_psk_len) return error.TrailingBytes;
    return mem.readInt(u16, block[0..2], .big);
}

/// Build a ServerHello pre_shared_key extension_data payload into `out`.
pub fn buildServerPsk(out: []u8, selected: u16) Error![]const u8 {
    if (out.len < server_psk_len) return error.NoSpaceLeft;
    mem.writeInt(u16, out[0..2], selected, .big);
    return out[0..server_psk_len];
}

/// Return the offset of the ClientHello binder list length field.
///
/// PSK binders are computed over a truncated ClientHello that includes the
/// identities vector but excludes the binders vector.
pub fn binderListOffset(block: []const u8) Error!usize {
    var off: usize = 0;
    const identities_len = try readU16(block, &off);
    if (block.len - off < identities_len) return error.BufferTooShort;
    off += identities_len;
    if (block.len - off < 2) return error.BufferTooShort;
    return off;
}

fn readU16(bytes: []const u8, off: *usize) Error!u16 {
    if (bytes.len - off.* < 2) return error.BufferTooShort;
    const value = mem.readInt(u16, bytes[off.*..][0..2], .big);
    off.* += 2;
    return value;
}

fn identityListLen(identities: []const PskIdentity) Error!usize {
    var total: usize = 0;
    for (identities) |identity| {
        const item_len = try identity.wireLen();
        if (max_identity_list_len - total < item_len) return error.IdentityListTooLarge;
        total += item_len;
    }
    return total;
}

fn binderListLen(binders: []const []const u8) Error!usize {
    var total: usize = 0;
    for (binders) |binder| {
        if (binder.len > max_binder_len) return error.BinderTooLarge;
        const item_len = 1 + binder.len;
        if (max_binder_list_len - total < item_len) return error.BinderListTooLarge;
        total += item_len;
    }
    return total;
}

fn validateIdentities(body: []const u8) Error!void {
    var it = IdentityIterator.init(body);
    while (try it.next()) |_| {}
}

fn validateBinders(body: []const u8) Error!void {
    var it = BinderIterator.init(body);
    while (try it.next()) |_| {}
}

const testing = std.testing;

test "known-answer client pre_shared_key payload parses and exposes binder offset" {
    // Arrange.
    const wire = [_]u8{
        0x00, 0x09,
        0x00, 0x03,
        'a',  'b',
        'c',  0x01,
        0x02, 0x03,
        0x04, 0x00,
        0x04, 0x03,
        0xaa, 0xbb,
        0xcc,
    };

    // Act.
    const offset = try binderListOffset(&wire);
    var parsed = try parseClientPsk(&wire);
    const first_identity = try parsed.identities.next();
    const no_identity = try parsed.identities.next();
    const first_binder = try parsed.binders.next();
    const no_binder = try parsed.binders.next();

    // Assert.
    try testing.expectEqual(@as(usize, 11), offset);
    try testing.expect(first_identity != null);
    try testing.expectEqualSlices(u8, "abc", first_identity.?.identity);
    try testing.expectEqual(@as(u32, 0x0102_0304), first_identity.?.obfuscated_ticket_age);
    try testing.expect(no_identity == null);
    try testing.expect(first_binder != null);
    try testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb, 0xcc }, first_binder.?);
    try testing.expect(no_binder == null);
}

test "buildClientPsk round-trips multiple identities and binders" {
    // Arrange.
    const identities = [_]PskIdentity{
        .{ .identity = "ticket-one", .obfuscated_ticket_age = 10 },
        .{ .identity = "ticket-two", .obfuscated_ticket_age = 20 },
    };
    const binder_a = [_]u8{ 0x11, 0x12, 0x13, 0x14 };
    const binder_b = [_]u8{ 0x21, 0x22 };
    const binders = [_][]const u8{ &binder_a, &binder_b };
    var out: [64]u8 = undefined;

    // Act.
    const wire = try buildClientPsk(&out, &identities, &binders);
    var parsed = try parseClientPsk(wire);
    const identity_a = (try parsed.identities.next()).?;
    const identity_b = (try parsed.identities.next()).?;
    const identity_end = try parsed.identities.next();
    const parsed_binder_a = (try parsed.binders.next()).?;
    const parsed_binder_b = (try parsed.binders.next()).?;
    const binder_end = try parsed.binders.next();

    // Assert.
    try testing.expectEqualSlices(u8, "ticket-one", identity_a.identity);
    try testing.expectEqual(@as(u32, 10), identity_a.obfuscated_ticket_age);
    try testing.expectEqualSlices(u8, "ticket-two", identity_b.identity);
    try testing.expectEqual(@as(u32, 20), identity_b.obfuscated_ticket_age);
    try testing.expect(identity_end == null);
    try testing.expectEqualSlices(u8, &binder_a, parsed_binder_a);
    try testing.expectEqualSlices(u8, &binder_b, parsed_binder_b);
    try testing.expect(binder_end == null);
    try testing.expectEqual(@as(usize, 44), wire.len);
}

test "parseClientPsk rejects every truncation of a non-empty payload" {
    // Arrange.
    const wire = [_]u8{
        0x00, 0x09,
        0x00, 0x03,
        'p',  's',
        'k',  0xaa,
        0xbb, 0xcc,
        0xdd, 0x00,
        0x03, 0x02,
        0xee, 0xff,
    };

    // Act and assert.
    var len: usize = 0;
    while (len < wire.len) : (len += 1) {
        try testing.expectError(error.BufferTooShort, parseClientPsk(wire[0..len]));
    }
}

test "parseClientPsk rejects malformed identity and binder list bodies" {
    // Arrange.
    const short_identity_body = [_]u8{
        0x00, 0x03,
        0x00, 0x02,
        0xaa, 0x00,
        0x00,
    };
    const short_binder_body = [_]u8{
        0x00, 0x06,
        0x00, 0x00,
        0x11, 0x22,
        0x33, 0x44,
        0x00, 0x02,
        0x02, 0xaa,
    };

    // Act and assert.
    try testing.expectError(error.BufferTooShort, parseClientPsk(&short_identity_body));
    try testing.expectError(error.BufferTooShort, parseClientPsk(&short_binder_body));
}

test "parseClientPsk rejects trailing bytes after binder list" {
    // Arrange.
    const wire = [_]u8{
        0x00, 0x06,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x01,
        0x00, 0x01,
        0x00, 0xff,
    };

    // Act and assert.
    try testing.expectError(error.TrailingBytes, parseClientPsk(&wire));
}

test "buildClientPsk reports caller buffer and vector size errors" {
    // Arrange.
    const identity = [_]PskIdentity{
        .{ .identity = "id", .obfuscated_ticket_age = 1 },
    };
    const binder = [_]u8{0xaa};
    const binders = [_][]const u8{&binder};
    var small_out: [11]u8 = undefined;
    var too_large_identity: [max_identity_len + 1]u8 = undefined;
    const too_large_binder = [_]u8{0} ** (max_binder_len + 1);

    // Act and assert.
    try testing.expectError(error.NoSpaceLeft, buildClientPsk(&small_out, &identity, &binders));
    try testing.expectError(
        error.IdentityTooLarge,
        buildClientPsk(&small_out, &.{.{ .identity = &too_large_identity, .obfuscated_ticket_age = 1 }}, &binders),
    );
    try testing.expectError(
        error.BinderTooLarge,
        buildClientPsk(&small_out, &identity, &.{&too_large_binder}),
    );
}

test "buildClientPsk reports aggregate identity and binder list overflow" {
    // Arrange.
    var large_identity: [max_identity_len - 5]u8 = undefined;
    const one_byte = [_]u8{0xaa};
    const large_binder = [_]u8{0xbb} ** max_binder_len;
    var many_binders: [257][]const u8 = undefined;
    for (&many_binders) |*slot| {
        slot.* = &large_binder;
    }

    // Act and assert.
    try testing.expectError(
        error.IdentityListTooLarge,
        buildClientPsk(
            &.{},
            &.{
                .{ .identity = &large_identity, .obfuscated_ticket_age = 1 },
                .{ .identity = &one_byte, .obfuscated_ticket_age = 2 },
            },
            &.{},
        ),
    );
    try testing.expectError(
        error.BinderListTooLarge,
        buildClientPsk(
            &.{},
            &.{},
            &many_binders,
        ),
    );
}

test "known-answer server pre_shared_key payload builds and parses selected identity" {
    // Arrange.
    var out: [2]u8 = undefined;

    // Act.
    const wire = try buildServerPsk(&out, 0x1234);
    const selected = try parseServerPsk(wire);

    // Assert.
    try testing.expectEqualSlices(u8, &.{ 0x12, 0x34 }, wire);
    try testing.expectEqual(@as(u16, 0x1234), selected);
}

test "server pre_shared_key parser and builder reject bad lengths" {
    // Arrange.
    var empty: [0]u8 = .{};
    const short = [_]u8{0x12};
    const long = [_]u8{ 0x12, 0x34, 0x56 };

    // Act and assert.
    try testing.expectError(error.NoSpaceLeft, buildServerPsk(&empty, 0));
    try testing.expectError(error.BufferTooShort, parseServerPsk(&short));
    try testing.expectError(error.TrailingBytes, parseServerPsk(&long));
}

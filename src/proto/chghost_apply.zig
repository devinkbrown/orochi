//! Per-recipient IRCv3 CHGHOST wire builder.
//!
//! This module has no daemon state. Callers decide which visible clients share
//! a channel with the changed user; this code only gates on that visibility plus
//! the IRCv3 chghost capability and appends the canonical wire line.
const std = @import("std");
const chghost = @import("chghost.zig");

pub const Allocator = std.mem.Allocator;
pub const Error = chghost.ChghostError || Allocator.Error;
pub const Params = chghost.Params;
pub const Prefix = chghost.Prefix;

/// Caller-provided recipient visibility/capability facts.
pub const Recipient = struct {
    common_channel: bool = false,
    chghost_cap: bool = false,
};

/// The new identity fields carried by CHGHOST.
pub const UserHost = struct {
    user: []const u8,
    host: []const u8,
};

/// Validate a CHGHOST user@host pair using the shared IRCv3 identity rules.
pub fn validateUserHost(new_identity: UserHost) chghost.ChghostError!void {
    return validateUserHostWith(.{}, new_identity);
}

/// Validate a CHGHOST user@host pair using caller-selected limits.
pub fn validateUserHostWith(comptime params: Params, new_identity: UserHost) chghost.ChghostError!void {
    try chghost.validateUserWith(params, new_identity.user);
    try chghost.validateHostWith(params, new_identity.host);
}

/// Whether this recipient should receive a native IRCv3 CHGHOST broadcast.
pub fn shouldReceive(recipient: Recipient) bool {
    return recipient.common_channel and recipient.chghost_cap;
}

/// Maximum bytes needed for a CHGHOST line under the selected validation limits.
pub fn maxLineBytes(comptime params: Params) usize {
    return 1 + params.max_nick_bytes + 1 + params.max_user_bytes + 1 + params.max_host_bytes +
        " CHGHOST ".len + params.max_user_bytes + 1 + params.max_host_bytes;
}

/// Append `:oldnick!olduser@oldhost CHGHOST newuser newhost` for one recipient.
///
/// Returns null when the recipient is not both common-channel visible and
/// chghost-capable. Returned slices point into `out` and are invalidated by
/// later mutations of that list.
pub fn appendForRecipient(
    allocator: Allocator,
    out: *std.ArrayList(u8),
    recipient: Recipient,
    old_prefix: Prefix,
    new_identity: UserHost,
) Error!?[]const u8 {
    return appendForRecipientWith(.{}, allocator, out, recipient, old_prefix, new_identity);
}

/// Append a per-recipient CHGHOST line using caller-selected limits.
pub fn appendForRecipientWith(
    comptime params: Params,
    allocator: Allocator,
    out: *std.ArrayList(u8),
    recipient: Recipient,
    old_prefix: Prefix,
    new_identity: UserHost,
) Error!?[]const u8 {
    if (!shouldReceive(recipient)) return null;

    var scratch: [maxLineBytes(params)]u8 = undefined;
    const line = try chghost.buildChghostLineWith(
        params,
        &scratch,
        old_prefix,
        new_identity.user,
        new_identity.host,
    );

    const start = out.items.len;
    try out.appendSlice(allocator, line);
    return out.items[start..];
}

test "builds exact per-recipient CHGHOST bytes" {
    const allocator = std.testing.allocator;
    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);

    const line = try appendForRecipient(allocator, &out, .{
        .common_channel = true,
        .chghost_cap = true,
    }, .{
        .nick = "oldnick",
        .user = "olduser",
        .host = "oldhost.example",
    }, .{
        .user = "newuser",
        .host = "cloak/users/oldnick",
    });

    try std.testing.expect(line != null);
    try std.testing.expectEqualStrings(
        ":oldnick!olduser@oldhost.example CHGHOST newuser cloak/users/oldnick",
        line.?,
    );
    try std.testing.expectEqualStrings(line.?, out.items);
}

test "skips recipients without common-channel visibility or chghost cap" {
    const allocator = std.testing.allocator;
    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);

    const old_prefix = Prefix{ .nick = "oldnick", .user = "olduser", .host = "oldhost.example" };
    const new_identity = UserHost{ .user = "newuser", .host = "newhost.example" };

    try std.testing.expectEqual(
        @as(?[]const u8, null),
        try appendForRecipient(allocator, &out, .{ .common_channel = false, .chghost_cap = true }, old_prefix, new_identity),
    );
    try std.testing.expectEqual(
        @as(?[]const u8, null),
        try appendForRecipient(allocator, &out, .{ .common_channel = true, .chghost_cap = false }, old_prefix, new_identity),
    );
    try std.testing.expectEqual(@as(usize, 0), out.items.len);
}

test "host validation accepts IRCv3 chghost host syntax" {
    try validateUserHost(.{ .user = "newuser", .host = "cloak/users/alice" });
    try validateUserHost(.{ .user = "newuser", .host = "2001:db8::1" });
    try validateUserHost(.{ .user = "newuser", .host = "[2001:db8::1]" });
    try validateUserHost(.{ .user = "newuser", .host = "gateway_user.example" });
}

test "rejects malformed user host and prefix fields" {
    const allocator = std.testing.allocator;
    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);

    try std.testing.expectError(error.InvalidUser, validateUserHost(.{ .user = "", .host = "host.example" }));
    try std.testing.expectError(error.InvalidUser, validateUserHost(.{ .user = "bad user", .host = "host.example" }));
    try std.testing.expectError(error.InvalidUser, validateUserHost(.{ .user = "bad@user", .host = "host.example" }));
    try std.testing.expectError(error.InvalidHost, validateUserHost(.{ .user = "newuser", .host = "" }));
    try std.testing.expectError(error.InvalidHost, validateUserHost(.{ .user = "newuser", .host = "bad host" }));
    try std.testing.expectError(error.InvalidHost, validateUserHost(.{ .user = "newuser", .host = "bad\rhost" }));

    try std.testing.expectError(error.InvalidNick, appendForRecipient(allocator, &out, .{
        .common_channel = true,
        .chghost_cap = true,
    }, .{
        .nick = "bad nick",
        .user = "olduser",
        .host = "oldhost.example",
    }, .{
        .user = "newuser",
        .host = "newhost.example",
    }));
    try std.testing.expectError(error.InvalidHost, appendForRecipient(allocator, &out, .{
        .common_channel = true,
        .chghost_cap = true,
    }, .{
        .nick = "oldnick",
        .user = "olduser",
        .host = "oldhost.example",
    }, .{
        .user = "newuser",
        .host = "bad\nhost",
    }));
}

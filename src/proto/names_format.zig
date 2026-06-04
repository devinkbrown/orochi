//! Pure NAMES member token formatting helpers.
//!
//! This module formats the member token that appears inside the trailing
//! parameter of an RPL_NAMREPLY (353) line. Reply folding, visibility, and
//! validation are owned by the caller.
const std = @import("std");

pub const Member = struct {
    nick: []const u8,
    user: []const u8,
    host: []const u8,
    all_prefixes: []const u8,
    highest_prefix: []const u8,
};

pub const RecipientCaps = struct {
    multi_prefix: bool = false,
    userhost_in_names: bool = false,
};

pub const NamesFormatError = error{
    OutputTooSmall,
};

pub fn memberTokenLen(member: Member, caps: RecipientCaps) usize {
    var len = visiblePrefixes(member, caps).len + member.nick.len;
    if (caps.userhost_in_names) {
        len += 1 + member.user.len + 1 + member.host.len;
    }
    return len;
}

pub fn formatMemberToken(
    allocator: std.mem.Allocator,
    member: Member,
    caps: RecipientCaps,
) std.mem.Allocator.Error![]u8 {
    const token = try allocator.alloc(u8, memberTokenLen(member, caps));
    writeMemberTokenAssumeCapacity(token, member, caps);
    return token;
}

pub fn writeMemberToken(
    out: []u8,
    member: Member,
    caps: RecipientCaps,
) NamesFormatError![]const u8 {
    const len = memberTokenLen(member, caps);
    if (out.len < len) return error.OutputTooSmall;
    writeMemberTokenAssumeCapacity(out[0..len], member, caps);
    return out[0..len];
}

fn visiblePrefixes(member: Member, caps: RecipientCaps) []const u8 {
    if (caps.multi_prefix) return member.all_prefixes;
    return member.highest_prefix;
}

fn writeMemberTokenAssumeCapacity(out: []u8, member: Member, caps: RecipientCaps) void {
    var n: usize = 0;
    const prefixes = visiblePrefixes(member, caps);

    copyInto(out, &n, prefixes);
    copyInto(out, &n, member.nick);
    if (caps.userhost_in_names) {
        out[n] = '!';
        n += 1;
        copyInto(out, &n, member.user);
        out[n] = '@';
        n += 1;
        copyInto(out, &n, member.host);
    }
}

fn copyInto(out: []u8, n: *usize, bytes: []const u8) void {
    @memcpy(out[n.*..][0..bytes.len], bytes);
    n.* += bytes.len;
}

test "member token formats all recipient capability combinations" {
    const allocator = std.testing.allocator;
    const member = Member{
        .nick = "alice",
        .user = "aliceu",
        .host = "client.example",
        .all_prefixes = "~.@+",
        .highest_prefix = "~",
    };

    const plain = try formatMemberToken(allocator, member, .{});
    defer allocator.free(plain);
    try std.testing.expectEqualStrings("~alice", plain);

    const multiprefix = try formatMemberToken(allocator, member, .{ .multi_prefix = true });
    defer allocator.free(multiprefix);
    try std.testing.expectEqualStrings("~.@+alice", multiprefix);

    const userhost = try formatMemberToken(allocator, member, .{ .userhost_in_names = true });
    defer allocator.free(userhost);
    try std.testing.expectEqualStrings("~alice!aliceu@client.example", userhost);

    const both = try formatMemberToken(allocator, member, .{
        .multi_prefix = true,
        .userhost_in_names = true,
    });
    defer allocator.free(both);
    try std.testing.expectEqualStrings("~.@+alice!aliceu@client.example", both);
}

//! Pure IRCv3 NAMESX and UHNAMES member-entry formatting.
//!
//! This module owns only the per-member token that appears inside the trailing
//! RPL_NAMREPLY (353) names list. Reply folding, channel visibility, membership
//! ordering, and validation are caller responsibilities.
const std = @import("std");
const numeric = @import("numeric.zig");

pub const rpl_namreply = numeric.Numeric.RPL_NAMREPLY;
pub const rpl_endofnames = numeric.Numeric.RPL_ENDOFNAMES;

pub const multi_prefix_cap = "multi-prefix";
pub const uhnames_cap = "userhost-in-names";
pub const isupport_prefix = "(Qqov)~.@+";

pub const NamesxError = error{
    OutputTooSmall,
};

/// Mizuchi channel member ranks, highest authority last for compact bit layout.
/// Wire mapping: founder +Q '~' > owner +q '.' > op +o '@' > voice +v '+'.
pub const MemberRank = enum(u3) {
    voice,
    op,
    owner,
    founder,
};

/// Tiny bitset for all NAMES-visible member prefix ranks.
pub const MemberRanks = struct {
    bits: u8 = 0,

    pub fn empty() MemberRanks {
        return .{};
    }

    pub fn fromRanks(ranks: []const MemberRank) MemberRanks {
        var set = MemberRanks.empty();
        for (ranks) |rank| set.add(rank);
        return set;
    }

    pub fn add(self: *MemberRanks, rank: MemberRank) void {
        self.bits |= bit(rank);
    }

    pub fn remove(self: *MemberRanks, rank: MemberRank) void {
        self.bits &= ~bit(rank);
    }

    pub fn contains(self: MemberRanks, rank: MemberRank) bool {
        return (self.bits & bit(rank)) != 0;
    }
};

pub const Ranks = MemberRanks;

/// Inline prefix string returned by prefixesFor().
pub const PrefixString = struct {
    bytes: [4]u8 = [_]u8{0} ** 4,
    len: u8 = 0,

    pub fn asSlice(self: *const PrefixString) []const u8 {
        return self.bytes[0..self.len];
    }
};

/// Return the visible NAMES prefix string for `ranks`.
///
/// With `multi_prefix`, all held prefixes are emitted in highest-to-lowest
/// order. Without it, only the single highest held prefix is emitted.
pub fn prefixesFor(ranks: MemberRanks, multi_prefix: bool) PrefixString {
    var out = PrefixString{};

    if (multi_prefix) {
        if (ranks.contains(.founder)) appendPrefix(&out, '~');
        if (ranks.contains(.owner)) appendPrefix(&out, '.');
        if (ranks.contains(.op)) appendPrefix(&out, '@');
        if (ranks.contains(.voice)) appendPrefix(&out, '+');
        return out;
    }

    if (ranks.contains(.founder)) {
        appendPrefix(&out, '~');
    } else if (ranks.contains(.owner)) {
        appendPrefix(&out, '.');
    } else if (ranks.contains(.op)) {
        appendPrefix(&out, '@');
    } else if (ranks.contains(.voice)) {
        appendPrefix(&out, '+');
    }

    return out;
}

/// Write `PREFIXnick`, or `PREFIXnick!user@host` when UHNAMES is enabled.
pub fn formatNamesEntry(
    out: []u8,
    multi_prefix: bool,
    uhnames: bool,
    nick: []const u8,
    user: []const u8,
    host: []const u8,
    ranks: MemberRanks,
) NamesxError![]const u8 {
    var prefixes = prefixesFor(ranks, multi_prefix);
    const prefix_bytes = prefixes.asSlice();
    const needed = entryLen(prefix_bytes, uhnames, nick, user, host) catch return error.OutputTooSmall;
    if (out.len < needed) return error.OutputTooSmall;

    var n: usize = 0;
    append(out, &n, prefix_bytes);
    append(out, &n, nick);
    if (uhnames) {
        appendByte(out, &n, '!');
        append(out, &n, user);
        appendByte(out, &n, '@');
        append(out, &n, host);
    }
    return out[0..n];
}

fn entryLen(
    prefixes: []const u8,
    uhnames: bool,
    nick: []const u8,
    user: []const u8,
    host: []const u8,
) error{Overflow}!usize {
    var len = try addLen(prefixes.len, nick.len);
    if (uhnames) {
        len = try addLen(len, 1);
        len = try addLen(len, user.len);
        len = try addLen(len, 1);
        len = try addLen(len, host.len);
    }
    return len;
}

fn addLen(a: usize, b: usize) error{Overflow}!usize {
    return std.math.add(usize, a, b) catch error.Overflow;
}

fn bit(rank: MemberRank) u8 {
    return @as(u8, 1) << @intFromEnum(rank);
}

fn appendPrefix(out: *PrefixString, prefix: u8) void {
    out.bytes[out.len] = prefix;
    out.len += 1;
}

fn append(out: []u8, n: *usize, bytes: []const u8) void {
    @memcpy(out[n.*..][0..bytes.len], bytes);
    n.* += bytes.len;
}

fn appendByte(out: []u8, n: *usize, byte: u8) void {
    out[n.*] = byte;
    n.* += 1;
}

test "single vs multi prefix for founder op voice member" {
    const allocator = std.testing.allocator;
    const ranks = MemberRanks.fromRanks(&.{ .founder, .op, .voice });

    const single = prefixesFor(ranks, false);
    try std.testing.expectEqualStrings("~", single.asSlice());

    const multi = prefixesFor(ranks, true);
    try std.testing.expectEqualStrings("~@+", multi.asSlice());

    const out = try allocator.alloc(u8, 32);
    defer allocator.free(out);

    try std.testing.expectEqualStrings(
        "~alice",
        try formatNamesEntry(out, false, false, "alice", "aliceu", "host.example", ranks),
    );
    try std.testing.expectEqualStrings(
        "~@+alice",
        try formatNamesEntry(out, true, false, "alice", "aliceu", "host.example", ranks),
    );
}

test "uhnames on and off" {
    const allocator = std.testing.allocator;
    const ranks = MemberRanks.fromRanks(&.{.owner});
    const out = try allocator.alloc(u8, 64);
    defer allocator.free(out);

    try std.testing.expectEqualStrings(
        ".alice",
        try formatNamesEntry(out, false, false, "alice", "aliceu", "client.example", ranks),
    );
    try std.testing.expectEqualStrings(
        ".alice!aliceu@client.example",
        try formatNamesEntry(out, false, true, "alice", "aliceu", "client.example", ranks),
    );
}

test "overflow returns output too small" {
    const allocator = std.testing.allocator;
    const ranks = MemberRanks.fromRanks(&.{ .founder, .owner, .op, .voice });
    const out = try allocator.alloc(u8, 4);
    defer allocator.free(out);

    try std.testing.expectError(
        error.OutputTooSmall,
        formatNamesEntry(out, true, true, "alice", "aliceu", "client.example", ranks),
    );
}

test "ordering highest to lowest" {
    const allocator = std.testing.allocator;
    const ranks = MemberRanks.fromRanks(&.{ .voice, .owner, .founder, .op });
    const multi = prefixesFor(ranks, true);
    try std.testing.expectEqualStrings("~.@+", multi.asSlice());

    const out = try allocator.alloc(u8, 32);
    defer allocator.free(out);

    try std.testing.expectEqualStrings(
        "~.@+alice",
        try formatNamesEntry(out, true, false, "alice", "aliceu", "host.example", ranks),
    );
}

test "consumes numeric metadata" {
    try std.testing.expectEqual(@as(u16, 353), numeric.code(rpl_namreply));
    try std.testing.expectEqual(@as(u16, 366), numeric.code(rpl_endofnames));
}

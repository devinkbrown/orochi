//! Per-client session snapshot — the wire format carried across a Helix UPGRADE
//! so a registered client can be re-created on the successor.
//!
//! This is the *content* of a per-client capsule field: the identity/state needed
//! to reconstruct a recognizable registered session (nick, realname, account,
//! visible + real host, away, oper). The client's socket fd is carried separately
//! (SCM_RIGHTS / inherited fd); this is only the session state that pairs with it.
//! Caps, umodes, and channel membership are a later increment.
//!
//! Wire format (all integers little-endian):
//!   [u16 len][nick][u16 len][realname][u16 len][account]
//!   [u16 len][real_host][u16 len][host][u16 len][away]
//!   [u8 flags]   bit0=logged_in  bit1=away_active  bit2=is_oper
//!   [i32 fd]     the client's socket fd (inherited across execve), -1 if none
const std = @import("std");

pub const Error = error{ Truncated, TooLong };

/// A plain, allocation-free view of a client's session state.
pub const Snapshot = struct {
    nick: []const u8 = "",
    realname: []const u8 = "",
    account: []const u8 = "",
    real_host: []const u8 = "",
    host: []const u8 = "",
    away: []const u8 = "",
    logged_in: bool = false,
    away_active: bool = false,
    is_oper: bool = false,
    /// The client's socket fd, preserved across execve (CLOEXEC cleared by the
    /// predecessor) so the successor re-attaches the live connection. -1 = none.
    fd: i32 = -1,
};

const flag_logged_in: u8 = 1 << 0;
const flag_away_active: u8 = 1 << 1;
const flag_is_oper: u8 = 1 << 2;

/// Encode `snap` into a freshly-allocated buffer the caller owns.
pub fn encode(allocator: std.mem.Allocator, snap: Snapshot) (Error || std.mem.Allocator.Error)![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    inline for (.{ snap.nick, snap.realname, snap.account, snap.real_host, snap.host, snap.away }) |s| {
        if (s.len > std.math.maxInt(u16)) return error.TooLong;
        var len_le: [2]u8 = undefined;
        std.mem.writeInt(u16, &len_le, @intCast(s.len), .little);
        try out.appendSlice(allocator, &len_le);
        try out.appendSlice(allocator, s);
    }
    var flags: u8 = 0;
    if (snap.logged_in) flags |= flag_logged_in;
    if (snap.away_active) flags |= flag_away_active;
    if (snap.is_oper) flags |= flag_is_oper;
    try out.append(allocator, flags);
    var fd_le: [4]u8 = undefined;
    std.mem.writeInt(i32, &fd_le, snap.fd, .little);
    try out.appendSlice(allocator, &fd_le);
    return out.toOwnedSlice(allocator);
}

/// Decode a snapshot, returning views that borrow `bytes`.
pub fn decode(bytes: []const u8) Error!Snapshot {
    var r = Reader{ .buf = bytes };
    const nick = try r.lenPrefixed();
    const realname = try r.lenPrefixed();
    const account = try r.lenPrefixed();
    const real_host = try r.lenPrefixed();
    const host = try r.lenPrefixed();
    const away = try r.lenPrefixed();
    const flags = try r.byte();
    const fd = try r.i32le();
    return .{
        .nick = nick,
        .realname = realname,
        .account = account,
        .real_host = real_host,
        .host = host,
        .away = away,
        .logged_in = flags & flag_logged_in != 0,
        .away_active = flags & flag_away_active != 0,
        .is_oper = flags & flag_is_oper != 0,
        .fd = fd,
    };
}

const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    fn byte(self: *Reader) Error!u8 {
        if (self.pos + 1 > self.buf.len) return error.Truncated;
        const b = self.buf[self.pos];
        self.pos += 1;
        return b;
    }
    fn i32le(self: *Reader) Error!i32 {
        if (self.pos + 4 > self.buf.len) return error.Truncated;
        const v = std.mem.readInt(i32, self.buf[self.pos..][0..4], .little);
        self.pos += 4;
        return v;
    }
    fn lenPrefixed(self: *Reader) Error![]const u8 {
        if (self.pos + 2 > self.buf.len) return error.Truncated;
        const n = std.mem.readInt(u16, self.buf[self.pos..][0..2], .little);
        self.pos += 2;
        if (self.pos + n > self.buf.len) return error.Truncated;
        const s = self.buf[self.pos .. self.pos + n];
        self.pos += n;
        return s;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "snapshot encode/decode round-trips identity + flags" {
    const allocator = testing.allocator;
    const snap = Snapshot{
        .nick = "alice",
        .realname = "Alice Example",
        .account = "alice",
        .real_host = "10.0.0.5",
        .host = "cloak-ab12.mizuchi",
        .away = "biab",
        .logged_in = true,
        .away_active = true,
        .is_oper = false,
        .fd = 42,
    };
    const bytes = try encode(allocator, snap);
    defer allocator.free(bytes);

    const got = try decode(bytes);
    try testing.expectEqual(@as(i32, 42), got.fd);
    try testing.expectEqualStrings("alice", got.nick);
    try testing.expectEqualStrings("Alice Example", got.realname);
    try testing.expectEqualStrings("alice", got.account);
    try testing.expectEqualStrings("10.0.0.5", got.real_host);
    try testing.expectEqualStrings("cloak-ab12.mizuchi", got.host);
    try testing.expectEqualStrings("biab", got.away);
    try testing.expect(got.logged_in and got.away_active and !got.is_oper);
}

test "empty snapshot round-trips" {
    const allocator = testing.allocator;
    const bytes = try encode(allocator, .{});
    defer allocator.free(bytes);
    const got = try decode(bytes);
    try testing.expectEqual(@as(usize, 0), got.nick.len);
    try testing.expect(!got.logged_in and !got.away_active and !got.is_oper);
}

test "decode rejects a truncated buffer" {
    try testing.expectError(error.Truncated, decode(&[_]u8{ 5, 0, 'a' })); // claims 5, has 1
    try testing.expectError(error.Truncated, decode(&[_]u8{0})); // first length cut off
}

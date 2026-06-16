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
//!   [u16 nchan]  ( [u16 len][name][u8 member-modes] )*   channel memberships
//!   [i64 connected_at_ms][i64 last_message_ms]   OPTIONAL trailing block
//!
//! The trailing signon block carries the client's CLOCK_MONOTONIC signon and
//! last-message timestamps so WHOIS idle/signon survive an in-place UPGRADE.
//! CLOCK_MONOTONIC is system-wide and unaffected by execve, so the predecessor's
//! values stay directly comparable on the successor (same host, same boot). The
//! block is OPTIONAL: a snapshot written by a pre-signon build omits it, and the
//! decoder defaults both to 0 so the successor falls back to "now" — no client is
//! dropped on the single upgrade that crosses this format change.
const std = @import("std");

pub const Error = error{ Truncated, TooLong };

/// One channel membership carried for a client: the channel name + the member's
/// status-mode bits (chanmode.MemberModes.bits).
pub const ChannelMembership = struct {
    name: []const u8,
    modes: u8 = 0,
};

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
    /// Channel memberships to re-join on the successor (ENCODE input only).
    channels: []const ChannelMembership = &.{},
    /// The raw trailing channel-list bytes (DECODE output); walk via `channelIter`.
    channels_blob: []const u8 = "",
    /// CLOCK_MONOTONIC signon timestamp (ms). 0 = unknown (pre-signon snapshot);
    /// the successor falls back to its own "now" when restoring.
    connected_at_ms: i64 = 0,
    /// CLOCK_MONOTONIC last-message timestamp (ms) driving WHOIS idle. 0 = unknown.
    last_message_ms: i64 = 0,
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

    if (snap.channels.len > std.math.maxInt(u16)) return error.TooLong;
    var nch_le: [2]u8 = undefined;
    std.mem.writeInt(u16, &nch_le, @intCast(snap.channels.len), .little);
    try out.appendSlice(allocator, &nch_le);
    for (snap.channels) |ch| {
        if (ch.name.len > std.math.maxInt(u16)) return error.TooLong;
        var len_le: [2]u8 = undefined;
        std.mem.writeInt(u16, &len_le, @intCast(ch.name.len), .little);
        try out.appendSlice(allocator, &len_le);
        try out.appendSlice(allocator, ch.name);
        try out.append(allocator, ch.modes);
    }
    // Trailing signon block (see file header): two monotonic timestamps so the
    // successor can restore WHOIS idle/signon across an in-place UPGRADE.
    var ts_le: [8]u8 = undefined;
    std.mem.writeInt(i64, &ts_le, snap.connected_at_ms, .little);
    try out.appendSlice(allocator, &ts_le);
    std.mem.writeInt(i64, &ts_le, snap.last_message_ms, .little);
    try out.appendSlice(allocator, &ts_le);
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
    // The channel list begins here; the iterator self-limits by its leading count,
    // so `channels_blob` stays "the rest" exactly as before — trailing signon
    // bytes (if any) sit past the counted entries and are never iterated.
    const channels_blob = r.buf[r.pos..];
    // Locate the optional trailing signon block by walking past the channel list.
    var connected_at_ms: i64 = 0;
    var last_message_ms: i64 = 0;
    if (channelRegionEnd(r.buf, r.pos)) |chan_end| {
        if (r.buf.len - chan_end >= 16) {
            connected_at_ms = std.mem.readInt(i64, r.buf[chan_end..][0..8], .little);
            last_message_ms = std.mem.readInt(i64, r.buf[chan_end + 8 ..][0..8], .little);
        }
    }
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
        .channels_blob = channels_blob,
        .connected_at_ms = connected_at_ms,
        .last_message_ms = last_message_ms,
    };
}

/// Iterator over a decoded snapshot's `channels_blob` (the trailing channel list).
pub const ChannelIter = struct {
    blob: []const u8,
    pos: usize = 0,
    remaining: ?u16 = null,

    pub fn next(self: *ChannelIter) ?ChannelMembership {
        if (self.remaining == null) {
            if (self.blob.len < 2) {
                self.remaining = 0;
                return null;
            }
            self.remaining = std.mem.readInt(u16, self.blob[0..2], .little);
            self.pos = 2;
        }
        if (self.remaining.? == 0) return null;
        if (self.pos + 2 > self.blob.len) return null;
        const n = std.mem.readInt(u16, self.blob[self.pos..][0..2], .little);
        self.pos += 2;
        if (self.pos + n + 1 > self.blob.len) return null;
        const name = self.blob[self.pos .. self.pos + n];
        self.pos += n;
        const modes = self.blob[self.pos];
        self.pos += 1;
        self.remaining.? -= 1;
        return .{ .name = name, .modes = modes };
    }
};

pub fn channelIter(blob: []const u8) ChannelIter {
    return .{ .blob = blob };
}

/// Return the absolute offset in `buf` one past the channel list that starts at
/// `start` (a u16 count followed by that many `[u16 len][name][u8 modes]` entries),
/// or null if the list is malformed/truncated. Used only to locate the optional
/// trailing signon block; channel iteration itself is unaffected.
fn channelRegionEnd(buf: []const u8, start: usize) ?usize {
    if (buf.len - start < 2) return null;
    const nchan = std.mem.readInt(u16, buf[start..][0..2], .little);
    var p = start + 2;
    var i: u16 = 0;
    while (i < nchan) : (i += 1) {
        if (p + 2 > buf.len) return null;
        const n = std.mem.readInt(u16, buf[p..][0..2], .little);
        p += 2;
        if (p + n + 1 > buf.len) return null;
        p += n + 1;
    }
    return p;
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
        .host = "cloak-ab12.orochi",
        .away = "biab",
        .logged_in = true,
        .away_active = true,
        .is_oper = false,
        .fd = 42,
        .channels = &.{
            .{ .name = "#ops", .modes = 0b101 },
            .{ .name = "#lounge", .modes = 0 },
        },
        .connected_at_ms = 1_700_000_000_123,
        .last_message_ms = 1_700_000_500_456,
    };
    const bytes = try encode(allocator, snap);
    defer allocator.free(bytes);

    const got = try decode(bytes);
    try testing.expectEqual(@as(i32, 42), got.fd);
    try testing.expectEqual(@as(i64, 1_700_000_000_123), got.connected_at_ms);
    try testing.expectEqual(@as(i64, 1_700_000_500_456), got.last_message_ms);
    var it = channelIter(got.channels_blob);
    const c0 = it.next().?;
    try testing.expectEqualStrings("#ops", c0.name);
    try testing.expectEqual(@as(u8, 0b101), c0.modes);
    const c1 = it.next().?;
    try testing.expectEqualStrings("#lounge", c1.name);
    try testing.expect(it.next() == null);
    try testing.expectEqualStrings("alice", got.nick);
    try testing.expectEqualStrings("Alice Example", got.realname);
    try testing.expectEqualStrings("alice", got.account);
    try testing.expectEqualStrings("10.0.0.5", got.real_host);
    try testing.expectEqualStrings("cloak-ab12.orochi", got.host);
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
    try testing.expectEqual(@as(i64, 0), got.connected_at_ms);
    try testing.expectEqual(@as(i64, 0), got.last_message_ms);
}

test "decode tolerates a pre-signon snapshot (no trailing block)" {
    const allocator = testing.allocator;
    // Build a snapshot, then truncate the 16-byte trailing signon block to emulate
    // a capsule written by a build that predates the signon-carry format change.
    const bytes = try encode(allocator, .{
        .nick = "bob",
        .fd = 7,
        .channels = &.{.{ .name = "#a", .modes = 1 }},
        .connected_at_ms = 1234,
        .last_message_ms = 5678,
    });
    defer allocator.free(bytes);
    const old = bytes[0 .. bytes.len - 16];

    const got = try decode(old);
    try testing.expectEqualStrings("bob", got.nick);
    try testing.expectEqual(@as(i32, 7), got.fd);
    // Channels still parse; signon defaults to 0 → successor falls back to "now".
    var it = channelIter(got.channels_blob);
    const c0 = it.next().?;
    try testing.expectEqualStrings("#a", c0.name);
    try testing.expect(it.next() == null);
    try testing.expectEqual(@as(i64, 0), got.connected_at_ms);
    try testing.expectEqual(@as(i64, 0), got.last_message_ms);
}

test "decode rejects a truncated buffer" {
    try testing.expectError(error.Truncated, decode(&[_]u8{ 5, 0, 'a' })); // claims 5, has 1
    try testing.expectError(error.Truncated, decode(&[_]u8{0})); // first length cut off
}

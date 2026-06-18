//! Per-client session snapshot — the wire format carried across a Helix UPGRADE
//! so a registered client can be re-created on the successor.
//!
//! This is the *content* of a per-client capsule field: the identity/state needed
//! to reconstruct a recognizable registered session (nick, realname, account,
//! visible + real host, away, oper + the full oper grant). The client's socket fd
//! is carried separately (SCM_RIGHTS / inherited fd); this is only the session
//! state that pairs with it. Client-settable umodes are a later increment.
//!
//! Wire format (all integers little-endian):
//!   [u16 len][nick][u16 len][realname][u16 len][account]
//!   [u16 len][real_host][u16 len][host][u16 len][away]
//!   [u8 flags]   bit0=logged_in  bit1=away_active  bit2=is_oper
//!   [i32 fd]     the client's socket fd (inherited across execve), -1 if none
//!   [u16 nchan]  ( [u16 len][name][u8 member-modes] )*   channel memberships
//!   [i64 connected_at_ms][i64 last_message_ms]   OPTIONAL trailing block
//!   [u16 len][caps]   OPTIONAL trailing CAP list (space-separated names)
//!   [u64 oper_priv_bits][u16 len][oper_class][u16 len][oper_title]  OPTIONAL
//!
//! The oper-grant block (OPTIONAL, written after the caps block) carries the
//! operator's privilege bits (OperPrivileges.toBits — append-only ordinals) plus
//! class + title, so a restored oper keeps its FULL grant and the server-managed
//! +a admin umode derives correctly. Omitting it (pre-grant build) decodes to 0
//! bits → a bare `is_oper` with no privileges, exactly the pre-fix behavior.
//!
//! The trailing signon block carries the client's CLOCK_MONOTONIC signon and
//! last-message timestamps so WHOIS idle/signon survive an in-place UPGRADE.
//! CLOCK_MONOTONIC is system-wide and unaffected by execve, so the predecessor's
//! values stay directly comparable on the successor (same host, same boot). The
//! block is OPTIONAL: a snapshot written by a pre-signon build omits it, and the
//! decoder defaults both to 0 so the successor falls back to "now" — no client is
//! dropped on the single upgrade that crosses this format change.
//!
//! The caps block (also OPTIONAL, written only after the signon block) carries the
//! negotiated IRCv3 CAP set BY NAME — a space-separated list like
//! "echo-message server-time message-tags". Names, not raw bits, because the
//! CapId bit positions shift whenever an upgrade adds/removes/reorders a cap; a
//! name survives that and an unknown name is simply dropped on restore. Omitting
//! it (pre-caps build) decodes to "" so the successor restores no caps — exactly
//! the pre-fix behavior, never a misattributed bit.
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
    /// Negotiated IRCv3 CAP names, space-separated (e.g. "echo-message sasl").
    /// Empty = no caps carried (pre-caps snapshot, or none negotiated). Carried
    /// by name so it survives a build that adds/removes/reorders cap bits.
    caps: []const u8 = "",
    /// Operator grant carried across the UPGRADE so a restored oper keeps its FULL
    /// privilege set — and the derived +a admin umode — not just the `is_oper`
    /// bool. `oper_priv_bits` is `OperPrivileges.toBits()` (append-only ordinals).
    /// 0 bits / empty strings = no grant carried (pre-grant snapshot) → restores
    /// as a bare `is_oper`, exactly the prior behavior.
    oper_priv_bits: u64 = 0,
    oper_class: []const u8 = "",
    oper_title: []const u8 = "",
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
    // Trailing CAP block (see file header): the negotiated cap set, by name, so it
    // survives a build that shifts cap bit positions. Sits past the signon block.
    if (snap.caps.len > std.math.maxInt(u16)) return error.TooLong;
    var caps_len_le: [2]u8 = undefined;
    std.mem.writeInt(u16, &caps_len_le, @intCast(snap.caps.len), .little);
    try out.appendSlice(allocator, &caps_len_le);
    try out.appendSlice(allocator, snap.caps);
    // Trailing oper-grant block (see header): privilege bits + class + title so a
    // restored oper keeps its full grant (and the derived +a). Sits past caps.
    var bits_le: [8]u8 = undefined;
    std.mem.writeInt(u64, &bits_le, snap.oper_priv_bits, .little);
    try out.appendSlice(allocator, &bits_le);
    inline for (.{ snap.oper_class, snap.oper_title }) |s| {
        if (s.len > std.math.maxInt(u16)) return error.TooLong;
        var len_le: [2]u8 = undefined;
        std.mem.writeInt(u16, &len_le, @intCast(s.len), .little);
        try out.appendSlice(allocator, &len_le);
        try out.appendSlice(allocator, s);
    }
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
    // Locate the optional trailing signon block by walking past the channel list,
    // then the optional CAP block immediately after it. Both default-empty so a
    // capsule from a build predating either field still decodes cleanly.
    var connected_at_ms: i64 = 0;
    var last_message_ms: i64 = 0;
    var caps: []const u8 = "";
    var oper_priv_bits: u64 = 0;
    var oper_class: []const u8 = "";
    var oper_title: []const u8 = "";
    // Walk the optional trailing blocks with a running cursor `p`: signon (16) →
    // caps ([u16][bytes]) → oper grant ([u64][u16][class][u16][title]). Each is
    // gated on enough bytes remaining, so a capsule from a build predating any
    // block decodes cleanly with that block (and everything after it) defaulted.
    if (channelRegionEnd(r.buf, r.pos)) |chan_end| {
        var p = chan_end;
        if (r.buf.len - p >= 16) {
            connected_at_ms = std.mem.readInt(i64, r.buf[p..][0..8], .little);
            last_message_ms = std.mem.readInt(i64, r.buf[p + 8 ..][0..8], .little);
            p += 16;
            if (r.buf.len - p >= 2) {
                const n = std.mem.readInt(u16, r.buf[p..][0..2], .little);
                p += 2;
                if (p + n <= r.buf.len) {
                    caps = r.buf[p .. p + n];
                    p += n;
                } else p = r.buf.len; // malformed caps length → stop
            }
            if (r.buf.len - p >= 8) {
                oper_priv_bits = std.mem.readInt(u64, r.buf[p..][0..8], .little);
                p += 8;
                inline for (.{ &oper_class, &oper_title }) |dst| {
                    if (r.buf.len - p >= 2) {
                        const m = std.mem.readInt(u16, r.buf[p..][0..2], .little);
                        p += 2;
                        if (p + m <= r.buf.len) {
                            dst.* = r.buf[p .. p + m];
                            p += m;
                        }
                    }
                }
            }
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
        .caps = caps,
        .oper_priv_bits = oper_priv_bits,
        .oper_class = oper_class,
        .oper_title = oper_title,
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
        .caps = "echo-message server-time sasl",
    };
    const bytes = try encode(allocator, snap);
    defer allocator.free(bytes);

    const got = try decode(bytes);
    try testing.expectEqual(@as(i32, 42), got.fd);
    try testing.expectEqual(@as(i64, 1_700_000_000_123), got.connected_at_ms);
    try testing.expectEqual(@as(i64, 1_700_000_500_456), got.last_message_ms);
    try testing.expectEqualStrings("echo-message server-time sasl", got.caps);
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
    try testing.expectEqual(@as(usize, 0), got.caps.len);
}

test "caps round-trip and empty caps decode to empty" {
    const allocator = testing.allocator;
    const bytes = try encode(allocator, .{ .nick = "n", .caps = "" });
    defer allocator.free(bytes);
    const got = try decode(bytes);
    try testing.expectEqual(@as(usize, 0), got.caps.len);
}

test "decode tolerates a pre-signon snapshot (no trailing blocks)" {
    const allocator = testing.allocator;
    // Build a snapshot, then truncate the 16-byte signon block + 2-byte caps block
    // to emulate a capsule written by a build that predates both trailing fields.
    const bytes = try encode(allocator, .{
        .nick = "bob",
        .fd = 7,
        .channels = &.{.{ .name = "#a", .modes = 1 }},
        .connected_at_ms = 1234,
        .last_message_ms = 5678,
    });
    defer allocator.free(bytes);
    const old = bytes[0 .. bytes.len - 18];

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
    try testing.expectEqual(@as(usize, 0), got.caps.len);
}

test "decode tolerates a pre-caps snapshot (signon present, caps absent)" {
    const allocator = testing.allocator;
    // A capsule from the signon-carry build: it has the 16-byte signon block but no
    // 2-byte caps block. Strip only the caps block; signon must still restore.
    const bytes = try encode(allocator, .{
        .nick = "carol",
        .fd = 9,
        .connected_at_ms = 4321,
        .last_message_ms = 8765,
        .caps = "echo-message",
    });
    defer allocator.free(bytes);
    const old = bytes[0 .. bytes.len - ("echo-message".len + 2)];

    const got = try decode(old);
    try testing.expectEqualStrings("carol", got.nick);
    try testing.expectEqual(@as(i64, 4321), got.connected_at_ms);
    try testing.expectEqual(@as(i64, 8765), got.last_message_ms);
    try testing.expectEqual(@as(usize, 0), got.caps.len);
}

test "oper grant round-trips (priv bits + class + title)" {
    const allocator = testing.allocator;
    const bytes = try encode(allocator, .{
        .nick = "kain",
        .account = "kain",
        .logged_in = true,
        .is_oper = true,
        .caps = "sasl",
        .oper_priv_bits = 0x0000_0000_0000_0140, // arbitrary bitmask
        .oper_class = "admin",
        .oper_title = "Server Administrator",
    });
    defer allocator.free(bytes);
    const got = try decode(bytes);
    try testing.expect(got.is_oper);
    try testing.expectEqual(@as(u64, 0x0000_0000_0000_0140), got.oper_priv_bits);
    try testing.expectEqualStrings("admin", got.oper_class);
    try testing.expectEqualStrings("Server Administrator", got.oper_title);
    try testing.expectEqualStrings("sasl", got.caps); // caps still parse before the oper block
}

test "decode tolerates a pre-oper-grant snapshot (caps present, oper block absent)" {
    const allocator = testing.allocator;
    // A capsule from the caps-carry build: signon + caps blocks, but no oper block.
    // Strip the oper block (8 bits + two empty len-prefixed strings = 8+2+2=12).
    const bytes = try encode(allocator, .{ .nick = "dan", .caps = "echo-message", .is_oper = true });
    defer allocator.free(bytes);
    const old = bytes[0 .. bytes.len - 12];
    const got = try decode(old);
    try testing.expectEqualStrings("dan", got.nick);
    try testing.expectEqualStrings("echo-message", got.caps);
    try testing.expect(got.is_oper);
    try testing.expectEqual(@as(u64, 0), got.oper_priv_bits); // defaulted → bare is_oper
    try testing.expectEqual(@as(usize, 0), got.oper_class.len);
}

test "decode rejects a truncated buffer" {
    try testing.expectError(error.Truncated, decode(&[_]u8{ 5, 0, 'a' })); // claims 5, has 1
    try testing.expectError(error.Truncated, decode(&[_]u8{0})); // first length cut off
}

// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! MEMBERSHIP frame payload codec (S2S remote-member propagation, #6 live).
//!
//! Carries one convergent membership fact between mesh peers: "on `origin_node`,
//! nick `nick` is present in `channel` with `status`, as of `hlc`" (or, when
//! `present` is false, has left). The route table applies these last-writer-wins
//! by `hlc` (see route_table.applyMembership), so out-of-order delivery still
//! converges. Alongside the membership fact the event carries the member's
//! visible identity (username, realname, cloaked/visible host) so remote peers
//! can render the real `user@host` in NAMES/JOIN/WHOIS instead of a
//! `mesh@<server>` placeholder. Compact fixed binary layout (little-endian):
//!
//!   present:u8 | status:u8 | origin_node:u64 | hlc:u64 |
//!   chan_len:u16 | chan… | nick_len:u16 | nick… |
//!   user_len:u16 | user… | real_len:u16 | real… | host_len:u16 | host… |
//!   [setter_len:u16 | setter…] [account_len:u16 | account…]
//!
//! The trailing `setter` and `account` blocks are OPTIONAL and disambiguated by
//! COUNT, not by a tag: zero trailing blocks = neither; one = `setter` only (the
//! pre-account wire format, what older peers emit); two = `setter` (possibly
//! empty) then `account`. Because a lone trailing block is always `setter`, the
//! encoder FORCES an (empty) setter slot whenever it appends an account, so the
//! account is unambiguously the second block. The daemon only sets `account` for
//! a peer that negotiated the member-account handshake feature, so an older peer
//! (strict `TrailingBytes`) never receives the second block.
//!
//! Bounded by the per-field limits so a hostile peer cannot pin large buffers;
//! decode borrows the input (no allocation). Identity fields may be empty
//! (e.g. on a part event); consumers substitute their placeholder fallbacks.
const std = @import("std");

pub const max_channel_len = 128;
pub const max_nick_len = 64;
pub const max_username_len = 32;
pub const max_realname_len = 256;
pub const max_host_len = 255;
pub const max_setter_len = 64;
pub const max_account_len = 64;
/// Real (uncloaked) host/IP — only ever emitted over a SECURED link to an
/// oper-info-capable peer, and shown only to operators on the receiving node.
pub const max_real_host_len = 255;
/// TLS client-certificate fingerprint (lowercase SHA-256 hex = 64 chars).
pub const max_certfp_len = 64;
const fixed_prefix = 1 + 1 + 8 + 8; // present, status, origin_node, hlc

/// Upper bound on one encoded event (all fields at their limits) — size the
/// stack encode buffer with this.
pub const max_encoded_len = fixed_prefix +
    2 + max_channel_len +
    2 + max_nick_len +
    2 + max_username_len +
    2 + max_realname_len +
    2 + max_host_len +
    2 + max_setter_len +
    2 + max_account_len +
    2 + max_real_host_len +
    2 + max_certfp_len;

pub const Error = error{
    Truncated,
    NameTooLong,
    TrailingBytes,
};

pub const MembershipEvent = struct {
    present: bool,
    status: u4,
    origin_node: u64,
    hlc: u64,
    channel: []const u8, // borrows the encode buffer (encode) / input (decode)
    nick: []const u8,
    /// The member's username (USER ident) as its home node sees it ("" = unknown).
    username: []const u8 = "",
    /// The member's realname (GECOS) ("" = unknown).
    realname: []const u8 = "",
    /// The member's VISIBLE host — cloak/vhost when set ("" = unknown).
    host: []const u8 = "",
    /// The nick that SET this member's status (for an explicit `/MODE +q`), so a
    /// remote node renders `:setter MODE …` instead of the origin server. "" =
    /// none (join auto-status, services, …); when empty the field is OMITTED from
    /// the wire so an empty-setter event stays byte-identical to the pre-setter
    /// format — backward-compatible for every membership event except a MODE.
    setter: []const u8 = "",
    /// The member's authenticated ACCOUNT name ("" = not logged in / unknown).
    /// Lets a remote node recognize that a colliding nick is the SAME identity
    /// (account-aware reconcile) instead of running an account-blind contest that
    /// would rename a logged-in user to its mesh UID. OPTIONAL trailing block:
    /// emitted only when non-empty AND the peer negotiated the member-account
    /// feature; when emitted it always follows a (possibly empty) setter block.
    account: []const u8 = "",
    /// The member's REAL (uncloaked) host/IP ("" = unknown/withheld). SENSITIVE:
    /// emitted only over a SECURED link to a peer that negotiated `member-oper-info`
    /// (see cap_member_oper_info), and surfaced only to operators on the receiver.
    /// OPTIONAL trailing block #3 — follows a (possibly empty) setter+account.
    real_host: []const u8 = "",
    /// The member's TLS client-cert fingerprint ("" = none). Same sensitivity and
    /// gating as `real_host`. OPTIONAL trailing block #4 — follows real_host.
    certfp: []const u8 = "",
};

pub fn encodedLen(ev: MembershipEvent) Error!usize {
    if (ev.channel.len > max_channel_len or ev.nick.len > max_nick_len) return error.NameTooLong;
    if (ev.username.len > max_username_len) return error.NameTooLong;
    if (ev.realname.len > max_realname_len) return error.NameTooLong;
    if (ev.host.len > max_host_len) return error.NameTooLong;
    if (ev.setter.len > max_setter_len) return error.NameTooLong;
    if (ev.account.len > max_account_len) return error.NameTooLong;
    if (ev.real_host.len > max_real_host_len) return error.NameTooLong;
    if (ev.certfp.len > max_certfp_len) return error.NameTooLong;
    // Optional trailing blocks are positional and disambiguated by COUNT, so any
    // present block forces (possibly empty) slots for every earlier optional block:
    // setter(1) < account(2) < real_host(3) < certfp(4). An event with none stays
    // byte-identical to the pre-setter wire format.
    const want_certfp = ev.certfp.len != 0;
    const want_real_host = ev.real_host.len != 0 or want_certfp;
    const want_account = ev.account.len != 0 or want_real_host;
    const setter_slot = ev.setter.len != 0 or want_account;
    return fixed_prefix +
        2 + ev.channel.len +
        2 + ev.nick.len +
        2 + ev.username.len +
        2 + ev.realname.len +
        2 + ev.host.len +
        (if (setter_slot) @as(usize, 2 + ev.setter.len) else 0) +
        (if (want_account) @as(usize, 2 + ev.account.len) else 0) +
        (if (want_real_host) @as(usize, 2 + ev.real_host.len) else 0) +
        (if (want_certfp) @as(usize, 2 + ev.certfp.len) else 0);
}

fn putBytes16(out: []u8, i: *usize, bytes: []const u8) void {
    std.mem.writeInt(u16, out[i.*..][0..2], @intCast(bytes.len), .little);
    i.* += 2;
    @memcpy(out[i.*..][0..bytes.len], bytes);
    i.* += bytes.len;
}

/// Encode into `out`; returns the written slice. `out` must be >= encodedLen.
pub fn encode(ev: MembershipEvent, out: []u8) Error![]const u8 {
    const need = try encodedLen(ev);
    if (out.len < need) return error.Truncated;
    var i: usize = 0;
    out[i] = @intFromBool(ev.present);
    i += 1;
    out[i] = ev.status;
    i += 1;
    std.mem.writeInt(u64, out[i..][0..8], ev.origin_node, .little);
    i += 8;
    std.mem.writeInt(u64, out[i..][0..8], ev.hlc, .little);
    i += 8;
    putBytes16(out, &i, ev.channel);
    putBytes16(out, &i, ev.nick);
    putBytes16(out, &i, ev.username);
    putBytes16(out, &i, ev.realname);
    putBytes16(out, &i, ev.host);
    // Optional trailing blocks, positional + count-disambiguated. Any present
    // block forces (possibly empty) slots for every earlier one:
    // setter(1) < account(2) < real_host(3) < certfp(4).
    const want_certfp = ev.certfp.len != 0;
    const want_real_host = ev.real_host.len != 0 or want_certfp;
    const want_account = ev.account.len != 0 or want_real_host;
    if (ev.setter.len != 0 or want_account) putBytes16(out, &i, ev.setter);
    if (want_account) putBytes16(out, &i, ev.account);
    if (want_real_host) putBytes16(out, &i, ev.real_host);
    if (want_certfp) putBytes16(out, &i, ev.certfp);
    return out[0..i];
}

fn takeBytes16(bytes: []const u8, i: *usize, max_len: usize) Error![]const u8 {
    if (bytes.len < i.* + 2) return error.Truncated;
    const len = std.mem.readInt(u16, bytes[i.*..][0..2], .little);
    i.* += 2;
    if (len > max_len) return error.NameTooLong;
    if (bytes.len < i.* + len) return error.Truncated;
    const out = bytes[i.* .. i.* + len];
    i.* += len;
    return out;
}

fn validateLineField(bytes: []const u8, reject_space: bool) Error!void {
    for (bytes) |byte| {
        if (byte < 0x20 or byte == 0x7f or (reject_space and byte == ' ')) {
            return error.NameTooLong;
        }
    }
}

/// Decode from `bytes`; the returned string fields borrow `bytes`.
pub fn decode(bytes: []const u8) Error!MembershipEvent {
    if (bytes.len < fixed_prefix + 2) return error.Truncated;
    var i: usize = 0;
    const present = bytes[i] != 0;
    i += 1;
    const status_raw = bytes[i];
    i += 1;
    if (status_raw > 0x0f) return error.NameTooLong; // status is a u4
    const origin_node = std.mem.readInt(u64, bytes[i..][0..8], .little);
    i += 8;
    const hlc = std.mem.readInt(u64, bytes[i..][0..8], .little);
    i += 8;

    const channel = try takeBytes16(bytes, &i, max_channel_len);
    const nick = try takeBytes16(bytes, &i, max_nick_len);
    const username = try takeBytes16(bytes, &i, max_username_len);
    const realname = try takeBytes16(bytes, &i, max_realname_len);
    const host = try takeBytes16(bytes, &i, max_host_len);
    // Optional trailing blocks, disambiguated by count: the FIRST is always the
    // setter (present on a MODE event or whenever an account follows), the SECOND
    // is the account (newer peers that negotiated the member-account feature).
    // Zero trailing blocks is the common pre-setter wire format.
    // The THIRD trailing block is real_host (oper-info-capable peers), the FOURTH
    // is certfp. An older/plaintext peer never emits them, so they stay "".
    var setter: []const u8 = "";
    var account: []const u8 = "";
    var real_host: []const u8 = "";
    var certfp: []const u8 = "";
    if (i < bytes.len) setter = try takeBytes16(bytes, &i, max_setter_len);
    if (i < bytes.len) account = try takeBytes16(bytes, &i, max_account_len);
    if (i < bytes.len) real_host = try takeBytes16(bytes, &i, max_real_host_len);
    if (i < bytes.len) certfp = try takeBytes16(bytes, &i, max_certfp_len);

    if (i != bytes.len) return error.TrailingBytes;
    if (channel.len == 0 or nick.len == 0) return error.NameTooLong;
    try validateLineField(channel, true);
    try validateLineField(nick, true);
    try validateLineField(username, false);
    try validateLineField(realname, false);
    try validateLineField(host, false);
    try validateLineField(setter, true);
    try validateLineField(account, true);
    try validateLineField(real_host, true);
    try validateLineField(certfp, true);
    return .{
        .present = present,
        .status = @intCast(status_raw),
        .origin_node = origin_node,
        .hlc = hlc,
        .channel = channel,
        .nick = nick,
        .username = username,
        .realname = realname,
        .host = host,
        .setter = setter,
        .account = account,
        .real_host = real_host,
        .certfp = certfp,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "membership event round-trips" {
    const ev = MembershipEvent{
        .present = true,
        .status = 0b0100,
        .origin_node = 0xDEADBEEFCAFE,
        .hlc = 12345,
        .channel = "#chat",
        .nick = "alice",
        .username = "alice",
        .realname = "Alice Liddell",
        .host = "cloak-1a2b3c.users.orochi",
    };
    var buf: [max_encoded_len]u8 = undefined;
    const wire = try encode(ev, &buf);
    try testing.expectEqual(try encodedLen(ev), wire.len);

    const got = try decode(wire);
    try testing.expectEqual(true, got.present);
    try testing.expectEqual(@as(u4, 0b0100), got.status);
    try testing.expectEqual(@as(u64, 0xDEADBEEFCAFE), got.origin_node);
    try testing.expectEqual(@as(u64, 12345), got.hlc);
    try testing.expectEqualStrings("#chat", got.channel);
    try testing.expectEqualStrings("alice", got.nick);
    try testing.expectEqualStrings("alice", got.username);
    try testing.expectEqualStrings("Alice Liddell", got.realname);
    try testing.expectEqualStrings("cloak-1a2b3c.users.orochi", got.host);
}

test "empty identity fields round-trip (legacy placeholder producers)" {
    const ev = MembershipEvent{
        .present = true,
        .status = 0,
        .origin_node = 3,
        .hlc = 7,
        .channel = "#c",
        .nick = "n",
    };
    var buf: [max_encoded_len]u8 = undefined;
    const wire = try encode(ev, &buf);
    const got = try decode(wire);
    try testing.expectEqualStrings("", got.username);
    try testing.expectEqualStrings("", got.realname);
    try testing.expectEqualStrings("", got.host);
}

test "a part event (present=false) round-trips" {
    const ev = MembershipEvent{ .present = false, .status = 0, .origin_node = 7, .hlc = 9, .channel = "&local", .nick = "bob" };
    var buf: [max_encoded_len]u8 = undefined;
    const wire = try encode(ev, &buf);
    const got = try decode(wire);
    try testing.expectEqual(false, got.present);
    try testing.expectEqualStrings("&local", got.channel);
}

test "a part event (present=false) carries identity (mesh-host departure fix)" {
    // The daemon now propagates the departing member's real identity on QUIT/PART
    // (not an empty placeholder), so the far side renders user@host not mesh@srv.
    // Identity must round-trip just like a JOIN, since the codec never branches on
    // `present` — only the membership FACT (present/status/hlc) drives convergence.
    const ev = MembershipEvent{
        .present = false,
        .status = 0,
        .origin_node = 1,
        .hlc = 42,
        .channel = "#root",
        .nick = "sh0rt1e",
        .username = "sh0rt1e",
        .realname = "real name with spaces",
        .host = "8f384d80.c665a180.c2555cf6.ip.ircxnet",
    };
    var buf: [max_encoded_len]u8 = undefined;
    const wire = try encode(ev, &buf);
    const got = try decode(wire);
    try testing.expectEqual(false, got.present);
    try testing.expectEqualStrings("sh0rt1e", got.nick);
    try testing.expectEqualStrings("sh0rt1e", got.username);
    try testing.expectEqualStrings("real name with spaces", got.realname);
    try testing.expectEqualStrings("8f384d80.c665a180.c2555cf6.ip.ircxnet", got.host);
}

test "truncated input is rejected" {
    const ev = MembershipEvent{ .present = true, .status = 1, .origin_node = 1, .hlc = 1, .channel = "#c", .nick = "n", .username = "u", .realname = "r", .host = "h" };
    var buf: [max_encoded_len]u8 = undefined;
    const wire = try encode(ev, &buf);
    // Cut anywhere — every prefix shorter than the full event must be rejected.
    var cut: usize = 0;
    while (cut < wire.len) : (cut += 1) {
        try testing.expectError(error.Truncated, decode(wire[0..cut]));
    }
}

test "trailing bytes are rejected" {
    // Encode WITH ALL FOUR optional blocks (setter + account + real_host + certfp)
    // so every read consumes its field; the pad byte after the full event is then
    // the genuine trailing-bytes case (not a truncated optional block — a lone byte
    // would otherwise look like a truncated real_host/certfp length prefix).
    const ev = MembershipEvent{ .present = true, .status = 1, .origin_node = 1, .hlc = 1, .channel = "#c", .nick = "n", .setter = "kain", .account = "kacct", .real_host = "203.0.113.9", .certfp = "ab" };
    var buf: [max_encoded_len]u8 = undefined;
    const wire = try encode(ev, &buf);
    var padded: [max_encoded_len + 1]u8 = undefined;
    @memcpy(padded[0..wire.len], wire);
    padded[wire.len] = 0xAA;
    try testing.expectError(error.TrailingBytes, decode(padded[0 .. wire.len + 1]));
}

test "account round-trips alongside a setter" {
    const ev = MembershipEvent{ .present = true, .status = 0b0100, .origin_node = 2, .hlc = 9, .channel = "#root", .nick = "kain", .setter = "trev", .account = "kain" };
    var buf: [max_encoded_len]u8 = undefined;
    const got = try decode(try encode(ev, &buf));
    try testing.expectEqualStrings("trev", got.setter);
    try testing.expectEqualStrings("kain", got.account);
}

test "account forces an empty setter slot so it stays the second trailing block" {
    // No setter, but an account: the encoder must emit an EMPTY setter block first
    // so the account is unambiguously the second block on decode.
    const ev = MembershipEvent{ .present = true, .status = 0, .origin_node = 2, .hlc = 9, .channel = "#root", .nick = "kain", .account = "kain" };
    var buf: [max_encoded_len]u8 = undefined;
    const got = try decode(try encode(ev, &buf));
    try testing.expectEqualStrings("", got.setter);
    try testing.expectEqualStrings("kain", got.account);
}

test "a lone trailing block decodes as setter, never account (old-peer compat)" {
    // What an older (pre-account) peer emits for a MODE: a single trailing setter,
    // no account. The new decoder must read it as the setter and leave account "".
    const ev = MembershipEvent{ .present = true, .status = 0b0100, .origin_node = 2, .hlc = 9, .channel = "#root", .nick = "kain", .setter = "trev" };
    var buf: [max_encoded_len]u8 = undefined;
    const got = try decode(try encode(ev, &buf));
    try testing.expectEqualStrings("trev", got.setter);
    try testing.expectEqualStrings("", got.account);
}

test "real_host + certfp round-trip and force the earlier optional slots" {
    // certfp present with no setter/account/real_host: the encoder forces empty
    // setter+account+real_host slots so certfp is unambiguously the 4th block.
    const ev = MembershipEvent{
        .present = true,
        .status = 0b0100,
        .origin_node = 2,
        .hlc = 9,
        .channel = "#root",
        .nick = "kain",
        .real_host = "fe80::921b:eff:fefe:8a87",
        .certfp = "495bfcdfe3a66f6781f41a4e27ba56bc7e347d36aab02f6bde2576bc31846dcb",
    };
    var buf: [max_encoded_len]u8 = undefined;
    const got = try decode(try encode(ev, &buf));
    try testing.expectEqualStrings("", got.setter);
    try testing.expectEqualStrings("", got.account);
    try testing.expectEqualStrings("fe80::921b:eff:fefe:8a87", got.real_host);
    try testing.expectEqualStrings("495bfcdfe3a66f6781f41a4e27ba56bc7e347d36aab02f6bde2576bc31846dcb", got.certfp);
}

test "real_host without certfp leaves certfp empty; absent both stays old-format" {
    const with = MembershipEvent{ .present = true, .status = 0, .origin_node = 2, .hlc = 9, .channel = "#c", .nick = "n", .account = "acct", .real_host = "203.0.113.7" };
    var buf: [max_encoded_len]u8 = undefined;
    const got = try decode(try encode(with, &buf));
    try testing.expectEqualStrings("acct", got.account);
    try testing.expectEqualStrings("203.0.113.7", got.real_host);
    try testing.expectEqualStrings("", got.certfp);

    // No oper-info fields → byte-identical to the pre-oper-info wire (account only).
    const without = MembershipEvent{ .present = true, .status = 0, .origin_node = 2, .hlc = 9, .channel = "#c", .nick = "n", .account = "acct" };
    var buf2: [max_encoded_len]u8 = undefined;
    const got2 = try decode(try encode(without, &buf2));
    try testing.expectEqualStrings("", got2.real_host);
    try testing.expectEqualStrings("", got2.certfp);
}

test "an over-long real_host / certfp is rejected by encode" {
    const big_host = "a" ** (max_real_host_len + 1);
    const ev_h = MembershipEvent{ .present = true, .status = 0, .origin_node = 1, .hlc = 1, .channel = "#c", .nick = "n", .real_host = big_host };
    var buf: [max_encoded_len]u8 = undefined;
    try testing.expectError(error.NameTooLong, encode(ev_h, &buf));
    const big_fp = "a" ** (max_certfp_len + 1);
    const ev_f = MembershipEvent{ .present = true, .status = 0, .origin_node = 1, .hlc = 1, .channel = "#c", .nick = "n", .certfp = big_fp };
    try testing.expectError(error.NameTooLong, encode(ev_f, &buf));
}

test "an over-long account is rejected by encode" {
    const big = "a" ** (max_account_len + 1);
    const ev = MembershipEvent{ .present = true, .status = 0, .origin_node = 1, .hlc = 1, .channel = "#c", .nick = "n", .account = big };
    try testing.expectError(error.NameTooLong, encodedLen(ev));
}

test "setter round-trips and an empty setter stays old-format compatible" {
    // A MODE event carries the setter; it round-trips.
    const with_setter = MembershipEvent{ .present = true, .status = 0b0100, .origin_node = 2, .hlc = 9, .channel = "#root", .nick = "trev", .setter = "kain" };
    var b1: [max_encoded_len]u8 = undefined;
    const w1 = try encode(with_setter, &b1);
    try testing.expectEqualStrings("kain", (try decode(w1)).setter);

    // An empty setter is OMITTED from the wire: the encoding is byte-identical to
    // a struct built WITHOUT a setter field at all (backward/forward compatible).
    const no_setter = MembershipEvent{ .present = true, .status = 0, .origin_node = 2, .hlc = 9, .channel = "#root", .nick = "trev" };
    const empty_setter = MembershipEvent{ .present = true, .status = 0, .origin_node = 2, .hlc = 9, .channel = "#root", .nick = "trev", .setter = "" };
    var b2: [max_encoded_len]u8 = undefined;
    var b3: [max_encoded_len]u8 = undefined;
    const w2 = try encode(no_setter, &b2);
    const w3 = try encode(empty_setter, &b3);
    try testing.expectEqualSlices(u8, w2, w3); // empty setter => identical bytes
    try testing.expectEqualStrings("", (try decode(w3)).setter);
}

test "over-long names are rejected by encode and decode" {
    const big = "#" ++ ("x" ** max_channel_len);
    const ev = MembershipEvent{ .present = true, .status = 0, .origin_node = 1, .hlc = 1, .channel = big, .nick = "n" };
    try testing.expectError(error.NameTooLong, encodedLen(ev));

    const big_user = "u" ** (max_username_len + 1);
    const ev2 = MembershipEvent{ .present = true, .status = 0, .origin_node = 1, .hlc = 1, .channel = "#c", .nick = "n", .username = big_user };
    try testing.expectError(error.NameTooLong, encodedLen(ev2));

    const big_real = "r" ** (max_realname_len + 1);
    const ev3 = MembershipEvent{ .present = true, .status = 0, .origin_node = 1, .hlc = 1, .channel = "#c", .nick = "n", .realname = big_real };
    try testing.expectError(error.NameTooLong, encodedLen(ev3));

    const big_host = "h" ** (max_host_len + 1);
    const ev4 = MembershipEvent{ .present = true, .status = 0, .origin_node = 1, .hlc = 1, .channel = "#c", .nick = "n", .host = big_host };
    try testing.expectError(error.NameTooLong, encodedLen(ev4));
}

test "decode rejects an over-long identity length prefix" {
    // Build a valid event, then corrupt the username length to exceed the cap.
    const ev = MembershipEvent{ .present = true, .status = 0, .origin_node = 1, .hlc = 1, .channel = "#c", .nick = "n", .username = "u" };
    var buf: [max_encoded_len]u8 = undefined;
    const wire = try encode(ev, &buf);
    var corrupt: [max_encoded_len]u8 = undefined;
    @memcpy(corrupt[0..wire.len], wire);
    // username length lives right after chan(2+2) + nick(2+1) past the fixed prefix.
    const user_len_off = 18 + 2 + 2 + 2 + 1;
    std.mem.writeInt(u16, corrupt[user_len_off..][0..2], max_username_len + 1, .little);
    try testing.expectError(error.NameTooLong, decode(corrupt[0..wire.len]));
}

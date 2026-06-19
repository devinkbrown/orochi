//! OBSERVE_EVENT frame payload codec (network-wide operator OBSERVE feed).
//!
//! Carries one OBSERVE lifecycle record between mesh peers: "on `origin_server`,
//! the watched subject `nick!user@host` (account, detail) did `action`". Like an
//! oper event it is a one-shot NOTIFICATION — peers do not store it; each runs
//! its OWN local OBSERVE registry (per-oper glob mask + action filter) against the
//! carried subject and pushes a `:<origin_server> EVENT <oper> OBSERVE …` line to
//! every matching watcher, so a standing `EVENT OBSERVE <mask>` spans the mesh.
//!
//! The subject's `host` is the REAL (uncloaked) host — OBSERVE is an operator-
//! trust surface — so this frame is carried on the SIGNED S2S path.
//!
//! Compact binary layout (little-endian); `acct_present` distinguishes a null
//! account (rendered `acct=*`) from an empty one:
//!
//!   action:u8 | acct_present:u8 |
//!   origin_len:u16 | origin… | nick_len:u16 | nick… | user_len:u16 | user… |
//!   host_len:u16 | host… | acct_len:u16 | acct… | detail_len:u16 | detail…
//!
//! Bounded per-field so a hostile peer cannot pin large buffers; decode borrows
//! the input (no allocation).
const std = @import("std");

pub const max_origin_len = 128;
pub const max_nick_len = 64;
pub const max_user_len = 64;
pub const max_host_len = 256;
pub const max_account_len = 64;
pub const max_detail_len = 256;
const fixed_prefix = 1 + 1; // action, acct_present

/// Upper bound on one encoded event (all fields at their limits).
pub const max_encoded_len = fixed_prefix +
    2 + max_origin_len +
    2 + max_nick_len +
    2 + max_user_len +
    2 + max_host_len +
    2 + max_account_len +
    2 + max_detail_len;

pub const Error = error{
    Truncated,
    NameTooLong,
    TrailingBytes,
};

pub const ObserveEvent = struct {
    /// OBSERVE action as its raw `observe.Action` enum(u8) value (the server maps
    /// to/from the enum, re-validating, so this codec stays daemon-independent).
    action: u8,
    /// The server name where the event was raised (rendered as the source).
    origin_server: []const u8,
    nick: []const u8,
    user: []const u8,
    host: []const u8,
    /// Watched subject's account; null is preserved across the wire (renders as
    /// `acct=*`) and is distinct from an empty account.
    account: ?[]const u8 = null,
    /// Action-specific extra (new nick, quit reason, …); may carry spaces.
    detail: []const u8 = "",
};

pub fn encodedLen(ev: ObserveEvent) Error!usize {
    const account: []const u8 = ev.account orelse "";
    if (ev.origin_server.len > max_origin_len) return error.NameTooLong;
    if (ev.nick.len > max_nick_len) return error.NameTooLong;
    if (ev.user.len > max_user_len) return error.NameTooLong;
    if (ev.host.len > max_host_len) return error.NameTooLong;
    if (account.len > max_account_len) return error.NameTooLong;
    if (ev.detail.len > max_detail_len) return error.NameTooLong;
    return fixed_prefix +
        2 + ev.origin_server.len +
        2 + ev.nick.len +
        2 + ev.user.len +
        2 + ev.host.len +
        2 + account.len +
        2 + ev.detail.len;
}

fn putBytes16(out: []u8, i: *usize, bytes: []const u8) void {
    std.mem.writeInt(u16, out[i.*..][0..2], @intCast(bytes.len), .little);
    i.* += 2;
    @memcpy(out[i.*..][0..bytes.len], bytes);
    i.* += bytes.len;
}

/// Encode into `out`; returns the written slice. `out` must be >= encodedLen.
pub fn encode(ev: ObserveEvent, out: []u8) Error![]const u8 {
    const need = try encodedLen(ev);
    if (out.len < need) return error.Truncated;
    var i: usize = 0;
    out[i] = ev.action;
    i += 1;
    out[i] = @intFromBool(ev.account != null);
    i += 1;
    const account: []const u8 = ev.account orelse "";
    putBytes16(out, &i, ev.origin_server);
    putBytes16(out, &i, ev.nick);
    putBytes16(out, &i, ev.user);
    putBytes16(out, &i, ev.host);
    putBytes16(out, &i, account);
    putBytes16(out, &i, ev.detail);
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

/// Reject control bytes (and optionally spaces) so a hostile peer can never
/// smuggle a CR/LF — and thus an injected line — into the rendered output.
fn validateLineField(bytes: []const u8, reject_space: bool) Error!void {
    for (bytes) |byte| {
        if (byte < 0x20 or byte == 0x7f or (reject_space and byte == ' ')) {
            return error.NameTooLong;
        }
    }
}

/// Decode from `bytes`; the returned string fields borrow `bytes`.
pub fn decode(bytes: []const u8) Error!ObserveEvent {
    if (bytes.len < fixed_prefix + 2) return error.Truncated;
    var i: usize = 0;
    const action = bytes[i];
    i += 1;
    const acct_present = bytes[i] != 0;
    i += 1;

    const origin = try takeBytes16(bytes, &i, max_origin_len);
    const nick = try takeBytes16(bytes, &i, max_nick_len);
    const user = try takeBytes16(bytes, &i, max_user_len);
    const host = try takeBytes16(bytes, &i, max_host_len);
    const account = try takeBytes16(bytes, &i, max_account_len);
    const detail = try takeBytes16(bytes, &i, max_detail_len);

    if (i != bytes.len) return error.TrailingBytes;
    if (origin.len == 0 or nick.len == 0) return error.NameTooLong;
    // origin + the hostmask components are single tokens (no spaces); detail may
    // carry spaces (quit reason) but never control bytes.
    try validateLineField(origin, true);
    try validateLineField(nick, true);
    try validateLineField(user, true);
    try validateLineField(host, true);
    try validateLineField(account, true);
    try validateLineField(detail, false);
    return .{
        .action = action,
        .origin_server = origin,
        .nick = nick,
        .user = user,
        .host = host,
        .account = if (acct_present) account else null,
        .detail = detail,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "observe event round-trips with an account" {
    const ev = ObserveEvent{
        .action = 0, // connect
        .origin_server = "eshmaki.me",
        .nick = "sh0rt1e",
        .user = "shorty",
        .host = "real.host.example",
        .account = "shorty",
        .detail = "",
    };
    var buf: [max_encoded_len]u8 = undefined;
    const wire = try encode(ev, &buf);
    try testing.expectEqual(try encodedLen(ev), wire.len);

    const got = try decode(wire);
    try testing.expectEqual(@as(u8, 0), got.action);
    try testing.expectEqualStrings("eshmaki.me", got.origin_server);
    try testing.expectEqualStrings("sh0rt1e", got.nick);
    try testing.expectEqualStrings("shorty", got.user);
    try testing.expectEqualStrings("real.host.example", got.host);
    try testing.expectEqualStrings("shorty", got.account.?);
    try testing.expectEqualStrings("", got.detail);
}

test "null account survives the round-trip distinct from empty" {
    const null_acct = ObserveEvent{ .action = 1, .origin_server = "n", .nick = "a", .user = "u", .host = "h", .account = null, .detail = "Ping timeout" };
    var buf: [max_encoded_len]u8 = undefined;
    const got = try decode(try encode(null_acct, &buf));
    try testing.expect(got.account == null);
    try testing.expectEqualStrings("Ping timeout", got.detail);

    const empty_acct = ObserveEvent{ .action = 1, .origin_server = "n", .nick = "a", .user = "u", .host = "h", .account = "", .detail = "" };
    var buf2: [max_encoded_len]u8 = undefined;
    const got2 = try decode(try encode(empty_acct, &buf2));
    try testing.expect(got2.account != null);
    try testing.expectEqualStrings("", got2.account.?);
}

test "truncated input is rejected at every prefix" {
    const ev = ObserveEvent{ .action = 2, .origin_server = "ircx.us", .nick = "z", .user = "u", .host = "h", .account = "acc", .detail = "old -> new" };
    var buf: [max_encoded_len]u8 = undefined;
    const wire = try encode(ev, &buf);
    var cut: usize = 0;
    while (cut < wire.len) : (cut += 1) {
        try testing.expectError(error.Truncated, decode(wire[0..cut]));
    }
}

test "trailing bytes rejected" {
    const ev = ObserveEvent{ .action = 0, .origin_server = "n", .nick = "a", .user = "u", .host = "h", .account = null, .detail = "" };
    var buf: [max_encoded_len]u8 = undefined;
    const wire = try encode(ev, &buf);
    var padded: [max_encoded_len + 1]u8 = undefined;
    @memcpy(padded[0..wire.len], wire);
    padded[wire.len] = 0xAA;
    try testing.expectError(error.TrailingBytes, decode(padded[0 .. wire.len + 1]));
}

test "over-long fields rejected by encode" {
    const big_host = "x" ** (max_host_len + 1);
    try testing.expectError(error.NameTooLong, encodedLen(.{ .action = 0, .origin_server = "n", .nick = "a", .user = "u", .host = big_host, .account = null, .detail = "" }));
}

test "control bytes and empty nick/origin rejected by decode" {
    // Newline smuggled into the detail is rejected.
    const inj = ObserveEvent{ .action = 0, .origin_server = "n", .nick = "a", .user = "u", .host = "h", .account = null, .detail = "a\nb" };
    var ibuf: [max_encoded_len]u8 = undefined;
    try testing.expectError(error.NameTooLong, decode(try encode(inj, &ibuf)));

    // A space in the host (a single token) is rejected.
    const sp = ObserveEvent{ .action = 0, .origin_server = "n", .nick = "a", .user = "u", .host = "h ost", .account = null, .detail = "" };
    var sbuf: [max_encoded_len]u8 = undefined;
    try testing.expectError(error.NameTooLong, decode(try encode(sp, &sbuf)));

    // Empty nick rejected (minimal hand-built frame: origin "n", all else empty).
    var mini: [fixed_prefix + (2 + 1) + 5 * 2]u8 = undefined;
    @memset(&mini, 0);
    mini[0] = 0; // action
    mini[1] = 0; // acct_present
    std.mem.writeInt(u16, mini[2..4], 1, .little); // origin_len = 1
    mini[4] = 'n';
    // remaining length prefixes (nick,user,host,acct,detail) stay 0 -> empty nick
    try testing.expectError(error.NameTooLong, decode(&mini));
}

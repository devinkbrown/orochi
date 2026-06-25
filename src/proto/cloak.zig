// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deterministic host/IP cloaking (charybdis-grade hierarchical scheme).
//!
//! Every cloak segment is a keyed HMAC-SHA256 token over a *cumulative prefix*
//! of the real address, truncated to 32 bits and rendered as 8 lowercase hex
//! digits. Because each segment depends only on the prefix up to that point:
//!
//!   * the SAME real input + key always yields the SAME cloak (deterministic),
//!   * a different key yields a completely different cloak (unlinkable),
//!   * two addresses in the same subnet SHARE the broad-prefix segments and
//!     differ in the specific ones, so subnet bans (`*.<t24>.<t16>.ip.net`)
//!     keep working without ever exposing the raw address.
//!
//! Shapes produced (with the default `ircxnet` suffix):
//!
//!   IPv4  `a.b.c.d`            -> `<t/32>.<t/24>.<t/16>.ip.ircxnet`
//!   IPv6  `2001:db8::1`        -> `<t/128>.<t/64>.<t/48>.<t/32>.ip6.ircxnet`
//!   rDNS  `dsl-1.pool.isp.com` -> `ircxnet-<token>.isp.com`
//!   acct  `Kain` @ `IRCXNet`   -> `kain.users.ircxnet` (no key needed)
//!
//! The most specific token comes FIRST (leftmost), matching DNS semantics
//! where the rightmost labels are the broadest: masking the leading labels
//! while keeping a shared tail is exactly what makes wildcard bans coherent.
const std = @import("std");

const HmacSha256 = std.crypto.auth.hmac.Hmac(std.crypto.hash.sha2.Sha256);
const Net = std.Io.net;

pub const key_len = 32;
pub const tag_len = std.crypto.hash.sha2.Sha256.digest_length;
pub const max_hostname_len = 253;
pub const max_cloak_len = max_hostname_len;

/// Hex digits per HMAC-derived cloak token (32 bits of keyed output).
pub const token_hex_len = 8;

/// Default network-identifying suffix carried by every cloaked host so users
/// and opers can tell at a glance that a host is cloaked. Configurable via
/// `[cloak] suffix`.
pub const default_suffix = "ircxnet";

/// Label between the account name and the network in account cloaks
/// (`<account>.users.<network>`).
pub const account_subdomain = "users";

pub const CloakError = error{
    InvalidKey,
    InvalidHostname,
    InvalidAccount,
    OutputTooSmall,
};

/// Fixed-width key material for address cloaking.
///
/// The fixed 32-byte shape keeps the HMAC key path simple and gives callers a
/// single place to wipe key bytes when rotating or tearing down server state.
pub const SecretKey = struct {
    bytes: [key_len]u8,

    pub fn init(bytes: [key_len]u8) SecretKey {
        return .{ .bytes = bytes };
    }

    pub fn fromSlice(bytes: []const u8) CloakError!SecretKey {
        if (bytes.len != key_len) return error.InvalidKey;
        return .{ .bytes = bytes[0..key_len].* };
    }

    pub fn declassify(self: *const SecretKey) [key_len]u8 {
        return self.bytes;
    }

    pub fn wipe(self: *SecretKey) void {
        secureZero(&self.bytes);
    }
};

/// Formatting options for cloak output.
pub const Options = struct {
    /// Network-identifying suffix appended to IP cloaks (`....ip.<suffix>`)
    /// and used as the token-label prefix for hostname cloaks
    /// (`<suffix>-<token>.<domain>`). Must be hostname-safe.
    suffix: []const u8 = default_suffix,
};

/// Class of address recognized by `classify`.
pub const AddressKind = enum {
    ipv4,
    ipv6,
    hostname,
};

/// Return how `address` will be cloaked.
pub fn classify(address: []const u8) AddressKind {
    const parsed = Net.IpAddress.parse(address, 0) catch return .hostname;
    return switch (parsed) {
        .ip4 => .ipv4,
        .ip6 => .ipv6,
    };
}

/// Cloak an IPv4, IPv6, or resolved hostname into caller-provided storage.
pub fn cloak(
    out: []u8,
    key: *const SecretKey,
    address: []const u8,
    options: Options,
) CloakError![]const u8 {
    if (Net.IpAddress.parse(address, 0)) |parsed| {
        return switch (parsed) {
            .ip4 => |ip4| cloakIPv4(out, key, ip4.bytes, options),
            .ip6 => |ip6| cloakIPv6(out, key, ip6.bytes, options),
        };
    } else |_| {
        return cloakHostname(out, key, address, options);
    }
}

/// Cloak raw IPv4 bytes hierarchically: one token per cumulative prefix
/// (/32 full address, /24, /16), most specific first, then the `ip` marker
/// and the network suffix. Two addresses in the same /24 share everything
/// after the first label; two in the same /16 share everything after the
/// second.
pub fn cloakIPv4(
    out: []u8,
    key: *const SecretKey,
    address: [4]u8,
    options: Options,
) CloakError![]const u8 {
    var t_full: [token_hex_len]u8 = undefined;
    var t_24: [token_hex_len]u8 = undefined;
    var t_16: [token_hex_len]u8 = undefined;
    token(&t_full, key, "ip4/32|", address[0..4]);
    token(&t_24, key, "ip4/24|", address[0..3]);
    token(&t_16, key, "ip4/16|", address[0..2]);
    return std.fmt.bufPrint(
        out,
        "{s}.{s}.{s}.ip.{s}",
        .{ &t_full, &t_24, &t_16, options.suffix },
    ) catch error.OutputTooSmall;
}

/// Cloak raw IPv6 bytes hierarchically at routing-structure granularity:
/// one token per cumulative prefix (/128 full address, /64, /48, /32), most
/// specific first, then the `ip6` marker and the network suffix. Two
/// addresses in the same /64 share everything after the first label.
pub fn cloakIPv6(
    out: []u8,
    key: *const SecretKey,
    address: [16]u8,
    options: Options,
) CloakError![]const u8 {
    var t_full: [token_hex_len]u8 = undefined;
    var t_64: [token_hex_len]u8 = undefined;
    var t_48: [token_hex_len]u8 = undefined;
    var t_32: [token_hex_len]u8 = undefined;
    token(&t_full, key, "ip6/128|", address[0..16]);
    token(&t_64, key, "ip6/64|", address[0..8]);
    token(&t_48, key, "ip6/48|", address[0..6]);
    token(&t_32, key, "ip6/32|", address[0..4]);
    return std.fmt.bufPrint(
        out,
        "{s}.{s}.{s}.{s}.ip6.{s}",
        .{ &t_full, &t_64, &t_48, &t_32, options.suffix },
    ) catch error.OutputTooSmall;
}

/// Cloak a resolved hostname: replace every label left of the registrable
/// domain with a single `<suffix>-<token>` label (token = keyed HMAC over the
/// FULL normalized hostname, so two hosts under the same domain are
/// unlinkable to each other and to their real names), keeping the registrable
/// domain + TLD visible so `*.example.com` bans still work.
///
/// A small public-suffix heuristic keeps three labels for multi-part TLDs
/// (`co.uk`, `com.au`, ...). At least one label is always masked: a host that
/// IS its own registrable domain keeps one fewer label. Single-label hosts
/// have no usable domain and fall back to `<suffix>-<token>.<suffix>`.
pub fn cloakHostname(
    out: []u8,
    key: *const SecretKey,
    hostname: []const u8,
    options: Options,
) CloakError![]const u8 {
    var normalized_buf: [max_hostname_len]u8 = undefined;
    const normalized = try normalizeHostname(&normalized_buf, hostname);

    var tok: [token_hex_len]u8 = undefined;
    token(&tok, key, "host|", normalized);

    var n: usize = 0;
    try append(out, &n, options.suffix);
    try appendByte(out, &n, '-');
    try append(out, &n, &tok);
    try appendByte(out, &n, '.');

    const labels = countLabels(normalized);
    if (labels == 1) {
        try append(out, &n, options.suffix);
    } else {
        try append(out, &n, registrableSuffix(normalized, labels));
    }
    return out[0..n];
}

/// Friendly cloak for a logged-in account: `<account>.users.<network>`,
/// lowercased and sanitized to hostname-safe characters. Stable across
/// restarts and key rotation (no secret involved); the server decides when to
/// present this instead of the IP/host cloak.
pub fn cloakAccount(
    out: []u8,
    account: []const u8,
    network: []const u8,
) CloakError![]const u8 {
    var n: usize = 0;
    try appendSanitizedLabel(out, &n, account, error.InvalidAccount);
    try appendByte(out, &n, '.');
    try append(out, &n, account_subdomain);
    try appendByte(out, &n, '.');
    if (network.len == 0) {
        try append(out, &n, default_suffix);
    } else {
        try appendSanitizedLabel(out, &n, network, error.InvalidHostname);
    }
    return out[0..n];
}

/// Derive one 32-bit cloak token: HMAC-SHA256(key, domain || data) truncated
/// to 4 bytes and rendered as 8 lowercase hex digits. The domain string
/// separates token families so e.g. an IPv4 /16 prefix and an IPv6 /32 prefix
/// over the same bytes can never produce related tokens.
fn token(
    out: *[token_hex_len]u8,
    key: *const SecretKey,
    domain: []const u8,
    data: []const u8,
) void {
    var key_bytes = key.declassify();
    defer secureZero(&key_bytes);

    var tag: [tag_len]u8 = undefined;
    defer secureZero(&tag);
    var mac = HmacSha256.init(&key_bytes);
    mac.update(domain);
    mac.update(data);
    mac.final(&tag);

    for (tag[0 .. token_hex_len / 2], 0..) |byte, i| {
        out[i * 2] = hex_digit[byte >> 4];
        out[i * 2 + 1] = hex_digit[byte & 0x0f];
    }
}

/// The visible (kept) tail of a multi-label hostname: normally the last two
/// labels, three when the last two look like a multi-part public suffix
/// (both three bytes or fewer, e.g. `co.uk`), clamped so at least one label
/// is always masked.
fn registrableSuffix(normalized: []const u8, labels: usize) []const u8 {
    std.debug.assert(labels >= 2);
    var keep: usize = 2;
    if (labels >= 3) {
        const last = lastLabel(normalized);
        const before = lastLabel(normalized[0 .. normalized.len - last.len - 1]);
        if (last.len <= 3 and before.len <= 3) keep = 3;
    }
    if (keep >= labels) keep = labels - 1;

    // Walk back over `keep` dots from the end to find the suffix start.
    var dots: usize = 0;
    var i = normalized.len;
    while (i > 0) {
        i -= 1;
        if (normalized[i] == '.') {
            dots += 1;
            if (dots == keep) return normalized[i + 1 ..];
        }
    }
    return normalized;
}

fn lastLabel(s: []const u8) []const u8 {
    if (std.mem.lastIndexOfScalar(u8, s, '.')) |i| return s[i + 1 ..];
    return s;
}

fn normalizeHostname(out: *[max_hostname_len]u8, hostname: []const u8) CloakError![]const u8 {
    if (hostname.len == 0) return error.InvalidHostname;
    var in = hostname;
    if (in[in.len - 1] == '.') {
        in = in[0 .. in.len - 1];
    }
    if (in.len == 0 or in.len > max_hostname_len) return error.InvalidHostname;

    var label_len: usize = 0;
    for (in, 0..) |c, i| {
        if (c == '.') {
            if (label_len == 0) return error.InvalidHostname;
            label_len = 0;
            out[i] = c;
            continue;
        }
        if (!isHostnameByte(c)) return error.InvalidHostname;
        label_len += 1;
        if (label_len > 63) return error.InvalidHostname;
        out[i] = std.ascii.toLower(c);
    }
    if (label_len == 0) return error.InvalidHostname;
    return out[0..in.len];
}

fn countLabels(hostname: []const u8) usize {
    var labels: usize = 1;
    for (hostname) |c| {
        labels += @intFromBool(c == '.');
    }
    return labels;
}

/// Append `value` lowercased with non-hostname bytes mapped to '-', trimmed
/// of leading/trailing '-'. Fails with `empty_err` when nothing usable
/// remains or the resulting label would exceed the DNS label limit.
fn appendSanitizedLabel(
    out: []u8,
    n: *usize,
    value: []const u8,
    comptime empty_err: CloakError,
) CloakError!void {
    var buf: [63]u8 = undefined;
    var len: usize = 0;
    for (value) |c| {
        const mapped: u8 = if (isHostnameByte(c)) std.ascii.toLower(c) else '-';
        if (len == 0 and mapped == '-') continue; // trim leading
        if (len >= buf.len) return empty_err;
        buf[len] = mapped;
        len += 1;
    }
    while (len > 0 and buf[len - 1] == '-') len -= 1; // trim trailing
    if (len == 0) return empty_err;
    try append(out, n, buf[0..len]);
}

fn append(out: []u8, n: *usize, bytes: []const u8) CloakError!void {
    if (out.len - n.* < bytes.len) return error.OutputTooSmall;
    @memcpy(out[n.*..][0..bytes.len], bytes);
    n.* += bytes.len;
}

fn appendByte(out: []u8, n: *usize, byte: u8) CloakError!void {
    if (out.len - n.* == 0) return error.OutputTooSmall;
    out[n.*] = byte;
    n.* += 1;
}

fn isHostnameByte(c: u8) bool {
    return switch (c) {
        'a'...'z', 'A'...'Z', '0'...'9', '-' => true,
        else => false,
    };
}

fn secureZero(buf: []u8) void {
    for (buf) |*b| {
        const vp: *volatile u8 = @ptrCast(b);
        vp.* = 0;
    }
}

const hex_digit = "0123456789abcdef";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

const test_key = SecretKey.init([_]u8{
    0x6d, 0x69, 0x7a, 0x75, 0x63, 0x68, 0x69, 0x20,
    0x63, 0x6c, 0x6f, 0x61, 0x6b, 0x20, 0x6b, 0x65,
    0x79, 0x20, 0x76, 0x31, 0x20, 0x74, 0x65, 0x73,
    0x74, 0x20, 0x6f, 0x6e, 0x6c, 0x79, 0x21, 0x00,
});

const other_key = SecretKey.init([_]u8{0xa5} ** key_len);

/// Split a dotted cloak into its labels (test helper).
fn splitLabels(buf: *[16][]const u8, host: []const u8) [][]const u8 {
    var it = std.mem.splitScalar(u8, host, '.');
    var n: usize = 0;
    while (it.next()) |label| {
        buf[n] = label;
        n += 1;
    }
    return buf[0..n];
}

fn isHexToken(label: []const u8) bool {
    if (label.len != token_hex_len) return false;
    for (label) |c| {
        switch (c) {
            '0'...'9', 'a'...'f' => {},
            else => return false,
        }
    }
    return true;
}

test "same IP gets the same stable cloak" {
    var a: [max_cloak_len]u8 = undefined;
    var b: [max_cloak_len]u8 = undefined;

    const ca = try cloak(&a, &test_key, "203.0.113.99", .{});
    const cb = try cloak(&b, &test_key, "203.0.113.99", .{});

    try testing.expectEqualSlices(u8, ca, cb);
}

test "different IPs get different cloaks" {
    var a: [max_cloak_len]u8 = undefined;
    var b: [max_cloak_len]u8 = undefined;

    const ca = try cloak(&a, &test_key, "203.0.113.99", .{});
    const cb = try cloak(&b, &test_key, "203.0.113.100", .{});

    try testing.expect(!std.mem.eql(u8, ca, cb));
}

test "IPv4 cloak has token.token.token.ip.suffix shape and leaks no octet" {
    var out: [max_cloak_len]u8 = undefined;
    const c = try cloak(&out, &test_key, "203.0.113.99", .{});

    var lbuf: [16][]const u8 = undefined;
    const labels = splitLabels(&lbuf, c);
    try testing.expectEqual(@as(usize, 5), labels.len);
    try testing.expect(isHexToken(labels[0]));
    try testing.expect(isHexToken(labels[1]));
    try testing.expect(isHexToken(labels[2]));
    try testing.expectEqualStrings("ip", labels[3]);
    try testing.expectEqualStrings(default_suffix, labels[4]);

    // No label is a raw octet of the real address.
    for (labels) |label| {
        try testing.expect(!std.mem.eql(u8, label, "203"));
        try testing.expect(!std.mem.eql(u8, label, "0"));
        try testing.expect(!std.mem.eql(u8, label, "113"));
        try testing.expect(!std.mem.eql(u8, label, "99"));
    }
}

test "IPv4 same /24 shares upper segments, differs in the most-specific one" {
    var a: [max_cloak_len]u8 = undefined;
    var b: [max_cloak_len]u8 = undefined;
    const ca = try cloak(&a, &test_key, "203.0.113.5", .{});
    const cb = try cloak(&b, &test_key, "203.0.113.77", .{});

    var la_buf: [16][]const u8 = undefined;
    var lb_buf: [16][]const u8 = undefined;
    const la = splitLabels(&la_buf, ca);
    const lb = splitLabels(&lb_buf, cb);

    try testing.expect(!std.mem.eql(u8, la[0], lb[0])); // /32 differs
    try testing.expectEqualStrings(la[1], lb[1]); // shared /24
    try testing.expectEqualStrings(la[2], lb[2]); // shared /16
}

test "IPv4 same /16 different /24 shares only the /16 segment" {
    var a: [max_cloak_len]u8 = undefined;
    var b: [max_cloak_len]u8 = undefined;
    const ca = try cloak(&a, &test_key, "203.0.113.5", .{});
    const cb = try cloak(&b, &test_key, "203.0.200.5", .{});

    var la_buf: [16][]const u8 = undefined;
    var lb_buf: [16][]const u8 = undefined;
    const la = splitLabels(&la_buf, ca);
    const lb = splitLabels(&lb_buf, cb);

    try testing.expect(!std.mem.eql(u8, la[0], lb[0]));
    try testing.expect(!std.mem.eql(u8, la[1], lb[1]));
    try testing.expectEqualStrings(la[2], lb[2]); // shared /16
}

test "IPv4 unrelated networks share no segments" {
    var a: [max_cloak_len]u8 = undefined;
    var b: [max_cloak_len]u8 = undefined;
    const ca = try cloak(&a, &test_key, "203.0.113.5", .{});
    const cb = try cloak(&b, &test_key, "9.8.7.6", .{});

    var la_buf: [16][]const u8 = undefined;
    var lb_buf: [16][]const u8 = undefined;
    const la = splitLabels(&la_buf, ca);
    const lb = splitLabels(&lb_buf, cb);

    try testing.expect(!std.mem.eql(u8, la[0], lb[0]));
    try testing.expect(!std.mem.eql(u8, la[1], lb[1]));
    try testing.expect(!std.mem.eql(u8, la[2], lb[2]));
}

test "IPv6 cloak shape, determinism, and /64 / /48 coherence" {
    var a: [max_cloak_len]u8 = undefined;
    var a2: [max_cloak_len]u8 = undefined;
    var b: [max_cloak_len]u8 = undefined;
    var c: [max_cloak_len]u8 = undefined;
    var d: [max_cloak_len]u8 = undefined;

    // Same /64, different interface IDs.
    const ca = try cloak(&a, &test_key, "2001:db8:85a3:1:8a2e:370:7334:1234", .{});
    const ca2 = try cloak(&a2, &test_key, "2001:db8:85a3:1:8a2e:370:7334:1234", .{});
    const cb = try cloak(&b, &test_key, "2001:db8:85a3:1:dead:beef:cafe:1", .{});
    // Same /48, different /64.
    const cc = try cloak(&c, &test_key, "2001:db8:85a3:ffff:1:2:3:4", .{});
    // Unrelated network.
    const cd = try cloak(&d, &test_key, "fd00:1:2:3:4:5:6:7", .{});

    try testing.expectEqualSlices(u8, ca, ca2);

    var la_buf: [16][]const u8 = undefined;
    var lb_buf: [16][]const u8 = undefined;
    var lc_buf: [16][]const u8 = undefined;
    var ld_buf: [16][]const u8 = undefined;
    const la = splitLabels(&la_buf, ca);
    const lb = splitLabels(&lb_buf, cb);
    const lc = splitLabels(&lc_buf, cc);
    const ld = splitLabels(&ld_buf, cd);

    try testing.expectEqual(@as(usize, 6), la.len);
    try testing.expect(isHexToken(la[0]));
    try testing.expect(isHexToken(la[1]));
    try testing.expect(isHexToken(la[2]));
    try testing.expect(isHexToken(la[3]));
    try testing.expectEqualStrings("ip6", la[4]);
    try testing.expectEqualStrings(default_suffix, la[5]);

    // Same /64: only the full-address token differs.
    try testing.expect(!std.mem.eql(u8, la[0], lb[0]));
    try testing.expectEqualStrings(la[1], lb[1]);
    try testing.expectEqualStrings(la[2], lb[2]);
    try testing.expectEqualStrings(la[3], lb[3]);

    // Same /48: /64 token differs too, /48 and /32 shared.
    try testing.expect(!std.mem.eql(u8, la[0], lc[0]));
    try testing.expect(!std.mem.eql(u8, la[1], lc[1]));
    try testing.expectEqualStrings(la[2], lc[2]);
    try testing.expectEqualStrings(la[3], lc[3]);

    // Unrelated: nothing shared.
    try testing.expect(!std.mem.eql(u8, la[0], ld[0]));
    try testing.expect(!std.mem.eql(u8, la[1], ld[1]));
    try testing.expect(!std.mem.eql(u8, la[2], ld[2]));
    try testing.expect(!std.mem.eql(u8, la[3], ld[3]));
}

test "IPv6 cloak leaks no raw hextet labels" {
    var out: [max_cloak_len]u8 = undefined;
    const c = try cloak(&out, &test_key, "2001:db8:85a3:1:8a2e:370:7334:1234", .{});

    var lbuf: [16][]const u8 = undefined;
    const labels = splitLabels(&lbuf, c);
    const raw = [_][]const u8{ "2001", "db8", "85a3", "8a2e", "370", "7334", "1234" };
    for (labels[0..4]) |label| {
        for (raw) |r| try testing.expect(!std.mem.eql(u8, label, r));
    }
}

test "hostnames mask all dynamic labels and preserve the registrable domain" {
    var out: [max_cloak_len]u8 = undefined;
    const c = try cloak(&out, &test_key, "Client-123.POOL.Example.Net", .{});

    try testing.expect(std.mem.endsWith(u8, c, ".example.net"));
    try testing.expect(std.mem.startsWith(u8, c, default_suffix ++ "-"));
    try testing.expect(!std.mem.containsAtLeast(u8, c, 1, "client-123"));
    try testing.expect(!std.mem.containsAtLeast(u8, c, 1, "pool"));

    // Exactly one masked label: <suffix>-<8 hex>.
    const dot = std.mem.indexOfScalar(u8, c, '.').?;
    const masked = c[0..dot];
    try testing.expectEqual(default_suffix.len + 1 + token_hex_len, masked.len);
    try testing.expect(isHexToken(masked[default_suffix.len + 1 ..]));
}

test "hostname cloak is deterministic and unlinkable across sibling hosts" {
    var a: [max_cloak_len]u8 = undefined;
    var a2: [max_cloak_len]u8 = undefined;
    var b: [max_cloak_len]u8 = undefined;

    const ca = try cloak(&a, &test_key, "alpha.example.com", .{});
    const ca2 = try cloak(&a2, &test_key, "alpha.example.com", .{});
    const cb = try cloak(&b, &test_key, "beta.example.com", .{});

    try testing.expectEqualSlices(u8, ca, ca2);
    try testing.expect(!std.mem.eql(u8, ca, cb)); // siblings get distinct tokens
    try testing.expect(std.mem.endsWith(u8, ca, ".example.com"));
    try testing.expect(std.mem.endsWith(u8, cb, ".example.com"));
}

test "two-label hostnames still mask the registrable label" {
    var out: [max_cloak_len]u8 = undefined;
    const c = try cloak(&out, &test_key, "example.com", .{});

    try testing.expect(std.mem.endsWith(u8, c, ".com"));
    try testing.expect(!std.mem.containsAtLeast(u8, c, 1, "example"));
    try testing.expect(std.mem.startsWith(u8, c, default_suffix ++ "-"));
}

test "multi-part TLDs keep three labels" {
    var out: [max_cloak_len]u8 = undefined;
    const c = try cloak(&out, &test_key, "dsl-99.cust.foo.co.uk", .{});

    try testing.expect(std.mem.endsWith(u8, c, ".foo.co.uk"));
    try testing.expect(!std.mem.containsAtLeast(u8, c, 1, "dsl-99"));
    try testing.expect(!std.mem.containsAtLeast(u8, c, 1, "cust"));
}

test "host that IS a multi-part-TLD domain still masks one label" {
    var out: [max_cloak_len]u8 = undefined;
    const c = try cloak(&out, &test_key, "foo.co.uk", .{});

    try testing.expect(std.mem.endsWith(u8, c, ".co.uk"));
    try testing.expect(!std.mem.containsAtLeast(u8, c, 1, "foo."));
}

test "single-label hostnames fall back to the cloak suffix" {
    var out: [max_cloak_len]u8 = undefined;
    const c = try cloak(&out, &test_key, "localhost", .{});

    try testing.expect(std.mem.startsWith(u8, c, default_suffix ++ "-"));
    try testing.expect(std.mem.endsWith(u8, c, "." ++ default_suffix));
    try testing.expect(!std.mem.containsAtLeast(u8, c, 1, "localhost"));
}

test "custom suffix flows through every cloak form" {
    const opts: Options = .{ .suffix = "mynet" };
    var a: [max_cloak_len]u8 = undefined;
    var b: [max_cloak_len]u8 = undefined;
    var c: [max_cloak_len]u8 = undefined;

    const ca = try cloak(&a, &test_key, "203.0.113.99", opts);
    const cb = try cloak(&b, &test_key, "2001:db8::1", opts);
    const cc = try cloak(&c, &test_key, "node.example.org", opts);

    try testing.expect(std.mem.endsWith(u8, ca, ".ip.mynet"));
    try testing.expect(std.mem.endsWith(u8, cb, ".ip6.mynet"));
    try testing.expect(std.mem.startsWith(u8, cc, "mynet-"));
}

test "suffix does not affect token values (segments stay ban-compatible)" {
    var a: [max_cloak_len]u8 = undefined;
    var b: [max_cloak_len]u8 = undefined;
    const ca = try cloak(&a, &test_key, "203.0.113.99", .{});
    const cb = try cloak(&b, &test_key, "203.0.113.99", .{ .suffix = "mynet" });

    var la_buf: [16][]const u8 = undefined;
    var lb_buf: [16][]const u8 = undefined;
    const la = splitLabels(&la_buf, ca);
    const lb = splitLabels(&lb_buf, cb);
    try testing.expectEqualStrings(la[0], lb[0]);
    try testing.expectEqualStrings(la[1], lb[1]);
    try testing.expectEqualStrings(la[2], lb[2]);
}

test "different secret produces a completely different cloak" {
    var a: [max_cloak_len]u8 = undefined;
    var b: [max_cloak_len]u8 = undefined;

    inline for (.{ "203.0.113.99", "2001:db8::1", "node.example.org" }) |addr| {
        const ca = try cloak(&a, &test_key, addr, .{});
        const cb = try cloak(&b, &other_key, addr, .{});
        try testing.expect(!std.mem.eql(u8, ca, cb));

        // Even the leading segment must differ (full unlinkability per key).
        var la_buf: [16][]const u8 = undefined;
        var lb_buf: [16][]const u8 = undefined;
        const la = splitLabels(&la_buf, ca);
        const lb = splitLabels(&lb_buf, cb);
        try testing.expect(!std.mem.eql(u8, la[0], lb[0]));
    }
}

test "account cloak is friendly, sanitized, and key-free" {
    var out: [max_cloak_len]u8 = undefined;

    const c = try cloakAccount(&out, "Kain", "IRCXNet");
    try testing.expectEqualStrings("kain.users.ircxnet", c);

    const c2 = try cloakAccount(&out, "Some_User!", "IRCXNet");
    try testing.expectEqualStrings("some-user.users.ircxnet", c2);

    // Empty network falls back to the default suffix.
    const c3 = try cloakAccount(&out, "kain", "");
    try testing.expectEqualStrings("kain.users." ++ default_suffix, c3);
}

test "account cloak rejects unusable account names" {
    var out: [max_cloak_len]u8 = undefined;
    try testing.expectError(error.InvalidAccount, cloakAccount(&out, "", "net"));
    try testing.expectError(error.InvalidAccount, cloakAccount(&out, "!!!", "net"));
}

test "small output buffers fail cleanly" {
    var out: [4]u8 = undefined;
    try testing.expectError(error.OutputTooSmall, cloak(&out, &test_key, "203.0.113.99", .{}));
    try testing.expectError(error.OutputTooSmall, cloak(&out, &test_key, "host.example.com", .{}));
    try testing.expectError(error.OutputTooSmall, cloakAccount(&out, "kain", "ircxnet"));
}

test "classify recognizes address kinds" {
    try testing.expectEqual(AddressKind.ipv4, classify("198.51.100.7"));
    try testing.expectEqual(AddressKind.ipv6, classify("2001:db8::1"));
    try testing.expectEqual(AddressKind.hostname, classify("host.example.com"));
}

test {
    testing.refAllDecls(@This());
}

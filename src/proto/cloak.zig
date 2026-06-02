//! Deterministic host/IP cloaking.
//!
//! Cloaks are keyed HMAC-SHA256 masks over canonical address bytes or
//! normalized hostname text. IPv4 preserves the high octets and masks the low
//! octets, IPv6 preserves the high groups and masks the low groups, and
//! hostnames replace leading labels while keeping a useful DNS suffix.
const std = @import("std");

const HmacSha256 = std.crypto.auth.hmac.Hmac(std.crypto.hash.sha2.Sha256);
const Net = std.Io.net;

pub const key_len = 32;
pub const tag_len = std.crypto.hash.sha2.Sha256.digest_length;
pub const max_hostname_len = 253;
pub const max_cloak_len = max_hostname_len;

pub const CloakError = error{
    InvalidKey,
    InvalidHostname,
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

/// Formatting options for hostname fallback cases.
pub const Options = struct {
    fallback_suffix: []const u8 = "cloak",
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
            .ip4 => |ip4| cloakIPv4(out, key, ip4.bytes),
            .ip6 => |ip6| cloakIPv6(out, key, ip6.bytes),
        };
    } else |_| {
        return cloakHostname(out, key, address, options);
    }
}

/// Cloak raw IPv4 bytes by preserving the high two octets and masking the low two.
pub fn cloakIPv4(out: []u8, key: *const SecretKey, address: [4]u8) CloakError![]const u8 {
    var msg: [1 + 4]u8 = undefined;
    msg[0] = '4';
    @memcpy(msg[1..], &address);

    var tag = hmac(key, &msg);
    defer secureZero(&tag);

    const masked_2 = maskByte(address[2], tag[0]);
    const masked_3 = maskByte(address[3], tag[1]);
    return std.fmt.bufPrint(
        out,
        "{d}.{d}.{d}.{d}",
        .{ address[0], address[1], masked_2, masked_3 },
    ) catch error.OutputTooSmall;
}

/// Cloak raw IPv6 bytes by preserving the high four groups and masking the low four.
pub fn cloakIPv6(out: []u8, key: *const SecretKey, address: [16]u8) CloakError![]const u8 {
    var msg: [1 + 16]u8 = undefined;
    msg[0] = '6';
    @memcpy(msg[1..], &address);

    var tag = hmac(key, &msg);
    defer secureZero(&tag);

    var groups: [8]u16 = undefined;
    for (&groups, 0..) |*group, i| {
        group.* = std.mem.readInt(u16, address[i * 2 ..][0..2], .big);
    }
    groups[4] = maskGroup(groups[4], std.mem.readInt(u16, tag[0..2], .big));
    groups[5] = maskGroup(groups[5], std.mem.readInt(u16, tag[2..4], .big));
    groups[6] = maskGroup(groups[6], std.mem.readInt(u16, tag[4..6], .big));
    groups[7] = maskGroup(groups[7], std.mem.readInt(u16, tag[6..8], .big));

    return std.fmt.bufPrint(
        out,
        "{x}:{x}:{x}:{x}:{x}:{x}:{x}:{x}",
        .{
            groups[0],
            groups[1],
            groups[2],
            groups[3],
            groups[4],
            groups[5],
            groups[6],
            groups[7],
        },
    ) catch error.OutputTooSmall;
}

/// Cloak a hostname by replacing leading labels with keyed hex labels.
///
/// Hostnames with at least three labels preserve the last two labels. Two-label
/// hostnames preserve the final label. Single-label hostnames receive
/// `options.fallback_suffix` as their visible suffix.
pub fn cloakHostname(
    out: []u8,
    key: *const SecretKey,
    hostname: []const u8,
    options: Options,
) CloakError![]const u8 {
    var normalized_buf: [max_hostname_len]u8 = undefined;
    const normalized = try normalizeHostname(&normalized_buf, hostname);
    var tag = hmacHostname(key, normalized);
    defer secureZero(&tag);

    const labels = countLabels(normalized);
    const masked_labels: usize = if (labels >= 3) labels - 2 else 1;
    const single_label = labels == 1;

    var n: usize = 0;
    var label_index: usize = 0;
    var pos: usize = 0;
    while (label_index < masked_labels) : (label_index += 1) {
        if (label_index != 0) try appendByte(out, &n, '.');
        try appendMaskedLabel(out, &n, tagSegment(&tag, label_index));
        pos = nextLabelEnd(normalized, pos);
        if (pos < normalized.len) pos += 1;
    }

    if (single_label) {
        if (options.fallback_suffix.len != 0) {
            try appendByte(out, &n, '.');
            try append(out, &n, options.fallback_suffix);
        }
    } else {
        try appendByte(out, &n, '.');
        try append(out, &n, normalized[pos..]);
    }

    return out[0..n];
}

fn hmac(key: *const SecretKey, msg: []const u8) [tag_len]u8 {
    var key_bytes = key.declassify();
    defer secureZero(&key_bytes);

    var tag: [tag_len]u8 = undefined;
    HmacSha256.create(&tag, msg, &key_bytes);
    return tag;
}

fn hmacHostname(key: *const SecretKey, normalized: []const u8) [tag_len]u8 {
    var key_bytes = key.declassify();
    defer secureZero(&key_bytes);

    var tag: [tag_len]u8 = undefined;
    var mac = HmacSha256.init(&key_bytes);
    mac.update("h");
    mac.update(normalized);
    mac.final(&tag);
    return tag;
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

fn nextLabelEnd(hostname: []const u8, start: usize) usize {
    var i = start;
    while (i < hostname.len and hostname[i] != '.') : (i += 1) {}
    return i;
}

fn tagSegment(tag: *const [tag_len]u8, index: usize) u32 {
    const offset = (index * 4) % tag_len;
    return std.mem.readInt(u32, tag[offset..][0..4], .big);
}

fn appendMaskedLabel(out: []u8, n: *usize, segment: u32) CloakError!void {
    try appendByte(out, n, 'm');
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        const shift: u5 = @intCast((7 - i) * 4);
        const nibble: u8 = @intCast((segment >> shift) & 0x0f);
        try appendByte(out, n, hex_digit[nibble]);
    }
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

fn maskByte(original: u8, candidate: u8) u8 {
    return candidate +% @as(u8, @intFromBool(candidate == original));
}

fn maskGroup(original: u16, candidate: u16) u16 {
    return candidate +% @as(u16, @intFromBool(candidate == original));
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

const test_key = SecretKey.init([_]u8{
    0x6d, 0x69, 0x7a, 0x75, 0x63, 0x68, 0x69, 0x20,
    0x63, 0x6c, 0x6f, 0x61, 0x6b, 0x20, 0x6b, 0x65,
    0x79, 0x20, 0x76, 0x31, 0x20, 0x74, 0x65, 0x73,
    0x74, 0x20, 0x6f, 0x6e, 0x6c, 0x79, 0x21, 0x00,
});

test "same IP gets the same stable cloak" {
    var a: [max_cloak_len]u8 = undefined;
    var b: [max_cloak_len]u8 = undefined;

    const ca = try cloak(&a, &test_key, "203.0.113.99", .{});
    const cb = try cloak(&b, &test_key, "203.0.113.99", .{});

    try std.testing.expectEqualSlices(u8, ca, cb);
}

test "different IPs get different cloaks" {
    var a: [max_cloak_len]u8 = undefined;
    var b: [max_cloak_len]u8 = undefined;

    const ca = try cloak(&a, &test_key, "203.0.113.99", .{});
    const cb = try cloak(&b, &test_key, "203.0.113.100", .{});

    try std.testing.expect(!std.mem.eql(u8, ca, cb));
}

test "IPv4 masks low octets" {
    var out: [max_cloak_len]u8 = undefined;
    const c = try cloak(&out, &test_key, "203.0.113.99", .{});

    try std.testing.expect(std.mem.startsWith(u8, c, "203.0."));
    try std.testing.expect(!std.mem.containsAtLeast(u8, c, 1, ".113."));
    try std.testing.expect(!std.mem.endsWith(u8, c, ".99"));
}

test "IPv6 masks low groups" {
    var out: [max_cloak_len]u8 = undefined;
    const c = try cloak(&out, &test_key, "2001:db8:85a3:0:8a2e:370:7334:1234", .{});

    try std.testing.expect(std.mem.startsWith(u8, c, "2001:db8:85a3:0:"));
    try std.testing.expect(!std.mem.containsAtLeast(u8, c, 1, ":8a2e:"));
    try std.testing.expect(!std.mem.containsAtLeast(u8, c, 1, ":370:"));
    try std.testing.expect(!std.mem.containsAtLeast(u8, c, 1, ":7334:"));
    try std.testing.expect(!std.mem.endsWith(u8, c, ":1234"));
}

test "hostnames mask leading labels and preserve suffix" {
    var out: [max_cloak_len]u8 = undefined;
    const c = try cloak(&out, &test_key, "Client-123.POOL.Example.Net", .{});

    try std.testing.expect(std.mem.endsWith(u8, c, ".example.net"));
    try std.testing.expect(!std.mem.containsAtLeast(u8, c, 1, "client-123"));
    try std.testing.expect(!std.mem.containsAtLeast(u8, c, 1, "pool"));
}

test "single-label hostnames get fallback suffix" {
    var out: [max_cloak_len]u8 = undefined;
    const c = try cloak(&out, &test_key, "localhost", .{});

    try std.testing.expect(std.mem.startsWith(u8, c, "m"));
    try std.testing.expect(std.mem.endsWith(u8, c, ".cloak"));
    try std.testing.expect(!std.mem.containsAtLeast(u8, c, 1, "localhost"));
}

test "small output buffers fail cleanly" {
    var out: [4]u8 = undefined;
    try std.testing.expectError(error.OutputTooSmall, cloak(&out, &test_key, "203.0.113.99", .{}));
}

test {
    std.testing.refAllDecls(@This());
}

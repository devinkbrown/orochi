//! Host masking styles for privacy-preserving daemon displays.
//!
//! The functions in this module are pure and allocation-free. Callers provide
//! the output buffer for styles that need to construct a masked host; `.none`
//! returns the original host slice unchanged.

const std = @import("std");

const Sha256 = std.crypto.hash.sha2.Sha256;

/// Supported host masking styles.
pub const Style = enum {
    none,
    asterisk,
    obfuscate,
    hash,
};

/// Errors returned while rendering a masked host.
pub const Error = error{
    OutputTooSmall,
};

/// Render `host` according to `style`.
///
/// `.none` returns `host` directly. Other styles write into `out` and return a
/// slice of that buffer. `key` is used only by `.hash`.
pub fn maskHost(out: []u8, host: []const u8, style: Style, key: []const u8) Error![]const u8 {
    return switch (style) {
        .none => host,
        .asterisk => maskAsterisk(out, host),
        .obfuscate => maskObfuscate(out, host),
        .hash => maskHash(out, host, key),
    };
}

fn maskAsterisk(out: []u8, host: []const u8) Error![]const u8 {
    if (host.len == 0) return copyOut(out, "");
    const first_dot = findByte(host, '.') orelse return copyOut(out, "*");
    _ = first_dot;

    const tail = asteriskTail(host);
    const needed = 2 + tail.len;
    if (out.len < needed) return error.OutputTooSmall;

    out[0] = '*';
    out[1] = '.';
    @memcpy(out[2..needed], tail);
    return out[0..needed];
}

fn maskObfuscate(out: []u8, host: []const u8) Error![]const u8 {
    const first_dot = findByte(host, '.') orelse return host;
    const last_dot = findLastByte(host, '.') orelse return host;
    if (first_dot == last_dot) return host;

    const head = host[0..first_dot];
    const tail = host[last_dot + 1 ..];
    const needed = head.len + 3 + tail.len;
    if (out.len < needed) return error.OutputTooSmall;

    var pos: usize = 0;
    @memcpy(out[pos .. pos + head.len], head);
    pos += head.len;
    out[pos] = '.';
    pos += 1;
    out[pos] = '*';
    pos += 1;
    out[pos] = '.';
    pos += 1;
    @memcpy(out[pos .. pos + tail.len], tail);
    pos += tail.len;
    return out[0..pos];
}

fn maskHash(out: []u8, host: []const u8, key: []const u8) Error![]const u8 {
    const tld = lastLabel(host);
    const suffix_len: usize = if (tld.len == 0) 0 else 1 + tld.len;
    const needed = "hidden-".len + 8 + suffix_len;
    if (out.len < needed) return error.OutputTooSmall;

    var digest: [Sha256.digest_length]u8 = undefined;
    var hasher = Sha256.init(.{});
    hasher.update(key);
    hasher.update(host);
    hasher.final(&digest);

    var pos: usize = 0;
    @memcpy(out[pos .. pos + "hidden-".len], "hidden-");
    pos += "hidden-".len;
    writeHexBytePair(out[pos .. pos + 8], digest[0..4]);
    pos += 8;

    if (tld.len != 0) {
        out[pos] = '.';
        pos += 1;
        @memcpy(out[pos .. pos + tld.len], tld);
        pos += tld.len;
    }

    return out[0..pos];
}

fn asteriskTail(host: []const u8) []const u8 {
    const last_dot = findLastByte(host, '.') orelse return host;
    const before_last = host[0..last_dot];
    const second_last = findLastByte(before_last, '.');
    const start = if (second_last) |dot| dot + 1 else last_dot + 1;
    return host[start..];
}

fn lastLabel(host: []const u8) []const u8 {
    const last_dot = findLastByte(host, '.') orelse return host;
    return host[last_dot + 1 ..];
}

fn copyOut(out: []u8, value: []const u8) Error![]const u8 {
    if (out.len < value.len) return error.OutputTooSmall;
    @memcpy(out[0..value.len], value);
    return out[0..value.len];
}

fn findByte(bytes: []const u8, needle: u8) ?usize {
    var i: usize = 0;
    while (i < bytes.len) : (i += 1) {
        if (bytes[i] == needle) return i;
    }
    return null;
}

fn findLastByte(bytes: []const u8, needle: u8) ?usize {
    var i = bytes.len;
    while (i > 0) {
        i -= 1;
        if (bytes[i] == needle) return i;
    }
    return null;
}

fn writeHexBytePair(out: []u8, bytes: []const u8) void {
    const alphabet = "0123456789abcdef";
    var pos: usize = 0;
    for (bytes) |byte| {
        out[pos] = alphabet[byte >> 4];
        pos += 1;
        out[pos] = alphabet[byte & 0x0f];
        pos += 1;
    }
}

test "asterisk keeps the registrable-looking tail" {
    var out: [64]u8 = undefined;
    const masked = try maskHost(&out, "a.b.example.com", .asterisk, "");
    try std.testing.expectEqualStrings("*.example.com", masked);
}

test "obfuscate keeps the edge labels" {
    var out: [64]u8 = undefined;
    const masked = try maskHost(&out, "a.b.example.com", .obfuscate, "");
    try std.testing.expectEqualStrings("a.*.com", masked);
}

test "hash is stable for one key and changes for another" {
    var left_buf: [64]u8 = undefined;
    var right_buf: [64]u8 = undefined;
    var other_buf: [64]u8 = undefined;

    const left = try maskHost(&left_buf, "a.b.example.com", .hash, "key-one");
    const right = try maskHost(&right_buf, "a.b.example.com", .hash, "key-one");
    const other = try maskHost(&other_buf, "a.b.example.com", .hash, "key-two");

    try std.testing.expectEqualStrings(left, right);
    try std.testing.expect(!std.mem.eql(u8, left, other));
    try std.testing.expect(std.mem.startsWith(u8, left, "hidden-"));
    try std.testing.expect(std.mem.endsWith(u8, left, ".com"));
}

test "none returns the original host" {
    var out: [1]u8 = undefined;
    const host = "a.b.example.com";
    const masked = try maskHost(&out, host, .none, "");
    try std.testing.expectEqual(@intFromPtr(host.ptr), @intFromPtr(masked.ptr));
    try std.testing.expectEqualStrings(host, masked);
}

test "small output buffer is rejected" {
    var out: [4]u8 = undefined;
    try std.testing.expectError(
        error.OutputTooSmall,
        maskHost(&out, "a.b.example.com", .asterisk, ""),
    );
    try std.testing.expectError(
        error.OutputTooSmall,
        maskHost(&out, "a.b.example.com", .hash, "key"),
    );
}

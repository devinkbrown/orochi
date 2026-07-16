// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! IRCv3 `msgid` tag generator — mints the unique per-message id the server
//! stamps as `@msgid=...` on PRIVMSG/NOTICE/TAGMSG (and that message-redaction
//! later references). Validation of received ids lives in `msgedit.isValidMsgid`;
//! this is the minting half of the `msgid` capability.
//!
//! Ids are opaque, fixed-length, URL-safe Crockford base32 over 128 bits derived
//! from a per-boot `seed` and a monotonic `counter`, so they are collision-free
//! within a boot and disjoint across boots (different seed). No RNG is used — the
//! seed is supplied by the caller (e.g. the daemon's boot entropy), keeping this
//! deterministic and testable.
const std = @import("std");

/// 128 bits / 5 bits-per-char, rounded up.
pub const id_len: usize = 26;

const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"; // Crockford base32 (no I,L,O,U)

pub const Generator = struct {
    seed: u64,
    counter: u64 = 0,

    pub fn init(seed: u64) Generator {
        return .{ .seed = seed };
    }

    /// Mint the next unique msgid into `buf` (must be >= `id_len`). Returns the
    /// id slice (always exactly `id_len` chars).
    pub fn next(self: *Generator, buf: []u8) []const u8 {
        std.debug.assert(buf.len >= id_len);
        self.counter +%= 1;
        // Two splitmix64 draws -> 128 bits, mixing seed and counter so ids are
        // opaque (not a visible counter) while staying unique per (seed,counter).
        const hi = splitmix64(self.seed ^ (self.counter *% 0x9E3779B97F4A7C15));
        const lo = splitmix64((self.seed *% 0xD1B54A32D192ED03) +% self.counter);
        return encode128(hi, lo, buf[0..id_len]);
    }
};

/// Stable event id shared by every attachment and receiving mesh node. The
/// authenticated `(origin_node, hlc)` pair already names one mesh event; hash it
/// under a dedicated domain and encode the first 128 bits in the existing
/// Crockford format so local and remote clients can reference the same msgid.
pub fn fromMeshEvent(origin_node: u64, hlc: u64, buf: []u8) []const u8 {
    std.debug.assert(buf.len >= id_len);
    const domain = "orochi-msgid-mesh-event-v1\x00";
    var material: [domain.len + 16]u8 = undefined;
    @memcpy(material[0..domain.len], domain);
    std.mem.writeInt(u64, material[domain.len..][0..8], origin_node, .big);
    std.mem.writeInt(u64, material[domain.len + 8 ..][0..8], hlc, .big);
    var digest: [std.crypto.hash.Blake3.digest_length]u8 = undefined;
    std.crypto.hash.Blake3.hash(&material, &digest, .{});
    const hi = std.mem.readInt(u64, digest[0..8], .big);
    const lo = std.mem.readInt(u64, digest[8..16], .big);
    return encode128(hi, lo, buf[0..id_len]);
}

fn splitmix64(x0: u64) u64 {
    var z = x0 +% 0x9E3779B97F4A7C15;
    z = (z ^ (z >> 30)) *% 0xBF58476D1CE4E5B9;
    z = (z ^ (z >> 27)) *% 0x94D049BB133111EB;
    return z ^ (z >> 31);
}

/// Encode the 128-bit value (hi:lo) as `id_len` base32 chars, MSB first.
fn encode128(hi: u64, lo: u64, out: []u8) []const u8 {
    var value: u128 = (@as(u128, hi) << 64) | @as(u128, lo);
    var i: usize = id_len;
    while (i > 0) {
        i -= 1;
        out[i] = alphabet[@intCast(value & 0x1f)];
        value >>= 5;
    }
    return out;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const msgedit = @import("msgedit.zig");

test "ids are fixed length and valid msgids" {
    var g = Generator.init(0xC0FFEE);
    var buf: [id_len]u8 = undefined;
    var n: usize = 0;
    while (n < 100) : (n += 1) {
        const id = g.next(&buf);
        try testing.expectEqual(id_len, id.len);
        try testing.expect(msgedit.isValidMsgid(id));
    }
}

test "ids are unique across a long run" {
    var g = Generator.init(42);
    var seen = std.AutoHashMap([id_len]u8, void).init(testing.allocator);
    defer seen.deinit();
    var buf: [id_len]u8 = undefined;
    var n: usize = 0;
    while (n < 5000) : (n += 1) {
        const id = g.next(&buf);
        var key: [id_len]u8 = undefined;
        @memcpy(&key, id);
        const gop = try seen.getOrPut(key);
        try testing.expect(!gop.found_existing); // no collision
    }
}

test "different seeds yield different id streams" {
    var a = Generator.init(1);
    var b = Generator.init(2);
    var ba: [id_len]u8 = undefined;
    var bb: [id_len]u8 = undefined;
    try testing.expect(!std.mem.eql(u8, a.next(&ba), b.next(&bb)));
}

test "mesh event ids are deterministic and bind both origin and hlc" {
    var a: [id_len]u8 = undefined;
    var b: [id_len]u8 = undefined;
    var c: [id_len]u8 = undefined;
    var d: [id_len]u8 = undefined;
    try testing.expectEqualStrings(fromMeshEvent(7, 11, &a), fromMeshEvent(7, 11, &b));
    try testing.expect(!std.mem.eql(u8, fromMeshEvent(8, 11, &c), a[0..]));
    try testing.expect(!std.mem.eql(u8, fromMeshEvent(7, 12, &d), a[0..]));
    try testing.expect(msgedit.isValidMsgid(a[0..]));
}

// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Typed hash / HMAC / HKDF primitives (planning/02, "Primitive Layer").
//!
//! These wrap `std.crypto` but expose a orochi-native surface where the
//! digest of one algorithm cannot be silently substituted for another: each
//! `Hash(alg)` has a distinct fixed-size `Digest` array type, and HMAC / HKDF
//! are parameterized by the same algorithm tag so the chain stays type-checked
//! end to end. Key material is accepted/returned through `Secret(T)` (see
//! `secret.zig`) where it is ergonomic, while leaving raw-slice entry points
//! for transcript and label bytes that are public by construction.
//!
//! TLS 1.3 `expandLabel` (HKDF-Expand-Label, RFC 8446 §7.1) is provided on top
//! of HKDF so the traffic-secret schedule has one audited implementation.
//!
//! No attacker-reachable `unreachable`/`@panic`: output-length and label-length
//! limits are checked and surfaced as errors instead of std's debug asserts.
const std = @import("std");
const Secret = @import("secret.zig").Secret;

/// Supported hash algorithms. SHA-2 family only for M0 (planning/02).
pub const Alg = enum {
    sha256,
    sha384,
    sha512,

    /// Output size of the digest in bytes.
    pub fn digestLen(comptime self: Alg) usize {
        return self.Std().digest_length;
    }

    /// Internal block size in bytes (HMAC pad width).
    pub fn blockLen(comptime self: Alg) usize {
        return self.Std().block_length;
    }

    /// The backing `std.crypto.hash` type for this algorithm.
    pub fn Std(comptime self: Alg) type {
        const sha2 = std.crypto.hash.sha2;
        return switch (self) {
            .sha256 => sha2.Sha256,
            .sha384 => sha2.Sha384,
            .sha512 => sha2.Sha512,
        };
    }
};

/// `Hash(alg)` exposes a typed digest plus one-shot and incremental hashing.
///
/// The `Digest` member is a distinct `[N]u8` array type per algorithm, so a
/// SHA-256 digest cannot be passed where a SHA-384 digest is expected.
pub fn Hash(comptime alg: Alg) type {
    return struct {
        const Self = @This();
        const Impl = alg.Std();

        /// Fixed-size digest type for this algorithm.
        pub const Digest = [alg.digestLen()]u8;
        /// Digest length in bytes.
        pub const digest_len = alg.digestLen();
        /// Internal block length in bytes.
        pub const block_len = alg.blockLen();
        /// The algorithm tag, for callers that need to thread it through.
        pub const algorithm: Alg = alg;

        /// One-shot hash of `msg`.
        pub fn hash(msg: []const u8) Digest {
            var out: Digest = undefined;
            Impl.hash(msg, &out, .{});
            return out;
        }

        /// Incremental hasher: `init` then `update`* then `final`.
        pub const Hasher = struct {
            state: Impl,

            /// Start a fresh hashing state.
            pub fn init() Hasher {
                return .{ .state = Impl.init(.{}) };
            }

            /// Absorb more message bytes.
            pub fn update(self: *Hasher, msg: []const u8) void {
                self.state.update(msg);
            }

            /// Produce the digest. The hasher must not be reused afterwards.
            pub fn final(self: *Hasher) Digest {
                var out: Digest = undefined;
                self.state.final(&out);
                return out;
            }
        };

        /// Convenience constructor mirroring `Hasher.init`.
        pub fn hasher() Hasher {
            return Hasher.init();
        }
    };
}

pub const Sha256 = Hash(.sha256);
pub const Sha384 = Hash(.sha384);
pub const Sha512 = Hash(.sha512);

/// `Hmac(alg)` is HMAC keyed by the same hash family, RFC 2104.
///
/// The MAC tag shares the algorithm's `Digest` type so it cannot be confused
/// with a tag from another hash. Keys arrive as `Secret([]const u8)`-style key
/// bytes; both raw-slice and `Secret` entry points are provided.
pub fn Hmac(comptime alg: Alg) type {
    return struct {
        const Self = @This();
        const Impl = std.crypto.auth.hmac.Hmac(alg.Std());

        /// Tag type, identical in shape to the hash digest.
        pub const Tag = [alg.digestLen()]u8;
        /// Tag length in bytes.
        pub const tag_len = alg.digestLen();
        /// The algorithm tag.
        pub const algorithm: Alg = alg;

        /// One-shot MAC over `msg` with raw key bytes.
        pub fn create(key: []const u8, msg: []const u8) Tag {
            var out: Tag = undefined;
            Impl.create(&out, msg, key);
            return out;
        }

        /// One-shot MAC over `msg` with a `Secret`-wrapped key slice.
        pub fn createSecret(key: *const Secret([]const u8), msg: []const u8) Tag {
            return create(key.declassify(), msg);
        }

        /// Incremental MAC: `init` then `update`* then `final`.
        pub const Mac = struct {
            state: Impl,

            /// Start a keyed MAC state from raw key bytes.
            pub fn init(key: []const u8) Mac {
                return .{ .state = Impl.init(key) };
            }

            /// Absorb more message bytes.
            pub fn update(self: *Mac, msg: []const u8) void {
                self.state.update(msg);
            }

            /// Produce the tag. The MAC state must not be reused afterwards.
            pub fn final(self: *Mac) Tag {
                var out: Tag = undefined;
                self.state.final(&out);
                return out;
            }
        };

        /// Begin an incremental MAC keyed by raw key bytes.
        pub fn init(key: []const u8) Mac {
            return Mac.init(key);
        }
    };
}

pub const HmacSha256 = Hmac(.sha256);
pub const HmacSha384 = Hmac(.sha384);
pub const HmacSha512 = Hmac(.sha512);

/// Errors surfaced by HKDF instead of std's debug asserts.
pub const HkdfError = error{
    /// Requested output exceeds 255 * HashLen (RFC 5869 limit).
    OutputTooLong,
    /// HKDF-Expand-Label label/context exceeded the TLS 1.3 wire limits.
    LabelTooLong,
    /// A caller-supplied runtime label was empty. Exporter labels (RFC 5705 /
    /// 8446 §7.5) must be non-empty; an empty label yields a nonsense exporter.
    EmptyLabel,
};

/// `Hkdf(alg)` is HKDF (RFC 5869) over the matching HMAC.
///
/// `extract` and `expand` mirror the RFC; `expandLabel` adds TLS 1.3's
/// HKDF-Expand-Label (RFC 8446 §7.1). The pseudorandom key (PRK) is treated as
/// key material and returned wrapped in `Secret`.
pub fn Hkdf(comptime alg: Alg) type {
    return struct {
        const Self = @This();
        const Mac = Hmac(alg);

        /// PRK / output-block length in bytes (== HashLen).
        pub const prk_len = alg.digestLen();
        /// PRK type: a `Secret`-wrapped fixed array.
        pub const Prk = Secret([prk_len]u8);
        /// The algorithm tag.
        pub const algorithm: Alg = alg;

        /// RFC 5869 §2.2: PRK = HMAC(salt, IKM). A zero-length `salt` is
        /// substituted with HashLen zero bytes by the HMAC construction, per
        /// the RFC. IKM is key material; pass it as a `Secret` slice.
        pub fn extract(salt: []const u8, ikm: *const Secret([]const u8)) Prk {
            const tag = Mac.create(salt, ikm.declassify());
            return Prk.init(tag);
        }

        /// RFC 5869 §2.2 with raw IKM bytes, for transcript-derived inputs that
        /// are already handled inside the CT zone by the caller.
        pub fn extractRaw(salt: []const u8, ikm: []const u8) Prk {
            return Prk.init(Mac.create(salt, ikm));
        }

        /// RFC 5869 §2.3: OKM = HKDF-Expand(PRK, info, L), written into `out`.
        /// Returns `error.OutputTooLong` when `out.len > 255 * HashLen`.
        pub fn expand(prk: *const Prk, info: []const u8, out: []u8) HkdfError!void {
            const n = std.math.divCeil(usize, out.len, prk_len) catch return HkdfError.OutputTooLong;
            if (n > 255) return HkdfError.OutputTooLong;

            const prk_bytes = prk.declassify();
            var t: [prk_len]u8 = undefined;
            var t_len: usize = 0; // 0 for T(0) (empty), prk_len afterwards
            var written: usize = 0;
            // `n` is bounded to [0, 255], so the counter byte never overflows.
            var block: usize = 0;

            while (written < out.len) : (block += 1) {
                const counter: u8 = @intCast(block + 1); // RFC counter starts at 1
                var mac = Mac.init(&prk_bytes);
                if (t_len != 0) mac.update(t[0..t_len]);
                mac.update(info);
                mac.update(&[_]u8{counter});
                t = mac.final();
                t_len = prk_len;

                const take = @min(prk_len, out.len - written);
                @memcpy(out[written..][0..take], t[0..take]);
                written += take;
            }
            // Wipe the intermediate block; it is derived key material.
            secureZero(&t);
        }

        /// TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1):
        ///   HkdfLabel = u16(len) || vec8("tls13 " ++ label) || vec8(context)
        ///   OKM       = HKDF-Expand(secret, HkdfLabel, len)
        /// `label` is the bare label (e.g. "derived"); the "tls13 " prefix is
        /// added here. The full prefixed label must fit in one byte of length
        /// and `context` likewise (TLS 1.3 wire limits).
        pub fn expandLabel(
            prk: *const Prk,
            comptime label: []const u8,
            context: []const u8,
            out: []u8,
        ) HkdfError!void {
            const prefix = "tls13 ";
            const full_label = prefix ++ label;
            comptime {
                if (full_label.len > 255) @compileError("HKDF-Expand-Label label too long");
            }
            if (context.len > 255) return HkdfError.LabelTooLong;
            if (out.len > std.math.maxInt(u16)) return HkdfError.OutputTooLong;

            // Build the structured HkdfLabel on the stack. Max size:
            // 2 (len) + 1 + full_label.len + 1 + 255 (context).
            var buf: [2 + 1 + full_label.len + 1 + 255]u8 = undefined;
            var n: usize = 0;

            std.mem.writeInt(u16, buf[0..2], @intCast(out.len), .big);
            n = 2;

            buf[n] = @intCast(full_label.len);
            n += 1;
            @memcpy(buf[n..][0..full_label.len], full_label);
            n += full_label.len;

            buf[n] = @intCast(context.len);
            n += 1;
            @memcpy(buf[n..][0..context.len], context);
            n += context.len;

            try expand(prk, buf[0..n], out);
        }

        /// Runtime-label form of `expandLabel`, for APIs such as the TLS 1.3
        /// exporter where the caller supplies a protocol label.
        pub fn expandLabelRuntime(
            prk: *const Prk,
            label: []const u8,
            context: []const u8,
            out: []u8,
        ) HkdfError!void {
            const prefix = "tls13 ";
            if (label.len == 0) return HkdfError.EmptyLabel;
            if (label.len > 255 - prefix.len) return HkdfError.LabelTooLong;
            if (context.len > 255) return HkdfError.LabelTooLong;
            if (out.len > std.math.maxInt(u16)) return HkdfError.OutputTooLong;

            var buf: [2 + 1 + 255 + 1 + 255]u8 = undefined;
            var n: usize = 0;

            std.mem.writeInt(u16, buf[0..2], @intCast(out.len), .big);
            n = 2;

            const full_label_len = prefix.len + label.len;
            buf[n] = @intCast(full_label_len);
            n += 1;
            @memcpy(buf[n..][0..prefix.len], prefix);
            n += prefix.len;
            @memcpy(buf[n..][0..label.len], label);
            n += label.len;

            buf[n] = @intCast(context.len);
            n += 1;
            @memcpy(buf[n..][0..context.len], context);
            n += context.len;

            try expand(prk, buf[0..n], out);
        }
    };
}

pub const HkdfSha256 = Hkdf(.sha256);
pub const HkdfSha384 = Hkdf(.sha384);
pub const HkdfSha512 = Hkdf(.sha512);

/// Best-effort zeroization the optimizer must not elide. Local mirror of the
/// `secret.zig` discipline so this file stays self-contained.
fn secureZero(buf: []u8) void {
    for (buf) |*b| {
        const vp: *volatile u8 = @ptrCast(b);
        vp.* = 0;
    }
}

// ---------------------------------------------------------------------------
// Tests: RFC known-answer vectors compared against hex constants.
// ---------------------------------------------------------------------------

/// Decode a compile-time hex string into a fixed byte array.
fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "SHA-256 one-shot KATs (FIPS 180-4 / RFC 6234)" {
    // "abc"
    try std.testing.expectEqualSlices(
        u8,
        &hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        &Sha256.hash("abc"),
    );
    // empty string
    try std.testing.expectEqualSlices(
        u8,
        &hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        &Sha256.hash(""),
    );
    // 448-bit message
    try std.testing.expectEqualSlices(
        u8,
        &hex("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
        &Sha256.hash("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
    );
}

test "SHA-256 incremental matches one-shot" {
    var h = Sha256.hasher();
    h.update("ab");
    h.update("c");
    try std.testing.expectEqual(Sha256.hash("abc"), h.final());
}

test "SHA-384 / SHA-512 KATs for \"abc\"" {
    try std.testing.expectEqualSlices(
        u8,
        &hex("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed" ++
            "8086072ba1e7cc2358baeca134c825a7"),
        &Sha384.hash("abc"),
    );
    try std.testing.expectEqualSlices(
        u8,
        &hex("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" ++
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
        &Sha512.hash("abc"),
    );
    // distinct digest types must have distinct lengths
    try std.testing.expectEqual(@as(usize, 48), Sha384.digest_len);
    try std.testing.expectEqual(@as(usize, 64), Sha512.digest_len);
}

test "HMAC-SHA256 KATs (RFC 4231 test cases 1, 2, 4)" {
    // Case 1: key = 0x0b*20, data = "Hi There"
    {
        const key = [_]u8{0x0b} ** 20;
        const tag = HmacSha256.create(&key, "Hi There");
        try std.testing.expectEqualSlices(
            u8,
            &hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
            &tag,
        );
    }
    // Case 2: key = "Jefe", data = "what do ya want for nothing?"
    {
        const tag = HmacSha256.create("Jefe", "what do ya want for nothing?");
        try std.testing.expectEqualSlices(
            u8,
            &hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
            &tag,
        );
    }
    // Case 4: key = 0x01..0x19, data = 0xcd*50
    {
        const key = hex("0102030405060708090a0b0c0d0e0f10111213141516171819");
        const data = [_]u8{0xcd} ** 50;
        const tag = HmacSha256.create(&key, &data);
        try std.testing.expectEqualSlices(
            u8,
            &hex("82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"),
            &tag,
        );
    }
}

test "HMAC-SHA256 incremental matches one-shot" {
    const key = [_]u8{0x0b} ** 20;
    var m = HmacSha256.init(&key);
    m.update("Hi ");
    m.update("There");
    try std.testing.expectEqual(HmacSha256.create(&key, "Hi There"), m.final());
}

test "HKDF-SHA256 KAT (RFC 5869 Appendix A.1)" {
    const ikm_bytes = [_]u8{0x0b} ** 22;
    const salt = hex("000102030405060708090a0b0c");
    const info = hex("f0f1f2f3f4f5f6f7f8f9");

    const ikm = Secret([]const u8).init(&ikm_bytes);
    const prk = HkdfSha256.extract(&salt, &ikm);

    try std.testing.expectEqualSlices(
        u8,
        &hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"),
        &prk.declassify(),
    );

    var okm: [42]u8 = undefined;
    try HkdfSha256.expand(&prk, &info, &okm);
    try std.testing.expectEqualSlices(
        u8,
        &hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf" ++
            "34007208d5b887185865"),
        &okm,
    );
}

test "HKDF-SHA256 with empty salt/info (RFC 5869 Appendix A.3)" {
    const ikm_bytes = [_]u8{0x0b} ** 22;
    const ikm = Secret([]const u8).init(&ikm_bytes);
    const prk = HkdfSha256.extract("", &ikm);

    try std.testing.expectEqualSlices(
        u8,
        &hex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"),
        &prk.declassify(),
    );

    var okm: [42]u8 = undefined;
    try HkdfSha256.expand(&prk, "", &okm);
    try std.testing.expectEqualSlices(
        u8,
        &hex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d" ++
            "9d201395faa4b61a96c8"),
        &okm,
    );
}

test "HKDF expand rejects oversized output" {
    const prk = HkdfSha256.Prk.init([_]u8{0} ** 32);
    var big: [256 * 32 + 1]u8 = undefined;
    try std.testing.expectError(HkdfError.OutputTooLong, HkdfSha256.expand(&prk, "", &big));
}

test "HKDF-Expand-Label produces stable TLS 1.3 derived secret shape" {
    // Vector cross-checked against an independent HKDF-Expand-Label using the
    // empty-transcript "derived" secret from TLS 1.3 key schedule.
    // early_secret = HKDF-Extract(salt=0, IKM=0^HashLen)
    const zeros = [_]u8{0} ** 32;
    const ikm = Secret([]const u8).init(&zeros);
    const early = HkdfSha256.extract("", &ikm);

    // empty_hash = SHA256("")
    const empty_hash = Sha256.hash("");
    var derived: [32]u8 = undefined;
    try HkdfSha256.expandLabel(&early, "derived", &empty_hash, &derived);

    // Known TLS 1.3 "derived" secret for the all-zero PSK / empty transcript.
    try std.testing.expectEqualSlices(
        u8,
        &hex("6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba"),
        &derived,
    );
}

test {
    std.testing.refAllDecls(@This());
}

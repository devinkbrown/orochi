//! TLS 1.3 HKDF key schedule helpers (RFC 8446 section 7).
//!
//! This module is deliberately pure: callers provide transcript hashes and key
//! inputs, and the helpers return typed secret material without touching record
//! state, sockets, or daemon code. HKDF and HMAC come from `hash.zig` so the
//! implementation stays on Orochi's typed crypto surface.
const std = @import("std");
const hash = @import("hash.zig");
const Secret = @import("secret.zig").Secret;

pub const Error = hash.HkdfError || error{
    BadTranscriptHash,
};

pub fn KeySchedule(comptime alg: hash.Alg) type {
    return struct {
        const Self = @This();
        const Hash = hash.Hash(alg);
        const Hkdf = hash.Hkdf(alg);
        const Mac = hash.Hmac(alg);

        pub const hash_alg = alg;
        pub const hash_len = Hash.digest_len;
        pub const SecretBytes = Secret([hash_len]u8);

        pub const TrafficSecrets = struct {
            client: SecretBytes,
            server: SecretBytes,

            pub fn wipe(self: *TrafficSecrets) void {
                self.client.wipe();
                self.server.wipe();
            }
        };

        pub const DerivedChain = struct {
            early: SecretBytes,
            handshake: SecretBytes,
            master: SecretBytes,
            exporter_master: SecretBytes,
            handshake_traffic: TrafficSecrets,
            application_traffic: TrafficSecrets,

            pub fn wipe(self: *DerivedChain) void {
                self.early.wipe();
                self.handshake.wipe();
                self.master.wipe();
                self.exporter_master.wipe();
                self.handshake_traffic.wipe();
                self.application_traffic.wipe();
            }
        };

        /// Hash a caller-owned transcript buffer with the schedule hash.
        pub fn transcriptHash(messages: []const u8) Hash.Digest {
            return Hash.hash(messages);
        }

        /// The empty transcript hash used by RFC 8446's "derived" transitions.
        pub fn emptyTranscriptHash() Hash.Digest {
            return Hash.hash("");
        }

        /// RFC 8446 section 7.1 HKDF-Expand-Label.
        pub fn hkdfExpandLabel(
            secret: *const SecretBytes,
            comptime label: []const u8,
            context: []const u8,
            out: []u8,
        ) Error!void {
            try Hkdf.expandLabel(secret, label, context, out);
        }

        /// RFC 8446 section 7.1 HKDF-Expand-Label with a runtime label.
        pub fn hkdfExpandLabelRuntime(
            secret: *const SecretBytes,
            label: []const u8,
            context: []const u8,
            out: []u8,
        ) Error!void {
            try Hkdf.expandLabelRuntime(secret, label, context, out);
        }

        /// RFC 8446 section 7.1 Derive-Secret.
        pub fn deriveSecret(
            secret: *const SecretBytes,
            comptime label: []const u8,
            transcript_hash: []const u8,
        ) Error!SecretBytes {
            if (transcript_hash.len != hash_len) return error.BadTranscriptHash;
            var out: [hash_len]u8 = undefined;
            try hkdfExpandLabel(secret, label, transcript_hash, &out);
            return SecretBytes.init(out);
        }

        /// RFC 8446 section 7.1 Derive-Secret with a runtime label.
        pub fn deriveSecretRuntime(
            secret: *const SecretBytes,
            label: []const u8,
            transcript_hash: []const u8,
        ) Error!SecretBytes {
            if (transcript_hash.len != hash_len) return error.BadTranscriptHash;
            var out: [hash_len]u8 = undefined;
            try hkdfExpandLabelRuntime(secret, label, transcript_hash, &out);
            return SecretBytes.init(out);
        }

        /// Early Secret = HKDF-Extract(0, PSK).
        ///
        /// An empty PSK means "no PSK" and is substituted with HashLen zero
        /// bytes, matching RFC 8446's unavailable-secret rule.
        pub fn earlySecret(psk: []const u8) SecretBytes {
            const zero_salt = [_]u8{0} ** hash_len;
            const zero_ikm = [_]u8{0} ** hash_len;
            const ikm = if (psk.len == 0) zero_ikm[0..] else psk;
            return Hkdf.extractRaw(&zero_salt, ikm);
        }

        /// Handshake Secret = HKDF-Extract(Derive-Secret(Early, "derived", ""),
        /// (EC)DHE). An empty shared secret is treated as unavailable.
        pub fn handshakeSecret(
            early: *const SecretBytes,
            shared_secret: []const u8,
        ) Error!SecretBytes {
            var derived = try deriveSecret(early, "derived", &emptyTranscriptHash());
            defer derived.wipe();

            const zero_ikm = [_]u8{0} ** hash_len;
            const ikm = if (shared_secret.len == 0) zero_ikm[0..] else shared_secret;
            return Hkdf.extractRaw(&derived.declassify(), ikm);
        }

        /// Master Secret = HKDF-Extract(Derive-Secret(Handshake, "derived", ""),
        /// 0).
        pub fn masterSecret(handshake: *const SecretBytes) Error!SecretBytes {
            var derived = try deriveSecret(handshake, "derived", &emptyTranscriptHash());
            defer derived.wipe();
            const zero_ikm = [_]u8{0} ** hash_len;
            return Hkdf.extractRaw(&derived.declassify(), &zero_ikm);
        }

        pub fn handshakeTrafficSecrets(
            handshake: *const SecretBytes,
            transcript_hash: []const u8,
        ) Error!TrafficSecrets {
            return .{
                .client = try deriveSecret(handshake, "c hs traffic", transcript_hash),
                .server = try deriveSecret(handshake, "s hs traffic", transcript_hash),
            };
        }

        pub fn applicationTrafficSecrets(
            master: *const SecretBytes,
            transcript_hash: []const u8,
        ) Error!TrafficSecrets {
            return .{
                .client = try deriveSecret(master, "c ap traffic", transcript_hash),
                .server = try deriveSecret(master, "s ap traffic", transcript_hash),
            };
        }

        /// Exporter Master Secret = Derive-Secret(Master, "exp master",
        /// Handshake Context).
        pub fn exporterMasterSecret(
            master: *const SecretBytes,
            transcript_hash: []const u8,
        ) Error!SecretBytes {
            return deriveSecret(master, "exp master", transcript_hash);
        }

        /// RFC 8446 section 7.5 TLS-Exporter.
        pub fn exportKeyingMaterial(
            exporter_master_secret: *const SecretBytes,
            label: []const u8,
            context_value: []const u8,
            out: []u8,
        ) Error!void {
            var derived = try deriveSecretRuntime(exporter_master_secret, label, &emptyTranscriptHash());
            defer derived.wipe();
            const context_hash = Hash.hash(context_value);
            try hkdfExpandLabel(&derived, "exporter", &context_hash, out);
        }

        /// RFC 9266 tls-exporter channel-binding value.
        pub fn channelBindingTlsExporter(
            exporter_master_secret: *const SecretBytes,
            out: *[32]u8,
        ) Error!void {
            try exportKeyingMaterial(exporter_master_secret, "EXPORTER-Channel-Binding", "", out[0..]);
        }

        pub fn finishedKey(base_key: *const SecretBytes) Error!SecretBytes {
            var out: [hash_len]u8 = undefined;
            try hkdfExpandLabel(base_key, "finished", "", &out);
            return SecretBytes.init(out);
        }

        pub fn finishedVerifyData(
            finished_key: *const SecretBytes,
            transcript_hash: []const u8,
        ) Error![hash_len]u8 {
            if (transcript_hash.len != hash_len) return error.BadTranscriptHash;
            const key = finished_key.declassify();
            return Mac.create(&key, transcript_hash);
        }

        /// Convenience chain for a 1-RTT TLS 1.3 schedule. The caller supplies
        /// already-computed transcript hashes for the handshake traffic point
        /// and the application traffic point.
        pub fn deriveChain(
            psk: []const u8,
            shared_secret: []const u8,
            handshake_transcript_hash: []const u8,
            application_transcript_hash: []const u8,
        ) Error!DerivedChain {
            var early = earlySecret(psk);
            errdefer early.wipe();

            var handshake = try handshakeSecret(&early, shared_secret);
            errdefer handshake.wipe();

            var handshake_traffic = try handshakeTrafficSecrets(&handshake, handshake_transcript_hash);
            errdefer handshake_traffic.wipe();

            var master = try masterSecret(&handshake);
            errdefer master.wipe();

            var application_traffic = try applicationTrafficSecrets(&master, application_transcript_hash);
            errdefer application_traffic.wipe();

            var exporter_master = try exporterMasterSecret(&master, application_transcript_hash);
            errdefer exporter_master.wipe();

            return .{
                .early = early,
                .handshake = handshake,
                .master = master,
                .exporter_master = exporter_master,
                .handshake_traffic = handshake_traffic,
                .application_traffic = application_traffic,
            };
        }

        comptime {
            _ = Self;
        }
    };
}

pub const Sha256 = KeySchedule(.sha256);
pub const Sha384 = KeySchedule(.sha384);
pub const Sha512 = KeySchedule(.sha512);

fn hexAlloc(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
    if (s.len % 2 != 0) return error.InvalidCharacter;
    const out = try allocator.alloc(u8, s.len / 2);
    errdefer allocator.free(out);
    _ = try std.fmt.hexToBytes(out, s);
    return out;
}

fn expectHex(comptime expected_hex: []const u8, actual: []const u8) !void {
    const allocator = std.testing.allocator;
    const expected = try hexAlloc(allocator, expected_hex);
    defer allocator.free(expected);
    try std.testing.expectEqualSlices(u8, expected, actual);
}

test "RFC 8448 HKDF-Expand-Label derives TLS 1.3 derived secret" {
    var early = Sha256.earlySecret("");
    defer early.wipe();

    const empty_hash = Sha256.emptyTranscriptHash();
    var derived: [Sha256.hash_len]u8 = undefined;
    try Sha256.hkdfExpandLabel(&early, "derived", &empty_hash, &derived);

    try expectHex(
        "6f2615a108c702c5678f54fc9dbab697" ++
            "16c076189c48250cebeac3576c3611ba",
        &derived,
    );
}

test "RFC 8448 Derive-Secret publishes handshake traffic secrets" {
    const allocator = std.testing.allocator;
    const shared_secret = try hexAlloc(
        allocator,
        "8bd4054fb55b9d63fdfbacf9f04b9f0d" ++
            "35e6d63f537563efd46272900f89492d",
    );
    defer allocator.free(shared_secret);
    const hello_hash = try hexAlloc(
        allocator,
        "860c06edc07858ee8e78f0e7428c58ed" ++
            "d6b43f2ca3e6e95f02ed063cf0e1cad8",
    );
    defer allocator.free(hello_hash);

    var early = Sha256.earlySecret("");
    defer early.wipe();
    var handshake = try Sha256.handshakeSecret(&early, shared_secret);
    defer handshake.wipe();
    try expectHex(
        "1dc826e93606aa6fdc0aadc12f741b01" ++
            "046aa6b99f691ed221a9f0ca043fbeac",
        &handshake.declassify(),
    );

    var traffic = try Sha256.handshakeTrafficSecrets(&handshake, hello_hash);
    defer traffic.wipe();
    try expectHex(
        "b3eddb126e067f35a780b3abf45e2d8f" ++
            "3b1a950738f52e9600746a0e27a55a21",
        &traffic.client.declassify(),
    );
    try expectHex(
        "b67b7d690cc16c4e75e54213cb2d37b4" ++
            "e9c912bcded9105d42befd59d391ad38",
        &traffic.server.declassify(),
    );
}

test "RFC 8448 early handshake master chain over caller transcript hashes" {
    const allocator = std.testing.allocator;
    const shared_secret = try hexAlloc(
        allocator,
        "8bd4054fb55b9d63fdfbacf9f04b9f0d" ++
            "35e6d63f537563efd46272900f89492d",
    );
    defer allocator.free(shared_secret);
    const hello_hash = try hexAlloc(
        allocator,
        "860c06edc07858ee8e78f0e7428c58ed" ++
            "d6b43f2ca3e6e95f02ed063cf0e1cad8",
    );
    defer allocator.free(hello_hash);
    const server_finished_hash = try hexAlloc(
        allocator,
        "9608102a0f1ccc6db6250b7b7e417b1a" ++
            "000eaada3daae4777a7686c9ff83df13",
    );
    defer allocator.free(server_finished_hash);

    var chain = try Sha256.deriveChain("", shared_secret, hello_hash, server_finished_hash);
    defer chain.wipe();

    try expectHex(
        "33ad0a1c607ec03b09e6cd9893680ce2" ++
            "10adf300aa1f2660e1b22e10f170f92a",
        &chain.early.declassify(),
    );
    try expectHex(
        "18df06843d13a08bf2a449844c5f8a47" ++
            "8001bc4d4c627984d5a41da8d0402919",
        &chain.master.declassify(),
    );
    try expectHex(
        "fe22f881176eda18eb8f44529e6792c5" ++
            "0c9a3f89452f68d8ae311b4309d3cf50",
        &chain.exporter_master.declassify(),
    );
    try expectHex(
        "9e40646ce79a7f9dc05af8889bce6552" ++
            "875afa0b06df0087f792ebb7c17504a5",
        &chain.application_traffic.client.declassify(),
    );
    try expectHex(
        "a11af9f05531f856ad47116b45a95032" ++
            "8204b4f44bfb6b3a4b4f1f3fcb631643",
        &chain.application_traffic.server.declassify(),
    );
}

test "TLS 1.3 schedule rejects malformed transcript hashes" {
    var early = Sha256.earlySecret("");
    defer early.wipe();
    try std.testing.expectError(error.BadTranscriptHash, Sha256.deriveSecret(&early, "derived", "short"));
}

test "RFC 8448 schedule exports RFC 9266 tls-exporter channel binding" {
    const allocator = std.testing.allocator;
    const shared_secret = try hexAlloc(
        allocator,
        "8bd4054fb55b9d63fdfbacf9f04b9f0d" ++
            "35e6d63f537563efd46272900f89492d",
    );
    defer allocator.free(shared_secret);
    const hello_hash = try hexAlloc(
        allocator,
        "860c06edc07858ee8e78f0e7428c58ed" ++
            "d6b43f2ca3e6e95f02ed063cf0e1cad8",
    );
    defer allocator.free(hello_hash);
    const server_finished_hash = try hexAlloc(
        allocator,
        "9608102a0f1ccc6db6250b7b7e417b1a" ++
            "000eaada3daae4777a7686c9ff83df13",
    );
    defer allocator.free(server_finished_hash);

    var chain = try Sha256.deriveChain("", shared_secret, hello_hash, server_finished_hash);
    defer chain.wipe();

    var channel_binding: [32]u8 = undefined;
    try Sha256.channelBindingTlsExporter(&chain.exporter_master, &channel_binding);
    try expectHex(
        "e3b0946bf2f4668144f22872e0afd51d" ++
            "c9608638c6f9b2584b98c6cd3a4affad",
        &channel_binding,
    );

    var same_again: [32]u8 = undefined;
    try Sha256.exportKeyingMaterial(&chain.exporter_master, "EXPORTER-Channel-Binding", "", &same_again);
    try std.testing.expectEqualSlices(u8, &channel_binding, &same_again);

    var different_context: [32]u8 = undefined;
    try Sha256.exportKeyingMaterial(&chain.exporter_master, "EXPORTER-Channel-Binding", "x", &different_context);
    try expectHex(
        "31018a0846c27dd3a254e86168349f5d" ++
            "7455d78bdd912da703bf3ef25cd2ad4b",
        &different_context,
    );
    try std.testing.expect(!std.mem.eql(u8, &channel_binding, &different_context));

    var different_label: [32]u8 = undefined;
    try Sha256.exportKeyingMaterial(&chain.exporter_master, "other", "", &different_label);
    try expectHex(
        "bf34b0388297e5d393dda95ace8f02f30" ++
            "813af2032e4d98dc69e30d4805c90c1",
        &different_label,
    );
    try std.testing.expect(!std.mem.eql(u8, &channel_binding, &different_label));

    var bounded = [_]u8{0xa5} ** 40;
    try Sha256.exportKeyingMaterial(&chain.exporter_master, "EXPORTER-Channel-Binding", "", bounded[4..36]);
    try std.testing.expectEqual(@as(u8, 0xa5), bounded[0]);
    try std.testing.expectEqual(@as(u8, 0xa5), bounded[3]);
    try std.testing.expectEqual(@as(u8, 0xa5), bounded[36]);
    try std.testing.expectEqual(@as(u8, 0xa5), bounded[39]);
}

test {
    std.testing.refAllDecls(@This());
}

//! TLS certificate material loader for the daemon's TLS listener.
//!
//! Resolves the leaf certificate chain + Ed25519 signing key that the TLS server
//! handshake needs, from one of two sources:
//!   * **On-disk material** — when both `cert_path` and `key_path` are supplied,
//!     the files are read and decoded. Each accepts either PEM (a
//!     `-----BEGIN CERTIFICATE-----` / `-----BEGIN PRIVATE KEY-----` block) or
//!     raw DER, detected by sniffing for the PEM armor.
//!   * **Self-signed bootstrap** — when no paths are given and TLS is enabled,
//!     a fresh Ed25519 keypair is generated (seeded from the OS CSPRNG) and a
//!     short-lived self-signed leaf is minted with `dns_name` as its subject.
//!
//! The returned `Loaded` shape mirrors `crypto/tls_handshake.Config`
//! (`cert_chain` + an Ed25519 `signing_key`); the live listener is wired by
//! `main.zig`, which owns the handshake. The cert chain bytes are caller-owned —
//! call `Loaded.deinit` to release them.
const std = @import("std");

const pem = @import("../proto/pem.zig");
const ed25519_pkcs8 = @import("../proto/ed25519_pkcs8.zig");
const x509_selfsign = @import("../proto/x509_selfsign.zig");
const x509 = @import("../crypto/x509.zig");
const random = @import("../crypto/random.zig");

comptime {
    if (@bitSizeOf(usize) != 64) @compileError("tls_certs requires a 64-bit target");
}

const Ed25519 = std.crypto.sign.Ed25519;

/// PEM armor markers used to distinguish PEM input from raw DER.
const cert_pem_label = "CERTIFICATE";
const key_pem_label = "PRIVATE KEY";
const pem_begin_marker = "-----BEGIN";

/// Upper bound on a single on-disk cert or key file. Generous for a leaf chain;
/// guards against runaway reads of an attacker-controlled path.
const max_file_bytes: usize = 256 * 1024;

/// Validity window for the bootstrap leaf: backdated one hour to absorb clock
/// skew, valid for roughly one year.
const bootstrap_backdate_s: i64 = 3600;
const bootstrap_lifetime_s: i64 = 365 * 24 * 3600;

pub const Error = error{
    /// `cert_path` set without `key_path` (or vice versa).
    IncompletePathPair,
    /// Neither on-disk paths nor `enabled` bootstrap were requested.
    NothingToLoad,
} ||
    std.Io.Dir.ReadFileAllocError ||
    pem.Error ||
    ed25519_pkcs8.ParseError ||
    x509_selfsign.Error ||
    std.crypto.errors.IdentityElementError ||
    std.crypto.errors.NonCanonicalError ||
    std.crypto.errors.KeyMismatchError ||
    std.crypto.errors.WeakPublicKeyError ||
    random.Error;

/// Inputs for `loadOrBootstrap`. Strings are borrowed for the duration of the
/// call only (paths are read immediately; `dns_name` is copied into the cert).
pub const Options = struct {
    enabled: bool = false,
    cert_path: ?[]const u8 = null,
    key_path: ?[]const u8 = null,
    /// Subject name minted into the self-signed bootstrap leaf.
    dns_name: []const u8 = "localhost",
};

/// Resolved TLS material. Shape matches `crypto/tls_handshake.Config`:
/// `cert_chain` is a leaf-first list of DER certificates, `signing_key` is the
/// Ed25519 key that signs the TLS 1.3 CertificateVerify. The chain bytes are
/// owned by this struct; the signing key is a value.
pub const Loaded = struct {
    cert_chain: [][]const u8,
    signing_key: Ed25519.KeyPair,

    pub fn deinit(self: *Loaded, allocator: std.mem.Allocator) void {
        for (self.cert_chain) |der| allocator.free(der);
        allocator.free(self.cert_chain);
        std.crypto.secureZero(u8, std.mem.asBytes(&self.signing_key.secret_key));
        self.* = undefined;
    }
};

/// Load TLS material from disk, or bootstrap a self-signed leaf.
///
/// Precedence: if both `cert_path` and `key_path` are set, the on-disk material
/// wins. Supplying exactly one of the pair is an error. Otherwise, when
/// `enabled`, a self-signed leaf is bootstrapped; with neither paths nor
/// `enabled`, `error.NothingToLoad` is returned.
pub fn loadOrBootstrap(allocator: std.mem.Allocator, io: std.Io, opts: Options) Error!Loaded {
    const has_cert = opts.cert_path != null;
    const has_key = opts.key_path != null;
    if (has_cert != has_key) return error.IncompletePathPair;

    if (has_cert and has_key) {
        return loadFromDisk(allocator, io, opts.cert_path.?, opts.key_path.?);
    }
    if (!opts.enabled) return error.NothingToLoad;
    return bootstrap(allocator, io, opts.dns_name);
}

/// Read and decode an on-disk certificate + private key pair.
fn loadFromDisk(allocator: std.mem.Allocator, io: std.Io, cert_path: []const u8, key_path: []const u8) Error!Loaded {
    const cert_der = try loadCertDer(allocator, io, cert_path);
    errdefer allocator.free(cert_der);

    const seed = try loadKeySeed(allocator, io, key_path);
    const key_pair = try Ed25519.KeyPair.generateDeterministic(seed);

    const chain = try allocator.alloc([]const u8, 1);
    chain[0] = cert_der;
    return .{ .cert_chain = chain, .signing_key = key_pair };
}

/// Read a certificate file (PEM or DER) and return owned DER bytes.
fn loadCertDer(allocator: std.mem.Allocator, io: std.Io, path: []const u8) Error![]const u8 {
    const raw = try readFileOwned(allocator, io, path);
    defer allocator.free(raw);

    if (!isPem(raw)) return allocator.dupe(u8, raw);

    const der_buf = try allocator.alloc(u8, raw.len);
    defer allocator.free(der_buf);
    const der = try pem.decode(raw, cert_pem_label, der_buf);
    return allocator.dupe(u8, der);
}

/// Read a private key file (PEM or DER PKCS#8) and return the 32-byte Ed25519 seed.
fn loadKeySeed(allocator: std.mem.Allocator, io: std.Io, path: []const u8) Error![ed25519_pkcs8.seed_len]u8 {
    const raw = try readFileOwned(allocator, io, path);
    defer allocator.free(raw);

    if (!isPem(raw)) return ed25519_pkcs8.parse(raw);

    const der_buf = try allocator.alloc(u8, raw.len);
    defer allocator.free(der_buf);
    const der = try pem.decode(raw, key_pem_label, der_buf);
    return ed25519_pkcs8.parse(der);
}

/// Generate a fresh Ed25519 keypair and mint a self-signed leaf for `dns_name`.
fn bootstrap(allocator: std.mem.Allocator, io: std.Io, dns_name: []const u8) Error!Loaded {
    var seed: [Ed25519.KeyPair.seed_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &seed);
    try random.fillOsEntropy(&seed);
    const key_pair = try Ed25519.KeyPair.generateDeterministic(seed);

    const now = std.Io.Clock.real.now(io).toSeconds();
    var der_buf: [1024]u8 = undefined;
    const der = try x509_selfsign.buildSelfSigned(&der_buf, .{
        .common_name = dns_name,
        .not_before = now - bootstrap_backdate_s,
        .not_after = now + bootstrap_lifetime_s,
        .serial = &bootstrap_serial,
        .key_pair = key_pair,
        // Standards TLS clients match the SAN, not the CN, so the bootstrap leaf
        // carries dns_name as a SAN and is marked a CA so it can self-anchor.
        .dns_names = &.{dns_name},
        .is_ca = true,
    });

    const owned = try allocator.dupe(u8, der);
    errdefer allocator.free(owned);
    const chain = try allocator.alloc([]const u8, 1);
    chain[0] = owned;
    return .{ .cert_chain = chain, .signing_key = key_pair };
}

/// Fixed nonzero serial for bootstrap leaves; uniqueness across boots is not
/// required since these are ephemeral, single-host certificates.
const bootstrap_serial = [_]u8{ 0x53, 0x55, 0x5a, 0x55 }; // "SUZU"

/// True when `bytes` looks like PEM (carries the BEGIN armor).
fn isPem(bytes: []const u8) bool {
    return std.mem.indexOf(u8, bytes, pem_begin_marker) != null;
}

/// Read a whole file into an owned buffer, bounded by `max_file_bytes`. Uses the
/// Zig 0.16 `std.Io` layer so the caller controls the IO implementation.
fn readFileOwned(allocator: std.mem.Allocator, io: std.Io, path: []const u8) Error![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(max_file_bytes));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "loadOrBootstrap: no paths mints a verifiable self-signed leaf for dns_name" {
    // Arrange
    const allocator = testing.allocator;
    const dns_name = "irc.example.test";

    // Act
    var loaded = try loadOrBootstrap(allocator, testing.io, .{ .enabled = true, .dns_name = dns_name });
    defer loaded.deinit(allocator);

    // Assert
    try testing.expectEqual(@as(usize, 1), loaded.cert_chain.len);
    const cert = try x509.parse(loaded.cert_chain[0]);
    // The bootstrap leaf is self-signed: its embedded public key must match the
    // returned signing key, and its TBS signature must verify under that key.
    try expectSelfSignedBy(loaded.cert_chain[0], loaded.signing_key);
    // When the certificate carries SAN entries, dns_name must be present; the
    // current minter encodes dns_name as the subject CN, so SAN may be empty.
    if (cert.san_dns_count != 0) {
        var found = false;
        for (cert.san_dns[0..cert.san_dns_count]) |name| {
            if (std.mem.eql(u8, name, dns_name)) found = true;
        }
        try testing.expect(found);
    }
}

test "loadOrBootstrap: bootstrap keypairs differ across calls" {
    // Arrange
    const allocator = testing.allocator;

    // Act
    var a = try loadOrBootstrap(allocator, testing.io, .{ .enabled = true, .dns_name = "a.test" });
    defer a.deinit(allocator);
    var b = try loadOrBootstrap(allocator, testing.io, .{ .enabled = true, .dns_name = "a.test" });
    defer b.deinit(allocator);

    // Assert: fresh OS entropy per call yields distinct public keys.
    try testing.expect(!std.mem.eql(
        u8,
        &a.signing_key.public_key.toBytes(),
        &b.signing_key.public_key.toBytes(),
    ));
}

test "loadOrBootstrap: disabled with no paths reports NothingToLoad" {
    // Arrange / Act / Assert
    try testing.expectError(
        error.NothingToLoad,
        loadOrBootstrap(testing.allocator, testing.io, .{ .enabled = false }),
    );
}

test "loadOrBootstrap: a lone cert_path is rejected" {
    // Arrange / Act / Assert
    try testing.expectError(
        error.IncompletePathPair,
        loadOrBootstrap(testing.allocator, testing.io, .{ .enabled = true, .cert_path = "leaf.pem" }),
    );
}

test "loadOrBootstrap: PEM round-trip from disk decodes cert + key" {
    // Arrange: mint a DER cert + key, wrap both as PEM, write to a temp dir.
    const allocator = testing.allocator;
    const seed = [_]u8{0x21} ** Ed25519.KeyPair.seed_length;
    const key_pair = try Ed25519.KeyPair.generateDeterministic(seed);

    var cert_der_buf: [768]u8 = undefined;
    const cert_der = try x509_selfsign.buildSelfSigned(&cert_der_buf, .{
        .common_name = "disk.test",
        .not_before = 1_704_067_200,
        .not_after = 1_735_689_599,
        .serial = &.{ 0x01, 0x02 },
        .key_pair = key_pair,
    });

    var key_der_buf: [ed25519_pkcs8.der_len]u8 = undefined;
    const key_der = try ed25519_pkcs8.encode(&key_der_buf, seed);

    var cert_pem_buf: [4096]u8 = undefined;
    const cert_pem = try pem.encode(&cert_pem_buf, cert_pem_label, cert_der);
    var key_pem_buf: [4096]u8 = undefined;
    const key_pem = try pem.encode(&key_pem_buf, key_pem_label, key_der);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "leaf.pem", .data = cert_pem });
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "leaf.key", .data = key_pem });
    const cert_path = try tmpPath(allocator, tmp, "leaf.pem");
    defer allocator.free(cert_path);
    const key_path = try tmpPath(allocator, tmp, "leaf.key");
    defer allocator.free(key_path);

    // Act
    var loaded = try loadOrBootstrap(allocator, testing.io, .{
        .enabled = true,
        .cert_path = cert_path,
        .key_path = key_path,
    });
    defer loaded.deinit(allocator);

    // Assert: decoded chain equals the source DER and the key recovers the seed.
    try testing.expectEqual(@as(usize, 1), loaded.cert_chain.len);
    try testing.expectEqualSlices(u8, cert_der, loaded.cert_chain[0]);
    try testing.expectEqualSlices(
        u8,
        &key_pair.public_key.toBytes(),
        &loaded.signing_key.public_key.toBytes(),
    );
}

test "loadOrBootstrap: raw DER files (no PEM armor) load directly" {
    // Arrange
    const allocator = testing.allocator;
    const seed = [_]u8{0x37} ** Ed25519.KeyPair.seed_length;
    const key_pair = try Ed25519.KeyPair.generateDeterministic(seed);

    var cert_der_buf: [768]u8 = undefined;
    const cert_der = try x509_selfsign.buildSelfSigned(&cert_der_buf, .{
        .common_name = "der.test",
        .not_before = 1_704_067_200,
        .not_after = 1_735_689_599,
        .serial = &.{0x09},
        .key_pair = key_pair,
    });
    var key_der_buf: [ed25519_pkcs8.der_len]u8 = undefined;
    const key_der = try ed25519_pkcs8.encode(&key_der_buf, seed);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "leaf.der", .data = cert_der });
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "leaf.key.der", .data = key_der });
    const cert_path = try tmpPath(allocator, tmp, "leaf.der");
    defer allocator.free(cert_path);
    const key_path = try tmpPath(allocator, tmp, "leaf.key.der");
    defer allocator.free(key_path);

    // Act
    var loaded = try loadOrBootstrap(allocator, testing.io, .{
        .enabled = true,
        .cert_path = cert_path,
        .key_path = key_path,
    });
    defer loaded.deinit(allocator);

    // Assert
    try testing.expectEqualSlices(u8, cert_der, loaded.cert_chain[0]);
    try testing.expectEqualSlices(
        u8,
        &key_pair.public_key.toBytes(),
        &loaded.signing_key.public_key.toBytes(),
    );
}

/// Build a cwd-relative path into a testing tmp dir, matching `testing.tmpDir`'s
/// `.zig-cache/tmp/<sub_path>` layout so `std.Io.Dir.cwd()` reads resolve.
fn tmpPath(allocator: std.mem.Allocator, tmp: testing.TmpDir, name: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/{s}", .{ tmp.sub_path, name });
}

/// Verify that `cert_der` is a self-signed Ed25519 certificate whose embedded
/// SPKI public key equals `key_pair`'s and whose TBS signature verifies.
fn expectSelfSignedBy(cert_der: []const u8, key_pair: Ed25519.KeyPair) !void {
    var cert_cursor: usize = 0;
    const cert = try readTlv(cert_der, &cert_cursor);
    var body_cursor: usize = 0;
    const tbs = try readTlv(cert.value, &body_cursor);
    _ = try readTlv(cert.value, &body_cursor); // signatureAlgorithm
    const sig_bits = try readTlv(cert.value, &body_cursor);

    const sig = Ed25519.Signature.fromBytes(
        sig_bits.value[1..][0..Ed25519.Signature.encoded_length].*,
    );
    try sig.verify(tbs.full, key_pair.public_key);
}

const Tlv = struct {
    tag: u8,
    value: []const u8,
    full: []const u8,
};

/// Minimal DER TLV reader for the self-signed verification assertion.
fn readTlv(input: []const u8, cursor: *usize) !Tlv {
    const start = cursor.*;
    if (input.len - cursor.* < 2) return error.Truncated;
    const tag = input[cursor.*];
    cursor.* += 1;
    const len_byte = input[cursor.*];
    cursor.* += 1;
    var len: usize = 0;
    if ((len_byte & 0x80) == 0) {
        len = len_byte;
    } else {
        const count = len_byte & 0x7f;
        if (count == 0 or count > @sizeOf(usize)) return error.BadLength;
        if (input.len - cursor.* < count) return error.Truncated;
        for (0..count) |_| {
            len = (len << 8) | input[cursor.*];
            cursor.* += 1;
        }
    }
    if (input.len - cursor.* < len) return error.Truncated;
    const value = input[cursor.* .. cursor.* + len];
    cursor.* += len;
    return .{ .tag = tag, .value = value, .full = input[start..cursor.*] };
}

test {
    testing.refAllDecls(@This());
}

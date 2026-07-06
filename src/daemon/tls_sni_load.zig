// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! `[[tls.sni]]` certificate load loop, extracted from `main.zig` so it is unit
//! testable under `std.testing.allocator` (which fails a test on any leak).
//!
//! `buildSniCerts` loads each configured SNI entry with the SAME loader as the
//! default TLS cert (`tls_certs.loadOrBootstrap`, wired via `default_loader`),
//! validates its chain via an injected `validateChain` predicate (production
//! passes `main.validateTlsChain`; tests pass a stub), retains the loaded
//! material in a caller-owned list, and returns a `[]tls_server.SniCert`
//! selection list for the listener.
//!
//! Both the loader and the validator are injected so tests can drive every
//! error path deterministically (load failure, validation failure, and OOM at
//! any allocation) without real cert files or fragile allocation-index guesses.
//! Production wires the real implementations (`default_loader`, `validateChain`).
//!
//! Ownership contract (unchanged from the original inline loop):
//!   * Each loaded `tls_certs.Loaded` is appended to `out_loaded`, which the
//!     CALLER owns for the server's lifetime and frees (each element via
//!     `Loaded.deinit`, which secure-zeros key material). The loaded certs must
//!     outlive the server because the returned `SniCert`s only BORROW their
//!     `cert_chain` bytes and ALIAS the signing keys.
//!   * The returned `[]SniCert` is caller-owned (free the slice; its contents are
//!     borrows, never freed individually).
//!   * On ANY error the partial `[]SniCert` is freed and the just-loaded but
//!     not-yet-appended entry is `deinit`'d (secure-zeros its keys) before the
//!     error is returned. Entries already appended to `out_loaded` stay retained
//!     — the caller frees them. This mirrors the default cert's fail-fast: the
//!     caller disables TLS wholesale rather than standing up a half-configured
//!     listener.
const std = @import("std");

const tls_certs = @import("tls_certs.zig");
const config_format = @import("config_format.zig");
const tls_server = @import("../crypto/tls_server.zig");

const SniCertDef = config_format.Config.SniCertDef;

comptime {
    if (@bitSizeOf(usize) != 64) @compileError("tls_sni_load requires a 64-bit target");
}

/// Chain-acceptance predicate. Production passes `main.validateTlsChain`.
pub const ValidateFn = *const fn (chain: []const []const u8) anyerror!void;

/// Certificate loader. Production passes `default_loader`, which wraps
/// `tls_certs.loadOrBootstrap`. Injectable so tests can substitute a leak-clean
/// stub and drive OOM at deterministic allocation points.
pub const LoadFn = *const fn (
    allocator: std.mem.Allocator,
    io: std.Io,
    opts: tls_certs.Options,
) anyerror!tls_certs.Loaded;

fn loadViaCerts(allocator: std.mem.Allocator, io: std.Io, opts: tls_certs.Options) anyerror!tls_certs.Loaded {
    return tls_certs.loadOrBootstrap(allocator, io, opts);
}

/// The production loader: the SAME path used for the default TLS cert.
pub const default_loader: LoadFn = &loadViaCerts;

/// Load every `[[tls.sni]]` entry and build the listener's SNI selection list.
///
/// * `entries` — the parsed `[[tls.sni]]` definitions (paths + server names).
/// * `dns_name` — subject fed to the bootstrap minter when an entry omits paths
///   (matches how the default cert bootstraps); on-disk entries ignore it.
/// * `out_loaded` — caller-owned sink that RETAINS each successfully loaded
///   `Loaded` for the server's lifetime. The returned certs borrow from these.
/// * `validateChain` — chain acceptance predicate (`default`: real validator).
/// * `loadFn` — certificate loader (`default_loader` in production).
///
/// Returns a caller-owned `[]tls_server.SniCert`. On error the partial list is
/// freed and the just-loaded entry is `deinit`'d; entries already in `out_loaded`
/// remain (the caller frees them).
pub fn buildSniCerts(
    allocator: std.mem.Allocator,
    io: std.Io,
    entries: []const SniCertDef,
    dns_name: []const u8,
    out_loaded: *std.ArrayList(tls_certs.Loaded),
    validateChain: ValidateFn,
    loadFn: LoadFn,
) ![]tls_server.SniCert {
    const built = try allocator.alloc(tls_server.SniCert, entries.len);
    errdefer allocator.free(built);

    for (entries, 0..) |entry, i| {
        // Load with the SAME loader as the default cert. A bootstrap (paths
        // omitted) mints a self-signed leaf for `dns_name`.
        var sni_material = try loadFn(allocator, io, .{
            .enabled = true,
            .cert_path = entry.cert_path,
            .key_path = entry.key_path,
            .dns_name = dns_name,
        });

        // Reject a malformed/expired entry BEFORE retaining it. The just-loaded
        // material is deinit'd (secure-zeros keys) so it does not leak; `errdefer`
        // frees the partial `built`.
        validateChain(sni_material.cert_chain) catch |err| {
            sni_material.deinit(allocator);
            return err;
        };

        // Retain for the server lifetime. If the append allocation fails, the
        // just-loaded material is deinit'd (it was never handed to the list) and
        // `errdefer` frees `built`.
        out_loaded.append(allocator, sni_material) catch |err| {
            sni_material.deinit(allocator);
            return err;
        };

        // The listener entry BORROWS the chain bytes and ALIASES the keys owned
        // by the copy now living in `out_loaded`.
        built[i] = .{
            .server_names = entry.server_names,
            .cert_chain = sni_material.cert_chain,
            .signing_key = sni_material.signing_key,
            .ecdsa_p256_signing_key = sni_material.ecdsa_p256_signing_key,
            .rsa_signing_key = sni_material.rsa_signing_key,
        };
    }

    return built;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

const pem = @import("../proto/pem.zig");
const ed25519_pkcs8 = @import("../proto/ed25519_pkcs8.zig");
const x509_selfsign = @import("../proto/x509_selfsign.zig");
const Ed25519 = std.crypto.sign.Ed25519;

const cert_pem_label = "CERTIFICATE";
const key_pem_label = "PRIVATE KEY";

/// Accept-any chain predicate (production's `validateTlsChain` stand-in for the
/// happy path).
fn acceptAnyChain(chain: []const []const u8) anyerror!void {
    _ = chain;
}

/// Deterministic, stateless failure predicate: rejects any chain that is not a
/// single leaf. Test fixtures give the "good" entry a 1-cert file and the "bad"
/// entry a 2-cert file, so validation fails on exactly that entry.
fn rejectMultiCertChain(chain: []const []const u8) anyerror!void {
    if (chain.len != 1) return error.SniChainRejected;
}

/// Leak-clean stub loader for the allocation-failure sweep. Allocates a minimal
/// owned `Loaded` (a 4-byte fake DER chain + an Ed25519 key) so the sweep can
/// exercise `buildSniCerts`'s OWN allocation points (the `built` alloc and the
/// `out_loaded` append, including the deinit-on-append-failure branch) at
/// deterministic indices — without descending into the real loader.
fn stubLoader(allocator: std.mem.Allocator, io: std.Io, opts: tls_certs.Options) anyerror!tls_certs.Loaded {
    _ = io;
    _ = opts;
    const der = try allocator.alloc(u8, 4);
    errdefer allocator.free(der);
    @memset(der, 0xAB);
    const chain = try allocator.alloc([]const u8, 1);
    chain[0] = der;
    const key_pair = Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x7A))) catch unreachable;
    return .{ .cert_chain = chain, .key_kind = .ed25519, .signing_key = key_pair };
}

/// Mint a deterministic Ed25519 self-signed leaf DER for `cn`, seeded by `seed`.
fn mintLeafDer(out: *[768]u8, cn: []const u8, seed: u8) ![]const u8 {
    const key_pair = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(seed)));
    return x509_selfsign.buildSelfSigned(out, .{
        .common_name = cn,
        .not_before = 1_704_067_200,
        .not_after = 1_735_689_599,
        .serial = &.{ 0x01, seed },
        .key_pair = key_pair,
    });
}

/// Encode a deterministic Ed25519 PKCS#8 private key PEM into `out`.
fn mintKeyPem(out: *[4096]u8, seed: u8) ![]const u8 {
    var key_der_buf: [ed25519_pkcs8.der_len]u8 = undefined;
    const key_der = try ed25519_pkcs8.encode(&key_der_buf, @as([Ed25519.KeyPair.seed_length]u8, @splat(seed)));
    return pem.encode(out, key_pem_label, key_der);
}

/// Write a single-cert PEM + matching key PEM into `tmp`.
fn writeLeafFixture(tmp: testing.TmpDir, cert_name: []const u8, key_name: []const u8, cn: []const u8, seed: u8) !void {
    var der_buf: [768]u8 = undefined;
    const der = try mintLeafDer(&der_buf, cn, seed);
    var cert_pem_buf: [4096]u8 = undefined;
    const cert_pem = try pem.encode(&cert_pem_buf, cert_pem_label, der);
    var key_pem_buf: [4096]u8 = undefined;
    const key_pem = try mintKeyPem(&key_pem_buf, seed);
    try tmp.dir.writeFile(testing.io, .{ .sub_path = cert_name, .data = cert_pem });
    try tmp.dir.writeFile(testing.io, .{ .sub_path = key_name, .data = key_pem });
}

/// Write a TWO-cert PEM chain file + one key PEM into `tmp`. The loader accepts
/// any well-formed cert(s); it never cross-checks that the key matches, so a
/// standalone key is fine. `rejectMultiCertChain` fails on the resulting 2-elem
/// chain, letting a test drive a validation failure on a specific entry.
fn writeTwoCertFixture(tmp: testing.TmpDir, cert_name: []const u8, key_name: []const u8, seed: u8) !void {
    var der1_buf: [768]u8 = undefined;
    const der1 = try mintLeafDer(&der1_buf, "leaf.sni.test", seed);
    var der2_buf: [768]u8 = undefined;
    const der2 = try mintLeafDer(&der2_buf, "intermediate.sni.test", seed +% 1);
    var pem1_buf: [4096]u8 = undefined;
    const pem1 = try pem.encode(&pem1_buf, cert_pem_label, der1);
    var pem2_buf: [4096]u8 = undefined;
    const pem2 = try pem.encode(&pem2_buf, cert_pem_label, der2);
    var joined: [8192]u8 = undefined;
    @memcpy(joined[0..pem1.len], pem1);
    @memcpy(joined[pem1.len..][0..pem2.len], pem2);
    var key_pem_buf: [4096]u8 = undefined;
    const key_pem = try mintKeyPem(&key_pem_buf, seed);
    try tmp.dir.writeFile(testing.io, .{ .sub_path = cert_name, .data = joined[0 .. pem1.len + pem2.len] });
    try tmp.dir.writeFile(testing.io, .{ .sub_path = key_name, .data = key_pem });
}

/// Build a cwd-relative path into a testing tmp dir, matching `testing.tmpDir`'s
/// `.zig-cache/tmp/<sub_path>` layout so `std.Io.Dir.cwd()` reads resolve.
fn tmpPath(allocator: std.mem.Allocator, tmp: testing.TmpDir, name: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/{s}", .{ tmp.sub_path, name });
}

fn freeLoaded(allocator: std.mem.Allocator, loaded: *std.ArrayList(tls_certs.Loaded)) void {
    for (loaded.items) |*l| l.deinit(allocator);
    loaded.deinit(allocator);
}

test "buildSniCerts: two valid entries build a 2-elem list, no leak" {
    // Arrange: two on-disk leaf+key pairs, loaded through the REAL loader.
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeLeafFixture(tmp, "a.pem", "a.key", "a.sni.test", 0x11);
    try writeLeafFixture(tmp, "b.pem", "b.key", "b.sni.test", 0x22);

    const a_cert = try tmpPath(allocator, tmp, "a.pem");
    defer allocator.free(a_cert);
    const a_key = try tmpPath(allocator, tmp, "a.key");
    defer allocator.free(a_key);
    const b_cert = try tmpPath(allocator, tmp, "b.pem");
    defer allocator.free(b_cert);
    const b_key = try tmpPath(allocator, tmp, "b.key");
    defer allocator.free(b_key);

    const entries = [_]SniCertDef{
        .{ .server_names = &.{"a.sni.test"}, .cert_path = a_cert, .key_path = a_key },
        .{ .server_names = &.{"b.sni.test"}, .cert_path = b_cert, .key_path = b_key },
    };

    var loaded: std.ArrayList(tls_certs.Loaded) = .empty;
    defer freeLoaded(allocator, &loaded);

    // Act
    const built = try buildSniCerts(allocator, testing.io, &entries, "unused.test", &loaded, acceptAnyChain, default_loader);
    defer allocator.free(built);

    // Assert: two entries, both retained, and the listener certs BORROW the
    // retained chain bytes (pointer identity, not a copy).
    try testing.expectEqual(@as(usize, 2), built.len);
    try testing.expectEqual(@as(usize, 2), loaded.items.len);
    try testing.expect(built[0].cert_chain.len >= 1);
    try testing.expect(built[1].cert_chain.len >= 1);
    try testing.expectEqual(loaded.items[0].cert_chain[0].ptr, built[0].cert_chain[0].ptr);
    try testing.expectEqual(loaded.items[1].cert_chain[0].ptr, built[1].cert_chain[0].ptr);
    try testing.expectEqualStrings("a.sni.test", built[0].server_names[0]);
    try testing.expectEqualStrings("b.sni.test", built[1].server_names[0]);
}

test "buildSniCerts: validation failure on entry[1] frees built + entry[1], retains entry[0], no leak" {
    // Arrange: entry[0] is a single leaf (passes rejectMultiCertChain); entry[1]
    // is a 2-cert chain (fails), forcing a validation failure on the 2nd entry
    // AFTER its material has been loaded through the REAL loader.
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeLeafFixture(tmp, "ok.pem", "ok.key", "ok.sni.test", 0x33);
    try writeTwoCertFixture(tmp, "bad.pem", "bad.key", 0x44);

    const ok_cert = try tmpPath(allocator, tmp, "ok.pem");
    defer allocator.free(ok_cert);
    const ok_key = try tmpPath(allocator, tmp, "ok.key");
    defer allocator.free(ok_key);
    const bad_cert = try tmpPath(allocator, tmp, "bad.pem");
    defer allocator.free(bad_cert);
    const bad_key = try tmpPath(allocator, tmp, "bad.key");
    defer allocator.free(bad_key);

    const entries = [_]SniCertDef{
        .{ .server_names = &.{"ok.sni.test"}, .cert_path = ok_cert, .key_path = ok_key },
        .{ .server_names = &.{"bad.sni.test"}, .cert_path = bad_cert, .key_path = bad_key },
    };

    var loaded: std.ArrayList(tls_certs.Loaded) = .empty;
    // The caller owns entry[0]'s retained material even on failure; free it here.
    // A leak of entry[1]'s just-loaded material (not deinit'd on the error path)
    // would trip `testing.allocator`.
    defer freeLoaded(allocator, &loaded);

    // Act / Assert: the validator's error propagates, entry[1]'s material is
    // deinit'd inside buildSniCerts, `built` is freed by its errdefer, and
    // entry[0] stays retained in `loaded`.
    const res = buildSniCerts(allocator, testing.io, &entries, "unused.test", &loaded, rejectMultiCertChain, default_loader);
    try testing.expectError(error.SniChainRejected, res);
    try testing.expectEqual(@as(usize, 1), loaded.items.len);
    try testing.expectEqual(@as(usize, 1), loaded.items[0].cert_chain.len);
}

test "buildSniCerts: allocation failure at any own allocation is leak-clean" {
    // A leak-clean stub loader isolates buildSniCerts's OWN allocation points, so
    // the FailingAllocator sweep exercises the `built` alloc, each stub load, and
    // the `out_loaded` append (incl. the deinit-on-append-failure branch) at
    // deterministic indices. `checkAllAllocationFailures` fails allocation
    // 0, 1, 2, ... in turn and asserts each run either succeeds or returns
    // OutOfMemory with NO leak.
    const entries = [_]SniCertDef{
        .{ .server_names = &.{"c.sni.test"}, .cert_path = "c.pem", .key_path = "c.key" },
        .{ .server_names = &.{"d.sni.test"}, .cert_path = "d.pem", .key_path = "d.key" },
    };

    const Sweep = struct {
        fn run(alloc: std.mem.Allocator, io: std.Io, defs: []const SniCertDef) !void {
            var loaded: std.ArrayList(tls_certs.Loaded) = .empty;
            defer freeLoaded(alloc, &loaded);
            const built = try buildSniCerts(alloc, io, defs, "unused.test", &loaded, acceptAnyChain, stubLoader);
            alloc.free(built);
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Sweep.run, .{ testing.io, @as([]const SniCertDef, &entries) });
}

test {
    testing.refAllDecls(@This());
}

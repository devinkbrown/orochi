//! MLS (RFC 9420) Key Schedule — per-epoch secret derivation.
//!
//! Implements the labeled KDF (`ExpandWithLabel`, `DeriveSecret`) and the full
//! epoch key schedule as specified in RFC 9420 §8.
//!
//! Cipher suite assumed: MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
//!   Hash:   SHA-256  (Nh = 32)
//!   KDF:    HKDF-SHA256
//!
//! Self-contained: std.crypto only, no sibling @import.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;

/// Output length of the hash / PRK for this cipher suite (SHA-256 → 32 bytes).
pub const Nh: usize = HkdfSha256.prk_length; // 32

// ---------------------------------------------------------------------------
// KDFLabel struct encoding (RFC 9420 §5.2)
//
//   struct {
//       uint16 length;
//       opaque label<V>;   // "MLS 1.0 " + label
//       opaque context<V>;
//   } KDFLabel;
//
// All length-prefixed vectors use a 1-byte prefix for the label (max 255)
// and a 4-byte prefix for context (per the RFC's variable-length encoding).
// ---------------------------------------------------------------------------

const MLS_PREFIX = "MLS 1.0 ";

/// Encode a KDFLabel into `buf` and return the number of bytes written.
/// `buf` must be large enough:  2 + 1 + mls_prefix.len + label.len + 4 + context.len
fn encodeKdfLabel(
    buf: []u8,
    length: u16,
    label: []const u8,
    context: []const u8,
) usize {
    var offset: usize = 0;

    // uint16 length (big-endian)
    buf[offset] = @truncate(length >> 8);
    buf[offset + 1] = @truncate(length & 0xFF);
    offset += 2;

    // opaque label<V> — 1-byte length prefix
    const full_label_len: usize = MLS_PREFIX.len + label.len;
    buf[offset] = @intCast(full_label_len);
    offset += 1;
    @memcpy(buf[offset .. offset + MLS_PREFIX.len], MLS_PREFIX);
    offset += MLS_PREFIX.len;
    @memcpy(buf[offset .. offset + label.len], label);
    offset += label.len;

    // opaque context<V> — 4-byte length prefix (big-endian)
    const ctx_len: u32 = @intCast(context.len);
    buf[offset] = @truncate(ctx_len >> 24);
    buf[offset + 1] = @truncate((ctx_len >> 16) & 0xFF);
    buf[offset + 2] = @truncate((ctx_len >> 8) & 0xFF);
    buf[offset + 3] = @truncate(ctx_len & 0xFF);
    offset += 4;
    @memcpy(buf[offset .. offset + context.len], context);
    offset += context.len;

    return offset;
}

/// Compute the maximum buffer size needed for `encodeKdfLabel`.
fn kdfLabelSize(label: []const u8, context: []const u8) usize {
    return 2 + 1 + MLS_PREFIX.len + label.len + 4 + context.len;
}

// ---------------------------------------------------------------------------
// Core labeled KDF primitives
// ---------------------------------------------------------------------------

/// RFC 9420 §5.2  ExpandWithLabel(secret, label, context, length)
///
/// Derives `length` bytes from `secret` using the MLS-labeled KDF.
/// `out` must be exactly `length` bytes (caller-allocated).
pub fn expandWithLabel(
    out: []u8,
    secret: *const [Nh]u8,
    label: []const u8,
    context: []const u8,
) void {
    const buf_size = kdfLabelSize(label, context);
    // Stack-allocate up to 512 bytes; heap fallback not needed for typical MLS
    // labels (<< 255 chars) and typical context sizes (<< 200 bytes).
    var stack_buf: [512]u8 = undefined;
    std.debug.assert(buf_size <= stack_buf.len);
    const n = encodeKdfLabel(&stack_buf, @intCast(out.len), label, context);
    HkdfSha256.expand(out, stack_buf[0..n], secret.*);
}

/// RFC 9420 §5.2  DeriveSecret(secret, label)
///
/// Returns a [Nh]u8 derived with empty context.
pub fn deriveSecret(secret: *const [Nh]u8, label: []const u8) [Nh]u8 {
    var out: [Nh]u8 = undefined;
    expandWithLabel(&out, secret, label, "");
    return out;
}

// ---------------------------------------------------------------------------
// Epoch key schedule
// ---------------------------------------------------------------------------

/// All named secrets derived for a single MLS epoch (RFC 9420 §8.1).
pub const EpochSecrets = struct {
    /// Input to the next epoch's schedule.
    init_secret: [Nh]u8,

    joiner_secret: [Nh]u8,
    epoch_secret: [Nh]u8,

    sender_data_secret: [Nh]u8,
    encryption_secret: [Nh]u8,
    exporter_secret: [Nh]u8,
    external_secret: [Nh]u8,
    confirmation_key: [Nh]u8,
    membership_key: [Nh]u8,
    resumption_psk: [Nh]u8,
    epoch_authenticator: [Nh]u8,
};

/// Derive the MLS PSK secret from a slice of pre-shared keys.
/// For simplicity this implementation uses the all-zeros PSK secret when
/// `psk_secret` is null (the common case with no external PSKs).
/// Callers that handle external/resumption PSKs should compute the
/// PSK secret themselves and pass it here.
fn pskOrZero(psk_secret: ?*const [Nh]u8) [Nh]u8 {
    if (psk_secret) |p| return p.*;
    return [_]u8{0} ** Nh;
}

/// RFC 9420 §8.1 — derive all epoch secrets.
///
/// Parameters
/// ----------
/// `prev_init_secret`  — `init_secret` from the previous epoch (or all-zeros
///                        for the first epoch / welcome).
/// `commit_secret`     — the path secret from the ratchet tree commit.
/// `group_context`     — the serialised GroupContext for this epoch (used as
///                        the HKDF extraction salt input context).
/// `psk_secret`        — optional pre-shared key secret; pass null for none.
pub fn deriveEpochSecrets(
    prev_init_secret: *const [Nh]u8,
    commit_secret: *const [Nh]u8,
    group_context: []const u8,
    psk_secret: ?*const [Nh]u8,
) EpochSecrets {
    // Step 1: joiner_secret = HKDF-Extract(init_secret_[n-1], commit_secret)
    //         RFC 9420 uses DeriveSecret + Extract here; the salt is the
    //         ExpandWithLabel of init_secret with "joiner".
    //
    //   joiner_secret = HKDF-Extract(
    //       ExpandWithLabel(init_secret, "joiner", GroupContext, Nh),
    //       commit_secret)
    var joiner_salt: [Nh]u8 = undefined;
    expandWithLabel(&joiner_salt, prev_init_secret, "joiner", group_context);

    const joiner_secret = HkdfSha256.extract(&joiner_salt, commit_secret);

    // Step 2: epoch_secret = HKDF-Extract(
    //             ExpandWithLabel(joiner_secret, "member", psk_secret, Nh),
    //             "")
    //   where psk_secret is the PSK input.
    const psk = pskOrZero(psk_secret);
    var member_salt: [Nh]u8 = undefined;
    expandWithLabel(&member_salt, &joiner_secret, "member", &psk);

    const epoch_secret = HkdfSha256.extract(&member_salt, "");

    // Step 3: derive all named secrets from epoch_secret.
    const sender_data_secret = deriveSecret(&epoch_secret, "sender data");
    const encryption_secret = deriveSecret(&epoch_secret, "encryption");
    const exporter_secret = deriveSecret(&epoch_secret, "exporter");
    const external_secret = deriveSecret(&epoch_secret, "external");
    const confirmation_key = deriveSecret(&epoch_secret, "confirm");
    const membership_key = deriveSecret(&epoch_secret, "membership");
    const resumption_psk = deriveSecret(&epoch_secret, "resumption");
    const epoch_authenticator = deriveSecret(&epoch_secret, "authentication");

    // Step 4: init_secret for next epoch.
    const init_secret = deriveSecret(&epoch_secret, "init");

    return .{
        .init_secret = init_secret,
        .joiner_secret = joiner_secret,
        .epoch_secret = epoch_secret,
        .sender_data_secret = sender_data_secret,
        .encryption_secret = encryption_secret,
        .exporter_secret = exporter_secret,
        .external_secret = external_secret,
        .confirmation_key = confirmation_key,
        .membership_key = membership_key,
        .resumption_psk = resumption_psk,
        .epoch_authenticator = epoch_authenticator,
    };
}

// ---------------------------------------------------------------------------
// Exporter (RFC 9420 §8.5)
//
//   MLS-Exporter(label, context, length) =
//       ExpandWithLabel(
//           DeriveSecret(exporter_secret, label),
//           "exporter",
//           Hash(context),
//           length)
// ---------------------------------------------------------------------------

/// Export a secret from an epoch's `exporter_secret`.
///
/// `out` must be pre-allocated by the caller to the desired length.
pub fn exporter(
    out: []u8,
    exporter_secret: *const [Nh]u8,
    label: []const u8,
    context: []const u8,
) void {
    const Sha256 = std.crypto.hash.sha2.Sha256;

    // DeriveSecret(exporter_secret, label)
    const derived = deriveSecret(exporter_secret, label);

    // Hash(context)
    var ctx_hash: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(context, &ctx_hash, .{});

    // ExpandWithLabel(derived, "exporter", Hash(context), len(out))
    expandWithLabel(out, &derived, "exporter", &ctx_hash);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "encodeKdfLabel basic structure" {
    const label = "test";
    const context = "ctx";
    var buf: [64]u8 = undefined;
    const n = encodeKdfLabel(&buf, 32, label, context);

    // 2 (length) + 1 (label len prefix) + 8 (MLS_PREFIX) + 4 (label) + 4 (ctx len prefix) + 3 (ctx)
    const expected_n: usize = 2 + 1 + MLS_PREFIX.len + label.len + 4 + context.len;
    try std.testing.expectEqual(expected_n, n);

    // uint16 length = 32
    try std.testing.expectEqual(@as(u8, 0), buf[0]);
    try std.testing.expectEqual(@as(u8, 32), buf[1]);

    // label length byte
    try std.testing.expectEqual(@as(u8, MLS_PREFIX.len + label.len), buf[2]);
}

test "expandWithLabel output length correctness" {
    const secret = [_]u8{0xAB} ** Nh;
    var out16: [16]u8 = undefined;
    var out32: [32]u8 = undefined;
    var out64: [64]u8 = undefined;

    expandWithLabel(&out16, &secret, "test", "");
    expandWithLabel(&out32, &secret, "test", "");
    expandWithLabel(&out64, &secret, "test", "");

    // Each call produces the correct number of bytes.
    try std.testing.expectEqual(@as(usize, 16), out16.len);
    try std.testing.expectEqual(@as(usize, 32), out32.len);
    try std.testing.expectEqual(@as(usize, 64), out64.len);

    // Outputs for different requested lengths must all be non-zero (not degenerate).
    const zero16 = [_]u8{0} ** 16;
    const zero32 = [_]u8{0} ** 32;
    try std.testing.expect(!mem.eql(u8, &out16, &zero16));
    try std.testing.expect(!mem.eql(u8, &out32, &zero32));

    // Requesting the same label/context/length again must be identical (determinism).
    var out32b: [32]u8 = undefined;
    expandWithLabel(&out32b, &secret, "test", "");
    try std.testing.expectEqualSlices(u8, &out32, &out32b);
}

test "expandWithLabel determinism" {
    const secret = [_]u8{0x42} ** Nh;
    var a: [Nh]u8 = undefined;
    var b: [Nh]u8 = undefined;

    expandWithLabel(&a, &secret, "sender data", "group-ctx");
    expandWithLabel(&b, &secret, "sender data", "group-ctx");

    try std.testing.expectEqualSlices(u8, &a, &b);
}

test "expandWithLabel label separation" {
    const secret = [_]u8{0x01} ** Nh;
    var a: [Nh]u8 = undefined;
    var b: [Nh]u8 = undefined;

    expandWithLabel(&a, &secret, "label-one", "ctx");
    expandWithLabel(&b, &secret, "label-two", "ctx");

    try std.testing.expect(!mem.eql(u8, &a, &b));
}

test "expandWithLabel context separation" {
    const secret = [_]u8{0x02} ** Nh;
    var a: [Nh]u8 = undefined;
    var b: [Nh]u8 = undefined;

    expandWithLabel(&a, &secret, "key", "context-A");
    expandWithLabel(&b, &secret, "key", "context-B");

    try std.testing.expect(!mem.eql(u8, &a, &b));
}

test "deriveSecret determinism and Nh-length output" {
    const secret = [_]u8{0xFF} ** Nh;
    const a = deriveSecret(&secret, "encryption");
    const b = deriveSecret(&secret, "encryption");
    try std.testing.expectEqualSlices(u8, &a, &b);
    try std.testing.expectEqual(Nh, a.len);
}

test "deriveSecret label separation" {
    const secret = [_]u8{0x10} ** Nh;
    const a = deriveSecret(&secret, "init");
    const b = deriveSecret(&secret, "member");
    try std.testing.expect(!mem.eql(u8, &a, &b));
}

test "epoch derivation is deterministic" {
    const init = [_]u8{0x00} ** Nh;
    const commit = [_]u8{0x11} ** Nh;
    const gc = "group-context-v1";

    const e1 = deriveEpochSecrets(&init, &commit, gc, null);
    const e2 = deriveEpochSecrets(&init, &commit, gc, null);

    try std.testing.expectEqualSlices(u8, &e1.epoch_secret, &e2.epoch_secret);
    try std.testing.expectEqualSlices(u8, &e1.sender_data_secret, &e2.sender_data_secret);
    try std.testing.expectEqualSlices(u8, &e1.encryption_secret, &e2.encryption_secret);
    try std.testing.expectEqualSlices(u8, &e1.exporter_secret, &e2.exporter_secret);
    try std.testing.expectEqualSlices(u8, &e1.external_secret, &e2.external_secret);
    try std.testing.expectEqualSlices(u8, &e1.confirmation_key, &e2.confirmation_key);
    try std.testing.expectEqualSlices(u8, &e1.membership_key, &e2.membership_key);
    try std.testing.expectEqualSlices(u8, &e1.resumption_psk, &e2.resumption_psk);
    try std.testing.expectEqualSlices(u8, &e1.epoch_authenticator, &e2.epoch_authenticator);
    try std.testing.expectEqualSlices(u8, &e1.init_secret, &e2.init_secret);
}

test "all named epoch secrets are distinct" {
    const init = [_]u8{0x00} ** Nh;
    const commit = [_]u8{0x22} ** Nh;
    const gc = "group-context-separation";

    const e = deriveEpochSecrets(&init, &commit, gc, null);

    const secrets = [_]*const [Nh]u8{
        &e.sender_data_secret,
        &e.encryption_secret,
        &e.exporter_secret,
        &e.external_secret,
        &e.confirmation_key,
        &e.membership_key,
        &e.resumption_psk,
        &e.epoch_authenticator,
        &e.init_secret,
    };

    for (secrets, 0..) |a, i| {
        for (secrets[i + 1 ..]) |b| {
            try std.testing.expect(!mem.eql(u8, a, b));
        }
    }
}

test "different commit_secret produces different epoch_secret" {
    const init = [_]u8{0x00} ** Nh;
    const commit_a = [_]u8{0x33} ** Nh;
    const commit_b = [_]u8{0x44} ** Nh;
    const gc = "group-context";

    const ea = deriveEpochSecrets(&init, &commit_a, gc, null);
    const eb = deriveEpochSecrets(&init, &commit_b, gc, null);

    try std.testing.expect(!mem.eql(u8, &ea.epoch_secret, &eb.epoch_secret));
}

test "different init_secret produces different epoch_secret" {
    const init_a = [_]u8{0xAA} ** Nh;
    const init_b = [_]u8{0xBB} ** Nh;
    const commit = [_]u8{0x55} ** Nh;
    const gc = "group-context";

    const ea = deriveEpochSecrets(&init_a, &commit, gc, null);
    const eb = deriveEpochSecrets(&init_b, &commit, gc, null);

    try std.testing.expect(!mem.eql(u8, &ea.epoch_secret, &eb.epoch_secret));
}

test "PSK changes epoch_secret" {
    const init = [_]u8{0x00} ** Nh;
    const commit = [_]u8{0x66} ** Nh;
    const gc = "psk-test";

    const psk = [_]u8{0x77} ** Nh;

    const e_no_psk = deriveEpochSecrets(&init, &commit, gc, null);
    const e_psk = deriveEpochSecrets(&init, &commit, gc, &psk);

    try std.testing.expect(!mem.eql(u8, &e_no_psk.epoch_secret, &e_psk.epoch_secret));
}

test "epoch chaining: init_secret of epoch N feeds epoch N+1" {
    const init0 = [_]u8{0x00} ** Nh;
    const commit0 = [_]u8{0xC0} ** Nh;
    const commit1 = [_]u8{0xC1} ** Nh;
    const gc = "chain-test";

    const e0 = deriveEpochSecrets(&init0, &commit0, gc, null);
    const e1_from_chain = deriveEpochSecrets(&e0.init_secret, &commit1, gc, null);

    // Recompute e1 from the same inputs — must be identical
    const e1_repeat = deriveEpochSecrets(&e0.init_secret, &commit1, gc, null);

    try std.testing.expectEqualSlices(u8, &e1_from_chain.epoch_secret, &e1_repeat.epoch_secret);
    try std.testing.expectEqualSlices(u8, &e1_from_chain.init_secret, &e1_repeat.init_secret);

    // epoch 0 and epoch 1 must differ despite same group_context
    try std.testing.expect(!mem.eql(u8, &e0.epoch_secret, &e1_from_chain.epoch_secret));
}

test "epoch chaining is sensitive to commit_secret at each epoch" {
    const init0 = [_]u8{0x00} ** Nh;
    const commit0 = [_]u8{0xD0} ** Nh;
    const commit1_a = [_]u8{0xD1} ** Nh;
    const commit1_b = [_]u8{0xD2} ** Nh;
    const gc = "chain-sensitivity";

    const e0 = deriveEpochSecrets(&init0, &commit0, gc, null);
    const e1_a = deriveEpochSecrets(&e0.init_secret, &commit1_a, gc, null);
    const e1_b = deriveEpochSecrets(&e0.init_secret, &commit1_b, gc, null);

    try std.testing.expect(!mem.eql(u8, &e1_a.epoch_secret, &e1_b.epoch_secret));
}

test "exporter is deterministic" {
    const es = [_]u8{0x88} ** Nh;
    var out_a: [32]u8 = undefined;
    var out_b: [32]u8 = undefined;

    exporter(&out_a, &es, "test-label", "app-context");
    exporter(&out_b, &es, "test-label", "app-context");

    try std.testing.expectEqualSlices(u8, &out_a, &out_b);
}

test "exporter label separation" {
    const es = [_]u8{0x99} ** Nh;
    var out_a: [32]u8 = undefined;
    var out_b: [32]u8 = undefined;

    exporter(&out_a, &es, "label-alpha", "ctx");
    exporter(&out_b, &es, "label-beta", "ctx");

    try std.testing.expect(!mem.eql(u8, &out_a, &out_b));
}

test "exporter context separation" {
    const es = [_]u8{0xAA} ** Nh;
    var out_a: [32]u8 = undefined;
    var out_b: [32]u8 = undefined;

    exporter(&out_a, &es, "shared-label", "ctx-1");
    exporter(&out_b, &es, "shared-label", "ctx-2");

    try std.testing.expect(!mem.eql(u8, &out_a, &out_b));
}

test "exporter variable output lengths" {
    const es = [_]u8{0xBB} ** Nh;
    var out16: [16]u8 = undefined;
    var out48: [48]u8 = undefined;

    exporter(&out16, &es, "var-len", "ctx");
    exporter(&out48, &es, "var-len", "ctx");

    // Both outputs have the requested length (compile-time guarantee, but sanity-check).
    try std.testing.expectEqual(@as(usize, 16), out16.len);
    try std.testing.expectEqual(@as(usize, 48), out48.len);

    // Outputs must be non-degenerate.
    const zero16 = [_]u8{0} ** 16;
    const zero48 = [_]u8{0} ** 48;
    try std.testing.expect(!mem.eql(u8, &out16, &zero16));
    try std.testing.expect(!mem.eql(u8, &out48, &zero48));

    // Repeating same call produces same result.
    var out16b: [16]u8 = undefined;
    exporter(&out16b, &es, "var-len", "ctx");
    try std.testing.expectEqualSlices(u8, &out16, &out16b);
}

test "exporter uses epoch exporter_secret correctly" {
    const init = [_]u8{0x00} ** Nh;
    const commit = [_]u8{0xEE} ** Nh;
    const gc = "exporter-epoch-test";

    const epoch = deriveEpochSecrets(&init, &commit, gc, null);

    var out: [Nh]u8 = undefined;
    exporter(&out, &epoch.exporter_secret, "app", "data");

    // Re-derive and compare
    var out2: [Nh]u8 = undefined;
    exporter(&out2, &epoch.exporter_secret, "app", "data");

    try std.testing.expectEqualSlices(u8, &out, &out2);

    // Using a different epoch's exporter_secret must produce a different value
    const init2 = [_]u8{0x01} ** Nh;
    const epoch2 = deriveEpochSecrets(&init2, &commit, gc, null);

    var out3: [Nh]u8 = undefined;
    exporter(&out3, &epoch2.exporter_secret, "app", "data");

    try std.testing.expect(!mem.eql(u8, &out, &out3));
}

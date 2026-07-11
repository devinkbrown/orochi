// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! WebAuthn (passkey) credential storage codec + ceremony helpers.
//!
//! Pure, allocation-light glue for the `WEBAUTHN` command (see
//! `modules/accounts.zig` + `server.zig`). This module owns:
//!   - the durable-record encode/decode for a passkey credential bound to an
//!     account (mirrors the certfp storage record shape in `services.zig`),
//!   - the props-family key builders (keyed by credential id + per-account list),
//!   - fail-closed `clientDataJSON` parsing (type / challenge / origin) via the
//!     standard-library JSON parser over a caller-provided fixed buffer (no heap),
//!   - constant-time challenge matching + origin allow-list checks.
//!
//! Signature verification, COSE-key parse, and attested-credential-data parse
//! live in `crypto/webauthn.zig`; this module never touches private keys and
//! performs no I/O — every buffer is caller-owned.

const std = @import("std");
const base64url = @import("../proto/base64url.zig");

// -- Sizing bounds -----------------------------------------------------------

/// Raw challenge length (bytes). A 32-byte CSPRNG challenge per WebAuthn's
/// recommendation (≥ 16 bytes); single-use and time-bounded by the caller.
pub const challenge_len: usize = 32;

/// Max raw credential-id length accepted (bytes). WebAuthn caps credentialId at
/// 1023 bytes; passkeys are far smaller. 256 keeps keys bounded while covering
/// every real authenticator.
pub const max_cred_id_bytes: usize = 256;
/// Max base64url length of an accepted credential id.
pub const max_cred_id_b64: usize = base64url.encodedLen(max_cred_id_bytes);

/// Max user-supplied label length (bytes, pre-encoding).
pub const max_label_bytes: usize = 64;
pub const max_label_b64: usize = base64url.encodedLen(max_label_bytes);

/// Max COSE public-key length (bytes). ES256 ≈ 77, EdDSA ≈ 42; 512 is generous.
pub const max_cose_key_bytes: usize = 512;
const max_cose_key_b64: usize = base64url.encodedLen(max_cose_key_bytes);

/// Max accepted clientDataJSON length (bytes). Real values are a few hundred
/// bytes; the cap bounds the JSON parse arena and rejects hostile bloat.
pub const max_client_data_bytes: usize = 4096;

/// Max passkeys bound to one account (LIST/allow-list bound).
pub const max_creds_per_account: usize = 16;

/// Account-name cap for key sizing (matches the session `AccountName` cap).
const account_max: usize = 64;

const record_version = "W1";
const cred_key_prefix = "webauthn:";
const account_list_key_prefix = "webauthns:";

/// Buffer sizes for the props-family keys.
pub const cred_key_max: usize = cred_key_prefix.len + max_cred_id_b64;
pub const account_list_key_max: usize = account_list_key_prefix.len + account_max;

/// Buffer size for one encoded credential record value.
pub const record_value_max: usize = record_version.len + 1 + account_max + 1 +
    10 + 1 + // sign_count (u32, ≤ 10 digits)
    20 + 1 + // created_unix (i64, ≤ 20 chars)
    max_label_b64 + 1 +
    max_cose_key_b64;

/// Buffer size for the per-account credential-id list value.
pub const account_list_value_max: usize = max_creds_per_account * (max_cred_id_b64 + 1);

// -- Errors ------------------------------------------------------------------

pub const Error = error{
    Malformed,
    TooLong,
    InvalidJson,
    MissingField,
    WrongType,
    ListFull,
    BufferTooSmall,
    InvalidBase64,
};

// -- Credential-id validation + keys ----------------------------------------

/// Whether a credential-id string is a well-formed, in-bounds unpadded
/// url-safe base64 token (the on-wire + key form). Rejects empty, over-long,
/// padded, and out-of-alphabet input so it is safe to use directly as a store
/// key without escaping.
pub fn validCredIdB64(s: []const u8) bool {
    if (s.len == 0 or s.len > max_cred_id_b64) return false;
    for (s) |c| {
        const ok = (c >= 'A' and c <= 'Z') or (c >= 'a' and c <= 'z') or
            (c >= '0' and c <= '9') or c == '-' or c == '_';
        if (!ok) return false;
    }
    return true;
}

/// Whether a user-supplied passkey label is safe to store durably and to
/// reflect back onto the wire: in-bounds and free of control bytes (< 0x20,
/// which covers CR/LF/NUL) and DEL (0x7f). High-bit bytes (UTF-8 continuation /
/// multibyte) are allowed — labels are human-readable names. Empty is allowed
/// (the label is optional).
///
/// This is the input-boundary guard: rejecting a control-laden label here keeps
/// the durable store poison-free and means the `WEBAUTHN` LIST/RENAME EVENT
/// reply never has to be silently dropped by the downstream Event-Spine render
/// firewall. That firewall (`event_spine.unsafeTextByte`) remains the last line
/// of defence against injection; this validator ensures nothing reaches it.
pub fn validLabel(label: []const u8) bool {
    if (label.len > max_label_bytes) return false;
    for (label) |c| {
        if (c < 0x20 or c == 0x7f) return false;
    }
    return true;
}

/// Build the props-family key for a credential record, or null if it will not
/// fit. Caller must have validated `cred_id_b64` with `validCredIdB64`.
pub fn credKey(buf: []u8, cred_id_b64: []const u8) ?[]const u8 {
    return std.fmt.bufPrint(buf, cred_key_prefix ++ "{s}", .{cred_id_b64}) catch null;
}

/// Build the props-family key for an account's credential-id list.
pub fn accountListKey(buf: []u8, account: []const u8) ?[]const u8 {
    if (account.len > account_max) return null;
    return std.fmt.bufPrint(buf, account_list_key_prefix ++ "{s}", .{account}) catch null;
}

// -- Record codec ------------------------------------------------------------

/// A decoded credential record. All slices borrow the decoded `value` buffer
/// (or, for `cose_key`/`label`, a caller buffer via `decodeCoseKey`/`decodeLabel`).
pub const Record = struct {
    account: []const u8,
    sign_count: u32,
    created_unix: i64,
    /// base64url of the user label (may be empty).
    label_b64: []const u8,
    /// base64url of the COSE public key (CBOR).
    cose_key_b64: []const u8,

    /// Decode the COSE public key bytes into `out`. Returns the populated slice.
    pub fn decodeCoseKey(self: Record, out: []u8) Error![]const u8 {
        return base64url.decode(out, self.cose_key_b64) catch return error.InvalidBase64;
    }

    /// Decode the label bytes into `out`. Returns the populated slice (possibly
    /// empty).
    pub fn decodeLabel(self: Record, out: []u8) Error![]const u8 {
        if (self.label_b64.len == 0) return out[0..0];
        return base64url.decode(out, self.label_b64) catch return error.InvalidBase64;
    }
};

/// Encode a credential record value. `label_b64` / `cose_key_b64` must already
/// be url-safe base64 (no delimiter bytes). Returns the populated slice of `out`.
pub fn encodeRecord(
    account: []const u8,
    sign_count: u32,
    created_unix: i64,
    label_b64: []const u8,
    cose_key_b64: []const u8,
    out: []u8,
) Error![]const u8 {
    if (account.len > account_max or label_b64.len > max_label_b64 or
        cose_key_b64.len > max_cose_key_b64) return error.TooLong;
    return std.fmt.bufPrint(out, "{s}|{s}|{d}|{d}|{s}|{s}", .{
        record_version,
        account,
        sign_count,
        created_unix,
        label_b64,
        cose_key_b64,
    }) catch return error.BufferTooSmall;
}

/// Decode a credential record value. Fail-closed: a bad version, wrong field
/// count, or non-numeric counter/timestamp is `Malformed`.
pub fn decodeRecord(value: []const u8) Error!Record {
    var it = std.mem.splitScalar(u8, value, '|');
    const version = it.next() orelse return error.Malformed;
    if (!std.mem.eql(u8, version, record_version)) return error.Malformed;
    const account = it.next() orelse return error.Malformed;
    if (account.len == 0 or account.len > account_max) return error.Malformed;
    const count_s = it.next() orelse return error.Malformed;
    const created_s = it.next() orelse return error.Malformed;
    const label_b64 = it.next() orelse return error.Malformed;
    const cose_key_b64 = it.next() orelse return error.Malformed;
    if (it.next() != null) return error.Malformed; // no trailing fields
    const sign_count = std.fmt.parseInt(u32, count_s, 10) catch return error.Malformed;
    const created_unix = std.fmt.parseInt(i64, created_s, 10) catch return error.Malformed;
    if (cose_key_b64.len == 0 or cose_key_b64.len > max_cose_key_b64) return error.Malformed;
    if (label_b64.len > max_label_b64) return error.Malformed;
    return .{
        .account = account,
        .sign_count = sign_count,
        .created_unix = created_unix,
        .label_b64 = label_b64,
        .cose_key_b64 = cose_key_b64,
    };
}

// -- Per-account credential-id list (newline-separated) ----------------------

/// Append `cred_id_b64` to the newline-separated list `existing`, writing the
/// new list into `out`. Returns the populated slice, or null when the id is
/// already present (idempotent). `ListFull` when the per-account cap is hit.
pub fn listAppend(existing: []const u8, cred_id_b64: []const u8, out: []u8) Error!?[]const u8 {
    var count: usize = 0;
    var it = std.mem.splitScalar(u8, existing, '\n');
    while (it.next()) |entry| {
        if (entry.len == 0) continue;
        if (std.mem.eql(u8, entry, cred_id_b64)) return null; // already present
        count += 1;
    }
    if (count >= max_creds_per_account) return error.ListFull;
    if (existing.len == 0) {
        const v = std.fmt.bufPrint(out, "{s}", .{cred_id_b64}) catch return error.BufferTooSmall;
        return v;
    }
    const v = std.fmt.bufPrint(out, "{s}\n{s}", .{ existing, cred_id_b64 }) catch return error.BufferTooSmall;
    return v;
}

/// Remove `cred_id_b64` from `existing`, writing the result into `out`. Returns
/// the populated slice (empty when the last entry is removed), or null when the
/// id was not present.
pub fn listRemove(existing: []const u8, cred_id_b64: []const u8, out: []u8) Error!?[]const u8 {
    var len: usize = 0;
    var removed = false;
    var it = std.mem.splitScalar(u8, existing, '\n');
    while (it.next()) |entry| {
        if (entry.len == 0) continue;
        if (std.mem.eql(u8, entry, cred_id_b64)) {
            removed = true;
            continue;
        }
        if (len != 0) {
            if (len >= out.len) return error.BufferTooSmall;
            out[len] = '\n';
            len += 1;
        }
        if (len + entry.len > out.len) return error.BufferTooSmall;
        @memcpy(out[len..][0..entry.len], entry);
        len += entry.len;
    }
    if (!removed) return null;
    return out[0..len];
}

/// Iterate the credential ids in a per-account list into `out`, returning the
/// populated prefix. Entries borrow `list`.
pub fn listIds(list: []const u8, out: [][]const u8) []const []const u8 {
    var n: usize = 0;
    var it = std.mem.splitScalar(u8, list, '\n');
    while (it.next()) |entry| {
        if (entry.len == 0) continue;
        if (n >= out.len) break;
        out[n] = entry;
        n += 1;
    }
    return out[0..n];
}

// -- clientDataJSON ----------------------------------------------------------

/// The three collected-client-data fields the ceremony binds against. Slices
/// borrow either the source `json` or the `scratch` arena passed to
/// `parseClientData`; both must outlive use.
pub const ClientData = struct {
    /// Ceremony type: "webauthn.create" (register) or "webauthn.get" (auth).
    type_str: []const u8,
    /// base64url(rawChallenge), per WebAuthn §5.8.1 (always url-safe, no pad).
    challenge_b64: []const u8,
    /// The caller's top-level browsing-context origin.
    origin: []const u8,
};

/// Parse a clientDataJSON object, extracting `type`, `challenge`, and `origin`.
///
/// The WebAuthn spec forbids exact byte-matching of clientDataJSON, so this
/// parses it as JSON (via the standard library) over a caller-provided fixed
/// buffer — no heap. Fail-closed: over-long input, non-object roots, missing
/// keys, and non-string values all return an error.
pub fn parseClientData(json: []const u8, scratch: []u8) Error!ClientData {
    if (json.len > max_client_data_bytes) return error.TooLong;
    var fba = std.heap.FixedBufferAllocator.init(scratch);
    const parsed = std.json.parseFromSliceLeaky(std.json.Value, fba.allocator(), json, .{}) catch
        return error.InvalidJson;
    if (parsed != .object) return error.InvalidJson;
    const obj = parsed.object;
    const t = obj.get("type") orelse return error.MissingField;
    const c = obj.get("challenge") orelse return error.MissingField;
    const o = obj.get("origin") orelse return error.MissingField;
    if (t != .string or c != .string or o != .string) return error.WrongType;
    return .{ .type_str = t.string, .challenge_b64 = c.string, .origin = o.string };
}

/// Constant-time check that a clientDataJSON `challenge` (base64url) decodes to
/// exactly the `expected` raw challenge bytes. Any decode failure or length
/// mismatch is a (non-secret) `false`; the byte compare itself is constant-time.
pub fn challengeMatchesB64(expected: []const u8, challenge_b64: []const u8) bool {
    if (expected.len != challenge_len) return false;
    var buf: [challenge_len]u8 = undefined;
    const decoded = base64url.decode(&buf, challenge_b64) catch return false;
    if (decoded.len != challenge_len) return false;
    return std.crypto.timing_safe.eql([challenge_len]u8, buf, expected[0..challenge_len].*);
}

/// Whether `origin` exactly matches one of the configured allowed origins
/// (case-insensitive, per URL host rules). An empty allow-list denies all.
pub fn originAllowed(origin: []const u8, allowed: []const []const u8) bool {
    for (allowed) |a| {
        if (std.ascii.eqlIgnoreCase(origin, a)) return true;
    }
    return false;
}

// -- Ceremony-type constants -------------------------------------------------

pub const type_create = "webauthn.create";
pub const type_get = "webauthn.get";

// ===========================================================================
// Tests
// ===========================================================================

const testing = std.testing;

test "validCredIdB64: accepts url-safe tokens, rejects padding/empty/alphabet" {
    try testing.expect(validCredIdB64("abcDEF-_123"));
    try testing.expect(!validCredIdB64("")); // empty
    try testing.expect(!validCredIdB64("abc=")); // padding not allowed as a key
    try testing.expect(!validCredIdB64("abc/def")); // standard-alphabet '/'
    try testing.expect(!validCredIdB64("abc+def")); // standard-alphabet '+'
    try testing.expect(!validCredIdB64("abc\ndef")); // newline (list separator)
    var too_long: [max_cred_id_b64 + 1]u8 = @splat('A');
    try testing.expect(!validCredIdB64(&too_long));
}

test "validLabel: accepts printable/UTF-8, rejects control bytes + over-long" {
    try testing.expect(validLabel("")); // optional
    try testing.expect(validLabel("phone"));
    try testing.expect(validLabel("Alice's YubiKey 5C")); // punctuation ok
    try testing.expect(validLabel("passkey \xc3\xa9\xf0\x9f\x94\x91")); // UTF-8 (é + emoji)
    try testing.expect(!validLabel("bad\r\nPRIVMSG")); // CR/LF smuggle
    try testing.expect(!validLabel("nul\x00here")); // NUL
    try testing.expect(!validLabel("tab\there")); // TAB (< 0x20)
    try testing.expect(!validLabel("del\x7fhere")); // DEL
    var too_long: [max_label_bytes + 1]u8 = @splat('a');
    try testing.expect(!validLabel(&too_long));
}

test "record codec: round-trip" {
    var out: [record_value_max]u8 = undefined;
    const label = "phone";
    var label_b64_buf: [max_label_b64]u8 = undefined;
    const label_b64 = try base64url.encode(&label_b64_buf, label);
    const cose_b64 = "AQIDBA"; // arbitrary
    const value = try encodeRecord("alice", 42, 1_700_000_000, label_b64, cose_b64, &out);

    const rec = try decodeRecord(value);
    try testing.expectEqualStrings("alice", rec.account);
    try testing.expectEqual(@as(u32, 42), rec.sign_count);
    try testing.expectEqual(@as(i64, 1_700_000_000), rec.created_unix);
    try testing.expectEqualStrings(cose_b64, rec.cose_key_b64);

    var label_out: [max_label_bytes]u8 = undefined;
    const got_label = try rec.decodeLabel(label_out[0..]);
    try testing.expectEqualStrings(label, got_label);
}

test "record codec: empty label round-trips" {
    var out: [record_value_max]u8 = undefined;
    const value = try encodeRecord("bob", 0, 1, "", "AQID", &out);
    const rec = try decodeRecord(value);
    try testing.expectEqual(@as(usize, 0), rec.label_b64.len);
    var lbuf: [max_label_bytes]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), (try rec.decodeLabel(lbuf[0..])).len);
}

test "decodeRecord: fail-closed on malformed values" {
    try testing.expectError(error.Malformed, decodeRecord(""));
    try testing.expectError(error.Malformed, decodeRecord("W2|alice|1|1|x|y")); // bad version
    try testing.expectError(error.Malformed, decodeRecord("W1|alice|notanum|1|x|y"));
    try testing.expectError(error.Malformed, decodeRecord("W1|alice|1|notanum|x|y"));
    try testing.expectError(error.Malformed, decodeRecord("W1|alice|1|1|x")); // too few fields
    try testing.expectError(error.Malformed, decodeRecord("W1|alice|1|1|x|y|extra")); // too many
    try testing.expectError(error.Malformed, decodeRecord("W1|alice|1|1|x|")); // empty cose
}

test "list append/remove: idempotent + full-cap + missing" {
    var out: [account_list_value_max]u8 = undefined;

    const a = (try listAppend("", "id1", &out)).?;
    try testing.expectEqualStrings("id1", a);

    var out2: [account_list_value_max]u8 = undefined;
    const b = (try listAppend("id1", "id2", &out2)).?;
    try testing.expectEqualStrings("id1\nid2", b);

    // Idempotent: appending an existing id returns null.
    try testing.expect((try listAppend("id1\nid2", "id1", &out)) == null);

    // Remove middle-or-only.
    var out3: [account_list_value_max]u8 = undefined;
    const r = (try listRemove("id1\nid2", "id1", &out3)).?;
    try testing.expectEqualStrings("id2", r);

    // Remove last leaves empty.
    const r2 = (try listRemove("id2", "id2", &out3)).?;
    try testing.expectEqual(@as(usize, 0), r2.len);

    // Remove missing → null.
    try testing.expect((try listRemove("id1\nid2", "nope", &out3)) == null);

    // Cap enforcement.
    var full: std.ArrayListUnmanaged(u8) = .empty;
    defer full.deinit(testing.allocator);
    var i: usize = 0;
    while (i < max_creds_per_account) : (i += 1) {
        if (i != 0) try full.append(testing.allocator, '\n');
        var nb: [8]u8 = undefined;
        try full.appendSlice(testing.allocator, std.fmt.bufPrint(&nb, "c{d}", .{i}) catch unreachable);
    }
    var big: [account_list_value_max]u8 = undefined;
    try testing.expectError(error.ListFull, listAppend(full.items, "overflow", &big));
}

test "parseClientData: extracts fields, tolerates member order + extras" {
    var scratch: [8192]u8 = undefined;
    const json =
        \\{"crossOrigin":false,"origin":"https://chat.example","type":"webauthn.get","challenge":"aGVsbG8"}
    ;
    const cd = try parseClientData(json, &scratch);
    try testing.expectEqualStrings("webauthn.get", cd.type_str);
    try testing.expectEqualStrings("aGVsbG8", cd.challenge_b64);
    try testing.expectEqualStrings("https://chat.example", cd.origin);
}

test "parseClientData: fail-closed on malformed / missing / wrong-type / oversized" {
    var scratch: [8192]u8 = undefined;
    try testing.expectError(error.InvalidJson, parseClientData("not json", &scratch));
    try testing.expectError(error.InvalidJson, parseClientData("[1,2,3]", &scratch)); // array root
    try testing.expectError(error.MissingField, parseClientData("{\"type\":\"webauthn.get\"}", &scratch));
    try testing.expectError(error.WrongType, parseClientData(
        "{\"type\":1,\"challenge\":\"a\",\"origin\":\"b\"}",
        &scratch,
    ));
    var big: [max_client_data_bytes + 1]u8 = @splat('a');
    try testing.expectError(error.TooLong, parseClientData(&big, &scratch));
}

test "challengeMatchesB64: matches exact, rejects tamper/length/bad-b64" {
    var expected: [challenge_len]u8 = undefined;
    for (&expected, 0..) |*b, i| b.* = @intCast(i);
    var b64: [base64url.encodedLen(challenge_len)]u8 = undefined;
    const enc = try base64url.encode(&b64, &expected);

    try testing.expect(challengeMatchesB64(&expected, enc));

    // Tampered challenge.
    var tampered = expected;
    tampered[0] ^= 0xff;
    var tb64: [base64url.encodedLen(challenge_len)]u8 = undefined;
    const tenc = try base64url.encode(&tb64, &tampered);
    try testing.expect(!challengeMatchesB64(&expected, tenc));

    // Wrong decoded length (encodes 16 bytes, expected is 32).
    var short: [16]u8 = @splat(1);
    var sb64: [base64url.encodedLen(16)]u8 = undefined;
    const senc = try base64url.encode(&sb64, &short);
    try testing.expect(!challengeMatchesB64(&expected, senc));

    // Not valid base64url.
    try testing.expect(!challengeMatchesB64(&expected, "!!!!"));
    // Wrong expected length is always false.
    try testing.expect(!challengeMatchesB64(short[0..16], enc));
}

test "originAllowed: case-insensitive exact match; empty list denies" {
    const allowed = [_][]const u8{ "https://chat.example", "https://alt.example:8443" };
    try testing.expect(originAllowed("https://chat.example", &allowed));
    try testing.expect(originAllowed("HTTPS://CHAT.EXAMPLE", &allowed));
    try testing.expect(originAllowed("https://alt.example:8443", &allowed));
    try testing.expect(!originAllowed("https://evil.example", &allowed));
    try testing.expect(!originAllowed("https://chat.example.evil", &allowed));
    try testing.expect(!originAllowed("https://chat.example", &.{}));
}

test "credKey/accountListKey: build within bounds" {
    var kb: [cred_key_max]u8 = undefined;
    try testing.expectEqualStrings("webauthn:abc", credKey(&kb, "abc").?);
    var akb: [account_list_key_max]u8 = undefined;
    try testing.expectEqualStrings("webauthns:alice", accountListKey(&akb, "alice").?);
    var too_long: [account_max + 1]u8 = @splat('a');
    try testing.expect(accountListKey(&akb, &too_long) == null);
}

//! Account `SET EMAIL` with re-verification.
//!
//! This module is the pure-logic spine behind the real server command
//! `ACCOUNT SET EMAIL <addr>` and its confirmation `ACCOUNT VERIFY EMAIL
//! <token>`.  Per the Mizuchi architecture there are **no pseudo-clients**:
//! email changes flow through genuine server commands and numerics, and this
//! file owns the syntactic + state-machine half of that flow.
//!
//! It deliberately complements `account_verify.zig`:
//!
//!   * `account_verify.zig` is a heap-backed, multi-account `VerifyStore`
//!     (StringHashMap, allocator-owned hex tokens, loose contact bytes).  It is
//!     a generic "verify a contact" store.
//!   * This file is **allocation-free**: a single `EmailChange` struct holds the
//!     one pending email-change for one account in fixed inline buffers, and
//!     `validateEmail` enforces real `local@domain` email syntax that the
//!     generic contact validator does not.
//!
//! Everything here is pure: no I/O, no clocks, no globals.  Callers supply the
//! current monotonic time (`now_ms`) and the random token bytes, which keeps the
//! logic fully deterministic and unit-testable.

const std = @import("std");

// ---------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------

/// Maximum length of a full email address (`local@domain`). RFC 5321 caps the
/// forward-path at 254 octets; we adopt that as the hard ceiling.
pub const max_email_len: usize = 254;

/// Maximum length of the local-part (text before the `@`). RFC 5321 §4.5.3.1.1.
pub const max_local_len: usize = 64;

/// Maximum length of the domain part (text after the `@`).
pub const max_domain_len: usize = 255;

/// Number of raw random bytes a confirmation token is built from. The stored
/// token is the lowercase hex expansion, i.e. `token_raw_bytes * 2` chars.
pub const token_raw_bytes: usize = 16;

/// Length of the stored hex confirmation token.
pub const token_hex_len: usize = token_raw_bytes * 2;

/// Default time-to-live for a pending email change, in milliseconds (24h).
pub const default_ttl_ms: u64 = 24 * 60 * 60 * 1000;

// ---------------------------------------------------------------------------
// Email validation
// ---------------------------------------------------------------------------

/// Why an email address was rejected.
pub const EmailError = error{
    Empty,
    TooLong,
    MissingAt,
    MultipleAt,
    EmptyLocal,
    LocalTooLong,
    EmptyDomain,
    DomainTooLong,
    ControlByte,
    Whitespace,
    InvalidLocalByte,
    InvalidDomainByte,
    DomainNoDot,
    DomainEdgeDot,
    DomainEmptyLabel,
    DomainEdgeHyphen,
};

/// A validated split of an email address into its two halves.  Slices borrow
/// from the caller's input buffer; no allocation is performed.
pub const EmailParts = struct {
    local: []const u8,
    domain: []const u8,
};

/// Validate an email address syntactically and return its parts.
///
/// Rules enforced (intentionally pragmatic, not the full RFC 5322 grammar):
///   * non-empty, total length within `max_email_len`
///   * exactly one `@`, with a non-empty local-part and domain
///   * no control bytes (< 0x20 or 0x7f) and no whitespace anywhere
///   * local-part: printable ASCII excluding `@` and whitespace; no leading,
///     trailing, or doubled `.`
///   * domain: letters/digits/`-`/`.`; at least one `.`; labels non-empty and
///     not edged with `-`; no leading/trailing `.`
pub fn validateEmail(addr: []const u8) EmailError!EmailParts {
    if (addr.len == 0) return error.Empty;
    if (addr.len > max_email_len) return error.TooLong;

    // Global byte scan: reject control bytes / whitespace before structural work.
    for (addr) |b| {
        if (b == ' ' or b == '\t' or b == '\r' or b == '\n') return error.Whitespace;
        if (b < 0x20 or b == 0x7f) return error.ControlByte;
    }

    // Exactly one '@'.
    var at_index: ?usize = null;
    for (addr, 0..) |b, i| {
        if (b == '@') {
            if (at_index != null) return error.MultipleAt;
            at_index = i;
        }
    }
    const at = at_index orelse return error.MissingAt;

    const local = addr[0..at];
    const domain = addr[at + 1 ..];

    try validateLocal(local);
    try validateDomain(domain);

    return .{ .local = local, .domain = domain };
}

/// Convenience predicate wrapper over `validateEmail`.
pub fn isValidEmail(addr: []const u8) bool {
    _ = validateEmail(addr) catch return false;
    return true;
}

fn validateLocal(local: []const u8) EmailError!void {
    if (local.len == 0) return error.EmptyLocal;
    if (local.len > max_local_len) return error.LocalTooLong;
    if (local[0] == '.' or local[local.len - 1] == '.') return error.InvalidLocalByte;

    var prev_dot = false;
    for (local) |b| {
        if (b == '.') {
            if (prev_dot) return error.InvalidLocalByte; // doubled dot
            prev_dot = true;
            continue;
        }
        prev_dot = false;
        if (!validLocalByte(b)) return error.InvalidLocalByte;
    }
}

fn validateDomain(domain: []const u8) EmailError!void {
    if (domain.len == 0) return error.EmptyDomain;
    if (domain.len > max_domain_len) return error.DomainTooLong;
    if (domain[0] == '.' or domain[domain.len - 1] == '.') return error.DomainEdgeDot;

    var has_dot = false;
    var label_len: usize = 0;
    var label_first: u8 = 0;
    var prev: u8 = 0;

    for (domain, 0..) |b, i| {
        if (b == '.') {
            has_dot = true;
            if (label_len == 0) return error.DomainEmptyLabel;
            if (label_first == '-' or prev == '-') return error.DomainEdgeHyphen;
            label_len = 0;
            prev = b;
            continue;
        }
        if (!validDomainByte(b)) return error.InvalidDomainByte;
        if (label_len == 0) label_first = b;
        label_len += 1;
        prev = b;
        _ = i;
    }

    // Trailing label (no terminating dot, already checked edge dot above).
    if (label_len == 0) return error.DomainEmptyLabel;
    if (label_first == '-' or prev == '-') return error.DomainEdgeHyphen;
    if (!has_dot) return error.DomainNoDot;
}

/// Local-part bytes: printable ASCII excluding `@`, `.` (handled separately),
/// and whitespace/control (already excluded by the global scan).
fn validLocalByte(b: u8) bool {
    if (b == '@') return false;
    return switch (b) {
        'a'...'z', 'A'...'Z', '0'...'9' => true,
        // Common, conservative subset of RFC atom + dot-atom specials.
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '/', '=', '?', '^', '_', '`', '{', '|', '}', '~' => true,
        else => false,
    };
}

/// Domain bytes (LDH: letters, digits, hyphen). Dots are handled separately.
fn validDomainByte(b: u8) bool {
    return switch (b) {
        'a'...'z', 'A'...'Z', '0'...'9', '-' => true,
        else => false,
    };
}

// ---------------------------------------------------------------------------
// Pending email-change flow
// ---------------------------------------------------------------------------

/// State of an `EmailChange` slot.
pub const State = enum {
    /// No change in flight.
    idle,
    /// A new email is pending confirmation.
    pending,
};

/// Outcome of a `confirm` attempt.
pub const ConfirmResult = enum {
    /// Token matched; the new email was committed.
    committed,
    /// No change is pending for this slot.
    no_pending,
    /// The pending change has expired (caller should clear it).
    expired,
    /// Token did not match the pending record.
    bad_token,
    /// The pending record was already consumed (single-use replay).
    already_used,
};

/// Errors returned when starting a change.
pub const IssueError = EmailError || error{
    /// Random token bytes were not exactly `token_raw_bytes` long.
    BadTokenBytes,
};

/// A single account's pending email-change record.
///
/// Allocation-free: the new email and the hex token live in inline fixed
/// buffers.  One `EmailChange` tracks at most one in-flight change for one
/// account, which matches the `ACCOUNT SET EMAIL` semantics (a new request
/// supersedes any earlier pending one).
pub const EmailChange = struct {
    state: State = .idle,
    /// Backing storage for the pending new email.
    email_buf: [max_email_len]u8 = undefined,
    email_len: usize = 0,
    /// Lowercase hex confirmation token.
    token: [token_hex_len]u8 = undefined,
    /// Time the pending change was issued (ms, caller-supplied clock).
    issued_ms: u64 = 0,
    /// Time-to-live in ms; the change expires at `issued_ms + ttl_ms`.
    ttl_ms: u64 = default_ttl_ms,

    /// Create an empty, idle slot with the default TTL.
    pub fn init() EmailChange {
        return .{};
    }

    /// Create an empty, idle slot with a custom TTL.
    pub fn initTtl(ttl_ms: u64) EmailChange {
        return .{ .ttl_ms = ttl_ms };
    }

    /// Begin a pending email change.
    ///
    /// Validates `new_email`, then stores it together with a fresh hex token
    /// derived from `random_bytes` (which must be exactly `token_raw_bytes`).
    /// Any prior pending change in this slot is overwritten. Returns a borrowed
    /// view of the stored hex token.
    pub fn issue(
        self: *EmailChange,
        new_email: []const u8,
        random_bytes: []const u8,
        now_ms: u64,
    ) IssueError![]const u8 {
        if (random_bytes.len != token_raw_bytes) return error.BadTokenBytes;
        _ = try validateEmail(new_email); // length already bounded by validation

        std.mem.copyForwards(u8, self.email_buf[0..new_email.len], new_email);
        self.email_len = new_email.len;
        encodeHex(random_bytes, self.token[0..]);
        self.issued_ms = now_ms;
        self.state = .pending;
        return self.token[0..];
    }

    /// Whether this slot currently holds an unexpired pending change.
    pub fn isPending(self: *const EmailChange, now_ms: u64) bool {
        return self.state == .pending and !self.isExpired(now_ms);
    }

    /// True once `issued_ms + ttl_ms` has elapsed (only meaningful while pending).
    pub fn isExpired(self: *const EmailChange, now_ms: u64) bool {
        if (self.state != .pending) return false;
        return now_ms >= self.issued_ms +| self.ttl_ms;
    }

    /// Borrowed view of the pending new email, if any.
    pub fn pendingEmail(self: *const EmailChange) ?[]const u8 {
        if (self.state != .pending) return null;
        return self.email_buf[0..self.email_len];
    }

    /// Confirm a pending change with its token.
    ///
    /// On success the change is committed: the slot returns to `idle` (the
    /// record is consumed, so the token cannot be replayed) and the committed
    /// address is returned via `out`/the result. Comparison is constant-time
    /// over the token bytes.
    pub fn confirm(
        self: *EmailChange,
        token: []const u8,
        now_ms: u64,
        out: *CommitInfo,
    ) ConfirmResult {
        if (self.state != .pending) return .no_pending;
        if (self.isExpired(now_ms)) return .expired;
        if (!tokenMatches(self.token[0..], token)) return .bad_token;

        // Capture the committed value before clearing.
        out.* = .{ .email = self.email_buf[0..self.email_len] };
        // Single-use: consume the pending record.
        self.state = .idle;
        return .committed;
    }

    /// Cancel/reject a pending change without committing. Returns true if one
    /// was actually pending.
    pub fn cancel(self: *EmailChange) bool {
        if (self.state != .pending) return false;
        self.state = .idle;
        self.email_len = 0;
        return true;
    }

    /// Clear the slot if it holds an expired pending change. Returns true if a
    /// record was swept.
    pub fn sweepExpired(self: *EmailChange, now_ms: u64) bool {
        if (self.state == .pending and self.isExpired(now_ms)) {
            self.state = .idle;
            self.email_len = 0;
            return true;
        }
        return false;
    }
};

/// Details handed back to the caller on a successful `confirm`.  The `email`
/// slice borrows the `EmailChange`'s internal buffer and stays valid until the
/// next mutation of that struct; callers that need to persist it must copy.
pub const CommitInfo = struct {
    email: []const u8,
};

// ---------------------------------------------------------------------------
// Token helpers
// ---------------------------------------------------------------------------

fn encodeHex(bytes: []const u8, out: []u8) void {
    std.debug.assert(out.len >= bytes.len * 2);
    const digits = "0123456789abcdef";
    for (bytes, 0..) |b, i| {
        out[i * 2] = digits[b >> 4];
        out[i * 2 + 1] = digits[b & 0x0f];
    }
}

/// Constant-time comparison of the stored token against a candidate, guarding
/// against timing oracles on the confirmation path.
fn tokenMatches(expected: []const u8, actual: []const u8) bool {
    if (expected.len != actual.len) return false;
    var diff: u8 = 0;
    for (expected, actual) |e, a| diff |= e ^ a;
    return diff == 0;
}

// ===========================================================================
// Tests
// ===========================================================================

const testing = std.testing;

// --- validateEmail --------------------------------------------------------

test "validateEmail accepts a normal address and splits parts" {
    const parts = try validateEmail("alice@example.com");
    try testing.expectEqualStrings("alice", parts.local);
    try testing.expectEqualStrings("example.com", parts.domain);
}

test "validateEmail accepts dotted local and subdomain" {
    const parts = try validateEmail("a.b.c@mail.sub.example.co.uk");
    try testing.expectEqualStrings("a.b.c", parts.local);
    try testing.expectEqualStrings("mail.sub.example.co.uk", parts.domain);
}

test "validateEmail accepts permitted special local bytes" {
    try testing.expect(isValidEmail("user+tag_name-99@host.io"));
    try testing.expect(isValidEmail("weird!#$%&'*+/=?^_`{|}~@x.dev"));
}

test "validateEmail rejects empty input" {
    try testing.expectError(error.Empty, validateEmail(""));
}

test "validateEmail rejects overly long address" {
    var buf: [max_email_len + 10]u8 = undefined;
    @memset(buf[0..], 'a');
    buf[200] = '@';
    // make a valid-looking domain tail but exceed total length
    const long = buf[0 .. max_email_len + 1];
    try testing.expectError(error.TooLong, validateEmail(long));
}

test "validateEmail rejects missing and multiple at signs" {
    try testing.expectError(error.MissingAt, validateEmail("noatsign.com"));
    try testing.expectError(error.MultipleAt, validateEmail("a@b@c.com"));
}

test "validateEmail rejects empty local or domain" {
    try testing.expectError(error.EmptyLocal, validateEmail("@example.com"));
    try testing.expectError(error.EmptyDomain, validateEmail("user@"));
}

test "validateEmail rejects whitespace and control bytes" {
    try testing.expectError(error.Whitespace, validateEmail("a b@example.com"));
    try testing.expectError(error.Whitespace, validateEmail("a@exa mple.com"));
    try testing.expectError(error.Whitespace, validateEmail("a@example.com\n"));
    try testing.expectError(error.ControlByte, validateEmail("a\x01b@example.com"));
    try testing.expectError(error.ControlByte, validateEmail("a@b.com\x7f"));
}

test "validateEmail rejects bad local dots" {
    try testing.expectError(error.InvalidLocalByte, validateEmail(".user@example.com"));
    try testing.expectError(error.InvalidLocalByte, validateEmail("user.@example.com"));
    try testing.expectError(error.InvalidLocalByte, validateEmail("us..er@example.com"));
}

test "validateEmail rejects domain without a dot" {
    try testing.expectError(error.DomainNoDot, validateEmail("user@localhost"));
}

test "validateEmail rejects domain edge dots and empty labels" {
    try testing.expectError(error.DomainEdgeDot, validateEmail("user@.example.com"));
    try testing.expectError(error.DomainEdgeDot, validateEmail("user@example.com."));
    try testing.expectError(error.DomainEmptyLabel, validateEmail("user@example..com"));
}

test "validateEmail rejects domain label edge hyphens" {
    try testing.expectError(error.DomainEdgeHyphen, validateEmail("user@-example.com"));
    try testing.expectError(error.DomainEdgeHyphen, validateEmail("user@example-.com"));
}

test "validateEmail rejects illegal local and domain bytes" {
    try testing.expectError(error.InvalidLocalByte, validateEmail("us\"er@example.com"));
    try testing.expectError(error.InvalidDomainByte, validateEmail("user@ex_ample.com"));
}

test "validateEmail enforces local-part length cap" {
    var buf: [max_local_len + 1 + 12]u8 = undefined;
    @memset(buf[0 .. max_local_len + 1], 'a');
    buf[max_local_len + 1] = '@';
    std.mem.copyForwards(u8, buf[max_local_len + 2 ..], "host.dev");
    const addr = buf[0 .. max_local_len + 2 + "host.dev".len];
    try testing.expectError(error.LocalTooLong, validateEmail(addr));
}

// --- EmailChange flow -----------------------------------------------------

const sample_bytes = [_]u8{
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
};

test "issue stores pending email and returns hex token" {
    var ec = EmailChange.init();
    const tok = try ec.issue("new@example.com", sample_bytes[0..], 1000);

    try testing.expectEqual(token_hex_len, tok.len);
    try testing.expectEqualStrings("00112233445566778899aabbccddeeff", tok);
    try testing.expect(ec.isPending(1000));
    try testing.expectEqualStrings("new@example.com", ec.pendingEmail().?);
}

test "issue rejects malformed email without entering pending state" {
    var ec = EmailChange.init();
    try testing.expectError(error.DomainNoDot, ec.issue("bad@localhost", sample_bytes[0..], 1));
    try testing.expectEqual(State.idle, ec.state);
    try testing.expect(ec.pendingEmail() == null);
}

test "issue rejects wrong-sized token bytes" {
    var ec = EmailChange.init();
    try testing.expectError(error.BadTokenBytes, ec.issue("a@b.com", sample_bytes[0..8], 1));
    try testing.expectEqual(State.idle, ec.state);
}

test "confirm commits the change with the correct token" {
    var ec = EmailChange.init();
    const tok = try ec.issue("alice@new.org", sample_bytes[0..], 5);

    var info: CommitInfo = undefined;
    const res = ec.confirm(tok, 10, &info);
    try testing.expectEqual(ConfirmResult.committed, res);
    try testing.expectEqualStrings("alice@new.org", info.email);
    // Slot returns to idle; nothing pending afterwards.
    try testing.expectEqual(State.idle, ec.state);
    try testing.expect(!ec.isPending(10));
}

test "confirm rejects a bad token and keeps the record pending" {
    var ec = EmailChange.init();
    _ = try ec.issue("bob@new.org", sample_bytes[0..], 5);

    var info: CommitInfo = undefined;
    const res = ec.confirm("deadbeefdeadbeefdeadbeefdeadbeef", 10, &info);
    try testing.expectEqual(ConfirmResult.bad_token, res);
    try testing.expect(ec.isPending(10)); // still pending, can retry
}

test "confirm replay after success reports no pending" {
    var ec = EmailChange.init();
    const tok_view = try ec.issue("carol@new.org", sample_bytes[0..], 5);
    // Copy the token because the slot buffer survives but we want a stable value.
    var tok_copy: [token_hex_len]u8 = undefined;
    std.mem.copyForwards(u8, tok_copy[0..], tok_view);

    var info: CommitInfo = undefined;
    try testing.expectEqual(ConfirmResult.committed, ec.confirm(tok_copy[0..], 10, &info));
    // Second use of the same token: single-use, nothing pending.
    try testing.expectEqual(ConfirmResult.no_pending, ec.confirm(tok_copy[0..], 11, &info));
}

test "confirm on an idle slot reports no pending" {
    var ec = EmailChange.init();
    var info: CommitInfo = undefined;
    try testing.expectEqual(ConfirmResult.no_pending, ec.confirm("whatever", 1, &info));
}

test "pending change expires after its ttl" {
    var ec = EmailChange.initTtl(1000);
    const tok = try ec.issue("dave@new.org", sample_bytes[0..], 100);

    try testing.expect(ec.isPending(900)); // 100..1100 window
    try testing.expect(!ec.isExpired(1099));
    try testing.expect(ec.isExpired(1100)); // issued(100) + ttl(1000)

    var info: CommitInfo = undefined;
    try testing.expectEqual(ConfirmResult.expired, ec.confirm(tok, 1100, &info));
    try testing.expect(!ec.isPending(1100));
}

test "sweepExpired clears only expired pending records" {
    var ec = EmailChange.initTtl(50);
    _ = try ec.issue("e@x.io", sample_bytes[0..], 0);

    try testing.expect(!ec.sweepExpired(49)); // not yet expired
    try testing.expect(ec.sweepExpired(50)); // now expired -> swept
    try testing.expectEqual(State.idle, ec.state);
    try testing.expect(!ec.sweepExpired(100)); // nothing left to sweep
}

test "cancel rejects a pending change" {
    var ec = EmailChange.init();
    _ = try ec.issue("f@x.io", sample_bytes[0..], 0);
    try testing.expect(ec.cancel());
    try testing.expect(!ec.isPending(0));
    try testing.expect(!ec.cancel()); // already idle
}

test "issue supersedes a prior pending change" {
    var ec = EmailChange.init();
    _ = try ec.issue("first@x.io", sample_bytes[0..], 0);

    const other = [_]u8{0xab} ** token_raw_bytes;
    const tok2 = try ec.issue("second@y.io", other[0..], 1);
    try testing.expectEqualStrings("second@y.io", ec.pendingEmail().?);
    try testing.expectEqualStrings("abababababababababababababababab", tok2);

    // The first token no longer confirms anything.
    var info: CommitInfo = undefined;
    try testing.expectEqual(ConfirmResult.bad_token, ec.confirm("00112233445566778899aabbccddeeff", 2, &info));
    // The new token does.
    try testing.expectEqual(ConfirmResult.committed, ec.confirm(tok2, 2, &info));
    try testing.expectEqualStrings("second@y.io", info.email);
}

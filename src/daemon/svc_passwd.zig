//! Account password management as real server commands.
//!
//! Orochi exposes password changes and resets as first-class server commands
//! (`SET PASSWORD`, `RESETPASS`), never via pseudo-clients. This module is the
//! pure decision core for those commands:
//!
//!   * `PasswordPolicy` — length and equality rules for new passwords.
//!   * `changePassword` — verify the presented old password against a stored
//!     verifier, enforce policy, and produce a fresh verifier for the new one.
//!   * `ResetTokenStore` — issue single-use, time-bounded reset tokens and
//!     validate/consume them to authorize a password set.
//!
//! Crypto is pluggable. This module never hashes or compares bytes itself: the
//! caller passes a `Hasher` (a `hashFn` to derive a verifier and a `verifyFn`
//! to check a candidate against a stored verifier). Verifiers are opaque byte
//! slices to this layer. Likewise, reset tokens are opaque bytes the caller
//! generates from a real RNG — this module only tracks lifetime and single use.
//!
//! There is no I/O, no real cryptography, and no global mutable state here, so
//! the logic is trivially testable and reusable across command handlers.

const std = @import("std");

// --------------------------------------------------------------------------
// Password policy
// --------------------------------------------------------------------------

/// Bounds applied to a proposed new password before it is hashed.
///
/// Lengths are measured in bytes of the raw password as presented by the
/// client. The defaults are deliberately conservative; command handlers may
/// supply stricter values.
pub const PasswordPolicy = struct {
    /// Minimum accepted password length in bytes.
    min_len: usize = 8,
    /// Maximum accepted password length in bytes. Guards against
    /// resource-exhaustion via absurdly long inputs handed to a slow KDF.
    max_len: usize = 256,
    /// When true, the new password may not byte-equal the old password.
    forbid_same_as_old: bool = true,

    /// Reasons a proposed new password may be rejected by policy.
    pub const Decision = enum {
        ok,
        too_short,
        too_long,
        same_as_old,
    };

    /// Evaluates `new_password` against this policy.
    ///
    /// `old_password` is the raw old password, used only for the equality
    /// check; pass an empty slice (or any value) when no old password applies
    /// and `forbid_same_as_old` is false. This comparison is plaintext-to-
    /// plaintext and is not constant time; it is a usability rule, not a
    /// security boundary, and the old password is already known to the caller.
    pub fn check(
        self: PasswordPolicy,
        new_password: []const u8,
        old_password: []const u8,
    ) Decision {
        if (new_password.len < self.min_len) return .too_short;
        if (new_password.len > self.max_len) return .too_long;
        if (self.forbid_same_as_old and
            std.mem.eql(u8, new_password, old_password))
        {
            return .same_as_old;
        }
        return .ok;
    }
};

// --------------------------------------------------------------------------
// Pluggable hashing
// --------------------------------------------------------------------------

/// Caller-supplied crypto strategy.
///
/// `hashFn` derives an owned verifier (e.g. a PHC string) for a password using
/// `allocator`; the caller owns and later frees the returned bytes. `verifyFn`
/// reports whether `candidate` matches `verifier`. A `null` `verifyFn` means
/// the old password cannot be checked, so any change that requires old-password
/// verification will be rejected with `wrong_old_password`.
pub const Hasher = struct {
    hashFn: *const fn (allocator: std.mem.Allocator, password: []const u8) anyerror![]u8,
    verifyFn: ?*const fn (verifier: []const u8, candidate: []const u8) bool = null,

    fn hash(self: Hasher, allocator: std.mem.Allocator, password: []const u8) ![]u8 {
        return self.hashFn(allocator, password);
    }

    fn verify(self: Hasher, verifier: []const u8, candidate: []const u8) bool {
        const f = self.verifyFn orelse return false;
        return f(verifier, candidate);
    }
};

// --------------------------------------------------------------------------
// SET PASSWORD (authenticated change)
// --------------------------------------------------------------------------

/// Outcome of an authenticated password change attempt.
pub const ChangeOutcome = enum {
    changed,
    wrong_old_password,
    rejected_too_short,
    rejected_too_long,
    rejected_same_as_old,
};

/// Result of `changePassword`: an outcome plus, on success, the owned new
/// verifier the caller must persist (and is responsible for freeing).
pub const ChangeResult = struct {
    outcome: ChangeOutcome,
    /// New verifier bytes, owned by the caller. Non-null only when
    /// `outcome == .changed`.
    new_verifier: ?[]u8 = null,
};

fn outcomeForDecision(d: PasswordPolicy.Decision) ChangeOutcome {
    return switch (d) {
        .ok => .changed, // unreachable in practice; resolved before use
        .too_short => .rejected_too_short,
        .too_long => .rejected_too_long,
        .same_as_old => .rejected_same_as_old,
    };
}

/// Changes a password after verifying the presented old password.
///
/// Steps, in order:
///   1. Verify `old_password` against `stored_verifier` via `hasher.verifyFn`.
///   2. Enforce `policy` on `new_password` (length, not-equal-to-old).
///   3. Hash `new_password` into a fresh owned verifier.
///
/// On any failure the returned `new_verifier` is null and `stored_verifier`
/// remains authoritative. The allocator is only touched on the hashing step,
/// so failed verification or policy rejection never allocates.
pub fn changePassword(
    allocator: std.mem.Allocator,
    hasher: Hasher,
    stored_verifier: []const u8,
    old_password: []const u8,
    new_password: []const u8,
    policy: PasswordPolicy,
) !ChangeResult {
    if (!hasher.verify(stored_verifier, old_password)) {
        return .{ .outcome = .wrong_old_password };
    }

    const decision = policy.check(new_password, old_password);
    if (decision != .ok) {
        return .{ .outcome = outcomeForDecision(decision) };
    }

    const verifier = try hasher.hash(allocator, new_password);
    return .{ .outcome = .changed, .new_verifier = verifier };
}

// --------------------------------------------------------------------------
// RESETPASS (token-authorized set)
// --------------------------------------------------------------------------

/// Bounds for the reset-token store.
pub const ResetParams = struct {
    /// Maximum concurrently outstanding reset tokens.
    max_tokens: usize = 65536,
    /// Token lifetime in milliseconds before it is treated as expired.
    ttl_ms: u64 = 60 * 60 * 1000,
    /// Maximum accepted account-name length in bytes.
    max_account_bytes: usize = 128,
    /// Maximum accepted token length in bytes.
    max_token_bytes: usize = 256,
    /// Minimum accepted token length in bytes (reject empty/trivial tokens).
    min_token_bytes: usize = 16,
};

/// Errors returned while issuing a reset token.
pub const IssueError = std.mem.Allocator.Error || error{
    InvalidAccount,
    AccountTooLong,
    InvalidToken,
    TokenTooLong,
    TooManyTokens,
};

/// A single outstanding password-reset token. Owned by `ResetTokenStore`.
pub const ResetToken = struct {
    /// Account this token authorizes a password set for.
    account: []const u8,
    /// Opaque token bytes supplied by the caller (from a real RNG).
    token: []const u8,
    /// Millisecond timestamp when the token was issued.
    issued_ms: u64,
    /// Millisecond timestamp after which the token is expired.
    expires_ms: u64,

    /// True when `now_ms` is at or past the expiry instant.
    pub fn isExpired(self: ResetToken, now_ms: u64) bool {
        return now_ms >= self.expires_ms;
    }

    fn deinit(self: *ResetToken, allocator: std.mem.Allocator) void {
        allocator.free(self.account);
        allocator.free(self.token);
        self.* = undefined;
    }
};

/// Outcome of consuming a reset token.
pub const ConsumeOutcome = enum {
    /// Token matched, was live, and is now consumed; caller may set password.
    authorized,
    /// No outstanding token exists for the account.
    no_token,
    /// A token exists but the presented bytes do not match it.
    bad_token,
    /// The matching token has expired and has been discarded.
    expired,
};

/// Single-use, time-bounded reset tokens keyed by account name.
///
/// At most one outstanding token exists per account; issuing again replaces any
/// prior token (invalidating it). Consuming a token removes it, so replaying
/// the same bytes yields `no_token`.
pub const ResetTokenStore = struct {
    allocator: std.mem.Allocator,
    params: ResetParams,
    entries: std.StringHashMap(ResetToken),

    /// Creates an empty store using caller-provided bounds.
    pub fn init(allocator: std.mem.Allocator, params: ResetParams) ResetTokenStore {
        return .{
            .allocator = allocator,
            .params = params,
            .entries = std.StringHashMap(ResetToken).init(allocator),
        };
    }

    /// Frees all outstanding tokens and invalidates the store.
    ///
    /// Each record's `account` aliases its map key, so `value.deinit` releases
    /// the key allocation; the key must not be freed separately.
    pub fn deinit(self: *ResetTokenStore) void {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.entries.deinit();
        self.* = undefined;
    }

    /// Number of outstanding tokens.
    pub fn count(self: *const ResetTokenStore) usize {
        return self.entries.count();
    }

    /// Issues (or replaces) the reset token for `account`.
    ///
    /// `token` must be caller-generated opaque bytes within the configured
    /// length bounds. Returns the stored token slice (a view into store-owned
    /// memory) on success. Issuing a new token for an account that already has
    /// one replaces and frees the old token, so the prior token is invalidated.
    pub fn issue(
        self: *ResetTokenStore,
        account: []const u8,
        token: []const u8,
        now_ms: u64,
    ) IssueError![]const u8 {
        if (account.len == 0) return error.InvalidAccount;
        if (account.len > self.params.max_account_bytes) return error.AccountTooLong;
        if (token.len < self.params.min_token_bytes) return error.InvalidToken;
        if (token.len > self.params.max_token_bytes) return error.TokenTooLong;

        const existing = self.entries.getEntry(account);
        if (existing == null and self.entries.count() >= self.params.max_tokens) {
            return error.TooManyTokens;
        }

        const token_copy = try self.allocator.dupe(u8, token);
        errdefer self.allocator.free(token_copy);

        const record = ResetToken{
            .account = undefined, // filled below depending on insert/replace
            .token = token_copy,
            .issued_ms = now_ms,
            .expires_ms = now_ms +| self.params.ttl_ms,
        };

        if (existing) |entry| {
            // Replace in place: keep the existing owned key (which `account`
            // aliases) and free only the old token, invalidating it.
            self.allocator.free(entry.value_ptr.token);
            entry.value_ptr.token = token_copy;
            entry.value_ptr.issued_ms = record.issued_ms;
            entry.value_ptr.expires_ms = record.expires_ms;
            return entry.value_ptr.token;
        }

        const key_copy = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(key_copy);

        var new_record = record;
        new_record.account = key_copy;
        try self.entries.putNoClobber(key_copy, new_record);
        return self.entries.getPtr(key_copy).?.token;
    }

    /// Looks up the outstanding token for `account` without consuming it.
    pub fn peek(self: *const ResetTokenStore, account: []const u8) ?ResetToken {
        return self.entries.get(account);
    }

    /// Validates and consumes the reset token for `account`.
    ///
    /// On `.authorized` the token is removed (single use). On `.expired` the
    /// stale token is also removed. On `.bad_token` the token is left in place
    /// so a correct retry within the TTL still works. Token comparison uses a
    /// constant-time check to avoid leaking match progress via timing.
    pub fn consume(
        self: *ResetTokenStore,
        account: []const u8,
        token: []const u8,
        now_ms: u64,
    ) ConsumeOutcome {
        const entry = self.entries.getEntry(account) orelse return .no_token;

        if (entry.value_ptr.isExpired(now_ms)) {
            self.removeEntry(entry.key_ptr.*);
            return .expired;
        }

        if (!constantTimeEql(entry.value_ptr.token, token)) {
            return .bad_token;
        }

        self.removeEntry(entry.key_ptr.*);
        return .authorized;
    }

    /// Removes and frees the record stored under `key` (a store-owned key).
    ///
    /// The record's `account` field aliases the map key's allocation, so
    /// `value.deinit` frees the key; we must not free `kv.key` again.
    fn removeEntry(self: *ResetTokenStore, key: []const u8) void {
        if (self.entries.fetchRemove(key)) |kv| {
            var value = kv.value;
            value.deinit(self.allocator);
        }
    }
};

/// Length-aware constant-time byte comparison.
///
/// Returns false immediately on length mismatch (length is not secret here),
/// otherwise compares every byte without short-circuiting so the time taken
/// does not reveal the position of the first differing byte.
fn constantTimeEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var diff: u8 = 0;
    for (a, b) |x, y| diff |= x ^ y;
    return diff == 0;
}

// --------------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------------

const testing = std.testing;

// A trivial reversible "hasher" for tests: the verifier is the password with a
// fixed prefix, and verify just strips and compares. No real crypto.
const test_prefix = "v1:";

fn testHash(allocator: std.mem.Allocator, password: []const u8) anyerror![]u8 {
    return std.fmt.allocPrint(allocator, "{s}{s}", .{ test_prefix, password });
}

fn testVerify(verifier: []const u8, candidate: []const u8) bool {
    if (!std.mem.startsWith(u8, verifier, test_prefix)) return false;
    return std.mem.eql(u8, verifier[test_prefix.len..], candidate);
}

fn testHasher() Hasher {
    return .{ .hashFn = testHash, .verifyFn = testVerify };
}

test "policy accepts a compliant password" {
    const policy = PasswordPolicy{};
    try testing.expectEqual(PasswordPolicy.Decision.ok, policy.check("hunter2!!", "old-secret"));
}

test "policy rejects too-short password" {
    const policy = PasswordPolicy{ .min_len = 8 };
    try testing.expectEqual(PasswordPolicy.Decision.too_short, policy.check("short", "old"));
}

test "policy rejects too-long password" {
    const policy = PasswordPolicy{ .max_len = 10 };
    try testing.expectEqual(PasswordPolicy.Decision.too_long, policy.check("this is way too long", "old"));
}

test "policy rejects new password equal to old" {
    const policy = PasswordPolicy{ .min_len = 4 };
    try testing.expectEqual(PasswordPolicy.Decision.same_as_old, policy.check("samesame", "samesame"));
}

test "policy allows same-as-old when configured" {
    const policy = PasswordPolicy{ .min_len = 4, .forbid_same_as_old = false };
    try testing.expectEqual(PasswordPolicy.Decision.ok, policy.check("samesame", "samesame"));
}

test "changePassword succeeds with correct old password and compliant new" {
    const allocator = testing.allocator;
    const stored = try testHash(allocator, "old-password");
    defer allocator.free(stored);

    const result = try changePassword(
        allocator,
        testHasher(),
        stored,
        "old-password",
        "brand-new-pass",
        .{},
    );
    try testing.expectEqual(ChangeOutcome.changed, result.outcome);
    try testing.expect(result.new_verifier != null);
    defer allocator.free(result.new_verifier.?);

    // The new verifier must validate the new password and reject the old one.
    try testing.expect(testVerify(result.new_verifier.?, "brand-new-pass"));
    try testing.expect(!testVerify(result.new_verifier.?, "old-password"));
}

test "changePassword rejects a wrong old password without allocating" {
    const allocator = testing.allocator;
    const stored = try testHash(allocator, "real-old");
    defer allocator.free(stored);

    const result = try changePassword(
        allocator,
        testHasher(),
        stored,
        "wrong-old",
        "brand-new-pass",
        .{},
    );
    try testing.expectEqual(ChangeOutcome.wrong_old_password, result.outcome);
    try testing.expect(result.new_verifier == null);
}

test "changePassword enforces policy after verifying old password" {
    const allocator = testing.allocator;
    const stored = try testHash(allocator, "old-password");
    defer allocator.free(stored);

    const too_short = try changePassword(allocator, testHasher(), stored, "old-password", "x", .{ .min_len = 8 });
    try testing.expectEqual(ChangeOutcome.rejected_too_short, too_short.outcome);
    try testing.expect(too_short.new_verifier == null);

    const same = try changePassword(allocator, testHasher(), stored, "old-password", "old-password", .{ .min_len = 4 });
    try testing.expectEqual(ChangeOutcome.rejected_same_as_old, same.outcome);
    try testing.expect(same.new_verifier == null);
}

test "changePassword rejects when no verifyFn is available" {
    const allocator = testing.allocator;
    const hasher = Hasher{ .hashFn = testHash, .verifyFn = null };
    const result = try changePassword(allocator, hasher, "v1:whatever", "anything", "new-password", .{});
    try testing.expectEqual(ChangeOutcome.wrong_old_password, result.outcome);
}

test "reset token issue then consume authorizes once" {
    var store = ResetTokenStore.init(testing.allocator, .{});
    defer store.deinit();

    const tok = "0123456789abcdef-token";
    _ = try store.issue("alice", tok, 1000);
    try testing.expectEqual(@as(usize, 1), store.count());

    try testing.expectEqual(ConsumeOutcome.authorized, store.consume("alice", tok, 2000));
    try testing.expectEqual(@as(usize, 0), store.count());
}

test "reset token cannot be replayed after consume" {
    var store = ResetTokenStore.init(testing.allocator, .{});
    defer store.deinit();

    const tok = "0123456789abcdef-token";
    _ = try store.issue("bob", tok, 0);
    try testing.expectEqual(ConsumeOutcome.authorized, store.consume("bob", tok, 1));
    // Replay: token is gone.
    try testing.expectEqual(ConsumeOutcome.no_token, store.consume("bob", tok, 2));
}

test "reset token expires after ttl and is discarded" {
    var store = ResetTokenStore.init(testing.allocator, .{ .ttl_ms = 1000 });
    defer store.deinit();

    const tok = "0123456789abcdef-token";
    _ = try store.issue("carol", tok, 0);
    // At exactly ttl it is expired.
    try testing.expectEqual(ConsumeOutcome.expired, store.consume("carol", tok, 1000));
    try testing.expectEqual(@as(usize, 0), store.count());
    // Subsequent attempt finds nothing.
    try testing.expectEqual(ConsumeOutcome.no_token, store.consume("carol", tok, 1001));
}

test "wrong token bytes are rejected but leave the token live for retry" {
    var store = ResetTokenStore.init(testing.allocator, .{});
    defer store.deinit();

    const tok = "0123456789abcdef-token";
    _ = try store.issue("dave", tok, 0);
    try testing.expectEqual(ConsumeOutcome.bad_token, store.consume("dave", "wrong-token-here!", 10));
    // Correct token still works afterward.
    try testing.expectEqual(ConsumeOutcome.authorized, store.consume("dave", tok, 20));
}

test "consuming an unknown account reports no_token" {
    var store = ResetTokenStore.init(testing.allocator, .{});
    defer store.deinit();
    try testing.expectEqual(ConsumeOutcome.no_token, store.consume("nobody", "0123456789abcdef", 0));
}

test "issuing again replaces and invalidates the prior token" {
    var store = ResetTokenStore.init(testing.allocator, .{});
    defer store.deinit();

    const first = "first-token-aaaaaa";
    const second = "second-token-bbbbb";
    _ = try store.issue("erin", first, 0);
    _ = try store.issue("erin", second, 5);
    try testing.expectEqual(@as(usize, 1), store.count());

    // Old token no longer matches.
    try testing.expectEqual(ConsumeOutcome.bad_token, store.consume("erin", first, 10));
    // New token authorizes.
    try testing.expectEqual(ConsumeOutcome.authorized, store.consume("erin", second, 11));
}

test "issue validates account and token bounds" {
    var store = ResetTokenStore.init(testing.allocator, .{ .min_token_bytes = 16, .max_token_bytes = 32, .max_account_bytes = 8 });
    defer store.deinit();

    try testing.expectError(error.InvalidAccount, store.issue("", "0123456789abcdef", 0));
    try testing.expectError(error.AccountTooLong, store.issue("toolongaccount", "0123456789abcdef", 0));
    try testing.expectError(error.InvalidToken, store.issue("ok", "short", 0));
    try testing.expectError(error.TokenTooLong, store.issue("ok", "0123456789abcdef0123456789abcdef0", 0));
}

test "issue enforces max_tokens for new accounts only" {
    var store = ResetTokenStore.init(testing.allocator, .{ .max_tokens = 1 });
    defer store.deinit();

    const tok = "0123456789abcdef-tok";
    _ = try store.issue("first", tok, 0);
    try testing.expectError(error.TooManyTokens, store.issue("second", tok, 0));
    // Re-issuing for the existing account is allowed (replacement, not growth).
    _ = try store.issue("first", "another-token-1234", 1);
    try testing.expectEqual(@as(usize, 1), store.count());
}

test "peek reveals an outstanding token without consuming it" {
    var store = ResetTokenStore.init(testing.allocator, .{});
    defer store.deinit();

    const tok = "0123456789abcdef-token";
    _ = try store.issue("frank", tok, 0);

    const seen = store.peek("frank").?;
    try testing.expect(std.mem.eql(u8, seen.token, tok));
    try testing.expect(!seen.isExpired(10));
    // Still present after peek.
    try testing.expectEqual(@as(usize, 1), store.count());
    try testing.expect(store.peek("ghost") == null);
}

test "constantTimeEql matches std.mem.eql semantics" {
    try testing.expect(constantTimeEql("abc", "abc"));
    try testing.expect(!constantTimeEql("abc", "abd"));
    try testing.expect(!constantTimeEql("abc", "ab"));
    try testing.expect(constantTimeEql("", ""));
}

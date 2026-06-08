//! Account ⇄ TLS client-certificate-fingerprint bindings for SASL EXTERNAL.
//!
//! A logged-in user binds the fingerprint of the client cert they presented
//! (via `CERTADD`) to their account; a later connection that presents the same
//! cert can then authenticate with SASL EXTERNAL — no password sent. This is the
//! account-side lookup; the live certfp itself is derived by `proto/certfp.zig`
//! from the negotiated leaf and the EXTERNAL mechanism matches it here.
//!
//! In-memory mirror (mirrors `scram_store.zig`): bindings made this run are
//! authoritative; persistence parity with the account store is a follow-up
//! (rebuild on load via `bind`). Keyed by fingerprint so EXTERNAL verification
//! is a single hashmap probe.

const std = @import("std");
const certfp = @import("../proto/certfp.zig");

pub const CertfpBindError = error{
    InvalidFingerprint,
    AccountTooLong,
    OutOfMemory,
};

/// Maximum stored account-name length (matches the account store's bound).
pub const max_account_len: usize = 64;

pub const CertfpBindStore = struct {
    allocator: std.mem.Allocator,
    /// fingerprint (lowercase hex) -> owned account name.
    entries: std.StringHashMapUnmanaged([]u8),

    pub fn init(allocator: std.mem.Allocator) CertfpBindStore {
        return .{ .allocator = allocator, .entries = .empty };
    }

    pub fn deinit(self: *CertfpBindStore) void {
        var it = self.entries.iterator();
        while (it.next()) |e| {
            self.allocator.free(e.key_ptr.*);
            self.allocator.free(e.value_ptr.*);
        }
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    /// Bind `fingerprint` to `account`. Re-binding the same fingerprint replaces
    /// the owner (the most recent CERTADD wins). One account may own many certs.
    pub fn bind(self: *CertfpBindStore, account: []const u8, fingerprint: []const u8) CertfpBindError!void {
        certfp.validateFingerprint(fingerprint) catch return error.InvalidFingerprint;
        if (account.len == 0 or account.len > max_account_len) return error.AccountTooLong;

        if (self.entries.getPtr(fingerprint)) |slot| {
            const new_acct = try self.allocator.dupe(u8, account);
            self.allocator.free(slot.*);
            slot.* = new_acct;
            return;
        }
        const key = try self.allocator.dupe(u8, fingerprint);
        errdefer self.allocator.free(key);
        const val = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(val);
        try self.entries.put(self.allocator, key, val);
    }

    /// The account owning `fingerprint`, or null. Borrowed (store-owned).
    pub fn accountForFingerprint(self: *const CertfpBindStore, fingerprint: []const u8) ?[]const u8 {
        if (fingerprint.len != certfp.fingerprint_len) return null;
        return self.entries.get(fingerprint);
    }

    /// Remove a binding; returns whether one was present.
    pub fn unbind(self: *CertfpBindStore, fingerprint: []const u8) bool {
        if (self.entries.fetchRemove(fingerprint)) |kv| {
            self.allocator.free(kv.key);
            self.allocator.free(kv.value);
            return true;
        }
        return false;
    }
};

test "bind then lookup returns the bound account" {
    const alloc = std.testing.allocator;
    var store = CertfpBindStore.init(alloc);
    defer store.deinit();

    const fp = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    try store.bind("alice", fp);
    try std.testing.expectEqualStrings("alice", store.accountForFingerprint(fp).?);
    try std.testing.expect(store.accountForFingerprint("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff") == null);
}

test "rebinding a fingerprint replaces the owner" {
    const alloc = std.testing.allocator;
    var store = CertfpBindStore.init(alloc);
    defer store.deinit();

    const fp = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    try store.bind("alice", fp);
    try store.bind("bob", fp);
    try std.testing.expectEqualStrings("bob", store.accountForFingerprint(fp).?);
}

test "rejects malformed fingerprints and oversize accounts" {
    const alloc = std.testing.allocator;
    var store = CertfpBindStore.init(alloc);
    defer store.deinit();

    try std.testing.expectError(error.InvalidFingerprint, store.bind("alice", "short"));
    const fp = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const long = "a" ** (max_account_len + 1);
    try std.testing.expectError(error.AccountTooLong, store.bind(long, fp));
}

test "unbind removes a present binding" {
    const alloc = std.testing.allocator;
    var store = CertfpBindStore.init(alloc);
    defer store.deinit();

    const fp = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    try store.bind("alice", fp);
    try std.testing.expect(store.unbind(fp));
    try std.testing.expect(!store.unbind(fp));
    try std.testing.expect(store.accountForFingerprint(fp) == null);
}

//! Per-account SCRAM-SHA-256 credential store for the Mizuchi IRC daemon.
//!
//! The account database (see `services.zig`) only persists a PBKDF2 password
//! hash, which is enough to verify PLAIN but carries no SCRAM-specific material.
//! A SCRAM-SHA-256 exchange (RFC 5802 / RFC 7677) instead needs, per account, a
//! `{salt, iteration_count, StoredKey, ServerKey}` tuple so the server can run
//! the challenge/response without ever seeing the cleartext password again.
//!
//! This module owns that tuple in memory. It mirrors the account store rather
//! than persisting: the daemon repopulates it as accounts register (and could
//! backfill on load), so a restart simply re-derives nothing — clients must
//! re-register or re-identify to seed credentials. Keeping it in memory avoids
//! widening the on-disk account record format while still letting a live
//! SCRAM-SHA-256 exchange complete against a registered account.
//!
//! Storage uses an unmanaged map keyed by the canonical (lowercased) account
//! name. The map owns every key and the variable-length salt bytes; the
//! fixed-size StoredKey/ServerKey digests are stored inline by value. All bytes
//! are duplicated on insert and freed on overwrite or teardown.

const std = @import("std");

const sasl = @import("../proto/sasl.zig");
const mechrouter = @import("../proto/sasl_mechrouter.zig");
const crypto_random = @import("../crypto/random.zig");

/// SCRAM-SHA-256 digest length (StoredKey / ServerKey size), in bytes.
/// Derived from `ScramRecord` so it tracks the canonical record definition.
pub const digest_len = @typeInfo(@FieldType(sasl.ScramRecord, "stored_key")).array.len;

/// Salt length, in bytes, generated for new SCRAM credentials. 16 bytes matches
/// the account store's PBKDF2 salt width and exceeds the RFC's minimum.
pub const salt_len: usize = 16;

/// PBKDF2-HMAC-SHA256 iteration count used when deriving SCRAM credentials.
/// RFC 7677 mandates a minimum of 4096; the higher default here matches the
/// account store's password-hashing cost so SCRAM is no weaker than PLAIN.
pub const default_iterations: u32 = 100_000;

/// Errors surfaced when deriving or storing SCRAM credentials.
pub const ScramStoreError = error{
    /// Kernel entropy was unavailable while generating a salt.
    EntropyFailed,
    /// PBKDF2/HMAC key derivation rejected the parameters.
    DeriveFailed,
    /// The account name was empty or exceeded the supported length.
    InvalidAccount,
    /// Allocation failed while duplicating the key or salt.
    OutOfMemory,
};

/// Maximum supported account-name length. Matches the account store's
/// `account_max` so any registrable account name fits.
const MAX_ACCOUNT_LEN: usize = 32;

/// One account's stored SCRAM material. The salt is an owned, heap-allocated
/// slice; the digests are inline fixed arrays.
const Entry = struct {
    salt: []u8,
    iterations: u32,
    stored_key: [digest_len]u8,
    server_key: [digest_len]u8,
};

/// In-memory registry of per-account SCRAM-SHA-256 credentials.
pub const ScramStore = struct {
    allocator: std.mem.Allocator,
    /// Maps canonical account name -> SCRAM material. Keys and salt bytes owned.
    entries: std.StringHashMapUnmanaged(Entry),

    /// Create an empty store backed by `allocator`.
    pub fn init(allocator: std.mem.Allocator) ScramStore {
        return .{ .allocator = allocator, .entries = .empty };
    }

    /// Free every owned key and salt, then the backing table. The store must
    /// not be used after this call.
    pub fn deinit(self: *ScramStore) void {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            // Scrub the salt before release: it is not secret on its own, but
            // co-locating zeroization with key material keeps the policy local.
            secureZero(entry.value_ptr.salt);
            self.allocator.free(entry.value_ptr.salt);
            secureZero(&entry.value_ptr.stored_key);
            secureZero(&entry.value_ptr.server_key);
        }
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    /// Derive SCRAM-SHA-256 credentials for `account` from `password` using a
    /// freshly generated salt and `default_iterations`, then store them. An
    /// existing entry for the same account is overwritten (its prior salt and
    /// digests are freed/scrubbed first). The cleartext password is never
    /// retained.
    ///
    /// The salt is drawn from Linux `getrandom(2)` via the crypto entropy layer
    /// — never `std.crypto.random` — so it is suitable for credential material.
    pub fn deriveAndStore(
        self: *ScramStore,
        account: []const u8,
        password: []const u8,
    ) ScramStoreError!void {
        if (account.len == 0 or account.len > MAX_ACCOUNT_LEN) return error.InvalidAccount;

        var salt: [salt_len]u8 = undefined;
        crypto_random.fillOsEntropy(&salt) catch return error.EntropyFailed;

        try self.storeWithSalt(account, password, &salt, default_iterations);
        secureZero(&salt);
    }

    /// Derive and store SCRAM credentials using a caller-supplied salt and
    /// iteration count. Exposed primarily for deterministic tests and for
    /// callers that must reuse a salt; production registration should prefer
    /// `deriveAndStore`, which generates a fresh salt.
    pub fn storeWithSalt(
        self: *ScramStore,
        account: []const u8,
        password: []const u8,
        salt: []const u8,
        iterations: u32,
    ) ScramStoreError!void {
        if (account.len == 0 or account.len > MAX_ACCOUNT_LEN) return error.InvalidAccount;

        // Derive into a temporary record; the salt slice borrows the caller's
        // buffer only for the duration of derivation.
        const record = sasl.recordFromPassword(password, salt, iterations) catch
            return error.DeriveFailed;

        // Duplicate the salt into store-owned memory before touching the map so
        // a failure leaves existing state intact.
        const owned_salt = self.allocator.dupe(u8, salt) catch return error.OutOfMemory;
        errdefer self.allocator.free(owned_salt);

        const new_entry = Entry{
            .salt = owned_salt,
            .iterations = iterations,
            .stored_key = record.stored_key,
            .server_key = record.server_key,
        };

        if (self.entries.getEntry(account)) |existing| {
            // Overwrite in place: scrub and free the prior salt/digests, keep
            // the map's owned key.
            secureZero(existing.value_ptr.salt);
            self.allocator.free(existing.value_ptr.salt);
            secureZero(&existing.value_ptr.stored_key);
            secureZero(&existing.value_ptr.server_key);
            existing.value_ptr.* = new_entry;
            return;
        }

        const owned_key = self.allocator.dupe(u8, account) catch return error.OutOfMemory;
        errdefer self.allocator.free(owned_key);
        try self.entries.put(self.allocator, owned_key, new_entry);
    }

    /// Look up SCRAM credentials for `account`, returning a `ScramRecord` whose
    /// `salt` slice borrows store-owned memory. The record stays valid until the
    /// entry is overwritten or the store is torn down. Returns null for an
    /// unknown account.
    pub fn lookup(self: *const ScramStore, account: []const u8) ?sasl.ScramRecord {
        const entry = self.entries.get(account) orelse return null;
        return .{
            .salt = entry.salt,
            .iterations = entry.iterations,
            .stored_key = entry.stored_key,
            .server_key = entry.server_key,
        };
    }

    /// Adapter exposing this store as the mechrouter's SCRAM-SHA-256 credential
    /// source. The returned fat pointer borrows `self`, so the `ScramStore` must
    /// outlive every connection that copies it (own it alongside the `Server`).
    pub fn scram256Lookup(self: *ScramStore) mechrouter.Scram256Lookup {
        return .{ .ptr = self, .lookupFn = lookupThunk };
    }

    fn lookupThunk(ptr: *anyopaque, username: []const u8) ?sasl.ScramRecord {
        const self: *const ScramStore = @ptrCast(@alignCast(ptr));
        return self.lookup(username);
    }
};

fn secureZero(buf: []u8) void {
    for (buf) |*b| {
        const vp: *volatile u8 = @ptrCast(b);
        vp.* = 0;
    }
}

test "deriveAndStore then lookup returns SCRAM material for the account" {
    // Arrange
    var store = ScramStore.init(std.testing.allocator);
    defer store.deinit();

    // Act
    try store.deriveAndStore("alice", "correct horse battery staple");
    const record = store.lookup("alice");

    // Assert
    try std.testing.expect(record != null);
    try std.testing.expectEqual(@as(usize, salt_len), record.?.salt.len);
    try std.testing.expectEqual(default_iterations, record.?.iterations);
    try std.testing.expect(store.lookup("nobody") == null);
}

test "storeWithSalt is deterministic for a fixed salt and iteration count" {
    // Arrange
    var store_a = ScramStore.init(std.testing.allocator);
    defer store_a.deinit();
    var store_b = ScramStore.init(std.testing.allocator);
    defer store_b.deinit();
    const salt = "fixed-scram-salt";

    // Act
    try store_a.storeWithSalt("alice", "pencil", salt, 4096);
    try store_b.storeWithSalt("alice", "pencil", salt, 4096);
    const rec_a = store_a.lookup("alice").?;
    const rec_b = store_b.lookup("alice").?;

    // Assert
    try std.testing.expectEqualSlices(u8, &rec_a.stored_key, &rec_b.stored_key);
    try std.testing.expectEqualSlices(u8, &rec_a.server_key, &rec_b.server_key);
}

test "deriveAndStore overwrites an existing account in place" {
    // Arrange
    var store = ScramStore.init(std.testing.allocator);
    defer store.deinit();
    try store.deriveAndStore("alice", "first password value");
    const first = store.lookup("alice").?;
    var first_stored = first.stored_key;

    // Act: re-deriving with a new password (and fresh salt) replaces the entry.
    try store.deriveAndStore("alice", "second password value");
    const second = store.lookup("alice").?;

    // Assert
    try std.testing.expectEqual(@as(u32, 1), store.entries.count());
    try std.testing.expect(!std.mem.eql(u8, &first_stored, &second.stored_key));
}

test "empty or oversize account names are rejected" {
    // Arrange
    var store = ScramStore.init(std.testing.allocator);
    defer store.deinit();
    const too_long = "x" ** (MAX_ACCOUNT_LEN + 1);

    // Act / Assert
    try std.testing.expectError(error.InvalidAccount, store.deriveAndStore("", "password value here"));
    try std.testing.expectError(error.InvalidAccount, store.deriveAndStore(too_long, "password value here"));
}

test {
    std.testing.refAllDecls(@This());
}

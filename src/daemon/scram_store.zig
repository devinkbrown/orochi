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
const rwlock = @import("../substrate/rwlock.zig");

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
    lock: rwlock.RwLock = .{},
    /// Optional durable backfill source consulted by `resolve` on a miss.
    loader: ?Loader = null,

    /// Create an empty store backed by `allocator`.
    pub fn init(allocator: std.mem.Allocator) ScramStore {
        return .{ .allocator = allocator, .entries = .empty };
    }

    /// Free every owned key and salt, then the backing table. The store must
    /// not be used after this call.
    pub fn deinit(self: *ScramStore) void {
        {
            self.lock.lockExclusive();
            defer self.lock.unlockExclusive();

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
        }
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
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        if (account.len == 0 or account.len > MAX_ACCOUNT_LEN) return error.InvalidAccount;

        var salt: [salt_len]u8 = undefined;
        crypto_random.fillOsEntropy(&salt) catch return error.EntropyFailed;
        defer secureZero(&salt);

        try self.storeWithSaltUnlocked(account, password, &salt, default_iterations);
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
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        try self.storeWithSaltUnlocked(account, password, salt, iterations);
    }

    fn storeWithSaltUnlocked(
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

    /// Insert a PRECOMPUTED SCRAM record (salt, iterations, stored_key,
    /// server_key) directly, WITHOUT re-deriving from a password. Used to
    /// repopulate the store from durable storage after a restart. Overwrites any
    /// existing entry for the account.
    pub fn importRecord(self: *ScramStore, account: []const u8, record: sasl.ScramRecord) ScramStoreError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        if (account.len == 0 or account.len > MAX_ACCOUNT_LEN) return error.InvalidAccount;

        const owned_salt = self.allocator.dupe(u8, record.salt) catch return error.OutOfMemory;
        errdefer self.allocator.free(owned_salt);

        const new_entry = Entry{
            .salt = owned_salt,
            .iterations = record.iterations,
            .stored_key = record.stored_key,
            .server_key = record.server_key,
        };

        if (self.entries.getEntry(account)) |existing| {
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

    /// Backfill source for `resolve`: when an account is missing from the live
    /// store, `loadFn` is consulted (e.g. a durable on-disk mirror). The returned
    /// record's `salt` need only stay valid for the duration of the call —
    /// `resolve` copies it via `importRecord` before returning.
    pub const Loader = struct {
        ptr: *anyopaque,
        loadFn: *const fn (ptr: *anyopaque, account: []const u8) ?sasl.ScramRecord,
    };

    /// Attach (or clear) the backfill loader consulted on a `resolve` miss.
    pub fn setLoader(self: *ScramStore, loader: ?Loader) void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        self.loader = loader;
    }

    /// Resolve SCRAM credentials for `account`: the live store first, then the
    /// backfill loader (caching a hit via `importRecord`). This is the path the
    /// mechrouter uses, so a SCRAM login works after a restart even before any
    /// in-memory entry exists. Returns null when unknown everywhere.
    pub fn resolve(self: *ScramStore, account: []const u8) ?sasl.ScramRecord {
        if (self.lookup(account)) |r| return r;
        const loader = blk: {
            self.lock.lockShared();
            defer self.lock.unlockShared();
            break :blk self.loader;
        } orelse return null;
        const loaded = loader.loadFn(loader.ptr, account) orelse return null;
        self.importRecord(account, loaded) catch return null;
        return self.lookup(account);
    }

    /// Number of bytes `serializeRecord` writes: u32 iterations, u16 salt length,
    /// the salt, then the two fixed-size digests.
    pub const serialized_max = 4 + 2 + salt_len + digest_len + digest_len;

    /// Serialize a record into `out` (length `serialized_max` for a `salt_len`
    /// salt); returns the written slice. Caller persists these bytes.
    pub fn serializeRecord(record: sasl.ScramRecord, out: []u8) ?[]const u8 {
        const total = 6 + record.salt.len + digest_len + digest_len;
        if (record.salt.len > std.math.maxInt(u16) or out.len < total) return null;
        std.mem.writeInt(u32, out[0..4], record.iterations, .big);
        std.mem.writeInt(u16, out[4..6], @intCast(record.salt.len), .big);
        var off: usize = 6;
        @memcpy(out[off..][0..record.salt.len], record.salt);
        off += record.salt.len;
        @memcpy(out[off..][0..digest_len], &record.stored_key);
        off += digest_len;
        @memcpy(out[off..][0..digest_len], &record.server_key);
        off += digest_len;
        return out[0..off];
    }

    /// Parse bytes produced by `serializeRecord`. The returned record's `salt`
    /// borrows `bytes` (copy it if it must outlive them). Null on malformed input.
    pub fn deserializeRecord(bytes: []const u8) ?sasl.ScramRecord {
        if (bytes.len < 6) return null;
        const iterations = std.mem.readInt(u32, bytes[0..4], .big);
        const sl = std.mem.readInt(u16, bytes[4..6], .big);
        const need = 6 + @as(usize, sl) + digest_len + digest_len;
        if (bytes.len < need) return null;
        var rec = sasl.ScramRecord{
            .salt = bytes[6 .. 6 + sl],
            .iterations = iterations,
            .stored_key = undefined,
            .server_key = undefined,
        };
        @memcpy(&rec.stored_key, bytes[6 + sl ..][0..digest_len]);
        @memcpy(&rec.server_key, bytes[6 + sl + digest_len ..][0..digest_len]);
        return rec;
    }

    /// Look up SCRAM credentials for `account`, returning a `ScramRecord` whose
    /// `salt` slice borrows store-owned memory. The record stays valid until the
    /// entry is overwritten or the store is torn down. Returns null for an
    /// unknown account.
    pub fn lookup(self: *const ScramStore, account: []const u8) ?sasl.ScramRecord {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();

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
        self.lock.lockShared();
        defer self.lock.unlockShared();

        return .{ .ptr = self, .lookupFn = lookupThunk };
    }

    fn lookupThunk(ptr: *anyopaque, username: []const u8) ?sasl.ScramRecord {
        const self: *ScramStore = @ptrCast(@alignCast(ptr));
        return self.resolve(username);
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

const ScramMtCtx = struct {
    store: *ScramStore,
    writer_id: usize,
    iters: usize,
    failures: *std.atomic.Value(u32),

    fn writer(ctx: *ScramMtCtx) void {
        var name_buf: [MAX_ACCOUNT_LEN]u8 = undefined;
        var i: usize = 0;
        while (i < ctx.iters) : (i += 1) {
            const name = std.fmt.bufPrint(&name_buf, "scram{d}_{d}", .{ ctx.writer_id, i }) catch unreachable;
            var salt = [_]u8{@intCast(ctx.writer_id * ctx.iters + i + 1)} ** salt_len;
            ctx.store.storeWithSalt(name, "thread password value", &salt, 4096) catch {
                _ = ctx.failures.fetchAdd(1, .monotonic);
                return;
            };
        }
    }

    fn reader(ctx: *ScramMtCtx) void {
        var i: usize = 0;
        while (i < ctx.iters * 4) : (i += 1) {
            const record = ctx.store.lookup("seed") orelse {
                _ = ctx.failures.fetchAdd(1, .monotonic);
                return;
            };
            if (record.salt.len != salt_len or record.iterations != 4096) {
                _ = ctx.failures.fetchAdd(1, .monotonic);
                return;
            }
            std.mem.doNotOptimizeAway(record.stored_key);
        }
    }
};

test "ScramStore concurrent writers and readers preserve entries" {
    var store = ScramStore.init(std.testing.allocator);
    defer store.deinit();

    const seed_salt = [_]u8{0xA5} ** salt_len;
    try store.storeWithSalt("seed", "thread password value", &seed_salt, 4096);

    const writers = 4;
    const readers = 4;
    const iters = 24;
    var failures = std.atomic.Value(u32).init(0);
    var ctxs: [writers]ScramMtCtx = undefined;
    for (0..writers) |i| {
        ctxs[i] = .{ .store = &store, .writer_id = i, .iters = iters, .failures = &failures };
    }

    var threads: [writers + readers]std.Thread = undefined;
    var spawned: usize = 0;
    errdefer for (threads[0..spawned]) |t| t.join();
    for (0..writers) |i| {
        threads[spawned] = std.Thread.spawn(.{}, ScramMtCtx.writer, .{&ctxs[i]}) catch return error.SkipZigTest;
        spawned += 1;
    }
    for (0..readers) |i| {
        threads[spawned] = std.Thread.spawn(.{}, ScramMtCtx.reader, .{&ctxs[i % writers]}) catch return error.SkipZigTest;
        spawned += 1;
    }
    for (threads[0..spawned]) |t| t.join();

    try std.testing.expectEqual(@as(u32, 0), failures.load(.monotonic));
    try std.testing.expectEqual(@as(u32, 1 + writers * iters), store.entries.count());
    for (0..writers) |w| {
        var name_buf: [MAX_ACCOUNT_LEN]u8 = undefined;
        for (0..iters) |i| {
            const name = std.fmt.bufPrint(&name_buf, "scram{d}_{d}", .{ w, i }) catch unreachable;
            try std.testing.expect(store.lookup(name) != null);
        }
    }
}

test "serialize/deserialize round-trips a SCRAM record" {
    var store = ScramStore.init(std.testing.allocator);
    defer store.deinit();
    try store.deriveAndStore("alice", "pencil");
    const rec = store.lookup("alice").?;

    var buf: [ScramStore.serialized_max]u8 = undefined;
    const bytes = ScramStore.serializeRecord(rec, &buf).?;
    const back = ScramStore.deserializeRecord(bytes).?;

    try std.testing.expectEqual(rec.iterations, back.iterations);
    try std.testing.expectEqualSlices(u8, rec.salt, back.salt);
    try std.testing.expectEqualSlices(u8, &rec.stored_key, &back.stored_key);
    try std.testing.expectEqualSlices(u8, &rec.server_key, &back.server_key);
    try std.testing.expect(ScramStore.deserializeRecord("short") == null);
}

const TestLoader = struct {
    bytes: []const u8,
    fn load(ptr: *anyopaque, account: []const u8) ?sasl.ScramRecord {
        const self: *TestLoader = @ptrCast(@alignCast(ptr));
        if (!std.mem.eql(u8, account, "alice")) return null;
        return ScramStore.deserializeRecord(self.bytes);
    }
};

test "resolve backfills a missing account from the loader, then caches" {
    var src = ScramStore.init(std.testing.allocator);
    defer src.deinit();
    try src.deriveAndStore("alice", "pencil");
    var buf: [ScramStore.serialized_max]u8 = undefined;
    const bytes = ScramStore.serializeRecord(src.lookup("alice").?, &buf).?;

    var cold = ScramStore.init(std.testing.allocator);
    defer cold.deinit();
    var loader = TestLoader{ .bytes = bytes };
    cold.setLoader(.{ .ptr = &loader, .loadFn = TestLoader.load });

    try std.testing.expect(cold.lookup("alice") == null); // not cached yet
    const resolved = cold.resolve("alice").?; // backfills from loader
    try std.testing.expectEqual(src.lookup("alice").?.iterations, resolved.iterations);
    try std.testing.expect(cold.lookup("alice") != null); // now cached in-memory
    try std.testing.expect(cold.resolve("bob") == null); // loader declines
}

test {
    std.testing.refAllDecls(@This());
}

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
const rwlock = @import("../substrate/rwlock.zig");

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
    lookup_accounts: std.ArrayListUnmanaged([]u8) = .empty,
    lock: rwlock.RwLock = .{},

    pub fn init(allocator: std.mem.Allocator) CertfpBindStore {
        return .{ .allocator = allocator, .entries = .empty };
    }

    pub fn deinit(self: *CertfpBindStore) void {
        {
            self.lock.lockExclusive();
            defer self.lock.unlockExclusive();

            var it = self.entries.iterator();
            while (it.next()) |e| {
                self.allocator.free(e.key_ptr.*);
                self.allocator.free(e.value_ptr.*);
            }
            self.entries.deinit(self.allocator);
            for (self.lookup_accounts.items) |account| self.allocator.free(account);
            self.lookup_accounts.deinit(self.allocator);
        }
        self.* = undefined;
    }

    /// Bind `fingerprint` to `account`. Re-binding the same fingerprint replaces
    /// the owner (the most recent CERTADD wins). One account may own many certs.
    pub fn bind(self: *CertfpBindStore, account: []const u8, fingerprint: []const u8) CertfpBindError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

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

    /// The account owning `fingerprint`, or null. Retained by this store.
    pub fn accountForFingerprint(self: *const CertfpBindStore, fingerprint: []const u8) ?[]const u8 {
        const self_mut = @constCast(self);
        self_mut.lock.lockExclusive();
        defer self_mut.lock.unlockExclusive();

        if (fingerprint.len != certfp.fingerprint_len) return null;
        const account = self_mut.entries.get(fingerprint) orelse return null;
        const copy = self_mut.allocator.dupe(u8, account) catch return null;
        self_mut.lookup_accounts.append(self_mut.allocator, copy) catch {
            self_mut.allocator.free(copy);
            return null;
        };
        return copy;
    }

    /// Remove a binding; returns whether one was present.
    pub fn unbind(self: *CertfpBindStore, fingerprint: []const u8) bool {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

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

const CertfpMtCtx = struct {
    store: *CertfpBindStore,
    writer_id: usize,
    iters: usize,
    failures: *std.atomic.Value(u32),

    fn fpFor(out: *[certfp.fingerprint_len]u8, writer_id: usize, i: usize, suffix: usize) []const u8 {
        return std.fmt.bufPrint(out, "{x:0>64}", .{writer_id * 10000 + i * 2 + suffix + 1}) catch unreachable;
    }

    fn writer(ctx: *CertfpMtCtx) void {
        var fp_buf: [certfp.fingerprint_len]u8 = undefined;
        var tmp_buf: [certfp.fingerprint_len]u8 = undefined;
        var acct_buf: [max_account_len]u8 = undefined;
        var i: usize = 0;
        while (i < ctx.iters) : (i += 1) {
            const acct = std.fmt.bufPrint(&acct_buf, "acct{d}_{d}", .{ ctx.writer_id, i }) catch unreachable;
            const fp = fpFor(&fp_buf, ctx.writer_id, i, 0);
            ctx.store.bind(acct, fp) catch {
                _ = ctx.failures.fetchAdd(1, .monotonic);
                return;
            };

            const tmp = fpFor(&tmp_buf, ctx.writer_id, i, 1);
            ctx.store.bind(acct, tmp) catch {
                _ = ctx.failures.fetchAdd(1, .monotonic);
                return;
            };
            if (!ctx.store.unbind(tmp)) {
                _ = ctx.failures.fetchAdd(1, .monotonic);
                return;
            }
        }
    }

    fn reader(ctx: *CertfpMtCtx) void {
        const seed = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        var i: usize = 0;
        while (i < ctx.iters * 4) : (i += 1) {
            const acct = ctx.store.accountForFingerprint(seed) orelse {
                _ = ctx.failures.fetchAdd(1, .monotonic);
                return;
            };
            if (!std.mem.eql(u8, acct, "seed")) {
                _ = ctx.failures.fetchAdd(1, .monotonic);
                return;
            }
        }
    }
};

test "CertfpBindStore concurrent writers and readers preserve bindings" {
    const alloc = std.testing.allocator;
    var store = CertfpBindStore.init(alloc);
    defer store.deinit();

    const seed = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    try store.bind("seed", seed);

    const writers = 4;
    const readers = 4;
    const iters = 64;
    var failures = std.atomic.Value(u32).init(0);
    var ctxs: [writers]CertfpMtCtx = undefined;
    for (0..writers) |i| {
        ctxs[i] = .{ .store = &store, .writer_id = i, .iters = iters, .failures = &failures };
    }

    var threads: [writers + readers]std.Thread = undefined;
    var spawned: usize = 0;
    errdefer for (threads[0..spawned]) |t| t.join();
    for (0..writers) |i| {
        threads[spawned] = std.Thread.spawn(.{}, CertfpMtCtx.writer, .{&ctxs[i]}) catch return error.SkipZigTest;
        spawned += 1;
    }
    for (0..readers) |i| {
        threads[spawned] = std.Thread.spawn(.{}, CertfpMtCtx.reader, .{&ctxs[i % writers]}) catch return error.SkipZigTest;
        spawned += 1;
    }
    for (threads[0..spawned]) |t| t.join();

    try std.testing.expectEqual(@as(u32, 0), failures.load(.monotonic));
    try std.testing.expectEqual(@as(u32, 1 + writers * iters), store.entries.count());
    var fp_buf: [certfp.fingerprint_len]u8 = undefined;
    for (0..writers) |w| {
        for (0..iters) |i| {
            const fp = CertfpMtCtx.fpFor(&fp_buf, w, i, 0);
            try std.testing.expect(store.accountForFingerprint(fp) != null);
        }
    }
}

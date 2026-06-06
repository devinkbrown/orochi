//! DNS TXT domain-ownership verification state.
//!
//! This module performs no DNS I/O. The daemon resolves TXT records elsewhere
//! and feeds the TXT values into `Verifier.check`.

const std = @import("std");

comptime {
    if (@bitSizeOf(usize) != 64) @compileError("dns_verify requires a 64-bit target");
}

/// Verification result for a pending domain proof.
pub const Result = enum {
    verified,
    expired,
    no_pending,
    mismatch,
};

/// A stored pending domain proof.
///
/// The string fields are owned by `Verifier` while the pending entry is stored.
/// Values returned by `Verifier.pending` are borrowed views that remain valid
/// until the entry is replaced, cleared, swept, or the verifier is deinitialized.
pub const Pending = struct {
    /// Account that requested the proof.
    account: []const u8,
    /// Lowercase canonical domain being proved.
    domain: []const u8,
    /// Lowercase hexadecimal token expected in the TXT value.
    token: []const u8,
    /// Wall-clock issue time in milliseconds.
    issued_ms: i64,
};

/// Runtime bounds for domain verification state.
pub const Params = struct {
    /// Maximum number of pending proofs retained at once.
    max_pending: usize = 4096,
    /// Maximum account name length in bytes.
    max_account_bytes: usize = 128,
    /// Maximum domain name length in bytes.
    max_domain_bytes: usize = 255,
    /// Number of caller-supplied random bytes encoded into the token.
    token_bytes: usize = 24,
    /// Proof lifetime in milliseconds.
    ttl_ms: i64 = 15 * 60 * 1000,
};

/// Errors returned while issuing a new domain proof.
pub const VerifyError = std.mem.Allocator.Error || error{
    InvalidAccount,
    AccountTooLong,
    InvalidDomain,
    DomainTooLong,
    InvalidTokenBytes,
    RandomBytesTooShort,
    KeyTooLong,
    TokenBytesTooLong,
    TooManyPending,
};

/// Pure DNS TXT domain-ownership verifier.
pub const Verifier = struct {
    allocator: std.mem.Allocator,
    params: Params,
    entries: std.StringHashMap(Pending),

    const Self = @This();

    /// Create an empty verifier using `allocator` and `params`.
    pub fn init(allocator: std.mem.Allocator, params: Params) Self {
        return .{
            .allocator = allocator,
            .params = params,
            .entries = std.StringHashMap(Pending).init(allocator),
        };
    }

    /// Release all owned keys and pending strings.
    pub fn deinit(self: *Self) void {
        self.clearAll();
        self.entries.deinit();
        self.* = undefined;
    }

    /// Issue or replace a pending proof for `account` and `domain`.
    ///
    /// `random_bytes` must contain at least `params.token_bytes` bytes. The
    /// token is lowercase hexadecimal and is the exact TXT value the user must
    /// publish at `_mizuchi-verify.<domain>`. The returned token is borrowed
    /// from the verifier and remains valid until the entry is mutated.
    pub fn issue(
        self: *Self,
        account: []const u8,
        domain: []const u8,
        random_bytes: []const u8,
        now: i64,
    ) VerifyError![]const u8 {
        try validateAccount(self.params, account);
        try validateDomain(self.params, domain);
        if (self.params.token_bytes == 0) return error.InvalidTokenBytes;
        if (random_bytes.len < self.params.token_bytes) return error.RandomBytesTooShort;

        var next = try makePending(self.allocator, self.params, account, domain, random_bytes, now);
        errdefer freePending(self.allocator, &next);

        if (self.findStoredKey(account, domain)) |key| {
            const slot = self.entries.getPtr(key).?;
            freePending(self.allocator, slot);
            slot.* = next;
            return slot.token;
        }

        if (self.entries.count() >= self.params.max_pending) return error.TooManyPending;

        const owned_key = try makeKey(self.allocator, account, next.domain);
        errdefer self.allocator.free(owned_key);

        try self.entries.putNoClobber(owned_key, next);
        return self.entries.getPtr(owned_key).?.token;
    }

    /// Build the TXT record name for `domain` into `out`.
    ///
    /// Returns the populated prefix of `out`, or an empty slice when `domain`
    /// is invalid or `out` is too small. The domain portion is lowercased.
    pub fn recordName(self: *const Self, domain: []const u8, out: []u8) []const u8 {
        validateDomain(self.params, domain) catch return out[0..0];

        const prefix = "_mizuchi-verify.";
        const needed = prefix.len + domain.len;
        if (out.len < needed) return out[0..0];

        @memcpy(out[0..prefix.len], prefix);
        for (domain, 0..) |byte, index| {
            out[prefix.len + index] = std.ascii.toLower(byte);
        }
        return out[0..needed];
    }

    /// Check TXT values for a pending proof.
    ///
    /// Returns `.verified` when any TXT value exactly equals the stored token.
    /// This method does not remove entries; callers may use `clear` after a
    /// verified result, or `sweepExpired` for expired entries.
    pub fn check(
        self: *const Self,
        account: []const u8,
        domain: []const u8,
        txt_values: []const []const u8,
        now: i64,
    ) Result {
        validateAccount(self.params, account) catch return .no_pending;
        validateDomain(self.params, domain) catch return .no_pending;

        const stored = self.findPending(account, domain) orelse return .no_pending;
        if (isExpired(self.params, stored.*, now)) return .expired;

        for (txt_values) |value| {
            if (std.mem.eql(u8, value, stored.token)) return .verified;
        }
        return .mismatch;
    }

    /// Return the pending proof for `account` and `domain`, if present.
    ///
    /// The returned value is a borrowed view into the verifier.
    pub fn pending(self: *const Self, account: []const u8, domain: []const u8) ?Pending {
        validateAccount(self.params, account) catch return null;
        validateDomain(self.params, domain) catch return null;
        const stored = self.findPending(account, domain) orelse return null;
        return stored.*;
    }

    /// Remove and release the pending proof for `account` and `domain`.
    pub fn clear(self: *Self, account: []const u8, domain: []const u8) void {
        const key = self.findStoredKey(account, domain) orelse return;
        var removed = self.entries.fetchRemove(key).?;
        self.allocator.free(removed.key);
        freePending(self.allocator, &removed.value);
    }

    /// Remove and release every expired pending proof.
    pub fn sweepExpired(self: *Self, now: i64) void {
        while (self.findExpiredKey(now)) |key| {
            var removed = self.entries.fetchRemove(key).?;
            self.allocator.free(removed.key);
            freePending(self.allocator, &removed.value);
        }
    }

    fn clearAll(self: *Self) void {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            freePending(self.allocator, entry.value_ptr);
        }
        self.entries.clearRetainingCapacity();
    }

    fn findPending(self: *const Self, account: []const u8, domain: []const u8) ?*const Pending {
        const key = self.findStoredKey(account, domain) orelse return null;
        return self.entries.getPtr(key);
    }

    fn findStoredKey(self: *const Self, account: []const u8, domain: []const u8) ?[]const u8 {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            if (matchesPair(entry.value_ptr.*, account, domain)) return entry.key_ptr.*;
        }
        return null;
    }

    fn findExpiredKey(self: *const Self, now: i64) ?[]const u8 {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            if (isExpired(self.params, entry.value_ptr.*, now)) return entry.key_ptr.*;
        }
        return null;
    }
};

fn makePending(
    allocator: std.mem.Allocator,
    params: Params,
    account: []const u8,
    domain: []const u8,
    random_bytes: []const u8,
    now: i64,
) VerifyError!Pending {
    const account_copy = try allocator.dupe(u8, account);
    errdefer allocator.free(account_copy);

    const domain_copy = try allocator.dupe(u8, domain);
    errdefer allocator.free(domain_copy);
    for (domain_copy) |*byte| {
        byte.* = std.ascii.toLower(byte.*);
    }

    const token_len = std.math.mul(usize, params.token_bytes, 2) catch return error.TokenBytesTooLong;
    const token_copy = try allocator.alloc(u8, token_len);
    errdefer allocator.free(token_copy);
    writeHex(token_copy, random_bytes[0..params.token_bytes]);

    return .{
        .account = account_copy,
        .domain = domain_copy,
        .token = token_copy,
        .issued_ms = now,
    };
}

fn makeKey(allocator: std.mem.Allocator, account: []const u8, canonical_domain: []const u8) VerifyError![]const u8 {
    const key_with_sep = std.math.add(usize, account.len, 1) catch return error.KeyTooLong;
    const key_len = std.math.add(usize, key_with_sep, canonical_domain.len) catch return error.KeyTooLong;
    const key = try allocator.alloc(u8, key_len);
    errdefer allocator.free(key);

    @memcpy(key[0..account.len], account);
    key[account.len] = 0;
    @memcpy(key[account.len + 1 ..][0..canonical_domain.len], canonical_domain);
    return key;
}

fn freePending(allocator: std.mem.Allocator, pending_value: *Pending) void {
    allocator.free(pending_value.account);
    allocator.free(pending_value.domain);
    allocator.free(pending_value.token);
    pending_value.* = undefined;
}

fn writeHex(out: []u8, bytes: []const u8) void {
    const alphabet = "0123456789abcdef";
    for (bytes, 0..) |byte, index| {
        out[index * 2] = alphabet[byte >> 4];
        out[index * 2 + 1] = alphabet[byte & 0x0f];
    }
}

fn matchesPair(stored: Pending, account: []const u8, domain: []const u8) bool {
    return std.mem.eql(u8, stored.account, account) and std.ascii.eqlIgnoreCase(stored.domain, domain);
}

fn isExpired(params: Params, pending_value: Pending, now: i64) bool {
    if (params.ttl_ms <= 0) return true;
    const expires_ms = std.math.add(i64, pending_value.issued_ms, params.ttl_ms) catch return false;
    return now >= expires_ms;
}

fn validateAccount(params: Params, account: []const u8) VerifyError!void {
    if (account.len == 0) return error.InvalidAccount;
    if (account.len > params.max_account_bytes) return error.AccountTooLong;
    for (account) |byte| {
        if (byte == 0 or byte <= 0x20 or byte == 0x7f) return error.InvalidAccount;
    }
}

fn validateDomain(params: Params, domain: []const u8) VerifyError!void {
    if (domain.len == 0) return error.InvalidDomain;
    if (domain.len > params.max_domain_bytes) return error.DomainTooLong;
    if (domain.len > 255) return error.DomainTooLong;
    if (domain[0] == '.' or domain[domain.len - 1] == '.') return error.InvalidDomain;

    var label_len: usize = 0;
    var label_start: usize = 0;
    for (domain, 0..) |byte, index| {
        switch (byte) {
            'a'...'z', 'A'...'Z', '0'...'9', '-' => {
                if (label_len == 0) label_start = index;
                label_len += 1;
                if (label_len > 63) return error.InvalidDomain;
            },
            '.' => {
                if (!validLabel(domain[label_start..index])) return error.InvalidDomain;
                label_len = 0;
                label_start = index + 1;
            },
            else => return error.InvalidDomain,
        }
    }

    if (!validLabel(domain[label_start..])) return error.InvalidDomain;
}

fn validLabel(label: []const u8) bool {
    if (label.len == 0 or label.len > 63) return false;
    if (label[0] == '-' or label[label.len - 1] == '-') return false;
    return true;
}

const testing = std.testing;

test "issue returns token and recordName formats lowercase TXT name" {
    // Arrange.
    var verifier = Verifier.init(testing.allocator, .{ .token_bytes = 3 });
    defer verifier.deinit();
    const random = [_]u8{ 0xab, 0xcd, 0xef };
    var out: [64]u8 = undefined;

    // Act.
    const token = try verifier.issue("alice", "Example.COM", &random, 1_000);
    const record = verifier.recordName("Example.COM", &out);

    // Assert.
    try testing.expectEqualStrings("abcdef", token);
    try testing.expectEqualStrings("_mizuchi-verify.example.com", record);
    const stored = verifier.pending("alice", "example.com").?;
    try testing.expectEqualStrings("example.com", stored.domain);
}

test "check returns verified when any TXT value matches token" {
    // Arrange.
    var verifier = Verifier.init(testing.allocator, .{ .token_bytes = 2, .ttl_ms = 100 });
    defer verifier.deinit();
    const random = [_]u8{ 0x12, 0x34 };
    const token = try verifier.issue("alice", "example.net", &random, 10);
    const txt_values = [_][]const u8{ "wrong", token, "other" };

    // Act.
    const result = verifier.check("alice", "EXAMPLE.NET", &txt_values, 50);

    // Assert.
    try testing.expectEqual(Result.verified, result);
}

test "check returns mismatch when TXT values do not match token" {
    // Arrange.
    var verifier = Verifier.init(testing.allocator, .{ .token_bytes = 2, .ttl_ms = 100 });
    defer verifier.deinit();
    const random = [_]u8{ 0x12, 0x34 };
    try testing.expectEqualStrings("1234", try verifier.issue("alice", "example.net", &random, 10));
    const txt_values = [_][]const u8{ "1235", "abcd" };

    // Act.
    const result = verifier.check("alice", "example.net", &txt_values, 50);

    // Assert.
    try testing.expectEqual(Result.mismatch, result);
}

test "check returns expired when pending token is past ttl" {
    // Arrange.
    var verifier = Verifier.init(testing.allocator, .{ .token_bytes = 2, .ttl_ms = 100 });
    defer verifier.deinit();
    const random = [_]u8{ 0x12, 0x34 };
    try testing.expectEqualStrings("1234", try verifier.issue("alice", "example.net", &random, 10));
    const txt_values = [_][]const u8{"1234"};

    // Act.
    const result = verifier.check("alice", "example.net", &txt_values, 110);

    // Assert.
    try testing.expectEqual(Result.expired, result);
}

test "check returns no_pending when no entry exists" {
    // Arrange.
    var verifier = Verifier.init(testing.allocator, .{});
    defer verifier.deinit();
    const txt_values = [_][]const u8{"anything"};

    // Act.
    const result = verifier.check("alice", "example.net", &txt_values, 1);

    // Assert.
    try testing.expectEqual(Result.no_pending, result);
}

test "issue replaces prior token for same account and domain" {
    // Arrange.
    var verifier = Verifier.init(testing.allocator, .{ .token_bytes = 2 });
    defer verifier.deinit();
    const first_random = [_]u8{ 0x12, 0x34 };
    const second_random = [_]u8{ 0xab, 0xcd };

    // Act.
    const first = try verifier.issue("alice", "Example.NET", &first_random, 10);
    try testing.expectEqualStrings("1234", first);
    const second = try verifier.issue("alice", "example.net", &second_random, 20);
    const stored = verifier.pending("alice", "EXAMPLE.NET").?;

    // Assert.
    try testing.expectEqualStrings("abcd", second);
    try testing.expectEqualStrings("abcd", stored.token);
    try testing.expectEqual(@as(i64, 20), stored.issued_ms);
    try testing.expectEqual(@as(usize, 1), verifier.entries.count());
}

test "sweepExpired frees expired entries and keeps live entries" {
    // Arrange.
    var verifier = Verifier.init(testing.allocator, .{ .token_bytes = 1, .ttl_ms = 50 });
    defer verifier.deinit();
    const first_random = [_]u8{0x01};
    const second_random = [_]u8{0x02};
    try testing.expectEqualStrings("01", try verifier.issue("alice", "old.example", &first_random, 10));
    try testing.expectEqualStrings("02", try verifier.issue("bob", "new.example", &second_random, 80));

    // Act.
    verifier.sweepExpired(100);

    // Assert.
    try testing.expectEqual(@as(?Pending, null), verifier.pending("alice", "old.example"));
    try testing.expect(verifier.pending("bob", "new.example") != null);
}

test "clear removes stored proof and deinit releases remaining entries" {
    // Arrange.
    var verifier = Verifier.init(testing.allocator, .{ .token_bytes = 1 });
    defer verifier.deinit();
    const first_random = [_]u8{0x01};
    const second_random = [_]u8{0x02};
    try testing.expectEqualStrings("01", try verifier.issue("alice", "one.example", &first_random, 10));
    try testing.expectEqualStrings("02", try verifier.issue("bob", "two.example", &second_random, 20));

    // Act.
    verifier.clear("alice", "ONE.EXAMPLE");

    // Assert.
    try testing.expectEqual(@as(?Pending, null), verifier.pending("alice", "one.example"));
    try testing.expect(verifier.pending("bob", "two.example") != null);
}

test "bounds reject invalid input and full pending set" {
    // Arrange.
    var verifier = Verifier.init(testing.allocator, .{
        .max_pending = 1,
        .max_account_bytes = 5,
        .max_domain_bytes = 11,
        .token_bytes = 2,
    });
    defer verifier.deinit();
    const random = [_]u8{ 0x12, 0x34 };
    const short_random = [_]u8{0x12};

    // Act.
    try testing.expectEqualStrings("1234", try verifier.issue("alice", "example.net", &random, 1));

    // Assert.
    try testing.expectError(error.AccountTooLong, verifier.issue("longer", "other.net", &random, 2));
    try testing.expectError(error.InvalidAccount, verifier.issue("bad x", "other.net", &random, 2));
    try testing.expectError(error.DomainTooLong, verifier.issue("bob", "too-long.example", &random, 2));
    try testing.expectError(error.InvalidDomain, verifier.issue("bob", "-bad.net", &random, 2));
    try testing.expectError(error.RandomBytesTooShort, verifier.issue("bob", "other.net", &short_random, 2));
    try testing.expectError(error.TooManyPending, verifier.issue("bob", "other.net", &random, 2));
}

test "recordName returns empty slice for invalid domain or small output" {
    // Arrange.
    var verifier = Verifier.init(testing.allocator, .{});
    defer verifier.deinit();
    var small: [8]u8 = undefined;
    var enough: [64]u8 = undefined;

    // Act.
    const too_small = verifier.recordName("example.net", &small);
    const invalid = verifier.recordName("bad_domain", &enough);

    // Assert.
    try testing.expectEqual(@as(usize, 0), too_small.len);
    try testing.expectEqual(@as(usize, 0), invalid.len);
}

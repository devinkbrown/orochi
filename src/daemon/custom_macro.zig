//! Per-account custom text macros for the Orochi IRC daemon.
//!
//! A macro maps a short name to an expansion string, scoped to the owning
//! account. Lookups use a composite key of "account\x00name" so that distinct
//! accounts can independently define identically named macros without
//! collision. Names are bounded to keep keys compact; expansions are bounded
//! to keep memory predictable. Each account may hold at most a fixed number of
//! macros.

const std = @import("std");

/// Maximum length, in bytes, of a macro name.
pub const max_name_len: usize = 32;

/// Maximum length, in bytes, of a macro expansion.
pub const max_expansion_len: usize = 400;

/// Maximum number of macros a single account may define.
pub const max_per_account: usize = 100;

/// Byte separating the account segment from the name segment in a composite
/// key. NUL can never appear in a valid account or name, so it is an
/// unambiguous delimiter.
const key_sep: u8 = 0x00;

/// Errors returned when a macro definition is rejected.
pub const MacroError = error{
    /// The name or expansion was empty, oversized, or otherwise unusable.
    InvalidMacro,
} || std.mem.Allocator.Error;

/// Owns a set of per-account text macros.
///
/// All keys and values are heap-owned by this structure; callers retain
/// ownership of nothing they pass in. `expand` returns a borrowed slice valid
/// only until the next mutating call for that key.
pub const CustomMacro = struct {
    allocator: std.mem.Allocator,
    /// Composite-key ("account\x00name") -> owned expansion text.
    entries: std.StringHashMapUnmanaged([]u8),

    /// Creates an empty macro store backed by `allocator`.
    pub fn init(allocator: std.mem.Allocator) CustomMacro {
        return .{
            .allocator = allocator,
            .entries = .{},
        };
    }

    /// Frees every owned key and expansion, then releases the table.
    pub fn deinit(self: *CustomMacro) void {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    /// Defines (or overwrites) the macro `name` for `account`.
    ///
    /// On overwrite the previous expansion is freed and the existing key is
    /// reused. Empty or oversized names/expansions are rejected with
    /// `error.InvalidMacro`. A fresh definition that would exceed
    /// `max_per_account` for the account is also rejected.
    pub fn define(
        self: *CustomMacro,
        account: []const u8,
        name: []const u8,
        expansion: []const u8,
    ) MacroError!void {
        if (!isValidName(name)) return error.InvalidMacro;
        if (!isValidExpansion(expansion)) return error.InvalidMacro;

        var key_buf: [max_name_len + 1 + 256]u8 = undefined;
        const key = composeKey(&key_buf, account, name) orelse
            return error.InvalidMacro;

        if (self.entries.getEntry(key)) |entry| {
            // Overwrite: reuse the existing key, swap the expansion.
            const new_val = try self.allocator.dupe(u8, expansion);
            self.allocator.free(entry.value_ptr.*);
            entry.value_ptr.* = new_val;
            return;
        }

        // Fresh definition: enforce the per-account cap first.
        if (self.countAccount(account) >= max_per_account) {
            return error.InvalidMacro;
        }

        const owned_key = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(owned_key);
        const owned_val = try self.allocator.dupe(u8, expansion);
        errdefer self.allocator.free(owned_val);

        try self.entries.putNoClobber(self.allocator, owned_key, owned_val);
    }

    /// Returns the expansion for `account`'s macro `name`, or null if absent.
    ///
    /// The returned slice is owned by the store and remains valid until the
    /// macro is overwritten, undefined, or the store is deinitialized.
    pub fn expand(self: *const CustomMacro, account: []const u8, name: []const u8) ?[]const u8 {
        if (!isValidName(name)) return null;
        var key_buf: [max_name_len + 1 + 256]u8 = undefined;
        const key = composeKey(&key_buf, account, name) orelse return null;
        return self.entries.get(key);
    }

    /// Removes `account`'s macro `name`. Returns true if a macro was removed.
    pub fn undefine(self: *CustomMacro, account: []const u8, name: []const u8) bool {
        if (!isValidName(name)) return false;
        var key_buf: [max_name_len + 1 + 256]u8 = undefined;
        const key = composeKey(&key_buf, account, name) orelse return false;

        if (self.entries.fetchRemove(key)) |kv| {
            self.allocator.free(kv.key);
            self.allocator.free(kv.value);
            return true;
        }
        return false;
    }

    /// Removes every macro owned by `account`. Returns the count removed.
    pub fn clearAccount(self: *CustomMacro, account: []const u8) usize {
        var removed: usize = 0;
        var it = self.entries.iterator();
        // Collect matching keys first; mutating during iteration is unsafe.
        var doomed: std.ArrayList([]const u8) = .empty;
        defer doomed.deinit(self.allocator);

        while (it.next()) |entry| {
            if (keyMatchesAccount(entry.key_ptr.*, account)) {
                // Best-effort: if recording fails, fall back to direct removal
                // after iteration cannot proceed; but appends rarely fail.
                doomed.append(self.allocator, entry.key_ptr.*) catch {
                    // On OOM, free what we can directly and continue.
                    continue;
                };
            }
        }

        for (doomed.items) |key| {
            if (self.entries.fetchRemove(key)) |kv| {
                self.allocator.free(kv.key);
                self.allocator.free(kv.value);
                removed += 1;
            }
        }
        return removed;
    }

    /// Counts the macros currently owned by `account`.
    fn countAccount(self: *const CustomMacro, account: []const u8) usize {
        var count: usize = 0;
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            if (keyMatchesAccount(entry.key_ptr.*, account)) count += 1;
        }
        return count;
    }
};

/// Validates a macro name: non-empty, within bound, and free of the key
/// separator (NUL).
fn isValidName(name: []const u8) bool {
    if (name.len == 0 or name.len > max_name_len) return false;
    return std.mem.indexOfScalar(u8, name, key_sep) == null;
}

/// Validates an expansion: non-empty and within bound.
fn isValidExpansion(expansion: []const u8) bool {
    return expansion.len != 0 and expansion.len <= max_expansion_len;
}

/// Writes "account\x00name" into `buf`, returning the populated slice, or null
/// if it would not fit. Account must not contain the separator byte.
fn composeKey(buf: []u8, account: []const u8, name: []const u8) ?[]const u8 {
    if (std.mem.indexOfScalar(u8, account, key_sep) != null) return null;
    const total = account.len + 1 + name.len;
    if (total > buf.len) return null;
    @memcpy(buf[0..account.len], account);
    buf[account.len] = key_sep;
    @memcpy(buf[account.len + 1 ..][0..name.len], name);
    return buf[0..total];
}

/// Reports whether `key` ("account\x00name") belongs to `account`.
fn keyMatchesAccount(key: []const u8, account: []const u8) bool {
    if (key.len < account.len + 1) return false;
    if (!std.mem.eql(u8, key[0..account.len], account)) return false;
    return key[account.len] == key_sep;
}

test "define, expand, and overwrite" {
    const a = std.testing.allocator;
    var store = CustomMacro.init(a);
    defer store.deinit();

    try store.define("alice", "greet", "hello there");
    try std.testing.expectEqualStrings("hello there", store.expand("alice", "greet").?);

    // Overwrite frees the old expansion and installs the new one.
    try store.define("alice", "greet", "good evening");
    try std.testing.expectEqualStrings("good evening", store.expand("alice", "greet").?);

    // Rejections.
    try std.testing.expectError(error.InvalidMacro, store.define("alice", "", "x"));
    try std.testing.expectError(error.InvalidMacro, store.define("alice", "ok", ""));
    const big_name = "n" ** (max_name_len + 1);
    try std.testing.expectError(error.InvalidMacro, store.define("alice", big_name, "x"));
    const big_exp = "e" ** (max_expansion_len + 1);
    try std.testing.expectError(error.InvalidMacro, store.define("alice", "ok", big_exp));

    // Missing lookup yields null.
    try std.testing.expect(store.expand("alice", "nope") == null);
}

test "undefine removes only the targeted macro" {
    const a = std.testing.allocator;
    var store = CustomMacro.init(a);
    defer store.deinit();

    try store.define("bob", "one", "first");
    try store.define("bob", "two", "second");

    try std.testing.expect(store.undefine("bob", "one"));
    try std.testing.expect(store.expand("bob", "one") == null);
    try std.testing.expectEqualStrings("second", store.expand("bob", "two").?);

    // Removing again, or removing the unknown, returns false.
    try std.testing.expect(!store.undefine("bob", "one"));
    try std.testing.expect(!store.undefine("bob", "missing"));
}

test "clearAccount is scoped to one account" {
    const a = std.testing.allocator;
    var store = CustomMacro.init(a);
    defer store.deinit();

    try store.define("carol", "x", "cx");
    try store.define("carol", "y", "cy");
    try store.define("dave", "x", "dx");

    const removed = store.clearAccount("carol");
    try std.testing.expectEqual(@as(usize, 2), removed);

    // Carol's macros are gone; Dave's identically named macro survives.
    try std.testing.expect(store.expand("carol", "x") == null);
    try std.testing.expect(store.expand("carol", "y") == null);
    try std.testing.expectEqualStrings("dx", store.expand("dave", "x").?);

    // Clearing an account with nothing returns zero.
    try std.testing.expectEqual(@as(usize, 0), store.clearAccount("carol"));
}

test "per-account cap is enforced for fresh definitions" {
    const a = std.testing.allocator;
    var store = CustomMacro.init(a);
    defer store.deinit();

    var i: usize = 0;
    var buf: [max_name_len]u8 = undefined;
    while (i < max_per_account) : (i += 1) {
        const name = try std.fmt.bufPrint(&buf, "m{d}", .{i});
        try store.define("erin", name, "v");
    }
    // One more fresh macro is rejected.
    try std.testing.expectError(error.InvalidMacro, store.define("erin", "overflow", "v"));
    // Overwriting an existing one is still allowed at the cap.
    try store.define("erin", "m0", "changed");
    try std.testing.expectEqualStrings("changed", store.expand("erin", "m0").?);
}

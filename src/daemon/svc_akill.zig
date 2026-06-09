//! Pure AKILL store and parser for network-wide service bans.
//!
//! This module intentionally contains no daemon, protocol, dispatch, or services
//! imports. The live daemon can wire these records to real server commands and
//! numerics; this file only owns AKILL data, parses service command payloads,
//! matches masks, and prunes expired entries.

const std = @import("std");

/// Runtime limits for an AKILL store.
pub const Params = struct {
    max_entries: usize = 4096,
    max_mask: usize = 256,
    max_reason: usize = 512,
    max_setter: usize = 64,
};

/// Store mutation and validation errors.
pub const AkillError = std.mem.Allocator.Error || error{
    EmptyMask,
    EmptyReason,
    EmptySetter,
    MaskTooLong,
    ReasonTooLong,
    SetterTooLong,
    TooManyEntries,
    InvalidExpiry,
};

/// Parser errors for service AKILL command payloads.
pub const ParseError = error{
    EmptyCommand,
    UnknownCommand,
    MissingDuration,
    MissingMask,
    MissingReason,
    TrailingInput,
    InvalidDuration,
    DurationTooLarge,
    InvalidExpiry,
};

/// A single network AKILL. String fields are owned by `Store` after `add`.
pub const Akill = struct {
    mask: []const u8,
    reason: []const u8,
    setter: []const u8,
    added_at: i64,
    /// Absolute expiry in epoch milliseconds. Null means permanent.
    expires_at: ?i64 = null,

    pub fn isExpired(self: Akill, now_ms: i64) bool {
        return if (self.expires_at) |expiry| expiry <= now_ms else false;
    }
};

/// Parsed AKILL service command. Slices borrow from the input line and setter.
pub const Command = union(enum) {
    add: Akill,
    remove: []const u8,
    list,
};

/// Owned AKILL registry with insertion-ordered listing.
pub const Store = struct {
    allocator: std.mem.Allocator,
    params: Params,
    entries: std.ArrayListUnmanaged(Akill) = .empty,

    pub fn init(allocator: std.mem.Allocator, params: Params) Store {
        return .{ .allocator = allocator, .params = params };
    }

    pub fn deinit(self: *Store) void {
        for (self.entries.items) |*entry| freeAkill(self.allocator, entry);
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    /// Add or replace an AKILL by mask, case-insensitively. Strings are cloned.
    pub fn add(self: *Store, entry: Akill) AkillError!*const Akill {
        try self.validate(entry);

        const existing = self.indexOf(entry.mask);
        if (existing == null and self.entries.items.len >= self.params.max_entries) {
            return error.TooManyEntries;
        }

        var owned = try self.clone(entry);
        errdefer freeAkill(self.allocator, &owned);

        if (existing) |index| {
            freeAkill(self.allocator, &self.entries.items[index]);
            self.entries.items[index] = owned;
            return &self.entries.items[index];
        }

        try self.entries.append(self.allocator, owned);
        return &self.entries.items[self.entries.items.len - 1];
    }

    /// Remove an AKILL by mask, case-insensitively. Returns true if present.
    pub fn remove(self: *Store, mask: []const u8) bool {
        const index = self.indexOf(mask) orelse return false;
        var removed = self.entries.orderedRemove(index);
        freeAkill(self.allocator, &removed);
        return true;
    }

    /// Copy stored AKILLs into `out` in insertion order.
    pub fn list(self: *const Store, out: []Akill) []const Akill {
        const n = @min(out.len, self.entries.items.len);
        @memcpy(out[0..n], self.entries.items[0..n]);
        return out[0..n];
    }

    /// Return the first active AKILL matching `hostmask`, or null.
    ///
    /// Expired AKILLs are swept as a side effect, so the returned pointer always
    /// points at an active entry still owned by the store.
    pub fn matches(self: *Store, hostmask: []const u8, now_ms: i64) ?*const Akill {
        if (hostmask.len == 0) return null;
        _ = self.sweepExpired(now_ms);
        for (self.entries.items) |*entry| {
            if (globMatch(entry.mask, hostmask)) return entry;
        }
        return null;
    }

    /// Remove expired entries and return the number swept.
    pub fn sweepExpired(self: *Store, now_ms: i64) usize {
        var swept: usize = 0;
        var i: usize = 0;
        while (i < self.entries.items.len) {
            if (self.entries.items[i].isExpired(now_ms)) {
                var removed = self.entries.orderedRemove(i);
                freeAkill(self.allocator, &removed);
                swept += 1;
            } else {
                i += 1;
            }
        }
        return swept;
    }

    pub fn count(self: *const Store) usize {
        return self.entries.items.len;
    }

    fn validate(self: *const Store, entry: Akill) AkillError!void {
        if (entry.mask.len == 0) return error.EmptyMask;
        if (entry.reason.len == 0) return error.EmptyReason;
        if (entry.setter.len == 0) return error.EmptySetter;
        if (entry.mask.len > self.params.max_mask) return error.MaskTooLong;
        if (entry.reason.len > self.params.max_reason) return error.ReasonTooLong;
        if (entry.setter.len > self.params.max_setter) return error.SetterTooLong;
        if (entry.expires_at) |expiry| {
            if (expiry <= entry.added_at) return error.InvalidExpiry;
        }
    }

    fn clone(self: *Store, entry: Akill) std.mem.Allocator.Error!Akill {
        const mask = try self.allocator.dupe(u8, entry.mask);
        errdefer self.allocator.free(mask);
        const reason = try self.allocator.dupe(u8, entry.reason);
        errdefer self.allocator.free(reason);
        const setter = try self.allocator.dupe(u8, entry.setter);
        return .{
            .mask = mask,
            .reason = reason,
            .setter = setter,
            .added_at = entry.added_at,
            .expires_at = entry.expires_at,
        };
    }

    fn indexOf(self: *const Store, mask: []const u8) ?usize {
        for (self.entries.items, 0..) |entry, index| {
            if (std.ascii.eqlIgnoreCase(entry.mask, mask)) return index;
        }
        return null;
    }
};

fn freeAkill(allocator: std.mem.Allocator, entry: *Akill) void {
    allocator.free(entry.mask);
    allocator.free(entry.reason);
    allocator.free(entry.setter);
    entry.* = undefined;
}

/// Parse a service AKILL payload:
///
///   ADD <duration> <mask> :<reason>
///   REMOVE <mask>
///   LIST
///
/// Duration accepts `permanent`, `perm`, `0`, or a positive integer with an
/// optional suffix: `ms`, `s`, `m`, `h`, `d`, `w`. Plain integers are seconds.
pub fn parseCommand(line: []const u8, setter: []const u8, now_ms: i64) ParseError!Command {
    var cursor: usize = 0;
    const verb = nextToken(line, &cursor) orelse return error.EmptyCommand;

    if (std.ascii.eqlIgnoreCase(verb, "ADD")) {
        const duration = nextToken(line, &cursor) orelse return error.MissingDuration;
        const mask = nextToken(line, &cursor) orelse return error.MissingMask;
        var reason = trimSpaces(line[cursor..]);
        if (reason.len == 0) return error.MissingReason;
        if (reason[0] == ':') reason = trimSpaces(reason[1..]);
        if (reason.len == 0) return error.MissingReason;
        const expires_at = try expiryFromDuration(duration, now_ms);
        return .{ .add = .{
            .mask = mask,
            .reason = reason,
            .setter = setter,
            .added_at = now_ms,
            .expires_at = expires_at,
        } };
    }

    if (std.ascii.eqlIgnoreCase(verb, "REMOVE") or
        std.ascii.eqlIgnoreCase(verb, "DEL") or
        std.ascii.eqlIgnoreCase(verb, "DELETE") or
        std.ascii.eqlIgnoreCase(verb, "RM"))
    {
        const mask = nextToken(line, &cursor) orelse return error.MissingMask;
        if (trimSpaces(line[cursor..]).len != 0) return error.TrailingInput;
        return .{ .remove = mask };
    }

    if (std.ascii.eqlIgnoreCase(verb, "LIST")) {
        if (trimSpaces(line[cursor..]).len != 0) return error.TrailingInput;
        return .list;
    }

    return error.UnknownCommand;
}

/// Parse a duration token to milliseconds. Null means permanent.
pub fn parseDurationMs(token: []const u8) ParseError!?u64 {
    const raw = trimSpaces(token);
    if (raw.len == 0) return error.InvalidDuration;
    if (std.ascii.eqlIgnoreCase(raw, "permanent") or
        std.ascii.eqlIgnoreCase(raw, "perm") or
        std.ascii.eqlIgnoreCase(raw, "never"))
    {
        return null;
    }

    var digits_len: usize = 0;
    while (digits_len < raw.len and std.ascii.isDigit(raw[digits_len])) {
        digits_len += 1;
    }
    if (digits_len == 0) return error.InvalidDuration;

    const value = std.fmt.parseInt(u64, raw[0..digits_len], 10) catch return error.InvalidDuration;
    const suffix = raw[digits_len..];
    if (value == 0) {
        if (suffix.len == 0) return null;
        return error.InvalidDuration;
    }

    const multiplier: u64 = if (suffix.len == 0 or std.ascii.eqlIgnoreCase(suffix, "s"))
        1000
    else if (std.ascii.eqlIgnoreCase(suffix, "ms"))
        1
    else if (std.ascii.eqlIgnoreCase(suffix, "m"))
        60 * 1000
    else if (std.ascii.eqlIgnoreCase(suffix, "h"))
        60 * 60 * 1000
    else if (std.ascii.eqlIgnoreCase(suffix, "d"))
        24 * 60 * 60 * 1000
    else if (std.ascii.eqlIgnoreCase(suffix, "w"))
        7 * 24 * 60 * 60 * 1000
    else
        return error.InvalidDuration;

    return std.math.mul(u64, value, multiplier) catch error.DurationTooLarge;
}

fn expiryFromDuration(token: []const u8, now_ms: i64) ParseError!?i64 {
    const duration = try parseDurationMs(token) orelse return null;
    const duration_i64 = std.math.cast(i64, duration) orelse return error.DurationTooLarge;
    if (now_ms > std.math.maxInt(i64) - duration_i64) return error.DurationTooLarge;
    const expiry = now_ms + duration_i64;
    if (expiry <= now_ms) return error.InvalidExpiry;
    return expiry;
}

/// Iterative, case-insensitive `*`/`?` glob matcher for IRC hostmasks.
pub fn globMatch(pattern: []const u8, text: []const u8) bool {
    var p: usize = 0;
    var t: usize = 0;
    var star: ?usize = null;
    var mark: usize = 0;

    while (t < text.len) {
        if (p < pattern.len and (pattern[p] == '?' or std.ascii.toLower(pattern[p]) == std.ascii.toLower(text[t]))) {
            p += 1;
            t += 1;
        } else if (p < pattern.len and pattern[p] == '*') {
            star = p;
            mark = t;
            p += 1;
        } else if (star) |s| {
            p = s + 1;
            mark += 1;
            t = mark;
        } else {
            return false;
        }
    }

    while (p < pattern.len and pattern[p] == '*') p += 1;
    return p == pattern.len;
}

fn nextToken(input: []const u8, cursor: *usize) ?[]const u8 {
    while (cursor.* < input.len and isSpace(input[cursor.*])) cursor.* += 1;
    if (cursor.* >= input.len) return null;
    const start = cursor.*;
    while (cursor.* < input.len and !isSpace(input[cursor.*])) cursor.* += 1;
    return input[start..cursor.*];
}

fn trimSpaces(input: []const u8) []const u8 {
    return std.mem.trim(u8, input, " \t\r\n");
}

fn isSpace(byte: u8) bool {
    return byte == ' ' or byte == '\t' or byte == '\r' or byte == '\n';
}

fn mk(mask: []const u8, reason: []const u8, expires_at: ?i64) Akill {
    return .{
        .mask = mask,
        .reason = reason,
        .setter = "OperServ",
        .added_at = 1000,
        .expires_at = expires_at,
    };
}

test "parse add with timed duration and trailing reason" {
    const parsed = try parseCommand("ADD 10m *!*@bad.example :spambots", "services.example", 1_000);
    switch (parsed) {
        .add => |entry| {
            try std.testing.expectEqualStrings("*!*@bad.example", entry.mask);
            try std.testing.expectEqualStrings("spambots", entry.reason);
            try std.testing.expectEqualStrings("services.example", entry.setter);
            try std.testing.expectEqual(@as(i64, 1_000), entry.added_at);
            try std.testing.expectEqual(@as(?i64, 601_000), entry.expires_at);
        },
        else => return error.TestExpectedEqual,
    }
}

test "parse permanent add remove aliases and list" {
    const permanent = try parseCommand("add permanent *@*.bad :network abuse", "oper", 50);
    try std.testing.expectEqual(@as(?i64, null), permanent.add.expires_at);

    const zero = try parseCommand("ADD 0 *@*.bad :network abuse", "oper", 50);
    try std.testing.expectEqual(@as(?i64, null), zero.add.expires_at);

    const del = try parseCommand("DEL *@*.bad", "oper", 50);
    try std.testing.expectEqualStrings("*@*.bad", del.remove);

    const list = try parseCommand("LIST", "oper", 50);
    try std.testing.expectEqual(std.meta.Tag(Command).list, std.meta.activeTag(list));
}

test "parse rejects malformed commands" {
    try std.testing.expectError(error.EmptyCommand, parseCommand("   ", "oper", 0));
    try std.testing.expectError(error.UnknownCommand, parseCommand("KILL *@bad :x", "oper", 0));
    try std.testing.expectError(error.MissingDuration, parseCommand("ADD", "oper", 0));
    try std.testing.expectError(error.MissingMask, parseCommand("ADD 1h", "oper", 0));
    try std.testing.expectError(error.MissingReason, parseCommand("ADD 1h *@bad", "oper", 0));
    try std.testing.expectError(error.TrailingInput, parseCommand("REMOVE *@bad extra", "oper", 0));
    try std.testing.expectError(error.TrailingInput, parseCommand("LIST extra", "oper", 0));
}

test "parse duration units and overflow" {
    try std.testing.expectEqual(@as(?u64, 1), try parseDurationMs("1ms"));
    try std.testing.expectEqual(@as(?u64, 2_000), try parseDurationMs("2"));
    try std.testing.expectEqual(@as(?u64, 3_000), try parseDurationMs("3s"));
    try std.testing.expectEqual(@as(?u64, 4 * 60 * 1000), try parseDurationMs("4m"));
    try std.testing.expectEqual(@as(?u64, 5 * 60 * 60 * 1000), try parseDurationMs("5h"));
    try std.testing.expectEqual(@as(?u64, 6 * 24 * 60 * 60 * 1000), try parseDurationMs("6d"));
    try std.testing.expectEqual(@as(?u64, 7 * 7 * 24 * 60 * 60 * 1000), try parseDurationMs("7w"));
    try std.testing.expectEqual(@as(?u64, null), try parseDurationMs("never"));
    try std.testing.expectError(error.InvalidDuration, parseDurationMs("ms"));
    try std.testing.expectError(error.InvalidDuration, parseDurationMs("1x"));
    try std.testing.expectError(error.InvalidDuration, parseDurationMs("0s"));
    try std.testing.expectError(error.DurationTooLarge, parseDurationMs("18446744073709551615w"));
}

test "add list match and case-insensitive glob" {
    var store = Store.init(std.testing.allocator, .{});
    defer store.deinit();

    _ = try store.add(mk("*!*@*.Evil.Example", "bad host", null));
    _ = try store.add(mk("sp?m!*@host.test", "bad nick", null));

    var out: [4]Akill = undefined;
    const listed = store.list(&out);
    try std.testing.expectEqual(@as(usize, 2), listed.len);
    try std.testing.expectEqualStrings("bad host", listed[0].reason);

    const host_hit = store.matches("bob!~b@leaf.evil.example", 2_000).?;
    try std.testing.expectEqualStrings("*!*@*.Evil.Example", host_hit.mask);
    const nick_hit = store.matches("spam!u@host.test", 2_000).?;
    try std.testing.expectEqualStrings("sp?m!*@host.test", nick_hit.mask);
    try std.testing.expect(store.matches("alice!u@good.example", 2_000) == null);
}

test "add replaces same mask case-insensitively without changing count" {
    var store = Store.init(std.testing.allocator, .{});
    defer store.deinit();

    _ = try store.add(mk("*!*@dup.example", "first", null));
    _ = try store.add(mk("*!*@DUP.EXAMPLE", "second", 5_000));

    try std.testing.expectEqual(@as(usize, 1), store.count());
    const hit = store.matches("a!b@dup.example", 2_000).?;
    try std.testing.expectEqualStrings("second", hit.reason);
    try std.testing.expectEqual(@as(?i64, 5_000), hit.expires_at);
}

test "remove by mask is case-insensitive" {
    var store = Store.init(std.testing.allocator, .{});
    defer store.deinit();

    _ = try store.add(mk("*!*@remove.example", "gone", null));
    try std.testing.expect(store.remove("*!*@REMOVE.EXAMPLE"));
    try std.testing.expect(!store.remove("*!*@remove.example"));
    try std.testing.expectEqual(@as(usize, 0), store.count());
}

test "matches returns only active entries and sweeps expired" {
    var store = Store.init(std.testing.allocator, .{});
    defer store.deinit();

    _ = try store.add(mk("*!*@temporary.example", "short", 2_000));
    try std.testing.expect(store.matches("a!b@temporary.example", 1_999) != null);
    try std.testing.expect(store.matches("a!b@temporary.example", 2_000) == null);
    try std.testing.expectEqual(@as(usize, 0), store.count());
}

test "sweep removes all expired entries and leaves permanent entries" {
    var store = Store.init(std.testing.allocator, .{});
    defer store.deinit();

    _ = try store.add(mk("*!*@a.example", "a", 1_500));
    _ = try store.add(mk("*!*@b.example", "b", 2_500));
    _ = try store.add(mk("*!*@c.example", "c", null));

    try std.testing.expectEqual(@as(usize, 1), store.sweepExpired(2_000));
    try std.testing.expectEqual(@as(usize, 2), store.count());
    try std.testing.expectEqual(@as(usize, 1), store.sweepExpired(3_000));
    try std.testing.expectEqual(@as(usize, 1), store.count());
    try std.testing.expect(store.matches("x!y@c.example", 4_000) != null);
}

test "store validates limits and expiry" {
    var store = Store.init(std.testing.allocator, .{ .max_entries = 1, .max_mask = 8, .max_reason = 4, .max_setter = 4 });
    defer store.deinit();

    try std.testing.expectError(error.EmptyMask, store.add(mk("", "bad", null)));
    try std.testing.expectError(error.EmptyReason, store.add(mk("*@bad", "", null)));

    var no_setter = mk("*@bad", "bad", null);
    no_setter.setter = "";
    try std.testing.expectError(error.EmptySetter, store.add(no_setter));

    try std.testing.expectError(error.MaskTooLong, store.add(mk("toolong-mask", "bad", null)));
    try std.testing.expectError(error.ReasonTooLong, store.add(mk("*@bad", "longer", null)));

    var long_setter = mk("*@bad", "bad", null);
    long_setter.setter = "setter";
    try std.testing.expectError(error.SetterTooLong, store.add(long_setter));

    var invalid_expiry = mk("*@bad", "bad", 1000);
    invalid_expiry.setter = "oper";
    try std.testing.expectError(error.InvalidExpiry, store.add(invalid_expiry));

    var ok = mk("*@ok", "bad", null);
    ok.setter = "oper";
    _ = try store.add(ok);

    var two = mk("*@two", "bad", null);
    two.setter = "oper";
    try std.testing.expectError(error.TooManyEntries, store.add(two));
}

test "glob matcher covers star question backtracking and empty text" {
    try std.testing.expect(globMatch("*", ""));
    try std.testing.expect(globMatch("*!*@*.example", "n!u@a.b.example"));
    try std.testing.expect(globMatch("a*b?d", "aZZbXd"));
    try std.testing.expect(globMatch("CASE*", "casefold"));
    try std.testing.expect(!globMatch("a?c", "ac"));
    try std.testing.expect(!globMatch("*@bad.example", "nick!user@good.example"));
}

test "no leak under add replace remove and sweep churn" {
    var store = Store.init(std.testing.allocator, .{ .max_entries = 128 });
    defer store.deinit();

    for (0..80) |i| {
        var mask_buf: [48]u8 = undefined;
        var reason_buf: [48]u8 = undefined;
        const mask = try std.fmt.bufPrint(&mask_buf, "*!*@host{d}.example", .{i % 16});
        const reason = try std.fmt.bufPrint(&reason_buf, "reason {d}", .{i});
        _ = try store.add(.{
            .mask = mask,
            .reason = reason,
            .setter = "OperServ",
            .added_at = @intCast(i),
            .expires_at = @intCast(i + 1_000),
        });
    }

    try std.testing.expect(store.count() <= 16);
    _ = store.sweepExpired(2_000);
    try std.testing.expectEqual(@as(usize, 0), store.count());

    for (0..32) |i| {
        var mask_buf: [48]u8 = undefined;
        const mask = try std.fmt.bufPrint(&mask_buf, "*!*@remove{d}.example", .{i});
        _ = try store.add(mk(mask, "remove", null));
        try std.testing.expect(store.remove(mask));
    }
}

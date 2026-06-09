//! Per-account metadata for the Mizuchi IRC daemon.
//!
//! This module is deliberately separate from IRCv3 METADATA. It models one real
//! server command, `ACCTMETA`, plus numeric reply metadata that a daemon command
//! handler can render without introducing services pseudo-clients.

const std = @import("std");

pub const command_name = "ACCTMETA";

pub const max_accounts: usize = 65536;
pub const max_account_bytes: usize = 64;
pub const max_url_bytes: usize = 200;
pub const max_location_bytes: usize = 80;
pub const max_pronouns_bytes: usize = 32;
pub const max_timezone_bytes: usize = 48;

const field_count: usize = 4;

/// Mizuchi-local server numerics for the `ACCTMETA` command surface.
pub const Numeric = enum(u16) {
    RPL_ACCTMETA = 778,
    RPL_ACCTMETAEND = 779,
    ERR_ACCTMETAKEY = 780,
    ERR_ACCTMETAVALUE = 781,
};

/// Allowed account metadata keys. Unknown keys are rejected rather than stored.
pub const Field = enum(u8) {
    url,
    location,
    pronouns,
    timezone,
};

pub const EntryView = struct {
    key: []const u8,
    value: []const u8,
};

pub const Query = struct {
    account: []const u8,
    field: Field,
};

pub const SetRequest = struct {
    account: []const u8,
    field: Field,
    value: []const u8,
};

pub const Request = union(enum) {
    set: SetRequest,
    get: Query,
    delete: Query,
    list: []const u8,
};

pub const ApplyResult = union(enum) {
    set,
    value: ?[]const u8,
    deleted: bool,
    list: []const EntryView,
};

pub const Error = std.mem.Allocator.Error || error{
    InvalidAccount,
    KeyNotAllowed,
    ValueTooLong,
    InvalidValue,
    TooManyAccounts,
    OutputTooSmall,
};

pub const ParseError = Error || error{
    EmptyLine,
    UnsupportedCommand,
    NeedMoreParams,
};

const StoredAccount = struct {
    values: [field_count]?[]u8 = [_]?[]u8{null} ** field_count,

    fn deinit(self: *StoredAccount, allocator: std.mem.Allocator) void {
        for (&self.values) |*maybe_value| {
            if (maybe_value.*) |value| allocator.free(value);
            maybe_value.* = null;
        }
    }

    fn set(self: *StoredAccount, allocator: std.mem.Allocator, field: Field, value: []const u8) std.mem.Allocator.Error!void {
        const index = fieldIndex(field);
        const owned = try allocator.dupe(u8, value);
        errdefer allocator.free(owned);

        if (self.values[index]) |old| allocator.free(old);
        self.values[index] = owned;
    }

    fn get(self: *const StoredAccount, field: Field) ?[]const u8 {
        return self.values[fieldIndex(field)];
    }

    fn delete(self: *StoredAccount, allocator: std.mem.Allocator, field: Field) bool {
        const index = fieldIndex(field);
        const value = self.values[index] orelse return false;
        allocator.free(value);
        self.values[index] = null;
        return true;
    }

    fn list(self: *const StoredAccount, out: []EntryView) Error![]const EntryView {
        var needed: usize = 0;
        for (all_fields) |field| {
            if (self.values[fieldIndex(field)] != null) needed += 1;
        }
        if (out.len < needed) return error.OutputTooSmall;

        var written: usize = 0;
        for (all_fields) |field| {
            if (self.values[fieldIndex(field)]) |value| {
                out[written] = .{ .key = fieldName(field), .value = value };
                written += 1;
            }
        }
        return out[0..written];
    }

    fn empty(self: *const StoredAccount) bool {
        for (self.values) |maybe_value| {
            if (maybe_value != null) return false;
        }
        return true;
    }
};

pub const Store = struct {
    allocator: std.mem.Allocator,
    accounts: std.StringHashMap(StoredAccount),
    max_account_count: usize,

    pub fn init(allocator: std.mem.Allocator) Store {
        return initWithLimit(allocator, max_accounts);
    }

    pub fn initWithLimit(allocator: std.mem.Allocator, max_account_count: usize) Store {
        return .{
            .allocator = allocator,
            .accounts = std.StringHashMap(StoredAccount).init(allocator),
            .max_account_count = max_account_count,
        };
    }

    pub fn deinit(self: *Store) void {
        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.accounts.deinit();
        self.* = undefined;
    }

    /// Set an allowlisted account metadata value. Account keys are canonicalized
    /// to lowercase; values are heap-owned by this store.
    pub fn set(self: *Store, account: []const u8, field: Field, value: []const u8) Error!void {
        var key_buf: [max_account_bytes]u8 = undefined;
        const account_key = try accountKey(account, &key_buf);
        try validateValue(field, value);

        if (self.accounts.getPtr(account_key)) |stored| {
            try stored.set(self.allocator, field, value);
            return;
        }

        if (self.accounts.count() >= self.max_account_count) return error.TooManyAccounts;

        const owned_key = try self.allocator.dupe(u8, account_key);
        errdefer self.allocator.free(owned_key);
        var stored = StoredAccount{};
        errdefer stored.deinit(self.allocator);
        try stored.set(self.allocator, field, value);
        try self.accounts.putNoClobber(owned_key, stored);
    }

    /// Return a borrowed value for one account metadata key, if it exists.
    pub fn get(self: *const Store, account: []const u8, field: Field) ?[]const u8 {
        var key_buf: [max_account_bytes]u8 = undefined;
        const account_key = accountKey(account, &key_buf) catch return null;
        const stored = self.accounts.get(account_key) orelse return null;
        return stored.get(field);
    }

    /// Delete one metadata key. Empty account records are dropped immediately.
    pub fn delete(self: *Store, account: []const u8, field: Field) bool {
        var key_buf: [max_account_bytes]u8 = undefined;
        const account_key = accountKey(account, &key_buf) catch return false;
        const entry = self.accounts.getEntry(account_key) orelse return false;
        if (!entry.value_ptr.delete(self.allocator, field)) return false;

        if (entry.value_ptr.empty()) {
            const owned_key = entry.key_ptr.*;
            var stored = entry.value_ptr.*;
            self.accounts.removeByPtr(entry.key_ptr);
            stored.deinit(self.allocator);
            self.allocator.free(owned_key);
        }
        return true;
    }

    /// List metadata for an account in stable allowlist order.
    pub fn list(self: *const Store, account: []const u8, out: []EntryView) Error![]const EntryView {
        var key_buf: [max_account_bytes]u8 = undefined;
        const account_key = try accountKey(account, &key_buf);
        const stored = self.accounts.get(account_key) orelse return out[0..0];
        return stored.list(out);
    }

    pub fn countAccounts(self: *const Store) usize {
        return self.accounts.count();
    }

    pub fn countFields(self: *const Store, account: []const u8) usize {
        var out: [field_count]EntryView = undefined;
        return (self.list(account, &out) catch return 0).len;
    }

    /// Apply a parsed request. `list_out` is used only for `.list` requests.
    pub fn apply(self: *Store, request: Request, list_out: []EntryView) Error!ApplyResult {
        return switch (request) {
            .set => |req| blk: {
                try self.set(req.account, req.field, req.value);
                break :blk .{ .set = {} };
            },
            .get => |req| .{ .value = self.get(req.account, req.field) },
            .delete => |req| .{ .deleted = self.delete(req.account, req.field) },
            .list => |account| .{ .list = try self.list(account, list_out) },
        };
    }
};

pub fn parseField(key: []const u8) ?Field {
    for (all_fields) |field| {
        if (std.ascii.eqlIgnoreCase(key, fieldName(field))) return field;
    }
    return null;
}

pub fn fieldName(field: Field) []const u8 {
    return switch (field) {
        .url => "url",
        .location => "location",
        .pronouns => "pronouns",
        .timezone => "timezone",
    };
}

pub fn maxValueBytes(field: Field) usize {
    return switch (field) {
        .url => max_url_bytes,
        .location => max_location_bytes,
        .pronouns => max_pronouns_bytes,
        .timezone => max_timezone_bytes,
    };
}

/// Parse one IRC command line for `ACCTMETA`.
///
/// Accepted forms:
/// - `ACCTMETA <account> SET <key> :<value>`
/// - `ACCTMETA <account> GET <key>`
/// - `ACCTMETA <account> DELETE <key>`
/// - `ACCTMETA <account> LIST`
pub fn parseLine(line: []const u8) ParseError!Request {
    var cursor = Cursor.init(trimLine(line));
    if (cursor.peekWord()) |first| {
        if (first.len > 0 and first[0] == '@') _ = cursor.nextWord().?;
    }
    if (cursor.peekWord()) |first| {
        if (first.len > 0 and first[0] == ':') _ = cursor.nextWord().?;
    }

    const command = cursor.next() orelse return error.EmptyLine;
    if (!std.ascii.eqlIgnoreCase(command, command_name)) return error.UnsupportedCommand;

    const account = cursor.next() orelse return error.NeedMoreParams;
    try validateAccount(account);
    const verb = cursor.next() orelse return error.NeedMoreParams;

    if (std.ascii.eqlIgnoreCase(verb, "LIST")) {
        return .{ .list = account };
    }

    const key = cursor.next() orelse return error.NeedMoreParams;
    const field = parseField(key) orelse return error.KeyNotAllowed;

    if (std.ascii.eqlIgnoreCase(verb, "GET")) {
        return .{ .get = .{ .account = account, .field = field } };
    }
    if (std.ascii.eqlIgnoreCase(verb, "DELETE") or std.ascii.eqlIgnoreCase(verb, "DEL")) {
        return .{ .delete = .{ .account = account, .field = field } };
    }
    if (std.ascii.eqlIgnoreCase(verb, "SET")) {
        const value = cursor.next() orelse return error.NeedMoreParams;
        try validateValue(field, value);
        return .{ .set = .{ .account = account, .field = field, .value = value } };
    }

    return error.UnsupportedCommand;
}

fn validateAccount(account: []const u8) Error!void {
    if (account.len == 0 or account.len > max_account_bytes) return error.InvalidAccount;
    for (account) |byte| {
        if (!isAccountChar(byte)) return error.InvalidAccount;
    }
}

fn accountKey(account: []const u8, out: *[max_account_bytes]u8) Error![]const u8 {
    try validateAccount(account);
    for (account, 0..) |byte, index| {
        out[index] = std.ascii.toLower(byte);
    }
    return out[0..account.len];
}

fn validateValue(field: Field, value: []const u8) Error!void {
    if (value.len > maxValueBytes(field)) return error.ValueTooLong;
    for (value) |byte| {
        if (byte < 0x20 or byte == 0x7f) return error.InvalidValue;
    }
}

fn isAccountChar(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or byte == '_' or byte == '-' or byte == '.';
}

fn fieldIndex(field: Field) usize {
    return @intFromEnum(field);
}

const all_fields = [_]Field{ .url, .location, .pronouns, .timezone };

const Cursor = struct {
    line: []const u8,
    pos: usize = 0,

    fn init(line: []const u8) Cursor {
        return .{ .line = line };
    }

    fn peekWord(self: *Cursor) ?[]const u8 {
        const saved = self.pos;
        const token = self.nextWord();
        self.pos = saved;
        return token;
    }

    fn nextWord(self: *Cursor) ?[]const u8 {
        while (self.pos < self.line.len and self.line[self.pos] == ' ') self.pos += 1;
        if (self.pos >= self.line.len) return null;

        const start = self.pos;
        while (self.pos < self.line.len and self.line[self.pos] != ' ') self.pos += 1;
        return self.line[start..self.pos];
    }

    fn next(self: *Cursor) ?[]const u8 {
        while (self.pos < self.line.len and self.line[self.pos] == ' ') self.pos += 1;
        if (self.pos >= self.line.len) return null;

        if (self.line[self.pos] == ':') {
            const value = self.line[self.pos + 1 ..];
            self.pos = self.line.len;
            return value;
        }

        const start = self.pos;
        while (self.pos < self.line.len and self.line[self.pos] != ' ') self.pos += 1;
        return self.line[start..self.pos];
    }
};

fn trimLine(line: []const u8) []const u8 {
    var end = line.len;
    while (end > 0 and (line[end - 1] == '\r' or line[end - 1] == '\n')) end -= 1;
    return line[0..end];
}

const testing = std.testing;

test "set get delete and case-normalized account keys" {
    var store = Store.init(testing.allocator);
    defer store.deinit();

    var source = [_]u8{ 'h', 't', 't', 'p', 's', ':', '/', '/', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 't', 'e', 's', 't' };
    try store.set("Alice", .url, &source);
    source[8] = 'X';

    try testing.expectEqualStrings("https://example.test", store.get("alice", .url).?);
    try testing.expectEqualStrings("https://example.test", store.get("ALICE", .url).?);
    try testing.expectEqual(@as(usize, 1), store.countAccounts());
    try testing.expectEqual(@as(usize, 1), store.countFields("alice"));

    try store.set("alice", .location, "Osaka");
    try testing.expect(store.delete("ALICE", .url));
    try testing.expect(store.get("alice", .url) == null);
    try testing.expectEqualStrings("Osaka", store.get("alice", .location).?);
    try testing.expectEqual(@as(usize, 1), store.countAccounts());

    try testing.expect(store.delete("alice", .location));
    try testing.expectEqual(@as(usize, 0), store.countAccounts());
}

test "replace owns the new value and preserves other fields" {
    var store = Store.init(testing.allocator);
    defer store.deinit();

    try store.set("bob", .pronouns, "he/him");
    try store.set("bob", .timezone, "UTC");
    try store.set("bob", .pronouns, "they/them");

    try testing.expectEqualStrings("they/them", store.get("bob", .pronouns).?);
    try testing.expectEqualStrings("UTC", store.get("bob", .timezone).?);
}

test "list returns stable allowlist order and checks caller buffer size" {
    var store = Store.init(testing.allocator);
    defer store.deinit();

    try store.set("carol", .timezone, "Europe/Berlin");
    try store.set("carol", .url, "https://example.test/carol");
    try store.set("carol", .pronouns, "she/her");

    var too_small: [2]EntryView = undefined;
    try testing.expectError(error.OutputTooSmall, store.list("carol", &too_small));

    var out: [field_count]EntryView = undefined;
    const entries = try store.list("carol", &out);
    try testing.expectEqual(@as(usize, 3), entries.len);
    try testing.expectEqualStrings("url", entries[0].key);
    try testing.expectEqualStrings("https://example.test/carol", entries[0].value);
    try testing.expectEqualStrings("pronouns", entries[1].key);
    try testing.expectEqualStrings("she/her", entries[1].value);
    try testing.expectEqualStrings("timezone", entries[2].key);
    try testing.expectEqualStrings("Europe/Berlin", entries[2].value);

    const missing = try store.list("nobody", &out);
    try testing.expectEqual(@as(usize, 0), missing.len);
}

test "allowlist account and value bounds are enforced" {
    var store = Store.initWithLimit(testing.allocator, 1);
    defer store.deinit();

    try testing.expect(parseField("bio") == null);
    try testing.expectEqual(Field.url, parseField("URL").?);
    try testing.expectError(error.InvalidAccount, store.set("", .url, "https://example.test"));
    try testing.expectError(error.InvalidAccount, store.set("bad account", .url, "https://example.test"));

    const too_long_url = "x" ** (max_url_bytes + 1);
    try testing.expectError(error.ValueTooLong, store.set("alice", .url, too_long_url));
    try testing.expectError(error.InvalidValue, store.set("alice", .location, "bad\nplace"));

    try store.set("alice", .timezone, "UTC");
    try testing.expectError(error.TooManyAccounts, store.set("bob", .timezone, "UTC"));
}

test "parse ACCTMETA command lines with prefix tags and trailing values" {
    const parsed = try parseLine("@label=1 :nick!u@h ACCTMETA Alice SET url :https://example.test/a b");
    switch (parsed) {
        .set => |req| {
            try testing.expectEqualStrings("Alice", req.account);
            try testing.expectEqual(Field.url, req.field);
            try testing.expectEqualStrings("https://example.test/a b", req.value);
        },
        else => return error.TestUnexpectedResult,
    }

    const get = try parseLine("ACCTMETA alice GET PRONOUNS\r\n");
    switch (get) {
        .get => |req| {
            try testing.expectEqualStrings("alice", req.account);
            try testing.expectEqual(Field.pronouns, req.field);
        },
        else => return error.TestUnexpectedResult,
    }

    const del = try parseLine("ACCTMETA alice DEL timezone");
    switch (del) {
        .delete => |req| try testing.expectEqual(Field.timezone, req.field),
        else => return error.TestUnexpectedResult,
    }

    const list = try parseLine("ACCTMETA alice LIST");
    switch (list) {
        .list => |account| try testing.expectEqualStrings("alice", account),
        else => return error.TestUnexpectedResult,
    }
}

test "parse rejects non-ACCTMETA commands and bad parameters" {
    try testing.expectError(error.UnsupportedCommand, parseLine("PRIVMSG helper :SET url https://example.test"));
    try testing.expectError(error.NeedMoreParams, parseLine("ACCTMETA alice SET url"));
    try testing.expectError(error.KeyNotAllowed, parseLine("ACCTMETA alice GET bio"));
    try testing.expectError(error.ValueTooLong, parseLine("ACCTMETA alice SET pronouns :" ++ ("p" ** (max_pronouns_bytes + 1))));
}

test "apply executes parsed requests without allocating for parser state" {
    var store = Store.init(testing.allocator);
    defer store.deinit();

    var list_out: [field_count]EntryView = undefined;
    _ = try store.apply(try parseLine("ACCTMETA dave SET location :Berlin"), &list_out);
    _ = try store.apply(try parseLine("ACCTMETA dave SET timezone :Europe/Berlin"), &list_out);

    const value = try store.apply(try parseLine("ACCTMETA dave GET location"), &list_out);
    switch (value) {
        .value => |maybe_value| try testing.expectEqualStrings("Berlin", maybe_value.?),
        else => return error.TestUnexpectedResult,
    }

    const listed = try store.apply(try parseLine("ACCTMETA dave LIST"), &list_out);
    switch (listed) {
        .list => |entries| {
            try testing.expectEqual(@as(usize, 2), entries.len);
            try testing.expectEqualStrings("location", entries[0].key);
            try testing.expectEqualStrings("timezone", entries[1].key);
        },
        else => return error.TestUnexpectedResult,
    }

    const deleted = try store.apply(try parseLine("ACCTMETA dave DELETE timezone"), &list_out);
    switch (deleted) {
        .deleted => |ok| try testing.expect(ok),
        else => return error.TestUnexpectedResult,
    }
    try testing.expect(store.get("dave", .timezone) == null);
}

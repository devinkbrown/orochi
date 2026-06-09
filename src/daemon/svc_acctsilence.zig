//! Account-scoped server-side silence lists.
//!
//! This module is deliberately standalone and std-only so it can be tested and
//! integrated independently. It models a real daemon command, `ACCTSILENCE`,
//! and real numeric replies for listing entries. It does not route through
//! pseudo-client service users.

const std = @import("std");

/// Native server command parsed by this module.
pub const command_name = "ACCTSILENCE";

/// Standard SILENCE list numerics reused for the account-scoped list view.
pub const RPL_SILELIST: u16 = 271;
pub const RPL_ENDOFSILELIST: u16 = 272;
pub const ERR_UNKNOWNCOMMAND: u16 = 421;
pub const ERR_NEEDMOREPARAMS: u16 = 461;

pub const DEFAULT_MAX_ENTRIES_PER_ACCOUNT: usize = 64;
pub const DEFAULT_MAX_ACCOUNT_BYTES: usize = 64;
pub const DEFAULT_MAX_MASK_BYTES: usize = 128;
pub const DEFAULT_MAX_LINE_BYTES: usize = 512;
pub const DEFAULT_MAX_SERVER_BYTES: usize = 255;
pub const DEFAULT_MAX_REQUESTER_BYTES: usize = 64;

pub const AcctSilenceError = std.mem.Allocator.Error || error{
    InvalidCommand,
    InvalidAction,
    InvalidKind,
    InvalidAccount,
    InvalidMask,
    AccountTooLong,
    MaskTooLong,
    LimitReached,
    OutputTooSmall,
    LineTooLong,
    InvalidServerName,
    InvalidRequester,
};

pub const Params = struct {
    max_entries_per_account: usize = DEFAULT_MAX_ENTRIES_PER_ACCOUNT,
    max_account_bytes: usize = DEFAULT_MAX_ACCOUNT_BYTES,
    max_mask_bytes: usize = DEFAULT_MAX_MASK_BYTES,
    max_line_bytes: usize = DEFAULT_MAX_LINE_BYTES,
    max_server_bytes: usize = DEFAULT_MAX_SERVER_BYTES,
    max_requester_bytes: usize = DEFAULT_MAX_REQUESTER_BYTES,
};

/// Message class affected by a silence entry.
pub const Kind = enum {
    all,
    privmsg,
    notice,
    tagmsg,

    pub fn parse(bytes: []const u8) AcctSilenceError!Kind {
        if (asciiEql(bytes, "all")) return .all;
        if (asciiEql(bytes, "privmsg")) return .privmsg;
        if (asciiEql(bytes, "notice")) return .notice;
        if (asciiEql(bytes, "tagmsg")) return .tagmsg;
        return error.InvalidKind;
    }

    pub fn tag(self: Kind) []const u8 {
        return switch (self) {
            .all => "all",
            .privmsg => "privmsg",
            .notice => "notice",
            .tagmsg => "tagmsg",
        };
    }

    pub fn covers(self: Kind, requested: Kind) bool {
        return self == .all or self == requested or requested == .all;
    }
};

pub const Action = enum {
    list,
    add,
    remove,

    pub fn parse(bytes: []const u8) AcctSilenceError!Action {
        if (asciiEql(bytes, "list")) return .list;
        if (asciiEql(bytes, "add")) return .add;
        if (asciiEql(bytes, "+")) return .add;
        if (asciiEql(bytes, "remove")) return .remove;
        if (asciiEql(bytes, "del")) return .remove;
        if (asciiEql(bytes, "delete")) return .remove;
        if (asciiEql(bytes, "-")) return .remove;
        return error.InvalidAction;
    }
};

pub const Entry = struct {
    kind: Kind,
    mask: []const u8,
};

pub const Request = union(Action) {
    list,
    add: Entry,
    remove: Entry,
};

pub const ReplyContext = struct {
    server_name: []const u8,
    requester: []const u8,
};

pub const Store = struct {
    allocator: std.mem.Allocator,
    params: Params,
    accounts: std.StringHashMap(AccountList),

    pub fn init(allocator: std.mem.Allocator) Store {
        return initWithParams(allocator, .{});
    }

    pub fn initWithParams(allocator: std.mem.Allocator, params: Params) Store {
        return .{
            .allocator = allocator,
            .params = params,
            .accounts = std.StringHashMap(AccountList).init(allocator),
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

    /// Add `mask` for `account` and `kind`. Returns false for duplicates.
    pub fn add(self: *Store, account: []const u8, mask: []const u8, kind: Kind) AcctSilenceError!bool {
        try validateAccount(account, self.params.max_account_bytes);
        try validateMask(mask, self.params.max_mask_bytes);

        if (self.findAccount(account)) |entry| {
            return entry.value_ptr.add(self.allocator, self.params.max_entries_per_account, .{
                .kind = kind,
                .mask = mask,
            });
        }

        const account_copy = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(account_copy);

        const gop = try self.accounts.getOrPut(account_copy);
        if (gop.found_existing) {
            self.allocator.free(account_copy);
            return gop.value_ptr.add(self.allocator, self.params.max_entries_per_account, .{
                .kind = kind,
                .mask = mask,
            });
        }

        gop.key_ptr.* = account_copy;
        gop.value_ptr.* = .{};
        errdefer {
            const owned_key = gop.key_ptr.*;
            gop.value_ptr.deinit(self.allocator);
            self.accounts.removeByPtr(gop.key_ptr);
            self.allocator.free(owned_key);
        }

        return gop.value_ptr.add(self.allocator, self.params.max_entries_per_account, .{
            .kind = kind,
            .mask = mask,
        });
    }

    /// Remove exactly `mask` and `kind` from `account`. Returns false when absent.
    pub fn remove(self: *Store, account: []const u8, mask: []const u8, kind: Kind) AcctSilenceError!bool {
        try validateAccount(account, self.params.max_account_bytes);
        try validateMask(mask, self.params.max_mask_bytes);

        const entry = self.findAccount(account) orelse return false;
        const removed = entry.value_ptr.remove(self.allocator, .{ .kind = kind, .mask = mask });
        if (entry.value_ptr.entries.items.len == 0) {
            const owned_key = entry.key_ptr.*;
            entry.value_ptr.deinit(self.allocator);
            self.accounts.removeByPtr(entry.key_ptr);
            self.allocator.free(owned_key);
        }
        return removed;
    }

    /// Copy `account`'s entries into caller storage in insertion order.
    pub fn list(self: *const Store, account: []const u8, out: []Entry) AcctSilenceError![]const Entry {
        try validateAccount(account, self.params.max_account_bytes);
        const account_list = self.findAccountConst(account) orelse return out[0..0];
        if (account_list.entries.items.len > out.len) return error.OutputTooSmall;

        for (account_list.entries.items, 0..) |entry, index| {
            out[index] = .{ .kind = entry.kind, .mask = entry.mask };
        }
        return out[0..account_list.entries.items.len];
    }

    /// Return true when `account` has silenced `sender_hostmask` for `kind`.
    pub fn isSilenced(self: *const Store, account: []const u8, sender_hostmask: []const u8, kind: Kind) bool {
        _ = parseHostmask(sender_hostmask) orelse return false;
        const account_list = self.findAccountConst(account) orelse return false;
        for (account_list.entries.items) |entry| {
            if (entry.kind.covers(kind) and hostmaskGlobMatch(entry.mask, sender_hostmask)) return true;
        }
        return false;
    }

    /// Apply a parsed request for `account`. `list` returns false because it does
    /// not mutate the store; add/remove return whether the store changed.
    pub fn apply(self: *Store, account: []const u8, request: Request) AcctSilenceError!bool {
        return switch (request) {
            .list => false,
            .add => |entry| try self.add(account, entry.mask, entry.kind),
            .remove => |entry| try self.remove(account, entry.mask, entry.kind),
        };
    }

    fn findAccount(self: *Store, account: []const u8) ?std.StringHashMap(AccountList).Entry {
        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            if (asciiEql(entry.key_ptr.*, account)) return entry;
        }
        return null;
    }

    fn findAccountConst(self: *const Store, account: []const u8) ?*const AccountList {
        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            if (asciiEql(entry.key_ptr.*, account)) return entry.value_ptr;
        }
        return null;
    }
};

const OwnedEntry = struct {
    kind: Kind,
    mask: []u8,
};

const AccountList = struct {
    entries: std.ArrayList(OwnedEntry) = .empty,

    fn deinit(self: *AccountList, allocator: std.mem.Allocator) void {
        for (self.entries.items) |entry| allocator.free(entry.mask);
        self.entries.deinit(allocator);
    }

    fn add(self: *AccountList, allocator: std.mem.Allocator, max_entries: usize, entry: Entry) AcctSilenceError!bool {
        for (self.entries.items) |existing| {
            if (existing.kind == entry.kind and asciiEql(existing.mask, entry.mask)) return false;
        }
        if (self.entries.items.len >= max_entries) return error.LimitReached;

        const mask_copy = try allocator.dupe(u8, entry.mask);
        errdefer allocator.free(mask_copy);
        try self.entries.append(allocator, .{ .kind = entry.kind, .mask = mask_copy });
        return true;
    }

    fn remove(self: *AccountList, allocator: std.mem.Allocator, entry: Entry) bool {
        for (self.entries.items, 0..) |existing, index| {
            if (existing.kind == entry.kind and asciiEql(existing.mask, entry.mask)) {
                const owned = self.entries.orderedRemove(index);
                allocator.free(owned.mask);
                return true;
            }
        }
        return false;
    }
};

/// Parse `ACCTSILENCE` parameters after the command has already been split.
pub fn parse(params: []const []const u8) AcctSilenceError!Request {
    if (params.len == 0) return .list;
    const action = try Action.parse(params[0]);
    return switch (action) {
        .list => {
            if (params.len != 1) return error.InvalidAction;
            return .list;
        },
        .add, .remove => {
            if (params.len != 3) return error.InvalidAction;
            const kind = try Kind.parse(params[1]);
            try validateMask(params[2], DEFAULT_MAX_MASK_BYTES);
            const entry = Entry{ .kind = kind, .mask = params[2] };
            return switch (action) {
                .add => .{ .add = entry },
                .remove => .{ .remove = entry },
                .list => unreachable,
            };
        },
    };
}

/// Parse a raw command line such as `ACCTSILENCE ADD all *!*@bad.example`.
pub fn parseLine(line: []const u8) AcctSilenceError!Request {
    const trimmed = std.mem.trim(u8, line, " \t\r\n");
    if (trimmed.len == 0) return error.InvalidCommand;

    var parts = std.mem.tokenizeAny(u8, trimmed, " \t");
    const command = parts.next() orelse return error.InvalidCommand;
    if (!asciiEql(command, command_name)) return error.InvalidCommand;

    var params_buf: [3][]const u8 = undefined;
    var count: usize = 0;
    while (parts.next()) |part| {
        if (count == params_buf.len) return error.InvalidAction;
        params_buf[count] = part;
        count += 1;
    }

    return parse(params_buf[0..count]);
}

/// Match `pattern` against `sender_hostmask` as `nick!user@host` components.
/// `*` matches any byte run and `?` matches one byte, case-insensitively.
pub fn hostmaskGlobMatch(pattern: []const u8, sender_hostmask: []const u8) bool {
    const pattern_mask = parseHostmask(pattern) orelse return false;
    const sender_mask = parseHostmask(sender_hostmask) orelse return false;

    return globMatch(pattern_mask.nick, sender_mask.nick) and
        globMatch(pattern_mask.user, sender_mask.user) and
        globMatch(pattern_mask.host, sender_mask.host);
}

/// Write one `RPL_SILELIST` line for an account-silence entry.
pub fn writeListNumeric(out: []u8, ctx: ReplyContext, entry: Entry) AcctSilenceError![]const u8 {
    return writeListNumericWith(.{}, out, ctx, entry);
}

pub fn writeListNumericWith(comptime params: Params, out: []u8, ctx: ReplyContext, entry: Entry) AcctSilenceError![]const u8 {
    try validateContext(params, ctx);
    try validateMask(entry.mask, params.max_mask_bytes);

    var b = LineBuilder.init(out, params.max_line_bytes);
    try b.numericPrefix(RPL_SILELIST, ctx.server_name, ctx.requester);
    try b.spaceParam(entry.kind.tag());
    try b.spaceParam(entry.mask);
    try b.spaceTrailing("is account-silenced");
    try b.crlf();
    return b.slice();
}

/// Write the terminating `RPL_ENDOFSILELIST` line for account-silence listing.
pub fn writeEndOfListNumeric(out: []u8, ctx: ReplyContext) AcctSilenceError![]const u8 {
    return writeEndOfListNumericWith(.{}, out, ctx);
}

pub fn writeEndOfListNumericWith(comptime params: Params, out: []u8, ctx: ReplyContext) AcctSilenceError![]const u8 {
    try validateContext(params, ctx);

    var b = LineBuilder.init(out, params.max_line_bytes);
    try b.numericPrefix(RPL_ENDOFSILELIST, ctx.server_name, ctx.requester);
    try b.spaceTrailing("End of account SILENCE list");
    try b.crlf();
    return b.slice();
}

pub fn formatCode(code: u16, buf: []u8) []const u8 {
    buf[0] = @as(u8, '0') + @as(u8, @intCast((code / 100) % 10));
    buf[1] = @as(u8, '0') + @as(u8, @intCast((code / 10) % 10));
    buf[2] = @as(u8, '0') + @as(u8, @intCast(code % 10));
    return buf[0..3];
}

const Hostmask = struct {
    nick: []const u8,
    user: []const u8,
    host: []const u8,
};

fn parseHostmask(bytes: []const u8) ?Hostmask {
    const bang = indexOf(bytes, '!', 0) orelse return null;
    const at = indexOf(bytes, '@', bang + 1) orelse return null;

    if (bang == 0 or at == bang + 1 or at + 1 == bytes.len) return null;
    if (indexOf(bytes, '!', bang + 1) != null) return null;
    if (indexOf(bytes, '@', at + 1) != null) return null;

    return .{
        .nick = bytes[0..bang],
        .user = bytes[bang + 1 .. at],
        .host = bytes[at + 1 ..],
    };
}

fn validateContext(comptime params: Params, ctx: ReplyContext) AcctSilenceError!void {
    try validateParam(ctx.server_name, params.max_server_bytes, error.InvalidServerName);
    try validateParam(ctx.requester, params.max_requester_bytes, error.InvalidRequester);
}

fn validateAccount(account: []const u8, max_account_bytes: usize) AcctSilenceError!void {
    if (account.len == 0) return error.InvalidAccount;
    if (account.len > max_account_bytes) return error.AccountTooLong;
    try validateParam(account, max_account_bytes, error.InvalidAccount);
}

fn validateMask(mask: []const u8, max_mask_bytes: usize) AcctSilenceError!void {
    if (mask.len == 0) return error.InvalidMask;
    if (mask.len > max_mask_bytes) return error.MaskTooLong;
    _ = parseHostmask(mask) orelse return error.InvalidMask;

    for (mask) |byte| {
        switch (byte) {
            0, ',', ' ', '\t', '\r', '\n' => return error.InvalidMask,
            else => {},
        }
    }
}

fn validateParam(bytes: []const u8, max_bytes: usize, comptime err: AcctSilenceError) AcctSilenceError!void {
    if (bytes.len == 0 or bytes.len > max_bytes or bytes[0] == ':') return err;
    for (bytes) |byte| {
        if (byte <= ' ' or byte == 0x7f) return err;
    }
}

fn globMatch(pattern: []const u8, text: []const u8) bool {
    var pattern_index: usize = 0;
    var text_index: usize = 0;
    var star_index: ?usize = null;
    var star_text_index: usize = 0;

    while (text_index < text.len) {
        if (pattern_index < pattern.len) {
            const token = nextGlobToken(pattern, pattern_index);
            switch (token.kind) {
                .any_run => {
                    star_index = pattern_index;
                    pattern_index = token.next;
                    star_text_index = text_index;
                    continue;
                },
                .any_one => {
                    pattern_index = token.next;
                    text_index += 1;
                    continue;
                },
                .literal => {
                    if (rfc1459Equal(token.byte, text[text_index])) {
                        pattern_index = token.next;
                        text_index += 1;
                        continue;
                    }
                },
            }
        }

        if (star_index) |index| {
            const token = nextGlobToken(pattern, index);
            star_text_index += 1;
            text_index = star_text_index;
            pattern_index = token.next;
        } else {
            return false;
        }
    }

    while (pattern_index < pattern.len) {
        const token = nextGlobToken(pattern, pattern_index);
        if (token.kind != .any_run) return false;
        pattern_index = token.next;
    }

    return true;
}

const GlobTokenKind = enum {
    literal,
    any_one,
    any_run,
};

const GlobToken = struct {
    kind: GlobTokenKind,
    byte: u8 = 0,
    next: usize,
};

fn nextGlobToken(pattern: []const u8, index: usize) GlobToken {
    const byte = pattern[index];
    if (byte == '\\' and index + 1 < pattern.len and isEscapable(pattern[index + 1])) {
        return .{ .kind = .literal, .byte = pattern[index + 1], .next = index + 2 };
    }

    return switch (byte) {
        '*' => .{ .kind = .any_run, .next = index + 1 },
        '?' => .{ .kind = .any_one, .next = index + 1 },
        else => .{ .kind = .literal, .byte = byte, .next = index + 1 },
    };
}

fn isEscapable(byte: u8) bool {
    return byte == '*' or byte == '?' or byte == '\\';
}

fn rfc1459Equal(a: u8, b: u8) bool {
    return rfc1459Fold(a) == rfc1459Fold(b);
}

fn rfc1459Fold(byte: u8) u8 {
    return switch (byte) {
        'A'...'Z' => byte + ('a' - 'A'),
        '[' => '{',
        ']' => '}',
        '\\' => '|',
        '^' => '~',
        else => byte,
    };
}

fn asciiEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |left, right| {
        if (asciiLower(left) != asciiLower(right)) return false;
    }
    return true;
}

fn asciiLower(byte: u8) u8 {
    return if (byte >= 'A' and byte <= 'Z') byte + ('a' - 'A') else byte;
}

fn indexOf(bytes: []const u8, needle: u8, start: usize) ?usize {
    var index = start;
    while (index < bytes.len) : (index += 1) {
        if (bytes[index] == needle) return index;
    }
    return null;
}

const LineBuilder = struct {
    out: []u8,
    max_line_bytes: usize,
    len: usize = 0,

    fn init(out: []u8, max_line_bytes: usize) LineBuilder {
        return .{ .out = out, .max_line_bytes = max_line_bytes };
    }

    fn slice(self: *const LineBuilder) []const u8 {
        return self.out[0..self.len];
    }

    fn numericPrefix(self: *LineBuilder, code: u16, server_name: []const u8, requester: []const u8) AcctSilenceError!void {
        try self.appendByte(':');
        try self.appendBytes(server_name);
        try self.appendByte(' ');
        var code_buf: [3]u8 = undefined;
        try self.appendBytes(formatCode(code, &code_buf));
        try self.appendByte(' ');
        try self.appendBytes(requester);
    }

    fn spaceParam(self: *LineBuilder, bytes: []const u8) AcctSilenceError!void {
        try self.appendByte(' ');
        try self.appendBytes(bytes);
    }

    fn spaceTrailing(self: *LineBuilder, bytes: []const u8) AcctSilenceError!void {
        try self.appendBytes(" :");
        try self.appendBytes(bytes);
    }

    fn crlf(self: *LineBuilder) AcctSilenceError!void {
        try self.appendBytes("\r\n");
    }

    fn appendBytes(self: *LineBuilder, bytes: []const u8) AcctSilenceError!void {
        if (self.len + bytes.len > self.out.len) return error.OutputTooSmall;
        if (self.len + bytes.len > self.max_line_bytes) return error.LineTooLong;
        @memcpy(self.out[self.len .. self.len + bytes.len], bytes);
        self.len += bytes.len;
    }

    fn appendByte(self: *LineBuilder, byte: u8) AcctSilenceError!void {
        if (self.len == self.out.len) return error.OutputTooSmall;
        if (self.len + 1 > self.max_line_bytes) return error.LineTooLong;
        self.out[self.len] = byte;
        self.len += 1;
    }
};

test "parse real ACCTSILENCE command forms" {
    try std.testing.expectEqual(Request.list, try parseLine("ACCTSILENCE"));
    try std.testing.expectEqual(Request.list, try parseLine("acctsilence list\r\n"));

    const add_req = try parseLine("ACCTSILENCE ADD all *!*@bad.example");
    try std.testing.expectEqual(Kind.all, add_req.add.kind);
    try std.testing.expectEqualStrings("*!*@bad.example", add_req.add.mask);

    const del_req = try parseLine("ACCTSILENCE remove notice noisy!*@*.example.net");
    try std.testing.expectEqual(Kind.notice, del_req.remove.kind);
    try std.testing.expectEqualStrings("noisy!*@*.example.net", del_req.remove.mask);

    const plus_req = try parse(&.{ "+", "privmsg", "nick!*@host" });
    try std.testing.expectEqual(Kind.privmsg, plus_req.add.kind);
}

test "parser rejects pseudo-client service traffic and malformed actions" {
    try std.testing.expectError(error.InvalidCommand, parseLine("PRIVMSG NickServ :SILENCE add all *!*@bad"));
    try std.testing.expectError(error.InvalidCommand, parseLine("NickServ SILENCE add all *!*@bad"));
    try std.testing.expectError(error.InvalidAction, parseLine("ACCTSILENCE ADD all"));
    try std.testing.expectError(error.InvalidKind, parseLine("ACCTSILENCE ADD dcc *!*@bad"));
    try std.testing.expectError(error.InvalidMask, parseLine("ACCTSILENCE ADD all *"));
    try std.testing.expectError(error.InvalidMask, parseLine("ACCTSILENCE ADD all nick!user@host,other"));
}

test "store add list remove and case-insensitive duplicate handling" {
    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    try std.testing.expect(try store.add("Alice", "bad!*@example.test", .all));
    try std.testing.expect(try store.add("alice", "noisy!*@*.example.net", .notice));
    try std.testing.expect(!try store.add("ALICE", "BAD!*@EXAMPLE.TEST", .all));
    try std.testing.expect(try store.add("alice", "bad!*@example.test", .privmsg));

    var out: [8]Entry = undefined;
    const entries = try store.list("aLiCe", &out);
    try std.testing.expectEqual(@as(usize, 3), entries.len);
    try std.testing.expectEqual(Kind.all, entries[0].kind);
    try std.testing.expectEqualStrings("bad!*@example.test", entries[0].mask);
    try std.testing.expectEqual(Kind.notice, entries[1].kind);
    try std.testing.expectEqual(Kind.privmsg, entries[2].kind);

    try std.testing.expect(try store.remove("ALICE", "bad!*@example.test", .privmsg));
    try std.testing.expect(!try store.remove("ALICE", "bad!*@example.test", .privmsg));
    try std.testing.expectEqual(@as(usize, 2), (try store.list("alice", &out)).len);
}

test "isSilenced honors account kind and all coverage" {
    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    _ = try store.add("alice", "bad!*@*.example.test", .all);
    _ = try store.add("alice", "notice!*@host.test", .notice);
    _ = try store.add("bob", "bad!*@*.example.test", .privmsg);

    try std.testing.expect(store.isSilenced("ALICE", "Bad!~u@chat.example.test", .privmsg));
    try std.testing.expect(store.isSilenced("alice", "Bad!~u@chat.example.test", .notice));
    try std.testing.expect(store.isSilenced("alice", "notice!user@HOST.TEST", .notice));
    try std.testing.expect(!store.isSilenced("alice", "notice!user@HOST.TEST", .privmsg));
    try std.testing.expect(store.isSilenced("bob", "bad!u@chat.example.test", .privmsg));
    try std.testing.expect(!store.isSilenced("bob", "bad!u@chat.example.test", .notice));
    try std.testing.expect(!store.isSilenced("carol", "bad!u@chat.example.test", .privmsg));
    try std.testing.expect(!store.isSilenced("alice", "not-a-hostmask", .privmsg));
}

test "apply parsed add remove and list requests" {
    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    try std.testing.expect(try store.apply("acct", try parseLine("ACCTSILENCE ADD privmsg spam!*@host")));
    try std.testing.expect(!try store.apply("acct", try parseLine("ACCTSILENCE LIST")));
    try std.testing.expect(store.isSilenced("acct", "spam!u@host", .privmsg));
    try std.testing.expect(try store.apply("acct", try parseLine("ACCTSILENCE DEL privmsg spam!*@host")));
    try std.testing.expect(!store.isSilenced("acct", "spam!u@host", .privmsg));
}

test "hostmask glob is component-safe and rfc1459 case-insensitive" {
    try std.testing.expect(hostmaskGlobMatch("*!*@*.example.com", "Nick!user@CHAT.EXAMPLE.COM"));
    try std.testing.expect(hostmaskGlobMatch("n?ck!u*@host", "N[ck!User@HOST"));
    try std.testing.expect(hostmaskGlobMatch("[\\]^!*@host", "{|}~!u@host"));
    try std.testing.expect(!hostmaskGlobMatch("nick*@host", "nick!user@host"));
    try std.testing.expect(!hostmaskGlobMatch("*!*@*.example.com", "nick!user@example.net"));
    try std.testing.expect(!hostmaskGlobMatch("*", "nick!user@host"));
    try std.testing.expect(!hostmaskGlobMatch("*!*@*", "nick"));
}

test "escaped glob wildcards are literals" {
    try std.testing.expect(hostmaskGlobMatch("literal\\*!*@host", "literal*!u@host"));
    try std.testing.expect(hostmaskGlobMatch("what\\?!*@host", "what?!u@host"));
    try std.testing.expect(!hostmaskGlobMatch("literal\\*!*@host", "literalXYZ!u@host"));
}

test "limits and validation avoid partial allocations" {
    var store = Store.initWithParams(std.testing.allocator, .{
        .max_entries_per_account = 1,
        .max_account_bytes = 5,
        .max_mask_bytes = 16,
    });
    defer store.deinit();

    try std.testing.expect(try store.add("acct", "a!b@c", .all));
    try std.testing.expectError(error.LimitReached, store.add("acct", "d!e@f", .all));
    try std.testing.expectError(error.AccountTooLong, store.add("account", "a!b@c", .all));
    try std.testing.expectError(error.MaskTooLong, store.add("acct", "nick!user@very-long-host", .all));
    try std.testing.expectError(error.InvalidMask, store.add("acct", "nick user@host", .all));
}

test "removing final entry releases account bucket" {
    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    try std.testing.expect(try store.add("acct", "a!b@c", .all));
    try std.testing.expect(try store.remove("acct", "a!b@c", .all));

    var out: [1]Entry = undefined;
    try std.testing.expectEqual(@as(usize, 0), (try store.list("acct", &out)).len);
    try std.testing.expect(try store.add("ACCT", "d!e@f", .notice));
    try std.testing.expect(store.isSilenced("acct", "d!e@f", .notice));
}

test "list output buffer size is enforced" {
    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    _ = try store.add("acct", "a!b@c", .all);
    _ = try store.add("acct", "d!e@f", .notice);

    var too_small: [1]Entry = undefined;
    try std.testing.expectError(error.OutputTooSmall, store.list("acct", &too_small));
}

test "numeric builders emit real server numeric lines" {
    var buf: [256]u8 = undefined;
    const ctx = ReplyContext{ .server_name = "irc.example", .requester = "Alice" };

    const list_line = try writeListNumeric(&buf, ctx, .{ .kind = .all, .mask = "*!*@bad.example" });
    try std.testing.expectEqualStrings(":irc.example 271 Alice all *!*@bad.example :is account-silenced\r\n", list_line);

    const end_line = try writeEndOfListNumeric(&buf, ctx);
    try std.testing.expectEqualStrings(":irc.example 272 Alice :End of account SILENCE list\r\n", end_line);
}

test "numeric builders validate context and output limits" {
    var small: [8]u8 = undefined;
    const ctx = ReplyContext{ .server_name = "irc.example", .requester = "Alice" };

    try std.testing.expectError(error.OutputTooSmall, writeListNumeric(&small, ctx, .{
        .kind = .all,
        .mask = "*!*@bad.example",
    }));
    try std.testing.expectError(error.InvalidServerName, writeEndOfListNumeric(&small, .{
        .server_name = ":bad",
        .requester = "Alice",
    }));
    try std.testing.expectError(error.InvalidRequester, writeEndOfListNumeric(&small, .{
        .server_name = "irc.example",
        .requester = "Bad User",
    }));
}

test "formatCode writes three digit numerics" {
    var buf: [3]u8 = undefined;
    try std.testing.expectEqualStrings("271", formatCode(RPL_SILELIST, &buf));
    try std.testing.expectEqualStrings("461", formatCode(ERR_NEEDMOREPARAMS, &buf));
}

//! Pure channel-founder transfer state for Orochi services.
//!
//! This file deliberately imports only `std`: it owns no daemon state, performs
//! no IRC I/O, and never models services as pseudo-clients. Callers bridge these
//! plans to real server commands and numerics.

const std = @import("std");

pub const MAX_CHANNEL_BYTES: usize = 64;
pub const MAX_ACCOUNT_BYTES: usize = 32;
pub const MAX_TOKEN_BYTES: usize = 32;
pub const DEFAULT_MAX_ACCOUNTS: usize = 65536;
pub const DEFAULT_MAX_CHANNELS: usize = 65536;
pub const DEFAULT_MAX_PENDING: usize = 4096;
pub const DEFAULT_TTL_MS: u64 = 24 * 60 * 60 * 1000;

pub const Params = struct {
    max_channel_bytes: usize = MAX_CHANNEL_BYTES,
    max_account_bytes: usize = MAX_ACCOUNT_BYTES,
    max_accounts: usize = DEFAULT_MAX_ACCOUNTS,
    max_channels: usize = DEFAULT_MAX_CHANNELS,
    max_pending: usize = DEFAULT_MAX_PENDING,
    pending_ttl_ms: u64 = DEFAULT_TTL_MS,
};

pub const TransferError = std.mem.Allocator.Error || error{
    InvalidChannel,
    ChannelTooLong,
    InvalidAccount,
    AccountTooLong,
    SameAccount,
    AccountUnknown,
    ChannelUnknown,
    ChannelExists,
    NotFounder,
    PendingExists,
    PendingUnknown,
    PendingExpired,
    ConfirmingAccountMismatch,
    CancelAccountMismatch,
    TooManyAccounts,
    TooManyChannels,
    TooManyPending,
    InvalidToken,
};

pub const ParseError = error{
    InvalidCommand,
    InvalidSubcommand,
    NeedMoreParams,
    TooManyParams,
    InvalidChannel,
    ChannelTooLong,
    InvalidAccount,
    AccountTooLong,
    InvalidToken,
    InvalidTimestamp,
};

/// Numeric hints for a server-command bridge. Success numerics are Orochi-local
/// service numerics; failures map to standard IRC numerics where possible.
pub const TransferNumeric = enum(u16) {
    RPL_CHANTRANSFERPENDING = 806,
    RPL_CHANTRANSFERDONE = 807,
    RPL_CHANTRANSFERCANCELLED = 808,
    RPL_CHANTRANSFEREXPIRED = 809,
    ERR_NOSUCHCHANNEL = 403,
    ERR_ERRONEUSNICKNAME = 432,
    ERR_NICKNAMEINUSE = 433,
    ERR_NEEDMOREPARAMS = 461,
    ERR_CHANOPRIVSNEEDED = 482,
    ERR_INVALIDTOKEN = 908,

    pub fn value(self: TransferNumeric) u16 {
        return @intFromEnum(self);
    }

    pub fn fromError(err: anyerror) ?TransferNumeric {
        return switch (err) {
            error.InvalidChannel,
            error.ChannelTooLong,
            => .ERR_NOSUCHCHANNEL,
            error.InvalidAccount,
            error.AccountTooLong,
            error.SameAccount,
            => .ERR_ERRONEUSNICKNAME,
            error.AccountUnknown => .ERR_NICKNAMEINUSE,
            error.ChannelUnknown => .ERR_NOSUCHCHANNEL,
            error.NotFounder,
            error.PendingExists,
            error.ConfirmingAccountMismatch,
            error.CancelAccountMismatch,
            => .ERR_CHANOPRIVSNEEDED,
            error.PendingUnknown,
            error.PendingExpired,
            error.InvalidToken,
            => .ERR_INVALIDTOKEN,
            error.TooManyAccounts,
            error.TooManyChannels,
            error.TooManyPending,
            error.ChannelExists,
            => .ERR_NEEDMOREPARAMS,
            error.OutOfMemory => null,
            else => null,
        };
    }
};

pub fn InlineText(comptime max_len: usize) type {
    return struct {
        bytes: [max_len]u8 = undefined,
        len: u16 = 0,

        pub fn init(input: []const u8) error{StringTooLong}!@This() {
            if (input.len > max_len) return error.StringTooLong;
            var out = @This(){};
            if (input.len != 0) @memcpy(out.bytes[0..input.len], input);
            out.len = @intCast(input.len);
            return out;
        }

        pub fn asSlice(self: *const @This()) []const u8 {
            return self.bytes[0..self.len];
        }
    };
}

pub const ChannelText = InlineText(MAX_CHANNEL_BYTES);
pub const AccountText = InlineText(MAX_ACCOUNT_BYTES);

pub const TransferToken = struct {
    bytes: [MAX_TOKEN_BYTES]u8,

    pub fn parse(raw: []const u8) ParseError!TransferToken {
        if (raw.len != MAX_TOKEN_BYTES) return error.InvalidToken;
        var out: TransferToken = undefined;
        for (raw, 0..) |byte, i| {
            if (!std.ascii.isHex(byte)) return error.InvalidToken;
            out.bytes[i] = std.ascii.toLower(byte);
        }
        return out;
    }

    pub fn asSlice(self: *const TransferToken) []const u8 {
        return self.bytes[0..];
    }

    pub fn eql(a: TransferToken, b: TransferToken) bool {
        return std.mem.eql(u8, a.asSlice(), b.asSlice());
    }
};

pub const ParsedCommand = union(enum) {
    initiate: struct {
        channel: []const u8,
        to_account: []const u8,
    },
    confirm: struct {
        token: TransferToken,
    },
    cancel: struct {
        token: TransferToken,
    },
    expire: struct {
        now_ms: u64,
    },
};

pub const PendingInfo = struct {
    token: TransferToken,
    channel: []const u8,
    from_account: []const u8,
    to_account: []const u8,
    created_ms: u64,
    expires_ms: u64,
};

pub const Initiated = struct {
    numeric: TransferNumeric = .RPL_CHANTRANSFERPENDING,
    pending: PendingInfo,
};

pub const Completed = struct {
    numeric: TransferNumeric = .RPL_CHANTRANSFERDONE,
    channel: ChannelText,
    old_founder: AccountText,
    new_founder: AccountText,
};

pub const Cancelled = struct {
    numeric: TransferNumeric = .RPL_CHANTRANSFERCANCELLED,
    pending: PendingInfo,
};

const Account = struct {
    name: []u8,
};

const Channel = struct {
    name: []u8,
    founder: []u8,
};

const Pending = struct {
    token: TransferToken,
    channel: []u8,
    from_account: []u8,
    to_account: []u8,
    created_ms: u64,
    expires_ms: u64,

    fn info(self: *const Pending) PendingInfo {
        return .{
            .token = self.token,
            .channel = self.channel,
            .from_account = self.from_account,
            .to_account = self.to_account,
            .created_ms = self.created_ms,
            .expires_ms = self.expires_ms,
        };
    }
};

pub const Store = struct {
    allocator: std.mem.Allocator,
    params: Params,
    accounts: std.ArrayList(Account) = .empty,
    channels: std.ArrayList(Channel) = .empty,
    pending: std.ArrayList(Pending) = .empty,
    next_token_id: u64 = 1,

    pub fn init(allocator: std.mem.Allocator) Store {
        return initWithParams(allocator, .{});
    }

    pub fn initWithParams(allocator: std.mem.Allocator, params: Params) Store {
        return .{
            .allocator = allocator,
            .params = params,
        };
    }

    pub fn deinit(self: *Store) void {
        for (self.accounts.items) |account| self.allocator.free(account.name);
        self.accounts.deinit(self.allocator);

        for (self.channels.items) |channel| {
            self.allocator.free(channel.name);
            self.allocator.free(channel.founder);
        }
        self.channels.deinit(self.allocator);

        for (self.pending.items) |item| freePending(self.allocator, item);
        self.pending.deinit(self.allocator);

        self.* = undefined;
    }

    pub fn addAccount(self: *Store, account: []const u8) TransferError!bool {
        try validateAccountWith(self.params, account);
        if (self.findAccount(account) != null) return false;
        if (self.accounts.items.len >= self.params.max_accounts) return error.TooManyAccounts;
        const owned = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(owned);
        try self.accounts.append(self.allocator, .{ .name = owned });
        return true;
    }

    pub fn hasAccount(self: *const Store, account: []const u8) bool {
        return self.findAccount(account) != null;
    }

    pub fn registerChannel(self: *Store, channel: []const u8, founder: []const u8) TransferError!bool {
        try validateChannelWith(self.params, channel);
        try validateAccountWith(self.params, founder);
        if (self.findAccount(founder) == null) return error.AccountUnknown;
        if (self.findChannel(channel) != null) return error.ChannelExists;
        if (self.channels.items.len >= self.params.max_channels) return error.TooManyChannels;

        const owned_channel = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(owned_channel);
        const owned_founder = try self.allocator.dupe(u8, founder);
        errdefer self.allocator.free(owned_founder);
        try self.channels.append(self.allocator, .{ .name = owned_channel, .founder = owned_founder });
        return true;
    }

    pub fn founderOf(self: *const Store, channel: []const u8) ?[]const u8 {
        const idx = self.findChannel(channel) orelse return null;
        return self.channels.items[idx].founder;
    }

    /// Initiates a transfer at timestamp zero, useful for deterministic tests.
    pub fn initiate(self: *Store, channel: []const u8, from: []const u8, to_account: []const u8) TransferError!Initiated {
        return self.initiateAt(channel, from, to_account, 0);
    }

    /// Validates founder authority and creates one pending transfer for a channel.
    pub fn initiateAt(
        self: *Store,
        channel: []const u8,
        from: []const u8,
        to_account: []const u8,
        now_ms: u64,
    ) TransferError!Initiated {
        try validateChannelWith(self.params, channel);
        try validateAccountWith(self.params, from);
        try validateAccountWith(self.params, to_account);
        if (accountEql(from, to_account)) return error.SameAccount;
        if (self.findAccount(to_account) == null) return error.AccountUnknown;

        const channel_idx = self.findChannel(channel) orelse return error.ChannelUnknown;
        if (!accountEql(self.channels.items[channel_idx].founder, from)) return error.NotFounder;
        if (self.findPendingByChannel(channel) != null) return error.PendingExists;
        if (self.pending.items.len >= self.params.max_pending) return error.TooManyPending;

        const token = self.nextToken(channel, from, to_account);
        const owned_channel = try self.allocator.dupe(u8, self.channels.items[channel_idx].name);
        errdefer self.allocator.free(owned_channel);
        const owned_from = try self.allocator.dupe(u8, self.channels.items[channel_idx].founder);
        errdefer self.allocator.free(owned_from);
        const owned_to = try self.allocator.dupe(u8, to_account);
        errdefer self.allocator.free(owned_to);

        const item: Pending = .{
            .token = token,
            .channel = owned_channel,
            .from_account = owned_from,
            .to_account = owned_to,
            .created_ms = now_ms,
            .expires_ms = now_ms +| self.params.pending_ttl_ms,
        };
        try self.pending.append(self.allocator, item);
        return .{ .pending = self.pending.items[self.pending.items.len - 1].info() };
    }

    /// Confirms and commits a transfer. `by_account` must be the recipient.
    pub fn confirm(self: *Store, token: TransferToken, by_account: []const u8) TransferError!Completed {
        return self.confirmAt(token, by_account, 0);
    }

    /// Confirms and commits a transfer, rejecting expired tokens first.
    pub fn confirmAt(self: *Store, token: TransferToken, by_account: []const u8, now_ms: u64) TransferError!Completed {
        try validateAccountWith(self.params, by_account);
        const idx = self.findPendingByToken(token) orelse return error.PendingUnknown;
        if (isExpired(self.pending.items[idx], now_ms)) {
            const removed = self.pending.orderedRemove(idx);
            freePending(self.allocator, removed);
            return error.PendingExpired;
        }
        if (!accountEql(self.pending.items[idx].to_account, by_account)) return error.ConfirmingAccountMismatch;

        const channel_idx = self.findChannel(self.pending.items[idx].channel) orelse return error.ChannelUnknown;
        const new_founder = try self.allocator.dupe(u8, self.pending.items[idx].to_account);
        errdefer self.allocator.free(new_founder);

        const removed = self.pending.orderedRemove(idx);
        self.allocator.free(self.channels.items[channel_idx].founder);
        self.channels.items[channel_idx].founder = new_founder;

        const completed: Completed = .{
            .channel = ChannelText.init(self.channels.items[channel_idx].name) catch unreachable,
            .old_founder = AccountText.init(removed.from_account) catch unreachable,
            .new_founder = AccountText.init(self.channels.items[channel_idx].founder) catch unreachable,
        };
        self.allocator.free(removed.channel);
        self.allocator.free(removed.to_account);
        self.allocator.free(removed.from_account);
        return completed;
    }

    /// Cancels a pending transfer. The current founder or recipient may cancel.
    pub fn cancel(self: *Store, token: TransferToken, by_account: []const u8) TransferError!Cancelled {
        try validateAccountWith(self.params, by_account);
        const idx = self.findPendingByToken(token) orelse return error.PendingUnknown;
        const item = self.pending.items[idx];
        if (!accountEql(item.from_account, by_account) and !accountEql(item.to_account, by_account)) {
            return error.CancelAccountMismatch;
        }

        const copied = try copyPendingInfo(self.allocator, item);
        const removed = self.pending.orderedRemove(idx);
        freePending(self.allocator, removed);
        return .{ .pending = copied };
    }

    pub fn deinitCancelled(self: *Store, cancelled: *Cancelled) void {
        freePendingInfo(self.allocator, cancelled.pending);
        cancelled.* = undefined;
    }

    pub fn pendingInfo(self: *const Store, token: TransferToken) ?PendingInfo {
        const idx = self.findPendingByToken(token) orelse return null;
        return self.pending.items[idx].info();
    }

    pub fn pendingCount(self: *const Store) usize {
        return self.pending.items.len;
    }

    /// Removes expired pending transfers and returns the number removed.
    pub fn expire(self: *Store, now_ms: u64) usize {
        var removed_count: usize = 0;
        var i: usize = 0;
        while (i < self.pending.items.len) {
            if (isExpired(self.pending.items[i], now_ms)) {
                const removed = self.pending.swapRemove(i);
                freePending(self.allocator, removed);
                removed_count += 1;
            } else {
                i += 1;
            }
        }
        return removed_count;
    }

    fn findAccount(self: *const Store, account: []const u8) ?usize {
        for (self.accounts.items, 0..) |item, i| {
            if (accountEql(item.name, account)) return i;
        }
        return null;
    }

    fn findChannel(self: *const Store, channel: []const u8) ?usize {
        for (self.channels.items, 0..) |item, i| {
            if (channelEql(item.name, channel)) return i;
        }
        return null;
    }

    fn findPendingByChannel(self: *const Store, channel: []const u8) ?usize {
        for (self.pending.items, 0..) |item, i| {
            if (channelEql(item.channel, channel)) return i;
        }
        return null;
    }

    fn findPendingByToken(self: *const Store, token: TransferToken) ?usize {
        for (self.pending.items, 0..) |item, i| {
            if (item.token.eql(token)) return i;
        }
        return null;
    }

    fn nextToken(self: *Store, channel: []const u8, from: []const u8, to_account: []const u8) TransferToken {
        const id = self.next_token_id;
        self.next_token_id +%= 1;
        var h = std.hash.Wyhash.init(0x6d697a7563686955);
        h.update(channel);
        h.update(&.{0});
        h.update(from);
        h.update(&.{0});
        h.update(to_account);
        h.update(&intBytes(id));

        var token: TransferToken = undefined;
        writeHex64(token.bytes[0..16], id);
        writeHex64(token.bytes[16..32], h.final());
        return token;
    }
};

pub fn parseCommand(args: []const []const u8) ParseError!ParsedCommand {
    if (args.len < 2) return error.NeedMoreParams;
    if (!std.ascii.eqlIgnoreCase(args[0], "CHANNEL") and !std.ascii.eqlIgnoreCase(args[0], "CS")) {
        return error.InvalidCommand;
    }

    if (std.ascii.eqlIgnoreCase(args[1], "TRANSFER")) {
        if (args.len < 4) return error.NeedMoreParams;
        if (args.len > 4) return error.TooManyParams;
        try parseValidateChannel(args[2]);
        try parseValidateAccount(args[3]);
        return .{ .initiate = .{ .channel = args[2], .to_account = args[3] } };
    }
    if (std.ascii.eqlIgnoreCase(args[1], "TRANSFER-CONFIRM") or std.ascii.eqlIgnoreCase(args[1], "CONFIRMTRANSFER")) {
        if (args.len < 3) return error.NeedMoreParams;
        if (args.len > 3) return error.TooManyParams;
        return .{ .confirm = .{ .token = try TransferToken.parse(args[2]) } };
    }
    if (std.ascii.eqlIgnoreCase(args[1], "TRANSFER-CANCEL") or std.ascii.eqlIgnoreCase(args[1], "CANCELTRANSFER")) {
        if (args.len < 3) return error.NeedMoreParams;
        if (args.len > 3) return error.TooManyParams;
        return .{ .cancel = .{ .token = try TransferToken.parse(args[2]) } };
    }
    if (std.ascii.eqlIgnoreCase(args[1], "TRANSFER-EXPIRE")) {
        if (args.len < 3) return error.NeedMoreParams;
        if (args.len > 3) return error.TooManyParams;
        return .{ .expire = .{ .now_ms = std.fmt.parseInt(u64, args[2], 10) catch return error.InvalidTimestamp } };
    }
    return error.InvalidSubcommand;
}

pub fn validateChannel(channel: []const u8) TransferError!void {
    return validateChannelWith(.{}, channel);
}

pub fn validateAccount(account: []const u8) TransferError!void {
    return validateAccountWith(.{}, account);
}

fn validateChannelWith(params: Params, channel: []const u8) TransferError!void {
    if (channel.len == 0 or channel[0] != '#') return error.InvalidChannel;
    if (channel.len > params.max_channel_bytes) return error.ChannelTooLong;
    for (channel) |byte| {
        if (byte == 0 or byte == '\r' or byte == '\n' or byte == ' ' or byte == ',') {
            return error.InvalidChannel;
        }
    }
}

fn validateAccountWith(params: Params, account: []const u8) TransferError!void {
    if (account.len == 0) return error.InvalidAccount;
    if (account.len > params.max_account_bytes) return error.AccountTooLong;
    for (account) |byte| {
        if (!isAccountByte(byte)) return error.InvalidAccount;
    }
}

fn parseValidateChannel(channel: []const u8) ParseError!void {
    validateChannel(channel) catch |err| switch (err) {
        error.InvalidChannel => return error.InvalidChannel,
        error.ChannelTooLong => return error.ChannelTooLong,
        else => unreachable,
    };
}

fn parseValidateAccount(account: []const u8) ParseError!void {
    validateAccount(account) catch |err| switch (err) {
        error.InvalidAccount => return error.InvalidAccount,
        error.AccountTooLong => return error.AccountTooLong,
        else => unreachable,
    };
}

fn isAccountByte(byte: u8) bool {
    return (byte >= 'a' and byte <= 'z') or
        (byte >= 'A' and byte <= 'Z') or
        (byte >= '0' and byte <= '9') or
        byte == '_' or byte == '-' or byte == '.';
}

fn accountEql(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

fn channelEql(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

fn isExpired(pending: Pending, now_ms: u64) bool {
    return now_ms >= pending.expires_ms;
}

fn copyPendingInfo(allocator: std.mem.Allocator, pending: Pending) TransferError!PendingInfo {
    const channel = try allocator.dupe(u8, pending.channel);
    errdefer allocator.free(channel);
    const from = try allocator.dupe(u8, pending.from_account);
    errdefer allocator.free(from);
    const to = try allocator.dupe(u8, pending.to_account);
    errdefer allocator.free(to);
    return .{
        .token = pending.token,
        .channel = channel,
        .from_account = from,
        .to_account = to,
        .created_ms = pending.created_ms,
        .expires_ms = pending.expires_ms,
    };
}

fn freePendingInfo(allocator: std.mem.Allocator, info: PendingInfo) void {
    allocator.free(info.channel);
    allocator.free(info.from_account);
    allocator.free(info.to_account);
}

fn freePending(allocator: std.mem.Allocator, pending: Pending) void {
    allocator.free(pending.channel);
    allocator.free(pending.from_account);
    allocator.free(pending.to_account);
}

fn intBytes(value: u64) [8]u8 {
    var out: [8]u8 = undefined;
    std.mem.writeInt(u64, &out, value, .little);
    return out;
}

fn writeHex64(out: []u8, value: u64) void {
    std.debug.assert(out.len == 16);
    const alphabet = "0123456789abcdef";
    var shift: u6 = 60;
    for (out) |*byte| {
        byte.* = alphabet[@as(usize, @intCast((value >> shift) & 0xf))];
        shift -%= 4;
    }
}

const testing = std.testing;

fn seedStore() !Store {
    var store = Store.init(testing.allocator);
    errdefer store.deinit();
    _ = try store.addAccount("alice");
    _ = try store.addAccount("bob");
    _ = try store.addAccount("carol");
    _ = try store.registerChannel("#orochi", "alice");
    return store;
}

test "initiate creates a pending founder transfer token" {
    var store = try seedStore();
    defer store.deinit();

    const result = try store.initiateAt("#Orochi", "ALICE", "bob", 100);
    try testing.expectEqual(TransferNumeric.RPL_CHANTRANSFERPENDING, result.numeric);
    try testing.expectEqualStrings("#orochi", result.pending.channel);
    try testing.expectEqualStrings("alice", result.pending.from_account);
    try testing.expectEqualStrings("bob", result.pending.to_account);
    try testing.expectEqual(@as(u64, 100), result.pending.created_ms);
    try testing.expectEqual(@as(u64, 100 + DEFAULT_TTL_MS), result.pending.expires_ms);
    try testing.expectEqual(@as(usize, MAX_TOKEN_BYTES), result.pending.token.asSlice().len);
    try testing.expectEqual(@as(usize, 1), store.pendingCount());
}

test "recipient confirmation commits and consumes pending transfer" {
    var store = try seedStore();
    defer store.deinit();

    const initiated = try store.initiate("#orochi", "alice", "bob");
    const done = try store.confirm(initiated.pending.token, "BOB");
    try testing.expectEqual(TransferNumeric.RPL_CHANTRANSFERDONE, done.numeric);
    try testing.expectEqualStrings("#orochi", done.channel.asSlice());
    try testing.expectEqualStrings("alice", done.old_founder.asSlice());
    try testing.expectEqualStrings("bob", done.new_founder.asSlice());
    try testing.expectEqualStrings("bob", store.founderOf("#OROCHI").?);
    try testing.expectEqual(@as(usize, 0), store.pendingCount());
}

test "non-recipient cannot confirm token" {
    var store = try seedStore();
    defer store.deinit();

    const initiated = try store.initiate("#orochi", "alice", "bob");
    try testing.expectError(error.ConfirmingAccountMismatch, store.confirm(initiated.pending.token, "carol"));
    try testing.expectEqualStrings("alice", store.founderOf("#orochi").?);
    try testing.expectEqual(@as(usize, 1), store.pendingCount());
}

test "only current founder can initiate transfer" {
    var store = try seedStore();
    defer store.deinit();

    try testing.expectError(error.NotFounder, store.initiate("#orochi", "bob", "carol"));
}

test "transfer target must be a known account and not self" {
    var store = try seedStore();
    defer store.deinit();

    try testing.expectError(error.SameAccount, store.initiate("#orochi", "alice", "ALICE"));
    try testing.expectError(error.AccountUnknown, store.initiate("#orochi", "alice", "mallory"));
}

test "only one pending transfer per channel" {
    var store = try seedStore();
    defer store.deinit();

    _ = try store.initiate("#orochi", "alice", "bob");
    try testing.expectError(error.PendingExists, store.initiate("#OROCHI", "alice", "carol"));
}

test "founder or recipient can cancel, unrelated account cannot" {
    var store = try seedStore();
    defer store.deinit();

    const initiated = try store.initiate("#orochi", "alice", "bob");
    try testing.expectError(error.CancelAccountMismatch, store.cancel(initiated.pending.token, "carol"));

    var cancelled = try store.cancel(initiated.pending.token, "ALICE");
    defer store.deinitCancelled(&cancelled);
    try testing.expectEqual(TransferNumeric.RPL_CHANTRANSFERCANCELLED, cancelled.numeric);
    try testing.expectEqualStrings("#orochi", cancelled.pending.channel);
    try testing.expectEqualStrings("bob", cancelled.pending.to_account);
    try testing.expectEqual(@as(usize, 0), store.pendingCount());
}

test "expired token is removed and cannot commit" {
    var store = Store.initWithParams(testing.allocator, .{ .pending_ttl_ms = 10 });
    defer store.deinit();
    _ = try store.addAccount("alice");
    _ = try store.addAccount("bob");
    _ = try store.registerChannel("#ops", "alice");

    const initiated = try store.initiateAt("#ops", "alice", "bob", 5);
    try testing.expectError(error.PendingExpired, store.confirmAt(initiated.pending.token, "bob", 15));
    try testing.expectEqualStrings("alice", store.founderOf("#ops").?);
    try testing.expectEqual(@as(usize, 0), store.pendingCount());
}

test "expire removes all due pending transfers" {
    var store = Store.initWithParams(testing.allocator, .{ .pending_ttl_ms = 10 });
    defer store.deinit();
    _ = try store.addAccount("alice");
    _ = try store.addAccount("bob");
    _ = try store.addAccount("carol");
    _ = try store.addAccount("dave");
    _ = try store.registerChannel("#a", "alice");
    _ = try store.registerChannel("#b", "carol");

    _ = try store.initiateAt("#a", "alice", "bob", 1);
    _ = try store.initiateAt("#b", "carol", "dave", 20);
    try testing.expectEqual(@as(usize, 1), store.expire(11));
    try testing.expectEqual(@as(usize, 1), store.pendingCount());
    try testing.expectEqual(@as(usize, 1), store.expire(30));
    try testing.expectEqual(@as(usize, 0), store.pendingCount());
}

test "account and channel validation reject malformed names" {
    try testing.expectError(error.InvalidChannel, validateChannel("orochi"));
    try testing.expectError(error.InvalidChannel, validateChannel("#bad name"));
    try testing.expectError(error.InvalidAccount, validateAccount(""));
    try testing.expectError(error.InvalidAccount, validateAccount("bad!acct"));
}

test "capacity limits are enforced without leaking" {
    var store = Store.initWithParams(testing.allocator, .{ .max_accounts = 1, .max_channels = 1, .max_pending = 1 });
    defer store.deinit();

    _ = try store.addAccount("alice");
    try testing.expectError(error.TooManyAccounts, store.addAccount("bob"));
    _ = try store.registerChannel("#a", "alice");
    try testing.expectError(error.ChannelExists, store.registerChannel("#A", "alice"));
}

test "parse real CHANNEL transfer commands" {
    const init = try parseCommand(&.{ "CHANNEL", "TRANSFER", "#orochi", "bob" });
    try testing.expectEqualStrings("#orochi", init.initiate.channel);
    try testing.expectEqualStrings("bob", init.initiate.to_account);

    const token = try TransferToken.parse("0123456789abcdef0123456789abcdef");
    const confirm = try parseCommand(&.{ "CS", "TRANSFER-CONFIRM", "0123456789ABCDEF0123456789ABCDEF" });
    try testing.expect(confirm.confirm.token.eql(token));

    const cancel = try parseCommand(&.{ "CHANNEL", "CANCELTRANSFER", "0123456789abcdef0123456789abcdef" });
    try testing.expect(cancel.cancel.token.eql(token));

    const expire_cmd = try parseCommand(&.{ "CHANNEL", "TRANSFER-EXPIRE", "1234" });
    try testing.expectEqual(@as(u64, 1234), expire_cmd.expire.now_ms);
}

test "parser rejects pseudo-client service syntax" {
    try testing.expectError(error.InvalidCommand, parseCommand(&.{ "PRIVMSG", "ChanServ", ":TRANSFER", "#orochi", "bob" }));
    try testing.expectError(error.InvalidCommand, parseCommand(&.{ "ChanServ", "TRANSFER", "#orochi", "bob" }));
}

test "parser validates arity and token form" {
    try testing.expectError(error.NeedMoreParams, parseCommand(&.{ "CHANNEL", "TRANSFER", "#orochi" }));
    try testing.expectError(error.TooManyParams, parseCommand(&.{ "CHANNEL", "TRANSFER", "#orochi", "bob", "extra" }));
    try testing.expectError(error.InvalidToken, parseCommand(&.{ "CHANNEL", "TRANSFER-CONFIRM", "not-a-token" }));
    try testing.expectError(error.InvalidTimestamp, parseCommand(&.{ "CHANNEL", "TRANSFER-EXPIRE", "soon" }));
}

test "numeric mapping covers state-machine failures" {
    try testing.expectEqual(TransferNumeric.ERR_NOSUCHCHANNEL, TransferNumeric.fromError(error.ChannelUnknown).?);
    try testing.expectEqual(TransferNumeric.ERR_ERRONEUSNICKNAME, TransferNumeric.fromError(error.SameAccount).?);
    try testing.expectEqual(TransferNumeric.ERR_CHANOPRIVSNEEDED, TransferNumeric.fromError(error.NotFounder).?);
    try testing.expectEqual(TransferNumeric.ERR_INVALIDTOKEN, TransferNumeric.fromError(error.PendingExpired).?);
    try testing.expect(TransferNumeric.fromError(error.OutOfMemory) == null);
}

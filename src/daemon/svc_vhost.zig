//! Pure service-side virtual-host request state.
//!
//! Services using this module are represented as server commands and numeric
//! outcomes by the caller. This file intentionally contains no daemon or proto
//! imports and never models NickServ/ChanServ/MemoServ-style pseudo-clients.

const std = @import("std");

pub const default_max_requests: usize = 4096;
pub const default_max_accounts: usize = 4096;
pub const default_max_account_bytes: usize = 128;
pub const default_max_oper_bytes: usize = 64;
pub const default_max_vhost_bytes: usize = 255;
pub const default_max_reason_bytes: usize = 300;
pub const dns_label_max_bytes: usize = 63;

pub const Limits = struct {
    max_requests: usize = default_max_requests,
    max_accounts: usize = default_max_accounts,
    max_account_bytes: usize = default_max_account_bytes,
    max_oper_bytes: usize = default_max_oper_bytes,
    max_vhost_bytes: usize = default_max_vhost_bytes,
    max_reason_bytes: usize = default_max_reason_bytes,
};

pub const Status = enum {
    pending,
    approved,
    rejected,
};

pub const ApplyResult = enum {
    requested,
    approved,
    rejected,
    activated,
};

pub const Error = std.mem.Allocator.Error || error{
    InvalidAccount,
    AccountTooLong,
    InvalidOper,
    OperTooLong,
    InvalidVHost,
    VHostTooShort,
    VHostTooLong,
    InvalidReason,
    ReasonTooLong,
    QueueFull,
    AccountLimit,
    NotFound,
    NotPending,
    NotApproved,
    AlreadyActive,
    OutputTooSmall,
};

pub const ParseError = error{
    EmptyCommand,
    UnknownCommand,
    MissingParameter,
    TooManyParameters,
};

pub const CommandError = ParseError || Error;

pub const RequestView = struct {
    account: []const u8,
    vhost: []const u8,
    status: Status,
    requested_ms: i64,
    decided_ms: i64,
    decided_by: []const u8,
    reason: []const u8,
};

pub const AccountView = struct {
    account: []const u8,
    active_vhost: ?[]const u8,
    approved_count: usize,
};

pub const ParsedCommand = union(enum) {
    request: struct {
        account: []const u8,
        vhost: []const u8,
    },
    approve: struct {
        oper: []const u8,
        account: []const u8,
    },
    reject: struct {
        oper: []const u8,
        account: []const u8,
        reason: []const u8,
    },
    activate: struct {
        account: []const u8,
        vhost: ?[]const u8 = null,
    },
};

const Request = struct {
    account: []const u8,
    vhost: []const u8,
    status: Status,
    requested_ms: i64,
    decided_ms: i64 = 0,
    decided_by: []const u8,
    reason: []const u8,

    fn view(self: *const Request) RequestView {
        return .{
            .account = self.account,
            .vhost = self.vhost,
            .status = self.status,
            .requested_ms = self.requested_ms,
            .decided_ms = self.decided_ms,
            .decided_by = self.decided_by,
            .reason = self.reason,
        };
    }

    fn deinit(self: *Request, allocator: std.mem.Allocator) void {
        allocator.free(self.account);
        allocator.free(self.vhost);
        allocator.free(self.decided_by);
        allocator.free(self.reason);
        self.* = undefined;
    }
};

const AccountRecord = struct {
    account: []const u8,
    approved: std.ArrayListUnmanaged([]const u8) = .empty,
    active_index: ?usize = null,

    fn view(self: *const AccountRecord) AccountView {
        return .{
            .account = self.account,
            .active_vhost = if (self.active_index) |index| self.approved.items[index] else null,
            .approved_count = self.approved.items.len,
        };
    }

    fn findApproved(self: *const AccountRecord, vhost: []const u8) ?usize {
        for (self.approved.items, 0..) |approved, index| {
            if (hostEquals(approved, vhost)) return index;
        }
        return null;
    }

    fn deinit(self: *AccountRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.account);
        for (self.approved.items) |host| allocator.free(host);
        self.approved.deinit(allocator);
        self.* = undefined;
    }
};

pub const Store = struct {
    allocator: std.mem.Allocator,
    limits: Limits,
    requests: std.StringHashMap(Request),
    accounts: std.StringHashMap(AccountRecord),
    request_count: usize = 0,
    account_count: usize = 0,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, limits: Limits) Self {
        return .{
            .allocator = allocator,
            .limits = limits,
            .requests = std.StringHashMap(Request).init(allocator),
            .accounts = std.StringHashMap(AccountRecord).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.clearRequests();
        self.clearAccounts();
        self.requests.deinit();
        self.accounts.deinit();
        self.* = undefined;
    }

    pub fn request(self: *Self, account: []const u8, vhost: []const u8, now_ms: i64) Error!void {
        try validateAccountWith(self.limits, account);
        try validateVHostWith(self.limits, vhost);

        var next = try makeRequest(self.allocator, account, vhost, now_ms);
        errdefer next.deinit(self.allocator);

        if (self.findRequestKey(account)) |key| {
            const slot = self.requests.getPtr(key).?;
            slot.deinit(self.allocator);
            slot.* = next;
            return;
        }

        if (self.request_count >= self.limits.max_requests) return error.QueueFull;

        const key = try makeFoldedKey(self.allocator, account);
        errdefer self.allocator.free(key);
        try self.requests.putNoClobber(key, next);
        self.request_count += 1;
    }

    pub fn approve(self: *Self, oper: []const u8, account: []const u8, now_ms: i64) Error!void {
        try validateOperWith(self.limits, oper);
        try validateAccountWith(self.limits, account);

        const request_ptr = self.findRequest(account) orelse return error.NotFound;
        if (request_ptr.status != .pending) return error.NotPending;

        const approved_host = request_ptr.vhost;
        var record = try self.ensureAccount(request_ptr.account);
        if (record.findApproved(approved_host) == null) {
            const host_copy = try self.allocator.dupe(u8, approved_host);
            errdefer self.allocator.free(host_copy);
            try record.approved.append(self.allocator, host_copy);
        }

        const oper_copy = try self.allocator.dupe(u8, oper);
        errdefer self.allocator.free(oper_copy);

        self.allocator.free(request_ptr.decided_by);
        request_ptr.decided_by = oper_copy;
        request_ptr.status = .approved;
        request_ptr.decided_ms = now_ms;
    }

    pub fn reject(self: *Self, oper: []const u8, account: []const u8, reason: []const u8, now_ms: i64) Error!void {
        try validateOperWith(self.limits, oper);
        try validateAccountWith(self.limits, account);
        try validateReasonWith(self.limits, reason);

        const request_ptr = self.findRequest(account) orelse return error.NotFound;
        if (request_ptr.status != .pending) return error.NotPending;

        const oper_copy = try self.allocator.dupe(u8, oper);
        errdefer self.allocator.free(oper_copy);
        const reason_copy = try self.allocator.dupe(u8, reason);
        errdefer self.allocator.free(reason_copy);

        self.allocator.free(request_ptr.decided_by);
        self.allocator.free(request_ptr.reason);
        request_ptr.decided_by = oper_copy;
        request_ptr.reason = reason_copy;
        request_ptr.status = .rejected;
        request_ptr.decided_ms = now_ms;
    }

    pub fn activate(self: *Self, account: []const u8, maybe_vhost: ?[]const u8) Error!void {
        try validateAccountWith(self.limits, account);
        if (maybe_vhost) |vhost| try validateVHostWith(self.limits, vhost);

        const record = self.findAccount(account) orelse return error.NotFound;
        const index = if (maybe_vhost) |vhost|
            record.findApproved(vhost) orelse return error.NotApproved
        else if (record.approved.items.len == 0)
            return error.NotApproved
        else
            record.approved.items.len - 1;

        if (record.active_index != null and record.active_index.? == index) return error.AlreadyActive;
        record.active_index = index;
    }

    pub fn apply(self: *Self, command: ParsedCommand, now_ms: i64) Error!ApplyResult {
        switch (command) {
            .request => |cmd| {
                try self.request(cmd.account, cmd.vhost, now_ms);
                return .requested;
            },
            .approve => |cmd| {
                try self.approve(cmd.oper, cmd.account, now_ms);
                return .approved;
            },
            .reject => |cmd| {
                try self.reject(cmd.oper, cmd.account, cmd.reason, now_ms);
                return .rejected;
            },
            .activate => |cmd| {
                try self.activate(cmd.account, cmd.vhost);
                return .activated;
            },
        }
    }

    pub fn parseAndApply(self: *Self, line: []const u8, now_ms: i64) CommandError!ApplyResult {
        return self.apply(try parseCommand(line), now_ms);
    }

    pub fn getRequest(self: *const Self, account: []const u8) ?RequestView {
        const request_ptr = self.findRequestConst(account) orelse return null;
        return request_ptr.view();
    }

    pub fn getAccount(self: *const Self, account: []const u8) ?AccountView {
        const record = self.findAccountConst(account) orelse return null;
        return record.view();
    }

    pub fn activeVHost(self: *const Self, account: []const u8) ?[]const u8 {
        const record = self.findAccountConst(account) orelse return null;
        const index = record.active_index orelse return null;
        return record.approved.items[index];
    }

    pub fn approvedList(self: *const Self, account: []const u8, out: [][]const u8) Error![]const []const u8 {
        const record = self.findAccountConst(account) orelse return error.NotFound;
        if (out.len < record.approved.items.len) return error.OutputTooSmall;
        @memcpy(out[0..record.approved.items.len], record.approved.items);
        return out[0..record.approved.items.len];
    }

    pub fn pendingList(self: *const Self, out: []RequestView) Error![]const RequestView {
        const needed = self.pendingCount();
        if (out.len < needed) return error.OutputTooSmall;

        var index: usize = 0;
        var it = self.requests.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.status != .pending) continue;
            out[index] = entry.value_ptr.view();
            index += 1;
        }
        return out[0..index];
    }

    pub fn clearRequest(self: *Self, account: []const u8) void {
        const key = self.findRequestKey(account) orelse return;
        var removed = self.requests.fetchRemove(key).?;
        self.allocator.free(removed.key);
        removed.value.deinit(self.allocator);
        self.request_count -= 1;
    }

    fn clearRequests(self: *Self) void {
        var it = self.requests.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.requests.clearRetainingCapacity();
        self.request_count = 0;
    }

    fn clearAccounts(self: *Self) void {
        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.accounts.clearRetainingCapacity();
        self.account_count = 0;
    }

    fn ensureAccount(self: *Self, account: []const u8) Error!*AccountRecord {
        if (self.findAccount(account)) |record| return record;
        if (self.account_count >= self.limits.max_accounts) return error.AccountLimit;

        const key = try makeFoldedKey(self.allocator, account);
        errdefer self.allocator.free(key);
        const account_copy = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(account_copy);

        try self.accounts.putNoClobber(key, .{ .account = account_copy });
        self.account_count += 1;
        return self.accounts.getPtr(key).?;
    }

    fn findRequest(self: *Self, account: []const u8) ?*Request {
        const key = self.findRequestKey(account) orelse return null;
        return self.requests.getPtr(key);
    }

    fn findRequestConst(self: *const Self, account: []const u8) ?*const Request {
        const key = self.findRequestKey(account) orelse return null;
        return self.requests.getPtr(key);
    }

    fn findRequestKey(self: *const Self, account: []const u8) ?[]const u8 {
        var it = self.requests.iterator();
        while (it.next()) |entry| {
            if (foldedEquals(entry.key_ptr.*, account)) return entry.key_ptr.*;
        }
        return null;
    }

    fn findAccount(self: *Self, account: []const u8) ?*AccountRecord {
        const key = self.findAccountKey(account) orelse return null;
        return self.accounts.getPtr(key);
    }

    fn findAccountConst(self: *const Self, account: []const u8) ?*const AccountRecord {
        const key = self.findAccountKey(account) orelse return null;
        return self.accounts.getPtr(key);
    }

    fn findAccountKey(self: *const Self, account: []const u8) ?[]const u8 {
        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            if (foldedEquals(entry.key_ptr.*, account)) return entry.key_ptr.*;
        }
        return null;
    }

    fn pendingCount(self: *const Self) usize {
        var total: usize = 0;
        var it = self.requests.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.status == .pending) total += 1;
        }
        return total;
    }
};

pub fn parseCommand(line: []const u8) ParseError!ParsedCommand {
    var parser = Parser{ .line = line };
    const first = parser.nextToken() orelse return error.EmptyCommand;
    const verb = if (isCommandPrefix(first))
        parser.nextToken() orelse return error.MissingParameter
    else
        first;

    if (asciiEqlIgnoreCase(verb, "REQUEST")) {
        const account = parser.nextToken() orelse return error.MissingParameter;
        const vhost = parser.nextToken() orelse return error.MissingParameter;
        try parser.expectEnd();
        return .{ .request = .{ .account = account, .vhost = vhost } };
    }
    if (asciiEqlIgnoreCase(verb, "APPROVE")) {
        const oper = parser.nextToken() orelse return error.MissingParameter;
        const account = parser.nextToken() orelse return error.MissingParameter;
        try parser.expectEnd();
        return .{ .approve = .{ .oper = oper, .account = account } };
    }
    if (asciiEqlIgnoreCase(verb, "REJECT")) {
        const oper = parser.nextToken() orelse return error.MissingParameter;
        const account = parser.nextToken() orelse return error.MissingParameter;
        const reason = parser.nextTrailing() orelse return error.MissingParameter;
        return .{ .reject = .{ .oper = oper, .account = account, .reason = reason } };
    }
    if (asciiEqlIgnoreCase(verb, "ACTIVATE")) {
        const account = parser.nextToken() orelse return error.MissingParameter;
        const vhost = parser.nextToken();
        try parser.expectEnd();
        return .{ .activate = .{ .account = account, .vhost = vhost } };
    }
    return error.UnknownCommand;
}

pub fn validateVHost(vhost: []const u8) Error!void {
    return validateVHostWith(.{}, vhost);
}

pub fn validateAccount(account: []const u8) Error!void {
    return validateAccountWith(.{}, account);
}

pub fn validateOper(oper: []const u8) Error!void {
    return validateOperWith(.{}, oper);
}

fn makeRequest(allocator: std.mem.Allocator, account: []const u8, vhost: []const u8, now_ms: i64) Error!Request {
    const account_copy = try allocator.dupe(u8, account);
    errdefer allocator.free(account_copy);
    const vhost_copy = try makeLowerHost(allocator, vhost);
    errdefer allocator.free(vhost_copy);
    const decided_by = try allocator.dupe(u8, "");
    errdefer allocator.free(decided_by);
    const reason = try allocator.dupe(u8, "");
    errdefer allocator.free(reason);

    return .{
        .account = account_copy,
        .vhost = vhost_copy,
        .status = .pending,
        .requested_ms = now_ms,
        .decided_by = decided_by,
        .reason = reason,
    };
}

fn makeLowerHost(allocator: std.mem.Allocator, vhost: []const u8) Error![]const u8 {
    const copy = try allocator.dupe(u8, vhost);
    for (copy) |*byte| byte.* = std.ascii.toLower(byte.*);
    return copy;
}

fn makeFoldedKey(allocator: std.mem.Allocator, text: []const u8) Error![]const u8 {
    const key = try allocator.dupe(u8, text);
    for (key) |*byte| byte.* = std.ascii.toLower(byte.*);
    return key;
}

fn foldedEquals(stored_key: []const u8, value: []const u8) bool {
    if (stored_key.len != value.len) return false;
    for (stored_key, value) |left, right| {
        if (left != std.ascii.toLower(right)) return false;
    }
    return true;
}

fn hostEquals(left: []const u8, right: []const u8) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b| {
        if (std.ascii.toLower(a) != std.ascii.toLower(b)) return false;
    }
    return true;
}

fn validateAccountWith(limits: Limits, account: []const u8) Error!void {
    if (account.len == 0) return error.InvalidAccount;
    if (account.len > limits.max_account_bytes) return error.AccountTooLong;
    for (account) |byte| {
        if (byte <= 0x20 or byte == 0x7f or byte == ':') return error.InvalidAccount;
    }
}

fn validateOperWith(limits: Limits, oper: []const u8) Error!void {
    if (oper.len == 0) return error.InvalidOper;
    if (oper.len > limits.max_oper_bytes) return error.OperTooLong;
    for (oper) |byte| {
        if (byte <= 0x20 or byte == 0x7f or byte == ':') return error.InvalidOper;
    }
}

fn validateReasonWith(limits: Limits, reason: []const u8) Error!void {
    if (reason.len == 0) return error.InvalidReason;
    if (reason.len > limits.max_reason_bytes) return error.ReasonTooLong;
    for (reason) |byte| {
        if (byte < 0x20 or byte == 0x7f) return error.InvalidReason;
    }
}

fn validateVHostWith(limits: Limits, vhost: []const u8) Error!void {
    if (vhost.len == 0) return error.VHostTooShort;
    if (vhost.len > limits.max_vhost_bytes) return error.VHostTooLong;
    if (vhost[0] == '.' or vhost[vhost.len - 1] == '.') return error.InvalidVHost;

    var label_len: usize = 0;
    var label_start: usize = 0;
    for (vhost, 0..) |byte, index| {
        if (!validVHostByte(byte)) return error.InvalidVHost;
        if (byte == '.') {
            try validateLabel(vhost[label_start..index], label_len);
            label_len = 0;
            label_start = index + 1;
        } else {
            label_len += 1;
            if (label_len > dns_label_max_bytes) return error.InvalidVHost;
        }
    }
    try validateLabel(vhost[label_start..], label_len);
}

fn validateLabel(label: []const u8, label_len: usize) Error!void {
    if (label_len == 0) return error.InvalidVHost;
    if (label[0] == '-' or label[label.len - 1] == '-') return error.InvalidVHost;
}

fn validVHostByte(byte: u8) bool {
    return switch (byte) {
        'A'...'Z', 'a'...'z', '0'...'9', '.', '-' => true,
        else => false,
    };
}

fn isCommandPrefix(token: []const u8) bool {
    return asciiEqlIgnoreCase(token, "VHOST") or
        asciiEqlIgnoreCase(token, "SVHOST") or
        asciiEqlIgnoreCase(token, "SVCVHOST");
}

fn asciiEqlIgnoreCase(left: []const u8, right: []const u8) bool {
    return std.ascii.eqlIgnoreCase(left, right);
}

const Parser = struct {
    line: []const u8,
    index: usize = 0,

    fn nextToken(self: *Parser) ?[]const u8 {
        self.skipSpaces();
        if (self.index >= self.line.len) return null;
        if (self.line[self.index] == ':') return null;
        const start = self.index;
        while (self.index < self.line.len and self.line[self.index] != ' ') : (self.index += 1) {}
        return self.line[start..self.index];
    }

    fn nextTrailing(self: *Parser) ?[]const u8 {
        self.skipSpaces();
        if (self.index >= self.line.len) return null;
        if (self.line[self.index] == ':') {
            const trailing = self.line[self.index + 1 ..];
            self.index = self.line.len;
            return trailing;
        }
        const token = self.nextToken() orelse return null;
        if (self.nextToken() != null) return null;
        return token;
    }

    fn expectEnd(self: *Parser) ParseError!void {
        if (self.nextToken() != null) return error.TooManyParameters;
    }

    fn skipSpaces(self: *Parser) void {
        while (self.index < self.line.len and self.line[self.index] == ' ') : (self.index += 1) {}
    }
};

const testing = std.testing;

test "request stores normalized pending vhost and borrowed request view" {
    var store = Store.init(testing.allocator, .{});
    defer store.deinit();

    try store.request("Alice", "Staff.Example.Net", 1000);
    const request_view = store.getRequest("alice").?;

    try testing.expectEqualStrings("Alice", request_view.account);
    try testing.expectEqualStrings("staff.example.net", request_view.vhost);
    try testing.expectEqual(Status.pending, request_view.status);
    try testing.expectEqual(@as(i64, 1000), request_view.requested_ms);
    try testing.expectEqual(@as(i64, 0), request_view.decided_ms);
    try testing.expectEqualStrings("", request_view.decided_by);
    try testing.expectEqualStrings("", request_view.reason);
}

test "vhost validator enforces host syntax length and allowed bytes" {
    try validateVHost("a.example");
    try validateVHost("A-1.example.net");
    try validateVHost("singlelabel");

    try testing.expectError(error.VHostTooShort, validateVHost(""));
    try testing.expectError(error.InvalidVHost, validateVHost(".leading.example"));
    try testing.expectError(error.InvalidVHost, validateVHost("trailing.example."));
    try testing.expectError(error.InvalidVHost, validateVHost("two..dots.example"));
    try testing.expectError(error.InvalidVHost, validateVHost("-bad.example"));
    try testing.expectError(error.InvalidVHost, validateVHost("bad-.example"));
    try testing.expectError(error.InvalidVHost, validateVHost("bad_host.example"));
    try testing.expectError(error.InvalidVHost, validateVHost("bad host.example"));
    try testing.expectError(error.InvalidVHost, validateVHost("bad/example"));

    var long_label: [64]u8 = undefined;
    @memset(&long_label, 'a');
    try testing.expectError(error.InvalidVHost, validateVHost(long_label[0..]));
}

test "request replacement keeps one pending entry per account" {
    var store = Store.init(testing.allocator, .{});
    defer store.deinit();

    try store.request("Alice", "old.example", 10);
    try store.request("ALICE", "new.example", 20);

    var out: [2]RequestView = undefined;
    const pending = try store.pendingList(&out);
    try testing.expectEqual(@as(usize, 1), pending.len);
    try testing.expectEqualStrings("ALICE", pending[0].account);
    try testing.expectEqualStrings("new.example", pending[0].vhost);
    try testing.expectEqual(@as(i64, 20), pending[0].requested_ms);
}

test "approve stores vhost for account and removes it from pending list" {
    var store = Store.init(testing.allocator, .{});
    defer store.deinit();

    try store.request("alice", "Staff.Example", 100);
    try store.approve("OperOne", "ALICE", 200);

    const request_view = store.getRequest("alice").?;
    try testing.expectEqual(Status.approved, request_view.status);
    try testing.expectEqual(@as(i64, 200), request_view.decided_ms);
    try testing.expectEqualStrings("OperOne", request_view.decided_by);

    const account = store.getAccount("alice").?;
    try testing.expectEqualStrings("alice", account.account);
    try testing.expectEqual(@as(usize, 1), account.approved_count);
    try testing.expect(account.active_vhost == null);

    var approved_buf: [2][]const u8 = undefined;
    const approved = try store.approvedList("ALICE", &approved_buf);
    try testing.expectEqual(@as(usize, 1), approved.len);
    try testing.expectEqualStrings("staff.example", approved[0]);

    var pending_buf: [1]RequestView = undefined;
    const pending = try store.pendingList(&pending_buf);
    try testing.expectEqual(@as(usize, 0), pending.len);
}

test "activate requires approved vhost and supports explicit or latest host" {
    var store = Store.init(testing.allocator, .{});
    defer store.deinit();

    try store.request("alice", "one.example", 1);
    try store.approve("oper", "alice", 2);
    try testing.expectError(error.NotApproved, store.activate("alice", "two.example"));

    try store.activate("alice", "ONE.EXAMPLE");
    try testing.expectEqualStrings("one.example", store.activeVHost("ALICE").?);
    try testing.expectError(error.AlreadyActive, store.activate("alice", null));

    try store.request("alice", "two.example", 3);
    try store.approve("oper", "alice", 4);
    try store.activate("alice", null);
    try testing.expectEqualStrings("two.example", store.activeVHost("alice").?);
}

test "reject records oper reason and does not approve the vhost" {
    var store = Store.init(testing.allocator, .{});
    defer store.deinit();

    try store.request("alice", "reject.example", 10);
    try store.reject("oper", "alice", "does not identify the user", 20);

    const request_view = store.getRequest("alice").?;
    try testing.expectEqual(Status.rejected, request_view.status);
    try testing.expectEqualStrings("oper", request_view.decided_by);
    try testing.expectEqualStrings("does not identify the user", request_view.reason);
    try testing.expect(store.getAccount("alice") == null);
    try testing.expectError(error.NotFound, store.activate("alice", null));
}

test "limits reject queue account oper and reason overflows without leaks" {
    var bounded_queue = Store.init(testing.allocator, .{
        .max_requests = 1,
        .max_account_bytes = 5,
        .max_oper_bytes = 4,
        .max_reason_bytes = 4,
    });
    defer bounded_queue.deinit();

    try bounded_queue.request("alice", "one.example", 1);
    try testing.expectError(error.QueueFull, bounded_queue.request("bob", "two.example", 2));
    try testing.expectError(error.AccountTooLong, bounded_queue.request("charlie", "two.example", 2));
    try testing.expectError(error.OperTooLong, bounded_queue.approve("operx", "alice", 3));
    try testing.expectError(error.ReasonTooLong, bounded_queue.reject("oper", "alice", "later", 4));

    var bounded_accounts = Store.init(testing.allocator, .{ .max_accounts = 1 });
    defer bounded_accounts.deinit();

    try bounded_accounts.request("alice", "one.example", 1);
    try bounded_accounts.approve("oper", "alice", 2);
    try bounded_accounts.request("bob", "two.example", 3);
    try testing.expectError(error.AccountLimit, bounded_accounts.approve("oper", "bob", 4));
}

test "pending list reports output too small and clear removes request storage" {
    var store = Store.init(testing.allocator, .{});
    defer store.deinit();

    try store.request("alice", "one.example", 1);
    try store.request("bob", "two.example", 2);
    var too_small: [1]RequestView = undefined;
    try testing.expectError(error.OutputTooSmall, store.pendingList(&too_small));

    store.clearRequest("alice");
    try testing.expect(store.getRequest("alice") == null);

    var out: [1]RequestView = undefined;
    const pending = try store.pendingList(&out);
    try testing.expectEqual(@as(usize, 1), pending.len);
    try testing.expectEqualStrings("bob", pending[0].account);
}

test "parser accepts real service command forms without pseudo client names" {
    const req = try parseCommand("VHOST REQUEST alice Staff.Example");
    try testing.expectEqualStrings("alice", req.request.account);
    try testing.expectEqualStrings("Staff.Example", req.request.vhost);

    const approve = try parseCommand("SVHOST APPROVE oper Alice");
    try testing.expectEqualStrings("oper", approve.approve.oper);
    try testing.expectEqualStrings("Alice", approve.approve.account);

    const reject_cmd = try parseCommand("SVCVHOST REJECT oper alice :not tied to account");
    try testing.expectEqualStrings("oper", reject_cmd.reject.oper);
    try testing.expectEqualStrings("alice", reject_cmd.reject.account);
    try testing.expectEqualStrings("not tied to account", reject_cmd.reject.reason);

    const activate = try parseCommand("ACTIVATE alice staff.example");
    try testing.expectEqualStrings("alice", activate.activate.account);
    try testing.expectEqualStrings("staff.example", activate.activate.vhost.?);
}

test "parser rejects unknown missing and extra parameters" {
    try testing.expectError(error.EmptyCommand, parseCommand("   "));
    try testing.expectError(error.UnknownCommand, parseCommand("NickServ REQUEST alice host.example"));
    try testing.expectError(error.MissingParameter, parseCommand("VHOST REQUEST alice"));
    try testing.expectError(error.TooManyParameters, parseCommand("APPROVE oper alice extra"));
    try testing.expectError(error.MissingParameter, parseCommand("REJECT oper alice"));
}

test "parse and apply drives request approve and activation flow" {
    var store = Store.init(testing.allocator, .{});
    defer store.deinit();

    try testing.expectEqual(ApplyResult.requested, try store.parseAndApply("VHOST REQUEST alice Fancy.Example", 10));
    try testing.expectEqual(ApplyResult.approved, try store.parseAndApply("VHOST APPROVE oper alice", 20));
    try testing.expectEqual(ApplyResult.activated, try store.parseAndApply("VHOST ACTIVATE alice fancy.example", 30));

    const request_view = store.getRequest("alice").?;
    try testing.expectEqual(Status.approved, request_view.status);
    try testing.expectEqualStrings("fancy.example", store.activeVHost("alice").?);
}

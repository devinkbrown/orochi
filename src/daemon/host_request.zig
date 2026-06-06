//! Virtual-host request approval store.
//!
//! This module owns a bounded set of per-account virtual-host requests. It does
//! not perform any network I/O and leaves application of approved hosts to the
//! caller.

const std = @import("std");

comptime {
    if (@bitSizeOf(usize) != 64) @compileError("host_request requires a 64-bit target");
}

/// Review state for a virtual-host request.
pub const Status = enum {
    pending,
    approved,
    denied,
};

/// A stored virtual-host request.
///
/// String fields are owned by the queue while the request is stored. A request
/// returned by `Queue.take` transfers those owned strings to the caller, which
/// must release them with `deinit`.
pub const Request = struct {
    /// Account name as submitted by the user.
    account: []const u8,
    /// Requested virtual host.
    vhost: []const u8,
    /// Current review status.
    status: Status,
    /// Wall-clock time the request was submitted, in milliseconds.
    requested_ms: i64,
    /// Wall-clock time the request was approved or denied, in milliseconds.
    decided_ms: i64 = 0,
    /// Denial reason. Empty unless `status` is `denied`.
    reason: []const u8,

    /// Release the owned strings held by this request.
    pub fn deinit(self: *Request, allocator: std.mem.Allocator) void {
        allocator.free(self.account);
        allocator.free(self.vhost);
        allocator.free(self.reason);
        self.* = undefined;
    }
};

/// Runtime bounds for a virtual-host request queue.
pub const Params = struct {
    /// Maximum number of account entries retained by the queue.
    max_requests: usize = 4096,
    /// Maximum account name length in bytes.
    max_account_bytes: usize = 128,
    /// Minimum virtual-host length in bytes.
    min_vhost_bytes: usize = 1,
    /// Maximum virtual-host length in bytes.
    max_vhost_bytes: usize = 255,
    /// Maximum denial reason length in bytes.
    max_reason_bytes: usize = 300,
};

/// Errors returned by virtual-host request operations.
pub const QueueError = std.mem.Allocator.Error || error{
    InvalidAccount,
    AccountTooLong,
    InvalidVHost,
    VHostTooShort,
    VHostTooLong,
    InvalidReason,
    ReasonTooLong,
    QueueFull,
    NotFound,
    NotPending,
    OutputTooSmall,
};

/// Bounded per-account virtual-host request queue.
pub const Queue = struct {
    allocator: std.mem.Allocator,
    params: Params,
    requests: std.StringHashMap(Request),
    count: usize = 0,

    const Self = @This();

    /// Create an empty queue using `allocator` and `params`.
    pub fn init(allocator: std.mem.Allocator, params: Params) Self {
        return .{
            .allocator = allocator,
            .params = params,
            .requests = std.StringHashMap(Request).init(allocator),
        };
    }

    /// Release all owned account keys and request strings.
    pub fn deinit(self: *Self) void {
        self.clearAll();
        self.requests.deinit();
        self.* = undefined;
    }

    /// Submit or replace the active request for `account`.
    ///
    /// `account` and `vhost` are copied. Account lookup is case-insensitive;
    /// the originally submitted account spelling is retained in the request.
    pub fn submit(self: *Self, account: []const u8, vhost: []const u8, now: i64) QueueError!void {
        try validateAccount(self.params, account);
        try validateVHost(self.params, vhost);

        var next = try makeRequest(self.allocator, account, vhost, now);
        errdefer next.deinit(self.allocator);

        if (self.findStoredKey(account)) |key| {
            const slot = self.requests.getPtr(key).?;
            slot.deinit(self.allocator);
            slot.* = next;
            return;
        }

        if (self.count >= self.params.max_requests) return error.QueueFull;

        const owned_key = try makeAccountKey(self.allocator, account);
        errdefer self.allocator.free(owned_key);

        try self.requests.putNoClobber(owned_key, next);
        self.count += 1;
    }

    /// Approve the pending request for `account`.
    pub fn approve(self: *Self, account: []const u8, now: i64) QueueError!void {
        try validateAccount(self.params, account);
        const request = self.findRequest(account) orelse return error.NotFound;
        if (request.status != .pending) return error.NotPending;

        request.status = .approved;
        request.decided_ms = now;
    }

    /// Deny the pending request for `account` with an owned copy of `reason`.
    pub fn deny(self: *Self, account: []const u8, reason: []const u8, now: i64) QueueError!void {
        try validateAccount(self.params, account);
        try validateReason(self.params, reason);

        const request = self.findRequest(account) orelse return error.NotFound;
        if (request.status != .pending) return error.NotPending;

        const reason_copy = try self.allocator.dupe(u8, reason);
        errdefer self.allocator.free(reason_copy);

        self.allocator.free(request.reason);
        request.reason = reason_copy;
        request.status = .denied;
        request.decided_ms = now;
    }

    /// Return the stored request for `account`, if present.
    ///
    /// The returned request is a borrowed view into the queue. Its string fields
    /// remain valid until the next mutating operation for that account or queue
    /// deinitialization.
    pub fn get(self: *const Self, account: []const u8) ?Request {
        const request = self.findRequestConst(account) orelse return null;
        return request.*;
    }

    /// Copy pending request views into `buf` for operator review.
    ///
    /// Returns `error.OutputTooSmall` when `buf` cannot hold every pending
    /// request. Returned strings are borrowed from the queue.
    pub fn pendingList(self: *const Self, buf: []Request) QueueError![]const Request {
        const needed = self.pendingCount();
        if (buf.len < needed) return error.OutputTooSmall;

        var index: usize = 0;
        var it = self.requests.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.status != .pending) continue;
            buf[index] = entry.value_ptr.*;
            index += 1;
        }
        return buf[0..index];
    }

    /// Remove and return the request for `account`, transferring string ownership.
    ///
    /// The caller must release a returned request with `Request.deinit`.
    pub fn take(self: *Self, account: []const u8) ?Request {
        const key = self.findStoredKey(account) orelse return null;
        const removed = self.requests.fetchRemove(key).?;
        self.allocator.free(removed.key);
        self.count -= 1;
        return removed.value;
    }

    /// Remove and release the request for `account`, if present.
    pub fn clear(self: *Self, account: []const u8) void {
        const key = self.findStoredKey(account) orelse return;
        var removed = self.requests.fetchRemove(key).?;
        self.allocator.free(removed.key);
        removed.value.deinit(self.allocator);
        self.count -= 1;
    }

    fn clearAll(self: *Self) void {
        var it = self.requests.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.requests.clearRetainingCapacity();
        self.count = 0;
    }

    fn findRequest(self: *Self, account: []const u8) ?*Request {
        const key = self.findStoredKey(account) orelse return null;
        return self.requests.getPtr(key);
    }

    fn findRequestConst(self: *const Self, account: []const u8) ?*const Request {
        const key = self.findStoredKey(account) orelse return null;
        return self.requests.getPtr(key);
    }

    fn findStoredKey(self: *const Self, account: []const u8) ?[]const u8 {
        var it = self.requests.iterator();
        while (it.next()) |entry| {
            if (accountMatches(entry.key_ptr.*, account)) return entry.key_ptr.*;
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

fn makeRequest(allocator: std.mem.Allocator, account: []const u8, vhost: []const u8, now: i64) QueueError!Request {
    const account_copy = try allocator.dupe(u8, account);
    errdefer allocator.free(account_copy);

    const vhost_copy = try allocator.dupe(u8, vhost);
    errdefer allocator.free(vhost_copy);

    const reason_copy = try allocator.dupe(u8, "");
    errdefer allocator.free(reason_copy);

    return .{
        .account = account_copy,
        .vhost = vhost_copy,
        .status = .pending,
        .requested_ms = now,
        .reason = reason_copy,
    };
}

fn makeAccountKey(allocator: std.mem.Allocator, account: []const u8) QueueError![]const u8 {
    const key = try allocator.dupe(u8, account);
    for (key) |*byte| {
        byte.* = std.ascii.toLower(byte.*);
    }
    return key;
}

fn accountMatches(stored_key: []const u8, account: []const u8) bool {
    if (stored_key.len != account.len) return false;
    for (stored_key, account) |left, right| {
        if (left != std.ascii.toLower(right)) return false;
    }
    return true;
}

fn validateAccount(params: Params, account: []const u8) QueueError!void {
    if (account.len == 0) return error.InvalidAccount;
    if (account.len > params.max_account_bytes) return error.AccountTooLong;
    for (account) |byte| {
        if (byte == 0 or byte <= 0x20 or byte == 0x7f) return error.InvalidAccount;
    }
}

fn validateVHost(params: Params, vhost: []const u8) QueueError!void {
    if (vhost.len < params.min_vhost_bytes) return error.VHostTooShort;
    if (vhost.len > params.max_vhost_bytes) return error.VHostTooLong;
    for (vhost) |byte| {
        if (!validVHostByte(byte)) return error.InvalidVHost;
    }
}

fn validateReason(params: Params, reason: []const u8) QueueError!void {
    if (reason.len == 0) return error.InvalidReason;
    if (reason.len > params.max_reason_bytes) return error.ReasonTooLong;
}

fn validVHostByte(byte: u8) bool {
    return switch (byte) {
        'A'...'Z', 'a'...'z', '0'...'9', '.', '-' => true,
        else => false,
    };
}

test "submit then get returns the stored pending request" {
    // Arrange
    var queue = Queue.init(std.testing.allocator, .{});
    defer queue.deinit();

    // Act
    try queue.submit("Alice", "staff.example.net", 1_000);
    const request = queue.get("Alice").?;

    // Assert
    try std.testing.expectEqualStrings("Alice", request.account);
    try std.testing.expectEqualStrings("staff.example.net", request.vhost);
    try std.testing.expectEqual(Status.pending, request.status);
    try std.testing.expectEqual(@as(i64, 1_000), request.requested_ms);
    try std.testing.expectEqual(@as(i64, 0), request.decided_ms);
    try std.testing.expectEqualStrings("", request.reason);
}

test "vhost validation accepts allowed bytes and rejects bad bytes" {
    // Arrange
    var queue = Queue.init(std.testing.allocator, .{});
    defer queue.deinit();

    // Act
    try queue.submit("alice", "Az-09.example", 1);

    // Assert
    try std.testing.expectError(error.InvalidVHost, queue.submit("bob", "bad_host", 2));
    try std.testing.expectError(error.InvalidVHost, queue.submit("carol", "bad host", 3));
    try std.testing.expectError(error.InvalidVHost, queue.submit("dave", "bad/host", 4));
    try std.testing.expect(queue.get("alice") != null);
}

test "vhost validation enforces configured length bounds" {
    // Arrange
    var queue = Queue.init(std.testing.allocator, .{
        .min_vhost_bytes = 3,
        .max_vhost_bytes = 8,
    });
    defer queue.deinit();

    // Act
    try queue.submit("alice", "a.b", 1);

    // Assert
    try std.testing.expectError(error.VHostTooShort, queue.submit("bob", "ab", 2));
    try std.testing.expectError(error.VHostTooLong, queue.submit("carol", "toolong.example", 3));
}

test "approve transitions pending request and records decision timestamp" {
    // Arrange
    var queue = Queue.init(std.testing.allocator, .{});
    defer queue.deinit();
    try queue.submit("alice", "approved.example", 100);

    // Act
    try queue.approve("ALICE", 200);
    const request = queue.get("alice").?;

    // Assert
    try std.testing.expectEqual(Status.approved, request.status);
    try std.testing.expectEqual(@as(i64, 100), request.requested_ms);
    try std.testing.expectEqual(@as(i64, 200), request.decided_ms);
    try std.testing.expectEqualStrings("", request.reason);
    try std.testing.expectError(error.NotPending, queue.approve("alice", 300));
}

test "deny transitions pending request stores reason and records timestamp" {
    // Arrange
    var queue = Queue.init(std.testing.allocator, .{});
    defer queue.deinit();
    try queue.submit("alice", "denied.example", 100);

    // Act
    try queue.deny("alice", "too broad", 250);
    const request = queue.get("ALICE").?;

    // Assert
    try std.testing.expectEqual(Status.denied, request.status);
    try std.testing.expectEqual(@as(i64, 250), request.decided_ms);
    try std.testing.expectEqualStrings("too broad", request.reason);
    try std.testing.expectError(error.NotPending, queue.deny("alice", "again", 300));
}

test "pending list returns only pending requests" {
    // Arrange
    var queue = Queue.init(std.testing.allocator, .{});
    defer queue.deinit();
    try queue.submit("alice", "one.example", 1);
    try queue.submit("bob", "two.example", 2);
    try queue.submit("carol", "three.example", 3);
    try queue.approve("bob", 4);
    try queue.deny("carol", "not allowed", 5);

    // Act
    var out: [2]Request = undefined;
    const pending = try queue.pendingList(&out);

    // Assert
    try std.testing.expectEqual(@as(usize, 1), pending.len);
    try std.testing.expectEqualStrings("alice", pending[0].account);
    try std.testing.expectEqual(Status.pending, pending[0].status);
}

test "pending list reports output too small" {
    // Arrange
    var queue = Queue.init(std.testing.allocator, .{});
    defer queue.deinit();
    try queue.submit("alice", "one.example", 1);
    try queue.submit("bob", "two.example", 2);

    // Act
    var out: [1]Request = undefined;

    // Assert
    try std.testing.expectError(error.OutputTooSmall, queue.pendingList(&out));
}

test "replacement frees old request and keeps one entry" {
    // Arrange
    var queue = Queue.init(std.testing.allocator, .{});
    defer queue.deinit();
    try queue.submit("alice", "old.example", 1);

    // Act
    try queue.submit("alice", "new.example", 2);
    const request = queue.get("alice").?;
    var out: [1]Request = undefined;
    const pending = try queue.pendingList(&out);

    // Assert
    try std.testing.expectEqual(@as(usize, 1), pending.len);
    try std.testing.expectEqualStrings("new.example", request.vhost);
    try std.testing.expectEqual(@as(i64, 2), request.requested_ms);
}

test "account keys are matched case insensitively" {
    // Arrange
    var queue = Queue.init(std.testing.allocator, .{});
    defer queue.deinit();

    // Act
    try queue.submit("Alice", "first.example", 1);
    try queue.submit("ALICE", "second.example", 2);
    try queue.approve("alice", 3);
    const request = queue.get("aLiCe").?;

    // Assert
    try std.testing.expectEqualStrings("ALICE", request.account);
    try std.testing.expectEqualStrings("second.example", request.vhost);
    try std.testing.expectEqual(Status.approved, request.status);
}

test "configured limits reject excessive account reason and request counts" {
    // Arrange
    var queue = Queue.init(std.testing.allocator, .{
        .max_requests = 1,
        .max_account_bytes = 5,
        .max_reason_bytes = 4,
    });
    defer queue.deinit();

    // Act
    try queue.submit("alice", "one.example", 1);

    // Assert
    try std.testing.expectError(error.AccountTooLong, queue.submit("toolong", "two.example", 2));
    try std.testing.expectError(error.QueueFull, queue.submit("bob", "two.example", 3));
    try std.testing.expectError(error.ReasonTooLong, queue.deny("alice", "later", 4));
    try std.testing.expectError(error.InvalidReason, queue.deny("alice", "", 5));
}

test "take transfers ownership and clear removes stored requests" {
    // Arrange
    var queue = Queue.init(std.testing.allocator, .{});
    defer queue.deinit();
    try queue.submit("alice", "one.example", 1);
    try queue.submit("bob", "two.example", 2);

    // Act
    var taken = queue.take("ALICE").?;
    defer taken.deinit(std.testing.allocator);
    queue.clear("bob");

    // Assert
    try std.testing.expectEqualStrings("alice", taken.account);
    try std.testing.expectEqualStrings("one.example", taken.vhost);
    try std.testing.expect(queue.get("alice") == null);
    try std.testing.expect(queue.get("bob") == null);
    try std.testing.expect(queue.take("missing") == null);
}

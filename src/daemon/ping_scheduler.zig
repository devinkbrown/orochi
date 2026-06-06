//! Multi-connection PING and idle timeout scheduler.
//!
//! This module layers a per-id due queue over `timeout_policy.ConnTimer`. The
//! lower-level timer still owns all liveness rules for one connection; this
//! scheduler only keeps many connection ids ordered by their next injected-clock
//! deadline.

const std = @import("std");
const timeout_policy = @import("timeout_policy.zig");

comptime {
    if (@bitSizeOf(usize) != 64) @compileError("ping scheduler requires a 64-bit target");
}

/// Stable daemon-local identifier for one connection.
pub const ConnectionId = u64;

/// Tunable storage limits for a scheduler instance.
pub const Params = struct {
    /// Maximum number of connections tracked at once.
    max_connections: usize = 65_536,
};

/// Errors returned by scheduler mutation methods.
pub const Error = std.mem.Allocator.Error || timeout_policy.PolicyError || error{
    /// The supplied connection id is already tracked.
    ConnectionExists,
    /// The scheduler is already tracking `Params.max_connections` ids.
    ConnectionLimit,
    /// The supplied connection id is not tracked.
    UnknownConnection,
};

/// Action due for a connection whose deadline has elapsed.
pub const Action = enum(u2) {
    /// Caller should send a keepalive PING, then call `recordPingSent`.
    send_ping,
    /// Caller should close an unregistered connection.
    drop_registration_timeout,
    /// Caller should close a connection whose PING went unanswered.
    drop_ping_timeout,
};

/// One due scheduler event returned to the caller.
pub const DueEvent = struct {
    /// Connection id whose deadline has elapsed.
    id: ConnectionId,
    /// Action the caller should take for this connection.
    action: Action,
    /// Deadline that made this event due.
    due_ms: u64,
};

/// Public view of the next queued deadline.
pub const DueTimer = struct {
    /// Connection id associated with this deadline.
    id: ConnectionId,
    /// Monotonic millisecond timestamp at which the id becomes due.
    due_ms: u64,
};

/// Per-connection PING scheduler with an ordered due queue.
pub const PingScheduler = struct {
    allocator: std.mem.Allocator,
    params: Params,
    connections: std.AutoHashMapUnmanaged(ConnectionId, Connection) = .empty,
    queue: std.ArrayListUnmanaged(DueTimer) = .empty,
    connection_count: usize = 0,

    const Connection = struct {
        timer: timeout_policy.ConnTimer,
    };

    /// Initialize an empty scheduler with default limits.
    pub fn init(allocator: std.mem.Allocator) PingScheduler {
        return initWith(.{}, allocator);
    }

    /// Initialize an empty scheduler with caller-provided limits.
    pub fn initWith(params: Params, allocator: std.mem.Allocator) PingScheduler {
        return .{
            .allocator = allocator,
            .params = params,
        };
    }

    /// Release queue and map storage.
    pub fn deinit(self: *PingScheduler) void {
        self.queue.deinit(self.allocator);
        self.connections.deinit(self.allocator);
        self.* = undefined;
    }

    /// Track a newly accepted connection at `connected_at_ms`.
    pub fn add(
        self: *PingScheduler,
        id: ConnectionId,
        policy: timeout_policy.Policy,
        connected_at_ms: u64,
    ) Error!void {
        const checked_policy = try timeout_policy.validate(policy);
        if (self.connections.contains(id)) return error.ConnectionExists;
        if (self.connection_count >= self.params.max_connections) return error.ConnectionLimit;

        const timer = timeout_policy.ConnTimer.init(checked_policy, connected_at_ms);
        try self.connections.put(self.allocator, id, .{ .timer = timer });
        errdefer _ = self.connections.remove(id);

        try self.insertQueued(.{ .id = id, .due_ms = nextDueMs(&timer) });
        self.connection_count += 1;
    }

    /// Stop tracking a connection.
    ///
    /// Returns true when an id existed and was removed.
    pub fn remove(self: *PingScheduler, id: ConnectionId) bool {
        if (!self.connections.remove(id)) return false;
        _ = self.removeQueued(id);
        self.connection_count -= 1;
        return true;
    }

    /// Record inbound activity and reschedule the connection's next deadline.
    pub fn recordActivity(self: *PingScheduler, id: ConnectionId, now_ms: u64) Error!void {
        const conn = self.connections.getPtr(id) orelse return error.UnknownConnection;
        conn.timer.recordActivity(now_ms);
        try self.reschedule(id);
    }

    /// Mark the connection as registered and reschedule its idle PING deadline.
    pub fn markRegistered(self: *PingScheduler, id: ConnectionId, now_ms: u64) Error!void {
        const conn = self.connections.getPtr(id) orelse return error.UnknownConnection;
        conn.timer.markRegistered(now_ms);
        try self.reschedule(id);
    }

    /// Record that the caller sent the requested PING.
    ///
    /// The connection is rescheduled to the PONG grace deadline.
    pub fn recordPingSent(self: *PingScheduler, id: ConnectionId, now_ms: u64) Error!void {
        const conn = self.connections.getPtr(id) orelse return error.UnknownConnection;
        conn.timer.recordPingSent(now_ms);
        try self.reschedule(id);
    }

    /// Record a PONG and reschedule the connection's next idle PING deadline.
    pub fn recordPong(self: *PingScheduler, id: ConnectionId, now_ms: u64) Error!void {
        const conn = self.connections.getPtr(id) orelse return error.UnknownConnection;
        conn.timer.recordPong(now_ms);
        try self.reschedule(id);
    }

    /// Fill `out` with due events at `now_ms`, preserving deadline order.
    ///
    /// Events are not removed automatically. After a `.send_ping` event, call
    /// `recordPingSent`; after a drop event, call `remove`.
    pub fn due(self: *const PingScheduler, now_ms: u64, out: []DueEvent) usize {
        var count: usize = 0;
        for (self.queue.items) |queued| {
            if (queued.due_ms > now_ms) break;
            if (count >= out.len) break;

            const conn = self.connections.get(queued.id) orelse continue;
            const action = toSchedulerAction(conn.timer.tick(now_ms)) orelse continue;
            out[count] = .{
                .id = queued.id,
                .action = action,
                .due_ms = queued.due_ms,
            };
            count += 1;
        }
        return count;
    }

    /// Return the earliest queued deadline, or null when no connections exist.
    pub fn nextDue(self: *const PingScheduler) ?DueTimer {
        if (self.queue.items.len == 0) return null;
        return self.queue.items[0];
    }

    /// Return one connection's queued deadline, or null when it is unknown.
    pub fn nextDueFor(self: *const PingScheduler, id: ConnectionId) ?u64 {
        for (self.queue.items) |queued| {
            if (queued.id == id) return queued.due_ms;
        }
        return null;
    }

    /// Return milliseconds until one connection's deadline, or null if unknown.
    pub fn remaining(self: *const PingScheduler, id: ConnectionId, now_ms: u64) ?u64 {
        const due_ms = self.nextDueFor(id) orelse return null;
        if (now_ms >= due_ms) return 0;
        return due_ms - now_ms;
    }

    /// Return the number of currently tracked connections.
    pub fn len(self: *const PingScheduler) usize {
        return self.connection_count;
    }

    /// Return whether no connections are currently tracked.
    pub fn isEmpty(self: *const PingScheduler) bool {
        return self.connection_count == 0;
    }

    fn reschedule(self: *PingScheduler, id: ConnectionId) Error!void {
        const conn = self.connections.getPtr(id) orelse return error.UnknownConnection;
        _ = self.removeQueued(id);
        try self.insertQueued(.{ .id = id, .due_ms = nextDueMs(&conn.timer) });
    }

    fn insertQueued(self: *PingScheduler, timer: DueTimer) std.mem.Allocator.Error!void {
        const index = self.insertIndex(timer);
        try self.queue.insert(self.allocator, index, timer);
    }

    fn insertIndex(self: *const PingScheduler, timer: DueTimer) usize {
        for (self.queue.items, 0..) |queued, index| {
            if (timer.due_ms < queued.due_ms) return index;
            if (timer.due_ms == queued.due_ms and timer.id < queued.id) return index;
        }
        return self.queue.items.len;
    }

    fn removeQueued(self: *PingScheduler, id: ConnectionId) bool {
        for (self.queue.items, 0..) |queued, index| {
            if (queued.id == id) {
                _ = self.queue.orderedRemove(index);
                return true;
            }
        }
        return false;
    }
};

fn nextDueMs(timer: *const timeout_policy.ConnTimer) u64 {
    if (!timer.registered) {
        return saturatingAdd(timer.connected_at_ms, timer.policy.registration_ms);
    }

    if (timer.ping_sent_ms) |sent_ms| {
        return saturatingAdd(sent_ms, timer.policy.ping_timeout_ms);
    }

    return saturatingAdd(timer.last_activity_ms, timer.policy.ping_interval_ms);
}

fn saturatingAdd(base: u64, delta: u64) u64 {
    const max = std.math.maxInt(u64);
    if (max - base < delta) return max;
    return base + delta;
}

fn toSchedulerAction(action: timeout_policy.Action) ?Action {
    return switch (action) {
        .none => null,
        .send_ping => .send_ping,
        .drop_registration_timeout => .drop_registration_timeout,
        .drop_ping_timeout => .drop_ping_timeout,
    };
}

const testing = std.testing;

test "add queues registration deadlines in timestamp and id order" {
    // Arrange.
    const allocator = testing.allocator;
    const policy = timeout_policy.Policy{ .registration_ms = 100, .ping_interval_ms = 500, .ping_timeout_ms = 50 };
    var scheduler = PingScheduler.init(allocator);
    defer scheduler.deinit();

    // Act.
    try scheduler.add(30, policy, 1000);
    try scheduler.add(10, policy, 900);
    try scheduler.add(20, policy, 900);

    // Assert.
    try testing.expectEqual(@as(usize, 3), scheduler.len());
    try testing.expectEqual(@as(u64, 1000), scheduler.nextDue().?.due_ms);
    try testing.expectEqual(@as(ConnectionId, 10), scheduler.nextDue().?.id);

    var due_buf: [3]DueEvent = undefined;
    const due_count = scheduler.due(1000, due_buf[0..]);
    try testing.expectEqual(@as(usize, 2), due_count);
    try testing.expectEqual(@as(ConnectionId, 10), due_buf[0].id);
    try testing.expectEqual(@as(ConnectionId, 20), due_buf[1].id);
    try testing.expectEqual(Action.drop_registration_timeout, due_buf[0].action);
}

test "markRegistered switches a connection from registration deadline to ping deadline" {
    // Arrange.
    const allocator = testing.allocator;
    const policy = timeout_policy.Policy{ .registration_ms = 100, .ping_interval_ms = 500, .ping_timeout_ms = 50 };
    var scheduler = PingScheduler.init(allocator);
    defer scheduler.deinit();
    try scheduler.add(1, policy, 1000);

    // Act.
    try scheduler.markRegistered(1, 1050);

    // Assert.
    try testing.expectEqual(@as(?u64, 1550), scheduler.nextDueFor(1));
    try testing.expectEqual(@as(?u64, 50), scheduler.remaining(1, 1500));

    var due_buf: [1]DueEvent = undefined;
    try testing.expectEqual(@as(usize, 0), scheduler.due(1549, due_buf[0..]));
    try testing.expectEqual(@as(usize, 1), scheduler.due(1550, due_buf[0..]));
    try testing.expectEqual(Action.send_ping, due_buf[0].action);
}

test "recordActivity resets an idle ping deadline" {
    // Arrange.
    const allocator = testing.allocator;
    const policy = timeout_policy.Policy{ .registration_ms = 100, .ping_interval_ms = 500, .ping_timeout_ms = 50 };
    var scheduler = PingScheduler.init(allocator);
    defer scheduler.deinit();
    try scheduler.add(1, policy, 0);
    try scheduler.markRegistered(1, 0);

    // Act.
    try scheduler.recordActivity(1, 400);

    // Assert.
    try testing.expectEqual(@as(?u64, 900), scheduler.nextDueFor(1));
    var due_buf: [1]DueEvent = undefined;
    try testing.expectEqual(@as(usize, 0), scheduler.due(899, due_buf[0..]));
    try testing.expectEqual(@as(usize, 1), scheduler.due(900, due_buf[0..]));
    try testing.expectEqual(Action.send_ping, due_buf[0].action);
}

test "recordPingSent schedules the pong grace deadline and due reports drop" {
    // Arrange.
    const allocator = testing.allocator;
    const policy = timeout_policy.Policy{ .registration_ms = 100, .ping_interval_ms = 500, .ping_timeout_ms = 50 };
    var scheduler = PingScheduler.init(allocator);
    defer scheduler.deinit();
    try scheduler.add(7, policy, 0);
    try scheduler.markRegistered(7, 0);

    // Act.
    try scheduler.recordPingSent(7, 500);

    // Assert.
    try testing.expectEqual(@as(?u64, 550), scheduler.nextDueFor(7));
    var due_buf: [1]DueEvent = undefined;
    try testing.expectEqual(@as(usize, 0), scheduler.due(549, due_buf[0..]));
    try testing.expectEqual(@as(usize, 1), scheduler.due(550, due_buf[0..]));
    try testing.expectEqual(Action.drop_ping_timeout, due_buf[0].action);
}

test "recordPong clears outstanding ping and starts a fresh idle interval" {
    // Arrange.
    const allocator = testing.allocator;
    const policy = timeout_policy.Policy{ .registration_ms = 100, .ping_interval_ms = 500, .ping_timeout_ms = 50 };
    var scheduler = PingScheduler.init(allocator);
    defer scheduler.deinit();
    try scheduler.add(7, policy, 0);
    try scheduler.markRegistered(7, 0);
    try scheduler.recordPingSent(7, 500);

    // Act.
    try scheduler.recordPong(7, 525);

    // Assert.
    try testing.expectEqual(@as(?u64, 1025), scheduler.nextDueFor(7));
    var due_buf: [1]DueEvent = undefined;
    try testing.expectEqual(@as(usize, 0), scheduler.due(1024, due_buf[0..]));
    try testing.expectEqual(@as(usize, 1), scheduler.due(1025, due_buf[0..]));
    try testing.expectEqual(Action.send_ping, due_buf[0].action);
}

test "due honors output capacity without removing events" {
    // Arrange.
    const allocator = testing.allocator;
    const policy = timeout_policy.Policy{ .registration_ms = 10, .ping_interval_ms = 500, .ping_timeout_ms = 50 };
    var scheduler = PingScheduler.init(allocator);
    defer scheduler.deinit();
    try scheduler.add(1, policy, 0);
    try scheduler.add(2, policy, 0);
    try scheduler.add(3, policy, 0);

    // Act.
    var first: [2]DueEvent = undefined;
    const first_count = scheduler.due(10, first[0..]);
    var second: [3]DueEvent = undefined;
    const second_count = scheduler.due(10, second[0..]);

    // Assert.
    try testing.expectEqual(@as(usize, 2), first_count);
    try testing.expectEqual(@as(ConnectionId, 1), first[0].id);
    try testing.expectEqual(@as(ConnectionId, 2), first[1].id);
    try testing.expectEqual(@as(usize, 3), second_count);
    try testing.expectEqual(@as(ConnectionId, 3), second[2].id);
    try testing.expectEqual(@as(usize, 3), scheduler.len());
}

test "remove deletes map state and queued deadline" {
    // Arrange.
    const allocator = testing.allocator;
    const policy = timeout_policy.Policy{ .registration_ms = 10, .ping_interval_ms = 500, .ping_timeout_ms = 50 };
    var scheduler = PingScheduler.init(allocator);
    defer scheduler.deinit();
    try scheduler.add(1, policy, 0);
    try scheduler.add(2, policy, 0);

    // Act.
    const removed = scheduler.remove(1);
    const removed_again = scheduler.remove(1);

    // Assert.
    try testing.expect(removed);
    try testing.expect(!removed_again);
    try testing.expectEqual(@as(usize, 1), scheduler.len());
    try testing.expectEqual(@as(?u64, null), scheduler.nextDueFor(1));
    try testing.expectEqual(@as(?u64, 10), scheduler.nextDueFor(2));
}

test "add rejects duplicate ids zero windows and capacity overflow" {
    // Arrange.
    const allocator = testing.allocator;
    const policy = timeout_policy.Policy{ .registration_ms = 10, .ping_interval_ms = 500, .ping_timeout_ms = 50 };
    var scheduler = PingScheduler.initWith(.{ .max_connections = 1 }, allocator);
    defer scheduler.deinit();

    // Act and assert.
    try scheduler.add(1, policy, 0);
    try testing.expectError(error.ConnectionExists, scheduler.add(1, policy, 0));
    try testing.expectError(error.ConnectionLimit, scheduler.add(2, policy, 0));
    try testing.expectError(error.ZeroWindow, scheduler.add(3, .{ .registration_ms = 0 }, 0));
}

test "mutating an unknown id returns UnknownConnection" {
    // Arrange.
    const allocator = testing.allocator;
    var scheduler = PingScheduler.init(allocator);
    defer scheduler.deinit();

    // Act and assert.
    try testing.expectError(error.UnknownConnection, scheduler.markRegistered(1, 0));
    try testing.expectError(error.UnknownConnection, scheduler.recordActivity(1, 0));
    try testing.expectError(error.UnknownConnection, scheduler.recordPingSent(1, 0));
    try testing.expectError(error.UnknownConnection, scheduler.recordPong(1, 0));
    try testing.expectEqual(@as(?u64, null), scheduler.remaining(1, 0));
}

test "deadline addition saturates near max integer" {
    // Arrange.
    const allocator = testing.allocator;
    const max = std.math.maxInt(u64);
    const policy = timeout_policy.Policy{ .registration_ms = 100, .ping_interval_ms = 500, .ping_timeout_ms = 50 };
    var scheduler = PingScheduler.init(allocator);
    defer scheduler.deinit();

    // Act.
    try scheduler.add(1, policy, max - 10);

    // Assert.
    try testing.expectEqual(@as(?u64, max), scheduler.nextDueFor(1));
    var due_buf: [1]DueEvent = undefined;
    try testing.expectEqual(@as(usize, 0), scheduler.due(max, due_buf[0..]));
}

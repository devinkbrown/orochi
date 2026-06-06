//! Min-heap deadline queue for opaque numeric identifiers.
//!
//! The queue stores absolute millisecond deadlines supplied by the caller.  It
//! never reads a clock itself, and it returns only the opaque `u64` ids when
//! deadlines become due.
const std = @import("std");

comptime {
    if (@bitSizeOf(usize) != 64) @compileError("deadline queue requires a 64-bit target");
}

/// Public view of one queued deadline.
pub const DueItem = struct {
    /// Opaque identifier associated with the deadline.
    id: u64,
    /// Absolute millisecond timestamp at which the id becomes due.
    due_ms: i64,
};

/// Tunable storage limits for a deadline queue instance.
pub const Params = struct {
    /// Maximum number of ids tracked at once.
    max_items: usize = std.math.maxInt(usize),
};

/// Errors returned by queue mutation methods.
pub const Error = std.mem.Allocator.Error || error{
    /// The supplied id is already queued.
    DuplicateId,
    /// The queue has reached `Params.max_items`.
    QueueFull,
};

/// Allocator-owned min-heap keyed by absolute millisecond deadline.
pub const DeadlineQueue = struct {
    const Self = @This();

    const Node = struct {
        id: u64,
        due_ms: i64,
        seq: u64,
    };

    allocator: std.mem.Allocator,
    params: Params,
    heap: std.ArrayListUnmanaged(Node) = .empty,
    indexes: std.AutoHashMapUnmanaged(u64, usize) = .empty,
    next_seq: u64 = 0,

    /// Initialize an empty queue with default limits.
    pub fn init(allocator: std.mem.Allocator) Self {
        return initWith(.{}, allocator);
    }

    /// Initialize an empty queue with caller-provided limits.
    pub fn initWith(params: Params, allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .params = params,
        };
    }

    /// Release all heap and index storage.
    pub fn deinit(self: *Self) void {
        self.heap.deinit(self.allocator);
        self.indexes.deinit(self.allocator);
        self.* = undefined;
    }

    /// Remove all queued ids while retaining allocated storage.
    pub fn clear(self: *Self) void {
        self.heap.clearRetainingCapacity();
        self.indexes.clearRetainingCapacity();
    }

    /// Queue `id` for the absolute millisecond deadline `due_ms`.
    pub fn push(self: *Self, id: u64, due_ms: i64) Error!void {
        if (self.indexes.contains(id)) return error.DuplicateId;
        if (self.heap.items.len >= self.params.max_items) return error.QueueFull;

        try self.indexes.ensureUnusedCapacity(self.allocator, 1);
        try self.heap.ensureUnusedCapacity(self.allocator, 1);

        const index = self.heap.items.len;
        self.heap.appendAssumeCapacity(.{
            .id = id,
            .due_ms = due_ms,
            .seq = self.next_seq,
        });
        self.next_seq +%= 1;
        self.indexes.putAssumeCapacityNoClobber(id, index);
        self.siftUp(index);
    }

    /// Return the earliest queued deadline without removing it.
    pub fn peek(self: *const Self) ?DueItem {
        if (self.heap.items.len == 0) return null;
        return publicItem(self.heap.items[0]);
    }

    /// Remove and return the earliest id whose deadline is at or before `now_ms`.
    pub fn popDue(self: *Self, now_ms: i64) ?u64 {
        if (self.heap.items.len == 0) return null;
        if (self.heap.items[0].due_ms > now_ms) return null;
        return self.removeAt(0).id;
    }

    /// Remove `id` from the queue.
    ///
    /// Returns true when an item existed and was removed.
    pub fn remove(self: *Self, id: u64) bool {
        const index = self.indexes.get(id) orelse return false;
        _ = self.removeAt(index);
        return true;
    }

    /// Return the queued deadline for `id`, or null when it is not queued.
    pub fn dueFor(self: *const Self, id: u64) ?i64 {
        const index = self.indexes.get(id) orelse return null;
        return self.heap.items[index].due_ms;
    }

    /// Return whether `id` is currently queued.
    pub fn contains(self: *const Self, id: u64) bool {
        return self.indexes.contains(id);
    }

    /// Return the number of currently queued ids.
    pub fn len(self: *const Self) usize {
        return self.heap.items.len;
    }

    /// Return whether the queue has no queued ids.
    pub fn isEmpty(self: *const Self) bool {
        return self.heap.items.len == 0;
    }

    fn removeAt(self: *Self, index: usize) Node {
        const removed = self.heap.items[index];
        _ = self.indexes.remove(removed.id);

        const last = self.heap.pop().?;
        if (index < self.heap.items.len) {
            self.heap.items[index] = last;
            self.indexes.getPtr(last.id).?.* = index;
            self.repairAt(index);
        }

        return removed;
    }

    fn repairAt(self: *Self, index: usize) void {
        if (index > 0 and self.lessThan(index, parentIndex(index))) {
            self.siftUp(index);
        } else {
            self.siftDown(index);
        }
    }

    fn siftUp(self: *Self, start: usize) void {
        var index = start;
        while (index > 0) {
            const parent = parentIndex(index);
            if (!self.lessThan(index, parent)) break;
            self.swapNodes(index, parent);
            index = parent;
        }
    }

    fn siftDown(self: *Self, start: usize) void {
        var index = start;
        while (true) {
            const left = index * 2 + 1;
            if (left >= self.heap.items.len) break;

            const right = left + 1;
            var smallest = left;
            if (right < self.heap.items.len and self.lessThan(right, left)) {
                smallest = right;
            }

            if (!self.lessThan(smallest, index)) break;
            self.swapNodes(index, smallest);
            index = smallest;
        }
    }

    fn swapNodes(self: *Self, a: usize, b: usize) void {
        std.mem.swap(Node, &self.heap.items[a], &self.heap.items[b]);
        self.indexes.getPtr(self.heap.items[a].id).?.* = a;
        self.indexes.getPtr(self.heap.items[b].id).?.* = b;
    }

    fn lessThan(self: *const Self, a: usize, b: usize) bool {
        const left = self.heap.items[a];
        const right = self.heap.items[b];
        const due_order = std.math.order(left.due_ms, right.due_ms);
        if (due_order != .eq) return due_order == .lt;
        return left.seq < right.seq;
    }

    fn parentIndex(index: usize) usize {
        return (index - 1) / 2;
    }

    fn publicItem(node: Node) DueItem {
        return .{
            .id = node.id,
            .due_ms = node.due_ms,
        };
    }
};

/// Initialize an empty deadline queue with default limits.
pub fn init(allocator: std.mem.Allocator) DeadlineQueue {
    return DeadlineQueue.init(allocator);
}

const testing = std.testing;

test "popDue returns ids in deadline order" {
    // Arrange.
    var queue = DeadlineQueue.init(testing.allocator);
    defer queue.deinit();

    try queue.push(30, 30);
    try queue.push(10, 10);
    try queue.push(20, 20);
    try queue.push(21, 20);

    // Act.
    const first = queue.peek();
    const popped = [_]?u64{
        queue.popDue(100),
        queue.popDue(100),
        queue.popDue(100),
        queue.popDue(100),
        queue.popDue(100),
    };

    // Assert.
    try testing.expectEqual(DueItem{ .id = 10, .due_ms = 10 }, first.?);
    try testing.expectEqual(@as(?u64, 10), popped[0]);
    try testing.expectEqual(@as(?u64, 20), popped[1]);
    try testing.expectEqual(@as(?u64, 21), popped[2]);
    try testing.expectEqual(@as(?u64, 30), popped[3]);
    try testing.expectEqual(@as(?u64, null), popped[4]);
    try testing.expect(queue.isEmpty());
}

test "popDue only removes ids at or before the threshold" {
    // Arrange.
    var queue = DeadlineQueue.init(testing.allocator);
    defer queue.deinit();

    try queue.push(1, 10);
    try queue.push(2, 20);
    try queue.push(3, 30);

    // Act.
    const early = queue.popDue(19);
    const blocked = queue.popDue(19);
    const next = queue.peek();
    const exact = queue.popDue(20);

    // Assert.
    try testing.expectEqual(@as(?u64, 1), early);
    try testing.expectEqual(@as(?u64, null), blocked);
    try testing.expectEqual(DueItem{ .id = 2, .due_ms = 20 }, next.?);
    try testing.expectEqual(@as(?u64, 2), exact);
    try testing.expectEqual(@as(usize, 1), queue.len());
    try testing.expectEqual(@as(?i64, 30), queue.dueFor(3));
}

test "remove deletes arbitrary ids and repairs heap order" {
    // Arrange.
    var queue = DeadlineQueue.init(testing.allocator);
    defer queue.deinit();

    try queue.push(5, 50);
    try queue.push(1, 10);
    try queue.push(3, 30);
    try queue.push(2, 20);
    try queue.push(4, 40);

    // Act.
    const removed_middle = queue.remove(3);
    const removed_missing = queue.remove(3);
    const removed_root = queue.remove(1);
    const after_remove = [_]?u64{
        queue.popDue(100),
        queue.popDue(100),
        queue.popDue(100),
    };

    // Assert.
    try testing.expect(removed_middle);
    try testing.expect(!removed_missing);
    try testing.expect(removed_root);
    try testing.expect(!queue.contains(1));
    try testing.expect(!queue.contains(3));
    try testing.expectEqual(@as(?u64, 2), after_remove[0]);
    try testing.expectEqual(@as(?u64, 4), after_remove[1]);
    try testing.expectEqual(@as(?u64, 5), after_remove[2]);
    try testing.expect(queue.isEmpty());
}

test "empty queue operations are inert" {
    // Arrange.
    var queue = DeadlineQueue.init(testing.allocator);
    defer queue.deinit();

    // Act.
    const peeked = queue.peek();
    const popped = queue.popDue(0);
    const removed = queue.remove(123);

    // Assert.
    try testing.expectEqual(@as(?DueItem, null), peeked);
    try testing.expectEqual(@as(?u64, null), popped);
    try testing.expect(!removed);
    try testing.expectEqual(@as(usize, 0), queue.len());
    try testing.expect(queue.isEmpty());
}

test "duplicate ids are rejected and capacity is enforced" {
    // Arrange.
    var queue = DeadlineQueue.initWith(.{ .max_items = 1 }, testing.allocator);
    defer queue.deinit();

    // Act.
    try queue.push(1, 10);
    const duplicate = queue.push(1, 20);
    const full = queue.push(2, 20);

    // Assert.
    try testing.expectError(error.DuplicateId, duplicate);
    try testing.expectError(error.QueueFull, full);
    try testing.expectEqual(DueItem{ .id = 1, .due_ms = 10 }, queue.peek().?);
}

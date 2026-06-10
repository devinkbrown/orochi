//! Ringlane provided-buffer ring bookkeeping.
//!
//! This module owns the pure, allocation-free state around io_uring
//! provided-buffer rings: caller-owned recv buffers, logical head/tail counts,
//! descriptor replenishment, and the lease lifecycle created by multishot recv
//! completions. Live io_uring registration is intentionally a thin wrapper over
//! Zig std's Linux helpers; the invariants that matter to Orochi are tested
//! without setting up a kernel ring.
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
// io_uring is a Linux-only fast path; `void` off-Linux so this module compiles
// for every target (the live wrapper below is comptime-gated to match).
const IoUring = if (builtin.os.tag == .linux) linux.IoUring else void;

/// Maximum number of entries accepted by io_uring provided-buffer rings.
pub const max_buffer_count: u16 = 1 << 15;

/// Errors from pure buffer-ring bookkeeping.
pub const BufRingError = error{
    NotRegistered,
    BufferIdOutOfRange,
    BufferTooLarge,
    BufferUnavailable,
    PoolExhausted,
    LeaseConsumed,
    StaleLease,
    WrongBufferGroup,
};

/// A recv buffer selected by the kernel and handed to user space.
///
/// A lease must be consumed by `BufRing(...).recycle`/`replenish`. The ring
/// validates group, buffer id, and generation before making the buffer visible
/// again, so a double recycle is rejected instead of publishing the same buffer
/// twice.
pub const BufLease = struct {
    group_id: u16,
    buffer_id: u16,
    len: usize,
    generation: u32,
    consumed: bool = false,

    pub fn id(self: BufLease) u16 {
        return self.buffer_id;
    }

    pub fn isConsumed(self: BufLease) bool {
        return self.consumed;
    }
};

/// Live registration wrapper for a provided-buffer ring.
///
/// This is deliberately only the mmap/register/publish/free surface. The
/// safety policy stays in `BufRing`: register pure descriptors first, submit
/// recvs with buffer selection, convert each CQE buffer id to a `BufLease`, then
/// recycle exactly once. Tests avoid this wrapper because many CI sandboxes
/// reject io_uring setup.
pub const LiveBufRing = if (builtin.os.tag == .linux) struct {
    ring_fd: linux.fd_t,
    br: *align(std.heap.page_size_min) linux.io_uring_buf_ring,
    entries: u16,
    group_id: u16,

    /// Register a live shared provided-buffer ring against `ring`.
    pub fn init(ring: *IoUring, entries: u16, group_id: u16) !LiveBufRing {
        const br = try IoUring.setup_buf_ring(ring.fd, entries, group_id, .{ .inc = false });
        IoUring.buf_ring_init(br);
        return .{ .ring_fd = ring.fd, .br = br, .entries = entries, .group_id = group_id };
    }

    pub fn deinit(self: *LiveBufRing) void {
        IoUring.free_buf_ring(self.ring_fd, self.br, self.entries, self.group_id);
        self.br = undefined;
        self.entries = 0;
    }

    /// Publish one caller-owned buffer into the live ring.
    pub fn publish(self: *LiveBufRing, buffer: []u8, buffer_id: u16) BufRingError!void {
        if (self.entries == 0 or buffer_id >= self.entries) return error.BufferIdOutOfRange;
        if (buffer.len > std.math.maxInt(u32)) return error.BufferTooLarge;

        const mask = IoUring.buf_ring_mask(self.entries);
        IoUring.buf_ring_add(self.br, buffer, buffer_id, mask, 0);
        IoUring.buf_ring_advance(self.br, 1);
    }
} else struct {
    // io_uring provided-buffer rings are a Linux-only fast path; off-Linux the
    // pure BufRing(...) pool above is still portable and testable.
};

fn validateConfig(comptime buffer_size: usize, comptime buffer_count: u16) void {
    comptime {
        if (buffer_size == 0) @compileError("buf_ring buffer_size must be non-zero");
        if (buffer_size > std.math.maxInt(u32)) @compileError("buf_ring buffer_size must fit u32");
        if (buffer_count == 0) @compileError("buf_ring buffer_count must be non-zero");
        if (buffer_count > max_buffer_count) @compileError("buf_ring buffer_count is too large");
        if (!std.math.isPowerOfTwo(buffer_count)) @compileError("buf_ring buffer_count must be a power of two");
    }
}

/// Inline provided-buffer pool and pure ring state.
///
/// `buffer_count` must be a non-zero power of two no larger than 32768.
/// Storage is inline and hot-path methods do not allocate. The descriptor ring
/// mirrors liburing's `io_uring_buf_ring_add`: descriptor writes land at
/// `tail & mask`, then tail advances.
pub fn BufRing(comptime buffer_size: usize, comptime buffer_count: u16) type {
    validateConfig(buffer_size, buffer_count);

    return struct {
        const Self = @This();
        const mask: u16 = buffer_count - 1;

        const SlotState = enum(u8) {
            free,
            provided,
            leased,
        };

        group_id: u16,
        registered: bool = false,
        head: u16 = 0,
        tail: u16 = 0,
        provided_count: u16 = 0,
        storage: [@as(usize, buffer_count) * buffer_size]u8 = undefined,
        descriptors: [buffer_count]linux.io_uring_buf = undefined,
        states: [buffer_count]SlotState = undefined,
        generations: [buffer_count]u32 = undefined,

        pub fn init(group_id: u16) Self {
            var self: Self = .{ .group_id = group_id };
            self.clearSlots();
            return self;
        }

        /// Reset the pool and publish every buffer into the pure ring.
        pub fn registerAll(self: *Self) void {
            self.clearSlots();
            self.registered = true;
            var id: u16 = 0;
            while (id < buffer_count) : (id += 1) {
                self.publishUnchecked(id);
            }
        }

        /// Convert a recv CQE's selected buffer id and byte count into a lease.
        pub fn leaseFromCompletion(self: *Self, buffer_id: u16, len: usize) BufRingError!BufLease {
            if (!self.registered) return error.NotRegistered;
            if (buffer_id >= buffer_count) return error.BufferIdOutOfRange;
            if (len > buffer_size) return error.BufferTooLarge;
            if (self.provided_count == 0) return error.PoolExhausted;
            if (self.states[buffer_id] != .provided) return error.BufferUnavailable;

            self.states[buffer_id] = .leased;
            self.provided_count -= 1;
            self.head +%= 1;

            return .{
                .group_id = self.group_id,
                .buffer_id = buffer_id,
                .len = len,
                .generation = self.generations[buffer_id],
            };
        }

        /// Return a lease to the provided-buffer ring.
        pub fn recycle(self: *Self, lease: *BufLease) BufRingError!void {
            try self.replenish(lease);
        }

        /// Alias for `recycle`, named after the io_uring action: make one used
        /// buffer visible to the kernel again.
        pub fn replenish(self: *Self, lease: *BufLease) BufRingError!void {
            if (!self.registered) return error.NotRegistered;
            if (lease.consumed) return error.LeaseConsumed;
            if (lease.group_id != self.group_id) return error.WrongBufferGroup;
            if (lease.buffer_id >= buffer_count) return error.BufferIdOutOfRange;

            const id = lease.buffer_id;
            if (self.states[id] != .leased or self.generations[id] != lease.generation) {
                lease.consumed = true;
                return error.StaleLease;
            }

            self.generations[id] +%= 1;
            self.publishUnchecked(id);
            lease.consumed = true;
            lease.len = 0;
        }

        /// Full backing buffer for an id.
        pub fn buffer(self: *Self, buffer_id: u16) BufRingError![]u8 {
            if (buffer_id >= buffer_count) return error.BufferIdOutOfRange;
            return self.bufferUnchecked(buffer_id);
        }

        /// Bytes selected by a live recv completion for this lease.
        pub fn leaseBytes(self: *Self, lease: BufLease) BufRingError![]const u8 {
            try self.validateLiveLease(lease);
            return self.bufferUnchecked(lease.buffer_id)[0..lease.len];
        }

        /// Mutable view for parsers that normalize in-place before recycling.
        pub fn leaseBytesMut(self: *Self, lease: BufLease) BufRingError![]u8 {
            try self.validateLiveLease(lease);
            return self.bufferUnchecked(lease.buffer_id)[0..lease.len];
        }

        pub fn available(self: *const Self) u16 {
            return self.provided_count;
        }

        pub fn capacity(_: *const Self) u16 {
            return buffer_count;
        }

        pub fn bufferSize(_: *const Self) usize {
            return buffer_size;
        }

        pub fn ringHead(self: *const Self) u16 {
            return self.head;
        }

        pub fn ringTail(self: *const Self) u16 {
            return self.tail;
        }

        pub fn descriptorAt(self: *const Self, ring_index: u16) BufRingError!linux.io_uring_buf {
            if (ring_index >= buffer_count) return error.BufferIdOutOfRange;
            return self.descriptors[ring_index];
        }

        fn clearSlots(self: *Self) void {
            self.registered = false;
            self.head = 0;
            self.tail = 0;
            self.provided_count = 0;
            for (&self.states) |*state| state.* = .free;
            for (&self.generations) |*gen| gen.* = 0;
            for (&self.descriptors) |*desc| desc.* = .{ .addr = 0, .len = 0, .bid = 0, .resv = 0 };
        }

        fn publishUnchecked(self: *Self, buffer_id: u16) void {
            const slot = self.tail & mask;
            const buf = self.bufferUnchecked(buffer_id);
            self.descriptors[slot] = .{
                .addr = @intFromPtr(buf.ptr),
                .len = @intCast(buf.len),
                .bid = buffer_id,
                .resv = 0,
            };
            self.tail +%= 1;
            self.provided_count += 1;
            self.states[buffer_id] = .provided;
        }

        fn bufferUnchecked(self: *Self, buffer_id: u16) []u8 {
            const start = @as(usize, buffer_id) * buffer_size;
            return self.storage[start .. start + buffer_size];
        }

        fn validateLiveLease(self: *Self, lease: BufLease) BufRingError!void {
            if (!self.registered) return error.NotRegistered;
            if (lease.consumed) return error.LeaseConsumed;
            if (lease.group_id != self.group_id) return error.WrongBufferGroup;
            if (lease.buffer_id >= buffer_count) return error.BufferIdOutOfRange;
            if (lease.len > buffer_size) return error.BufferTooLarge;
            if (self.states[lease.buffer_id] != .leased) return error.StaleLease;
            if (self.generations[lease.buffer_id] != lease.generation) return error.StaleLease;
        }
    };
}

const testing = std.testing;

test "lease then recycle" {
    var ring = BufRing(32, 4).init(9);
    ring.registerAll();

    try testing.expectEqual(@as(u16, 4), ring.available());
    try testing.expectEqual(@as(u16, 0), ring.ringHead());
    try testing.expectEqual(@as(u16, 4), ring.ringTail());

    var lease = try ring.leaseFromCompletion(2, 11);
    try testing.expectEqual(@as(u16, 2), lease.id());
    try testing.expectEqual(@as(usize, 11), (try ring.leaseBytes(lease)).len);
    try testing.expectEqual(@as(u16, 3), ring.available());
    try testing.expectEqual(@as(u16, 1), ring.ringHead());

    try ring.recycle(&lease);
    try testing.expect(lease.isConsumed());
    try testing.expectEqual(@as(u16, 4), ring.available());
    try testing.expectEqual(@as(u16, 5), ring.ringTail());
    try testing.expectEqual(@as(u16, 2), (try ring.descriptorAt(0)).bid);
}

test "double-recycle rejected" {
    var ring = BufRing(16, 4).init(3);
    ring.registerAll();

    var lease = try ring.leaseFromCompletion(1, 8);
    try ring.recycle(&lease);
    try testing.expectError(error.LeaseConsumed, ring.recycle(&lease));

    var stale = lease;
    stale.consumed = false;
    try testing.expectError(error.StaleLease, ring.recycle(&stale));
    try testing.expectEqual(@as(u16, 4), ring.available());
}

test "pool exhaustion" {
    var ring = BufRing(8, 4).init(1);
    ring.registerAll();

    var leases: [4]BufLease = undefined;
    var id: u16 = 0;
    while (id < 4) : (id += 1) {
        leases[id] = try ring.leaseFromCompletion(id, 4);
    }

    try testing.expectEqual(@as(u16, 0), ring.available());
    try testing.expectError(error.PoolExhausted, ring.leaseFromCompletion(0, 1));

    try ring.recycle(&leases[0]);
    try testing.expectEqual(@as(u16, 1), ring.available());
}

test "replenish wraps correctly" {
    var ring = BufRing(8, 4).init(5);
    ring.registerAll();

    var a = try ring.leaseFromCompletion(0, 1);
    var b = try ring.leaseFromCompletion(1, 1);
    var c = try ring.leaseFromCompletion(2, 1);
    var d = try ring.leaseFromCompletion(3, 1);

    try ring.replenish(&a);
    try ring.replenish(&b);
    try ring.replenish(&c);
    try ring.replenish(&d);

    try testing.expectEqual(@as(u16, 4), ring.available());
    try testing.expectEqual(@as(u16, 4), ring.ringHead());
    try testing.expectEqual(@as(u16, 8), ring.ringTail());
    try testing.expectEqual(@as(u16, 0), (try ring.descriptorAt(0)).bid);
    try testing.expectEqual(@as(u16, 1), (try ring.descriptorAt(1)).bid);
    try testing.expectEqual(@as(u16, 2), (try ring.descriptorAt(2)).bid);
    try testing.expectEqual(@as(u16, 3), (try ring.descriptorAt(3)).bid);
}

test "lease validation rejects malformed completions" {
    var ring = BufRing(8, 4).init(7);

    try testing.expectError(error.NotRegistered, ring.leaseFromCompletion(0, 1));
    ring.registerAll();
    try testing.expectError(error.BufferIdOutOfRange, ring.leaseFromCompletion(4, 1));
    try testing.expectError(error.BufferTooLarge, ring.leaseFromCompletion(0, 9));

    var lease = try ring.leaseFromCompletion(0, 1);
    lease.group_id = 99;
    try testing.expectError(error.WrongBufferGroup, ring.recycle(&lease));
}

test {
    testing.refAllDecls(@This());
}

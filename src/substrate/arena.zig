//! Scoped allocator toolkit for hot-path substrate memory.
//!
//! `BumpArena` owns a caller-sized byte region and exposes both explicit
//! typed allocation helpers and a `std.mem.Allocator` view for scratch users.
//! `Slab(T, capacity)` is a fixed typed pool with generation-checked handles,
//! so frees are O(1), reuse is predictable, and stale/double frees are
//! rejected. `ConnArena` wraps the same arena policy for connection lifetime
//! state and per-dispatch scratch frames.
const std = @import("std");

const Allocator = std.mem.Allocator;
const Alignment = std.mem.Alignment;

const backing_alignment: Alignment = .@"64";

/// Runtime allocator usage snapshot.
pub const ArenaStats = struct {
    capacity: usize,
    used: usize,
    peak: usize,

    pub fn available(self: ArenaStats) usize {
        return self.capacity - self.used;
    }
};

/// Mark for rewinding a bump arena.
pub const ArenaMark = struct {
    offset: usize,
};

/// Owning bump allocator with reset marks and scratch-frame support.
pub const BumpArena = struct {
    backing: Allocator,
    buffer: []u8,
    cursor: usize = 0,
    peak: usize = 0,

    const Self = @This();

    /// Allocate `capacity` bytes from `backing` for arena-owned storage.
    pub fn init(backing: Allocator, capacity: usize) Allocator.Error!Self {
        if (capacity == 0) return error.OutOfMemory;

        const ptr = backing.rawAlloc(capacity, backing_alignment, @returnAddress()) orelse
            return error.OutOfMemory;
        return .{
            .backing = backing,
            .buffer = ptr[0..capacity],
        };
    }

    /// Release the arena backing store. Outstanding arena allocations become invalid.
    pub fn deinit(self: *Self) void {
        if (self.buffer.len == 0) return;

        self.backing.rawFree(self.buffer, backing_alignment, @returnAddress());
        self.buffer = &[_]u8{};
        self.cursor = 0;
        self.peak = 0;
    }

    /// Return a `std.mem.Allocator` backed by this arena.
    pub fn allocator(self: *Self) Allocator {
        return .{ .ptr = self, .vtable = &allocator_vtable };
    }

    /// Current rewind point.
    pub fn mark(self: *const Self) ArenaMark {
        return .{ .offset = self.cursor };
    }

    /// Rewind to a previous mark.
    pub fn resetToMark(self: *Self, rewind: ArenaMark) !void {
        if (rewind.offset > self.cursor) return error.InvalidMark;
        self.cursor = rewind.offset;
    }

    /// Zero bytes above `rewind`, then rewind to that mark.
    pub fn secureResetToMark(self: *Self, rewind: ArenaMark) !void {
        if (rewind.offset > self.cursor) return error.InvalidMark;
        std.crypto.secureZero(u8, self.buffer[rewind.offset..self.cursor]);
        self.cursor = rewind.offset;
    }

    /// Rewind all arena allocations.
    pub fn resetAll(self: *Self) void {
        self.cursor = 0;
    }

    /// Zero all used bytes, then rewind to empty.
    pub fn secureResetAll(self: *Self) void {
        std.crypto.secureZero(u8, self.buffer[0..self.cursor]);
        self.cursor = 0;
    }

    /// Start a scratch frame that can be ended independently.
    pub fn scratchFrame(self: *Self) ScratchFrame {
        return .{ .arena = self, .rewind = self.mark() };
    }

    /// Allocate raw aligned bytes from the arena.
    pub fn allocBytes(self: *Self, len: usize, alignment: Alignment) Allocator.Error![]u8 {
        if (len == 0) return self.buffer[self.cursor..self.cursor];

        const base = @intFromPtr(self.buffer.ptr);
        const start = base + self.cursor;
        const aligned_start = std.mem.alignForward(usize, start, alignment.toByteUnits());
        const aligned_offset = aligned_start - base;
        const end = std.math.add(usize, aligned_offset, len) catch return error.OutOfMemory;
        if (end > self.buffer.len) return error.OutOfMemory;

        self.cursor = end;
        if (self.cursor > self.peak) self.peak = self.cursor;
        return self.buffer[aligned_offset..end];
    }

    /// Allocate `count` typed items from the arena.
    pub fn alloc(self: *Self, comptime T: type, count: usize) Allocator.Error![]T {
        const byte_len = std.math.mul(usize, @sizeOf(T), count) catch return error.OutOfMemory;
        const bytes = try self.allocBytes(byte_len, .of(T));
        const ptr: [*]T = @ptrCast(@alignCast(bytes.ptr));
        return ptr[0..count];
    }

    /// Allocate one typed value from the arena.
    pub fn create(self: *Self, comptime T: type) Allocator.Error!*T {
        const items = try self.alloc(T, 1);
        return &items[0];
    }

    /// Current usage statistics.
    pub fn stats(self: *const Self) ArenaStats {
        return .{
            .capacity = self.buffer.len,
            .used = self.cursor,
            .peak = self.peak,
        };
    }

    fn rawAlloc(ctx: *anyopaque, len: usize, alignment: Alignment, _: usize) ?[*]u8 {
        const self: *Self = @ptrCast(@alignCast(ctx));
        const bytes = self.allocBytes(len, alignment) catch return null;
        return bytes.ptr;
    }

    fn rawResize(ctx: *anyopaque, memory: []u8, _: Alignment, new_len: usize, _: usize) bool {
        const self: *Self = @ptrCast(@alignCast(ctx));
        const base = @intFromPtr(self.buffer.ptr);
        const mem_start = @intFromPtr(memory.ptr);
        if (mem_start < base) return false;

        const offset = mem_start - base;
        const old_end = std.math.add(usize, offset, memory.len) catch return false;
        if (old_end != self.cursor) return false;
        const new_end = std.math.add(usize, offset, new_len) catch return false;
        if (new_end > self.buffer.len) return false;

        self.cursor = new_end;
        if (self.cursor > self.peak) self.peak = self.cursor;
        return true;
    }

    fn rawRemap(ctx: *anyopaque, memory: []u8, alignment: Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        if (rawResize(ctx, memory, alignment, new_len, ret_addr)) return memory.ptr;
        return null;
    }

    fn rawFree(ctx: *anyopaque, memory: []u8, _: Alignment, _: usize) void {
        const self: *Self = @ptrCast(@alignCast(ctx));
        const base = @intFromPtr(self.buffer.ptr);
        const mem_start = @intFromPtr(memory.ptr);
        if (mem_start < base) return;

        const offset = mem_start - base;
        const end = std.math.add(usize, offset, memory.len) catch return;
        if (end == self.cursor) self.cursor = offset;
    }

    const allocator_vtable = Allocator.VTable{
        .alloc = rawAlloc,
        .resize = rawResize,
        .remap = rawRemap,
        .free = rawFree,
    };
};

/// Scoped scratch mark. Call `end` to rewind; `allocator` borrows the parent.
pub const ScratchFrame = struct {
    arena: *BumpArena,
    rewind: ArenaMark,
    active: bool = true,

    const Self = @This();

    pub fn allocator(self: *Self) Allocator {
        return self.arena.allocator();
    }

    pub fn alloc(self: *Self, comptime T: type, count: usize) Allocator.Error![]T {
        if (!self.active) return error.OutOfMemory;
        return self.arena.alloc(T, count);
    }

    pub fn end(self: *Self) void {
        if (!self.active) return;
        self.arena.resetToMark(self.rewind) catch {};
        self.active = false;
    }

    pub fn secureEnd(self: *Self) void {
        if (!self.active) return;
        self.arena.secureResetToMark(self.rewind) catch {};
        self.active = false;
    }
};

/// Fixed-size typed slab with O(1) allocation and free.
pub fn Slab(comptime T: type, comptime capacity: usize) type {
    comptime {
        if (capacity == 0) @compileError("slab capacity must be non-zero");
        if (capacity > std.math.maxInt(u32)) @compileError("slab capacity must fit in u32 handles");
    }

    return struct {
        const Self = @This();
        const none = std.math.maxInt(u32);

        const Slot = struct {
            storage: [@sizeOf(T)]u8 align(@alignOf(T)) = undefined,
            next_free: u32 = none,
            generation: u32 = 1,
            occupied: bool = false,
        };

        /// Stable object handle. Generation rejects stale and double frees.
        pub const Handle = struct {
            index: u32,
            generation: u32,
        };

        /// Live pointer and the handle needed to release it.
        pub const Entry = struct {
            ptr: *T,
            handle: Handle,
        };

        slots: [capacity]Slot = initSlots(),
        free_head: u32 = 0,
        used_count: usize = 0,

        pub fn init() Self {
            return .{};
        }

        pub fn count(self: *const Self) usize {
            return self.used_count;
        }

        pub fn available(self: *const Self) usize {
            return capacity - self.used_count;
        }

        /// Reserve a slot and return its pointer plus handle.
        pub fn alloc(self: *Self) !Entry {
            if (self.free_head == none) return error.OutOfMemory;

            const index = self.free_head;
            const slot = &self.slots[index];
            self.free_head = slot.next_free;
            slot.next_free = none;
            slot.occupied = true;
            self.used_count += 1;

            return .{
                .ptr = slotPtr(slot),
                .handle = .{ .index = index, .generation = slot.generation },
            };
        }

        /// Construct a value inside a reserved slot.
        pub fn create(self: *Self, value: T) !Entry {
            const item = try self.alloc();
            item.ptr.* = value;
            return item;
        }

        /// Resolve a live handle into a pointer.
        pub fn get(self: *Self, handle: Handle) ?*T {
            const index = self.validate(handle) orelse return null;
            return slotPtr(&self.slots[index]);
        }

        /// Free a live handle. Stale, forged, or repeated handles return errors.
        pub fn free(self: *Self, handle: Handle) !void {
            const index = self.validate(handle) orelse return error.InvalidHandle;
            const slot = &self.slots[index];

            slot.occupied = false;
            slot.generation +%= 1;
            if (slot.generation == 0) slot.generation = 1;
            slot.next_free = self.free_head;
            self.free_head = @intCast(index);
            self.used_count -= 1;
        }

        fn validate(self: *const Self, handle: Handle) ?usize {
            const index: usize = handle.index;
            if (index >= capacity) return null;

            const slot = self.slots[index];
            if (!slot.occupied) return null;
            if (slot.generation != handle.generation) return null;
            return index;
        }

        fn slotPtr(slot: *Slot) *T {
            return @ptrCast(@alignCast(&slot.storage));
        }

        fn initSlots() [capacity]Slot {
            var slots: [capacity]Slot = undefined;
            for (&slots, 0..) |*slot, i| {
                slot.* = .{
                    .next_free = if (i + 1 == capacity) none else @as(u32, @intCast(i + 1)),
                };
            }
            return slots;
        }
    };
}

/// Connection-lifetime arena with dispatch-local scratch frames.
pub const ConnArena = struct {
    arena: BumpArena,

    const Self = @This();

    pub fn init(backing: Allocator, capacity: usize) Allocator.Error!Self {
        return .{ .arena = try BumpArena.init(backing, capacity) };
    }

    pub fn deinit(self: *Self) void {
        self.arena.deinit();
    }

    pub fn allocator(self: *Self) Allocator {
        return self.arena.allocator();
    }

    pub fn resetForDisconnect(self: *Self) void {
        self.arena.secureResetAll();
    }

    pub fn dispatchFrame(self: *Self) ScratchFrame {
        return self.arena.scratchFrame();
    }

    pub fn stats(self: *const Self) ArenaStats {
        return self.arena.stats();
    }
};

test "arena alloc and reset mark rewind" {
    var arena = try BumpArena.init(std.testing.allocator, 256);
    defer arena.deinit();

    const first = try arena.alloc(u32, 4);
    first[0] = 10;
    const mark = arena.mark();
    const temp = try arena.alloc(u8, 64);
    temp[0] = 99;
    try std.testing.expect(arena.stats().used > mark.offset);

    try arena.resetToMark(mark);
    try std.testing.expectEqual(mark.offset, arena.stats().used);

    const reused = try arena.alloc(u8, 64);
    try std.testing.expectEqual(temp.ptr, reused.ptr);
    try std.testing.expectEqual(@as(u32, 10), first[0]);
}

test "scratch frame rewinds only framed allocations" {
    var arena = try BumpArena.init(std.testing.allocator, 192);
    defer arena.deinit();

    _ = try arena.alloc(u8, 16);
    const before = arena.stats().used;

    var frame = arena.scratchFrame();
    _ = try frame.alloc(u64, 8);
    try std.testing.expect(arena.stats().used > before);
    frame.end();

    try std.testing.expectEqual(before, arena.stats().used);
}

test "slab alloc free reuse and no double free" {
    var slab = Slab(u64, 2).init();

    const a = try slab.create(11);
    const b = try slab.create(22);
    try std.testing.expectEqual(@as(usize, 2), slab.count());
    try std.testing.expectError(error.OutOfMemory, slab.alloc());

    try slab.free(a.handle);
    try std.testing.expectError(error.InvalidHandle, slab.free(a.handle));

    const c = try slab.create(33);
    try std.testing.expectEqual(a.ptr, c.ptr);
    try std.testing.expectEqual(@as(u64, 33), c.ptr.*);
    try std.testing.expect(c.handle.generation != a.handle.generation);

    try slab.free(b.handle);
    try slab.free(c.handle);
    try std.testing.expectEqual(@as(usize, 0), slab.count());
}

test "alignment respected by arena and slab" {
    const Wide = extern struct {
        bytes: [32]u8 align(32),
    };

    var arena = try BumpArena.init(std.testing.allocator, 512);
    defer arena.deinit();

    _ = try arena.alloc(u8, 1);
    const wide = try arena.alloc(Wide, 2);
    try std.testing.expectEqual(@as(usize, 0), @intFromPtr(wide.ptr) % @alignOf(Wide));

    var slab = Slab(Wide, 2).init();
    const item = try slab.alloc();
    try std.testing.expectEqual(@as(usize, 0), @intFromPtr(item.ptr) % @alignOf(Wide));
}

test "arena exhaustion handled without leaks" {
    var arena = try BumpArena.init(std.testing.allocator, 32);
    defer arena.deinit();

    _ = try arena.alloc(u8, 24);
    try std.testing.expectError(error.OutOfMemory, arena.alloc(u64, 8));
}

test "connection arena wraps lifetime and dispatch scratch" {
    var conn = try ConnArena.init(std.testing.allocator, 256);
    defer conn.deinit();

    const lifetime = try conn.arena.create(u32);
    lifetime.* = 7;
    const before = conn.stats().used;

    var frame = conn.dispatchFrame();
    _ = try frame.alloc(u8, 80);
    frame.end();

    try std.testing.expectEqual(before, conn.stats().used);
    try std.testing.expectEqual(@as(u32, 7), lifetime.*);

    conn.resetForDisconnect();
    try std.testing.expectEqual(@as(usize, 0), conn.stats().used);
}

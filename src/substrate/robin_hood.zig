// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

const std = @import("std");

const default_capacity: usize = 16;

/// Generic open-addressing hash map using Robin Hood probing.
///
/// `hashFn` must be deterministic for the lifetime of an entry and `eqlFn`
/// must define key equality for keys with matching hashes.
pub fn RobinHoodMap(
    comptime K: type,
    comptime V: type,
    comptime hashFn: fn (K) u64,
    comptime eqlFn: fn (K, K) bool,
) type {
    return struct {
        const Self = @This();

        const Slot = struct {
            occupied: bool,
            hash: u64,
            key: K,
            value: V,
        };

        pub const Entry = struct {
            key: *const K,
            value: *V,
        };

        pub const ConstEntry = struct {
            key: *const K,
            value: *const V,
        };

        pub const Iterator = struct {
            map: *Self,
            index: usize = 0,

            pub fn next(self: *Iterator) ?Entry {
                while (self.index < self.map.slots.len) {
                    const index = self.index;
                    self.index += 1;
                    if (self.map.slots[index].occupied) {
                        return .{
                            .key = &self.map.slots[index].key,
                            .value = &self.map.slots[index].value,
                        };
                    }
                }
                return null;
            }
        };

        pub const ConstIterator = struct {
            map: *const Self,
            index: usize = 0,

            pub fn next(self: *ConstIterator) ?ConstEntry {
                while (self.index < self.map.slots.len) {
                    const index = self.index;
                    self.index += 1;
                    if (self.map.slots[index].occupied) {
                        return .{
                            .key = &self.map.slots[index].key,
                            .value = &self.map.slots[index].value,
                        };
                    }
                }
                return null;
            }
        };

        allocator: std.mem.Allocator,
        slots: []Slot = &.{},
        count: usize = 0,

        pub fn init(allocator: std.mem.Allocator) Self {
            return .{ .allocator = allocator };
        }

        pub fn initCapacity(allocator: std.mem.Allocator, requested_capacity: usize) !Self {
            var map = Self.init(allocator);
            errdefer map.deinit();

            const actual_capacity = try normalizeCapacity(requested_capacity);
            if (actual_capacity != 0) {
                map.slots = try allocateSlots(allocator, actual_capacity);
            }

            return map;
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.slots);
            self.* = .{ .allocator = self.allocator };
        }

        pub fn len(self: *const Self) usize {
            return self.count;
        }

        pub fn capacity(self: *const Self) usize {
            return self.slots.len;
        }

        pub fn contains(self: *const Self, key: K) bool {
            return self.findIndex(key, hashFn(key)) != null;
        }

        pub fn get(self: *Self, key: K) ?*V {
            const index = self.findIndex(key, hashFn(key)) orelse return null;
            return &self.slots[index].value;
        }

        pub fn getConst(self: *const Self, key: K) ?*const V {
            const index = self.findIndex(key, hashFn(key)) orelse return null;
            return &self.slots[index].value;
        }

        /// Insert or replace a value. Returns the previous value on replace.
        pub fn put(self: *Self, key: K, value: V) !?V {
            const hash = hashFn(key);
            if (self.findIndex(key, hash)) |index| {
                const old = self.slots[index].value;
                self.slots[index].value = value;
                return old;
            }

            try self.ensureCapacityFor(self.count + 1);
            self.insertFresh(.{
                .occupied = true,
                .hash = hash,
                .key = key,
                .value = value,
            });
            return null;
        }

        /// Remove a key and return the removed value when present.
        pub fn remove(self: *Self, key: K) ?V {
            const index = self.findIndex(key, hashFn(key)) orelse return null;
            const old = self.slots[index].value;
            self.shiftBackwardFrom(index);
            self.count -= 1;
            return old;
        }

        pub fn iterator(self: *Self) Iterator {
            return .{ .map = self };
        }

        pub fn constIterator(self: *const Self) ConstIterator {
            return .{ .map = self };
        }

        fn findIndex(self: *const Self, key: K, hash: u64) ?usize {
            if (self.slots.len == 0) return null;

            var index = self.indexFor(hash);
            var distance: usize = 0;

            while (true) {
                const slot = &self.slots[index];
                if (!slot.occupied) return null;

                const resident_distance = self.probeDistance(slot.hash, index);
                if (resident_distance < distance) return null;

                if (slot.hash == hash and eqlFn(slot.key, key)) return index;

                index = self.nextIndex(index);
                distance += 1;
            }
        }

        fn allocateSlots(allocator: std.mem.Allocator, slot_capacity: usize) ![]Slot {
            const slots = try allocator.alloc(Slot, slot_capacity);
            for (slots) |*slot| {
                slot.* = emptySlot();
            }
            return slots;
        }

        fn emptySlot() Slot {
            return .{
                .occupied = false,
                .hash = 0,
                .key = undefined,
                .value = undefined,
            };
        }

        fn ensureCapacityFor(self: *Self, needed: usize) !void {
            if (needed <= maxLoad(self.slots.len)) return;

            var new_capacity = if (self.slots.len == 0) default_capacity else try doubleCapacity(self.slots.len);
            while (needed > maxLoad(new_capacity)) {
                new_capacity = try doubleCapacity(new_capacity);
            }

            try self.rehash(new_capacity);
        }

        fn rehash(self: *Self, new_capacity: usize) !void {
            const new_slots = try allocateSlots(self.allocator, new_capacity);
            errdefer self.allocator.free(new_slots);

            const old_slots = self.slots;
            self.slots = new_slots;
            self.count = 0;

            for (old_slots) |slot| {
                if (slot.occupied) {
                    self.insertFresh(slot);
                }
            }

            self.allocator.free(old_slots);
        }

        fn insertFresh(self: *Self, fresh: Slot) void {
            std.debug.assert(self.slots.len != 0);
            std.debug.assert(fresh.occupied);

            var moving = fresh;
            var index = self.indexFor(moving.hash);
            var distance: usize = 0;

            while (true) {
                if (!self.slots[index].occupied) {
                    self.slots[index] = moving;
                    self.count += 1;
                    return;
                }

                const resident_distance = self.probeDistance(self.slots[index].hash, index);
                if (resident_distance < distance) {
                    const displaced = self.slots[index];
                    self.slots[index] = moving;
                    moving = displaced;
                    distance = resident_distance;
                }

                index = self.nextIndex(index);
                distance += 1;
            }
        }

        fn shiftBackwardFrom(self: *Self, removed_index: usize) void {
            var hole = removed_index;
            var next = self.nextIndex(hole);

            while (self.slots[next].occupied and self.probeDistance(self.slots[next].hash, next) != 0) {
                self.slots[hole] = self.slots[next];
                hole = next;
                next = self.nextIndex(next);
            }

            self.slots[hole] = emptySlot();
        }

        fn indexFor(self: *const Self, hash: u64) usize {
            std.debug.assert(self.slots.len != 0);
            return @intCast(hash & @as(u64, @intCast(self.slots.len - 1)));
        }

        fn nextIndex(self: *const Self, index: usize) usize {
            return (index + 1) & (self.slots.len - 1);
        }

        fn probeDistance(self: *const Self, hash: u64, index: usize) usize {
            const home = self.indexFor(hash);
            return (index + self.slots.len - home) & (self.slots.len - 1);
        }

        fn verifyProbeInvariants(self: *const Self) bool {
            var occupied: usize = 0;
            for (self.slots, 0..) |slot, index| {
                if (!slot.occupied) continue;
                occupied += 1;

                const found = self.findIndex(slot.key, slot.hash) orelse return false;
                if (found != index) return false;

                var walk = self.indexFor(slot.hash);
                while (walk != index) : (walk = self.nextIndex(walk)) {
                    if (!self.slots[walk].occupied) return false;
                }
            }

            if (occupied != self.count) return false;
            return true;
        }
    };
}

fn normalizeCapacity(requested: usize) !usize {
    if (requested == 0) return 0;

    var capacity: usize = 2;
    while (capacity < requested) {
        capacity = try doubleCapacity(capacity);
    }
    return capacity;
}

fn doubleCapacity(capacity: usize) !usize {
    if (capacity > std.math.maxInt(usize) / 2) return error.CapacityOverflow;
    return capacity * 2;
}

fn maxLoad(capacity: usize) usize {
    if (capacity == 0) return 0;
    if (capacity < 8) return capacity - 1;
    return capacity - (capacity / 8);
}

const U32Map = RobinHoodMap(u32, u64, hashU32, eqlU32);

fn hashU32(key: u32) u64 {
    return mix64(@as(u64, key));
}

fn eqlU32(a: u32, b: u32) bool {
    return a == b;
}

fn collisionHash(_: u32) u64 {
    return 0;
}

fn lowBitsHash(key: u32) u64 {
    return @intCast(key & 3);
}

fn mix64(input: u64) u64 {
    var z = input +% 0x9e37_79b9_7f4a_7c15;
    z = (z ^ (z >> 30)) *% 0xbf58_476d_1ce4_e5b9;
    z = (z ^ (z >> 27)) *% 0x94d0_49bb_1331_11eb;
    return z ^ (z >> 31);
}

const SplitMix64 = struct {
    state: u64,

    fn init(seed: u64) SplitMix64 {
        return .{ .state = seed };
    }

    fn next(self: *SplitMix64) u64 {
        self.state +%= 0x9e37_79b9_7f4a_7c15;
        return mix64(self.state);
    }

    fn bounded(self: *SplitMix64, upper: u32) u32 {
        std.debug.assert(upper != 0);
        return @intCast(self.next() % upper);
    }
};

fn expectValid(map: anytype) !void {
    try std.testing.expect(map.verifyProbeInvariants());
}

fn expectMatchesOracle(map: *U32Map, oracle: *std.AutoHashMap(u32, u64)) !void {
    try std.testing.expectEqual(oracle.count(), map.len());

    var oracle_it = oracle.iterator();
    while (oracle_it.next()) |entry| {
        const found = map.getConst(entry.key_ptr.*) orelse return error.MissingMapEntry;
        try std.testing.expectEqual(entry.value_ptr.*, found.*);
    }

    var seen: usize = 0;
    var map_it = map.constIterator();
    while (map_it.next()) |entry| {
        const found = oracle.get(entry.key.*) orelse return error.MissingOracleEntry;
        try std.testing.expectEqual(found, entry.value.*);
        seen += 1;
    }
    try std.testing.expectEqual(oracle.count(), seen);
    try expectValid(map);
}

test "put get contains remove and iterator basics" {
    var map = U32Map.init(std.testing.allocator);
    defer map.deinit();

    try std.testing.expectEqual(@as(usize, 0), map.len());
    try std.testing.expect(!map.contains(7));
    try std.testing.expectEqual(@as(?*u64, null), map.get(7));

    try std.testing.expectEqual(@as(?u64, null), try map.put(7, 70));
    try std.testing.expectEqual(@as(?u64, null), try map.put(11, 110));
    try std.testing.expectEqual(@as(usize, 2), map.len());
    try std.testing.expect(map.contains(7));
    try std.testing.expectEqual(@as(u64, 70), map.get(7).?.*);

    try std.testing.expectEqual(@as(?u64, 70), try map.put(7, 700));
    try std.testing.expectEqual(@as(usize, 2), map.len());
    try std.testing.expectEqual(@as(u64, 700), map.getConst(7).?.*);

    var iter_count: usize = 0;
    var iter_sum: u64 = 0;
    var it = map.iterator();
    while (it.next()) |entry| {
        iter_count += 1;
        iter_sum += entry.value.*;
    }
    try std.testing.expectEqual(@as(usize, 2), iter_count);
    try std.testing.expectEqual(@as(u64, 810), iter_sum);

    try std.testing.expectEqual(@as(?u64, 700), map.remove(7));
    try std.testing.expectEqual(@as(?u64, null), map.remove(7));
    try std.testing.expect(!map.contains(7));
    try std.testing.expectEqual(@as(usize, 1), map.len());
    try expectValid(&map);
}

test "random operations match std AutoHashMap oracle" {
    var map = U32Map.init(std.testing.allocator);
    defer map.deinit();

    var oracle = std.AutoHashMap(u32, u64).init(std.testing.allocator);
    defer oracle.deinit();

    var rng = SplitMix64.init(0x726f_6269_6e68_6f6f);
    for (0..6000) |step| {
        const key = rng.bounded(257);
        const value = rng.next();
        switch (rng.bounded(4)) {
            0, 1 => {
                const previous = oracle.get(key);
                try std.testing.expectEqual(previous, try map.put(key, value));
                try oracle.put(key, value);
            },
            2 => {
                const previous = oracle.get(key);
                try std.testing.expectEqual(previous, map.remove(key));
                _ = oracle.remove(key);
            },
            else => {
                const expected = oracle.get(key);
                const actual = map.getConst(key);
                if (expected) |expected_value| {
                    try std.testing.expect(actual != null);
                    try std.testing.expectEqual(expected_value, actual.?.*);
                    try std.testing.expect(map.contains(key));
                } else {
                    try std.testing.expect(actual == null);
                    try std.testing.expect(!map.contains(key));
                }
            },
        }

        if (step % 97 == 0) {
            try expectMatchesOracle(&map, &oracle);
        }
    }

    try expectMatchesOracle(&map, &oracle);
}

test "backward shift delete preserves lookup chains and probe invariants" {
    const CollidingMap = RobinHoodMap(u32, u64, collisionHash, eqlU32);
    var map = try CollidingMap.initCapacity(std.testing.allocator, 16);
    defer map.deinit();

    for (0..10) |i| {
        try std.testing.expectEqual(@as(?u64, null), try map.put(@intCast(i), @intCast(i * 10)));
    }
    try expectValid(&map);

    try std.testing.expectEqual(@as(?u64, 0), map.remove(0));
    try std.testing.expectEqual(@as(?u64, 30), map.remove(3));
    try expectValid(&map);

    for (1..10) |i| {
        if (i == 3) continue;
        try std.testing.expectEqual(@as(u64, @intCast(i * 10)), map.getConst(@intCast(i)).?.*);
    }
    try std.testing.expectEqual(@as(?*const u64, null), map.getConst(0));
    try std.testing.expectEqual(@as(?*const u64, null), map.getConst(3));
}

test "grow rehashes every entry correctly" {
    var map = try U32Map.initCapacity(std.testing.allocator, 2);
    defer map.deinit();

    const initial_capacity = map.capacity();
    for (0..400) |i| {
        try std.testing.expectEqual(@as(?u64, null), try map.put(@intCast(i), @intCast(i + 1000)));
    }

    try std.testing.expect(map.capacity() > initial_capacity);
    try std.testing.expectEqual(@as(usize, 400), map.len());
    for (0..400) |i| {
        try std.testing.expectEqual(@as(u64, @intCast(i + 1000)), map.getConst(@intCast(i)).?.*);
    }
    try expectValid(&map);
}

test "high load factor remains correct without tombstones" {
    const LowBitsMap = RobinHoodMap(u32, u64, lowBitsHash, eqlU32);
    var map = try LowBitsMap.initCapacity(std.testing.allocator, 128);
    defer map.deinit();

    for (0..112) |i| {
        try std.testing.expectEqual(@as(?u64, null), try map.put(@intCast(i), @intCast(i * 17)));
    }
    try std.testing.expectEqual(@as(usize, 128), map.capacity());
    try std.testing.expectEqual(@as(usize, 112), map.len());

    for (0..112) |i| {
        try std.testing.expectEqual(@as(u64, @intCast(i * 17)), map.getConst(@intCast(i)).?.*);
    }

    for (0..56) |i| {
        const key: u32 = @intCast(i * 2);
        try std.testing.expectEqual(@as(?u64, @intCast(key * 17)), map.remove(key));
    }

    var occupied: usize = 0;
    for (map.slots) |slot| {
        if (slot.occupied) occupied += 1;
    }
    try std.testing.expectEqual(map.len(), occupied);

    for (0..112) |i| {
        const key: u32 = @intCast(i);
        if (key % 2 == 0 and key < 112) {
            try std.testing.expect(!map.contains(key));
        } else {
            try std.testing.expectEqual(@as(u64, @intCast(key * 17)), map.getConst(key).?.*);
        }
    }
    try expectValid(&map);
}

test "deterministic insertion and removal produce deterministic iteration" {
    var a = U32Map.init(std.testing.allocator);
    defer a.deinit();
    var b = U32Map.init(std.testing.allocator);
    defer b.deinit();

    for (0..160) |i| {
        const key: u32 = @intCast((i * 37) % 251);
        try std.testing.expectEqual(try a.put(key, @intCast(i)), try b.put(key, @intCast(i)));
    }
    for (0..80) |i| {
        const key: u32 = @intCast((i * 19) % 251);
        try std.testing.expectEqual(a.remove(key), b.remove(key));
    }

    var ai = a.constIterator();
    var bi = b.constIterator();
    while (true) {
        const av = ai.next();
        const bv = bi.next();
        try std.testing.expectEqual(av == null, bv == null);
        if (av == null) break;
        try std.testing.expectEqual(av.?.key.*, bv.?.key.*);
        try std.testing.expectEqual(av.?.value.*, bv.?.value.*);
    }
    try expectValid(&a);
    try expectValid(&b);
}

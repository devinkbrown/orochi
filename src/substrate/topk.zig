// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

const std = @import("std");

/// A bounded Space-Saving heavy-hitters monitor.
///
/// `T` must be usable with `std.AutoHashMap`, such as integers, enums, and
/// other value types with automatic hashing support.
pub fn SpaceSaving(comptime T: type) type {
    return struct {
        const Self = @This();

        pub const Entry = struct {
            item: T,
            count: usize,
            @"error": usize,
        };

        const Slot = struct {
            item: T,
            count: usize,
            @"error": usize,
            order: usize,
        };

        allocator: std.mem.Allocator,
        capacity_value: usize,
        slots: std.ArrayList(Slot) = .empty,
        index: std.AutoHashMap(T, usize),
        next_order: usize = 0,

        pub fn init(allocator: std.mem.Allocator, capacity_value: usize) Self {
            return .{
                .allocator = allocator,
                .capacity_value = capacity_value,
                .index = std.AutoHashMap(T, usize).init(allocator),
            };
        }

        pub fn deinit(self: *Self) void {
            self.index.deinit();
            self.slots.deinit(self.allocator);
            self.* = undefined;
        }

        pub fn capacity(self: Self) usize {
            return self.capacity_value;
        }

        pub fn len(self: Self) usize {
            return self.slots.items.len;
        }

        pub fn contains(self: *const Self, item: T) bool {
            return self.index.contains(item);
        }

        pub fn count(self: *const Self, item: T) ?usize {
            const slot_index = self.index.get(item) orelse return null;
            return self.slots.items[slot_index].count;
        }

        pub fn overestimateError(self: *const Self, item: T) ?usize {
            const slot_index = self.index.get(item) orelse return null;
            return self.slots.items[slot_index].@"error";
        }

        pub fn lowerBound(self: *const Self, item: T) ?usize {
            const slot_index = self.index.get(item) orelse return null;
            const slot = self.slots.items[slot_index];
            return slot.count - slot.@"error";
        }

        pub fn offer(self: *Self, item: T) !void {
            if (self.capacity_value == 0) return;

            if (self.index.get(item)) |slot_index| {
                self.slots.items[slot_index].count += 1;
                return;
            }

            if (self.slots.items.len < self.capacity_value) {
                const slot_index = self.slots.items.len;
                try self.slots.append(self.allocator, .{
                    .item = item,
                    .count = 1,
                    .@"error" = 0,
                    .order = self.takeOrder(),
                });
                try self.index.put(item, slot_index);
                return;
            }

            const victim_index = self.minSlotIndex();
            const victim = self.slots.items[victim_index];
            _ = self.index.remove(victim.item);

            self.slots.items[victim_index] = .{
                .item = item,
                .count = victim.count + 1,
                .@"error" = victim.count,
                .order = self.takeOrder(),
            };
            try self.index.put(item, victim_index);
        }

        pub fn offerMany(self: *Self, item: T, n: usize) !void {
            var i: usize = 0;
            while (i < n) : (i += 1) {
                try self.offer(item);
            }
        }

        /// Returns up to `k` monitored entries sorted by descending estimated
        /// count, then ascending over-estimation error.
        pub fn topK(self: *const Self, allocator: std.mem.Allocator, k: usize) ![]Entry {
            const n = @min(k, self.slots.items.len);
            var out: std.ArrayList(Entry) = .empty;
            errdefer out.deinit(allocator);

            for (self.slots.items) |slot| {
                try out.append(allocator, .{
                    .item = slot.item,
                    .count = slot.count,
                    .@"error" = slot.@"error",
                });
            }

            std.mem.sort(Entry, out.items, {}, entryLessThan);

            if (out.items.len == n) {
                return out.toOwnedSlice(allocator);
            }

            const sorted = try out.toOwnedSlice(allocator);
            errdefer allocator.free(sorted);

            const trimmed = try allocator.alloc(Entry, n);
            @memcpy(trimmed, sorted[0..n]);
            allocator.free(sorted);
            return trimmed;
        }

        fn takeOrder(self: *Self) usize {
            const order = self.next_order;
            self.next_order += 1;
            return order;
        }

        fn minSlotIndex(self: *const Self) usize {
            std.debug.assert(self.slots.items.len > 0);

            var best: usize = 0;
            var i: usize = 1;
            while (i < self.slots.items.len) : (i += 1) {
                if (slotLessThan(self.slots.items[i], self.slots.items[best])) {
                    best = i;
                }
            }
            return best;
        }

        fn slotLessThan(lhs: Slot, rhs: Slot) bool {
            if (lhs.count != rhs.count) return lhs.count < rhs.count;
            if (lhs.@"error" != rhs.@"error") return lhs.@"error" < rhs.@"error";
            return lhs.order < rhs.order;
        }

        fn entryLessThan(_: void, lhs: Entry, rhs: Entry) bool {
            if (lhs.count != rhs.count) return lhs.count > rhs.count;
            return lhs.@"error" < rhs.@"error";
        }
    };
}

fn trueCount(stream: []const u8, item: u8) usize {
    var n: usize = 0;
    for (stream) |seen| {
        if (seen == item) n += 1;
    }
    return n;
}

fn expectReported(
    tracker: *const SpaceSaving(u8),
    item: u8,
    expected_true_count: usize,
) !void {
    const estimated = tracker.count(item) orelse return error.ItemMissing;
    const over_error = tracker.overestimateError(item) orelse return error.ItemMissing;

    try std.testing.expect(estimated >= over_error);
    try std.testing.expect(estimated - over_error <= expected_true_count);
    try std.testing.expect(expected_true_count <= estimated);
}

test "skewed stream reports true top k in order" {
    const allocator = std.testing.allocator;
    var tracker = SpaceSaving(u8).init(allocator, 6);
    defer tracker.deinit();

    try tracker.offerMany('a', 30);
    try tracker.offerMany('b', 21);
    try tracker.offerMany('c', 14);
    try tracker.offerMany('d', 5);
    try tracker.offerMany('e', 3);
    try tracker.offerMany('f', 1);

    const top = try tracker.topK(allocator, 3);
    defer allocator.free(top);

    try std.testing.expectEqual(@as(usize, 3), top.len);
    try std.testing.expectEqual(@as(u8, 'a'), top[0].item);
    try std.testing.expectEqual(@as(u8, 'b'), top[1].item);
    try std.testing.expectEqual(@as(u8, 'c'), top[2].item);
    try std.testing.expect(top[0].count >= top[1].count);
    try std.testing.expect(top[1].count >= top[2].count);
}

test "reported counts bound the true count" {
    const allocator = std.testing.allocator;
    const stream = "aaaabbbbccccddeeffghijklmnopqrstuvwxyz";

    var tracker = SpaceSaving(u8).init(allocator, 5);
    defer tracker.deinit();

    for (stream) |item| {
        try tracker.offer(item);
    }

    const top = try tracker.topK(allocator, tracker.len());
    defer allocator.free(top);

    for (top) |entry| {
        const exact = trueCount(stream, entry.item);
        try std.testing.expect(entry.count >= entry.@"error");
        try std.testing.expect(entry.count - entry.@"error" <= exact);
        try std.testing.expect(exact <= entry.count);
    }
}

test "items below capacity may be evicted" {
    const allocator = std.testing.allocator;
    var tracker = SpaceSaving(u8).init(allocator, 3);
    defer tracker.deinit();

    try tracker.offer('a');
    try tracker.offer('b');
    try tracker.offer('c');
    try std.testing.expect(tracker.contains('a'));

    try tracker.offer('d');

    try std.testing.expectEqual(@as(usize, 3), tracker.len());
    try std.testing.expect(!tracker.contains('a'));
    try std.testing.expect(tracker.contains('d'));
}

test "minimum slot is replaced on overflow with recorded error" {
    const allocator = std.testing.allocator;
    var tracker = SpaceSaving(u8).init(allocator, 3);
    defer tracker.deinit();

    try tracker.offerMany('a', 4);
    try tracker.offerMany('b', 2);
    try tracker.offer('c');
    try tracker.offer('d');

    try std.testing.expect(tracker.contains('a'));
    try std.testing.expect(tracker.contains('b'));
    try std.testing.expect(!tracker.contains('c'));
    try std.testing.expect(tracker.contains('d'));
    try std.testing.expectEqual(@as(usize, 2), tracker.count('d').?);
    try std.testing.expectEqual(@as(usize, 1), tracker.overestimateError('d').?);
    try std.testing.expectEqual(@as(usize, 1), tracker.lowerBound('d').?);
}

test "deterministic on a fixed stream" {
    const allocator = std.testing.allocator;
    const stream = "abcaaadefbbbghicccaaabbbcccdddeee";

    var left = SpaceSaving(u8).init(allocator, 4);
    defer left.deinit();

    var right = SpaceSaving(u8).init(allocator, 4);
    defer right.deinit();

    for (stream) |item| {
        try left.offer(item);
        try right.offer(item);
    }

    const left_top = try left.topK(allocator, 4);
    defer allocator.free(left_top);

    const right_top = try right.topK(allocator, 4);
    defer allocator.free(right_top);

    try std.testing.expectEqual(left_top.len, right_top.len);
    for (left_top, right_top) |l, r| {
        try std.testing.expectEqual(l.item, r.item);
        try std.testing.expectEqual(l.count, r.count);
        try std.testing.expectEqual(l.@"error", r.@"error");
    }
}

test "zero capacity accepts offers and reports no entries" {
    const allocator = std.testing.allocator;
    var tracker = SpaceSaving(u8).init(allocator, 0);
    defer tracker.deinit();

    try tracker.offerMany('a', 10);

    const top = try tracker.topK(allocator, 10);
    defer allocator.free(top);

    try std.testing.expectEqual(@as(usize, 0), tracker.len());
    try std.testing.expectEqual(@as(usize, 0), top.len);
}

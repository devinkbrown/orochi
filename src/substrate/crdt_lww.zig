// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

const std = @import("std");

/// A hybrid-logical-clock style tag used to impose a total order on writes.
///
/// Later timestamps win. When timestamps are equal, the higher replica id wins.
/// Equal tags represent the same write event.
pub const Tag = struct {
    timestamp: u64,
    replica: u64,

    pub fn init(timestamp: u64, replica: u64) Tag {
        return .{
            .timestamp = timestamp,
            .replica = replica,
        };
    }

    pub fn order(lhs: Tag, rhs: Tag) std.math.Order {
        if (lhs.timestamp < rhs.timestamp) return .lt;
        if (lhs.timestamp > rhs.timestamp) return .gt;
        if (lhs.replica < rhs.replica) return .lt;
        if (lhs.replica > rhs.replica) return .gt;
        return .eq;
    }

    pub fn isAfter(lhs: Tag, rhs: Tag) bool {
        return lhs.order(rhs) == .gt;
    }
};

pub fn LwwRegister(comptime Value: type) type {
    return struct {
        const Self = @This();

        const Entry = struct {
            tag: Tag,
            value: Value,
        };

        entry: ?Entry = null,

        pub fn empty() Self {
            return .{ .entry = null };
        }

        pub fn init(value_: Value, timestamp: u64, replica: u64) Self {
            return .{
                .entry = .{
                    .tag = Tag.init(timestamp, replica),
                    .value = value_,
                },
            };
        }

        /// Records a local write with the caller-provided HLC tag.
        ///
        /// Callers are expected to provide monotonically increasing tags for
        /// local writes. Remote convergence is handled by merge.
        pub fn set(self: *Self, value_: Value, timestamp: u64, replica: u64) void {
            self.entry = .{
                .tag = Tag.init(timestamp, replica),
                .value = value_,
            };
        }

        /// Merges another register into this one.
        ///
        /// Returns true when this register changed.
        pub fn merge(self: *Self, other: Self) bool {
            const incoming = other.entry orelse return false;
            const current = self.entry orelse {
                self.entry = incoming;
                return true;
            };

            if (incoming.tag.isAfter(current.tag)) {
                self.entry = incoming;
                return true;
            }

            return false;
        }

        pub fn value(self: Self) ?Value {
            const entry_ = self.entry orelse return null;
            return entry_.value;
        }

        pub fn tag(self: Self) ?Tag {
            const entry_ = self.entry orelse return null;
            return entry_.tag;
        }
    };
}

const TestRegister = LwwRegister(u64);

fn expectRegister(register: TestRegister, expected_value: u64, expected_ts: u64, expected_replica: u64) !void {
    try std.testing.expectEqual(@as(?u64, expected_value), register.value());
    try std.testing.expectEqual(Tag.init(expected_ts, expected_replica), register.tag().?);
}

fn foldOrder(indices: []const usize, states: []const TestRegister) TestRegister {
    var acc = TestRegister.empty();
    for (indices) |index| {
        _ = acc.merge(states[index]);
    }
    return acc;
}

test "empty register has no value or tag" {
    const register = TestRegister.empty();
    try std.testing.expectEqual(@as(?u64, null), register.value());
    try std.testing.expectEqual(@as(?Tag, null), register.tag());
}

test "set stores value and supplied tag" {
    var register = TestRegister.empty();
    register.set(42, 100, 7);
    try expectRegister(register, 42, 100, 7);

    register.set(55, 101, 7);
    try expectRegister(register, 55, 101, 7);
}

test "concurrent set merges deterministically by timestamp" {
    var a = TestRegister.empty();
    var b = TestRegister.empty();
    a.set(10, 10, 1);
    b.set(20, 11, 2);

    var left = a;
    var right = b;
    try std.testing.expect(left.merge(b));
    try std.testing.expect(!right.merge(a));

    try expectRegister(left, 20, 11, 2);
    try expectRegister(right, 20, 11, 2);
}

test "timestamp ties break by replica" {
    var low_replica = TestRegister.init(1, 50, 2);
    var high_replica = TestRegister.init(2, 50, 9);

    try std.testing.expect(low_replica.merge(high_replica));
    try std.testing.expect(!high_replica.merge(low_replica));

    try expectRegister(low_replica, 2, 50, 9);
    try expectRegister(high_replica, 2, 50, 9);
}

test "value reflects winner after repeated merges" {
    var register = TestRegister.init(100, 1, 1);
    const older = TestRegister.init(50, 0, 99);
    const winner = TestRegister.init(900, 2, 3);
    const same_timestamp_lower_replica = TestRegister.init(800, 2, 2);

    try std.testing.expect(!register.merge(older));
    try std.testing.expect(register.merge(winner));
    try std.testing.expect(!register.merge(same_timestamp_lower_replica));
    try expectRegister(register, 900, 2, 3);
}

test "merge is idempotent" {
    var register = TestRegister.init(7, 4, 1);
    const same = register;

    try std.testing.expect(!register.merge(same));
    try expectRegister(register, 7, 4, 1);
}

test "merge is commutative for distinct tags" {
    const a = TestRegister.init(1, 5, 8);
    const b = TestRegister.init(2, 5, 9);
    const c = TestRegister.init(3, 6, 1);

    var ab = a;
    _ = ab.merge(b);
    var ba = b;
    _ = ba.merge(a);
    try expectRegister(ab, 2, 5, 9);
    try expectRegister(ba, 2, 5, 9);

    var ac = a;
    _ = ac.merge(c);
    var ca = c;
    _ = ca.merge(a);
    try expectRegister(ac, 3, 6, 1);
    try expectRegister(ca, 3, 6, 1);
}

test "merge is associative" {
    const a = TestRegister.init(1, 5, 1);
    const b = TestRegister.init(2, 6, 1);
    const c = TestRegister.init(3, 6, 9);

    var left_inner = a;
    _ = left_inner.merge(b);
    _ = left_inner.merge(c);

    var right_inner = b;
    _ = right_inner.merge(c);
    var right = a;
    _ = right.merge(right_inner);

    try expectRegister(left_inner, 3, 6, 9);
    try expectRegister(right, 3, 6, 9);
}

test "merge result is stable over pseudo-random orders" {
    const states = [_]TestRegister{
        TestRegister.init(10, 2, 2),
        TestRegister.init(20, 4, 3),
        TestRegister.init(30, 4, 9),
        TestRegister.init(40, 1, 99),
        TestRegister.init(50, 3, 1),
    };

    var prng = std.Random.DefaultPrng.init(0x6d697a75636869);
    const random = prng.random();

    var order = [_]usize{ 0, 1, 2, 3, 4 };
    for (0..64) |_| {
        random.shuffle(usize, &order);
        const folded = foldOrder(&order, &states);
        try expectRegister(folded, 30, 4, 9);
    }
}

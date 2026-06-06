const std = @import("std");

pub const AbBucket = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) AbBucket {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *AbBucket) void {
        _ = self;
    }

    pub fn bucket(self: *AbBucket, account: []const u8, experiment: []const u8, n_buckets: u32) u32 {
        _ = self;
        if (n_buckets == 0) return 0;

        var hasher = std.hash.Wyhash.init(0x6d_69_7a_75_63_68_69);
        hasher.update(experiment);
        hasher.update(&.{0});
        hasher.update(account);

        return @intCast(hasher.final() % n_buckets);
    }
};

test "AbBucket is stable for the same inputs" {
    var buckets = AbBucket.init(std.testing.allocator);
    defer buckets.deinit();

    const first = buckets.bucket("alice", "layout", 100);
    const second = buckets.bucket("alice", "layout", 100);
    try std.testing.expectEqual(first, second);
}

test "AbBucket keeps values inside range" {
    var buckets = AbBucket.init(std.testing.allocator);
    defer buckets.deinit();

    try std.testing.expect(buckets.bucket("bob", "copy", 1) < 1);
    try std.testing.expect(buckets.bucket("bob", "copy", 7) < 7);
    try std.testing.expect(buckets.bucket("bob", "copy", 1024) < 1024);
}

test "AbBucket includes experiment in hash input" {
    var buckets = AbBucket.init(std.testing.allocator);
    defer buckets.deinit();

    const a = buckets.bucket("stable-account", "exp-a", 4_294_967_291);
    const b = buckets.bucket("stable-account", "exp-b", 4_294_967_291);
    try std.testing.expect(a != b);
}

const std = @import("std");

const max_entries = 4096;
const max_key_len = 64;

pub const TopkTallyError = error{
    KeyTooLong,
    TooManyEntries,
    CountOverflow,
};

pub const TopkTally = struct {
    allocator: std.mem.Allocator,
    counts: std.StringHashMap(u64),

    pub const Entry = struct {
        key: []const u8,
        count: u64,
    };

    pub fn init(allocator: std.mem.Allocator) TopkTally {
        return .{
            .allocator = allocator,
            .counts = std.StringHashMap(u64).init(allocator),
        };
    }

    pub fn deinit(self: *TopkTally) void {
        var it = self.counts.iterator();
        while (it.next()) |entry| self.allocator.free(entry.key_ptr.*);
        self.counts.deinit();
        self.* = undefined;
    }

    pub fn bump(self: *TopkTally, key: []const u8) !void {
        try checkKey(key);
        if (!self.counts.contains(key) and self.counts.count() >= max_entries) {
            return TopkTallyError.TooManyEntries;
        }

        if (self.counts.getPtr(key)) |count| {
            if (count.* == std.math.maxInt(u64)) return TopkTallyError.CountOverflow;
            count.* += 1;
            return;
        }

        const owned_key = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(owned_key);
        try self.counts.put(owned_key, 1);
    }

    pub fn top(self: *const TopkTally, n: usize, out: []Entry) usize {
        const limit = @min(n, out.len);
        var written: usize = 0;

        while (written < limit) : (written += 1) {
            var best: ?Entry = null;
            var it = self.counts.iterator();
            while (it.next()) |entry| {
                const candidate: Entry = .{
                    .key = entry.key_ptr.*,
                    .count = entry.value_ptr.*,
                };
                if (alreadySelected(out[0..written], candidate.key)) continue;
                if (best == null or entryBeats(candidate, best.?)) best = candidate;
            }
            out[written] = best orelse return written;
        }

        return written;
    }

    pub fn countOf(self: *const TopkTally, key: []const u8) u64 {
        if (!validKey(key)) return 0;
        return self.counts.get(key) orelse 0;
    }
};

fn entryBeats(a: TopkTally.Entry, b: TopkTally.Entry) bool {
    if (a.count != b.count) return a.count > b.count;
    return std.mem.lessThan(u8, a.key, b.key);
}

fn alreadySelected(entries: []const TopkTally.Entry, key: []const u8) bool {
    for (entries) |entry| {
        if (std.mem.eql(u8, entry.key, key)) return true;
    }
    return false;
}

fn checkKey(key: []const u8) TopkTallyError!void {
    if (!validKey(key)) return TopkTallyError.KeyTooLong;
}

fn validKey(key: []const u8) bool {
    return key.len <= max_key_len;
}

const testing = std.testing;

test "bump creates and increments counts" {
    var tally = TopkTally.init(testing.allocator);
    defer tally.deinit();

    try tally.bump("join");
    try tally.bump("join");
    try tally.bump("part");

    try testing.expectEqual(@as(u64, 2), tally.countOf("join"));
    try testing.expectEqual(@as(u64, 1), tally.countOf("part"));
    try testing.expectEqual(@as(u64, 0), tally.countOf("quit"));
}

test "top returns highest counts first" {
    var tally = TopkTally.init(testing.allocator);
    defer tally.deinit();

    try tally.bump("alpha");
    try tally.bump("beta");
    try tally.bump("beta");
    try tally.bump("gamma");
    try tally.bump("gamma");
    try tally.bump("gamma");

    var out: [2]TopkTally.Entry = undefined;
    try testing.expectEqual(@as(usize, 2), tally.top(2, &out));
    try testing.expectEqualStrings("gamma", out[0].key);
    try testing.expectEqual(@as(u64, 3), out[0].count);
    try testing.expectEqualStrings("beta", out[1].key);
}

test "top uses key ordering for equal counts" {
    var tally = TopkTally.init(testing.allocator);
    defer tally.deinit();

    try tally.bump("zeta");
    try tally.bump("alpha");

    var out: [2]TopkTally.Entry = undefined;
    try testing.expectEqual(@as(usize, 2), tally.top(10, &out));
    try testing.expectEqualStrings("alpha", out[0].key);
    try testing.expectEqualStrings("zeta", out[1].key);
}

test "key cap is enforced" {
    var tally = TopkTally.init(testing.allocator);
    defer tally.deinit();

    var long_key: [max_key_len + 1]u8 = undefined;
    @memset(&long_key, 'k');
    try testing.expectError(TopkTallyError.KeyTooLong, tally.bump(&long_key));
}

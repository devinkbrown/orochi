const std = @import("std");
const toml = @import("../proto/toml.zig");

pub const default_max_entries: usize = 4096;

/// Runtime-tunable dedup window. Defaults preserve the historical hardcoded
/// behaviour; the orchestrator overlays the `[filter]` TOML section via
/// `Config.applyToml` before constructing a `DuplicateFilter`.
pub const Config = struct {
    /// Dedup FIFO window size (recent message-hash memory).
    max_entries: usize = default_max_entries,

    /// Overlay `[filter]` keys from a parsed TOML document onto `cfg`. Missing
    /// keys leave the current value untouched. Pure: no I/O, never fails.
    pub fn applyToml(cfg: *Config, doc: *const toml.Document) void {
        if (doc.getUint("filter.dedup_window")) |v| {
            if (v >= 1) cfg.max_entries = @intCast(v);
        }
    }
};

pub const DuplicateFilter = struct {
    /// Back-compat alias for the historical default window size.
    pub const max_entries: usize = default_max_entries;

    allocator: std.mem.Allocator,
    set: std.AutoHashMap(u64, void),
    fifo: std.ArrayList(u64),
    cfg: Config,

    pub fn init(allocator: std.mem.Allocator) DuplicateFilter {
        return initWithConfig(allocator, .{});
    }

    pub fn initWithConfig(allocator: std.mem.Allocator, cfg: Config) DuplicateFilter {
        return .{
            .allocator = allocator,
            .set = std.AutoHashMap(u64, void).init(allocator),
            .fifo = .empty,
            .cfg = cfg,
        };
    }

    pub fn deinit(self: *DuplicateFilter) void {
        self.set.deinit();
        self.fifo.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn seen(self: *DuplicateFilter, hash: u64) bool {
        if (self.set.contains(hash)) return true;
        self.insert(hash) catch @panic("duplicate filter allocation failed");
        return false;
    }

    pub fn len(self: *const DuplicateFilter) usize {
        return self.fifo.items.len;
    }

    pub fn contains(self: *const DuplicateFilter, hash: u64) bool {
        return self.set.contains(hash);
    }

    pub fn clear(self: *DuplicateFilter) void {
        self.set.clearRetainingCapacity();
        self.fifo.clearRetainingCapacity();
    }

    fn insert(self: *DuplicateFilter, hash: u64) !void {
        if (self.fifo.items.len >= self.cfg.max_entries) {
            const oldest = self.fifo.orderedRemove(0);
            _ = self.set.remove(oldest);
        }

        try self.fifo.append(self.allocator, hash);
        errdefer _ = self.fifo.orderedRemove(self.fifo.items.len - 1);
        try self.set.put(hash, {});
    }
};

test "seen returns false once then true for the same hash" {
    var filter = DuplicateFilter.init(std.testing.allocator);
    defer filter.deinit();

    try std.testing.expect(!filter.seen(42));
    try std.testing.expect(filter.seen(42));
    try std.testing.expectEqual(@as(usize, 1), filter.len());
}

test "bounded fifo evicts the oldest hash" {
    var filter = DuplicateFilter.init(std.testing.allocator);
    defer filter.deinit();

    var hash: u64 = 0;
    while (hash < DuplicateFilter.max_entries) : (hash += 1) {
        try std.testing.expect(!filter.seen(hash));
    }

    try std.testing.expectEqual(@as(usize, DuplicateFilter.max_entries), filter.len());
    try std.testing.expect(filter.contains(0));
    try std.testing.expect(!filter.seen(DuplicateFilter.max_entries));
    try std.testing.expect(!filter.contains(0));
    try std.testing.expect(filter.contains(DuplicateFilter.max_entries));
    try std.testing.expectEqual(@as(usize, DuplicateFilter.max_entries), filter.len());
}

test "duplicate hits do not move or grow the fifo" {
    var filter = DuplicateFilter.init(std.testing.allocator);
    defer filter.deinit();

    try std.testing.expect(!filter.seen(1));
    try std.testing.expect(!filter.seen(2));
    try std.testing.expect(filter.seen(1));
    try std.testing.expectEqual(@as(usize, 2), filter.len());
}

test "clear removes all remembered hashes" {
    var filter = DuplicateFilter.init(std.testing.allocator);
    defer filter.deinit();

    try std.testing.expect(!filter.seen(9));
    try std.testing.expect(!filter.seen(10));
    filter.clear();
    try std.testing.expectEqual(@as(usize, 0), filter.len());
    try std.testing.expect(!filter.contains(9));
    try std.testing.expect(!filter.seen(9));
}

test "Config default preserves historical window" {
    const cfg = Config{};
    try std.testing.expectEqual(default_max_entries, cfg.max_entries);
}

test "Config.applyToml overlays filter.dedup_window" {
    var doc = try toml.parse(std.testing.allocator, "[filter]\ndedup_window = 256\n");
    defer doc.deinit(std.testing.allocator);

    var cfg = Config{};
    cfg.applyToml(&doc);
    try std.testing.expectEqual(@as(usize, 256), cfg.max_entries);
}

test "initWithConfig honours a smaller dedup window" {
    var filter = DuplicateFilter.initWithConfig(std.testing.allocator, .{ .max_entries = 2 });
    defer filter.deinit();

    try std.testing.expect(!filter.seen(1));
    try std.testing.expect(!filter.seen(2));
    try std.testing.expect(!filter.seen(3)); // evicts hash 1
    try std.testing.expectEqual(@as(usize, 2), filter.len());
    try std.testing.expect(!filter.contains(1));
    try std.testing.expect(filter.contains(3));
}

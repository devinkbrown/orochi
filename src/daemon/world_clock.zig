//! Saved account time zone offsets.
const std = @import("std");

pub const Zone = struct {
    label: []const u8,
    offset_minutes: i64,
};

pub const Error = std.mem.Allocator.Error || error{TooManyZones};

const max_zones_per_account: usize = 16;

const ZoneList = struct {
    zones: std.ArrayListUnmanaged(Zone) = .empty,

    fn deinit(self: *ZoneList, allocator: std.mem.Allocator) void {
        for (self.zones.items) |zone| allocator.free(zone.label);
        self.zones.deinit(allocator);
    }

    fn findIndex(self: *const ZoneList, label: []const u8) ?usize {
        for (self.zones.items, 0..) |zone, index| {
            if (std.mem.eql(u8, zone.label, label)) return index;
        }
        return null;
    }
};

pub const WorldClock = struct {
    allocator: std.mem.Allocator,
    accounts: std.StringHashMap(ZoneList),

    pub fn init(allocator: std.mem.Allocator) WorldClock {
        return .{
            .allocator = allocator,
            .accounts = std.StringHashMap(ZoneList).init(allocator),
        };
    }

    pub fn deinit(self: *WorldClock) void {
        var iterator = self.accounts.iterator();
        while (iterator.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.accounts.deinit();
        self.* = undefined;
    }

    pub fn add(self: *WorldClock, account: []const u8, label: []const u8, offset_minutes: i64) Error!void {
        const zone_list = try self.ensureAccount(account);
        if (zone_list.findIndex(label)) |index| {
            zone_list.zones.items[index].offset_minutes = offset_minutes;
            return;
        }
        if (zone_list.zones.items.len >= max_zones_per_account) return error.TooManyZones;

        const owned_label = try self.allocator.dupe(u8, label);
        errdefer self.allocator.free(owned_label);
        try zone_list.zones.append(self.allocator, .{
            .label = owned_label,
            .offset_minutes = offset_minutes,
        });
    }

    pub fn remove(self: *WorldClock, account: []const u8, label: []const u8) bool {
        const entry = self.accounts.getEntry(account) orelse return false;
        const index = entry.value_ptr.findIndex(label) orelse return false;

        const removed = entry.value_ptr.zones.items[index];
        self.allocator.free(removed.label);
        std.mem.copyForwards(
            Zone,
            entry.value_ptr.zones.items[index..],
            entry.value_ptr.zones.items[index + 1 ..],
        );
        entry.value_ptr.zones.items.len -= 1;

        if (entry.value_ptr.zones.items.len == 0) self.dropAccount(entry);
        return true;
    }

    pub fn list(self: *const WorldClock, account: []const u8, out: []Zone) usize {
        const zones = self.accounts.getPtr(account) orelse return 0;
        const count = @min(out.len, zones.zones.items.len);
        @memcpy(out[0..count], zones.zones.items[0..count]);
        return count;
    }

    fn ensureAccount(self: *WorldClock, account: []const u8) Error!*ZoneList {
        if (self.accounts.getPtr(account)) |zone_list| return zone_list;

        const owned_account = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(owned_account);
        try self.accounts.putNoClobber(owned_account, .{});
        return self.accounts.getPtr(account).?;
    }

    fn dropAccount(self: *WorldClock, entry: std.StringHashMap(ZoneList).Entry) void {
        const owned_account = entry.key_ptr.*;
        entry.value_ptr.zones.deinit(self.allocator);
        self.accounts.removeByPtr(entry.key_ptr);
        self.allocator.free(owned_account);
    }
};

const testing = std.testing;

test "add and list saved zones for one account" {
    var clock = WorldClock.init(testing.allocator);
    defer clock.deinit();

    try clock.add("alice", "UTC", 0);
    try clock.add("alice", "Berlin", 120);

    var out: [4]Zone = undefined;
    const count = clock.list("alice", &out);
    try testing.expectEqual(@as(usize, 2), count);
    try testing.expectEqualStrings("UTC", out[0].label);
    try testing.expectEqual(@as(i64, 120), out[1].offset_minutes);
}

test "add replaces a matching label" {
    var clock = WorldClock.init(testing.allocator);
    defer clock.deinit();

    try clock.add("alice", "Local", 60);
    try clock.add("alice", "Local", 120);

    var out: [2]Zone = undefined;
    try testing.expectEqual(@as(usize, 1), clock.list("alice", &out));
    try testing.expectEqual(@as(i64, 120), out[0].offset_minutes);
}

test "remove drops labels and prunes empty accounts" {
    var clock = WorldClock.init(testing.allocator);
    defer clock.deinit();

    try clock.add("alice", "UTC", 0);
    try testing.expect(clock.remove("alice", "UTC"));
    try testing.expect(!clock.remove("alice", "UTC"));

    var out: [1]Zone = undefined;
    try testing.expectEqual(@as(usize, 0), clock.list("alice", &out));
}

test "zone cap is enforced per account" {
    var clock = WorldClock.init(testing.allocator);
    defer clock.deinit();

    var index: usize = 0;
    while (index < 16) : (index += 1) {
        var label_buf: [16]u8 = undefined;
        const label = try std.fmt.bufPrint(&label_buf, "z{d}", .{index});
        try clock.add("alice", label, @intCast(index));
    }
    try testing.expectError(error.TooManyZones, clock.add("alice", "extra", 0));
}

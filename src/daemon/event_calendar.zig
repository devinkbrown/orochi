//! Per-channel scheduled event calendar.
const std = @import("std");

pub const Event = struct {
    id: u64,
    when_ms: i64,
    title: []const u8,
};

pub const Error = std.mem.Allocator.Error || error{IdExhausted};

const StoredEvent = Event;

const EventList = struct {
    events: std.ArrayListUnmanaged(StoredEvent) = .empty,

    fn deinit(self: *EventList, allocator: std.mem.Allocator) void {
        for (self.events.items) |event| allocator.free(event.title);
        self.events.deinit(allocator);
    }

    fn findIndex(self: *const EventList, id: u64) ?usize {
        for (self.events.items, 0..) |event, index| {
            if (event.id == id) return index;
        }
        return null;
    }

    fn appendSorted(self: *EventList, allocator: std.mem.Allocator, event: StoredEvent) std.mem.Allocator.Error!void {
        try self.events.append(allocator, event);
        var index = self.events.items.len - 1;
        while (index > 0 and eventLess(self.events.items[index], self.events.items[index - 1])) : (index -= 1) {
            std.mem.swap(StoredEvent, &self.events.items[index], &self.events.items[index - 1]);
        }
    }
};

pub const EventCalendar = struct {
    allocator: std.mem.Allocator,
    channels: std.StringHashMap(EventList),
    next_id: u64 = 1,

    pub fn init(allocator: std.mem.Allocator) EventCalendar {
        return .{
            .allocator = allocator,
            .channels = std.StringHashMap(EventList).init(allocator),
        };
    }

    pub fn deinit(self: *EventCalendar) void {
        var iterator = self.channels.iterator();
        while (iterator.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.channels.deinit();
        self.* = undefined;
    }

    pub fn add(self: *EventCalendar, channel: []const u8, when_ms: i64, title: []const u8) Error!u64 {
        if (self.next_id == 0) return error.IdExhausted;

        const owned_title = try self.allocator.dupe(u8, title);
        errdefer self.allocator.free(owned_title);

        const list = try self.ensureChannel(channel);
        const id = self.next_id;
        self.next_id +%= 1;
        try list.appendSorted(self.allocator, .{
            .id = id,
            .when_ms = when_ms,
            .title = owned_title,
        });
        return id;
    }

    pub fn upcoming(self: *const EventCalendar, channel: []const u8, now_ms: i64, out: []Event) usize {
        const list = self.channels.getPtr(channel) orelse return 0;
        var count: usize = 0;
        for (list.events.items) |event| {
            if (event.when_ms < now_ms) continue;
            if (count >= out.len) break;
            out[count] = event;
            count += 1;
        }
        return count;
    }

    pub fn cancel(self: *EventCalendar, channel: []const u8, id: u64) bool {
        const entry = self.channels.getEntry(channel) orelse return false;
        const index = entry.value_ptr.findIndex(id) orelse return false;

        const removed = entry.value_ptr.events.items[index];
        self.allocator.free(removed.title);
        std.mem.copyForwards(
            StoredEvent,
            entry.value_ptr.events.items[index..],
            entry.value_ptr.events.items[index + 1 ..],
        );
        entry.value_ptr.events.items.len -= 1;

        if (entry.value_ptr.events.items.len == 0) self.dropChannel(entry);
        return true;
    }

    fn ensureChannel(self: *EventCalendar, channel: []const u8) Error!*EventList {
        if (self.channels.getPtr(channel)) |list| return list;

        const owned_channel = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(owned_channel);
        try self.channels.putNoClobber(owned_channel, .{});
        return self.channels.getPtr(channel).?;
    }

    fn dropChannel(self: *EventCalendar, entry: std.StringHashMap(EventList).Entry) void {
        const owned_channel = entry.key_ptr.*;
        entry.value_ptr.events.deinit(self.allocator);
        self.channels.removeByPtr(entry.key_ptr);
        self.allocator.free(owned_channel);
    }
};

fn eventLess(a: StoredEvent, b: StoredEvent) bool {
    if (a.when_ms != b.when_ms) return a.when_ms < b.when_ms;
    return a.id < b.id;
}

const testing = std.testing;

test "add returns stable ids and upcoming is sorted" {
    var calendar = EventCalendar.init(testing.allocator);
    defer calendar.deinit();

    const later = try calendar.add("#ops", 3000, "deploy");
    const earlier = try calendar.add("#ops", 1000, "standup");

    var out: [4]Event = undefined;
    const count = calendar.upcoming("#ops", 0, &out);
    try testing.expectEqual(@as(usize, 2), count);
    try testing.expectEqual(earlier, out[0].id);
    try testing.expectEqual(later, out[1].id);
    try testing.expectEqualStrings("standup", out[0].title);
}

test "upcoming filters old events and honors output capacity" {
    var calendar = EventCalendar.init(testing.allocator);
    defer calendar.deinit();

    _ = try calendar.add("#ops", 1000, "old");
    _ = try calendar.add("#ops", 2000, "soon");
    _ = try calendar.add("#ops", 3000, "next");

    var out: [1]Event = undefined;
    const count = calendar.upcoming("#ops", 1500, &out);
    try testing.expectEqual(@as(usize, 1), count);
    try testing.expectEqualStrings("soon", out[0].title);
}

test "cancel removes one event and prunes empty channels" {
    var calendar = EventCalendar.init(testing.allocator);
    defer calendar.deinit();

    const id = try calendar.add("#ops", 1000, "one");
    try testing.expect(calendar.cancel("#ops", id));
    try testing.expect(!calendar.cancel("#ops", id));

    var out: [1]Event = undefined;
    try testing.expectEqual(@as(usize, 0), calendar.upcoming("#ops", 0, &out));
}

test "events are isolated by channel" {
    var calendar = EventCalendar.init(testing.allocator);
    defer calendar.deinit();

    _ = try calendar.add("#a", 1000, "alpha");
    _ = try calendar.add("#b", 1000, "beta");

    var out: [2]Event = undefined;
    const count = calendar.upcoming("#b", 0, &out);
    try testing.expectEqual(@as(usize, 1), count);
    try testing.expectEqualStrings("beta", out[0].title);
}

// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

const std = @import("std");

pub const max_fields = 16;

pub const Category = enum {
    connectivity,
    transport,
    recovery,
    security,
};

pub const FieldValue = union(enum) {
    int: i64,
    uint: u64,
    str: []const u8,
    boolean: bool,
};

pub const Field = struct {
    key: []const u8,
    val: FieldValue,
};

pub const Event = struct {
    time_us: u64,
    category: Category,
    event_type: []const u8,
    fields: [max_fields]Field = undefined,
    field_count: u8 = 0,

    pub fn init(time_us: u64, category: Category, event_type: []const u8) Event {
        return .{
            .time_us = time_us,
            .category = category,
            .event_type = event_type,
        };
    }

    pub fn withFields(time_us: u64, category: Category, event_type: []const u8, fields: []const Field) !Event {
        if (fields.len > max_fields) return error.TooManyFields;

        var event = Event.init(time_us, category, event_type);
        for (fields) |field| {
            try event.addField(field.key, field.val);
        }
        return event;
    }

    pub fn addField(self: *Event, key: []const u8, val: FieldValue) !void {
        if (self.field_count >= max_fields) return error.TooManyFields;
        self.fields[self.field_count] = .{ .key = key, .val = val };
        self.field_count += 1;
    }

    pub fn fieldSlice(self: *const Event) []const Field {
        return self.fields[0..self.field_count];
    }
};

pub const CategoryFilter = struct {
    connectivity: bool = true,
    transport: bool = true,
    recovery: bool = true,
    security: bool = true,

    pub fn all() CategoryFilter {
        return .{};
    }

    pub fn none() CategoryFilter {
        return .{
            .connectivity = false,
            .transport = false,
            .recovery = false,
            .security = false,
        };
    }

    pub fn only(category: Category) CategoryFilter {
        var filter = CategoryFilter.none();
        switch (category) {
            .connectivity => filter.connectivity = true,
            .transport => filter.transport = true,
            .recovery => filter.recovery = true,
            .security => filter.security = true,
        }
        return filter;
    }

    pub fn matches(self: CategoryFilter, category: Category) bool {
        return switch (category) {
            .connectivity => self.connectivity,
            .transport => self.transport,
            .recovery => self.recovery,
            .security => self.security,
        };
    }
};

pub fn Recorder(comptime capacity: usize) type {
    if (capacity == 0) @compileError("qlog Recorder capacity must be greater than zero");

    return struct {
        const Self = @This();

        events: [capacity]Event = undefined,
        start: usize = 0,
        len: usize = 0,

        pub fn init() Self {
            return .{};
        }

        pub fn record(self: *Self, event: Event) void {
            if (self.len < capacity) {
                self.events[(self.start + self.len) % capacity] = event;
                self.len += 1;
                return;
            }

            self.events[self.start] = event;
            self.start = (self.start + 1) % capacity;
        }

        pub fn count(self: *const Self) usize {
            return self.len;
        }

        pub fn at(self: *const Self, index: usize) ?*const Event {
            if (index >= self.len) return null;
            return &self.events[(self.start + index) % capacity];
        }

        pub fn exportNdjson(self: *const Self, out: *std.ArrayList(u8), allocator: std.mem.Allocator, filter: CategoryFilter) !void {
            var i: usize = 0;
            while (i < self.len) : (i += 1) {
                const event = self.at(i).?;
                if (!filter.matches(event.category)) continue;
                try serializeEvent(out, allocator, event);
                try out.append(allocator, '\n');
            }
        }
    };
}

pub fn serializeEvents(out: *std.ArrayList(u8), allocator: std.mem.Allocator, events: []const Event, filter: CategoryFilter) !void {
    for (events) |*event| {
        if (!filter.matches(event.category)) continue;
        try serializeEvent(out, allocator, event);
        try out.append(allocator, '\n');
    }
}

pub fn serializeEvent(out: *std.ArrayList(u8), allocator: std.mem.Allocator, event: *const Event) !void {
    try out.appendSlice(allocator, "{\"time_us\":");
    try appendUnsigned(out, allocator, event.time_us);
    try out.appendSlice(allocator, ",\"category\":");
    try appendJsonString(out, allocator, @tagName(event.category));
    try out.appendSlice(allocator, ",\"event_type\":");
    try appendJsonString(out, allocator, event.event_type);
    try out.appendSlice(allocator, ",\"fields\":{");

    for (event.fieldSlice(), 0..) |field, index| {
        if (index != 0) try out.append(allocator, ',');
        try appendJsonString(out, allocator, field.key);
        try out.append(allocator, ':');
        try appendFieldValue(out, allocator, field.val);
    }

    try out.appendSlice(allocator, "}}");
}

fn appendFieldValue(out: *std.ArrayList(u8), allocator: std.mem.Allocator, value: FieldValue) !void {
    switch (value) {
        .int => |v| try appendSigned(out, allocator, v),
        .uint => |v| try appendUnsigned(out, allocator, v),
        .str => |v| try appendJsonString(out, allocator, v),
        .boolean => |v| try out.appendSlice(allocator, if (v) "true" else "false"),
    }
}

fn appendSigned(out: *std.ArrayList(u8), allocator: std.mem.Allocator, value: i64) !void {
    var buf: [32]u8 = undefined;
    const text = try std.fmt.bufPrint(&buf, "{}", .{value});
    try out.appendSlice(allocator, text);
}

fn appendUnsigned(out: *std.ArrayList(u8), allocator: std.mem.Allocator, value: u64) !void {
    var buf: [32]u8 = undefined;
    const text = try std.fmt.bufPrint(&buf, "{}", .{value});
    try out.appendSlice(allocator, text);
}

fn appendJsonString(out: *std.ArrayList(u8), allocator: std.mem.Allocator, text: []const u8) !void {
    try out.append(allocator, '"');
    for (text) |byte| {
        switch (byte) {
            '"' => try out.appendSlice(allocator, "\\\""),
            '\\' => try out.appendSlice(allocator, "\\\\"),
            '\n' => try out.appendSlice(allocator, "\\n"),
            '\r' => try out.appendSlice(allocator, "\\r"),
            '\t' => try out.appendSlice(allocator, "\\t"),
            0x08 => try out.appendSlice(allocator, "\\b"),
            0x0c => try out.appendSlice(allocator, "\\f"),
            0x00...0x07, 0x0b, 0x0e...0x1f => {
                try out.appendSlice(allocator, "\\u00");
                try out.append(allocator, hexLower(byte >> 4));
                try out.append(allocator, hexLower(byte & 0x0f));
            },
            else => try out.append(allocator, byte),
        }
    }
    try out.append(allocator, '"');
}

fn hexLower(nibble: u8) u8 {
    return if (nibble < 10) '0' + nibble else 'a' + (nibble - 10);
}

test "record N events and preserve insertion order before overflow" {
    var recorder = Recorder(4).init();

    var i: u64 = 0;
    while (i < 4) : (i += 1) {
        var event = Event.init(100 + i, .transport, "packet_sent");
        try event.addField("seq", .{ .uint = i });
        recorder.record(event);
    }

    try std.testing.expectEqual(@as(usize, 4), recorder.count());
    try std.testing.expectEqual(@as(u64, 100), recorder.at(0).?.time_us);
    try std.testing.expectEqual(@as(u64, 101), recorder.at(1).?.time_us);
    try std.testing.expectEqual(@as(u64, 102), recorder.at(2).?.time_us);
    try std.testing.expectEqual(@as(u64, 103), recorder.at(3).?.time_us);
    try std.testing.expect(recorder.at(4) == null);
}

test "ring overflow keeps newest capacity events in order" {
    var recorder = Recorder(3).init();

    var i: u64 = 0;
    while (i < 7) : (i += 1) {
        recorder.record(Event.init(i, .recovery, "loss_timer"));
    }

    try std.testing.expectEqual(@as(usize, 3), recorder.count());
    try std.testing.expectEqual(@as(u64, 4), recorder.at(0).?.time_us);
    try std.testing.expectEqual(@as(u64, 5), recorder.at(1).?.time_us);
    try std.testing.expectEqual(@as(u64, 6), recorder.at(2).?.time_us);
}

test "serialize produces stable deterministic output" {
    var recorder = Recorder(4).init();

    var connected = Event.init(10, .connectivity, "path_ready");
    try connected.addField("path", .{ .str = "primary" });
    try connected.addField("rtt_us", .{ .uint = 4200 });
    recorder.record(connected);

    var key_update = Event.init(11, .security, "key_update");
    try key_update.addField("epoch", .{ .int = -1 });
    try key_update.addField("confirmed", .{ .boolean = true });
    recorder.record(key_update);

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(std.testing.allocator);

    try recorder.exportNdjson(&out, std.testing.allocator, CategoryFilter.all());

    const expected =
        "{\"time_us\":10,\"category\":\"connectivity\",\"event_type\":\"path_ready\",\"fields\":{\"path\":\"primary\",\"rtt_us\":4200}}\n" ++
        "{\"time_us\":11,\"category\":\"security\",\"event_type\":\"key_update\",\"fields\":{\"epoch\":-1,\"confirmed\":true}}\n";
    try std.testing.expectEqualStrings(expected, out.items);
}

test "category filter selects correctly" {
    var recorder = Recorder(5).init();
    recorder.record(Event.init(1, .connectivity, "connected"));
    recorder.record(Event.init(2, .transport, "packet_received"));
    recorder.record(Event.init(3, .recovery, "packet_lost"));
    recorder.record(Event.init(4, .security, "handshake_done"));

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(std.testing.allocator);

    try recorder.exportNdjson(&out, std.testing.allocator, CategoryFilter.only(.recovery));

    const expected =
        "{\"time_us\":3,\"category\":\"recovery\",\"event_type\":\"packet_lost\",\"fields\":{}}\n";
    try std.testing.expectEqualStrings(expected, out.items);
}

test "string escaping handles quotes newlines slashes and control chars" {
    var event = Event.init(7, .transport, "escaped\n\"type\"");
    try event.addField("quote", .{ .str = "say \"hello\"" });
    try event.addField("slash", .{ .str = "a\\b" });
    try event.addField("line", .{ .str = "one\ntwo\rthree\tfour" });
    try event.addField("control", .{ .str = "\x01\x08\x0c\x1f" });

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(std.testing.allocator);

    try serializeEvent(&out, std.testing.allocator, &event);

    const expected =
        "{\"time_us\":7,\"category\":\"transport\",\"event_type\":\"escaped\\n\\\"type\\\"\",\"fields\":{\"quote\":\"say \\\"hello\\\"\",\"slash\":\"a\\\\b\",\"line\":\"one\\ntwo\\rthree\\tfour\",\"control\":\"\\u0001\\b\\f\\u001f\"}}";
    try std.testing.expectEqualStrings(expected, out.items);
}

test "field value types serialize correctly" {
    var event = Event.init(99, .security, "field_values");
    try event.addField("neg", .{ .int = -42 });
    try event.addField("pos", .{ .uint = 18446744073709551615 });
    try event.addField("name", .{ .str = "onyx" });
    try event.addField("ok", .{ .boolean = false });

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(std.testing.allocator);

    try serializeEvent(&out, std.testing.allocator, &event);

    const expected =
        "{\"time_us\":99,\"category\":\"security\",\"event_type\":\"field_values\",\"fields\":{\"neg\":-42,\"pos\":18446744073709551615,\"name\":\"onyx\",\"ok\":false}}";
    try std.testing.expectEqualStrings(expected, out.items);
}

test "field capacity is bounded" {
    var event = Event.init(1, .transport, "many_fields");

    var i: usize = 0;
    while (i < max_fields) : (i += 1) {
        try event.addField("k", .{ .uint = i });
    }

    try std.testing.expectError(error.TooManyFields, event.addField("overflow", .{ .boolean = true }));
}

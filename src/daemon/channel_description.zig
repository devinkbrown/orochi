//! Per-channel summary and rules text.
const std = @import("std");

pub const Error = std.mem.Allocator.Error || error{
    EmptyChannel,
    ChannelTooLong,
    FieldTooLong,
    TooManyChannels,
};

pub const Config = struct {
    max_channels: usize = 4096,
    max_channel_len: usize = 128,
    max_field_len: usize = 400,
};

pub const Field = enum {
    summary,
    rules,
};

pub const Desc = struct {
    summary: ?[]const u8 = null,
    rules: ?[]const u8 = null,
};

pub const ChannelDescription = struct {
    allocator: std.mem.Allocator,
    config: Config,
    descriptions: std.StringHashMap(Desc),

    pub fn init(allocator: std.mem.Allocator) ChannelDescription {
        return initWithConfig(allocator, .{});
    }

    pub fn initWithConfig(allocator: std.mem.Allocator, config: Config) ChannelDescription {
        return .{
            .allocator = allocator,
            .config = config,
            .descriptions = std.StringHashMap(Desc).init(allocator),
        };
    }

    pub fn deinit(self: *ChannelDescription) void {
        var it = self.descriptions.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.freeDesc(entry.value_ptr.*);
        }
        self.descriptions.deinit();
        self.* = undefined;
    }

    pub fn setField(self: *ChannelDescription, channel: []const u8, field: Field, val: []const u8) Error!void {
        try self.validateChannel(channel);
        if (val.len > self.config.max_field_len) return error.FieldTooLong;

        const owned_val = try self.allocator.dupe(u8, val);
        errdefer self.allocator.free(owned_val);

        if (self.descriptions.getEntry(channel)) |entry| {
            self.replaceField(entry.value_ptr, field, owned_val);
            return;
        }

        if (self.descriptions.count() >= self.config.max_channels) return error.TooManyChannels;

        const owned_channel = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(owned_channel);

        var desc: Desc = .{};
        setDescField(&desc, field, owned_val);
        try self.descriptions.putNoClobber(owned_channel, desc);
    }

    pub fn get(self: *const ChannelDescription, channel: []const u8) ?Desc {
        return self.descriptions.get(channel);
    }

    pub fn clear(self: *ChannelDescription, channel: []const u8) bool {
        const entry = self.descriptions.getEntry(channel) orelse return false;
        const owned_channel = entry.key_ptr.*;
        const desc = entry.value_ptr.*;
        self.descriptions.removeByPtr(entry.key_ptr);
        self.allocator.free(owned_channel);
        self.freeDesc(desc);
        return true;
    }

    fn replaceField(self: *ChannelDescription, desc: *Desc, field: Field, owned_val: []const u8) void {
        switch (field) {
            .summary => {
                if (desc.summary) |old| self.allocator.free(old);
                desc.summary = owned_val;
            },
            .rules => {
                if (desc.rules) |old| self.allocator.free(old);
                desc.rules = owned_val;
            },
        }
    }

    fn freeDesc(self: *ChannelDescription, desc: Desc) void {
        if (desc.summary) |summary| self.allocator.free(summary);
        if (desc.rules) |rules| self.allocator.free(rules);
    }

    fn validateChannel(self: *const ChannelDescription, channel: []const u8) Error!void {
        if (channel.len == 0) return error.EmptyChannel;
        if (channel.len > self.config.max_channel_len) return error.ChannelTooLong;
    }
};

fn setDescField(desc: *Desc, field: Field, owned_val: []const u8) void {
    switch (field) {
        .summary => desc.summary = owned_val,
        .rules => desc.rules = owned_val,
    }
}

const testing = std.testing;

test "setField stores and retrieves summary" {
    var descriptions = ChannelDescription.init(testing.allocator);
    defer descriptions.deinit();

    try descriptions.setField("#main", .summary, "general discussion");
    const desc = descriptions.get("#main").?;
    try testing.expectEqualStrings("general discussion", desc.summary.?);
    try testing.expect(desc.rules == null);
}

test "summary and rules update independently" {
    var descriptions = ChannelDescription.init(testing.allocator);
    defer descriptions.deinit();

    try descriptions.setField("#main", .summary, "old");
    try descriptions.setField("#main", .rules, "be kind");
    try descriptions.setField("#main", .summary, "new");
    const desc = descriptions.get("#main").?;
    try testing.expectEqualStrings("new", desc.summary.?);
    try testing.expectEqualStrings("be kind", desc.rules.?);
}

test "clear removes description state" {
    var descriptions = ChannelDescription.init(testing.allocator);
    defer descriptions.deinit();

    try descriptions.setField("#main", .rules, "read the topic");
    try testing.expect(descriptions.clear("#main"));
    try testing.expect(!descriptions.clear("#main"));
    try testing.expect(descriptions.get("#main") == null);
}

test "field length and channel caps are enforced" {
    var descriptions = ChannelDescription.initWithConfig(testing.allocator, .{ .max_channels = 1, .max_channel_len = 4, .max_field_len = 3 });
    defer descriptions.deinit();

    try testing.expectError(error.EmptyChannel, descriptions.setField("", .summary, "ok"));
    try testing.expectError(error.ChannelTooLong, descriptions.setField("#toolong", .summary, "ok"));
    try testing.expectError(error.FieldTooLong, descriptions.setField("#ok", .summary, "long"));
    try descriptions.setField("#one", .summary, "one");
    try testing.expectError(error.TooManyChannels, descriptions.setField("#two", .rules, "two"));
}

test "empty field values are preserved" {
    var descriptions = ChannelDescription.init(testing.allocator);
    defer descriptions.deinit();

    try descriptions.setField("#main", .summary, "");
    const desc = descriptions.get("#main").?;
    try testing.expectEqualStrings("", desc.summary.?);
}

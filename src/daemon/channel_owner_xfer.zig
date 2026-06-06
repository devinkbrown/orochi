const std = @import("std");

pub const ChannelOwnerXfer = struct {
    const max_name_len = 128;
    const max_offers = 4096;

    allocator: std.mem.Allocator,
    offers: std.ArrayList(Offer) = .empty,
    accepted_from: std.ArrayList([]u8) = .empty,

    const Offer = struct {
        channel: []u8,
        from: []u8,
        to: []u8,
    };

    pub fn init(allocator: std.mem.Allocator) ChannelOwnerXfer {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *ChannelOwnerXfer) void {
        for (self.offers.items) |offer_item| {
            self.allocator.free(offer_item.channel);
            self.allocator.free(offer_item.from);
            self.allocator.free(offer_item.to);
        }
        self.offers.deinit(self.allocator);

        for (self.accepted_from.items) |from| {
            self.allocator.free(from);
        }
        self.accepted_from.deinit(self.allocator);

        self.* = ChannelOwnerXfer.init(self.allocator);
    }

    pub fn offer(self: *ChannelOwnerXfer, channel: []const u8, from: []const u8, to: []const u8) !void {
        try validateName(channel);
        try validateName(from);
        try validateName(to);

        const channel_copy = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(channel_copy);
        const from_copy = try self.allocator.dupe(u8, from);
        errdefer self.allocator.free(from_copy);
        const to_copy = try self.allocator.dupe(u8, to);
        errdefer self.allocator.free(to_copy);

        try self.accepted_from.ensureTotalCapacity(self.allocator, self.accepted_from.items.len + self.offers.items.len + 1);

        if (self.find(channel)) |index| {
            const old = self.offers.items[index];
            self.allocator.free(old.channel);
            self.allocator.free(old.from);
            self.allocator.free(old.to);
            self.offers.items[index] = .{
                .channel = channel_copy,
                .from = from_copy,
                .to = to_copy,
            };
            return;
        }

        if (self.offers.items.len >= max_offers) return error.TooManyOffers;
        try self.offers.append(self.allocator, .{
            .channel = channel_copy,
            .from = from_copy,
            .to = to_copy,
        });
    }

    pub fn accept(self: *ChannelOwnerXfer, channel: []const u8, to: []const u8) ?[]const u8 {
        const index = self.find(channel) orelse return null;
        if (!std.mem.eql(u8, self.offers.items[index].to, to)) return null;

        const accepted = self.offers.orderedRemove(index);
        self.allocator.free(accepted.channel);
        self.allocator.free(accepted.to);
        self.accepted_from.appendAssumeCapacity(accepted.from);
        return accepted.from;
    }

    pub fn cancel(self: *ChannelOwnerXfer, channel: []const u8) bool {
        const index = self.find(channel) orelse return false;
        const removed = self.offers.orderedRemove(index);
        self.allocator.free(removed.channel);
        self.allocator.free(removed.from);
        self.allocator.free(removed.to);
        return true;
    }

    pub fn pendingTo(self: *const ChannelOwnerXfer, channel: []const u8) ?[]const u8 {
        const index = self.find(channel) orelse return null;
        return self.offers.items[index].to;
    }

    fn find(self: *const ChannelOwnerXfer, channel: []const u8) ?usize {
        for (self.offers.items, 0..) |offer_item, index| {
            if (std.mem.eql(u8, offer_item.channel, channel)) return index;
        }
        return null;
    }

    fn validateName(value: []const u8) !void {
        if (value.len == 0) return error.EmptyName;
        if (value.len > max_name_len) return error.NameTooLong;
    }
};

test "offer records and replaces a pending transfer" {
    var xfer = ChannelOwnerXfer.init(std.testing.allocator);
    defer xfer.deinit();

    try xfer.offer("#zig", "alice", "bob");
    try std.testing.expectEqualStrings("bob", xfer.pendingTo("#zig").?);

    try xfer.offer("#zig", "carol", "dave");
    try std.testing.expectEqualStrings("dave", xfer.pendingTo("#zig").?);
}

test "accept consumes only when the target matches" {
    var xfer = ChannelOwnerXfer.init(std.testing.allocator);
    defer xfer.deinit();

    try xfer.offer("#ops", "root", "next");
    try std.testing.expect(xfer.accept("#ops", "other") == null);
    try std.testing.expectEqualStrings("next", xfer.pendingTo("#ops").?);

    const from = xfer.accept("#ops", "next").?;
    try std.testing.expectEqualStrings("root", from);
    try std.testing.expect(xfer.pendingTo("#ops") == null);
}

test "cancel reports whether an offer existed" {
    var xfer = ChannelOwnerXfer.init(std.testing.allocator);
    defer xfer.deinit();

    try xfer.offer("#team", "one", "two");
    try std.testing.expect(xfer.cancel("#team"));
    try std.testing.expect(!xfer.cancel("#team"));
    try std.testing.expect(xfer.pendingTo("#team") == null);
}


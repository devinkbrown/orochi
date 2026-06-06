const std = @import("std");

pub const ChannelBanAppeal = struct {
    const max_channel_len = 128;
    const max_account_len = 128;
    const max_text_len = 300;
    const max_appeals = 4096;

    pub const Appeal = struct {
        id: u64,
        account: []const u8,
        text: []const u8,
        resolved: bool,
    };

    allocator: std.mem.Allocator,
    records: std.ArrayList(StoredAppeal) = .empty,
    open_cache: std.ArrayList(Appeal) = .empty,
    next_id: u64 = 1,

    const StoredAppeal = struct {
        channel: []u8,
        id: u64,
        account: []u8,
        text: []u8,
        resolved: bool,
    };

    pub fn init(allocator: std.mem.Allocator) ChannelBanAppeal {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *ChannelBanAppeal) void {
        for (self.records.items) |record| {
            self.allocator.free(record.channel);
            self.allocator.free(record.account);
            self.allocator.free(record.text);
        }
        self.records.deinit(self.allocator);
        self.open_cache.deinit(self.allocator);
        self.* = ChannelBanAppeal.init(self.allocator);
    }

    pub fn file(self: *ChannelBanAppeal, channel: []const u8, account: []const u8, text: []const u8) !u64 {
        try validate(channel, max_channel_len, error.EmptyChannel, error.ChannelTooLong);
        try validate(account, max_account_len, error.EmptyAccount, error.AccountTooLong);
        if (text.len == 0) return error.EmptyText;
        if (text.len > max_text_len) return error.TextTooLong;
        if (self.records.items.len >= max_appeals) return error.TooManyAppeals;
        if (self.next_id == std.math.maxInt(u64)) return error.IdSpaceExhausted;

        const channel_copy = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(channel_copy);
        const account_copy = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(account_copy);
        const text_copy = try self.allocator.dupe(u8, text);
        errdefer self.allocator.free(text_copy);

        try self.open_cache.ensureTotalCapacity(self.allocator, self.records.items.len + 1);

        const id = self.next_id;
        self.next_id += 1;
        try self.records.append(self.allocator, .{
            .channel = channel_copy,
            .id = id,
            .account = account_copy,
            .text = text_copy,
            .resolved = false,
        });
        return id;
    }

    pub fn resolve(self: *ChannelBanAppeal, channel: []const u8, id: u64) bool {
        for (self.records.items) |*record| {
            if (record.id == id and std.mem.eql(u8, record.channel, channel)) {
                if (record.resolved) return false;
                record.resolved = true;
                return true;
            }
        }
        return false;
    }

    pub fn open(self: *ChannelBanAppeal, channel: []const u8) []const Appeal {
        self.open_cache.clearRetainingCapacity();
        for (self.records.items) |record| {
            if (record.resolved) continue;
            if (!std.mem.eql(u8, record.channel, channel)) continue;
            self.open_cache.appendAssumeCapacity(.{
                .id = record.id,
                .account = record.account,
                .text = record.text,
                .resolved = false,
            });
        }
        return self.open_cache.items;
    }

    fn validate(value: []const u8, max_len: usize, empty_error: anyerror, long_error: anyerror) !void {
        if (value.len == 0) return empty_error;
        if (value.len > max_len) return long_error;
    }
};

test "file creates open appeals with stable ids" {
    var appeals = ChannelBanAppeal.init(std.testing.allocator);
    defer appeals.deinit();

    const first = try appeals.file("#dev", "alice", "I fixed the issue.");
    const second = try appeals.file("#dev", "bob", "Please review.");
    try std.testing.expectEqual(@as(u64, 1), first);
    try std.testing.expectEqual(@as(u64, 2), second);

    const open_items = appeals.open("#dev");
    try std.testing.expectEqual(@as(usize, 2), open_items.len);
    try std.testing.expectEqualStrings("alice", open_items[0].account);
    try std.testing.expectEqualStrings("Please review.", open_items[1].text);
}

test "resolve hides an appeal from open results" {
    var appeals = ChannelBanAppeal.init(std.testing.allocator);
    defer appeals.deinit();

    const first = try appeals.file("#dev", "alice", "one");
    _ = try appeals.file("#dev", "bob", "two");

    try std.testing.expect(appeals.resolve("#dev", first));
    try std.testing.expect(!appeals.resolve("#dev", first));

    const open_items = appeals.open("#dev");
    try std.testing.expectEqual(@as(usize, 1), open_items.len);
    try std.testing.expectEqualStrings("bob", open_items[0].account);
}

test "open is scoped by channel" {
    var appeals = ChannelBanAppeal.init(std.testing.allocator);
    defer appeals.deinit();

    _ = try appeals.file("#a", "alice", "for a");
    _ = try appeals.file("#b", "bob", "for b");

    const a_items = appeals.open("#a");
    try std.testing.expectEqual(@as(usize, 1), a_items.len);
    try std.testing.expectEqualStrings("for a", a_items[0].text);

    const missing = appeals.open("#missing");
    try std.testing.expectEqual(@as(usize, 0), missing.len);
}

test "text cap is enforced" {
    var appeals = ChannelBanAppeal.init(std.testing.allocator);
    defer appeals.deinit();

    const long = "x" ** 301;
    try std.testing.expectError(error.TextTooLong, appeals.file("#dev", "alice", long));
    try std.testing.expectError(error.EmptyText, appeals.file("#dev", "alice", ""));
}

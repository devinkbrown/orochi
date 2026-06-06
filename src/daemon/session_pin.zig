const std = @import("std");

pub const SessionPin = struct {
    const Entry = struct {
        code: []u8,
        expires_ms: i64,
    };

    allocator: std.mem.Allocator,
    pins: std.StringHashMap(Entry),

    pub fn init(allocator: std.mem.Allocator) SessionPin {
        return .{
            .allocator = allocator,
            .pins = std.StringHashMap(Entry).init(allocator),
        };
    }

    pub fn deinit(self: *SessionPin) void {
        var it = self.pins.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.code);
        }
        self.pins.deinit();
    }

    pub fn issue(self: *SessionPin, account: []const u8, code: []const u8, expires_ms: i64) !void {
        if (self.pins.getPtr(account)) |entry| {
            const owned_code = try self.allocator.dupe(u8, code);
            self.allocator.free(entry.code);
            entry.* = .{
                .code = owned_code,
                .expires_ms = expires_ms,
            };
            return;
        }

        const owned_account = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(owned_account);

        const owned_code = try self.allocator.dupe(u8, code);
        errdefer self.allocator.free(owned_code);

        try self.pins.putNoClobber(owned_account, .{
            .code = owned_code,
            .expires_ms = expires_ms,
        });
    }

    pub fn verify(self: *SessionPin, account: []const u8, code: []const u8, now_ms: i64) bool {
        if (self.pins.fetchRemove(account)) |removed| {
            defer self.allocator.free(removed.key);
            defer self.allocator.free(removed.value.code);

            if (now_ms > removed.value.expires_ms) return false;
            return std.mem.eql(u8, removed.value.code, code);
        }
        return false;
    }

    pub fn pending(self: *SessionPin, account: []const u8, now_ms: i64) bool {
        const entry = self.pins.get(account) orelse return false;
        return now_ms <= entry.expires_ms;
    }
};

test "SessionPin verifies matching code and consumes it" {
    var pins = SessionPin.init(std.testing.allocator);
    defer pins.deinit();

    try pins.issue("alice", "123456", 1_000);
    try std.testing.expect(pins.pending("alice", 999));
    try std.testing.expect(pins.verify("alice", "123456", 1_000));
    try std.testing.expect(!pins.pending("alice", 1_000));
    try std.testing.expect(!pins.verify("alice", "123456", 1_000));
}

test "SessionPin rejects mismatch and still consumes challenge" {
    var pins = SessionPin.init(std.testing.allocator);
    defer pins.deinit();

    try pins.issue("bob", "111111", 500);
    try std.testing.expect(!pins.verify("bob", "222222", 100));
    try std.testing.expect(!pins.pending("bob", 100));
}

test "SessionPin rejects expired code" {
    var pins = SessionPin.init(std.testing.allocator);
    defer pins.deinit();

    try pins.issue("carol", "777777", 99);
    try std.testing.expect(!pins.pending("carol", 100));
    try std.testing.expect(!pins.verify("carol", "777777", 100));
}

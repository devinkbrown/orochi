//! Registered-channel expiry policy for Mizuchi services.
//!
//! This module is intentionally standalone: it models service-owned channel
//! registration metadata and expiry decisions without importing daemon or proto
//! code. Services remain real server commands and numerics; nothing here models
//! service pseudo-clients.
const std = @import("std");

pub const record_version = "CX1";
pub const max_channel_bytes: usize = 200;
pub const default_noexpire_mask: u32 = 1 << 0;

pub const ParseError = error{
    EmptyRecord,
    UnsupportedVersion,
    MissingField,
    TrailingField,
    InvalidChannel,
    InvalidLastUsed,
    InvalidFlags,
};

pub const FormatError = error{
    OutputTooSmall,
    InvalidChannel,
};

pub const IndexError = std.mem.Allocator.Error || error{InvalidChannel};

/// Borrowed registered-channel expiry metadata.
pub const RegisteredChannel = struct {
    channel: []const u8,
    last_used_ms: u64,
    flags: u32 = 0,

    pub fn noexpire(self: RegisteredChannel, mask: u32) bool {
        return mask != 0 and (self.flags & mask) != 0;
    }
};

/// Complete decision input for an expiry check.
pub const ExpiryPolicy = struct {
    now_ms: u64,
    inactivity_threshold_ms: u64,
    noexpire_mask: u32 = default_noexpire_mask,
};

/// True when a registered channel should be expired by `policy`.
pub fn isExpired(channel: RegisteredChannel, policy: ExpiryPolicy) bool {
    if (channel.noexpire(policy.noexpire_mask)) return false;
    if (channel.last_used_ms > policy.now_ms) return false;
    return policy.now_ms - channel.last_used_ms >= policy.inactivity_threshold_ms;
}

/// Parse the sidecar format `CX1|<channel>|<last_used_ms>|<flags>`.
///
/// The returned slices borrow from `line`.
pub fn parseRecord(line: []const u8) ParseError!RegisteredChannel {
    if (line.len == 0) return error.EmptyRecord;

    var it = std.mem.splitScalar(u8, line, '|');
    const version = it.next() orelse return error.MissingField;
    if (!std.mem.eql(u8, version, record_version)) return error.UnsupportedVersion;

    const channel = it.next() orelse return error.MissingField;
    if (!validChannelName(channel)) return error.InvalidChannel;

    const last_used_text = it.next() orelse return error.MissingField;
    const last_used_ms = std.fmt.parseInt(u64, last_used_text, 10) catch return error.InvalidLastUsed;

    const flags_text = it.next() orelse return error.MissingField;
    const flags = std.fmt.parseInt(u32, flags_text, 10) catch return error.InvalidFlags;

    if (it.next() != null) return error.TrailingField;
    return .{ .channel = channel, .last_used_ms = last_used_ms, .flags = flags };
}

/// Format the sidecar record into caller-owned storage.
pub fn formatRecord(out: []u8, channel: RegisteredChannel) FormatError![]const u8 {
    if (!validChannelName(channel.channel)) return error.InvalidChannel;
    return std.fmt.bufPrint(
        out,
        "{s}|{s}|{}|{}",
        .{ record_version, channel.channel, channel.last_used_ms, channel.flags },
    ) catch error.OutputTooSmall;
}

/// Collect borrowed channel names that are expired under `policy`.
///
/// The returned slice is owned by `allocator`; each element points at the input
/// records and must not be freed individually.
pub fn collectExpired(
    allocator: std.mem.Allocator,
    records: []const RegisteredChannel,
    policy: ExpiryPolicy,
) std.mem.Allocator.Error![][]const u8 {
    var expired: std.ArrayList([]const u8) = .empty;
    errdefer expired.deinit(allocator);

    for (records) |record| {
        if (isExpired(record, policy)) try expired.append(allocator, record.channel);
    }

    return expired.toOwnedSlice(allocator);
}

const StoredChannel = struct {
    channel: []u8,
    last_used_ms: u64,
    flags: u32,

    fn view(self: StoredChannel) RegisteredChannel {
        return .{
            .channel = self.channel,
            .last_used_ms = self.last_used_ms,
            .flags = self.flags,
        };
    }
};

/// Owning in-memory index for registered-channel expiry metadata.
///
/// It is deliberately small and linear: channel registration counts are service
/// state, not hot message-path state, and a simple structure keeps ownership and
/// standalone testing obvious.
pub const ExpiryIndex = struct {
    allocator: std.mem.Allocator,
    items: std.ArrayList(StoredChannel) = .empty,

    pub fn init(allocator: std.mem.Allocator) ExpiryIndex {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *ExpiryIndex) void {
        for (self.items.items) |item| self.allocator.free(item.channel);
        self.items.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn count(self: *const ExpiryIndex) usize {
        return self.items.items.len;
    }

    pub fn get(self: *const ExpiryIndex, channel: []const u8) ?RegisteredChannel {
        const index = self.findIndex(channel) orelse return null;
        return self.items.items[index].view();
    }

    /// Insert or replace the complete expiry metadata for a registered channel.
    pub fn put(self: *ExpiryIndex, record: RegisteredChannel) IndexError!void {
        if (!validChannelName(record.channel)) return error.InvalidChannel;

        if (self.findIndex(record.channel)) |index| {
            self.items.items[index].last_used_ms = record.last_used_ms;
            self.items.items[index].flags = record.flags;
            return;
        }

        const owned = try self.allocator.dupe(u8, record.channel);
        errdefer self.allocator.free(owned);
        try self.items.append(self.allocator, .{
            .channel = owned,
            .last_used_ms = record.last_used_ms,
            .flags = record.flags,
        });
    }

    /// Record channel activity. Missing channels are added as registered
    /// channels without any flags; existing flags are preserved.
    pub fn touch(self: *ExpiryIndex, channel: []const u8, now_ms: u64) IndexError!void {
        if (!validChannelName(channel)) return error.InvalidChannel;

        if (self.findIndex(channel)) |index| {
            self.items.items[index].last_used_ms = now_ms;
            return;
        }

        try self.put(.{ .channel = channel, .last_used_ms = now_ms });
    }

    pub fn setNoExpire(self: *ExpiryIndex, channel: []const u8, enabled: bool, mask: u32) IndexError!void {
        if (!validChannelName(channel)) return error.InvalidChannel;
        if (mask == 0) return;

        if (self.findIndex(channel)) |index| {
            if (enabled) {
                self.items.items[index].flags |= mask;
            } else {
                self.items.items[index].flags &= ~mask;
            }
            return;
        }

        try self.put(.{
            .channel = channel,
            .last_used_ms = 0,
            .flags = if (enabled) mask else 0,
        });
    }

    pub fn remove(self: *ExpiryIndex, channel: []const u8) bool {
        const index = self.findIndex(channel) orelse return false;
        const item = self.items.orderedRemove(index);
        self.allocator.free(item.channel);
        return true;
    }

    /// Remove expired channels and return their owned names.
    ///
    /// The caller owns the returned slice and each name inside it.
    pub fn sweepExpired(self: *ExpiryIndex, result_allocator: std.mem.Allocator, policy: ExpiryPolicy) std.mem.Allocator.Error![][]u8 {
        var expired: std.ArrayList([]u8) = .empty;
        errdefer {
            for (expired.items) |name| self.allocator.free(name);
            expired.deinit(result_allocator);
        }

        var i: usize = 0;
        while (i < self.items.items.len) {
            if (isExpired(self.items.items[i].view(), policy)) {
                try expired.append(result_allocator, self.items.items[i].channel);
                _ = self.items.orderedRemove(i);
            } else {
                i += 1;
            }
        }

        return expired.toOwnedSlice(result_allocator);
    }

    fn findIndex(self: *const ExpiryIndex, channel: []const u8) ?usize {
        for (self.items.items, 0..) |item, index| {
            if (std.ascii.eqlIgnoreCase(item.channel, channel)) return index;
        }
        return null;
    }
};

pub fn validChannelName(channel: []const u8) bool {
    if (channel.len < 2 or channel.len > max_channel_bytes) return false;
    switch (channel[0]) {
        '#', '&', '+', '!' => {},
        else => return false,
    }

    for (channel[1..]) |ch| {
        switch (ch) {
            0, 1...31, 127, ' ', ',', ':' => return false,
            else => {},
        }
    }

    return true;
}

test "parse sidecar record borrows fields" {
    const record = try parseRecord("CX1|#mizuchi|123456|1");
    try std.testing.expectEqualStrings("#mizuchi", record.channel);
    try std.testing.expectEqual(@as(u64, 123456), record.last_used_ms);
    try std.testing.expectEqual(@as(u32, 1), record.flags);
    try std.testing.expect(record.noexpire(default_noexpire_mask));
}

test "parse rejects malformed records" {
    try std.testing.expectError(error.EmptyRecord, parseRecord(""));
    try std.testing.expectError(error.UnsupportedVersion, parseRecord("C1|#mizuchi|10|0"));
    try std.testing.expectError(error.MissingField, parseRecord("CX1|#mizuchi|10"));
    try std.testing.expectError(error.InvalidChannel, parseRecord("CX1|mizuchi|10|0"));
    try std.testing.expectError(error.InvalidLastUsed, parseRecord("CX1|#mizuchi|soon|0"));
    try std.testing.expectError(error.InvalidFlags, parseRecord("CX1|#mizuchi|10|no"));
    try std.testing.expectError(error.TrailingField, parseRecord("CX1|#mizuchi|10|0|extra"));
}

test "format sidecar record and parse round trip" {
    var buf: [64]u8 = undefined;
    const line = try formatRecord(&buf, .{
        .channel = "#ops",
        .last_used_ms = 987,
        .flags = default_noexpire_mask,
    });
    try std.testing.expectEqualStrings("CX1|#ops|987|1", line);

    const parsed = try parseRecord(line);
    try std.testing.expectEqualStrings("#ops", parsed.channel);
    try std.testing.expectEqual(@as(u64, 987), parsed.last_used_ms);
    try std.testing.expect(parsed.noexpire(default_noexpire_mask));
}

test "format rejects invalid channel and small buffers" {
    var small: [4]u8 = undefined;
    try std.testing.expectError(error.InvalidChannel, formatRecord(&small, .{ .channel = "ops", .last_used_ms = 1 }));
    try std.testing.expectError(error.OutputTooSmall, formatRecord(&small, .{ .channel = "#ops", .last_used_ms = 1 }));
}

test "validChannelName enforces standalone IRC-safe basics" {
    try std.testing.expect(validChannelName("#mizuchi"));
    try std.testing.expect(validChannelName("&local"));
    try std.testing.expect(validChannelName("+modeless"));
    try std.testing.expect(validChannelName("!safe"));
    try std.testing.expect(!validChannelName("#"));
    try std.testing.expect(!validChannelName("mizuchi"));
    try std.testing.expect(!validChannelName("#bad name"));
    try std.testing.expect(!validChannelName("#bad,chan"));
    try std.testing.expect(!validChannelName("#bad:chan"));
    try std.testing.expect(!validChannelName("#bad\nchan"));
}

test "isExpired observes threshold boundary and now before last_used" {
    const policy = ExpiryPolicy{ .now_ms = 1_500, .inactivity_threshold_ms = 500 };
    try std.testing.expect(isExpired(.{ .channel = "#old", .last_used_ms = 1_000 }, policy));
    try std.testing.expect(!isExpired(.{ .channel = "#fresh", .last_used_ms = 1_001 }, policy));
    try std.testing.expect(!isExpired(.{ .channel = "#future", .last_used_ms = 2_000 }, policy));
}

test "isExpired skips channels with noexpire flag" {
    const policy = ExpiryPolicy{ .now_ms = 10_000, .inactivity_threshold_ms = 1_000 };
    try std.testing.expect(!isExpired(.{
        .channel = "#keep",
        .last_used_ms = 0,
        .flags = default_noexpire_mask,
    }, policy));
}

test "zero threshold expires anything not protected at or before now" {
    const policy = ExpiryPolicy{ .now_ms = 10, .inactivity_threshold_ms = 0 };
    try std.testing.expect(isExpired(.{ .channel = "#now", .last_used_ms = 10 }, policy));
    try std.testing.expect(!isExpired(.{ .channel = "#later", .last_used_ms = 11 }, policy));
}

test "collectExpired returns borrowed names in input order" {
    const records = [_]RegisteredChannel{
        .{ .channel = "#old", .last_used_ms = 10 },
        .{ .channel = "#keep", .last_used_ms = 0, .flags = default_noexpire_mask },
        .{ .channel = "#fresh", .last_used_ms = 90 },
        .{ .channel = "#older", .last_used_ms = 1 },
    };

    const expired = try collectExpired(std.testing.allocator, &records, .{
        .now_ms = 100,
        .inactivity_threshold_ms = 90,
    });
    defer std.testing.allocator.free(expired);

    try std.testing.expectEqual(@as(usize, 2), expired.len);
    try std.testing.expectEqualStrings("#old", expired[0]);
    try std.testing.expectEqualStrings("#older", expired[1]);
}

test "ExpiryIndex tracks activity and preserves flags on touch" {
    var index = ExpiryIndex.init(std.testing.allocator);
    defer index.deinit();

    try index.put(.{ .channel = "#mizuchi", .last_used_ms = 10, .flags = default_noexpire_mask });
    try index.touch("#Mizuchi", 20);

    const record = index.get("#mizuchi") orelse return error.TestUnexpectedNull;
    try std.testing.expectEqual(@as(usize, 1), index.count());
    try std.testing.expectEqual(@as(u64, 20), record.last_used_ms);
    try std.testing.expect(record.noexpire(default_noexpire_mask));
}

test "ExpiryIndex setNoExpire can create and clear protected records" {
    var index = ExpiryIndex.init(std.testing.allocator);
    defer index.deinit();

    try index.setNoExpire("#ops", true, default_noexpire_mask);
    var record = index.get("#ops") orelse return error.TestUnexpectedNull;
    try std.testing.expect(record.noexpire(default_noexpire_mask));
    try std.testing.expectEqual(@as(u64, 0), record.last_used_ms);

    try index.setNoExpire("#OPS", false, default_noexpire_mask);
    record = index.get("#ops") orelse return error.TestUnexpectedNull;
    try std.testing.expect(!record.noexpire(default_noexpire_mask));
}

test "ExpiryIndex rejects invalid channels" {
    var index = ExpiryIndex.init(std.testing.allocator);
    defer index.deinit();

    try std.testing.expectError(error.InvalidChannel, index.put(.{ .channel = "ops", .last_used_ms = 1 }));
    try std.testing.expectError(error.InvalidChannel, index.touch("#bad name", 1));
    try std.testing.expectError(error.InvalidChannel, index.setNoExpire("", true, default_noexpire_mask));
}

test "ExpiryIndex sweep removes expired and returns owned names" {
    var index = ExpiryIndex.init(std.testing.allocator);
    defer index.deinit();

    try index.put(.{ .channel = "#old", .last_used_ms = 10 });
    try index.put(.{ .channel = "#keep", .last_used_ms = 0, .flags = default_noexpire_mask });
    try index.put(.{ .channel = "#fresh", .last_used_ms = 95 });
    try index.put(.{ .channel = "#older", .last_used_ms = 1 });

    const expired = try index.sweepExpired(std.testing.allocator, .{
        .now_ms = 100,
        .inactivity_threshold_ms = 90,
    });
    defer {
        for (expired) |name| std.testing.allocator.free(name);
        std.testing.allocator.free(expired);
    }

    try std.testing.expectEqual(@as(usize, 2), expired.len);
    try std.testing.expectEqualStrings("#old", expired[0]);
    try std.testing.expectEqualStrings("#older", expired[1]);
    try std.testing.expectEqual(@as(usize, 2), index.count());
    try std.testing.expect(index.get("#keep") != null);
    try std.testing.expect(index.get("#fresh") != null);
    try std.testing.expect(index.get("#old") == null);
}

test "ExpiryIndex remove frees records and reports misses" {
    var index = ExpiryIndex.init(std.testing.allocator);
    defer index.deinit();

    try index.touch("#one", 1);
    try index.touch("#two", 2);

    try std.testing.expect(index.remove("#ONE"));
    try std.testing.expect(!index.remove("#missing"));
    try std.testing.expectEqual(@as(usize, 1), index.count());
    try std.testing.expect(index.get("#two") != null);
}

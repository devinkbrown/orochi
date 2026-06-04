//! Pure in-memory store for server operator ban lines.
//!
//! This module owns all entry strings and performs no I/O. D-line matching
//! supports exact/glob masks plus IPv4 CIDR masks when both sides parse as
//! dotted IPv4 addresses.
const std = @import("std");
const root = @import("root");

pub const Kind = enum {
    kline,
    dline,
    xline,
    resv,
};

pub const Params = struct {
    max_entries_per_kind: usize = 256,
    max_mask: usize = 256,
    max_reason: usize = 512,
};

pub const BanDbError = error{
    EmptyMask,
    MaskTooLong,
    ReasonTooLong,
    TooManyEntries,
};

pub const Entry = struct {
    kind: Kind,
    mask: []const u8,
    reason: []const u8,
    set_by: []const u8,
    set_at: i64,
    duration_secs: u32,
};

pub const Store = struct {
    allocator: std.mem.Allocator,
    params: Params,
    entries: std.ArrayList(Entry) = .empty,

    pub fn init(allocator: std.mem.Allocator, params: Params) Store {
        return .{
            .allocator = allocator,
            .params = params,
        };
    }

    pub fn deinit(self: *Store) void {
        for (self.entries.items) |*entry| {
            deinitEntry(self.allocator, entry);
        }
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn add(self: *Store, entry: Entry) (BanDbError || std.mem.Allocator.Error)!void {
        try self.validate(entry);

        var owned = try self.cloneEntry(entry);
        errdefer deinitEntry(self.allocator, &owned);

        if (self.indexOf(entry.kind, entry.mask)) |idx| {
            deinitEntry(self.allocator, &self.entries.items[idx]);
            self.entries.items[idx] = owned;
            return;
        }

        if (self.countKind(entry.kind) >= self.params.max_entries_per_kind) {
            return error.TooManyEntries;
        }
        try self.entries.append(self.allocator, owned);
    }

    pub fn remove(self: *Store, kind: Kind, mask: []const u8) bool {
        const idx = self.indexOf(kind, mask) orelse return false;
        var removed = self.entries.orderedRemove(idx);
        deinitEntry(self.allocator, &removed);
        return true;
    }

    pub fn find(self: *Store, kind: Kind, target: []const u8, now: i64) ?*const Entry {
        self.pruneExpiredKind(kind, now);
        for (self.entries.items) |*entry| {
            if (entry.kind != kind) continue;
            if (matches(kind, entry.mask, target)) {
                return entry;
            }
        }
        return null;
    }

    pub fn list(self: *const Store, kind: Kind, out: []Entry) []const Entry {
        var count: usize = 0;
        for (self.entries.items) |*entry| {
            if (entry.kind != kind) continue;
            if (count == out.len) break;
            out[count] = entry.*;
            count += 1;
        }
        return out[0..count];
    }

    pub fn len(self: *const Store, kind: Kind) usize {
        return self.countKind(kind);
    }

    pub fn pruneExpired(self: *Store, now: i64) void {
        var idx: usize = 0;
        while (idx < self.entries.items.len) {
            if (isExpired(self.entries.items[idx].set_at, self.entries.items[idx].duration_secs, now)) {
                var removed = self.entries.orderedRemove(idx);
                deinitEntry(self.allocator, &removed);
            } else {
                idx += 1;
            }
        }
    }

    fn validate(self: *const Store, entry: Entry) BanDbError!void {
        if (entry.mask.len == 0) return error.EmptyMask;
        if (entry.mask.len > self.params.max_mask) return error.MaskTooLong;
        if (entry.reason.len > self.params.max_reason) return error.ReasonTooLong;
    }

    fn cloneEntry(self: *Store, entry: Entry) std.mem.Allocator.Error!Entry {
        const mask = try self.allocator.dupe(u8, entry.mask);
        errdefer self.allocator.free(mask);
        const reason = try self.allocator.dupe(u8, entry.reason);
        errdefer self.allocator.free(reason);
        const set_by = try self.allocator.dupe(u8, entry.set_by);
        errdefer self.allocator.free(set_by);
        return .{
            .kind = entry.kind,
            .mask = mask,
            .reason = reason,
            .set_by = set_by,
            .set_at = entry.set_at,
            .duration_secs = entry.duration_secs,
        };
    }

    fn indexOf(self: *const Store, kind: Kind, mask: []const u8) ?usize {
        for (self.entries.items, 0..) |entry, idx| {
            if (entry.kind == kind and std.mem.eql(u8, entry.mask, mask)) return idx;
        }
        return null;
    }

    fn countKind(self: *const Store, kind: Kind) usize {
        var count: usize = 0;
        for (self.entries.items) |entry| {
            if (entry.kind == kind) count += 1;
        }
        return count;
    }

    fn pruneExpiredKind(self: *Store, kind: Kind, now: i64) void {
        var idx: usize = 0;
        while (idx < self.entries.items.len) {
            const entry = self.entries.items[idx];
            if (entry.kind == kind and isExpired(entry.set_at, entry.duration_secs, now)) {
                var removed = self.entries.orderedRemove(idx);
                deinitEntry(self.allocator, &removed);
            } else {
                idx += 1;
            }
        }
    }
};

fn deinitEntry(allocator: std.mem.Allocator, entry: *Entry) void {
    allocator.free(entry.mask);
    allocator.free(entry.reason);
    allocator.free(entry.set_by);
    entry.* = undefined;
}

pub fn add(store: *Store, entry: Entry) (BanDbError || std.mem.Allocator.Error)!void {
    return store.add(entry);
}

pub fn remove(store: *Store, kind: Kind, mask: []const u8) bool {
    return store.remove(kind, mask);
}

pub fn find(store: *Store, kind: Kind, target: []const u8, now: i64) ?*const Entry {
    return store.find(kind, target, now);
}

pub fn list(store: *const Store, kind: Kind, out: []Entry) []const Entry {
    return store.list(kind, out);
}

pub fn matches(kind: Kind, mask: []const u8, target: []const u8) bool {
    return switch (kind) {
        .dline => dlineMatches(mask, target),
        .kline, .xline, .resv => globMatch(mask, target),
    };
}

fn isExpired(set_at: i64, duration_secs: u32, now: i64) bool {
    if (duration_secs == 0) return false;
    const duration: i64 = duration_secs;
    if (set_at > std.math.maxInt(i64) - duration) return false;
    return set_at + duration < now;
}

fn dlineMatches(mask: []const u8, target: []const u8) bool {
    if (parseCidr(mask)) |cidr| {
        if (parseIpv4(target)) |addr| {
            return cidr.contains(addr);
        }
    }
    return globMatch(mask, target);
}

fn globMatch(mask: []const u8, text: []const u8) bool {
    if (@hasDecl(root, "proto")) {
        return root.proto.listx.globMatch(mask, text);
    }
    return localGlobMatch(mask, text);
}

fn localGlobMatch(mask: []const u8, text: []const u8) bool {
    var mask_i: usize = 0;
    var text_i: usize = 0;
    var star_i: ?usize = null;
    var retry_text_i: usize = 0;

    while (text_i < text.len) {
        if (mask_i < mask.len and (mask[mask_i] == '?' or asciiEqual(mask[mask_i], text[text_i]))) {
            mask_i += 1;
            text_i += 1;
        } else if (mask_i < mask.len and mask[mask_i] == '*') {
            star_i = mask_i;
            mask_i += 1;
            retry_text_i = text_i;
        } else if (star_i) |star| {
            mask_i = star + 1;
            retry_text_i += 1;
            text_i = retry_text_i;
        } else {
            return false;
        }
    }

    while (mask_i < mask.len and mask[mask_i] == '*') {
        mask_i += 1;
    }

    return mask_i == mask.len;
}

fn asciiEqual(a: u8, b: u8) bool {
    return std.ascii.toLower(a) == std.ascii.toLower(b);
}

const Ipv4Cidr = struct {
    addr: u32,
    prefix_bits: u6,

    fn contains(self: Ipv4Cidr, addr: u32) bool {
        if (self.prefix_bits == 0) return true;
        const shift: u5 = @intCast(32 - self.prefix_bits);
        const all_bits: u32 = std.math.maxInt(u32);
        const mask: u32 = all_bits << shift;
        return (self.addr & mask) == (addr & mask);
    }
};

fn parseCidr(bytes: []const u8) ?Ipv4Cidr {
    const slash = std.mem.indexOfScalar(u8, bytes, '/') orelse return null;
    if (std.mem.indexOfScalar(u8, bytes[slash + 1 ..], '/') != null) return null;
    const addr = parseIpv4(bytes[0..slash]) orelse return null;
    const prefix_int = std.fmt.parseInt(u8, bytes[slash + 1 ..], 10) catch return null;
    if (prefix_int > 32) return null;
    return .{
        .addr = addr,
        .prefix_bits = @intCast(prefix_int),
    };
}

fn parseIpv4(bytes: []const u8) ?u32 {
    var parts: [4]u8 = undefined;
    var part_count: usize = 0;
    var start: usize = 0;

    while (start <= bytes.len) {
        if (part_count == parts.len) return null;
        const end = std.mem.indexOfScalarPos(u8, bytes, start, '.') orelse bytes.len;
        if (end == start) return null;
        parts[part_count] = std.fmt.parseInt(u8, bytes[start..end], 10) catch return null;
        part_count += 1;
        if (end == bytes.len) break;
        start = end + 1;
    }

    if (part_count != parts.len) return null;
    return (@as(u32, parts[0]) << 24) |
        (@as(u32, parts[1]) << 16) |
        (@as(u32, parts[2]) << 8) |
        @as(u32, parts[3]);
}

fn testEntry(kind: Kind, mask: []const u8) Entry {
    return .{
        .kind = kind,
        .mask = mask,
        .reason = "test reason",
        .set_by = "oper",
        .set_at = 100,
        .duration_secs = 0,
    };
}

test "add find remove" {
    var store = Store.init(std.testing.allocator, .{});
    defer store.deinit();

    try store.add(testEntry(.kline, "*@bad.example"));
    const found = store.find(.kline, "user@bad.example", 100).?;
    try std.testing.expectEqual(.kline, found.kind);
    try std.testing.expectEqualStrings("*@bad.example", found.mask);
    try std.testing.expectEqualStrings("test reason", found.reason);
    try std.testing.expectEqualStrings("oper", found.set_by);

    try std.testing.expect(store.remove(.kline, "*@bad.example"));
    try std.testing.expect(store.find(.kline, "user@bad.example", 100) == null);
    try std.testing.expect(!store.remove(.kline, "*@bad.example"));
}

test "glob match is case-insensitive" {
    var store = Store.init(std.testing.allocator, .{});
    defer store.deinit();

    try store.add(testEntry(.xline, "Bad * User"));
    try std.testing.expect(store.find(.xline, "bad Real user", 100) != null);
    try std.testing.expect(store.find(.xline, "good real user", 100) == null);

    try store.add(testEntry(.resv, "#Team-*"));
    try std.testing.expect(store.find(.resv, "#team-OPS", 100) != null);
}

test "dline matches ipv4 cidr and glob fallback" {
    var store = Store.init(std.testing.allocator, .{});
    defer store.deinit();

    try store.add(testEntry(.dline, "192.0.2.0/24"));
    try store.add(testEntry(.dline, "10.0.*"));

    try std.testing.expect(store.find(.dline, "192.0.2.44", 100) != null);
    try std.testing.expect(store.find(.dline, "192.0.3.44", 100) == null);
    try std.testing.expect(store.find(.dline, "10.0.9.1", 100) != null);
}

test "expiry pruning" {
    var store = Store.init(std.testing.allocator, .{});
    defer store.deinit();

    try store.add(.{
        .kind = .kline,
        .mask = "*@short.example",
        .reason = "short",
        .set_by = "oper",
        .set_at = 10,
        .duration_secs = 5,
    });

    try std.testing.expect(store.find(.kline, "u@short.example", 15) != null);
    try std.testing.expect(store.find(.kline, "u@short.example", 16) == null);
    try std.testing.expectEqual(@as(usize, 0), store.len(.kline));
}

test "list ordering" {
    var store = Store.init(std.testing.allocator, .{});
    defer store.deinit();

    try store.add(testEntry(.resv, "#a"));
    try store.add(testEntry(.kline, "*@elsewhere"));
    try store.add(testEntry(.resv, "#b"));
    try store.add(testEntry(.resv, "#c"));

    var out: [4]Entry = undefined;
    const entries = store.list(.resv, &out);
    try std.testing.expectEqual(@as(usize, 3), entries.len);
    try std.testing.expectEqualStrings("#a", entries[0].mask);
    try std.testing.expectEqualStrings("#b", entries[1].mask);
    try std.testing.expectEqualStrings("#c", entries[2].mask);
}

test "bounds and duplicate replacement" {
    var store = Store.init(std.testing.allocator, .{
        .max_entries_per_kind = 1,
        .max_mask = 8,
        .max_reason = 8,
    });
    defer store.deinit();

    try std.testing.expectError(error.EmptyMask, store.add(testEntry(.kline, "")));
    try std.testing.expectError(error.MaskTooLong, store.add(testEntry(.kline, "too-long-mask")));
    try std.testing.expectError(error.ReasonTooLong, store.add(.{
        .kind = .kline,
        .mask = "*@a",
        .reason = "too long reason",
        .set_by = "oper",
        .set_at = 0,
        .duration_secs = 0,
    }));

    try store.add(.{
        .kind = .kline,
        .mask = "*@a",
        .reason = "initial",
        .set_by = "oper",
        .set_at = 100,
        .duration_secs = 0,
    });
    try store.add(.{
        .kind = .kline,
        .mask = "*@a",
        .reason = "changed",
        .set_by = "oper2",
        .set_at = 200,
        .duration_secs = 0,
    });
    try std.testing.expectEqual(@as(usize, 1), store.len(.kline));
    try std.testing.expectEqualStrings("changed", store.find(.kline, "u@a", 200).?.reason);
    try std.testing.expectError(error.TooManyEntries, store.add(.{
        .kind = .kline,
        .mask = "*@b",
        .reason = "second",
        .set_by = "oper",
        .set_at = 100,
        .duration_secs = 0,
    }));
}

test "no leak fill expire deinit" {
    var store = Store.init(std.testing.allocator, .{ .max_entries_per_kind = 64 });
    defer store.deinit();

    for (0..32) |idx| {
        var mask_buf: [32]u8 = undefined;
        const mask = try std.fmt.bufPrint(&mask_buf, "*@host{d}.example", .{idx});
        try store.add(.{
            .kind = .kline,
            .mask = mask,
            .reason = "temporary",
            .set_by = "oper",
            .set_at = @intCast(idx),
            .duration_secs = 1,
        });
    }

    try std.testing.expectEqual(@as(usize, 32), store.len(.kline));
    store.pruneExpired(100);
    try std.testing.expectEqual(@as(usize, 0), store.len(.kline));

    for (0..8) |idx| {
        var mask_buf: [32]u8 = undefined;
        const mask = try std.fmt.bufPrint(&mask_buf, "#reserved-{d}", .{idx});
        try store.add(testEntry(.resv, mask));
    }
}

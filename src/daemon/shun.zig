// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Network-wide silent mute policy.
//!
//! A shunned user remains connected, but message paths can ask this pure store
//! whether the user's nick!user@host mask should be silently dropped.

const std = @import("std");

/// A single network-wide silent mute entry.
pub const Shun = struct {
    mask: []const u8,
    reason: []const u8,
    set_by: []const u8,
    created_ms: i64,
    /// Absolute expiry in epoch milliseconds; 0 means permanent.
    expires_ms: i64 = 0,

    /// Return whether this entry has expired at `now_ms`.
    pub fn isExpired(self: Shun, now_ms: i64) bool {
        return self.expires_ms != 0 and self.expires_ms <= now_ms;
    }
};

/// Storage and validation limits for a `ShunList`.
pub const Params = struct {
    max_shuns: usize = 1024,
    max_mask: usize = 256,
    max_reason: usize = 512,
    max_setter: usize = 64,
};

/// Errors returned while validating or storing shun entries.
pub const ShunError = error{
    EmptyMask,
    MaskTooLong,
    ReasonTooLong,
    SetterTooLong,
    TooManyShuns,
};

/// Owning registry for network-wide silent mutes.
pub const ShunList = struct {
    allocator: std.mem.Allocator,
    params: Params,
    shuns: std.ArrayListUnmanaged(Shun) = .empty,

    /// Initialize an empty list with the supplied allocator and limits.
    pub fn init(allocator: std.mem.Allocator, params: Params) ShunList {
        return .{ .allocator = allocator, .params = params };
    }

    /// Free all owned strings and backing storage.
    pub fn deinit(self: *ShunList) void {
        for (self.shuns.items) |*shun| freeShun(self.allocator, shun);
        self.shuns.deinit(self.allocator);
        self.* = undefined;
    }

    /// Add a shun, duplicating its strings. An existing entry with the same
    /// mask is replaced in place.
    pub fn add(self: *ShunList, shun: Shun) (ShunError || std.mem.Allocator.Error)!void {
        try self.validate(shun);

        var owned = try self.clone(shun);
        errdefer freeShun(self.allocator, &owned);

        if (self.indexOf(shun.mask)) |idx| {
            freeShun(self.allocator, &self.shuns.items[idx]);
            self.shuns.items[idx] = owned;
            return;
        }

        if (self.shuns.items.len >= self.params.max_shuns) return error.TooManyShuns;
        try self.shuns.append(self.allocator, owned);
    }

    /// Remove a shun by exact mask. Returns true when an entry was present.
    pub fn remove(self: *ShunList, mask: []const u8) bool {
        const idx = self.indexOf(mask) orelse return false;
        var removed = self.shuns.orderedRemove(idx);
        freeShun(self.allocator, &removed);
        return true;
    }

    /// Return whether `hostmask` matches any active shun. Expired entries are
    /// pruned as a side effect.
    pub fn isShunned(self: *ShunList, hostmask: []const u8, now_ms: i64) bool {
        self.pruneExpired(now_ms);
        for (self.shuns.items) |shun| {
            if (globMatch(shun.mask, hostmask)) return true;
        }
        return false;
    }

    /// Copy stored shuns into `out` and return the filled prefix. Returned
    /// entries borrow owned strings from the list.
    pub fn list(self: *const ShunList, out: []Shun) []Shun {
        const n = @min(out.len, self.shuns.items.len);
        @memcpy(out[0..n], self.shuns.items[0..n]);
        return out[0..n];
    }

    /// Return the number of stored shuns.
    pub fn count(self: *const ShunList) usize {
        return self.shuns.items.len;
    }

    /// Remove every entry whose expiry is at or before `now_ms`.
    pub fn pruneExpired(self: *ShunList, now_ms: i64) void {
        var i: usize = 0;
        while (i < self.shuns.items.len) {
            if (self.shuns.items[i].isExpired(now_ms)) {
                var removed = self.shuns.orderedRemove(i);
                freeShun(self.allocator, &removed);
            } else {
                i += 1;
            }
        }
    }

    fn validate(self: *const ShunList, shun: Shun) ShunError!void {
        if (shun.mask.len == 0) return error.EmptyMask;
        if (shun.mask.len > self.params.max_mask) return error.MaskTooLong;
        if (shun.reason.len > self.params.max_reason) return error.ReasonTooLong;
        if (shun.set_by.len > self.params.max_setter) return error.SetterTooLong;
    }

    fn clone(self: *ShunList, shun: Shun) std.mem.Allocator.Error!Shun {
        const mask = try self.allocator.dupe(u8, shun.mask);
        errdefer self.allocator.free(mask);
        const reason = try self.allocator.dupe(u8, shun.reason);
        errdefer self.allocator.free(reason);
        const set_by = try self.allocator.dupe(u8, shun.set_by);
        return .{
            .mask = mask,
            .reason = reason,
            .set_by = set_by,
            .created_ms = shun.created_ms,
            .expires_ms = shun.expires_ms,
        };
    }

    fn indexOf(self: *const ShunList, mask: []const u8) ?usize {
        for (self.shuns.items, 0..) |shun, idx| {
            if (std.mem.eql(u8, shun.mask, mask)) return idx;
        }
        return null;
    }
};

fn freeShun(allocator: std.mem.Allocator, shun: *Shun) void {
    allocator.free(shun.mask);
    allocator.free(shun.reason);
    allocator.free(shun.set_by);
    shun.* = undefined;
}

fn globMatch(pattern: []const u8, text: []const u8) bool {
    var p: usize = 0;
    var t: usize = 0;
    var star: ?usize = null;
    var mark: usize = 0;

    while (t < text.len) {
        if (p < pattern.len and (pattern[p] == '?' or eqlFold(pattern[p], text[t]))) {
            p += 1;
            t += 1;
        } else if (p < pattern.len and pattern[p] == '*') {
            star = p;
            mark = t;
            p += 1;
        } else if (star) |s| {
            p = s + 1;
            mark += 1;
            t = mark;
        } else {
            return false;
        }
    }

    while (p < pattern.len and pattern[p] == '*') p += 1;
    return p == pattern.len;
}

fn eqlFold(a: u8, b: u8) bool {
    return std.ascii.toLower(a) == std.ascii.toLower(b);
}

fn mkShun(mask: []const u8) Shun {
    return .{
        .mask = mask,
        .reason = "quiet",
        .set_by = "oper",
        .created_ms = 100,
        .expires_ms = 0,
    };
}

const testing = std.testing;

test "add remove and list preserve owned shun data" {
    // Arrange.
    var shuns = ShunList.init(testing.allocator, .{});
    defer shuns.deinit();

    // Act.
    try shuns.add(mkShun("*!*@bad.example"));
    try shuns.add(.{
        .mask = "ann!*@host.example",
        .reason = "flood",
        .set_by = "admin",
        .created_ms = 200,
        .expires_ms = 0,
    });
    var out: [4]Shun = undefined;
    const listed = shuns.list(&out);

    // Assert.
    try testing.expectEqual(@as(usize, 2), shuns.count());
    try testing.expectEqual(@as(usize, 2), listed.len);
    try testing.expectEqualStrings("*!*@bad.example", listed[0].mask);
    try testing.expectEqualStrings("ann!*@host.example", listed[1].mask);
    try testing.expectEqualStrings("flood", listed[1].reason);
    try testing.expect(shuns.remove("*!*@bad.example"));
    try testing.expect(!shuns.remove("*!*@bad.example"));
    try testing.expectEqual(@as(usize, 1), shuns.count());
}

test "isShunned matches hostmasks with case-insensitive glob rules" {
    // Arrange.
    var shuns = ShunList.init(testing.allocator, .{});
    defer shuns.deinit();
    try shuns.add(mkShun("BadNick!*@*.Example.NET"));
    try shuns.add(mkShun("sp?m!*@192.0.2.*"));

    // Act.
    const nick_hit = shuns.isShunned("badnick!~u@edge.example.net", 500);
    const address_hit = shuns.isShunned("spam!u@192.0.2.44", 500);
    const miss = shuns.isShunned("friend!u@good.example.net", 500);

    // Assert.
    try testing.expect(nick_hit);
    try testing.expect(address_hit);
    try testing.expect(!miss);
}

test "isShunned prunes expired entries before matching" {
    // Arrange.
    var shuns = ShunList.init(testing.allocator, .{});
    defer shuns.deinit();
    var expired = mkShun("*!*@expired.example");
    expired.expires_ms = 1000;
    var active = mkShun("*!*@active.example");
    active.expires_ms = 2000;
    try shuns.add(expired);
    try shuns.add(active);

    // Act.
    const expired_hit = shuns.isShunned("a!b@expired.example", 1000);
    const active_hit = shuns.isShunned("a!b@active.example", 1000);

    // Assert.
    try testing.expect(!expired_hit);
    try testing.expect(active_hit);
    try testing.expectEqual(@as(usize, 1), shuns.count());
}

test "pruneExpired removes only entries whose expiry has passed" {
    // Arrange.
    var shuns = ShunList.init(testing.allocator, .{});
    defer shuns.deinit();
    var permanent = mkShun("*!*@permanent.example");
    permanent.expires_ms = 0;
    var edge = mkShun("*!*@edge.example");
    edge.expires_ms = 500;
    var later = mkShun("*!*@later.example");
    later.expires_ms = 501;
    try shuns.add(permanent);
    try shuns.add(edge);
    try shuns.add(later);

    // Act.
    shuns.pruneExpired(500);
    var out: [4]Shun = undefined;
    const listed = shuns.list(&out);

    // Assert.
    try testing.expectEqual(@as(usize, 2), listed.len);
    try testing.expectEqualStrings("*!*@permanent.example", listed[0].mask);
    try testing.expectEqualStrings("*!*@later.example", listed[1].mask);
}

test "add replaces an existing shun with the same mask" {
    // Arrange.
    var shuns = ShunList.init(testing.allocator, .{});
    defer shuns.deinit();
    var first = mkShun("*!*@dup.example");
    first.reason = "first";
    first.set_by = "one";
    first.created_ms = 100;
    var second = mkShun("*!*@dup.example");
    second.reason = "second";
    second.set_by = "two";
    second.created_ms = 200;
    second.expires_ms = 5000;

    // Act.
    try shuns.add(first);
    try shuns.add(second);
    var out: [2]Shun = undefined;
    const listed = shuns.list(&out);

    // Assert.
    try testing.expectEqual(@as(usize, 1), shuns.count());
    try testing.expectEqualStrings("second", listed[0].reason);
    try testing.expectEqualStrings("two", listed[0].set_by);
    try testing.expectEqual(@as(i64, 200), listed[0].created_ms);
    try testing.expectEqual(@as(i64, 5000), listed[0].expires_ms);
}

test "limits reject invalid shuns and allow replacement at capacity" {
    // Arrange.
    var shuns = ShunList.init(testing.allocator, .{
        .max_shuns = 1,
        .max_mask = 8,
        .max_reason = 4,
        .max_setter = 5,
    });
    defer shuns.deinit();

    // Act and assert.
    try testing.expectError(error.EmptyMask, shuns.add(mkShun("")));
    try testing.expectError(error.MaskTooLong, shuns.add(mkShun("toolong-mask")));
    var bad_reason = mkShun("a!*@b");
    bad_reason.reason = "longer";
    try testing.expectError(error.ReasonTooLong, shuns.add(bad_reason));
    var bad_setter = mkShun("a!*@b");
    bad_setter.reason = "ok";
    bad_setter.set_by = "longer";
    try testing.expectError(error.SetterTooLong, shuns.add(bad_setter));

    var valid = mkShun("a!*@b");
    valid.reason = "ok";
    try shuns.add(valid);
    var replacement = mkShun("a!*@b");
    replacement.reason = "next";
    try shuns.add(replacement);
    var overflow = mkShun("c!*@d");
    overflow.reason = "ok";
    try testing.expectError(error.TooManyShuns, shuns.add(overflow));
}

test "list truncates to caller buffer without mutating storage" {
    // Arrange.
    var shuns = ShunList.init(testing.allocator, .{});
    defer shuns.deinit();
    try shuns.add(mkShun("a!*@one.example"));
    try shuns.add(mkShun("b!*@two.example"));
    var out: [1]Shun = undefined;

    // Act.
    const listed = shuns.list(&out);

    // Assert.
    try testing.expectEqual(@as(usize, 1), listed.len);
    try testing.expectEqual(@as(usize, 2), shuns.count());
    try testing.expectEqualStrings("a!*@one.example", listed[0].mask);
}

test "glob matcher handles star question and empty text edge cases" {
    // Arrange.
    const broad = "*";
    const suffix = "*@*.example";
    const single = "a?c";
    const no_match = "a?d";

    // Act and assert.
    try testing.expect(globMatch(broad, ""));
    try testing.expect(globMatch(suffix, "nick!user@sub.example"));
    try testing.expect(globMatch(single, "AbC"));
    try testing.expect(!globMatch(no_match, "abc"));
    try testing.expect(!globMatch("nick!*", "other!user@host"));
}

test "churn through add replace remove and prune leaks no allocations" {
    // Arrange.
    var shuns = ShunList.init(testing.allocator, .{ .max_shuns = 64 });
    defer shuns.deinit();

    // Act.
    for (0..32) |idx| {
        var buf: [48]u8 = undefined;
        const mask = try std.fmt.bufPrint(&buf, "user{d}!*@host{d}.example", .{ idx, idx });
        var shun = mkShun(mask);
        shun.expires_ms = @intCast(1000 + idx);
        try shuns.add(shun);
    }
    for (0..16) |idx| {
        var buf: [48]u8 = undefined;
        const mask = try std.fmt.bufPrint(&buf, "user{d}!*@host{d}.example", .{ idx, idx });
        var replacement = mkShun(mask);
        replacement.reason = "swap";
        replacement.expires_ms = 900;
        try shuns.add(replacement);
    }
    shuns.pruneExpired(1000);
    for (16..32) |idx| {
        var buf: [48]u8 = undefined;
        const mask = try std.fmt.bufPrint(&buf, "user{d}!*@host{d}.example", .{ idx, idx });
        _ = shuns.remove(mask);
    }

    // Assert.
    try testing.expectEqual(@as(usize, 0), shuns.count());
}

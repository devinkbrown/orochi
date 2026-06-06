//! Standalone spam and abuse filter policy engine.
//!
//! The engine owns rule text, scans caller-provided fields, and returns the
//! first insertion-ordered match. It performs no network I/O and does not
//! depend on any other project module.
const std = @import("std");

comptime {
    if (@sizeOf(usize) != 8) @compileError("spamfilter requires a 64-bit target");
}

/// Action to take when a filter rule matches.
pub const Action = enum { warn, block, kill, akill, gline };

/// Field mask describing which scan-context fields a rule evaluates.
pub const Target = packed struct {
    privmsg: bool = false,
    notice: bool = false,
    nick: bool = false,
    user: bool = false,
    gecos: bool = false,
    channel: bool = false,
    away: bool = false,
    topic: bool = false,
};

/// Caller-facing filter rule.
pub const Rule = struct {
    id: []const u8,
    pattern: []const u8,
    action: Action,
    target: Target,
    ttl_secs: u64 = 0,
    reason: []const u8 = "",
};

/// Tunable limits for a filter store.
pub const Params = struct {
    max_rules: usize = 1024,
    max_id_bytes: usize = 64,
    max_pattern_bytes: usize = 512,
    max_reason_bytes: usize = 512,
};

/// Errors returned while validating or storing filter rules.
pub const FilterError = std.mem.Allocator.Error || error{
    DuplicateId,
    EmptyId,
    EmptyPattern,
    EmptyTarget,
    IdTooLong,
    PatternTooLong,
    ReasonTooLong,
    TooManyRules,
};

/// Field that produced a filter match.
pub const Field = enum {
    privmsg,
    notice,
    nick,
    user,
    host,
    gecos,
    channel,
    away,
    topic,
};

/// Caller-provided text fields to scan.
pub const ScanContext = struct {
    privmsg: ?[]const u8 = null,
    notice: ?[]const u8 = null,
    nick: ?[]const u8 = null,
    user: ?[]const u8 = null,
    host: ?[]const u8 = null,
    gecos: ?[]const u8 = null,
    channel: ?[]const u8 = null,
    away: ?[]const u8 = null,
    topic: ?[]const u8 = null,
};

/// A successful filter match.
pub const Match = struct {
    rule: Rule,
    field: Field,
};

/// Owned filter rule store and matcher.
pub const Filter = struct {
    allocator: std.mem.Allocator,
    params: Params,
    rules: std.ArrayList(StoredRule),
    index: std.StringHashMap(usize),

    const StoredRule = struct {
        id: []u8,
        pattern: []u8,
        action: Action,
        target: Target,
        ttl_secs: u64,
        reason: []u8,

        fn view(self: *const StoredRule) Rule {
            return .{
                .id = self.id,
                .pattern = self.pattern,
                .action = self.action,
                .target = self.target,
                .ttl_secs = self.ttl_secs,
                .reason = self.reason,
            };
        }
    };

    /// Initialize a filter with default limits.
    pub fn init(allocator: std.mem.Allocator) Filter {
        return initWithParams(allocator, .{});
    }

    /// Initialize a filter with explicit limits.
    pub fn initWithParams(allocator: std.mem.Allocator, params: Params) Filter {
        return .{
            .allocator = allocator,
            .params = params,
            .rules = .empty,
            .index = std.StringHashMap(usize).init(allocator),
        };
    }

    /// Free all owned rule storage and invalidate this filter.
    pub fn deinit(self: *Filter) void {
        self.clear();
        self.rules.deinit(self.allocator);
        self.index.deinit();
        self.* = undefined;
    }

    /// Remove all rules while retaining allocated backing capacity.
    pub fn clear(self: *Filter) void {
        for (self.rules.items) |rule| {
            self.freeStoredRule(rule);
        }
        self.rules.clearRetainingCapacity();
        self.index.clearRetainingCapacity();
    }

    /// Add a rule, taking owned copies of `id`, `pattern`, and `reason`.
    pub fn add(self: *Filter, rule: Rule) FilterError!void {
        try self.validateRule(rule);
        if (self.index.contains(rule.id)) return error.DuplicateId;
        if (self.rules.items.len >= self.params.max_rules) return error.TooManyRules;

        const owned_id = try self.allocator.dupe(u8, rule.id);
        errdefer self.allocator.free(owned_id);
        const owned_pattern = try self.allocator.dupe(u8, rule.pattern);
        errdefer self.allocator.free(owned_pattern);
        const owned_reason = try self.allocator.dupe(u8, rule.reason);
        errdefer self.allocator.free(owned_reason);

        const slot = self.rules.items.len;
        try self.rules.append(self.allocator, .{
            .id = owned_id,
            .pattern = owned_pattern,
            .action = rule.action,
            .target = rule.target,
            .ttl_secs = rule.ttl_secs,
            .reason = owned_reason,
        });
        errdefer self.freeStoredRule(self.rules.orderedRemove(slot));

        try self.index.putNoClobber(owned_id, slot);
    }

    /// Remove a rule by id and free its owned storage.
    pub fn remove(self: *Filter, id: []const u8) bool {
        const removed_index = self.index.fetchRemove(id) orelse return false;
        const slot = removed_index.value;
        const removed_rule = self.rules.orderedRemove(slot);
        self.freeStoredRule(removed_rule);

        var i: usize = slot;
        while (i < self.rules.items.len) : (i += 1) {
            self.index.getPtr(self.rules.items[i].id).?.* = i;
        }
        return true;
    }

    /// Copy visible rules into `buf`, returning the written prefix.
    pub fn list(self: *const Filter, buf: []Rule) []Rule {
        const count = @min(buf.len, self.rules.items.len);
        for (self.rules.items[0..count], 0..) |rule, index| {
            buf[index] = rule.view();
        }
        return buf[0..count];
    }

    /// Return the first insertion-ordered rule matching `context`, if any.
    pub fn check(self: *const Filter, context: ScanContext) ?Match {
        for (self.rules.items) |rule| {
            if (rule.target.privmsg and matchesField(rule.pattern, context.privmsg)) {
                return .{ .rule = rule.view(), .field = .privmsg };
            }
            if (rule.target.notice and matchesField(rule.pattern, context.notice)) {
                return .{ .rule = rule.view(), .field = .notice };
            }
            if (rule.target.nick and matchesField(rule.pattern, context.nick)) {
                return .{ .rule = rule.view(), .field = .nick };
            }
            if (rule.target.user and matchesField(rule.pattern, context.user)) {
                return .{ .rule = rule.view(), .field = .user };
            }
            if (rule.target.user and matchesField(rule.pattern, context.host)) {
                return .{ .rule = rule.view(), .field = .host };
            }
            if (rule.target.gecos and matchesField(rule.pattern, context.gecos)) {
                return .{ .rule = rule.view(), .field = .gecos };
            }
            if (rule.target.channel and matchesField(rule.pattern, context.channel)) {
                return .{ .rule = rule.view(), .field = .channel };
            }
            if (rule.target.away and matchesField(rule.pattern, context.away)) {
                return .{ .rule = rule.view(), .field = .away };
            }
            if (rule.target.topic and matchesField(rule.pattern, context.topic)) {
                return .{ .rule = rule.view(), .field = .topic };
            }
        }
        return null;
    }

    fn validateRule(self: *const Filter, rule: Rule) FilterError!void {
        if (rule.id.len == 0) return error.EmptyId;
        if (rule.id.len > self.params.max_id_bytes) return error.IdTooLong;
        if (rule.pattern.len == 0) return error.EmptyPattern;
        if (rule.pattern.len > self.params.max_pattern_bytes) return error.PatternTooLong;
        if (rule.reason.len > self.params.max_reason_bytes) return error.ReasonTooLong;
        if (!hasAnyTarget(rule.target)) return error.EmptyTarget;
    }

    fn freeStoredRule(self: *Filter, rule: StoredRule) void {
        self.allocator.free(rule.id);
        self.allocator.free(rule.pattern);
        self.allocator.free(rule.reason);
    }
};

fn hasAnyTarget(target: Target) bool {
    return target.privmsg or
        target.notice or
        target.nick or
        target.user or
        target.gecos or
        target.channel or
        target.away or
        target.topic;
}

fn matchesField(pattern: []const u8, maybe_text: ?[]const u8) bool {
    const text = maybe_text orelse return false;
    return if (isGlob(pattern))
        globMatchesIgnoreCase(pattern, text)
    else
        containsIgnoreCase(text, pattern);
}

fn isGlob(pattern: []const u8) bool {
    for (pattern) |byte| {
        switch (byte) {
            '*', '?' => return true,
            else => {},
        }
    }
    return false;
}

fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (needle.len > haystack.len) return false;

    var start: usize = 0;
    while (start <= haystack.len - needle.len) : (start += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[start .. start + needle.len], needle)) {
            return true;
        }
    }
    return false;
}

fn globMatchesIgnoreCase(pattern: []const u8, text: []const u8) bool {
    var pattern_index: usize = 0;
    var text_index: usize = 0;
    var star_index: ?usize = null;
    var star_text_index: usize = 0;

    while (text_index < text.len) {
        if (pattern_index < pattern.len and
            (pattern[pattern_index] == '?' or asciiByteEql(pattern[pattern_index], text[text_index])))
        {
            pattern_index += 1;
            text_index += 1;
            continue;
        }

        if (pattern_index < pattern.len and pattern[pattern_index] == '*') {
            star_index = pattern_index;
            pattern_index += 1;
            star_text_index = text_index;
            continue;
        }

        if (star_index) |star| {
            pattern_index = star + 1;
            star_text_index += 1;
            text_index = star_text_index;
            continue;
        }

        return false;
    }

    while (pattern_index < pattern.len and pattern[pattern_index] == '*') {
        pattern_index += 1;
    }
    return pattern_index == pattern.len;
}

fn asciiByteEql(a: u8, b: u8) bool {
    return std.ascii.toLower(a) == std.ascii.toLower(b);
}

test "plain substring rule matches privmsg text" {
    // Arrange
    var filter = Filter.init(std.testing.allocator);
    defer filter.deinit();
    try filter.add(.{
        .id = "spam-1",
        .pattern = "cheap pills",
        .action = .block,
        .target = .{ .privmsg = true },
        .reason = "advertising",
    });

    // Act
    const found = filter.check(.{ .privmsg = "Get CHEAP PILLS now" });

    // Assert
    try std.testing.expect(found != null);
    try std.testing.expectEqual(Field.privmsg, found.?.field);
    try std.testing.expectEqual(Action.block, found.?.rule.action);
    try std.testing.expectEqualStrings("spam-1", found.?.rule.id);
}

test "glob rule matches prefix suffix middle and question mark forms" {
    // Arrange
    var filter = Filter.init(std.testing.allocator);
    defer filter.deinit();
    try filter.add(.{
        .id = "glob-prefix",
        .pattern = "spam*",
        .action = .warn,
        .target = .{ .privmsg = true },
    });
    try filter.add(.{
        .id = "glob-suffix",
        .pattern = "*tail",
        .action = .block,
        .target = .{ .notice = true },
    });
    try filter.add(.{
        .id = "glob-middle",
        .pattern = "*middle*",
        .action = .kill,
        .target = .{ .topic = true },
    });
    try filter.add(.{
        .id = "glob-question",
        .pattern = "b?d",
        .action = .akill,
        .target = .{ .nick = true },
    });

    // Act
    const prefix = filter.check(.{ .privmsg = "spam-burst" });
    const suffix = filter.check(.{ .notice = "long-tail" });
    const middle = filter.check(.{ .topic = "left-MIDDLE-right" });
    const question = filter.check(.{ .nick = "bad" });

    // Assert
    try std.testing.expect(prefix != null);
    try std.testing.expectEqualStrings("glob-prefix", prefix.?.rule.id);
    try std.testing.expect(suffix != null);
    try std.testing.expectEqualStrings("glob-suffix", suffix.?.rule.id);
    try std.testing.expect(middle != null);
    try std.testing.expectEqualStrings("glob-middle", middle.?.rule.id);
    try std.testing.expect(question != null);
    try std.testing.expectEqualStrings("glob-question", question.?.rule.id);
}

test "plain and glob matching are ascii case insensitive" {
    // Arrange
    var filter = Filter.init(std.testing.allocator);
    defer filter.deinit();
    try filter.add(.{
        .id = "plain-case",
        .pattern = "MiXeD",
        .action = .warn,
        .target = .{ .privmsg = true },
    });
    try filter.add(.{
        .id = "glob-case",
        .pattern = "Ab*Z",
        .action = .block,
        .target = .{ .notice = true },
    });

    // Act
    const plain = filter.check(.{ .privmsg = "prefix mixed suffix" });
    const glob = filter.check(.{ .notice = "abuse-z" });

    // Assert
    try std.testing.expect(plain != null);
    try std.testing.expectEqualStrings("plain-case", plain.?.rule.id);
    try std.testing.expect(glob != null);
    try std.testing.expectEqualStrings("glob-case", glob.?.rule.id);
}

test "target gating prevents privmsg rule from matching nick scan" {
    // Arrange
    var filter = Filter.init(std.testing.allocator);
    defer filter.deinit();
    try filter.add(.{
        .id = "message-only",
        .pattern = "badnick",
        .action = .block,
        .target = .{ .privmsg = true },
    });

    // Act
    const found = filter.check(.{ .nick = "badnick" });

    // Assert
    try std.testing.expect(found == null);
}

test "user target can report hostname match" {
    // Arrange
    var filter = Filter.init(std.testing.allocator);
    defer filter.deinit();
    try filter.add(.{
        .id = "host-rule",
        .pattern = "*.example.test",
        .action = .gline,
        .target = .{ .user = true },
    });

    // Act
    const found = filter.check(.{ .host = "dialup.example.test" });

    // Assert
    try std.testing.expect(found != null);
    try std.testing.expectEqual(Field.host, found.?.field);
    try std.testing.expectEqual(Action.gline, found.?.rule.action);
}

test "ttl value and reason are carried through match and list views" {
    // Arrange
    var filter = Filter.init(std.testing.allocator);
    defer filter.deinit();
    try filter.add(.{
        .id = "temporary",
        .pattern = "burst",
        .action = .warn,
        .target = .{ .privmsg = true },
        .ttl_secs = 3600,
        .reason = "temporary flood pattern",
    });
    var listed_buf: [1]Rule = undefined;

    // Act
    const found = filter.check(.{ .privmsg = "burst text" });
    const listed = filter.list(&listed_buf);

    // Assert
    try std.testing.expect(found != null);
    try std.testing.expectEqual(@as(u64, 3600), found.?.rule.ttl_secs);
    try std.testing.expectEqualStrings("temporary flood pattern", found.?.rule.reason);
    try std.testing.expectEqual(@as(usize, 1), listed.len);
    try std.testing.expectEqual(@as(u64, 3600), listed[0].ttl_secs);
    try std.testing.expectEqualStrings("temporary flood pattern", listed[0].reason);
}

test "remove deletes rule and reports misses without leaks" {
    // Arrange
    var filter = Filter.init(std.testing.allocator);
    defer filter.deinit();
    try filter.add(.{
        .id = "first",
        .pattern = "one",
        .action = .warn,
        .target = .{ .privmsg = true },
    });
    try filter.add(.{
        .id = "second",
        .pattern = "two",
        .action = .block,
        .target = .{ .privmsg = true },
    });

    // Act
    const removed_first = filter.remove("first");
    const removed_missing = filter.remove("first");
    const first_match = filter.check(.{ .privmsg = "one" });
    const second_match = filter.check(.{ .privmsg = "two" });

    // Assert
    try std.testing.expect(removed_first);
    try std.testing.expect(!removed_missing);
    try std.testing.expect(first_match == null);
    try std.testing.expect(second_match != null);
    try std.testing.expectEqualStrings("second", second_match.?.rule.id);
}

test "limits reject oversized and duplicate rules without leaks" {
    // Arrange
    var filter = Filter.initWithParams(std.testing.allocator, .{
        .max_rules = 1,
        .max_id_bytes = 4,
        .max_pattern_bytes = 5,
        .max_reason_bytes = 6,
    });
    defer filter.deinit();

    // Act
    try filter.add(.{
        .id = "one",
        .pattern = "abc",
        .action = .warn,
        .target = .{ .privmsg = true },
        .reason = "short",
    });

    // Assert
    try std.testing.expectError(error.DuplicateId, filter.add(.{
        .id = "one",
        .pattern = "def",
        .action = .warn,
        .target = .{ .privmsg = true },
    }));
    try std.testing.expectError(error.TooManyRules, filter.add(.{
        .id = "two",
        .pattern = "def",
        .action = .warn,
        .target = .{ .privmsg = true },
    }));
    try std.testing.expectError(error.IdTooLong, filter.add(.{
        .id = "toolong",
        .pattern = "abc",
        .action = .warn,
        .target = .{ .privmsg = true },
    }));
    try std.testing.expectError(error.PatternTooLong, filter.add(.{
        .id = "pat",
        .pattern = "abcdef",
        .action = .warn,
        .target = .{ .privmsg = true },
    }));
    try std.testing.expectError(error.ReasonTooLong, filter.add(.{
        .id = "why",
        .pattern = "abc",
        .action = .warn,
        .target = .{ .privmsg = true },
        .reason = "toolong",
    }));
}

test "empty id pattern and target are rejected without leaks" {
    // Arrange
    var filter = Filter.init(std.testing.allocator);
    defer filter.deinit();

    // Act and Assert
    try std.testing.expectError(error.EmptyId, filter.add(.{
        .id = "",
        .pattern = "abc",
        .action = .warn,
        .target = .{ .privmsg = true },
    }));
    try std.testing.expectError(error.EmptyPattern, filter.add(.{
        .id = "id",
        .pattern = "",
        .action = .warn,
        .target = .{ .privmsg = true },
    }));
    try std.testing.expectError(error.EmptyTarget, filter.add(.{
        .id = "id",
        .pattern = "abc",
        .action = .warn,
        .target = .{},
    }));
}

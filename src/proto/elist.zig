//! ELIST extended LIST filters for RPL_LIST (322).
//!
//! Parsed mask filters borrow slices from the input filter text. The returned
//! filter set owns only its filter array and must be deinitialized by caller.
const std = @import("std");
const listx = @import("listx.zig");
const limits_config = @import("limits_config.zig");

pub const DEFAULT_MAX_FILTER_BYTES: usize = 512;
pub const DEFAULT_MAX_MASK_BYTES: usize = 128;

pub const ElistError = std.mem.Allocator.Error || error{
    InvalidParameter,
    InvalidFilter,
    InvalidMask,
    InvalidValue,
    FilterTooLong,
    MaskTooLong,
};

pub const Comparison = enum {
    greater_than,
    less_than,

    fn fromByte(byte: u8) ?Comparison {
        return switch (byte) {
            '>' => .greater_than,
            '<' => .less_than,
            else => null,
        };
    }

    fn accepts(self: Comparison, actual: u64, threshold: u64) bool {
        return switch (self) {
            .greater_than => actual >= threshold,
            .less_than => actual <= threshold,
        };
    }
};

pub const Filter = union(enum) {
    min_users: u64,
    max_users: u64,
    created_older_than: u64,
    created_younger_than: u64,
    topic_older_than: u64,
    topic_younger_than: u64,
    include_mask: []const u8,
    exclude_mask: []const u8,
};

pub const Channel = struct {
    name: []const u8,
    users: u64,
    created_ago: u64,
    topic_age: u64,
};

pub const Params = struct {
    max_filter_bytes: usize = DEFAULT_MAX_FILTER_BYTES,
    max_mask_bytes: usize = DEFAULT_MAX_MASK_BYTES,

    /// Derive `Params` from the central policy limits (config-driven).
    /// `max_filter_bytes` is a wire budget and keeps its default.
    pub fn fromLimits(limits: *const limits_config.Limits) Params {
        return .{
            .max_mask_bytes = limits.list_mask_len,
        };
    }
};

pub const FilterSet = struct {
    filters: std.ArrayList(Filter) = .empty,

    pub fn deinit(self: *FilterSet, allocator: std.mem.Allocator) void {
        self.filters.deinit(allocator);
        self.* = undefined;
    }

    pub fn slice(self: *const FilterSet) []const Filter {
        return self.filters.items;
    }

    pub fn matches(self: *const FilterSet, channel: Channel) bool {
        return matchesFilters(self.slice(), channel);
    }
};

/// Parse a single LIST filter parameter, such as ">10,C<30,#z*,!#old*".
pub fn parse(allocator: std.mem.Allocator, input: []const u8) ElistError!FilterSet {
    return parseWith(.{}, allocator, input);
}

/// Parse tokenized LIST parameters. ELIST accepts zero or one filter parameter.
pub fn parseParams(allocator: std.mem.Allocator, params: []const []const u8) ElistError!FilterSet {
    return parseParamsWith(.{}, allocator, params);
}

pub fn parseParamsWith(
    comptime params: Params,
    allocator: std.mem.Allocator,
    list_params: []const []const u8,
) ElistError!FilterSet {
    if (list_params.len > 1) return error.InvalidParameter;
    if (list_params.len == 0) return FilterSet{};
    return parseWith(params, allocator, list_params[0]);
}

pub fn parseWith(
    comptime params: Params,
    allocator: std.mem.Allocator,
    input: []const u8,
) ElistError!FilterSet {
    if (input.len > params.max_filter_bytes) return error.FilterTooLong;

    var set = FilterSet{};
    errdefer set.deinit(allocator);

    if (input.len == 0) return set;

    var cursor: usize = 0;
    while (cursor <= input.len) {
        const next = findByte(input, cursor, ',') orelse input.len;
        try set.filters.append(allocator, try parseFilterWith(params, input[cursor..next]));
        if (next == input.len) break;
        cursor = next + 1;
    }

    return set;
}

pub fn parseFilter(token: []const u8) ElistError!Filter {
    return parseFilterWith(.{}, token);
}

pub fn parseFilterWith(comptime params: Params, token: []const u8) ElistError!Filter {
    if (token.len == 0) return error.InvalidFilter;
    if (token.len > params.max_filter_bytes) return error.FilterTooLong;
    try validateFilterBytes(token);

    if (token[0] == '>' or token[0] == '<') {
        const value = try parseDecimal(token[1..]);
        return if (token[0] == '>')
            Filter{ .min_users = value }
        else
            Filter{ .max_users = value };
    }

    if (token.len >= 3 and asciiEqual(token[0], 'C')) {
        const comparison = Comparison.fromByte(token[1]) orelse return error.InvalidFilter;
        const value = try parseDecimal(token[2..]);
        return switch (comparison) {
            .greater_than => Filter{ .created_older_than = value },
            .less_than => Filter{ .created_younger_than = value },
        };
    }

    if (token.len >= 3 and asciiEqual(token[0], 'T')) {
        const comparison = Comparison.fromByte(token[1]) orelse return error.InvalidFilter;
        const value = try parseDecimal(token[2..]);
        return switch (comparison) {
            .greater_than => Filter{ .topic_older_than = value },
            .less_than => Filter{ .topic_younger_than = value },
        };
    }

    if (token[0] == '!') {
        const mask = token[1..];
        try validateMaskWith(params, mask);
        return Filter{ .exclude_mask = mask };
    }

    try validateMaskWith(params, token);
    return Filter{ .include_mask = token };
}

pub fn matchesFilters(filters: []const Filter, channel: Channel) bool {
    var has_include_mask = false;
    var include_matched = false;

    for (filters) |filter| {
        switch (filter) {
            .min_users => |threshold| {
                if (!Comparison.greater_than.accepts(channel.users, threshold)) return false;
            },
            .max_users => |threshold| {
                if (!Comparison.less_than.accepts(channel.users, threshold)) return false;
            },
            .created_older_than => |threshold| {
                if (!Comparison.greater_than.accepts(channel.created_ago, threshold)) return false;
            },
            .created_younger_than => |threshold| {
                if (!Comparison.less_than.accepts(channel.created_ago, threshold)) return false;
            },
            .topic_older_than => |threshold| {
                if (!Comparison.greater_than.accepts(channel.topic_age, threshold)) return false;
            },
            .topic_younger_than => |threshold| {
                if (!Comparison.less_than.accepts(channel.topic_age, threshold)) return false;
            },
            .include_mask => |mask| {
                has_include_mask = true;
                include_matched = include_matched or listx.globMatch(mask, channel.name);
            },
            .exclude_mask => |mask| {
                if (listx.globMatch(mask, channel.name)) return false;
            },
        }
    }

    return !has_include_mask or include_matched;
}

fn validateFilterBytes(token: []const u8) ElistError!void {
    for (token) |byte| {
        switch (byte) {
            0, ',', ' ', '\t', '\r', '\n' => return error.InvalidFilter,
            else => {},
        }
    }
}

fn validateMaskWith(comptime params: Params, mask: []const u8) ElistError!void {
    if (mask.len == 0) return error.InvalidMask;
    if (mask.len > params.max_mask_bytes) return error.MaskTooLong;
    if (mask[0] == '!') return error.InvalidMask;

    for (mask) |byte| {
        switch (byte) {
            0, ',', ' ', '\t', '\r', '\n' => return error.InvalidMask,
            else => {},
        }
    }
}

fn parseDecimal(bytes: []const u8) ElistError!u64 {
    if (bytes.len == 0) return error.InvalidValue;

    var value: u64 = 0;
    for (bytes) |byte| {
        if (byte < '0' or byte > '9') return error.InvalidValue;
        const digit: u64 = byte - '0';
        if (value > (std.math.maxInt(u64) - digit) / 10) return error.InvalidValue;
        value = value * 10 + digit;
    }

    return value;
}

fn findByte(bytes: []const u8, start: usize, needle: u8) ?usize {
    var cursor = start;
    while (cursor < bytes.len) : (cursor += 1) {
        if (bytes[cursor] == needle) return cursor;
    }
    return null;
}

fn asciiEqual(left: u8, right: u8) bool {
    return asciiLower(left) == asciiLower(right);
}

fn asciiLower(byte: u8) u8 {
    return if (byte >= 'A' and byte <= 'Z') byte + ('a' - 'A') else byte;
}

const testing = std.testing;

fn expectOne(input: []const u8) !Filter {
    var set = try parse(testing.allocator, input);
    defer set.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 1), set.slice().len);
    return set.slice()[0];
}

test "parse user count filters" {
    try testing.expectEqual(@as(u64, 10), (try expectOne(">10")).min_users);
    try testing.expectEqual(@as(u64, 50), (try expectOne("<50")).max_users);
}

test "parse created age filters in minutes" {
    try testing.expectEqual(@as(u64, 15), (try expectOne("C>15")).created_older_than);
    try testing.expectEqual(@as(u64, 30), (try expectOne("C<30")).created_younger_than);
    try testing.expectEqual(@as(u64, 15), (try expectOne("c>15")).created_older_than);
}

test "parse topic age filters in minutes" {
    try testing.expectEqual(@as(u64, 5), (try expectOne("T>5")).topic_older_than);
    try testing.expectEqual(@as(u64, 45), (try expectOne("T<45")).topic_younger_than);
    try testing.expectEqual(@as(u64, 5), (try expectOne("t>5")).topic_older_than);
}

test "parse include and exclude masks" {
    try testing.expectEqualStrings("#zig*", (try expectOne("#zig*")).include_mask);
    try testing.expectEqualStrings("#old*", (try expectOne("!#old*")).exclude_mask);
}

test "matches user counts and ages" {
    var set = try parse(testing.allocator, ">10,<50,C>60,C<120,T>5,T<30");
    defer set.deinit(testing.allocator);

    try testing.expect(set.matches(.{
        .name = "#zig",
        .users = 42,
        .created_ago = 90,
        .topic_age = 10,
    }));
    try testing.expect(!set.matches(.{
        .name = "#small",
        .users = 9,
        .created_ago = 90,
        .topic_age = 10,
    }));
    try testing.expect(!set.matches(.{
        .name = "#young-topic",
        .users = 42,
        .created_ago = 90,
        .topic_age = 3,
    }));
}

test "matches include mask disjunction and exclude masks" {
    var set = try parse(testing.allocator, "#zig*,#dev*,!#dev-old");
    defer set.deinit(testing.allocator);

    try testing.expect(set.matches(.{
        .name = "#ZIG",
        .users = 1,
        .created_ago = 0,
        .topic_age = 0,
    }));
    try testing.expect(set.matches(.{
        .name = "#dev-new",
        .users = 1,
        .created_ago = 0,
        .topic_age = 0,
    }));
    try testing.expect(!set.matches(.{
        .name = "#ops",
        .users = 1,
        .created_ago = 0,
        .topic_age = 0,
    }));
    try testing.expect(!set.matches(.{
        .name = "#dev-old",
        .users = 1,
        .created_ago = 0,
        .topic_age = 0,
    }));
}

test "combined filters" {
    var set = try parse(testing.allocator, ">5,<100,C>10,T<20,#team*,!#team-private");
    defer set.deinit(testing.allocator);

    try testing.expect(set.matches(.{
        .name = "#team-chat",
        .users = 20,
        .created_ago = 40,
        .topic_age = 12,
    }));
    try testing.expect(!set.matches(.{
        .name = "#team-private",
        .users = 20,
        .created_ago = 40,
        .topic_age = 12,
    }));
    try testing.expect(!set.matches(.{
        .name = "#team-chat",
        .users = 20,
        .created_ago = 8,
        .topic_age = 12,
    }));
}

test "parse params accepts zero or one LIST filter parameter" {
    var empty = try parseParams(testing.allocator, &.{});
    defer empty.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 0), empty.slice().len);

    var set = try parseParams(testing.allocator, &.{">1,#z*"});
    defer set.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 2), set.slice().len);

    try testing.expectError(error.InvalidParameter, parseParams(testing.allocator, &.{ ">1", "#z*" }));
}

test "parse params rejects malformed LIST C filter" {
    try testing.expectError(error.InvalidFilter, parseParams(testing.allocator, &.{"C10"}));
}

test "malformed filters are rejected" {
    try testing.expectError(error.InvalidFilter, parse(testing.allocator, ","));
    try testing.expectError(error.InvalidFilter, parse(testing.allocator, ">1,"));
    try testing.expectError(error.InvalidValue, parse(testing.allocator, ">"));
    try testing.expectError(error.InvalidValue, parse(testing.allocator, "<abc"));
    try testing.expectError(error.InvalidFilter, parse(testing.allocator, "C10"));
    try testing.expectError(error.InvalidFilter, parse(testing.allocator, "T=10"));
    try testing.expectError(error.InvalidValue, parse(testing.allocator, "C>abc"));
    try testing.expectError(error.InvalidMask, parse(testing.allocator, "!"));
    try testing.expectError(error.InvalidFilter, parse(testing.allocator, "#bad mask"));
    try testing.expectError(error.InvalidValue, parse(testing.allocator, ">18446744073709551616"));
}

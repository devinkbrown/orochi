//! Legacy +s server-notice mask helpers backed by Event Spine categories.
//!
//! This parser accepts both raw snomask strings (`+cf-k`) and MODE-shaped
//! strings (`MODE oper +s cf`). Unknown letters are ignored so older peers can
//! send letters that Orochi no longer routes as separate notice channels.
const std = @import("std");
const root = @import("root");
const event_spine = if (@hasDecl(root, "daemon")) root.daemon.event_spine else StandaloneEventSpine;

pub const EventCategory = event_spine.EventCategory;
pub const CategoryMask = event_spine.CategoryMask;

pub const MAX_LETTERS: usize = mappings.len;

pub const Error = error{
    OutputTooSmall,
};

pub const ModeOp = enum {
    add,
    remove,
};

pub const Mapping = struct {
    letter: u8,
    category: EventCategory,
};

/// Canonical legacy snomask letters, ordered for stable rendering.
pub const mappings = [_]Mapping{
    .{ .letter = 'c', .category = .connect },
    .{ .letter = 'q', .category = .disconnect },
    .{ .letter = 's', .category = .server_link },
    .{ .letter = 'f', .category = .flood },
    .{ .letter = 'e', .category = .@"error" },
    .{ .letter = 'a', .category = .announce },
    .{ .letter = 'o', .category = .oper_action },
    .{ .letter = 'k', .category = .kill },
    .{ .letter = 'm', .category = .spam },
    .{ .letter = 'd', .category = .debug },
    .{ .letter = 'p', .category = .policy },
    .{ .letter = 'v', .category = .service },
    .{ .letter = 'x', .category = .security },
};

comptime {
    if (mappings.len > 64) @compileError("snomask mappings must fit CategoryMask bits");
}

pub fn categoryFromLetter(letter: u8) ?EventCategory {
    const normalized = std.ascii.toLower(letter);
    for (mappings) |mapping| {
        if (mapping.letter == normalized) return mapping.category;
    }
    return null;
}

pub fn letterForCategory(category: EventCategory) ?u8 {
    for (mappings) |mapping| {
        if (mapping.category == category) return mapping.letter;
    }
    return null;
}

/// Parse a raw snomask or MODE-shaped string into a mask from empty state.
///
/// A string without an explicit operation is treated as additions, so `cf` and
/// `+cf` both produce connect+flood. Removals are still parsed; from empty state
/// they naturally leave the removed categories absent.
pub fn parse(input: []const u8) CategoryMask {
    var mask = CategoryMask.empty();
    apply(&mask, input);
    return mask;
}

/// Apply raw or MODE-shaped snomask operations to an existing mask.
pub fn apply(mask: *CategoryMask, input: []const u8) void {
    var it = std.mem.tokenizeAny(u8, input, " \t\r\n");
    const first = it.next() orelse return;

    if (std.ascii.eqlIgnoreCase(first, "MODE")) {
        _ = it.next() orelse return;
        while (it.next()) |mode_token| {
            if (containsSnomaskMode(mode_token)) {
                const letters = it.next() orelse return;
                applyLetters(mask, letters);
                return;
            }
        }
        return;
    }

    applyLetters(mask, first);
    while (it.next()) |token| applyLetters(mask, token);
}

/// Apply a compact snomask letter string such as `+cf-k`.
pub fn applyLetters(mask: *CategoryMask, letters: []const u8) void {
    var op: ModeOp = .add;

    for (letters) |ch| {
        switch (ch) {
            '+' => op = .add,
            '-' => op = .remove,
            else => {
                const category = categoryFromLetter(ch) orelse continue;
                switch (op) {
                    .add => mask.add(category),
                    .remove => mask.remove(category),
                }
            },
        }
    }
}

/// Render a mask as canonical legacy snomask letters, without a leading `+s`.
pub fn render(mask: CategoryMask, out: []u8) Error![]const u8 {
    return writeLetters(mask, out);
}

pub fn writeLetters(mask: CategoryMask, out: []u8) Error![]const u8 {
    var n: usize = 0;
    for (mappings) |mapping| {
        if (!mask.contains(mapping.category)) continue;
        if (n >= out.len) return error.OutputTooSmall;
        out[n] = mapping.letter;
        n += 1;
    }
    return out[0..n];
}

pub fn renderedLen(mask: CategoryMask) usize {
    var n: usize = 0;
    for (mappings) |mapping| {
        if (mask.contains(mapping.category)) n += 1;
    }
    return n;
}

fn containsSnomaskMode(modes: []const u8) bool {
    for (modes) |ch| {
        if (ch == 's') return true;
    }
    return false;
}

const StandaloneEventSpine = struct {
    const Category = enum(u6) {
        connect,
        disconnect,
        server_link,
        flood,
        @"error",
        announce,
        oper_action,
        kill,
        spam,
        debug,
        policy,
        service,
        security,
    };
    pub const EventCategory = Category;

    const Mask = struct {
        bits: u64 = 0,

        pub fn empty() Mask {
            return .{};
        }

        pub fn add(self: *Mask, category: Category) void {
            self.bits |= bit(category);
        }

        pub fn remove(self: *Mask, category: Category) void {
            self.bits &= ~bit(category);
        }

        pub fn contains(self: Mask, category: Category) bool {
            return (self.bits & bit(category)) != 0;
        }

        fn bit(category: Category) u64 {
            return @as(u64, 1) << @intFromEnum(category);
        }
    };
    pub const CategoryMask = Mask;
};

test "parse letters to mask and render round trip" {
    const allocator = std.testing.allocator;
    const parsed = parse("cfkos");

    try std.testing.expect(parsed.contains(.connect));
    try std.testing.expect(parsed.contains(.flood));
    try std.testing.expect(parsed.contains(.kill));
    try std.testing.expect(parsed.contains(.oper_action));
    try std.testing.expect(parsed.contains(.server_link));
    try std.testing.expect(!parsed.contains(.debug));

    const out = try allocator.alloc(u8, MAX_LETTERS);
    defer allocator.free(out);

    try std.testing.expectEqualStrings("csfok", try render(parsed, out));
    try std.testing.expectEqual(parsed.bits, parse(try render(parsed, out)).bits);
}

test "unknown letters are ignored" {
    const allocator = std.testing.allocator;
    const parsed = parse("+c?Z!f");

    try std.testing.expect(parsed.contains(.connect));
    try std.testing.expect(parsed.contains(.flood));
    try std.testing.expect(!parsed.contains(.kill));

    const out = try allocator.alloc(u8, MAX_LETTERS);
    defer allocator.free(out);

    try std.testing.expectEqualStrings("cf", try render(parsed, out));
}

test "add and remove semantics update an existing mask" {
    var mask = CategoryMask.empty();
    apply(&mask, "+cfko");
    apply(&mask, "-fk+d");

    try std.testing.expect(mask.contains(.connect));
    try std.testing.expect(!mask.contains(.flood));
    try std.testing.expect(!mask.contains(.kill));
    try std.testing.expect(mask.contains(.oper_action));
    try std.testing.expect(mask.contains(.debug));
}

test "mode shaped input applies snomask letters" {
    const allocator = std.testing.allocator;
    var mask = parse("MODE oper +s cfk");
    apply(&mask, "MODE oper +s -f+o");

    const out = try allocator.alloc(u8, MAX_LETTERS);
    defer allocator.free(out);

    try std.testing.expectEqualStrings("cok", try render(mask, out));
}

test "render reports bounded output" {
    var one: [1]u8 = undefined;
    const mask = parse("cf");

    try std.testing.expectError(error.OutputTooSmall, render(mask, one[0..]));
    try std.testing.expectEqual(@as(usize, 2), renderedLen(mask));
}

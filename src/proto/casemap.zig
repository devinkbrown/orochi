// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! IRC nickname and channel case mapping helpers.
//!
//! The helpers fold bytes into caller-owned output storage. They intentionally
//! do not allocate, which keeps comparison paths predictable for hot command
//! dispatch and membership lookups.
const std = @import("std");

/// Supported IRC case-mapping rules.
pub const Mapping = enum(u1) {
    ascii,
    rfc1459,
};

/// Case mapping bounds for callers that want a named configuration object.
pub const Params = struct {
    max_name_bytes: usize = 512,
};

/// Errors returned while folding bytes into caller-owned storage.
pub const CaseMapError = error{
    OutputTooSmall,
};

/// Allocation-free case mapper with fixed mapping parameters.
pub const CaseMap = struct {
    mapping: Mapping,
    params: Params = .{},

    /// Create a case mapper for the selected mapping and bounds.
    pub fn init(mapping: Mapping, params: Params) CaseMap {
        return .{ .mapping = mapping, .params = params };
    }

    /// Release mapper resources.
    pub fn deinit(self: *CaseMap) void {
        self.* = undefined;
    }

    /// Fold `input` into `out` using this mapper's configured mapping.
    pub fn fold(self: CaseMap, input: []const u8, out: []u8) CaseMapError![]const u8 {
        _ = self.params;
        return foldInto(input, out, self.mapping);
    }

    /// Return true when both byte strings compare equal under this mapper.
    pub fn eql(self: CaseMap, a: []const u8, b: []const u8) bool {
        _ = self.params;
        return eqlFolded(a, b, self.mapping);
    }
};

/// Fold `input` into `out` using the selected IRC case mapping.
pub fn fold(input: []const u8, out: []u8, mapping: Mapping) CaseMapError![]const u8 {
    return foldInto(input, out, mapping);
}

/// Return true when both byte strings compare equal under the selected mapping.
pub fn eql(a: []const u8, b: []const u8, mapping: Mapping) bool {
    return eqlFolded(a, b, mapping);
}

fn foldInto(input: []const u8, out: []u8, mapping: Mapping) CaseMapError![]const u8 {
    if (out.len < input.len) return error.OutputTooSmall;

    for (input, 0..) |byte, index| {
        out[index] = foldByte(byte, mapping);
    }

    return out[0..input.len];
}

fn eqlFolded(a: []const u8, b: []const u8, mapping: Mapping) bool {
    if (a.len != b.len) return false;

    for (a, b) |left, right| {
        if (foldByte(left, mapping) != foldByte(right, mapping)) return false;
    }

    return true;
}

fn foldByte(byte: u8, mapping: Mapping) u8 {
    return switch (mapping) {
        .ascii => foldAscii(byte),
        .rfc1459 => switch (byte) {
            '{' => '[',
            '}' => ']',
            '|' => '\\',
            '^' => '~',
            else => foldAscii(byte),
        },
    };
}

fn foldAscii(byte: u8) u8 {
    return if (byte >= 'A' and byte <= 'Z') byte + ('a' - 'A') else byte;
}

test "ascii fold lowercases letters and preserves non letters" {
    // Arrange.
    const allocator = std.testing.allocator;
    const input = "Nick-123_[]\\~{}|^";
    const expected = "nick-123_[]\\~{}|^";
    const out = try allocator.alloc(u8, input.len);
    defer allocator.free(out);

    // Act.
    const folded = try fold(input, out, .ascii);

    // Assert.
    try std.testing.expectEqualStrings(expected, folded);
}

test "rfc1459 fold maps special channel and nickname characters" {
    // Arrange.
    const allocator = std.testing.allocator;
    const input = "Nick{}|^[]\\~";
    const expected = "nick[]\\~[]\\~";
    const out = try allocator.alloc(u8, input.len);
    defer allocator.free(out);

    // Act.
    const folded = try fold(input, out, .rfc1459);

    // Assert.
    try std.testing.expectEqualStrings(expected, folded);
}

test "equality uses ascii mapping without rfc1459 special equivalence" {
    // Arrange.
    const mixed = "Alice{}|^";
    const lower = "alice{}|^";
    const bracketed = "alice[]\\~";

    // Act.
    const same_letters = eql(mixed, lower, .ascii);
    const same_specials = eql(mixed, bracketed, .ascii);

    // Assert.
    try std.testing.expect(same_letters);
    try std.testing.expect(!same_specials);
}

test "equality uses rfc1459 letter and special equivalence" {
    // Arrange.
    const raw = "Chan{}|^";
    const folded = "chan[]\\~";

    // Act.
    const equal = eql(raw, folded, .rfc1459);

    // Assert.
    try std.testing.expect(equal);
}

test "fold reports output too small" {
    // Arrange.
    const input = "abc";
    var out: [2]u8 = undefined;

    // Act and assert.
    try std.testing.expectError(error.OutputTooSmall, fold(input, &out, .ascii));
}

test "case mapper delegates fold and equality" {
    // Arrange.
    const allocator = std.testing.allocator;
    var mapper = CaseMap.init(.rfc1459, .{});
    defer mapper.deinit();
    const input = "User{}|^";
    const expected = "user[]\\~";
    const out = try allocator.alloc(u8, input.len);
    defer allocator.free(out);

    // Act.
    const folded = try mapper.fold(input, out);
    const equal = mapper.eql(input, expected);

    // Assert.
    try std.testing.expectEqualStrings(expected, folded);
    try std.testing.expect(equal);
}

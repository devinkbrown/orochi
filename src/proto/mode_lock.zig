// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure services channel mode-lock policy evaluation.
//!
//! This module owns no live channel state. It parses a compact locked mode
//! specification and evaluates caller-provided MODE deltas against that policy.
const std = @import("std");

/// Compile-time and runtime limits for mode-lock parsing.
pub const Params = struct {
    /// Maximum bytes accepted in one lock specification.
    max_spec_bytes: usize = 64,
};

/// Errors returned by mode-lock parsing, formatting, and enforcement.
pub const ModeLockError = error{
    EmptySpec,
    SpecTooLong,
    MissingOperation,
    MissingModeLetter,
    InvalidModeLetter,
    DuplicateMode,
    ConflictingLock,
    OutputTooSmall,
};

/// One policy decision for a requested mode transition.
pub const Decision = enum {
    allow,
    forbid,
    force_on,
    force_off,
};

/// Result slices produced by `enforce`.
pub const Enforcement = struct {
    /// Requested mode letters that may be set.
    allowed_on: []const u8,
    /// Requested mode letters that may be unset.
    allowed_off: []const u8,
    /// Locked-on letters that should be re-applied after forbidden removals.
    forced_on: []const u8,
    /// Locked-off letters that should be removed after forbidden additions.
    forced_off: []const u8,
};

/// Parsed services MLOCK specification over simple channel-mode letters.
pub const LockSpec = struct {
    required_on: ModeLetters = .empty(),
    required_off: ModeLetters = .empty(),

    /// Parse a lock specification with default limits.
    pub fn parse(spec: []const u8) ModeLockError!LockSpec {
        return parseWith(.{}, spec);
    }

    /// Parse a lock specification using caller-selected limits.
    pub fn parseWith(comptime params: Params, spec: []const u8) ModeLockError!LockSpec {
        if (spec.len == 0) return error.EmptySpec;
        if (spec.len > params.max_spec_bytes) return error.SpecTooLong;

        var out = LockSpec{};
        var op: ?Operation = null;
        var saw_letter_for_op = false;

        for (spec) |ch| {
            switch (ch) {
                '+' => {
                    if (op != null and !saw_letter_for_op) return error.MissingModeLetter;
                    op = .require_on;
                    saw_letter_for_op = false;
                },
                '-' => {
                    if (op != null and !saw_letter_for_op) return error.MissingModeLetter;
                    op = .require_off;
                    saw_letter_for_op = false;
                },
                else => {
                    const active_op = op orelse return error.MissingOperation;
                    try validateModeLetter(ch);
                    try out.add(active_op, ch);
                    saw_letter_for_op = true;
                },
            }
        }

        if (op != null and !saw_letter_for_op) return error.MissingModeLetter;
        return out;
    }

    /// Render this lock specification into caller-owned storage.
    pub fn format(self: LockSpec, out: []u8) ModeLockError![]const u8 {
        var n: usize = 0;
        if (!self.required_on.isEmpty()) {
            try appendByte(out, &n, '+');
            try appendLetters(out, &n, self.required_on);
        }
        if (!self.required_off.isEmpty()) {
            try appendByte(out, &n, '-');
            try appendLetters(out, &n, self.required_off);
        }
        if (n == 0) return error.EmptySpec;
        return out[0..n];
    }

    /// Return true when a letter is locked on by this spec.
    pub fn locksOn(self: LockSpec, letter: u8) bool {
        return validModeLetter(letter) and self.required_on.has(letter);
    }

    /// Return true when a letter is locked off by this spec.
    pub fn locksOff(self: LockSpec, letter: u8) bool {
        return validModeLetter(letter) and self.required_off.has(letter);
    }

    fn add(self: *LockSpec, op: Operation, letter: u8) ModeLockError!void {
        switch (op) {
            .require_on => {
                if (self.required_on.has(letter)) return error.DuplicateMode;
                if (self.required_off.has(letter)) return error.ConflictingLock;
                self.required_on.set(letter);
            },
            .require_off => {
                if (self.required_off.has(letter)) return error.DuplicateMode;
                if (self.required_on.has(letter)) return error.ConflictingLock;
                self.required_off.set(letter);
            },
        }
    }
};

/// Evaluate one requested channel-mode transition against a lock specification.
pub fn evaluate(spec: LockSpec, letter: u8, turning_on: bool) Decision {
    if (turning_on and spec.locksOff(letter)) return .forbid;
    if (!turning_on and spec.locksOn(letter)) return .forbid;
    return .allow;
}

/// Filter a requested mode delta and collect forced lock corrections.
pub fn enforce(
    spec: LockSpec,
    requested_on: []const u8,
    requested_off: []const u8,
    out_allowed_on: []u8,
    out_allowed_off: []u8,
    out_forced_on: []u8,
    out_forced_off: []u8,
) ModeLockError!Enforcement {
    var allowed_on_len: usize = 0;
    var allowed_off_len: usize = 0;
    var forced_on_len: usize = 0;
    var forced_off_len: usize = 0;

    for (requested_on) |letter| {
        try validateModeLetter(letter);
        switch (evaluate(spec, letter, true)) {
            .allow => try appendUnique(out_allowed_on, &allowed_on_len, letter),
            .forbid => try appendUnique(out_forced_off, &forced_off_len, letter),
            .force_on, .force_off => unreachable,
        }
    }

    for (requested_off) |letter| {
        try validateModeLetter(letter);
        switch (evaluate(spec, letter, false)) {
            .allow => try appendUnique(out_allowed_off, &allowed_off_len, letter),
            .forbid => try appendUnique(out_forced_on, &forced_on_len, letter),
            .force_on, .force_off => unreachable,
        }
    }

    return .{
        .allowed_on = out_allowed_on[0..allowed_on_len],
        .allowed_off = out_allowed_off[0..allowed_off_len],
        .forced_on = out_forced_on[0..forced_on_len],
        .forced_off = out_forced_off[0..forced_off_len],
    };
}

/// Packed set of supported simple mode letters.
pub const ModeLetters = packed struct(u64) {
    a: bool = false,
    b: bool = false,
    c: bool = false,
    d: bool = false,
    e: bool = false,
    f: bool = false,
    g: bool = false,
    h: bool = false,
    i: bool = false,
    j: bool = false,
    k: bool = false,
    l: bool = false,
    m: bool = false,
    n: bool = false,
    o: bool = false,
    p: bool = false,
    q: bool = false,
    r: bool = false,
    s: bool = false,
    t: bool = false,
    u: bool = false,
    v: bool = false,
    w: bool = false,
    x: bool = false,
    y: bool = false,
    z: bool = false,
    reserved: u38 = 0,

    /// Return an empty mode-letter set.
    pub fn empty() ModeLetters {
        return .{};
    }

    /// Return true when no mode letters are present.
    pub fn isEmpty(self: ModeLetters) bool {
        return @as(u64, @bitCast(self)) == 0;
    }

    /// Add one validated lowercase mode letter.
    pub fn set(self: *ModeLetters, letter: u8) void {
        switch (letter) {
            'a' => self.a = true,
            'b' => self.b = true,
            'c' => self.c = true,
            'd' => self.d = true,
            'e' => self.e = true,
            'f' => self.f = true,
            'g' => self.g = true,
            'h' => self.h = true,
            'i' => self.i = true,
            'j' => self.j = true,
            'k' => self.k = true,
            'l' => self.l = true,
            'm' => self.m = true,
            'n' => self.n = true,
            'o' => self.o = true,
            'p' => self.p = true,
            'q' => self.q = true,
            'r' => self.r = true,
            's' => self.s = true,
            't' => self.t = true,
            'u' => self.u = true,
            'v' => self.v = true,
            'w' => self.w = true,
            'x' => self.x = true,
            'y' => self.y = true,
            'z' => self.z = true,
            else => unreachable,
        }
    }

    /// Return true when a validated lowercase mode letter is present.
    pub fn has(self: ModeLetters, letter: u8) bool {
        return switch (letter) {
            'a' => self.a,
            'b' => self.b,
            'c' => self.c,
            'd' => self.d,
            'e' => self.e,
            'f' => self.f,
            'g' => self.g,
            'h' => self.h,
            'i' => self.i,
            'j' => self.j,
            'k' => self.k,
            'l' => self.l,
            'm' => self.m,
            'n' => self.n,
            'o' => self.o,
            'p' => self.p,
            'q' => self.q,
            'r' => self.r,
            's' => self.s,
            't' => self.t,
            'u' => self.u,
            'v' => self.v,
            'w' => self.w,
            'x' => self.x,
            'y' => self.y,
            'z' => self.z,
            else => unreachable,
        };
    }
};

const Operation = enum {
    require_on,
    require_off,
};

const render_order = "imntrspklabcdefghjoquvwxyz";

comptime {
    if (render_order.len != 26) @compileError("mode-lock render order must cover lowercase mode letters");
    for (render_order, 0..) |left, left_index| {
        if (!validModeLetterComptime(left)) @compileError("mode-lock render order has invalid letter");
        for (render_order[left_index + 1 ..]) |right| {
            if (left == right) @compileError("mode-lock render order has duplicate letter");
        }
    }
}

fn appendLetters(out: []u8, n: *usize, letters: ModeLetters) ModeLockError!void {
    for (render_order) |letter| {
        if (letters.has(letter)) try appendByte(out, n, letter);
    }
}

fn appendByte(out: []u8, n: *usize, byte: u8) ModeLockError!void {
    if (n.* >= out.len) return error.OutputTooSmall;
    out[n.*] = byte;
    n.* += 1;
}

fn appendUnique(out: []u8, n: *usize, byte: u8) ModeLockError!void {
    if (std.mem.indexOfScalar(u8, out[0..n.*], byte) != null) return;
    try appendByte(out, n, byte);
}

fn validateModeLetter(letter: u8) ModeLockError!void {
    if (!validModeLetter(letter)) return error.InvalidModeLetter;
}

fn validModeLetter(letter: u8) bool {
    return switch (letter) {
        'a'...'z' => true,
        else => false,
    };
}

fn validModeLetterComptime(comptime letter: u8) bool {
    return switch (letter) {
        'a'...'z' => true,
        else => false,
    };
}

test "parse format round trip keeps locked on and locked off sets" {
    // Arrange
    const allocator = std.testing.allocator;
    const out = try allocator.alloc(u8, 16);
    defer allocator.free(out);

    // Act
    const parsed = try LockSpec.parse("+ntr-kl");
    const rendered = try parsed.format(out);
    const reparsed = try LockSpec.parse(rendered);

    // Assert
    try std.testing.expectEqualStrings("+ntr-kl", rendered);
    try std.testing.expect(reparsed.locksOn('n'));
    try std.testing.expect(reparsed.locksOn('t'));
    try std.testing.expect(reparsed.locksOn('r'));
    try std.testing.expect(reparsed.locksOff('k'));
    try std.testing.expect(reparsed.locksOff('l'));
    try std.testing.expect(!reparsed.locksOn('k'));
}

test "evaluate forbids locked transitions" {
    // Arrange
    const spec = try LockSpec.parse("+nt-k");

    // Act and assert
    try std.testing.expectEqual(Decision.forbid, evaluate(spec, 'n', false));
    try std.testing.expectEqual(Decision.forbid, evaluate(spec, 't', false));
    try std.testing.expectEqual(Decision.forbid, evaluate(spec, 'k', true));
}

test "evaluate allows free and idempotent mode transitions" {
    // Arrange
    const spec = try LockSpec.parse("+nt-k");

    // Act and assert
    try std.testing.expectEqual(Decision.allow, evaluate(spec, 'n', true));
    try std.testing.expectEqual(Decision.allow, evaluate(spec, 'k', false));
    try std.testing.expectEqual(Decision.allow, evaluate(spec, 'm', true));
    try std.testing.expectEqual(Decision.allow, evaluate(spec, 'm', false));
}

test "enforce filters forbidden changes and emits forced corrections" {
    // Arrange
    const allocator = std.testing.allocator;
    const allowed_on = try allocator.alloc(u8, 8);
    defer allocator.free(allowed_on);
    const allowed_off = try allocator.alloc(u8, 8);
    defer allocator.free(allowed_off);
    const forced_on = try allocator.alloc(u8, 8);
    defer allocator.free(forced_on);
    const forced_off = try allocator.alloc(u8, 8);
    defer allocator.free(forced_off);
    const spec = try LockSpec.parse("+nt-k");

    // Act
    const result = try enforce(
        spec,
        "mk",
        "tns",
        allowed_on,
        allowed_off,
        forced_on,
        forced_off,
    );

    // Assert
    try std.testing.expectEqualStrings("m", result.allowed_on);
    try std.testing.expectEqualStrings("s", result.allowed_off);
    try std.testing.expectEqualStrings("tn", result.forced_on);
    try std.testing.expectEqualStrings("k", result.forced_off);
}

test "enforce deduplicates repeated requested corrections" {
    // Arrange
    var allowed_on: [4]u8 = undefined;
    var allowed_off: [4]u8 = undefined;
    var forced_on: [4]u8 = undefined;
    var forced_off: [4]u8 = undefined;
    const spec = try LockSpec.parse("+n-k");

    // Act
    const result = try enforce(spec, "kkm", "nnm", &allowed_on, &allowed_off, &forced_on, &forced_off);

    // Assert
    try std.testing.expectEqualStrings("m", result.allowed_on);
    try std.testing.expectEqualStrings("m", result.allowed_off);
    try std.testing.expectEqualStrings("n", result.forced_on);
    try std.testing.expectEqualStrings("k", result.forced_off);
}

test "parse rejects malformed specifications" {
    // Arrange, act, and assert
    try std.testing.expectError(error.EmptySpec, LockSpec.parse(""));
    try std.testing.expectError(error.MissingOperation, LockSpec.parse("nt"));
    try std.testing.expectError(error.MissingModeLetter, LockSpec.parse("+"));
    try std.testing.expectError(error.MissingModeLetter, LockSpec.parse("+-n"));
    try std.testing.expectError(error.InvalidModeLetter, LockSpec.parse("+N"));
    try std.testing.expectError(error.InvalidModeLetter, LockSpec.parse("+1"));
    try std.testing.expectError(error.DuplicateMode, LockSpec.parse("+nn"));
    try std.testing.expectError(error.ConflictingLock, LockSpec.parse("+n-n"));
    try std.testing.expectError(error.SpecTooLong, LockSpec.parseWith(.{ .max_spec_bytes = 3 }, "+nt-k"));
}

test "format reports output buffer limits" {
    // Arrange
    var out: [3]u8 = undefined;
    const spec = try LockSpec.parse("+nt-k");

    // Act and assert
    try std.testing.expectError(error.OutputTooSmall, spec.format(&out));
}

test "enforce reports output buffer limits and invalid requested letters" {
    // Arrange
    var allowed_on: [1]u8 = undefined;
    var allowed_off: [1]u8 = undefined;
    var forced_on: [1]u8 = undefined;
    var forced_off: [1]u8 = undefined;
    const spec = try LockSpec.parse("+n-k");

    // Act and assert
    try std.testing.expectError(
        error.OutputTooSmall,
        enforce(spec, "mr", "", &allowed_on, &allowed_off, &forced_on, &forced_off),
    );
    try std.testing.expectError(
        error.InvalidModeLetter,
        enforce(spec, "M", "", &allowed_on, &allowed_off, &forced_on, &forced_off),
    );
}

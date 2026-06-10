//! Standalone services MLOCK data model.
//!
//! Services in Orochi are real server commands and numerics, not pseudo-client
//! users. This module intentionally owns only pure parsing and reconciliation:
//! callers keep channel state and emit any resulting MODE replies themselves.
const std = @import("std");

pub const Params = struct {
    max_spec_bytes: usize = 128,
};

pub const MlockError = error{
    EmptySpec,
    SpecTooLong,
    MissingOperation,
    MissingModeLetter,
    InvalidModeLetter,
    DuplicateMode,
    ConflictingMode,
    OutputTooSmall,
};

pub const ModeSet = struct {
    bits: u64 = 0,

    pub fn empty() ModeSet {
        return .{};
    }

    pub fn parse(letters: []const u8) MlockError!ModeSet {
        var out = ModeSet.empty();
        const start: usize = if (letters.len > 0 and letters[0] == '+') 1 else 0;
        for (letters[start..]) |letter| {
            if (out.contains(letter)) return error.DuplicateMode;
            try out.add(letter);
        }
        return out;
    }

    pub fn add(self: *ModeSet, letter: u8) MlockError!void {
        const mask = try bitMask(letter);
        self.bits |= mask;
    }

    pub fn remove(self: *ModeSet, letter: u8) MlockError!void {
        const mask = try bitMask(letter);
        self.bits &= ~mask;
    }

    pub fn contains(self: ModeSet, letter: u8) bool {
        const idx = bitIndex(letter) orelse return false;
        return (self.bits & bitForIndex(idx)) != 0;
    }

    pub fn isEmpty(self: ModeSet) bool {
        return self.bits == 0;
    }

    pub fn count(self: ModeSet) usize {
        return @intCast(@popCount(self.bits));
    }

    pub fn eql(self: ModeSet, other: ModeSet) bool {
        return self.bits == other.bits;
    }

    pub fn unionWith(self: *ModeSet, other: ModeSet) void {
        self.bits |= other.bits;
    }

    pub fn subtract(self: *ModeSet, other: ModeSet) void {
        self.bits &= ~other.bits;
    }

    pub fn intersect(self: ModeSet, other: ModeSet) ModeSet {
        return .{ .bits = self.bits & other.bits };
    }

    pub fn without(self: ModeSet, other: ModeSet) ModeSet {
        return .{ .bits = self.bits & ~other.bits };
    }

    pub fn format(self: ModeSet, out: []u8) MlockError![]const u8 {
        var n: usize = 0;
        try appendLetters(out, &n, self);
        return out[0..n];
    }
};

pub const LockSpec = struct {
    locked_on: ModeSet = .{},
    locked_off: ModeSet = .{},

    pub fn parse(spec: []const u8) MlockError!LockSpec {
        return parseWith(.{}, spec);
    }

    pub fn parseWith(comptime params: Params, spec: []const u8) MlockError!LockSpec {
        if (spec.len == 0) return error.EmptySpec;
        if (spec.len > params.max_spec_bytes) return error.SpecTooLong;

        var out = LockSpec{};
        var op: ?LockOp = null;
        var saw_letter_for_op = false;

        for (spec) |ch| {
            switch (ch) {
                '+' => {
                    if (op != null and !saw_letter_for_op) return error.MissingModeLetter;
                    op = .on;
                    saw_letter_for_op = false;
                },
                '-' => {
                    if (op != null and !saw_letter_for_op) return error.MissingModeLetter;
                    op = .off;
                    saw_letter_for_op = false;
                },
                else => {
                    const active_op = op orelse return error.MissingOperation;
                    try out.add(active_op, ch);
                    saw_letter_for_op = true;
                },
            }
        }

        if (op != null and !saw_letter_for_op) return error.MissingModeLetter;
        return out;
    }

    pub fn locksOn(self: LockSpec, letter: u8) bool {
        return self.locked_on.contains(letter);
    }

    pub fn locksOff(self: LockSpec, letter: u8) bool {
        return self.locked_off.contains(letter);
    }

    pub fn format(self: LockSpec, out: []u8) MlockError![]const u8 {
        var n: usize = 0;
        if (!self.locked_on.isEmpty()) {
            try appendByte(out, &n, '+');
            try appendLetters(out, &n, self.locked_on);
        }
        if (!self.locked_off.isEmpty()) {
            try appendByte(out, &n, '-');
            try appendLetters(out, &n, self.locked_off);
        }
        if (n == 0) return error.EmptySpec;
        return out[0..n];
    }

    fn add(self: *LockSpec, op: LockOp, letter: u8) MlockError!void {
        _ = try bitMask(letter);
        switch (op) {
            .on => {
                if (self.locked_on.contains(letter)) return error.DuplicateMode;
                if (self.locked_off.contains(letter)) return error.ConflictingMode;
                try self.locked_on.add(letter);
            },
            .off => {
                if (self.locked_off.contains(letter)) return error.DuplicateMode;
                if (self.locked_on.contains(letter)) return error.ConflictingMode;
                try self.locked_off.add(letter);
            },
        }
    }
};

pub const ModeDelta = struct {
    add: ModeSet = .{},
    remove: ModeSet = .{},

    pub fn isEmpty(self: ModeDelta) bool {
        return self.add.isEmpty() and self.remove.isEmpty();
    }

    pub fn format(self: ModeDelta, out: []u8) MlockError![]const u8 {
        var n: usize = 0;
        if (!self.add.isEmpty()) {
            try appendByte(out, &n, '+');
            try appendLetters(out, &n, self.add);
        }
        if (!self.remove.isEmpty()) {
            try appendByte(out, &n, '-');
            try appendLetters(out, &n, self.remove);
        }
        return out[0..n];
    }
};

pub fn reconcile(current: ModeSet, lock: LockSpec) ModeDelta {
    return .{
        .add = lock.locked_on.without(current),
        .remove = current.intersect(lock.locked_off),
    };
}

pub fn apply(current: ModeSet, lock: LockSpec) ModeSet {
    var out = current;
    out.unionWith(lock.locked_on);
    out.subtract(lock.locked_off);
    return out;
}

const LockOp = enum {
    on,
    off,
};

const render_order = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

comptime {
    @setEvalBranchQuota(4096);
    if (render_order.len != 52) @compileError("MLOCK render order must cover A-Z and a-z");
    for (render_order, 0..) |left, left_index| {
        if (bitIndexComptime(left) == null) @compileError("MLOCK render order has invalid letter");
        for (render_order[left_index + 1 ..]) |right| {
            if (left == right) @compileError("MLOCK render order has duplicate letter");
        }
    }
}

fn appendLetters(out: []u8, n: *usize, set: ModeSet) MlockError!void {
    for (render_order) |letter| {
        if (set.contains(letter)) try appendByte(out, n, letter);
    }
}

fn appendByte(out: []u8, n: *usize, byte: u8) MlockError!void {
    if (n.* >= out.len) return error.OutputTooSmall;
    out[n.*] = byte;
    n.* += 1;
}

fn bitMask(letter: u8) MlockError!u64 {
    const idx = bitIndex(letter) orelse return error.InvalidModeLetter;
    return bitForIndex(idx);
}

fn bitForIndex(idx: u6) u64 {
    return @as(u64, 1) << idx;
}

fn bitIndex(letter: u8) ?u6 {
    return switch (letter) {
        'A'...'Z' => @intCast(letter - 'A'),
        'a'...'z' => @intCast(26 + letter - 'a'),
        else => null,
    };
}

fn bitIndexComptime(comptime letter: u8) ?u6 {
    return switch (letter) {
        'A'...'Z' => @intCast(letter - 'A'),
        'a'...'z' => @intCast(26 + letter - 'a'),
        else => null,
    };
}

test "parse lock spec separates locked on and locked off letters" {
    const spec = try LockSpec.parse("+nt-k");

    try std.testing.expect(spec.locksOn('n'));
    try std.testing.expect(spec.locksOn('t'));
    try std.testing.expect(spec.locksOff('k'));
    try std.testing.expect(!spec.locksOn('k'));
    try std.testing.expect(!spec.locksOff('n'));
}

test "parse supports repeated operators after at least one letter" {
    const spec = try LockSpec.parse("+n+t-k");
    var out: [8]u8 = undefined;

    try std.testing.expectEqualStrings("+nt-k", try spec.format(&out));
}

test "parse preserves case-sensitive channel mode letters" {
    const spec = try LockSpec.parse("+CM-S");

    try std.testing.expect(spec.locksOn('C'));
    try std.testing.expect(spec.locksOn('M'));
    try std.testing.expect(spec.locksOff('S'));
    try std.testing.expect(!spec.locksOn('c'));
    try std.testing.expect(!spec.locksOff('s'));
}

test "parse rejects malformed lock specifications" {
    try std.testing.expectError(error.EmptySpec, LockSpec.parse(""));
    try std.testing.expectError(error.MissingOperation, LockSpec.parse("nt"));
    try std.testing.expectError(error.MissingModeLetter, LockSpec.parse("+"));
    try std.testing.expectError(error.MissingModeLetter, LockSpec.parse("+-n"));
    try std.testing.expectError(error.MissingModeLetter, LockSpec.parse("+n-"));
    try std.testing.expectError(error.MissingModeLetter, LockSpec.parse("++n"));
    try std.testing.expectError(error.InvalidModeLetter, LockSpec.parse("+1"));
    try std.testing.expectError(error.InvalidModeLetter, LockSpec.parse("+_"));
    try std.testing.expectError(error.SpecTooLong, LockSpec.parseWith(.{ .max_spec_bytes = 3 }, "+nt-k"));
}

test "parse rejects duplicate and conflicting lock letters" {
    try std.testing.expectError(error.DuplicateMode, LockSpec.parse("+nn"));
    try std.testing.expectError(error.DuplicateMode, LockSpec.parse("-kk"));
    try std.testing.expectError(error.ConflictingMode, LockSpec.parse("+n-n"));
    try std.testing.expectError(error.ConflictingMode, LockSpec.parse("-k+k"));
}

test "format renders canonical lock spec order" {
    const spec = try LockSpec.parse("+tn-SC");
    var out: [16]u8 = undefined;

    try std.testing.expectEqualStrings("+nt-CS", try spec.format(&out));
}

test "format reports output buffer limits" {
    const spec = try LockSpec.parse("+nt-k");
    var out: [4]u8 = undefined;

    try std.testing.expectError(error.OutputTooSmall, spec.format(&out));
}

test "mode set parses optional plus-prefixed current modes" {
    const set = try ModeSet.parse("+ntC");

    try std.testing.expect(set.contains('n'));
    try std.testing.expect(set.contains('t'));
    try std.testing.expect(set.contains('C'));
    try std.testing.expect(!set.contains('c'));
    try std.testing.expectEqual(@as(usize, 3), set.count());
}

test "mode set rejects invalid and duplicate current mode letters" {
    try std.testing.expectError(error.InvalidModeLetter, ModeSet.parse("-nt"));
    try std.testing.expectError(error.InvalidModeLetter, ModeSet.parse("n t"));
    try std.testing.expectError(error.DuplicateMode, ModeSet.parse("nn"));
}

test "mode set formats all supported letters without allocation" {
    const all_letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    const set = try ModeSet.parse(all_letters);
    var out: [64]u8 = undefined;

    try std.testing.expectEqual(@as(usize, 52), set.count());
    try std.testing.expectEqualStrings(all_letters, try set.format(&out));
}

test "reconcile computes add and remove delta for current modes" {
    const current = try ModeSet.parse("km");
    const spec = try LockSpec.parse("+nt-k");
    const delta = reconcile(current, spec);
    var out: [8]u8 = undefined;

    try std.testing.expect(delta.add.contains('n'));
    try std.testing.expect(delta.add.contains('t'));
    try std.testing.expect(delta.remove.contains('k'));
    try std.testing.expect(!delta.remove.contains('m'));
    try std.testing.expectEqualStrings("+nt-k", try delta.format(&out));
}

test "reconcile is empty when current modes already satisfy lock" {
    const current = try ModeSet.parse("mnt");
    const spec = try LockSpec.parse("+nt-k");
    const delta = reconcile(current, spec);
    var out: [1]u8 = undefined;

    try std.testing.expect(delta.isEmpty());
    try std.testing.expectEqualStrings("", try delta.format(&out));
}

test "reconcile only removes locked-off modes that are currently set" {
    const current = try ModeSet.parse("mn");
    const spec = try LockSpec.parse("+n-kl");
    const delta = reconcile(current, spec);
    var out: [4]u8 = undefined;

    try std.testing.expect(delta.isEmpty());
    try std.testing.expectEqualStrings("", try delta.format(&out));
}

test "apply returns the channel modes after enforcing the lock" {
    const current = try ModeSet.parse("km");
    const spec = try LockSpec.parse("+nt-k");
    const applied = apply(current, spec);
    var out: [8]u8 = undefined;

    try std.testing.expect(applied.contains('m'));
    try std.testing.expect(applied.contains('n'));
    try std.testing.expect(applied.contains('t'));
    try std.testing.expect(!applied.contains('k'));
    try std.testing.expectEqualStrings("mnt", try applied.format(&out));
}

test "mode set mutation validates letters" {
    var set = ModeSet.empty();

    try set.add('n');
    try std.testing.expect(set.contains('n'));
    try set.remove('n');
    try std.testing.expect(!set.contains('n'));
    try std.testing.expectError(error.InvalidModeLetter, set.add('1'));
    try std.testing.expectError(error.InvalidModeLetter, set.remove('-'));
}

test "delta formatter reports output limits" {
    const current = try ModeSet.parse("k");
    const spec = try LockSpec.parse("+nt-k");
    const delta = reconcile(current, spec);
    var out: [4]u8 = undefined;

    try std.testing.expectError(error.OutputTooSmall, delta.format(&out));
}

//! Atheme-style per-channel FLAGS access model for Orochi.
//!
//! This complements the IRCX ACCESS list (`src/proto/ircx_access_store.zig`),
//! which assigns exactly one discrete `Level` per mask, and the unified
//! `scoped_access.zig` grant/restriction store. The FLAGS model instead grants
//! each (channel, target) pair an arbitrary *set* of capabilities drawn from a
//! fixed alphabet, mutated incrementally through `+flag`/`-flag` spec strings
//! (for example "+ov-h").
//!
//! `target` is an opaque, caller-defined identity string: an account name
//! (e.g. "alice") or a hostmask (e.g. "*!*@trusted.test"). This module does not
//! interpret targets, it only stores and compares them case-insensitively, so
//! it works for both the account-based and mask-based FLAGS conventions.
//!
//! This file is pure logic + tests. It imports only `std`.

const std = @import("std");

/// Fixed FLAGS alphabet. Each variant maps to exactly one lowercase ASCII
/// letter in the spec wire format. The set is modelled as a bitset over these.
pub const Flag = enum(u4) {
    voice = 0, // v: grant +v on join
    op = 1, // o: grant +o on join
    halfop = 2, // h: grant +h on join
    autoop = 3, // a: auto-reop on rejoin
    owner = 4, // q: channel owner (+q)
    founder = 5, // f: channel founder (full control)
    topic = 6, // t: may change topic
    recover = 7, // r: may RECOVER/seize the channel
    invite = 8, // i: may self-invite past +i
    akick_exempt = 9, // b: exempt from automated kick/ban

    /// Inclusive count of defined flags; doubles as the bitset width bound.
    pub const count: usize = @typeInfo(Flag).@"enum".fields.len;

    /// The single lowercase letter used in spec strings for this flag.
    pub fn letter(self: Flag) u8 {
        return switch (self) {
            .voice => 'v',
            .op => 'o',
            .halfop => 'h',
            .autoop => 'a',
            .owner => 'q',
            .founder => 'f',
            .topic => 't',
            .recover => 'r',
            .invite => 'i',
            .akick_exempt => 'b',
        };
    }

    /// Parse a single spec letter (case-insensitive) into a `Flag`.
    pub fn fromLetter(byte: u8) ?Flag {
        const lower = std.ascii.toLower(byte);
        return switch (lower) {
            'v' => .voice,
            'o' => .op,
            'h' => .halfop,
            'a' => .autoop,
            'q' => .owner,
            'f' => .founder,
            't' => .topic,
            'r' => .recover,
            'i' => .invite,
            'b' => .akick_exempt,
            else => null,
        };
    }
};

/// An immutable bitset over the `Flag` alphabet. All mutating helpers return a
/// new value rather than modifying the receiver (immutable style).
pub const FlagSet = struct {
    bits: u16 = 0,

    pub const empty: FlagSet = .{ .bits = 0 };

    fn mask(flag: Flag) u16 {
        return @as(u16, 1) << @intFromEnum(flag);
    }

    pub fn isEmpty(self: FlagSet) bool {
        return self.bits == 0;
    }

    pub fn has(self: FlagSet, flag: Flag) bool {
        return (self.bits & mask(flag)) != 0;
    }

    pub fn with(self: FlagSet, flag: Flag) FlagSet {
        return .{ .bits = self.bits | mask(flag) };
    }

    pub fn without(self: FlagSet, flag: Flag) FlagSet {
        return .{ .bits = self.bits & ~mask(flag) };
    }

    pub fn eql(self: FlagSet, other: FlagSet) bool {
        return self.bits == other.bits;
    }

    pub fn count(self: FlagSet) usize {
        return @popCount(self.bits);
    }

    /// Render the set as its canonical sorted letter sequence (alphabet order)
    /// into `out`. Returns the written slice. `out` must hold at least
    /// `Flag.count` bytes or `error.OutputTooSmall` is returned.
    pub fn render(self: FlagSet, out: []u8) SpecError![]const u8 {
        if (out.len < Flag.count) return error.OutputTooSmall;
        var len: usize = 0;
        inline for (@typeInfo(Flag).@"enum".fields) |field| {
            const flag: Flag = @enumFromInt(field.value);
            if (self.has(flag)) {
                out[len] = flag.letter();
                len += 1;
            }
        }
        return out[0..len];
    }
};

pub const SpecError = error{
    EmptySpec,
    UnknownFlag,
    DanglingSign,
    OutputTooSmall,
};

pub const StoreError = SpecError || std.mem.Allocator.Error || error{
    InvalidChannel,
    InvalidTarget,
    TooManyEntries,
    OutputTooSmall,
};

/// Result of applying a spec to a base set: a normalised add/remove delta plus
/// the resulting set.
pub const SpecDelta = struct {
    /// Flags switched on by the spec (relative to the alphabet, not the base).
    added: FlagSet = .empty,
    /// Flags switched off by the spec.
    removed: FlagSet = .empty,
    /// `base` with `added` applied then `removed` cleared.
    result: FlagSet = .empty,
};

/// Parse a `+/-flag` spec string against a base set, returning the delta and
/// resulting set without touching any storage.
///
/// Rules:
/// - A leading sign is required conceptually but a bare run of letters is
///   treated as additions (Atheme accepts "ov" == "+ov").
/// - Signs may alternate any number of times ("+ov-h+t").
/// - A sign with no following letters ("+", "ab+") is `DanglingSign`.
/// - An unrecognised letter is `UnknownFlag`.
/// - An empty spec is `EmptySpec`.
/// - If a flag appears under both signs, the last occurrence wins.
pub fn applySpec(base: FlagSet, spec: []const u8) SpecError!SpecDelta {
    if (spec.len == 0) return error.EmptySpec;

    var result = base;
    var added: FlagSet = .empty;
    var removed: FlagSet = .empty;

    var adding = true; // default polarity when no explicit sign yet
    var saw_letter_since_sign = true; // first run needs no sign
    var explicit_sign = false;

    for (spec) |byte| {
        switch (byte) {
            '+' => {
                if (explicit_sign and !saw_letter_since_sign) return error.DanglingSign;
                adding = true;
                explicit_sign = true;
                saw_letter_since_sign = false;
            },
            '-' => {
                if (explicit_sign and !saw_letter_since_sign) return error.DanglingSign;
                adding = false;
                explicit_sign = true;
                saw_letter_since_sign = false;
            },
            else => {
                const flag = Flag.fromLetter(byte) orelse return error.UnknownFlag;
                saw_letter_since_sign = true;
                if (adding) {
                    result = result.with(flag);
                    added = added.with(flag);
                    removed = removed.without(flag); // last occurrence wins
                } else {
                    result = result.without(flag);
                    removed = removed.with(flag);
                    added = added.without(flag);
                }
            },
        }
    }

    // A trailing sign with no letters is dangling.
    if (explicit_sign and !saw_letter_since_sign) return error.DanglingSign;

    return .{ .added = added, .removed = removed, .result = result };
}

const Entry = struct {
    channel: []u8,
    target: []u8,
    flags: FlagSet,
};

/// A single view of one stored (channel, target, flags) row. The string fields
/// borrow store-owned memory and are valid until the next mutation.
pub const EntryView = struct {
    channel: []const u8,
    target: []const u8,
    flags: FlagSet,
};

pub const DEFAULT_MAX_ENTRIES: usize = 512;
pub const DEFAULT_MAX_CHANNEL_BYTES: usize = 128;
pub const DEFAULT_MAX_TARGET_BYTES: usize = 128;

/// Per-(channel, target) FLAGS store. Mirrors the shape of `AccessStore`:
/// entries own their strings, every mutating call takes the store's allocator.
pub const ChannelFlags = struct {
    allocator: std.mem.Allocator,
    entries: std.ArrayListUnmanaged(Entry) = .empty,
    max_entries: usize = DEFAULT_MAX_ENTRIES,

    pub fn init(allocator: std.mem.Allocator) ChannelFlags {
        return .{ .allocator = allocator };
    }

    pub fn initWith(allocator: std.mem.Allocator, max_entries: usize) ChannelFlags {
        return .{ .allocator = allocator, .max_entries = max_entries };
    }

    pub fn deinit(self: *ChannelFlags) void {
        for (self.entries.items) |entry| freeEntry(self.allocator, entry);
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    /// Apply a `+/-flag` spec to (channel, target), returning the resulting
    /// flag set. Creating an entry, updating it, or dropping it to empty are
    /// all handled here.
    ///
    /// - If the target had no entry, the spec is applied against `.empty`.
    /// - If the resulting set is empty, the entry is removed (or never created).
    pub fn applyFlagSpec(
        self: *ChannelFlags,
        channel: []const u8,
        target: []const u8,
        spec: []const u8,
    ) StoreError!FlagSet {
        try validateChannel(channel);
        try validateTarget(target);

        const existing = self.findIndex(channel, target);
        const base: FlagSet = if (existing) |idx| self.entries.items[idx].flags else .empty;

        const delta = try applySpec(base, spec);

        if (existing) |idx| {
            if (delta.result.isEmpty()) {
                const removed = self.entries.orderedRemove(idx);
                freeEntry(self.allocator, removed);
            } else {
                self.entries.items[idx].flags = delta.result;
            }
            return delta.result;
        }

        // No existing entry. Nothing to persist if the result is empty.
        if (delta.result.isEmpty()) return delta.result;
        if (self.entries.items.len >= self.max_entries) return error.TooManyEntries;

        const channel_copy = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(channel_copy);
        const target_copy = try self.allocator.dupe(u8, target);
        errdefer self.allocator.free(target_copy);

        try self.entries.append(self.allocator, .{
            .channel = channel_copy,
            .target = target_copy,
            .flags = delta.result,
        });
        return delta.result;
    }

    /// Return the flag set for (channel, target), or `.empty` if no entry
    /// exists.
    pub fn flagsFor(self: *const ChannelFlags, channel: []const u8, target: []const u8) FlagSet {
        if (self.findIndex(channel, target)) |idx| return self.entries.items[idx].flags;
        return .empty;
    }

    /// Remove the entry for (channel, target). Returns true if one existed.
    pub fn remove(self: *ChannelFlags, channel: []const u8, target: []const u8) bool {
        const idx = self.findIndex(channel, target) orelse return false;
        const removed = self.entries.orderedRemove(idx);
        freeEntry(self.allocator, removed);
        return true;
    }

    /// Write every entry for `channel` into `out` (insertion order). Returns the
    /// populated prefix. `error.OutputTooSmall` if `out` cannot hold them all.
    pub fn listFor(
        self: *const ChannelFlags,
        channel: []const u8,
        out: []EntryView,
    ) StoreError![]const EntryView {
        var count: usize = 0;
        for (self.entries.items) |*entry| {
            if (!std.ascii.eqlIgnoreCase(entry.channel, channel)) continue;
            if (count >= out.len) return error.OutputTooSmall;
            out[count] = .{
                .channel = entry.channel,
                .target = entry.target,
                .flags = entry.flags,
            };
            count += 1;
        }
        return out[0..count];
    }

    /// Number of entries for `channel`.
    pub fn countFor(self: *const ChannelFlags, channel: []const u8) usize {
        var n: usize = 0;
        for (self.entries.items) |*entry| {
            if (std.ascii.eqlIgnoreCase(entry.channel, channel)) n += 1;
        }
        return n;
    }

    fn findIndex(self: *const ChannelFlags, channel: []const u8, target: []const u8) ?usize {
        for (self.entries.items, 0..) |entry, idx| {
            if (std.ascii.eqlIgnoreCase(entry.channel, channel) and
                std.ascii.eqlIgnoreCase(entry.target, target))
            {
                return idx;
            }
        }
        return null;
    }
};

fn freeEntry(allocator: std.mem.Allocator, entry: Entry) void {
    allocator.free(entry.channel);
    allocator.free(entry.target);
}

fn validateChannel(channel: []const u8) StoreError!void {
    if (channel.len == 0 or channel.len > DEFAULT_MAX_CHANNEL_BYTES) return error.InvalidChannel;
    switch (channel[0]) {
        '#', '&', '%', '+' => {},
        else => return error.InvalidChannel,
    }
    for (channel) |byte| {
        switch (byte) {
            ' ', ',', 0, '\r', '\n', 7 => return error.InvalidChannel,
            else => {},
        }
    }
}

fn validateTarget(target: []const u8) StoreError!void {
    if (target.len == 0 or target.len > DEFAULT_MAX_TARGET_BYTES) return error.InvalidTarget;
    if (target[0] == ':') return error.InvalidTarget;
    for (target) |byte| {
        switch (byte) {
            ' ', ',', 0, '\r', '\n' => return error.InvalidTarget,
            else => {},
        }
    }
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

test "Flag letter round-trips through fromLetter for whole alphabet" {
    inline for (@typeInfo(Flag).@"enum".fields) |field| {
        const flag: Flag = @enumFromInt(field.value);
        const letter = flag.letter();
        try std.testing.expectEqual(@as(?Flag, flag), Flag.fromLetter(letter));
        // Case-insensitive on input.
        try std.testing.expectEqual(@as(?Flag, flag), Flag.fromLetter(std.ascii.toUpper(letter)));
    }
    try std.testing.expectEqual(@as(usize, 10), Flag.count);
}

test "applySpec parses additive run and explicit signs" {
    // Bare run is additive.
    const a = try applySpec(.empty, "ov");
    try std.testing.expect(a.result.has(.op));
    try std.testing.expect(a.result.has(.voice));
    try std.testing.expectEqual(@as(usize, 2), a.result.count());

    // Explicit alternating signs: +ov-h+t against empty.
    const b = try applySpec(.empty, "+ov-h+t");
    try std.testing.expect(b.result.has(.op));
    try std.testing.expect(b.result.has(.voice));
    try std.testing.expect(b.result.has(.topic));
    try std.testing.expect(!b.result.has(.halfop));
    // -h removed nothing from empty base but is recorded as removed.
    try std.testing.expect(b.removed.has(.halfop));
    try std.testing.expect(b.added.has(.op));
}

test "applySpec accumulates onto a base set" {
    const base = FlagSet.empty.with(.op).with(.halfop);
    // Remove h, add v.
    const d = try applySpec(base, "-h+v");
    try std.testing.expect(d.result.has(.op));
    try std.testing.expect(d.result.has(.voice));
    try std.testing.expect(!d.result.has(.halfop));
    try std.testing.expectEqual(@as(usize, 2), d.result.count());
}

test "applySpec last occurrence of a flag wins" {
    const d = try applySpec(.empty, "+o-o");
    try std.testing.expect(!d.result.has(.op));
    try std.testing.expect(d.removed.has(.op));
    try std.testing.expect(!d.added.has(.op));

    const d2 = try applySpec(.empty, "-o+o");
    try std.testing.expect(d2.result.has(.op));
    try std.testing.expect(d2.added.has(.op));
    try std.testing.expect(!d2.removed.has(.op));
}

test "applySpec rejects unknown flag, empty spec, and dangling sign" {
    try std.testing.expectError(error.UnknownFlag, applySpec(.empty, "+oz"));
    try std.testing.expectError(error.UnknownFlag, applySpec(.empty, "x"));
    try std.testing.expectError(error.EmptySpec, applySpec(.empty, ""));
    try std.testing.expectError(error.DanglingSign, applySpec(.empty, "+"));
    try std.testing.expectError(error.DanglingSign, applySpec(.empty, "+o-"));
    try std.testing.expectError(error.DanglingSign, applySpec(.empty, "+o+-v"));
}

test "FlagSet render emits canonical alphabet order" {
    var buf: [Flag.count]u8 = undefined;
    // Insert in reverse-ish order, expect alphabet order: v,o,h,a,q,f,t,r,i,b.
    const set = FlagSet.empty.with(.topic).with(.voice).with(.op);
    const rendered = try set.render(&buf);
    // voice(v) value 0, op(o) value 1, topic(t) value 6 -> "vot"
    try std.testing.expectEqualStrings("vot", rendered);

    var tiny: [2]u8 = undefined;
    try std.testing.expectError(error.OutputTooSmall, set.render(&tiny));
}

test "ChannelFlags applyFlagSpec creates, accumulates, and reports" {
    var store = ChannelFlags.init(std.testing.allocator);
    defer store.deinit();

    const r1 = try store.applyFlagSpec("#zig", "alice", "+ov");
    try std.testing.expectEqual(@as(usize, 2), r1.count());
    try std.testing.expect(store.flagsFor("#zig", "alice").has(.op));

    // Accumulate: add halfop, remove voice.
    const r2 = try store.applyFlagSpec("#zig", "alice", "+h-v");
    try std.testing.expect(r2.has(.op));
    try std.testing.expect(r2.has(.halfop));
    try std.testing.expect(!r2.has(.voice));
    // Case-insensitive channel + target lookup.
    try std.testing.expect(store.flagsFor("#ZIG", "ALICE").has(.halfop));

    try std.testing.expectEqual(@as(usize, 1), store.countFor("#zig"));
}

test "ChannelFlags removal-to-empty drops the entry" {
    var store = ChannelFlags.init(std.testing.allocator);
    defer store.deinit();

    _ = try store.applyFlagSpec("#zig", "bob", "+o");
    try std.testing.expectEqual(@as(usize, 1), store.countFor("#zig"));

    // Removing the only flag empties the set and must drop the row.
    const r = try store.applyFlagSpec("#zig", "bob", "-o");
    try std.testing.expect(r.isEmpty());
    try std.testing.expectEqual(@as(usize, 0), store.countFor("#zig"));
    try std.testing.expect(store.flagsFor("#zig", "bob").isEmpty());

    // Applying a net-empty spec to a missing target creates nothing.
    const r2 = try store.applyFlagSpec("#zig", "carol", "+o-o");
    try std.testing.expect(r2.isEmpty());
    try std.testing.expectEqual(@as(usize, 0), store.countFor("#zig"));
}

test "ChannelFlags explicit remove and listFor" {
    var store = ChannelFlags.init(std.testing.allocator);
    defer store.deinit();

    _ = try store.applyFlagSpec("#zig", "alice", "+o");
    _ = try store.applyFlagSpec("#zig", "*!*@trusted.test", "+vt");
    _ = try store.applyFlagSpec("#other", "alice", "+f");

    var views: [8]EntryView = undefined;
    const listed = try store.listFor("#zig", &views);
    try std.testing.expectEqual(@as(usize, 2), listed.len);
    try std.testing.expectEqualStrings("alice", listed[0].target);
    try std.testing.expectEqualStrings("*!*@trusted.test", listed[1].target);

    try std.testing.expect(store.remove("#zig", "alice"));
    try std.testing.expect(!store.remove("#zig", "alice")); // already gone
    try std.testing.expectEqual(@as(usize, 1), store.countFor("#zig"));
    // #other untouched.
    try std.testing.expect(store.flagsFor("#other", "alice").has(.founder));
}

test "ChannelFlags enforces bounds and validates inputs" {
    var tiny = ChannelFlags.initWith(std.testing.allocator, 1);
    defer tiny.deinit();

    _ = try tiny.applyFlagSpec("#zig", "alice", "+o");
    try std.testing.expectError(error.TooManyEntries, tiny.applyFlagSpec("#zig", "bob", "+o"));

    // Updating an existing entry does not hit the entry cap.
    _ = try tiny.applyFlagSpec("#zig", "alice", "+v");
    try std.testing.expectEqual(@as(usize, 2), tiny.flagsFor("#zig", "alice").count());

    try std.testing.expectError(error.InvalidChannel, tiny.applyFlagSpec("zig", "alice", "+o"));
    try std.testing.expectError(error.InvalidChannel, tiny.applyFlagSpec("", "alice", "+o"));
    try std.testing.expectError(error.InvalidTarget, tiny.applyFlagSpec("#zig", "", "+o"));
    try std.testing.expectError(error.InvalidTarget, tiny.applyFlagSpec("#zig", "bad target", "+o"));

    // listFor output bound.
    var none: [0]EntryView = undefined;
    try std.testing.expectError(error.OutputTooSmall, tiny.listFor("#zig", &none));
}

test "FlagSet immutable helpers do not mutate the receiver" {
    const base = FlagSet.empty.with(.op);
    const more = base.with(.voice);
    try std.testing.expect(!base.has(.voice)); // base unchanged
    try std.testing.expect(more.has(.voice));
    const less = more.without(.op);
    try std.testing.expect(more.has(.op)); // more unchanged
    try std.testing.expect(!less.has(.op));
    try std.testing.expect(base.eql(FlagSet.empty.with(.op)));
}

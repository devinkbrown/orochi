//! Mizuchi oper server-notice masks (snomask) — a pure, allocation-free bitset
//! over server-notice categories plus a small `+/-` spec parser.
//!
//! A snomask is an operator's *subscription set* over the categories of notice
//! the daemon emits: connects, kills, flood, nick changes, oper actions, spam /
//! filter hits, debug, xline activity, globops, and botnet detections. Each
//! category has a stable, lower-case letter; an oper's mask renders to a
//! `+letters` string and is mutated by specs such as `+ck-f` or `+ckn`.
//!
//! This module is deliberately self-contained: it imports only `std`, owns no
//! storage, and operates on a `SnoMask` value the caller passes in. It does not
//! deliver notices, track subscribers, or touch the Event Spine — those layers
//! live elsewhere (`snote_router.zig`, `event_spine.zig`). The job here is the
//! letter vocabulary, the bitset, and the spec grammar, nothing more.
//!
//! Spec grammar (`applySpec`):
//!
//!   * A leading sign (`+` or `-`) opens an *additive run*: every category letter
//!     that follows is added (or removed) until the next sign flips the run.
//!   * With no leading sign the run defaults to addition, so `ck` == `+ck`.
//!   * Letters are matched case-insensitively against the category table.
//!   * An unknown letter aborts the whole spec with `error.UnknownLetter`; the
//!     base mask is returned unchanged so a bad spec is never partially applied.
//!   * A trailing sign with no following letter is a no-op for that run.

const std = @import("std");

/// The fixed vocabulary of server-notice categories an oper may subscribe to.
///
/// The enum's integer value is its bit position in `SnoMask`; the order here is
/// also the canonical render order for `render`, so keep additions append-only.
pub const Category = enum(u4) {
    /// `c` — client connections.
    connect = 0,
    /// `k` — KILLs.
    kill = 1,
    /// `f` — flood / throttling notices.
    flood = 2,
    /// `n` — nick changes.
    nick_change = 3,
    /// `o` — operator actions (OPER, MODE by oper, etc.).
    oper_action = 4,
    /// `s` — spam / filter hits.
    spam = 5,
    /// `d` — debug notices.
    debug = 6,
    /// `x` — xline (ban list) activity.
    xline = 7,
    /// `g` — globops.
    globops = 8,
    /// `b` — botnet detections.
    botnet = 9,

    /// The letter that names this category in a spec or rendered mask.
    pub fn letter(self: Category) u8 {
        return switch (self) {
            .connect => 'c',
            .kill => 'k',
            .flood => 'f',
            .nick_change => 'n',
            .oper_action => 'o',
            .spam => 's',
            .debug => 'd',
            .xline => 'x',
            .globops => 'g',
            .botnet => 'b',
        };
    }

    /// The category for `ch`, matched case-insensitively, or null if unknown.
    pub fn fromLetter(ch: u8) ?Category {
        const lower = std.ascii.toLower(ch);
        inline for (ALL) |category| {
            if (category.letter() == lower) return category;
        }
        return null;
    }
};

/// Every category in canonical (render) order.
pub const ALL = [_]Category{
    .connect, .kill,    .flood,   .nick_change, .oper_action,
    .spam,    .debug,   .xline,   .globops,     .botnet,
};

/// Upper bound on the body of a rendered mask (one byte per category). Callers
/// sizing a buffer should add 1 for the leading `+`.
pub const MAX_LETTERS: usize = ALL.len;

comptime {
    if (ALL.len > @bitSizeOf(Backing)) @compileError("too many categories for SnoMask backing int");
}

/// Unsigned integer wide enough to hold one bit per category.
const Backing = u16;

pub const Error = error{
    /// A spec named a letter outside the category vocabulary.
    UnknownLetter,
    /// `renderBuf` was handed a buffer smaller than the rendered mask.
    OutputTooSmall,
};

/// An operator's server-notice subscription set: a pure bitset over `Category`.
///
/// Construct with `empty`, `full`, `only`, or `fromCategories`; mutate via the
/// returned-copy helpers (`with`, `without`, `applySpec`) — every operation is
/// immutable and returns a fresh value, leaving the input untouched.
pub const SnoMask = struct {
    bits: Backing = 0,

    /// The empty mask — subscribed to nothing.
    pub fn empty() SnoMask {
        return .{ .bits = 0 };
    }

    /// The mask subscribed to every category.
    pub fn full() SnoMask {
        var mask = SnoMask.empty();
        inline for (ALL) |category| mask = mask.with(category);
        return mask;
    }

    /// A mask subscribed to exactly `category`.
    pub fn only(category: Category) SnoMask {
        return SnoMask.empty().with(category);
    }

    /// A mask subscribed to each category in `categories`.
    pub fn fromCategories(categories: []const Category) SnoMask {
        var mask = SnoMask.empty();
        for (categories) |category| mask = mask.with(category);
        return mask;
    }

    fn bit(category: Category) Backing {
        return @as(Backing, 1) << @intFromEnum(category);
    }

    /// Whether this mask is subscribed to `category`.
    pub fn subscribed(self: SnoMask, category: Category) bool {
        return self.bits & bit(category) != 0;
    }

    /// Whether the mask is subscribed to nothing.
    pub fn isEmpty(self: SnoMask) bool {
        return self.bits == 0;
    }

    /// Number of categories the mask is subscribed to.
    pub fn count(self: SnoMask) usize {
        return @popCount(self.bits);
    }

    /// A copy with `category` added (idempotent).
    pub fn with(self: SnoMask, category: Category) SnoMask {
        return .{ .bits = self.bits | bit(category) };
    }

    /// A copy with `category` removed (idempotent).
    pub fn without(self: SnoMask, category: Category) SnoMask {
        return .{ .bits = self.bits & ~bit(category) };
    }

    /// The union of two masks.
    pub fn unionWith(self: SnoMask, other: SnoMask) SnoMask {
        return .{ .bits = self.bits | other.bits };
    }

    /// Equality by subscription set.
    pub fn eql(self: SnoMask, other: SnoMask) bool {
        return self.bits == other.bits;
    }

    /// Apply a `+/-` spec to `self`, returning the resulting mask.
    ///
    /// The spec is a sequence of additive runs: a sign (`+`/`-`) selects whether
    /// the following letters are added or removed, and the run continues until
    /// the next sign. A spec with no leading sign starts in add mode, so `ck` and
    /// `+ck` are equivalent. An unknown letter rejects the entire spec with
    /// `error.UnknownLetter` and leaves `self` conceptually unchanged (the caller
    /// receives an error, not a partial mask).
    pub fn applySpec(self: SnoMask, spec: []const u8) Error!SnoMask {
        var result = self;
        var adding = true;
        for (spec) |ch| {
            switch (ch) {
                '+' => adding = true,
                '-' => adding = false,
                else => {
                    const category = Category.fromLetter(ch) orelse return error.UnknownLetter;
                    result = if (adding) result.with(category) else result.without(category);
                },
            }
        }
        return result;
    }

    /// Render the mask as a `+letters` string into `out`, returning the populated
    /// prefix. The empty mask renders as `"+"`. Fails if `out` cannot hold the
    /// result (at most `1 + MAX_LETTERS` bytes).
    pub fn renderBuf(self: SnoMask, out: []u8) Error![]const u8 {
        const needed = 1 + self.count();
        if (out.len < needed) return error.OutputTooSmall;
        out[0] = '+';
        var len: usize = 1;
        inline for (ALL) |category| {
            if (self.subscribed(category)) {
                out[len] = category.letter();
                len += 1;
            }
        }
        return out[0..len];
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "empty and full masks" {
    const e = SnoMask.empty();
    try testing.expect(e.isEmpty());
    try testing.expectEqual(@as(usize, 0), e.count());

    const f = SnoMask.full();
    try testing.expect(!f.isEmpty());
    try testing.expectEqual(ALL.len, f.count());
    inline for (ALL) |category| try testing.expect(f.subscribed(category));
}

test "letter <-> category round trips for every category" {
    inline for (ALL) |category| {
        try testing.expectEqual(category, Category.fromLetter(category.letter()).?);
        // Case-insensitive lookup.
        try testing.expectEqual(category, Category.fromLetter(std.ascii.toUpper(category.letter())).?);
    }
}

test "fromLetter rejects unknown letters" {
    try testing.expect(Category.fromLetter('z') == null);
    try testing.expect(Category.fromLetter('!') == null);
    try testing.expect(Category.fromLetter('a') == null);
}

test "with/without are immutable and idempotent" {
    const base = SnoMask.empty();
    const added = base.with(.kill);
    try testing.expect(base.isEmpty()); // base untouched
    try testing.expect(added.subscribed(.kill));
    try testing.expectEqual(added.bits, added.with(.kill).bits); // idempotent add

    const removed = added.without(.kill);
    try testing.expect(!removed.subscribed(.kill));
    try testing.expectEqual(removed.bits, removed.without(.kill).bits); // idempotent remove
}

test "subscribed reflects fromCategories and only" {
    const m = SnoMask.fromCategories(&.{ .connect, .kill, .debug });
    try testing.expectEqual(@as(usize, 3), m.count());
    try testing.expect(m.subscribed(.connect));
    try testing.expect(m.subscribed(.kill));
    try testing.expect(m.subscribed(.debug));
    try testing.expect(!m.subscribed(.flood));

    const single = SnoMask.only(.globops);
    try testing.expect(single.subscribed(.globops));
    try testing.expectEqual(@as(usize, 1), single.count());
}

test "applySpec parses leading-add default and explicit signs" {
    // No leading sign defaults to add.
    const a = try SnoMask.empty().applySpec("ck");
    try testing.expect(a.subscribed(.connect));
    try testing.expect(a.subscribed(.kill));
    try testing.expectEqual(@as(usize, 2), a.count());

    // Explicit +.
    const b = try SnoMask.empty().applySpec("+ck");
    try testing.expect(b.eql(a));
}

test "applySpec accumulates across +/- runs" {
    // Start with connect+kill+flood, then drop flood, add nick+oper.
    const base = SnoMask.fromCategories(&.{ .connect, .kill, .flood });
    const result = try base.applySpec("-f+no");
    try testing.expect(result.subscribed(.connect));
    try testing.expect(result.subscribed(.kill));
    try testing.expect(!result.subscribed(.flood));
    try testing.expect(result.subscribed(.nick_change));
    try testing.expect(result.subscribed(.oper_action));
    try testing.expectEqual(@as(usize, 4), result.count());
}

test "applySpec additive run continues until next sign" {
    // +ckn-fd: add c,k,n then remove f,d. f,d weren't set so removal is a no-op.
    const result = try SnoMask.empty().applySpec("+ckn-fd");
    try testing.expect(result.subscribed(.connect));
    try testing.expect(result.subscribed(.kill));
    try testing.expect(result.subscribed(.nick_change));
    try testing.expect(!result.subscribed(.flood));
    try testing.expect(!result.subscribed(.debug));
    try testing.expectEqual(@as(usize, 3), result.count());
}

test "applySpec is case-insensitive" {
    const result = try SnoMask.empty().applySpec("+CK");
    try testing.expect(result.subscribed(.connect));
    try testing.expect(result.subscribed(.kill));
}

test "applySpec rejects unknown letters without partial application" {
    const base = SnoMask.only(.connect);
    try testing.expectError(error.UnknownLetter, base.applySpec("+kz"));
    // Caller's base mask is a value and was never mutated.
    try testing.expect(base.subscribed(.connect));
    try testing.expect(!base.subscribed(.kill));
    try testing.expectEqual(@as(usize, 1), base.count());
}

test "applySpec handles empty spec and dangling signs" {
    const base = SnoMask.only(.spam);
    try testing.expect((try base.applySpec("")).eql(base));
    try testing.expect((try base.applySpec("+")).eql(base));
    try testing.expect((try base.applySpec("-")).eql(base));
    // A flip with no following letters changes nothing.
    try testing.expect((try base.applySpec("+-+")).eql(base));
}

test "render produces canonical-order +letters" {
    var buf: [1 + MAX_LETTERS]u8 = undefined;

    const empty = try SnoMask.empty().renderBuf(&buf);
    try testing.expectEqualStrings("+", empty);

    // Insertion order is c,k,f,n,o,s,d,x,g,b regardless of spec order.
    const mask = try SnoMask.empty().applySpec("+xkc");
    const rendered = try mask.renderBuf(&buf);
    try testing.expectEqualStrings("+ckx", rendered);

    const all = try SnoMask.full().renderBuf(&buf);
    try testing.expectEqualStrings("+ckfnosdxgb", all);
}

test "render reports too-small buffer" {
    var tiny: [2]u8 = undefined;
    const mask = SnoMask.fromCategories(&.{ .connect, .kill, .flood });
    try testing.expectError(error.OutputTooSmall, mask.renderBuf(&tiny));

    // Exactly-sized buffer (1 + count) succeeds.
    var exact: [4]u8 = undefined;
    const rendered = try mask.renderBuf(&exact);
    try testing.expectEqualStrings("+ckf", rendered);
}

test "unionWith and eql" {
    const a = SnoMask.fromCategories(&.{ .connect, .kill });
    const b = SnoMask.fromCategories(&.{ .kill, .debug });
    const u = a.unionWith(b);
    try testing.expect(u.eql(SnoMask.fromCategories(&.{ .connect, .kill, .debug })));
    try testing.expect(!a.eql(b));
}

test "round trip: render then re-parse yields the same mask" {
    const original = SnoMask.fromCategories(&.{ .connect, .nick_change, .botnet, .xline });
    var buf: [1 + MAX_LETTERS]u8 = undefined;
    const rendered = try original.renderBuf(&buf);
    const reparsed = try SnoMask.empty().applySpec(rendered);
    try testing.expect(reparsed.eql(original));
}

//! Mizuchi server-notice router — category → subscriber-set fan-out by `u64` id.
//!
//! This is a deliberately small, pure mapping layer that sits *beside* the typed
//! Event Spine (`event_spine.zig`), not on top of it. The Event Spine keys
//! subscribers by borrowed `[]const u8` ids and emits `Delivery` records (id +
//! event payload) plus IRCv3-tagged `NOTE EVENT` wire lines. This router instead:
//!
//!   * keys subscribers by an opaque `u64` id (the live server's bitcast client
//!     id), avoiding string lifetime juggling on the hot delivery path;
//!   * answers a single question — "which subscriber ids want this category?" —
//!     by writing a flat `[]u64` recipient list into a caller-owned buffer; and
//!   * renders a classic, tag-free server-notice line (`:server NOTICE * :*** …`)
//!     for operators that prefer the legacy snote presentation.
//!
//! The category vocabulary and bit-mask type are reused verbatim from the Event
//! Spine so the two layers never drift. The router owns no allocation: callers
//! supply the subscriber slot storage and every output buffer, so there is
//! nothing to free and the module is trivially testable in isolation.

const std = @import("std");
const event_spine = @import("event_spine.zig");

/// Re-exported so callers can name categories without importing both modules.
pub const Category = event_spine.EventCategory;
/// Re-exported bit mask over `Category` (see `event_spine.CategoryMask`).
pub const CategoryMask = event_spine.CategoryMask;

/// Opaque subscriber identity. The live server bitcasts its client id into this.
pub const SubscriberId = u64;

/// One caller-owned routing slot: a subscriber id plus the category mask it wants.
pub const Slot = struct {
    id: SubscriberId = 0,
    mask: CategoryMask = .{},
    /// `false` slots are free and ignored by every query.
    active: bool = false,
};

pub const SubscribeError = error{
    /// A mask with no categories would create a subscriber that never matches.
    EmptyMask,
    /// No free slot remained for a brand-new subscriber.
    TableFull,
};

pub const RecipientError = error{
    /// The caller's recipient buffer was smaller than the matching set.
    OutputTooSmall,
};

pub const FormatError = error{
    /// The notice text contained a control byte unsafe for a wire line.
    InvalidText,
    /// The server name was empty or contained whitespace / control bytes.
    InvalidServerName,
    /// The caller's output buffer could not hold the rendered line.
    OutputTooSmall,
};

/// A pure category → subscriber-set router over caller-owned `Slot` storage.
///
/// Subscriber ids are unique: re-subscribing an existing id replaces its mask
/// (it does not consume a second slot). All operations are O(n) over the slot
/// table, which is intentional — the table is small and the constant factor of a
/// linear scan beats a hash map for the few-dozen-oper case while staying
/// allocation-free.
pub const SnoteRouter = struct {
    slots: []Slot,

    /// Wrap caller-owned `slots`. The slots are reset to the inactive state so a
    /// freshly-`undefined` array is safe to pass in.
    pub fn init(slots: []Slot) SnoteRouter {
        for (slots) |*slot| slot.* = .{};
        return .{ .slots = slots };
    }

    /// Number of active subscribers.
    pub fn count(self: *const SnoteRouter) usize {
        var n: usize = 0;
        for (self.slots) |slot| {
            if (slot.active) n += 1;
        }
        return n;
    }

    /// Add `id` with `mask`, or replace `id`'s mask if it already subscribes.
    /// An empty mask is rejected; use `unsubscribe` to drop a subscriber.
    pub fn subscribe(self: *SnoteRouter, id: SubscriberId, mask: CategoryMask) SubscribeError!void {
        if (mask.isEmpty()) return error.EmptyMask;

        if (self.findActive(id)) |index| {
            self.slots[index].mask = mask;
            return;
        }

        const free = self.findFree() orelse return error.TableFull;
        self.slots[free] = .{ .id = id, .mask = mask, .active = true };
    }

    /// Add `categories` to `id`'s mask, creating the subscriber if absent.
    /// Equivalent to `subscribe` with the union of the old and new categories.
    pub fn addCategories(
        self: *SnoteRouter,
        id: SubscriberId,
        categories: []const Category,
    ) SubscribeError!void {
        const additions = CategoryMask.fromCategories(categories);
        if (self.findActive(id)) |index| {
            self.slots[index].mask = self.slots[index].mask.include(additions);
            if (self.slots[index].mask.isEmpty()) return error.EmptyMask;
            return;
        }
        try self.subscribe(id, additions);
    }

    /// Remove `categories` from `id`'s mask. The subscriber is dropped when its
    /// mask becomes empty. Returns true if `id` was subscribed before the call.
    /// Removing categories `id` did not have is a successful no-op.
    pub fn unsubscribeCategories(
        self: *SnoteRouter,
        id: SubscriberId,
        categories: []const Category,
    ) bool {
        const index = self.findActive(id) orelse return false;
        const next = self.slots[index].mask.exclude(CategoryMask.fromCategories(categories));
        if (next.isEmpty()) {
            self.slots[index] = .{};
        } else {
            self.slots[index].mask = next;
        }
        return true;
    }

    /// Drop `id` entirely. Returns true if it was subscribed.
    pub fn unsubscribe(self: *SnoteRouter, id: SubscriberId) bool {
        const index = self.findActive(id) orelse return false;
        self.slots[index] = .{};
        return true;
    }

    /// Whether `id` currently wants `category`.
    pub fn wants(self: *const SnoteRouter, id: SubscriberId, category: Category) bool {
        const index = self.findActive(id) orelse return false;
        return self.slots[index].mask.contains(category);
    }

    /// Current mask for `id`, or null if it is not subscribed.
    pub fn maskOf(self: *const SnoteRouter, id: SubscriberId) ?CategoryMask {
        const index = self.findActive(id) orelse return null;
        return self.slots[index].mask;
    }

    /// Write the ids of every subscriber that wants `category` into `out`,
    /// returning the populated prefix. Results follow slot order, which equals
    /// subscription order until a freed slot is reused; either way the output is
    /// deterministic for a given table state. Fails (without partial writes) if
    /// `out` is too small for the full matching set.
    pub fn recipients(
        self: *const SnoteRouter,
        category: Category,
        out: []SubscriberId,
    ) RecipientError![]const SubscriberId {
        if (self.matchCount(category) > out.len) return error.OutputTooSmall;

        var written: usize = 0;
        for (self.slots) |slot| {
            if (!slot.active) continue;
            if (!slot.mask.contains(category)) continue;
            out[written] = slot.id;
            written += 1;
        }
        return out[0..written];
    }

    /// Number of subscribers that want `category`.
    pub fn matchCount(self: *const SnoteRouter, category: Category) usize {
        var n: usize = 0;
        for (self.slots) |slot| {
            if (slot.active and slot.mask.contains(category)) n += 1;
        }
        return n;
    }

    fn findActive(self: *const SnoteRouter, id: SubscriberId) ?usize {
        for (self.slots, 0..) |slot, index| {
            if (slot.active and slot.id == id) return index;
        }
        return null;
    }

    fn findFree(self: *const SnoteRouter) ?usize {
        for (self.slots, 0..) |slot, index| {
            if (!slot.active) return index;
        }
        return null;
    }
};

/// Render a classic, tag-free server-notice line for `category` + `text`:
///
///   `:<server_name> NOTICE * :*** <CATEGORY>: <text>\r\n`
///
/// This is the legacy snote presentation, distinct from the Event Spine's
/// IRCv3-tagged `NOTE EVENT` wire format. Returns the populated prefix of `out`.
pub fn formatSnote(
    server_name: []const u8,
    category: Category,
    text: []const u8,
    out: []u8,
) FormatError![]const u8 {
    try validateServerName(server_name);
    if (!safeText(text)) return error.InvalidText;

    const line = std.fmt.bufPrint(
        out,
        ":{s} NOTICE * :*** {s}: {s}\r\n",
        .{ server_name, category.code(), text },
    ) catch return error.OutputTooSmall;
    return line;
}

/// Exact byte length `formatSnote` would produce for these inputs, so callers can
/// size buffers without a trial render. Does not validate the inputs.
pub fn snoteLen(server_name: []const u8, category: Category, text: []const u8) usize {
    // ":" + name + " NOTICE * :*** " + CODE + ": " + text + "\r\n"
    return 1 + server_name.len + " NOTICE * :*** ".len + category.code().len + ": ".len + text.len + "\r\n".len;
}

fn validateServerName(name: []const u8) FormatError!void {
    if (name.len == 0) return error.InvalidServerName;
    for (name) |ch| {
        if (ch <= ' ' or ch == 0x7f) return error.InvalidServerName;
    }
}

fn safeText(text: []const u8) bool {
    for (text) |ch| {
        if (ch < ' ' or ch == 0x7f) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "subscribe then route by single category" {
    var slots: [4]Slot = undefined;
    var router = SnoteRouter.init(&slots);

    try router.subscribe(1001, CategoryMask.fromCategories(&.{ .connect, .kill }));
    try router.subscribe(1002, CategoryMask.only(.kill));
    try router.subscribe(1003, CategoryMask.only(.debug));

    try testing.expectEqual(@as(usize, 3), router.count());

    var buf: [4]SubscriberId = undefined;
    const kills = try router.recipients(.kill, &buf);
    try testing.expectEqual(@as(usize, 2), kills.len);
    // Subscription order is preserved.
    try testing.expectEqual(@as(SubscriberId, 1001), kills[0]);
    try testing.expectEqual(@as(SubscriberId, 1002), kills[1]);

    const debugs = try router.recipients(.debug, &buf);
    try testing.expectEqual(@as(usize, 1), debugs.len);
    try testing.expectEqual(@as(SubscriberId, 1003), debugs[0]);
}

test "re-subscribe replaces mask without consuming a second slot" {
    var slots: [2]Slot = undefined;
    var router = SnoteRouter.init(&slots);

    try router.subscribe(7, CategoryMask.only(.connect));
    try router.subscribe(7, CategoryMask.only(.flood));
    try testing.expectEqual(@as(usize, 1), router.count());

    try testing.expect(!router.wants(7, .connect));
    try testing.expect(router.wants(7, .flood));
}

test "category mask filtering excludes non-matching subscribers" {
    var slots: [3]Slot = undefined;
    var router = SnoteRouter.init(&slots);

    try router.subscribe(10, CategoryMask.only(.security));
    try router.subscribe(20, CategoryMask.only(.spam));
    try router.subscribe(30, CategoryMask.fromCategories(&.{ .security, .spam }));

    try testing.expectEqual(@as(usize, 2), router.matchCount(.security));
    try testing.expectEqual(@as(usize, 2), router.matchCount(.spam));
    try testing.expectEqual(@as(usize, 0), router.matchCount(.connect));

    var buf: [3]SubscriberId = undefined;
    const none = try router.recipients(.connect, &buf);
    try testing.expectEqual(@as(usize, 0), none.len);
}

test "unsubscribe drops a subscriber and frees its slot for reuse" {
    var slots: [2]Slot = undefined;
    var router = SnoteRouter.init(&slots);

    try router.subscribe(1, CategoryMask.only(.connect));
    try router.subscribe(2, CategoryMask.only(.connect));
    try testing.expectError(error.TableFull, router.subscribe(3, CategoryMask.only(.connect)));

    try testing.expect(router.unsubscribe(1));
    try testing.expect(!router.unsubscribe(1)); // already gone

    // The freed slot (slot 0) is reused, so id 3 occupies it ahead of id 2.
    try router.subscribe(3, CategoryMask.only(.connect));
    try testing.expectEqual(@as(usize, 2), router.count());

    var buf: [2]SubscriberId = undefined;
    const recips = try router.recipients(.connect, &buf);
    try testing.expectEqual(@as(usize, 2), recips.len);
    try testing.expectEqual(@as(SubscriberId, 3), recips[0]);
    try testing.expectEqual(@as(SubscriberId, 2), recips[1]);
}

test "add and unsubscribe individual categories" {
    var slots: [2]Slot = undefined;
    var router = SnoteRouter.init(&slots);

    try router.addCategories(5, &.{.connect});
    try router.addCategories(5, &.{ .kill, .flood });
    try testing.expect(router.wants(5, .connect));
    try testing.expect(router.wants(5, .kill));
    try testing.expect(router.wants(5, .flood));

    try testing.expect(router.unsubscribeCategories(5, &.{.connect}));
    try testing.expect(!router.wants(5, .connect));
    try testing.expect(router.wants(5, .kill));

    // Removing the rest drops the subscriber entirely.
    try testing.expect(router.unsubscribeCategories(5, &.{ .kill, .flood }));
    try testing.expectEqual(@as(usize, 0), router.count());
    try testing.expect(!router.unsubscribeCategories(5, &.{.kill}));
}

test "empty mask is rejected on subscribe" {
    var slots: [1]Slot = undefined;
    var router = SnoteRouter.init(&slots);
    try testing.expectError(error.EmptyMask, router.subscribe(1, CategoryMask.empty()));
    try testing.expectEqual(@as(usize, 0), router.count());
}

test "recipients reports too-small buffers without partial writes" {
    var slots: [3]Slot = undefined;
    var router = SnoteRouter.init(&slots);

    try router.subscribe(1, CategoryMask.only(.announce));
    try router.subscribe(2, CategoryMask.only(.announce));

    var buf: [1]SubscriberId = undefined;
    try testing.expectError(error.OutputTooSmall, router.recipients(.announce, &buf));
}

test "maskOf returns the live mask or null" {
    var slots: [1]Slot = undefined;
    var router = SnoteRouter.init(&slots);

    try testing.expect(router.maskOf(9) == null);
    try router.subscribe(9, CategoryMask.only(.policy));
    const m = router.maskOf(9).?;
    try testing.expect(m.contains(.policy));
    try testing.expect(!m.contains(.connect));
}

test "formatSnote renders a tag-free legacy notice line" {
    var out: [256]u8 = undefined;
    const line = try formatSnote("mizuchi.local", .kill, "user removed by oper", &out);
    try testing.expectEqualStrings(
        ":mizuchi.local NOTICE * :*** KILL: user removed by oper\r\n",
        line,
    );
    try testing.expectEqual(snoteLen("mizuchi.local", .kill, "user removed by oper"), line.len);
}

test "formatSnote validates server name, text, and buffer size" {
    var out: [256]u8 = undefined;

    try testing.expectError(error.InvalidServerName, formatSnote("", .connect, "hi", &out));
    try testing.expectError(error.InvalidServerName, formatSnote("bad name", .connect, "hi", &out));
    try testing.expectError(error.InvalidText, formatSnote("mizuchi.local", .connect, "bad\nline", &out));

    var tiny: [8]u8 = undefined;
    try testing.expectError(error.OutputTooSmall, formatSnote("mizuchi.local", .connect, "connected", &tiny));
}

test "init resets undefined slot storage to inactive" {
    var slots: [4]Slot = undefined;
    var router = SnoteRouter.init(&slots);
    try testing.expectEqual(@as(usize, 0), router.count());
    try testing.expectEqual(@as(usize, 0), router.matchCount(.connect));
}

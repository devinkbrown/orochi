//! Registered-channel SET options for Mizuchi services.
//!
//! Per-channel persistent settings that the services layer applies to a
//! REGISTERED channel. These are NOT pseudo-client toggles: in Mizuchi services
//! are real server commands, so a `CHANNEL SET <#chan> <option> <value>` command
//! parses through `ChanSetStore.set` and the resulting `ChannelSettings` is read
//! back by the world when a channel is created/joined/topic-changed.
//!
//! Options:
//!   GUARD      bool   services holds the channel open (joins a holder / +P-like)
//!   KEEPTOPIC  bool   restore the stored TOPIC on channel recreation
//!   TOPICLOCK  bool   only access-holders may change the topic
//!   RESTRICTED bool   only access-holders may join
//!   PRIVATE    bool   hide the channel from LIST output
//!   FANTASY    bool   honour in-channel `!command` fantasy triggers
//!
//! Plus a stored TOPIC string (bounded) used by KEEPTOPIC.
//!
//! Pure logic: imports only `std`, performs no I/O, owns its allocations and
//! frees them on `deinit`.

const std = @import("std");

/// Maximum stored channel-name length (IRC channel names cap well under this).
pub const channel_name_max = 64;

/// Maximum stored KEEPTOPIC topic text length. IRC topics are commonly limited
/// to 390 bytes on the wire; 512 gives generous headroom without unbounded use.
pub const topic_max = 512;

/// A single boolean SET option.
pub const Option = enum {
    guard,
    keeptopic,
    topiclock,
    restricted,
    private,
    fantasy,

    /// Parse a case-insensitive option name. Returns `null` for unknown names.
    pub fn parse(text: []const u8) ?Option {
        if (text.len == 0 or text.len > 16) return null;
        var buf: [16]u8 = undefined;
        const lowered = asciiLowerInto(text, &buf);
        const map = .{
            .{ "guard", Option.guard },
            .{ "keeptopic", Option.keeptopic },
            .{ "topiclock", Option.topiclock },
            .{ "restricted", Option.restricted },
            .{ "private", Option.private },
            .{ "fantasy", Option.fantasy },
        };
        inline for (map) |entry| {
            if (std.mem.eql(u8, lowered, entry[0])) return entry[1];
        }
        return null;
    }

    /// Canonical lowercase name for display / serialization.
    pub fn name(self: Option) []const u8 {
        return switch (self) {
            .guard => "guard",
            .keeptopic => "keeptopic",
            .topiclock => "topiclock",
            .restricted => "restricted",
            .private => "private",
            .fantasy => "fantasy",
        };
    }
};

/// Errors surfaced by the SET parser/applier.
pub const ChanSetError = error{
    /// The option name was not recognized.
    UnknownOption,
    /// The supplied value could not be parsed as a boolean (ON/OFF/etc).
    InvalidValue,
    /// The channel name was empty or exceeded `channel_name_max`.
    InvalidChannel,
    /// The supplied topic text exceeded `topic_max`.
    TopicTooLong,
    /// Allocation failed.
    OutOfMemory,
};

/// Per-channel settings. All booleans default to `false`; `topic` defaults to
/// the empty slice. `topic` is owned by the enclosing `ChanSetStore` entry.
pub const ChannelSettings = struct {
    guard: bool = false,
    keeptopic: bool = false,
    topiclock: bool = false,
    restricted: bool = false,
    private: bool = false,
    fantasy: bool = false,
    topic: []const u8 = "",

    /// The all-defaults settings value.
    pub fn defaults() ChannelSettings {
        return .{};
    }

    /// Read a boolean option by enum.
    pub fn get(self: ChannelSettings, option: Option) bool {
        return switch (option) {
            .guard => self.guard,
            .keeptopic => self.keeptopic,
            .topiclock => self.topiclock,
            .restricted => self.restricted,
            .private => self.private,
            .fantasy => self.fantasy,
        };
    }

    /// True when every field is at its default (nothing to persist).
    pub fn isDefault(self: ChannelSettings) bool {
        return !self.guard and !self.keeptopic and !self.topiclock and
            !self.restricted and !self.private and !self.fantasy and
            self.topic.len == 0;
    }

    fn setBool(self: *ChannelSettings, option: Option, value: bool) void {
        switch (option) {
            .guard => self.guard = value,
            .keeptopic => self.keeptopic = value,
            .topiclock => self.topiclock = value,
            .restricted => self.restricted = value,
            .private => self.private = value,
            .fantasy => self.fantasy = value,
        }
    }
};

/// Parse a boolean SET value. Accepts a generous set of on/off spellings,
/// case-insensitively. Returns `error.InvalidValue` otherwise.
pub fn parseBool(value: []const u8) ChanSetError!bool {
    if (value.len == 0 or value.len > 8) return error.InvalidValue;
    var buf: [8]u8 = undefined;
    const lowered = asciiLowerInto(value, &buf);
    const on = .{ "on", "true", "yes", "1", "enable", "enabled" };
    const off = .{ "off", "false", "no", "0", "disable" };
    inline for (on) |t| {
        if (std.mem.eql(u8, lowered, t)) return true;
    }
    inline for (off) |t| {
        if (std.mem.eql(u8, lowered, t)) return false;
    }
    return error.InvalidValue;
}

/// A keyed store of `ChannelSettings`, one entry per registered channel. Channel
/// keys are ASCII case-folded (IRC channels are case-insensitive). Owns all key
/// and topic allocations.
pub const ChanSetStore = struct {
    allocator: std.mem.Allocator,
    map: std.StringHashMapUnmanaged(ChannelSettings) = .empty,

    pub fn init(allocator: std.mem.Allocator) ChanSetStore {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *ChanSetStore) void {
        var it = self.map.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            if (entry.value_ptr.topic.len != 0) self.allocator.free(entry.value_ptr.topic);
        }
        self.map.deinit(self.allocator);
        self.* = undefined;
    }

    /// Number of channels with non-default settings stored.
    pub fn count(self: *const ChanSetStore) usize {
        return self.map.count();
    }

    /// Look up the settings for `channel`. Returns `defaults()` when the channel
    /// has no stored entry. The returned `topic` slice (if any) is borrowed from
    /// the store and is valid until the entry is mutated or the store is freed.
    pub fn get(self: *const ChanSetStore, channel: []const u8) ChannelSettings {
        if (!validChannel(channel)) return ChannelSettings.defaults();
        var buf: [channel_name_max]u8 = undefined;
        const key = asciiLowerInto(channel, &buf);
        return self.map.get(key) orelse ChannelSettings.defaults();
    }

    /// Apply a boolean SET option. `option` and `value` are textual (as they
    /// arrive from the command parser).
    pub fn set(
        self: *ChanSetStore,
        channel: []const u8,
        option: []const u8,
        value: []const u8,
    ) ChanSetError!void {
        const opt = Option.parse(option) orelse return error.UnknownOption;
        const on = try parseBool(value);
        const entry = try self.ensure(channel);
        entry.setBool(opt, on);
        try self.pruneIfDefault(channel, entry);
    }

    /// Apply a boolean SET option using the already-parsed enum + bool. Mirrors
    /// `set` for callers that have validated the inputs upstream.
    pub fn setOption(
        self: *ChanSetStore,
        channel: []const u8,
        option: Option,
        value: bool,
    ) ChanSetError!void {
        const entry = try self.ensure(channel);
        entry.setBool(option, value);
        try self.pruneIfDefault(channel, entry);
    }

    /// Store the KEEPTOPIC topic text for `channel`. Copies `text`. An empty
    /// `text` clears the stored topic. Returns `error.TopicTooLong` when the
    /// text exceeds `topic_max`.
    pub fn setTopic(self: *ChanSetStore, channel: []const u8, text: []const u8) ChanSetError!void {
        if (text.len > topic_max) return error.TopicTooLong;
        const entry = try self.ensure(channel);
        const dup: []const u8 = if (text.len == 0) "" else try self.allocator.dupe(u8, text);
        errdefer if (dup.len != 0) self.allocator.free(dup);
        if (entry.topic.len != 0) self.allocator.free(entry.topic);
        entry.topic = dup;
        try self.pruneIfDefault(channel, entry);
    }

    /// Remove all stored settings for `channel`, freeing its allocations.
    /// No-op when the channel has no entry.
    pub fn clear(self: *ChanSetStore, channel: []const u8) void {
        if (!validChannel(channel)) return;
        var buf: [channel_name_max]u8 = undefined;
        const key = asciiLowerInto(channel, &buf);
        if (self.map.fetchRemove(key)) |kv| {
            self.allocator.free(kv.key);
            if (kv.value.topic.len != 0) self.allocator.free(kv.value.topic);
        }
    }

    /// Get a mutable entry for `channel`, creating a defaults entry (with an
    /// owned, case-folded key) when absent.
    fn ensure(self: *ChanSetStore, channel: []const u8) ChanSetError!*ChannelSettings {
        if (!validChannel(channel)) return error.InvalidChannel;
        var buf: [channel_name_max]u8 = undefined;
        const key = asciiLowerInto(channel, &buf);
        const gop = try self.map.getOrPut(self.allocator, key);
        if (!gop.found_existing) {
            const owned = self.allocator.dupe(u8, key) catch |e| {
                _ = self.map.remove(key);
                return e;
            };
            gop.key_ptr.* = owned;
            gop.value_ptr.* = ChannelSettings.defaults();
        }
        return gop.value_ptr;
    }

    /// Drop an entry that has returned to all-defaults so the store stays sparse.
    fn pruneIfDefault(self: *ChanSetStore, channel: []const u8, entry: *ChannelSettings) ChanSetError!void {
        if (!entry.isDefault()) return;
        self.clear(channel);
    }
};

/// True when `channel` is a non-empty name within `channel_name_max`.
fn validChannel(channel: []const u8) bool {
    return channel.len != 0 and channel.len <= channel_name_max;
}

/// Lowercase ASCII bytes of `src` into `dst` (which must be >= src.len) and
/// return the written slice. Non-ASCII bytes pass through unchanged.
fn asciiLowerInto(src: []const u8, dst: []u8) []u8 {
    std.debug.assert(dst.len >= src.len);
    for (src, 0..) |c, i| {
        dst[i] = std.ascii.toLower(c);
    }
    return dst[0..src.len];
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

const testing = std.testing;

test "defaults are all off and empty" {
    const d = ChannelSettings.defaults();
    try testing.expect(!d.guard);
    try testing.expect(!d.keeptopic);
    try testing.expect(!d.topiclock);
    try testing.expect(!d.restricted);
    try testing.expect(!d.private);
    try testing.expect(!d.fantasy);
    try testing.expectEqualStrings("", d.topic);
    try testing.expect(d.isDefault());
}

test "Option.parse is case-insensitive and rejects unknown" {
    try testing.expectEqual(Option.guard, Option.parse("guard").?);
    try testing.expectEqual(Option.keeptopic, Option.parse("KeepTopic").?);
    try testing.expectEqual(Option.topiclock, Option.parse("TOPICLOCK").?);
    try testing.expectEqual(Option.restricted, Option.parse("restricted").?);
    try testing.expectEqual(Option.private, Option.parse("Private").?);
    try testing.expectEqual(Option.fantasy, Option.parse("FANTASY").?);
    try testing.expect(Option.parse("bogus") == null);
    try testing.expect(Option.parse("") == null);
    try testing.expect(Option.parse("thisnameiswaytoolongtomatch") == null);
}

test "parseBool accepts on/off spellings and rejects junk" {
    try testing.expect(try parseBool("on"));
    try testing.expect(try parseBool("ON"));
    try testing.expect(try parseBool("true"));
    try testing.expect(try parseBool("Yes"));
    try testing.expect(try parseBool("1"));
    try testing.expect(try parseBool("enable"));
    try testing.expect(!try parseBool("off"));
    try testing.expect(!try parseBool("False"));
    try testing.expect(!try parseBool("no"));
    try testing.expect(!try parseBool("0"));
    try testing.expect(!try parseBool("disable"));
    try testing.expectError(error.InvalidValue, parseBool("maybe"));
    try testing.expectError(error.InvalidValue, parseBool(""));
    try testing.expectError(error.InvalidValue, parseBool("waytoolongvalue"));
}

test "set and clear each boolean option" {
    var store = ChanSetStore.init(testing.allocator);
    defer store.deinit();

    const opts = [_][]const u8{ "guard", "keeptopic", "topiclock", "restricted", "private", "fantasy" };
    const enums = [_]Option{ .guard, .keeptopic, .topiclock, .restricted, .private, .fantasy };

    inline for (opts, enums) |name, opt| {
        try store.set("#mizuchi", name, "on");
        try testing.expect(store.get("#mizuchi").get(opt));

        try store.set("#mizuchi", name, "off");
        try testing.expect(!store.get("#mizuchi").get(opt));
    }

    // All back to default -> entry pruned.
    try testing.expectEqual(@as(usize, 0), store.count());
}

test "multiple options coexist on one channel" {
    var store = ChanSetStore.init(testing.allocator);
    defer store.deinit();

    try store.set("#chan", "guard", "on");
    try store.set("#chan", "private", "on");
    try store.set("#chan", "fantasy", "on");

    const s = store.get("#chan");
    try testing.expect(s.guard);
    try testing.expect(s.private);
    try testing.expect(s.fantasy);
    try testing.expect(!s.keeptopic);
    try testing.expect(!s.restricted);
    try testing.expect(!s.topiclock);
    try testing.expectEqual(@as(usize, 1), store.count());
}

test "channel keys are case-insensitive" {
    var store = ChanSetStore.init(testing.allocator);
    defer store.deinit();

    try store.set("#MizuChi", "guard", "on");
    try testing.expect(store.get("#mizuchi").guard);
    try testing.expect(store.get("#MIZUCHI").guard);
    try testing.expectEqual(@as(usize, 1), store.count());

    store.clear("#MIZUCHI");
    try testing.expect(!store.get("#mizuchi").guard);
    try testing.expectEqual(@as(usize, 0), store.count());
}

test "KEEPTOPIC text is retained and updatable" {
    var store = ChanSetStore.init(testing.allocator);
    defer store.deinit();

    try store.set("#chan", "keeptopic", "on");
    try store.setTopic("#chan", "Welcome to Mizuchi");
    try testing.expect(store.get("#chan").keeptopic);
    try testing.expectEqualStrings("Welcome to Mizuchi", store.get("#chan").topic);

    // Update replaces, no leak.
    try store.setTopic("#chan", "New topic");
    try testing.expectEqualStrings("New topic", store.get("#chan").topic);

    // Empty clears the stored topic.
    try store.setTopic("#chan", "");
    try testing.expectEqualStrings("", store.get("#chan").topic);
    // keeptopic flag still set, so entry survives.
    try testing.expect(store.get("#chan").keeptopic);
}

test "setOption mirrors textual set" {
    var store = ChanSetStore.init(testing.allocator);
    defer store.deinit();

    try store.setOption("#chan", .restricted, true);
    try testing.expect(store.get("#chan").restricted);
    try store.setOption("#chan", .restricted, false);
    try testing.expect(!store.get("#chan").restricted);
    try testing.expectEqual(@as(usize, 0), store.count());
}

test "unknown option is rejected without creating an entry" {
    var store = ChanSetStore.init(testing.allocator);
    defer store.deinit();

    try testing.expectError(error.UnknownOption, store.set("#chan", "nosuchopt", "on"));
    try testing.expectError(error.InvalidValue, store.set("#chan", "guard", "perhaps"));
    try testing.expectEqual(@as(usize, 0), store.count());
}

test "invalid channel bounds rejected" {
    var store = ChanSetStore.init(testing.allocator);
    defer store.deinit();

    try testing.expectError(error.InvalidChannel, store.set("", "guard", "on"));

    const too_long = "#" ** channel_name_max ++ "x"; // > channel_name_max
    try testing.expect(too_long.len > channel_name_max);
    try testing.expectError(error.InvalidChannel, store.set(too_long, "guard", "on"));

    // get on invalid channel yields defaults, not a crash.
    try testing.expect(store.get("").isDefault());
    try testing.expect(store.get(too_long).isDefault());
}

test "topic too long rejected and leaves entry untouched" {
    var store = ChanSetStore.init(testing.allocator);
    defer store.deinit();

    try store.set("#chan", "keeptopic", "on");
    const big = "z" ** (topic_max + 1);
    try testing.expectError(error.TopicTooLong, store.setTopic("#chan", big));
    try testing.expectEqualStrings("", store.get("#chan").topic);

    // Exactly at the bound is accepted.
    const exact = "y" ** topic_max;
    try store.setTopic("#chan", exact);
    try testing.expectEqual(@as(usize, topic_max), store.get("#chan").topic.len);
}

test "clear frees topic and pruning keeps store sparse" {
    var store = ChanSetStore.init(testing.allocator);
    defer store.deinit();

    try store.setTopic("#chan", "ephemeral topic");
    try testing.expectEqual(@as(usize, 1), store.count());
    // Topic-only entry is non-default because topic.len != 0.
    try testing.expect(!store.get("#chan").isDefault());

    store.clear("#chan");
    try testing.expectEqual(@as(usize, 0), store.count());

    // Clearing a missing channel is a no-op.
    store.clear("#nope");
    try testing.expectEqual(@as(usize, 0), store.count());
}

test "many channels independent, no leaks" {
    var store = ChanSetStore.init(testing.allocator);
    defer store.deinit();

    var i: usize = 0;
    var namebuf: [32]u8 = undefined;
    while (i < 50) : (i += 1) {
        const ch = try std.fmt.bufPrint(&namebuf, "#room{d}", .{i});
        try store.set(ch, "guard", "on");
        try store.setTopic(ch, "topic");
    }
    try testing.expectEqual(@as(usize, 50), store.count());

    i = 0;
    while (i < 50) : (i += 1) {
        const ch = try std.fmt.bufPrint(&namebuf, "#room{d}", .{i});
        try testing.expect(store.get(ch).guard);
        try testing.expectEqualStrings("topic", store.get(ch).topic);
    }
}

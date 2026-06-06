//! Per-(account, channel) personal sticky note storage for the Mizuchi daemon.
//!
//! Each account may pin one short personal note per channel. Notes are private
//! to the account that authored them. Storage is keyed by a composite of the
//! account name and channel name joined by a NUL separator, which is a byte
//! that cannot legitimately appear inside either IRC name component.

const std = @import("std");

/// Separator byte used to join the account and channel into a composite key.
/// NUL is illegal in IRC names, so it can never collide with real input.
const key_sep: u8 = 0x00;

/// Maximum permitted length, in bytes, of a single sticky note's text.
const max_note_len: usize = 400;

/// Errors that may be returned when storing a note.
pub const NoteError = error{
    /// The supplied note text was empty or exceeded `max_note_len`.
    InvalidNote,
};

/// A collection of personal sticky notes, indexed by (account, channel).
///
/// Both the composite keys and the note texts are heap-owned by this struct.
/// The 64-bit-friendly `usize` lengths and `std.StringHashMap` backing make
/// this suitable for long-running daemon use without external dependencies.
pub const StickyNote = struct {
    allocator: std.mem.Allocator,
    /// Maps an owned "account\x00channel" key to its owned note text.
    entries: std.StringHashMapUnmanaged([]u8),

    /// Create an empty note store backed by `allocator`.
    pub fn init(allocator: std.mem.Allocator) StickyNote {
        return .{
            .allocator = allocator,
            .entries = .{},
        };
    }

    /// Release every owned key and note, leaving the struct unusable.
    pub fn deinit(self: *StickyNote) void {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    /// Build an owned composite key from the account and channel components.
    fn makeKey(self: *StickyNote, account: []const u8, channel: []const u8) ![]u8 {
        const total = account.len + 1 + channel.len;
        const buf = try self.allocator.alloc(u8, total);
        @memcpy(buf[0..account.len], account);
        buf[account.len] = key_sep;
        @memcpy(buf[account.len + 1 ..], channel);
        return buf;
    }

    /// Store (or overwrite) the note for `account` in `channel`.
    ///
    /// Overwriting an existing note frees the previous text. An empty note or
    /// one longer than `max_note_len` is rejected with `error.InvalidNote`,
    /// leaving any existing note untouched.
    pub fn set(
        self: *StickyNote,
        account: []const u8,
        channel: []const u8,
        text: []const u8,
    ) (NoteError || std.mem.Allocator.Error)!void {
        if (text.len == 0 or text.len > max_note_len) return NoteError.InvalidNote;

        const owned_text = try self.allocator.dupe(u8, text);
        errdefer self.allocator.free(owned_text);

        const probe_key = try self.makeKey(account, channel);

        if (self.entries.getEntry(probe_key)) |existing| {
            // Key already present: reuse the stored key, swap the value.
            self.allocator.free(probe_key);
            self.allocator.free(existing.value_ptr.*);
            existing.value_ptr.* = owned_text;
            return;
        }

        // New entry: the composite key becomes owned by the map.
        errdefer self.allocator.free(probe_key);
        try self.entries.put(self.allocator, probe_key, owned_text);
    }

    /// Return the note text for `account` in `channel`, or null if none exists.
    /// The returned slice is owned by the store and valid until mutated.
    pub fn get(self: *StickyNote, account: []const u8, channel: []const u8) ?[]const u8 {
        const probe_key = self.makeKey(account, channel) catch return null;
        defer self.allocator.free(probe_key);
        return self.entries.get(probe_key);
    }

    /// Remove the note for `account` in `channel`.
    /// Returns true if a note was removed, false if none existed.
    pub fn clear(self: *StickyNote, account: []const u8, channel: []const u8) bool {
        const probe_key = self.makeKey(account, channel) catch return false;
        defer self.allocator.free(probe_key);

        if (self.entries.fetchRemove(probe_key)) |kv| {
            self.allocator.free(kv.key);
            self.allocator.free(kv.value);
            return true;
        }
        return false;
    }

    /// Remove every note belonging to `account` across all channels.
    /// Returns the number of notes removed.
    ///
    /// Matching is anchored on the "account\x00" prefix so that an account
    /// whose name is a prefix of another (e.g. "bob" vs "bobby") is never
    /// confused: the NUL separator must immediately follow the account name.
    pub fn clearAccount(self: *StickyNote, account: []const u8) usize {
        const prefix = self.makeKey(account, "") catch return 0;
        defer self.allocator.free(prefix);

        var removed: usize = 0;
        var it = self.entries.iterator();
        // Collect first, then remove, to avoid mutating during iteration.
        // Bounded by entry count; daemon note volume is small per account.
        var doomed: std.ArrayListUnmanaged([]const u8) = .empty;
        defer doomed.deinit(self.allocator);

        while (it.next()) |entry| {
            const key = entry.key_ptr.*;
            if (key.len >= prefix.len and std.mem.eql(u8, key[0..prefix.len], prefix)) {
                doomed.append(self.allocator, key) catch continue;
            }
        }

        for (doomed.items) |key| {
            if (self.entries.fetchRemove(key)) |kv| {
                self.allocator.free(kv.key);
                self.allocator.free(kv.value);
                removed += 1;
            }
        }
        return removed;
    }
};

test "set, get, and overwrite a note" {
    var store = StickyNote.init(std.testing.allocator);
    defer store.deinit();

    try std.testing.expect(store.get("alice", "#river") == null);

    try store.set("alice", "#river", "first note");
    try std.testing.expectEqualStrings("first note", store.get("alice", "#river").?);

    // Overwrite frees the old text and stores the new one.
    try store.set("alice", "#river", "second note");
    try std.testing.expectEqualStrings("second note", store.get("alice", "#river").?);

    // Distinct channel for the same account is independent.
    try store.set("alice", "#lake", "lake note");
    try std.testing.expectEqualStrings("second note", store.get("alice", "#river").?);
    try std.testing.expectEqualStrings("lake note", store.get("alice", "#lake").?);
}

test "set rejects empty and oversize notes" {
    var store = StickyNote.init(std.testing.allocator);
    defer store.deinit();

    try std.testing.expectError(NoteError.InvalidNote, store.set("carol", "#x", ""));

    const too_long = [_]u8{'a'} ** (max_note_len + 1);
    try std.testing.expectError(NoteError.InvalidNote, store.set("carol", "#x", &too_long));

    // Exactly at the boundary is accepted.
    const at_limit = [_]u8{'b'} ** max_note_len;
    try store.set("carol", "#x", &at_limit);
    try std.testing.expectEqual(@as(usize, max_note_len), store.get("carol", "#x").?.len);

    // A rejected overwrite must leave the prior note intact.
    try std.testing.expectError(NoteError.InvalidNote, store.set("carol", "#x", ""));
    try std.testing.expectEqual(@as(usize, max_note_len), store.get("carol", "#x").?.len);
}

test "clear removes a single note and reports presence" {
    var store = StickyNote.init(std.testing.allocator);
    defer store.deinit();

    try std.testing.expect(!store.clear("dave", "#none"));

    try store.set("dave", "#here", "present");
    try std.testing.expect(store.clear("dave", "#here"));
    try std.testing.expect(store.get("dave", "#here") == null);
    try std.testing.expect(!store.clear("dave", "#here"));
}

test "clearAccount scopes to exact account, prefix-confusable safe" {
    var store = StickyNote.init(std.testing.allocator);
    defer store.deinit();

    // "bob" is a strict prefix of "bobby"; the NUL anchor must keep them apart.
    try store.set("bob", "#a", "bob a");
    try store.set("bob", "#b", "bob b");
    try store.set("bobby", "#a", "bobby a");
    try store.set("bobby", "#c", "bobby c");

    const removed = store.clearAccount("bob");
    try std.testing.expectEqual(@as(usize, 2), removed);

    // bob's notes are gone.
    try std.testing.expect(store.get("bob", "#a") == null);
    try std.testing.expect(store.get("bob", "#b") == null);

    // bobby's notes survive untouched.
    try std.testing.expectEqualStrings("bobby a", store.get("bobby", "#a").?);
    try std.testing.expectEqualStrings("bobby c", store.get("bobby", "#c").?);

    // Clearing an account with no notes returns zero.
    try std.testing.expectEqual(@as(usize, 0), store.clearAccount("ghost"));
}

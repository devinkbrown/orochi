//! PinBoard: a per-channel general notes board for the Orochi IRC daemon.
//!
//! Each channel owns an ordered list of pinned notes (capped at `max_notes`).
//! Notes carry a monotonically increasing identifier, the note text, the
//! author handle, and a millisecond timestamp.
//!
//! Allocator discipline: every byte handed out is duplicated into board-owned
//! storage and released in `remove`, `clearChannel`, and `deinit`. No aliasing
//! of caller buffers is retained.

const std = @import("std");

/// Maximum number of notes retained per channel.
pub const max_notes: usize = 64;

/// Maximum byte length of a single note's text.
pub const max_text_len: usize = 300;

/// Errors surfaced when posting a note.
pub const PostError = error{
    /// The note text was empty or exceeded `max_text_len`.
    InvalidNote,
    /// The channel's board is full (`max_notes` reached).
    BoardFull,
} || std.mem.Allocator.Error;

/// A single pinned note. `text` and `by` are board-owned slices.
pub const Note = struct {
    id: u64,
    text: []u8,
    by: []u8,
    at_ms: i64,
};

const NoteList = std.ArrayListUnmanaged(Note);

pub const PinBoard = struct {
    allocator: std.mem.Allocator,
    channels: std.StringHashMap(NoteList),
    next_id: u64,

    pub fn init(allocator: std.mem.Allocator) PinBoard {
        return .{
            .allocator = allocator,
            .channels = std.StringHashMap(NoteList).init(allocator),
            .next_id = 1,
        };
    }

    /// Release every channel key, note buffer, and list. The board is unusable
    /// afterwards.
    pub fn deinit(self: *PinBoard) void {
        var it = self.channels.iterator();
        while (it.next()) |entry| {
            self.freeList(entry.value_ptr);
            self.allocator.free(entry.key_ptr.*);
        }
        self.channels.deinit();
        self.* = undefined;
    }

    fn freeNote(self: *PinBoard, note: Note) void {
        self.allocator.free(note.text);
        self.allocator.free(note.by);
    }

    fn freeList(self: *PinBoard, notes: *NoteList) void {
        for (notes.items) |note| self.freeNote(note);
        notes.deinit(self.allocator);
    }

    /// Post a note to `channel`. Returns the assigned identifier.
    ///
    /// Rejects empty or oversize text with `error.InvalidNote`, and a full
    /// board with `error.BoardFull`. On any failure no state is mutated.
    pub fn post(self: *PinBoard, channel: []const u8, text: []const u8, by: []const u8, now: i64) PostError!u64 {
        if (text.len == 0 or text.len > max_text_len) return error.InvalidNote;

        const gop = try self.channels.getOrPut(channel);
        if (!gop.found_existing) {
            const key_copy = self.allocator.dupe(u8, channel) catch |err| {
                self.channels.removeByPtr(gop.key_ptr);
                return err;
            };
            gop.key_ptr.* = key_copy;
            gop.value_ptr.* = NoteList.empty;
        }

        const notes = gop.value_ptr;
        if (notes.items.len >= max_notes) return error.BoardFull;

        // Allocate note buffers up front; clean up on partial failure.
        const text_copy = try self.allocator.dupe(u8, text);
        errdefer self.allocator.free(text_copy);
        const by_copy = try self.allocator.dupe(u8, by);
        errdefer self.allocator.free(by_copy);

        const id = self.next_id;
        try notes.append(self.allocator, .{
            .id = id,
            .text = text_copy,
            .by = by_copy,
            .at_ms = now,
        });
        self.next_id += 1;
        return id;
    }

    /// Remove the note with `id` from `channel`. Returns true if removed.
    pub fn remove(self: *PinBoard, channel: []const u8, id: u64) bool {
        const notes = self.channels.getPtr(channel) orelse return false;
        for (notes.items, 0..) |note, idx| {
            if (note.id == id) {
                self.freeNote(note);
                _ = notes.orderedRemove(idx);
                return true;
            }
        }
        return false;
    }

    /// Borrow the ordered note slice for `channel`. Empty slice if absent.
    pub fn list(self: *PinBoard, channel: []const u8) []const Note {
        const notes = self.channels.getPtr(channel) orelse return &[_]Note{};
        return notes.items;
    }

    /// Drop every note for `channel` and forget the channel. Returns the count
    /// of notes that were cleared.
    pub fn clearChannel(self: *PinBoard, channel: []const u8) usize {
        const entry = self.channels.fetchRemove(channel) orelse return 0;
        var removed_list = entry.value;
        const count = removed_list.items.len;
        self.freeList(&removed_list);
        self.allocator.free(entry.key);
        return count;
    }
};

test "post assigns increasing ids and lists in order" {
    var board = PinBoard.init(std.testing.allocator);
    defer board.deinit();

    const id1 = try board.post("#general", "first note", "alice", 1000);
    const id2 = try board.post("#general", "second note", "bob", 2000);
    try std.testing.expect(id2 > id1);

    const notes = board.list("#general");
    try std.testing.expectEqual(@as(usize, 2), notes.len);
    try std.testing.expectEqual(id1, notes[0].id);
    try std.testing.expectEqualStrings("first note", notes[0].text);
    try std.testing.expectEqualStrings("bob", notes[1].by);
    try std.testing.expectEqual(@as(i64, 2000), notes[1].at_ms);
}

test "post rejects empty and oversize text" {
    var board = PinBoard.init(std.testing.allocator);
    defer board.deinit();

    try std.testing.expectError(error.InvalidNote, board.post("#x", "", "alice", 0));

    const big = [_]u8{'a'} ** (max_text_len + 1);
    try std.testing.expectError(error.InvalidNote, board.post("#x", &big, "alice", 0));

    // Exactly the limit must succeed.
    const exact = [_]u8{'b'} ** max_text_len;
    _ = try board.post("#x", &exact, "alice", 0);
    try std.testing.expectEqual(@as(usize, 1), board.list("#x").len);
}

test "remove and clearChannel free notes" {
    var board = PinBoard.init(std.testing.allocator);
    defer board.deinit();

    const id1 = try board.post("#c", "a", "u", 1);
    _ = try board.post("#c", "b", "u", 2);
    const id3 = try board.post("#c", "c", "u", 3);

    try std.testing.expect(board.remove("#c", id1));
    try std.testing.expect(!board.remove("#c", id1));
    try std.testing.expect(!board.remove("#missing", id3));
    try std.testing.expectEqual(@as(usize, 2), board.list("#c").len);

    const cleared = board.clearChannel("#c");
    try std.testing.expectEqual(@as(usize, 2), cleared);
    try std.testing.expectEqual(@as(usize, 0), board.list("#c").len);
    try std.testing.expectEqual(@as(usize, 0), board.clearChannel("#c"));
}

test "board enforces max_notes cap" {
    var board = PinBoard.init(std.testing.allocator);
    defer board.deinit();

    var i: usize = 0;
    while (i < max_notes) : (i += 1) {
        _ = try board.post("#full", "note", "u", @intCast(i));
    }
    try std.testing.expectEqual(max_notes, board.list("#full").len);
    try std.testing.expectError(error.BoardFull, board.post("#full", "overflow", "u", 0));
}

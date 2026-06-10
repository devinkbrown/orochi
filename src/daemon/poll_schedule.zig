//! poll_schedule.zig — Orochi IRC daemon
//!
//! Scheduled future channel polls. A `PollSchedule` holds a bounded set of
//! pending poll launches, each keyed by a monotonically-assigned 64-bit id and
//! a fire timestamp expressed in epoch milliseconds. Callers periodically query
//! `due()` to discover polls whose fire time has elapsed, then `fire()` each one
//! once its poll has actually been launched, which removes it from the schedule.
//!
//! Clean-room implementation: import only `std`.

const std = @import("std");

/// Maximum number of questions a single poll question may contain (bytes).
pub const max_question_len: usize = 200;

/// Maximum number of simultaneously pending scheduled polls.
pub const capacity: usize = 256;

/// Errors that scheduling may return.
pub const ScheduleError = error{
    /// The schedule is already holding `capacity` pending polls.
    ScheduleFull,
    /// The supplied question exceeds `max_question_len` bytes.
    QuestionTooLong,
    /// Underlying allocator failed.
    OutOfMemory,
};

/// A single scheduled poll entry. Strings are owned by the schedule.
pub const Entry = struct {
    id: u64,
    channel: []u8,
    question: []u8,
    fire_ms: i64,
};

pub const PollSchedule = struct {
    allocator: std.mem.Allocator,
    entries: std.ArrayListUnmanaged(Entry),
    next_id: u64,

    /// Create an empty schedule.
    pub fn init(allocator: std.mem.Allocator) PollSchedule {
        return .{
            .allocator = allocator,
            .entries = .empty,
            .next_id = 1,
        };
    }

    /// Release every owned entry and the backing storage.
    pub fn deinit(self: *PollSchedule) void {
        for (self.entries.items) |entry| {
            self.allocator.free(entry.channel);
            self.allocator.free(entry.question);
        }
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    /// Schedule a poll for the given channel/question to fire at `fire_ms`.
    /// Returns the freshly-assigned id on success.
    pub fn schedule(
        self: *PollSchedule,
        channel: []const u8,
        question: []const u8,
        fire_ms: i64,
    ) ScheduleError!u64 {
        if (question.len > max_question_len) return ScheduleError.QuestionTooLong;
        if (self.entries.items.len >= capacity) return ScheduleError.ScheduleFull;

        const channel_copy = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(channel_copy);

        const question_copy = try self.allocator.dupe(u8, question);
        errdefer self.allocator.free(question_copy);

        const id = self.next_id;

        try self.entries.append(self.allocator, .{
            .id = id,
            .channel = channel_copy,
            .question = question_copy,
            .fire_ms = fire_ms,
        });

        self.next_id += 1;
        return id;
    }

    /// Fill `out` with pointers to entries whose `fire_ms <= now_ms`. Entries are
    /// NOT removed; the caller must call `fire()` once each poll has launched.
    /// Returns the number of due entries written (bounded by `out.len`).
    pub fn due(self: *const PollSchedule, now_ms: i64, out: []*const Entry) usize {
        var count: usize = 0;
        for (self.entries.items) |*entry| {
            if (count >= out.len) break;
            if (entry.fire_ms <= now_ms) {
                out[count] = entry;
                count += 1;
            }
        }
        return count;
    }

    /// Remove a previously-due poll once it has been launched.
    /// Returns true if an entry with `id` existed and was removed.
    pub fn fire(self: *PollSchedule, id: u64) bool {
        return self.removeById(id);
    }

    /// Cancel (remove) a pending poll without launching it.
    /// Returns true if an entry with `id` existed and was removed.
    pub fn cancel(self: *PollSchedule, id: u64) bool {
        return self.removeById(id);
    }

    /// Number of polls currently pending.
    pub fn pending(self: *const PollSchedule) usize {
        return self.entries.items.len;
    }

    fn removeById(self: *PollSchedule, id: u64) bool {
        for (self.entries.items, 0..) |entry, idx| {
            if (entry.id == id) {
                self.allocator.free(entry.channel);
                self.allocator.free(entry.question);
                _ = self.entries.orderedRemove(idx);
                return true;
            }
        }
        return false;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "schedule assigns unique ids and tracks pending count" {
    const allocator = std.testing.allocator;
    var sched = PollSchedule.init(allocator);
    defer sched.deinit();

    try std.testing.expectEqual(@as(usize, 0), sched.pending());

    const a = try sched.schedule("#zig", "Tabs or spaces?", 1_000);
    const b = try sched.schedule("#orochi", "Best fish?", 2_000);

    try std.testing.expect(a != b);
    try std.testing.expectEqual(@as(usize, 2), sched.pending());
}

test "due returns only entries at or before now and leaves them pending" {
    const allocator = std.testing.allocator;
    var sched = PollSchedule.init(allocator);
    defer sched.deinit();

    _ = try sched.schedule("#a", "past", 100);
    _ = try sched.schedule("#b", "now", 500);
    _ = try sched.schedule("#c", "future", 900);

    var buf: [capacity]*const Entry = undefined;
    const n = sched.due(500, buf[0..]);

    try std.testing.expectEqual(@as(usize, 2), n);
    // Due entries are not removed.
    try std.testing.expectEqual(@as(usize, 3), sched.pending());

    // Returned entries are exactly the ones with fire_ms <= 500.
    for (buf[0..n]) |e| {
        try std.testing.expect(e.fire_ms <= 500);
    }
}

test "fire removes a due poll once and returns false afterward" {
    const allocator = std.testing.allocator;
    var sched = PollSchedule.init(allocator);
    defer sched.deinit();

    const id = try sched.schedule("#chan", "Launch?", 10);
    _ = try sched.schedule("#chan", "Other", 20);

    var buf: [4]*const Entry = undefined;
    try std.testing.expectEqual(@as(usize, 2), sched.due(100, buf[0..]));

    try std.testing.expect(sched.fire(id));
    try std.testing.expectEqual(@as(usize, 1), sched.pending());

    // Firing the same id again must fail; it is gone.
    try std.testing.expect(!sched.fire(id));

    // It no longer shows up as due.
    const n = sched.due(100, buf[0..]);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expect(n == 1 and buf[0].id != id);
}

test "cancel removes a pending poll without launching" {
    const allocator = std.testing.allocator;
    var sched = PollSchedule.init(allocator);
    defer sched.deinit();

    const id = try sched.schedule("#room", "Cancel me", 5_000);
    try std.testing.expect(sched.cancel(id));
    try std.testing.expectEqual(@as(usize, 0), sched.pending());
    try std.testing.expect(!sched.cancel(id));
}

test "schedule rejects oversized questions and respects capacity" {
    const allocator = std.testing.allocator;
    var sched = PollSchedule.init(allocator);
    defer sched.deinit();

    const too_long = [_]u8{'x'} ** (max_question_len + 1);
    try std.testing.expectError(ScheduleError.QuestionTooLong, sched.schedule("#x", too_long[0..], 0));

    var i: usize = 0;
    while (i < capacity) : (i += 1) {
        _ = try sched.schedule("#fill", "q", @intCast(i));
    }
    try std.testing.expectEqual(capacity, sched.pending());
    try std.testing.expectError(ScheduleError.ScheduleFull, sched.schedule("#x", "overflow", 0));
}

// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! In-flight S2S migration journal.
//!
//! The journal records phase progress for migration tokens so repeated S2S
//! frames can be handled idempotently while still exposing retry pressure. It
//! owns no payload data: a token maps only to phase metadata, making it suitable
//! for retry tracking and eventual pruning of completed or aborted migrations.

const std = @import("std");

pub const Token = [16]u8;

pub const Phase = enum {
    offered,
    transferring,
    committed,
    aborted,
};

pub const Entry = struct {
    phase: Phase,
    /// Number of times the current phase has been recorded for this token.
    attempts: u16,
    first_ms: i64,
    last_ms: i64,
};

pub const Journal = struct {
    map: std.AutoHashMapUnmanaged(Token, Entry) = .empty,

    /// Insert or update a token. Re-recording the same phase bumps `attempts`;
    /// moving to a new phase starts the attempt count for that phase.
    pub fn record(
        self: *Journal,
        allocator: std.mem.Allocator,
        token: Token,
        phase: Phase,
        now_ms: i64,
    ) std.mem.Allocator.Error!void {
        const gop = try self.map.getOrPut(allocator, token);
        if (!gop.found_existing) {
            gop.value_ptr.* = .{
                .phase = phase,
                .attempts = 1,
                .first_ms = now_ms,
                .last_ms = now_ms,
            };
            return;
        }

        updateEntry(gop.value_ptr, phase, now_ms);
    }

    pub fn get(self: *const Journal, token: Token) ?Entry {
        return self.map.get(token);
    }

    /// Mark an existing token aborted. Returns false when the token is unknown.
    pub fn markAborted(self: *Journal, token: Token, now_ms: i64) bool {
        const entry = self.map.getPtr(token) orelse return false;
        updateEntry(entry, .aborted, now_ms);
        return true;
    }

    /// Remove terminal entries whose `last_ms` is older than `ttl_ms`.
    /// Offered/transferring entries are kept regardless of age.
    pub fn prune(self: *Journal, now_ms: i64, ttl_ms: i64) void {
        var it = self.map.iterator();
        while (it.next()) |slot| {
            if (isTerminal(slot.value_ptr.phase) and isExpired(now_ms, slot.value_ptr.last_ms, ttl_ms)) {
                const token = slot.key_ptr.*;
                _ = self.map.remove(token);
                it = self.map.iterator();
            }
        }
    }

    pub fn count(self: *const Journal) usize {
        return self.map.count();
    }

    pub fn deinit(self: *Journal, allocator: std.mem.Allocator) void {
        self.map.deinit(allocator);
        self.* = .{};
    }
};

fn updateEntry(entry: *Entry, phase: Phase, now_ms: i64) void {
    if (entry.phase == phase) {
        if (entry.attempts < std.math.maxInt(u16)) {
            entry.attempts += 1;
        }
    } else {
        entry.phase = phase;
        entry.attempts = 1;
    }
    entry.last_ms = now_ms;
}

fn isTerminal(phase: Phase) bool {
    return switch (phase) {
        .offered, .transferring => false,
        .committed, .aborted => true,
    };
}

fn isExpired(now_ms: i64, last_ms: i64, ttl_ms: i64) bool {
    const age: i128 = @as(i128, now_ms) - @as(i128, last_ms);
    return age > @as(i128, ttl_ms);
}

fn tokenWithLast(byte: u8) Token {
    var token: Token = .{0} ** 16;
    token[15] = byte;
    return token;
}

const testing = std.testing;

test "record creates an entry" {
    const allocator = testing.allocator;
    var journal: Journal = .{};
    defer journal.deinit(allocator);

    const token = tokenWithLast(1);
    try journal.record(allocator, token, .offered, 100);

    try testing.expectEqual(@as(usize, 1), journal.count());
    const entry = journal.get(token) orelse return error.MissingEntry;
    try testing.expectEqual(Phase.offered, entry.phase);
    try testing.expectEqual(@as(u16, 1), entry.attempts);
    try testing.expectEqual(@as(i64, 100), entry.first_ms);
    try testing.expectEqual(@as(i64, 100), entry.last_ms);
}

test "re-recording the same phase bumps attempts and last timestamp" {
    const allocator = testing.allocator;
    var journal: Journal = .{};
    defer journal.deinit(allocator);

    const token = tokenWithLast(2);
    try journal.record(allocator, token, .transferring, 10);
    try journal.record(allocator, token, .transferring, 20);

    const entry = journal.get(token) orelse return error.MissingEntry;
    try testing.expectEqual(Phase.transferring, entry.phase);
    try testing.expectEqual(@as(u16, 2), entry.attempts);
    try testing.expectEqual(@as(i64, 10), entry.first_ms);
    try testing.expectEqual(@as(i64, 20), entry.last_ms);
}

test "changing phase resets attempts for the new phase" {
    const allocator = testing.allocator;
    var journal: Journal = .{};
    defer journal.deinit(allocator);

    const token = tokenWithLast(3);
    try journal.record(allocator, token, .offered, 1);
    try journal.record(allocator, token, .offered, 2);
    try journal.record(allocator, token, .transferring, 3);

    const entry = journal.get(token) orelse return error.MissingEntry;
    try testing.expectEqual(Phase.transferring, entry.phase);
    try testing.expectEqual(@as(u16, 1), entry.attempts);
    try testing.expectEqual(@as(i64, 1), entry.first_ms);
    try testing.expectEqual(@as(i64, 3), entry.last_ms);
}

test "attempt counter saturates on repeated records" {
    var entry = Entry{
        .phase = .offered,
        .attempts = std.math.maxInt(u16),
        .first_ms = 0,
        .last_ms = 0,
    };

    updateEntry(&entry, .offered, 5);

    try testing.expectEqual(@as(u16, std.math.maxInt(u16)), entry.attempts);
    try testing.expectEqual(@as(i64, 5), entry.last_ms);
}

test "get and markAborted update existing tokens and reject unknown tokens" {
    const allocator = testing.allocator;
    var journal: Journal = .{};
    defer journal.deinit(allocator);

    const known = tokenWithLast(4);
    const unknown = tokenWithLast(5);
    try testing.expect(!journal.markAborted(unknown, 25));
    try testing.expectEqual(@as(usize, 0), journal.count());

    try journal.record(allocator, known, .transferring, 10);
    try testing.expect(journal.markAborted(known, 30));

    const entry = journal.get(known) orelse return error.MissingEntry;
    try testing.expectEqual(Phase.aborted, entry.phase);
    try testing.expectEqual(@as(u16, 1), entry.attempts);
    try testing.expectEqual(@as(i64, 10), entry.first_ms);
    try testing.expectEqual(@as(i64, 30), entry.last_ms);

    try testing.expect(journal.markAborted(known, 40));
    const retried = journal.get(known) orelse return error.MissingEntry;
    try testing.expectEqual(@as(u16, 2), retried.attempts);
    try testing.expectEqual(@as(i64, 40), retried.last_ms);
}

test "prune drops old terminal entries but keeps in-flight and recent entries" {
    const allocator = testing.allocator;
    var journal: Journal = .{};
    defer journal.deinit(allocator);

    const old_committed = tokenWithLast(6);
    const old_aborted = tokenWithLast(7);
    const old_offered = tokenWithLast(8);
    const old_transferring = tokenWithLast(9);
    const recent_committed = tokenWithLast(10);

    try journal.record(allocator, old_committed, .committed, 100);
    try journal.record(allocator, old_aborted, .aborted, 110);
    try journal.record(allocator, old_offered, .offered, 90);
    try journal.record(allocator, old_transferring, .transferring, 80);
    try journal.record(allocator, recent_committed, .committed, 190);

    journal.prune(200, 50);

    try testing.expectEqual(@as(usize, 3), journal.count());
    try testing.expectEqual(null, journal.get(old_committed));
    try testing.expectEqual(null, journal.get(old_aborted));
    try testing.expect(journal.get(old_offered) != null);
    try testing.expect(journal.get(old_transferring) != null);
    try testing.expect(journal.get(recent_committed) != null);
}

test "prune uses last timestamp and requires age greater than ttl" {
    const allocator = testing.allocator;
    var journal: Journal = .{};
    defer journal.deinit(allocator);

    const refreshed = tokenWithLast(11);
    const boundary = tokenWithLast(12);

    try journal.record(allocator, refreshed, .committed, 1);
    try journal.record(allocator, refreshed, .committed, 175);
    try journal.record(allocator, boundary, .aborted, 150);

    journal.prune(200, 50);

    try testing.expect(journal.get(refreshed) != null);
    try testing.expect(journal.get(boundary) != null);

    journal.prune(201, 50);
    try testing.expect(journal.get(boundary) == null);
}

// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Server-side IRCv3 draft/multiline reassembler.
//!
//! This module keeps allocator-owned accumulators keyed by batch reference for
//! one client. Each completed batch returns an allocator-owned assembled
//! message and removes the accumulator from the map.
const std = @import("std");
const multiline = @import("multiline.zig");

pub const PayloadCommand = multiline.PayloadCommand;
pub const draft_multiline_batch = multiline.draft_multiline_batch;
pub const draft_multiline_concat_tag = multiline.draft_multiline_concat_tag;

pub const default_max_bytes: usize = multiline.default_max_bytes;
pub const default_max_chunks: usize = multiline.default_max_lines;
pub const default_max_ref_len: usize = multiline.default_max_ref_len;
pub const default_max_target_len: usize = multiline.default_max_target_len;

pub const AssemblerError = std.mem.Allocator.Error || error{
    BatchAlreadyOpen,
    NoOpenBatch,
    InvalidBatchReference,
    InvalidTarget,
    ConcatWithoutPreviousChunk,
    MaxBytesExceeded,
    MaxChunksExceeded,
    EmptyBatch,
};

pub const Config = struct {
    max_bytes: usize = default_max_bytes,
    max_chunks: usize = default_max_chunks,
    max_ref_len: usize = default_max_ref_len,
    max_target_len: usize = default_max_target_len,
};

pub const AssembledMessage = struct {
    command: PayloadCommand,
    target: []u8,
    text: []u8,
    chunk_count: usize,

    pub fn deinit(self: *AssembledMessage, allocator: std.mem.Allocator) void {
        allocator.free(self.target);
        allocator.free(self.text);
        self.* = undefined;
    }
};

/// Per-client accumulator map keyed by multiline batch reference.
pub fn Assembler(comptime config: Config) type {
    comptime {
        if (config.max_bytes == 0) @compileError("multiline assembler max_bytes must be non-zero");
        if (config.max_chunks == 0) @compileError("multiline assembler max_chunks must be non-zero");
        if (config.max_ref_len == 0) @compileError("multiline assembler max_ref_len must be non-zero");
        if (config.max_target_len == 0) @compileError("multiline assembler max_target_len must be non-zero");
    }

    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        batches: std.StringHashMap(Batch),

        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .allocator = allocator,
                .batches = std.StringHashMap(Batch).init(allocator),
            };
        }

        pub fn deinit(self: *Self) void {
            self.abortAll();
            self.batches.deinit();
            self.* = undefined;
        }

        pub fn count(self: *const Self) usize {
            return self.batches.count();
        }

        pub fn contains(self: *const Self, ref: []const u8) bool {
            return self.batches.contains(ref);
        }

        pub fn begin(self: *Self, ref: []const u8, target: []const u8, command: PayloadCommand) AssemblerError!void {
            try validateReference(ref);
            try validateTarget(target);
            if (ref.len > config.max_ref_len) return error.InvalidBatchReference;
            if (target.len > config.max_target_len) return error.InvalidTarget;
            if (self.batches.contains(ref)) return error.BatchAlreadyOpen;

            const owned_ref = try self.allocator.dupe(u8, ref);
            errdefer self.allocator.free(owned_ref);

            var batch = try Batch.init(self.allocator, target, command);
            errdefer batch.deinit(self.allocator);

            try self.batches.putNoClobber(owned_ref, batch);
        }

        pub fn chunk(self: *Self, ref: []const u8, text: []const u8, concat_flag: bool) AssemblerError!void {
            var batch = self.batches.getPtr(ref) orelse return error.NoOpenBatch;
            try batch.append(self.allocator, text, concat_flag, config.max_bytes, config.max_chunks);
        }

        pub fn end(self: *Self, ref: []const u8) AssemblerError!AssembledMessage {
            const removed = self.batches.fetchRemove(ref) orelse return error.NoOpenBatch;
            self.allocator.free(removed.key);

            var batch = removed.value;
            errdefer batch.deinit(self.allocator);
            return batch.finish(self.allocator);
        }

        pub fn abort(self: *Self, ref: []const u8) bool {
            const removed = self.batches.fetchRemove(ref) orelse return false;
            self.allocator.free(removed.key);
            var batch = removed.value;
            batch.deinit(self.allocator);
            return true;
        }

        pub fn abortAll(self: *Self) void {
            var it = self.batches.iterator();
            while (it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                entry.value_ptr.deinit(self.allocator);
            }
            self.batches.clearRetainingCapacity();
        }
    };
}

const Batch = struct {
    target: []u8,
    command: PayloadCommand,
    text: std.ArrayList(u8) = .empty,
    chunk_count: usize = 0,

    fn init(allocator: std.mem.Allocator, target: []const u8, command: PayloadCommand) std.mem.Allocator.Error!Batch {
        return .{
            .target = try allocator.dupe(u8, target),
            .command = command,
        };
    }

    fn deinit(self: *Batch, allocator: std.mem.Allocator) void {
        allocator.free(self.target);
        self.text.deinit(allocator);
        self.* = undefined;
    }

    fn append(
        self: *Batch,
        allocator: std.mem.Allocator,
        chunk_text: []const u8,
        concat_flag: bool,
        max_bytes: usize,
        max_chunks: usize,
    ) AssemblerError!void {
        if (concat_flag and self.chunk_count == 0) return error.ConcatWithoutPreviousChunk;
        if (self.chunk_count >= max_chunks) return error.MaxChunksExceeded;

        const separator_len: usize = if (self.chunk_count == 0 or concat_flag) 0 else 1;
        const added = checkedAdd(separator_len, chunk_text.len) orelse return error.MaxBytesExceeded;
        const next_len = checkedAdd(self.text.items.len, added) orelse return error.MaxBytesExceeded;
        if (next_len > max_bytes) return error.MaxBytesExceeded;

        try self.text.ensureTotalCapacity(allocator, next_len);
        if (separator_len != 0) self.text.appendAssumeCapacity('\n');
        self.text.appendSliceAssumeCapacity(chunk_text);
        self.chunk_count += 1;
    }

    fn finish(self: *Batch, allocator: std.mem.Allocator) AssemblerError!AssembledMessage {
        if (self.chunk_count == 0) return error.EmptyBatch;

        const target = self.target;
        const text = try self.text.toOwnedSlice(allocator);
        const message = AssembledMessage{
            .command = self.command,
            .target = target,
            .text = text,
            .chunk_count = self.chunk_count,
        };
        return message;
    }
};

fn validateReference(ref: []const u8) AssemblerError!void {
    if (ref.len == 0) return error.InvalidBatchReference;
    for (ref) |ch| {
        switch (ch) {
            'a'...'z', 'A'...'Z', '0'...'9', '-' => {},
            else => return error.InvalidBatchReference,
        }
    }
}

fn validateTarget(target: []const u8) AssemblerError!void {
    if (target.len == 0) return error.InvalidTarget;
    for (target) |ch| {
        switch (ch) {
            0, '\r', '\n', ' ' => return error.InvalidTarget,
            else => {},
        }
    }
}

fn checkedAdd(a: usize, b: usize) ?usize {
    const sum, const overflow = @addWithOverflow(a, b);
    return if (overflow != 0) null else sum;
}

test "assemble concat vs newline chunks" {
    const Impl = Assembler(.{ .max_bytes = 128, .max_chunks = 8 });
    var assembler = Impl.init(std.testing.allocator);
    defer assembler.deinit();

    try assembler.begin("abc", "#onyx", .privmsg);
    try assembler.chunk("abc", "hello", false);
    try assembler.chunk("abc", "how ", false);
    try assembler.chunk("abc", "are you?", true);

    var msg = try assembler.end("abc");
    defer msg.deinit(std.testing.allocator);

    try std.testing.expectEqual(.privmsg, msg.command);
    try std.testing.expectEqualStrings("#onyx", msg.target);
    try std.testing.expectEqualStrings("hello\nhow are you?", msg.text);
    try std.testing.expectEqual(@as(usize, 3), msg.chunk_count);
    try std.testing.expectEqual(@as(usize, 0), assembler.count());
}

test "overflow rejection" {
    const Impl = Assembler(.{ .max_bytes = 5, .max_chunks = 2 });
    var assembler = Impl.init(std.testing.allocator);
    defer assembler.deinit();

    try assembler.begin("lim", "#c", .notice);
    try assembler.chunk("lim", "123", false);
    try std.testing.expectError(error.MaxBytesExceeded, assembler.chunk("lim", "45", false));
    try std.testing.expectError(error.MaxChunksExceeded, blk: {
        try assembler.chunk("lim", "4", true);
        break :blk assembler.chunk("lim", "5", true);
    });

    try std.testing.expect(assembler.abort("lim"));
    try std.testing.expectEqual(@as(usize, 0), assembler.count());
}

test "abort frees" {
    const Impl = Assembler(.{ .max_bytes = 64, .max_chunks = 4 });
    var assembler = Impl.init(std.testing.allocator);
    defer assembler.deinit();

    try assembler.begin("drop", "#c", .privmsg);
    try assembler.chunk("drop", "temporary", false);

    try std.testing.expect(assembler.abort("drop"));
    try std.testing.expect(!assembler.abort("drop"));
    try std.testing.expectEqual(@as(usize, 0), assembler.count());
}

test "multiple concurrent batches" {
    const Impl = Assembler(.{ .max_bytes = 64, .max_chunks = 4 });
    var assembler = Impl.init(std.testing.allocator);
    defer assembler.deinit();

    try assembler.begin("one", "#a", .privmsg);
    try assembler.begin("two", "#b", .notice);
    try assembler.chunk("one", "first", false);
    try assembler.chunk("two", "alpha", false);
    try assembler.chunk("one", "line", false);
    try assembler.chunk("two", "beta", true);

    var first = try assembler.end("one");
    defer first.deinit(std.testing.allocator);
    try std.testing.expectEqual(.privmsg, first.command);
    try std.testing.expectEqualStrings("#a", first.target);
    try std.testing.expectEqualStrings("first\nline", first.text);

    var second = try assembler.end("two");
    defer second.deinit(std.testing.allocator);
    try std.testing.expectEqual(.notice, second.command);
    try std.testing.expectEqualStrings("#b", second.target);
    try std.testing.expectEqualStrings("alphabeta", second.text);

    try std.testing.expectEqual(@as(usize, 0), assembler.count());
}

// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

const std = @import("std");

const Blake3 = std.crypto.hash.Blake3;
const checkpoint_magic = "SIDX";
const checkpoint_version: u8 = 1;
const checkpoint_header_len: usize = 29;
const checkpoint_checksum_len: usize = Blake3.digest_length;

pub const SearchHit = []const u8;

pub const SearchIndex = struct {
    pub const Config = struct {
        max_words: usize = 8192,
        max_ids_per_word: usize = 1024,
        max_token_bytes: usize = 64,
        max_id_bytes: usize = 1024,
        max_checkpoint_bytes: usize = 64 * 1024 * 1024,
    };

    pub const Error = std.mem.Allocator.Error || error{ TooManyWords, TooManyIds, TokenTooLong, IdTooLong };
    pub const CheckpointError = std.mem.Allocator.Error || error{
        BadMagic,
        UnsupportedVersion,
        ConfigMismatch,
        CapacityExceeded,
        CheckpointTooLarge,
        Truncated,
        TrailingBytes,
        ChecksumMismatch,
        NonCanonicalOrder,
        InvalidField,
    };

    const IdList = struct {
        ids: std.ArrayListUnmanaged([]u8) = .empty,

        fn deinit(self: *IdList, allocator: std.mem.Allocator) void {
            for (self.ids.items) |id| allocator.free(id);
            self.ids.deinit(allocator);
        }

        fn find(self: *const IdList, msgid: []const u8) ?usize {
            for (self.ids.items, 0..) |id, i| {
                if (std.mem.eql(u8, id, msgid)) return i;
            }
            return null;
        }
    };

    allocator: std.mem.Allocator,
    cfg: Config,
    words: std.StringHashMap(IdList),

    pub fn init(allocator: std.mem.Allocator) SearchIndex {
        return initWithConfig(allocator, .{});
    }

    pub fn initWithConfig(allocator: std.mem.Allocator, cfg: Config) SearchIndex {
        return .{
            .allocator = allocator,
            .cfg = cfg,
            .words = std.StringHashMap(IdList).init(allocator),
        };
    }

    pub fn deinit(self: *SearchIndex) void {
        var it = self.words.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.words.deinit();
        self.* = undefined;
    }

    pub fn index(self: *SearchIndex, msgid: []const u8, text: []const u8) Error!void {
        if (msgid.len > self.cfg.max_id_bytes) return error.IdTooLong;
        _ = self.remove(msgid);

        var start: ?usize = null;
        for (text, 0..) |byte, i| {
            if (isWordByte(byte)) {
                if (start == null) start = i;
            } else if (start) |s| {
                try self.addToken(msgid, text[s..i]);
                start = null;
            }
        }
        if (start) |s| try self.addToken(msgid, text[s..]);
    }

    pub fn find(self: *SearchIndex, word: []const u8) []const SearchHit {
        var token_buf: [256]u8 = undefined;
        const token = normalizeToken(&token_buf, word) orelse return &.{};
        const list = self.words.getPtr(token) orelse return &.{};
        return list.ids.items;
    }

    pub fn remove(self: *SearchIndex, msgid: []const u8) bool {
        var removed = false;

        while (true) {
            var pruned = false;
            var it = self.words.iterator();
            while (it.next()) |entry| {
                while (entry.value_ptr.find(msgid)) |idx| {
                    const owned_id = entry.value_ptr.ids.swapRemove(idx);
                    self.allocator.free(owned_id);
                    removed = true;
                }
                if (entry.value_ptr.ids.items.len == 0) {
                    const owned_word = entry.key_ptr.*;
                    entry.value_ptr.deinit(self.allocator);
                    self.words.removeByPtr(entry.key_ptr);
                    self.allocator.free(owned_word);
                    pruned = true;
                    break;
                }
            }
            if (!pruned) break;
        }

        return removed;
    }

    /// Canonical checkpoint of the exact word -> ordered-msgid projection.
    /// Search hit order is user-visible, so ids retain their list order while
    /// word records are byte-sorted for deterministic state arenas.
    pub fn encodeCheckpoint(self: *const SearchIndex, allocator: std.mem.Allocator) CheckpointError![]u8 {
        if (self.cfg.max_words > std.math.maxInt(u32) or
            self.cfg.max_ids_per_word > std.math.maxInt(u32) or
            self.cfg.max_token_bytes > std.math.maxInt(u32) or
            self.cfg.max_id_bytes > std.math.maxInt(u32) or
            self.cfg.max_checkpoint_bytes < checkpoint_header_len + checkpoint_checksum_len)
            return error.ConfigMismatch;

        const keys = try allocator.alloc([]const u8, self.words.count());
        defer allocator.free(keys);
        var key_count: usize = 0;
        var it = self.words.iterator();
        while (it.next()) |entry| {
            keys[key_count] = entry.key_ptr.*;
            key_count += 1;
        }
        std.mem.sort([]const u8, keys, {}, struct {
            fn lessThan(_: void, a: []const u8, b: []const u8) bool {
                return std.mem.lessThan(u8, a, b);
            }
        }.lessThan);

        var body_len: usize = 0;
        for (keys) |word| {
            const ids = self.words.get(word).?.ids.items;
            if (word.len == 0 or word.len > self.cfg.max_token_bytes or
                ids.len == 0 or ids.len > self.cfg.max_ids_per_word)
                return error.CapacityExceeded;
            body_len = checkpointAdd(body_len, 8, self.cfg.max_checkpoint_bytes) catch return error.CheckpointTooLarge;
            body_len = checkpointAdd(body_len, word.len, self.cfg.max_checkpoint_bytes) catch return error.CheckpointTooLarge;
            for (ids) |id| {
                if (id.len > self.cfg.max_id_bytes) return error.CapacityExceeded;
                body_len = checkpointAdd(body_len, 4, self.cfg.max_checkpoint_bytes) catch return error.CheckpointTooLarge;
                body_len = checkpointAdd(body_len, id.len, self.cfg.max_checkpoint_bytes) catch return error.CheckpointTooLarge;
            }
        }
        const prefix_len = checkpointAdd(checkpoint_header_len, body_len, self.cfg.max_checkpoint_bytes) catch
            return error.CheckpointTooLarge;
        const total_len = checkpointAdd(prefix_len, checkpoint_checksum_len, self.cfg.max_checkpoint_bytes) catch
            return error.CheckpointTooLarge;
        const out = try allocator.alloc(u8, total_len);
        errdefer allocator.free(out);
        @memcpy(out[0..4], checkpoint_magic);
        out[4] = checkpoint_version;
        checkpointWriteU32(out[5..9], @intCast(self.cfg.max_words));
        checkpointWriteU32(out[9..13], @intCast(self.cfg.max_ids_per_word));
        checkpointWriteU32(out[13..17], @intCast(self.cfg.max_token_bytes));
        checkpointWriteU32(out[17..21], @intCast(self.cfg.max_id_bytes));
        checkpointWriteU32(out[21..25], @intCast(keys.len));
        checkpointWriteU32(out[25..29], @intCast(body_len));
        var pos = checkpoint_header_len;
        for (keys) |word| {
            const ids = self.words.get(word).?.ids.items;
            checkpointWriteU32(out[pos..][0..4], @intCast(word.len));
            pos += 4;
            checkpointWriteU32(out[pos..][0..4], @intCast(ids.len));
            pos += 4;
            @memcpy(out[pos..][0..word.len], word);
            pos += word.len;
            for (ids) |id| {
                checkpointWriteU32(out[pos..][0..4], @intCast(id.len));
                pos += 4;
                @memcpy(out[pos..][0..id.len], id);
                pos += id.len;
            }
        }
        std.debug.assert(pos == prefix_len);
        checkpointHash(out[0..prefix_len], out[prefix_len..]);
        return out;
    }

    /// Decode into an unpublished replacement. Every allocation is owned by
    /// the candidate, so malformed bytes or OOM never mutate a live index.
    pub fn decodeCheckpoint(allocator: std.mem.Allocator, cfg: Config, bytes: []const u8) CheckpointError!SearchIndex {
        if (bytes.len > cfg.max_checkpoint_bytes) return error.CheckpointTooLarge;
        if (bytes.len < checkpoint_header_len + checkpoint_checksum_len) return error.Truncated;
        if (!std.mem.eql(u8, bytes[0..4], checkpoint_magic)) return error.BadMagic;
        if (bytes[4] != checkpoint_version) return error.UnsupportedVersion;
        if (checkpointReadU32(bytes[5..9]) != cfg.max_words or
            checkpointReadU32(bytes[9..13]) != cfg.max_ids_per_word or
            checkpointReadU32(bytes[13..17]) != cfg.max_token_bytes or
            checkpointReadU32(bytes[17..21]) != cfg.max_id_bytes)
            return error.ConfigMismatch;
        const word_count: usize = checkpointReadU32(bytes[21..25]);
        const body_len: usize = checkpointReadU32(bytes[25..29]);
        if (word_count > cfg.max_words) return error.CapacityExceeded;
        const prefix_len = checkpointAdd(checkpoint_header_len, body_len, cfg.max_checkpoint_bytes) catch
            return error.CheckpointTooLarge;
        const expected_len = checkpointAdd(prefix_len, checkpoint_checksum_len, cfg.max_checkpoint_bytes) catch
            return error.CheckpointTooLarge;
        if (bytes.len < expected_len) return error.Truncated;
        if (bytes.len > expected_len) return error.TrailingBytes;
        var digest: [checkpoint_checksum_len]u8 = undefined;
        checkpointHash(bytes[0..prefix_len], &digest);
        if (!std.mem.eql(u8, &digest, bytes[prefix_len..])) return error.ChecksumMismatch;

        var restored = SearchIndex.initWithConfig(allocator, cfg);
        errdefer restored.deinit();
        var reader = CheckpointReader{ .bytes = bytes, .pos = checkpoint_header_len, .end = prefix_len };
        var previous_word: ?[]const u8 = null;
        for (0..word_count) |_| {
            const word_len: usize = try reader.readU32();
            const id_count: usize = try reader.readU32();
            if (word_len == 0 or word_len > cfg.max_token_bytes or
                id_count == 0 or id_count > cfg.max_ids_per_word)
                return error.CapacityExceeded;
            const word = try reader.readBytes(word_len);
            var normalized: [256]u8 = undefined;
            const canonical = normalizeToken(&normalized, word) orelse return error.InvalidField;
            if (!std.mem.eql(u8, canonical, word)) return error.InvalidField;
            if (previous_word) |previous| {
                if (!std.mem.lessThan(u8, previous, word)) return error.NonCanonicalOrder;
            }
            previous_word = word;

            const owned_word = try allocator.dupe(u8, word);
            errdefer allocator.free(owned_word);
            var list: IdList = .{};
            errdefer list.deinit(allocator);
            try list.ids.ensureTotalCapacity(allocator, id_count);
            for (0..id_count) |_| {
                const id_len: usize = try reader.readU32();
                if (id_len > cfg.max_id_bytes) return error.CapacityExceeded;
                const id = try reader.readBytes(id_len);
                for (list.ids.items) |prior| {
                    if (std.mem.eql(u8, prior, id)) return error.InvalidField;
                }
                list.ids.appendAssumeCapacity(try allocator.dupe(u8, id));
            }
            try restored.words.putNoClobber(owned_word, list);
        }
        if (reader.pos != reader.end) return error.TrailingBytes;
        return restored;
    }

    pub fn replaceFromCheckpoint(self: *SearchIndex, bytes: []const u8) CheckpointError!void {
        const replacement = try decodeCheckpoint(self.allocator, self.cfg, bytes);
        var old = self.*;
        self.* = replacement;
        old.deinit();
    }

    fn addToken(self: *SearchIndex, msgid: []const u8, raw: []const u8) Error!void {
        if (raw.len > self.cfg.max_token_bytes) return error.TokenTooLong;

        var stack: [256]u8 = undefined;
        const token = normalizeToken(&stack, raw) orelse return;
        if (token.len > self.cfg.max_token_bytes) return error.TokenTooLong;

        const list = try self.ensureWord(token);
        if (list.find(msgid) != null) return;
        if (list.ids.items.len >= self.cfg.max_ids_per_word) return error.TooManyIds;

        const owned_id = try self.allocator.dupe(u8, msgid);
        errdefer self.allocator.free(owned_id);
        try list.ids.append(self.allocator, owned_id);
    }

    fn ensureWord(self: *SearchIndex, word: []const u8) Error!*IdList {
        if (self.words.getPtr(word)) |list| return list;
        if (self.words.count() >= self.cfg.max_words) return error.TooManyWords;

        const owned = try self.allocator.dupe(u8, word);
        errdefer self.allocator.free(owned);
        try self.words.putNoClobber(owned, .{});
        return self.words.getPtr(owned).?;
    }

    fn isWordByte(byte: u8) bool {
        return std.ascii.isAlphanumeric(byte) or byte == '_';
    }

    fn normalizeToken(buf: []u8, raw: []const u8) ?[]const u8 {
        if (raw.len == 0 or raw.len > buf.len) return null;
        for (raw, 0..) |byte, i| {
            if (!isWordByte(byte)) return null;
            buf[i] = std.ascii.toLower(byte);
        }
        return buf[0..raw.len];
    }
};

fn checkpointAdd(a: usize, b: usize, limit: usize) error{Overflow}!usize {
    const sum = std.math.add(usize, a, b) catch return error.Overflow;
    if (sum > limit) return error.Overflow;
    return sum;
}

fn checkpointWriteU32(out: []u8, value: u32) void {
    std.mem.writeInt(u32, out[0..4], value, .big);
}

fn checkpointReadU32(bytes: []const u8) u32 {
    return std.mem.readInt(u32, bytes[0..4], .big);
}

fn checkpointHash(bytes: []const u8, out: []u8) void {
    std.debug.assert(out.len == checkpoint_checksum_len);
    var digest: [checkpoint_checksum_len]u8 = undefined;
    Blake3.hash(bytes, &digest, .{});
    @memcpy(out, &digest);
}

fn rewriteCheckpointHash(bytes: []u8) void {
    if (bytes.len < checkpoint_checksum_len) return;
    const prefix_len = bytes.len - checkpoint_checksum_len;
    checkpointHash(bytes[0..prefix_len], bytes[prefix_len..]);
}

const CheckpointReader = struct {
    bytes: []const u8,
    pos: usize,
    end: usize,

    fn readBytes(self: *CheckpointReader, len: usize) error{Truncated}![]const u8 {
        const next = std.math.add(usize, self.pos, len) catch return error.Truncated;
        if (next > self.end) return error.Truncated;
        const out = self.bytes[self.pos..next];
        self.pos = next;
        return out;
    }

    fn readU32(self: *CheckpointReader) error{Truncated}!u32 {
        return checkpointReadU32(try self.readBytes(4));
    }
};

const testing = std.testing;

test "index lowercases words and returns matching ids" {
    var indexer = SearchIndex.init(testing.allocator);
    defer indexer.deinit();

    try indexer.index("m1", "Hello search SEARCH");
    try indexer.index("m2", "search path");

    const hits = indexer.find("SEARCH");
    try testing.expectEqual(@as(usize, 2), hits.len);
    try testing.expectEqualStrings("m1", hits[0]);
    try testing.expectEqualStrings("m2", hits[1]);
}

test "remove deletes an id from every word" {
    var indexer = SearchIndex.init(testing.allocator);
    defer indexer.deinit();

    try indexer.index("a", "alpha beta");
    try indexer.index("b", "alpha");

    try testing.expect(indexer.remove("a"));
    try testing.expectEqual(@as(usize, 1), indexer.find("alpha").len);
    try testing.expectEqualStrings("b", indexer.find("alpha")[0]);
    try testing.expectEqual(@as(usize, 0), indexer.find("beta").len);
    try testing.expect(!indexer.remove("a"));
}

test "reindex replaces old words for the same id" {
    var indexer = SearchIndex.init(testing.allocator);
    defer indexer.deinit();

    try indexer.index("same", "old topic");
    try indexer.index("same", "new topic");

    try testing.expectEqual(@as(usize, 0), indexer.find("old").len);
    try testing.expectEqual(@as(usize, 1), indexer.find("new").len);
    try testing.expectEqual(@as(usize, 1), indexer.find("topic").len);
}

test "configured bounds reject oversize indexes" {
    var indexer = SearchIndex.initWithConfig(testing.allocator, .{
        .max_words = 1,
        .max_ids_per_word = 1,
        .max_token_bytes = 4,
    });
    defer indexer.deinit();

    try indexer.index("a", "tiny");
    try testing.expectError(error.TooManyWords, indexer.index("b", "next"));
    try testing.expectError(error.TooManyIds, indexer.index("b", "tiny"));
    try testing.expectError(error.TokenTooLong, indexer.index("c", "large"));
}

test "checkpoint preserves exact ordered search projection" {
    const cfg = SearchIndex.Config{
        .max_words = 16,
        .max_ids_per_word = 8,
        .max_token_bytes = 16,
        .max_id_bytes = 16,
        .max_checkpoint_bytes = 4096,
    };
    var source = SearchIndex.initWithConfig(testing.allocator, cfg);
    defer source.deinit();
    try source.index("m2", "Beta alpha");
    try source.index("m1", "alpha gamma");
    try source.index("m3", "beta");

    const wire = try source.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(wire);
    var restored = try SearchIndex.decodeCheckpoint(testing.allocator, cfg, wire);
    defer restored.deinit();
    try testing.expectEqual(@as(usize, 2), restored.find("alpha").len);
    try testing.expectEqualStrings("m2", restored.find("alpha")[0]);
    try testing.expectEqualStrings("m1", restored.find("alpha")[1]);
    try testing.expectEqual(@as(usize, 2), restored.find("BETA").len);
    try testing.expectEqualStrings("m2", restored.find("beta")[0]);
    try testing.expectEqualStrings("m3", restored.find("beta")[1]);
    const wire_again = try restored.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(wire_again);
    try testing.expectEqualSlices(u8, wire, wire_again);
}

test "checkpoint decode and replacement fail atomically" {
    const cfg = SearchIndex.Config{
        .max_words = 8,
        .max_ids_per_word = 4,
        .max_token_bytes = 16,
        .max_id_bytes = 16,
        .max_checkpoint_bytes = 4096,
    };
    var source = SearchIndex.initWithConfig(testing.allocator, cfg);
    defer source.deinit();
    try source.index("new", "alpha beta");
    const wire = try source.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(wire);

    for (0..wire.len) |len| {
        if (SearchIndex.decodeCheckpoint(testing.allocator, cfg, wire[0..len])) |value| {
            var unexpected = value;
            unexpected.deinit();
            return error.TestUnexpectedResult;
        } else |_| {}
    }

    var target = SearchIndex.initWithConfig(testing.allocator, cfg);
    defer target.deinit();
    try target.index("old", "sentinel");
    const corrupt = try testing.allocator.dupe(u8, wire);
    defer testing.allocator.free(corrupt);
    corrupt[0] ^= 1;
    try testing.expectError(error.BadMagic, target.replaceFromCheckpoint(corrupt));
    try testing.expectEqual(@as(usize, 1), target.find("sentinel").len);
    try testing.expectEqualStrings("old", target.find("sentinel")[0]);

    const Sweep = struct {
        fn run(allocator: std.mem.Allocator, config: SearchIndex.Config, bytes: []const u8) !void {
            var decoded = try SearchIndex.decodeCheckpoint(allocator, config, bytes);
            defer decoded.deinit();
            try testing.expectEqual(@as(usize, 1), decoded.find("alpha").len);
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Sweep.run, .{ cfg, wire });

    const ReplaceSweep = struct {
        fn run(allocator: std.mem.Allocator, config: SearchIndex.Config, bytes: []const u8) !void {
            var replacement_target = SearchIndex.initWithConfig(allocator, config);
            defer replacement_target.deinit();
            try replacement_target.index("old", "sentinel");
            replacement_target.replaceFromCheckpoint(bytes) catch |err| {
                try testing.expectEqual(@as(usize, 1), replacement_target.find("sentinel").len);
                try testing.expectEqualStrings("old", replacement_target.find("sentinel")[0]);
                try testing.expectEqual(@as(usize, 0), replacement_target.find("alpha").len);
                return err;
            };
            try testing.expectEqual(@as(usize, 0), replacement_target.find("sentinel").len);
            try testing.expectEqualStrings("new", replacement_target.find("alpha")[0]);
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, ReplaceSweep.run, .{ cfg, wire });
}

test "checkpoint rejects trailing duplicate and capacity-losing data" {
    const cfg = SearchIndex.Config{
        .max_words = 8,
        .max_ids_per_word = 4,
        .max_token_bytes = 16,
        .max_id_bytes = 16,
        .max_checkpoint_bytes = 4096,
    };
    var source = SearchIndex.initWithConfig(testing.allocator, cfg);
    defer source.deinit();
    try source.index("aa", "alpha bravo");
    try source.index("bb", "alpha");
    const wire = try source.encodeCheckpoint(testing.allocator);
    defer testing.allocator.free(wire);

    const trailing = try testing.allocator.alloc(u8, wire.len + 1);
    defer testing.allocator.free(trailing);
    @memcpy(trailing[0..wire.len], wire);
    trailing[wire.len] = 0;
    try testing.expectError(error.TrailingBytes, SearchIndex.decodeCheckpoint(testing.allocator, cfg, trailing));

    var other_cfg = cfg;
    other_cfg.max_words += 1;
    try testing.expectError(error.ConfigMismatch, SearchIndex.decodeCheckpoint(testing.allocator, other_cfg, wire));

    const first_word_offset = checkpoint_header_len;
    const first_word_len: usize = checkpointReadU32(wire[first_word_offset..][0..4]);
    const first_id_count: usize = checkpointReadU32(wire[first_word_offset + 4 ..][0..4]);
    try testing.expectEqual(@as(usize, 2), first_id_count);
    const first_ids_offset = first_word_offset + 8 + first_word_len;
    const first_id_len: usize = checkpointReadU32(wire[first_ids_offset..][0..4]);
    const first_id = wire[first_ids_offset + 4 ..][0..first_id_len];
    const second_id_offset = first_ids_offset + 4 + first_id_len;
    const second_id_len: usize = checkpointReadU32(wire[second_id_offset..][0..4]);
    try testing.expectEqual(first_id_len, second_id_len);

    const duplicate_id = try testing.allocator.dupe(u8, wire);
    defer testing.allocator.free(duplicate_id);
    @memcpy(duplicate_id[second_id_offset + 4 ..][0..second_id_len], first_id);
    rewriteCheckpointHash(duplicate_id);
    try testing.expectError(error.InvalidField, SearchIndex.decodeCheckpoint(testing.allocator, cfg, duplicate_id));

    const second_word_offset = second_id_offset + 4 + second_id_len;
    const second_word_len: usize = checkpointReadU32(wire[second_word_offset..][0..4]);
    try testing.expectEqual(first_word_len, second_word_len);
    const first_word = wire[first_word_offset + 8 ..][0..first_word_len];
    const duplicate_word = try testing.allocator.dupe(u8, wire);
    defer testing.allocator.free(duplicate_word);
    @memcpy(duplicate_word[second_word_offset + 8 ..][0..second_word_len], first_word);
    rewriteCheckpointHash(duplicate_word);
    try testing.expectError(error.NonCanonicalOrder, SearchIndex.decodeCheckpoint(testing.allocator, cfg, duplicate_word));

    const excess_ids = try testing.allocator.dupe(u8, wire);
    defer testing.allocator.free(excess_ids);
    checkpointWriteU32(excess_ids[first_word_offset + 4 ..][0..4], @intCast(cfg.max_ids_per_word + 1));
    rewriteCheckpointHash(excess_ids);
    try testing.expectError(error.CapacityExceeded, SearchIndex.decodeCheckpoint(testing.allocator, cfg, excess_ids));
}

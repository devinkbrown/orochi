//! Property and fuzz tests for the IRCv3 CHATHISTORY Lotus append log.
//!
//! These tests stress the content-addressed ring with deterministic, bounded
//! append/redact/evict sequences. A small reference model tracks retained ring
//! entries so query results can be checked against the public API, while the
//! store's content map is checked for the refcount invariant after each step.
const std = @import("std");
const chathistory = @import("chathistory.zig");

const seed: u64 = 0x63_68_61_74_68_69_73_74;
const random_iterations = 768;
const lookup_iterations = 512;
const drain_iterations = max_entries_per_target * 3;
const max_targets = 3;
const max_entries_per_target = 16;
const max_query_limit = max_entries_per_target + 5;
const max_msgid_bytes = 24;

const Store = chathistory.HistoryStore(
    max_targets,
    max_entries_per_target,
    32,
    24,
    max_msgid_bytes,
    128,
);

const TargetSpec = struct {
    target: chathistory.Target,
};

const targets = [_]TargetSpec{
    .{ .target = .{ .kind = .channel, .name = "#alpha" } },
    .{ .target = .{ .kind = .channel, .name = "#beta" } },
    .{ .target = .{ .kind = .user, .name = "carol" } },
};

const content_bank = [_][]const u8{
    "same-body",
    "mesh event one",
    "mesh event two",
    "redaction candidate",
    "small body",
    "dedupe payload",
    "retained content",
    "last visible line",
};

const sender_bank = [_][]const u8{
    "alice",
    "bob",
    "carol",
    "dan",
};

const ModelEntry = struct {
    hash: chathistory.ContentHash = [_]u8{0} ** 32,
    msgid_buf: [max_msgid_bytes]u8 = [_]u8{0} ** max_msgid_bytes,
    msgid_len: usize = 0,
    timestamp: chathistory.Hlc = .{},
    content: []const u8 = "",
    tombstone: bool = false,

    fn msgid(self: *const ModelEntry) []const u8 {
        return self.msgid_buf[0..self.msgid_len];
    }
};

const TargetModel = struct {
    entries: [max_entries_per_target]ModelEntry =
        [_]ModelEntry{.{}} ** max_entries_per_target,
    start: usize = 0,
    len: usize = 0,

    fn slot(self: *const TargetModel, logical_index: usize) usize {
        return (self.start + logical_index) % max_entries_per_target;
    }

    fn entry(self: *const TargetModel, logical_index: usize) *const ModelEntry {
        return &self.entries[self.slot(logical_index)];
    }

    fn entryMut(self: *TargetModel, logical_index: usize) *ModelEntry {
        return &self.entries[self.slot(logical_index)];
    }

    fn append(
        self: *TargetModel,
        hash: chathistory.ContentHash,
        msgid: []const u8,
        timestamp: chathistory.Hlc,
        content: []const u8,
    ) void {
        const write_index = if (self.len < max_entries_per_target) blk: {
            const index = self.slot(self.len);
            self.len += 1;
            break :blk index;
        } else blk: {
            const index = self.start;
            self.start = (self.start + 1) % max_entries_per_target;
            break :blk index;
        };

        var item = ModelEntry{
            .hash = hash,
            .msgid_len = msgid.len,
            .timestamp = timestamp,
            .content = content,
        };
        @memcpy(item.msgid_buf[0..msgid.len], msgid);
        self.entries[write_index] = item;
    }

    fn redactByMsgid(self: *TargetModel, msgid: []const u8) usize {
        var redacted: usize = 0;
        var i: usize = 0;
        while (i < self.len) : (i += 1) {
            const item = self.entryMut(i);
            if (!item.tombstone and std.mem.eql(u8, item.msgid(), msgid)) {
                item.tombstone = true;
                redacted += 1;
            }
        }
        return redacted;
    }

    fn redactByHash(self: *TargetModel, hash: chathistory.ContentHash) usize {
        var redacted: usize = 0;
        var i: usize = 0;
        while (i < self.len) : (i += 1) {
            const item = self.entryMut(i);
            if (!item.tombstone and std.mem.eql(u8, &item.hash, &hash)) {
                item.tombstone = true;
                redacted += 1;
            }
        }
        return redacted;
    }
};

const Model = struct {
    targets: [max_targets]TargetModel = [_]TargetModel{.{}} ** max_targets,

    fn target(self: *Model, index: usize) *TargetModel {
        return &self.targets[index];
    }

    fn targetConst(self: *const Model, index: usize) *const TargetModel {
        return &self.targets[index];
    }
};

const ExpectedRefs = struct {
    hashes: [max_targets * max_entries_per_target]chathistory.ContentHash =
        [_]chathistory.ContentHash{[_]u8{0} ** 32} ** (max_targets * max_entries_per_target),
    refs: [max_targets * max_entries_per_target]usize =
        [_]usize{0} ** (max_targets * max_entries_per_target),
    len: usize = 0,

    fn add(self: *ExpectedRefs, hash: chathistory.ContentHash) void {
        var i: usize = 0;
        while (i < self.len) : (i += 1) {
            if (std.mem.eql(u8, &self.hashes[i], &hash)) {
                self.refs[i] += 1;
                return;
            }
        }

        self.hashes[self.len] = hash;
        self.refs[self.len] = 1;
        self.len += 1;
    }

    fn refsFor(self: *const ExpectedRefs, hash: chathistory.ContentHash) usize {
        var i: usize = 0;
        while (i < self.len) : (i += 1) {
            if (std.mem.eql(u8, &self.hashes[i], &hash)) return self.refs[i];
        }
        return 0;
    }
};

const QueryCase = union(enum) {
    latest,
    before: chathistory.Hlc,
    after: chathistory.Hlc,
    around: chathistory.Hlc,
    between: chathistory.HlcRange,

    fn op(self: QueryCase) chathistory.QueryOp {
        return switch (self) {
            .latest => .latest,
            .before => |anchor| .{ .before = anchor },
            .after => |anchor| .{ .after = anchor },
            .around => |anchor| .{ .around = anchor },
            .between => |range| .{ .between = range },
        };
    }
};

fn expectedRefs(model: *const Model) ExpectedRefs {
    var refs = ExpectedRefs{};
    for (&model.targets) |*target_model| {
        var i: usize = 0;
        while (i < target_model.len) : (i += 1) {
            const item = target_model.entry(i);
            if (!item.tombstone) refs.add(item.hash);
        }
    }
    return refs;
}

fn expectContentRefInvariant(store: *const Store, model: *const Model) !void {
    const expected = expectedRefs(model);
    try std.testing.expectEqual(expected.len, store.uniqueContentCount());

    var content_it = store.contents.iterator();
    while (content_it.next()) |entry| {
        const refs = expected.refsFor(entry.key_ptr.*);
        try std.testing.expect(refs > 0);
        try std.testing.expectEqual(refs, entry.value_ptr.refs);
    }

    var i: usize = 0;
    while (i < expected.len) : (i += 1) {
        try std.testing.expect(store.contents.contains(expected.hashes[i]));
    }
}

fn appendModeled(
    store: *Store,
    model: *Model,
    target_index: usize,
    msgid: []const u8,
    sender: []const u8,
    timestamp: chathistory.Hlc,
    content: []const u8,
) !void {
    const before_len = model.targetConst(target_index).len;
    const result = try store.append(targets[target_index].target, msgid, sender, timestamp, content);
    model.target(target_index).append(result.hash, msgid, timestamp, content);

    try std.testing.expectEqual(model.targetConst(target_index).len, result.target_len);
    try std.testing.expectEqual(before_len == max_entries_per_target, result.evicted);
}

fn redactMsgidModeled(store: *Store, model: *Model, target_index: usize, msgid: []const u8) !void {
    const expected = model.target(target_index).redactByMsgid(msgid);
    const actual = store.redactByMsgid(targets[target_index].target, msgid) catch |err| {
        try std.testing.expectEqual(@as(usize, 0), expected);
        switch (err) {
            error.NotFound => return,
            else => return err,
        }
    };
    try std.testing.expectEqual(expected, actual);
}

fn redactHashModeled(
    store: *Store,
    model: *Model,
    target_index: usize,
    hash: chathistory.ContentHash,
) !void {
    const expected = model.target(target_index).redactByHash(hash);
    const actual = store.redactByHash(targets[target_index].target, hash) catch |err| {
        try std.testing.expectEqual(@as(usize, 0), expected);
        switch (err) {
            error.NotFound => return,
            else => return err,
        }
    };
    try std.testing.expectEqual(expected, actual);
}

fn matches(timestamp: chathistory.Hlc, case: QueryCase) bool {
    return switch (case) {
        .latest, .around => true,
        .before => |anchor| chathistory.Hlc.compare(timestamp, anchor) == .lt,
        .after => |anchor| chathistory.Hlc.compare(timestamp, anchor) == .gt,
        .between => |range| chathistory.Hlc.compare(timestamp, range.start) != .lt and
            chathistory.Hlc.compare(timestamp, range.end) != .gt,
    };
}

fn countMatching(model: *const TargetModel, case: QueryCase) usize {
    var count: usize = 0;
    var i: usize = 0;
    while (i < model.len) : (i += 1) {
        if (matches(model.entry(i).timestamp, case)) count += 1;
    }
    return count;
}

fn findPivot(model: *const TargetModel, anchor: chathistory.Hlc) usize {
    var i: usize = 0;
    while (i < model.len) : (i += 1) {
        if (chathistory.Hlc.compare(model.entry(i).timestamp, anchor) != .lt) return i;
    }
    return model.len - 1;
}

fn expectedEntryAt(model: *const TargetModel, case: QueryCase, limit: usize, index: usize) *const ModelEntry {
    switch (case) {
        .around => |anchor| {
            const take = @min(model.len, limit);
            const pivot = findPivot(model, anchor);
            const desired_left = @min(pivot, (take - 1) / 2);
            var start = pivot - desired_left;
            var available = model.len - start;

            if (available < take) {
                const short = take - available;
                start -= @min(start, short);
                available = model.len - start;
            }

            return model.entry(start + index);
        },
        else => {
            const total = countMatching(model, case);
            const take = @min(total, limit);
            const skip = total - take;
            var skipped: usize = 0;
            var written: usize = 0;
            var i: usize = 0;
            while (i < model.len) : (i += 1) {
                const item = model.entry(i);
                if (!matches(item.timestamp, case)) continue;
                if (skipped < skip) {
                    skipped += 1;
                    continue;
                }
                if (written == index) return item;
                written += 1;
                if (written == take) break;
            }
            unreachable;
        },
    }
}

fn expectedQueryLen(model: *const TargetModel, case: QueryCase, limit: usize) usize {
    if (limit == 0) return 0;
    return switch (case) {
        .around => @min(model.len, limit),
        else => @min(countMatching(model, case), limit),
    };
}

fn expectResultMatchesEntry(result: chathistory.MessageRef, expected: *const ModelEntry) !void {
    try std.testing.expectEqualSlices(u8, &expected.hash, &result.hash);
    try std.testing.expectEqualStrings(expected.msgid(), result.msgid);
    try std.testing.expectEqual(expected.timestamp, result.timestamp);
    try std.testing.expectEqual(expected.tombstone, result.tombstone);

    if (expected.tombstone) {
        try std.testing.expect(result.content == null);
    } else {
        try std.testing.expect(result.content != null);
        try std.testing.expectEqualStrings(expected.content, result.content.?);
    }
}

fn expectQueryMatchesModel(
    store: *const Store,
    model: *const Model,
    target_index: usize,
    case: QueryCase,
    limit: usize,
) !void {
    var out: [max_query_limit]chathistory.MessageRef = undefined;
    const actual = try store.query(targets[target_index].target, case.op(), limit, &out);
    const target_model = model.targetConst(target_index);
    const expected_len = expectedQueryLen(target_model, case, limit);

    try std.testing.expect(actual.len <= limit);
    try std.testing.expectEqual(expected_len, actual.len);

    var i: usize = 0;
    while (i < actual.len) : (i += 1) {
        try expectResultMatchesEntry(actual[i], expectedEntryAt(target_model, case, limit, i));
    }
}

fn timestampFor(iteration: usize, logical: u16) !chathistory.Hlc {
    return chathistory.Hlc.init(1_000 + @as(u64, @intCast(iteration)) * 17, logical);
}

fn randomQueryCase(random: std.Random, iteration: usize) !QueryCase {
    const anchor_a = try timestampFor(random.intRangeAtMost(usize, 0, iteration + 4), 0);
    const anchor_b = try timestampFor(random.intRangeAtMost(usize, 0, iteration + 4), 0);

    return switch (random.intRangeLessThan(u8, 0, 5)) {
        0 => .latest,
        1 => .{ .before = anchor_a },
        2 => .{ .after = anchor_a },
        3 => .{ .around = anchor_a },
        else => if (chathistory.Hlc.compare(anchor_a, anchor_b) == .gt)
            .{ .between = .{ .start = anchor_b, .end = anchor_a } }
        else
            .{ .between = .{ .start = anchor_a, .end = anchor_b } },
    };
}

fn randomRetainedEntry(random: std.Random, model: *const TargetModel) ?*const ModelEntry {
    if (model.len == 0) return null;
    return model.entry(random.intRangeLessThan(usize, 0, model.len));
}

fn randomLiveEntry(random: std.Random, model: *const TargetModel) ?*const ModelEntry {
    if (model.len == 0) return null;
    var offset: usize = random.intRangeLessThan(usize, 0, model.len);
    var visited: usize = 0;
    while (visited < model.len) : (visited += 1) {
        const item = model.entry(offset);
        if (!item.tombstone) return item;
        offset = (offset + 1) % model.len;
    }
    return null;
}

test "random append redact and evict preserves content refcounts" {
    var store = Store.init(std.testing.allocator);
    defer store.deinit();
    var model = Model{};

    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();

    var msgid_buf: [max_msgid_bytes]u8 = undefined;
    var iteration: usize = 0;
    while (iteration < random_iterations) : (iteration += 1) {
        const target_index = random.intRangeLessThan(usize, 0, targets.len);
        const action = random.intRangeLessThan(u8, 0, 10);

        if (action < 6 or model.targetConst(target_index).len == 0) {
            const msgid = try std.fmt.bufPrint(&msgid_buf, "m{}", .{iteration});
            const sender = sender_bank[random.intRangeLessThan(usize, 0, sender_bank.len)];
            const content = content_bank[random.intRangeLessThan(usize, 0, content_bank.len)];
            try appendModeled(
                &store,
                &model,
                target_index,
                msgid,
                sender,
                try timestampFor(iteration, @intCast(iteration % 13)),
                content,
            );
        } else if (action < 8) {
            if (randomRetainedEntry(random, model.targetConst(target_index))) |item| {
                try redactMsgidModeled(&store, &model, target_index, item.msgid());
            }
        } else {
            if (randomLiveEntry(random, model.targetConst(target_index))) |item| {
                try redactHashModeled(&store, &model, target_index, item.hash);
            }
        }

        try expectContentRefInvariant(&store, &model);

        const query_target = random.intRangeLessThan(usize, 0, targets.len);
        const limit = random.intRangeAtMost(usize, 0, max_query_limit);
        try expectQueryMatchesModel(&store, &model, query_target, try randomQueryCase(random, iteration), limit);
    }
}

test "queries respect limits and retained bounds after redaction and eviction" {
    var store = Store.init(std.testing.allocator);
    defer store.deinit();
    var model = Model{};

    var msgid_buf: [max_msgid_bytes]u8 = undefined;
    var i: usize = 0;
    while (i < max_entries_per_target * 2) : (i += 1) {
        const msgid = try std.fmt.bufPrint(&msgid_buf, "q{}", .{i});
        try appendModeled(
            &store,
            &model,
            0,
            msgid,
            "alice",
            try timestampFor(i, 0),
            content_bank[i % content_bank.len],
        );
        if (i % 3 == 1) {
            try redactMsgidModeled(&store, &model, 0, msgid);
        }
    }

    const query_cases = [_]QueryCase{
        .latest,
        .{ .after = try timestampFor(4, 0) },
        .{ .before = try timestampFor(max_entries_per_target * 2, 0) },
        .{ .around = try timestampFor(max_entries_per_target, 0) },
        .{ .between = .{
            .start = try timestampFor(6, 0),
            .end = try timestampFor(max_entries_per_target * 2, 0),
        } },
    };

    for (query_cases) |case| {
        var limit: usize = 0;
        while (limit <= max_query_limit) : (limit += 1) {
            try expectQueryMatchesModel(&store, &model, 0, case, limit);
        }
    }

    try expectContentRefInvariant(&store, &model);
}

test "query around limit zero and one are safe" {
    var store = Store.init(std.testing.allocator);
    defer store.deinit();
    var model = Model{};

    var msgid_buf: [max_msgid_bytes]u8 = undefined;
    var i: usize = 0;
    while (i < 5) : (i += 1) {
        const msgid = try std.fmt.bufPrint(&msgid_buf, "a{}", .{i});
        try appendModeled(
            &store,
            &model,
            1,
            msgid,
            "bob",
            try timestampFor(i, 0),
            content_bank[i % content_bank.len],
        );
    }

    try expectQueryMatchesModel(&store, &model, 1, .{ .around = try timestampFor(2, 0) }, 0);
    try expectQueryMatchesModel(&store, &model, 1, .{ .around = try timestampFor(2, 0) }, 1);
    try expectQueryMatchesModel(&store, &model, 1, .{ .around = try timestampFor(99, 0) }, 1);
}

test "arbitrary msgid and hash redaction lookups never panic" {
    var store = Store.init(std.testing.allocator);
    defer store.deinit();
    var model = Model{};

    var prng = std.Random.DefaultPrng.init(seed ^ 0x9e37_79b9_7f4a_7c15);
    const random = prng.random();

    var msgid_buf: [max_msgid_bytes]u8 = undefined;
    var i: usize = 0;
    while (i < max_entries_per_target) : (i += 1) {
        const msgid = try std.fmt.bufPrint(&msgid_buf, "l{}", .{i});
        try appendModeled(
            &store,
            &model,
            2,
            msgid,
            "carol",
            try timestampFor(i, 0),
            content_bank[i % content_bank.len],
        );
    }

    var lookup_msgid: [max_msgid_bytes + 8]u8 = undefined;
    var lookup_hash: chathistory.ContentHash = undefined;
    i = 0;
    while (i < lookup_iterations) : (i += 1) {
        random.bytes(&lookup_msgid);
        const len = random.intRangeAtMost(usize, 0, lookup_msgid.len);
        _ = store.redactByMsgid(targets[2].target, lookup_msgid[0..len]) catch |err| switch (err) {
            error.InvalidMsgid, error.NotFound => {},
            else => return err,
        };

        random.bytes(&lookup_hash);
        try redactHashModeled(&store, &model, 2, lookup_hash);
        try expectContentRefInvariant(&store, &model);
    }
}

test "unique content count drains to zero after live entries are redacted and evicted" {
    var store = Store.init(std.testing.allocator);
    defer store.deinit();
    var model = Model{};

    var msgid_buf: [max_msgid_bytes]u8 = undefined;
    var i: usize = 0;
    while (i < drain_iterations) : (i += 1) {
        const msgid = try std.fmt.bufPrint(&msgid_buf, "d{}", .{i});
        try appendModeled(
            &store,
            &model,
            0,
            msgid,
            "dan",
            try timestampFor(i, 0),
            content_bank[i % content_bank.len],
        );
        try redactMsgidModeled(&store, &model, 0, msgid);
        try expectContentRefInvariant(&store, &model);
    }

    try std.testing.expectEqual(@as(usize, 0), store.uniqueContentCount());
    try expectContentRefInvariant(&store, &model);
}

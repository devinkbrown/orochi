//! IRCv3 message-redaction storage and wire helpers.
//!
//! This module models DELETE-with-tombstone behavior only. It stores redacted
//! `msgid` references per target and renders REDACT notifications into
//! caller-owned buffers.
const std = @import("std");

/// Maximum IRCv3 `msgid` length accepted by the redaction edge.
pub const MAX_MSGID_LEN: usize = 255;

/// Default maximum target identifier length accepted by the redaction edge.
pub const MAX_TARGET_LEN: usize = 512;

/// Default maximum source prefix length accepted by the redaction edge.
pub const MAX_SOURCE_LEN: usize = 512;

/// Default maximum human-readable redaction reason length.
pub const MAX_REASON_LEN: usize = 1024;

/// Standard-reply FAIL code tokens used by REDACT.
pub const RedactNumeric = enum(u2) {
    INVALID_TARGET,
    UNKNOWN_MSGID,
    REDACT_FORBIDDEN,

    /// Return the standard-reply wire token for this REDACT failure.
    pub fn token(self: RedactNumeric) []const u8 {
        return switch (self) {
            .INVALID_TARGET => "INVALID_TARGET",
            .UNKNOWN_MSGID => "UNKNOWN_MSGID",
            .REDACT_FORBIDDEN => "REDACT_FORBIDDEN",
        };
    }
};

/// Runtime bounds for parsing, formatting, and tombstone retention.
pub const Params = struct {
    max_targets: usize = 1024,
    max_tombstones_per_target: usize = 128,
    max_target_bytes: usize = MAX_TARGET_LEN,
    max_msgid_bytes: usize = MAX_MSGID_LEN,
    max_source_bytes: usize = MAX_SOURCE_LEN,
    max_reason_bytes: usize = MAX_REASON_LEN,
    max_line_bytes: usize = 8191,
};

/// Errors returned by borrowed REDACT parsing and validation.
pub const ParseError = error{
    MissingTarget,
    MissingMsgid,
    TooManyParameters,
    InvalidTarget,
    InvalidMsgid,
    InvalidSource,
    InvalidReason,
};

/// Errors returned by the owned tombstone store.
pub const StoreError = std.mem.Allocator.Error || ParseError || error{
    InvalidParams,
};

/// Errors returned by REDACT line formatting.
pub const FormatError = ParseError || error{
    OutputTooSmall,
};

/// Borrowed REDACT command request.
pub const RedactRequest = struct {
    target: []const u8,
    msgid: []const u8,
    reason: ?[]const u8 = null,
};

/// Owned record proving a message was redacted.
pub const Tombstone = struct {
    target: []u8,
    msgid: []u8,
    by: []u8,
    reason: []u8,
    ts: i64,
};

/// Per-target redaction tombstone store.
pub const RedactionStore = struct {
    allocator: std.mem.Allocator,
    params: Params,
    targets: std.StringHashMap(TargetState),
    target_order: std.ArrayListUnmanaged([]const u8) = .empty,

    /// Create a store with default limits.
    pub fn init(allocator: std.mem.Allocator) RedactionStore {
        return initWithParams(allocator, .{});
    }

    /// Create a store with caller-selected limits.
    pub fn initWithParams(allocator: std.mem.Allocator, params: Params) RedactionStore {
        return .{
            .allocator = allocator,
            .params = params,
            .targets = std.StringHashMap(TargetState).init(allocator),
        };
    }

    /// Free every owned target, msgid, author, reason, and backing table.
    pub fn deinit(self: *RedactionStore) void {
        self.clear();
        self.target_order.deinit(self.allocator);
        self.targets.deinit();
        self.* = undefined;
    }

    /// Remove all tombstones while retaining no caller-owned slices.
    pub fn clear(self: *RedactionStore) void {
        var it = self.targets.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.targets.clearRetainingCapacity();
        self.target_order.clearRetainingCapacity();
    }

    /// Record or refresh a redaction tombstone for `target` and `msgid`.
    pub fn record(
        self: *RedactionStore,
        target: []const u8,
        msgid: []const u8,
        by: []const u8,
        reason: ?[]const u8,
        ts: i64,
    ) StoreError!void {
        try validateParams(self.params);
        try validateTargetWith(self.params, target);
        try validateMsgidWith(self.params, msgid);
        try validateSourceWith(self.params, by);
        if (reason) |text| try validateReasonWith(self.params, text);

        const state = try self.getOrCreateTarget(target);
        if (state.tombstones.getPtr(msgid)) |existing| {
            const owned_by = try self.allocator.dupe(u8, by);
            errdefer self.allocator.free(owned_by);
            const owned_reason = try self.allocator.dupe(u8, reason orelse "");
            errdefer self.allocator.free(owned_reason);

            self.allocator.free(existing.by);
            self.allocator.free(existing.reason);
            existing.by = owned_by;
            existing.reason = owned_reason;
            existing.ts = ts;
            return;
        }

        if (state.tombstones.count() >= self.params.max_tombstones_per_target) {
            state.evictOldest(self.allocator);
        }

        const owned_target = try self.allocator.dupe(u8, target);
        var inserted = false;
        var appended = false;
        errdefer if (!inserted) self.allocator.free(owned_target);

        const owned_msgid = try self.allocator.dupe(u8, msgid);
        errdefer if (!inserted) self.allocator.free(owned_msgid);

        const owned_by = try self.allocator.dupe(u8, by);
        errdefer if (!inserted) self.allocator.free(owned_by);

        const owned_reason = try self.allocator.dupe(u8, reason orelse "");
        errdefer if (!inserted) self.allocator.free(owned_reason);

        try state.order.append(self.allocator, owned_msgid);
        appended = true;
        errdefer if (appended and !inserted) {
            state.order.items.len -= 1;
        };

        try state.tombstones.putNoClobber(owned_msgid, .{
            .target = owned_target,
            .msgid = owned_msgid,
            .by = owned_by,
            .reason = owned_reason,
            .ts = ts,
        });
        inserted = true;
    }

    /// Return true when `target` already has a tombstone for `msgid`.
    pub fn isRedacted(self: *const RedactionStore, target: []const u8, msgid: []const u8) bool {
        const state = self.targets.getPtr(target) orelse return false;
        return state.tombstones.contains(msgid);
    }

    /// Return a borrowed copy of the stored tombstone, if present.
    pub fn get(self: *const RedactionStore, target: []const u8, msgid: []const u8) ?Tombstone {
        const state = self.targets.getPtr(target) orelse return null;
        return state.tombstones.get(msgid);
    }

    /// Copy tombstones for `target` into `buf` in oldest-to-newest order.
    pub fn listForTarget(self: *const RedactionStore, target: []const u8, buf: []Tombstone) []Tombstone {
        const state = self.targets.getPtr(target) orelse return buf[0..0];
        var count: usize = 0;
        for (state.order.items) |msgid| {
            if (count == buf.len) break;
            if (state.tombstones.get(msgid)) |tombstone| {
                buf[count] = tombstone;
                count += 1;
            }
        }
        return buf[0..count];
    }

    fn getOrCreateTarget(self: *RedactionStore, target: []const u8) StoreError!*TargetState {
        if (self.targets.getPtr(target)) |state| return state;

        if (self.targets.count() >= self.params.max_targets) {
            self.evictOldestTarget();
        }

        const owned_target = try self.allocator.dupe(u8, target);
        var inserted = false;
        var appended = false;
        errdefer if (!inserted) self.allocator.free(owned_target);

        try self.target_order.append(self.allocator, owned_target);
        appended = true;
        errdefer if (appended and !inserted) {
            self.target_order.items.len -= 1;
        };

        try self.targets.putNoClobber(owned_target, TargetState.init(self.allocator));
        inserted = true;
        return self.targets.getPtr(owned_target).?;
    }

    fn evictOldestTarget(self: *RedactionStore) void {
        if (self.target_order.items.len == 0) return;
        const target = self.target_order.orderedRemove(0);
        var removed = self.targets.fetchRemove(target) orelse return;
        self.allocator.free(removed.key);
        removed.value.deinit(self.allocator);
    }
};

/// Parse `REDACT <target> <msgid> [:reason]` parameters without allocating.
pub fn parse(args: []const []const u8) ParseError!RedactRequest {
    return parseBounded(.{}, args);
}

/// Parse REDACT parameters with caller-selected validation limits.
pub fn parseBounded(params: Params, args: []const []const u8) ParseError!RedactRequest {
    if (args.len == 0) return error.MissingTarget;
    if (args.len < 2) return error.MissingMsgid;
    if (args.len > 3) return error.TooManyParameters;

    try validateTargetWith(params, args[0]);
    try validateMsgidWith(params, args[1]);

    const reason = if (args.len == 3) stripTrailingMarker(args[2]) else null;
    if (reason) |text| try validateReasonWith(params, text);

    return .{
        .target = args[0],
        .msgid = args[1],
        .reason = reason,
    };
}

/// Format `:<source> REDACT <target> <msgid> [:reason]` into `out`.
pub fn formatRedactLine(
    out: []u8,
    source_prefix: []const u8,
    target: []const u8,
    msgid: []const u8,
    reason: ?[]const u8,
) FormatError![]const u8 {
    return formatRedactLineBounded(.{}, out, source_prefix, target, msgid, reason);
}

/// Format a REDACT line with caller-selected validation limits.
pub fn formatRedactLineBounded(
    params: Params,
    out: []u8,
    source_prefix: []const u8,
    target: []const u8,
    msgid: []const u8,
    reason: ?[]const u8,
) FormatError![]const u8 {
    const source = stripPrefixMarker(source_prefix);
    try validateSourceWith(params, source);
    try validateTargetWith(params, target);
    try validateMsgidWith(params, msgid);
    if (reason) |text| try validateReasonWith(params, text);

    var writer = SliceWriter{ .buf = out };
    try writer.appendByte(':');
    try writer.append(source);
    try writer.append(" REDACT ");
    try writer.append(target);
    try writer.appendByte(' ');
    try writer.append(msgid);
    if (reason) |text| {
        try writer.append(" :");
        try writer.append(text);
    }
    if (writer.len > params.max_line_bytes) return error.OutputTooSmall;
    return writer.slice();
}

const TargetState = struct {
    tombstones: std.StringHashMap(Tombstone),
    order: std.ArrayListUnmanaged([]const u8) = .empty,

    fn init(allocator: std.mem.Allocator) TargetState {
        return .{ .tombstones = std.StringHashMap(Tombstone).init(allocator) };
    }

    fn deinit(self: *TargetState, allocator: std.mem.Allocator) void {
        var it = self.tombstones.iterator();
        while (it.next()) |entry| {
            freeStoredTombstone(allocator, entry.key_ptr.*, entry.value_ptr.*);
        }
        self.tombstones.deinit();
        self.order.deinit(allocator);
        self.* = undefined;
    }

    fn evictOldest(self: *TargetState, allocator: std.mem.Allocator) void {
        if (self.order.items.len == 0) return;
        const msgid = self.order.orderedRemove(0);
        const removed = self.tombstones.fetchRemove(msgid) orelse return;
        freeStoredTombstone(allocator, removed.key, removed.value);
    }
};

fn freeStoredTombstone(allocator: std.mem.Allocator, key: []const u8, tombstone: Tombstone) void {
    allocator.free(tombstone.target);
    allocator.free(key);
    allocator.free(tombstone.by);
    allocator.free(tombstone.reason);
}

fn validateParams(params: Params) StoreError!void {
    if (params.max_targets == 0) return error.InvalidParams;
    if (params.max_tombstones_per_target == 0) return error.InvalidParams;
    if (params.max_target_bytes == 0) return error.InvalidParams;
    if (params.max_msgid_bytes == 0) return error.InvalidParams;
    if (params.max_source_bytes == 0) return error.InvalidParams;
}

fn validateTargetWith(params: Params, target: []const u8) ParseError!void {
    if (target.len == 0 or target.len > params.max_target_bytes or target[0] == ':') {
        return error.InvalidTarget;
    }
    try validateAtom(target, error.InvalidTarget);
}

fn validateMsgidWith(params: Params, msgid: []const u8) ParseError!void {
    if (msgid.len == 0 or msgid.len > params.max_msgid_bytes or msgid[0] == ':') {
        return error.InvalidMsgid;
    }
    try validateAtom(msgid, error.InvalidMsgid);
}

fn validateSourceWith(params: Params, source: []const u8) ParseError!void {
    if (source.len == 0 or source.len > params.max_source_bytes) return error.InvalidSource;
    try validateAtom(source, error.InvalidSource);
}

fn validateReasonWith(params: Params, reason: []const u8) ParseError!void {
    if (reason.len > params.max_reason_bytes) return error.InvalidReason;
    for (reason) |ch| {
        switch (ch) {
            0, '\r', '\n' => return error.InvalidReason,
            else => {},
        }
    }
    if (!std.unicode.utf8ValidateSlice(reason)) return error.InvalidReason;
}

fn validateAtom(value: []const u8, err: ParseError) ParseError!void {
    for (value) |ch| {
        switch (ch) {
            0, ' ', '\r', '\n' => return err,
            else => {},
        }
    }
    if (!std.unicode.utf8ValidateSlice(value)) return err;
}

fn stripTrailingMarker(value: []const u8) []const u8 {
    if (value.len != 0 and value[0] == ':') return value[1..];
    return value;
}

fn stripPrefixMarker(value: []const u8) []const u8 {
    if (value.len != 0 and value[0] == ':') return value[1..];
    return value;
}

const SliceWriter = struct {
    buf: []u8,
    len: usize = 0,

    fn append(self: *SliceWriter, bytes: []const u8) FormatError!void {
        if (self.buf.len - self.len < bytes.len) return error.OutputTooSmall;
        @memcpy(self.buf[self.len .. self.len + bytes.len], bytes);
        self.len += bytes.len;
    }

    fn appendByte(self: *SliceWriter, byte: u8) FormatError!void {
        if (self.len == self.buf.len) return error.OutputTooSmall;
        self.buf[self.len] = byte;
        self.len += 1;
    }

    fn slice(self: *const SliceWriter) []const u8 {
        return self.buf[0..self.len];
    }
};

test "parse accepts borrowed redact parameters with optional reason" {
    // Arrange.
    const args = [_][]const u8{ "#mesh", "msg-123", ":wrong channel" };

    // Act.
    const request = try parse(&args);

    // Assert.
    try std.testing.expectEqualStrings("#mesh", request.target);
    try std.testing.expectEqualStrings("msg-123", request.msgid);
    try std.testing.expectEqualStrings("wrong channel", request.reason.?);
    try std.testing.expect(request.target.ptr == args[0].ptr);
    try std.testing.expect(request.msgid.ptr == args[1].ptr);
}

test "parse rejects malformed redact parameters" {
    // Arrange, act, assert.
    try std.testing.expectError(error.MissingTarget, parse(&.{}));
    try std.testing.expectError(error.MissingMsgid, parse(&.{"#mesh"}));
    try std.testing.expectError(error.TooManyParameters, parse(&.{ "#mesh", "m1", ":one", "two" }));
    try std.testing.expectError(error.InvalidTarget, parse(&.{ ":#mesh", "m1" }));
    try std.testing.expectError(error.InvalidMsgid, parse(&.{ "#mesh", "bad id" }));
    try std.testing.expectError(error.InvalidReason, parse(&.{ "#mesh", "m1", "bad\nreason" }));
}

test "redact fail code tokens match standard reply values" {
    // Arrange, act, assert.
    try std.testing.expectEqualStrings("INVALID_TARGET", RedactNumeric.INVALID_TARGET.token());
    try std.testing.expectEqualStrings("UNKNOWN_MSGID", RedactNumeric.UNKNOWN_MSGID.token());
    try std.testing.expectEqualStrings("REDACT_FORBIDDEN", RedactNumeric.REDACT_FORBIDDEN.token());
}

test "record stores tombstone and get returns borrowed values" {
    // Arrange.
    const allocator = std.testing.allocator;
    var store = RedactionStore.initWithParams(allocator, .{
        .max_targets = 4,
        .max_tombstones_per_target = 4,
    });
    defer store.deinit();

    // Act.
    try store.record("#mesh", "m1", "alice!u@example.test", "cleanup", 42);

    // Assert.
    try std.testing.expect(store.isRedacted("#mesh", "m1"));
    const tombstone = store.get("#mesh", "m1").?;
    try std.testing.expectEqualStrings("#mesh", tombstone.target);
    try std.testing.expectEqualStrings("m1", tombstone.msgid);
    try std.testing.expectEqualStrings("alice!u@example.test", tombstone.by);
    try std.testing.expectEqualStrings("cleanup", tombstone.reason);
    try std.testing.expectEqual(@as(i64, 42), tombstone.ts);
}

test "record isolates identical msgids by target" {
    // Arrange.
    const allocator = std.testing.allocator;
    var store = RedactionStore.initWithParams(allocator, .{
        .max_targets = 4,
        .max_tombstones_per_target = 4,
    });
    defer store.deinit();

    // Act.
    try store.record("#alpha", "same", "oper", null, 1);

    // Assert.
    try std.testing.expect(store.isRedacted("#alpha", "same"));
    try std.testing.expect(!store.isRedacted("#beta", "same"));
    try std.testing.expect(store.get("#beta", "same") == null);
}

test "record refreshes existing tombstone without growing target list" {
    // Arrange.
    const allocator = std.testing.allocator;
    var store = RedactionStore.initWithParams(allocator, .{
        .max_targets = 2,
        .max_tombstones_per_target = 2,
    });
    defer store.deinit();

    // Act.
    try store.record("#mesh", "m1", "alice", "first", 1);
    try store.record("#mesh", "m1", "bob", "second", 2);

    // Assert.
    var buf: [2]Tombstone = undefined;
    const listed = store.listForTarget("#mesh", &buf);
    try std.testing.expectEqual(@as(usize, 1), listed.len);
    try std.testing.expectEqualStrings("bob", listed[0].by);
    try std.testing.expectEqualStrings("second", listed[0].reason);
    try std.testing.expectEqual(@as(i64, 2), listed[0].ts);
}

test "oldest tombstones and targets are evicted without leaks" {
    // Arrange.
    const allocator = std.testing.allocator;
    var store = RedactionStore.initWithParams(allocator, .{
        .max_targets = 1,
        .max_tombstones_per_target = 2,
    });
    defer store.deinit();

    // Act.
    try store.record("#one", "m1", "oper", "one", 1);
    try store.record("#one", "m2", "oper", "two", 2);
    try store.record("#one", "m3", "oper", "three", 3);
    try store.record("#two", "m4", "oper", "four", 4);

    // Assert.
    try std.testing.expect(!store.isRedacted("#one", "m1"));
    try std.testing.expect(!store.isRedacted("#one", "m2"));
    try std.testing.expect(!store.isRedacted("#one", "m3"));
    try std.testing.expect(store.isRedacted("#two", "m4"));
}

test "listForTarget returns oldest to newest tombstones up to buffer capacity" {
    // Arrange.
    const allocator = std.testing.allocator;
    var store = RedactionStore.initWithParams(allocator, .{
        .max_targets = 2,
        .max_tombstones_per_target = 4,
    });
    defer store.deinit();
    try store.record("#mesh", "m1", "oper", "one", 1);
    try store.record("#mesh", "m2", "oper", "two", 2);
    try store.record("#mesh", "m3", "oper", "three", 3);

    // Act.
    var buf: [2]Tombstone = undefined;
    const listed = store.listForTarget("#mesh", &buf);

    // Assert.
    try std.testing.expectEqual(@as(usize, 2), listed.len);
    try std.testing.expectEqualStrings("m1", listed[0].msgid);
    try std.testing.expectEqualStrings("m2", listed[1].msgid);
}

test "formatRedactLine renders source prefixed redact with reason" {
    // Arrange.
    var out: [128]u8 = undefined;

    // Act.
    const line = try formatRedactLine(&out, "server.example", "#mesh", "m1", "policy");

    // Assert.
    try std.testing.expectEqualStrings(":server.example REDACT #mesh m1 :policy", line);
}

test "formatRedactLine validates inputs and output capacity" {
    // Arrange.
    var out: [16]u8 = undefined;

    // Act, assert.
    try std.testing.expectError(
        error.OutputTooSmall,
        formatRedactLine(&out, "server.example", "#mesh", "m1", "policy"),
    );
    try std.testing.expectError(
        error.InvalidSource,
        formatRedactLine(&out, "bad source", "#mesh", "m1", null),
    );
    try std.testing.expectError(
        error.InvalidTarget,
        formatRedactLine(&out, "server.example", "bad target", "m1", null),
    );
    try std.testing.expectError(
        error.InvalidMsgid,
        formatRedactLine(&out, "server.example", "#mesh", "bad id", null),
    );
}

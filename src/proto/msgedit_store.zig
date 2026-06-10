//! Message-edit and redaction helpers for caller-owned message logs.
//!
//! This module intentionally does not own history storage. Callers pass the
//! target log slice they already maintain, and this file mutates only matching
//! records by IRCv3 `msgid`.
const std = @import("std");
const msgedit = @import("msgedit.zig");

pub const MAX_EDIT_TEXT_LEN: usize = msgedit.MAX_TEXT_VALUE_LEN;
pub const MAX_REASON_LEN: usize = msgedit.MAX_TEXT_VALUE_LEN;
pub const MAX_NOTIFICATION_LEN: usize = 8191;

pub const Error = std.mem.Allocator.Error || msgedit.ParseError || error{
    PermissionDenied,
    NotFound,
    AlreadyRedacted,
    TextTooLong,
    RevisionOverflow,
};

pub const Operation = enum {
    edit,
    redact,
};

/// Minimal mutable view of one caller-owned log entry.
pub const Record = struct {
    msgid: []const u8,
    text: []u8,
    revision: u32 = 0,
    tombstone: bool = false,
};

/// Authorization has already been decided by the caller.
pub const Permission = struct {
    allowed: bool,
};

pub const EditRequest = struct {
    target: []const u8,
    msgid: []const u8,
    text: []const u8,
};

pub const RedactRequest = struct {
    target: []const u8,
    msgid: []const u8,
    reason: ?[]const u8 = null,
};

pub const Request = union(Operation) {
    edit: EditRequest,
    redact: RedactRequest,
};

pub const Scratch = struct {
    interaction: msgedit.InteractionScratch = .{},
};

/// The replacement body is returned so the caller can release it if owned.
pub const ApplyResult = struct {
    index: usize,
    msgid: []const u8,
    revision: u32,
    replaced_text: ?[]u8 = null,
};

pub const EditNotification = struct {
    target: []const u8,
    msgid: []const u8,
    revision: u32,
    text: []const u8,
};

pub const RedactNotification = struct {
    target: []const u8,
    msgid: []const u8,
    reason: ?[]const u8 = null,
};

pub fn parseRedact(input: []const u8) Error!RedactRequest {
    const raw = try msgedit.parseRedact(input);
    return .{
        .target = raw.target,
        .msgid = raw.msgid,
        .reason = raw.reason,
    };
}

pub fn parseEdit(input: []const u8, scratch: *Scratch) Error!EditRequest {
    const raw = try msgedit.parseInteraction(input, &scratch.interaction);
    if (raw.command != .privmsg) return error.InvalidCommand;
    const msgid = raw.edit_of orelse return error.MissingMsgid;
    const text = raw.body orelse return error.MissingEditBody;
    try validateText(text);
    return .{
        .target = raw.target,
        .msgid = msgid,
        .text = text,
    };
}

pub fn parseRequest(input: []const u8, scratch: *Scratch) Error!Request {
    if (parseRedact(input)) |redact| {
        return .{ .redact = redact };
    } else |err| switch (err) {
        error.InvalidCommand => {},
        else => return err,
    }

    return .{ .edit = try parseEdit(input, scratch) };
}

pub fn applyRequest(
    allocator: std.mem.Allocator,
    records: []Record,
    request: Request,
    permission: Permission,
) Error!ApplyResult {
    return switch (request) {
        .edit => |edit| applyEdit(allocator, records, edit, permission),
        .redact => |redact| applyRedact(records, redact, permission),
    };
}

pub fn applyEdit(
    allocator: std.mem.Allocator,
    records: []Record,
    request: EditRequest,
    permission: Permission,
) Error!ApplyResult {
    if (!permission.allowed) return error.PermissionDenied;
    if (!msgedit.isValidMsgid(request.msgid)) return error.InvalidMsgid;
    try validateText(request.text);

    const index = findNewest(records, request.msgid) orelse return error.NotFound;
    if (records[index].tombstone) return error.AlreadyRedacted;
    if (records[index].revision == std.math.maxInt(u32)) return error.RevisionOverflow;

    const owned_text = try allocator.dupe(u8, request.text);
    const old_text = records[index].text;
    records[index].text = owned_text;
    records[index].revision += 1;

    return .{
        .index = index,
        .msgid = records[index].msgid,
        .revision = records[index].revision,
        .replaced_text = old_text,
    };
}

pub fn applyRedact(
    records: []Record,
    request: RedactRequest,
    permission: Permission,
) Error!ApplyResult {
    if (!permission.allowed) return error.PermissionDenied;
    if (!msgedit.isValidMsgid(request.msgid)) return error.InvalidMsgid;
    if (request.reason) |reason| try validateReason(reason);

    const index = findNewest(records, request.msgid) orelse return error.NotFound;
    records[index].tombstone = true;

    return .{
        .index = index,
        .msgid = records[index].msgid,
        .revision = records[index].revision,
    };
}

pub fn buildEditNotification(
    allocator: std.mem.Allocator,
    notification: EditNotification,
) Error![]u8 {
    try validateTarget(notification.target);
    if (!msgedit.isValidMsgid(notification.msgid)) return error.InvalidMsgid;
    try validateText(notification.text);

    var line: std.ArrayList(u8) = .empty;
    errdefer line.deinit(allocator);

    try appendByte(&line, allocator, '@');
    try appendTag(&line, allocator, "msgid", notification.msgid);
    try appendByte(&line, allocator, ';');
    try appendTag(&line, allocator, "+draft/edit", notification.msgid);
    try appendByte(&line, allocator, ';');
    try appendTagUnsigned(&line, allocator, "+draft/revision", notification.revision);
    try appendSlice(&line, allocator, " PRIVMSG ");
    try appendSlice(&line, allocator, notification.target);
    try appendSlice(&line, allocator, " :");
    try appendSlice(&line, allocator, notification.text);

    return line.toOwnedSlice(allocator);
}

pub fn buildRedactNotification(
    allocator: std.mem.Allocator,
    notification: RedactNotification,
) Error![]u8 {
    try validateTarget(notification.target);
    if (!msgedit.isValidMsgid(notification.msgid)) return error.InvalidMsgid;
    if (notification.reason) |reason| try validateReason(reason);

    var line: std.ArrayList(u8) = .empty;
    errdefer line.deinit(allocator);

    try appendByte(&line, allocator, '@');
    try appendTag(&line, allocator, "msgid", notification.msgid);
    try appendByte(&line, allocator, ';');
    try appendTag(&line, allocator, "+draft/redact", notification.msgid);
    try appendSlice(&line, allocator, " TAGMSG ");
    try appendSlice(&line, allocator, notification.target);
    if (notification.reason) |reason| {
        try appendSlice(&line, allocator, " :");
        try appendSlice(&line, allocator, reason);
    }

    return line.toOwnedSlice(allocator);
}

fn findNewest(records: []Record, msgid: []const u8) ?usize {
    var scanned: usize = 0;
    while (scanned < records.len) : (scanned += 1) {
        const index = records.len - 1 - scanned;
        if (msgedit.authorizationKeyMatches(records[index].msgid, msgid)) return index;
    }
    return null;
}

fn validateTarget(target: []const u8) Error!void {
    if (target.len == 0 or target[0] == ':') return error.InvalidTarget;
    for (target) |ch| {
        switch (ch) {
            0, ' ', '\r', '\n' => return error.InvalidTarget,
            else => {},
        }
    }
    if (!std.unicode.utf8ValidateSlice(target)) return error.InvalidTarget;
}

fn validateText(text: []const u8) Error!void {
    if (text.len > MAX_EDIT_TEXT_LEN) return error.TextTooLong;
    for (text) |ch| {
        switch (ch) {
            0, '\r', '\n' => return error.InvalidTagValue,
            else => {},
        }
    }
    if (!std.unicode.utf8ValidateSlice(text)) return error.InvalidTagValue;
}

fn validateReason(reason: []const u8) Error!void {
    if (reason.len > MAX_REASON_LEN) return error.TextTooLong;
    try validateText(reason);
}

fn appendTag(line: *std.ArrayList(u8), allocator: std.mem.Allocator, key: []const u8, value: []const u8) Error!void {
    try appendSlice(line, allocator, key);
    try appendByte(line, allocator, '=');
    try appendEscapedTagValue(line, allocator, value);
}

fn appendTagUnsigned(line: *std.ArrayList(u8), allocator: std.mem.Allocator, key: []const u8, value: u32) Error!void {
    var buf: [10]u8 = undefined;
    const rendered = std.fmt.bufPrint(&buf, "{d}", .{value}) catch unreachable;
    try appendTag(line, allocator, key, rendered);
}

fn appendEscapedTagValue(line: *std.ArrayList(u8), allocator: std.mem.Allocator, value: []const u8) Error!void {
    for (value) |ch| {
        switch (ch) {
            0 => return error.InvalidTagValue,
            ';' => try appendSlice(line, allocator, "\\:"),
            ' ' => try appendSlice(line, allocator, "\\s"),
            '\r' => try appendSlice(line, allocator, "\\r"),
            '\n' => try appendSlice(line, allocator, "\\n"),
            '\\' => try appendSlice(line, allocator, "\\\\"),
            else => try appendByte(line, allocator, ch),
        }
    }
}

fn appendSlice(line: *std.ArrayList(u8), allocator: std.mem.Allocator, bytes: []const u8) Error!void {
    if (bytes.len > MAX_NOTIFICATION_LEN - line.items.len) return error.OutputTooSmall;
    try line.appendSlice(allocator, bytes);
}

fn appendByte(line: *std.ArrayList(u8), allocator: std.mem.Allocator, byte: u8) Error!void {
    if (line.items.len == MAX_NOTIFICATION_LEN) return error.OutputTooSmall;
    try line.append(allocator, byte);
}

test "parse redact and edit requests" {
    const redact = try parseRedact("REDACT #orochi G6PuDDBWQYmu3HmXXOAPzA :wrong paste");
    try std.testing.expectEqualStrings("#orochi", redact.target);
    try std.testing.expectEqualStrings("G6PuDDBWQYmu3HmXXOAPzA", redact.msgid);
    try std.testing.expectEqualStrings("wrong paste", redact.reason.?);

    var scratch = Scratch{};
    const edit = try parseEdit(
        "@+draft/edit=server1-1480339715754191-21 PRIVMSG #orochi :patched message",
        &scratch,
    );
    try std.testing.expectEqualStrings("#orochi", edit.target);
    try std.testing.expectEqualStrings("server1-1480339715754191-21", edit.msgid);
    try std.testing.expectEqualStrings("patched message", edit.text);

    const request = try parseRequest("REDACT kain m-1", &scratch);
    try std.testing.expectEqual(Operation.redact, std.meta.activeTag(request));
}

test "apply edit and redact over caller records" {
    const allocator = std.testing.allocator;
    const text_one = try allocator.dupe(u8, "one");
    const text_two = try allocator.dupe(u8, "two");

    var records = [_]Record{
        .{ .msgid = "m1", .text = text_one },
        .{ .msgid = "m2", .text = text_two },
    };
    defer allocator.free(records[0].text);
    defer allocator.free(records[1].text);

    const edited = try applyEdit(allocator, &records, .{
        .target = "#orochi",
        .msgid = "m1",
        .text = "one edited",
    }, .{ .allowed = true });
    allocator.free(edited.replaced_text.?);

    try std.testing.expectEqual(@as(usize, 0), edited.index);
    try std.testing.expectEqual(@as(u32, 1), records[0].revision);
    try std.testing.expectEqualStrings("one edited", records[0].text);
    try std.testing.expect(!records[0].tombstone);

    const redacted = try applyRedact(&records, .{
        .target = "#orochi",
        .msgid = "m2",
    }, .{ .allowed = true });
    try std.testing.expectEqual(@as(usize, 1), redacted.index);
    try std.testing.expect(records[1].tombstone);
}

test "build notification bytes" {
    const allocator = std.testing.allocator;

    const edit = try buildEditNotification(allocator, .{
        .target = "#orochi",
        .msgid = "m1",
        .revision = 2,
        .text = "patched message",
    });
    defer allocator.free(edit);
    try std.testing.expectEqualStrings(
        "@msgid=m1;+draft/edit=m1;+draft/revision=2 PRIVMSG #orochi :patched message",
        edit,
    );

    const redact = try buildRedactNotification(allocator, .{
        .target = "#orochi",
        .msgid = "m1",
        .reason = "wrong paste",
    });
    defer allocator.free(redact);
    try std.testing.expectEqualStrings(
        "@msgid=m1;+draft/redact=m1 TAGMSG #orochi :wrong paste",
        redact,
    );
}

test "reject malformed requests and notifications" {
    var scratch = Scratch{};
    try std.testing.expectError(error.MissingMsgid, parseRedact("REDACT #orochi"));
    try std.testing.expectError(error.MissingEditBody, parseEdit("@+draft/edit=abc TAGMSG #c", &scratch));
    try std.testing.expectError(error.InvalidCommand, parseEdit("@+draft/edit=abc NOTICE #c :body", &scratch));
    try std.testing.expectError(error.InvalidMsgid, buildRedactNotification(std.testing.allocator, .{
        .target = "#orochi",
        .msgid = ":bad",
    }));
}

test "permission denied does not mutate records" {
    const allocator = std.testing.allocator;
    const text = try allocator.dupe(u8, "before");
    defer allocator.free(text);

    var records = [_]Record{
        .{ .msgid = "m1", .text = text },
    };

    try std.testing.expectError(error.PermissionDenied, applyEdit(allocator, &records, .{
        .target = "#orochi",
        .msgid = "m1",
        .text = "after",
    }, .{ .allowed = false }));

    try std.testing.expectEqual(@as(u32, 0), records[0].revision);
    try std.testing.expectEqualStrings("before", records[0].text);
    try std.testing.expect(!records[0].tombstone);

    try std.testing.expectError(error.PermissionDenied, applyRedact(&records, .{
        .target = "#orochi",
        .msgid = "m1",
    }, .{ .allowed = false }));
    try std.testing.expect(!records[0].tombstone);
}

// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! IRCv3 message interactions: replies, reactions, typing, edits, and redaction.
//!
//! The module keeps all attacker-facing parsing zero-copy and all outbound
//! rendering in caller-owned buffers. Message references are opaque IRCv3
//! `msgid` values; comparisons for authorization keys use a fixed-width scan.
const std = @import("std");
const irc_line = @import("irc_line.zig");

/// Conservative bound for message references carried in params or tags.
pub const MAX_MSGID_LEN: usize = 255;

/// Reaction payload bound. IRCv3 intentionally leaves reaction values open;
/// Orochi caps bytes at the protocol edge before moderation/storage.
pub const MAX_REACTION_LEN: usize = 128;

/// Optional redaction reason and edit body safety bound for this edge parser.
pub const MAX_TEXT_VALUE_LEN: usize = 1024;

pub const ParseError = irc_line.ParseError || irc_line.UnescapeError || error{
    MissingTarget,
    MissingMsgid,
    InvalidCommand,
    InvalidTarget,
    InvalidMsgid,
    InvalidTagKey,
    InvalidTagValue,
    InvalidTypingState,
    ConflictingTags,
    MissingReply,
    MissingEditBody,
    OutputTooSmall,
};

pub const MessageCommand = enum {
    privmsg,
    notice,
    tagmsg,

    fn parse(command: []const u8) ?MessageCommand {
        if (std.ascii.eqlIgnoreCase(command, "PRIVMSG")) return .privmsg;
        if (std.ascii.eqlIgnoreCase(command, "NOTICE")) return .notice;
        if (std.ascii.eqlIgnoreCase(command, "TAGMSG")) return .tagmsg;
        return null;
    }

    fn bytes(self: MessageCommand) []const u8 {
        return switch (self) {
            .privmsg => "PRIVMSG",
            .notice => "NOTICE",
            .tagmsg => "TAGMSG",
        };
    }
};

pub const TypingState = enum {
    active,
    paused,
    done,

    fn parse(value: []const u8) ?TypingState {
        if (std.mem.eql(u8, value, "active")) return .active;
        if (std.mem.eql(u8, value, "paused")) return .paused;
        if (std.mem.eql(u8, value, "done")) return .done;
        return null;
    }

    fn bytes(self: TypingState) []const u8 {
        return switch (self) {
            .active => "active",
            .paused => "paused",
            .done => "done",
        };
    }
};

pub const ReactionMode = enum {
    add,
    remove,
};

pub const Reaction = struct {
    mode: ReactionMode = .add,
    value: []const u8,
};

/// Parsed PRIVMSG/NOTICE/TAGMSG interaction metadata.
pub const Interaction = struct {
    command: MessageCommand,
    target: []const u8,
    body: ?[]const u8 = null,
    reply_to: ?[]const u8 = null,
    reaction: ?Reaction = null,
    typing: ?TypingState = null,
    edit_of: ?[]const u8 = null,

    pub fn isEdit(self: Interaction) bool {
        return self.edit_of != null;
    }

    pub fn isReply(self: Interaction) bool {
        return self.reply_to != null;
    }
};

/// Caller-owned decode storage for `parseInteraction`.
pub const InteractionScratch = struct {
    reply_to: [MAX_MSGID_LEN]u8 = undefined,
    reaction: [MAX_REACTION_LEN]u8 = undefined,
    typing: ["paused".len]u8 = undefined,
    edit_of: [MAX_MSGID_LEN]u8 = undefined,
};

/// Parsed REDACT command.
pub const Redact = struct {
    target: []const u8,
    msgid: []const u8,
    reason: ?[]const u8 = null,
};

/// Parsed `EDIT <target> <msgid> :<text>` command.
pub const EditCommand = struct {
    target: []const u8,
    msgid: []const u8,
    text: []const u8,
};

/// Caller-facing builder shape for message interactions.
pub const BuildInteraction = struct {
    command: MessageCommand = .tagmsg,
    target: []const u8,
    body: ?[]const u8 = null,
    reply_to: ?[]const u8 = null,
    reaction: ?Reaction = null,
    typing: ?TypingState = null,
    edit_of: ?[]const u8 = null,
};

/// Return true when `msgid` is valid for IRCv3 tag and command-param use.
pub fn isValidMsgid(msgid: []const u8) bool {
    if (msgid.len == 0 or msgid.len > MAX_MSGID_LEN) return false;
    if (msgid[0] == ':') return false;
    for (msgid) |ch| {
        switch (ch) {
            0, ' ', '\r', '\n' => return false,
            else => {},
        }
    }
    return std.unicode.utf8ValidateSlice(msgid);
}

/// Validate and parse one client or server relayed PRIVMSG/NOTICE/TAGMSG.
pub fn parseInteraction(input: []const u8, scratch: *InteractionScratch) ParseError!Interaction {
    var line = try parseTaggedLine(input);
    const command = MessageCommand.parse(line.command) orelse return error.InvalidCommand;
    const params = line.paramSlice();
    if (params.len == 0) return error.MissingTarget;
    try validateTarget(params[0]);

    var reply_to: ?[]const u8 = null;
    var reaction: ?Reaction = null;
    var typing: ?TypingState = null;
    var edit_of: ?[]const u8 = null;

    for (line.tagSlice()) |tag| {
        if (isReplyTag(tag.key)) {
            const decoded = try decodeTagValue(tag.value_raw, &scratch.reply_to, MAX_MSGID_LEN);
            if (!isValidMsgid(decoded)) return error.InvalidMsgid;
            reply_to = decoded;
        } else if (std.mem.eql(u8, tag.key, "+draft/react")) {
            if (reaction != null) return error.ConflictingTags;
            const decoded = try decodeTagValue(tag.value_raw, &scratch.reaction, MAX_REACTION_LEN);
            try validateFreeTagValue(decoded, MAX_REACTION_LEN);
            reaction = .{ .mode = .add, .value = decoded };
        } else if (std.mem.eql(u8, tag.key, "+draft/unreact")) {
            if (reaction != null) return error.ConflictingTags;
            const decoded = try decodeTagValue(tag.value_raw, &scratch.reaction, MAX_REACTION_LEN);
            try validateFreeTagValue(decoded, MAX_REACTION_LEN);
            reaction = .{ .mode = .remove, .value = decoded };
        } else if (isTypingTag(tag.key)) {
            const decoded = try decodeTagValue(tag.value_raw, &scratch.typing, "paused".len);
            typing = TypingState.parse(decoded) orelse return error.InvalidTypingState;
        } else if (std.mem.eql(u8, tag.key, "+draft/edit")) {
            const decoded = try decodeTagValue(tag.value_raw, &scratch.edit_of, MAX_MSGID_LEN);
            if (!isValidMsgid(decoded)) return error.InvalidMsgid;
            edit_of = decoded;
        }
    }

    if (reaction != null and reply_to == null) return error.MissingReply;
    if (typing != null and (reaction != null or reply_to != null or edit_of != null or command != .tagmsg)) {
        return error.ConflictingTags;
    }
    if (edit_of != null and (command == .tagmsg or line.trailing == null)) return error.MissingEditBody;

    return .{
        .command = command,
        .target = params[0],
        .body = line.trailing,
        .reply_to = reply_to,
        .reaction = reaction,
        .typing = typing,
        .edit_of = edit_of,
    };
}

/// Parse `REDACT <target> <msgid> [reason]`.
pub fn parseRedact(input: []const u8) ParseError!Redact {
    const line = try parseTaggedLine(input);
    if (!std.ascii.eqlIgnoreCase(line.command, "REDACT")) return error.InvalidCommand;
    const params = line.paramSlice();
    if (params.len == 0) return error.MissingTarget;
    if (params.len < 2) return error.MissingMsgid;
    try validateTarget(params[0]);
    if (!isValidMsgid(params[1])) return error.InvalidMsgid;
    if (line.trailing) |reason| try validateText(reason, MAX_TEXT_VALUE_LEN);
    return .{
        .target = params[0],
        .msgid = params[1],
        .reason = line.trailing,
    };
}

/// Parse `EDIT <target> <msgid> :<text>`.
pub fn parseEditCommand(input: []const u8) ParseError!EditCommand {
    const line = try parseTaggedLine(input);
    if (!std.ascii.eqlIgnoreCase(line.command, "EDIT")) return error.InvalidCommand;
    const params = line.paramSlice();
    if (params.len == 0) return error.MissingTarget;
    if (params.len < 2) return error.MissingMsgid;
    const text = line.trailing orelse return error.MissingEditBody;
    try validateTarget(params[0]);
    if (!isValidMsgid(params[1])) return error.InvalidMsgid;
    try validateText(text, MAX_TEXT_VALUE_LEN);
    return .{
        .target = params[0],
        .msgid = params[1],
        .text = text,
    };
}

/// Fixed-width authorization-key check for redaction/edit decisions keyed by msgid.
pub fn authorizationKeyMatches(auth_msgid: []const u8, requested_msgid: []const u8) bool {
    if (!isValidMsgid(auth_msgid) or !isValidMsgid(requested_msgid)) return false;

    var diff: usize = auth_msgid.len ^ requested_msgid.len;
    var index: usize = 0;
    while (index < MAX_MSGID_LEN) : (index += 1) {
        const a: u8 = if (index < auth_msgid.len) auth_msgid[index] else 0;
        const b: u8 = if (index < requested_msgid.len) requested_msgid[index] else 0;
        diff |= @as(usize, a ^ b);
    }
    return diff == 0;
}

/// Convenience wrapper for `authorizationKeyMatches(auth_msgid, redact.msgid)`.
pub fn redactAuthorized(auth_msgid: []const u8, redact: Redact) bool {
    return authorizationKeyMatches(auth_msgid, redact.msgid);
}

/// Render a PRIVMSG/NOTICE/TAGMSG with Orochi draft interaction tags.
pub fn buildInteraction(message: BuildInteraction, out: []u8) ParseError![]const u8 {
    try validateBuildInteraction(message);

    var writer = SliceWriter{ .buf = out };
    var tags = TagWriter{ .writer = &writer };

    if (message.reply_to) |msgid| try tags.value("+draft/reply", msgid);
    if (message.reaction) |reaction| {
        const key: []const u8 = if (reaction.mode == .add) "+draft/react" else "+draft/unreact";
        try tags.escaped(key, reaction.value);
    }
    if (message.typing) |typing| try tags.value("+draft/typing", typing.bytes());
    if (message.edit_of) |msgid| try tags.value("+draft/edit", msgid);
    try tags.finish();

    try writer.append(message.command.bytes());
    try writer.byte(' ');
    try writer.append(message.target);
    if (message.body) |body| {
        try writer.append(" :");
        try writer.append(body);
    }
    return writer.slice();
}

/// Render a REDACT command.
pub fn buildRedact(redact: Redact, out: []u8) ParseError![]const u8 {
    try validateTarget(redact.target);
    if (!isValidMsgid(redact.msgid)) return error.InvalidMsgid;
    if (redact.reason) |reason| try validateText(reason, MAX_TEXT_VALUE_LEN);

    var writer = SliceWriter{ .buf = out };
    try writer.append("REDACT ");
    try writer.append(redact.target);
    try writer.byte(' ');
    try writer.append(redact.msgid);
    if (redact.reason) |reason| {
        try writer.append(" :");
        try writer.append(reason);
    }
    return writer.slice();
}

fn validateBuildInteraction(message: BuildInteraction) ParseError!void {
    try validateTarget(message.target);
    if (message.reply_to) |msgid| {
        if (!isValidMsgid(msgid)) return error.InvalidMsgid;
    }
    if (message.reaction) |reaction| {
        try validateFreeTagValue(reaction.value, MAX_REACTION_LEN);
        if (message.reply_to == null) return error.MissingReply;
    }
    if (message.typing != null and (message.reply_to != null or message.reaction != null or message.edit_of != null or message.body != null or message.command != .tagmsg)) {
        return error.ConflictingTags;
    }
    if (message.edit_of) |msgid| {
        if (!isValidMsgid(msgid)) return error.InvalidMsgid;
        if (message.command == .tagmsg or message.body == null) return error.MissingEditBody;
    }
    if (message.command != .tagmsg and message.body == null) return error.MissingEditBody;
    if (message.body) |body| try validateText(body, MAX_TEXT_VALUE_LEN);
}

fn decodeTagValue(value_raw: ?[]const u8, scratch: []u8, max_len: usize) ParseError![]const u8 {
    const raw = value_raw orelse return error.InvalidTagValue;
    const decoded = try irc_line.unescapeTagValue(raw, scratch);
    try validateFreeTagValue(decoded, max_len);
    return decoded;
}

fn validateTarget(target: []const u8) ParseError!void {
    if (target.len == 0 or target[0] == ':') return error.InvalidTarget;
    try validateAtom(target, irc_line.MAX_LINE_BODY);
}

fn validateAtom(value: []const u8, max_len: usize) ParseError!void {
    if (value.len == 0 or value.len > max_len) return error.InvalidTagValue;
    for (value) |ch| {
        switch (ch) {
            0, ' ', '\r', '\n' => return error.InvalidTagValue,
            else => {},
        }
    }
    if (!std.unicode.utf8ValidateSlice(value)) return error.InvalidTagValue;
}

fn validateText(value: []const u8, max_len: usize) ParseError!void {
    if (value.len > max_len) return error.InvalidTagValue;
    for (value) |ch| {
        switch (ch) {
            0, '\r', '\n' => return error.InvalidTagValue,
            else => {},
        }
    }
    if (!std.unicode.utf8ValidateSlice(value)) return error.InvalidTagValue;
}

fn validateFreeTagValue(value: []const u8, max_len: usize) ParseError!void {
    try validateText(value, max_len);
}

fn isReplyTag(key: []const u8) bool {
    return std.mem.eql(u8, key, "+draft/reply") or std.mem.eql(u8, key, "+reply");
}

pub fn isTypingTag(key: []const u8) bool {
    return std.mem.eql(u8, key, "+draft/typing") or std.mem.eql(u8, key, "+typing");
}

const RawTag = struct {
    key: []const u8,
    value_raw: ?[]const u8,
};

const RawLine = struct {
    raw: []const u8,
    command: []const u8,
    params: [irc_line.MAXPARA][]const u8 = @splat(""),
    param_count: usize = 0,
    tags: [irc_line.MAXTAGS]RawTag = @splat(.{ .key = "", .value_raw = null }),
    tag_count: usize = 0,
    trailing: ?[]const u8 = null,

    fn paramSlice(self: *const RawLine) []const []const u8 {
        return self.params[0..self.param_count];
    }

    fn tagSlice(self: *const RawLine) []const RawTag {
        return self.tags[0..self.tag_count];
    }
};

fn parseTaggedLine(input: []const u8) ParseError!RawLine {
    const body = stripLineEnding(input);
    if (body.len == 0) return error.EmptyLine;
    if (body.len > irc_line.MAX_LINE_BODY) return error.OversizeLine;
    for (body) |ch| {
        switch (ch) {
            0 => return error.EmbeddedNul,
            '\r', '\n' => return error.EmbeddedLineBreak,
            else => {},
        }
    }

    var line = RawLine{ .raw = body, .command = "" };
    var cursor: usize = 0;

    if (body[cursor] == '@') {
        const end = findByte(body, cursor, ' ') orelse return error.MissingCommand;
        if (end == 1) return error.MalformedTags;
        try parseTags(body[cursor + 1 .. end], &line);
        cursor = skipSpaces(body, end);
        if (cursor >= body.len) return error.MissingCommand;
    }

    if (body[cursor] == ':') {
        const end = findByte(body, cursor, ' ') orelse return error.MissingCommand;
        if (end == cursor + 1) return error.MalformedPrefix;
        cursor = skipSpaces(body, end);
        if (cursor >= body.len) return error.MissingCommand;
    }

    const command_end = findByte(body, cursor, ' ') orelse body.len;
    if (command_end == cursor) return error.MissingCommand;
    line.command = body[cursor..command_end];
    cursor = skipSpaces(body, command_end);

    while (cursor < body.len) {
        if (body[cursor] == ':') {
            try appendParam(&line, body[cursor + 1 ..]);
            line.trailing = body[cursor + 1 ..];
            return line;
        }

        const param_end = findByte(body, cursor, ' ') orelse body.len;
        if (param_end > cursor) try appendParam(&line, body[cursor..param_end]);
        cursor = skipSpaces(body, param_end);
    }

    return line;
}

fn parseTags(raw: []const u8, line: *RawLine) ParseError!void {
    var cursor: usize = 0;
    while (cursor <= raw.len) {
        const next = findByte(raw, cursor, ';') orelse raw.len;
        if (next == cursor) return error.MalformedTags;
        if (line.tag_count >= irc_line.MAXTAGS) return error.TooManyTags;

        const item = raw[cursor..next];
        const eq = findByte(item, 0, '=');
        const key = if (eq) |pos| item[0..pos] else item;
        const value_raw = if (eq) |pos| item[pos + 1 ..] else null;
        if (!validTagKey(key)) return error.InvalidTagKey;

        line.tags[line.tag_count] = .{ .key = key, .value_raw = value_raw };
        line.tag_count += 1;

        if (next == raw.len) break;
        cursor = next + 1;
    }
}

fn appendParam(line: *RawLine, param: []const u8) ParseError!void {
    if (line.param_count >= irc_line.MAXPARA) return error.TooManyParams;
    line.params[line.param_count] = param;
    line.param_count += 1;
}

fn validTagKey(key: []const u8) bool {
    if (key.len == 0) return false;
    const start: usize = if (key[0] == '+') 1 else 0;
    if (start == key.len) return false;
    for (key[start..]) |ch| {
        switch (ch) {
            'a'...'z', 'A'...'Z', '0'...'9', '-', '.', '/', '_' => {},
            else => return false,
        }
    }
    return true;
}

fn stripLineEnding(input: []const u8) []const u8 {
    if (input.len >= 2 and input[input.len - 2] == '\r' and input[input.len - 1] == '\n') {
        return input[0 .. input.len - 2];
    }
    if (input.len >= 1 and (input[input.len - 1] == '\r' or input[input.len - 1] == '\n')) {
        return input[0 .. input.len - 1];
    }
    return input;
}

fn skipSpaces(bytes: []const u8, start: usize) usize {
    var cursor = start;
    while (cursor < bytes.len and bytes[cursor] == ' ') cursor += 1;
    return cursor;
}

fn findByte(bytes: []const u8, start: usize, needle: u8) ?usize {
    var cursor = start;
    while (cursor < bytes.len) : (cursor += 1) {
        if (bytes[cursor] == needle) return cursor;
    }
    return null;
}

const SliceWriter = struct {
    buf: []u8,
    len: usize = 0,

    fn append(self: *SliceWriter, bytes: []const u8) ParseError!void {
        if (self.buf.len - self.len < bytes.len) return error.OutputTooSmall;
        @memcpy(self.buf[self.len .. self.len + bytes.len], bytes);
        self.len += bytes.len;
    }

    fn byte(self: *SliceWriter, value: u8) ParseError!void {
        if (self.len == self.buf.len) return error.OutputTooSmall;
        self.buf[self.len] = value;
        self.len += 1;
    }

    fn slice(self: *SliceWriter) []const u8 {
        return self.buf[0..self.len];
    }
};

const TagWriter = struct {
    writer: *SliceWriter,
    count: usize = 0,

    fn value(self: *TagWriter, key: []const u8, value_bytes: []const u8) ParseError!void {
        try self.begin(key);
        try self.writer.byte('=');
        try self.writer.append(value_bytes);
    }

    fn escaped(self: *TagWriter, key: []const u8, value_bytes: []const u8) ParseError!void {
        try self.begin(key);
        try self.writer.byte('=');
        for (value_bytes) |ch| {
            switch (ch) {
                0, '\r', '\n' => return error.InvalidTagValue,
                ';' => try self.writer.append("\\:"),
                ' ' => try self.writer.append("\\s"),
                '\\' => try self.writer.append("\\\\"),
                else => try self.writer.byte(ch),
            }
        }
    }

    fn begin(self: *TagWriter, key: []const u8) ParseError!void {
        if (self.count == 0) {
            try self.writer.byte('@');
        } else {
            try self.writer.byte(';');
        }
        try self.writer.append(key);
        self.count += 1;
    }

    fn finish(self: *TagWriter) ParseError!void {
        if (self.count != 0) try self.writer.byte(' ');
    }
};

test "reply and reaction tag round-trip" {
    _ = std.testing.allocator;
    var out: [160]u8 = undefined;
    const rendered = try buildInteraction(.{
        .command = .tagmsg,
        .target = "#orochi",
        .reply_to = "msg-Alpha_123",
        .reaction = .{ .value = "looks good" },
    }, &out);
    try std.testing.expectEqualStrings(
        "@+draft/reply=msg-Alpha_123;+draft/react=looks\\sgood TAGMSG #orochi",
        rendered,
    );

    var scratch = InteractionScratch{};
    const parsed = try parseInteraction(rendered, &scratch);
    try std.testing.expectEqual(.tagmsg, parsed.command);
    try std.testing.expectEqualStrings("#orochi", parsed.target);
    try std.testing.expectEqualStrings("msg-Alpha_123", parsed.reply_to.?);
    try std.testing.expectEqual(.add, parsed.reaction.?.mode);
    try std.testing.expectEqualStrings("looks good", parsed.reaction.?.value);
}

test "typing tag round-trip" {
    var out: [96]u8 = undefined;
    const rendered = try buildInteraction(.{
        .target = "kain",
        .typing = .paused,
    }, &out);
    try std.testing.expectEqualStrings("@+draft/typing=paused TAGMSG kain", rendered);

    var scratch = InteractionScratch{};
    const parsed = try parseInteraction(rendered, &scratch);
    try std.testing.expectEqual(.tagmsg, parsed.command);
    try std.testing.expectEqualStrings("kain", parsed.target);
    try std.testing.expectEqual(.paused, parsed.typing.?);
}

test "redact parse and authorization-key msgid check" {
    const redact = try parseRedact("REDACT #orochi G6PuDDBWQYmu3HmXXOAPzA :wrong paste");
    try std.testing.expectEqualStrings("#orochi", redact.target);
    try std.testing.expectEqualStrings("G6PuDDBWQYmu3HmXXOAPzA", redact.msgid);
    try std.testing.expectEqualStrings("wrong paste", redact.reason.?);
    try std.testing.expect(redactAuthorized("G6PuDDBWQYmu3HmXXOAPzA", redact));
    try std.testing.expect(!redactAuthorized("G6PuDDBWQYmu3HmXXOAPzz", redact));
}

test "edit command parse" {
    const edit = try parseEditCommand("EDIT #orochi G6PuDDBWQYmu3HmXXOAPzA :patched message");
    try std.testing.expectEqualStrings("#orochi", edit.target);
    try std.testing.expectEqualStrings("G6PuDDBWQYmu3HmXXOAPzA", edit.msgid);
    try std.testing.expectEqualStrings("patched message", edit.text);

    try std.testing.expectError(error.MissingEditBody, parseEditCommand("EDIT #orochi G6PuDDBWQYmu3HmXXOAPzA"));
    try std.testing.expectError(error.InvalidMsgid, parseEditCommand("EDIT #orochi :bad :text"));
}

test "edit references are keyed by msgid" {
    var out: [160]u8 = undefined;
    const rendered = try buildInteraction(.{
        .command = .privmsg,
        .target = "#orochi",
        .body = "patched message",
        .edit_of = "server1-1480339715754191-21",
    }, &out);
    try std.testing.expectEqualStrings(
        "@+draft/edit=server1-1480339715754191-21 PRIVMSG #orochi :patched message",
        rendered,
    );

    var scratch = InteractionScratch{};
    const parsed = try parseInteraction(rendered, &scratch);
    try std.testing.expect(parsed.isEdit());
    try std.testing.expectEqualStrings("server1-1480339715754191-21", parsed.edit_of.?);
    try std.testing.expectEqualStrings("patched message", parsed.body.?);
}

test "malformed interactions are rejected" {
    try std.testing.expect(!isValidMsgid(":bad"));
    try std.testing.expect(!isValidMsgid("bad id"));
    var scratch = InteractionScratch{};
    try std.testing.expectError(error.MissingReply, parseInteraction("@+draft/react=ok TAGMSG #c", &scratch));
    try std.testing.expectError(error.InvalidTypingState, parseInteraction("@+draft/typing=idle TAGMSG #c", &scratch));
    try std.testing.expectError(error.ConflictingTags, parseInteraction("@+draft/reply=a;+draft/react=x;+draft/unreact=x TAGMSG #c", &scratch));
    try std.testing.expectError(error.InvalidMsgid, parseRedact("REDACT #c ::bad"));
    try std.testing.expectError(error.MissingEditBody, parseInteraction("@+draft/edit=abc TAGMSG #c", &scratch));
    try std.testing.expectError(error.InvalidTagKey, parseInteraction("@++bad=x TAGMSG #c", &scratch));
}

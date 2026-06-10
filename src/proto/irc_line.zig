//! Zero-copy IRC client line parser.
//!
//! The parser returns views into the caller-owned input buffer. It strips one
//! terminal CR, LF, or CRLF sequence for convenience, but rejects line breaks,
//! NUL bytes, malformed tags, and overfull bounded arrays in the line body.
const std = @import("std");

/// Maximum IRC parameters in one client line.
pub const MAXPARA: usize = 15;

/// Maximum IRCv3 message tags accepted on one client line.
pub const MAXTAGS: usize = 64;

/// Maximum line body size after removing a terminal CR/LF sequence.
pub const MAX_LINE_BODY: usize = 8191;

pub const ParseError = error{
    EmptyLine,
    OversizeLine,
    EmbeddedNul,
    EmbeddedLineBreak,
    MissingCommand,
    MalformedPrefix,
    MalformedTags,
    TooManyParams,
    TooManyTags,
};

pub const UnescapeError = error{
    OutputTooSmall,
};

/// One IRCv3 message tag. The value is intentionally raw and lazily decoded.
pub const TagView = struct {
    key: []const u8,
    value_raw: ?[]const u8,
};

/// Parsed IRC line with all slices pointing into the input passed to parseLine.
pub const LineView = struct {
    raw: []const u8,
    tags_raw: ?[]const u8 = null,
    prefix: ?[]const u8 = null,
    command: []const u8,
    params: [MAXPARA][]const u8 = [_][]const u8{""} ** MAXPARA,
    param_count: usize = 0,
    tags: [MAXTAGS]TagView = [_]TagView{.{ .key = "", .value_raw = null }} ** MAXTAGS,
    tag_count: usize = 0,
    trailing: ?[]const u8 = null,

    pub fn paramSlice(self: *const LineView) []const []const u8 {
        return self.params[0..self.param_count];
    }

    pub fn tagSlice(self: *const LineView) []const TagView {
        return self.tags[0..self.tag_count];
    }
};

/// Parse one caller-owned client line without modifying or allocating memory.
pub fn parseLine(input: []const u8) ParseError!LineView {
    const body = stripLineEnding(input);
    if (body.len == 0) return error.EmptyLine;
    if (body.len > MAX_LINE_BODY) return error.OversizeLine;

    for (body) |ch| {
        switch (ch) {
            0 => return error.EmbeddedNul,
            '\r', '\n' => return error.EmbeddedLineBreak,
            else => {},
        }
    }

    var view = LineView{ .raw = body, .command = "" };
    var cursor: usize = 0;

    if (body[cursor] == '@') {
        const tag_end = findSpace(body, cursor) orelse return error.MissingCommand;
        if (tag_end == 1) return error.MalformedTags;
        view.tags_raw = body[cursor..tag_end];
        try parseTags(body[cursor + 1 .. tag_end], &view);
        cursor = skipSpaces(body, tag_end);
        if (cursor >= body.len) return error.MissingCommand;
    }

    if (body[cursor] == ':') {
        const prefix_end = findSpace(body, cursor) orelse return error.MissingCommand;
        if (prefix_end == cursor + 1) return error.MalformedPrefix;
        view.prefix = body[cursor + 1 .. prefix_end];
        cursor = skipSpaces(body, prefix_end);
        if (cursor >= body.len) return error.MissingCommand;
    }

    const command_end = findSpace(body, cursor) orelse body.len;
    if (command_end == cursor) return error.MissingCommand;
    view.command = body[cursor..command_end];
    cursor = skipSpaces(body, command_end);

    while (cursor < body.len) {
        if (body[cursor] == ':') {
            try appendParam(&view, body[cursor + 1 ..]);
            view.trailing = body[cursor + 1 ..];
            return view;
        }

        const param_end = findSpace(body, cursor) orelse body.len;
        if (param_end > cursor) {
            try appendParam(&view, body[cursor..param_end]);
        }
        cursor = skipSpaces(body, param_end);
    }

    return view;
}

/// Decode an IRCv3 raw tag value into caller-provided storage.
///
/// Known escapes are `\:`, `\s`, `\r`, `\n`, and `\\`. Unknown escapes keep the
/// escaped byte; a final lone slash is preserved.
pub fn unescapeTagValue(raw: []const u8, out_buf: []u8) UnescapeError![]const u8 {
    var read: usize = 0;
    var write: usize = 0;

    while (read < raw.len) {
        const ch = raw[read];
        read += 1;

        const decoded = if (ch == '\\' and read < raw.len) blk: {
            const esc = raw[read];
            read += 1;
            break :blk switch (esc) {
                ':' => ';',
                's' => ' ',
                'r' => '\r',
                'n' => '\n',
                '\\' => '\\',
                else => esc,
            };
        } else ch;

        if (write >= out_buf.len) return error.OutputTooSmall;
        out_buf[write] = decoded;
        write += 1;
    }

    return out_buf[0..write];
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

fn parseTags(raw: []const u8, view: *LineView) ParseError!void {
    var cursor: usize = 0;
    while (cursor <= raw.len) {
        const next = findByte(raw, cursor, ';') orelse raw.len;
        if (next == cursor) return error.MalformedTags;
        if (view.tag_count >= MAXTAGS) return error.TooManyTags;

        const item = raw[cursor..next];
        const eq = findByte(item, 0, '=');
        const key = if (eq) |pos| item[0..pos] else item;
        const value_raw = if (eq) |pos| item[pos + 1 ..] else null;

        if (!validTagKey(key)) return error.MalformedTags;

        view.tags[view.tag_count] = .{ .key = key, .value_raw = value_raw };
        view.tag_count += 1;

        if (next == raw.len) break;
        cursor = next + 1;
    }
}

fn appendParam(view: *LineView, param: []const u8) ParseError!void {
    if (view.param_count >= MAXPARA) return error.TooManyParams;
    view.params[view.param_count] = param;
    view.param_count += 1;
}

fn validTagKey(key: []const u8) bool {
    if (key.len == 0) return false;
    for (key) |ch| {
        switch (ch) {
            'a'...'z', 'A'...'Z', '0'...'9', '-', '.', '/', '_' => {},
            else => return false,
        }
    }
    return true;
}

fn skipSpaces(bytes: []const u8, start: usize) usize {
    var cursor = start;
    while (cursor < bytes.len and bytes[cursor] == ' ') {
        cursor += 1;
    }
    return cursor;
}

fn findSpace(bytes: []const u8, start: usize) ?usize {
    return findByte(bytes, start, ' ');
}

fn findByte(bytes: []const u8, start: usize, needle: u8) ?usize {
    var cursor = start;
    while (cursor < bytes.len) : (cursor += 1) {
        if (bytes[cursor] == needle) return cursor;
    }
    return null;
}

test "parses untagged line without prefix" {
    const line = try parseLine("PING token");
    try std.testing.expectEqualStrings("PING token", line.raw);
    try std.testing.expectEqual(@as(?[]const u8, null), line.tags_raw);
    try std.testing.expectEqual(@as(?[]const u8, null), line.prefix);
    try std.testing.expectEqualStrings("PING", line.command);
    try std.testing.expectEqual(@as(usize, 1), line.param_count);
    try std.testing.expectEqualStrings("token", line.paramSlice()[0]);
    try std.testing.expectEqual(@as(usize, 0), line.tag_count);
}

test "parses prefix and normal params" {
    const line = try parseLine(":nick!user@host JOIN #orochi key");
    try std.testing.expectEqualStrings("nick!user@host", line.prefix.?);
    try std.testing.expectEqualStrings("JOIN", line.command);
    try std.testing.expectEqual(@as(usize, 2), line.param_count);
    try std.testing.expectEqualStrings("#orochi", line.paramSlice()[0]);
    try std.testing.expectEqualStrings("key", line.paramSlice()[1]);
}

test "parses trailing param with spaces" {
    const line = try parseLine(":a PRIVMSG #chan :hello there from orochi");
    try std.testing.expectEqualStrings("PRIVMSG", line.command);
    try std.testing.expectEqual(@as(usize, 2), line.param_count);
    try std.testing.expectEqualStrings("#chan", line.paramSlice()[0]);
    try std.testing.expectEqualStrings("hello there from orochi", line.paramSlice()[1]);
    try std.testing.expectEqualStrings("hello there from orochi", line.trailing.?);
}

test "strips CRLF and single line endings" {
    const crlf = try parseLine("QUIT :bye\r\n");
    try std.testing.expectEqualStrings("QUIT :bye", crlf.raw);
    try std.testing.expectEqualStrings("bye", crlf.trailing.?);

    const lf = try parseLine("PING abc\n");
    try std.testing.expectEqualStrings("PING abc", lf.raw);
    try std.testing.expectEqualStrings("abc", lf.paramSlice()[0]);

    const cr = try parseLine("PONG def\r");
    try std.testing.expectEqualStrings("PONG def", cr.raw);
    try std.testing.expectEqualStrings("def", cr.paramSlice()[0]);
}

test "parses IRCv3 tags with optional raw values" {
    const line = try parseLine("@aaa=bbb;vendor/tag;empty= :nick CMD arg");
    try std.testing.expectEqualStrings("@aaa=bbb;vendor/tag;empty=", line.tags_raw.?);
    try std.testing.expectEqual(@as(usize, 3), line.tag_count);
    try std.testing.expectEqualStrings("aaa", line.tagSlice()[0].key);
    try std.testing.expectEqualStrings("bbb", line.tagSlice()[0].value_raw.?);
    try std.testing.expectEqualStrings("vendor/tag", line.tagSlice()[1].key);
    try std.testing.expectEqual(@as(?[]const u8, null), line.tagSlice()[1].value_raw);
    try std.testing.expectEqualStrings("empty", line.tagSlice()[2].key);
    try std.testing.expectEqualStrings("", line.tagSlice()[2].value_raw.?);
    try std.testing.expectEqualStrings("nick", line.prefix.?);
    try std.testing.expectEqualStrings("CMD", line.command);
}

test "unescapes raw tag values into caller buffer" {
    var buf: [64]u8 = undefined;
    const decoded = try unescapeTagValue("a\\:b\\sc\\r\\n\\\\d", &buf);
    try std.testing.expectEqualSlices(u8, "a;b c\r\n\\d", decoded);
}

test "rejects too-small tag unescape buffers" {
    var buf: [2]u8 = undefined;
    try std.testing.expectError(error.OutputTooSmall, unescapeTagValue("abc", &buf));
}

test "rejects malformed input" {
    try std.testing.expectError(error.EmptyLine, parseLine("\r\n"));
    try std.testing.expectError(error.EmbeddedNul, parseLine("PING \x00x"));
    try std.testing.expectError(error.EmbeddedLineBreak, parseLine("PING a\nb"));
    try std.testing.expectError(error.MalformedTags, parseLine("@ CMD"));
    try std.testing.expectError(error.MalformedTags, parseLine("@a;;b CMD"));
    try std.testing.expectError(error.MalformedTags, parseLine("@bad,key CMD"));
    try std.testing.expectError(error.MalformedPrefix, parseLine(": CMD"));
    try std.testing.expectError(error.MissingCommand, parseLine("@a=b "));
}

test "rejects too many params" {
    try std.testing.expectError(
        error.TooManyParams,
        parseLine("CMD p0 p1 p2 p3 p4 p5 p6 p7 p8 p9 p10 p11 p12 p13 p14 p15"),
    );
}

test "rejects too many tags" {
    try std.testing.expectError(
        error.TooManyTags,
        parseLine("@a0;a1;a2;a3;a4;a5;a6;a7;a8;a9;a10;a11;a12;a13;a14;a15;a16;a17;a18;a19;a20;a21;a22;a23;a24;a25;a26;a27;a28;a29;a30;a31;a32;a33;a34;a35;a36;a37;a38;a39;a40;a41;a42;a43;a44;a45;a46;a47;a48;a49;a50;a51;a52;a53;a54;a55;a56;a57;a58;a59;a60;a61;a62;a63;a64 CMD"),
    );
}

test "rejects oversize line bodies" {
    const big = "A" ** (MAX_LINE_BODY + 1);
    try std.testing.expectError(error.OversizeLine, parseLine(big));
}

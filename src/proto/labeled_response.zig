//! Allocation-free IRCv3 labeled-response builders.
//!
//! The daemon decides when replies exist; this module only renders caller-owned
//! buffers so clients can correlate replies with an inbound `label` tag.
const std = @import("std");

pub const MAX_LABEL_LEN: usize = 64;
pub const MAX_BATCH_REF_LEN: usize = 64;
pub const MAX_LINE_BODY: usize = 8191;
pub const MAX_ESCAPED_LABEL_LEN: usize = MAX_LABEL_LEN * 2;
pub const MAX_WIRE_LINE: usize = 1 + "label=".len + MAX_ESCAPED_LABEL_LEN + 1 + MAX_LINE_BODY + 2;

pub const Error = error{
    DuplicateTag,
    InvalidBatchRef,
    InvalidLabel,
    InvalidLine,
    OutputTooSmall,
};

pub const LabeledError = Error;

/// Wrap one outbound reply with `@label=<label>`.
pub fn wrapSingle(out: []u8, label: []const u8, line: []const u8) Error![]const u8 {
    return prependTag(out, "label", label, try checkedLine(line, "label"), .escaped_value);
}

/// Build the opening `labeled-response` BATCH line.
pub fn beginBatch(out: []u8, label: []const u8, ref: []const u8) Error![]const u8 {
    try validateBatchRef(ref);
    var w = Writer{ .buf = out };
    try w.bytes("@label=");
    try w.escapedLabel(label);
    try w.bytes(" BATCH +");
    try w.bytes(ref);
    try w.bytes(" labeled-response\r\n");
    return w.slice();
}

/// Tag one line as a member of an already-open labeled-response batch.
pub fn wrapBatchLine(out: []u8, ref: []const u8, line: []const u8) Error![]const u8 {
    try validateBatchRef(ref);
    return prependTag(out, "batch", ref, try checkedLine(line, "batch"), .plain_value);
}

pub const batchLine = wrapBatchLine;

/// Build the closing BATCH line.
pub fn endBatch(out: []u8, ref: []const u8) Error![]const u8 {
    try validateBatchRef(ref);
    var w = Writer{ .buf = out };
    try w.bytes("BATCH -");
    try w.bytes(ref);
    try w.bytes("\r\n");
    return w.slice();
}

/// Build the labeled ACK used when a command has no outbound replies.
pub fn ack(out: []u8, label: []const u8) Error![]const u8 {
    var w = Writer{ .buf = out };
    try w.bytes("@label=");
    try w.escapedLabel(label);
    try w.bytes(" ACK\r\n");
    return w.slice();
}

pub fn tagLine(label: ?[]const u8, line: []const u8, out: []u8) Error![]const u8 {
    const id = label orelse {
        if (line.len > out.len) return error.OutputTooSmall;
        @memcpy(out[0..line.len], line);
        return out[0..line.len];
    };
    return wrapSingle(out, id, line);
}

pub fn buildAck(label: []const u8, out: []u8) Error![]const u8 {
    return ack(out, label);
}

const TagValueMode = enum { plain_value, escaped_value };

fn prependTag(
    out: []u8,
    key: []const u8,
    value: []const u8,
    body: []const u8,
    mode: TagValueMode,
) Error![]const u8 {
    var w = Writer{ .buf = out };
    try w.byte('@');
    try w.bytes(key);
    try w.byte('=');
    switch (mode) {
        .plain_value => try w.bytes(value),
        .escaped_value => try w.escapedLabel(value),
    }
    if (body[0] == '@') {
        try w.byte(';');
        try w.bytes(body[1..]);
    } else {
        try w.byte(' ');
        try w.bytes(body);
    }
    try w.bytes("\r\n");
    return w.slice();
}

fn checkedLine(line: []const u8, duplicate_key: []const u8) Error![]const u8 {
    const body = stripEnding(line);
    if (body.len == 0 or body.len > MAX_LINE_BODY) return error.InvalidLine;
    for (body) |ch| {
        switch (ch) {
            0, '\r', '\n' => return error.InvalidLine,
            else => {},
        }
    }
    if (body[0] == '@') {
        const tag_end = std.mem.indexOfScalar(u8, body, ' ') orelse return error.InvalidLine;
        if (tag_end == 1 or tag_end + 1 >= body.len) return error.InvalidLine;
        try checkedTags(body[1..tag_end], duplicate_key);
    }
    return body;
}

fn checkedTags(tags: []const u8, duplicate_key: []const u8) Error!void {
    var cursor: usize = 0;
    while (cursor < tags.len) {
        const len = std.mem.indexOfScalar(u8, tags[cursor..], ';') orelse tags.len - cursor;
        const item = tags[cursor .. cursor + len];
        if (item.len == 0) return error.InvalidLine;
        const eq = std.mem.indexOfScalar(u8, item, '=') orelse item.len;
        const key = item[0..eq];
        if (!validTagKey(key)) return error.InvalidLine;
        if (std.mem.eql(u8, key, duplicate_key)) return error.DuplicateTag;
        cursor += len;
        if (cursor < tags.len) cursor += 1;
    }
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

fn validateBatchRef(ref: []const u8) Error!void {
    if (ref.len == 0 or ref.len > MAX_BATCH_REF_LEN) return error.InvalidBatchRef;
    for (ref) |ch| {
        switch (ch) {
            'a'...'z', 'A'...'Z', '0'...'9', '-', '.', '/', '_' => {},
            else => return error.InvalidBatchRef,
        }
    }
}

fn validateLabel(label: []const u8) Error!void {
    if (label.len == 0 or label.len > MAX_LABEL_LEN) return error.InvalidLabel;
    for (label) |ch| if (ch == 0) return error.InvalidLabel;
}

fn stripEnding(line: []const u8) []const u8 {
    if (line.len >= 2 and line[line.len - 2] == '\r' and line[line.len - 1] == '\n') {
        return line[0 .. line.len - 2];
    }
    if (line.len >= 1 and (line[line.len - 1] == '\r' or line[line.len - 1] == '\n')) {
        return line[0 .. line.len - 1];
    }
    return line;
}

const Writer = struct {
    buf: []u8,
    len: usize = 0,

    fn bytes(self: *Writer, src: []const u8) Error!void {
        if (src.len > self.buf.len - self.len) return error.OutputTooSmall;
        @memcpy(self.buf[self.len .. self.len + src.len], src);
        self.len += src.len;
    }

    fn byte(self: *Writer, ch: u8) Error!void {
        if (self.len >= self.buf.len) return error.OutputTooSmall;
        self.buf[self.len] = ch;
        self.len += 1;
    }

    fn escapedLabel(self: *Writer, label: []const u8) Error!void {
        try validateLabel(label);
        for (label) |ch| {
            switch (ch) {
                ';' => try self.bytes("\\:"),
                ' ' => try self.bytes("\\s"),
                '\r' => try self.bytes("\\r"),
                '\n' => try self.bytes("\\n"),
                '\\' => try self.bytes("\\\\"),
                else => try self.byte(ch),
            }
        }
    }

    fn slice(self: *const Writer) []const u8 {
        return self.buf[0..self.len];
    }
};

const TestSink = struct {
    bytes: std.ArrayListUnmanaged(u8) = .empty,

    fn append(self: *TestSink, allocator: std.mem.Allocator, line: []const u8) !void {
        try self.bytes.appendSlice(allocator, line);
    }
};

test "single tag prepend" {
    var out: [128]u8 = undefined;
    const line = try wrapSingle(&out, "abc123", ":srv 401 me nick :No such nick\r\n");
    try std.testing.expectEqualStrings("@label=abc123 :srv 401 me nick :No such nick\r\n", line);
}

test "ACK on empty" {
    var out: [64]u8 = undefined;
    const line = try ack(&out, "empty-1");
    try std.testing.expectEqualStrings("@label=empty-1 ACK\r\n", line);
}

test "batch framing for multiple" {
    const allocator = std.testing.allocator;
    var sink = TestSink{};
    defer sink.bytes.deinit(allocator);

    var out: [MAX_WIRE_LINE]u8 = undefined;
    try sink.append(allocator, try beginBatch(&out, "whois-1", "b42"));
    try sink.append(allocator, try wrapBatchLine(&out, "b42", ":srv 311 me nick ~u h * :Name"));
    try sink.append(allocator, try wrapBatchLine(&out, "b42", "@time=2026-06-07T00:00:00.000Z :srv 318 me nick :End"));
    try sink.append(allocator, try endBatch(&out, "b42"));

    try std.testing.expectEqualStrings(
        "@label=whois-1 BATCH +b42 labeled-response\r\n" ++
            "@batch=b42 :srv 311 me nick ~u h * :Name\r\n" ++
            "@batch=b42;time=2026-06-07T00:00:00.000Z :srv 318 me nick :End\r\n" ++
            "BATCH -b42\r\n",
        sink.bytes.items,
    );
}

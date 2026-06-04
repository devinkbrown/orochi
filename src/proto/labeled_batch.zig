//! Pure IRCv3 labeled-response correlation policy.
//!
//! This layer decides whether a labeled command response is ACKed, tagged
//! directly, or wrapped in a labeled-response BATCH. It does not allocate.
const std = @import("std");
const labeled_response = @import("labeled_response.zig");

pub const Error = labeled_response.LabeledError;

pub const max_label_len: usize = labeled_response.MAX_LABEL_LEN;
pub const max_batch_ref_len: usize = labeled_response.MAX_BATCH_REF_LEN;
pub const max_wire_line: usize = labeled_response.MAX_WIRE_LINE;

/// Return true when `label` is acceptable for IRCv3 labeled-response emission.
///
/// Mizuchi treats labels as already-decoded tag values. They must be non-empty,
/// bounded, and contain no spaces or control bytes.
pub fn isValidLabel(label: []const u8) bool {
    if (label.len == 0 or label.len > max_label_len) return false;
    for (label) |ch| {
        if (ch <= ' ' or ch == 0x7f) return false;
    }
    return true;
}

pub fn validateLabel(label: []const u8) Error!void {
    if (!isValidLabel(label)) return error.InvalidLabel;
}

/// Allocation-free labeled-response emitter.
///
/// `scratch` is caller-owned storage used for rendered protocol lines. The
/// callback receives slices that remain valid only until the callback returns.
/// For a single labeled reply, the first fed line is held by slice until
/// `finish()`; keep that line storage alive for the emitter lifetime.
pub fn Emitter(comptime Context: type) type {
    return struct {
        const Self = @This();
        pub const SinkFn = *const fn (*Context, []const u8) anyerror!void;

        label: ?[]const u8,
        batch_ref: []const u8,
        scratch: []u8,
        context: *Context,
        sink: SinkFn,
        state: State = .empty,
        first: []const u8 = "",

        const State = enum {
            empty,
            have_one,
            batch_open,
            finished,
        };

        pub fn init(
            label: ?[]const u8,
            batch_ref: []const u8,
            scratch: []u8,
            context: *Context,
            sink: SinkFn,
        ) Error!Self {
            if (label) |id| try validateLabel(id);
            return .{
                .label = label,
                .batch_ref = batch_ref,
                .scratch = scratch,
                .context = context,
                .sink = sink,
            };
        }

        pub fn feed(self: *Self, line: []const u8) anyerror!void {
            if (self.state == .finished) return error.InvalidLine;

            const id = self.label orelse {
                try self.emit(line);
                return;
            };

            switch (self.state) {
                .empty => {
                    self.first = line;
                    self.state = .have_one;
                },
                .have_one => {
                    try validateBatchRef(self.batch_ref);
                    try self.emit(try writeBatchOpen(id, self.batch_ref, self.scratch));
                    try self.emit(try batchTagLine(self.batch_ref, self.first, self.scratch));
                    try self.emit(try batchTagLine(self.batch_ref, line, self.scratch));
                    self.state = .batch_open;
                },
                .batch_open => {
                    try self.emit(try batchTagLine(self.batch_ref, line, self.scratch));
                },
                .finished => unreachable,
            }
        }

        pub fn finish(self: *Self) anyerror!void {
            if (self.state == .finished) return;

            const id = self.label orelse {
                self.state = .finished;
                return;
            };

            switch (self.state) {
                .empty => try self.emit(try labeled_response.buildAck(id, self.scratch)),
                .have_one => try self.emit(try labeled_response.tagLine(id, self.first, self.scratch)),
                .batch_open => try self.emit(try writeBatchClose(self.batch_ref, self.scratch)),
                .finished => unreachable,
            }
            self.state = .finished;
        }

        fn emit(self: *Self, line: []const u8) anyerror!void {
            try self.sink(self.context, line);
        }
    };
}

pub fn emitSlice(
    comptime Context: type,
    context: *Context,
    sink: Emitter(Context).SinkFn,
    label: ?[]const u8,
    batch_ref: []const u8,
    scratch: []u8,
    lines: []const []const u8,
) anyerror!void {
    var emitter = try Emitter(Context).init(label, batch_ref, scratch, context, sink);
    for (lines) |line| try emitter.feed(line);
    try emitter.finish();
}

fn writeBatchOpen(label: []const u8, batch_ref: []const u8, out: []u8) Error![]const u8 {
    var cursor: usize = 0;
    try append(out, &cursor, "@label=");
    try appendEscapedTagValue(out, &cursor, label);
    try append(out, &cursor, " BATCH +");
    try append(out, &cursor, batch_ref);
    try append(out, &cursor, " labeled-response\r\n");
    return out[0..cursor];
}

fn writeBatchClose(batch_ref: []const u8, out: []u8) Error![]const u8 {
    var cursor: usize = 0;
    try append(out, &cursor, "BATCH -");
    try append(out, &cursor, batch_ref);
    try append(out, &cursor, "\r\n");
    return out[0..cursor];
}

fn batchTagLine(batch_ref: []const u8, line: []const u8, out: []u8) Error![]const u8 {
    const body = try validateOutboundLine(line, "batch");
    var cursor: usize = 0;
    try append(out, &cursor, "@batch=");
    try append(out, &cursor, batch_ref);
    if (body[0] == '@') {
        try appendByte(out, &cursor, ';');
        try append(out, &cursor, body[1..]);
    } else {
        try appendByte(out, &cursor, ' ');
        try append(out, &cursor, body);
    }
    try append(out, &cursor, "\r\n");
    return out[0..cursor];
}

fn validateBatchRef(batch_ref: []const u8) Error!void {
    if (batch_ref.len == 0 or batch_ref.len > max_batch_ref_len) return error.InvalidBatchRef;
    for (batch_ref) |ch| {
        switch (ch) {
            'a'...'z', 'A'...'Z', '0'...'9', '-', '.', '/', '_' => {},
            else => return error.InvalidBatchRef,
        }
    }
}

fn validateOutboundLine(line: []const u8, duplicate_key: []const u8) Error![]const u8 {
    const body = stripLineEnding(line);
    if (body.len == 0 or body.len > labeled_response.MAX_LINE_BODY) return error.InvalidLine;

    for (body) |ch| {
        switch (ch) {
            0, '\r', '\n' => return error.InvalidLine,
            else => {},
        }
    }

    if (body[0] == '@') {
        const tag_end = std.mem.indexOfScalar(u8, body, ' ') orelse return error.InvalidLine;
        if (tag_end == 1) return error.InvalidLine;
        if (skipSpaces(body, tag_end) >= body.len) return error.InvalidLine;
        try validateTagsNoDuplicate(body[1..tag_end], duplicate_key);
    }

    return body;
}

fn validateTagsNoDuplicate(tags: []const u8, duplicate_key: []const u8) Error!void {
    var cursor: usize = 0;
    while (cursor < tags.len) {
        const next = std.mem.indexOfScalar(u8, tags[cursor..], ';') orelse tags.len - cursor;
        const item = tags[cursor .. cursor + next];
        if (item.len == 0) return error.InvalidLine;

        const eq = std.mem.indexOfScalar(u8, item, '=') orelse item.len;
        const key = item[0..eq];
        if (!validTagKey(key)) return error.InvalidLine;
        if (std.mem.eql(u8, key, duplicate_key)) return error.DuplicateTag;

        cursor += next;
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

fn appendEscapedTagValue(out: []u8, cursor: *usize, value: []const u8) Error!void {
    try validateLabel(value);
    for (value) |ch| {
        switch (ch) {
            ';' => try append(out, cursor, "\\:"),
            '\\' => try append(out, cursor, "\\\\"),
            else => try appendByte(out, cursor, ch),
        }
    }
}

fn append(out: []u8, cursor: *usize, bytes: []const u8) Error!void {
    if (bytes.len > out.len -| cursor.*) return error.OutputTooSmall;
    @memcpy(out[cursor.* .. cursor.* + bytes.len], bytes);
    cursor.* += bytes.len;
}

fn appendByte(out: []u8, cursor: *usize, byte: u8) Error!void {
    if (cursor.* >= out.len) return error.OutputTooSmall;
    out[cursor.*] = byte;
    cursor.* += 1;
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

const TestSink = struct {
    allocator: std.mem.Allocator,
    bytes: std.ArrayList(u8) = .empty,

    fn emit(self: *TestSink, line: []const u8) !void {
        try self.bytes.appendSlice(self.allocator, line);
    }

    fn deinit(self: *TestSink) void {
        self.bytes.deinit(self.allocator);
    }
};

fn expectEmit(label: ?[]const u8, lines: []const []const u8, expected: []const u8) !void {
    var sink = TestSink{ .allocator = std.testing.allocator };
    defer sink.deinit();

    var scratch: [max_wire_line]u8 = undefined;
    try emitSlice(TestSink, &sink, TestSink.emit, label, "lb-ref-1", &scratch, lines);
    try std.testing.expectEqualStrings(expected, sink.bytes.items);
}

test "null label passthrough" {
    const lines = [_][]const u8{
        ":irc.example NOTICE me :one\r\n",
        "@time=2026-06-04T00:00:00.000Z :irc.example NOTICE me :two\r\n",
    };

    try expectEmit(null, &lines, lines[0] ++ lines[1]);
}

test "zero labeled replies emit ACK" {
    try expectEmit("cmd-1", &.{}, "@label=cmd-1 ACK\r\n");
}

test "one labeled reply is directly tagged" {
    const lines = [_][]const u8{
        ":irc.example 401 me nick :No such nick\r\n",
    };

    try expectEmit(
        "cmd-2",
        &lines,
        "@label=cmd-2 :irc.example 401 me nick :No such nick\r\n",
    );
}

test "three labeled replies are wrapped in a batch" {
    const lines = [_][]const u8{
        ":irc.example 311 me nick ~ident host * :Name\r\n",
        "@time=2026-06-04T00:00:00.000Z :irc.example 312 me nick irc.example :Server\r\n",
        ":irc.example 318 me nick :End of /WHOIS list.\r\n",
    };

    try expectEmit(
        "whois-3",
        &lines,
        "@label=whois-3 BATCH +lb-ref-1 labeled-response\r\n" ++
            "@batch=lb-ref-1 :irc.example 311 me nick ~ident host * :Name\r\n" ++
            "@batch=lb-ref-1;time=2026-06-04T00:00:00.000Z :irc.example 312 me nick irc.example :Server\r\n" ++
            "@batch=lb-ref-1 :irc.example 318 me nick :End of /WHOIS list.\r\n" ++
            "BATCH -lb-ref-1\r\n",
    );
}

test "bad label rejected" {
    var sink = TestSink{ .allocator = std.testing.allocator };
    defer sink.deinit();
    var scratch: [max_wire_line]u8 = undefined;

    try std.testing.expectError(
        error.InvalidLabel,
        Emitter(TestSink).init("bad label", "lb-ref-1", &scratch, &sink, TestSink.emit),
    );
    try std.testing.expectError(
        error.InvalidLabel,
        Emitter(TestSink).init("bad\x1flabel", "lb-ref-1", &scratch, &sink, TestSink.emit),
    );
}

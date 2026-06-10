//! IRCv3 BATCH framing helpers.
//!
//! Batch state is intentionally small and allocation-free. Callers provide
//! output buffers for emitted protocol lines, while the session tracks only
//! generated reference tags and nesting depth.
const std = @import("std");

pub const max_reference_len: usize = 32;
pub const default_max_line_body: usize = 8191;

/// IRCv3 batch type tokens supported by Orochi.
pub const BatchType = enum {
    netjoin,
    netsplit,
    chathistory,
    labeled,

    pub fn token(self: BatchType) []const u8 {
        return switch (self) {
            .netjoin => "netjoin",
            .netsplit => "netsplit",
            .chathistory => "chathistory",
            .labeled => "labeled",
        };
    }
};

pub const BatchError = error{
    OutputTooSmall,
    TooManyNestedBatches,
    CounterExhausted,
    InvalidReference,
    InvalidBatchType,
    InvalidParameter,
    InvalidLine,
    DuplicateBatchTag,
    UnbalancedClose,
    NoOpenBatch,
};

/// A validated IRCv3 batch reference tag.
pub const BatchRef = struct {
    bytes: [max_reference_len]u8 = [_]u8{0} ** max_reference_len,
    len: usize = 0,

    pub fn slice(self: *const BatchRef) []const u8 {
        return self.bytes[0..self.len];
    }

    pub fn eql(self: *const BatchRef, other: *const BatchRef) bool {
        return self.len == other.len and std.mem.eql(u8, self.slice(), other.slice());
    }
};

/// Compile-time session sizing. Output buffers remain caller-owned.
pub const Config = struct {
    max_depth: usize = 8,
    max_line_body: usize = default_max_line_body,
};

/// Result of opening a batch: generated ref plus the line written into `out`.
pub const OpenResult = struct {
    ref: BatchRef,
    line: []const u8,
};

/// Stack-based IRCv3 BATCH encoder with generated reference tags.
pub fn BatchSession(comptime config: Config) type {
    comptime {
        if (config.max_depth == 0) @compileError("BatchSession needs at least one stack slot");
        if (config.max_line_body == 0) @compileError("max_line_body must be non-zero");
    }

    return struct {
        const Self = @This();

        stack: [config.max_depth]BatchRef = [_]BatchRef{.{}} ** config.max_depth,
        depth: usize = 0,
        next_ref: u64 = 0,

        pub fn init(seed: u64) Self {
            return .{ .next_ref = seed };
        }

        pub fn isOpen(self: *const Self) bool {
            return self.depth != 0;
        }

        pub fn activeRef(self: *const Self) ?BatchRef {
            if (self.depth == 0) return null;
            return self.stack[self.depth - 1];
        }

        /// Open a generated batch and emit `BATCH +ref type [params...]`.
        pub fn open(
            self: *Self,
            batch_type: BatchType,
            params: []const []const u8,
            out: []u8,
        ) BatchError!OpenResult {
            return self.openNamed(batch_type.token(), params, out);
        }

        /// Open a generated batch with a caller-provided valid batch type token.
        pub fn openNamed(
            self: *Self,
            batch_type: []const u8,
            params: []const []const u8,
            out: []u8,
        ) BatchError!OpenResult {
            if (self.depth >= config.max_depth) return error.TooManyNestedBatches;
            try validateBatchType(batch_type);
            for (params) |param| try validateParameter(param);

            const id = nextId(self.next_ref) orelse return error.CounterExhausted;
            const ref = makeGeneratedRef(id);
            const line = try writeOpenLine(ref, batch_type, params, out);

            self.stack[self.depth] = ref;
            self.depth += 1;
            self.next_ref = id;
            return .{ .ref = ref, .line = line };
        }

        /// Close the active batch and emit `BATCH -ref`.
        pub fn close(self: *Self, out: []u8) BatchError![]const u8 {
            const ref = self.activeRef() orelse return error.UnbalancedClose;
            return self.closeRef(ref, out);
        }

        /// Close `ref` only if it is the active batch.
        pub fn closeRef(self: *Self, ref: BatchRef, out: []u8) BatchError![]const u8 {
            const active = self.activeRef() orelse return error.UnbalancedClose;
            if (!active.eql(&ref)) return error.UnbalancedClose;

            const line = try writeCloseLine(ref, out);
            self.depth -= 1;
            return line;
        }

        /// Add the active `batch=ref` message tag to an outbound IRC line.
        pub fn wrapLine(self: *const Self, line: []const u8, out: []u8) BatchError![]const u8 {
            const ref = self.activeRef() orelse return error.NoOpenBatch;
            return writeWrappedLine(ref, line, out, config.max_line_body);
        }
    };
}

pub const DefaultSession = BatchSession(.{});

fn nextId(current: u64) ?u64 {
    if (current == std.math.maxInt(u64)) return null;
    return current + 1;
}

fn makeGeneratedRef(id: u64) BatchRef {
    var ref = BatchRef{ .len = 18 };
    ref.bytes[0] = 'm';
    ref.bytes[1] = 'z';
    writeFixedHex(id, ref.bytes[2..18]);
    return ref;
}

fn writeFixedHex(value: u64, out: []u8) void {
    var shift: u6 = 60;
    var cursor: usize = 0;
    while (cursor < out.len) : (cursor += 1) {
        const nibble: u8 = @intCast((value >> shift) & 0x0f);
        out[cursor] = if (nibble < 10) '0' + nibble else 'a' + (nibble - 10);
        if (shift >= 4) {
            shift -= 4;
        } else {
            shift = 0;
        }
    }
}

fn writeOpenLine(
    ref: BatchRef,
    batch_type: []const u8,
    params: []const []const u8,
    out: []u8,
) BatchError![]const u8 {
    var cursor: usize = 0;
    try appendSlice(out, &cursor, "BATCH +");
    try appendSlice(out, &cursor, ref.slice());
    try appendByte(out, &cursor, ' ');
    try appendSlice(out, &cursor, batch_type);
    for (params) |param| {
        try appendByte(out, &cursor, ' ');
        try appendSlice(out, &cursor, param);
    }
    try appendSlice(out, &cursor, "\r\n");
    return out[0..cursor];
}

fn writeCloseLine(ref: BatchRef, out: []u8) BatchError![]const u8 {
    var cursor: usize = 0;
    try appendSlice(out, &cursor, "BATCH -");
    try appendSlice(out, &cursor, ref.slice());
    try appendSlice(out, &cursor, "\r\n");
    return out[0..cursor];
}

fn writeWrappedLine(
    ref: BatchRef,
    line: []const u8,
    out: []u8,
    max_line_body: usize,
) BatchError![]const u8 {
    const body = try validateOutboundLine(line, max_line_body);
    var cursor: usize = 0;

    if (body[0] == '@') {
        try validateTagsNoBatch(body);
        try appendSlice(out, &cursor, "@batch=");
        try appendSlice(out, &cursor, ref.slice());
        try appendByte(out, &cursor, ';');
        try appendSlice(out, &cursor, body[1..]);
    } else {
        try appendSlice(out, &cursor, "@batch=");
        try appendSlice(out, &cursor, ref.slice());
        try appendByte(out, &cursor, ' ');
        try appendSlice(out, &cursor, body);
    }

    try appendSlice(out, &cursor, "\r\n");
    return out[0..cursor];
}

fn validateOutboundLine(line: []const u8, max_line_body: usize) BatchError![]const u8 {
    const body = stripLineEnding(line);
    if (body.len == 0 or body.len > max_line_body) return error.InvalidLine;

    for (body) |ch| {
        switch (ch) {
            0, '\r', '\n' => return error.InvalidLine,
            else => {},
        }
    }

    if (body[0] == '@') {
        const tag_end = findByte(body, ' ') orelse return error.InvalidLine;
        if (tag_end == 1) return error.InvalidLine;
        const command_start = skipSpaces(body, tag_end);
        if (command_start >= body.len) return error.InvalidLine;
        try validateTagsNoBatch(body);
    }

    return body;
}

fn validateTagsNoBatch(body: []const u8) BatchError!void {
    if (body.len == 0 or body[0] != '@') return;
    const tag_end = findByte(body, ' ') orelse return error.InvalidLine;
    var cursor: usize = 1;
    while (cursor <= tag_end) {
        const next = findByteIn(body[cursor..tag_end], ';') orelse tag_end - cursor;
        const item = body[cursor .. cursor + next];
        if (item.len == 0) return error.InvalidLine;

        const eq = findByteIn(item, '=') orelse item.len;
        const key = item[0..eq];
        if (!validTagKey(key)) return error.InvalidLine;
        if (std.mem.eql(u8, key, "batch")) return error.DuplicateBatchTag;

        if (cursor + next == tag_end) break;
        cursor = cursor + next + 1;
    }
}

fn validateBatchType(batch_type: []const u8) BatchError!void {
    if (batch_type.len == 0) return error.InvalidBatchType;
    for (batch_type) |ch| {
        switch (ch) {
            'a'...'z', 'A'...'Z', '0'...'9', '-', '.', '/', '_' => {},
            else => return error.InvalidBatchType,
        }
    }
}

fn validateParameter(param: []const u8) BatchError!void {
    if (param.len == 0) return error.InvalidParameter;
    for (param) |ch| {
        switch (ch) {
            0, '\r', '\n', ' ' => return error.InvalidParameter,
            else => {},
        }
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
    while (cursor < bytes.len and bytes[cursor] == ' ') {
        cursor += 1;
    }
    return cursor;
}

fn findByte(bytes: []const u8, needle: u8) ?usize {
    return findByteIn(bytes, needle);
}

fn findByteIn(bytes: []const u8, needle: u8) ?usize {
    var cursor: usize = 0;
    while (cursor < bytes.len) : (cursor += 1) {
        if (bytes[cursor] == needle) return cursor;
    }
    return null;
}

fn appendByte(out: []u8, cursor: *usize, byte: u8) BatchError!void {
    if (cursor.* >= out.len) return error.OutputTooSmall;
    out[cursor.*] = byte;
    cursor.* += 1;
}

fn appendSlice(out: []u8, cursor: *usize, bytes: []const u8) BatchError!void {
    if (bytes.len > out.len -| cursor.*) return error.OutputTooSmall;
    @memcpy(out[cursor.* .. cursor.* + bytes.len], bytes);
    cursor.* += bytes.len;
}

test "open and close emit BATCH lines" {
    var session = DefaultSession.init(0);
    var out: [128]u8 = undefined;

    const opened = try session.open(.netjoin, &.{ "#orochi", "irc.example" }, &out);
    try std.testing.expectEqualStrings("mz0000000000000001", opened.ref.slice());
    try std.testing.expectEqualStrings(
        "BATCH +mz0000000000000001 netjoin #orochi irc.example\r\n",
        opened.line,
    );

    const closed = try session.close(&out);
    try std.testing.expectEqualStrings("BATCH -mz0000000000000001\r\n", closed);
    try std.testing.expect(!session.isOpen());
}

test "nested batches close in stack order" {
    var session = DefaultSession.init(0);
    var out: [128]u8 = undefined;

    const outer = try session.open(.netsplit, &.{ "irc.a", "irc.b" }, &out);
    const inner = try session.open(.labeled, &.{"label-1"}, &out);

    try std.testing.expectEqualStrings("mz0000000000000001", outer.ref.slice());
    try std.testing.expectEqualStrings("mz0000000000000002", inner.ref.slice());
    try std.testing.expectEqualStrings(inner.ref.slice(), session.activeRef().?.slice());

    try std.testing.expectError(error.UnbalancedClose, session.closeRef(outer.ref, &out));

    const inner_close = try session.close(&out);
    try std.testing.expectEqualStrings("BATCH -mz0000000000000002\r\n", inner_close);
    const outer_close = try session.close(&out);
    try std.testing.expectEqualStrings("BATCH -mz0000000000000001\r\n", outer_close);
}

test "outbound lines are tagged with active ref" {
    var session = DefaultSession.init(41);
    var out: [160]u8 = undefined;

    const opened = try session.open(.chathistory, &.{ "#orochi", "latest" }, &out);
    try std.testing.expectEqualStrings("mz000000000000002a", opened.ref.slice());

    const untagged = try session.wrapLine(":s PRIVMSG #orochi :hello\r\n", &out);
    try std.testing.expectEqualStrings(
        "@batch=mz000000000000002a :s PRIVMSG #orochi :hello\r\n",
        untagged,
    );

    const tagged = try session.wrapLine("@time=2026-06-02T00:00:00.000Z NOTICE #orochi :hi", &out);
    try std.testing.expectEqualStrings(
        "@batch=mz000000000000002a;time=2026-06-02T00:00:00.000Z NOTICE #orochi :hi\r\n",
        tagged,
    );
}

test "generated refs are unique" {
    var session = DefaultSession.init(0);
    var out: [128]u8 = undefined;

    const first = try session.open(.labeled, &.{"one"}, &out);
    const second = try session.open(.labeled, &.{"two"}, &out);

    try std.testing.expect(!first.ref.eql(&second.ref));
    try std.testing.expectEqualStrings("mz0000000000000001", first.ref.slice());
    try std.testing.expectEqualStrings("mz0000000000000002", second.ref.slice());
}

test "unbalanced close is rejected" {
    var session = DefaultSession.init(0);
    var out: [64]u8 = undefined;

    try std.testing.expectError(error.UnbalancedClose, session.close(&out));
}

test "invalid input is rejected without mutating open state" {
    var session = DefaultSession.init(0);
    var out: [160]u8 = undefined;

    try std.testing.expectError(error.InvalidParameter, session.open(.netjoin, &.{"bad param"}, &out));
    try std.testing.expect(!session.isOpen());

    _ = try session.open(.labeled, &.{"ok"}, &out);
    try std.testing.expectError(error.DuplicateBatchTag, session.wrapLine("@batch=evil PRIVMSG #c :x", &out));
    try std.testing.expectError(error.InvalidLine, session.wrapLine("PRIVMSG #c :bad\nmiddle\n", &out));
}

//! IRCv3 netsplit/netjoin batch framing helpers.
//!
//! This module only builds wire bytes for callers that have already decided a
//! client negotiated the IRCv3 batch capability. The sink is caller-owned, and
//! the framing path uses bounded stack scratch storage.
const std = @import("std");
const batch = @import("batch.zig");

pub const default_max_lines: usize = 256;
pub const default_max_server_name_len: usize = 255;

pub const NetsplitBatchError = batch.BatchError || error{
    EmptyBatch,
    TooManyLines,
    InvalidServer,
};

pub const Kind = enum {
    netsplit,
    netjoin,

    pub fn batchType(self: Kind) batch.BatchType {
        return switch (self) {
            .netsplit => .netsplit,
            .netjoin => .netjoin,
        };
    }

    pub fn lineCommand(self: Kind) []const u8 {
        return switch (self) {
            .netsplit => "QUIT",
            .netjoin => "JOIN",
        };
    }
};

pub const Config = struct {
    max_lines: usize = default_max_lines,
    max_line_body: usize = batch.default_max_line_body,
    max_server_name_len: usize = default_max_server_name_len,
};

/// Convenience sink for `std.ArrayList(u8)` in Zig 0.16's allocator-explicit API.
pub const ArrayListSink = struct {
    allocator: std.mem.Allocator,
    list: *std.ArrayList(u8),

    pub fn writeAll(self: *ArrayListSink, bytes: []const u8) std.mem.Allocator.Error!void {
        try self.list.appendSlice(self.allocator, bytes);
    }
};

/// Emit one `BATCH +ref netsplit server1 server2` envelope around QUIT lines.
pub fn emitNetsplit(
    comptime config: Config,
    sink: anytype,
    seed: u64,
    server1: []const u8,
    server2: []const u8,
    quit_lines: []const []const u8,
) anyerror!batch.BatchRef {
    return emitSlice(config, sink, .netsplit, seed, server1, server2, quit_lines);
}

/// Emit one `BATCH +ref netjoin server1 server2` envelope around JOIN lines.
pub fn emitNetjoin(
    comptime config: Config,
    sink: anytype,
    seed: u64,
    server1: []const u8,
    server2: []const u8,
    join_lines: []const []const u8,
) anyerror!batch.BatchRef {
    return emitSlice(config, sink, .netjoin, seed, server1, server2, join_lines);
}

/// Emit a complete netsplit or netjoin batch into `sink.writeAll`.
pub fn emitSlice(
    comptime config: Config,
    sink: anytype,
    kind: Kind,
    seed: u64,
    server1: []const u8,
    server2: []const u8,
    lines: []const []const u8,
) anyerror!batch.BatchRef {
    comptime validateConfig(config);

    if (lines.len == 0) return error.EmptyBatch;
    if (lines.len > config.max_lines) return error.TooManyLines;
    try validateServer(config, server1);
    try validateServer(config, server2);

    for (lines) |line| try validateEventLine(kind, line);

    const Session = batch.BatchSession(.{ .max_depth = 1, .max_line_body = config.max_line_body });
    var session = Session.init(seed);
    var out: [maxWireLine(config)]u8 = undefined;

    const opened = try session.open(kind.batchType(), &.{ server1, server2 }, &out);
    try sink.writeAll(opened.line);

    for (lines) |line| {
        try sink.writeAll(try session.wrapLine(line, &out));
    }

    try sink.writeAll(try session.close(&out));
    return opened.ref;
}

fn validateConfig(comptime config: Config) void {
    if (config.max_lines == 0) @compileError("netsplit batch max_lines must be non-zero");
    if (config.max_line_body == 0) @compileError("netsplit batch max_line_body must be non-zero");
    if (config.max_server_name_len == 0) @compileError("netsplit batch max_server_name_len must be non-zero");
}

fn maxWireLine(comptime config: Config) usize {
    return 1 + "batch=".len + batch.max_reference_len + 1 + config.max_line_body + 2;
}

fn validateServer(comptime config: Config, server: []const u8) NetsplitBatchError!void {
    if (server.len == 0 or server.len > config.max_server_name_len) return error.InvalidServer;
    for (server) |ch| {
        switch (ch) {
            0, '\r', '\n', ' ' => return error.InvalidServer,
            else => {},
        }
    }
}

fn validateEventLine(kind: Kind, line: []const u8) NetsplitBatchError!void {
    const body = stripLineEnding(line);
    if (body.len == 0) return error.InvalidLine;

    var cursor: usize = 0;
    if (body[cursor] == '@') {
        cursor = std.mem.indexOfScalar(u8, body, ' ') orelse return error.InvalidLine;
        cursor = skipSpaces(body, cursor);
        if (cursor >= body.len) return error.InvalidLine;
    }

    if (body[cursor] == ':') {
        const source_end = std.mem.indexOfScalar(u8, body[cursor..], ' ') orelse return error.InvalidLine;
        if (source_end == 1) return error.InvalidLine;
        cursor = skipSpaces(body, cursor + source_end);
        if (cursor >= body.len) return error.InvalidLine;
    }

    const command_end = std.mem.indexOfScalar(u8, body[cursor..], ' ') orelse body.len - cursor;
    const command = body[cursor .. cursor + command_end];
    if (!asciiEqlIgnoreCase(command, kind.lineCommand())) return error.InvalidLine;
}

fn asciiEqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |left, right| {
        if (std.ascii.toUpper(left) != std.ascii.toUpper(right)) return false;
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

fn build(kind: Kind, seed: u64, lines: []const []const u8) !std.ArrayList(u8) {
    const allocator = std.testing.allocator;
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);

    var sink = ArrayListSink{ .allocator = allocator, .list = &out };
    _ = try emitSlice(.{}, &sink, kind, seed, "hub.example", "leaf.example", lines);
    return out;
}

test "netsplit batch wraps several QUIT lines with exact envelope bytes" {
    const quits = [_][]const u8{
        ":alice!a@leaf QUIT :hub.example leaf.example",
        ":bob!b@leaf QUIT :hub.example leaf.example\r\n",
        "@time=2026-06-04T09:00:00.000Z :carol!c@leaf QUIT :hub.example leaf.example",
    };

    var out = try build(.netsplit, 0, &quits);
    defer out.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings(
        "BATCH +mz0000000000000001 netsplit hub.example leaf.example\r\n" ++
            "@batch=mz0000000000000001 :alice!a@leaf QUIT :hub.example leaf.example\r\n" ++
            "@batch=mz0000000000000001 :bob!b@leaf QUIT :hub.example leaf.example\r\n" ++
            "@batch=mz0000000000000001;time=2026-06-04T09:00:00.000Z :carol!c@leaf QUIT :hub.example leaf.example\r\n" ++
            "BATCH -mz0000000000000001\r\n",
        out.items,
    );
}

test "netjoin batch wraps JOIN lines with exact envelope bytes" {
    const joins = [_][]const u8{
        ":alice!a@leaf JOIN #ops",
        "@time=2026-06-04T09:01:00.000Z :bob!b@leaf JOIN #ops",
    };

    var out = try build(.netjoin, 41, &joins);
    defer out.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings(
        "BATCH +mz000000000000002a netjoin hub.example leaf.example\r\n" ++
            "@batch=mz000000000000002a :alice!a@leaf JOIN #ops\r\n" ++
            "@batch=mz000000000000002a;time=2026-06-04T09:01:00.000Z :bob!b@leaf JOIN #ops\r\n" ++
            "BATCH -mz000000000000002a\r\n",
        out.items,
    );
}
